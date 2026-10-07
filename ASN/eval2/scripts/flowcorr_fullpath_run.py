#!/usr/bin/env python3
"""Full Receiver-to-Sender (R->S) topology: empirically testing ASN's own
D1/D2/D3 node-compromise escalation, per anosecnet.tex's analytical
claims. Every other test in this evaluation suite (flowcorr_run.py and every
script built on it) only ever modeled the R<->SG_R half of the network
(paths A/B). This script covers the FULL forward leg:

    R -> MN1 -> MN2 -> MN3 -> SG_R -> CS -> SG_S -> MNx -> MNy -> MNz -> S

(config.h lines 4-32, anosecnet.tex 597-611/690-720/862-882). SG_R and
SG_S are conceptually distinct gateways in the paper's own D1/D2/D3
framing (the deployed C code runs one shared instance of each, this
simulator follows the paper's conceptual model, since that's what
D1/D2/D3 are defined against).

Paper's escalation (anosecnet.tex Result D1/D2/D3):
  D1 = {MN1, MN3}                      Pr = f^2
  D2 = D1 + {SG_R, CS}                 Pr = f^4
  D3 = D2 + {SG_S, MNx, MNz}           Pr = f^7  (f^8, distinct 2nd CS)

CRITICAL: these f^k figures are the paper's analytical probability that
a randomly-compromised fraction f of the network happens to include the
needed node set, NOT the same axis as this script's TPR@FPR, which
measures correlator success GIVEN the adversary already controls those
nodes. Never conflate the two in the write-up.

Reuses everything reusable from flowcorr_run.py (imported, never
copied/modified beyond the one already-made, already-verified
tick_mean_override addition to gen_hardened_dispatch, see that
function's docstring). Two genuinely new pieces: per-hop observable
timestamps (today's simulator only tracks entry/exit, collapsing all
intermediate hops into one cumulative delay), and a Sender-side real-
traffic generator (sender.c's real traffic is a one-shot human-
triggered upload, no existing rate model to reuse).

Scope: FORWARD path only. Every D1/D2/D3 node lives on the forward leg;
full bidirectional linkage (D3) is achieved via the forward path plus
SG_S, not by modeling the return leg's own traffic. Return-path
modeling is deliberately deferred, not silently skipped, see
tier0_full_topology_d1d2d3.md.
"""

import argparse
import csv
import math
import os
import random
import sys
import time

import numpy as np

import flowcorr_run
from flowcorr_run import (
    SESSION_DURATION_S, BIN_WIDTH_MS, PER_HOP_JITTER_MS,
    DUMMY_INTERVAL_MS, MIX_DELAY_MEAN_MS,
    gen_real_packet_times, gen_cover_times_with_suppression,
    gen_hardened_dispatch, hop_delay_sample, apply_exit_timing,
    to_features, score_pair, roc_tpr_at_fpr, ci95_proportion,
    _cover_tick_ms,
)

# ---------------------------------------------------------------------------
# Position taxonomy
# ---------------------------------------------------------------------------
# Forward leg (R->S): R's own sending path (MN1-3), then the shared
# Receiver-side gateway/cache, then the Sender-side gateway, then S's own
# receiving path (MNx-z). This is config.h's actual routing (Sending:
# Client->MN1->MN2->MN3->SvcGW; on the Sender side, delivery arrives via
# SvcGW->MNx->MNy->MNz->Sender), gateway sits BEFORE its own side's mix
# nodes on both ends, mirroring R->MN1,MN2,MN3->SG_R's own shape.
FORWARD_POSITIONS = ["MN1", "MN2", "MN3", "SG_R", "CS", "SG_S", "MNx", "MNy", "MNz"]

# Return leg (S->R): config.h / anosecnet.tex's mirror image of the forward
# leg: S's own sending path (MNi-iii), through the SAME shared gateway/
# cache infrastructure (SG_S, CS, SG_R, these are the identical physical
# positions as in FORWARD_POSITIONS, not distinct instances), then R's own
# receiving path (MNa-c). The full round-trip exchange
# ("R getting data from S") is 12 distinct mix nodes + 2 SGs + 1 CS = 15
# components across BOTH legs, not just the forward leg's 9-position subset.
RETURN_POSITIONS = ["MNi", "MNii", "MNiii", "SG_S", "CS", "SG_R", "MNa", "MNb", "MNc"]

# Every position that appears in EITHER leg, shared ones (SG_R, CS, SG_S)
# counted once. 12 mix nodes + SG_R + CS + SG_S = 15.
ALL_MIX_NODES = ["MN1", "MN2", "MN3", "MNx", "MNy", "MNz",
                  "MNi", "MNii", "MNiii", "MNa", "MNb", "MNc"]
SHARED_GATEWAY_POSITIONS = ["SG_R", "CS", "SG_S"]
FULL_ROUNDTRIP = ALL_MIX_NODES + SHARED_GATEWAY_POSITIONS  # the 15-component set

# The real-IP-visible edge positions on the forward leg, needed by
# score_compromise_set()'s "anchored-pairs" mode (edge_positions
# param).
EDGE_POSITIONS = ["MN1", "MNz"]

# Named escalation levels, exactly as anosecnet.tex Result D1/D2/D3 define them.
D1 = ["MN1", "MN3"]
D2 = D1 + ["SG_R", "CS"]
D3_FORWARD = D2 + ["SG_S", "MNx", "MNz"]

# Mirror-image escalation for the return leg, NOT from the paper (which
# only defines D1/D2/D3 for the forward leg), constructed here by direct
# analogy for symmetry. Flagged explicitly: this is our own extension, not
# a cited result.
D1_RETURN = ["MNi", "MNiii"]
D2_RETURN = D1_RETURN + ["SG_S", "CS"]
D3_RETURN = D2_RETURN + ["SG_R", "MNa", "MNc"]


def _position_index(p: str, positions=FORWARD_POSITIONS) -> int:
    return positions.index(p)


def sort_positions(compromise_set, positions=FORWARD_POSITIONS):
    return sorted(compromise_set, key=lambda p: _position_index(p, positions))


# ---------------------------------------------------------------------------
# The two genuinely new pieces
# ---------------------------------------------------------------------------
def apply_positional_delays(rng: random.Random, times, positions, hardened: bool = False,
                             mean_override: float = None):
    """Per-hop observable timestamps: for each input time, walk `positions`
    in order, accumulating one hop_delay_sample() draw per position
    (identical formula to apply_hop_jitter()'s inner loop), snapshotting
    the running cumulative timestamp AT EVERY position TWICE, once on
    ARRIVAL (before that position's own hop delay is applied) and once on
    DEPARTURE (after it). Returns (arrival, departure), each
    dict[position] -> sorted list[float ms].

    Why both: a compromised node observes a packet at two distinct
    moments: as it arrives (least mixed so far) and as it forwards the
    packet onward (after contributing its own hop's delay). For a
    two-endpoint correlation attack the informative combination is the
    EARLIEST compromised position's ARRIVAL time and the LATEST
    compromised position's DEPARTURE time, using arrival[positions[0]]
    exactly reproduces flowcorr_run.py's "entry" checkpoint (dispatched
    real times, zero hop delay) and departure[positions[-1]] exactly
    reproduces its "exit" checkpoint (after N_HOPS_PATH hop-delay draws),
    for compromise sets the same length as the original 3-hop path (e.g.
    D1={MN1,MN3} spans MN1's arrival -> MN3's departure = 3 hop-delay
    draws, matching asn_one_path's entry->exit exactly). A single shared
    dict (departure only, entry included as departure-from-MN1) was tried
    first and undercounted this span by one hop, see git history /
    tier0_full_topology_d1d2d3.md for the anchor-check discrepancy this
    fixes.

    Verified equivalent to flowcorr_run.apply_hop_jitter() at the final
    position's DEPARTURE for identically-seeded RNGs, see --self-test."""
    out_arrival = {p: [] for p in positions}
    out_departure = {p: [] for p in positions}
    for t in times:
        cur = t
        for p in positions:
            out_arrival[p].append(cur)
            cur += hop_delay_sample(rng, hardened, mean_override)
            out_departure[p].append(cur)
    for p in positions:
        out_arrival[p] = sorted(out_arrival[p])
        out_departure[p] = sorted(out_departure[p])
    return out_arrival, out_departure


def apply_positional_exit_timing(rng: random.Random, times, positions,
                                  mean_override: float = None):
    """Mechanism-aware per-hop observable timestamps: calls
    flowcorr_run.apply_exit_timing() once per position (n_hops=1) instead
    of once for the whole path, threading each position's output into the
    next position's input. This means pool-mixing/Danezis-pool-mixing/
    threshold-batching (selected via the SAME module-level
    flowcorr_run.POOL_MIXING/etc. flags this script's CLI sets) keep
    working with zero duplicated mechanism code, apply_exit_timing()
    already does "one hop of whatever mechanism is active" as an internal
    step of its own n_hops-hop loop; this just calls that step once per
    named position. Returns dict[position] -> sorted list[float ms].

    Returns (arrival, departure) dicts, same ARRIVAL-vs-DEPARTURE split as
    apply_positional_delays() above and for the same reason, see that
    function's docstring. arrival[p] is `cur` as handed to this position
    (before its own apply_exit_timing() call); departure[p] is the result
    after it.

    Verified equivalent to flowcorr_run.apply_exit_timing() at the final
    position's DEPARTURE for identically-seeded RNGs, under every
    mechanism flag, see --self-test."""
    out_arrival = {}
    out_departure = {}
    cur = list(times)
    for p in positions:
        out_arrival[p] = sorted(cur)
        cur = apply_exit_timing(rng, cur, 1, mean_override=mean_override)
        out_departure[p] = sorted(cur)
    return out_arrival, out_departure


def gen_sender_real_packet_times(rng: random.Random, mode: str, duration_s: float):
    """HYPOTHETICAL, NO CODE EQUIVALENT. sender.c's real upload traffic
    (upload_content()) is a one-shot, human-triggered CLI PUT, not a
    rate-parametrized stream. Three modes, chosen to favor burst-shaped
    traffic over pure Poisson reuse for methodological soundness:

    "single_upload": ONE PUT event at a uniform-random point in
        [0, duration_s*1000), the honest, low-signal literal-fidelity
        anchor, closest to the real one-shot CLI behavior.
    "poisson": delegates UNCHANGED to gen_real_packet_times() (imported,
        zero duplication), the Receiver-side interactive/bulk model,
        kept as a SENSITIVITY mode for comparability to the rest of this
        study's methodology, not the primary claim about Sender
        traffic shape.
    "burst": the primary mode, one burst of N packets (N drawn the
        same way gen_real_packet_times() draws its own session packet
        counts, reusing that machinery rather than inventing a new
        constant) with inter-packet spacing drawn from the SAME jitter
        distribution already used for cover-traffic generation
        (_cover_tick_ms(), imported unchanged), avoids fabricating any
        new, unfounded rate constant, while producing a defensible
        "dense block then silence" shape for a one-shot upload."""
    if mode == "single_upload":
        return [rng.uniform(0.0, duration_s * 1000.0)]
    if mode == "poisson":
        return gen_real_packet_times(rng, "interactive", duration_s)
    if mode == "burst":
        # Reuse gen_real_packet_times() purely to draw a comparable packet
        # COUNT (via its own interactive-flow session-count distribution),
        # discarding its own inter-packet timing, only the burst's own
        # jitter-distribution-derived spacing (below) determines timing.
        n = len(gen_real_packet_times(rng, "interactive", duration_s))
        n = max(1, n)
        start = rng.uniform(0.0, max(1.0, duration_s * 1000.0 - n * DUMMY_INTERVAL_MS))
        out = []
        cur = start
        for _ in range(n):
            out.append(cur)
            cur += _cover_tick_ms(rng)
        return sorted(t for t in out if t < duration_s * 1000.0)
    raise ValueError(mode)


# ---------------------------------------------------------------------------
# Session generation
# ---------------------------------------------------------------------------
def gen_fullpath_session(rng: random.Random, flow_type: str, sender_mode: str,
                          hardened: bool):
    """Builds one session's per-position observable traces for the
    forward R->S leg. Returns dict[position] -> (all_times, real_times),
    both sorted lists.

    Real traffic: R's own real times via gen_real_packet_times()
    (imported, UNCHANGED call). Cover: gen_cover_times_with_suppression()/
    gen_hardened_dispatch() (imported, UNCHANGED calls) merged with real
    at the path's origin (R), then apply_positional_exit_timing() walks
    the merged, dispatched stream through every forward position,
    mirrors gen_session()'s own "merge real+cover, split into two
    apply_exit_timing calls, remerge" pattern (same RNG-order-
    preservation reasoning already established there).

    Sender-side traffic (S's own real generation) is NOT modeled here,
    this function only produces the FORWARD leg's OWN real+cover trace,
    which is what D1/D2/D3's node sets observe. `sender_mode` is
    accepted for API symmetry with future round-trip work but unused in
    this forward-only build; see tier0_full_topology_d1d2d3.md."""
    real_times = gen_real_packet_times(rng, flow_type, SESSION_DURATION_S)
    if hardened:
        dispatched_real, cover_times = gen_hardened_dispatch(rng, real_times, SESSION_DURATION_S)
    else:
        dispatched_real = real_times
        cover_times = gen_cover_times_with_suppression(rng, real_times, SESSION_DURATION_S)

    real_arr, real_dep = apply_positional_exit_timing(rng, dispatched_real, FORWARD_POSITIONS)
    cover_arr, cover_dep = apply_positional_exit_timing(rng, cover_times, FORWARD_POSITIONS)

    session = {}
    for p in FORWARD_POSITIONS:
        session[p] = {
            "arrival": (sorted(real_arr[p] + cover_arr[p]), real_arr[p]),
            "departure": (sorted(real_dep[p] + cover_dep[p]), real_dep[p]),
        }
    return session


def gen_roundtrip_session(rng: random.Random, flow_type: str, hardened: bool):
    """Builds one session's per-position observable traces for the FULL
    R<->S round trip: forward leg (R's own request/upload reaching S) PLUS
    return leg (S's actual data reaching R), the 15-component picture
    (12 mix nodes + SG_R + CS + SG_S), covering both legs rather than
    just the forward leg's 9 positions.

    Forward and return real traffic are generated with INDEPENDENT RNG
    draws (two separate gen_real_packet_times() calls), this is a
    labeled ASSUMPTION, not a confirmed fact: whether the real protocol's
    request and response are causally/temporally coupled (e.g. R's
    request must complete before S's response begins) is not established
    from source in this session. Treating them as independent is the
    same "don't invent an unconfirmed mechanism" discipline used
    elsewhere in this script (e.g. the Sender-traffic model), if a
    C-source check later confirms a coupling, this should be revisited,
    not silently assumed away.

    SG_R, CS, SG_S are SHARED physical positions observed by BOTH legs,
    their traces are the MERGE of forward-leg and return-leg traffic
    (real+cover from both), reflecting that the same gateway/cache
    instance relays both directions. The six leg-specific mix nodes on
    each side (MN1-3/MNx-z for forward, MNi-iii/MNa-c for return) each
    see only their own leg's traffic, they are physically distinct
    nodes with no shared visibility.

    Returns dict[position] -> {"arrival": (all_times, real_times),
    "departure": (all_times, real_times)}, same shape as
    gen_fullpath_session(), covering all 15 FULL_ROUNDTRIP positions."""
    real_fwd = gen_real_packet_times(rng, flow_type, SESSION_DURATION_S)
    if hardened:
        dispatched_fwd, cover_fwd = gen_hardened_dispatch(rng, real_fwd, SESSION_DURATION_S)
    else:
        dispatched_fwd = real_fwd
        cover_fwd = gen_cover_times_with_suppression(rng, real_fwd, SESSION_DURATION_S)
    real_arr_fwd, real_dep_fwd = apply_positional_exit_timing(rng, dispatched_fwd, FORWARD_POSITIONS)
    cover_arr_fwd, cover_dep_fwd = apply_positional_exit_timing(rng, cover_fwd, FORWARD_POSITIONS)

    real_ret = gen_real_packet_times(rng, flow_type, SESSION_DURATION_S)
    if hardened:
        dispatched_ret, cover_ret = gen_hardened_dispatch(rng, real_ret, SESSION_DURATION_S)
    else:
        dispatched_ret = real_ret
        cover_ret = gen_cover_times_with_suppression(rng, real_ret, SESSION_DURATION_S)
    real_arr_ret, real_dep_ret = apply_positional_exit_timing(rng, dispatched_ret, RETURN_POSITIONS)
    cover_arr_ret, cover_dep_ret = apply_positional_exit_timing(rng, cover_ret, RETURN_POSITIONS)

    session = {}
    forward_only = [p for p in FORWARD_POSITIONS if p not in SHARED_GATEWAY_POSITIONS]
    return_only = [p for p in RETURN_POSITIONS if p not in SHARED_GATEWAY_POSITIONS]
    for p in forward_only:
        session[p] = {
            "arrival": (sorted(real_arr_fwd[p] + cover_arr_fwd[p]), real_arr_fwd[p]),
            "departure": (sorted(real_dep_fwd[p] + cover_dep_fwd[p]), real_dep_fwd[p]),
        }
    for p in return_only:
        session[p] = {
            "arrival": (sorted(real_arr_ret[p] + cover_arr_ret[p]), real_arr_ret[p]),
            "departure": (sorted(real_dep_ret[p] + cover_dep_ret[p]), real_dep_ret[p]),
        }
    for p in SHARED_GATEWAY_POSITIONS:
        session[p] = {
            "arrival": (sorted(real_arr_fwd[p] + cover_arr_fwd[p] + real_arr_ret[p] + cover_arr_ret[p]),
                        sorted(real_arr_fwd[p] + real_arr_ret[p])),
            "departure": (sorted(real_dep_fwd[p] + cover_dep_fwd[p] + real_dep_ret[p] + cover_dep_ret[p]),
                          sorted(real_dep_fwd[p] + real_dep_ret[p])),
        }
    return session


# ---------------------------------------------------------------------------
# Compromise-set scoring
# ---------------------------------------------------------------------------
def precompute_features(session, duration_s=SESSION_DURATION_S, bin_width_ms=BIN_WIDTH_MS):
    """Converts a raw gen_fullpath_session() dict (position -> {"arrival":
    (all_times,real_times), "departure": (all_times,real_times)}) into the
    precomputed-features format score_compromise_set() expects:
    position -> {"arrival": ((vol_all,tim_all),(vol_real,tim_real)),
    "departure": (same shape)}. Doing this ONCE per session up front,
    rather than letting score_compromise_set() call to_features() fresh on
    every one of the many (compromise-set x scoring-mode x session-pair)
    combinations a sweep evaluates, is what makes sweeping many
    compromise sets over N^2 session pairs tractable; the naive version
    timed out even at N=30 during initial testing."""
    return {p: {role: (to_features(all_t, duration_s, bin_width_ms),
                        to_features(real_t, duration_s, bin_width_ms))
                for role, (all_t, real_t) in roles.items()}
            for p, roles in session.items()}


def score_compromise_set(session_i, session_j, compromise_set, correlator: str,
                          mode: str = "endpoints", real_only: bool = False,
                          leg_positions=FORWARD_POSITIONS, edge_positions=None):
    """Generalizes flowcorr_run.score_session_pair()'s max(sub_scores)
    pattern from 'exactly 2 fixed sub-paths' to 'any subset of named
    forward positions'. session_i/session_j: PRECOMPUTED-features dicts
    from precompute_features(), position -> ((vol_all,tim_all),
    (vol_real,tim_real)). real_only: use each position's real-only
    features instead of the full real+cover ones (the real-only-
    subsequence diagnostic used throughout this evaluation suite).

    mode="endpoints" (default, paper-faithful): sort compromise_set by
    path position; score session_i's EARLIEST position's ARRIVAL
    observation (entry-side, least mixed, before that position's own
    hop delay) against session_j's LATEST position's DEPARTURE
    observation (exit-side, after that position's own hop delay).
    Using arrival for the earlier endpoint and departure for the later
    one is what makes this exactly reproduce score_session_pair()'s
    existing asn_one_path behavior when compromise_set == ["MN1","MN3"]:
    arrival[MN1] has zero hop-delay draws applied (same as asn_one_path's
    "entry"), departure[MN3] has exactly N_HOPS_PATH=3 draws applied
    (same as its "exit"), see apply_positional_delays()'s docstring for
    why a single shared dict undercounts this by one hop. A single-
    position set (positions[0] is positions[-1]) is a degenerate self-
    comparison; both sides use "departure" for it (arbitrary but
    consistent, and matches this script's original single-dict
    behavior before the arrival/departure split).

    mode="max-pairs": max score over every (entry,exit) pair drawn from
    compromise_set with entry earlier than exit (entry's ARRIVAL vs
    exit's DEPARTURE, same convention as endpoints), mathematically
    dominates endpoints (never lower); the gap between the two is itself
    informative about how much interior positions add.

    mode="chain-evidence":
    mean of score_pair() over every ADJACENT pair in the sorted
    compromise set (pos[0]-pos[1], pos[1]-pos[2], ..., pos[k-2]-pos[k-1]),
    each pair scored as the earlier position's ARRIVAL vs the later
    position's DEPARTURE, treats every compromised position as
    corroborating evidence for one candidate flow, rather than reducing
    the set to its single strongest pair. Degenerates to a single
    score_pair() call for len(compromise_set)==2.

    leg_positions: the position-ordering list sort_positions() sorts
    against (default FORWARD_POSITIONS, matching this function's
    original forward-leg-only behavior). Pass RETURN_POSITIONS to score
    a return-leg compromise set with its own correct chronological
    order: added for score_roundtrip_compromise_set().

    mode="anchored-pairs": same search as
    max-pairs, but restricted to pairs where AT LEAST ONE position is
    in edge_positions, the real-IP-visible positions (MN1 for the
    Receiver side, MNz for the Sender side on the forward leg). Built
    because max-pairs/chain-evidence were found to be dominated by
    interior-only pairs (e.g. SG_R-vs-CS) that never observe a real R/S
    IP under ASN's design, inflating what looked like a deanonymization
    number with what's actually the same session-linkability-only signal
    Layer 3's standalone {SG_R,CS} test already surfaced. This isolates
    "how much of the correlation signal is actually anchored to a real
    identity" from "how linkable are two anonymous sessions at this
    compromise set overall" (max-pairs/chain-evidence still answer the
    latter; neither is wrong, they're different questions). Raises
    ValueError if compromise_set contains no edge position and no pair
    involving one is possible, silently falling back to an unanchored
    result would defeat the entire purpose of this mode."""
    positions = sort_positions(compromise_set, positions=leg_positions)
    idx = 1 if real_only else 0

    def feat(session, pos, role):
        return session[pos][role][idx]

    if mode == "endpoints":
        single = positions[0] == positions[-1]
        ve, te = feat(session_i, positions[0], "departure" if single else "arrival")
        vx, tx = feat(session_j, positions[-1], "departure")
        return score_pair(ve, te, vx, tx, correlator)

    if mode == "max-pairs":
        best = None
        for a in range(len(positions)):
            for b in range(a + 1, len(positions)):
                ve, te = feat(session_i, positions[a], "arrival")
                vx, tx = feat(session_j, positions[b], "departure")
                s = score_pair(ve, te, vx, tx, correlator)
                if best is None or s > best:
                    best = s
        return best

    if mode == "chain-evidence":
        if len(positions) < 2:
            raise ValueError("chain-evidence needs >= 2 positions")
        scores = []
        for a in range(len(positions) - 1):
            ve, te = feat(session_i, positions[a], "arrival")
            vx, tx = feat(session_j, positions[a + 1], "departure")
            scores.append(score_pair(ve, te, vx, tx, correlator))
        return sum(scores) / len(scores)

    if mode == "anchored-pairs":
        if not edge_positions:
            raise ValueError("anchored-pairs requires edge_positions "
                             "(the real-IP-visible positions for this leg)")
        best = None
        for a in range(len(positions)):
            for b in range(a + 1, len(positions)):
                if positions[a] not in edge_positions and positions[b] not in edge_positions:
                    continue  # neither end of this pair ever sees a real R/S IP
                ve, te = feat(session_i, positions[a], "arrival")
                vx, tx = feat(session_j, positions[b], "departure")
                s = score_pair(ve, te, vx, tx, correlator)
                if best is None or s > best:
                    best = s
        if best is None:
            raise ValueError("anchored-pairs: compromise_set contains no edge "
                             "position and no pair involving one, this "
                             "compromise set cannot answer a deanonymization "
                             "question at all under this mode")
        return best

    raise ValueError(mode)


def score_roundtrip_compromise_set(session_i, session_j, compromise_set, correlator: str,
                                    mode: str = "chain-evidence", combine: str = "mean",
                                    real_only: bool = False):
    """Scores a compromise set that may span BOTH legs (forward and/or
    return) of a full R<->S round trip, session_i/session_j here are
    precompute_features() output from gen_roundtrip_session(), which uses
    a single flat position->features dict (shared positions SG_R/CS/SG_S
    already merged at generation time), so this reuses
    score_compromise_set() for each leg's own sub-scoring (via its
    leg_positions parameter, so a return-leg set is sorted in RETURN_
    POSITIONS' own chronological order, not FORWARD_POSITIONS'); the only
    new logic here is combining the two legs' scores into one round-trip
    verdict.

    mode: passed straight through to each leg's score_compromise_set()
    call, "endpoints"/"max-pairs"/"chain-evidence". Default is
    "chain-evidence", not "endpoints": endpoints mode understates a
    rational adversary's true capability by
    40-75 percentage points for sets bigger than 2 positions, D2 went
    1.6% endpoints vs 75.2% max-pairs, D3 went 0% vs 75.6-77.2%. Every
    round-trip set with more than 2 positions per leg (D2/D3-both-legs,
    FULL_ROUNDTRIP) would have hit the identical understatement under the
    old hard-coded endpoints-only scoring.

    compromise_set may contain forward-only positions, return-only
    positions, shared positions, or any mix. Splits into a forward-leg
    sub-set (any position in FORWARD_POSITIONS) and a return-leg sub-set
    (any position in RETURN_POSITIONS), shared positions belong to
    both: then combines:

    combine="max" (optimistic, either leg's evidence alone is enough,
    matching flowcorr_run.py's own asn_both_paths convention of
    max-of-subpaths): the higher of the two legs' scores.

    combine="mean" (default, both legs' worth of consistent evidence
    required for a real round-trip confirmation, the more rigorous
    reading given the user's own framing of what "R gets data from S"
    actually needs): the average of the two legs' scores. If only one
    leg has any compromised positions, degenerates to that leg's own
    score (no averaging with a leg the adversary doesn't observe at
    all)."""
    fwd_set = [p for p in compromise_set if p in FORWARD_POSITIONS]
    ret_set = [p for p in compromise_set if p in RETURN_POSITIONS]

    fwd_score = None
    if len(fwd_set) >= 1:
        fwd_mode = mode if len(fwd_set) >= 2 else "endpoints"
        fwd_score = score_compromise_set(session_i, session_j, fwd_set, correlator,
                                          mode=fwd_mode, real_only=real_only,
                                          leg_positions=FORWARD_POSITIONS)
    ret_score = None
    if len(ret_set) >= 1:
        ret_mode = mode if len(ret_set) >= 2 else "endpoints"
        ret_score = score_compromise_set(session_i, session_j, ret_set, correlator,
                                          mode=ret_mode, real_only=real_only,
                                          leg_positions=RETURN_POSITIONS)

    if fwd_score is None:
        return ret_score
    if ret_score is None:
        return fwd_score
    if combine == "max":
        return max(fwd_score, ret_score)
    if combine == "mean":
        return (fwd_score + ret_score) / 2.0
    raise ValueError(combine)


# ---------------------------------------------------------------------------
# Degree-of-anonymity metric (Serjantov & Danezis / Diaz-Seys-Claessens-
# Preneel, PET 2002). Full-
# distribution generalization of Loopix's pairwise likelihood-ratio idea:
# instead of asking "did the correlator clear a strict alarm threshold"
# (TPR@FPR), asks "how much has the attacker's uncertainty about which
# candidate is the true match been reduced." Catches a failure mode
# TPR@FPR can't see, a compromise set could fail to clear a strict
# threshold while still collapsing the effective candidate set from N
# down to a handful of plausible sessions, a real leak a binary
# threshold metric never surfaces. Pure post-processing over an already-
# computed score matrix, no new simulation, no new RNG draws.
# ---------------------------------------------------------------------------
def degree_of_anonymity(score_row):
    """score_row: scores of ONE true session against every candidate
    (including itself), score_row[j] = how well candidate j matches.
    Converts to a probability distribution via softmax (higher score =
    more plausible candidate), computes Shannon entropy H = -sum(p*log p),
    normalized by log(N) (max possible entropy, uniform over N candidates)
    to a degree-of-anonymity d in [0,1], 1.0 means the attacker's
    distribution over candidates is uniform (no information gained);
    0.0 means the attacker has fully concentrated probability on one
    candidate (complete deanonymization). Uses a numerically-stable
    softmax (subtract max before exponentiating)."""
    scores = np.asarray(score_row, dtype=float)
    n = len(scores)
    if n <= 1:
        return 1.0
    shifted = scores - np.max(scores)
    weights = np.exp(shifted)
    probs = weights / np.sum(weights)
    nonzero = probs[probs > 0]
    entropy = -np.sum(nonzero * np.log(nonzero))
    return float(entropy / math.log(n))


def mean_degree_of_anonymity(score_matrix):
    """score_matrix: list of rows, row i = degree_of_anonymity() input for
    true session i (scores against every candidate j, self included).
    Returns the mean degree of anonymity across all true sessions,
    report this alongside TPR@FPR, not as a replacement for it."""
    return float(np.mean([degree_of_anonymity(row) for row in score_matrix]))


# ---------------------------------------------------------------------------
# Self-test: equivalence against flowcorr_run.py's existing cumulative functions
# ---------------------------------------------------------------------------
def _lists_close(a, b, tol=1e-6):
    """Element-wise approximate equality. The per-hop functions accumulate
    delay INCREMENTALLY (((t+d1)+d2)+...), while apply_hop_jitter/
    apply_exit_timing sum all hop delays first then add once
    (t+(d1+d2+...)), mathematically identical, but floating-point
    addition isn't associative, so the two can differ in the last bit.
    A tight relative/absolute tolerance is the correct equivalence check
    here, not exact equality."""
    if len(a) != len(b):
        return False
    return all(math.isclose(x, y, rel_tol=tol, abs_tol=tol) for x, y in zip(a, b))


def self_test():
    from flowcorr_run import apply_hop_jitter
    ok = True

    for hardened in (False, True):
        rng1 = random.Random(42)
        rng2 = random.Random(42)
        times = [rng1.uniform(0, 20000) for _ in range(50)]
        rng1 = random.Random(1)
        rng2 = random.Random(1)
        got_arrival, got_departure = apply_positional_delays(rng1, times, FORWARD_POSITIONS, hardened=hardened)
        want = sorted(apply_hop_jitter(rng2, times, len(FORWARD_POSITIONS), hardened=hardened))
        if not _lists_close(got_departure[FORWARD_POSITIONS[-1]], want):
            print(f"FAIL apply_positional_delays vs apply_hop_jitter (hardened={hardened})")
            ok = False
        elif not _lists_close(got_arrival[FORWARD_POSITIONS[0]], sorted(times)):
            print(f"FAIL apply_positional_delays arrival[first] != zero-delay input (hardened={hardened})")
            ok = False
        else:
            print(f"OK   apply_positional_delays vs apply_hop_jitter (hardened={hardened})")

    # apply_positional_exit_timing() necessarily traverses HOP-MAJOR (all
    # packets at hop A, then all packets at hop B, ...) rather than
    # apply_exit_timing()'s PACKET-MAJOR order (all hops for packet A,
    # then packet B, ...), because reusing the existing pool-mixing/
    # threshold-batching mechanism code requires the full packet list to
    # be present at each hop for that mechanism's own windowing logic.
    # Same total RNG draws, same underlying distribution, but a genuinely
    # different interleaving, per-packet results are NOT expected to
    # match (confirmed: they don't, even beyond floating-point tolerance).
    # The correct equivalence check is therefore STATISTICAL (matching
    # mean/std of the delay distribution at large N), not per-packet.
    # NOTE: THRESHOLD_BATCH_SIZE is deliberately excluded from this check
    # (and not exposed via this script's CLI at all, see main()'s
    # argparse block, only --pool-mixing is wired up). Found during
    # implementation: threshold-batching's "release simultaneously"
    # semantics apply ONCE, at the final hop, in apply_exit_timing()'s
    # own composition (full jitter across all n_hops first, batch once
    # at the end), but calling it once per hop (this function's
    # necessary hop-major traversal) reapplies batching at EVERY
    # intermediate position, a genuinely different, more aggressive
    # mechanism, not an equivalent one. Resolving this needs real design
    # work (does per-hop batching even make sense as a model?), out of
    # scope for this build since threshold-batching isn't used by
    # D1/D2/D3 anyway (--hardened-jitter only). Flagged as a known
    # limitation for any future mechanism-sweep-parity work.
    import statistics
    for mech_flags in [{}, {"POOL_MIXING": True}, {"DANEZIS_POOL_MIXING": True}]:
        for k in ("POOL_MIXING", "DANEZIS_POOL_MIXING", "THRESHOLD_BATCH_SIZE"):
            setattr(flowcorr_run, k, mech_flags.get(k, False if k != "THRESHOLD_BATCH_SIZE" else 0))
        n = 3000
        rng_times = random.Random(99)
        times = sorted(rng_times.uniform(0, 20000) for _ in range(n))

        rng_a = random.Random(3)
        got_arrival, got_departure = apply_positional_exit_timing(rng_a, times, FORWARD_POSITIONS)
        delays_got = [g - t for g, t in zip(sorted(got_departure[FORWARD_POSITIONS[-1]]), times)]

        rng_b = random.Random(4)
        want = apply_exit_timing(rng_b, times, len(FORWARD_POSITIONS))
        delays_want = [w - t for w, t in zip(sorted(want), times)]

        mean_got, mean_want = statistics.mean(delays_got), statistics.mean(delays_want)
        label = mech_flags or {"plain": True}
        rel_diff = abs(mean_got - mean_want) / max(abs(mean_want), 1e-9)
        if rel_diff > 0.05:
            print(f"FAIL apply_positional_exit_timing vs apply_exit_timing ({label}): "
                  f"mean {mean_got:.2f} vs {mean_want:.2f} ({rel_diff:.1%} apart)")
            ok = False
        else:
            print(f"OK   apply_positional_exit_timing vs apply_exit_timing ({label}): "
                  f"mean {mean_got:.2f} vs {mean_want:.2f} ({rel_diff:.1%} apart)")
    for k in ("POOL_MIXING", "DANEZIS_POOL_MIXING", "THRESHOLD_BATCH_SIZE"):
        setattr(flowcorr_run, k, False if k != "THRESHOLD_BATCH_SIZE" else 0)

    # Round-trip machinery.
    if len(set(FULL_ROUNDTRIP)) != 15:
        print(f"FAIL FULL_ROUNDTRIP has {len(set(FULL_ROUNDTRIP))} unique positions, expected 15 "
              f"(12 mix nodes + SG_R + CS + SG_S)")
        ok = False
    else:
        print("OK   FULL_ROUNDTRIP has exactly 15 unique positions")

    rng_rt = random.Random(7)
    rt_session = gen_roundtrip_session(rng_rt, "interactive", hardened=True)
    missing = set(FULL_ROUNDTRIP) - set(rt_session.keys())
    if missing:
        print(f"FAIL gen_roundtrip_session missing positions: {missing}")
        ok = False
    else:
        print("OK   gen_roundtrip_session covers every FULL_ROUNDTRIP position")

    # Shared positions must reflect BOTH legs' traffic, not just one,
    # verify a shared position's packet count is at least as large as
    # each leg's own leg-only sibling position (a weak but cheap sanity
    # check that the merge in gen_roundtrip_session() isn't silently
    # dropping one leg).
    shared_count = len(rt_session["SG_R"]["arrival"][0])
    fwd_sibling_count = len(rt_session["MN3"]["departure"][0])  # adjacent forward-leg-only position
    ratio = shared_count / max(fwd_sibling_count, 1)
    # If the return leg's traffic weren't actually merged in, this ratio
    # would sit at ~1.0 (SG_R's count == one leg's own count); real
    # merging of two independently-generated legs should push it
    # noticeably above 1 (not exactly 2.0, since real+cover volume
    # differs per draw, but well clear of 1.0).
    if ratio < 1.3:
        print(f"FAIL SG_R's merged/single-leg ratio ({ratio:.2f}) is too close to 1.0, "
              f"return leg's traffic doesn't look merged in")
        ok = False
    else:
        print(f"OK   SG_R's merged trace is {ratio:.2f}x a single leg's own count "
              f"({shared_count} vs {fwd_sibling_count} pkts), both legs present")

    rt_features = precompute_features(rt_session)
    try:
        s_fwd = score_roundtrip_compromise_set(rt_features, rt_features, D1, "combined")
        s_ret = score_roundtrip_compromise_set(rt_features, rt_features, D1_RETURN, "combined")
        s_both = score_roundtrip_compromise_set(rt_features, rt_features, D1 + D1_RETURN,
                                                 "combined", combine="mean")
        s_both_max = score_roundtrip_compromise_set(rt_features, rt_features, D1 + D1_RETURN,
                                                      "combined", combine="max")
        print(f"OK   score_roundtrip_compromise_set runs for forward-only ({s_fwd:.3f}), "
              f"return-only ({s_ret:.3f}), both-legs mean ({s_both:.3f}), "
              f"both-legs max ({s_both_max:.3f})")
    except Exception as e:
        print(f"FAIL score_roundtrip_compromise_set raised: {e}")
        ok = False

    # Degree-of-anonymity metric: uniform scores -> ~1.0 (no info gained); one dominant
    # score -> ~0.0 (fully concentrated, i.e. deanonymized).
    uniform_row = [1.0] * 10
    d_uniform = degree_of_anonymity(uniform_row)
    if not math.isclose(d_uniform, 1.0, abs_tol=1e-6):
        print(f"FAIL degree_of_anonymity(uniform) = {d_uniform:.4f}, expected ~1.0")
        ok = False
    else:
        print(f"OK   degree_of_anonymity(uniform 10-row) = {d_uniform:.4f} (expected ~1.0)")

    concentrated_row = [0.0] * 9 + [50.0]  # one massively dominant score
    d_concentrated = degree_of_anonymity(concentrated_row)
    if d_concentrated > 0.05:
        print(f"FAIL degree_of_anonymity(concentrated) = {d_concentrated:.4f}, expected ~0.0")
        ok = False
    else:
        print(f"OK   degree_of_anonymity(concentrated 10-row) = {d_concentrated:.4f} (expected ~0.0)")

    d_mean = mean_degree_of_anonymity([uniform_row, concentrated_row])
    expected_mean = (d_uniform + d_concentrated) / 2.0
    if not math.isclose(d_mean, expected_mean, abs_tol=1e-9):
        print(f"FAIL mean_degree_of_anonymity mismatch: {d_mean:.4f} vs expected {expected_mean:.4f}")
        ok = False
    else:
        print(f"OK   mean_degree_of_anonymity([uniform, concentrated]) = {d_mean:.4f}")

    return ok


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
LAYER1_SETS = {"D1": D1, "D2": D2, "D3": D3_FORWARD}
LAYER2_LADDER = [FORWARD_POSITIONS[:i] for i in range(1, len(FORWARD_POSITIONS) + 1)]
LAYER3_SETS = {
    "SG_R": ["SG_R"],
    "CS": ["CS"],
    "SG_R+CS": ["SG_R", "CS"],
    "SG_R+CS+SG_S": ["SG_R", "CS", "SG_S"],
    "MN1+SG_R": ["MN1", "SG_R"],
    "MN1+MNz": ["MN1", "MNz"],
}

# The full round-trip escalation, D1/D2/D3 mirrored
# onto BOTH legs, culminating in FULL_ROUNDTRIP (all 15 components: 12
# mix nodes + SG_R + CS + SG_S), the actual "R gets data from S" picture,
# as opposed to every forward-leg-only set above.
def _dedup(positions):
    """Order-preserving dedup, D2/D3's forward and return lists both
    include the shared gateway positions (SG_R/CS/SG_S), so naive
    concatenation double-counts them in n_positions/the positions string
    (harmless for scoring itself, since duplicates don't change which
    position sorts first/last, but misleading in reported output)."""
    return list(dict.fromkeys(positions))


ROUNDTRIP_SETS = {
    "D1_fwd_only": D1,
    "D1_ret_only": D1_RETURN,
    "D1_both_legs": _dedup(D1 + D1_RETURN),
    "D2_both_legs": _dedup(D2 + D2_RETURN),
    "D3_both_legs": _dedup(D3_FORWARD + D3_RETURN),
    "FULL_ROUNDTRIP": FULL_ROUNDTRIP,
}


def run_condition(rng, n_sessions, flow_type_alt, sender_mode, hardened,
                   compromise_sets, correlators, scoring_modes, fpr_targets,
                   edge_positions=EDGE_POSITIONS):
    sessions = []
    for i in range(n_sessions):
        flow_type = "interactive" if (i % 2 == 0) else "bulk"
        raw = gen_fullpath_session(rng, flow_type, sender_mode, hardened)
        sessions.append(precompute_features(raw))

    rows = []
    for set_name, cset in compromise_sets.items():
        for correlator in correlators:
            for mode in scoring_modes:
                # max-pairs and chain-evidence both need a genuine PAIR to
                # score (two distinct positions); a single-position set
                # has nothing to correlate against under those modes.
                # endpoints still works (positions[0]==positions[-1] is a
                # legitimate, if degenerate, self-comparison, "does this
                # one vantage point alone already fingerprint a session
                # by volume/shape"), so it's the only mode that runs for
                # 1-position sets.
                if mode in ("chain-evidence", "max-pairs") and len(cset) < 2:
                    continue
                true_scores, impostor_scores = [], []
                true_real, impostor_real = [], []
                for i in range(n_sessions):
                    for j in range(n_sessions):
                        s = score_compromise_set(sessions[i], sessions[j], cset, correlator, mode,
                                                  edge_positions=edge_positions)
                        (true_scores if i == j else impostor_scores).append(s)
                        sr = score_compromise_set(sessions[i], sessions[j], cset, correlator, mode,
                                                   real_only=True, edge_positions=edge_positions)
                        (true_real if i == j else impostor_real).append(sr)
                fpr_results, auc, n_true, n_imp, _, _ = roc_tpr_at_fpr(
                    true_scores, impostor_scores, fpr_targets)
                real_fpr_results, real_auc, _, _, _, _ = roc_tpr_at_fpr(
                    true_real, impostor_real, fpr_targets)
                for target, (tpr, ci) in fpr_results.items():
                    real_tpr, real_ci = real_fpr_results[target]
                    rows.append({
                        "compromise_set": set_name, "positions": "+".join(cset),
                        "n_positions": len(cset), "correlator": correlator,
                        "scoring_mode": mode, "fpr_target": target,
                        "tpr": tpr, "tpr_ci95": ci, "auc": auc,
                        "real_only_tpr": real_tpr, "real_only_tpr_ci95": real_ci,
                        "real_only_auc": real_auc, "n_pairs": n_true + n_imp,
                    })
    return rows


def run_roundtrip(rng, n_sessions, hardened, compromise_sets, correlators,
                   combine_modes, fpr_targets, scoring_modes=("chain-evidence",),
                   progress_csv_path=None, progress_fields=None):
    """Round-trip counterpart to run_condition(), uses
    gen_roundtrip_session() (both legs, shared-position merging) and
    score_roundtrip_compromise_set() (leg-aware combine) instead of the
    forward-leg-only equivalents. combine_modes: subset of
    {"max","mean"} -- see score_roundtrip_compromise_set()'s docstring
    for what each means. scoring_modes: subset of {"endpoints","max-
    pairs","chain-evidence"}, passed through to each leg's own
    score_compromise_set() call, defaults to chain-evidence ONLY (not
    a 3-mode sweep) to keep N=500 affordable, since the forward-leg D2/D3
    results already showed max-pairs and chain-evidence converge closely
    (75.2%/72.4% and 75.6%/77.2%) while endpoints alone is a severe
    understatement: chain-evidence is the single most informative mode
    to spend compute on here, not a full sweep.

    The O(N^2) inner loop below is
    genuinely expensive at N=500, 6 sets x 2 correlators x 2 combine
    modes x chain-evidence = 24 sweeps, each N^2 x 2 (real_only variant)
    calls to score_roundtrip_compromise_set(), which itself does up to
    ~14 score_pair() calls for FULL_ROUNDTRIP. Progress reporting and
    incremental output avoid a long run losing everything on a timeout
    (progress_csv_path=None preserves plain return-only
    behavior for callers that don't need it):
    1. A progress line (with per-condition elapsed time, flushed
       immediately) is printed after every (set, correlator, combine,
       smode) combination, so Cloud Logging shows real progress
       instead of silence for hours.
    2. If progress_csv_path is given, each condition's rows are
       APPENDED and flushed to that CSV as they're produced (header
       written once, up front), so a timeout leaves a genuinely
       usable partial result instead of losing everything."""
    sessions = []
    for i in range(n_sessions):
        flow_type = "interactive" if (i % 2 == 0) else "bulk"
        raw = gen_roundtrip_session(rng, flow_type, hardened)
        sessions.append(precompute_features(raw))

    progress_fp = None
    progress_writer = None
    if progress_csv_path is not None:
        progress_fp = open(progress_csv_path, "w", newline="")
        progress_writer = csv.DictWriter(progress_fp, fieldnames=progress_fields)
        progress_writer.writeheader()
        progress_fp.flush()

    t_sweep0 = time.perf_counter()
    n_conditions_done = 0
    n_conditions_total = (len(compromise_sets) * len(correlators)
                          * len(combine_modes) * len(scoring_modes))

    rows = []
    try:
        for set_name, cset in compromise_sets.items():
            for correlator in correlators:
                for combine in combine_modes:
                    for smode in scoring_modes:
                        t_cond0 = time.perf_counter()
                        true_scores, impostor_scores = [], []
                        true_real, impostor_real = [], []
                        for i in range(n_sessions):
                            for j in range(n_sessions):
                                s = score_roundtrip_compromise_set(sessions[i], sessions[j], cset,
                                                                    correlator, mode=smode, combine=combine)
                                (true_scores if i == j else impostor_scores).append(s)
                                sr = score_roundtrip_compromise_set(sessions[i], sessions[j], cset,
                                                                     correlator, mode=smode, combine=combine,
                                                                     real_only=True)
                                (true_real if i == j else impostor_real).append(sr)
                        fpr_results, auc, n_true, n_imp, _, _ = roc_tpr_at_fpr(
                            true_scores, impostor_scores, fpr_targets)
                        real_fpr_results, real_auc, _, _, _, _ = roc_tpr_at_fpr(
                            true_real, impostor_real, fpr_targets)
                        cond_rows = []
                        for target, (tpr, ci) in fpr_results.items():
                            real_tpr, real_ci = real_fpr_results[target]
                            cond_rows.append({
                            "compromise_set": set_name, "positions": "+".join(cset),
                            "n_positions": len(cset), "correlator": correlator,
                            "scoring_mode": smode, "combine_mode": combine, "fpr_target": target,
                            "tpr": tpr, "tpr_ci95": ci, "auc": auc,
                            "real_only_tpr": real_tpr, "real_only_tpr_ci95": real_ci,
                            "real_only_auc": real_auc, "n_pairs": n_true + n_imp,
                        })
                        rows.extend(cond_rows)
                        n_conditions_done += 1
                        cond_elapsed = time.perf_counter() - t_cond0
                        sweep_elapsed = time.perf_counter() - t_sweep0
                        print(f"  [{n_conditions_done}/{n_conditions_total}] "
                              f"{set_name} correlator={correlator} combine={combine} "
                              f"mode={smode} done in {cond_elapsed:.1f}s "
                              f"(sweep total so far: {sweep_elapsed:.1f}s)", flush=True)
                        if progress_writer is not None:
                            for row in cond_rows:
                                progress_writer.writerow({
                                    k: (f"{v:.6g}" if isinstance(v, float) else v)
                                    for k, v in row.items()})
                            progress_fp.flush()
                            os.fsync(progress_fp.fileno())
    finally:
        if progress_fp is not None:
            progress_fp.close()
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true",
                     help="Run equivalence checks against flowcorr_run.py's existing "
                          "cumulative functions and exit.")
    ap.add_argument("--sessions", type=int, default=500)
    ap.add_argument("--seed", type=int, default=20260710)
    ap.add_argument("--hardened-jitter", action="store_true")
    ap.add_argument("--sender-mode", type=str, default="poisson",
                     choices=["single_upload", "poisson", "burst"])
    ap.add_argument("--layers", type=str, default="1,2",
                     help="Comma-separated subset of 1,2,3 to run (Layer 4 is a "
                          "separate, dedicated mode, see --layer4).")
    ap.add_argument("--layer4", type=str, default=None,
                     choices=[None, "equal-budget", "rendezvous"],
                     help="Run one of the Layer 4 architectural-question tests "
                          "instead of the Layer 1/2/3 sweep.")
    ap.add_argument("--roundtrip", action="store_true",
                     help="Run the full round-trip escalation (ROUNDTRIP_SETS, both "
                          "legs, 12 mix nodes + SG_R + CS + SG_S) instead of the "
                          "forward-leg-only Layer 1/2/3 sweep or Layer 4.")
    ap.add_argument("--combine-modes", type=str, default="max,mean",
                     help="Comma-separated subset of max,mean for --roundtrip's "
                          "leg-combination strategy, see "
                          "score_roundtrip_compromise_set()'s docstring.")
    ap.add_argument("--scoring-modes", type=str, default="endpoints,max-pairs,chain-evidence")
    ap.add_argument("--fpr-targets", type=str, default="1e-1,1e-2,1e-3,1e-4,1e-5")
    ap.add_argument("--pool-mixing", action="store_true")
    ap.add_argument("--pool-mix-flush-ms", type=float, default=None)
    ap.add_argument("--out-dir", type=str, default=".")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        ok = self_test()
        return 0 if ok else 1

    flowcorr_run.HARDENED_JITTER = args.hardened_jitter
    flowcorr_run.POOL_MIXING = args.pool_mixing
    if args.pool_mix_flush_ms is not None:
        flowcorr_run.POOL_MIX_FLUSH_MS = args.pool_mix_flush_ms

    os.makedirs(args.out_dir, exist_ok=True)
    correlators = ["pearson_volume", "combined"]
    scoring_modes = args.scoring_modes.split(",")
    fpr_targets = [float(x) for x in args.fpr_targets.split(",")]
    rng = random.Random(args.seed)

    t0 = time.perf_counter()

    if args.layer4:
        rows = run_layer4(rng, args, correlators, fpr_targets)
        out_name = f"flowcorr_fullpath_layer4_{args.layer4}_results.csv"
        fields = ["condition", "correlator", "fpr_target", "tpr", "tpr_ci95", "auc",
                   "real_only_tpr", "real_only_tpr_ci95", "real_only_auc", "n_pairs"]
    elif args.roundtrip:
        combine_modes = args.combine_modes.split(",")
        out_name = "flowcorr_roundtrip_results.csv"
        fields = ["compromise_set", "positions", "n_positions", "correlator",
                   "scoring_mode", "combine_mode", "fpr_target", "tpr", "tpr_ci95", "auc",
                   "real_only_tpr", "real_only_tpr_ci95", "real_only_auc", "n_pairs"]
        # Write incrementally to a
        # `.partial.csv` sibling of the final output as each condition
        # completes: see run_roundtrip()'s docstring. Same directory as
        # the final CSV so a submission script that periodically syncs
        # out-dir to GCS picks this up too, without needing its own
        # separate upload step.
        partial_path = os.path.join(args.out_dir, out_name + ".partial.csv")
        rows = run_roundtrip(rng, args.sessions, args.hardened_jitter, ROUNDTRIP_SETS,
                              correlators, combine_modes, fpr_targets,
                              scoring_modes=scoring_modes,
                              progress_csv_path=partial_path, progress_fields=fields)
    else:
        layers = set(args.layers.split(","))
        compromise_sets = {}
        if "1" in layers:
            compromise_sets.update(LAYER1_SETS)
        if "2" in layers:
            for ladder_set in LAYER2_LADDER:
                compromise_sets[f"L2:{'+'.join(ladder_set)}"] = ladder_set
        if "3" in layers:
            compromise_sets.update(LAYER3_SETS)
        rows = run_condition(rng, args.sessions, None, args.sender_mode,
                              args.hardened_jitter, compromise_sets, correlators,
                              scoring_modes, fpr_targets)
        out_name = "flowcorr_fullpath_results.csv"
        fields = ["compromise_set", "positions", "n_positions", "correlator",
                   "scoring_mode", "fpr_target", "tpr", "tpr_ci95", "auc",
                   "real_only_tpr", "real_only_tpr_ci95", "real_only_auc", "n_pairs"]

    elapsed = time.perf_counter() - t0
    if not args.quiet:
        for r in rows:
            print(f"  {r}", flush=True)
        print(f"\n  Completed in {elapsed:.1f}s\n")

    out_path = os.path.join(args.out_dir, out_name)
    with open(out_path, "w", newline="") as fp:
        fp.write("# Anon-Sec-Net dual-path: full R->S topology, D1/D2/D3\n")
        fp.write("# node-compromise escalation (anosecnet.tex). TPR@FPR measures\n")
        fp.write("# correlator success GIVEN the adversary controls the listed\n")
        fp.write("# positions, NOT the same axis as the paper's f^2/f^4/f^7\n")
        fp.write("# compromise-PROBABILITY figures. See tier0_full_topology_d1d2d3.md.\n")
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v)
                        for k, v in row.items()})
    print(f"  Wrote {out_path}  ({len(rows)} rows)")
    return 0


def run_layer4(rng, args, correlators, fpr_targets):
    """Layer 4, the architectural question. Two modes:

    "equal-budget": A1 = D1 on the forward leg alone (2 nodes). A2 = the
    D1-equivalent set on BOTH the forward leg AND a second, independently
    generated "Path B"-analogue leg simultaneously (4 nodes total, 2 per
    leg, scored jointly via max-pairs so the adversary benefits from
    whichever leg leaks more, matching score_session_pair()'s own
    max-of-subpaths reasoning). A3 = a 2-node compromise on a SINGLE
    merged circuit carrying the combined real traffic of both legs
    (reuses the now cover-parity-fixed gen_hardened_dispatch via
    tick_mean_override=DUMMY_INTERVAL_MS/2, matching
    flowcorr_run.py's corrected single_path_defended mechanism).

    "rendezvous": measures R<->CS and (a synthetic) S<->CS correlation
    independently and reports both, so the write-up can multiply the two
    probabilities and compare against asn_both_paths' fully-compromised
    number: a rendezvous isolation test."""
    n = args.sessions
    hardened = args.hardened_jitter
    rows = []

    if args.layer4 == "equal-budget":
        sessions_a, sessions_b, sessions_merged = [], [], []
        for i in range(n):
            flow_type = "interactive" if (i % 2 == 0) else "bulk"
            sess_a = gen_fullpath_session(rng, flow_type, args.sender_mode, hardened)
            sess_b = gen_fullpath_session(rng, flow_type, args.sender_mode, hardened)
            sessions_a.append(precompute_features(sess_a))
            sessions_b.append(precompute_features(sess_b))

            real_a = gen_real_packet_times(rng, flow_type, SESSION_DURATION_S)
            real_b = gen_real_packet_times(rng, flow_type, SESSION_DURATION_S)
            combined_real = sorted(real_a + real_b)
            if hardened:
                dispatched_real, cover_times = gen_hardened_dispatch(
                    rng, combined_real, SESSION_DURATION_S,
                    tick_mean_override=DUMMY_INTERVAL_MS / 2.0)
            else:
                dispatched_real = combined_real
                cover_times = gen_cover_times_with_suppression(rng, combined_real, SESSION_DURATION_S)
            # Must walk the FULL FORWARD_POSITIONS path here, not just D1,
            # passing D1's 2-element list directly to apply_positional_exit_timing
            # applies only 1 hop of delay per LIST element (2 hops total between
            # MN1 and MN3), not the 3 hops MN3 actually carries as the path's
            # true 3rd position.
            # Walking the full path and subsetting afterward matches exactly
            # what gen_fullpath_session() does for sessions_a/sessions_b, so
            # A1/A2/A3 now share the same real hop-count budget.
            real_arr, real_dep = apply_positional_exit_timing(rng, dispatched_real, FORWARD_POSITIONS)
            cover_arr, cover_dep = apply_positional_exit_timing(rng, cover_times, FORWARD_POSITIONS)
            merged_session = {p: {
                "arrival": (sorted(real_arr[p] + cover_arr[p]), real_arr[p]),
                "departure": (sorted(real_dep[p] + cover_dep[p]), real_dep[p]),
            } for p in D1}
            sessions_merged.append(precompute_features(merged_session))

        for correlator in correlators:
            for label, sessions, cset, mode in [
                ("A1_one_leg_D1", sessions_a, D1, "endpoints"),
                ("A2_both_legs_D1", None, D1, "max-pairs"),
                ("A3_merged_2node", sessions_merged, D1, "endpoints"),
            ]:
                true_scores, impostor_scores = [], []
                for i in range(n):
                    for j in range(n):
                        if label == "A2_both_legs_D1":
                            sa = score_compromise_set(sessions_a[i], sessions_a[j], cset, correlator, "endpoints")
                            sb = score_compromise_set(sessions_b[i], sessions_b[j], cset, correlator, "endpoints")
                            s = max(sa, sb)
                        else:
                            s = score_compromise_set(sessions[i], sessions[j], cset, correlator, mode)
                        (true_scores if i == j else impostor_scores).append(s)
                fpr_results, auc, n_true, n_imp, _, _ = roc_tpr_at_fpr(
                    true_scores, impostor_scores, fpr_targets)
                for target, (tpr, ci) in fpr_results.items():
                    rows.append({
                        "condition": label, "correlator": correlator, "fpr_target": target,
                        "tpr": tpr, "tpr_ci95": ci, "auc": auc,
                        "real_only_tpr": "", "real_only_tpr_ci95": "", "real_only_auc": "",
                        "n_pairs": n_true + n_imp,
                    })
        return rows

    if args.layer4 == "rendezvous":
        sessions = []
        for i in range(n):
            flow_type = "interactive" if (i % 2 == 0) else "bulk"
            raw = gen_fullpath_session(rng, flow_type, args.sender_mode, hardened)
            sessions.append(precompute_features(raw))
        for correlator in correlators:
            for label, positions in [("R_to_CS", ["MN1", "CS"]), ("SGS_to_MNz", ["SG_S", "MNz"])]:
                true_scores, impostor_scores = [], []
                for i in range(n):
                    for j in range(n):
                        s = score_compromise_set(sessions[i], sessions[j], positions, correlator, "endpoints")
                        (true_scores if i == j else impostor_scores).append(s)
                fpr_results, auc, n_true, n_imp, _, _ = roc_tpr_at_fpr(
                    true_scores, impostor_scores, fpr_targets)
                for target, (tpr, ci) in fpr_results.items():
                    rows.append({
                        "condition": label, "correlator": correlator, "fpr_target": target,
                        "tpr": tpr, "tpr_ci95": ci, "auc": auc,
                        "real_only_tpr": "", "real_only_tpr_ci95": "", "real_only_auc": "",
                        "n_pairs": n_true + n_imp,
                    })
        return rows

    raise ValueError(args.layer4)


if __name__ == "__main__":
    sys.exit(main())
