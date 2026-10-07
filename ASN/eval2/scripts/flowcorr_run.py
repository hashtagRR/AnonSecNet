#!/usr/bin/env python3
"""
flowcorr_run.py: Task B: empirical flow-correlation attack on dual-path splitting

Measures whether ASN's dual-path split defeats end-to-end timing correlation,
versus a single-path (Tor-equivalent) baseline, as a matching problem.

WHY A SYNTHETIC GENERATOR (documented per the task spec's fallback clause)
---------------------------------------------------------------------------
The harness has no per-packet timestamped ingress/egress trace capability
(measure.h's P3 probe only counts aggregate cover/real bytes per second, not
individual packet arrival times at each hop). Driving the live C binaries for
the thousands of sessions needed for a matching-problem ROC (see below) would
also take hours over real sockets. Per the task spec's explicit fallback
("If you have no real traffic model, use a documented synthetic generator...
and state the parameters"), this script generates synthetic per-session
event traces using the REAL measured/configured parameters from this
codebase:
  - WIRE_PACKET_SIZE = 1024 bytes fixed (common/config.h), both ASN and the
    Tor-equivalent baseline carry fixed-size cells here, so only TIMING
    carries a correlation signal, not packet size.
  - DUMMY_INTERVAL_MS = 100 (common/config.h): ASN cover traffic is a Poisson
    process with this mean inter-packet interval.
  - Real per-hop crypto cost ~5.0us (results/figure2_perhop_latency_dev_workstation.csv) is
    negligible next to network jitter and is folded into a per-hop latency
    jitter term (see PER_HOP_JITTER_MS below); it does not materially affect
    a timing-correlation attack at millisecond granularity.
  - Cover-suppression logic matches client.c's outbound_cover_thread exactly:
    one real packet suppresses exactly one subsequent cover slot (one-for-one
    credit counter), not a hard on/off switch.

THE ACTUAL ASN SPLITTING POLICY (documented, per the task spec's instruction
to match whatever the implementation actually does rather than assume a
50/50 per-packet round-robin split)
---------------------------------------------------------------------------
Reading client.c/mix_node.c: Anon-Sec-Net does NOT split a single flow's
packets round-robin across path A and path B. Path A carries the ENTIRE
outbound direction (Receiver -> SG); path B carries the ENTIRE inbound
direction (SG -> Receiver). This is a direction split, not a per-packet
volume split. Consequently the three conditions evaluated here are:

  single_path     : Tor-equivalent. One 3-hop circuit carries BOTH
                     directions. Adversary controls guard (entry) + exit,
                     sees the full bidirectional flow at both ends. No cover
                     traffic (per spec).
  asn_one_path    : Adversary controls the Receiver-facing and SG-facing
                     mix node of ONE of the two paths (e.g. MN1 + MN3), so
                     it sees only ONE direction of the flow, this is the
                     realistic partial-observation case for ASN.
  asn_both_paths  : Adversary controls both ends of BOTH paths (4 distinct
                     mix-node identities: MN1, MN3, MNa, MNc) and so sees
                     both directions, the upper-bound case, structurally
                     comparable to what single_path's 2-node adversary gets
                     "for free," but here costing the adversary twice as
                     many compromised positions.

Cover traffic travels every hop of both paths, forward and return,
indistinguishably from real traffic, dropped only at its final
destination (SG for path A, the Receiver for path B) via a flag
encrypted end-to-end, unreadable by any mix node. Both entry and exit
see a real+cover mixture on every condition/path below.

CORRELATORS
---------------------------------------------------------------------------
Both are the "weakest -> strongest" statistical baseline the spec asks for
(no learned/CNN correlator, the spec explicitly allows skipping that
stretch goal). Both bin each observed event stream into fixed-width time
bins over the observation window and build two feature vectors per stream:
  volume[i]  = packet count in bin i
  timing[i]  = mean inter-packet interval within bin i (bin width if empty)
  pearson_volume : Pearson correlation of the two streams' volume vectors
                    only (weakest, single feature).
  combined       : mean of {Pearson(volume), cosine(volume), Pearson(timing),
                    cosine(timing)} (stronger, uses both timing and volume).

EVALUATION
---------------------------------------------------------------------------
Standard matching-problem setup: N sessions per condition, N true
(entry,exit) pairs from the same session, N*(N-1) impostor pairs (entry of
session i against exit of session j, i!=j). ROC swept over the correlator
score threshold; TPR reported at fixed FPR in {1e-1, 1e-2, 1e-3}, plus AUC.
Wilson-score 95% CI on TPR (n = N true pairs, matching montecarlo_figure4.py
convention).

Usage:
    python flowcorr_run.py [--sessions 200] [--seed 20260710] [--out-dir .]
"""

import argparse
import csv
import math
import os
import random
import sys
import time

import numpy as np

# ---------------------------------------------------------------------------
# Parameters (documented, drawn from the real implementation where possible)
# ---------------------------------------------------------------------------
DUMMY_INTERVAL_MS   = 100.0     # common/config.h DUMMY_INTERVAL_MS (ASN cover mean interval)
SESSION_DURATION_S  = 20.0      # observation window per session
BIN_WIDTH_MS        = 500.0     # correlator bin width
PER_HOP_JITTER_MS   = (1.0, 0.4)  # (mean, std) added latency per mix hop, Gaussian, floor 0
N_HOPS_PATH         = 3          # hops per path (both ASN paths and the Tor-equivalent circuit)

# ASN_LOOPIX_MIXING hardened build. Set HARDENED_JITTER=True (via
# --hardened-jitter, or by setting this module attribute directly before
# calling gen_session) to switch on TWO distinct mechanisms, both gated by
# this one flag since they're both build-time consequences of the same
# ASN_LOOPIX_MIXING flag in the real code:
#   1. Per-hop mixing delay (hop_delay_sample()) on top of
#      PER_HOP_JITTER_MS: the exact common/config.h constants and draw
#      formula mix_node.c::mix_delay_sleep() uses (inverse-CDF
#      exponential, capped), an analytical match to the real RNG, not a
#      Gaussian fit to noisy empirical proxy data (Figure 3's
#      session-setup measurement exercises a different code path,
#      ECDHE handshakes, not DATA/RETURN forwarding, so it isn't a
#      faithful source for this specific per-hop number).
#   2. Shared-clock, bounded-aggregate-rate dispatch, see
#      gen_hardened_dispatch(), ported from coverleak_run.py's
#      gen_hardened_shared_clock(): in place of the legacy one-for-one
#      credit-suppression cover model, for path A (client.c/sender.c's
#      real mailbox mechanism) and the single_path_cover ablation.
# Both are applied ONLY to ASN's own conditions/sub-paths (asn_one_path,
# asn_both_paths' path A, single_path_cover), never to single_path
# (Tor-equivalent), which does not run ASN_LOOPIX_MIXING, and never to
# path B's dispatch specifically (mechanism 2 only, see asn_both_paths'
# own comment for why path B's SG-side dispatch isn't actually
# rate-bounded in the real implementation, hardened build or not).
HARDENED_JITTER     = False
MIX_DELAY_MEAN_MS   = 50.0    # common/config.h MIX_DELAY_MEAN_MS
MIX_DELAY_MAX_MS    = 500.0   # common/config.h MIX_DELAY_MAX_MS

# Path A's and Path B's cover-tick
# generation currently draw from a single shared rng object passed into
# gen_session(), sequentially (Path A's draws, then Path B's). That's not
# literally correlated by protocol design, but not proven independent
# either: there is exactly one entropy source per session driving both
# paths. Default False preserves that exact existing behavior (shared
# rng, byte-identical output to every previously-published number).
# --independent-path-rng forks Path B onto its own random.Random instance,
# reproducibly seeded from a single draw off the shared stream (so the
# whole run stays deterministic under --seed) but statistically
# independent of Path A's subsequent draws from that point on. Only
# affects asn_both_paths (the only condition with two real cover-bearing
# sub-paths to decorrelate), asn_both_paths_no_cover has no cover
# generation step to correlate.
INDEPENDENT_PATH_RNG = False

# Path A's dispatch is rate-bounded
# under --hardened-jitter (gen_hardened_dispatch, the shared-clock
# mailbox); Path B's is NOT, by design, see the matching comment on
# asn_both_paths below (service_gateway.c's response dispatch fires
# immediately, uncapped, hardened build or not; only the per-hop mixing
# delay applies to it). Default False preserves that exact real
# asymmetry (byte-identical to every previously-published number).
# --symmetric-dispatch is an ABLATION CONTROL, not a claim about the real
# implementation: when set (and --hardened-jitter is also set), Path B is
# forced through the same gen_hardened_dispatch queueing Path A gets, to
# measure whether the real asymmetry matters to a joint adversary. No
# effect when --hardened-jitter is off (there is no dispatch mechanism to
# force symmetric in the legacy build).
SYMMETRIC_DISPATCH = False

# --hardened-jitter currently gates BOTH the dispatch mechanism (mailbox/
# queueing vs. legacy immediate-send) AND whether hop_delay_sample()'s
# exponential mixing-delay term fires, there is no way to add the
# exponential delay to LEGACY (immediate) dispatch, so a true 2x2
# (dispatch mechanism x delay-or-not) isn't expressible with just
# --hardened-jitter/--mix-delay-mean-ms: a "legacy + 50ms delay" test case
# silently no-ops today for exactly this reason. --legacy-mix-delay decouples
# them: it adds the exponential term (hardened=True passed to jitter
# calls) WITHOUT switching to hardened dispatch (dispatch-mechanism
# selection is untouched, still gated on HARDENED_JITTER alone). No
# effect when HARDENED_JITTER is already True (already gets both). Only
# wired into asn_one_path/asn_both_paths, NOT single_path_cover, whose
# own --hardened-jitter behavior is a deliberately coupled, different
# design choice (see that branch's own comment) and shouldn't be
# reinterpreted by this flag.
LEGACY_MIX_DELAY = False

# Genuine batch/pool mixing (ASN_POOL_MIXING, see apply_pool_mixing()
# below), a real, already-implemented alternative to per-packet delay,
# previously only modeled in flowcorr_hopdecoy_ml.py (hardcoded
# POOL_MIX_FLUSH_MS=250, no sweep, no real-only diagnostic, only wired to
# the hop-decoy conditions). Wired here directly into
# asn_one_path/asn_both_paths (same scope as LEGACY_MIX_DELAY, not
# single_path_cover) so it gets the full existing TPR@FPR + real-only
# pipeline and a sweepable flush interval, matching every other timing
# mechanism measured here. POOL_MIXING and HARDENED_JITTER/LEGACY_MIX_DELAY are
# mutually exclusive alternatives for the hop-traversal step (both
# operate on the same already-dispatched real/cover times to produce the
# exit-side observation), if POOL_MIXING is set it takes precedence,
# matching production's own framing of these as separate, not stacked,
# mechanisms.
POOL_MIXING = False
POOL_MIX_FLUSH_MS = 250.0    # mix_node.c's POOL_MIX_FLUSH_MS, post-fix value

# Danezis-style continuous-time pool mixing, HYPOTHETICAL, see
# apply_danezis_pool_mixing()'s docstring. Distinct from POOL_MIXING
# above (which is ASN's actual deterministic whole-window-release
# mechanism), this is a genuinely different, probabilistic-per-round
# release discipline with no equivalent in ASN's C code. Same precedence
# tier as POOL_MIXING/THRESHOLD_BATCH_SIZE in apply_exit_timing (a
# mutually-exclusive alternative to jitter, not stacked); POOL_MIXING
# takes precedence if both are set. 0.0 default (via
# DANEZIS_POOL_MIXING=False) is byte-identical to prior numbers.
DANEZIS_POOL_MIXING = False
DANEZIS_ROUND_MS = 100.0        # round interval; no production analogue to anchor a default to
DANEZIS_RELEASE_PROB = 0.3      # per-round release probability; mean sojourn = round_ms/release_prob

# Asymmetric per-path delay distributions, Path B's exponential
# mixing-delay MEAN can now differ from Path A's (MIX_DELAY_MEAN_MS),
# while keeping the same distribution family (exponential). None
# (default) means Path B uses the same MIX_DELAY_MEAN_MS as Path A,
# byte-identical to prior numbers. Only takes effect under
# --hardened-jitter/--legacy-mix-delay (the exponential term's own
# gating, unchanged), has no effect under --pool-mixing/
# --danezis-pool-mixing/--threshold-batch-size, which don't use this
# term at all.
MIX_DELAY_MEAN_MS_B = None

# Asymmetric per-path cover rate, HYPOTHETICAL, no equivalent in
# ASN's C code (both paths' cover
# generation uses the same DUMMY_INTERVAL_MS constant). Lets Path B's
# cover-tick mean differ from Path A's/the module default, mirroring
# MIX_DELAY_MEAN_MS_B's pattern above but for cover rate instead of
# mixing delay. None (default) = off, byte-identical to prior numbers.
# Only wired onto asn_both_paths' Path B call to gen_cover_times_with_
# suppression() (the plain/non-hardened cover generator), deliberately
# NOT threaded into gen_hardened_dispatch(), which conflates the cover
# fill rate with the dispatch tick rate itself; overriding one without
# the other there would silently also change Path B's effective
# dispatch throughput, a different and confounding effect. The design
# rationale against per-client randomised cover rate, "inverts the
# defence... a stable per-client rate is a direct fingerprint", motivates
# this test: it measures whether a PATH-level (not per-client) rate
# asymmetry has the same danger.
COVER_RATE_MEAN_MS_B = None

# Standalone reorder window, HYPOTHETICAL, no equivalent mechanism exists in ASN's C code
# (see apply_reorder_window()'s docstring for the exact scope and its
# real/cover-separate simplification). 0.0 = off, byte-identical to
# every previously-published number. Combinable with hop-jitter or
# pool-mixing (applied as a post-step in apply_exit_timing), unlike
# POOL_MIXING which replaces jitter rather than stacking with it.
REORDER_WINDOW_MS = 0.0

# Threshold/hybrid batching, HYPOTHETICAL, no packet-count-triggered release exists in
# ASN's C code (see apply_threshold_batching()'s docstring). 0 = off,
# byte-identical to every previously-published number. Same precedence
# tier as POOL_MIXING in apply_exit_timing (a genuine alternative to
# jitter/pool-mixing for the hop-traversal step, not stacked with them);
# if both POOL_MIXING and THRESHOLD_BATCH_SIZE are set, pool mixing
# takes precedence (checked first in apply_exit_timing).
THRESHOLD_BATCH_SIZE = 0
THRESHOLD_BATCH_TIMEOUT_MS = 0.0   # >0 makes this hybrid (threshold OR timeout)

# Probabilistic cover-drop dispatch, HYPOTHETICAL, see
# gen_cover_drop_dispatch()'s docstring for the full "no code
# equivalent" verification and the two
# variants. 0.0 = off, byte-identical to every previously-published
# number. Unlike the hop-traversal-step mechanisms above (pool mixing,
# threshold batching, reorder window), this REPLACES the dispatch
# mechanism itself (takes precedence over --hardened-jitter's
# gen_hardened_dispatch and the legacy credit-suppression path when set);
# the hop-traversal step (jitter/pool-mixing/threshold-batching) still
# applies on top afterward, unchanged, same layering as always.
COVER_DROP_PROB = 0.0
COVER_DROP_WORK_CONSERVING = False

# Packet-level striping: TrafficSliver-style secret
# per-packet path assignment, replacing ASN's current strict directional
# split (Path A = 100% outbound, Path B = 100% inbound) with a
# probabilistic one. See split_by_ratio()'s docstring. 1.0 (default) =
# fully directional, byte-identical to every previously-published
# asn_both_paths number. 0.5 = fully mixed/striped (fair coin-flip per
# packet regardless of direction). Only affects asn_both_paths (the only
# condition with two physical paths to stripe across). The existing
# max-of-subpaths scoring in score_session_pair() already represents the
# JOINT (both-paths) adversary correctly under striping with no further
# changes: striping's claimed protection is specifically against a
# SINGLE-VANTAGE adversary (sees only one physical path), which needs a
# separate single-subpath (not max) scoring pass, not yet built (see
# tier3_striping_scope.md for the precise, small addition needed).
SPLIT_RATIO = 1.0

# Interactive flow: short, bursty, Poisson arrivals (e.g. web/API traffic)
INTERACTIVE_MEAN_IPI_MS = (150.0, 400.0)   # sampled uniformly per-session mean inter-packet interval
# Bulk flow: large, sustained fill (e.g. file transfer)
BULK_MEAN_IPI_MS        = (8.0, 25.0)


# ---------------------------------------------------------------------------
# Wilson-score CI (matches montecarlo_figure4.py convention)
# ---------------------------------------------------------------------------
def ci95_proportion(k: int, n: int) -> float:
    if n == 0:
        return 0.0
    z = 1.959964
    p = k / n
    denom = 1 + z * z / n
    spread = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return spread


# ---------------------------------------------------------------------------
# Flow generation
# ---------------------------------------------------------------------------
def gen_real_packet_times(rng: random.Random, flow_type: str, duration_s: float):
    """Poisson-process real packet arrival times (ms) over [0, duration_s*1000)."""
    if flow_type == "interactive":
        mean_ipi = rng.uniform(*INTERACTIVE_MEAN_IPI_MS)
    else:
        mean_ipi = rng.uniform(*BULK_MEAN_IPI_MS)
    times = []
    t = 0.0
    horizon = duration_s * 1000.0
    while t < horizon:
        t += rng.expovariate(1.0 / mean_ipi)
        if t < horizon:
            times.append(t)
    return times


def _cover_tick_ms(rng: random.Random, mean_override: float = None) -> float:
    """One inter-tick interval for the DUMMY_INTERVAL_MS Poisson cover
    clock, clamped to [10,1000]ms to match poisson_interval_ms() in
    client.c/sender.c/client_instrumented.c/mix_node.c exactly.

    `mean_override`: use this mean instead of the module-level
    DUMMY_INTERVAL_MS: lets
    Path B draw cover ticks from a different mean rate than Path A's,
    same distribution family, mirroring hop_delay_sample()'s
    mean_override pattern for the mixing delay. None (default)
    preserves exact prior behavior."""
    mean = mean_override if mean_override is not None else DUMMY_INTERVAL_MS
    iv = rng.expovariate(1.0 / mean)
    if iv < 10.0:
        iv = 10.0
    if iv > 1000.0:
        iv = 1000.0
    return iv


def gen_cover_times_with_suppression(rng: random.Random, real_times, duration_s: float,
                                      mean_override: float = None):
    """Reproduces client.c::outbound_cover_thread's one-for-one suppression:
    a Poisson-scheduled cover tick is skipped if a real-packet 'credit' is
    outstanding (one real packet consumes exactly one subsequent cover
    slot); otherwise a cover packet is emitted at that tick.

    `mean_override`: see _cover_tick_ms()'s docstring, None (default)
    preserves exact prior behavior."""
    horizon = duration_s * 1000.0
    credits = 0
    real_iter = iter(sorted(real_times))
    next_real = next(real_iter, None)
    cover_times = []
    t = 0.0
    while t < horizon:
        t += _cover_tick_ms(rng, mean_override)
        if t >= horizon:
            break
        while next_real is not None and next_real <= t:
            credits += 1
            next_real = next(real_iter, None)
        if credits > 0:
            credits -= 1   # suppress this cover slot
        else:
            cover_times.append(t)
    return cover_times


QUEUE_DEPTH_HARDENED = 63   # matches coverleak_run.py's constant of the same
                            # name: client_instrumented.c's pq_free()
                            # reserves one ring-buffer sentinel slot, so
                            # usable capacity is PKT_QUEUE_DEPTH(64)-1.


def gen_hardened_dispatch(rng: random.Random, real_arrival_times, duration_s: float,
                           tick_mean_override: float = None):
    """The ASN_LOOPIX_MIXING shared-clock
    dispatch mechanism, ported from coverleak_run.py's
    gen_hardened_shared_clock() (see that function's docstring for why
    an independent-cover-clock model leaks more than no mitigation
    at all).

    Unlike gen_hardened_shared_clock(), which generates real arrivals
    itself from a load_level/R_MAX_PPS rate (Task C's parametrization),
    this takes an already-generated real_arrival_times list (this file's
    own flow_type-based interactive/bulk generator, gen_real_packet_times())
    and feeds it through the SAME queue+dispatch discipline: one shared
    Poisson clock at COVER_CEILING_PPS-equivalent mean (DUMMY_INTERVAL_MS,
    identical to _cover_tick_ms above), draining a bounded real-packet
    queue preferentially and only sending cover when the queue is empty.
    This bounds AGGREGATE observable rate at the dispatch clock's rate
    regardless of the underlying flow's demand, the actual mechanism
    the anonymity-set claim depends on, NOT merely added
    propagation jitter (see HARDENED_JITTER/hop_delay_sample() above,
    which models a DIFFERENT, weaker effect and was the only thing
    --hardened-jitter applied before this function existed).

    Returns (dispatched_real_times, cover_times): dispatched_real_times
    are the actual SEND times after queueing delay (not
    real_arrival_times verbatim, a real packet is only observable once
    it clears the queue at a dispatch tick), cover_times fill every tick
    where the queue was empty.

    `tick_mean_override`: use this mean instead of the module-level
    DUMMY_INTERVAL_MS for the dispatch clock. single_path_defended merges
    two paths' real traffic into one stream and feeds it through ONE
    gen_hardened_dispatch() call, but the
    split design runs TWO INDEPENDENT dispatch clocks (one per path),
    each generating cover only when ITS OWN queue is empty. With ~2x
    the real-packet density and only 1x the tick rate, the merged
    queue is almost never empty, confirmed empirically: the split
    design generated 189 cover packets across both paths in one test
    seed, the naive merged version generated exactly 1. Doubling the
    dispatch clock's rate (tick_mean_override=DUMMY_INTERVAL_MS/2) for
    the merged single-circuit condition restores comparable aggregate
    dispatch capacity/cover volume to what two independent per-path
    clocks would produce, this is what makes the comparison
    apples-to-apples rather than confounded. None (default) preserves
    exact prior behavior for every existing caller."""
    horizon = duration_s * 1000.0
    real_sorted = sorted(real_arrival_times)
    arrivals = iter(real_sorted)
    next_arrival = next(arrivals, None)

    queue_depth = 0
    dispatched_real, cover_times, t = [], [], 0.0
    while t < horizon:
        t += _cover_tick_ms(rng, tick_mean_override)
        if t >= horizon:
            break
        while next_arrival is not None and next_arrival <= t:
            if queue_depth < QUEUE_DEPTH_HARDENED:
                queue_depth += 1
            next_arrival = next(arrivals, None)
        if queue_depth > 0:
            queue_depth -= 1
            dispatched_real.append(t)
        else:
            cover_times.append(t)
    return dispatched_real, cover_times


def hop_delay_sample(rng: random.Random, hardened: bool, mean_override: float = None) -> float:
    """One hop's added latency: crypto-only Gaussian jitter, plus (if
    hardened) the ASN_LOOPIX_MIXING per-hop mixing delay drawn from the
    exact same formula as mix_node.c::mix_delay_sleep().

    `hardened` is passed explicitly per call site (not read from the
    module-level HARDENED_JITTER flag directly): ASN_LOOPIX_MIXING is
    an ASN-only build flag; the single_path
    (Tor-equivalent) baseline never runs it and must not get ASN's mixing
    delay applied just because --hardened-jitter was passed for the ASN
    conditions in the same run. See gen_session()'s per-condition calls.

    `mean_override`: use this mean
    instead of the module-level MIX_DELAY_MEAN_MS, lets Path B draw
    from a different exponential mean than Path A (asymmetric per-path
    delay, MIX_DELAY_MEAN_MS_B), same distribution family, different
    parameter, without touching the global every other call site reads.
    None (default) preserves exact prior behavior."""
    mean, std = PER_HOP_JITTER_MS
    delay = max(0.0, rng.gauss(mean, std))
    if hardened:
        u = rng.random()
        while u <= 0.0:
            u = rng.random()
        mix_mean = mean_override if mean_override is not None else MIX_DELAY_MEAN_MS
        mix = -mix_mean * math.log(u)
        if mix > MIX_DELAY_MAX_MS:
            mix = MIX_DELAY_MAX_MS
        delay += mix
    return delay


def gen_cover_drop_dispatch(rng: random.Random, real_arrival_times, duration_s: float,
                             drop_prob: float, work_conserving: bool):
    """Probabilistic cover-drop mechanism, HYPOTHETICAL, NO CODE
    EQUIVALENT. Verified absent from client.c/mix_node.c (grep for
    drop_prob/DROP_PROB/p_drop: zero matches), ASN's actual cover-drop
    behavior is deterministic, not probabilistic (cover travels every
    hop, dropped only at final destination via an encrypted flag). This
    explores a DIFFERENT, redesigned mechanism: what if intermediate
    hops could probabilistically drop cover in transit? Two variants;
    build work-conserving first, since deletion-only can only ever
    reproduce the classifier-confusion
    result already demonstrated by single_path_cover.

    Unlike gen_hardened_dispatch() (which gives real ABSOLUTE priority
    over cover at every tick, so cover never sits queued "ahead of" a
    real packet in the first place, structurally unable to represent
    "dropping cover lets the real packet behind it advance"), this uses
    a strict FIFO queue: real and cover packets (cover on its own
    independent Poisson process, same mean rate as the existing cover
    tick) are merged in arrival order and dispatched one per tick in
    that same order, so a cover packet CAN sit ahead of a queued real
    packet.

    drop_prob: probability a cover packet, once it reaches the head of
    the FIFO queue, is dropped instead of dispatched.
    work_conserving:
      False (deletion-only, Variant A): a dropped cover packet's slot is
        simply wasted, the dispatch clock still advances one tick per
        loop iteration exactly as if nothing were dropped, so a real
        packet behind it in the FIFO is COMPLETELY unaffected, still
        waiting for its own natural tick. Real timing is provably
        unperturbed by this variant, by construction.
      True (work-conserving, Variant B): a dropped cover packet's slot
        is NOT wasted, the queue head is re-checked immediately at the
        SAME tick instead of waiting for the next one, so a real packet
        directly behind a dropped cover in the FIFO dispatches AT THAT
        SAME tick, advanced from whatever later tick it would otherwise
        have waited for.

    Returns (dispatched_real, cover_times), matching gen_hardened_dispatch's
    return shape so it drops into gen_session()'s existing call pattern.

    Real packets must never be lost, only cover may ever be dropped
    (Variant A's docstring above promises "Real timing is provably
    unperturbed by this variant, by construction"). To guarantee that,
    each cover packet's drop_prob outcome is decided AT GENERATION TIME
    instead of at dispatch time: generating cover as an independent
    full-rate Poisson process and thinning only at the FIFO head would
    make combined (real+cover) admission exceed the single dispatch
    clock's throughput for any real traffic, an unstable queue whose
    backlog grows across the session. By the Poisson-thinning theorem,
    independently keeping each point of a Poisson process with
    probability (1-drop_prob) produces a Poisson process at rate
    cover_rate*(1-drop_prob), i.e. the distribution of SURVIVING cover
    is identical to before. The difference: a DROPPED cover packet now
    never occupies a FIFO slot at all, so only real + surviving cover
    ever contend for dispatch ticks (rho = real_rate +
    cover_rate*(1-drop_prob), comfortably stable at the drop_prob=0.5/0.9
    operating points tested here), real packets are
    structurally guaranteed to always reach the front and dispatch,
    never capacity- or horizon-bound. Variant A (deletion-only) now
    matches its docstring exactly: a dropped cover packet leaves no
    trace and touches nothing, real timing is unperturbed by construction.
    Variant B (work-conserving) is reinterpreted as: at the moment a
    cover packet WOULD have arrived and been dropped, if a packet is
    already queued waiting for its natural tick, dispatch it right then
    instead: the "packet behind the dropped cover advances" effect,
    without ever admitting the dropped cover as queue dead-weight."""
    horizon = duration_s * 1000.0
    surviving_cover, dropped_cover = [], []
    tc = 0.0
    while tc < horizon:
        tc += _cover_tick_ms(rng)
        if tc >= horizon:
            break
        if rng.random() < drop_prob:
            dropped_cover.append(tc)
        else:
            surviving_cover.append(tc)

    timeline = sorted([(t, "real") for t in real_arrival_times] +
                       [(t, "cover") for t in surviving_cover] +
                       [(t, "dropped") for t in dropped_cover])
    dispatched_real, cover_times = [], []
    t = 0.0
    ti = 0
    queue = []   # FIFO of ("real"|"cover", arrival_t), only real/surviving-cover ever enter
    while t < horizon and (ti < len(timeline) or queue):
        t += _cover_tick_ms(rng)
        if t >= horizon:
            break
        while ti < len(timeline) and timeline[ti][0] <= t:
            arrival_t, kind = timeline[ti]
            ti += 1
            if kind == "dropped":
                if work_conserving and queue:
                    _, head_kind = queue.pop(0)
                    if head_kind == "real":
                        dispatched_real.append(arrival_t)
                    else:
                        cover_times.append(arrival_t)
                # else (deletion-only, or nothing waiting): no trace, no effect
                continue
            queue.append((arrival_t, kind))
        if queue and queue[0][0] <= t:
            _, kind = queue.pop(0)
            if kind == "real":
                dispatched_real.append(t)
            else:
                cover_times.append(t)
    return sorted(dispatched_real), sorted(cover_times)


def apply_hop_jitter(rng: random.Random, times, n_hops: int, hardened: bool = False,
                      mean_override: float = None):
    """Add cumulative per-hop forwarding latency + jitter to a list of
    entry-side timestamps to model the corresponding exit-side observation.
    `hardened`, see hop_delay_sample()'s comment; defaults to False so
    existing call sites that don't pass it explicitly are unaffected.
    `mean_override`, see hop_delay_sample()'s comment; None (default)
    preserves exact prior behavior."""
    out = []
    for t in times:
        delay = sum(hop_delay_sample(rng, hardened, mean_override) for _ in range(n_hops))
        out.append(t + delay)
    return out


def apply_pool_mixing(rng: random.Random, times, n_hops: int):
    """Genuine batch/pool mixing (ASN_POOL_MIXING, mix_node.c's
    stratified-shuffle version), ported from flowcorr_hopdecoy_ml.py's
    apply_pool_mixing(): SAME mechanism, generalized to take n_hops and
    read POOL_MIX_FLUSH_MS as a module-level sweepable global instead of
    a hardcoded constant, so it plugs into gen_session()'s existing
    per-condition call sites as a genuine alternative to apply_hop_jitter
    (not stacked with it, per-packet delay vs pool mixing are
    independent, alternative mechanisms, tested separately as well as
    together with hop-decoy).

    At each intermediate hop, a packet arriving at time t is captured
    into whichever POOL_MIX_FLUSH_MS-wide window it falls in, then
    released at a uniformly random point within that SAME window's
    dispatch: batching changes HOW MANY packets land in a given
    correlator bin, not just WHEN within a bin a packet lands (which is
    all apply_hop_jitter's per-packet delay does). Applied once per
    intermediate hop, compounding exactly like the real mechanism."""
    out = []
    for t in times:
        cur = t
        for _ in range(n_hops):
            cur += max(0.0, rng.gauss(*PER_HOP_JITTER_MS))  # propagation/crypto jitter, same as always
            bucket_release = (math.floor(cur / POOL_MIX_FLUSH_MS) + 1) * POOL_MIX_FLUSH_MS
            cur = bucket_release + rng.uniform(0.0, POOL_MIX_FLUSH_MS)
        out.append(cur)
    return out


def apply_danezis_pool_mixing(rng: random.Random, times, n_hops: int,
                               round_ms: float, release_prob: float):
    """Danezis-style
    continuous-time pool mixing, HYPOTHETICAL, no equivalent exists in
    ASN's C code. Genuinely different from apply_pool_mixing() above:
    that function deterministically releases EVERY packet in a window at
    the window's own boundary (bounded sojourn time, at most
    POOL_MIX_FLUSH_MS). Here, a packet entering the pool is released at
    the FIRST round boundary only with probability `release_prob`; if
    not selected, it stays in the pool and is independently re-rolled at
    every subsequent round_ms boundary until it is released, sojourn
    time is geometrically distributed (mean round_ms/release_prob), not
    bounded by a single window width. This is the mechanism a "pool mix
    releases a random subset each round" description refers to,
    distinct from mix_node.c's actual whole-window-release pool mixing.

    Modelled per-packet independently (each packet's own release-round
    draw is independent of what else is notionally in the pool at the
    same time), a standard simplifying assumption for this class of
    mix, since round-to-round release decisions are i.i.d. Bernoulli(p)
    regardless of pool occupancy in the canonical continuous-time pool
    mix formulation this models."""
    out = []
    for t in times:
        cur = t
        for _ in range(n_hops):
            cur += max(0.0, rng.gauss(*PER_HOP_JITTER_MS))
            release_round = math.ceil(cur / round_ms) * round_ms
            while rng.random() >= release_prob:
                release_round += round_ms
            cur = release_round
        out.append(cur)
    return out


def apply_reorder_window(rng: random.Random, times, window_ms: float):
    """A standalone
    packet-reordering window, HYPOTHETICAL, no equivalent mechanism or
    build flag exists in ASN's C code (verified absent, same epistemic
    status as Ask D's cover-drop exploration; see TEST_MATRIX_DESIGN.md).
    Groups already-computed exit-side timestamps into non-overlapping
    window_ms-wide buckets and reassigns each an independent uniform-
    random time within that SAME bucket, same packets, same per-window
    volume (a volume-only correlator sees zero effect from this alone),
    but fine-grained inter-packet order/timing within a window is
    scrambled. Combinable with (applied on top of, not instead of)
    apply_exit_timing's hop-jitter/pool-mixing mechanisms, unlike
    POOL_MIXING which is a genuine alternative to jitter.

    KNOWN SIMPLIFICATION, not silently glossed over: this is applied to
    the real-only and cover-only sub-lists SEPARATELY (same split-call
    pattern the rest of gen_session() uses for the real-only diagnostic),
    so real packets are reordered only among themselves within a window
    and cover packets only among themselves, NOT jointly mixed across
    the real/cover boundary the way a real reordering buffer would
    reorder whatever packets happen to be sitting in it regardless of
    type. A joint version would need restructuring the real/cover-tagged
    concatenation-then-split pattern used throughout this file; scoped
    out for now as a possible refinement, not built here."""
    if window_ms <= 0 or not times:
        return list(times)
    out = []
    for t in times:
        bucket_start = math.floor(t / window_ms) * window_ms
        out.append(bucket_start + rng.uniform(0.0, window_ms))
    return out


def apply_threshold_batching(times, batch_size: int, timeout_ms: float = 0.0):
    """Threshold (and
    optionally hybrid threshold-OR-timeout) batching, HYPOTHETICAL, no
    equivalent mechanism exists in ASN's C code (pool mixing, the only
    real batching mechanism, is time-window-only; see POOL_MIXING's
    docstring: there is no packet-count trigger anywhere). A genuine
    alternative to jitter/pool-mixing for the hop-traversal step, not
    stacked with them (same precedence tier as POOL_MIXING in
    apply_exit_timing). Deterministic (no rng draws), all K packets in
    a completed batch are released simultaneously at the triggering
    packet's own arrival time, matching "released as a batch" literally
    (compare pool-mixing's within-window RANDOM release, a different,
    softer perturbation already covering that shape).

    batch_size: release once this many packets have accumulated.
    timeout_ms: if >0, ALSO release early once this much time has
    elapsed since the current batch's first packet, even if batch_size
    hasn't been reached (hybrid mode); 0 (default) = pure threshold,
    no timeout escape, a batch can wait arbitrarily long for its
    (batch_size-1) remaining slots to fill in a sparse trace."""
    sorted_times = sorted(times)
    out = []
    batch = []
    batch_start = None
    for t in sorted_times:
        if not batch:
            batch_start = t
        batch.append(t)
        hit_threshold = len(batch) >= batch_size
        hit_timeout = timeout_ms > 0 and (t - batch_start) >= timeout_ms
        if hit_threshold or hit_timeout:
            out.extend([t] * len(batch))
            batch = []
    if batch:
        out.extend([batch[-1]] * len(batch))   # flush any incomplete trailing batch
    return out


def split_by_ratio(rng: random.Random, times, ratio: float):
    """Packet-level striping: independently assigns each packet in `times` to its "home" path
    (probability `ratio`) or the "other" path (probability `1-ratio`).
    ratio=1.0 -> every packet stays home (today's fully-directional
    asn_both_paths, byte-identical). ratio=0.5 -> a fair coin-flip per
    packet, fully mixed/striped (TrafficSliver-style). Returns
    (home_times, away_times)."""
    home, away = [], []
    for t in times:
        (home if rng.random() < ratio else away).append(t)
    return home, away


def apply_exit_timing(rng: random.Random, times, n_hops: int, mean_override: float = None):
    """Dispatches to whichever hop-traversal timing mechanism is active
    for asn_one_path/asn_both_paths this run: pool mixing takes
    precedence if --pool-mixing is set (see POOL_MIXING's module-level
    docstring for why these are alternatives, not stacked), then
    Danezis-style pool mixing if --danezis-pool-mixing is set, then
    threshold batching, else the existing per-packet jitter path
    (--hardened-jitter/--legacy-mix-delay). Default (none set) is
    byte-identical to the plain apply_hop_jitter call every previously-
    published number used.

    `mean_override`: only affects the
    plain jitter path (the exponential mixing-delay term), passed as
    MIX_DELAY_MEAN_MS_B for Path B's asn_both_paths calls when set, to
    give Path B a different delay mean than Path A. Has no effect on
    pool-mixing/Danezis-pool-mixing/threshold-batching, which don't use
    MIX_DELAY_MEAN_MS at all."""
    if POOL_MIXING:
        result = apply_pool_mixing(rng, times, n_hops)
    elif DANEZIS_POOL_MIXING:
        result = apply_danezis_pool_mixing(rng, times, n_hops, DANEZIS_ROUND_MS, DANEZIS_RELEASE_PROB)
    elif THRESHOLD_BATCH_SIZE > 0:
        # Batching operates on the already-hop-jittered arrival times
        # (propagation delay still applies before the batch trigger sees
        # them), same "apply base jitter, then a further mechanism"
        # composition pool-mixing itself uses internally.
        jittered = apply_hop_jitter(rng, times, n_hops, hardened=(HARDENED_JITTER or LEGACY_MIX_DELAY),
                                     mean_override=mean_override)
        result = apply_threshold_batching(jittered, THRESHOLD_BATCH_SIZE, THRESHOLD_BATCH_TIMEOUT_MS)
    else:
        result = apply_hop_jitter(rng, times, n_hops, hardened=(HARDENED_JITTER or LEGACY_MIX_DELAY),
                                   mean_override=mean_override)
    if REORDER_WINDOW_MS > 0:
        result = apply_reorder_window(rng, result, REORDER_WINDOW_MS)
    return result


def gen_session(rng: random.Random, flow_type: str, condition: str,
                 real_times_override: list = None):
    """Returns a list of (entry_times_ms, exit_times_ms, real_entry_ms,
    real_exit_ms) sub-path observations for one session under one
    condition. single_path and asn_one_path return a single sub-path;
    asn_both_paths returns two (path A and path B), kept SEPARATE rather
    than merged, see score_session_pair() for why merging into one blob
    would understate the adversary's power.

    real_entry/real_exit (the real-only-subsequence diagnostic): the SAME
    entry/exit observation with cover
    packets removed, what an adversary would see if it could somehow
    tell real and cover packets apart (it cannot, on this network, since
    that flag is unreadable to every mix node), this is a
    deliberately unrealistic, ground-truth-cheating view, useful only as
    a diagnostic: if a defense's overall TPR drops but its real-only TPR
    does not, the defense is only diluting the correlator with cover
    noise, not actually disturbing the real traffic's own timing
    signature, and would be defeated instantly by any adversary who ever
    gains real/cover ground truth another way (e.g. a future flag leak,
    or simply guessing on repeated observation). For no-cover conditions,
    real_entry/real_exit equal entry/exit exactly.

    `real_times_override` (active watermark attack):
    if given, used INSTEAD of calling gen_real_packet_times(), lets an
    external caller (flowcorr_watermark.py) inject a delay-watermarked
    real-packet-times list and have it flow through this function's
    EXISTING dispatch/defense pipeline unchanged, so the watermark is
    evaluated against every defense mechanism already built
    (pool-mixing, threshold-batching, reorder, etc.) without duplicating
    any of that logic. Only affects the single-real_times conditions
    (single_path/single_path_cover/asn_one_path*), asn_both_paths still
    generates its own two real_times lists internally, out of scope for
    the initial watermark build (see tier4_watermark_scope.md). None
    (default) preserves exact prior behavior for every existing caller.

    IMPORTANT for reproducibility: every condition below computes
    real_entry/real_exit by SPLITTING an existing single
    apply_hop_jitter(rng, real+cover, ...) call into two sequential calls,
    apply_hop_jitter(rng, real, ...) then apply_hop_jitter(rng, cover, ...)
    -- since Python's list concatenation preserves each list's own
    element order, this draws the exact same random values in the exact
    same sequence as the original one-call version, so entry/exit and the
    RNG stream position after gen_session() returns are BOTH byte-for-byte
    identical to before this diagnostic was added. No previously-published
    number for any existing condition changes."""
    real_times = (real_times_override if real_times_override is not None
                  else gen_real_packet_times(rng, flow_type, SESSION_DURATION_S))

    if condition == "single_path":
        # Tor-equivalent: no cover, single bidirectional circuit, entry and
        # exit both see the same real packets, exit lagged by hop jitter.
        entry = sorted(real_times)
        exit_ = sorted(apply_hop_jitter(rng, real_times, N_HOPS_PATH))
        return [(entry, exit_, entry, exit_)]

    if condition == "single_path_cover":
        # Single-path baseline given the
        # SAME entry-side cover treatment as the ASN arms below, structurally
        # identical to single_path otherwise. Isolates whether the reported
        # correlation-resistance gap is a property of the dual-path
        # architecture or just of cover traffic, see asn_one_path_no_cover
        # for the complementary ablation, and README.md/anosecnet.tex for the
        # 2x2 {single,dual}x{cover,no-cover} this pair completes.
        # --hardened-jitter also switches this ablation's
        # dispatch mechanism to the real shared-clock model (see
        # gen_hardened_dispatch()) instead of only adding propagation
        # jitter: this ablation exists specifically to isolate cover's
        # own contribution, so it needs the CORRECT cover mechanism under
        # test, not just delay noise layered on the legacy one.
        if HARDENED_JITTER:
            dispatched_real, cover_times = gen_hardened_dispatch(rng, real_times, SESSION_DURATION_S)
        else:
            dispatched_real = real_times
            cover_times = gen_cover_times_with_suppression(rng, real_times, SESSION_DURATION_S)
        entry = sorted(dispatched_real + cover_times)
        # exit sees only the (dispatched, possibly queue-delayed) real
        # times: this ablation deliberately keeps cover un-forwarded,
        # unlike ASN's own paths below, since it exists to isolate cover's
        # contribution on an otherwise Tor-like single circuit, not to
        # model ASN's actual (now end-to-end) forwarding behavior.
        exit_ = sorted(apply_hop_jitter(rng, dispatched_real, N_HOPS_PATH, hardened=HARDENED_JITTER))
        # real-only diagnostic: exit_ is already real-only by this
        # ablation's own design (see comment above); entry's real subset
        # is dispatched_real directly (no jitter applied on the entry
        # side in this branch, so no RNG-stream concern splitting it out).
        real_entry = sorted(dispatched_real)
        return [(entry, exit_, real_entry, exit_)]

    if condition == "asn_one_path":
        # Entry (Receiver-facing hop) AND exit (SG-facing hop) both see
        # real+cover mixed. Cover travels every hop to the SG and is
        # dropped only there, via a flag inside the end-to-end GCM
        # payload no mix node can read, so the exit-side (SG-facing)
        # mix node forwards cover exactly like real traffic,
        # indistinguishably, and its observation is a real+cover mixture
        # too, not real-only.
        # --hardened-jitter switches to the real shared-clock
        # dispatch model (gen_hardened_dispatch()), see the
        # anonymity-set claim this measurement exists to evaluate. Both entry and exit observe the
        # SAME dispatched (real+cover) stream, jittered by propagation
        # only for entry and by propagation+ASN's own mixing delay for
        # exit, since the packets physically traverse the hops between
        # them.
        if COVER_DROP_PROB > 0:
            dispatched_real, cover_times = gen_cover_drop_dispatch(
                rng, real_times, SESSION_DURATION_S, COVER_DROP_PROB, COVER_DROP_WORK_CONSERVING)
        elif HARDENED_JITTER:
            dispatched_real, cover_times = gen_hardened_dispatch(rng, real_times, SESSION_DURATION_S)
        else:
            dispatched_real = real_times
            cover_times = gen_cover_times_with_suppression(rng, real_times, SESSION_DURATION_S)
        entry = sorted(dispatched_real + cover_times)
        # Split into two sequential apply_hop_jitter() calls (real, then
        # cover) rather than one call on the concatenation, identical
        # RNG draws, identical exit_ (see gen_session()'s docstring), and
        # gives the real-only exit-side trace as a free byproduct.
        jittered_real_x = apply_exit_timing(rng, dispatched_real, N_HOPS_PATH)
        jittered_cover_x = apply_exit_timing(rng, cover_times, N_HOPS_PATH)
        exit_ = sorted(jittered_real_x + jittered_cover_x)
        real_entry = sorted(dispatched_real)
        real_exit = sorted(jittered_real_x)
        return [(entry, exit_, real_entry, real_exit)]

    if condition == "single_path_defended":
        # The direct "same total
        # traffic, same defenses, ONE circuit instead of two" comparison
        # against asn_both_paths. Merges what would
        # be Path A's (outbound) and Path B's (inbound) real traffic into
        # ONE combined stream, the same total conversation asn_both_paths
        # splits across two physical paths, and routes it through a
        # SINGLE circuit's cover+dispatch mechanism, mirroring
        # asn_one_path's exact dispatch logic (same COVER_DROP_PROB/
        # HARDENED_JITTER precedence) but on the merged, single-circuit
        # stream and observed as ONE entry/exit pair rather than two
        # separate sub-paths. If a Tor-style single circuit given the
        # SAME cover+mixing-delay defenses ASN applies per-path did just
        # as well (or better) than asn_both_paths' fully-compromised
        # number, that would mean the path SPLIT itself adds nothing once
        # an adversary has both directions anyway, if it does
        # meaningfully worse, that's direct evidence the split itself
        # (not just the defenses) is doing some of the protecting even
        # under full compromise.
        real_times_b = gen_real_packet_times(rng, flow_type, SESSION_DURATION_S)
        combined_real = sorted(real_times + real_times_b)
        if COVER_DROP_PROB > 0:
            dispatched_real, cover_times = gen_cover_drop_dispatch(
                rng, combined_real, SESSION_DURATION_S, COVER_DROP_PROB, COVER_DROP_WORK_CONSERVING)
        elif HARDENED_JITTER:
            # Dispatch clock rate DOUBLED (tick_mean_override=DUMMY_INTERVAL_MS/2);
            # see gen_hardened_dispatch()'s docstring: the split design
            # runs TWO independent per-path dispatch clocks (double the
            # aggregate tick capacity of one), so a single merged circuit
            # at the default clock rate would generate far less cover
            # once real-packet density approaches the tick rate.
            # Doubling the rate restores comparable aggregate
            # dispatch/cover capacity, making this an apples-to-apples
            # "same total traffic, same defenses" comparison instead of
            # a confounded "same traffic, way less cover" one.
            dispatched_real, cover_times = gen_hardened_dispatch(
                rng, combined_real, SESSION_DURATION_S,
                tick_mean_override=DUMMY_INTERVAL_MS / 2.0)
        else:
            dispatched_real = combined_real
            cover_times = gen_cover_times_with_suppression(rng, combined_real, SESSION_DURATION_S)
        entry = sorted(dispatched_real + cover_times)
        jittered_real_x = apply_exit_timing(rng, dispatched_real, N_HOPS_PATH)
        jittered_cover_x = apply_exit_timing(rng, cover_times, N_HOPS_PATH)
        exit_ = sorted(jittered_real_x + jittered_cover_x)
        real_entry = sorted(dispatched_real)
        real_exit = sorted(jittered_real_x)
        return [(entry, exit_, real_entry, real_exit)]

    if condition == "asn_one_path_no_cover":
        # The dual-path (one-direction-
        # observed) arm with cover ablated, all else identical to
        # asn_one_path. Isolates the path-splitting architecture's own
        # contribution from cover traffic's contribution, see
        # single_path_cover above for the complementary ablation.
        entry = sorted(real_times)
        exit_ = sorted(apply_hop_jitter(rng, real_times, N_HOPS_PATH))
        return [(entry, exit_, entry, exit_)]

    if condition == "asn_one_path_entry_cover":
        # "Entry-only cover" / "cover
        # dropped mid-path (e.g. at MN2)" analytical reference for the
        # dual-path (one-direction-observed) case, mirrors
        # single_path_cover's entry/exit asymmetry (entry sees
        # real+cover, exit sees real-only, cover deliberately not
        # forwarded) but using asn_one_path's own dispatch mechanism
        # instead of the plain single-path one, isolating cover's OWN
        # contribution to asn_one_path specifically. This completes the
        # {single-path, dual-path-one-observed} x {full end-to-end
        # cover, entry-only cover, no cover} matrix, single_path
        # already has all three (single_path_cover is its middle term);
        # asn_one_path previously only had the two endpoints (asn_one_path
        # itself, asn_one_path_no_cover).
        #
        # Under this file's 2-checkpoint (entry/exit) observation model,
        # "cover dropped at MN1" and "cover dropped at MN2" (or anywhere
        # else strictly between entry and exit) are OBSERVATIONALLY
        # IDENTICAL: both mean the exit-side adversary sees no cover,
        # regardless of exactly where between the two checkpoints it was
        # removed. So this single condition answers both
        # "entry-only cover" and "cover dropped at MN2
        # specifically" at once.
        if COVER_DROP_PROB > 0:
            dispatched_real, cover_times = gen_cover_drop_dispatch(
                rng, real_times, SESSION_DURATION_S, COVER_DROP_PROB, COVER_DROP_WORK_CONSERVING)
        elif HARDENED_JITTER:
            dispatched_real, cover_times = gen_hardened_dispatch(rng, real_times, SESSION_DURATION_S)
        else:
            dispatched_real = real_times
            cover_times = gen_cover_times_with_suppression(rng, real_times, SESSION_DURATION_S)
        entry = sorted(dispatched_real + cover_times)
        exit_ = sorted(apply_exit_timing(rng, dispatched_real, N_HOPS_PATH))
        real_entry = sorted(dispatched_real)
        return [(entry, exit_, real_entry, exit_)]

    if condition == "asn_both_paths":
        # Both directions observed: path-A (outbound) and path-B
        # (inbound/return), kept as two SEPARATE sub-path observations. We
        # model the return-direction real traffic (the SG's responses) as a
        # second, independent Poisson process at the same mean rate.
        #
        # Path B's exit-side (Receiver-facing, e.g. MNa)
        # observation is real+cover mixed too, same reasoning as
        # asn_one_path above but for the return direction.
        # Return-path cover is genuine, SG-originated, Sphinx-return-
        # header-valid cover that traverses every return hop
        # indistinguishably from a real response, so both
        # ends of path B see a real+cover mixture.
        # Path A's dispatch, under --hardened-jitter, switches
        # to the real shared-clock model (matches client.c/sender.c's
        # mailbox mechanism). Path B deliberately does NOT: the SG's
        # response dispatch (service_gateway.c's send_response_ex(), both
        # the real path and the cover path) has no shared-clock rate
        # bounding in the actual implementation, hardened build or not,
        # it fires immediately on a matched real request or cover ticket,
        # uncapped. Modeling path B as rate-bounded here would overstate
        # what the code actually does. What DOES apply to path B under a
        # hardened build is the per-hop mixing delay itself
        # (mix_node.c's mix_delay_sleep() runs unconditionally on both
        # handle_data() and handle_return() under ASN_LOOPIX_MIXING),
        # so exit_b still gets hardened=True hop jitter even though its
        # dispatch mechanism is unchanged.
        real_times_b = gen_real_packet_times(rng, flow_type, SESSION_DURATION_S)
        # Fork Path B onto its own rng, reproducibly
        # seeded off the shared stream, when --independent-path-rng is set;
        # see INDEPENDENT_PATH_RNG's module-level docstring. Default
        # (rng_b = rng) is byte-identical to every previously-published
        # asn_both_paths number: same object, same draw order, no change.
        rng_b = random.Random(rng.random()) if INDEPENDENT_PATH_RNG else rng
        # Packet-level striping: SPLIT_RATIO=1.0
        # (default) is the fully-directional model (every
        # outbound packet stays on Path A, every inbound stays on Path
        # B). SPLIT_RATIO<1.0 independently re-assigns each direction's
        # REAL packets to the OTHER path with probability (1-ratio),
        # TrafficSliver-style secret per-packet path assignment. Cover
        # generation is untouched (still generated independently per
        # physical path, as always), only real-packet path membership
        # is striped. real_times_for_a/real_times_for_b replace
        # real_times/real_times_b everywhere below.
        if SPLIT_RATIO < 1.0:
            real_a_home, real_a_away = split_by_ratio(rng, real_times, SPLIT_RATIO)
            real_b_home, real_b_away = split_by_ratio(rng_b, real_times_b, SPLIT_RATIO)
            real_times_for_a = sorted(real_a_home + real_b_away)
            real_times_for_b = sorted(real_b_home + real_a_away)
        else:
            real_times_for_a = real_times
            real_times_for_b = real_times_b
        if COVER_DROP_PROB > 0:
            # HYPOTHETICAL: only wired onto
            # Path A, not Path B, to keep this a bounded first test
            # rather than compounding with Path B's own asymmetric
            # dispatch mechanism (SYMMETRIC_DISPATCH) in the same run.
            dispatched_real_a, cover_a = gen_cover_drop_dispatch(
                rng, real_times_for_a, SESSION_DURATION_S, COVER_DROP_PROB, COVER_DROP_WORK_CONSERVING)
        elif HARDENED_JITTER:
            dispatched_real_a, cover_a = gen_hardened_dispatch(rng, real_times_for_a, SESSION_DURATION_S)
        else:
            dispatched_real_a = real_times_for_a
            cover_a = gen_cover_times_with_suppression(rng, real_times_for_a, SESSION_DURATION_S)
        if HARDENED_JITTER and SYMMETRIC_DISPATCH:
            dispatched_real_b, cover_b = gen_hardened_dispatch(rng_b, real_times_for_b, SESSION_DURATION_S)
        else:
            dispatched_real_b = real_times_for_b
            cover_b = gen_cover_times_with_suppression(rng_b, real_times_for_b, SESSION_DURATION_S,
                                                         mean_override=COVER_RATE_MEAN_MS_B)
        entry_a = sorted(dispatched_real_a + cover_a)
        # Split into two sequential apply_hop_jitter() calls per sub-path
        # (real, then cover), identical RNG draws/exit_ as the single-call
        # version (see gen_session()'s docstring), real-only trace as a
        # free byproduct.
        jittered_real_xa = apply_exit_timing(rng, dispatched_real_a, N_HOPS_PATH)
        jittered_cover_xa = apply_exit_timing(rng, cover_a, N_HOPS_PATH)
        exit_a = sorted(jittered_real_xa + jittered_cover_xa)
        entry_b = sorted(dispatched_real_b + cover_b)
        jittered_real_xb = apply_exit_timing(rng_b, dispatched_real_b, N_HOPS_PATH,
                                              mean_override=MIX_DELAY_MEAN_MS_B)
        jittered_cover_xb = apply_exit_timing(rng_b, cover_b, N_HOPS_PATH,
                                               mean_override=MIX_DELAY_MEAN_MS_B)
        exit_b = sorted(jittered_real_xb + jittered_cover_xb)
        real_entry_a = sorted(dispatched_real_a)
        real_exit_a = sorted(jittered_real_xa)
        real_entry_b = sorted(dispatched_real_b)
        real_exit_b = sorted(jittered_real_xb)
        return [(entry_a, exit_a, real_entry_a, real_exit_a),
                (entry_b, exit_b, real_entry_b, real_exit_b)]

    if condition == "asn_both_paths_no_cover":
        # The no-cover ceiling for the
        # BOTH-directions-observed adversary, completing the same
        # {single,dual}x{cover,no-cover} logic single_path_cover/
        # asn_one_path_no_cover already establish for the single-
        # direction cases. Appended as the LAST condition in main()'s
        # conditions list so it consumes RNG draws
        # only after every other condition has already
        # drawn its own. No cover, no dispatch
        # mechanism, both directions modeled as two independent real-only
        # Poisson processes, structurally identical to asn_both_paths
        # above with cover_a/cover_b simply absent.
        real_times_b = gen_real_packet_times(rng, flow_type, SESSION_DURATION_S)
        entry_a = sorted(real_times)
        exit_a = sorted(apply_hop_jitter(rng, real_times, N_HOPS_PATH))
        entry_b = sorted(real_times_b)
        exit_b = sorted(apply_hop_jitter(rng, real_times_b, N_HOPS_PATH))
        return [(entry_a, exit_a, entry_a, exit_a),
                (entry_b, exit_b, entry_b, exit_b)]

    raise ValueError(condition)


# ---------------------------------------------------------------------------
# Feature extraction: binned volume + binned mean inter-packet interval
# ---------------------------------------------------------------------------
def to_features(times_ms, duration_s: float, bin_width_ms: float):
    n_bins = int(math.ceil(duration_s * 1000.0 / bin_width_ms))
    volume = np.zeros(n_bins, dtype=np.float64)
    timing = np.full(n_bins, bin_width_ms, dtype=np.float64)
    if not times_ms:
        return volume, timing
    arr = np.array(sorted(times_ms))
    bins = np.clip((arr // bin_width_ms).astype(int), 0, n_bins - 1)
    for b in range(n_bins):
        mask = bins == b
        cnt = int(mask.sum())
        volume[b] = cnt
        if cnt >= 2:
            in_bin = np.sort(arr[mask])
            timing[b] = float(np.mean(np.diff(in_bin)))
    return volume, timing


def pearson(a, b):
    if np.std(a) < 1e-12 or np.std(b) < 1e-12:
        return 0.0
    return float(np.corrcoef(a, b)[0, 1])


def cosine(a, b):
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    if na < 1e-12 or nb < 1e-12:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


def score_pair(vol_e, tim_e, vol_x, tim_x, correlator: str) -> float:
    if correlator == "pearson_volume":
        return pearson(vol_e, vol_x)
    if correlator == "combined":
        return float(np.mean([
            pearson(vol_e, vol_x), cosine(vol_e, vol_x),
            pearson(tim_e, tim_x), cosine(tim_e, tim_x),
        ]))
    raise ValueError(correlator)


# ---------------------------------------------------------------------------
# ROC / TPR-at-FPR
# ---------------------------------------------------------------------------
def roc_tpr_at_fpr(true_scores, impostor_scores, fpr_targets):
    true_scores = np.array(true_scores)
    impostor_scores = np.array(impostor_scores)
    thresholds = np.unique(np.concatenate([true_scores, impostor_scores]))[::-1]
    n_true = len(true_scores)
    n_imp = len(impostor_scores)

    tprs, fprs = [], []
    for thr in thresholds:
        tprs.append(np.mean(true_scores >= thr))
        fprs.append(np.mean(impostor_scores >= thr))
    tprs = np.array([0.0] + tprs + [1.0])
    fprs = np.array([0.0] + fprs + [1.0])
    order = np.argsort(fprs)
    fprs_sorted, tprs_sorted = fprs[order], tprs[order]
    trapezoid = getattr(np, "trapezoid", None) or np.trapz
    auc = float(trapezoid(tprs_sorted, fprs_sorted))

    results = {}
    for target in fpr_targets:
        idx = np.searchsorted(fprs_sorted, target, side="right") - 1
        idx = max(0, min(idx, len(tprs_sorted) - 1))
        tpr_at = float(tprs_sorted[idx])
        hits = int(round(tpr_at * n_true))
        ci = ci95_proportion(hits, n_true)
        results[target] = (tpr_at, ci)
    return results, auc, n_true, n_imp, fprs_sorted, tprs_sorted


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    global HARDENED_JITTER, MIX_DELAY_MEAN_MS, INDEPENDENT_PATH_RNG, SYMMETRIC_DISPATCH, LEGACY_MIX_DELAY, POOL_MIXING, POOL_MIX_FLUSH_MS, REORDER_WINDOW_MS, THRESHOLD_BATCH_SIZE, THRESHOLD_BATCH_TIMEOUT_MS, COVER_DROP_PROB, COVER_DROP_WORK_CONSERVING, SPLIT_RATIO, DANEZIS_POOL_MIXING, DANEZIS_ROUND_MS, DANEZIS_RELEASE_PROB, MIX_DELAY_MEAN_MS_B, COVER_RATE_MEAN_MS_B
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sessions", type=int, default=200,
                     help="Sessions per condition (N true pairs; N*(N-1) impostor pairs)")
    ap.add_argument("--seed", type=int, default=20260710)
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--fpr-targets", default="1e-1,1e-2,1e-3",
                     help="Comma-separated FPR operating points. Note: meaningful "
                          "resolution at a given FPR requires n_impostor_pairs >> 1/FPR "
                          "-- e.g. FPR=1e-5 needs --sessions >~500 (N*(N-1) impostor "
                          "pairs), not the default 200.")
    ap.add_argument("--hardened-jitter", action="store_true",
                     help="Add ASN_LOOPIX_MIXING's per-hop mixing delay on top of the "
                          "baseline crypto-only jitter (see HARDENED_JITTER docstring)")
    ap.add_argument("--mix-delay-mean-ms", type=float, default=MIX_DELAY_MEAN_MS,
                     help="Task 3 sensitivity sweep: override the mixing delay's mean "
                          "(ms) used when --hardened-jitter is set. Default matches "
                          "common/config.h's MIX_DELAY_MEAN_MS=50.0, i.e. the same "
                          "value every other hardened-mode result in this paper uses. "
                          "Cap (MIX_DELAY_MAX_MS) is left unchanged at every value, "
                          "matching mix_node.c/mix_node_instrumented.c's own sweep "
                          "override, which also holds the cap fixed.")
    ap.add_argument("--independent-path-rng", action="store_true",
                     help="Fork Path B's cover-tick/jitter "
                          "RNG onto its own reproducibly-seeded stream, independent of "
                          "Path A's (see INDEPENDENT_PATH_RNG's module-level docstring). "
                          "Default (off) is byte-identical to every previously-published "
                          "asn_both_paths number. Only affects asn_both_paths.")
    ap.add_argument("--symmetric-dispatch", action="store_true",
                     help="ABLATION CONTROL (not the real "
                          "implementation): force Path B through the same rate-bounded "
                          "shared-clock dispatch Path A gets under --hardened-jitter, "
                          "instead of Path B's real uncapped-immediate dispatch (see "
                          "SYMMETRIC_DISPATCH's module-level docstring). No effect "
                          "without --hardened-jitter. Default (off) is byte-identical to "
                          "every previously-published asn_both_paths number.")
    ap.add_argument("--legacy-mix-delay", action="store_true",
                     help="Mechanism A/B attribution refinement: add the exponential "
                          "per-hop mixing delay (--mix-delay-mean-ms) to LEGACY "
                          "(immediate) dispatch, without switching to hardened "
                          "mailbox/queueing dispatch, decouples dispatch mechanism "
                          "from delay-addition for a true 2x2 (see LEGACY_MIX_DELAY's "
                          "module-level docstring). No effect if --hardened-jitter is "
                          "also set (already gets both). Only affects "
                          "asn_one_path/asn_both_paths, not single_path_cover.")
    ap.add_argument("--pool-mixing", action="store_true",
                     help="Genuine batch/pool mixing (ASN_POOL_MIXING) "
                          "instead of per-packet jitter, for asn_one_path/asn_both_paths. "
                          "Alternative to, not stacked with, --hardened-jitter/"
                          "--legacy-mix-delay (takes precedence if both are set). See "
                          "POOL_MIXING's module-level docstring.")
    ap.add_argument("--pool-mix-flush-ms", type=float, default=POOL_MIX_FLUSH_MS,
                     help="Sensitivity sweep: override the pool-mix flush "
                          "window's width (ms), only used when --pool-mixing is set. "
                          "Default matches mix_node.c's POOL_MIX_FLUSH_MS=250.0.")
    ap.add_argument("--reorder-window-ms", type=float, default=REORDER_WINDOW_MS,
                     help="HYPOTHETICAL (no code equivalent): "
                          "standalone reorder-window width (ms) for asn_one_path/"
                          "asn_both_paths, applied on top of whatever hop-jitter/"
                          "pool-mixing mechanism is active. 0 (default) = off, "
                          "byte-identical to every previously-published number. "
                          "See apply_reorder_window()'s docstring for scope/caveats.")
    ap.add_argument("--threshold-batch-size", type=int, default=THRESHOLD_BATCH_SIZE,
                     help="HYPOTHETICAL (no code equivalent): release "
                          "packets in batches of this many for asn_one_path/"
                          "asn_both_paths, instead of jitter/pool-mixing (takes "
                          "precedence over jitter, yields to --pool-mixing if both "
                          "set). 0 (default) = off. See "
                          "apply_threshold_batching()'s docstring.")
    ap.add_argument("--threshold-batch-timeout-ms", type=float, default=THRESHOLD_BATCH_TIMEOUT_MS,
                     help="Hybrid mode: also release a batch early once this many ms "
                          "have elapsed since its first packet, even if "
                          "--threshold-batch-size hasn't been reached. Only used when "
                          "--threshold-batch-size is set. 0 (default) = pure threshold.")
    ap.add_argument("--cover-drop-prob", type=float, default=COVER_DROP_PROB,
                     help="HYPOTHETICAL (no code equivalent, "
                          "verified absent): probability a cover packet is dropped once "
                          "it reaches the head of a FIFO dispatch queue, for asn_one_path/"
                          "asn_both_paths' Path A. Replaces --hardened-jitter's dispatch "
                          "mechanism when set (takes precedence). 0 (default) = off, "
                          "byte-identical to prior numbers. See "
                          "gen_cover_drop_dispatch()'s docstring.")
    ap.add_argument("--cover-drop-work-conserving", action="store_true",
                     help="Variant B (work-conserving): a dropped cover packet's slot "
                          "isn't wasted, a queued real packet directly behind it in "
                          "the FIFO advances to that same tick. Default (off) is Variant "
                          "A (deletion-only): real timing is provably unaffected by "
                          "drops. Only used when --cover-drop-prob is set.")
    ap.add_argument("--split-ratio", type=float, default=SPLIT_RATIO,
                     help="TrafficSliver-style packet-level striping for "
                          "asn_both_paths, probability a direction's real packet "
                          "stays on its 'home' path rather than being secretly "
                          "reassigned to the other one. 1.0 (default) = fully "
                          "directional, byte-identical to prior numbers. 0.5 = fully "
                          "mixed/striped. See SPLIT_RATIO's module-level docstring.")
    ap.add_argument("--danezis-pool-mixing", action="store_true",
                     help="HYPOTHETICAL (no code equivalent): "
                          "Danezis-style continuous-time pool mixing (per-round "
                          "probabilistic release, geometric sojourn time) for "
                          "asn_one_path/asn_both_paths, distinct from --pool-mixing's "
                          "deterministic whole-window release. Takes precedence over "
                          "--threshold-batch-size, yields to --pool-mixing if both are "
                          "set. See apply_danezis_pool_mixing()'s docstring.")
    ap.add_argument("--danezis-round-ms", type=float, default=DANEZIS_ROUND_MS,
                     help="Round interval for --danezis-pool-mixing.")
    ap.add_argument("--danezis-release-prob", type=float, default=DANEZIS_RELEASE_PROB,
                     help="Per-round release probability for --danezis-pool-mixing; "
                          "mean sojourn = round_ms/release_prob.")
    ap.add_argument("--mix-delay-mean-ms-b", type=float, default=MIX_DELAY_MEAN_MS_B,
                     help="Path B's exponential mixing-delay mean, "
                          "if different from Path A's (--mix-delay-mean-ms), "
                          "asymmetric per-path delay distributions, asn_both_paths "
                          "only. None (default) = Path B uses the same mean as Path A, "
                          "byte-identical to prior numbers. Only affects the plain "
                          "jitter path, not pool-mixing/Danezis/threshold-batching.")
    ap.add_argument("--cover-rate-mean-ms-b", type=float, default=COVER_RATE_MEAN_MS_B,
                     help="Path B's cover-tick mean interval, if "
                          "different from DUMMY_INTERVAL_MS, asymmetric per-path "
                          "cover rate, asn_both_paths only. None (default) = Path B "
                          "uses the same mean as Path A, byte-identical to prior "
                          "numbers. Only affects the plain (non-hardened) cover "
                          "dispatch path, see COVER_RATE_MEAN_MS_B's docstring for "
                          "why it isn't threaded into --hardened-jitter's dispatch.")
    args = ap.parse_args()

    HARDENED_JITTER = args.hardened_jitter
    MIX_DELAY_MEAN_MS = args.mix_delay_mean_ms
    INDEPENDENT_PATH_RNG = args.independent_path_rng
    SYMMETRIC_DISPATCH = args.symmetric_dispatch
    LEGACY_MIX_DELAY = args.legacy_mix_delay
    POOL_MIXING = args.pool_mixing
    POOL_MIX_FLUSH_MS = args.pool_mix_flush_ms
    REORDER_WINDOW_MS = args.reorder_window_ms
    THRESHOLD_BATCH_SIZE = args.threshold_batch_size
    THRESHOLD_BATCH_TIMEOUT_MS = args.threshold_batch_timeout_ms
    COVER_DROP_PROB = args.cover_drop_prob
    COVER_DROP_WORK_CONSERVING = args.cover_drop_work_conserving
    SPLIT_RATIO = args.split_ratio
    DANEZIS_POOL_MIXING = args.danezis_pool_mixing
    DANEZIS_ROUND_MS = args.danezis_round_ms
    DANEZIS_RELEASE_PROB = args.danezis_release_prob
    MIX_DELAY_MEAN_MS_B = args.mix_delay_mean_ms_b
    COVER_RATE_MEAN_MS_B = args.cover_rate_mean_ms_b

    os.makedirs(args.out_dir, exist_ok=True)
    traces_dir = os.path.join(args.out_dir, "flowcorr_traces")
    os.makedirs(traces_dir, exist_ok=True)

    rng = random.Random(args.seed)
    # single_path_cover and
    # asn_one_path_no_cover complete the {single,dual}x{cover,no-cover} 2x2
    # that isolates the dual-path architecture's contribution from cover
    # traffic's contribution. asn_both_paths is left cover-only (matching
    # the paper's own reported condition); the ablation only needs to be
    # run once per architecture, and asn_one_path already covers "dual".
    # The two new conditions are appended AFTER the three original ones
    # (rather than interleaved) so they consume rng draws only after the
    # original three have already drawn theirs, so
    # single_path/asn_one_path/asn_both_paths stay numerically stable for
    # the same --seed rather than shifting by RNG-stream position.
    # asn_both_paths_no_cover is appended LAST for the identical reason.
    conditions = ["single_path", "asn_one_path", "asn_both_paths",
                  "single_path_cover", "asn_one_path_no_cover",
                  "asn_both_paths_no_cover", "asn_one_path_entry_cover",
                  "single_path_defended"]
    correlators = ["pearson_volume", "combined"]
    fpr_targets = [float(x) for x in args.fpr_targets.split(",")]

    t0 = time.perf_counter()
    result_rows = []
    roc_curve_rows = []
    # Real-only-subsequence TPR, logged
    # alongside overall TPR for every condition, see gen_session()'s
    # docstring for what this diagnostic is and why. Written to a SEPARATE
    # output file (flowcorr_realonly_results.csv) rather than mixed into
    # flowcorr_results.csv, so every existing consumer of that file (plot
    # scripts, cited numbers) is unaffected.
    realonly_result_rows = []
    # Single-vantage-adversary TPR,
    # logged alongside the overall (joint, max-of-subpaths) TPR for every
    # multi-sub-path condition. See score_session_pair_single_vantage()'s
    # docstring below for what this measures and why it's the number
    # that actually tests striping's claimed protective value (the joint
    # number is expected to sit at ceiling regardless of split ratio).
    singlevantage_result_rows = []

    for condition in conditions:
        # Half interactive, half bulk flows, alternating for balance. Each
        # session is a list of 1 (single_path/asn_one_path) or 2
        # (asn_both_paths) sub-path (entry, exit) observations.
        sessions = []
        for i in range(args.sessions):
            flow_type = "interactive" if i % 2 == 0 else "bulk"
            sessions.append(gen_session(rng, flow_type, condition))

        # Save a handful of example traces for documentation/inspection
        # (per the task spec: don't commit huge trace files, just enough to
        # illustrate the generator's output).
        sample_path = os.path.join(traces_dir, f"{condition}_sample.csv")
        with open(sample_path, "w", newline="") as fp:
            fp.write("# First 3 sessions' entry/exit event timestamps (ms), illustrative only\n")
            fp.write("session,subpath,side,t_ms\n")
            w = csv.writer(fp)
            for i in range(min(3, args.sessions)):
                for sp, (e, x, _re, _rx) in enumerate(sessions[i]):
                    for t in e:
                        w.writerow([i, sp, "entry", f"{t:.3f}"])
                    for t in x:
                        w.writerow([i, sp, "exit", f"{t:.3f}"])

        # Precompute (volume, timing) feature vectors for every sub-path of
        # every session, once for the real observer's actual (real+cover)
        # view, once for the real-only-subsequence diagnostic view.
        features = []   # features[i] = [(vol_e, tim_e, vol_x, tim_x), ...] per sub-path
        realonly_features = []
        for subpaths in sessions:
            feat, real_feat = [], []
            for e, x, re, rx in subpaths:
                ve, te = to_features(e, SESSION_DURATION_S, BIN_WIDTH_MS)
                vx, tx = to_features(x, SESSION_DURATION_S, BIN_WIDTH_MS)
                feat.append((ve, te, vx, tx))
                rve, rte = to_features(re, SESSION_DURATION_S, BIN_WIDTH_MS)
                rvx, rtx = to_features(rx, SESSION_DURATION_S, BIN_WIDTH_MS)
                real_feat.append((rve, rte, rvx, rtx))
            features.append(feat)
            realonly_features.append(real_feat)

        def score_session_pair(i, j, correlator, feat=features):
            """Score session i's entry-side observation against session j's
            exit-side observation. For multi-sub-path conditions
            (asn_both_paths) the adversary computes a score per sub-path
            (path A, path B independently) and takes the MAX, an
            adversary who controls both paths is at least as strong as one
            who controls either path alone, since they can always fall back
            to whichever single path leaks more; merging both paths' events
            into one blob before scoring would instead just add
            cross-path noise and understate this adversary's power.
            `feat` defaults to the real+cover feature array; pass
            `realonly_features` for the real-only-subsequence
            diagnostic (same session pairing, different underlying trace)."""
            sub_scores = [
                score_pair(feat[i][k][0], feat[i][k][1],
                           feat[j][k][2], feat[j][k][3], correlator)
                for k in range(len(feat[i]))
            ]
            return max(sub_scores)

        def score_session_pair_single_vantage(i, j, correlator, feat=features):
            """Single-vantage variant
            of score_session_pair(). An adversary who compromises only ONE
            physical path (sub-path index 0, "Path A") and must correlate
            whatever partial, direction-mixed traffic that path happens to
            carry under --split-ratio striping, returns sub_scores[0]
            instead of max(sub_scores). Under ASN's default strict
            directional split (--split-ratio 1.0), this is identical to
            score_session_pair() for asn_one_path-shaped visibility; the
            interesting case is ratio<1.0, where Path A's content is a
            random mix of both original directions and a single-vantage
            adversary sees a diluted partial sample instead of one
            direction's complete traffic. Only meaningful for multi-sub-
            path conditions, see the `len(features[0]) > 1` guard below,
            which skips this pass for single-sub-path conditions where it
            would just duplicate score_session_pair()'s own output."""
            sub_scores = [
                score_pair(feat[i][k][0], feat[i][k][1],
                           feat[j][k][2], feat[j][k][3], correlator)
                for k in range(len(feat[i]))
            ]
            return sub_scores[0]

        for correlator in correlators:
            true_scores = []
            impostor_scores = []
            for i in range(args.sessions):
                for j in range(args.sessions):
                    s = score_session_pair(i, j, correlator)
                    if i == j:
                        true_scores.append(s)
                    else:
                        impostor_scores.append(s)

            fpr_results, auc, n_true, n_imp, fprs_curve, tprs_curve = roc_tpr_at_fpr(
                true_scores, impostor_scores, fpr_targets)

            for target, (tpr, ci) in fpr_results.items():
                result_rows.append({
                    "condition": condition,
                    "correlator": correlator,
                    "fpr_target": target,
                    "tpr": tpr,
                    "tpr_ci95": ci,
                    "auc": auc,
                    "n_pairs": n_true + n_imp,
                })
            # Subsample the full ROC curve (it can have O(n_true+n_imp) points)
            # to a manageable number of rows for the CSV/figure.
            n_curve_points = 300
            idxs = np.unique(np.linspace(0, len(fprs_curve) - 1, n_curve_points).astype(int))
            for idx in idxs:
                roc_curve_rows.append({
                    "condition": condition, "correlator": correlator,
                    "fpr": float(fprs_curve[idx]), "tpr": float(tprs_curve[idx]),
                })
            if not args.quiet:
                print(f"  {condition:16s} {correlator:16s} AUC={auc:.4f}  "
                      f"TPR@{min(fpr_targets):g}={fpr_results[min(fpr_targets)][0]:.4f}", flush=True)

            # Tier-0 real-only-subsequence diagnostic: identical scoring
            # pipeline, same session pairing, real-only trace instead of
            # the real+cover mixture. Cheap (same O(sessions^2) pass,
            # already-computed features) and, per the diagnostic's own
            # purpose, expected to sit at or near ceiling for every
            # condition tested, if it doesn't, that's a real finding to
            # report, not an error to suppress.
            real_true, real_impostor = [], []
            for i in range(args.sessions):
                for j in range(args.sessions):
                    s = score_session_pair(i, j, correlator, feat=realonly_features)
                    (real_true if i == j else real_impostor).append(s)
            real_fpr_results, real_auc, real_n_true, real_n_imp, _, _ = roc_tpr_at_fpr(
                real_true, real_impostor, fpr_targets)
            for target, (tpr, ci) in real_fpr_results.items():
                realonly_result_rows.append({
                    "condition": condition,
                    "correlator": correlator,
                    "fpr_target": target,
                    "tpr": tpr,
                    "tpr_ci95": ci,
                    "auc": real_auc,
                    "n_pairs": real_n_true + real_n_imp,
                })
            if not args.quiet:
                print(f"    {'':16s} {'(real-only)':16s} AUC={real_auc:.4f}  "
                      f"TPR@{min(fpr_targets):g}={real_fpr_results[min(fpr_targets)][0]:.4f}",
                      flush=True)

            # Single-vantage diagnostic: same scoring pipeline,
            # sub_scores[0] instead of max(sub_scores). Only meaningful
            # for multi-sub-path conditions (asn_both_paths and its
            # no-cover variant), for single-sub-path conditions this
            # would be identical to the overall score already computed
            # above, so it's skipped to avoid redundant output rows.
            if len(features[0]) > 1:
                sv_true, sv_impostor = [], []
                for i in range(args.sessions):
                    for j in range(args.sessions):
                        s = score_session_pair_single_vantage(i, j, correlator)
                        (sv_true if i == j else sv_impostor).append(s)
                sv_fpr_results, sv_auc, sv_n_true, sv_n_imp, _, _ = roc_tpr_at_fpr(
                    sv_true, sv_impostor, fpr_targets)
                for target, (tpr, ci) in sv_fpr_results.items():
                    singlevantage_result_rows.append({
                        "condition": condition,
                        "correlator": correlator,
                        "fpr_target": target,
                        "tpr": tpr,
                        "tpr_ci95": ci,
                        "auc": sv_auc,
                        "n_pairs": sv_n_true + sv_n_imp,
                    })
                if not args.quiet:
                    print(f"    {'':16s} {'(single-vantage)':16s} AUC={sv_auc:.4f}  "
                          f"TPR@{min(fpr_targets):g}={sv_fpr_results[min(fpr_targets)][0]:.4f}",
                          flush=True)

    elapsed = time.perf_counter() - t0
    if not args.quiet:
        print(f"\n  Completed in {elapsed:.1f}s\n")

    out_path = os.path.join(args.out_dir, "flowcorr_results.csv")
    with open(out_path, "w", newline="") as fp:
        fp.write("# Anon-Sec-Net Task B: empirical flow-correlation attack results\n")
        fp.write(f"# {args.sessions} sessions/condition -> {args.sessions} true pairs, "
                  f"{args.sessions*(args.sessions-1)} impostor pairs\n")
        fp.write("# condition: single_path (Tor-eq, full bidirectional visibility, no cover) |\n")
        fp.write("#            single_path_cover (Tor-eq + same cover treatment as ASN) |\n")
        fp.write("#            asn_one_path_no_cover (dual-path, one direction observed, cover ablated) |\n")
        fp.write("#            asn_one_path (one direction observed, realistic partial case) |\n")
        fp.write("#            asn_both_paths (both directions observed, upper bound) |\n")
        fp.write("#            asn_both_paths_no_cover (both directions, no-cover ceiling)\n")
        fp.write("# single_path_cover and asn_one_path_no_cover\n")
        fp.write("# isolate cover traffic's contribution from the dual-path architecture's own\n")
        fp.write("# contribution to correlation resistance. See anosecnet.tex Sec. eval:flowcorr.\n")
        fp.write("# correlator: pearson_volume (weakest, single feature) | combined (Pearson+cosine, volume+timing)\n")
        fp.write("# tpr_ci95: Wilson-score 95% CI half-width, n = sessions (true pairs)\n")
        fields = ["condition", "correlator", "fpr_target", "tpr", "tpr_ci95", "auc", "n_pairs"]
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        for row in result_rows:
            w.writerow({
                k: (f"{v:.6g}" if isinstance(v, float) else v)
                for k, v in row.items()
            })
    print(f"  Wrote {out_path}  ({len(result_rows)} rows)")

    roc_path = os.path.join(args.out_dir, "flowcorr_roc_curves.csv")
    with open(roc_path, "w", newline="") as fp:
        fp.write("# Anon-Sec-Net Task B: full ROC curves (subsampled to ~300 points each)\n")
        fp.write("# for fig_flowcorr2.pdf/.eps\n")
        w = csv.DictWriter(fp, fieldnames=["condition", "correlator", "fpr", "tpr"])
        w.writeheader()
        for row in roc_curve_rows:
            w.writerow({
                k: (f"{v:.6g}" if isinstance(v, float) else v)
                for k, v in row.items()
            })
    print(f"  Wrote {roc_path}  ({len(roc_curve_rows)} rows)")

    realonly_path = os.path.join(args.out_dir, "flowcorr_realonly_results.csv")
    with open(realonly_path, "w", newline="") as fp:
        fp.write("# Anon-Sec-Net Task B: real-only-\n")
        fp.write("# subsequence TPR, same session pairing/methodology as flowcorr_results.csv\n")
        fp.write("# but scored on each condition's real-only trace (cover packets filtered\n")
        fp.write("# out using generator ground truth, an adversary cannot actually do this\n")
        fp.write("# on the live network; this is a diagnostic upper bound, not a claim about\n")
        fp.write("# what's observable). Purpose: catch cover-drop illusions, if a condition's\n")
        fp.write("# overall TPR (flowcorr_results.csv) drops relative to another condition but\n")
        fp.write("# its real-only TPR here does not drop correspondingly, the apparent\n")
        fp.write("# protection is diluting the correlator with cover noise, not disturbing the\n")
        fp.write("# real traffic's own timing signature, and would not survive an adversary\n")
        fp.write("# that ever gains real/cover ground truth another way.\n")
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        for row in realonly_result_rows:
            w.writerow({
                k: (f"{v:.6g}" if isinstance(v, float) else v)
                for k, v in row.items()
            })
    print(f"  Wrote {realonly_path}  ({len(realonly_result_rows)} rows)")

    if singlevantage_result_rows:
        singlevantage_path = os.path.join(args.out_dir, "flowcorr_singlevantage_results.csv")
        with open(singlevantage_path, "w", newline="") as fp:
            fp.write("# Anon-Sec-Net Task B, packet striping:\n")
            fp.write("# single-vantage-adversary TPR, same session pairing/methodology as\n")
            fp.write("# flowcorr_results.csv but scored using only ONE sub-path's score\n")
            fp.write("# (sub_scores[0], \"Path A\") instead of max(sub_scores) over both.\n")
            fp.write("# Only written for multi-sub-path conditions (asn_both_paths and its\n")
            fp.write("# no-cover variant). Purpose: the joint (max-of-subpaths) score in\n")
            fp.write("# flowcorr_results.csv is expected to sit at ceiling regardless of\n")
            fp.write("# --split-ratio, since striping changes packet-to-path CONTENT, not\n")
            fp.write("# per-path timing, this single-vantage number is the one that\n")
            fp.write("# actually tests striping's claimed protective value (diluting the\n")
            fp.write("# total information ONE compromised path sees), per TrafficSliver's\n")
            fp.write("# own claim. See tier3_striping_scope.md.\n")
            w = csv.DictWriter(fp, fieldnames=fields)
            w.writeheader()
            for row in singlevantage_result_rows:
                w.writerow({
                    k: (f"{v:.6g}" if isinstance(v, float) else v)
                    for k, v in row.items()
                })
        print(f"  Wrote {singlevantage_path}  ({len(singlevantage_result_rows)} rows)")

    print(f"  Wrote illustrative sample traces -> {traces_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
