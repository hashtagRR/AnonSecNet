#!/usr/bin/env python3
"""
coverleak_run.py: Task C: cover-traffic load-leakage study

Tests whether ASN's *adaptive* cover discipline (cover suppressed
one-for-one as real traffic is sent, client.c::outbound_cover_thread)
leaks the client's current real-traffic load to a link observer, versus a
Loopix-style constant-rate scheme that should leak ~nothing by
construction. Also evaluates one smoothing mitigation.

WHICH MECHANISM IS "ASN ADAPTIVE", AND A FINDING ABOUT THE EXISTING FIGURE
---------------------------------------------------------------------------
Reading the codebase turned up two DIFFERENT cover mechanisms, not one:

  1. Production `client.c::outbound_cover_thread`: a Poisson cover clock at
     DUMMY_INTERVAL_MS=100ms mean (~10 pkt/s "cover ceiling"), where each
     cover tick is SUPPRESSED if a real packet was sent recently (one real
     packet consumes exactly one subsequent cover-tick credit, see
     g_real_traffic_pending). Real packets are sent immediately over their
     own connection, uncoupled from the cover clock, so real traffic can
     exceed the ~10 pkt/s cover ceiling, and once it does, cover drops to
     zero and the AGGREGATE link rate rises with it. This matches the
     paper's own prose ("when real-traffic volume exceeds the cover
     ceiling, real traffic takes precedence and cover is suspended") and is
     what "ASN adaptive" means in this script.

  2. The benchmark harness used to produce the *existing*
     `results/figure7_cover_overhead_*.csv` figures,
     `tests/ASN/client_instrumented.c`'s `SET_RATE`-driven
     `outbound_cover_thread`: a SINGLE Poisson clock at the same ~10 pkt/s
     rate where EVERY tick is real with probability `load_fraction` and
     cover otherwise (Bernoulli slot substitution). This pins the AGGREGATE
     rate at a constant ~10 pkt/s for every load fraction from 0 to 1,
     structurally unable to leak load by rate, which is exactly Loopix's
     constant-rate design, not ASN's described adaptive one. This script's
     `loopix_constant` scheme reimplements this same mechanism (documented
     as such) and reuses it as the Loopix-style baseline.

    In other words: the existing cover-overhead figure in this repository
    was almost certainly measured under a mechanism that is, structurally,
    the Loopix-style baseline being tested here as the *comparison point*,
    not the adaptive discipline the paper's Design and Discussion sections
    describe and evaluate. This is a separate, previously undocumented
    finding from cross-checking the paper against the code, noted here
    because it directly explains why this potential side channel was never
    caught by the existing benchmark suite: the tool used to sweep "load"
    for Figure 5/7 cannot exhibit it by construction.

SCHEMES
---------------------------------------------------------------------------
  asn_adaptive    : production client.c mechanism (see above). Real-packet
                    Poisson rate = load_level * R_MAX_PPS, uncapped;
                    one-for-one credit suppression of cover.
  loopix_constant : Bernoulli-slot mechanism (see above). Aggregate rate
                    pinned at COVER_CEILING_PPS regardless of load_level;
                    "real" throughput delivered is therefore capped at the
                    ceiling too, the structural cost of a non-leaking
                    constant-rate scheme.
  asn_mitigated   : asn_adaptive with a smoothed (trailing-window,
                    probabilistic) suppression schedule instead of an
                    instantaneous hard on/off credit counter, the
                    "ramp cover down/up over a window" mitigation the task
                    spec suggests.
  asn_hardened    : ASN_LOOPIX_MIXING production mechanism. Real and
                    cover share ONE fixed-rate Poisson
                    dispatch clock at COVER_CEILING_PPS; real packets are
                    queued (bounded depth 64) at a load-scaled arrival rate
                    and drained preferentially each tick, cover fills the
                    rest. Aggregate rate is bounded at the ceiling
                    regardless of load, see gen_hardened_shared_clock()
                    for the design and the earlier, empirically-worse
                    "independent additive cover" attempt this replaced.

ATTACK
---------------------------------------------------------------------------
A global passive adversary observes only the aggregate link stream
(inter-packet timestamps; packet size carries no signal, fixed
WIRE_PACKET_SIZE). For each scheme and each non-idle load level L, a
logistic-regression classifier is trained/evaluated (5-fold CV) on
windowed features (packet count, mean/std/max inter-packet interval per
5s window) to distinguish "idle" windows (load_level=0) from "load_level=L"
windows. Reported per (scheme, load_level): AUC and accuracy of this
active-vs-idle discrimination (Wilson-score 95% CI on accuracy), plus
cover-overhead percentage for that load level.

Usage:
    python coverleak_run.py [--windows 300] [--seed 20260710] [--out-dir .]
"""

import argparse
import csv
import math
import os
import random
import sys
import time

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import roc_auc_score, accuracy_score
from sklearn.preprocessing import StandardScaler

# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------
DUMMY_INTERVAL_MS   = 100.0                  # common/config.h DUMMY_INTERVAL_MS
COVER_CEILING_PPS   = 1000.0 / DUMMY_INTERVAL_MS   # ~10 packets/sec
R_MAX_PPS           = 30.0                   # real-traffic demand at load_level=1.0
SESSION_DURATION_S  = 60.0                   # matches the existing cover-overhead window convention
WINDOW_S            = 5.0                    # classifier feature window
SMOOTH_WINDOW_S     = 3.0                    # asn_mitigated trailing smoothing window
LOAD_LEVELS         = [round(0.1 * i, 1) for i in range(1, 10)]   # 0.1 .. 0.9, matches Figure 5


# ---------------------------------------------------------------------------
# Wilson-score CI
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
# Traffic generation
# ---------------------------------------------------------------------------
def _dispatch_tick_ms(rng: random.Random) -> float:
    """One inter-tick interval for the ~COVER_CEILING_PPS Poisson dispatch/
    cover clock, clamped to [10,1000]ms to match poisson_interval_ms() in
    client.c/sender.c/client_instrumented.c/mix_node.c exactly (config.h's
    DUMMY_INTERVAL_MS mean)."""
    mean_ipi = 1000.0 / COVER_CEILING_PPS
    iv = rng.expovariate(1.0 / mean_ipi)
    if iv < 10.0:
        iv = 10.0
    if iv > 1000.0:
        iv = 1000.0
    return iv


def _real_arrival_tick_ms(rng: random.Random, rate_pps: float) -> float:
    """One inter-arrival interval for the hardened real-packet arrival
    clock, clamped to [1,2000]ms to match real_interval_ms() in
    client_instrumented.c exactly."""
    mean_ipi = 1000.0 / rate_pps
    iv = rng.expovariate(1.0 / mean_ipi)
    if iv < 1.0:
        iv = 1.0
    if iv > 2000.0:
        iv = 2000.0
    return iv


def gen_real_times(rng: random.Random, rate_pps: float, duration_s: float):
    if rate_pps <= 0:
        return []
    times, t, horizon = [], 0.0, duration_s * 1000.0
    mean_ipi = 1000.0 / rate_pps
    while t < horizon:
        t += rng.expovariate(1.0 / mean_ipi)
        if t < horizon:
            times.append(t)
    return times


def gen_cover_asn_adaptive(rng: random.Random, real_times, duration_s: float):
    """client.c's exact one-for-one credit-suppression scheme (reused from
    Task B's flowcorr_run.py::gen_cover_times_with_suppression)."""
    horizon = duration_s * 1000.0
    credits = 0
    real_iter = iter(sorted(real_times))
    next_real = next(real_iter, None)
    cover_times, t = [], 0.0
    while t < horizon:
        t += _dispatch_tick_ms(rng)
        if t >= horizon:
            break
        while next_real is not None and next_real <= t:
            credits += 1
            next_real = next(real_iter, None)
        if credits > 0:
            credits -= 1
        else:
            cover_times.append(t)
    return cover_times


def gen_cover_asn_mitigated(rng: random.Random, real_times, duration_s: float):
    """Smoothed suppression: instead of an instantaneous hard credit
    counter, estimate the real-packet rate over a trailing SMOOTH_WINDOW_S
    window at each cover tick, and suppress PROBABILISTICALLY with
    probability min(1, smoothed_rate / COVER_CEILING_PPS) rather than
    on/off. This ramps cover down/up gradually as load rises/falls instead
    of snapping to zero the instant one real packet is credited."""
    horizon = duration_s * 1000.0
    real_sorted = np.array(sorted(real_times))
    cover_times, t = [], 0.0
    while t < horizon:
        t += _dispatch_tick_ms(rng)
        if t >= horizon:
            break
        window_start = t - SMOOTH_WINDOW_S * 1000.0
        n_recent = int(np.sum((real_sorted >= window_start) & (real_sorted <= t)))
        smoothed_rate = n_recent / SMOOTH_WINDOW_S
        p_suppress = min(1.0, smoothed_rate / COVER_CEILING_PPS)
        if rng.random() >= p_suppress:
            cover_times.append(t)
    return cover_times


QUEUE_DEPTH_HARDENED = 63   # client_instrumented.c's pq_free() reserves one ring-buffer
                            # sentinel slot to distinguish full/empty, PKT_QUEUE_DEPTH=64
                            # but usable capacity is PKT_QUEUE_DEPTH-1


def gen_hardened_shared_clock(rng: random.Random, load_level: float, duration_s: float):
    """ASN_LOOPIX_MIXING production mechanism.

    An independent-clock model, where cover fires on its OWN
    independent Poisson clock unconditionally, additive with real
    traffic sent immediately and uncapped, leaks MORE than a rate-bounded
    mechanism (AUC 0.91-1.0 across nearly every load level, vs. the
    asn_adaptive scheme's 0.48-0.52 through L=0.3): additive
    independent generation removes the one thing that bounds
    aggregate rate at all.

    This mechanism instead: real and cover share ONE fixed-rate Poisson dispatch
    clock (COVER_CEILING_PPS mean, same clock cover always used). Real
    packets "arrive" (become available to send) at a Poisson rate of
    load_level * R_MAX_PPS and are queued (bounded depth
    QUEUE_DEPTH_HARDENED, newest dropped once full, matches
    client_instrumented.c's g_real_q). Each dispatch tick drains the
    real queue preferentially; only sends cover if the real queue is
    empty. This bounds the AGGREGATE observable rate at COVER_CEILING_PPS
    regardless of load_level, only the real/cover split of that fixed
    rate shifts with load, which a passive rate-only observer cannot see.
    Matches production client.c/sender.c's mailbox-priority dispatch and
    client_instrumented.c's real_arrival_thread + single shared
    outbound_cover_thread."""
    horizon = duration_s * 1000.0
    rate_pps = load_level * R_MAX_PPS

    def _arrivals():
        # Matches real_interval_ms()'s clamped draw exactly (not the
        # generic, unclamped gen_real_times, real arrivals in hardened
        # mode are specifically generated by that clamped C function).
        at = 0.0
        while at < horizon and rate_pps > 0:
            at += _real_arrival_tick_ms(rng, rate_pps)
            if at < horizon:
                yield at
    arrivals = iter(_arrivals())
    next_arrival = next(arrivals, None)

    queue_depth = 0
    real_times, cover_times, t = [], [], 0.0
    while t < horizon:
        t += _dispatch_tick_ms(rng)
        if t >= horizon:
            break
        while next_arrival is not None and next_arrival <= t:
            if queue_depth < QUEUE_DEPTH_HARDENED:
                queue_depth += 1
            next_arrival = next(arrivals, None)
        if queue_depth > 0:
            queue_depth -= 1
            real_times.append(t)
        else:
            cover_times.append(t)
    return real_times, cover_times


def gen_loopix_constant(rng: random.Random, target_real_pps: float, duration_s: float,
                          load_fraction: float):
    """Bernoulli-slot constant-rate scheme, matching
    tests/ASN/client_instrumented.c's SET_RATE mechanism exactly: ONE
    Poisson clock at the cover ceiling rate; each tick is real with
    probability load_fraction, cover otherwise. Aggregate rate is pinned
    at COVER_CEILING_PPS regardless of load_fraction, the delivered real
    throughput is therefore capped at COVER_CEILING_PPS * load_fraction,
    which may be less than target_real_pps if target_real_pps exceeds the
    ceiling (the structural throughput cost of a non-leaking scheme)."""
    horizon = duration_s * 1000.0
    real_times, cover_times, t = [], [], 0.0
    while t < horizon:
        t += _dispatch_tick_ms(rng)
        if t >= horizon:
            break
        if rng.random() < load_fraction:
            real_times.append(t)
        else:
            cover_times.append(t)
    return real_times, cover_times


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------
def window_features(times_ms, win_start, win_end):
    in_win = sorted(t for t in times_ms if win_start <= t < win_end)
    count = len(in_win)
    if count >= 2:
        gaps = np.diff(in_win)
        mean_ipi, std_ipi, max_ipi = float(np.mean(gaps)), float(np.std(gaps)), float(np.max(gaps))
    else:
        mean_ipi, std_ipi, max_ipi = WINDOW_S * 1000.0, 0.0, WINDOW_S * 1000.0
    return [count, mean_ipi, std_ipi, max_ipi]


def session_windows(all_times_ms, duration_s: float, window_s: float):
    n_windows = int(duration_s // window_s)
    return [window_features(all_times_ms, i * window_s * 1000.0, (i + 1) * window_s * 1000.0)
            for i in range(n_windows)]


# ---------------------------------------------------------------------------
# Session generators per scheme (return: all observed link times, overhead)
# ---------------------------------------------------------------------------
def gen_session_asn(rng, load_level: float, mitigated: bool):
    real = gen_real_times(rng, load_level * R_MAX_PPS, SESSION_DURATION_S)
    cover = (gen_cover_asn_mitigated if mitigated else gen_cover_asn_adaptive)(
        rng, real, SESSION_DURATION_S)
    overhead = len(cover) / max(1, (len(cover) + len(real))) * 100.0
    return sorted(real + cover), overhead


def gen_session_loopix(rng, load_level: float):
    real, cover = gen_loopix_constant(rng, load_level * R_MAX_PPS, SESSION_DURATION_S, load_level)
    overhead = len(cover) / max(1, (len(cover) + len(real))) * 100.0
    return sorted(real + cover), overhead


def gen_session_hardened(rng, load_level: float):
    """ASN_LOOPIX_MIXING production mechanism (see gen_hardened_shared_clock)."""
    real, cover = gen_hardened_shared_clock(rng, load_level, SESSION_DURATION_S)
    overhead = len(cover) / max(1, (len(cover) + len(real))) * 100.0
    return sorted(real + cover), overhead


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--windows", type=int, default=300,
                     help="Independent 60s sessions per (scheme, load_level) class "
                          "(each yields 12 five-second feature windows)")
    ap.add_argument("--seed", type=int, default=20260710)
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    rng = random.Random(args.seed)
    schemes = ["asn_adaptive", "loopix_constant", "asn_mitigated", "asn_hardened"]

    t0 = time.perf_counter()
    result_rows = []

    def gen_for_scheme(scheme, load_level):
        if scheme == "loopix_constant":
            return gen_session_loopix(rng, load_level)
        if scheme == "asn_hardened":
            return gen_session_hardened(rng, load_level)
        return gen_session_asn(rng, load_level, mitigated=(scheme == "asn_mitigated"))

    for scheme in schemes:
        # Idle reference class (load_level = 0)
        idle_feats = []
        idle_overheads = []
        idle_groups = []
        for sess_idx in range(args.windows):
            times, oh = gen_for_scheme(scheme, 0.0)
            windows = session_windows(times, SESSION_DURATION_S, WINDOW_S)
            idle_feats.extend(windows)
            idle_groups.extend([sess_idx] * len(windows))
            idle_overheads.append(oh)

        for load_level in LOAD_LEVELS:
            load_feats = []
            load_overheads = []
            load_groups = []
            for sess_idx in range(args.windows):
                times, oh = gen_for_scheme(scheme, load_level)
                windows = session_windows(times, SESSION_DURATION_S, WINDOW_S)
                load_feats.extend(windows)
                # Offset past idle_groups' ids, idle and load sessions are
                # independently generated (separate loops above), so their
                # group ids must never collide even though both start at 0.
                load_groups.extend([args.windows + sess_idx] * len(windows))
                load_overheads.append(oh)

            X = np.array(idle_feats + load_feats)
            y = np.array([0] * len(idle_feats) + [1] * len(load_feats))
            # A plain StratifiedKFold split at the WINDOW level would let
            # multiple 5s windows from the SAME 60s session land in both
            # train and test, a session-level leak that lets the
            # classifier partially memorize per-session noise instead of
            # the genuine load-level signal, inflating AUC/accuracy.
            # StratifiedGroupKFold with `groups` keyed on session index
            # keeps every window from one session on the same side of
            # the split.
            groups = np.array(idle_groups + load_groups)

            skf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=args.seed)
            aucs, accs = [], []
            for train_idx, test_idx in skf.split(X, y, groups):
                scaler = StandardScaler().fit(X[train_idx])
                Xtr, Xte = scaler.transform(X[train_idx]), scaler.transform(X[test_idx])
                clf = LogisticRegression(max_iter=1000).fit(Xtr, y[train_idx])
                proba = clf.predict_proba(Xte)[:, 1]
                pred = clf.predict(Xte)
                aucs.append(roc_auc_score(y[test_idx], proba))
                accs.append(accuracy_score(y[test_idx], pred))

            auc_mean, acc_mean = float(np.mean(aucs)), float(np.mean(accs))
            n_test_total = len(y)
            hits = int(round(acc_mean * n_test_total))
            acc_ci = ci95_proportion(hits, n_test_total)
            overhead_pct = float(np.mean(load_overheads))

            result_rows.append({
                "scheme": scheme, "load_level": load_level,
                "attacker_metric": "auc_active_vs_idle",
                "value": auc_mean, "value_ci95": "", "overhead_pct": overhead_pct,
            })
            result_rows.append({
                "scheme": scheme, "load_level": load_level,
                "attacker_metric": "accuracy_active_vs_idle",
                "value": acc_mean, "value_ci95": acc_ci, "overhead_pct": overhead_pct,
            })

            if not args.quiet:
                print(f"  {scheme:16s} L={load_level:.1f}  AUC={auc_mean:.3f}  "
                      f"acc={acc_mean:.3f}  overhead={overhead_pct:.1f}%", flush=True)

    elapsed = time.perf_counter() - t0
    if not args.quiet:
        print(f"\n  Completed in {elapsed:.1f}s\n")

    out_path = os.path.join(args.out_dir, "cover_leakage.csv")
    with open(out_path, "w", newline="") as fp:
        fp.write("# Anon-Sec-Net Task C: cover-traffic load-leakage results\n")
        fp.write(f"# {args.windows} 60s sessions per (scheme, load_level) class, "
                  f"5-fold cross-validated logistic regression\n")
        fp.write("# scheme: asn_adaptive (production client.c credit-suppression) |\n")
        fp.write("#         loopix_constant (Bernoulli-slot fixed-rate, matches\n")
        fp.write("#         tests/ASN/client_instrumented.c's SET_RATE mechanism) |\n")
        fp.write("#         asn_mitigated (asn_adaptive + smoothed trailing-window suppression)\n")
        fp.write("# attacker_metric: auc_active_vs_idle | accuracy_active_vs_idle\n")
        fp.write("#   (binary classifier distinguishing idle windows from load_level windows)\n")
        fp.write("# value_ci95: Wilson-score 95% CI half-width (accuracy only; blank for AUC)\n")
        fields = ["scheme", "load_level", "attacker_metric", "value", "value_ci95", "overhead_pct"]
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        for row in result_rows:
            w.writerow({
                k: (f"{v:.6g}" if isinstance(v, float) else v)
                for k, v in row.items()
            })
    print(f"  Wrote {out_path}  ({len(result_rows)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
