#!/usr/bin/env python3
"""Active timing watermark/tagging attack.

Every defense mechanism evaluated so far (pool mixing, threshold
batching, reorder window, cover-drop, striping, ...) is evaluated
against a PASSIVE correlator: does an adversary who watches entry and
exit, without perturbing anything, still match sessions? This script
answers a different question: can an adversary who ACTIVELY perturbs
the traffic at entry (an interval-based delay watermark, Wang & Reiter
style) still recover their own watermark at exit despite whatever
passive defense is active? The right metric is bit-error-rate (BER) of
the recovered watermark code, not TPR/FPR, this is a signal-detection
problem, not the matching problem every other script here
solves.

Reuses flowcorr_run.py's gen_session() EXISTING dispatch/defense
pipeline unchanged (via gen_session()'s new real_times_override
parameter), the watermark is injected as a pre-perturbation of the
real-packet-times list BEFORE it enters whatever defense mechanism is
configured (set via the same module-level flags flowcorr_gru.py already
uses this same pattern for: flowcorr_run.POOL_MIXING = ..., etc.).
Currently scoped to single-real_times conditions only (single_path,
single_path_cover, asn_one_path*), asn_both_paths is out of scope for
this initial build.
"""

import argparse
import csv
import os
import random
import sys
import time

import flowcorr_run
from flowcorr_run import gen_session, gen_real_packet_times, SESSION_DURATION_S


def inject_watermark(real_times, code_bits, window_ms: float, delta_ms: float):
    """Delay-based watermark injection (Wang & Reiter style). Partitions
    the session timeline into non-overlapping windows of width
    window_ms (window w = [w*window_ms, (w+1)*window_ms)). Every real
    packet whose ORIGINAL arrival time falls in a window whose code bit
    is 1 gets a TAPERED delay added, delta_ms scaled down linearly to
    0 as the packet's own within-window offset approaches window_ms,
    so no packet can ever cross into the next window; bit=0 windows are
    left untouched. Packets past the last window
    (t >= len(code_bits)*window_ms) are left unmarked, code_bits
    should be sized so window_ms*len(code_bits) covers the full
    SESSION_DURATION_S window.

    The delay is tapered rather than added unconditionally or hard-
    clamped: adding delta_ms unconditionally would let marked packets
    near a window's tail cross into the next window, and when two
    marked windows are consecutive, the migrated-out tail packets land
    at low offsets in the following marked window, dragging its own
    mean back toward baseline and corrupting detectability. A hard
    clamp (min(t+delta_ms, window_end-epsilon)) avoids that but creates
    a pile-up of every near-tail packet at exactly the same clamped
    value, fragile to any subsequent positive perturbation applied
    downstream (e.g. gen_session()'s own small per-hop crypto jitter):
    the whole pile-up gets pushed across the boundary at once by even a
    sub-millisecond nudge. The tapered delay has no boundary to pile up
    against, so it's robust to any downstream perturbation smaller than
    the taper's own margin."""
    marked = []
    for t in real_times:
        w = int(t // window_ms)
        if w < len(code_bits) and code_bits[w] == 1:
            offset = t - w * window_ms
            scaled_delay = delta_ms * (1.0 - offset / window_ms)
            marked.append(t + scaled_delay)
        else:
            marked.append(t)
    return sorted(marked)


def detect_watermark(observed_times, window_ms: float, n_windows: int, delta_ms: float):
    """Differential detection: the detector only sees the OBSERVED
    (post-defense) trace, never the original unmarked positions, so it
    cannot compare against "what it would have looked like unmarked"
    directly. Per window (using the SAME window boundaries AND delta_ms
    the injector used, both known to the attacker, since they chose
    them), compute the mean within-window offset (t mod window_ms) of
    packets whose CURRENT arrival falls in that window. A marked (bit=1)
    window's real packets arrive systematically later within their
    window than an unmarked one's, threshold each window's mean
    offset against the THEORETICAL midpoint between the expected
    unmarked class mean (window_ms/2, exact for a Poisson/uniform-
    arrival process) and the expected marked class mean. For the
    tapered injection above (new_offset = o*(1-delta_ms/window_ms) +
    delta_ms for o ~ Uniform(0,window_ms)), E[new_offset] =
    window_ms/2 + delta_ms/2, so the midpoint between the two class
    means is window_ms/2 + delta_ms/4. Returns a list of n_windows
    recovered bits.

    A fixed, theoretically-grounded threshold is used rather than the
    empirical median of all windows' means in the same trial: for
    even-length code arrays, a median-based threshold with a strict `>`
    comparison means the median element can never decode as 1 even when
    it IS a genuinely marked window; and a short random code has no
    guarantee of a balanced marked/unmarked split (e.g. 5-8 of 8 windows
    marked by chance happens ~50% of the time for L=8), so the empirical
    median can sit INSIDE the marked-window distribution rather than
    between the two, causing systematic misclassification independent
    of sample size or delta magnitude."""
    offsets_by_window = [[] for _ in range(n_windows)]
    for t in observed_times:
        w = int(t // window_ms)
        if w < n_windows:
            offsets_by_window[w].append(t - w * window_ms)
    means = [(sum(o) / len(o) if o else window_ms / 2.0) for o in offsets_by_window]
    threshold = window_ms / 2.0 + delta_ms / 4.0
    return [1 if m > threshold else 0 for m in means]


def compute_ber(injected_bits, recovered_bits) -> float:
    n = len(injected_bits)
    errors = sum(1 for a, b in zip(injected_bits, recovered_bits) if a != b)
    return errors / n


def run_ber_eval(rng: random.Random, condition: str, n_sessions: int,
                  code_length: int, window_ms: float, delta_ms: float):
    """One (condition, code_length, delta_ms) point: n_sessions
    sessions, each with its own random code, injected/detected/scored
    independently. Returns (mean_ber, mean_ber_realonly, n),
    mean_ber uses the full (real+cover-mixed) exit trace, the view a
    real network-level watermark attacker actually has; mean_ber_realonly
    is the same real-only-subsequence diagnostic used elsewhere in this
    evaluation suite (ground-truth-cheating upper bound, not realistically
    observable: see gen_session()'s docstring), included for the same
    reason: if overall BER stays high (~0.5, destroyed) while real-only
    BER is low (watermark recoverable given real/cover ground truth),
    that's the same classifier-confusion signature looked for
    elsewhere in this suite, just for an active
    attacker instead of a passive one."""
    bers, bers_realonly = [], []
    for _ in range(n_sessions):
        flow_type = "interactive" if rng.random() < 0.5 else "bulk"
        real_times = gen_real_packet_times(rng, flow_type, SESSION_DURATION_S)
        code_bits = [rng.randint(0, 1) for _ in range(code_length)]
        marked_real_times = inject_watermark(real_times, code_bits, window_ms, delta_ms)
        sub_paths = gen_session(rng, flow_type, condition,
                                 real_times_override=marked_real_times)
        _entry, exit_, _real_entry, real_exit = sub_paths[0]
        recovered = detect_watermark(exit_, window_ms, code_length, delta_ms)
        bers.append(compute_ber(code_bits, recovered))
        recovered_real = detect_watermark(real_exit, window_ms, code_length, delta_ms)
        bers_realonly.append(compute_ber(code_bits, recovered_real))
    n = len(bers)
    return sum(bers) / n, sum(bers_realonly) / n, n


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sessions", type=int, default=500)
    ap.add_argument("--seed", type=int, default=20260710)
    ap.add_argument("--conditions", type=str,
                     default="single_path,asn_one_path,asn_one_path_entry_cover")
    ap.add_argument("--code-lengths", type=str, default="4,8,16",
                     help="window_ms is computed PER code length as "
                          "SESSION_DURATION_S*1000/L, so every window carries "
                          "packets (full session coverage, no wasted/empty "
                          "trailing windows), see run_ber_eval()'s docstring "
                          "for why the original design (fixed window_ms swept "
                          "against a fixed code-length LIST, per the original "
                          "scope doc's suggested L in {16,32,64,128}) starves "
                          "larger L of packets-per-window at this simulator's "
                          "20s SESSION_DURATION_S and was corrected.")
    ap.add_argument("--delta-frac", type=str, default="0.1,0.2,0.3,0.4",
                     help="Injected delay as a FRACTION of window_ms (not an "
                          "absolute ms value), the achievable BER depends on "
                          "delta relative to window width, not its absolute "
                          "size, so sweeping a fraction stays comparable across "
                          "different code lengths (different window_ms).")
    ap.add_argument("--hardened-jitter", action="store_true",
                     help="see flowcorr_run.py's --hardened-jitter help")
    ap.add_argument("--pool-mixing", action="store_true",
                     help="see flowcorr_run.py's --pool-mixing help, test the "
                          "watermark against the strongest-found "
                          "passive defense.")
    ap.add_argument("--pool-mix-flush-ms", type=float, default=None,
                     help="see flowcorr_run.py's --pool-mix-flush-ms help")
    ap.add_argument("--threshold-batch-size", type=int, default=0,
                     help="see flowcorr_run.py's --threshold-batch-size help")
    ap.add_argument("--out-dir", type=str, default=".")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    flowcorr_run.HARDENED_JITTER = args.hardened_jitter
    flowcorr_run.POOL_MIXING = args.pool_mixing
    if args.pool_mix_flush_ms is not None:
        flowcorr_run.POOL_MIX_FLUSH_MS = args.pool_mix_flush_ms
    flowcorr_run.THRESHOLD_BATCH_SIZE = args.threshold_batch_size

    os.makedirs(args.out_dir, exist_ok=True)
    conditions = args.conditions.split(",")
    code_lengths = [int(x) for x in args.code_lengths.split(",")]
    delta_fracs = [float(x) for x in args.delta_frac.split(",")]

    t0 = time.perf_counter()
    rows = []
    for condition in conditions:
        for code_length in code_lengths:
            window_ms = (SESSION_DURATION_S * 1000.0) / code_length
            for delta_frac in delta_fracs:
                delta_ms = window_ms * delta_frac
                rng = random.Random(args.seed)
                ber, ber_realonly, n = run_ber_eval(
                    rng, condition, args.sessions, code_length, window_ms, delta_ms)
                rows.append({
                    "condition": condition, "code_length": code_length,
                    "window_ms": window_ms, "delta_frac": delta_frac,
                    "delta_ms": delta_ms,
                    "ber": ber, "ber_realonly": ber_realonly, "n_sessions": n,
                })
                if not args.quiet:
                    print(f"  {condition:24s} L={code_length:4d}  window={window_ms:7.1f}ms  "
                          f"delta={delta_ms:6.1f}ms ({delta_frac:.0%})  "
                          f"BER={ber:.4f}  BER(real-only)={ber_realonly:.4f}", flush=True)

    elapsed = time.perf_counter() - t0
    if not args.quiet:
        print(f"\n  Completed in {elapsed:.1f}s\n")

    out_path = os.path.join(args.out_dir, "flowcorr_watermark_results.csv")
    with open(out_path, "w", newline="") as fp:
        fp.write("# Anon-Sec-Net dual-path: active timing watermark\n")
        fp.write("# attack (interval-based delay watermark, Wang & Reiter style).\n")
        fp.write("# BER = bit-error-rate of the recovered watermark code against the\n")
        fp.write("# observed (real+cover-mixed) exit trace, the realistic view a\n")
        fp.write("# network-level watermark attacker actually has. BER~0.5 = watermark\n")
        fp.write("# destroyed (indistinguishable from random guessing); BER~0 = intact.\n")
        fp.write("# ber_realonly: same detection on the real-only-subsequence ground-\n")
        fp.write("# truth view (diagnostic upper bound, not realistically observable --\n")
        fp.write("# see gen_session()'s docstring). A gap between ber and ber_realonly\n")
        fp.write("# is the same classifier-confusion signature applied to an\n")
        fp.write("# active attacker instead of a passive one.\n")
        fields = ["condition", "code_length", "window_ms", "delta_frac", "delta_ms",
                  "ber", "ber_realonly", "n_sessions"]
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v)
                        for k, v in row.items()})
    print(f"  Wrote {out_path}  ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
