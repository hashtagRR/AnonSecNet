#!/usr/bin/env python3
"""
asn_repeated_sessions.py: Task A follow-up: cumulative disclosure risk
over repeated use (statistical/intersection-attack angle).

WHY THIS EXISTS
---------------------------------------------------------------------------
The disclosure ladder (D1/D2/D3, and its correlated-compromise extension
in this task) is a PER-SESSION, static-compromise model, the paper says
so directly: "the model is a per-session static-compromise model that does
not address adaptive adversaries" (Limitations). Separately, the paper's
own Section on Long-Term Intersection Attacks states its identifier-layer
defence (no persistent cryptographic value across sessions) "addresses the
cryptographic-identifier vector specifically, but is not a general
intersection-attack defence", an explicit admission that the
COMPROMISE-based repeated-use risk (as opposed to the identifier-linking
risk) is not analysed anywhere in the paper.

This script closes that gap using nothing but arithmetic already validated
in this task: if a user makes N independent-path-selection sessions over
time, and each session independently has probability p of triggering a
full disclosure event (Result D1/D2 under this task's rho-parametrised
model), the probability that AT LEAST ONE of those N sessions discloses
the user is:

    P_cumulative(N) = 1 - (1 - p)^N

This is standard "any hit in N independent trials" arithmetic, not a new
statistical model, the contribution is applying it to this system's
already-derived per-session p(f, rho, k), and reporting the practically
meaningful quantity it implies: N_50, the number of sessions at which
cumulative disclosure risk crosses 50%, as a function of f and rho.

CAVEAT (stated once here, not re-derived): this assumes each session's
path selection is independent of prior sessions' (uniform re-sampling of
mix nodes/SG/CS every session, matching the Uniformity assumption already
in the base model). If a real deployment reuses paths or a small node
pool across a user's sessions, disclosure events become positively
correlated across sessions too, and N_50 would be smaller than reported
here: i.e. this script's numbers are, like Result D2 itself, a best
case, not a worst case. This mirrors exactly how the base ladder's f^4
figure is flagged as a best case under the Independence assumption.

Usage:
    python asn_repeated_sessions.py --out-dir .
"""

import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from asn_correlated_disclosure import analytic_shared_operator

EVENTS = {"D1": 2, "D2": 4}


def cumulative_prob(p: float, n: int) -> float:
    """P(at least one disclosure in n independent sessions), numerically
    stable for very small p (uses log1p rather than 1-(1-p)**n directly,
    which underflows to exactly 0.0 for p ~ 1e-8 and large n)."""
    if p <= 0.0:
        return 0.0
    if p >= 1.0:
        return 1.0
    import math
    log_survive = n * math.log1p(-p)
    return -math.expm1(log_survive)


def sessions_to_threshold(p: float, threshold: float):
    """Smallest integer N such that cumulative_prob(p, N) >= threshold,
    or None if p == 0 (never reached)."""
    if p <= 0.0:
        return None
    if p >= threshold:
        return 1
    import math
    # 1-(1-p)^N >= threshold  =>  N >= log(1-threshold) / log(1-p)
    n = math.log(1.0 - threshold) / math.log1p(-p)
    return max(1, int(math.ceil(n)))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--f-values", default="0.05,0.10,0.20")
    ap.add_argument("--rho-values", default="0.0,0.01,0.05,0.1")
    ap.add_argument("--threshold", type=float, default=0.5,
                     help="Cumulative-risk threshold for N_50-style reporting")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    f_values = [float(x) for x in args.f_values.split(",")]
    rho_values = [float(x) for x in args.rho_values.split(",")]
    n_grid = [1, 5, 10, 50, 100, 500, 1_000, 5_000, 10_000, 50_000, 100_000,
              500_000, 1_000_000, 5_000_000, 10_000_000]

    print("=" * 76)
    print("  Task A follow-up: cumulative disclosure risk over repeated sessions")
    print("=" * 76)
    print(f"  Threshold for N_{{{args.threshold:.0%}}}: {args.threshold:.0%} cumulative "
          f"probability of >=1 disclosure event")
    print()

    # -- N_50-style table: sessions until cumulative risk crosses threshold,
    summary_rows = []
    print(f"  {'event':>4} {'f':>6} {'rho':>6}   {'per-session p':>16}   "
          f"{'N_{:.0%}'.format(args.threshold):>14}")
    print("  " + "-" * 60)
    for event, k in EVENTS.items():
        for f in f_values:
            for rho in rho_values:
                p = analytic_shared_operator(f, rho, k)
                n_thresh = sessions_to_threshold(p, args.threshold)
                summary_rows.append({
                    "event": event, "k": k, "f": f, "rho": rho,
                    "per_session_p": p,
                    "n_threshold": n_thresh if n_thresh is not None else "",
                })
                n_str = f"{n_thresh:,}" if n_thresh is not None else "never (p=0)"
                print(f"  {event:>4} {f:>6.2f} {rho:>6.2f}   {p:>16.4e}   {n_str:>14}")
    print()

    summary_path = os.path.join(args.out_dir, "asn_repeated_sessions_n50.csv")
    with open(summary_path, "w", newline="") as fp:
        fp.write("# Task A follow-up: sessions until cumulative disclosure risk\n")
        fp.write(f"# crosses {args.threshold:.0%}, i.e. P(>=1 disclosure in N independent\n")
        fp.write("# sessions) = 1-(1-p)^N >= threshold, solved for N.\n")
        fp.write("# CAVEAT: assumes independent path re-selection each session (see\n")
        fp.write("# docstring), a best case, like the base p(f,rho,k) figures themselves.\n")
        w = csv.DictWriter(fp, fieldnames=["event", "k", "f", "rho", "per_session_p", "n_threshold"])
        w.writeheader()
        for r in summary_rows:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v)
                        for k, v in r.items()})
    print(f"  Wrote {summary_path}  ({len(summary_rows)} rows)")

    # -- Full curves: cumulative probability vs N, for the figure,
    curve_rows = []
    for event, k in EVENTS.items():
        for f in f_values:
            for rho in rho_values:
                p = analytic_shared_operator(f, rho, k)
                for n in n_grid:
                    curve_rows.append({
                        "event": event, "k": k, "f": f, "rho": rho,
                        "n_sessions": n, "cumulative_p": cumulative_prob(p, n),
                    })

    curve_path = os.path.join(args.out_dir, "asn_repeated_sessions_curves.csv")
    with open(curve_path, "w", newline="") as fp:
        fp.write("# Task A follow-up: cumulative disclosure probability vs N sessions\n")
        w = csv.DictWriter(fp, fieldnames=["event", "k", "f", "rho", "n_sessions", "cumulative_p"])
        w.writeheader()
        for r in curve_rows:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v)
                        for k, v in r.items()})
    print(f"  Wrote {curve_path}  ({len(curve_rows)} rows)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
