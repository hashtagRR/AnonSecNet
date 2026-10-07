#!/usr/bin/env python3
"""
asn_ablation_disclosure.py: Task A follow-up: ablating the two design
elements behind the disclosure ladder's D2 figure.

WHY THIS EXISTS
---------------------------------------------------------------------------
The paper's novelty claim rests on COMBINING two design elements:
  1. Dual-path routing (two disjoint 3-hop paths instead of Tor's one).
     Under the Correlation-capability assumption, routing-level linkage
     only requires the entry+exit of ONE path (Result D1: f^2), so
     dual-path routing contributes NOTHING to the mix-network-position
     exponent over a single path's own entry-exit correlation, both are
     f^2, identical to Tor's own entry-exit figure.
  2. Role-decoupled infrastructure (Service Gateway and Cache Server drawn
     from operator populations distinct from the mix nodes), which adds
     two more independently-compromised positions on top of whichever
     routing is used.

Nothing in the paper or in Task A isolates which element does the work.
A reviewer can reasonably ask: would either alone get you most of the
benefit? This ablation answers that directly, using the paper's own
counting-argument exponents (Results D1/D2) combined with Task A's
correlated-compromise machinery (imported directly, not reimplemented) to
see whether the answer changes once independence is relaxed.

THE FOUR CONFIGURATIONS (paper's own component-counting logic, corrected)
---------------------------------------------------------------------------
  baseline        : single path, no role decoupling.      f^3  (Tor hidden service)
  dual_path_only  : two paths, no role decoupling.         f^2  (= Event D1)
  role_decouple_only : single path, +SG+CS role separation. f^4  (single-path+SG+CS,
                        the second baseline already used in the paper's Table)
  both (ASN)      : two paths + role separation.            f^4  (= Event D2, ASN's
                        actual design)

Under the corrected counting argument, dual_path_only and both_asn are NOT
additive extensions of role_decouple_only, dual-path routing contributes
a zero exponent increment (2 -> 2 is really "no routing-level gain over a
single path's own entry-exit", not "+3 positions"), so role_decouple_only
and both_asn land on the exact same exponent (f^4). This is the headline
finding: dual-path routing provides zero analytical benefit once
independence-correlation is accounted for, and it is role-decoupling alone
that does all the work. This script's contribution is checking whether
that finding survives Task A's correlated-compromise model as rho rises.

Usage:
    python asn_ablation_disclosure.py --out-dir .
"""

import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from asn_correlated_disclosure import analytic_shared_operator, crossover_rho

CONFIGS = {
    "baseline_single_path":    3,   # Tor hidden service, f^3
    "dual_path_only":          2,   # Event D1, f^2
    "role_decouple_only":      4,   # single-path + SG+CS, f^4
    "both_asn":                4,   # Event D2, f^4 (ASN's actual design;
                                     # identical to role_decouple_only)
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--f-grid-lo", type=float, default=0.01)
    ap.add_argument("--f-grid-hi", type=float, default=0.99)
    ap.add_argument("--f-grid-n", type=int, default=99)
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    baseline_k = CONFIGS["baseline_single_path"]

    # -- Table 1: additivity check at rho=0 (pure independence) ----------
    print("=" * 70)
    print("  Additivity check at rho=0 (independence): is the combination")
    print("  exactly what you'd get from adding each element's own gain?")
    print("=" * 70)
    for f in (0.05, 0.1, 0.2, 0.3):
        vals = {name: analytic_shared_operator(f, 0.0, k) for name, k in CONFIGS.items()}
        print(f"  f={f:.2f}  baseline(f^3)={vals['baseline_single_path']:.3e}  "
              f"dual_path(f^2)={vals['dual_path_only']:.3e}  "
              f"role_decouple(f^4)={vals['role_decouple_only']:.3e}  "
              f"both(f^4)={vals['both_asn']:.3e}")
    print()
    print("  (dual_path_only == baseline_single_path's own entry-exit figure")
    print("   f^2, not a further-raised exponent, dual-path routing does not")
    print("   compose additively with role-decoupling under the corrected")
    print("   counting argument. role_decouple_only and both_asn are IDENTICAL")
    print("   (f^4): dual-path contributes nothing on top of role-decoupling.")
    print("   The rho sweep below checks whether this holds as correlation rises.)")
    print()

    # -- Crossover rho*(f) for each configuration vs the single-path baseline,
    f_grid = [args.f_grid_lo + i * (args.f_grid_hi - args.f_grid_lo) / (args.f_grid_n - 1)
              for i in range(args.f_grid_n)]

    rows = []
    for name, k in CONFIGS.items():
        if name == "baseline_single_path":
            continue
        for f in f_grid:
            baseline_prob = f ** baseline_k
            rho_star = crossover_rho(f, k, baseline_prob)
            rows.append({"config": name, "k": k, "f": f,
                         "rho_star": "" if rho_star is None else rho_star})

    out_path = os.path.join(args.out_dir, "asn_ablation_crossover.csv")
    with open(out_path, "w", newline="") as fp:
        fp.write("# Task A follow-up: crossover rho* for each design element in isolation,\n")
        fp.write("# all measured against the single-path f^3 baseline (Tor hidden service).\n")
        fp.write("# config: dual_path_only (f^2) | role_decouple_only (f^4) | both_asn (f^4, ASN's actual design)\n")
        fp.write("# rho_star: correlation at which this config's disclosure probability rises\n")
        fp.write("# to equal the f^3 baseline (empty = no crossover in [0,1] at this f)\n")
        w = csv.DictWriter(fp, fieldnames=["config", "k", "f", "rho_star"])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"  Wrote {out_path}  ({len(rows)} rows)")

    # Headline numbers at f=0.1 (the deployment-realistic point Task A uses)
    print()
    print("  Headline: crossover rho* vs Tor f^3 baseline, at f=0.10")
    print("  " + "-" * 55)
    for name, k in CONFIGS.items():
        if name == "baseline_single_path":
            continue
        baseline_prob = 0.10 ** baseline_k
        rho_star = crossover_rho(0.10, k, baseline_prob)
        rs = f"{rho_star:.4f}" if rho_star is not None else "no crossover in [0,1]"
        print(f"    {name:22s} (f^{k})  rho* = {rs}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
