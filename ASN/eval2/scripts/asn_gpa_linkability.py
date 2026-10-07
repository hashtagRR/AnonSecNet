#!/usr/bin/env python3
"""
asn_gpa_linkability.py: Task A follow-up: quantifying the passive
network-observer (GPA) linkability risk from a static topology.

WHY THIS EXISTS
---------------------------------------------------------------------------
The implementation redraws its 12-node (+SG+CS) topology
exactly once, never per session, contrary to the paper's own Uniformity
assumption. asn_topology_freshness.py quantified the compromise-ladder side of that gap
(N_50(B) = B * N_50(1)) but explicitly left the other, more consequential
side unquantified: a Receiver/Sender that always contacts the identical
fixed entry mix node is trivially linkable across sessions by a *purely
passive* network-level observer, no compromise, no timing correlation,
no learned classifier, just "does this IP always talk to the same first
hop." MN1 (for the Client) and MNi (for
the Sender) are literally the only nodes that ever see the Client/Sender's
real IP address, which is exactly the node whose fixed identity matters
here.

WHAT THIS SCRIPT DOES NOT MODEL, AND WHY THAT'S THE HONEST FRAMING
---------------------------------------------------------------------------
This is not a disclosure-probability ramp like the compromise ladder.
Under the ACTUAL implementation (one entry node, fixed forever), the very
first session a GPA observes already gives certain linkage between that
client IP and "an ASN user", there is no probabilistic model to build
for the actual system, because the answer is deterministic: p=1 from
session 1. Building a fake probabilistic curve for the actual system would
overclaim precision this question doesn't have.

The quantity that DOES vary, and that this script computes, is a
COUNTERFACTUAL comparison: what surveillance cost would a GPA face against
a properly-implemented system that honored the paper's own Uniformity
assumption (a real per-session draw from an entry-node population of size
M), versus the M=1 special case that is what's actually built? This
reuses exactly the same cumulative-probability machinery as
asn_repeated_sessions.py (`sessions_to_threshold`), just applied to a
different per-session probability: instead of "does this session trigger
a full compromise-ladder disclosure," it's "does this session's entry-node
draw land on one of the k nodes a resource-limited GPA can afford to
instrument," p_obs = k/M (capped at 1). This is the standard framing used
in the guard-node-discovery literature (e.g. Tor guard fingerprinting):
an adversary with a fixed vantage-point budget k needs multiple
observations to be confident of linkage against a diverse population, but
gets it for free against a small or fixed one.

Two adversary-strength regimes are reported:
  - PARTIAL GPA: instruments only k of the M candidate entry nodes.
    N_50 = sessions until 50% cumulative chance of >=1 observed session.
  - CERTAIN LINKAGE: minimum k (as a fraction of M) needed for p_obs=1,
    i.e. guaranteed observation on the very first session regardless of
    which node gets drawn. For a properly diverse system this means
    instrumenting the ENTIRE population (k=M); for the actual system
    (M=1) it is trivially k=1, one link is the whole network.

Usage:
    python asn_gpa_linkability.py --out-dir .
"""

import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from asn_repeated_sessions import cumulative_prob, sessions_to_threshold

# M = size of the entry-node population a properly-implemented, per-session
# uniform-random draw (the paper's own Uniformity assumption) would draw
# from. M=1 is what's actually built: a single
# hardcoded MN1 for every Client, every session, forever.
POPULATION_SIZES = [1, 3, 10, 50, 100, 500]

# k = number of entry nodes a resource-limited passive adversary can afford
# to instrument (own, subpoena, or otherwise observe traffic at). These are
# illustrative orders of magnitude, not a claim about any real adversary's
# actual budget, the point is the RATIO k/M, not either number alone.
VANTAGE_BUDGETS = [1, 3, 10]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--population-sizes", default=",".join(str(m) for m in POPULATION_SIZES))
    ap.add_argument("--vantage-budgets", default=",".join(str(k) for k in VANTAGE_BUDGETS))
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    m_values = [int(x) for x in args.population_sizes.split(",")]
    k_values = [int(x) for x in args.vantage_budgets.split(",")]

    print("=" * 86)
    print("  Task A follow-up: GPA vantage-point cost of a passive first-hop")
    print("  linkability attack, as a function of assumed entry-node population size")
    print("=" * 86)
    print(f"  Actual implementation: M=1, every row")
    print(f"  below with M=1 is what's actually deployed today; M>1 rows are the")
    print(f"  counterfactual the paper's own Uniformity assumption describes.")
    print()

    header = f"  {'M (population)':>16}  " + "  ".join(f"N_50(k={k})" for k in k_values) + f"  {'k for certain linkage':>22}"
    print(header)
    print("  " + "-" * (18 + 14 * len(k_values) + 24))

    rows = []
    for m in m_values:
        n50s = []
        for k in k_values:
            k_eff = min(k, m)
            p_obs = k_eff / m
            n50 = sessions_to_threshold(p_obs, args.threshold)
            n50s.append(n50)
            rows.append({
                "population_m": m, "vantage_budget_k": k, "k_effective": k_eff,
                "p_obs_per_session": p_obs, "n_threshold": n50 if n50 is not None else "",
            })
        certain_k = m  # need to instrument the entire population for p_obs=1
        vals_str = "  ".join(f"{(v if v is not None else 'never'):>10}" for v in n50s)
        print(f"  {m:>16}  {vals_str}  {certain_k:>22}")

    print()
    print("  Reading the M=1 row: N_50(k=1)=1 for every k, the actual system gives")
    print("  a GPA that watches the single fixed entry node CERTAIN linkage on the")
    print("  very first session, for free, no matter how small its budget is. This")
    print("  is not a probabilistic risk to weigh against other attacks, it is a")
    print("  deterministic property of a fixed topology.")
    print()
    print("  Reading larger-M rows: a properly diverse deployment forces the SAME")
    print("  k=1 adversary to wait many sessions (N_50 grows linearly with M) before")
    print("  it is even 50% likely to have observed the target even once, and")
    print("  achieving CERTAIN linkage costs instrumenting the entire M-node")
    print("  population, exactly the deployment cost the paper's own Uniformity")
    print("  assumption is meant to impose on an adversary, and exactly what the")
    print("  fixed-topology testbed simplification gives away for free.")

    out_path = os.path.join(args.out_dir, "asn_gpa_linkability.csv")
    with open(out_path, "w", newline="") as fp:
        fp.write("# Task A follow-up: GPA vantage-point cost of passive first-hop linkage.\n")
        fp.write("# population_m: size of the entry-node population a per-session uniform\n")
        fp.write("#   draw would use (M=1 is the actual implementation).\n")
        fp.write("# vantage_budget_k / k_effective: number of entry nodes the adversary\n")
        fp.write("#   instruments (capped at M).\n")
        fp.write("# p_obs_per_session = k_effective / population_m.\n")
        fp.write("# n_threshold: sessions until cumulative P(>=1 observed) >= threshold.\n")
        w = csv.DictWriter(fp, fieldnames=["population_m", "vantage_budget_k", "k_effective",
                                            "p_obs_per_session", "n_threshold"])
        w.writeheader()
        for r in rows:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v)
                        for k, v in r.items()})
    print()
    print(f"  Wrote {out_path}  ({len(rows)} rows)")

    # -- Full curves (cumulative P(>=1 observed) vs N) for the figure,
    n_grid = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1_000, 2_000, 5_000, 10_000]
    curve_rows = []
    for m in m_values:
        for k in k_values:
            k_eff = min(k, m)
            p_obs = k_eff / m
            for n in n_grid:
                curve_rows.append({
                    "population_m": m, "vantage_budget_k": k,
                    "n_sessions": n, "cumulative_p": cumulative_prob(p_obs, n),
                })
    curve_path = os.path.join(args.out_dir, "asn_gpa_linkability_curves.csv")
    with open(curve_path, "w", newline="") as fp:
        fp.write("# Task A follow-up: cumulative P(>=1 observed session) vs N sessions,\n")
        fp.write("# for a GPA with vantage budget k against entry-node population M.\n")
        w = csv.DictWriter(fp, fieldnames=["population_m", "vantage_budget_k",
                                            "n_sessions", "cumulative_p"])
        w.writeheader()
        for r in curve_rows:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v)
                        for k, v in r.items()})
    print(f"  Wrote {curve_path}  ({len(curve_rows)} rows)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
