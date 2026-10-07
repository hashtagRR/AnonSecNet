#!/usr/bin/env python3
"""
asn_topology_freshness.py: Task A follow-up: how topology-redraw
frequency changes the repeated-session disclosure risk from
asn_repeated_sessions.py, given the actual implementation redraws never.

WHY THIS EXISTS
---------------------------------------------------------------------------
Item 4's N_50 figures (asn_repeated_sessions.py) assume every session
independently redraws its path from the populations M/G/C, matching the
paper's own Uniformity assumption ("each component selected for a session
is drawn uniformly at random from its population"). Checking that
assumption against the code (while scoping this follow-up) found it is
NOT implemented anywhere: client.c/sender.c hardcode a fixed 12-node
(+SG+CS) topology via config.h #define constants; there is no
node-selection logic, and the only rand() calls in the routing code are
for the cover-traffic Poisson clock.

This script quantifies what that gap actually means for repeated-session
risk, parametrized by B = the number of consecutive sessions that share
one topology draw before a fresh one happens (B=1 recovers item 4's
numbers exactly; B->infinity is the current prototype's literal behavior
-- one draw, forever).

THE RELATIONSHIP (closed form, no new simulation needed)
---------------------------------------------------------------------------
With batch size B, N total sessions contain only ceil(N/B) independent
draws (not N), so:

    P(>=1 disclosure in N sessions | batch B) = 1 - (1-p)^ceil(N/B)

and therefore N_50(B) = B * N_50(1) (exactly when N/B is an integer),
where N_50(1) is item 4's already-computed fresh-redraw figure. As
B -> infinity, only ONE draw ever happens for that deployment's whole
lifetime: cumulative risk is flat at p forever and N_50 is undefined
(never reached) whenever p < threshold, which holds for every f, rho, k
combination in this task's realistic range.

THE TWO-SIDED IMPLICATION (stated here, not modelled further)
---------------------------------------------------------------------------
A static topology being SAFER against the compromise-based disclosure
ladder is only one side of the picture. A Receiver that always contacts
the identical fixed set of mix nodes is trivially linkable across
sessions by a purely passive network-level observer, no node
compromise, no timing correlation, no learned classifier required, just
"does this Receiver always talk to the same first hop." This is the same
vulnerability class as Tor guard-fingerprinting in the literature, and it
would directly undermine the paper's claimed GPA-resistance (Sec.
"Resistance against the Global Passive Adversary") if the fixed-topology
behavior found here is anything more than a testbed simplification.
Quantifying THAT risk is a distinct, larger piece of work this script
does not attempt, this script only closes the compromise-ladder side
of the question.

Usage:
    python asn_topology_freshness.py --out-dir .
"""

import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from asn_correlated_disclosure import analytic_shared_operator
from asn_repeated_sessions import sessions_to_threshold

EVENTS = {"D2": 4}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--f", type=float, default=0.10)
    ap.add_argument("--rho-values", default="0.0,0.01,0.05,0.1")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--batch-sizes", default="1,10,100,1000,10000")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    rho_values = [float(x) for x in args.rho_values.split(",")]
    batch_sizes = [int(x) for x in args.batch_sizes.split(",")]

    print("=" * 78)
    print("  Task A follow-up: topology-redraw frequency vs. repeated-session risk")
    print("=" * 78)
    print(f"  f={args.f:.2f}, threshold={args.threshold:.0%}, event=D2 (k=4)")
    print()
    print(f"  {'rho':>6}   {'per-session p':>16}   " +
          "   ".join(f"N_50(B={b})" for b in batch_sizes))
    print("  " + "-" * (30 + 14 * len(batch_sizes)))

    rows = []
    for rho in rho_values:
        p = analytic_shared_operator(args.f, rho, EVENTS["D2"])
        n50_fresh = sessions_to_threshold(p, args.threshold)
        vals = []
        for b in batch_sizes:
            n50_b = None if n50_fresh is None else b * n50_fresh
            vals.append(n50_b)
            rows.append({
                "f": args.f, "rho": rho, "per_session_p": p,
                "batch_size": b, "n_threshold": n50_b if n50_b is not None else "",
            })
        val_strs = [f"{v:,}" if v is not None else "never" for v in vals]
        print(f"  {rho:>6.2f}   {p:>16.4e}   " + "   ".join(f"{s:>12}" for s in val_strs))

    print()
    print("  Current prototype's ACTUAL behavior: B=infinity --")
    print("  topology drawn ONCE, never redrawn. Cumulative risk is flat at the")
    print("  per-session p forever; N_50 is never reached for any p<0.5 (true for")
    print("  every row above). Counter-intuitively, this is SAFER against the")
    print("  compromise-based disclosure ladder than the paper's own stated")
    print("  Uniformity assumption (fresh redraw every session, B=1) would be --")
    print("  but see the docstring for the network-level")
    print("  linkability risk this same fixed-topology behavior introduces, which")
    print("  is NOT captured by this (or any) compromise-based analysis.")

    out_path = os.path.join(args.out_dir, "asn_topology_freshness.csv")
    with open(out_path, "w", newline="") as fp:
        fp.write("# Task A follow-up: N_50 vs topology-redraw batch size B\n")
        fp.write("# B=1 matches asn_repeated_sessions.py's fresh-redraw figures exactly.\n")
        fp.write("# B=infinity (not representable in this table) is the current\n")
        fp.write("# prototype's literal behavior, see docstring.\n")
        w = csv.DictWriter(fp, fieldnames=["f", "rho", "per_session_p", "batch_size", "n_threshold"])
        w.writeheader()
        for r in rows:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v)
                        for k, v in r.items()})
    print(f"\n  Wrote {out_path}  ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
