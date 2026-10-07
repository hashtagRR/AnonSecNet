#!/usr/bin/env python3
"""
asn_guard_policy_n50.py: Task 1 step 4: repeated-use disclosure risk
under the reference client's actual guard-set entry policy
(`anosecnet.tex`'s Path Construction, `sec:design:pathconstruction`).

WHY THIS EXISTS
---------------------------------------------------------------------------
asn_topology_freshness.py already covers the two extremes: B=1 (fresh
redraw of the entire path every session, item 4's compounding N_50) and
B->infinity (the actual *benchmark harness*'s one-draw-forever fixed
topology, flat risk but certain GPA linkage, see the paper's explicit
scope note that no Figure/Table reflects guard selection, only
`client.exe` implements it). Neither extreme matches the guard-set policy
`client.exe` actually runs: MN1 (path A's entry) and MNa (path B's entry)
persist from a small guard set of size G, each drawn once from a
population of size M with malicious fraction f; MN2/MN3 (path A) and
MNb/MNc (path B) redraw fresh every session, independent of the guard
sets and of each other, matching the base Uniformity assumption for
those four positions only.

D1 (routing-level linkage) needs
only ONE path's entry+exit (the entry-exit-suffices argument,
MN2 and the entirety of path B are provably unnecessary), not all six
positions across both paths. Every distinct disclosure
event needs its own guard-draw composition, see MODEL below.

MODEL
---------------------------------------------------------------------------
K_A (path A's guard draw) and K_B (path B's guard draw) are each drawn
ONCE per client deployment, independently, as Hypergeometric(M,
round(f*M), G) random variables, this is the entire point of a guard
policy, and treating it as anything other than hypergeometric would
silently reintroduce naive per-session re-sampling. Conditional on K_A
(resp. K_B), the per-session probability that THIS session's actual
guard draw from the fixed set is malicious is K_A/G (resp. K_B/G),
fixed for the deployment's lifetime, unlike the fresh positions, which
are independent Bernoulli(f) trials every session exactly as in the base
per-session model (`asn_repeated_sessions.py`).

Per-event guard-conditional per-session probability, derived directly
from Result D1/D2/D3's own corrected counting argument
(`anosecnet.tex:1093-1132`), substituting the guard-conditional ratio for
whichever position is guard-persistent and leaving every fresh position
as an independent f:

    p_D1(K_A)       = (K_A/G) * f            -- MN1 (guard) + MN3 (fresh);
                                                  MN2 and all of path B drop
                                                  out entirely, per Result D1.
    p_D2(K_A)       = (K_A/G) * f^3           -- D1's factor, plus fresh
                                                  SG_R and fresh CS.
    p_D3(K_A, K_B)  = (K_A/G) * (K_B/G) * f^5, D2's factor, plus path B's
                                                  own entry(guard)+exit(fresh)
                                                  by the SAME entry-exit
                                                  argument (MNb drops out,
                                                  exactly as MN2 did for
                                                  D1), plus fresh SG_S.

By construction, E[K/G] = f (Hypergeometric mean), so the EXPECTED
per-session probability over all possible guard draws recovers each
event's own corrected base-model exponent: E[p_D1] = f*f = f^2,
E[p_D2] = f*f^3 = f^4, E[p_D3] = f*f*f^5 = f^7, verified numerically
below, not just asserted.

D1 and D2 depend only on K_A (path A's own guard draw) and are computed
by enumerating the marginal Hypergeometric(M, round(f*M), G) support
directly (G+1 outcomes). D3 depends on both K_A and K_B and is computed
by enumerating the full (G+1) x (G+1) joint support (treating the two
disjoint guard-set draws as independent, a reasonable approximation at
M=100, G=3; the true negative correlation between two disjoint draws
from the same finite population is negligible at this population size).

The point of this script, per event, is the SPREAD around that
expectation, not just the expectation itself: a lucky clean-guard-set
deployment (K_A=0, or for D3 also K_B=0) removes that path's
entry-compromise contribution to p_session entirely, for that
deployment, forever, for D1/D2 this means p_session=0 outright whenever
K_A=0 (D1/D2 need no other guard). An unlucky deployment (a malicious
node lands in the relevant guard set(s)) gets a materially WORSE and,
critically, PERMANENT entry-compromise risk that no amount of subsequent
safe behaviour can dilute, the same concentrated-vs-diluted-exposure
trade-off Tor's own guard design deliberately makes and defends
(Dingledine, Hopper, Kadianakis, Mathewson, "One Fast Guard for Life (or
9 Months)", HotPETs 2014; also cited in the paper's own Path Construction
section as elahi2012guards), not a defect specific to this system's
version of the idea.

WORKED EXAMPLES, f=0.10, G=3 (verify against the CSV before quoting
these anywhere):
  - D1, K_A=G=3 (guard entirely malicious): ratio (K_A/G)=1 drops out,
    p_session = f = 0.10 (MN1 already certain, only MN3's fresh draw
    matters). N_50 = ln(2)/0.10 = 6.93 -> 7 sessions, a deployment this
    unlucky discloses almost immediately.
  - D1, K_A=1 (minimal nonzero): ratio = 1/3, p_session = f/3 = 0.03333.
    N_50 = ln(2)/0.03333 = 20.8 -> 21 sessions.
  - D1, K_A=0 (clean guard, probability (1-f)-weighted... see CSV for
    the exact hypergeometric weight): p_session = 0 exactly, N_50 = inf
    -- this specific mechanism never fires for this deployment, though
    the paper's other findings (GPA-linkability, SDA) are unaffected.
  - D2, K_A=G=3: p_session = f^3 = 1.0e-3. N_50 (log1p-exact, not the
    naive ln(2)/p approximation) = 693 sessions.
  - D2, K_A=1: p_session = f^3/3 = 3.333e-4. N_50 = ln(2)/3.333e-4 =
    2079.4 -> 2080 sessions.

Reuses asn_repeated_sessions.py's cumulative_prob/sessions_to_threshold
exactly (same numerically-stable log1p formulation), applied per
guard-draw outcome rather than to a single scalar p.

CAVEAT: this only closes the compromise-ladder side of the guard-policy
question (does repeated use eventually trigger a D1/D2/D3-type
disclosure). It does NOT model the GPA-linkability side (does a passive
observer learn which G-sized set, or which specific guard, a client
uses), that is a distinct, separately quantifiable question in the same
spirit as asn_gpa_linkability.py, not attempted here.

Usage:
    python asn_guard_policy_n50.py --out-dir .
"""

import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from asn_repeated_sessions import cumulative_prob, sessions_to_threshold

THRESHOLD = 0.50
EVENTS = ("D1", "D2", "D3")


def apply_rho(p_session: float, f: float, rho: float) -> float:
    """Apply the paper's shared-operator mixture model
    (asn_correlated_disclosure.py::analytic_shared_operator) on top of a
    guard-draw-conditional p_session, exactly as it is applied to the
    plain f^k baseline elsewhere in this task: with probability rho, a
    single shared operator secretly governs the whole session at once
    (collapsing to probability f regardless of how the guard draw went);
    otherwise the guard-conditional p_session applies unchanged."""
    return rho * f + (1 - rho) * p_session


def hypergeom_pmf(M: int, K_pop: int, G: int):
    """Exact Hypergeometric(M, K_pop, G) pmf over k=0..G, via math.comb."""
    from math import comb
    total = comb(M, G)
    pmf = []
    for k in range(0, G + 1):
        if k > K_pop or (G - k) > (M - K_pop):
            pmf.append(0.0)
            continue
        pmf.append(comb(K_pop, k) * comb(M - K_pop, G - k) / total)
    return pmf


def p_guard_only(event: str, kA: int, G: int, f: float) -> float:
    """Guard-draw-conditional per-session probability for one event,
    before the rho mixture, see MODEL in the module docstring."""
    ratio_a = kA[0] / G if isinstance(kA, tuple) else kA / G
    if event == "D1":
        return ratio_a * f
    if event == "D2":
        return ratio_a * (f ** 3)
    raise ValueError(event)


def guard_policy_distribution_single(event: str, M: int, G: int, f: float,
                                      rho: float, n_sessions_grid):
    """D1/D2: enumerate the marginal K_A support only (path B is
    irrelevant to both events post-correction)."""
    K_pop = round(f * M)
    pmf = hypergeom_pmf(M, K_pop, G)

    rows = []
    for kA in range(G + 1):
        prob = pmf[kA]
        if prob <= 0.0:
            continue
        pg = p_guard_only(event, kA, G, f)
        p_session = apply_rho(pg, f, rho)
        n50 = sessions_to_threshold(p_session, THRESHOLD)
        row = {
            "K_A": kA, "K_B": "", "draw_prob": prob,
            "p_guard_only": pg,
            "p_session": p_session,
            "N_50": n50 if n50 is not None else float("inf"),
        }
        for n in n_sessions_grid:
            row[f"P_disclosure_by_N{n}"] = cumulative_prob(p_session, n)
        rows.append(row)
    return rows


def guard_policy_distribution_d3(M: int, G: int, f: float, rho: float,
                                  n_sessions_grid):
    """D3: full (G+1) x (G+1) joint K_A x K_B enumeration (both paths'
    guards matter for full bidirectional disclosure)."""
    K_pop = round(f * M)
    pmf = hypergeom_pmf(M, K_pop, G)

    rows = []
    for kA in range(G + 1):
        for kB in range(G + 1):
            prob = pmf[kA] * pmf[kB]
            if prob <= 0.0:
                continue
            pg = (kA / G) * (kB / G) * (f ** 5)
            p_session = apply_rho(pg, f, rho)
            n50 = sessions_to_threshold(p_session, THRESHOLD)
            row = {
                "K_A": kA, "K_B": kB, "draw_prob": prob,
                "p_guard_only": pg,
                "p_session": p_session,
                "N_50": n50 if n50 is not None else float("inf"),
            }
            for n in n_sessions_grid:
                row[f"P_disclosure_by_N{n}"] = cumulative_prob(p_session, n)
            rows.append(row)
    return rows


def summarize(event: str, rows, n_sessions_grid):
    """Probability-weighted summary stats over the guard-draw distribution.
    "Clean" means N_50 == inf, i.e. p_guard_only == 0 exactly, for D1/D2
    this is K_A==0 alone; for D3 it is K_A==0 OR K_B==0 (either guard set
    being clean already zeroes the (K_A/G)*(K_B/G) product), NOT K_A==0
    AND K_B==0, computed directly from N_50 rather than hand-rolled per
    event, to avoid re-introducing that exact off-by-logic bug."""
    p_clean = sum(r["draw_prob"] for r in rows if r["N_50"] == float("inf"))
    p_any_malicious_guard = 1.0 - p_clean
    e_p_session = sum(r["draw_prob"] * r["p_session"] for r in rows)
    bad_bar = 10_000
    p_n50_below_bad_bar = sum(
        r["draw_prob"] for r in rows
        if r["N_50"] != float("inf") and r["N_50"] <= bad_bar
    )
    out = {
        "P(clean guard set(s))": p_clean,
        "P(>=1 malicious guard, relevant set(s))": p_any_malicious_guard,
        "E[p_session] over guard draws": e_p_session,
        f"P(N_50 <= {bad_bar})": p_n50_below_bad_bar,
    }
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--M", type=int, default=100,
                     help="total mix-node population size (default 100)")
    ap.add_argument("--G", type=int, default=3,
                     help="guard set size per entry position (default 3)")
    ap.add_argument("--f-values", default="0.10")
    ap.add_argument("--rho-values", default="0.0,0.01")
    ap.add_argument("--n-grid", default="21,64,100,631,10000,100000,1000000")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    f_values = [float(x) for x in args.f_values.split(",")]
    rho_values = [float(x) for x in args.rho_values.split(",")]
    n_grid = [int(x) for x in args.n_grid.split(",")]

    detail_path = os.path.join(args.out_dir, "guard_policy_n50_detail.csv")
    summary_path = os.path.join(args.out_dir, "guard_policy_n50_summary.csv")

    detail_fields = ["event", "f", "rho", "M", "G", "K_A", "K_B", "draw_prob",
                      "p_guard_only", "p_session", "N_50"] + \
                     [f"P_disclosure_by_N{n}" for n in n_grid]
    summary_rows = []

    with open(detail_path, "w", newline="") as fp:
        fp.write(f"# Guard-set entry policy N_50 distribution, M={args.M}, G={args.G}\n")
        fp.write("# D1: p_guard_only=(K_A/G)*f      (MN1 guard, MN3 fresh; MN2/path B irrelevant)\n")
        fp.write("# D2: p_guard_only=(K_A/G)*f^3    (D1's factor + fresh SG_R, fresh CS)\n")
        fp.write("# D3: p_guard_only=(K_A/G)*(K_B/G)*f^5  (D2's factor + path B entry(guard)+exit(fresh) + fresh SG_S)\n")
        fp.write("# p_session applies the paper's rho shared-operator mixture on top.\n")
        fp.write(f"# K_A,K_B drawn once from Hypergeometric(M={args.M}, round(f*M), G={args.G})\n")
        fp.write("# per client deployment; K_B blank for D1/D2 (not applicable to those events).\n")
        writer = csv.DictWriter(fp, fieldnames=detail_fields)
        writer.writeheader()

        for f in f_values:
            for rho in rho_values:
                for event in EVENTS:
                    if event == "D3":
                        rows = guard_policy_distribution_d3(args.M, args.G, f, rho, n_grid)
                    else:
                        rows = guard_policy_distribution_single(event, args.M, args.G, f, rho, n_grid)
                    for r in rows:
                        out_row = {"event": event, "f": f, "rho": rho,
                                   "M": args.M, "G": args.G, **r}
                        writer.writerow({k: (f"{v:.6e}" if isinstance(v, float) else v)
                                          for k, v in out_row.items()})

                    summ = summarize(event, rows, n_grid)
                    summ_row = {"event": event, "f": f, "rho": rho,
                                "M": args.M, "G": args.G, **summ}
                    summary_rows.append(summ_row)
                    print(f"event={event}  f={f:.2f}  rho={rho}  M={args.M}  G={args.G}")
                    for k, v in summ.items():
                        print(f"    {k}: {v:.6g}")

    with open(summary_path, "w", newline="") as fp:
        fieldnames = list(summary_rows[0].keys())
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        for row in summary_rows:
            writer.writerow({k: (f"{v:.6e}" if isinstance(v, float) else v)
                              for k, v in row.items()})

    print("\nWrote", detail_path)
    print("Wrote", summary_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
