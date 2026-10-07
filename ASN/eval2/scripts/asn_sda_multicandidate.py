#!/usr/bin/env python3
"""
asn_sda_multicandidate.py: Task 4: multi-candidate extension of the
single-candidate Wald SPRT statistical disclosure attack in
asn_statistical_disclosure.py (Table 6 / Section 4.10).

WHY THIS EXISTS
---------------------------------------------------------------------------
Section 4.10's SPRT models ONE candidate (sender, receiver) pair tested
against ONE decoy population via a single sequence of rounds, and says so
explicitly: "this models identification of one candidate against one decoy
population implicitly via the FPR; a real multi-candidate SDA testing many
decoys simultaneously requires a multi-hypothesis extension (e.g.
Bonferroni-corrected) not built here." This script builds it.

MODEL
---------------------------------------------------------------------------
K candidates are tested simultaneously: exactly one is the true
correspondent (H1), the other K-1 are decoys (H0), all sharing the SAME
per-round (TPR, FPR) operating point from asn_statistical_disclosure.py's
OPERATING_POINTS (imported, not re-measured). Each candidate runs its own
independent SPRT sequence of rounds against that specific candidate. The
adversary's problem is now a multiple-testing one: across K simultaneous
tests, what is the probability that AT LEAST ONE decoy is wrongly flagged
as the correspondent (family-wise false-identification), and how many
rounds does correctly identifying the true correspondent take?

Two corrections are implemented, matching the task's explicit requirement
to report both rather than only the conservative one:

  BONFERRONI (exact, controls family-wise error rate). The per-candidate
  Wald boundary is recomputed with alpha' = alpha/K instead of alpha
  (wald_boundaries(alpha/K, beta) from asn_statistical_disclosure.py,
  unchanged otherwise). Because the K SPRTs are run on independent
  observation streams (a structural assumption already stated in the base
  script: flow-correlation evidence about candidate i says nothing about
  candidate j), this exactly controls P(>=1 false accept among the K-1
  decoys) <= alpha, verified here by direct Monte Carlo simulation of all
  K parallel SPRTs together, not by trusting the asymptotic formula alone.

  BENJAMINI-HOCHBERG (approximate; a named, honest approximation, not a
  rigorous sequential-FDR method). Classical BH needs a fixed p-value per
  completed test; an SPRT's stopping time is data-dependent, and rigorous
  sequential-FDR control (e.g. Foster & Stine's alpha-investing, online-FDR
  methods) is a distinct, larger literature this script does not attempt
  to implement. Instead: every candidate's SPRT runs to completion under
  the UNCORRECTED (base) alpha/beta boundary; a candidate that stops at
  "accept H1" with cumulative log-likelihood-ratio L is assigned an
  approximate one-sided p-value p = exp(-L), the classical asymptotic Wald
  relationship between boundary height and false-accept probability (the
  same relationship that motivates A = ln((1-beta)/alpha) ~= ln(1/alpha)
  for small beta, i.e. alpha ~= exp(-A) is the design-time version of
  this same approximation, not a new assumption introduced here). A
  candidate that stops at "accept H0" is assigned p=1 (no positive
  evidence to correct for). The standard BH step-up procedure is then
  applied to these K proxy p-values at level q=alpha to decide which
  "accept H1" calls survive. This is explicitly an approximation and is
  labelled as such in every place it is reported.

Both procedures are evaluated at the paper's own two headline operating
points (Section 4.10 Table 6): the strict FPR=1e-3 point (fixed
correlator, dual-path, TPR=0.55) and the weakest measured point,
FPR=0.1 (TPR=0.72), with alpha=beta=0.01 as in the base script.

Usage:
    python asn_sda_multicandidate.py --trials 5000 --seed 20260718 --out-dir .
"""

import argparse
import csv
import math
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from asn_statistical_disclosure import (
    wald_boundaries, per_round_llr_terms, OPERATING_POINTS,
)

# The paper's two headline operating points (Table 6), derived from
# OPERATING_POINTS by label rather than hand-typed, a hand-typed copy
# here previously drifted from the source (0.55 vs the correct 0.545 for
# fixed_both_paths_fpr1e-3), the same drift-prone anti-pattern already
# fixed once in asn_combined_bc_adversary.py.
_by_label = {label: (label, fpr, tpr)
             for label, correlator, vantage, fpr, tpr in OPERATING_POINTS}
HEADLINE_STRICT = _by_label["fixed_both_paths_fpr1e-3"]
HEADLINE_WEAKEST = _by_label["fixed_both_paths_fpr1e-1"]

ALPHA = BETA = 0.01
K_VALUES = [1, 10, 100, 1000]


def run_one_sprt(tpr, fpr, A, Bb, llr_m, llr_nm, true_hypothesis, rng,
                  max_rounds=200_000):
    """One SPRT run against a single candidate. Returns (decision, rounds,
    final_llr) where final_llr is the LLR value at the stopping round
    (used only for the BH p-value proxy)."""
    p_match = tpr if true_hypothesis == "H1" else fpr
    llr = 0.0
    rounds = 0
    while rounds < max_rounds:
        rounds += 1
        match = rng.random() < p_match
        llr += llr_m if match else llr_nm
        if llr >= A:
            return "H1", rounds, llr
        if llr <= Bb:
            return "H0", rounds, llr
    return ("H1" if llr > (A + Bb) / 2 else "H0"), rounds, llr


def benjamini_hochberg(pvalues, q):
    """Standard BH step-up. Returns the set of original indices flagged as
    discoveries at FDR level q."""
    m = len(pvalues)
    indexed = sorted(enumerate(pvalues), key=lambda x: x[1])
    cutoff_rank = 0
    for rank, (_idx, p) in enumerate(indexed, start=1):
        if p <= (rank / m) * q:
            cutoff_rank = rank
    if cutoff_rank == 0:
        return set()
    return {indexed[i][0] for i in range(cutoff_rank)}


def simulate_bonferroni(tpr, fpr, K, n_trials, rng):
    """Exact Bonferroni: per-candidate boundary uses alpha/K. Runs K
    parallel SPRTs (1 true H1 + K-1 true H0) per trial, n_trials times."""
    alpha_corrected = ALPHA / K
    A, Bb = wald_boundaries(alpha_corrected, BETA)
    llr_m, llr_nm = per_round_llr_terms(tpr, fpr)

    true_pair_rounds = []
    true_pair_correct = 0
    trials_with_false_id = 0

    for _ in range(n_trials):
        d1, r1, _ = run_one_sprt(tpr, fpr, A, Bb, llr_m, llr_nm, "H1", rng)
        true_pair_rounds.append(r1)
        if d1 == "H1":
            true_pair_correct += 1

        any_false_id = False
        for _ in range(K - 1):
            d0, _r0, _ = run_one_sprt(tpr, fpr, A, Bb, llr_m, llr_nm, "H0", rng)
            if d0 == "H1":
                any_false_id = True
        if any_false_id:
            trials_with_false_id += 1

    true_pair_rounds.sort()
    n = len(true_pair_rounds)
    return {
        "alpha_corrected": alpha_corrected,
        "median_rounds_true_pair": true_pair_rounds[n // 2],
        "mean_rounds_true_pair": sum(true_pair_rounds) / n,
        "true_pair_detection_rate": true_pair_correct / n_trials,
        "family_wise_false_id_rate": trials_with_false_id / n_trials,
    }


def simulate_bh(tpr, fpr, K, n_trials, rng):
    """Approximate BH: all K SPRTs run under the UNCORRECTED boundary,
    p-value proxies computed, BH step-up applied at q=ALPHA."""
    A, Bb = wald_boundaries(ALPHA, BETA)
    llr_m, llr_nm = per_round_llr_terms(tpr, fpr)

    true_pair_rounds = []
    true_pair_survives_bh = 0
    trials_with_false_id = 0

    for _ in range(n_trials):
        decisions = []
        rounds_list = []
        llrs = []

        d1, r1, l1 = run_one_sprt(tpr, fpr, A, Bb, llr_m, llr_nm, "H1", rng)
        decisions.append(d1); rounds_list.append(r1); llrs.append(l1)
        true_pair_rounds.append(r1)

        for _ in range(K - 1):
            d0, r0, l0 = run_one_sprt(tpr, fpr, A, Bb, llr_m, llr_nm, "H0", rng)
            decisions.append(d0); rounds_list.append(r0); llrs.append(l0)

        pvalues = [
            min(1.0, math.exp(-llrs[i])) if decisions[i] == "H1" else 1.0
            for i in range(K)
        ]
        flagged = benjamini_hochberg(pvalues, ALPHA)

        if 0 in flagged:
            true_pair_survives_bh += 1
        if any(i in flagged for i in range(1, K)):
            trials_with_false_id += 1

    true_pair_rounds.sort()
    n = len(true_pair_rounds)
    return {
        "median_rounds_true_pair": true_pair_rounds[n // 2],
        "mean_rounds_true_pair": sum(true_pair_rounds) / n,
        "true_pair_detection_rate": true_pair_survives_bh / n_trials,
        "family_wise_false_id_rate": trials_with_false_id / n_trials,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trials", type=int, default=5000,
                     help="Monte Carlo trials per (operating point, K, correction method)")
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--seed", type=int, default=20260718)
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    rng = random.Random(args.seed)

    print("=" * 88)
    print("  Task 4: multi-candidate SDA (Bonferroni + Benjamini-Hochberg)")
    print("=" * 88)

    rows = []
    for label, fpr, tpr in (HEADLINE_STRICT, HEADLINE_WEAKEST):
        for K in K_VALUES:
            bonf = simulate_bonferroni(tpr, fpr, K, args.trials, rng)
            bh = simulate_bh(tpr, fpr, K, args.trials, rng)
            row = {
                "operating_point": label, "fpr": fpr, "tpr": tpr, "K": K,
                "alpha": ALPHA, "beta": BETA,
                "bonf_alpha_corrected": bonf["alpha_corrected"],
                "bonf_median_rounds_true_pair": bonf["median_rounds_true_pair"],
                "bonf_mean_rounds_true_pair": bonf["mean_rounds_true_pair"],
                "bonf_true_pair_detection_rate": bonf["true_pair_detection_rate"],
                "bonf_family_wise_false_id_rate": bonf["family_wise_false_id_rate"],
                "bh_median_rounds_true_pair": bh["median_rounds_true_pair"],
                "bh_mean_rounds_true_pair": bh["mean_rounds_true_pair"],
                "bh_true_pair_detection_rate": bh["true_pair_detection_rate"],
                "bh_family_wise_false_id_rate": bh["family_wise_false_id_rate"],
            }
            rows.append(row)
            print(f"  {label:26s} K={K:5d}  "
                  f"Bonf: median={bonf['median_rounds_true_pair']:4d} "
                  f"det={bonf['true_pair_detection_rate']:.3f} "
                  f"FWfalseID={bonf['family_wise_false_id_rate']:.4f}  |  "
                  f"BH: median={bh['median_rounds_true_pair']:4d} "
                  f"det={bh['true_pair_detection_rate']:.3f} "
                  f"FWfalseID={bh['family_wise_false_id_rate']:.4f}")

    out_path = os.path.join(args.out_dir, "asn_sda_multicandidate.csv")
    with open(out_path, "w", newline="") as fp:
        fp.write("# Multi-candidate SDA: Bonferroni (exact, alpha/K boundary) vs.\n")
        fp.write("# Benjamini-Hochberg (approximate p-value-proxy step-up, q=alpha)\n")
        fp.write(f"# alpha=beta={ALPHA}, trials={args.trials}, seed={args.seed}\n")
        writer = csv.DictWriter(fp, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v)
                              for k, v in row.items()})
    print("\nWrote", out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
