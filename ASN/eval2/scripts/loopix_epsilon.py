#!/usr/bin/env python3
"""loopix_epsilon.py, Loopix-style likelihood-ratio metric
(epsilon = max |log(p_true/p_impostor)|) for D1/D2/D3, a secondary
statistic alongside TPR@FPR.

Reproduces the exact session-generation call sequence flowcorr_fullpath_
run.py's own --layers 1 CLI path uses (seed=20260710, N=500,
--hardened-jitter, sender_mode=poisson [the default]), so the same 500
sessions that produced the published D1 anchor (TPR@1e-5=0.242,
combined correlator, endpoints mode) are regenerated bit-for-bit,
confirmed below via the anchor check before trusting the epsilon
numbers, matching this script's own reproducibility discipline.

HOW TO RUN
----------
    cd eval2/scripts
    python3 loopix_epsilon.py [--sessions 500] [--seed 20260710]
"""
import argparse
import math
import random
import sys

import flowcorr_run
import flowcorr_fullpath_run as fp


def loopix_epsilon(true_scores, impostor_scores, n_bins=40, alpha=1.0):
    """Histogram-based, Laplace-smoothed max log-likelihood-ratio.
    alpha=1.0 pseudo-observation per bin avoids the degenerate
    "any bin with one-sided support -> epsilon=inf" failure mode a raw
    empirical-density ratio would hit at finite N, explicitly a
    smoothed, finite lower-bound estimate of the true epsilon, not the
    exact supremum, and disclosed as such rather than silently reported
    as if it were exact."""
    lo = min(min(true_scores), min(impostor_scores))
    hi = max(max(true_scores), max(impostor_scores))
    if hi <= lo:
        return 0.0, 0
    width = (hi - lo) / n_bins
    true_counts = [0] * n_bins
    imp_counts = [0] * n_bins

    def bin_of(x):
        b = int((x - lo) / width)
        return min(max(b, 0), n_bins - 1)

    for x in true_scores:
        true_counts[bin_of(x)] += 1
    for x in impostor_scores:
        imp_counts[bin_of(x)] += 1

    n_true, n_imp = len(true_scores), len(impostor_scores)
    max_eps = 0.0
    max_bin = None
    for b in range(n_bins):
        p_true = (true_counts[b] + alpha) / (n_true + alpha * n_bins)
        p_imp = (imp_counts[b] + alpha) / (n_imp + alpha * n_bins)
        eps = abs(math.log(p_true / p_imp))
        if eps > max_eps:
            max_eps = eps
            max_bin = b
    return max_eps, max_bin


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sessions", type=int, default=500)
    ap.add_argument("--seed", type=int, default=20260710)
    ap.add_argument("--sender-mode", default="poisson")
    ap.add_argument("--correlator", default="combined")
    ap.add_argument("--mode", default="endpoints")
    ap.add_argument("--fpr-target", type=float, default=1e-5)
    args = ap.parse_args()

    flowcorr_run.HARDENED_JITTER = True

    rng = random.Random(args.seed)
    sessions = []
    for i in range(args.sessions):
        flow_type = "interactive" if (i % 2 == 0) else "bulk"
        raw = fp.gen_fullpath_session(rng, flow_type, args.sender_mode, True)
        sessions.append(fp.precompute_features(raw))

    print(f"Generated {args.sessions} sessions (seed={args.seed}, hardened, "
          f"sender_mode={args.sender_mode}).\n")

    results = []
    for set_name, cset in fp.LAYER1_SETS.items():
        true_scores, impostor_scores = [], []
        for i in range(args.sessions):
            for j in range(args.sessions):
                s = fp.score_compromise_set(sessions[i], sessions[j], cset,
                                             args.correlator, args.mode)
                (true_scores if i == j else impostor_scores).append(s)

        fpr_results, auc, n_true, n_imp, _, _ = flowcorr_run.roc_tpr_at_fpr(
            true_scores, impostor_scores, [args.fpr_target])
        tpr = fpr_results[args.fpr_target][0]

        eps, max_bin = loopix_epsilon(true_scores, impostor_scores)
        results.append((set_name, tpr, auc, eps))
        print(f"{set_name}: TPR@{args.fpr_target:.0e}={tpr:.3f}  AUC={auc:.4f}  "
              f"Loopix-eps(alpha=1,40 bins)={eps:.3f}  (n_true={n_true}, n_imp={n_imp})")

    if args.sessions == 500 and args.correlator == "combined" and args.mode == "endpoints":
        print(f"\nAnchor check: D1's TPR@1e-5 above should be 0.242 "
              f"(published anchor, combined/endpoints).")
        d1_tpr = next(r[1] for r in results if r[0] == "D1")
        if abs(d1_tpr - 0.242) < 1e-9:
            print("PASS: D1 anchor reproduced exactly.")
        else:
            print(f"MISMATCH: got {d1_tpr}, expected 0.242, DO NOT TRUST these epsilon numbers.")
            sys.exit(1)


if __name__ == "__main__":
    main()
