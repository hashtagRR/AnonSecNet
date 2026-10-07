#!/usr/bin/env python3
"""
asn_combined_bc_adversary.py: Task A/B/C follow-up: a GPA that uses
Task B's flow-correlation signal AND Task C's activity-level-leakage
signal SIMULTANEOUSLY, rather than either alone.

WHY THIS EXISTS
---------------------------------------------------------------------------
No adversary that
combines Task C's activity-leakage signal with Task B's flow-correlation
signal had been evaluated before this: a realistic adversary would use both
simultaneously, and nothing in the prior work modeled their
combination. Both attacks are real, both are already measured (Task B:
flowcorr_run.py/flowcorr_ml.py; Task C: coverleak_run.py), what's
missing is putting them together within a single adversary decision.

MODEL
---------------------------------------------------------------------------
This reuses the Wald-SPRT accumulation machinery already built for the
statistical disclosure attack (asn_statistical_disclosure.py), extended
from "many rounds of the SAME evidence channel" to "one round with TWO
evidence channels combined." Per observed session, the adversary computes:

  1. A flow-correlation decision (Task B's `combined` correlator,
     asn_both_paths condition, reusing flowcorr_run.py's TPR/FPR at a
     chosen operating point).
  2. An activity-level decision (Task C's logistic-regression classifier,
     asn_adaptive scheme, reusing coverleak_run.py's exact session/window
     generators and 5-fold-CV pipeline, re-run here rather than
     re-implemented, at the load level already identified as
     the AUC-0.9 detection transition, L=0.5).

Treating the two channels as CONDITIONALLY INDEPENDENT given the true
hypothesis (an approximation, see Limitations below, both ultimately
derive from the same underlying real-traffic process, but they measure
genuinely different statistics: Task B measures INTER-PATH timing/volume
correlation, Task C measures SINGLE-PATH packet-count distribution shape
-- there is no obvious mechanism coupling them beyond the shared "is this
session actually carrying the target's real traffic" ground truth, which
IS the thing being tested, not a confound of the test itself), their
log-likelihood-ratio contributions from a single joint observation add:

    LLR_combined = LLR_flowcorr + LLR_activity

This is fed into the identical Wald SPRT boundaries used in
asn_statistical_disclosure.py, and the resulting rounds-to-confident-ID is
compared against running EITHER channel alone.

Usage:
    python asn_combined_bc_adversary.py --seed 20260710 --out-dir .
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
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flowcorr_run import roc_tpr_at_fpr
from coverleak_run import (
    SESSION_DURATION_S, WINDOW_S, R_MAX_PPS,
    gen_session_asn, session_windows,
)
from asn_statistical_disclosure import (
    wald_boundaries, per_round_llr_terms, simulate_sprt, OPERATING_POINTS,
)

# Task B's already-measured operating points (asn_both_paths, combined
# correlator: flowcorr_results.csv). Not re-measured here. Derived from
# asn_statistical_disclosure.py's OPERATING_POINTS (the actual source of
# truth, itself checked against flowcorr_results.csv) instead of a second,
# independently hand-typed copy, so the two can never drift out of sync.
FLOWCORR_TPR_FPR = {
    fpr: tpr for label, correlator, vantage, fpr, tpr in OPERATING_POINTS
    if correlator == "combined" and vantage == "asn_both_paths"
}

# Headline single-point load level for the activity-level channel: L=0.5,
# the AUC-0.9 detection transition point (the "chance-to-near-total-
# detection" crossover). Kept as
# the default for --load; the full LOAD_LEVELS sweep below (--load-sweep)
# covers other load levels.
ACTIVITY_LOAD_LEVEL = 0.5

# Same load-level grid Task C itself swept (coverleak_run.py's own
# LOAD_LEVELS, matching Figure 5), reused here rather than a
# fresh choice, so this sweep is directly comparable point-for-point.
LOAD_LEVELS = [round(0.1 * i, 1) for i in range(1, 10)]  # 0.1 .. 0.9


def build_activity_channel(rng: random.Random, n_windows: int, fpr_targets,
                            load_level: float = ACTIVITY_LOAD_LEVEL):
    """Reuses coverleak_run.py's exact session/window generators and
    LogisticRegression pipeline (imported, not reimplemented) to produce
    held-out (idle vs. active) classifier scores, then runs Task B's own
    ROC/TPR-at-FPR pipeline (also imported) on them for a directly
    comparable operating-point table."""
    idle_feats, load_feats = [], []
    idle_groups, load_groups = [], []
    for sess_idx in range(n_windows):
        times, _ = gen_session_asn(rng, 0.0, mitigated=False)
        windows = session_windows(times, SESSION_DURATION_S, WINDOW_S)
        idle_feats.extend(windows)
        idle_groups.extend([sess_idx] * len(windows))
    for sess_idx in range(n_windows):
        times, _ = gen_session_asn(rng, load_level, mitigated=False)
        windows = session_windows(times, SESSION_DURATION_S, WINDOW_S)
        load_feats.extend(windows)
        # Offset past idle_groups' ids, independently generated sessions,
        # so ids must never collide (see coverleak_run.py's matching
        # comment).
        load_groups.extend([n_windows + sess_idx] * len(windows))

    X = np.array(idle_feats + load_feats)
    y = np.array([0] * len(idle_feats) + [1] * len(load_feats))
    groups = np.array(idle_groups + load_groups)

    skf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=rng.randint(0, 2**31 - 1))
    held_out_proba = np.zeros(len(y))
    for train_idx, test_idx in skf.split(X, y, groups):
        scaler = StandardScaler().fit(X[train_idx])
        Xtr, Xte = scaler.transform(X[train_idx]), scaler.transform(X[test_idx])
        clf = LogisticRegression(max_iter=1000).fit(Xtr, y[train_idx])
        held_out_proba[test_idx] = clf.predict_proba(Xte)[:, 1]

    true_scores = held_out_proba[y == 1]
    impostor_scores = held_out_proba[y == 0]
    results, auc, n_true, n_imp, _, _ = roc_tpr_at_fpr(true_scores, impostor_scores, fpr_targets)

    # Rule-of-three substitute for a raw TPR of exactly 1.000 (0 false
    # negatives observed in this held-out sample), same fix
    # asn_statistical_disclosure.py's own OPERATING_POINTS table already
    # documents and applies for its hardcoded values (see that file's
    # header comment): a point TPR=1.0 is not usable directly in
    # per_round_llr_terms()'s log((1-tpr)/(1-fpr)) arithmetic (division
    # by/log of exactly zero, a real ValueError, not hypothetical, hit
    # here at load_level>=0.6 where the activity classifier saturates).
    # Uncapped at L=0.5 (the original single-point default), which never
    # produced an exact 1.0, only --load-sweep's higher load levels
    # exposed this, since asn_statistical_disclosure.py's own table was
    # hand-curated with this substitution already applied, but this
    # script's live-computed activity_tpr never went through the same
    # step until now.
    tpr_out = {}
    for fpr, (tpr, _ci) in results.items():
        if tpr >= 1.0:
            tpr = 1.0 - 3.0 / n_true
        tpr_out[fpr] = tpr
    return tpr_out, auc


def run_for_load_level(load_level, rng, args, fpr_targets):
    """One load level's worth of the flowcorr_only/activity_only/
    combined_bc comparison across every fpr_targets point. Factored out
    of main() so --load-sweep can call this once per LOAD_LEVELS entry
    without duplicating the SPRT/combined-LLR logic, instead of only
    ever running once at the fixed ACTIVITY_LOAD_LEVEL=0.5 point."""
    t0 = time.perf_counter()
    activity_tpr, activity_auc = build_activity_channel(rng, args.windows, fpr_targets, load_level)
    print(f"  Activity-level channel (L={load_level}, AUC={activity_auc:.3f}) "
          f"TPR@FPR: {activity_tpr}")
    print(f"  Flow-correlation channel (asn_both_paths, combined) TPR@FPR: {FLOWCORR_TPR_FPR}")
    print(f"  (activity channel measured in {time.perf_counter()-t0:.1f}s)")

    alpha = beta = 0.01
    rows = []
    for fpr in fpr_targets:
        tpr_b = FLOWCORR_TPR_FPR[fpr]
        tpr_c = activity_tpr[fpr]

        for label, tpr_h1, fpr_h0, channels in [
            ("flowcorr_only", tpr_b, fpr, 1),
            ("activity_only", tpr_c, fpr, 1),
        ]:
            mc_h1 = simulate_sprt(tpr_h1, fpr_h0, alpha, beta, args.sprt_trials, "H1", rng)
            rows.append({
                "load_level": load_level, "fpr_target": fpr, "adversary": label,
                "median_rounds_true_pair": mc_h1["median_rounds"],
                "mean_rounds_true_pair": mc_h1["mean_rounds"],
                "accuracy": mc_h1["empirical_accuracy"],
            })

        # Combined channel: LLR per round = LLR_flowcorr + LLR_activity.
        # Simulate directly (two independent Bernoulli draws per round,
        # summed LLR) rather than reusing simulate_sprt's single-channel
        # loop, since the evidence source now has two independent legs.
        A, Bb = wald_boundaries(alpha, beta)
        llr_m_b, llr_nm_b = per_round_llr_terms(tpr_b, fpr)
        llr_m_c, llr_nm_c = per_round_llr_terms(tpr_c, fpr)

        def simulate_combined(true_hypothesis, n_trials):
            rounds_list = []
            correct = 0
            for _ in range(n_trials):
                llr = 0.0
                rounds = 0
                decision = None
                while rounds < 200_000:
                    rounds += 1
                    p_b = tpr_b if true_hypothesis == "H1" else fpr
                    p_c = tpr_c if true_hypothesis == "H1" else fpr
                    match_b = rng.random() < p_b
                    match_c = rng.random() < p_c
                    llr += (llr_m_b if match_b else llr_nm_b)
                    llr += (llr_m_c if match_c else llr_nm_c)
                    if llr >= A:
                        decision = "H1"
                        break
                    if llr <= Bb:
                        decision = "H0"
                        break
                if decision is None:
                    decision = "H1" if llr > (A + Bb) / 2 else "H0"
                rounds_list.append(rounds)
                if decision == true_hypothesis:
                    correct += 1
            rounds_list.sort()
            n = len(rounds_list)
            return {
                "median_rounds": rounds_list[n // 2],
                "mean_rounds": sum(rounds_list) / n,
                "empirical_accuracy": correct / n_trials,
            }

        mc_combined = simulate_combined("H1", args.sprt_trials)
        rows.append({
            "load_level": load_level, "fpr_target": fpr, "adversary": "combined_bc",
            "median_rounds_true_pair": mc_combined["median_rounds"],
            "mean_rounds_true_pair": mc_combined["mean_rounds"],
            "accuracy": mc_combined["empirical_accuracy"],
        })

        print(f"\n  FPR target {fpr}:")
        for r in rows[-3:]:
            print(f"    {r['adversary']:14s} median={r['median_rounds_true_pair']:3d} rounds "
                  f"mean={r['mean_rounds_true_pair']:.2f}  acc={r['accuracy']:.3f}")

    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--windows", type=int, default=300,
                     help="Sessions per class for the activity-level channel (matches coverleak_run.py default)")
    ap.add_argument("--sprt-trials", type=int, default=20_000)
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--seed", type=int, default=20260710)
    ap.add_argument("--load-sweep", action="store_true",
                     help="Run every load level in LOAD_LEVELS (Task C's own "
                          "0.1..0.9 grid) instead of just the headline L=0.5 "
                          "point. "
                          "Writes a separate asn_combined_bc_load_sweep.csv "
                          "rather than changing asn_combined_bc.csv's "
                          "existing single-load-level format/schema.")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    rng = random.Random(args.seed)
    fpr_targets = [0.1, 0.01, 0.001]

    print("=" * 78)
    print("  Combined B+C adversary: flow correlation + activity-level leakage")
    print("=" * 78)

    if not args.load_sweep:
        rows = run_for_load_level(ACTIVITY_LOAD_LEVEL, rng, args, fpr_targets)

        out_path = os.path.join(args.out_dir, "asn_combined_bc.csv")
        with open(out_path, "w", newline="") as fp:
            fp.write("# Combined B+C adversary: Wald SPRT accumulating Task B's flow-\n")
            fp.write("# correlation LLR and Task C's activity-level-leakage LLR (L=0.5,\n")
            fp.write("# the AUC-0.9 transition point) either separately\n")
            fp.write("# (flowcorr_only / activity_only) or jointly per round (combined_bc,\n")
            fp.write("# summed LLR, treated as conditionally independent, see docstring\n")
            fp.write("# Limitations). alpha=beta=0.01 (99% confidence) throughout.\n")
            fp.write("# REPRODUCIBILITY NOTE: --seed makes median_rounds_\n")
            fp.write("# true_pair (the value actually cited in the paper) exactly reproducible.\n")
            fp.write("# mean_rounds_true_pair/accuracy are NOT bit-reproducible run-to-run at a\n")
            fp.write("# fixed seed (~0.1-1% drift), sklearn's LogisticRegression inside a\n")
            fp.write("# StratifiedKFold pipeline inherits BLAS-level floating-point\n")
            fp.write("# nondeterminism (multi-threaded reduction order) that --seed cannot\n")
            fp.write("# control.\n")
            fp.write("# See --load-sweep / asn_combined_bc_load_sweep.csv for the same\n")
            fp.write("# comparison repeated across every load level Task C measured.\n")
            fields = ["fpr_target", "adversary", "median_rounds_true_pair",
                      "mean_rounds_true_pair", "accuracy"]
            w = csv.DictWriter(fp, fieldnames=fields)
            w.writeheader()
            for r in rows:
                r = {k: v for k, v in r.items() if k != "load_level"}
                w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v) for k, v in r.items()})
        print(f"\n  Wrote {out_path}  ({len(rows)} rows)")
        return 0

    # --load-sweep: repeat the whole comparison at every load level Task C
    # itself measured, rather than only testing at L=0.5.
    all_rows = []
    for load_level in LOAD_LEVELS:
        print(f"\n{'-' * 78}\n  load_level = {load_level}\n{'-' * 78}")
        all_rows.extend(run_for_load_level(load_level, rng, args, fpr_targets))

    out_path = os.path.join(args.out_dir, "asn_combined_bc_load_sweep.csv")
    with open(out_path, "w", newline="") as fp:
        fp.write("# Combined B+C adversary, load-level sweep: same Wald SPRT comparison\n")
        fp.write("# as asn_combined_bc.csv (flowcorr_only / activity_only / combined_bc,\n")
        fp.write("# alpha=beta=0.01), repeated at every load_level in Task C's own\n")
        fp.write("# 0.1..0.9 grid (coverleak_run.py's LOAD_LEVELS / Figure 5) instead of\n")
        fp.write("# only the L=0.5 AUC-0.9 transition point. Same reproducibility caveat as\n")
        fp.write("# asn_combined_bc.csv: median_rounds_true_pair is exactly reproducible\n")
        fp.write("# at a fixed --seed, mean_rounds_true_pair/accuracy are not (sklearn/\n")
        fp.write("# BLAS floating-point nondeterminism, ~0.1-1% drift).\n")
        fields = ["load_level", "fpr_target", "adversary", "median_rounds_true_pair",
                  "mean_rounds_true_pair", "accuracy"]
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        for r in all_rows:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v) for k, v in r.items()})
    print(f"\n  Wrote {out_path}  ({len(all_rows)} rows)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
