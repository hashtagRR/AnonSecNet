#!/usr/bin/env python3
"""
flowcorr_ml.py: Task B follow-up: stress-test the flow-correlation
finding against a learned (not hand-picked-statistic) correlator.

WHY THIS EXISTS
---------------------------------------------------------------------------
flowcorr_run.py's headline number (TPR@FPR=1e-3: asn_one_path ~0.52,
asn_both_paths ~0.55, vs single_path 1.00) was measured with two fixed
statistical correlators (Pearson-on-volume, and a hand-averaged combination
of Pearson+cosine over volume+timing). Its own docstring flags this as a
"weakest -> strongest statistical baseline," explicitly skipping a
learned/CNN correlator as a stretch goal. That's the natural next question
a reviewer asks: does the partial-mitigation result survive a stronger
adversary, or was it an artifact of underpowered correlators?

This script reuses flowcorr_run.py's exact session generator (same
generative model, same documented parameters, imported directly, not
reimplemented) and adds a learned correlator: a small MLP classifier
trained to discriminate true (same-session) entry/exit pairs from impostor
pairs, given the raw binned volume+timing feature vectors (not just their
Pearson/cosine summary). This is a genuine step up in adversary power,
the classifier can learn nonlinear, bin-specific, cross-feature patterns a
fixed formula cannot, while stopping short of a full raw-packet-sequence
CNN (DeepCorr/DeepCoFFEA-style), which would need real per-packet traces
at a scale this synthetic harness was not built to produce. Framed
honestly as "a stronger correlator," not "the strongest possible."

METHODOLOGY
---------------------------------------------------------------------------
1. Generate a TRAIN pool of sessions per condition (separate RNG stream
   from the test pool, no leakage). Build training examples: every true
   pair (label=1) plus NEG_PER_POS randomly sampled impostor pairs per
   session (label=0), full N^2 negative enumeration isn't needed for
   training, only balanced coverage.
2. Feature vector per (entry, exit) pair: concatenated volume/timing bins
   for both sides, their element-wise product (lets the model learn
   "does a volume bump on one side line up with a bump on the other,"
   which is what a correlation-style CNN filter would learn), and the
   four existing pearson/cosine scalars as extra features (so the learned
   model is a strict superset of what `combined` can already express).
3. Fit StandardScaler + MLPClassifier (small: 2 hidden layers) on the
   training pool.
4. Generate a held-out TEST pool matching flowcorr_run.py's own N and
   methodology (full N true pairs, N*(N-1) impostor pairs), score every
   pair with the trained classifier's predicted probability, and run the
   identical ROC/TPR-at-FPR pipeline as flowcorr_run.py for direct
   comparability.

Usage:
    python flowcorr_ml.py [--train-sessions 300] [--test-sessions 200]
                           [--neg-per-pos 5] [--seed 20260710] [--out-dir .]
"""

import argparse
import csv
import math
import os
import random
import sys
import time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import flowcorr_run
from flowcorr_run import (
    SESSION_DURATION_S, BIN_WIDTH_MS, ci95_proportion, gen_session,
    to_features, roc_tpr_at_fpr,
)


def pairwise_features(feat_i, feat_j):
    """feat_i, feat_j: (vol_e, tim_e, vol_x, tim_x) for one sub-path each.
    Returns a flat feature vector: entry bins, exit bins, element-wise
    product of volumes and of timings, plus the four scalar correlators
    flowcorr_run.py already computes (so the learned model strictly
    subsumes the fixed-formula correlators' information)."""
    vol_e, tim_e = feat_i[0], feat_i[1]
    vol_x, tim_x = feat_j[2], feat_j[3]

    def pearson(a, b):
        if np.std(a) < 1e-12 or np.std(b) < 1e-12:
            return 0.0
        return float(np.corrcoef(a, b)[0, 1])

    def cosine(a, b):
        na, nb = np.linalg.norm(a), np.linalg.norm(b)
        if na < 1e-12 or nb < 1e-12:
            return 0.0
        return float(np.dot(a, b) / (na * nb))

    scalars = np.array([
        pearson(vol_e, vol_x), cosine(vol_e, vol_x),
        pearson(tim_e, tim_x), cosine(tim_e, tim_x),
    ])
    return np.concatenate([vol_e, tim_e, vol_x, tim_x,
                            vol_e * vol_x, tim_e * tim_x, scalars])


def session_features(sessions):
    """sessions: list of per-session sub-path lists (1 or 2 sub-paths).
    Returns list-of-lists: features[i][k] = (vol_e,tim_e,vol_x,tim_x) for
    sub-path k of session i."""
    out = []
    for subpaths in sessions:
        feat = []
        for e, x, *_ in subpaths:
            ve, te = to_features(e, SESSION_DURATION_S, BIN_WIDTH_MS)
            vx, tx = to_features(x, SESSION_DURATION_S, BIN_WIDTH_MS)
            feat.append((ve, te, vx, tx))
        out.append(feat)
    return out


def score_max_over_subpaths(clf, scaler, feat_i, feat_j):
    """Max predicted P(same-session) over sub-paths, mirroring
    flowcorr_run.py's score_session_pair max-of-subpaths semantics."""
    n_sub = len(feat_i)
    X = np.stack([pairwise_features(feat_i[k], feat_j[k]) for k in range(n_sub)])
    probs = clf.predict_proba(scaler.transform(X))[:, 1]
    return float(np.max(probs))


def batch_score_all_pairs(clf, scaler, features, n_sessions):
    """Vectorized scoring of all N true pairs + N*(N-1) impostor pairs.
    Builds one big feature matrix per sub-path index and calls
    predict_proba once per sub-path (not once per pair), this is what
    keeps this tractable at N~200 (40k pairs) instead of the ~45s the
    pure-Python per-pair loop in flowcorr_run.py takes for two much
    cheaper scalar correlators."""
    n_sub = len(features[0])
    all_probs = np.zeros((n_sub, n_sessions, n_sessions), dtype=np.float64)

    for k in range(n_sub):
        vol_e_all = np.stack([features[i][k][0] for i in range(n_sessions)])
        tim_e_all = np.stack([features[i][k][1] for i in range(n_sessions)])
        vol_x_all = np.stack([features[i][k][2] for i in range(n_sessions)])
        tim_x_all = np.stack([features[i][k][3] for i in range(n_sessions)])

        # All (i, j) combinations, row-major: index i*N + j
        ve = np.repeat(vol_e_all, n_sessions, axis=0)
        te = np.repeat(tim_e_all, n_sessions, axis=0)
        vx = np.tile(vol_x_all, (n_sessions, 1))
        tx = np.tile(tim_x_all, (n_sessions, 1))

        def batch_pearson(a, b):
            a_c = a - a.mean(axis=1, keepdims=True)
            b_c = b - b.mean(axis=1, keepdims=True)
            num = (a_c * b_c).sum(axis=1)
            den = np.sqrt((a_c ** 2).sum(axis=1) * (b_c ** 2).sum(axis=1))
            out = np.zeros(len(a))
            mask = den > 1e-12
            out[mask] = num[mask] / den[mask]
            return out

        def batch_cosine(a, b):
            na = np.linalg.norm(a, axis=1)
            nb = np.linalg.norm(b, axis=1)
            out = np.zeros(len(a))
            mask = (na > 1e-12) & (nb > 1e-12)
            out[mask] = (a[mask] * b[mask]).sum(axis=1) / (na[mask] * nb[mask])
            return out

        scalars = np.stack([
            batch_pearson(ve, vx), batch_cosine(ve, vx),
            batch_pearson(te, tx), batch_cosine(te, tx),
        ], axis=1)

        X = np.concatenate([ve, te, vx, tx, ve * vx, te * tx, scalars], axis=1)
        probs = clf.predict_proba(scaler.transform(X))[:, 1]
        all_probs[k] = probs.reshape(n_sessions, n_sessions)

    return all_probs.max(axis=0)   # (N, N), max over sub-paths


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--train-sessions", type=int, default=300)
    ap.add_argument("--test-sessions", type=int, default=200)
    ap.add_argument("--neg-per-pos", type=int, default=5)
    ap.add_argument("--seed", type=int, default=20260710)
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--fpr-targets", default="1e-1,1e-2,1e-3",
                     help="Comma-separated FPR operating points; see flowcorr_run.py's "
                          "--fpr-targets help for the resolution caveat (needs "
                          "--test-sessions correspondingly larger for strict targets).")
    ap.add_argument("--hardened-jitter", action="store_true",
                     help="see flowcorr_run.py's --hardened-jitter help")
    args = ap.parse_args()

    flowcorr_run.HARDENED_JITTER = args.hardened_jitter

    os.makedirs(args.out_dir, exist_ok=True)
    from sklearn.neural_network import MLPClassifier
    from sklearn.preprocessing import StandardScaler

    conditions = ["single_path", "asn_one_path", "asn_both_paths"]
    fpr_targets = [float(x) for x in args.fpr_targets.split(",")]
    t0 = time.perf_counter()
    result_rows = []
    roc_curve_rows = []

    for condition in conditions:
        # --- Train pool (separate RNG stream: seed+1, never overlaps the
        # test pool's trace generation) ---
        train_rng = random.Random(args.seed + 1)
        train_sessions = [
            gen_session(train_rng, "interactive" if i % 2 == 0 else "bulk", condition)
            for i in range(args.train_sessions)
        ]
        train_feat = session_features(train_sessions)

        clf = MLPClassifier(hidden_layer_sizes=(32, 16), max_iter=500,
                             random_state=args.seed, early_stopping=True)
        scaler = StandardScaler()

        X_train, y_train = [], []
        for i in range(args.train_sessions):
            n_sub = len(train_feat[i])
            for k in range(n_sub):
                X_train.append(pairwise_features(train_feat[i][k], train_feat[i][k]))
                y_train.append(1)
            neg_js = train_rng.sample(
                [j for j in range(args.train_sessions) if j != i],
                min(args.neg_per_pos, args.train_sessions - 1))
            for j in neg_js:
                k = train_rng.randrange(n_sub)
                X_train.append(pairwise_features(train_feat[i][k], train_feat[j][k]))
                y_train.append(0)

        X_train = np.stack(X_train)
        y_train = np.array(y_train)
        scaler.fit(X_train)
        clf.fit(scaler.transform(X_train), y_train)

        # --- Test pool (matches flowcorr_run.py's own N and methodology) ---
        test_rng = random.Random(args.seed)
        test_sessions = [
            gen_session(test_rng, "interactive" if i % 2 == 0 else "bulk", condition)
            for i in range(args.test_sessions)
        ]
        test_feat = session_features(test_sessions)
        score_matrix = batch_score_all_pairs(clf, scaler, test_feat, args.test_sessions)

        true_scores = [score_matrix[i, i] for i in range(args.test_sessions)]
        impostor_scores = [score_matrix[i, j]
                            for i in range(args.test_sessions)
                            for j in range(args.test_sessions) if i != j]

        fpr_results, auc, n_true, n_imp, fprs_curve, tprs_curve = roc_tpr_at_fpr(
            true_scores, impostor_scores, fpr_targets)

        for target, (tpr, ci) in fpr_results.items():
            result_rows.append({
                "condition": condition, "correlator": "learned_mlp",
                "fpr_target": target, "tpr": tpr, "tpr_ci95": ci,
                "auc": auc, "n_pairs": n_true + n_imp,
            })
        n_curve_points = 300
        idxs = np.unique(np.linspace(0, len(fprs_curve) - 1, n_curve_points).astype(int))
        for idx in idxs:
            roc_curve_rows.append({
                "condition": condition, "correlator": "learned_mlp",
                "fpr": float(fprs_curve[idx]), "tpr": float(tprs_curve[idx]),
            })
        if not args.quiet:
            print(f"  {condition:16s} learned_mlp      AUC={auc:.4f}  "
                  f"TPR@{min(fpr_targets):g}={fpr_results[min(fpr_targets)][0]:.4f}  "
                  f"(train n={len(y_train)}, {int(y_train.sum())} pos)", flush=True)

    elapsed = time.perf_counter() - t0
    if not args.quiet:
        print(f"\n  Completed in {elapsed:.1f}s\n")

    out_path = os.path.join(args.out_dir, "flowcorr_ml_results.csv")
    with open(out_path, "w", newline="") as fp:
        fp.write("# Anon-Sec-Net Task B follow-up: learned-correlator (MLP) results\n")
        fp.write(f"# train_sessions={args.train_sessions} (separate RNG stream from test), "
                  f"test_sessions={args.test_sessions}, neg_per_pos={args.neg_per_pos}\n")
        fp.write("# Directly comparable to flowcorr_results.csv's pearson_volume/combined rows\n")
        fields = ["condition", "correlator", "fpr_target", "tpr", "tpr_ci95", "auc", "n_pairs"]
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        for row in result_rows:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v)
                        for k, v in row.items()})
    print(f"  Wrote {out_path}  ({len(result_rows)} rows)")

    roc_path = os.path.join(args.out_dir, "flowcorr_ml_roc_curves.csv")
    with open(roc_path, "w", newline="") as fp:
        fp.write("# Anon-Sec-Net Task B follow-up: learned-correlator (MLP) ROC curves\n")
        w = csv.DictWriter(fp, fieldnames=["condition", "correlator", "fpr", "tpr"])
        w.writeheader()
        for row in roc_curve_rows:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v)
                        for k, v in row.items()})
    print(f"  Wrote {roc_path}  ({len(roc_curve_rows)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
