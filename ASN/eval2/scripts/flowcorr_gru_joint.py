#!/usr/bin/env python3
"""
flowcorr_gru_joint.py: Task B follow-up #3: a JOINT both-paths correlator.

WHY THIS EXISTS
---------------------------------------------------------------------------
Every correlator in this project so far (pearson_volume, combined,
learned_mlp in flowcorr_ml.py, gru_contrastive in flowcorr_gru.py) scores
ONE sub-path (entry, exit) pair at a time. For asn_both_paths, the
both-paths adversary's score is computed as max(score_A, score_B), two
INDEPENDENTLY encoded/scored sub-paths, never a joint decision that looks
at path A and path B's timing simultaneously. That means no existing
result actually tests whether observing both directions of a dual-path
session leaks something a single-direction adversary (or an adversary who
treats the two directions independently) cannot get, e.g. a joint
cross-path timing correlation (do path A's inter-packet gaps and path B's
inter-packet gaps co-vary in a session-identifying way, beyond what either
path's own timing shows alone?).

This script builds that missing joint model: a single GRU encoder whose
input at each time bin is the CONCATENATION of both paths' (volume,
timing) features: [vol_A, tim_A, vol_B, tim_B], 4 channels instead of 2
-- producing ONE embedding per session side (entry, exit) instead of one
embedding per sub-path. The score between two sessions is a single dot
product, not a max over two independent sub-scores. If dual-path routing
leaks a cross-path signal that the existing max-of-two-subpaths approach
misses, this is the model that would find it; if it performs the same as
(or worse than) the existing gru_contrastive max-of-two score on
asn_both_paths, that is itself a real, reportable null result, evidence
that treating the two paths independently already captures what a joint
adversary can extract.

Sub-path ordering: gen_session()'s asn_both_paths/asn_both_paths_no_cover
branches always return [path_A_tuple, path_B_tuple] in that fixed order
(verified by direct reading of flowcorr_run.py, path A is always index
0, path B always index 1, consistent across every session), so
channel-concatenating index 0 and index 1 is well-defined and consistent
across the whole dataset. This joint model is only meaningful for the two
both-paths conditions (asn_both_paths, asn_both_paths_no_cover); it is not
run on single_path/asn_one_path, which only ever produce one sub-path.

CAVEAT (train-set size, not hidden): the existing gru_contrastive model
trains on 2 (entry,exit) pairs per asn_both_paths session (one per
sub-path), so --train-sessions 500 gives it 1000 training pairs. This
joint model produces exactly 1 joint (entry,exit) pair per session (it
makes one decision per session, not per sub-path), so the same
--train-sessions 500 gives it only 500 training pairs. This is an
unavoidable, honest consequence of the two problems being framed
differently, not a hyperparameter to tune around, reported as-is.

Requires torch (already a project dependency, see flowcorr_gru.py).

Usage:
    python flowcorr_gru_joint.py --train-sessions 500 --test-sessions 500 \
        --seed 20260710 --out-dir .
"""

import argparse
import csv
import os
import random
import sys
import time

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import flowcorr_run
from flowcorr_run import (
    SESSION_DURATION_S, BIN_WIDTH_MS, gen_session, to_features, roc_tpr_at_fpr,
)
import flowcorr_gru
from flowcorr_gru import contrastive_loss, standardize, embed_all

EMBED_DIM = 32
HIDDEN_SIZE = 32
JOINT_CONDITIONS = ("asn_both_paths", "asn_both_paths_no_cover")


class JointGRU(nn.Module):
    """Same shape as flowcorr_gru.py's SiameseGRU, but input_size=4: both
    paths' (volume, timing) features concatenated channel-wise at every
    time bin, so the GRU sees both paths' timing jointly, not one at a
    time."""
    def __init__(self, hidden_size=HIDDEN_SIZE, embed_dim=EMBED_DIM):
        super().__init__()
        self.gru = nn.GRU(input_size=4, hidden_size=hidden_size, num_layers=1, batch_first=True)
        self.proj = nn.Linear(hidden_size, embed_dim)

    def forward(self, x):
        # x: (B, T, 4)
        _, h_n = self.gru(x)
        emb = self.proj(h_n[-1])
        return F.normalize(emb, dim=-1)


def build_joint_sequence_pairs(sessions):
    """sessions: list of per-session sub-path lists, each with EXACTLY 2
    sub-paths (path A, path B) in that fixed order. Returns a flat list of
    (entry_seq, exit_seq) arrays, shape (T, 4) each, ONE pair per
    session (not one per sub-path)."""
    pairs = []
    for subpaths in sessions:
        assert len(subpaths) == 2, (
            "flowcorr_gru_joint.py requires both-paths sessions "
            f"(got {len(subpaths)} sub-paths); use flowcorr_gru.py for "
            "single_path/asn_one_path.")
        (e_a, x_a, *_), (e_b, x_b, *_) = subpaths
        ve_a, te_a = to_features(e_a, SESSION_DURATION_S, BIN_WIDTH_MS)
        ve_b, te_b = to_features(e_b, SESSION_DURATION_S, BIN_WIDTH_MS)
        vx_a, tx_a = to_features(x_a, SESSION_DURATION_S, BIN_WIDTH_MS)
        vx_b, tx_b = to_features(x_b, SESSION_DURATION_S, BIN_WIDTH_MS)
        entry_seq = np.stack([ve_a, te_a, ve_b, te_b], axis=1).astype(np.float32)
        exit_seq = np.stack([vx_a, tx_a, vx_b, tx_b], axis=1).astype(np.float32)
        pairs.append((entry_seq, exit_seq))
    return pairs


def train_encoder_joint(train_pairs, epochs=60, batch_size=64, lr=2e-3, seed=0):
    torch.manual_seed(seed)
    entry_arr = np.stack([p[0] for p in train_pairs])
    exit_arr = np.stack([p[1] for p in train_pairs])
    entry_arr, [exit_arr] = standardize(entry_arr, [exit_arr])

    model = JointGRU()
    opt = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5)
    entry_t = torch.from_numpy(entry_arr)
    exit_t = torch.from_numpy(exit_arr)
    n = entry_t.shape[0]

    model.train()
    for epoch in range(epochs):
        perm = torch.randperm(n)
        for start in range(0, n, batch_size):
            idx = perm[start:start + batch_size]
            if len(idx) < 2:
                continue
            opt.zero_grad()
            emb_e = model(entry_t[idx])
            emb_x = model(exit_t[idx])
            loss = contrastive_loss(emb_e, emb_x)
            loss.backward()
            opt.step()
    return model


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--train-sessions", type=int, default=500)
    ap.add_argument("--test-sessions", type=int, default=500)
    ap.add_argument("--seed", type=int, default=20260710)
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--fpr-targets", default="1e-1,1e-2,1e-3,1e-4,1e-5")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--hardened-jitter", action="store_true",
                     help="see flowcorr_run.py's --hardened-jitter help")
    args = ap.parse_args()

    flowcorr_run.HARDENED_JITTER = args.hardened_jitter

    os.makedirs(args.out_dir, exist_ok=True)
    fpr_targets = [float(x) for x in args.fpr_targets.split(",")]

    rng_train = random.Random(args.seed)
    rng_test = random.Random(args.seed + 999_983)  # separate stream, no leakage

    t0 = time.perf_counter()
    result_rows = []
    roc_curve_rows = []

    for condition in JOINT_CONDITIONS:
        train_sessions = [gen_session(rng_train, "interactive" if i % 2 == 0 else "bulk", condition)
                           for i in range(args.train_sessions)]
        train_pairs = build_joint_sequence_pairs(train_sessions)

        condition_seed = (args.seed + 500_000 * (JOINT_CONDITIONS.index(condition) + 1)) % (2**31)
        model = train_encoder_joint(train_pairs, seed=condition_seed)

        test_sessions = [gen_session(rng_test, "interactive" if i % 2 == 0 else "bulk", condition)
                          for i in range(args.test_sessions)]
        test_pairs = build_joint_sequence_pairs(test_sessions)

        entry_train_arr = np.stack([p[0] for p in train_pairs])
        mean = entry_train_arr.reshape(-1, 4).mean(axis=0)
        std = entry_train_arr.reshape(-1, 4).std(axis=0) + 1e-6

        entry_test_arr = np.stack([(p[0] - mean) / std for p in test_pairs]).astype(np.float32)
        exit_test_arr = np.stack([(p[1] - mean) / std for p in test_pairs]).astype(np.float32)
        entry_embeds = embed_all(model, entry_test_arr)
        exit_embeds = embed_all(model, exit_test_arr)

        n = args.test_sessions
        true_scores, impostor_scores = [], []
        for i in range(n):
            for j in range(n):
                s = float(np.dot(entry_embeds[i], exit_embeds[j]))
                (true_scores if i == j else impostor_scores).append(s)

        fpr_results, auc, n_true, n_imp, fprs_curve, tprs_curve = roc_tpr_at_fpr(
            true_scores, impostor_scores, fpr_targets)

        for target, (tpr, ci) in fpr_results.items():
            result_rows.append({
                "condition": condition, "correlator": "gru_joint",
                "fpr_target": target, "tpr": tpr, "tpr_ci95": ci,
                "auc": auc, "n_pairs": n_true + n_imp,
            })

        n_curve_points = 300
        idxs = np.unique(np.linspace(0, len(fprs_curve) - 1, n_curve_points).astype(int))
        for idx in idxs:
            roc_curve_rows.append({
                "condition": condition, "correlator": "gru_joint",
                "fpr": float(fprs_curve[idx]), "tpr": float(tprs_curve[idx]),
            })

        if not args.quiet:
            strict = min(fpr_targets)
            print(f"  {condition:24s} gru_joint  AUC={auc:.4f}  "
                  f"TPR@{strict:g}={fpr_results[strict][0]:.4f}  "
                  f"(train={time.perf_counter()-t0:.1f}s cumulative)", flush=True)

    out_path = os.path.join(args.out_dir, "flowcorr_gru_joint_results.csv")
    with open(out_path, "w", newline="") as fp:
        fp.write("# Task B follow-up #3: JOINT both-paths Siamese GRU\n")
        fp.write("# (gru_joint), single embedding per session side from BOTH\n")
        fp.write("# paths' concatenated (vol,tim) features, ONE score per session\n")
        fp.write("# pair (not max-of-two-subpath-scores like gru_contrastive's\n")
        fp.write("# asn_both_paths row in flowcorr_gru_results.csv). Only defined\n")
        fp.write("# for asn_both_paths/asn_both_paths_no_cover (2 sub-paths/session).\n")
        fp.write(f"# train_sessions={args.train_sessions} (separate RNG stream from\n")
        fp.write(f"# test), test_sessions={args.test_sessions}.\n")
        fields = ["condition", "correlator", "fpr_target", "tpr", "tpr_ci95", "auc", "n_pairs"]
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        for r in result_rows:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v) for k, v in r.items()})
    print(f"\n  Wrote {out_path}  ({len(result_rows)} rows)")

    curve_path = os.path.join(args.out_dir, "flowcorr_gru_joint_roc_curves.csv")
    with open(curve_path, "w", newline="") as fp:
        w = csv.DictWriter(fp, fieldnames=["condition", "correlator", "fpr", "tpr"])
        w.writeheader()
        for r in roc_curve_rows:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v) for k, v in r.items()})
    print(f"  Wrote {curve_path}  ({len(roc_curve_rows)} rows)")

    print(f"\n  Completed in {time.perf_counter()-t0:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
