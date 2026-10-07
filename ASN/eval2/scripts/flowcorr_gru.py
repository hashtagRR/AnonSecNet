#!/usr/bin/env python3
"""
flowcorr_gru.py: Task B follow-up #2: a sequence-aware, metric-learning
correlator (Siamese GRU + contrastive loss), closer in spirit to
DeepCoFFEA/RECTor than flowcorr_ml.py's MLP-on-concatenated-features
classifier.

WHY THIS EXISTS
---------------------------------------------------------------------------
LITERATURE_GAPS.md §3.5 item 3: our existing learned correlator
(flowcorr_ml.py) is an MLP trained as a binary classifier on a
CONCATENATED, flattened feature vector (entry bins + exit bins +
element-wise products + 4 scalar correlators), it has no notion of
sequence/temporal structure, treating the time bins (40 at this project's
native 20s/500ms binning; the bin count scales with session duration, see
SESSION_DURATION_S) as independent input dimensions. Current published SOTA (DeepCoFFEA: metric learning +
amplification; RECTor: GRU-based temporal encoding + attention-based
multiple-instance learning; FlowCoPCL: contrastive learning) is built
around two ideas ours doesn't use: (1) a genuine SEQUENCE encoder that
models temporal order, and (2) METRIC/CONTRASTIVE learning (embed
same-session entry/exit into nearby points in a learned space) rather
than binary classification on a flat feature vector.

This script is an honest, scaled-down instance of that idea, not a
reimplementation of DeepCoFFEA or RECTor's actual published architecture
(both are much larger models trained on real, not synthetic, packet
traces at a scale this harness doesn't produce), built to test whether
even a small step in that direction (GRU encoder + InfoNCE-style
contrastive loss, on the SAME synthetic traces and binned features
flowcorr_run.py/flowcorr_ml.py already use) measurably improves TPR@FPR
over the existing MLP correlator.

MODEL
---------------------------------------------------------------------------
A single shared ("Siamese") GRU encoder maps a (volume, timing) binned
sequence: entry-side OR exit-side, same encoder for both, to a fixed
32-dim, L2-normalized embedding. Training uses a symmetric InfoNCE
(NT-Xent) contrastive loss over mini-batches: for a batch of B true
(entry, exit) pairs, the B-1 other exit-side embeddings in the same batch
serve as in-batch negatives (and vice versa for the reverse direction),
no explicit negative sampling needed, matching standard contrastive-
learning practice and, loosely, DeepCoFFEA's "amplification" idea of
using a large negative pool per positive.

At test time, pairs are scored by cosine similarity between the trained
encoder's embeddings (not passed through a classifier head at all, pure
metric-learning style), and run through the identical ROC/TPR-at-FPR
pipeline (imported from flowcorr_run.py) used by every other correlator
in this project, for direct comparability.

Requires torch (already a project dependency).

Usage:
    python flowcorr_gru.py --train-sessions 500 --test-sessions 500 \
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

EMBED_DIM = 32
HIDDEN_SIZE = 32


class SiameseGRU(nn.Module):
    def __init__(self, hidden_size=HIDDEN_SIZE, embed_dim=EMBED_DIM):
        super().__init__()
        self.gru = nn.GRU(input_size=2, hidden_size=hidden_size, num_layers=1, batch_first=True)
        self.proj = nn.Linear(hidden_size, embed_dim)

    def forward(self, x):
        # x: (B, T, 2)
        _, h_n = self.gru(x)
        emb = self.proj(h_n[-1])
        return F.normalize(emb, dim=-1)


def build_sequence_pairs(sessions):
    """sessions: list of per-session sub-path lists. Returns a flat list
    of (entry_seq, exit_seq) arrays, shape (T, 2) each, one entry per
    sub-path (asn_both_paths sessions contribute 2 pairs each)."""
    pairs = []
    for subpaths in sessions:
        for e, x, *_ in subpaths:
            ve, te = to_features(e, SESSION_DURATION_S, BIN_WIDTH_MS)
            vx, tx = to_features(x, SESSION_DURATION_S, BIN_WIDTH_MS)
            entry_seq = np.stack([ve, te], axis=1).astype(np.float32)
            exit_seq = np.stack([vx, tx], axis=1).astype(np.float32)
            pairs.append((entry_seq, exit_seq))
    return pairs


def standardize(train_arr, other_arrs):
    mean = train_arr.reshape(-1, train_arr.shape[-1]).mean(axis=0)
    std = train_arr.reshape(-1, train_arr.shape[-1]).std(axis=0) + 1e-6
    def apply(a):
        return (a - mean) / std
    return apply(train_arr), [apply(a) for a in other_arrs]


def contrastive_loss(emb_e, emb_x, temperature=0.1):
    """Symmetric InfoNCE over a batch: emb_e[i]/emb_x[i] are the positive
    pair, other batch members are in-batch negatives."""
    logits = emb_e @ emb_x.T / temperature
    labels = torch.arange(emb_e.shape[0])
    loss_e2x = F.cross_entropy(logits, labels)
    loss_x2e = F.cross_entropy(logits.T, labels)
    return (loss_e2x + loss_x2e) / 2.0


def train_encoder(train_pairs, epochs=60, batch_size=64, lr=2e-3, seed=0):
    torch.manual_seed(seed)
    entry_arr = np.stack([p[0] for p in train_pairs])
    exit_arr = np.stack([p[1] for p in train_pairs])
    entry_arr, [exit_arr] = standardize(entry_arr, [exit_arr])

    model = SiameseGRU()
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
    return model, (entry_arr.mean(axis=(0, 1)), entry_arr.std(axis=(0, 1)))


def embed_all(model, arr):
    model.eval()
    with torch.no_grad():
        return model(torch.from_numpy(arr)).numpy()


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
    ap.add_argument("--pool-mixing", action="store_true",
                     help="Pass-through to "
                          "flowcorr_run.py's --pool-mixing, to re-check the fixed-"
                          "correlator pool-mixing sweep against the GRU-contrastive "
                          "correlator before trusting any pool-mixing TPR claim from "
                          "the fixed correlator alone (anosecnet.tex's own 'report "
                          "the harder test' discipline).")
    ap.add_argument("--pool-mix-flush-ms", type=float, default=None,
                     help="see flowcorr_run.py's --pool-mix-flush-ms help; only used "
                          "when --pool-mixing is set")
    ap.add_argument("--threshold-batch-size", type=int, default=0,
                     help="Pass-through to "
                          "flowcorr_run.py's --threshold-batch-size, to re-check the "
                          "fixed-correlator threshold-batching sweep against the "
                          "GRU-contrastive correlator before trusting any near-zero "
                          "fixed-correlator TPR from it (same correlator-strength-"
                          "artifact concern the pool-mixing correction raised).")
    ap.add_argument("--threshold-batch-timeout-ms", type=float, default=0.0,
                     help="see flowcorr_run.py's --threshold-batch-timeout-ms help; "
                          "only used when --threshold-batch-size is set")
    args = ap.parse_args()

    flowcorr_run.HARDENED_JITTER = args.hardened_jitter
    flowcorr_run.POOL_MIXING = args.pool_mixing
    if args.pool_mix_flush_ms is not None:
        flowcorr_run.POOL_MIX_FLUSH_MS = args.pool_mix_flush_ms
    flowcorr_run.THRESHOLD_BATCH_SIZE = args.threshold_batch_size
    flowcorr_run.THRESHOLD_BATCH_TIMEOUT_MS = args.threshold_batch_timeout_ms

    os.makedirs(args.out_dir, exist_ok=True)
    fpr_targets = [float(x) for x in args.fpr_targets.split(",")]
    conditions = ["single_path", "asn_one_path", "asn_both_paths"]

    rng_train = random.Random(args.seed)
    rng_test = random.Random(args.seed + 999_983)  # separate stream, no leakage

    t0 = time.perf_counter()
    result_rows = []
    roc_curve_rows = []

    for condition in conditions:
        train_sessions = [gen_session(rng_train, "interactive" if i % 2 == 0 else "bulk", condition)
                           for i in range(args.train_sessions)]
        train_pairs = build_sequence_pairs(train_sessions)

        # hash(condition) used to seed this, Python randomizes str hash()
        # per process by default (PYTHONHASHSEED unset), so --seed did NOT
        # actually make model init reproducible run-to-run despite the flag
        # implying it did. Fixed to a deterministic per-condition offset,
        # matching this file's own rng_test = args.seed + 999_983 convention
        # for separate, reproducible streams.
        condition_seed = (args.seed + 500_000 * (conditions.index(condition) + 1)) % (2**31)
        model, _ = train_encoder(train_pairs, seed=condition_seed)

        test_sessions = [gen_session(rng_test, "interactive" if i % 2 == 0 else "bulk", condition)
                          for i in range(args.test_sessions)]

        # Precompute per-session, per-subpath (entry_seq, exit_seq), standardized
        # with the SAME (train-fit) stats via re-deriving mean/std from train_pairs.
        entry_train_arr = np.stack([p[0] for p in train_pairs])
        mean = entry_train_arr.reshape(-1, 2).mean(axis=0)
        std = entry_train_arr.reshape(-1, 2).std(axis=0) + 1e-6

        n_sub_test = []
        entry_embeds = []  # entry_embeds[i] = list of per-subpath embeddings
        exit_embeds = []
        for subpaths in test_sessions:
            e_list, x_list = [], []
            for e, x, *_ in subpaths:
                ve, te = to_features(e, SESSION_DURATION_S, BIN_WIDTH_MS)
                vx, tx = to_features(x, SESSION_DURATION_S, BIN_WIDTH_MS)
                entry_seq = ((np.stack([ve, te], axis=1).astype(np.float32) - mean) / std)
                exit_seq = ((np.stack([vx, tx], axis=1).astype(np.float32) - mean) / std)
                e_list.append(embed_all(model, entry_seq[None, ...])[0])
                x_list.append(embed_all(model, exit_seq[None, ...])[0])
            entry_embeds.append(e_list)
            exit_embeds.append(x_list)
            n_sub_test.append(len(e_list))

        n = args.test_sessions
        n_sub = n_sub_test[0]
        true_scores, impostor_scores = [], []
        for i in range(n):
            for j in range(n):
                sub_scores = [float(np.dot(entry_embeds[i][k], exit_embeds[j][k]))
                              for k in range(n_sub)]
                s = max(sub_scores)
                (true_scores if i == j else impostor_scores).append(s)

        fpr_results, auc, n_true, n_imp, fprs_curve, tprs_curve = roc_tpr_at_fpr(
            true_scores, impostor_scores, fpr_targets)

        for target, (tpr, ci) in fpr_results.items():
            result_rows.append({
                "condition": condition, "correlator": "gru_contrastive",
                "fpr_target": target, "tpr": tpr, "tpr_ci95": ci,
                "auc": auc, "n_pairs": n_true + n_imp,
            })

        n_curve_points = 300
        idxs = np.unique(np.linspace(0, len(fprs_curve) - 1, n_curve_points).astype(int))
        for idx in idxs:
            roc_curve_rows.append({
                "condition": condition, "correlator": "gru_contrastive",
                "fpr": float(fprs_curve[idx]), "tpr": float(tprs_curve[idx]),
            })

        if not args.quiet:
            strict = min(fpr_targets)
            print(f"  {condition:16s} gru_contrastive  AUC={auc:.4f}  "
                  f"TPR@{strict:g}={fpr_results[strict][0]:.4f}  "
                  f"(train={time.perf_counter()-t0:.1f}s cumulative)", flush=True)

    out_path = os.path.join(args.out_dir, "flowcorr_gru_results.csv")
    with open(out_path, "w", newline="") as fp:
        fp.write("# Task B follow-up #2: Siamese GRU + InfoNCE-contrastive-loss\n")
        fp.write(f"# correlator. train_sessions={args.train_sessions} (separate RNG\n")
        fp.write(f"# stream from test), test_sessions={args.test_sessions}. Directly\n")
        fp.write("# comparable to flowcorr_results.csv / flowcorr_ml_results.csv.\n")
        fields = ["condition", "correlator", "fpr_target", "tpr", "tpr_ci95", "auc", "n_pairs"]
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        for r in result_rows:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v) for k, v in r.items()})
    print(f"\n  Wrote {out_path}  ({len(result_rows)} rows)")

    curve_path = os.path.join(args.out_dir, "flowcorr_gru_roc_curves.csv")
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
