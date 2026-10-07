#!/usr/bin/env python3
"""
flowcorr_hopdecoy_gru.py: same hop-decoy/pool-mixing conditions as
flowcorr_hopdecoy_ml.py, scored against the paper's
hardest correlator: the Siamese GRU + contrastive-loss sequence encoder
(flowcorr_gru.py), the closest analogue in this project to real
published sequence-aware attacks (DeepCoFFEA/RECTor). Reuses
flowcorr_gru.py's model/training code and flowcorr_hopdecoy_ml.py's
condition generators, both imported unmodified.

Usage:
    python flowcorr_hopdecoy_gru.py --train-sessions 300 --test-sessions 200 \
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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flowcorr_run import SESSION_DURATION_S, BIN_WIDTH_MS, to_features, roc_tpr_at_fpr  # noqa: E402
from flowcorr_gru import train_encoder, embed_all  # noqa: E402
from flowcorr_hopdecoy_ml import gen_for_condition  # noqa: E402


def build_sequence_pair(session):
    """session: [(entry_times, exit_times)] (single sub-path, matching
    gen_for_condition's return shape for these conditions)."""
    e, x = session[0]
    ve, te = to_features(e, SESSION_DURATION_S, BIN_WIDTH_MS)
    vx, tx = to_features(x, SESSION_DURATION_S, BIN_WIDTH_MS)
    entry_seq = np.stack([ve, te], axis=1).astype(np.float32)
    exit_seq = np.stack([vx, tx], axis=1).astype(np.float32)
    return entry_seq, exit_seq


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--train-sessions", type=int, default=300)
    ap.add_argument("--test-sessions", type=int, default=200)
    ap.add_argument("--seed", type=int, default=20260710)
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--fpr-targets", default="1e-1,1e-2,1e-3")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    fpr_targets = [float(x) for x in args.fpr_targets.split(",")]
    conditions = ["single_path", "asn_hopdecoy_nodelay", "asn_hopdecoy_honestmid",
                  "asn_hopdecoy_poolmix"]
    t0 = time.perf_counter()
    result_rows = []

    for ci, condition in enumerate(conditions):
        train_rng = random.Random(args.seed + 1)
        train_pairs = [build_sequence_pair(gen_for_condition(train_rng, condition, i))
                       for i in range(args.train_sessions)]

        condition_seed = (args.seed + 500_000 * (ci + 1)) % (2**31)
        model, _ = train_encoder(train_pairs, seed=condition_seed)

        entry_train_arr = np.stack([p[0] for p in train_pairs])
        mean = entry_train_arr.reshape(-1, 2).mean(axis=0)
        std = entry_train_arr.reshape(-1, 2).std(axis=0) + 1e-6

        test_rng = random.Random(args.seed)
        entry_embeds, exit_embeds = [], []
        for i in range(args.test_sessions):
            e_seq, x_seq = build_sequence_pair(gen_for_condition(test_rng, condition, i))
            e_seq = (e_seq - mean) / std
            x_seq = (x_seq - mean) / std
            entry_embeds.append(embed_all(model, e_seq[None, ...])[0])
            exit_embeds.append(embed_all(model, x_seq[None, ...])[0])

        true_scores, impostor_scores = [], []
        for i in range(args.test_sessions):
            for j in range(args.test_sessions):
                s = float(np.dot(entry_embeds[i], exit_embeds[j]))
                (true_scores if i == j else impostor_scores).append(s)

        fpr_results, auc, n_true, n_imp, _, _ = roc_tpr_at_fpr(
            true_scores, impostor_scores, fpr_targets)
        for target, (tpr, ci_) in fpr_results.items():
            result_rows.append({
                "condition": condition, "correlator": "gru_contrastive",
                "fpr_target": target, "tpr": tpr, "tpr_ci95": ci_,
                "auc": auc, "n_pairs": n_true + n_imp,
            })
        strict = min(fpr_targets)
        print(f"  {condition:28s} gru_contrastive  AUC={auc:.4f}  "
              f"TPR@{strict:g}={fpr_results[strict][0]:.4f}  "
              f"(elapsed={time.perf_counter()-t0:.1f}s)", flush=True)

    out_path = os.path.join(args.out_dir, "flowcorr_hopdecoy_gru_results.csv")
    with open(out_path, "w", newline="") as fp:
        fp.write("# Hop-decoy + pool-mixing vs GRU-contrastive correlator\n")
        fp.write(f"# train_sessions={args.train_sessions}, test_sessions={args.test_sessions}\n")
        fields = ["condition", "correlator", "fpr_target", "tpr", "tpr_ci95", "auc", "n_pairs"]
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        for row in result_rows:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v)
                        for k, v in row.items()})
    print(f"  Wrote {out_path}  ({len(result_rows)} rows)")


if __name__ == "__main__":
    torch.set_num_threads(4)
    sys.exit(main())
