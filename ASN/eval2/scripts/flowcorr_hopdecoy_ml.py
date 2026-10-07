#!/usr/bin/env python3
"""
flowcorr_hopdecoy_ml.py: stress-tests the hop-decoy + pool-mixing
mechanism against the paper's LEARNED (MLP) correlator,
not just the fixed statistical ones flowcorr_run.py defines. Both
flowcorr_ml.py and flowcorr_gru.py are trained/tested purely on
flowcorr_run.py's synthetic generator (no real-trace input path exists),
and a learned classifier needs far more than the ~20 real sessions a live
run (flowcorr_hopdecoy_live_run.sh) can practically capture to train
without overfitting, so this reuses the SAME synthetic-generator
approach flowcorr_run.py's own docstring documents and justifies ("use a
documented synthetic generator ... state the parameters"), adding THREE
new conditions that model the hop-decoy/pool-mixing mechanism using this
codebase's ACTUAL config.h/mix_node.c constants (HOP_DECOY_FRACTION_PCT=30,
HOP_DECOY_ENTRY/MID/EXIT_WEIGHT_PCT=10/80/10, POOL_MIX_FLUSH_MS=250), not
fitted/estimated rates. flowcorr_run.py/flowcorr_ml.py are imported, never
modified.

Three new conditions, all built on asn_one_path's existing cover/dispatch
model:
  asn_hopdecoy_nodelay  : hop-decoy packet-dropping only, no mixing at all
                          -- synthetic analogue of the live "decoy_only" run.
  asn_hopdecoy_honestmid: hop-decoy dropping + ASN_LOOPIX_MIXING-style
                          per-packet delay applied only to the exit-side
                          hop jitter, analogue of the live
                          "hopdecoy_honestmid" run (MN1/MN3 don't honestly
                          delay in this model either, matching the real
                          threat model: a compromised node has no reason
                          to cooperate with its own defense).
  asn_hopdecoy_poolmix  : hop-decoy dropping + genuine batch/pool mixing
                          (see apply_pool_mixing() below), analogue of
                          the live "hopdecoy_poolmix" run.
single_path (Tor-equivalent, unmodified) is kept as the baseline.

Usage:
    python flowcorr_hopdecoy_ml.py --train-sessions 300 --test-sessions 200 \
        --seed 20260710 --out-dir .
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
from flowcorr_run import (  # noqa: E402
    SESSION_DURATION_S, BIN_WIDTH_MS, N_HOPS_PATH, PER_HOP_JITTER_MS,
    gen_real_packet_times, gen_session, apply_hop_jitter,
    _cover_tick_ms, to_features, roc_tpr_at_fpr,
)
from flowcorr_ml import pairwise_features, batch_score_all_pairs  # noqa: E402

# config.h/mix_node.c's actual constants, not fitted values.
HOP_DECOY_FRACTION_PCT = 30
HOP_DECOY_EXIT_WEIGHT_PCT = 10
POOL_MIX_FLUSH_MS = 250.0  # mix_node.c's POOL_MIX_FLUSH_MS, post-fix value
N_INTERMEDIATE_HOPS = N_HOPS_PATH  # MN1->MN2->MN3, matches apply_hop_jitter's convention


def apply_pool_mixing(rng, times):
    """Models genuine batch/pool mixing (mix_node.c's ASN_POOL_MIXING,
    stratified-shuffle version): at each
    intermediate hop, a packet arriving at time t is captured into
    whichever POOL_MIX_FLUSH_MS-wide window it falls in, then released at
    a uniformly random point within that SAME window's dispatch, not
    just nudged by a small delay like ASN_LOOPIX_MIXING's per-packet
    jitter (hop_delay_sample()), which only shifts WHEN within a bin a
    packet lands. Batching changes HOW MANY packets land in a given
    correlator bin in the first place, which is what the live measurement
    showed hits the volume-only correlator (barely touched by pure delay)
    much harder. Applied once per intermediate hop, compounding exactly
    like the real per-hop mechanism, every hop between entry and exit
    pool-mixes independently in the actual build."""
    out = []
    for t in times:
        cur = t
        for _ in range(N_INTERMEDIATE_HOPS):
            cur += max(0.0, rng.gauss(*PER_HOP_JITTER_MS))  # propagation/crypto jitter, same as always
            bucket_release = (math.floor(cur / POOL_MIX_FLUSH_MS) + 1) * POOL_MIX_FLUSH_MS
            cur = bucket_release + rng.uniform(0.0, POOL_MIX_FLUSH_MS)
        out.append(cur)
    return out


def gen_entry_exit_with_hopdecoy(rng, real_times, duration_s, mixing_mode):
    """entry sees every dispatched packet (real, ordinary cover, AND every
    hop-decoy regardless of where it terminates, entry is always where a
    decoy is BUILT). exit sees real + ordinary cover always, but a
    hop-decoy only survives to exit with probability
    HOP_DECOY_EXIT_WEIGHT_PCT/100 (drawn independently per decoy, matching
    packet_sphinx_decoy_hop()'s weighted-random single termination-hop
    choice in the real implementation). mixing_mode: "none" | "delay" |
    "poolmix"."""
    horizon = duration_s * 1000.0
    credits = 0
    real_iter = iter(sorted(real_times))
    next_real = next(real_iter, None)
    entry_times, exit_survivor_times = [], []
    t = 0.0
    while t < horizon:
        t += _cover_tick_ms(rng)
        if t >= horizon:
            break
        while next_real is not None and next_real <= t:
            credits += 1
            next_real = next(real_iter, None)
        entry_times.append(t)
        if credits > 0:
            credits -= 1
            exit_survivor_times.append(t)          # real packet: always survives
        elif rng.uniform(0, 100) < HOP_DECOY_FRACTION_PCT:
            if rng.uniform(0, 100) < HOP_DECOY_EXIT_WEIGHT_PCT:
                exit_survivor_times.append(t)       # decoy terminates AT exit hop
            # else: dropped at entry or middle hop, entry-only
        else:
            exit_survivor_times.append(t)           # ordinary SG-reaching cover

    if mixing_mode == "poolmix":
        exit_times = sorted(apply_pool_mixing(rng, exit_survivor_times))
    else:
        exit_times = sorted(apply_hop_jitter(rng, exit_survivor_times, N_HOPS_PATH,
                                              hardened=(mixing_mode == "delay")))
    return sorted(entry_times), exit_times


def gen_session_hopdecoy(rng, flow_type, mixing_mode):
    real_times = gen_real_packet_times(rng, flow_type, SESSION_DURATION_S)
    entry, exit_ = gen_entry_exit_with_hopdecoy(
        rng, real_times, SESSION_DURATION_S, mixing_mode)
    return [(entry, exit_)]


def session_features(sessions):
    out = []
    for subpaths in sessions:
        feat = []
        for e, x, *_ in subpaths:
            ve, te = to_features(e, SESSION_DURATION_S, BIN_WIDTH_MS)
            vx, tx = to_features(x, SESSION_DURATION_S, BIN_WIDTH_MS)
            feat.append((ve, te, vx, tx))
        out.append(feat)
    return out


def gen_for_condition(rng, condition, i):
    flow_type = "interactive" if i % 2 == 0 else "bulk"
    if condition == "single_path":
        return gen_session(rng, flow_type, "single_path")
    if condition == "asn_hopdecoy_nodelay":
        return gen_session_hopdecoy(rng, flow_type, mixing_mode="none")
    if condition == "asn_hopdecoy_honestmid":
        return gen_session_hopdecoy(rng, flow_type, mixing_mode="delay")
    if condition == "asn_hopdecoy_poolmix":
        return gen_session_hopdecoy(rng, flow_type, mixing_mode="poolmix")
    raise ValueError(condition)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--train-sessions", type=int, default=300)
    ap.add_argument("--test-sessions", type=int, default=200)
    ap.add_argument("--neg-per-pos", type=int, default=5)
    ap.add_argument("--seed", type=int, default=20260710)
    ap.add_argument("--out-dir", default=".")
    args = ap.parse_args()

    from sklearn.neural_network import MLPClassifier
    from sklearn.preprocessing import StandardScaler

    os.makedirs(args.out_dir, exist_ok=True)
    conditions = ["single_path", "asn_hopdecoy_nodelay", "asn_hopdecoy_honestmid",
                  "asn_hopdecoy_poolmix"]
    t0 = time.perf_counter()
    result_rows = []

    for condition in conditions:
        train_rng = random.Random(args.seed + 1)
        train_sessions = [gen_for_condition(train_rng, condition, i)
                           for i in range(args.train_sessions)]
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

        test_rng = random.Random(args.seed)
        test_sessions = [gen_for_condition(test_rng, condition, i)
                          for i in range(args.test_sessions)]
        test_feat = session_features(test_sessions)
        score_matrix = batch_score_all_pairs(clf, scaler, test_feat, args.test_sessions)

        true_scores = [score_matrix[i, i] for i in range(args.test_sessions)]
        impostor_scores = [score_matrix[i, j]
                            for i in range(args.test_sessions)
                            for j in range(args.test_sessions) if i != j]

        fpr_results, auc, n_true, n_imp, _, _ = roc_tpr_at_fpr(
            true_scores, impostor_scores, [0.1, 0.01, 0.001])
        for target, (tpr, ci) in fpr_results.items():
            result_rows.append({
                "condition": condition, "correlator": "learned_mlp",
                "fpr_target": target, "tpr": tpr, "tpr_ci95": ci,
                "auc": auc, "n_pairs": n_true + n_imp,
            })
        t1, c1 = fpr_results[0.1]
        t01, c01 = fpr_results[0.01]
        t001, c001 = fpr_results[0.001]
        print(f"  {condition:28s} learned_mlp  AUC={auc:.4f}  "
              f"TPR@0.1={t1:.4f}+/-{c1:.4f}  TPR@0.01={t01:.4f}+/-{c01:.4f}  "
              f"TPR@0.001={t001:.4f}+/-{c001:.4f}")

    print(f"\n  Completed in {time.perf_counter()-t0:.1f}s")

    out_path = os.path.join(args.out_dir, "flowcorr_hopdecoy_ml_results.csv")
    with open(out_path, "w", newline="") as fp:
        fp.write("# Hop-decoy + pool-mixing vs learned (MLP) correlator\n")
        fp.write(f"# train_sessions={args.train_sessions}, test_sessions={args.test_sessions}\n")
        fields = ["condition", "correlator", "fpr_target", "tpr", "tpr_ci95", "auc", "n_pairs"]
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        for row in result_rows:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v)
                        for k, v in row.items()})
    print(f"  Wrote {out_path}  ({len(result_rows)} rows)")


if __name__ == "__main__":
    sys.exit(main())
