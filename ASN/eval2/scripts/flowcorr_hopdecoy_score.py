#!/usr/bin/env python3
"""
flowcorr_hopdecoy_score.py: scores real MN1/MN3 traces captured by
flowcorr_hopdecoy_live_run.sh using the SAME correlator functions
flowcorr_run.py already defines (Pearson volume, combined Pearson+cosine
volume+timing), imported, not reimplemented, so the scoring methodology
matches every other result in this file exactly. flowcorr_run.py is
read-only here.

Ground truth: each node's trace groups by its own local session-table
index (stable for one session's lifetime at that ONE node, not
comparable across nodes directly). Sessions are launched externally in a
known, staggered order (flowcorr_hopdecoy_live_run.sh, 1.5s apart); at
this concurrency, with no session-table reclamation, the Nth session to
FIRST APPEAR at MN1 (sorted by first-seen time) is the same real session
as the Nth to first appear at MN3, so sessions are paired by rank
order, not by session-table index directly. This is a controlled-
experiment pairing assumption (documented, not something a real attacker
would have), used only to know which pairs are "true" vs "impostor"
for scoring, never fed to the correlator itself as a feature.

Usage:
    python flowcorr_hopdecoy_score.py --out-dir hopdecoy_live \
        --modes plain,decoy_only,hopdecoy,hopdecoy_honestmid,hopdecoy_poolmix
"""
import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flowcorr_run import to_features, score_pair, roc_tpr_at_fpr  # noqa: E402

BIN_WIDTH_MS = 500.0

CONDITION_LABELS = {
    "plain": "Baseline: no hop-decoy, no delay anywhere (mix_node.exe)",
    "decoy_only": "Hop-decoy ONLY, zero delay on any hop (mix_node_hopdecoy.exe)",
    "hopdecoy": "Hop-decoy + delay honestly run on ALL hops incl. MN1/MN3 "
                "(overstates the effect, a compromised MN1/MN3 wouldn't "
                "cooperate with its own delay)",
    "hopdecoy_honestmid": "Hop-decoy + delay ONLY at MN2 (MN1/MN3 delay=0) "
                           "-- the realistic version",
    "hopdecoy_poolmix": "Hop-decoy + genuine batch/pool mixing at every hop "
                         "(mix_node_hopdecoy_poolmix.exe)",
}


def load_sessions(path):
    """Returns list of sorted-time-lists per session-table index, ordered
    by each session's own first-seen timestamp ascending (rank order)."""
    groups = {}
    with open(path) as f:
        for row in csv.reader(f):
            if len(row) != 2:
                continue
            sidx, t = row
            groups.setdefault(int(sidx), []).append(float(t))
    sessions = []
    for _sidx, times in groups.items():
        times.sort()
        sessions.append((times[0], times))
    sessions.sort(key=lambda x: x[0])
    return [t for _, t in sessions]


def duration_s(entry_sessions, exit_sessions):
    all_t = [t for s in entry_sessions + exit_sessions for t in s]
    span_ms = (max(all_t) - min(all_t)) if all_t else 1000.0
    return max(span_ms / 1000.0, 1.0)


def score_condition(entry_path, exit_path, label):
    entry_sessions = load_sessions(entry_path)
    exit_sessions = load_sessions(exit_path)
    n = min(len(entry_sessions), len(exit_sessions))
    if len(entry_sessions) != len(exit_sessions):
        print(f"  [{label}] WARNING: {len(entry_sessions)} MN1 sessions vs "
              f"{len(exit_sessions)} MN3 sessions, using first {n} of each "
              f"by rank")
    entry_sessions = entry_sessions[:n]
    exit_sessions = exit_sessions[:n]

    dur = duration_s(entry_sessions, exit_sessions)
    entry_feats, exit_feats = [], []
    for times in entry_sessions:
        t0 = times[0]
        v, t = to_features([x - t0 for x in times], dur, BIN_WIDTH_MS)
        entry_feats.append((v, t))
    for times in exit_sessions:
        t0 = times[0]
        v, t = to_features([x - t0 for x in times], dur, BIN_WIDTH_MS)
        exit_feats.append((v, t))

    for correlator in ("pearson_volume", "combined"):
        true_scores, impostor_scores = [], []
        for i in range(n):
            for j in range(n):
                s = score_pair(entry_feats[i][0], entry_feats[i][1],
                                exit_feats[j][0], exit_feats[j][1], correlator)
                (true_scores if i == j else impostor_scores).append(s)
        fpr_results, auc, n_true, n_imp, _, _ = roc_tpr_at_fpr(
            true_scores, impostor_scores, [0.1, 0.01])
        t1, c1 = fpr_results[0.1]
        t01, c01 = fpr_results[0.01]
        print(f"  [{label}] {correlator:16s} AUC={auc:.4f}  "
              f"TPR@0.1={t1:.4f}+/-{c1:.4f}  TPR@0.01={t01:.4f}+/-{c01:.4f}  "
              f"(n_true={n_true}, n_impostor={n_imp})")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", default="hopdecoy_live",
                     help="directory flowcorr_hopdecoy_live_run.sh wrote traces into")
    ap.add_argument("--modes", default="plain,decoy_only,hopdecoy,"
                                        "hopdecoy_honestmid,hopdecoy_poolmix")
    args = ap.parse_args()

    # Entry/exit hop ports are 9040/9042 (config.h's PORT_MIX_I/III).
    # Some older committed traces are still named with earlier ports,
    # left alone, not renamed. Try both conventions, new first (matches
    # what a fresh flowcorr_hopdecoy_live_run.sh run now actually writes).
    for mode in args.modes.split(","):
        candidates_e = [
            os.path.join(args.out_dir, f"hopdecoy_trace_9040_{mode}.csv"),
            os.path.join(args.out_dir, "hopdecoy_trace_9040.csv"),
            os.path.join(args.out_dir, f"hopdecoy_trace_9030_{mode}.csv"),
            os.path.join(args.out_dir, "hopdecoy_trace_9030.csv"),
        ]
        candidates_x = [
            os.path.join(args.out_dir, f"hopdecoy_trace_9042_{mode}.csv"),
            os.path.join(args.out_dir, "hopdecoy_trace_9042.csv"),
            os.path.join(args.out_dir, f"hopdecoy_trace_9032_{mode}.csv"),
            os.path.join(args.out_dir, "hopdecoy_trace_9032.csv"),
        ]
        e = next((p for p in candidates_e if os.path.exists(p)), candidates_e[0])
        x = next((p for p in candidates_x if os.path.exists(p)), candidates_x[0])
        if not (os.path.exists(e) and os.path.exists(x)):
            print(f"[{mode}] SKIPPED, trace files not found "
                  f"(run flowcorr_hopdecoy_live_run.sh {mode} <out-dir> first)")
            continue
        print(f"{CONDITION_LABELS.get(mode, mode)}:")
        score_condition(e, x, mode)
        print()


if __name__ == "__main__":
    sys.exit(main())
