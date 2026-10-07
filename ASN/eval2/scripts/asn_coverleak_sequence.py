#!/usr/bin/env python3
"""
asn_coverleak_sequence.py: Task C follow-up: sequence-aware (LSTM and
a small Transformer) attackers on raw inter-packet-
interval sequences, vs. coverleak_run.py's 5s-windowed summary-statistic
baseline.

WHY THIS EXISTS
---------------------------------------------------------------------------
The logistic-regression-on-windowed-statistics attack is a
reasonable, literature-consistent choice but not adversarially
strongest: a sequence-aware model (an LSTM or small transformer over
the raw inter-packet-interval sequence, rather than 5s-window summary
statistics) could plausibly detect the load transition *faster*
(fewer real packets needed before AUC saturates), which matters for how
quickly a GPA could distinguish activity levels in a live deployment, not
just whether it eventually can. This script builds that model and tests
that specific claim.

MODEL
---------------------------------------------------------------------------
coverleak_run.py's baseline reduces every 5s window to 4 summary numbers
(packet count, mean/std/max inter-packet interval) before classifying.
This script instead feeds the RAW inter-packet-interval sequence within a
window directly into a small LSTM (single layer, 32 hidden units) that
reads the sequence step-by-step and classifies from its final hidden
state: the sequence order and fine-grained burst structure a 4-number
summary discards is available to this model. Sequences are log1p-scaled
(IPIs span orders of magnitude between real-traffic and cover-traffic
regimes) and padded/masked to a fixed max length per experiment.

Reuses coverleak_run.py's exact session generators (`gen_real_times`,
`gen_cover_asn_adaptive`) unmodified, only the feature extraction and
classifier differ from the baseline.

TWO EXPERIMENTS, BOTH OPERATIONALIZING "DETECTS FASTER"
---------------------------------------------------------------------------
A. Shorter windows, fixed load L=0.5 (the established AUC-0.9
   transition point): sweep window duration W in {1, 2, 3, 5} seconds.
   Does the LSTM reach the baseline's 5s AUC using less observation time?
B. Fixed window W=5s, lower loads L in {0.1, 0.2, 0.3, 0.4, 0.5}: does the
   LSTM detect load levels the baseline (near chance up to L=0.3) cannot?

Both experiments re-run the baseline classifier (imported logic, not
reimplemented) at the SAME window/load grid for a fair, directly
comparable AUC-vs-AUC table.

TRANSFORMER VARIANT
---------------------------------------------------------------------------
Since the LSTM alone doesn't outperform the baseline, this also tries a
different architecture: a compact
Transformer encoder (2 layers, d_model=32, 2 heads, learned positional
embeddings, masked mean-pool readout) over the SAME raw log1p-scaled IPI
input the LSTM uses, trained/evaluated at the identical grid points, so
any AUC difference is attributable to architecture alone, not features
or data. See IPISeqTransformer/train_transformer/score_transformer below.

Requires torch (CPU is fine; sequences and models here are small).

Usage:
    python asn_coverleak_sequence.py --sessions 300 --seed 20260710 --out-dir .
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
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from coverleak_run import R_MAX_PPS, gen_real_times, gen_cover_asn_adaptive
from flowcorr_run import roc_tpr_at_fpr

MAX_SEQ_LEN = 400   # generous upper bound; longer sequences truncated


# ---------------------------------------------------------------------------
# Session -> windowed raw-IPI-sequence / summary-stat features
# ---------------------------------------------------------------------------
def gen_window_events(rng: random.Random, load_level: float, window_s: float):
    """One session's worth of (real+cover) event times within [0, window_s),
    using coverleak_run.py's exact generators, restricted to a single
    window rather than the full 60s session (a real adversary observing
    for W seconds only sees W seconds of traffic, generating the full
    60s session and truncating is equivalent and simpler)."""
    real = gen_real_times(rng, load_level * R_MAX_PPS, window_s)
    cover = gen_cover_asn_adaptive(rng, real, window_s)
    return sorted(real + cover)


def to_sequence_feature(times_ms, max_len=MAX_SEQ_LEN):
    """Raw IPI sequence (ms), log1p-scaled, padded/truncated to max_len.
    Returns (sequence, true_length)."""
    if len(times_ms) < 2:
        ipis = np.array([0.0], dtype=np.float32)
    else:
        ipis = np.diff(np.array(times_ms, dtype=np.float64)).astype(np.float32)
    ipis = np.log1p(ipis)
    length = min(len(ipis), max_len)
    seq = np.zeros(max_len, dtype=np.float32)
    seq[:length] = ipis[:length]
    return seq, max(1, length)


def standardize_sequences(X_train, X_other_list):
    """Z-score using train-set statistics over non-padding positions only
    (padding stays 0, which is also the standardized mean, avoids the
    model learning to use padding-vs-real-value scale as a shortcut
    feature). X_other_list: list of additional arrays to transform with
    the same fitted stats (e.g. the test set)."""
    mask = X_train != 0.0
    if mask.sum() == 0:
        mean, std = 0.0, 1.0
    else:
        vals = X_train[mask]
        mean, std = float(vals.mean()), float(vals.std() + 1e-6)
    def apply(X):
        out = X.copy()
        m = X != 0.0
        out[m] = (X[m] - mean) / std
        return out
    return apply(X_train), [apply(X) for X in X_other_list]


def to_summary_feature(times_ms):
    """coverleak_run.py's exact 4-number window_features, reimplemented
    inline (single-window special case of the imported function's logic)
    to avoid importing a function tied to its fixed 5s/60s session
    assumptions."""
    count = len(times_ms)
    if count >= 2:
        gaps = np.diff(np.array(times_ms))
        mean_ipi, std_ipi, max_ipi = float(np.mean(gaps)), float(np.std(gaps)), float(np.max(gaps))
    else:
        mean_ipi, std_ipi, max_ipi = 0.0, 0.0, 0.0
    return [count, mean_ipi, std_ipi, max_ipi]


# ---------------------------------------------------------------------------
# LSTM classifier
# ---------------------------------------------------------------------------
class IPISeqLSTM(nn.Module):
    def __init__(self, hidden_size=32):
        super().__init__()
        self.lstm = nn.LSTM(input_size=1, hidden_size=hidden_size, num_layers=1, batch_first=True)
        self.head = nn.Linear(hidden_size, 1)

    def forward(self, seq_batch, lengths):
        # seq_batch: (B, T), lengths: (B,)
        x = seq_batch.unsqueeze(-1)  # (B, T, 1)
        packed = nn.utils.rnn.pack_padded_sequence(
            x, lengths.cpu(), batch_first=True, enforce_sorted=False)
        _, (h_n, _) = self.lstm(packed)
        logits = self.head(h_n[-1]).squeeze(-1)
        return logits


def train_lstm(X_seq, lengths, y, epochs=150, lr=3e-3, seed=0, batch_size=32):
    torch.manual_seed(seed)
    model = IPISeqLSTM()
    opt = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)
    loss_fn = nn.BCEWithLogitsLoss()
    X_t = torch.from_numpy(X_seq)
    len_t = torch.from_numpy(lengths)
    y_t = torch.from_numpy(y.astype(np.float32))
    n = X_t.shape[0]
    model.train()
    for epoch in range(epochs):
        perm = torch.randperm(n)
        for start in range(0, n, batch_size):
            idx = perm[start:start + batch_size]
            opt.zero_grad()
            logits = model(X_t[idx], len_t[idx])
            loss = loss_fn(logits, y_t[idx])
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 5.0)
            opt.step()
    return model


def score_lstm(model, X_seq, lengths):
    model.eval()
    with torch.no_grad():
        logits = model(torch.from_numpy(X_seq), torch.from_numpy(lengths))
        return torch.sigmoid(logits).numpy()


# ---------------------------------------------------------------------------
# Transformer classifier. Same raw log1p-scaled IPI input as the LSTM,
# so any difference in result is attributable to architecture, not
# features.
# ---------------------------------------------------------------------------
class IPISeqTransformer(nn.Module):
    def __init__(self, d_model=32, nhead=2, num_layers=2, max_len=MAX_SEQ_LEN):
        super().__init__()
        self.input_proj = nn.Linear(1, d_model)
        # Learned positional embedding, not sinusoidal, sequence length
        # here is at most MAX_SEQ_LEN (400) and this is a from-scratch
        # small model with no pretraining to transfer positional priors
        # from, so a learned table is simpler and equally standard at
        # this scale.
        self.pos_embed = nn.Parameter(torch.randn(max_len, d_model) * 0.02)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead, dim_feedforward=d_model * 2,
            batch_first=True, dropout=0.1)
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.head = nn.Linear(d_model, 1)

    def forward(self, seq_batch, lengths):
        # seq_batch: (B, T), lengths: (B,)
        B, T = seq_batch.shape
        x = self.input_proj(seq_batch.unsqueeze(-1)) + self.pos_embed[:T].unsqueeze(0)
        arange = torch.arange(T, device=seq_batch.device).unsqueeze(0)
        pad_mask = arange >= lengths.unsqueeze(1)  # True where padded, (B, T)
        out = self.encoder(x, src_key_padding_mask=pad_mask)  # (B, T, d_model)
        # Masked mean-pool over valid (non-padded) positions rather than a
        # [CLS]-token or last-position readout, matches the LSTM's
        # "summarize the whole sequence" role without introducing an
        # asymmetry (a [CLS] token would need its own untested design
        # choice; mean-pool is the more directly comparable minimal
        # variant given the LSTM already reads the whole sequence into
        # its final hidden state).
        valid = (~pad_mask).unsqueeze(-1).float()
        pooled = (out * valid).sum(dim=1) / valid.sum(dim=1).clamp(min=1.0)
        logits = self.head(pooled).squeeze(-1)
        return logits


def train_transformer(X_seq, lengths, y, epochs=150, lr=3e-3, seed=0, batch_size=32,
                       max_len=MAX_SEQ_LEN):
    torch.manual_seed(seed)
    model = IPISeqTransformer(max_len=max_len)
    opt = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)
    loss_fn = nn.BCEWithLogitsLoss()
    X_t = torch.from_numpy(X_seq)
    len_t = torch.from_numpy(lengths)
    y_t = torch.from_numpy(y.astype(np.float32))
    n = X_t.shape[0]
    model.train()
    for epoch in range(epochs):
        perm = torch.randperm(n)
        for start in range(0, n, batch_size):
            idx = perm[start:start + batch_size]
            opt.zero_grad()
            logits = model(X_t[idx], len_t[idx])
            loss = loss_fn(logits, y_t[idx])
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 5.0)
            opt.step()
    return model


def score_transformer(model, X_seq, lengths):
    model.eval()
    with torch.no_grad():
        logits = model(torch.from_numpy(X_seq), torch.from_numpy(lengths))
        return torch.sigmoid(logits).numpy()


# ---------------------------------------------------------------------------
# One (load_level, window_s) grid point: generate data, train+eval both
# classifiers on a held-out split, return AUC/TPR-at-FPR for each.
# ---------------------------------------------------------------------------
def run_grid_point(rng_data: random.Random, load_level: float, window_s: float,
                    n_sessions: int, fpr_targets, seed: int = 0):
    idle_times = [gen_window_events(rng_data, 0.0, window_s) for _ in range(n_sessions)]
    load_times = [gen_window_events(rng_data, load_level, window_s) for _ in range(n_sessions)]

    n_train = n_sessions // 2
    train_idle, test_idle = idle_times[:n_train], idle_times[n_train:]
    train_load, test_load = load_times[:n_train], load_times[n_train:]

    # ---- Baseline: LogisticRegression on 4-number summary stats ----
    Xtr_sum = np.array([to_summary_feature(t) for t in train_idle + train_load])
    ytr = np.array([0] * len(train_idle) + [1] * len(train_load))
    Xte_sum = np.array([to_summary_feature(t) for t in test_idle + test_load])
    yte = np.array([0] * len(test_idle) + [1] * len(test_load))

    scaler = StandardScaler().fit(Xtr_sum)
    clf = LogisticRegression(max_iter=1000).fit(scaler.transform(Xtr_sum), ytr)
    proba_baseline = clf.predict_proba(scaler.transform(Xte_sum))[:, 1]

    # ---- LSTM: raw IPI sequence ----
    max_len = min(MAX_SEQ_LEN, max(2, max(len(t) for t in train_idle + train_load + [[0, 0]])))
    seq_lengths = lambda times_list: [to_sequence_feature(t, max_len) for t in times_list]

    tr_feats = seq_lengths(train_idle) + seq_lengths(train_load)
    te_feats = seq_lengths(test_idle) + seq_lengths(test_load)
    Xtr_seq = np.stack([f[0] for f in tr_feats]).astype(np.float32)
    Ltr = np.array([f[1] for f in tr_feats], dtype=np.int64)
    Xte_seq = np.stack([f[0] for f in te_feats]).astype(np.float32)
    Lte = np.array([f[1] for f in te_feats], dtype=np.int64)
    Xtr_seq, [Xte_seq] = standardize_sequences(Xtr_seq, [Xte_seq])

    # Combines --seed with (load_level, window_s) so --seed genuinely
    # controls both the data (via rng_data) and the model's own training
    # stochasticity (weight init, batch order), while still giving each
    # grid point its own distinct seed.
    grid_seed = seed * 1000003 + int(load_level * 1000 + window_s)
    model = train_lstm(Xtr_seq, Ltr, ytr, seed=grid_seed)
    proba_lstm = score_lstm(model, Xte_seq, Lte)

    # ---- Transformer: same raw IPI sequence, different architecture ----
    tmodel = train_transformer(Xtr_seq, Ltr, ytr,
                                seed=grid_seed, max_len=max_len)
    proba_transformer = score_transformer(tmodel, Xte_seq, Lte)

    results = {}
    for name, proba in [("baseline_summary", proba_baseline), ("lstm_sequence", proba_lstm),
                         ("transformer_sequence", proba_transformer)]:
        true_scores = proba[yte == 1]
        impostor_scores = proba[yte == 0]
        roc_results, auc, n_true, n_imp, _, _ = roc_tpr_at_fpr(true_scores, impostor_scores, fpr_targets)
        results[name] = {"auc": auc, "tpr_at_fpr": {f: roc_results[f][0] for f in fpr_targets}}
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sessions", type=int, default=300,
                     help="Total sessions per class (idle/load), split half train / half test")
    ap.add_argument("--seed", type=int, default=20260710)
    ap.add_argument("--out-dir", default=".")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    rng_data = random.Random(args.seed)
    fpr_targets = [0.1, 0.01]

    rows = []
    t0 = time.perf_counter()

    print("=" * 78)
    print("  Task C follow-up: sequence-aware (LSTM) attacker vs. windowed baseline")
    print("=" * 78)

    # ---- Experiment A: fixed load L=0.5, sweep window duration ----
    print("\n  Experiment A: fixed load L=0.5, window duration swept")
    for window_s in [1.0, 2.0, 3.0, 5.0]:
        res = run_grid_point(rng_data, 0.5, window_s, args.sessions, fpr_targets, seed=args.seed)
        for model_name, r in res.items():
            rows.append({
                "experiment": "A_window_sweep", "load_level": 0.5, "window_s": window_s,
                "model": model_name, "auc": r["auc"],
                "tpr_fpr0.1": r["tpr_at_fpr"][0.1], "tpr_fpr0.01": r["tpr_at_fpr"][0.01],
            })
        print(f"    W={window_s:.0f}s  baseline AUC={res['baseline_summary']['auc']:.3f}  "
              f"lstm AUC={res['lstm_sequence']['auc']:.3f}  "
              f"transformer AUC={res['transformer_sequence']['auc']:.3f}")

    # ---- Experiment B: fixed window W=5s, sweep load level ----
    print("\n  Experiment B: fixed window W=5s, load level swept")
    for load_level in [0.1, 0.2, 0.3, 0.4, 0.5]:
        res = run_grid_point(rng_data, load_level, 5.0, args.sessions, fpr_targets, seed=args.seed)
        for model_name, r in res.items():
            rows.append({
                "experiment": "B_load_sweep", "load_level": load_level, "window_s": 5.0,
                "model": model_name, "auc": r["auc"],
                "tpr_fpr0.1": r["tpr_at_fpr"][0.1], "tpr_fpr0.01": r["tpr_at_fpr"][0.01],
            })
        print(f"    L={load_level:.1f}  baseline AUC={res['baseline_summary']['auc']:.3f}  "
              f"lstm AUC={res['lstm_sequence']['auc']:.3f}  "
              f"transformer AUC={res['transformer_sequence']['auc']:.3f}")

    print(f"\n  Completed in {time.perf_counter()-t0:.1f}s")

    out_path = os.path.join(args.out_dir, "asn_coverleak_sequence.csv")
    with open(out_path, "w", newline="") as fp:
        fp.write("# Task C follow-up: sequence-aware (LSTM and Transformer, raw IPI\n")
        fp.write("# sequence) attackers vs. coverleak_run.py's windowed-summary-statistic\n")
        fp.write("# baseline. Transformer uses the same raw-IPI input as the\n")
        fp.write("# LSTM, so any AUC gap between the two is attributable to architecture.\n")
        fp.write("# experiment A: fixed load_level=0.5, window_s swept (1/2/3/5s).\n")
        fp.write("# experiment B: fixed window_s=5.0, load_level swept (0.1-0.5).\n")
        fields = ["experiment", "load_level", "window_s", "model", "auc",
                  "tpr_fpr0.1", "tpr_fpr0.01"]
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v) for k, v in r.items()})
    print(f"  Wrote {out_path}  ({len(rows)} rows)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
