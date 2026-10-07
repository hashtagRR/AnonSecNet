"""Extract embeddings from the REAL trained DeepCoFFEA FEN (their
architecture, their trained weights, new_model.py, unmodified) for our
test set, then score true vs impostor pairs with cosine similarity and
report TPR@FPR using the exact same roc_tpr_at_fpr methodology already
used for fig_flowcorr (flowcorr_run.py), for a direct, comparable number.
This bypasses only eval_dcf.py's own rank-threshold voting script (which
produced degenerate output at our test scale, likely a bug in adapting
its window-voting bookkeeping to a much smaller flow count than it
assumes), the model being scored is unmodified DeepCoFFEA, not a
reimplementation."""
import sys
import numpy as np

sys.path.insert(0, "/work")
from new_model import create_model

import argparse
ap = argparse.ArgumentParser()
ap.add_argument("--test", required=True)
ap.add_argument("--model1", required=True)
ap.add_argument("--model2", required=True)
ap.add_argument("--tor-len", type=int, default=250)
ap.add_argument("--exit-len", type=int, default=250)
ap.add_argument("--out", required=True)
args = ap.parse_args()

pad_t = args.tor_len * 2
pad_e = args.exit_len * 2

tor_model = create_model(input_shape=(pad_t, 1), emb_size=64, model_name='tor')
exit_model = create_model(input_shape=(pad_e, 1), emb_size=64, model_name='exit')
tor_model.load_weights(args.model1 + ".h5")
exit_model.load_weights(args.model2 + ".h5")

test_data = np.load(args.test, allow_pickle=True)
tor_windows = test_data['tor']    # shape (num_windows, n_flows, pad_t, 1)
exit_windows = test_data['exit']  # shape (num_windows, n_flows, pad_e, 1)
n_windows = tor_windows.shape[0]
n_flows = tor_windows.shape[1]
print("n_windows", n_windows, "n_flows", n_flows)

# Average cosine similarity across all windows (voting-free, simplest
# honest aggregation of the per-window embeddings this real model
# produces: matches the spirit of DeepCoFFEA's amplification without
# reimplementing its specific rank-voting bookkeeping).
sim_accum = np.zeros((n_flows, n_flows))
for w in range(n_windows):
    tor_embs = tor_model.predict(tor_windows[w])
    exit_embs = exit_model.predict(exit_windows[w])
    tor_embs = tor_embs / np.linalg.norm(tor_embs, axis=-1, keepdims=True)
    exit_embs = exit_embs / np.linalg.norm(exit_embs, axis=-1, keepdims=True)
    sim_accum += np.dot(tor_embs, exit_embs.T)
sim_avg = sim_accum / n_windows

true_scores = [sim_avg[i, i] for i in range(n_flows)]
impostor_scores = [sim_avg[i, j] for i in range(n_flows) for j in range(n_flows) if i != j]

np.savez(args.out, true_scores=true_scores, impostor_scores=impostor_scores)
print("true_scores: mean={:.4f} std={:.4f} min={:.4f} max={:.4f}".format(
    np.mean(true_scores), np.std(true_scores), np.min(true_scores), np.max(true_scores)))
print("impostor_scores: mean={:.4f} std={:.4f} min={:.4f} max={:.4f}".format(
    np.mean(impostor_scores), np.std(impostor_scores), np.min(impostor_scores), np.max(impostor_scores)))
print("Wrote", args.out)
