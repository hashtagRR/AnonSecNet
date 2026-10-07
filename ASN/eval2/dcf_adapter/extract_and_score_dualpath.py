"""Like extract_and_score.py, but for the asn_both_paths condition:
groups each test flow by its ORIGINAL session (recovered from the saved
circuit-label idx: session = idx // 2, path = idx % 2, matching
gen_dcf_traces.py's write order), and scores a candidate (sender,
receiver) pair as max(similarity on path A, similarity on path B) when
BOTH paths for that session survived into the test set, mirroring
flowcorr_run.py's score_session_pair() convention exactly (an adversary
who controls both paths falls back to whichever leaks more, not an
average). Sessions where only one path survived the filter/test-split
are scored on that single path (adversary observes only one path)."""
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
tor_windows = test_data['tor']
exit_windows = test_data['exit']
labels = test_data['labels']  # circuit idx per test row, e.g. 384 -> session 192, path 0
n_windows = tor_windows.shape[0]
n_flows = tor_windows.shape[1]
print("n_windows", n_windows, "n_flows", n_flows, "n_labels", len(labels))

sim_accum = np.zeros((n_flows, n_flows))
for w in range(n_windows):
    tor_embs = tor_model.predict(tor_windows[w])
    exit_embs = exit_model.predict(exit_windows[w])
    tor_embs = tor_embs / np.linalg.norm(tor_embs, axis=-1, keepdims=True)
    exit_embs = exit_embs / np.linalg.norm(exit_embs, axis=-1, keepdims=True)
    sim_accum += np.dot(tor_embs, exit_embs.T)
sim_avg = sim_accum / n_windows

# Group test-row indices by session id.
session_of = {}
for row_i, idx in enumerate(labels):
    session = int(idx) // 2
    session_of.setdefault(session, []).append(row_i)

single_path_sessions = [rows for rows in session_of.values() if len(rows) == 1]
dual_path_sessions = [rows for rows in session_of.values() if len(rows) == 2]
print("sessions with both paths in test set:", len(dual_path_sessions),
      " / single-path-only:", len(single_path_sessions))

true_scores = []
impostor_scores = []
all_rows = list(range(n_flows))

for rows in session_of.values():
    # True pair: max similarity across this session's surviving path(s),
    # each path's true correlation is sim_avg[row, row].
    true_scores.append(max(sim_avg[r, r] for r in rows))

# Impostor pairs: for each session, pair its row(s) against a different
# session's row(s), again taking the max across whichever paths this
# candidate has.
session_ids = list(session_of.keys())
for i, sid_a in enumerate(session_ids):
    rows_a = session_of[sid_a]
    for sid_b in session_ids:
        if sid_b == sid_a:
            continue
        rows_b = session_of[sid_b]
        # candidate = rows_a (entry side), tested against rows_b (exit side)
        scores = [sim_avg[ra, rb] for ra in rows_a for rb in rows_b]
        impostor_scores.append(max(scores))

np.savez(args.out, true_scores=true_scores, impostor_scores=impostor_scores)
print("true_scores (session-level, max-over-paths): mean={:.4f} std={:.4f} n={}".format(
    np.mean(true_scores), np.std(true_scores), len(true_scores)))
print("impostor_scores (session-level, max-over-paths): mean={:.4f} std={:.4f} n={}".format(
    np.mean(impostor_scores), np.std(impostor_scores), len(impostor_scores)))
print("Wrote", args.out)
