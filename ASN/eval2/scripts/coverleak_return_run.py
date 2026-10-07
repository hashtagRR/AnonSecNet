#!/usr/bin/env python3
"""
coverleak_return_run.py: Task C methodology applied to the RETURN
direction: does real traffic leak activity level on the return-path
link, the same way coverleak_run.py answers that question for the
forward/client-dispatch link.

WHY THIS EXISTS
---------------------------------------------------------------------------
coverleak_run.py answers "does real traffic leak on the forward/client-
dispatch link" for the production client.c/sender.c mechanism, with a
proper multi-trial classifier (LogisticRegression, 5-fold CV, AUC). The
return-path side of that question needs the identical multi-trial
classifier treatment, not just a single-trial volume comparison. This
script is that treatment.

MODEL
---------------------------------------------------------------------------
The return path's packet-arrival process is NOT independent of the
forward path, it's directly downstream of it, so this reuses
coverleak_run.py's own forward-path generators rather than modeling the
return path as its own independent process:

  1. gen_real_times(), a session's real request arrivals (imported,
     unchanged).
  2. gen_cover_asn_adaptive(), the client/sender's own forward cover
     clock with Step-8.6-style one-for-one suppression when real traffic
     is present (imported, unchanged), this is the SAME mechanism
     confirmed today in both client.c and sender.c
     (g_real_traffic_pending), and is what made the empirical
     idle-vs-active return-path measurement come back NEGATIVE (fewer
     forward-cover ticks survive to trigger return-cover when real
     traffic is present) rather than the naively-expected increase.
  3. Hop-decoy diversion: each surviving forward-cover tick independently
     has a HOP_DECOY_FRACTION_PCT chance of terminating at an interior
     hop instead of reaching the SG (config.h), only "plain" (0%) and
     "decoy_only" (HOP_DECOY_FRACTION_PCT) are modeled, matching the two
     conditions the original live measurement used.
  4. The return-path mailbox (service_gateway.c):
     every forward-cover tick that DOES reach the SG is one dispatch
     trigger. If a real response is pending for this session at that
     moment, dispatch it (draining the mailbox); otherwise dispatch
     ordinary return-cover, either way, exactly one return-path packet.
     A real request's response becomes "pending" almost at the
     request's own arrival time (the round trip itself is fast relative
     to cover-tick spacing, and is not this section's own question).
     If no trigger arrives within PENDING_RESPONSE_MAX_WAIT_MS(400ms) of
     becoming pending, service_gateway.c's own flush thread dispatches it
     directly: an EXTRA return-path packet not tied to any cover
     trigger, the one mechanism that CAN add to (rather than redistribute
     within) the return-path stream.

Single-slot simplification: if a second real request arrives while one
is already pending, this model keeps the earlier pending timestamp
(doesn't extend the fallback deadline) rather than modeling the C code's
actual single-slot overwrite-and-lose-the-first-one behavior precisely,
a disclosed approximation, immaterial to the classifier features at the
load levels this sweeps (R_MAX_PPS spacing stays well above round-trip
time through the load levels tested).

ATTACK
---------------------------------------------------------------------------
A passive observer of the return-path link only (e.g. watching MNz, the
return path's entry hop closest to the SG) sees only packet arrival
times. Same classifier treatment as coverleak_run.py: per (scheme,
load_level), a logistic-regression classifier (5-fold CV) distinguishes
idle-session return-path windows from load_level-session windows using
windowed features (count, mean/std/max inter-packet interval per 5s
window, computed on RETURN-path times, not forward).

Usage:
    python coverleak_return_run.py [--windows 300] [--seed 20260710] [--out-dir .]
"""

import argparse
import csv
import os
import random
import sys
import time

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import roc_auc_score, accuracy_score
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from coverleak_run import (
    gen_real_times, gen_cover_asn_adaptive, window_features, session_windows,
    ci95_proportion, SESSION_DURATION_S, WINDOW_S, LOAD_LEVELS, R_MAX_PPS,
)

# config.h: HOP_DECOY_FRACTION_PCT (fraction of forward cover diverted
# before reaching the SG, hop-decoy builds only) and service_gateway.c's
# PENDING_RESPONSE_MAX_WAIT_MS (return-path mailbox's bounded fallback).
HOP_DECOY_FRACTION_PCT = 30
PENDING_RESPONSE_MAX_WAIT_MS = 400.0

SCHEMES = {"plain": 0, "decoy_only": HOP_DECOY_FRACTION_PCT}


def gen_return_times(rng: random.Random, real_times, forward_cover_times,
                      diversion_pct: int, duration_s: float):
    """Event-driven merge of real arrivals and SG-reaching forward-cover
    triggers (see module docstring). Returns sorted return-path packet
    times."""
    horizon = duration_s * 1000.0

    triggers = sorted(t for t in forward_cover_times
                       if rng.randint(0, 99) >= diversion_pct)
    real_sorted = sorted(real_times)

    return_times = []
    pending_since = None
    ri = ti = 0
    n_real, n_trig = len(real_sorted), len(triggers)

    while ri < n_real or ti < n_trig or pending_since is not None:
        next_real = real_sorted[ri] if ri < n_real else None
        next_trig = triggers[ti] if ti < n_trig else None
        next_fallback = (pending_since + PENDING_RESPONSE_MAX_WAIT_MS
                          if pending_since is not None else None)

        candidates = [(t, kind) for t, kind in (
            (next_real, "real"), (next_trig, "trig"), (next_fallback, "fallback"))
            if t is not None]
        if not candidates:
            break
        ev_t, ev_kind = min(candidates)
        if ev_t >= horizon:
            break

        if ev_kind == "real":
            if pending_since is None:
                pending_since = ev_t
            ri += 1
        elif ev_kind == "trig":
            return_times.append(ev_t)
            pending_since = None
            ti += 1
        else:  # fallback
            return_times.append(ev_t)
            pending_since = None

    return sorted(return_times)


def gen_session_return(rng, scheme: str, load_level: float):
    diversion_pct = SCHEMES[scheme]
    real = gen_real_times(rng, load_level * R_MAX_PPS, SESSION_DURATION_S)
    fwd_cover = gen_cover_asn_adaptive(rng, real, SESSION_DURATION_S)
    return_times = gen_return_times(rng, real, fwd_cover, diversion_pct, SESSION_DURATION_S)
    return return_times


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--windows", type=int, default=300,
                     help="Independent 60s sessions per (scheme, load_level) class")
    ap.add_argument("--seed", type=int, default=20260710)
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    rng = random.Random(args.seed)

    t0 = time.perf_counter()
    result_rows = []

    for scheme in SCHEMES:
        idle_feats = []
        idle_groups = []
        for sess_idx in range(args.windows):
            times = gen_session_return(rng, scheme, 0.0)
            windows = session_windows(times, SESSION_DURATION_S, WINDOW_S)
            idle_feats.extend(windows)
            idle_groups.extend([sess_idx] * len(windows))

        for load_level in LOAD_LEVELS:
            load_feats = []
            load_groups = []
            for sess_idx in range(args.windows):
                times = gen_session_return(rng, scheme, load_level)
                windows = session_windows(times, SESSION_DURATION_S, WINDOW_S)
                load_feats.extend(windows)
                # Offset past idle_groups' ids, independently generated
                # sessions, so ids must never collide (see coverleak_run.py's
                # matching comment).
                load_groups.extend([args.windows + sess_idx] * len(windows))

            X = np.array(idle_feats + load_feats)
            y = np.array([0] * len(idle_feats) + [1] * len(load_feats))
            groups = np.array(idle_groups + load_groups)

            skf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=args.seed)
            aucs, accs = [], []
            for train_idx, test_idx in skf.split(X, y, groups):
                scaler = StandardScaler().fit(X[train_idx])
                Xtr, Xte = scaler.transform(X[train_idx]), scaler.transform(X[test_idx])
                clf = LogisticRegression(max_iter=1000).fit(Xtr, y[train_idx])
                proba = clf.predict_proba(Xte)[:, 1]
                pred = clf.predict(Xte)
                aucs.append(roc_auc_score(y[test_idx], proba))
                accs.append(accuracy_score(y[test_idx], pred))

            auc_mean, acc_mean = float(np.mean(aucs)), float(np.mean(accs))
            n_test_total = len(y)
            hits = int(round(acc_mean * n_test_total))
            acc_ci = ci95_proportion(hits, n_test_total)

            # Mean return-path packet count per window, idle vs this load
            # level: direction check against the live measurement
            # (-36.5%/-36.9%, a DECREASE under load) rather than just AUC.
            idle_mean_count = float(np.mean([f[0] for f in idle_feats]))
            load_mean_count = float(np.mean([f[0] for f in load_feats]))
            count_change_pct = (100.0 * (load_mean_count - idle_mean_count)
                                 / idle_mean_count if idle_mean_count > 0 else 0.0)

            result_rows.append({
                "scheme": scheme, "load_level": load_level,
                "attacker_metric": "auc_active_vs_idle",
                "value": auc_mean, "value_ci95": "",
                "mean_count_change_pct": count_change_pct,
            })
            result_rows.append({
                "scheme": scheme, "load_level": load_level,
                "attacker_metric": "accuracy_active_vs_idle",
                "value": acc_mean, "value_ci95": acc_ci,
                "mean_count_change_pct": count_change_pct,
            })

            if not args.quiet:
                print(f"  {scheme:12s} L={load_level:.1f}  AUC={auc_mean:.3f}  "
                      f"acc={acc_mean:.3f}  count_change={count_change_pct:+.1f}%", flush=True)

    elapsed = time.perf_counter() - t0
    if not args.quiet:
        print(f"\n  Completed in {elapsed:.1f}s\n")

    out_path = os.path.join(args.out_dir, "coverleak_return.csv")
    with open(out_path, "w", newline="") as fp:
        fp.write("# Anon-Sec-Net Task C methodology applied to the RETURN direction\n")
        fp.write(f"# {args.windows} 60s sessions per (scheme, load_level) class, "
                  f"5-fold cross-validated logistic regression\n")
        fp.write("# scheme: plain (no hop-decoy diversion) | decoy_only "
                  f"(HOP_DECOY_FRACTION_PCT={HOP_DECOY_FRACTION_PCT}% diversion)\n")
        fp.write("# attacker_metric: auc_active_vs_idle | accuracy_active_vs_idle\n")
        fp.write("#   (binary classifier distinguishing idle return-path windows from\n")
        fp.write("#   load_level return-path windows)\n")
        fp.write("# value_ci95: Wilson-score 95% CI half-width (accuracy only; blank for AUC)\n")
        fp.write("# mean_count_change_pct: mean packets/window, load_level vs idle, sign\n")
        fp.write("#   check against the live measurement (-36.5%/-36.9%)\n")
        fields = ["scheme", "load_level", "attacker_metric", "value", "value_ci95",
                  "mean_count_change_pct"]
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        for row in result_rows:
            w.writerow({
                k: (f"{v:.6g}" if isinstance(v, float) else v)
                for k, v in row.items()
            })
    print(f"  Wrote {out_path}  ({len(result_rows)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
