#!/usr/bin/env python3
"""
seed_sensitivity.py: robustness check: do eval2's headline numbers hold
across several independent seeds, not just the one fixed seed (20260710)
every other script defaults to?

WHY THIS EXISTS
---------------------------------------------------------------------------
Every simulation in eval2 uses a single fixed seed (20260710) for its
headline numbers, a legitimate, cheap robustness check that was
missing until this script. Most of eval2's headline numbers turn out to be closed-form
(asn_correlated_disclosure.py's crossover rho*, asn_repeated_sessions.py's
N_50, asn_topology_freshness.py, asn_gpa_linkability.py, asn_ablation_
disclosure.py) and take no --seed argument at all, there is nothing to
check for those, they are exact arithmetic. The only genuinely stochastic
headline numbers in eval2 come from scripts that generate SYNTHETIC TRACES
(flow-correlation, cover-traffic timing) and measure a classifier against
them: flowcorr_run.py (Task B, fixed-formula correlator), flowcorr_ml.py
(Task B, learned correlator), and coverleak_run.py (Task C, activity-level
classifier). This script re-runs exactly those three at 5 seeds (the
existing default 20260710, plus 1/2/3/4) and reports the spread of each
headline number.

IMPORTANT: flowcorr_ml.py must be run with the SAME hyperparameters used
to produce the paper's headline number (train-sessions=500, neg-per-pos=8
-- see flowcorr_ml_results.csv's own header comment), not its own script
defaults (300/5), or the "seed sensitivity" will actually be measuring a
hyperparameter difference, not a seed difference. This bit the first
attempt at this check and is called out here so it isn't repeated.

Usage:
    python seed_sensitivity.py --seeds 20260710,1,2,3,4 --out-dir . --run-dir /tmp/seedcheck
    (--run-dir is where each seed's raw script output already lives, or
    will be written to, one subdirectory per seed: <run-dir>/s<seed>/)
"""

import argparse
import csv
import os
import statistics
import subprocess
import sys


HEADLINE_ROWS = [
    # (source_csv, match_fn description, csv filter fields)
    ("flowcorr_results.csv", "asn_one_path", "combined", "0.001"),
    ("flowcorr_results.csv", "asn_both_paths", "combined", "0.001"),
    ("flowcorr_ml_results.csv", "asn_one_path", "learned_mlp", "0.001"),
    ("flowcorr_ml_results.csv", "asn_both_paths", "learned_mlp", "0.001"),
]


def read_tpr(path, condition, correlator, fpr_target):
    if not os.path.exists(path):
        return None
    with open(path, newline="") as fp:
        lines = [l for l in fp if not l.startswith("#")]
    for row in csv.DictReader(lines):
        if (row["condition"] == condition and row["correlator"] == correlator
                and row["fpr_target"] == fpr_target):
            return float(row["tpr"])
    return None


def read_coverleak_transition(path):
    """Returns the load fraction L at which asn_adaptive's AUC first exceeds
    0.9 (the leakage-detection transition point), a single scalar summary
    of the whole curve's shape."""
    if not os.path.exists(path):
        return None
    with open(path, newline="") as fp:
        lines = [l for l in fp if not l.startswith("#")]
    rows = [r for r in csv.DictReader(lines)
            if r["scheme"] == "asn_adaptive" and r["attacker_metric"] == "auc_active_vs_idle"]
    rows.sort(key=lambda r: float(r["load_level"]))
    for r in rows:
        if float(r["value"]) > 0.9:
            return float(r["load_level"])
    return None


def run_seed(eval2_dir, venv_python, seed, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    fc = os.path.join(out_dir, "flowcorr_results.csv")
    if not os.path.exists(fc):
        subprocess.run([venv_python, "scripts/flowcorr_run.py",
                         "--sessions", "200", "--seed", str(seed), "--out-dir", out_dir],
                        cwd=eval2_dir, check=True, capture_output=True)
    ml = os.path.join(out_dir, "flowcorr_ml_results.csv")
    if not os.path.exists(ml):
        subprocess.run([venv_python, "scripts/flowcorr_ml.py",
                         "--train-sessions", "500", "--neg-per-pos", "8",
                         "--seed", str(seed), "--out-dir", out_dir],
                        cwd=eval2_dir, check=True, capture_output=True)
    cl = os.path.join(out_dir, "cover_leakage.csv")
    if not os.path.exists(cl):
        subprocess.run([venv_python, "scripts/coverleak_run.py",
                         "--seed", str(seed), "--out-dir", out_dir],
                        cwd=eval2_dir, check=True, capture_output=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seeds", default="20260710,1,2,3,4")
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--run-dir", default="/tmp/seedcheck",
                     help="where per-seed raw script output lives/goes")
    ap.add_argument("--venv-python",
                     default=os.path.join(os.path.dirname(os.path.dirname(
                         os.path.dirname(os.path.abspath(__file__)))), "..", ".venv", "bin", "python3"))
    ap.add_argument("--skip-run", action="store_true",
                     help="assume --run-dir is already populated, just summarize")
    args = ap.parse_args()

    eval2_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    seeds = [s.strip() for s in args.seeds.split(",")]

    if not args.skip_run:
        venv_python = os.path.abspath(args.venv_python)
        for s in seeds:
            out = os.path.join(args.run_dir, f"s{s}")
            print(f"  Running seed {s} -> {out}")
            run_seed(eval2_dir, venv_python, s, out)

    os.makedirs(args.out_dir, exist_ok=True)
    summary_rows = []

    print("\n  Task B (flow correlation), TPR @ FPR=1e-3, across seeds:")
    for csv_name, condition, correlator, fpr in HEADLINE_ROWS:
        vals = []
        for s in seeds:
            v = read_tpr(os.path.join(args.run_dir, f"s{s}", csv_name), condition, correlator, fpr)
            if v is not None:
                vals.append(v)
        if not vals:
            continue
        mean = statistics.mean(vals)
        spread = max(vals) - min(vals)
        print(f"    {condition:16s} {correlator:12s}: {vals} "
              f"mean={mean:.3f} range={spread:.3f}")
        summary_rows.append({
            "metric": f"{condition}_{correlator}_tpr_fpr1e-3",
            "seeds": ";".join(seeds),
            "values": ";".join(f"{v:.4f}" for v in vals),
            "mean": mean, "min": min(vals), "max": max(vals), "range": spread,
        })

    print("\n  Task C (cover-traffic leakage), AUC>0.9 transition load L, across seeds:")
    vals = []
    for s in seeds:
        v = read_coverleak_transition(os.path.join(args.run_dir, f"s{s}", "cover_leakage.csv"))
        if v is not None:
            vals.append(v)
    if vals:
        mean = statistics.mean(vals)
        spread = max(vals) - min(vals)
        print(f"    {vals} mean={mean:.3f} range={spread:.3f}")
        summary_rows.append({
            "metric": "coverleak_auc0.9_transition_load",
            "seeds": ";".join(seeds),
            "values": ";".join(f"{v:.4f}" for v in vals),
            "mean": mean, "min": min(vals), "max": max(vals), "range": spread,
        })

    out_path = os.path.join(args.out_dir, "seed_sensitivity_summary.csv")
    with open(out_path, "w", newline="") as fp:
        fp.write("# Seed-sensitivity check: eval2's stochastic headline numbers\n")
        fp.write("# (Task B TPR@FPR=1e-3, Task C's AUC-0.9 transition load) across\n")
        fp.write("# 5 seeds (20260710 default + 1/2/3/4). Closed-form headline\n")
        fp.write("# numbers (Task A's crossover rho*, N_50, GPA-linkability,\n")
        fp.write("# ablation, and this task's own SDA closed-form ASN) take no\n")
        fp.write("# --seed argument and are exact arithmetic, nothing to check.\n")
        fields = ["metric", "seeds", "values", "mean", "min", "max", "range"]
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        for r in summary_rows:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v) for k, v in r.items()})
    print(f"\n  Wrote {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
