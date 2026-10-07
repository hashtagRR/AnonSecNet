#!/usr/bin/env python3
"""Regenerate fig_delaysweep.pdf/.eps (Task 3): mixing-delay sensitivity.
(a) TPR vs mean delay at fixed FPR operating points (1e-3, 1e-5), full
sweep 10-200ms, dual-path combined correlator. (b) throughput retention
(% of same-machine zero-delay baseline) vs mean delay, one line per
concurrency level tested (N=1, 5, 10 only, this 2-vCPU host cannot
cleanly measure N=50+ without reproducing the hardware concurrency
ceiling already documented for Table 8)."""
import csv
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Paths relative to this script's location, not a hardcoded absolute
# checkout path, so the script stays runnable on any machine per
# eval2/README.md's "single command" reproduction claim.
_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
_EVAL2_DIR = os.path.dirname(_SCRIPTS_DIR)
_ASN_DIR = os.path.dirname(_EVAL2_DIR)
_REPO_ROOT = os.path.dirname(os.path.dirname(_ASN_DIR))

FLOWCORR_CSV = os.path.join(_EVAL2_DIR, "delay_sweep_flowcorr_summary.csv")
THROUGHPUT_CSV = os.path.join(_EVAL2_DIR, "delay_sweep_throughput_summary.csv")
OUT_STEM = os.path.join(_REPO_ROOT, "Submission_revised", "fig_delaysweep")

COLOR_STRICT = "#D55E00"
COLOR_WEAK = "#0072B2"
COLOR_N = {1: "#D55E00", 5: "#0072B2", 10: "#009E73"}

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9.6, 3.6))

delays, tpr_1e3, tpr_1e5 = [], [], []
with open(FLOWCORR_CSV) as f:
    for row in csv.DictReader(f):
        if row["correlator"] != "combined":
            continue
        d = int(row["delay_ms"])
        if row["fpr_target"] == "0.001":
            delays.append(d)
            tpr_1e3.append(float(row["tpr"]))
        elif row["fpr_target"] == "1e-05":
            tpr_1e5.append(float(row["tpr"]))

ax1.plot(delays, tpr_1e3, color=COLOR_STRICT, marker="o", markersize=5,
          linewidth=1.8, label="FPR=$10^{-3}$")
ax1.plot(delays, tpr_1e5, color=COLOR_WEAK, marker="s", markersize=5,
          linewidth=1.8, label="FPR=$10^{-5}$")
# No "chance" reference line: for TPR at a fixed FPR operating point,
# chance-level performance is TPR ~= FPR (the ROC diagonal), i.e. near 0
# on this axis, not 0.5, confirmed directly against the 200ms row
# (AUC~0.4995, actual chance) whose measured TPR is 0.01/0 there. A
# flat line at 0.5 was here before and was wrong: it sat near where the
# correlator is working well (the low-delay plateau) rather than where
# it's actually at chance, which would mislead a reader.
ax1.axvline(50, color="0.5", linestyle="--", linewidth=0.9, alpha=0.7)
ax1.text(52, 0.95, "paper's\noperating\npoint", fontsize=6.5, color="0.4", va="top")
ax1.set_xlabel("Mean mixing delay (ms)")
ax1.set_ylabel("True positive rate (TPR)")
ax1.set_ylim(-0.05, 1.05)
ax1.grid(True, linestyle=":", linewidth=0.5, color="0.8")
ax1.legend(loc="upper right", fontsize=8, frameon=False)
ax1.spines["top"].set_visible(False)
ax1.spines["right"].set_visible(False)
ax1.set_title("(a) Flow-correlation TPR vs. mean delay", fontsize=9)

by_n = {1: [], 5: [], 10: []}
with open(THROUGHPUT_CSV) as f:
    for row in csv.DictReader(f):
        n = int(row["n_clients"])
        if n in by_n:
            by_n[n].append((int(row["delay_ms"]), float(row["pct_of_zero_delay_baseline"])))

all_pcts = []
for n in (1, 5, 10):
    pts = sorted(by_n[n])
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    all_pcts.extend(ys)
    ax2.plot(xs, ys, color=COLOR_N[n], marker="o", markersize=5,
              linewidth=1.8, label=f"N={n}")

ax2.axhline(100, color="0.6", linestyle=":", linewidth=1.0)
ax2.axvline(50, color="0.5", linestyle="--", linewidth=0.9, alpha=0.7)
ax2.set_xlabel("Mean mixing delay (ms)")
ax2.set_ylabel("Throughput (% of same-machine\nzero-delay baseline)")
# Data-driven y-limits instead of a hardcoded
# 75-115 band, the previous fixed band happened not to clip any current
# data point (observed range 83.7-106.4%) but would silently clip any
# future run's values off the chart with no warning.
ax2.set_ylim(min(all_pcts) - 5, max(all_pcts) + 5)
ax2.grid(True, linestyle=":", linewidth=0.5, color="0.8")
ax2.legend(loc="lower left", fontsize=8, frameon=False)
ax2.spines["top"].set_visible(False)
ax2.spines["right"].set_visible(False)
ax2.set_title("(b) Throughput retention vs. mean delay\n(N=1,5,10 only, 2-vCPU host)", fontsize=9)

fig.tight_layout()
fig.savefig(OUT_STEM + ".pdf")
fig.savefig(OUT_STEM + ".eps")
print("Wrote", OUT_STEM + ".pdf/.eps")
