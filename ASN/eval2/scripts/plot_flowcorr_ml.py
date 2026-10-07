#!/usr/bin/env python3
"""
plot_flowcorr_ml.py: Task B follow-up: fixed vs. learned correlator
comparison at TPR@FPR=1e-3, grouped by condition.

Reads flowcorr_results.csv (pearson_volume, combined) and
flowcorr_ml_results.csv (learned_mlp), both filtered to fpr_target=0.001,
and renders a grouped bar chart answering "does the partial-mitigation
finding survive a stronger, learned adversary?"

Usage:
    python plot_flowcorr_ml.py [--dir .] [--out fig_flowcorr_ml.pdf]
"""

import argparse
import csv
import os
import sys


def load_csv(path):
    if not os.path.exists(path):
        print(f"ERROR: {path} not found.")
        sys.exit(1)
    with open(path, newline="") as fp:
        lines = [l for l in fp if not l.startswith("#")]
    return list(csv.DictReader(lines))


def plot(fixed_rows, ml_rows, out_path, dpi):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("ERROR: matplotlib and numpy are required.")
        sys.exit(1)

    conditions = ["single_path", "asn_one_path", "asn_both_paths"]
    COND_LABELS = {
        "single_path": "Single-path\n(Tor-equivalent)",
        "asn_one_path": "ASN, one\npath observed",
        "asn_both_paths": "ASN, both\npaths (upper bound)",
    }
    correlators = ["pearson_volume", "combined", "learned_mlp"]
    COLORS = {"pearson_volume": "#8FBEE0", "combined": "#185FA5", "learned_mlp": "#D85A30"}
    LABELS = {"pearson_volume": "Pearson (volume only)",
              "combined": "Combined (Pearson+cosine, vol+timing)",
              "learned_mlp": "Learned (MLP, binned features)"}

    all_rows = fixed_rows + ml_rows
    data = {}
    for r in all_rows:
        if abs(float(r["fpr_target"]) - 1e-3) > 1e-9:
            continue
        data[(r["condition"], r["correlator"])] = (float(r["tpr"]), float(r["tpr_ci95"]))

    fig, ax = plt.subplots(figsize=(8, 5))
    x = np.arange(len(conditions))
    width = 0.26

    for i, corr in enumerate(correlators):
        vals = [data.get((c, corr), (0, 0))[0] for c in conditions]
        errs = [data.get((c, corr), (0, 0))[1] for c in conditions]
        offset = (i - 1) * width
        ax.bar(x + offset, vals, width, yerr=errs, capsize=3,
               color=COLORS[corr], label=LABELS[corr], error_kw={"elinewidth": 1.2})

    ax.set_xticks(x)
    ax.set_xticklabels([COND_LABELS[c] for c in conditions], fontsize=10)
    ax.set_ylabel("TPR at FPR=$10^{-3}$", fontsize=11)
    ax.set_ylim(0, 1.08)
    ax.set_title("Does the partial-mitigation finding survive a stronger correlator?",
                 fontsize=11)
    ax.grid(True, axis="y", linestyle="--", alpha=0.4)
    ax.legend(fontsize=8.5, loc="upper left")
    ax.annotate(
        "learned correlator tracks the best fixed\ncorrelator closely, no dramatic break",
        xy=(0.98, 0.35), xycoords="axes fraction", fontsize=8, color="#5F5E5A",
        ha="right",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="white",
                  edgecolor="#D3D1C7", linewidth=0.6, alpha=0.92),
    )

    fig.tight_layout()
    ext = os.path.splitext(out_path)[1].lower()
    if ext == ".pdf":
        from matplotlib.backends.backend_pdf import PdfPages
        with PdfPages(out_path) as pdf:
            pdf.savefig(fig, dpi=dpi, bbox_inches="tight")
    else:
        fig.savefig(out_path, dpi=dpi, bbox_inches="tight")
    plt.close(fig)
    print(f"  Figure saved -> {out_path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=".")
    ap.add_argument("--out", default="fig_flowcorr_ml.pdf")
    ap.add_argument("--dpi", type=int, default=300)
    args = ap.parse_args()

    fixed_rows = load_csv(os.path.join(args.dir, "flowcorr_results.csv"))
    ml_rows = load_csv(os.path.join(args.dir, "flowcorr_ml_results.csv"))
    plot(fixed_rows, ml_rows, args.out, args.dpi)


if __name__ == "__main__":
    sys.exit(main())
