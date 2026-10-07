#!/usr/bin/env python3
"""
plot_combined_bc.py: combined B+C adversary: mean rounds to confident
ID, flowcorr-only vs. activity-only vs. combined, across FPR targets.

Usage:
    python plot_combined_bc.py [--dir .] [--out fig_combined_bc.pdf]
"""

import argparse
import csv
import os
import sys


def load_csv(path):
    if not os.path.exists(path):
        print(f"ERROR: {path} not found. Run asn_combined_bc_adversary.py first.")
        sys.exit(1)
    with open(path, newline="") as fp:
        lines = [l for l in fp if not l.startswith("#")]
    return list(csv.DictReader(lines))


def plot(rows, out_path, dpi):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("ERROR: matplotlib is required.")
        sys.exit(1)

    fprs = sorted({float(r["fpr_target"]) for r in rows}, reverse=True)
    adversaries = ["flowcorr_only", "activity_only", "combined_bc"]
    labels = ["Flow correlation\nonly (Task B)", "Activity leakage\nonly (Task C)",
              "Combined\n(B+C)"]
    colors = ["#0B3C6B", "#D85A30", "#5E9A4C"]

    fig, ax = plt.subplots(figsize=(8, 5.5))
    x = np.arange(len(fprs))
    width = 0.25

    for i, (adv, label, color) in enumerate(zip(adversaries, labels, colors)):
        vals = []
        for fpr in fprs:
            for r in rows:
                if abs(float(r["fpr_target"]) - fpr) < 1e-9 and r["adversary"] == adv:
                    vals.append(float(r["mean_rounds_true_pair"]))
                    break
        ax.bar(x + (i - 1) * width, vals, width, label=label, color=color, zorder=3)

    ax.set_xticks(x)
    ax.set_xticklabels([f"FPR={fpr:g}" for fpr in fprs], fontsize=10)
    ax.set_ylabel("Mean rounds to confident ID\n(SPRT, " + r"$\alpha=\beta=0.01$)", fontsize=10)
    ax.set_title("Combined B+C adversary needs fewer rounds\nthan either signal alone", fontsize=11)
    ax.grid(which="major", axis="y", linestyle=":", linewidth=0.5, color="#B4B2A9", alpha=0.7)
    ax.legend(loc="upper left", fontsize=8.5, framealpha=0.92, edgecolor="#B4B2A9")

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
    ap.add_argument("--out", default="fig_combined_bc.pdf")
    ap.add_argument("--dpi", type=int, default=300)
    args = ap.parse_args()

    rows = load_csv(os.path.join(args.dir, "asn_combined_bc.csv"))
    plot(rows, args.out, args.dpi)


if __name__ == "__main__":
    sys.exit(main())
