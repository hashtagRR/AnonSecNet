#!/usr/bin/env python3
"""
plot_flowcorr2.py: Task B: flow-correlation ROC figure

ROC curves (log-x, matching how flow-correlation results are conventionally
reported, e.g. DeepCorr/DeepCoFFEA) for the three conditions, "combined"
correlator by default.

Usage:
    python plot_flowcorr2.py [--dir .] [--out fig_flowcorr2.pdf] [--correlator combined]
"""

import argparse
import csv
import os
import sys


def load_csv(path):
    if not os.path.exists(path):
        print(f"ERROR: {path} not found. Run flowcorr_run.py first.")
        sys.exit(1)
    with open(path, newline="") as fp:
        lines = [l for l in fp if not l.startswith("#")]
    return list(csv.DictReader(lines))


def plot(roc_rows, result_rows, correlator, out_path, dpi):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("ERROR: matplotlib and numpy are required.")
        sys.exit(1)

    COLORS = {
        "single_path": "#D85A30",
        "asn_one_path": "#185FA5",
        "asn_both_paths": "#5E9A4C",
    }
    LABELS = {
        "single_path": "Single-path (Tor-equivalent)",
        "asn_one_path": "ASN dual-path, one path observed",
        "asn_both_paths": "ASN dual-path, both paths observed (upper bound)",
    }
    conditions = ["single_path", "asn_one_path", "asn_both_paths"]

    fig, ax = plt.subplots(figsize=(7, 5.5))

    auc_by_cond = {}
    for r in result_rows:
        if r["correlator"] == correlator:
            auc_by_cond[r["condition"]] = float(r["auc"])

    for cond in conditions:
        fprs, tprs = [], []
        for r in roc_rows:
            if r["condition"] == cond and r["correlator"] == correlator:
                fprs.append(max(float(r["fpr"]), 1e-4))  # floor for log-x
                tprs.append(float(r["tpr"]))
        pairs = sorted(zip(fprs, tprs))
        fprs = [p[0] for p in pairs]
        tprs = [p[1] for p in pairs]
        auc = auc_by_cond.get(cond, float("nan"))
        ax.plot(fprs, tprs, color=COLORS[cond], linewidth=1.8,
                  label=f"{LABELS[cond]}  (AUC={auc:.3f})", zorder=3)

    # Fixed-FPR reference lines
    for target in [1e-1, 1e-2, 1e-3]:
        ax.axvline(target, color="#B4B2A9", linewidth=0.6, linestyle=":", zorder=1)

    ax.plot([1e-4, 1.0], [1e-4, 1.0], color="#B4B2A9", linewidth=1.0,
              linestyle="--", zorder=1, label="Chance")

    ax.set_xscale("log")
    ax.set_xlim(1e-4, 1.0)
    ax.set_ylim(0, 1.02)
    ax.set_xlabel("False positive rate (impostor pairs)", fontsize=11)
    ax.set_ylabel("True positive rate (true pairs)", fontsize=11)
    ax.set_title(
        f"Flow-correlation ROC ({correlator} correlator)",
        fontsize=11, pad=10
    )
    ax.grid(which="major", linestyle=":", linewidth=0.5, color="#B4B2A9", alpha=0.7)
    ax.tick_params(axis="both", which="major", labelsize=9)
    ax.legend(loc="lower right", fontsize=8, framealpha=0.92, edgecolor="#B4B2A9")

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
    ap.add_argument("--out", default="fig_flowcorr2.pdf")
    ap.add_argument("--correlator", default="combined", choices=["pearson_volume", "combined"])
    ap.add_argument("--dpi", type=int, default=300)
    args = ap.parse_args()

    roc_rows = load_csv(os.path.join(args.dir, "flowcorr_roc_curves.csv"))
    result_rows = load_csv(os.path.join(args.dir, "flowcorr_results.csv"))
    plot(roc_rows, result_rows, args.correlator, args.out, args.dpi)


if __name__ == "__main__":
    sys.exit(main())
