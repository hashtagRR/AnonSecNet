#!/usr/bin/env python3
"""
plot_flowcorr_fpr_sweep.py: three-correlator comparison (fixed
'combined', MLP, GRU-contrastive) across the full FPR range down to
10^-5, asn_both_paths condition, the fair, same-operating-point
comparison against published DeepCoFFEA/FlowCoPCL numbers.

Usage:
    python plot_flowcorr_fpr_sweep.py [--dir .] [--out fig_flowcorr_fpr_sweep.pdf]
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


def plot(fixed_rows, ml_rows, gru_rows, out_path, dpi):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("ERROR: matplotlib is required.")
        sys.exit(1)

    fig, ax = plt.subplots(figsize=(8, 5.5))
    series = [
        ("Fixed (Pearson+cosine)", fixed_rows, "combined", "#0B3C6B"),
        ("MLP (flowcorr_ml.py)", ml_rows, "learned_mlp", "#D85A30"),
        ("GRU + contrastive (this pass)", gru_rows, "gru_contrastive", "#5E9A4C"),
    ]
    all_ys = []
    for label, rows, correlator, color in series:
        pts = sorted([(float(r["fpr_target"]), float(r["tpr"])) for r in rows
                      if r["condition"] == "asn_both_paths" and r["correlator"] == correlator])
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        all_ys.extend(ys)
        ax.plot(xs, ys, marker="o", color=color, linewidth=1.8, label=label)

    ax.axhline(0.5, color="#B0AEA4", linewidth=0.8, linestyle=(0, (3, 5)),
               label="DeepCoFFEA-class '>50% @ FPR=1e-5' bar")
    ax.set_xscale("log")
    ax.invert_xaxis()
    ax.set_xlabel("FPR operating point (stricter to the right)", fontsize=10)
    ax.set_ylabel("TPR (asn_both_paths)", fontsize=10)
    ax.set_title("Three correlators across the full FPR range\n"
                 "(fair comparison at DeepCoFFEA/FlowCoPCL's actual operating points)",
                 fontsize=11)
    ax.grid(which="major", linestyle=":", linewidth=0.5, color="#B4B2A9", alpha=0.7)
    ax.legend(loc="upper right", fontsize=8, framealpha=0.92, edgecolor="#B4B2A9")
    # Data-driven y-limits instead of a hardcoded
    # 0.35 floor, the previous fixed floor happened not to clip any
    # current data point (min observed TPR was 0.512) but would silently
    # clip any future run's lower values off the chart with no warning.
    y_lo = max(0.0, min(all_ys) - 0.05) if all_ys else 0.0
    y_hi = min(1.05, max(all_ys) + 0.05) if all_ys else 1.05
    ax.set_ylim(y_lo, y_hi)

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
    ap.add_argument("--fixed-csv", default="flowcorr_results.csv")
    ap.add_argument("--ml-csv", default="flowcorr_ml_results.csv")
    ap.add_argument("--gru-csv", default="flowcorr_gru_results.csv")
    ap.add_argument("--out", default="fig_flowcorr_fpr_sweep.pdf")
    ap.add_argument("--dpi", type=int, default=300)
    args = ap.parse_args()

    fixed_rows = load_csv(args.fixed_csv)
    ml_rows = load_csv(args.ml_csv)
    gru_rows = load_csv(args.gru_csv)
    plot(fixed_rows, ml_rows, gru_rows, args.out, args.dpi)


if __name__ == "__main__":
    sys.exit(main())
