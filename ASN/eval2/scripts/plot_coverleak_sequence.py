#!/usr/bin/env python3
"""
plot_coverleak_sequence.py: sequence-aware (LSTM) vs. windowed-baseline
AUC, across both experiments in asn_coverleak_sequence.csv.

Usage:
    python plot_coverleak_sequence.py [--dir .] [--out fig_coverleak_seq.pdf]
"""

import argparse
import csv
import os
import sys


def load_csv(path):
    if not os.path.exists(path):
        print(f"ERROR: {path} not found. Run asn_coverleak_sequence.py first.")
        sys.exit(1)
    with open(path, newline="") as fp:
        lines = [l for l in fp if not l.startswith("#")]
    return list(csv.DictReader(lines))


def plot(rows, out_path, dpi):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("ERROR: matplotlib is required.")
        sys.exit(1)

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.8))
    colors = {"baseline_summary": "#0B3C6B", "lstm_sequence": "#D85A30",
              "transformer_sequence": "#3F7D3F"}
    label_map = {"baseline_summary": "Baseline (5s window, 4 summary stats)",
                 "lstm_sequence": "LSTM (raw IPI sequence)",
                 "transformer_sequence": "Transformer (raw IPI sequence)"}
    # Older CSVs have no transformer_sequence rows,
    # skip it gracefully rather than plot an empty/broken line.
    models_present = [m for m in ("baseline_summary", "lstm_sequence", "transformer_sequence")
                       if any(r["model"] == m for r in rows)]

    ax = axes[0]
    exp_a = [r for r in rows if r["experiment"] == "A_window_sweep"]
    for model in models_present:
        pts = sorted([(float(r["window_s"]), float(r["auc"])) for r in exp_a if r["model"] == model])
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        ax.plot(xs, ys, marker="o", color=colors[model], label=label_map[model], linewidth=1.8)
    ax.set_xlabel("Observation window duration (s)", fontsize=10)
    ax.set_ylabel("AUC (active vs. idle, L=0.5)", fontsize=10)
    ax.set_title("Experiment A: shorter windows,\nfixed load L=0.5", fontsize=10.5)
    ax.grid(which="major", linestyle=":", linewidth=0.5, color="#B4B2A9", alpha=0.7)
    ax.legend(loc="lower right", fontsize=8, framealpha=0.92, edgecolor="#B4B2A9")
    ax.set_ylim(0.4, 1.02)

    ax = axes[1]
    exp_b = [r for r in rows if r["experiment"] == "B_load_sweep"]
    for model in models_present:
        pts = sorted([(float(r["load_level"]), float(r["auc"])) for r in exp_b if r["model"] == model])
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        ax.plot(xs, ys, marker="o", color=colors[model], label=label_map[model], linewidth=1.8)
    ax.axhline(0.5, color="#888780", linewidth=0.8, linestyle=(0, (3, 5)), label="chance")
    ax.set_xlabel("Load level $L$", fontsize=10)
    ax.set_ylabel("AUC (active vs. idle, W=5s)", fontsize=10)
    ax.set_title("Experiment B: lower loads,\nfixed window W=5s", fontsize=10.5)
    ax.grid(which="major", linestyle=":", linewidth=0.5, color="#B4B2A9", alpha=0.7)
    ax.legend(loc="lower right", fontsize=8, framealpha=0.92, edgecolor="#B4B2A9")
    ax.set_ylim(0.4, 1.02)

    # Title kept neutral/descriptive rather than asserting a directional
    # finding: a hardcoded conclusion here ("does not outperform") could
    # go stale as results are re-measured; the plotted curves already
    # show the comparison, no caption claim needed to duplicate it.
    fig.suptitle("Sequence-aware attacker(s) vs. windowed-summary-statistic\n"
                 "baseline, active-vs-idle detection AUC", fontsize=11)
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
    ap.add_argument("--out", default="fig_coverleak_seq.pdf")
    ap.add_argument("--dpi", type=int, default=300)
    args = ap.parse_args()

    rows = load_csv(os.path.join(args.dir, "asn_coverleak_sequence.csv"))
    plot(rows, args.out, args.dpi)


if __name__ == "__main__":
    sys.exit(main())
