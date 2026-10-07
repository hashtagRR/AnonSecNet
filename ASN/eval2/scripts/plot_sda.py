#!/usr/bin/env python3
"""
plot_sda.py: Task A follow-up: SPRT statistical-disclosure-attack rounds
needed for confident identification vs. the compromise-ladder's N_50.

Usage:
    python plot_sda.py [--dir .] [--out fig_sda.pdf]
"""

import argparse
import csv
import os
import sys


def load_csv(path):
    if not os.path.exists(path):
        print(f"ERROR: {path} not found. Run asn_statistical_disclosure.py first.")
        sys.exit(1)
    with open(path, newline="") as fp:
        lines = [l for l in fp if not l.startswith("#")]
    return list(csv.DictReader(lines))


def plot(rows, ladder_rows, out_path, dpi):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("ERROR: matplotlib is required.")
        sys.exit(1)

    target_alpha = "0.01"
    points = [r for r in rows if r["alpha"] == target_alpha]
    labels = [r["label"] for r in points]
    medians = [int(r["mc_median_rounds_true_pair"]) for r in points]

    ladder_n50 = None
    for r in ladder_rows:
        if r["event"] == "D1" and abs(float(r["rho"]) - 0.01) < 1e-9:
            ladder_n50 = int(float(r["n50_sessions"]))

    fig, ax = plt.subplots(figsize=(9, 5.5))
    colors = ["#0B3C6B"] * len(labels)
    bars = ax.bar(range(len(labels)), medians, color=colors, width=0.6, zorder=3)
    for b, v in zip(bars, medians):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.15, str(v),
                 ha="center", va="bottom", fontsize=9)

    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels([l.replace("_", "\n") for l in labels], fontsize=7.5)
    ax.set_ylabel("Median rounds to confident ID (SPRT, " + r"$\alpha=\beta=0.01$)", fontsize=10)
    ax.set_title("Statistical disclosure attack: rounds needed vs.\n"
                 "compromise-ladder's repeated-session threshold", fontsize=11)
    ax.grid(which="major", axis="y", linestyle=":", linewidth=0.5, color="#B4B2A9", alpha=0.7)

    if ladder_n50:
        ax.annotate(
            f"compromise-ladder N_50 at f=0.10, ρ=0.01:\n{ladder_n50:,} sessions "
            f"(off this chart's scale)",
            xy=(0.5, 0.92), xycoords="axes fraction", fontsize=8.5, color="#5F5E5A",
            ha="center",
            bbox=dict(boxstyle="round,pad=0.35", facecolor="white",
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
    ap.add_argument("--out", default="fig_sda.pdf")
    ap.add_argument("--dpi", type=int, default=300)
    args = ap.parse_args()

    rows = load_csv(os.path.join(args.dir, "asn_sda_sprt.csv"))
    ladder_rows = load_csv(os.path.join(args.dir, "asn_sda_vs_ladder.csv"))
    plot(rows, ladder_rows, args.out, args.dpi)


if __name__ == "__main__":
    sys.exit(main())
