#!/usr/bin/env python3
"""
plot_sda_noise.py: noise-aware SPRT: measured false-accept rate vs.
decoy-population heterogeneity (noise_cv), strict vs. weak FPR operating
points.

Usage:
    python plot_sda_noise.py [--dir .] [--out fig_sda_noise.pdf]
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


def plot(rows, out_path, dpi):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("ERROR: matplotlib is required.")
        sys.exit(1)

    labels = sorted({r["label"] for r in rows})
    colors = ["#0B3C6B", "#D85A30", "#5E9A4C", "#C9A227"]

    fig, ax = plt.subplots(figsize=(8, 5.5))
    for label, color in zip(labels, colors):
        pts = sorted([(float(r["noise_cv"]), float(r["mc_false_accept_rate"]))
                      for r in rows if r["label"] == label])
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        ax.plot(xs, ys, marker="o", color=color, linewidth=1.8, label=label.replace("_", " "))

    ax.axhline(0.01, color="#888780", linewidth=0.9, linestyle=(0, (3, 5)),
               label="target alpha = 0.01")
    ax.set_xlabel("Decoy heterogeneity (noise coefficient of variation)", fontsize=10)
    ax.set_ylabel("Measured false-accept rate", fontsize=10)
    ax.set_title("Naive SPRT's false-accept guarantee erodes under\n"
                 "decoy-population heterogeneity, at weak FPR operating points",
                 fontsize=11)
    ax.grid(which="major", linestyle=":", linewidth=0.5, color="#B4B2A9", alpha=0.7)
    ax.legend(loc="upper left", fontsize=8, framealpha=0.92, edgecolor="#B4B2A9")

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
    ap.add_argument("--out", default="fig_sda_noise.pdf")
    ap.add_argument("--dpi", type=int, default=300)
    args = ap.parse_args()

    rows = load_csv(os.path.join(args.dir, "asn_sda_noise_sensitivity.csv"))
    plot(rows, args.out, args.dpi)


if __name__ == "__main__":
    sys.exit(main())
