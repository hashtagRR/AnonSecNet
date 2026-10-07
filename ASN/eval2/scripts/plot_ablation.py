#!/usr/bin/env python3
"""
plot_ablation.py: Task A follow-up: crossover rho*(f) for each design
element in isolation, all measured against the single-path f^3 baseline.

Usage:
    python plot_ablation.py [--dir .] [--out fig_ablation.pdf]
"""

import argparse
import csv
import os
import sys


def load_csv(path):
    if not os.path.exists(path):
        print(f"ERROR: {path} not found. Run asn_ablation_disclosure.py first.")
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

    CONFIGS = ["dual_path_only", "role_decouple_only", "both_asn"]
    COLORS = {"dual_path_only": "#185FA5", "role_decouple_only": "#5E9A4C", "both_asn": "#D85A30"}
    LABELS = {"dual_path_only": r"Dual-path only ($f^6$)",
              "role_decouple_only": r"Role-decoupling only ($f^5$)",
              "both_asn": r"Both (ASN's actual design, $f^8$)"}

    fig, ax = plt.subplots(figsize=(7, 5.5))

    for cfg in CONFIGS:
        fs, rhos = [], []
        for r in rows:
            if r["config"] == cfg and r["rho_star"]:
                fs.append(float(r["f"]))
                rhos.append(float(r["rho_star"]))
        pairs = sorted(zip(fs, rhos))
        fs = [p[0] for p in pairs]
        rhos = [p[1] for p in pairs]
        ax.plot(fs, rhos, color=COLORS[cfg], linewidth=1.8, label=LABELS[cfg], zorder=3)

    ax.axvline(0.1, color="#888780", linewidth=0.8, linestyle=(0, (3, 5)), zorder=1)
    ax.annotate("f=0.1 (deployment-\nrealistic point)",
                xy=(0.115, 0.435), fontsize=7.5, color="#5F5E5A", ha="left")
    ax.annotate(
        "curves nearly coincide here:\nneither element is more robust\nthan the other at realistic f",
        xy=(0.03, 0.155), fontsize=7.5, color="#5F5E5A", ha="left",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="white",
                  edgecolor="#D3D1C7", linewidth=0.6, alpha=0.92),
    )
    ax.annotate(
        "diverge at higher f:\ncombination becomes most robust,\nrole-decoupling alone least robust",
        xy=(0.55, 0.30), fontsize=7.5, color="#5F5E5A",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="white",
                  edgecolor="#D3D1C7", linewidth=0.6, alpha=0.92),
    )

    ax.set_xlim(0, 1.0)
    ax.set_ylim(0, 0.7)
    ax.set_xlabel("Malicious fraction $f$", fontsize=11)
    ax.set_ylabel(r"Crossover correlation $\rho^*$ (vs. single-path $f^3$ baseline)", fontsize=10.5)
    ax.set_title("Ablation: which design element's advantage is more fragile\nto correlated compromise?", fontsize=11)
    ax.grid(which="major", linestyle=":", linewidth=0.5, color="#B4B2A9", alpha=0.7)
    ax.legend(loc="upper left", fontsize=9, framealpha=0.92, edgecolor="#B4B2A9")

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
    ap.add_argument("--out", default="fig_ablation.pdf")
    ap.add_argument("--dpi", type=int, default=300)
    args = ap.parse_args()

    rows = load_csv(os.path.join(args.dir, "asn_ablation_crossover.csv"))
    plot(rows, args.out, args.dpi)


if __name__ == "__main__":
    sys.exit(main())
