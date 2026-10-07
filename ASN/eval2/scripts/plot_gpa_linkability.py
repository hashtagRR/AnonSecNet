#!/usr/bin/env python3
"""
plot_gpa_linkability.py: Task A follow-up: cumulative P(>=1 observed
session) vs. number of sessions, for a k=1-vantage-point GPA against
several assumed entry-node population sizes M, contrasting the actual
implementation (M=1) against the paper's own Uniformity assumption
(M>1).

Usage:
    python plot_gpa_linkability.py [--dir .] [--out fig_gpa_linkability.pdf]
"""

import argparse
import csv
import os
import sys


def load_csv(path):
    if not os.path.exists(path):
        print(f"ERROR: {path} not found. Run asn_gpa_linkability.py first.")
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

    m_values = [1, 3, 10, 50, 100, 500]
    COLORS = ["#B3251E", "#0B3C6B", "#D85A30", "#5E9A4C", "#C9A227", "#6A4C93"]
    k_target = 1

    fig, ax = plt.subplots(figsize=(7.5, 5.5))

    for m, color in zip(m_values, COLORS):
        ns, ps = [], []
        for r in rows:
            if (int(r["population_m"]) == m and int(r["vantage_budget_k"]) == k_target):
                ns.append(int(r["n_sessions"]))
                ps.append(float(r["cumulative_p"]))
        pairs = sorted(zip(ns, ps))
        ns = [p[0] for p in pairs]
        ps = [p[1] for p in pairs]
        label = f"M={m} (actual implementation)" if m == 1 else f"M={m}"
        lw = 2.4 if m == 1 else 1.6
        ax.plot(ns, ps, color=color, linewidth=lw, marker="o", markersize=3,
                 label=label, zorder=3 if m == 1 else 2)

    ax.axhline(0.5, color="#888780", linewidth=0.8, linestyle=(0, (3, 5)), zorder=1,
               label="50% cumulative risk")
    ax.set_xscale("log")
    ax.set_xlabel("Number of sessions observed $N$", fontsize=11)
    ax.set_ylabel(r"Cumulative P($\geq$1 session linked), $k=1$-node GPA", fontsize=11)
    ax.set_title("Passive first-hop linkability vs. assumed entry-node population $M$\n"
                 "A single-vantage-point GPA needs 1 session at $M{=}1$ (actual);\n"
                 "$O(M)$ sessions at the paper's own diversity assumption",
                 fontsize=10.5)
    ax.grid(which="major", linestyle=":", linewidth=0.5, color="#B4B2A9", alpha=0.7)
    ax.legend(loc="lower right", fontsize=9, framealpha=0.92, edgecolor="#B4B2A9")
    ax.annotate(
        "at M=1 (today): certain linkage,\nsession 1, for free\n"
        "at M=500: ~347 sessions for\neven 50% chance of one hit",
        xy=(0.03, 0.60), xycoords="axes fraction", fontsize=8.5, color="#5F5E5A",
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
    ap.add_argument("--out", default="fig_gpa_linkability.pdf")
    ap.add_argument("--dpi", type=int, default=300)
    args = ap.parse_args()

    rows = load_csv(os.path.join(args.dir, "asn_gpa_linkability_curves.csv"))
    plot(rows, args.out, args.dpi)


if __name__ == "__main__":
    sys.exit(main())
