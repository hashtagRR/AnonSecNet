#!/usr/bin/env python3
"""
plot_repeated_sessions.py: Task A follow-up: cumulative disclosure risk
vs. number of repeated sessions, for D2 at f=0.10 across several rho.

Usage:
    python plot_repeated_sessions.py [--dir .] [--out fig_repeated.pdf]
"""

import argparse
import csv
import os
import sys


def load_csv(path):
    if not os.path.exists(path):
        print(f"ERROR: {path} not found. Run asn_repeated_sessions.py first.")
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

    rho_values = [0.0, 0.01, 0.05, 0.1]
    COLORS = ["#0B3C6B", "#D85A30", "#5E9A4C", "#C9A227"]
    f_target = 0.10

    fig, ax = plt.subplots(figsize=(7.5, 5.5))

    for rho, color in zip(rho_values, COLORS):
        ns, ps = [], []
        for r in rows:
            if (r["event"] == "D2" and abs(float(r["f"]) - f_target) < 1e-9
                    and abs(float(r["rho"]) - rho) < 1e-9):
                ns.append(int(r["n_sessions"]))
                ps.append(float(r["cumulative_p"]))
        pairs = sorted(zip(ns, ps))
        ns = [p[0] for p in pairs]
        ps = [p[1] for p in pairs]
        ax.plot(ns, ps, color=color, linewidth=1.8, marker="o", markersize=3,
                 label=rf"$\rho={rho:.2f}$", zorder=3)

    ax.axhline(0.5, color="#888780", linewidth=0.8, linestyle=(0, (3, 5)), zorder=1,
               label="50% cumulative risk")
    ax.set_xscale("log")
    ax.set_xlabel("Number of independent sessions $N$", fontsize=11)
    ax.set_ylabel(r"Cumulative P($\geq$1 disclosure event, D2)", fontsize=11)
    ax.set_title(f"Repeated-use disclosure risk (D2, $f={f_target:.2f}$)\n"
                 "How many sessions until the ladder's per-session guarantee erodes?",
                 fontsize=11)
    ax.grid(which="major", linestyle=":", linewidth=0.5, color="#B4B2A9", alpha=0.7)
    ax.legend(loc="lower right", fontsize=9, framealpha=0.92, edgecolor="#B4B2A9")
    ax.annotate(
        r"at $\rho=0$: needs ~69M sessions" "\n" r"at $\rho=0.01$: needs just 693",
        xy=(0.03, 0.75), xycoords="axes fraction", fontsize=8.5, color="#5F5E5A",
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
    ap.add_argument("--out", default="fig_repeated.pdf")
    ap.add_argument("--dpi", type=int, default=300)
    args = ap.parse_args()

    rows = load_csv(os.path.join(args.dir, "asn_repeated_sessions_curves.csv"))
    plot(rows, args.out, args.dpi)


if __name__ == "__main__":
    sys.exit(main())
