#!/usr/bin/env python3
"""
plot_figure4.py  --  Anon-Sec-Net v2  Figure 4: Anonymity Set Size

Generates a publication-quality log-scale plot of de-anonymisation probability
vs malicious node fraction f, for both Anon-Sec-Net (f^6) and Tor-equivalent
(f^3), showing theoretical curves alongside Monte Carlo validation points.

Requires: matplotlib, numpy
    pip install matplotlib numpy

Usage:
    python plot_figure4.py [--dir <csv_dir>] [--out <output.pdf>]
    python plot_figure4.py --out figure4.png --dpi 300
"""

import argparse
import csv
import os
import sys


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_csv(path):
    rows = []
    if not os.path.exists(path):
        print(f"ERROR: {path} not found. Run montecarlo_figure4.py first.")
        sys.exit(1)
    with open(path, newline="") as fp:
        lines = [l for l in fp if not l.startswith("#")]
    reader = csv.DictReader(lines)
    for row in reader:
        try:
            rows.append({k: float(v) for k, v in row.items()})
        except ValueError:
            continue
    return rows


# ---------------------------------------------------------------------------
# Plot
# ---------------------------------------------------------------------------

def plot(rows, out_path, dpi):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import matplotlib.ticker as ticker
        import numpy as np
    except ImportError:
        print("ERROR: matplotlib and numpy are required.")
        print("       pip install matplotlib numpy")
        sys.exit(1)

    f_vals      = np.array([r["f"]           for r in rows])
    asn_theory  = np.array([r["asn_theory"]  for r in rows])
    tor_theory  = np.array([r["tor_theory"]  for r in rows])
    asn_mc      = np.array([r["asn_mc"]      for r in rows])
    asn_ci      = np.array([r["asn_mc_ci95"] for r in rows])
    tor_mc      = np.array([r["tor_mc"]      for r in rows])
    tor_ci      = np.array([r["tor_mc_ci95"] for r in rows])

    # Smooth theory curves over dense f range
    f_dense    = np.linspace(0.001, 1.0, 500)
    asn_dense  = f_dense ** 6
    tor_dense  = f_dense ** 3

    # ── Figure setup ─────────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(7, 5))

    # Colour palette -- accessible, print-friendly
    CLR_ASN = "#185FA5"   # blue
    CLR_TOR = "#D85A30"   # coral/orange

    # ── Theory curves ────────────────────────────────────────────────────
    ax.plot(f_dense, asn_dense,
            color=CLR_ASN, linewidth=1.8, linestyle="-",
            label=r"Anon-Sec-Net  $f^6$  (theory)", zorder=3)

    ax.plot(f_dense, tor_dense,
            color=CLR_TOR, linewidth=1.8, linestyle="--",
            label=r"Tor-equivalent  $f^3$  (theory)", zorder=3)

    # ── Monte Carlo points with CI error bars ────────────────────────────
    # Only plot MC points where asn_mc > 0 (below MC resolution -> skip)
    asn_mask = asn_mc > 0
    tor_mask  = tor_mc > 0

    ax.errorbar(f_vals[asn_mask], asn_mc[asn_mask],
                yerr=asn_ci[asn_mask],
                fmt="o", color=CLR_ASN, markersize=4.5,
                capsize=3, capthick=1, linewidth=0.8, elinewidth=0.8,
                label="Anon-Sec-Net  (Monte Carlo)", zorder=4)

    ax.errorbar(f_vals[tor_mask], tor_mc[tor_mask],
                yerr=tor_ci[tor_mask],
                fmt="s", color=CLR_TOR, markersize=4.5,
                capsize=3, capthick=1, linewidth=0.8, elinewidth=0.8,
                label="Tor-equivalent  (Monte Carlo)", zorder=4)

    # ── Annotation: f=0.1 key claim ──────────────────────────────────────
    ax.annotate(
        r"$f=0.1$: ASN $\approx 10^{-6}$" + "\n" + r"Tor-eq $\approx 10^{-3}$  (1000× worse)",
        xy=(0.1, 1e-3), xycoords="data",
        xytext=(0.22, 2e-5), textcoords="data",
        fontsize=8,
        arrowprops=dict(arrowstyle="->", color="#444441",
                        connectionstyle="arc3,rad=0.25", lw=0.8),
        color="#444441",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="white",
                  edgecolor="#D3D1C7", linewidth=0.6, alpha=0.92),
    )

    # ── Axes ─────────────────────────────────────────────────────────────
    ax.set_yscale("log")
    ax.set_xlim(-0.01, 1.01)
    ax.set_ylim(1e-9, 2.0)

    ax.set_xlabel("Malicious node fraction  $f$", fontsize=11)
    ax.set_ylabel("De-anonymisation probability per session", fontsize=11)
    ax.set_title(
        "Figure 4. Anonymity set size: Anon-Sec-Net vs Tor-equivalent",
        fontsize=11, pad=10
    )

    # Major gridlines only, light
    ax.yaxis.set_major_locator(ticker.LogLocator(base=10, numticks=12))
    ax.yaxis.set_minor_locator(ticker.LogLocator(base=10, subs="auto", numticks=50))
    ax.grid(which="major", linestyle=":", linewidth=0.5, color="#B4B2A9", alpha=0.7)
    ax.grid(which="minor", linestyle=":", linewidth=0.3, color="#D3D1C7", alpha=0.5)

    ax.tick_params(axis="both", which="major", labelsize=9)
    ax.tick_params(axis="both", which="minor", labelsize=0)

    # ── Legend ───────────────────────────────────────────────────────────
    leg = ax.legend(
        loc="upper left", fontsize=8.5,
        framealpha=0.92, edgecolor="#B4B2A9",
        handlelength=2.2, labelspacing=0.5,
    )

    # ── MC resolution note ───────────────────────────────────────────────
    n_sessions = int(rows[0]["n_sessions"]) if rows else 10000
    mc_floor   = 1.0 / n_sessions
    ax.axhline(mc_floor, color="#888780", linewidth=0.7,
               linestyle=(0, (3, 5)), alpha=0.7, zorder=1)
    ax.text(1.005, mc_floor * 1.3,
            f"MC floor\n(1/{n_sessions:,})",
            fontsize=6.5, color="#5F5E5A",
            va="bottom", ha="left", linespacing=1.3)

    # ── Layout and save ──────────────────────────────────────────────────
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


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Plot Figure 4: Anonymity Set Size vs Malicious Fraction."
    )
    parser.add_argument(
        "--dir", default=".",
        help="Directory containing figure4_anonymity_set.csv",
    )
    parser.add_argument(
        "--out", default="figure4.png",
        help="Output file path (e.g. figure4.png, figure4.pdf)",
    )
    parser.add_argument(
        "--dpi", type=int, default=300,
        help="Resolution for raster output (default 300)",
    )
    args = parser.parse_args()

    csv_path = os.path.join(args.dir, "figure4_anonymity_set.csv")
    print(f"  Loading {csv_path} ...")
    rows = load_csv(csv_path)
    print(f"  Loaded {len(rows)} f-values,  n_sessions={int(rows[0]['n_sessions']):,}")

    print(f"  Plotting -> {args.out}")
    plot(rows, args.out, args.dpi)


if __name__ == "__main__":
    main()
