#!/usr/bin/env python3
"""
plot_correlated.py: Task A: correlated-compromise disclosure figure

Two-panel figure matching the style of scripts/plot_figure4.py:
  Left:  D2 (service-level) disclosure probability vs f, for several rho
         values, with the Tor hidden-service f^3 line overlaid.
  Right: crossover rho* vs f, for both single-path baselines.

Usage:
    python plot_correlated.py [--dir .] [--out fig_correlated.pdf]
"""

import argparse
import csv
import math
import os
import sys


def load_csv(path):
    if not os.path.exists(path):
        print(f"ERROR: {path} not found. Run asn_correlated_disclosure.py first.")
        sys.exit(1)
    with open(path, newline="") as fp:
        lines = [l for l in fp if not l.startswith("#")]
    return list(csv.DictReader(lines))


def wilson_bounds(k, n, z=1.959964):
    """Proper (asymmetric) Wilson score interval bounds for k successes in
    n trials. Unlike a symmetric +-spread applied around the raw proportion
    k/n, this stays within [0, 1] for any k including k=0, required for
    plotting rare-event Monte Carlo estimates on a log-scale y-axis, where
    a naive point-minus-spread goes negative and is unplottable."""
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    spread = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, center - spread), min(1.0, center + spread)


def plot(ladder_rows, crossover_rows, out_path, dpi):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import matplotlib.ticker as ticker
        import numpy as np
    except ImportError:
        print("ERROR: matplotlib and numpy are required.")
        sys.exit(1)

    CLR_ASN = "#185FA5"
    CLR_TOR = "#D85A30"
    CLR_SP5 = "#5E9A4C"
    RHO_CMAP = ["#0B3C6B", "#185FA5", "#4C8FC9", "#8FBEE0", "#C9DEEE", "#D85A30"]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # -- Panel 1: D2 probability vs f, several rho values ----------------
    rho_values = [0.0, 0.1, 0.3, 0.5, 0.7, 1.0]
    f_dense = np.linspace(0.01, 0.5, 200)

    for i, rho in enumerate(rho_values):
        d2 = rho * f_dense + (1 - rho) * (f_dense ** 8)
        ax1.plot(f_dense, d2, color=RHO_CMAP[i], linewidth=1.6,
                  label=rf"$\rho={rho:.1f}$", zorder=3)

    # Monte Carlo points for a couple of rho values as a sanity overlay.
    # Points with zero observed hits (common at small f*rho, the true
    # probability can be far below what n_sessions can resolve) are drawn
    # as upper-limit markers instead of point+symmetric-error-bar: a
    # symmetric +-CI around a zero estimate goes negative, which is
    # unplottable on a log axis and was rendering as a stray line
    # plunging to the bottom of the plot.
    first_mc_label_used = False
    for rho, marker in [(0.0, "o"), (0.5, "s"), (1.0, "^")]:
        n_sessions = None
        pts_f, pts_mc, pts_lo, pts_hi = [], [], [], []
        for r in ladder_rows:
            if r["event"] == "D2" and abs(float(r["rho"]) - rho) < 1e-9:
                n_sessions = int(r["n_sessions"])
                mc = float(r["asn_mc"])
                k = round(mc * n_sessions)
                lo, hi = wilson_bounds(k, n_sessions)
                pts_f.append(float(r["f"]))
                pts_mc.append(mc)
                pts_lo.append(lo)
                pts_hi.append(hi)

        zero_f  = [f for f, mc in zip(pts_f, pts_mc) if mc == 0.0]
        zero_hi = [hi for mc, hi in zip(pts_mc, pts_hi) if mc == 0.0]
        nz_f   = [f  for f, mc in zip(pts_f, pts_mc) if mc > 0.0]
        nz_mc  = [mc for mc      in pts_mc            if mc > 0.0]
        nz_lo  = [lo for mc, lo in zip(pts_mc, pts_lo) if mc > 0.0]
        nz_hi  = [hi for mc, hi in zip(pts_mc, pts_hi) if mc > 0.0]

        label = "Monte Carlo" if not first_mc_label_used else None
        if nz_f:
            # Clamp to >=0: lo/hi come from wilson_bounds(k, n) with
            # k = round(mc * n), so mc (the un-rounded rate) can sit
            # fractionally outside its own Wilson interval, matplotlib's
            # errorbar rejects negative yerr outright.
            yerr = [[max(0.0, mc - lo) for mc, lo in zip(nz_mc, nz_lo)],
                    [max(0.0, hi - mc) for mc, hi in zip(nz_mc, nz_hi)]]
            ax1.errorbar(nz_f, nz_mc, yerr=yerr, fmt=marker, color="#2B2A28",
                          markersize=3.5, capsize=2, linewidth=0.6,
                          elinewidth=0.6, alpha=0.75, zorder=4, label=label)
            first_mc_label_used = True
        if zero_f:
            # Draw at the Wilson upper bound with a downward cap: "true
            # value is at or below this point, zero hits in n_sessions."
            ax1.errorbar(zero_f, zero_hi, yerr=[hi * 0.6 for hi in zero_hi],
                          uplims=True, fmt="none", color="#2B2A28",
                          linewidth=0.6, elinewidth=0.6, alpha=0.6, zorder=4,
                          label=None if first_mc_label_used else "Monte Carlo (0 hits, upper limit)")
            first_mc_label_used = True

    tor_hs = f_dense ** 3
    ax1.plot(f_dense, tor_hs, color=CLR_TOR, linewidth=2.0, linestyle="--",
              label=r"Tor hidden service $f^3$", zorder=5)

    ax1.set_yscale("log")
    ax1.set_xlim(0, 0.5)
    ax1.set_ylim(1e-8, 1.0)
    ax1.set_xlabel(r"Malicious fraction $f$", fontsize=11)
    ax1.set_ylabel("D2 (service-level) disclosure probability", fontsize=11)
    ax1.set_title("(a) D2 vs $f$ under correlated compromise", fontsize=11)
    ax1.grid(which="major", linestyle=":", linewidth=0.5, color="#B4B2A9", alpha=0.7)
    ax1.tick_params(axis="both", which="major", labelsize=9)
    ax1.legend(loc="lower right", fontsize=7.5, framealpha=0.92,
               edgecolor="#B4B2A9", ncol=2)

    # -- Panel 2: crossover rho* vs f -------------------------------------
    for baseline, color, label in [
        ("tor_hs_f3", CLR_TOR, r"vs Tor hidden service $f^3$"),
        ("singlepath_sgcs_f5", CLR_SP5, r"vs single-path+SG+CS $f^5$"),
    ]:
        fs, rhos = [], []
        for r in crossover_rows:
            if r["baseline"] == baseline and r["rho_star"] != "":
                fs.append(float(r["f"]))
                rhos.append(float(r["rho_star"]))
        pairs = sorted(zip(fs, rhos))
        fs = [p[0] for p in pairs]
        rhos = [p[1] for p in pairs]
        ax2.plot(fs, rhos, color=color, linewidth=1.8, label=label, zorder=3)

    ax2.set_xlim(0, 1.0)
    ax2.set_ylim(0, 1.0)
    ax2.set_xlabel(r"Malicious fraction $f$", fontsize=11)
    ax2.set_ylabel(r"Crossover correlation $\rho^*$", fontsize=11)
    ax2.set_title(r"(b) $\rho^*$ where ASN D2 = baseline", fontsize=11)
    ax2.grid(which="major", linestyle=":", linewidth=0.5, color="#B4B2A9", alpha=0.7)
    ax2.tick_params(axis="both", which="major", labelsize=9)
    ax2.legend(loc="upper right", fontsize=8.5, framealpha=0.92, edgecolor="#B4B2A9")
    ax2.annotate(
        r"below the curve: ASN safer" "\n" r"above the curve: ASN worse",
        xy=(0.7, 0.15), fontsize=7.5, color="#5F5E5A",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="white",
                  edgecolor="#D3D1C7", linewidth=0.6, alpha=0.92),
    )

    fig.suptitle("Correlated-compromise disclosure model (Task A)", fontsize=12, y=1.02)
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
    ap.add_argument("--out", default="fig_correlated.pdf")
    ap.add_argument("--dpi", type=int, default=300)
    args = ap.parse_args()

    ladder_rows = load_csv(os.path.join(args.dir, "asn_correlated_ladder.csv"))
    crossover_rows = load_csv(os.path.join(args.dir, "asn_crossover_rho.csv"))
    plot(ladder_rows, crossover_rows, args.out, args.dpi)


if __name__ == "__main__":
    sys.exit(main())
