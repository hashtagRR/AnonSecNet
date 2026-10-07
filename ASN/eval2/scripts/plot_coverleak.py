#!/usr/bin/env python3
"""
plot_coverleak.py: Task C: cover-traffic load-leakage figure

Two panels:
  (a) Attacker AUC (active-vs-idle) vs load level, one curve per scheme.
  (b) Security-vs-overhead trade-off: overhead cost (x) vs attacker AUC (y)
      for asn_adaptive vs asn_mitigated at each load level, paired by
      load level to show whether the mitigation buys anything.

Usage:
    python plot_coverleak.py [--dir .] [--out fig_coverleak.pdf]
"""

import argparse
import csv
import os
import sys


def load_csv(path):
    if not os.path.exists(path):
        print(f"ERROR: {path} not found. Run coverleak_run.py first.")
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

    COLORS = {
        "asn_adaptive": "#185FA5",
        "loopix_constant": "#5E9A4C",
        "asn_mitigated": "#D85A30",
    }
    LABELS = {
        "asn_adaptive": "ASN adaptive (production client.c)",
        "loopix_constant": "Loopix-style constant-rate",
        "asn_mitigated": "ASN + smoothed suppression (mitigation)",
    }
    schemes = ["loopix_constant", "asn_adaptive", "asn_mitigated"]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # -- Panel (a): AUC vs load level -------------------------------------
    for scheme in schemes:
        loads, aucs = [], []
        for r in rows:
            if r["scheme"] == scheme and r["attacker_metric"] == "auc_active_vs_idle":
                loads.append(float(r["load_level"]))
                aucs.append(float(r["value"]))
        pairs = sorted(zip(loads, aucs))
        loads = [p[0] for p in pairs]
        aucs = [p[1] for p in pairs]
        marker = "o" if scheme != "loopix_constant" else "s"
        ax1.plot(loads, aucs, color=COLORS[scheme], linewidth=1.8, marker=marker,
                  markersize=4.5, label=LABELS[scheme], zorder=3)

    ax1.axhline(0.5, color="#888780", linewidth=0.8, linestyle=(0, (3, 5)),
                 zorder=1, label="Chance (AUC=0.5)")
    ax1.set_xlim(0.05, 0.95)
    ax1.set_ylim(0.4, 1.02)
    ax1.set_xlabel("Real-traffic load level", fontsize=11)
    ax1.set_ylabel("Attacker AUC (active vs idle)", fontsize=11)
    ax1.set_title("(a) Activity-level leak vs load", fontsize=11)
    ax1.grid(which="major", linestyle=":", linewidth=0.5, color="#B4B2A9", alpha=0.7)
    ax1.tick_params(axis="both", which="major", labelsize=9)
    ax1.legend(loc="center right", fontsize=7.5, framealpha=0.92, edgecolor="#B4B2A9")

    # -- Panel (b): security (AUC) vs overhead cost, paired by load level,
    for scheme, marker in [("asn_adaptive", "o"), ("asn_mitigated", "^")]:
        loads, aucs, ovh = [], [], []
        for r in rows:
            if r["scheme"] == scheme and r["attacker_metric"] == "auc_active_vs_idle":
                loads.append(float(r["load_level"]))
                aucs.append(float(r["value"]))
                ovh.append(float(r["overhead_pct"]))
        pairs = sorted(zip(loads, ovh, aucs))
        ovh_s = [p[1] for p in pairs]
        auc_s = [p[2] for p in pairs]
        ax2.plot(ovh_s, auc_s, color=COLORS[scheme], linewidth=1.2, linestyle=":",
                   alpha=0.6, zorder=2)
        ax2.scatter(ovh_s, auc_s, color=COLORS[scheme], marker=marker, s=45,
                     label=LABELS[scheme], zorder=3, edgecolor="white", linewidth=0.5)

    # annotate load levels on the adaptive curve
    for r in rows:
        if r["scheme"] == "asn_adaptive" and r["attacker_metric"] == "auc_active_vs_idle":
            L = float(r["load_level"])
            if L in (0.1, 0.3, 0.5, 0.7, 0.9):
                ax2.annotate(f"L={L:.1f}", (float(r["overhead_pct"]), float(r["value"])),
                              fontsize=6.5, color="#5F5E5A",
                              xytext=(3, 3), textcoords="offset points")

    ax2.axhline(0.5, color="#888780", linewidth=0.8, linestyle=(0, (3, 5)), zorder=1)
    ax2.set_xlabel("Cover-traffic overhead at this load level (%)", fontsize=11)
    ax2.set_ylabel("Attacker AUC (active vs idle)", fontsize=11)
    ax2.set_title("(b) Security vs overhead: is the mitigation worth it?", fontsize=10.5)
    ax2.grid(which="major", linestyle=":", linewidth=0.5, color="#B4B2A9", alpha=0.7)
    ax2.tick_params(axis="both", which="major", labelsize=9)
    ax2.legend(loc="lower right", fontsize=8, framealpha=0.92, edgecolor="#B4B2A9")
    ax2.annotate(
        "mitigated points sit at higher\noverhead for equal-or-worse AUC\n(dominated, not a trade-off)",
        xy=(0.97, 0.35), xycoords="axes fraction", fontsize=7.5, color="#5F5E5A",
        ha="right",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="white",
                  edgecolor="#D3D1C7", linewidth=0.6, alpha=0.92),
    )

    fig.suptitle("Cover-traffic load-leakage study (Task C)", fontsize=12, y=1.02)
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
    ap.add_argument("--out", default="fig_coverleak.pdf")
    ap.add_argument("--dpi", type=int, default=300)
    args = ap.parse_args()

    rows = load_csv(os.path.join(args.dir, "cover_leakage.csv"))
    plot(rows, args.out, args.dpi)


if __name__ == "__main__":
    sys.exit(main())
