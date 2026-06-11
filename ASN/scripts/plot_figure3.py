#!/usr/bin/env python3
"""
plot_figure3.py  --  Anon-Sec-Net v2  Figure 3: Path Construction Time

Reads figure3_path_construction.csv (and optionally tor_session_setup.csv) and produces
figure3_path_construction.pdf/.png as a grouped bar chart with 95% CI.

Usage:
    python plot_figure3.py [--asn-csv figure3_path_construction.csv]
                           [--tor-csv tor_session_setup.csv]
                           [--out-dir .]
"""

import argparse
import csv
import math
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


COLORS = {
    "asn": "#1f77b4",
    "tor": "#ff7f0e",
}
LABELS = {
    "asn": "Anon-Sec-Net",
    "tor": "Tor-equivalent",
}


def ci95(values):
    n = len(values)
    if n == 0:
        return 0.0, 0.0
    m = sum(values) / n
    if n == 1:
        return m, 0.0
    var = sum((x - m) ** 2 for x in values) / (n - 1)
    std = math.sqrt(var)
    t   = 2.0 if n < 30 else 1.96
    return m, t * std / math.sqrt(n)


def read_summary_csv(path):
    """Read a figure3_*.csv that has a summary row then raw samples."""
    summary = {}
    raw     = []
    if not os.path.exists(path):
        return summary, raw
    with open(path, newline="") as fp:
        lines = [l for l in fp if not l.startswith("#")]
    reader = csv.DictReader(lines)
    in_raw = False
    for row in reader:
        keys = list(row.keys())
        if keys and keys[0] == "protocol":
            summary = row
        # After the blank row the column heading changes to "# raw samples (ms)"
        # csv.DictReader will present it as the first key of the next "row"
    # Re-parse raw values manually
    with open(path) as fp:
        past_blank = False
        for line in fp:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("protocol") or line.startswith("ms"):
                continue
            # detect blank row between summary and raws
            parts = line.split(",")
            try:
                raw.append(float(parts[0]))
            except ValueError:
                pass
    # Remove the summary numbers from raw (first row values)
    return summary, raw


def read_plain_csv(path):
    """Read a plain single-column float CSV (e.g. tor_session_setup.csv)."""
    values = []
    if not os.path.exists(path):
        return values
    with open(path) as fp:
        for line in fp:
            line = line.strip()
            if not line or line.startswith("#") or line in ("ms", "session_ms"):
                continue
            try:
                values.append(float(line))
            except ValueError:
                pass
    return values


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--asn-csv", default="figure3_path_construction.csv")
    parser.add_argument("--tor-csv", default="tor_session_setup.csv")
    parser.add_argument("--out-dir", default=".")
    args = parser.parse_args()

    _, asn_raw = read_summary_csv(args.asn_csv)
    tor_raw    = read_plain_csv(args.tor_csv)

    if not asn_raw:
        sys.exit(f"ERROR: no ASN samples found in {args.asn_csv}")

    datasets = {"asn": asn_raw}
    if tor_raw:
        datasets["tor"] = tor_raw

    protos = [p for p in ["asn", "tor"] if p in datasets]

    means  = []
    cis    = []
    p5s    = []
    p95s   = []

    for p in protos:
        v = sorted(datasets[p])
        m, hw = ci95(v)
        means.append(m)
        cis.append(hw)
        n = len(v)
        p5s.append(v[max(0, int(n * 0.05))])
        p95s.append(v[min(n - 1, int(n * 0.95))])

    x     = np.arange(len(protos))
    width = 0.5

    fig, ax = plt.subplots(figsize=(5 if len(protos) == 1 else 6, 4))

    bars = ax.bar(
        x, means, width,
        yerr=cis,
        color=[COLORS[p] for p in protos],
        label=[LABELS[p] for p in protos],
        capsize=5,
        error_kw={"elinewidth": 1.5},
    )

    # annotate mean ± CI
    for i, (m, hw) in enumerate(zip(means, cis)):
        ax.text(x[i], m + hw + 0.5, f"{m:.1f}±{hw:.1f} ms",
                ha="center", va="bottom", fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels([LABELS[p] for p in protos], fontsize=10)
    ax.set_ylabel("Session setup time (ms)", fontsize=11)
    ax.set_title("Figure 3: Path Construction Time", fontsize=11)
    ax.set_ylim(bottom=0)
    ax.grid(True, axis="y", linestyle="--", alpha=0.4)

    # Add p5/p95 whiskers as text
    for i, (lo, hi) in enumerate(zip(p5s, p95s)):
        ax.text(x[i] + width / 2 + 0.02, lo, f"p5={lo:.1f}",
                va="center", fontsize=7, color="#555")
        ax.text(x[i] + width / 2 + 0.02, hi, f"p95={hi:.1f}",
                va="center", fontsize=7, color="#555")

    n_note = "  ".join(f"n={len(datasets[p])}" for p in protos)
    ax.text(0.97, 0.03, n_note, transform=ax.transAxes,
            ha="right", va="bottom", fontsize=8, color="#555")

    plt.tight_layout()
    os.makedirs(args.out_dir, exist_ok=True)
    for ext in ("pdf", "png"):
        out = os.path.join(args.out_dir, f"figure3_path_construction.{ext}")
        plt.savefig(out, dpi=150)
        print(f"  Saved -> {out}")
    plt.close()
    print("Done.")


if __name__ == "__main__":
    main()
