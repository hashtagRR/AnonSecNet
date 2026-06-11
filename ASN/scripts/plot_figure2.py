#!/usr/bin/env python3
"""
plot_figure2.py  --  Anon-Sec-Net v2  Figure 2: Per-hop Processing Latency

Reads figure5_per_hop_latency.csv and produces figure2_perhop_latency.pdf/.png.

Usage:
    python plot_figure2.py [--csv figure5_per_hop_latency.csv] [--out-dir .]
"""

import argparse
import csv
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np


# ── colour / style constants ─────────────────────────────────────────────────
COLORS = {
    "asn":     "#1f77b4",   # blue
    "tor":     "#ff7f0e",   # orange
    "nonanon": "#2ca02c",   # green
}
LABELS = {
    "asn":     "Anon-Sec-Net",
    "tor":     "Tor-equivalent",
    "nonanon": "No-anonymity baseline",
}
MARKERS = {
    "asn":     "o",
    "tor":     "s",
    "nonanon": "^",
}


def read_csv(path):
    rows = {}   # protocol -> list of (payload_bytes, mean_us, ci95_us)
    with open(path, newline="") as fp:
        reader = csv.DictReader(filter(lambda l: not l.startswith("#"), fp))
        for row in reader:
            proto = row["protocol"].strip()
            pb    = int(row["payload_bytes"])
            mean  = float(row["mean_us"])
            ci95  = float(row["ci95_us"])
            rows.setdefault(proto, []).append((pb, mean, ci95))
    # sort each protocol by payload size
    for k in rows:
        rows[k].sort()
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv",     default="figure5_per_hop_latency.csv")
    parser.add_argument("--out-dir", default=".")
    args = parser.parse_args()

    if not os.path.exists(args.csv):
        sys.exit(f"ERROR: {args.csv} not found")

    data = read_csv(args.csv)

    fig, ax = plt.subplots(figsize=(6, 4))

    for proto in ["asn", "tor", "nonanon"]:
        if proto not in data:
            continue
        pts = data[proto]
        xs  = [p[0] for p in pts]
        ys  = [p[1] for p in pts]
        err = [p[2] for p in pts]
        ax.errorbar(
            xs, ys, yerr=err,
            label=LABELS[proto],
            color=COLORS[proto],
            marker=MARKERS[proto],
            markersize=5,
            linewidth=1.5,
            capsize=3,
        )

    ax.set_xlabel("Payload size (bytes)", fontsize=11)
    ax.set_ylabel("Per-hop latency (µs)", fontsize=11)
    ax.set_title("Figure 2: Per-hop Cryptographic Processing Latency", fontsize=11)
    ax.legend(fontsize=9)
    ax.grid(True, linestyle="--", alpha=0.4)
    ax.set_xscale("log", base=2)
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{int(x)}"))
    ax.set_xlim(left=32)
    ax.set_ylim(bottom=0)

    plt.tight_layout()

    os.makedirs(args.out_dir, exist_ok=True)
    for ext in ("pdf", "png"):
        out = os.path.join(args.out_dir, f"figure2_perhop_latency.{ext}")
        plt.savefig(out, dpi=150)
        print(f"  Saved -> {out}")

    plt.close()
    print("Done.")


if __name__ == "__main__":
    main()
