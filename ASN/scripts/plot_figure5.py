#!/usr/bin/env python3
"""
plot_figure5.py  --  Anon-Sec-Net v2  Figure 5: Cover Traffic Overhead

Reads figure7_cover_overhead_120s.csv and produces
figure5_cover_overhead.pdf/.png.

Usage:
    python plot_figure5.py [--csv figure7_cover_overhead_120s.csv] [--out-dir .]
"""

import argparse
import csv
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


def read_csv(path):
    rows = []
    with open(path, newline="") as fp:
        reader = csv.DictReader(filter(lambda l: not l.startswith("#"), fp))
        for row in reader:
            rows.append({
                "load":  float(row["load_pct"]),
                "cover": float(row["cover_overhead_pct"]),
                "ci95":  float(row["ci95_pct"]),
            })
    rows.sort(key=lambda r: r["load"])
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv",     default="figure7_cover_overhead_120s.csv")
    parser.add_argument("--out-dir", default=".")
    args = parser.parse_args()

    if not os.path.exists(args.csv):
        sys.exit(f"ERROR: {args.csv} not found")

    rows = read_csv(args.csv)
    xs   = [r["load"]  for r in rows]
    ys   = [r["cover"] for r in rows]
    err  = [r["ci95"]  for r in rows]

    fig, ax = plt.subplots(figsize=(6, 4))

    ax.errorbar(xs, ys, yerr=err,
                color="#1f77b4", marker="o", markersize=5,
                linewidth=1.8, capsize=4,
                label="Anon-Sec-Net cover %")

    # Theoretical 100% cover at zero load reference line
    ax.axhline(100, color="#aaa", linestyle="--", linewidth=1, label="100% cover (ideal)")

    ax.set_xlabel("Real-traffic load (% of cover rate)", fontsize=11)
    ax.set_ylabel("Cover traffic as % of total traffic", fontsize=11)
    ax.set_title("Figure 5: Cover Traffic Overhead vs Load", fontsize=11)
    ax.set_xlim(0, max(xs) + 5)
    ax.set_ylim(0, 115)
    ax.legend(fontsize=9)
    ax.grid(True, linestyle="--", alpha=0.4)

    # Second y-axis showing overhead fraction (cover/(cover+real))
    # i.e. same data, just annotation
    plt.tight_layout()
    os.makedirs(args.out_dir, exist_ok=True)
    for ext in ("pdf", "png"):
        out = os.path.join(args.out_dir, f"figure5_cover_overhead.{ext}")
        plt.savefig(out, dpi=150)
        print(f"  Saved -> {out}")
    plt.close()
    print("Done.")


if __name__ == "__main__":
    main()
