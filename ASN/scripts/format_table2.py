#!/usr/bin/env python3
"""
format_table2.py  --  Anon-Sec-Net v2  Table 2: Throughput Comparison

Reads table2_results.csv and produces:
  - table2_throughput.tex   (LaTeX booktabs table)
  - table2_throughput.md    (Markdown table)
  - table2_throughput.png   (bar chart)

Usage:
    python format_table2.py [--csv table2_results.csv]
                            [--tor-csv tor_sg_goodput.csv]
                            [--out-dir .]
"""

import argparse
import csv
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


EXPECTED_N_CLIENTS = [1, 5, 10, 50, 100, 500, 1000]

PROTOCOL_LABELS = {
    "asn":     "Anon-Sec-Net",
    "tor":     "Tor-equivalent",
    "nonanon": "No-anonymity",
}
COLORS = {
    "asn":     "#1f77b4",
    "tor":     "#ff7f0e",
    "nonanon": "#2ca02c",
}


def read_csv(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, newline="") as fp:
        reader = csv.DictReader(filter(lambda l: not l.startswith("#"), fp))
        for row in reader:
            rows.append({
                "n":        int(row["n_clients"]),
                "proto":    row["protocol"].strip(),
                "mean_kbps": float(row.get("mean_kbps", 0)),
                "ci95_kbps": float(row.get("ci95_kbps", 0)),
                "peak_kbps": float(row.get("peak_kbps", 0)),
            })
    return rows


def pivot(rows):
    """Return dict: n_clients -> {proto: row}"""
    d = {}
    for r in rows:
        d.setdefault(r["n"], {})[r["proto"]] = r
    return d


def write_latex(pivoted, protos, path):
    col_headers = " & ".join(
        f"\\multicolumn{{2}}{{c}}{{{PROTOCOL_LABELS.get(p, p)}}}"
        for p in protos
    )
    sub_headers = " & ".join(
        "Mean (kbps) & CI$_{95}$ (kbps)"
        for _ in protos
    )
    ncols = 1 + 2 * len(protos)

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Table 2: Aggregate Throughput vs Concurrent Sessions (60 s runs)}",
        r"\label{tab:throughput}",
        r"\begin{tabular}{l" + "rr" * len(protos) + "}",
        r"\toprule",
        f"Sessions & {col_headers} \\\\",
        f"         & {sub_headers} \\\\",
        r"\midrule",
    ]

    for n in sorted(pivoted.keys()):
        cells = [str(n)]
        for p in protos:
            if p in pivoted[n]:
                r = pivoted[n][p]
                cells.append(f"{r['mean_kbps']:.1f}")
                cells.append(f"{r['ci95_kbps']:.1f}")
            else:
                cells += ["---", "---"]
        lines.append(" & ".join(cells) + r" \\")

    lines += [
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ]
    with open(path, "w") as fp:
        fp.write("\n".join(lines) + "\n")
    print(f"  Saved -> {path}")


def write_markdown(pivoted, protos, path):
    header = "| Sessions |" + "".join(
        f" {PROTOCOL_LABELS.get(p, p)} mean (kbps) | CI95 |"
        for p in protos
    )
    sep = "|---|" + "---|---|" * len(protos)
    lines = [header, sep]
    for n in sorted(pivoted.keys()):
        row = f"| {n} |"
        for p in protos:
            if p in pivoted[n]:
                r = pivoted[n][p]
                row += f" {r['mean_kbps']:.1f} | ±{r['ci95_kbps']:.1f} |"
            else:
                row += " — | — |"
        lines.append(row)
    with open(path, "w") as fp:
        fp.write("\n".join(lines) + "\n")
    print(f"  Saved -> {path}")


def write_chart(pivoted, protos, path):
    ns = sorted(pivoted.keys())
    x  = np.arange(len(ns))
    n_protos = len(protos)
    width = 0.7 / n_protos

    fig, ax = plt.subplots(figsize=(8, 4))

    for i, p in enumerate(protos):
        means = []
        cis   = []
        for n in ns:
            if p in pivoted[n]:
                means.append(pivoted[n][p]["mean_kbps"])
                cis.append(pivoted[n][p]["ci95_kbps"])
            else:
                means.append(0)
                cis.append(0)
        offset = (i - n_protos / 2 + 0.5) * width
        ax.bar(x + offset, means, width,
               yerr=cis,
               label=PROTOCOL_LABELS.get(p, p),
               color=COLORS.get(p, "#888"),
               capsize=3,
               error_kw={"elinewidth": 1.2})

    ax.set_xticks(x)
    ax.set_xticklabels([str(n) for n in ns])
    ax.set_xlabel("Concurrent sessions", fontsize=11)
    ax.set_ylabel("Aggregate throughput (kbps)", fontsize=11)
    ax.set_title("Table 2: Throughput vs Concurrent Sessions", fontsize=11)
    ax.legend(fontsize=9)
    ax.grid(True, axis="y", linestyle="--", alpha=0.4)
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"  Saved -> {path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv",     default="table2_results.csv")
    parser.add_argument("--tor-csv", default="tor_sg_goodput.csv",
                        help="Optional Tor-equivalent goodput CSV")
    parser.add_argument("--out-dir", default=".")
    args = parser.parse_args()

    if not os.path.exists(args.csv):
        sys.exit(f"ERROR: {args.csv} not found")

    rows = read_csv(args.csv)

    # Optionally inject Tor rows from a separate CSV
    if os.path.exists(args.tor_csv):
        tor_rows = read_csv(args.tor_csv)
        rows.extend(tor_rows)

    if not rows:
        sys.exit("ERROR: No data rows found")

    protos  = []
    seen    = set()
    for r in rows:
        if r["proto"] not in seen:
            protos.append(r["proto"])
            seen.add(r["proto"])

    pivoted = pivot(rows)

    os.makedirs(args.out_dir, exist_ok=True)

    write_latex   (pivoted, protos, os.path.join(args.out_dir, "table2_throughput.tex"))
    write_markdown(pivoted, protos, os.path.join(args.out_dir, "table2_throughput.md"))
    write_chart   (pivoted, protos, os.path.join(args.out_dir, "table2_throughput.png"))

    # Print a quick console summary
    print()
    print(f"{'Sessions':>10}", end="")
    for p in protos:
        print(f"  {PROTOCOL_LABELS.get(p,p):>20}", end="")
    print()
    for n in sorted(pivoted.keys()):
        print(f"{n:>10}", end="")
        for p in protos:
            if p in pivoted[n]:
                r = pivoted[n][p]
                print(f"  {r['mean_kbps']:>17.1f} kbps", end="")
            else:
                print(f"  {'---':>17}", end="")
        print()
    print("\nDone.")


if __name__ == "__main__":
    main()
