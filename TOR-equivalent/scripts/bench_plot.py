"""
bench_plot.py  --  Plot all benchmark results produced by bench.exe
Requires: matplotlib, numpy, pandas

Usage (run from project root):

    bench.exe fig2   > results_fig2.csv
    bench.exe fig3   > results_fig3.csv
    bench.exe fig4   > results_fig4.csv
    bench.exe fig5   > results_fig5.csv
    bench.exe table2 > results_table2.csv

    python bench_plot.py

Output: fig2_per_hop_latency.png, fig3_path_construction.png,
        fig4_anonymity_set.png, fig5_cover_traffic.png,
        table2_throughput.png  (and table2_summary.csv)
"""

import sys
import math
import numpy  as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from io import StringIO

FIGSIZE = (7, 4.5)
DPI     = 150

COLORS = {
    "ansn": "#1f77b4",
    "tor":  "#ff7f0e",
    "none": "#2ca02c",
}
LABELS = {
    "ansn": "AnonSecNet",
    "tor":  "Tor-equivalent",
    "none": "No-anonymity baseline",
}

# ─── helpers ──────────────────────────────────────────────────────────────────

def read_csv(path):
    """Read a bench.exe CSV where the column header is the last '# ...' line
    before the data rows (e.g. '# payload_bytes,variant,mean_us,ci95_us').
    Windows-style CRLF line endings are handled automatically."""
    comment_headers = []
    data_lines      = []
    try:
        with open(path, newline="") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("#"):
                    # Strip leading '#' and whitespace to get potential header
                    comment_headers.append(line.lstrip("#").strip())
                else:
                    data_lines.append(line)
    except FileNotFoundError:
        print(f"[plot] {path} not found — skipping")
        return None

    if not data_lines:
        print(f"[plot] {path} has no data rows — skipping")
        return None

    # Use the last comment line that contains commas as the column header
    header = None
    for c in reversed(comment_headers):
        if "," in c:
            header = c
            break

    if header is None:
        print(f"[plot] {path}: no header comment found — using first data row")
        header     = data_lines[0]
        data_lines = data_lines[1:]

    df = pd.read_csv(StringIO("\n".join([header] + data_lines)))
    # Strip whitespace from string columns
    for col in df.columns:
        if df[col].dtype == object: df[col] = df[col].str.strip()
    return df


# ─── Figure 2: Per-hop latency ────────────────────────────────────────────────

def plot_fig2(path="results_fig2.csv"):
    df = read_csv(path)
    if df is None:
        return

    fig, ax = plt.subplots(figsize=FIGSIZE)

    for variant in ["ansn", "tor", "none"]:
        sub = df[df["variant"] == variant].sort_values("payload_bytes")
        if sub.empty:
            continue
        ax.errorbar(
            sub["payload_bytes"], sub["mean_us"],
            yerr=sub["ci95_us"],
            label=LABELS.get(variant, variant),
            color=COLORS.get(variant, "grey"),
            marker="o", capsize=3, linewidth=1.5,
        )

    ax.set_xscale("log", base=2)
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(
        lambda x, _: f"{int(x)}" if x < 1024 else f"{int(x)//1024}K"))
    ax.set_xlabel("Payload size (bytes)")
    ax.set_ylabel("Per-hop processing latency (µs)")
    ax.set_title("Figure 2: Per-hop Processing Latency")
    ax.legend()
    ax.grid(True, which="both", linestyle="--", alpha=0.4)
    fig.tight_layout()
    out = "fig2_per_hop_latency.png"
    fig.savefig(out, dpi=DPI)
    print(f"[plot] saved {out}")
    plt.close(fig)

    # Print summary table
    print("\n=== Figure 2 summary ===")
    print(f"{'Payload':>10}  {'AnonSecNet µs':>14}  {'Tor µs':>10}  {'Baseline µs':>12}  {'ANSN/Tor ratio':>15}")
    for size in sorted(df["payload_bytes"].unique()):
        row = {v: df[(df["payload_bytes"]==size) & (df["variant"]==v)]["mean_us"].values
               for v in ["ansn","tor","none"]}
        a = row["ansn"][0]  if len(row["ansn"])  else float("nan")
        t = row["tor"][0]   if len(row["tor"])   else float("nan")
        n = row["none"][0]  if len(row["none"])  else float("nan")
        ratio = a/t if t else float("nan")
        print(f"{size:>10}  {a:>14.3f}  {t:>10.3f}  {n:>12.3f}  {ratio:>15.2f}x")


# ─── Figure 3: Path construction ─────────────────────────────────────────────

def plot_fig3(path="results_fig3.csv"):
    df = read_csv(path)
    if df is None:
        return

    fig, ax = plt.subplots(figsize=(5, 4))
    variants = df["variant"].tolist()
    means    = df["mean_ms"].tolist()
    ci95s    = df["ci95_ms"].tolist()
    x        = np.arange(len(variants))

    bars = ax.bar(x, means,
                  color=[COLORS.get(v, "grey") for v in variants],
                  yerr=ci95s, capsize=6, width=0.4)
    ax.set_xticks(x)
    ax.set_xticklabels([LABELS.get(v, v) for v in variants])
    ax.set_ylabel("Path construction time (ms)")
    ax.set_title("Figure 3: Path Construction Time")
    for bar, mean, ci in zip(bars, means, ci95s):
        ax.text(bar.get_x() + bar.get_width()/2, mean + ci + 0.2,
                f"{mean:.1f} ms", ha="center", va="bottom", fontsize=9)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()
    out = "fig3_path_construction.png"
    fig.savefig(out, dpi=DPI)
    print(f"[plot] saved {out}")
    plt.close(fig)

    print("\n=== Figure 3 summary ===")
    for _, row in df.iterrows():
        print(f"  {LABELS.get(row['variant'], row['variant'])}: "
              f"{row['mean_ms']:.2f} ms ± {row['ci95_ms']:.2f} ms (95% CI)")
    if len(df) >= 2:
        ratio = df.iloc[1]["mean_ms"] / df.iloc[0]["mean_ms"] \
                if df.iloc[0]["mean_ms"] else float("nan")
        print(f"  Ratio (ansn/tor): {ratio:.2f}x  (expected ~2x)")


# ─── Figure 4: Anonymity set size ────────────────────────────────────────────

def plot_fig4(path="results_fig4.csv"):
    df = read_csv(path)
    if df is None:
        return

    fig, ax = plt.subplots(figsize=FIGSIZE)

    for variant in ["ansn", "tor"]:
        sub = df[df["variant"] == variant].sort_values("f")
        if sub.empty:
            continue
        ax.semilogy(sub["f"], sub["deanon_prob_theory"],
                    label=f"{LABELS.get(variant, variant)} (theory)",
                    color=COLORS.get(variant, "grey"),
                    linewidth=2)
        mc = sub["deanon_rate_monte_carlo"].replace(0, float("nan"))
        ax.semilogy(sub["f"], mc,
                    label=f"{LABELS.get(variant, variant)} (Monte Carlo)",
                    color=COLORS.get(variant, "grey"),
                    linestyle="--", marker="x", alpha=0.7)

    ax.set_xlabel("Malicious node fraction f")
    ax.set_ylabel("De-anonymization probability (log scale)")
    ax.set_title("Figure 4: Anonymity Set Size vs Malicious Node Fraction")
    ax.legend(fontsize=8)
    ax.grid(True, which="both", linestyle="--", alpha=0.4)
    fig.tight_layout()
    out = "fig4_anonymity_set.png"
    fig.savefig(out, dpi=DPI)
    print(f"[plot] saved {out}")
    plt.close(fig)

    print("\n=== Figure 4 @ f=0.10 ===")
    for variant in ["ansn", "tor"]:
        row = df[(df["variant"]==variant) & (df["f"].round(2)==0.10)]
        if not row.empty:
            print(f"  {LABELS.get(variant,variant)}: "
                  f"theory={row['deanon_prob_theory'].values[0]:.2e}  "
                  f"MC={row['deanon_rate_monte_carlo'].values[0]:.2e}  "
                  f"(expected ansn=1e-6, tor=1e-3)")


# ─── Figure 5: Cover traffic overhead ────────────────────────────────────────

def plot_fig5(path="results_fig5.csv"):
    df = read_csv(path)
    if df is None:
        return

    fig, ax = plt.subplots(figsize=FIGSIZE)
    ax.plot(df["load_pct"], df["cover_overhead_pct"],
            color=COLORS["ansn"], marker="o", linewidth=2)
    ax.set_xlabel("Channel load (%)")
    ax.set_ylabel("Cover traffic overhead (% of total bytes)")
    ax.set_title("Figure 5: Cover Traffic Bandwidth Overhead")
    ax.set_ylim(0, 105)
    ax.grid(True, linestyle="--", alpha=0.4)
    for _, row in df.iterrows():
        ax.annotate(f"{row['cover_overhead_pct']:.0f}%",
                    (row["load_pct"], row["cover_overhead_pct"]),
                    textcoords="offset points", xytext=(0, 6),
                    ha="center", fontsize=8)
    fig.tight_layout()
    out = "fig5_cover_traffic.png"
    fig.savefig(out, dpi=DPI)
    print(f"[plot] saved {out}")
    plt.close(fig)

    print("\n=== Figure 5 summary ===")
    print(f"{'Load%':>6}  {'Cover overhead%':>16}")
    for _, row in df.iterrows():
        print(f"{row['load_pct']:>6.0f}  {row['cover_overhead_pct']:>16.1f}")


# ─── Table 2: Throughput ─────────────────────────────────────────────────────

def plot_table2(path="results_table2.csv"):
    df = read_csv(path)
    if df is None:
        return

    print("\n=== Table 2: Throughput Comparison Summary (Tor-equivalent) ===")
    print(f"{'Sessions':>10}  {'Duration(s)':>12}  "
          f"{'Total payload (B)':>18}  {'Throughput (B/s)':>18}  {'Throughput (MB/s)':>18}")
    for _, row in df.iterrows():
        tp = row["throughput_bytes_s"]
        print(f"{int(row['sessions']):>10}  {int(row['duration_s']):>12}  "
              f"{int(row['total_payload_bytes']):>18,}  "
              f"{tp:>18,.0f}  "
              f"{tp/1e6:>18.3f}")

    fig, ax = plt.subplots(figsize=FIGSIZE)
    ax.plot(df["sessions"], df["throughput_bytes_s"] / 1e6,
            color=COLORS["tor"], marker="o", linewidth=2)
    ax.set_xscale("log")
    ax.set_xlabel("Concurrent sessions (log scale)")
    ax.set_ylabel("Aggregate throughput (MB/s)")
    ax.set_title("Table 2: End-to-end Throughput (Tor-equivalent)")
    ax.grid(True, which="both", linestyle="--", alpha=0.4)
    fig.tight_layout()
    out = "table2_throughput.png"
    fig.savefig(out, dpi=DPI)
    print(f"[plot] saved {out}")
    plt.close(fig)

    df.to_csv("table2_summary.csv", index=False)
    print("[plot] saved table2_summary.csv")


# ─── main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    plot_fig2()
    plot_fig3()
    plot_fig4()
    plot_fig5()
    plot_table2()
