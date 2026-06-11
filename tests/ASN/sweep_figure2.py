#!/usr/bin/env python3
"""
sweep_figure2.py  --  Anon-Sec-Net v2  Figure 2: Per-hop Processing Latency

HOW TO RUN
----------
1. Build bench_figure2.exe (only needed once):

   gcc -Wall -Wextra -O2 -I. common/crypto.c common/net.c common/packet.c \
       bench_figure2.c -lssl -lcrypto -lws2_32 -lbcrypt -lm \
       -o bench_figure2.exe

2. Run the sweep (no nodes or client needed):

   python sweep_figure2.py [--reps 1000]

HOW IT WORKS
------------
bench_figure2.exe times all three variants in-process under identical
conditions (1000 invocations per payload size per variant):

  asn     : packet_sphinx_peel() on a valid 1024-byte wire packet.
            The wire packet is ALWAYS 1024 bytes regardless of logical
            payload size, so the per-hop cost is CONSTANT.  The flat line
            on the figure is the correct, expected result.

  tor     : crypto_aes_encrypt() + crypto_aes_decrypt() on payload_size
            bytes.  Models Tor's full AES-256-GCM re-encryption at each hop.
            Cost scales with payload size.

  nonanon : crypto_aes_encrypt() only on payload_size bytes.
            Minimum-crypto baseline with no anonymisation overhead.

This is the correct methodology for Section 13.1 of the spec:
  "instrument the per-hop processing function in each variant.
   Time the function across 1000 invocations per payload size."

All three variants are measured under identical in-process conditions with
no socket, thread, or scheduling overhead.
"""

import argparse
import csv
import math
import os
import subprocess
import sys


BENCH_EXE = "bench_figure2.exe"
BUILD_CMD = (
    "gcc -Wall -Wextra -O2 -I. "
    "common/crypto.c common/net.c common/packet.c "
    "bench_figure2.c "
    "-lssl -lcrypto -lws2_32 -lbcrypt -lm "
    "-o bench_figure2.exe"
)


# ── CSV reader / writer ───────────────────────────────────────────────────────

def read_bench_output(text):
    """Parse CSV lines from bench_figure2.exe stdout."""
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if parts[0] == "payload_bytes":   # header row
            continue
        if len(parts) != 9:
            continue
        try:
            rows.append({
                "payload_bytes": int(parts[0]),
                "protocol":      parts[1],
                "n":             int(parts[2]),
                "mean_us":       float(parts[3]),
                "ci95_us":       float(parts[4]),
                "min_us":        float(parts[5]),
                "max_us":        float(parts[6]),
                "p50_us":        float(parts[7]),
                "p95_us":        float(parts[8]),
            })
        except ValueError:
            continue
    return rows


def write_csv(rows, out_path):
    fields = ["payload_bytes", "protocol", "n",
              "mean_us", "ci95_us", "min_us", "max_us", "p50_us", "p95_us"]
    with open(out_path, "w", newline="") as fp:
        fp.write("# Anon-Sec-Net v2 Figure 2: per-hop crypto latency\n")
        fp.write("# Source: bench_figure2.exe (in-process, all variants)\n")
        fp.write("# ASN: constant cost (fixed 1024-byte wire packet, "
                 "max payload 499B)\n")
        fp.write("# Tor: AES-256-GCM encrypt+decrypt, scales with payload\n")
        fp.write("# nonanon: AES-256-GCM encrypt only\n")
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow({k: (f"{row[k]:.4f}" if isinstance(row[k], float)
                            else row[k])
                        for k in fields})


# ── Summary printer ───────────────────────────────────────────────────────────

def print_summary(rows):
    by_proto = {}
    for r in rows:
        by_proto.setdefault(r["protocol"], []).append(r)

    for proto, prows in sorted(by_proto.items()):
        print(f"\n  Protocol: {proto}")
        print(f"  {'payload_B':>10}  {'mean_us':>10}  {'±CI95':>8}  "
              f"{'p50':>8}  {'p95':>8}")
        print("  " + "-" * 54)
        for r in sorted(prows, key=lambda x: x["payload_bytes"]):
            print(f"  {r['payload_bytes']:>10}  "
                  f"{r['mean_us']:>10.3f}  "
                  f"{r['ci95_us']:>8.3f}  "
                  f"{r['p50_us']:>8.3f}  "
                  f"{r['p95_us']:>8.3f}")

    # Key comparison: ASN vs Tor at each size
    asn_by_size = {r["payload_bytes"]: r for r in by_proto.get("asn", [])}
    tor_by_size = {r["payload_bytes"]: r for r in by_proto.get("tor", [])}
    if asn_by_size and tor_by_size:
        print(f"\n  ASN vs Tor ratio (tor_mean / asn_mean):")
        print(f"  {'payload_B':>10}  {'ratio':>8}  {'winner':>8}")
        print("  " + "-" * 32)
        for ps in sorted(asn_by_size):
            if ps in tor_by_size:
                a = asn_by_size[ps]["mean_us"]
                t = tor_by_size[ps]["mean_us"]
                ratio = t / a if a > 0 else 0
                winner = "ASN" if a < t else "Tor"
                print(f"  {ps:>10}  {ratio:>8.2f}x  {winner:>8}")


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reps",    type=int, default=1000,
                        help="Invocations per payload size (spec: 1000)")
    parser.add_argument("--bench",   default=BENCH_EXE,
                        help="Path to bench_figure2.exe")
    parser.add_argument("--out-dir", default=".")
    parser.add_argument("--build",   action="store_true",
                        help="Build bench_figure2.exe before running")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    out_path = os.path.join(args.out_dir, "hop_timing_figure2.csv")

    print("=" * 60)
    print("  Anon-Sec-Net v2  Figure 2  Per-hop crypto latency")
    print("=" * 60)
    print(f"  Benchmark exe  : {args.bench}")
    print(f"  Reps per size  : {args.reps}")
    print(f"  Output         : {out_path}")
    print()

    # Optional build step
    if args.build:
        print(f"  Building {BENCH_EXE} ...")
        ret = os.system(BUILD_CMD)
        if ret != 0:
            print(f"ERROR: build failed (exit {ret})")
            print(f"  Command was: {BUILD_CMD}")
            sys.exit(1)
        print(f"  Build OK")
        print()

    # Check exe exists
    if not os.path.exists(args.bench):
        print(f"ERROR: {args.bench} not found.")
        print()
        print("  Build it first:")
        print(f"    {BUILD_CMD}")
        print()
        print("  Or run with --build to build automatically.")
        sys.exit(1)

    # Run benchmark
    print(f"  Running {args.bench} {args.reps} ...")
    print(f"  (3 variants × 11 payload sizes × {args.reps} reps"
          f"  ≈  {3 * 11 * args.reps / 1e6:.1f}M crypto operations)")
    print()

    try:
        result = subprocess.run(
            [args.bench, str(args.reps)],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        print("ERROR: benchmark timed out after 300s")
        sys.exit(1)
    except OSError as e:
        print(f"ERROR: could not run {args.bench}: {e}")
        sys.exit(1)

    if result.returncode != 0:
        print(f"ERROR: bench_figure2.exe exited with code {result.returncode}")
        if result.stderr:
            print(result.stderr)
        sys.exit(1)

    # Echo stderr (progress output from bench)
    if result.stderr.strip():
        for line in result.stderr.strip().splitlines():
            print(f"  {line}")
    print()

    # Parse output
    rows = read_bench_output(result.stdout)
    if not rows:
        print("ERROR: no data rows in bench output.")
        print("stdout was:")
        print(result.stdout[:500])
        sys.exit(1)

    print(f"  Collected {len(rows)} rows "
          f"({len(set(r['protocol'] for r in rows))} protocols × "
          f"{len(set(r['payload_bytes'] for r in rows))} payload sizes)")

    print_summary(rows)

    write_csv(rows, out_path)
    print(f"\n  Written -> {out_path}")
    print("  Done.")


if __name__ == "__main__":
    main()
