#!/usr/bin/env python3
"""
sweep_table2.py  --  Anon-Sec-Net v2  Table 2: Throughput

Measures aggregate throughput by launching N clients, letting each one
send real GET packets through the full Sphinx path (MN1->MN2->MN3->SG)
and reading sg_goodput.csv.

Each client runs at SET_RATE 1.0 (all-real mode) so every Poisson slot
sends a real GET packet. Cover packets are dropped at MN1 by design and
never reach the SG. This measures genuine end-to-end packet throughput.
For the manuscript this is reported as "SG packet processing throughput".

HOW TO RUN
----------
1. stop_nodes.bat  then  start_nodes.bat   (fresh session slots)
2. python seed_cache.py
3. del sg_goodput.csv session_setup.csv
4. python sweep_table2.py --counts 1,5,10,50,100 --duration 30
"""

import argparse
import csv
import math
import os
import subprocess
import sys
import time


def read_goodput_csv(path):
    values = []
    if not os.path.exists(path):
        return values
    with open(path) as fp:
        for line in fp:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) == 4 and parts[0] == "ts_ms" and parts[2] == "bps":
                try:
                    values.append(float(parts[3]))
                except ValueError:
                    continue
    return values


def count_session_csv(path):
    n = 0
    if not os.path.exists(path):
        return 0
    with open(path) as fp:
        for line in fp:
            line = line.strip()
            if not line or line.startswith("#") or line == "ms":
                continue
            try:
                float(line)
                n += 1
            except ValueError:
                continue
    return n


def ci95(values):
    if not values:
        return 0.0, 0.0
    n = len(values)
    m = sum(values) / n
    if n == 1:
        return m, 0.0
    var = sum((x - m) ** 2 for x in values) / (n - 1)
    std = math.sqrt(var)
    return m, (2.0 if n < 30 else 1.96) * std / math.sqrt(n)


def clear_csv(path, header):
    with open(path, "w") as fp:
        fp.write(header)


def stop_proc(proc):
    try:
        proc.stdin.write(b"quit\n")
        proc.stdin.flush()
    except OSError:
        pass
    try:
        proc.stdin.close()   # prevent GC broken-pipe OSError
    except OSError:
        pass
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


def run_session_count(n_clients, client_exe, session_csv,
                      goodput_csv, duration_s):
    clear_csv(goodput_csv, "# SG goodput\nts_ms,bps\n")
    time.sleep(0.3)

    before_sessions = count_session_csv(session_csv)

    # Launch clients with a stagger so the mix-node ECDHE accept queue
    # never floods.  Each client does 8 handshakes (~80-160ms); 200ms
    # between spawns keeps concurrent handshakes to at most 1-2.
    SPAWN_STAGGER_S = 0.2
    procs = []
    for i in range(n_clients):
        try:
            p = subprocess.Popen(
                [client_exe],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            procs.append(p)
        except Exception as e:
            print(f"\n    ERROR launching client: {e}")
        if i < n_clients - 1:
            time.sleep(SPAWN_STAGGER_S)

    if not procs:
        return None

    # Wait for all clients to complete path setup
    print(f"\n    Waiting for {len(procs)} client(s) to set up paths...",
          end="", flush=True)
    deadline = time.perf_counter() + 60
    while time.perf_counter() < deadline:
        time.sleep(0.5)
        ready = count_session_csv(session_csv) - before_sessions
        if ready >= len(procs):
            break
    ready = count_session_csv(session_csv) - before_sessions
    print(f" {ready}/{len(procs)} ready -- measuring for {duration_s}s")

    # Send SET_RATE 1.0 to all clients so they send real packets (not cover).
    # Cover packets are dropped at MN1 by design and never reach the SG.
    # Real packets travel MN1->MN2->MN3->SG and are counted by sg_goodput.
    for p in procs:
        try:
            p.stdin.write(b"SET_RATE 1.0\n")
            p.stdin.flush()
        except OSError:
            pass

    time.sleep(duration_s)

    # Stop all clients
    for p in procs:
        stop_proc(p)
    time.sleep(1.0)

    # Read goodput -- skip first 3 and last 2 samples (startup/teardown)
    values = read_goodput_csv(goodput_csv)
    if len(values) > 6:
        values = values[3:-2]

    # Filter zeros -- cover packets that were dropped before SG
    nonzero = [v for v in values if v > 0]
    working = nonzero if nonzero else values

    if not working:
        return {"n_clients": n_clients, "mean_bps": 0,
                "ci95_bps": 0, "peak_bps": 0, "n": 0}

    m, hw = ci95(working)
    return {
        "n_clients": n_clients,
        "mean_bps":  m,
        "ci95_bps":  hw,
        "peak_bps":  max(working),
        "n":         len(working),
        "n_total":   len(values),
    }


def read_baseline(path):
    values = read_goodput_csv(path)
    if not values:
        return None
    nonzero = [v for v in values if v > 0]
    working = nonzero if nonzero else values
    if not working:
        return None
    m, hw = ci95(working)
    return {"mean_bps": m, "ci95_bps": hw, "peak_bps": max(working)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--counts",      default="1,5,10,50,100")
    parser.add_argument("--duration",    type=int, default=30)
    parser.add_argument("--client-exe",  default="client_instrumented.exe")
    parser.add_argument("--session-csv", default="session_setup.csv")
    parser.add_argument("--goodput-csv", default="sg_goodput.csv")
    parser.add_argument("--tor-csv",     default="tor_sg_goodput.csv")
    parser.add_argument("--nonanon-csv", default="nonanon_sg_goodput.csv")
    parser.add_argument("--out-dir",     default=".")
    args = parser.parse_args()

    counts = [int(x.strip()) for x in args.counts.split(",") if x.strip()]
    os.makedirs(args.out_dir, exist_ok=True)
    out_path = os.path.join(args.out_dir, "table2_results.csv")

    MAX_SAFE = 1024
    over = [c for c in counts if c > MAX_SAFE]
    if over:
        print(f"WARNING: counts {over} exceed safe limit ({MAX_SAFE}).")
        print(f"         Increase MAX_SESSIONS in mix_node_instrumented.c")
        print(f"         and rebuild, or remove these counts.")
        counts = [c for c in counts if c <= MAX_SAFE]

    if not counts:
        print("ERROR: No valid counts.")
        sys.exit(1)

    print("=" * 60)
    print("  Anon-Sec-Net v2  Table 2  Throughput sweep")
    print("=" * 60)
    print(f"  Session counts : {counts}")
    print(f"  Duration/level : {args.duration}s")
    print(f"  Method         : real GET packets (SET_RATE 1.0) through full Sphinx path")
    print(f"  Client exe     : {args.client_exe}")
    print()

    if not os.path.exists(args.client_exe):
        print(f"ERROR: {args.client_exe} not found.")
        sys.exit(1)

    rows_asn = []
    for i, n in enumerate(counts):
        print(f"  N={n:3d} clients...", end="", flush=True)
        res = run_session_count(n, args.client_exe, args.session_csv,
                                args.goodput_csv, args.duration)
        if res:
            rows_asn.append(res)
            print(f"    mean={res['mean_bps']/1000:.1f} kbps  "
                  f"±{res['ci95_bps']/1000:.1f} kbps  "
                  f"peak={res['peak_bps']/1000:.1f} kbps  "
                  f"n={res['n']}/{res['n_total']}")
        else:
            print("    no data")

        if i < len(counts) - 1:
            print(f"    Restart nodes now to clear session slots, then press Enter...")
            input()

    tor     = read_baseline(args.tor_csv)
    nonanon = read_baseline(args.nonanon_csv)

    print()
    print("  Table 2: Throughput")
    print("  " + "=" * 65)
    print(f"  {'N':>6}  {'ASN mean':>12}  {'±CI':>10}  "
          f"{'TOR':>12}  {'No-anon':>12}")
    print("  " + "-" * 65)
    for r in rows_asn:
        tor_s  = f"{tor['mean_bps']/1000:.1f} kbps"    if tor    else "n/a"
        nona_s = f"{nonanon['mean_bps']/1000:.1f} kbps" if nonanon else "n/a"
        print(f"  {r['n_clients']:>6}  "
              f"{r['mean_bps']/1000:>10.1f} kbps  "
              f"{r['ci95_bps']/1000:>8.1f} kbps  "
              f"{tor_s:>12}  {nona_s:>12}")
    print("  " + "=" * 65)

    fields = ["n_clients","protocol","mean_bps","ci95_bps",
              "peak_bps","mean_kbps","ci95_kbps","peak_kbps","n_samples"]
    with open(out_path, "w", newline="") as fp:
        fp.write("# Anon-Sec-Net v2 Table 2: throughput vs concurrent sessions\n")
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        for r in rows_asn:
            w.writerow({
                "n_clients":  r["n_clients"],
                "protocol":   "asn",
                "mean_bps":   f"{r['mean_bps']:.1f}",
                "ci95_bps":   f"{r['ci95_bps']:.1f}",
                "peak_bps":   f"{r['peak_bps']:.1f}",
                "mean_kbps":  f"{r['mean_bps']/1000:.3f}",
                "ci95_kbps":  f"{r['ci95_bps']/1000:.3f}",
                "peak_kbps":  f"{r['peak_bps']/1000:.3f}",
                "n_samples":  r["n"],
            })
        if tor:
            w.writerow({"n_clients":"all","protocol":"tor",
                        "mean_bps": f"{tor['mean_bps']:.1f}",
                        "ci95_bps": f"{tor['ci95_bps']:.1f}",
                        "peak_bps": f"{tor['peak_bps']:.1f}",
                        "mean_kbps":f"{tor['mean_bps']/1000:.3f}",
                        "ci95_kbps":f"{tor['ci95_bps']/1000:.3f}",
                        "peak_kbps":f"{tor['peak_bps']/1000:.3f}",
                        "n_samples":"n/a"})
        if nonanon:
            w.writerow({"n_clients":"all","protocol":"nonanon",
                        "mean_bps": f"{nonanon['mean_bps']:.1f}",
                        "ci95_bps": f"{nonanon['ci95_bps']:.1f}",
                        "peak_bps": f"{nonanon['peak_bps']:.1f}",
                        "mean_kbps":f"{nonanon['mean_bps']/1000:.3f}",
                        "ci95_kbps":f"{nonanon['ci95_bps']/1000:.3f}",
                        "peak_kbps":f"{nonanon['peak_bps']/1000:.3f}",
                        "n_samples":"n/a"})

    print()
    print(f"  Written -> {out_path}")
    print("  Done.")


if __name__ == "__main__":
    main()