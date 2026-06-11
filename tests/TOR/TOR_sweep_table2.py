#!/usr/bin/env python3
"""
TOR_sweep_table2.py  --  Tor-Equivalent  Table 2: Throughput

Measures aggregate throughput by launching N tor_client instances,
letting each one build a 3-hop circuit (TN1->TN2->TN3) and send
real data cells through to the TOR SG, reading tor_sg_goodput.csv.

Between session counts the script automatically sends TOR_MODE_RESET
(0x1F) to each mix node to wipe session slots -- no manual restart needed.

HOW TO RUN
----------
1. start_tor_nodes.bat   (or run_tor_sweep.bat which does everything)
2. del tor_sg_goodput.csv tor_session_setup.csv
3. python TOR_sweep_table2.py --counts 1,5,10,50,100 --duration 30
"""

import argparse
import csv
import math
import os
import socket
import subprocess
import sys
import time

# TOR node ports (must match tor_config.h)
TOR_NODE_PORTS = [9040, 9041, 9042]
TOR_MODE_RESET = 0x1F


def reset_tor_nodes():
    """Send TOR_MODE_RESET (0x1F) to each mix node to wipe session stores."""
    for port in TOR_NODE_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect(("127.0.0.1", port))
            s.sendall(bytes([TOR_MODE_RESET]))
            s.close()
        except Exception:
            pass
    time.sleep(0.5)


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
        proc.stdin.close()
    except OSError:
        pass
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


def run_session_count(n_clients, client_exe, session_csv,
                      goodput_csv, duration_s):
    clear_csv(goodput_csv, "# TOR SG goodput\nts_ms,bps\n")
    time.sleep(0.3)

    before_sessions = count_session_csv(session_csv)

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

    print(f"\n    Waiting for {len(procs)} client(s) to build circuits...",
          end="", flush=True)
    deadline = time.perf_counter() + 60
    while time.perf_counter() < deadline:
        time.sleep(0.5)
        ready = count_session_csv(session_csv) - before_sessions
        if ready >= len(procs):
            break
    ready = count_session_csv(session_csv) - before_sessions
    print(f" {ready}/{len(procs)} ready -- measuring for {duration_s}s")

    for p in procs:
        try:
            p.stdin.write(b"SET_RATE 1.0\n")
            p.stdin.flush()
        except OSError:
            pass

    time.sleep(duration_s)

    for p in procs:
        stop_proc(p)
    time.sleep(1.0)

    values = read_goodput_csv(goodput_csv)
    if len(values) > 6:
        values = values[3:-2]

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
    parser.add_argument("--counts",      default="1,5,10,50,100,200")
    parser.add_argument("--duration",    type=int, default=30)
    parser.add_argument("--client-exe",  default="tor_client_instrumented.exe")
    parser.add_argument("--session-csv", default="tor_session_setup.csv")
    parser.add_argument("--goodput-csv", default="tor_sg_goodput.csv")
    parser.add_argument("--asn-csv",     default="sg_goodput.csv")
    parser.add_argument("--nonanon-csv", default="nonanon_sg_goodput.csv")
    parser.add_argument("--out-dir",     default=".")
    args = parser.parse_args()

    counts = [int(x.strip()) for x in args.counts.split(",") if x.strip()]
    os.makedirs(args.out_dir, exist_ok=True)
    out_path = os.path.join(args.out_dir, "tor_table2_results.csv")

    MAX_SAFE = 1024
    over = [c for c in counts if c > MAX_SAFE]
    if over:
        print(f"WARNING: counts {over} exceed safe limit ({MAX_SAFE}).")
        print(f"         Increase TOR_MAX_SESSIONS in tor_mix_node.c")
        print(f"         and rebuild, or remove these counts.")
        counts = [c for c in counts if c <= MAX_SAFE]

    if not counts:
        print("ERROR: No valid counts.")
        sys.exit(1)

    print("=" * 60)
    print("  Tor-Equivalent  Table 2  Throughput sweep")
    print("=" * 60)
    print(f"  Session counts : {counts}")
    print(f"  Duration/level : {args.duration}s")
    print(f"  Method         : real data cells through 3-hop GCM circuit")
    print(f"  Client exe     : {args.client_exe}")
    print()

    if not os.path.exists(args.client_exe):
        print(f"ERROR: {args.client_exe} not found.")
        sys.exit(1)

    rows_tor = []
    for i, n in enumerate(counts):
        print(f"  N={n:3d} clients...", end="", flush=True)
        res = run_session_count(n, args.client_exe, args.session_csv,
                                args.goodput_csv, args.duration)
        if res:
            rows_tor.append(res)
            print(f"    mean={res['mean_bps']/1000:.1f} kbps  "
                  f"+-{res['ci95_bps']/1000:.1f} kbps  "
                  f"peak={res['peak_bps']/1000:.1f} kbps  "
                  f"n={res['n']}/{res['n_total']}")
        else:
            print("    no data")

        # Auto-reset nodes between counts instead of manual restart
        if i < len(counts) - 1:
            print("    Resetting TOR node sessions...", end="", flush=True)
            reset_tor_nodes()
            print(" done.")

    asn     = read_baseline(args.asn_csv)
    nonanon = read_baseline(args.nonanon_csv)

    print()
    print("  Table 2: Throughput (Tor-equivalent)")
    print("  " + "=" * 65)
    print(f"  {'N':>6}  {'TOR mean':>12}  {'+-CI':>10}  "
          f"{'ASN':>12}  {'No-anon':>12}")
    print("  " + "-" * 65)
    for r in rows_tor:
        asn_s  = f"{asn['mean_bps']/1000:.1f} kbps"    if asn    else "n/a"
        nona_s = f"{nonanon['mean_bps']/1000:.1f} kbps" if nonanon else "n/a"
        print(f"  {r['n_clients']:>6}  "
              f"{r['mean_bps']/1000:>10.1f} kbps  "
              f"{r['ci95_bps']/1000:>8.1f} kbps  "
              f"{asn_s:>12}  {nona_s:>12}")
    print("  " + "=" * 65)

    fields = ["n_clients","protocol","mean_bps","ci95_bps",
              "peak_bps","mean_kbps","ci95_kbps","peak_kbps","n_samples"]
    with open(out_path, "w", newline="") as fp:
        fp.write("# Tor-Equivalent Table 2: throughput vs concurrent sessions\n")
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        for r in rows_tor:
            w.writerow({
                "n_clients":  r["n_clients"],
                "protocol":   "tor",
                "mean_bps":   f"{r['mean_bps']:.1f}",
                "ci95_bps":   f"{r['ci95_bps']:.1f}",
                "peak_bps":   f"{r['peak_bps']:.1f}",
                "mean_kbps":  f"{r['mean_bps']/1000:.3f}",
                "ci95_kbps":  f"{r['ci95_bps']/1000:.3f}",
                "peak_kbps":  f"{r['peak_bps']/1000:.3f}",
                "n_samples":  r["n"],
            })
        if asn:
            w.writerow({"n_clients":"all","protocol":"asn",
                        "mean_bps": f"{asn['mean_bps']:.1f}",
                        "ci95_bps": f"{asn['ci95_bps']:.1f}",
                        "peak_bps": f"{asn['peak_bps']:.1f}",
                        "mean_kbps":f"{asn['mean_bps']/1000:.3f}",
                        "ci95_kbps":f"{asn['ci95_bps']/1000:.3f}",
                        "peak_kbps":f"{asn['peak_bps']/1000:.3f}",
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
