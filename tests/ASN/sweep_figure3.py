#!/usr/bin/env python3
"""
sweep_figure3.py  --  Anon-Sec-Net v2  Figure 3: Path Construction Time

Runs the client_instrumented.exe repeatedly to collect 1000 session-setup
timing samples for ASN (dual path, 8 ECDHE handshakes) and reads the
pre-collected Tor-equivalent results from a separate CSV.

HOW IT WORKS
------------
client_instrumented.exe appends one line (milliseconds) to session_setup.csv
every time it successfully completes both path A and path B construction.

This script:
  1. Clears session_setup.csv
  2. Launches client_instrumented.exe N times in sequence
  3. Each launch: completes path setup, writes one timing, then exits
     (the script sends a 'quit' command via stdin after setup is done)
  4. Reads session_setup.csv and writes figure3_asn.csv
  5. Reads tor_session_setup.csv (your pre-collected Tor baseline) and writes
     figure3_tor.csv

PREREQUISITES
-------------
All mix nodes and SG must be running and idle before each client launch.
Because session state accumulates in the mix nodes, you may want to restart
the nodes between batches if MAX_SESSIONS (64) is reached. The script warns
you when that might be approaching.

The Tor-equivalent baseline CSV (tor_session_setup.csv) must be in the
same directory or specified via --tor-csv. Expected format: one float (ms)
per line, comments with #, optional header line "ms".

Usage:
    python sweep_figure3.py [--reps 1000] [--client-exe client_instrumented.exe]
                            [--out-dir .] [--tor-csv tor_session_setup.csv]
    python sweep_figure3.py --reps 20   # quick smoke test
"""

import argparse
import csv
import math
import os
import subprocess
import sys
import time
import socket


MAX_SESSIONS_PER_NODE = 1024  # from mix_node.c #define MAX_SESSIONS 1024
NODES_IN_USE          = 8    # 3 send + 3 recv + SG (counted twice) = 8 sessions

def stop_nodes():
    print("  [auto] stopping nodes...")
    subprocess.call(["stop_nodes.bat"], shell=True)
    time.sleep(3)   # allow sockets to close


def start_nodes():
    print("  [auto] starting nodes...")
    subprocess.call(["start_nodes.bat"], shell=True)

    # wait for key services
    for port in [9004, 9005, 9006, 9007, 9008, 9009]:
        wait_port(port)

    print("  [auto] nodes ready")


def wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect(("127.0.0.1", port))
                return True
            except:
                time.sleep(0.2)
    return False


def read_float_csv(path: str) -> list:
    """Read a single-column float CSV (comments with #, optional header)."""
    values = []
    if not os.path.exists(path):
        return values
    with open(path) as fp:
        for line in fp:
            line = line.strip()
            if not line or line.startswith("#") or line == "ms":
                continue
            try:
                values.append(float(line))
            except ValueError:
                continue
    return values


def ci95(values: list) -> tuple:
    if not values:
        return 0.0, 0.0
    n = len(values)
    m = sum(values) / n
    if n == 1:
        return m, 0.0
    var = sum((x - m) ** 2 for x in values) / (n - 1)
    std = math.sqrt(var)
    t   = 2.0 if n < 30 else 1.96
    return m, t * std / math.sqrt(n)


def write_summary(values: list, path: str, protocol: str) -> None:
    m, hw = ci95(values)
    sv    = sorted(values)
    n     = len(values)
    with open(path, "w", newline="") as fp:
        fp.write(f"# Anon-Sec-Net v2 Figure 3: path construction time ({protocol})\n")
        fp.write("# ms: milliseconds per complete session setup\n")
        w = csv.writer(fp)
        w.writerow(["protocol","n","mean_ms","ci95_ms","median_ms",
                    "p5_ms","p95_ms","min_ms","max_ms"])
        w.writerow([
            protocol, n,
            f"{m:.3f}", f"{hw:.3f}",
            f"{sv[n//2]:.3f}",
            f"{sv[max(0,int(n*0.05))]:.3f}",
            f"{sv[min(n-1,int(n*0.95))]:.3f}",
            f"{sv[0]:.3f}", f"{sv[-1]:.3f}",
        ])
        # Also write raw samples for the plotter
        w.writerow([])
        w.writerow(["# raw samples (ms)"])
        for v in values:
            w.writerow([f"{v:.3f}"])
    print(f"  Written -> {path}")


CLIENT_RESPONSE_PORT = 9020   # must match config.h CLIENT_RESPONSE_PORT


def kill_zombies() -> int:
    """Kill any leftover client_instrumented.exe processes on Windows.

    Returns the number of processes killed.
    """
    killed = 0
    if sys.platform != "win32":
        return killed
    try:
        out = subprocess.check_output(
            ["tasklist", "/FI", "IMAGENAME eq client_instrumented.exe",
             "/FO", "CSV", "/NH"],
            stderr=None
        ).decode(errors="replace")
        for row in out.splitlines():
            row = row.strip().strip('"')
            if not row or row.startswith("INFO"):
                continue
            parts = row.split('","|',)
            # tasklist CSV: "name","pid","session","#","mem"
            parts = [p.strip().strip('"') for p in row.split(",")]
            if len(parts) >= 2:
                try:
                    pid = int(parts[1])
                    subprocess.call(["taskkill", "/F", "/PID", str(pid)],
                                    stdout=subprocess.DEVNULL,
                                    stderr=None)
                    killed += 1
                except (ValueError, Exception):
                    pass
    except Exception:
        pass
    return killed


def wait_port_free(port: int, timeout: float = 10.0) -> bool:
    """Wait until nothing is listening on *port* (Windows/all platforms)."""
    import socket
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
                return True          # port is free
            except OSError:
                time.sleep(0.2)      # still held, retry
    return False                     # timed out


def run_client_once(client_exe: str, session_csv: str,
                    timeout: int = 15) -> bool:
    """Launch client_instrumented.exe, wait for path setup, then quit.

    Returns True if the client successfully wrote a new timing line.
    """
    # Kill any zombie clients from previous reps before starting.
    n = kill_zombies()
    if n:
        print(f"  [warn] killed {n} zombie client(s)", flush=True)

    # Wait for port 9020 to be free before binding a new client.
    if not wait_port_free(CLIENT_RESPONSE_PORT, timeout=8.0):
        print(f"  [warn] port {CLIENT_RESPONSE_PORT} still busy -- skipping rep",
              flush=True)
        return False

    before = len(read_float_csv(session_csv))

    try:
        proc = subprocess.Popen(
            [client_exe],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return False

    deadline = time.perf_counter() + timeout
    new_count = before

    while time.perf_counter() < deadline:
        time.sleep(0.1)
        new_count = len(read_float_csv(session_csv))
        if new_count >= before + 1:
            break

    # Stop client cleanly
    try:
        proc.communicate(input=b"quit\n", timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.communicate(timeout=2)
        except Exception:
            pass

    final_count = len(read_float_csv(session_csv))

    # ✅ STRICT CHECK
    if final_count == before + 1:
        return True
    else:
        print(f"  [warn] unexpected sample count: before={before}, after={final_count}")
        return False



def main():
    parser = argparse.ArgumentParser(
        description="Sweep Figure 3: path construction time."
    )
    parser.add_argument("--reps",       type=int,   default=1000,
                        help="Number of client runs (spec: 1000)")
    parser.add_argument("--client-exe", default="client_instrumented.exe",
                        help="Path to client_instrumented.exe")
    parser.add_argument("--session-csv",default="session_setup.csv",
                        help="Path to session_setup.csv written by the client")
    parser.add_argument("--tor-csv",    default="tor_session_setup.csv",
                        help="Path to pre-collected Tor-equivalent session CSV")
    parser.add_argument("--out-dir",    default=".",
                        help="Directory for output files")
    parser.add_argument("--no-clear",   action="store_true",
                        help="Do not clear session_setup.csv before the run")
    parser.add_argument("--timeout",    type=int, default=15,
                        help="Per-rep timeout in seconds (default 15)")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    print("=" * 60)
    print("  Anon-Sec-Net v2  Figure 3  Path construction time sweep")
    print("=" * 60)
    print(f"  Reps          : {args.reps}")
    print(f"  Client exe    : {args.client_exe}")
    print(f"  session CSV   : {args.session_csv}")
    print(f"  Tor CSV       : {args.tor_csv}")
    print(f"  Timeout/rep   : {args.timeout}s")
    print()

    # Warn about session store limits
    total_sessions = args.reps * NODES_IN_USE
    if total_sessions > MAX_SESSIONS_PER_NODE:
        slots_before_full = MAX_SESSIONS_PER_NODE // NODES_IN_USE
        print(f"  NOTE: mix nodes have MAX_SESSIONS={MAX_SESSIONS_PER_NODE}.")
        print(f"        Each client run uses ~{NODES_IN_USE} session slots.")
        print(f"        Nodes will fill up after ~{slots_before_full} runs.")
        print(f"        Restart mix nodes every {slots_before_full} reps, or")
        print(f"        increase MAX_SESSIONS in mix_node.c before building.")
        print()

    if not os.path.exists(args.client_exe):
        print(f"ERROR: {args.client_exe} not found.")
        print("       Build client_instrumented.exe and ensure it is in PATH.")
        sys.exit(1)

    # Clear session CSV
    if not args.no_clear:
        with open(args.session_csv, "w") as fp:
            fp.write("# session setup time (first connect -> both paths ready)\nms\n")
        print(f"  Cleared {args.session_csv}")

    slots_before_full = MAX_SESSIONS_PER_NODE // NODES_IN_USE

    # Run client N times
    successes = 0
    errors    = 0
    t_start   = time.perf_counter()

    for i in range(args.reps):
        if i > 0 and i % slots_before_full == 0:
                print()
                print(f"  [auto] restart at iteration {i}")
                print("  *** Auto-restarting nodes ***")

                stop_nodes()
                start_nodes()

                print("  [auto] nodes restarted, continuing...\n")
        ok = run_client_once(args.client_exe, args.session_csv,
                             timeout=args.timeout)
        if ok:
            successes += 1
        else:
            errors += 1

        elapsed = time.perf_counter() - t_start
        eta     = (elapsed / (i + 1)) * (args.reps - i - 1)

        if (i + 1) % 10 == 0 or i == 0:
            print(f"  [{i+1:4d}/{args.reps}]  ok={successes}  err={errors}  "
                  f"elapsed={elapsed:.0f}s  ETA={eta:.0f}s", flush=True)

        # (inter-rep pause is inside run_client_once)

    elapsed = time.perf_counter() - t_start
    print()
    print(f"  Completed: {successes} ok, {errors} errors, {elapsed:.1f}s total")

    # Read and summarise ASN results
    asn_values = read_float_csv(args.session_csv)

    # 🔒 HARD CAP to expected reps
    if len(asn_values) > args.reps:
        print(f"  [warn] trimming extra samples: {len(asn_values)} -> {args.reps}")
        asn_values = asn_values[:args.reps]
    if not asn_values:
        print("ERROR: no timing values collected. Check that mix nodes are running.")
        sys.exit(1)

    asn_m, asn_hw = ci95(asn_values)
    print()
    print(f"  ASN  n={len(asn_values)}  mean={asn_m:.2f}ms  ±{asn_hw:.2f}ms")

    asn_out = os.path.join(args.out_dir, "figure3_asn.csv")
    write_summary(asn_values, asn_out, "asn")

    # Read Tor baseline
    tor_values = read_float_csv(args.tor_csv)
    if tor_values:
        tor_m, tor_hw = ci95(tor_values)
        print(f"  TOR  n={len(tor_values)}  mean={tor_m:.2f}ms  ±{tor_hw:.2f}ms")
        if asn_m > 0:
            print(f"  Ratio ASN/TOR = {asn_m/tor_m:.2f}x  (spec expects ~2x)")
        tor_out = os.path.join(args.out_dir, "figure3_tor.csv")
        write_summary(tor_values, tor_out, "tor")
    else:
        print(f"  [SKIP] Tor CSV not found at {args.tor_csv}")
        print(f"         Copy your Tor baseline session_setup.csv there.")

    print()
    print("  Done.")


if __name__ == "__main__":
    main()