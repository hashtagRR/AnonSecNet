#!/usr/bin/env python3
"""
sweep_figure_bandwidth.py: per-hop bandwidth cost

Measures the per-hop downstream bandwidth cost of cover
traffic traveling every hop of both paths (forward MN1->MN2->MN3->SG,
return SG->MNc->MNb->MNa->Client). Figure 5/7's cover_overhead_figure5.csv
only counts the CLIENT's own outbound link (measure_link_bytes(), P3),
which doesn't capture what mix nodes forward downstream.
This script uses the P5 probe (measure_hop_bytes(),
common/measure.h) instead, which counts each hop's TOTAL inbound bandwidth
without a real/cover split, deliberately, since a mix node cannot make
that split.

HOW TO RUN
----------
1. cd to the ASN/ build directory (where the .exe binaries live)
2. python3 ../tests/ASN/sweep_figure_bandwidth.py [--duration 60]
   (starts/stops the 12-node cluster itself via start_nodes.sh/stop_nodes.sh)

Pass --client-exe client_instrumented_hardened.exe (and the cluster is
started via start_nodes_hardened.sh/stop_nodes_hardened.sh automatically
based on the exe name) for an ASN_LOOPIX_MIXING run.
"""

import argparse
import csv
import math
import os
import queue
import subprocess
import sys
import threading
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

LOAD_LEVELS = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
WARMUP_S    = 3

# Order MUST match start_nodes.sh's MIX_PORTS, then SG, then cache_server,
# that script writes nodes.pid in exactly this order, one PID per line.
MIX_PORTS = [9004, 9005, 9006, 9007, 9008, 9009,
             9040, 9041, 9042, 9043, 9044, 9045]

# Client-path hops of interest and the LINK each one's P5 counter
# represents (that node's own inbound side, see measure.h's comment).
# MN1's own P5 (Client->MN1) is included as a cross-check against the
# client's existing P3 outbound counter, not because it's new information.
HOP_LINKS = {
    9004: "Client -> MN1",
    9005: "MN1 -> MN2",
    9006: "MN2 -> MN3",
    9007: "MNb -> MNa",   # MNa, client-facing return exit
    9008: "MNc -> MNb",   # MNb
    9009: "SG -> MNc",    # MNc, SG-facing return entry
}
SG_LINK = "MN3 -> SG"


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


def read_bps_csv(path):
    """Same format as sg_goodput.csv / link_bytes.csv's sibling: rows of
    'ts_ms,<epoch>,bps,<n>'."""
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path) as fp:
        for line in fp:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) == 4 and parts[0] == "ts_ms" and parts[2] == "bps":
                try:
                    rows.append(float(parts[3]))
                except ValueError:
                    continue
    return rows


def read_nodes_pid(build_dir, pidfile_name):
    path = os.path.join(build_dir, pidfile_name)
    with open(path) as fp:
        pids = [int(line.strip()) for line in fp if line.strip()]
    if len(pids) < len(MIX_PORTS) + 1:
        print(f"ERROR: {pidfile_name} has {len(pids)} entries, expected "
              f"{len(MIX_PORTS) + 1}+ (12 mix nodes + SG [+ cache])",
              file=sys.stderr)
        sys.exit(1)
    port_to_pid = dict(zip(MIX_PORTS, pids[:len(MIX_PORTS)]))
    sg_pid = pids[len(MIX_PORTS)]
    return port_to_pid, sg_pid


class StdoutPump:
    def __init__(self, proc):
        self.proc = proc
        self.q = queue.Queue()
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    def _run(self):
        for line in self.proc.stdout:
            self.q.put(line)

    def echo_until(self, deadline, marker=None):
        seen = False
        while time.monotonic() < deadline:
            timeout = max(0.0, deadline - time.monotonic())
            try:
                line = self.q.get(timeout=min(0.1, timeout))
            except queue.Empty:
                continue
            sys.stdout.write(f"  [client] {line}")
            if marker and marker in line:
                seen = True
                break
        return seen

    def drain_for(self, seconds):
        self.echo_until(time.monotonic() + seconds)

    def flush_pending(self):
        end = time.monotonic() + 0.2
        while time.monotonic() < end:
            try:
                line = self.q.get(timeout=0.05)
            except queue.Empty:
                continue
            sys.stdout.write(f"  [client] {line}")


def start_client(client_exe, build_dir):
    exe = os.path.join(build_dir, client_exe)
    if not os.path.exists(exe):
        print(f"ERROR: {exe} not found", file=sys.stderr)
        sys.exit(1)
    proc = subprocess.Popen(
        [exe], cwd=build_dir,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, bufsize=1, universal_newlines=True,
    )
    return proc


def set_rate(proc, frac):
    proc.stdin.write(f"SET_RATE {frac:.3f}\n")
    proc.stdin.flush()


def run_level(proc, pump, build_dir, port_to_pid, sg_pid, load, duration_s,
              before_counts):
    set_rate(proc, load)
    pump.drain_for(duration_s)
    time.sleep(0.3)  # let the 200ms sampler flush the last window

    level = {"load": load}
    for port, pid in port_to_pid.items():
        if port not in HOP_LINKS:
            continue
        path = os.path.join(build_dir, f"hop_link_bytes_{pid}.csv")
        rows = read_bps_csv(path)
        new_rows = rows[before_counts.get(port, 0):]
        before_counts[port] = len(rows)
        m, hw = ci95(new_rows) if new_rows else (0.0, 0.0)
        level[port] = {"mean_bps": m, "ci95_bps": hw, "n": len(new_rows)}

    sg_path = os.path.join(build_dir, f"hop_link_bytes_{sg_pid}.csv")
    sg_rows = read_bps_csv(sg_path)
    sg_new = sg_rows[before_counts.get("sg", 0):]
    before_counts["sg"] = len(sg_rows)
    m, hw = ci95(sg_new) if sg_new else (0.0, 0.0)
    level["sg"] = {"mean_bps": m, "ci95_bps": hw, "n": len(sg_new)}

    return level


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--duration", type=int, default=60,
                     help="seconds per load level (spec:60, quick:10)")
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--client-exe", default="client_instrumented.exe")
    ap.add_argument("--build-dir", default=".",
                     help="directory containing the .exe binaries and "
                          "start_nodes*.sh/stop_nodes*.sh")
    args = ap.parse_args()

    build_dir = os.path.abspath(args.build_dir)
    os.makedirs(args.out_dir, exist_ok=True)
    out_path = os.path.join(args.out_dir, "figure_bandwidth_per_hop.csv")

    hardened = "hardened" in args.client_exe
    start_script = "start_nodes_hardened.sh" if hardened else "start_nodes.sh"
    stop_script = "stop_nodes_hardened.sh" if hardened else "stop_nodes.sh"
    pidfile_name = "nodes_hardened.pid" if hardened else "nodes.pid"
    # build_dir is code/ASN; code/tests/ASN is its SIBLING under code/, one
    # level up then into tests/ASN, not two levels (that would land
    # outside code/ entirely).
    tests_dir = os.path.abspath(os.path.join(build_dir, "..", "tests", "ASN"))

    print("=" * 70)
    print("  Anon-Sec-Net v2  Per-hop bandwidth sweep")
    print("=" * 70)
    print(f"  Load levels    : {[f'{l:.0%}' for l in LOAD_LEVELS]}")
    print(f"  Duration/level : {args.duration}s")
    print(f"  Client exe     : {args.client_exe}  (hardened={hardened})")
    print(f"  Output         : {out_path}")
    print()

    # Clean stale hop_link_bytes_*.csv / nodes.pid from a previous run so
    # before/after slicing (and PID reuse across runs) can't be ambiguous.
    for fn in os.listdir(build_dir):
        if fn.startswith("hop_link_bytes_") and fn.endswith(".csv"):
            try:
                os.remove(os.path.join(build_dir, fn))
            except OSError:
                pass

    print(f"  Starting cluster ({start_script}) ...")
    subprocess.check_call([os.path.join(tests_dir, start_script)], cwd=build_dir)
    subprocess.check_call([sys.executable,
                           os.path.join(build_dir, "scripts", "seed_cache.py")],
                          cwd=build_dir)

    port_to_pid, sg_pid = read_nodes_pid(build_dir, pidfile_name)
    print(f"  nodes.pid mapped: {port_to_pid}, sg_pid={sg_pid}")

    before_counts = {}
    results = []
    proc = None
    try:
        print(f"  Launching {args.client_exe} ...")
        proc = start_client(args.client_exe, build_dir)
        pump = StdoutPump(proc)

        ready = pump.echo_until(time.monotonic() + 60,
                                marker="Ready for SET_RATE")
        if not ready:
            print("ERROR: client did not become ready in 60s", file=sys.stderr)
            sys.exit(1)

        print(f"  Warmup ({WARMUP_S}s) at SET_RATE 0 ...")
        set_rate(proc, 0.0)
        pump.drain_for(WARMUP_S)
        # Prime before_counts post-warmup so warmup traffic isn't counted
        # against the first real load level.
        run_level(proc, pump, build_dir, port_to_pid, sg_pid, 0.0, 0.1,
                  before_counts)

        for load in LOAD_LEVELS:
            print(f"  Load {load:.0%}  {args.duration}s ...", end="", flush=True)
            level = run_level(proc, pump, build_dir, port_to_pid, sg_pid,
                              load, args.duration, before_counts)
            mn3_sg = level["sg"]["mean_bps"]
            mn1_mn2 = level.get(9005, {}).get("mean_bps", 0.0)
            print(f"  MN1->MN2={mn1_mn2:.0f}bps  MN3->SG={mn3_sg:.0f}bps")
            results.append(level)
            pump.flush_pending()

        set_rate(proc, 0.0)
        time.sleep(0.3)
        try:
            proc.stdin.write("quit\n")
            proc.stdin.flush()
            proc.wait(timeout=5)
        except Exception:
            proc.terminate()
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
        print(f"  Stopping cluster ({stop_script}) ...")
        subprocess.call([os.path.join(tests_dir, stop_script)], cwd=build_dir)

    if not results:
        print("\nERROR: no data collected.")
        sys.exit(1)

    all_ports = sorted(HOP_LINKS.keys())
    fields = ["load_pct"] + [f"{HOP_LINKS[p]}_bps" for p in all_ports] + \
             [f"{HOP_LINKS[p]}_ci95" for p in all_ports] + \
             [f"{SG_LINK}_bps", f"{SG_LINK}_ci95"]
    with open(out_path, "w", newline="") as fp:
        fp.write("# Anon-Sec-Net v2: per-hop total inbound bandwidth vs load\n"
                 "# real+cover undifferentiated by design (a mix node\n"
                 "# cannot distinguish them), see measure.h P5 / this\n"
                 "# script's own docstring.\n")
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        for r in results:
            row = {"load_pct": f"{r['load']*100:.0f}"}
            for p in all_ports:
                d = r.get(p, {"mean_bps": 0.0, "ci95_bps": 0.0})
                row[f"{HOP_LINKS[p]}_bps"] = f"{d['mean_bps']:.0f}"
                row[f"{HOP_LINKS[p]}_ci95"] = f"{d['ci95_bps']:.0f}"
            row[f"{SG_LINK}_bps"] = f"{r['sg']['mean_bps']:.0f}"
            row[f"{SG_LINK}_ci95"] = f"{r['sg']['ci95_bps']:.0f}"
            w.writerow(row)

    print(f"\n  Written -> {out_path}")
    print("  Done.")


if __name__ == "__main__":
    main()
