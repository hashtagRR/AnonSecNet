#!/usr/bin/env python3
"""
sweep_figure5.py  --  Anon-Sec-Net v2  Figure 5: Cover Traffic Bandwidth Overhead

HOW TO RUN
----------
1. start_nodes.bat  (all 8 infrastructure processes)
2. python seed_cache.py
3. python sweep_figure5.py [--duration 60]

The script launches client_instrumented.exe as a subprocess, drives the
load fraction via SET_RATE commands on the client's stdin, and reads BOTH
cover and real bytes from link_bytes.csv (written by the client).  This
implements Step 8.6 of the spec: probabilistic slot replacement, where
each Poisson slot is real with probability `load_fraction` and cover
otherwise.
"""

import argparse
import csv
import math
import os
import queue
import shutil
import subprocess
import sys
import threading
import time

LOAD_LEVELS  = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
WIRE_SIZE    = 1024
CLIENT_EXE   = "client_instrumented.exe"
LINK_CSV     = "link_bytes.csv"
WARMUP_S     = 3        # let cover thread fill ring queues before sampling


# ── CSV reader ────────────────────────────────────────────────────────────────
def read_link_csv(path):
    """Return list of (cover_bytes, real_bytes) per 200ms sampler window.

    The instrumented client samples every 200ms and writes scaled
    bytes/sec (each delta multiplied by 5).  Divide by 5 to recover raw
    bytes per window.
    """
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path) as fp:
        for line in fp:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            # Expected format: ts_ms,<epoch>,cover,<n>,real,<n>
            if len(parts) == 6 and parts[2] == "cover" and parts[4] == "real":
                try:
                    rows.append((float(parts[3]) / 5.0,
                                 float(parts[5]) / 5.0))
                except ValueError:
                    continue
    return rows


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


# ── Async stdout reader (works on Windows) ───────────────────────────────────
class StdoutPump:
    """Continuously drain a subprocess's stdout into a thread-safe queue
    so the child never blocks on a full pipe."""
    def __init__(self, proc):
        self.proc = proc
        self.q = queue.Queue()
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    def _run(self):
        for line in self.proc.stdout:
            self.q.put(line)

    def echo_until(self, deadline, marker=None):
        """Print lines until `deadline` (monotonic time) or until a line
        contains `marker`.  Returns True if marker was seen."""
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


# ── Subprocess driver ────────────────────────────────────────────────────────
def start_client():
    if not os.path.exists(CLIENT_EXE) and shutil.which(CLIENT_EXE) is None:
        print(f"ERROR: {CLIENT_EXE} not found in cwd or PATH",
              file=sys.stderr)
        sys.exit(1)

    proc = subprocess.Popen(
        [CLIENT_EXE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,                   # line-buffered
        universal_newlines=True,     # text mode
    )
    return proc


def set_rate(proc, frac):
    proc.stdin.write(f"SET_RATE {frac:.3f}\n")
    proc.stdin.flush()


# ── Per-level sweep ──────────────────────────────────────────────────────────
def run_level(proc, pump, link_csv, load, duration_s):
    set_rate(proc, load)
    before = len(read_link_csv(link_csv))

    pump.drain_for(duration_s)
    time.sleep(0.3)   # let the 200ms sampler flush the last window

    after = read_link_csv(link_csv)
    new_rows = after[before:]
    if not new_rows:
        return None

    cover_b = [c for c, _ in new_rows]
    real_b  = [r for _, r in new_rows]
    total_cover = sum(cover_b)
    total_real  = sum(real_b)
    total_bytes = total_cover + total_real

    cover_pct_overall = (100.0 * total_cover / total_bytes
                         if total_bytes > 0 else 100.0)

    pcts = []
    for c, r in zip(cover_b, real_b):
        s = c + r
        if s > 0:
            pcts.append(100.0 * c / s)

    _, hw = ci95(pcts)

    return {
        "load":      load,
        "cover_pct": cover_pct_overall,
        "ci95":      hw,
        "n":         len(new_rows),
        "cover_bps": total_cover * 8 / duration_s,
        "real_bps":  total_real  * 8 / duration_s,
    }


# ── main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=60,
                        help="seconds per load level (spec:60, quick:10)")
    parser.add_argument("--link-csv", default=LINK_CSV)
    parser.add_argument("--out-dir",  default=".")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    out_path = os.path.join(args.out_dir, "cover_overhead_figure5.csv")

    # Start with a clean link_bytes.csv so before/after slicing is unambiguous
    if os.path.exists(args.link_csv):
        try:
            os.remove(args.link_csv)
        except OSError:
            pass

    print("=" * 60)
    print("  Anon-Sec-Net v2  Figure 5  Cover traffic sweep")
    print("=" * 60)
    print(f"  Load levels    : {[f'{l:.0%}' for l in LOAD_LEVELS]}")
    print(f"  Duration/level : {args.duration}s")
    print(f"  link_bytes.csv : {args.link_csv}")
    print(f"  Output         : {out_path}")
    print()

    print("  Launching client_instrumented.exe ...")
    proc = start_client()
    pump = StdoutPump(proc)

    try:
        # Wait for the client to finish path-build + setup
        ready = pump.echo_until(time.monotonic() + 60,
                                marker="Ready for SET_RATE")
        if not ready:
            print("ERROR: client did not become ready in 60s",
                  file=sys.stderr)
            proc.terminate()
            sys.exit(1)

        print(f"  Warmup ({WARMUP_S}s) at SET_RATE 0 ...")
        set_rate(proc, 0.0)
        pump.drain_for(WARMUP_S)

        results = []
        for load in LOAD_LEVELS:
            print(f"  Load {load:.0%}  {args.duration}s ...",
                  end="", flush=True)
            res = run_level(proc, pump, args.link_csv, load, args.duration)
            if res:
                print(f"  cover={res['cover_pct']:.1f}% "
                      f"+/-{res['ci95']:.1f}%  n={res['n']}  "
                      f"cover_bps={res['cover_bps']:.0f}  "
                      f"real_bps={res['real_bps']:.0f}")
                results.append(res)
            else:
                print("  no data")
            pump.flush_pending()

        # Tell the client to exit cleanly
        set_rate(proc, 0.0)
        time.sleep(0.3)
        try:
            proc.stdin.write("quit\n")
            proc.stdin.flush()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.terminate()

    except Exception:
        proc.terminate()
        raise

    if not results:
        print("\nERROR: no data collected.")
        sys.exit(1)

    fields = ["load_pct", "cover_overhead_pct", "ci95_pct",
              "n_samples", "cover_bps", "real_bps"]
    with open(out_path, "w", newline="") as fp:
        fp.write("# Anon-Sec-Net v2 Figure 5: cover overhead vs load\n")
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        for r in results:
            w.writerow({
                "load_pct":           f"{r['load']*100:.0f}",
                "cover_overhead_pct": f"{r['cover_pct']:.2f}",
                "ci95_pct":           f"{r['ci95']:.2f}",
                "n_samples":          r["n"],
                "cover_bps":          f"{r['cover_bps']:.0f}",
                "real_bps":           f"{r['real_bps']:.0f}",
            })

    print(f"\n  Written -> {out_path}")
    print("  Done.")


if __name__ == "__main__":
    main()
