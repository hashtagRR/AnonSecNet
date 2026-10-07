#!/usr/bin/env python3
"""sweep_figure3_prod.py, Figure 3 (path construction time) re-measured
against PRODUCTION client.exe/mix_node.exe/service_gateway.exe, the
original sweep_figure3.py in this same directory drives
client_instrumented.exe, a frozen protocol snapshot that predates
RTT-based channel assignment entirely. This
script reuses that original's statistics/output format (mean/median/p5/
p95/ci95, CSV with raw samples) but launches client.exe directly and
extracts timing from the client's own "both paths ready" log line via
stdout, timestamped externally (no production code touched), same
black-box approach as sweep_table2_prod.py.

Does NOT measure content retrieval at all (no PUT/GET, no Sender
needed), purely path A + path B construction, matching the original
figure's own scope exactly.

HOW TO RUN
----------
cd to the ASN/ build directory (where the .exe binaries live), then:
    python3 ../tests/ASN/sweep_figure3_prod.py [--reps 1000] [out.csv]

Uses start_nodes_pool.sh/stop_nodes_pool.sh (this directory) to manage
the production node cluster, restarting periodically to avoid
service_gateway.c's session table filling up (MAX_SESSIONS=1024, 2
slots consumed per client run, fills around rep ~500-512 at this
sweep's pace, well inside SESSION_TTL_MS's 5-minute reclaim window; the
*original* instrumented-harness scripts document the identical
constraint and restart nodes between batches for the same reason).
"""
import argparse
import csv
import math
import os
import subprocess
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BUILD_DIR = os.path.join(SCRIPT_DIR, "..", "..", "ASN")
CLIENT_EXE = os.path.join(BUILD_DIR, "client.exe")
RESTART_EVERY = 400  # safely under SG's ~512-rep session-table-full point


def restart_network():
    subprocess.call([os.path.join(SCRIPT_DIR, "stop_nodes_pool.sh")])
    time.sleep(1)
    # Node identities regenerate on restart, stale TOFU pins from the
    # previous incarnation cause "PIN MISMATCH" rejections otherwise.
    subprocess.call(["rm", "-rf",
                      os.path.join(BUILD_DIR, "sender_pins"),
                      os.path.join(BUILD_DIR, "client_pins")])
    subprocess.call([os.path.join(SCRIPT_DIR, "start_nodes_pool.sh")])
    time.sleep(1)


def run_one():
    try:
        proc = subprocess.Popen(
            [CLIENT_EXE], cwd=BUILD_DIR,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
    except Exception:
        return None

    t0 = time.perf_counter()
    deadline = t0 + 15.0
    t_ready = None
    try:
        while time.perf_counter() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            if "both paths ready" in line:
                t_ready = time.perf_counter() - t0
                break
    except Exception:
        pass

    try:
        proc.stdin.write("quit\n")
        proc.stdin.flush()
    except (BrokenPipeError, OSError):
        pass
    try:
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

    return t_ready


def ci95(values):
    n = len(values)
    if n == 0:
        return 0.0, 0.0
    m = sum(values) / n
    if n == 1:
        return m, 0.0
    var = sum((x - m) ** 2 for x in values) / (n - 1)
    std = math.sqrt(var)
    t = 2.0 if n < 30 else 1.96
    return m, t * std / math.sqrt(n)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out_csv", nargs="?", default="figure3_asn_prod.csv")
    ap.add_argument("--reps", type=int, default=1000)
    args = ap.parse_args()

    restart_network()

    values_ms = []
    n_fail = 0
    t_sweep_start = time.perf_counter()

    for i in range(args.reps):
        if i > 0 and i % RESTART_EVERY == 0:
            print(f"  [restart] rep {i}: restarting network "
                  f"(session-table exhaustion avoidance)", flush=True)
            restart_network()

        t = run_one()
        if t is None:
            n_fail += 1
            print(f"  [warn] rep {i}: failed/timeout ({n_fail} total failures)", flush=True)
            continue
        ms = t * 1000.0
        values_ms.append(ms)
        if (i + 1) % 100 == 0 or i < 5:
            print(f"  rep {i+1}/{args.reps}: {ms:.3f}ms  "
                  f"(elapsed {time.perf_counter()-t_sweep_start:.1f}s, "
                  f"{len(values_ms)} good, {n_fail} failed)", flush=True)

    sweep_elapsed = time.perf_counter() - t_sweep_start
    print(f"\nCompleted {len(values_ms)}/{args.reps} reps ({n_fail} failed) "
          f"in {sweep_elapsed:.1f}s.\n")

    m, hw = ci95(values_ms)
    sv = sorted(values_ms)
    n = len(sv)
    with open(args.out_csv, "w", newline="") as fp:
        fp.write("# Anon-Sec-Net: Figure 3 path construction time, PRODUCTION client.exe\n")
        fp.write("# (includes RTT-based channel assignment probe --\n")
        fp.write("# NOT present in the original figure3_asn.csv, which used\n")
        fp.write("# client_instrumented.exe, a frozen pre-RTT-probe snapshot)\n")
        fp.write(f"# {n_fail} failed reps excluded (SG session-table transient/other)\n")
        fp.write("# ms: milliseconds per complete session (both paths) setup\n")
        w = csv.writer(fp)
        w.writerow(["protocol", "n", "mean_ms", "ci95_ms", "median_ms",
                    "p5_ms", "p95_ms", "min_ms", "max_ms"])
        if n:
            w.writerow([
                "asn_production", n, f"{m:.3f}", f"{hw:.3f}",
                f"{sv[n//2]:.3f}",
                f"{sv[max(0,int(n*0.05))]:.3f}",
                f"{sv[min(n-1,int(n*0.95))]:.3f}",
                f"{sv[0]:.3f}", f"{sv[-1]:.3f}",
            ])
        w.writerow([])
        w.writerow(["# raw samples (ms)"])
        for v in values_ms:
            w.writerow([f"{v:.3f}"])

    if n:
        print(f"mean={m:.3f}ms  ci95={hw:.3f}ms  median={sv[n//2]:.3f}ms  "
              f"p5={sv[max(0,int(n*0.05))]:.3f}ms  p95={sv[min(n-1,int(n*0.95))]:.3f}ms  "
              f"min={sv[0]:.3f}ms  max={sv[-1]:.3f}ms")
        print(f"\nCompare against published (client_instrumented.exe): "
              f"mean=6.32ms median=6.13ms p95=7.18ms (n=1000)")
    print(f"Written -> {args.out_csv}")


if __name__ == "__main__":
    main()
