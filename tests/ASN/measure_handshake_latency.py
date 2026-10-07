#!/usr/bin/env python3
"""measure_handshake_latency.py, decomposes one K_session/K_content
GET into phases (path construction / handshake / content fetch), a
per-request cost with no existing figure or table in the paper.

Pure black-box: drives production client.exe via stdin/stdout,
timestamping each of its own log lines with wall-clock time as they
arrive. No production code is modified.

HOW TO RUN
----------
cd to the ASN/ build directory, start_nodes_pool.sh, PUT some keys via
sender.exe, then:
    python3 ../tests/ASN/measure_handshake_latency.py --keys latkey0,latkey1,... [--trials 30]
"""
import argparse
import os
import subprocess
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BUILD_DIR = os.path.join(SCRIPT_DIR, "..", "..", "ASN")
CLIENT_EXE = os.path.join(BUILD_DIR, "client.exe")


def run_one_trial(key):
    proc = subprocess.Popen(
        [CLIENT_EXE], cwd=BUILD_DIR,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )
    t_start = time.perf_counter()

    def readline_until(pattern, timeout_s):
        deadline = time.perf_counter() + timeout_s
        while time.perf_counter() < deadline:
            line = proc.stdout.readline()
            if not line:
                return None
            t = time.perf_counter() - t_start
            if pattern in line:
                return t
        return None

    t_ready = readline_until("both paths ready", 15.0)
    if t_ready is None:
        proc.kill()
        return None

    proc.stdin.write(f"GET {key}\n")
    proc.stdin.flush()
    t_get_issued = time.perf_counter() - t_start

    t_last_poll = None
    t_response = None
    deadline = time.perf_counter() + 15.0
    while time.perf_counter() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        t = time.perf_counter() - t_start
        if "HANDSHAKE_POLL" in line:
            t_last_poll = t
        if "[Client] Response" in line:
            t_response = t
            break
        if "Could not establish a content key" in line or "REJECTED" in line:
            proc.stdin.write("quit\n")
            proc.stdin.flush()
            proc.wait(timeout=5)
            return None

    proc.stdin.write("quit\n")
    proc.stdin.flush()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    if t_response is None or t_last_poll is None:
        return None

    return {
        "path_construction_s": t_ready,
        "handshake_s": t_last_poll - t_get_issued,
        "fetch_s": t_response - t_last_poll,
        "total_get_to_response_s": t_response - t_get_issued,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keys", required=True, help="comma-separated list of pre-uploaded keys")
    ap.add_argument("--trials", type=int, default=30)
    args = ap.parse_args()
    keys = args.keys.split(",")

    results = []
    for i in range(args.trials):
        key = keys[i % len(keys)]
        r = run_one_trial(key)
        if r is None:
            print(f"trial {i} (key={key}): FAILED/timeout", flush=True)
            continue
        results.append(r)
        print(f"trial {i} (key={key}): path={r['path_construction_s']:.3f}s "
              f"handshake={r['handshake_s']:.3f}s fetch={r['fetch_s']:.3f}s "
              f"total_get_to_resp={r['total_get_to_response_s']:.3f}s", flush=True)

    if not results:
        print("\nNo successful trials.")
        sys.exit(1)

    def stats(key):
        vals = [r[key] for r in results]
        mean = sum(vals) / len(vals)
        var = sum((v - mean) ** 2 for v in vals) / max(1, len(vals) - 1)
        return mean, var ** 0.5, min(vals), max(vals)

    print(f"\n{len(results)}/{args.trials} successful trials.\n")
    for k in ["path_construction_s", "handshake_s", "fetch_s", "total_get_to_response_s"]:
        m, sd, lo, hi = stats(k)
        print(f"{k:<26} mean={m:.3f}s  stdev={sd:.3f}s  min={lo:.3f}s  max={hi:.3f}s")


if __name__ == "__main__":
    main()
