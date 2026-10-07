#!/usr/bin/env python3
"""sweep_table2_prod.py, Table 2 (aggregate throughput vs. concurrent
session count) re-measured against PRODUCTION client.exe/sender.exe,
the original ASN_sweep_table2.py in this same directory drives
client_instrumented.exe at SET_RATE 1.0 against content pre-seeded
directly into cache_server.exe via a raw socket (seed_cache.py),
bypassing Sender and K_session/K_content entirely. That methodology
cannot be reused for a production measurement: client_instrumented.exe
has no TYPE_PUT/HANDSHAKE_* support at all, and SET_RATE-driven synthetic
real packets have no content-layer semantics to decrypt.

This is a genuinely DIFFERENT metric, not a drop-in replacement: the
original reports raw SG PACKET throughput (bits/sec of TYPE_GET packets
reaching SG, no application-level success/failure concept). This script
reports completed END-TO-END content retrievals per second (full
handshake + GET + decrypt/verify), the application-level throughput a
real deployment's users would actually experience, the two numbers are
NOT directly comparable unit-for-unit.

Each of N concurrent client.exe Receivers gets its OWN pre-assigned,
never-shared key (avoids the known concurrent-same-key pending-slot
limitation entirely, rather than working around it) and loops GET on
that one key for the full measurement window, matching the original's
per-count measurement windows (default 30s) as closely as the different
methodology allows.

HOW TO RUN
----------
cd to the ASN/ build directory (where the .exe binaries live), then:
    python3 ../tests/ASN/sweep_table2_prod.py [out.csv] [--counts 1,5,10,50,100,200] [--duration 30]

Uses start_nodes_pool.sh/stop_nodes_pool.sh (this directory) to manage
the production node cluster between count levels.
"""
import argparse
import csv
import os
import re
import subprocess
import sys
import threading
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BUILD_DIR = os.path.join(SCRIPT_DIR, "..", "..", "ASN")
CLIENT_EXE = os.path.join(BUILD_DIR, "client.exe")
SENDER_EXE = os.path.join(BUILD_DIR, "sender.exe")
SPAWN_STAGGER_S = 0.05
# Rough average response payload size (bytes) for the kbps-equivalent
# estimate: content is "v{N}", a few bytes; NOT the same accounting
# the original packet-level bps used (which counted the full 1024-byte
# wire packet per TYPE_GET, not the decoded payload).
AVG_PAYLOAD_BYTES = 22


def restart_network():
    subprocess.call([os.path.join(SCRIPT_DIR, "stop_nodes_pool.sh")])
    time.sleep(1)
    # Node identities regenerate on restart, stale TOFU pins from the
    # previous incarnation cause "PIN MISMATCH" rejections otherwise.
    subprocess.call(["rm", "-rf",
                      os.path.join(BUILD_DIR, "sender_pins"),
                      os.path.join(BUILD_DIR, "client_pins")])
    subprocess.call([os.path.join(SCRIPT_DIR, "start_nodes_pool.sh")])
    time.sleep(2)


def ensure_keys_uploaded(n_keys):
    """PUT n_keys distinct keys via a real sender.exe, matching the
    convention client_id -> key f"t2key{client_id}" 1:1, so no two
    concurrent clients EVER race the same content key."""
    put_cmds = "".join(f"PUT t2key{i} v{i}\n" for i in range(n_keys))
    proc = subprocess.Popen(
        [SENDER_EXE], cwd=BUILD_DIR,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )
    proc.stdin.write(put_cmds)
    proc.stdin.flush()
    n_confirmed = 0
    deadline = time.perf_counter() + max(15.0, n_keys * 0.2)
    while n_confirmed < n_keys and time.perf_counter() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        if "Content uploaded successfully" in line:
            n_confirmed += 1
    print(f"  [setup] {n_confirmed}/{n_keys} keys confirmed uploaded", flush=True)
    return proc, n_confirmed  # proc kept running (heartbeat thread must stay alive)


def run_client_loop(client_id, key, out_list, response_port, t_window_end, workdir_base):
    env = dict(os.environ)
    env["ASN_CLIENT_RESPONSE_PORT"] = str(response_port)
    workdir = f"{workdir_base}/t2_client_{client_id}"
    os.makedirs(workdir, exist_ok=True)
    # Reused workdir across K-levels/restarts, node identities
    # regenerate on each restart_network(), so a pin from an earlier
    # K-level would falsely look like a MITM. Guard set is fine to keep
    # (still-valid node indices from the same consensus).
    subprocess.call(["rm", "-rf", os.path.join(workdir, "client_pins")])

    try:
        proc = subprocess.Popen(
            [CLIENT_EXE], cwd=workdir, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
    except Exception:
        return

    def readline_until(pattern, timeout_s):
        deadline = time.perf_counter() + timeout_s
        while time.perf_counter() < deadline:
            line = proc.stdout.readline()
            if not line:
                return False
            if re.search(pattern, line):
                return True
        return False

    if not readline_until(r"both paths ready", 20.0):
        try:
            proc.kill()
        except Exception:
            pass
        return

    completed = []
    while time.perf_counter() < t_window_end:
        t0 = time.perf_counter()
        try:
            proc.stdin.write(f"GET {key}\n")
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            break
        got_response = False
        deadline = time.perf_counter() + 15.0
        while time.perf_counter() < deadline:
            try:
                line = proc.stdout.readline()
            except Exception:
                break
            if not line:
                break
            if "[Client] Response" in line:
                got_response = True
                break
            if "Could not establish" in line or "REJECTED" in line:
                break
        if got_response:
            completed.append(time.perf_counter() - t0)

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

    out_list.extend(completed)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out_csv", nargs="?", default="table2_asn_prod.csv")
    ap.add_argument("--counts", default="1,5,10,50,100,200")
    ap.add_argument("--duration", type=float, default=30.0)
    ap.add_argument("--response-port-count", type=int, default=16,
                     help="must match SENDER_RESPONSE_PORT_COUNT the binaries were built with")
    ap.add_argument("--workdir-base", default="/tmp/asn_table2_prod")
    args = ap.parse_args()

    counts = [int(x) for x in args.counts.split(",")]
    os.makedirs(args.workdir_base, exist_ok=True)

    results = []
    for K in counts:
        # Retry the restart if key upload comes back (mostly) empty,
        # an occasional port-reuse race during rapid stop/start cycling
        # (existing stop_nodes_pool.sh's SIGTERM + 0.5s before its
        # fuser -k fallback isn't always enough time for 100+ processes
        # to fully release their ports before start_nodes_pool.sh tries
        # to rebind them), not a correctness issue with this script's
        # own logic, confirmed by re-running the identical sequence
        # by hand outside this loop and seeing it succeed cleanly.
        sender_proc = None
        n_confirmed = 0
        for attempt in range(3):
            restart_network()
            sender_proc, n_confirmed = ensure_keys_uploaded(K)
            if n_confirmed >= max(1, K // 2):
                break
            if attempt < 2:
                print(f"  [retry] K={K}: only {n_confirmed}/{K} keys uploaded, "
                      f"retrying network restart (attempt {attempt+2}/3)", flush=True)
                try:
                    sender_proc.kill()
                except Exception:
                    pass

        out_lists = [[] for _ in range(K)]
        threads = []
        base_port = 9020
        t_start = time.perf_counter()
        t_window_end = t_start + args.duration
        for i in range(K):
            key = f"t2key{i}"
            t = threading.Thread(target=run_client_loop,
                                  args=(i, key, out_lists[i], base_port + (i % 20),
                                        t_window_end, args.workdir_base))
            threads.append(t)
            t.start()
            if i < K - 1:
                time.sleep(SPAWN_STAGGER_S)
        for t in threads:
            t.join(timeout=args.duration + 30)
        elapsed = time.perf_counter() - t_start

        try:
            sender_proc.stdin.write("quit\n")
            sender_proc.stdin.flush()
        except Exception:
            pass
        try:
            sender_proc.wait(timeout=5)
        except Exception:
            sender_proc.kill()

        all_lat = [x for lst in out_lists for x in lst]
        n_total = len(all_lat)
        throughput = n_total / elapsed if elapsed > 0 else 0.0
        mean_lat = sum(all_lat) / n_total if n_total else float("nan")
        kbps_equiv = throughput * AVG_PAYLOAD_BYTES * 8 / 1000.0

        row = {"n_clients": K, "completed": n_total, "elapsed_s": elapsed,
               "get_per_s": throughput, "mean_latency_s": mean_lat,
               "kbps_equiv": kbps_equiv}
        results.append(row)
        print(f"K={K:<4} completed={n_total:<6} elapsed={elapsed:.1f}s "
              f"GET/s={throughput:.2f} mean_lat={mean_lat:.3f}s "
              f"kbps_equiv~={kbps_equiv:.2f}", flush=True)

    with open(args.out_csv, "w", newline="") as fp:
        fp.write("# Anon-Sec-Net: Table 2 throughput, PRODUCTION client.exe/sender.exe,\n")
        fp.write("# full K_session/K_content handshake per GET. NOT directly comparable\n")
        fp.write("# to the original table2_results.csv (raw SG packet bps, no handshake,\n")
        fp.write("# no Sender), see this script's own docstring.\n")
        w = csv.writer(fp)
        w.writerow(["n_clients", "completed", "elapsed_s", "get_per_s",
                    "mean_latency_s", "kbps_equiv_approx"])
        for r in results:
            w.writerow([r["n_clients"], r["completed"], f"{r['elapsed_s']:.2f}",
                        f"{r['get_per_s']:.3f}", f"{r['mean_latency_s']:.3f}",
                        f"{r['kbps_equiv']:.2f}"])
    print(f"\nWritten -> {args.out_csv}")


if __name__ == "__main__":
    main()
