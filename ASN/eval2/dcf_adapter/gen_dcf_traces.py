#!/usr/bin/env python3
"""Adapter: generate DeepCoFFEA-format trace files (inflow/outflow dirs,
"timestamp\tsize" per line) from this project's OWN, already-validated
synthetic trace generator (flowcorr_run.py's gen_session/rng), not a new
trace model, reuses the exact same functions that produced fig_flowcorr
and every §5.6 number, just called with more sessions and a longer
duration (30s instead of 20s) so DeepCoFFEA's own windowing (11 windows x
5s, 2s stride, spanning 22s) fits inside one session.

Packet size is fixed at 1024 (WIRE_PACKET_SIZE, config.h) for every event,
real or cover. This matches the actual wire format: ASN's
fixed-size-packet design means there is no
size signal to give DeepCoFFEA, by construction (see the paper's own
Section 3.6). Positive size marks every event (direction is separated by
file, not by sign, since inflow/outflow are already distinct files).

Usage:
    python gen_dcf_traces.py --condition single_path --n-sessions 400 --out-dir dcf_data_single
    python gen_dcf_traces.py --condition asn_both_paths --n-sessions 400 --out-dir dcf_data_asn
"""
import argparse
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import flowcorr_run as fc
fc.SESSION_DURATION_S = 30.0  # patched: fit DeepCoFFEA's 11x5s windows, 2s stride

WIRE_PACKET_SIZE = 1024
ADAPTER_DURATION_S = 30.0  # long enough for DCF's 11 x 5s windows, stride 2s


def write_flow(out_dir, subdir, idx, times_ms):
    d = os.path.join(out_dir, subdir)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "{}_0.txt".format(idx)), "w") as f:
        for t_ms in times_ms:
            f.write(f"{t_ms / 1000.0:.6f}\t{WIRE_PACKET_SIZE}\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--condition", required=True,
                     choices=["single_path", "asn_one_path", "asn_both_paths"])
    ap.add_argument("--n-sessions", type=int, default=400)
    ap.add_argument("--seed", type=int, default=20260719)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    os.makedirs(args.out_dir, exist_ok=True)

    idx = 0
    for i in range(args.n_sessions):
        flow_type = "interactive" if i % 2 == 0 else "bulk"
        subpaths = fc.gen_session(rng, flow_type, args.condition, )
        # gen_session's SESSION_DURATION_S global controls duration; patch
        # it for this call so windows fit (see ADAPTER_DURATION_S above).
        for entry_times, exit_times in subpaths:
            write_flow(args.out_dir, "inflow", idx, entry_times)
            write_flow(args.out_dir, "outflow", idx, exit_times)
            idx += 1

    print(f"Wrote {idx} flow pairs to {args.out_dir}/{{inflow,outflow}}/")


if __name__ == "__main__":
    main()
