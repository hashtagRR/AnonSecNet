#!/usr/bin/env python3
"""Calls DeepCoFFEA's OWN filter.py/new_dcf_parse.py functions (imported,
not reimplemented) against our generated trace directories, with only the
path/threshold arguments changed to match our data, same pattern their
own README documents ("modify line X before running"), just done via
import + function call instead of editing their module-level globals."""
import argparse
import os
import sys

sys.path.insert(0, "/work")
import dcf_filter_lib as dcf_filter
import dcf_parse_lib as dcf_parse

ap = argparse.ArgumentParser()
ap.add_argument("--data-dir", required=True, help="dir containing inflow/outflow")
ap.add_argument("--out-prefix", required=True)
ap.add_argument("--threshold", type=int, default=10)
ap.add_argument("--interval", type=int, default=5)
ap.add_argument("--num-windows", type=int, default=11)
ap.add_argument("--addnum", type=int, default=2)
args = ap.parse_args()

data_path = args.data_dir.rstrip("/") + "/"
file_list_path = args.out_prefix + "_filelist.txt"

print("=== filter.py: selecting flow pairs with enough packets per window ===")
dcf_filter.create_overlap_window_csv(
    data_path, file_list_path, args.threshold, args.interval,
    args.num_windows, args.addnum)

n_kept = sum(1 for _ in open(file_list_path))
print("Kept {} flow pairs after threshold filter".format(n_kept))
if n_kept == 0:
    print("ERROR: no flow pairs survived the threshold filter, lower --threshold")
    sys.exit(1)

print("=== new_dcf_parse.py: building windowed pickles ===")
dcf_parse.create_overlap_window_csv(
    data_path, file_list_path, args.out_prefix, args.interval,
    args.num_windows, args.addnum)

print("Done.")
