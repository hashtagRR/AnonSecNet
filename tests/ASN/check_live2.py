#!/usr/bin/env python3
"""Check the raw tail of link_bytes.csv to see what's actually there."""
import os, time

path = "link_bytes.csv"

def get_filesize(p):
    return os.path.getsize(p) if os.path.exists(p) else 0

def get_all_lines(p):
    if not os.path.exists(p): return []
    with open(p) as f:
        return f.readlines()

print("=== Current tail of link_bytes.csv ===")
lines = get_all_lines(path)
print(f"Total lines in file: {len(lines)}")
print("Last 10 lines:")
for l in lines[-10:]:
    print(f"  {repr(l.rstrip())}")

print()
size1 = get_filesize(path)
print(f"File size now: {size1} bytes")
print("Waiting 3 seconds...")
time.sleep(3)
size2 = get_filesize(path)
print(f"File size after 3s: {size2} bytes")
if size2 > size1:
    print(f"  GROWING (+{size2-size1} bytes) - sampler IS writing")
    print("Last 5 lines now:")
    for l in get_all_lines(path)[-5:]:
        print(f"  {repr(l.rstrip())}")
else:
    print("  NOT GROWING - sampler is NOT writing new data")
