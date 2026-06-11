#!/usr/bin/env python3
"""Quick check - is link_bytes.csv being actively written right now?"""
import os, time

path = "link_bytes.csv"

def count_rows(p):
    n = 0
    if not os.path.exists(p): return 0
    with open(p) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"): continue
            if line.startswith("ts_ms,cover"): continue
            parts = line.split(",")
            if len(parts) == 6 and parts[0] == "ts_ms" and parts[2] == "cover":
                n += 1
    return n

print("Watching link_bytes.csv for 5 seconds...")
before = count_rows(path)
time.sleep(5)
after = count_rows(path)
new = after - before
print(f"  Rows before: {before}")
print(f"  Rows after:  {after}")
print(f"  New rows in 5s: {new}")
if new > 0:
    print("  CLIENT IS ACTIVE - cover thread is writing. Ready to sweep.")
else:
    print("  NO NEW ROWS - client cover thread is not writing.")
    print("  Make sure client_instrumented.exe is running at the client> prompt.")
