#!/usr/bin/env bash
# run_delay_sweep_flowcorr.sh: Task 3: TPR@FPR vs mean mixing delay.
# Runs flowcorr_run.py --hardened-jitter at each delay value in the sweep,
# fixed FPR targets 1e-3 and 1e-5 (Table 6/8's own operating points),
# sessions=500 for 1e-5 resolution (matches the paper's existing FPR=1e-5
# comparison methodology exactly). Cap held fixed at MIX_DELAY_MAX_MS=500
# for every point.
set -eu
cd "$(dirname "$0")"

PYTHON3="../../../.venv/bin/python3"
[ -x "$PYTHON3" ] || PYTHON3="python3"

OUT_ROOT="$(pwd)/../delay_sweep"
mkdir -p "$OUT_ROOT"

for delay in 10 25 50 100 200; do
    dir="$OUT_ROOT/delay_${delay}ms"
    mkdir -p "$dir"
    echo "=== mean delay = ${delay}ms ==="
    "$PYTHON3" flowcorr_run.py \
        --sessions 500 --seed 20260718 \
        --hardened-jitter --mix-delay-mean-ms "$delay" \
        --fpr-targets 1e-3,1e-5 \
        --out-dir "$dir" --quiet
done

echo "Done. Per-delay results in $OUT_ROOT/delay_*ms/flowcorr_results.csv"
