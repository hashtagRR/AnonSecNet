#!/usr/bin/env bash
# run_delay_sweep_throughput.sh: Task 3: throughput vs mean mixing delay,
# N=1,5,10 only (this host has 2 vCPUs; the paper's own hardened Table 8
# comparison needed a 12/16-vCPU cloud machine to avoid a hardware
# concurrency ceiling above N~50, see anosecnet.tex's throughput section
# note on test-machine spec). Running N=50+ here would reproduce that same
# ceiling and contaminate the delay-sensitivity signal, not measure it.
set -eu
cd "$(dirname "$0")/../../ASN"

PYTHON3="../.venv/bin/python3"
[ -x "$PYTHON3" ] || PYTHON3="python3"

OUT_ROOT="$(pwd)/eval2/delay_sweep_throughput"
mkdir -p "$OUT_ROOT"

for delay in 10 25 50 100 200; do
    echo "=== mean delay = ${delay}ms ==="
    bash ../tests/ASN/stop_nodes_hardened.sh
    sleep 2
    export ASN_MIX_DELAY_MEAN_MS=$delay
    bash ../tests/ASN/start_nodes_hardened.sh
    "$PYTHON3" scripts/seed_cache.py > /dev/null 2>&1
    "$PYTHON3" ../tests/ASN/ASN_sweep_table2.py \
        --counts 1,5,10 --duration 20 \
        --client-exe ./client_instrumented_hardened.exe \
        --start-script start_nodes_hardened.sh --stop-script stop_nodes_hardened.sh \
        --out-dir "$OUT_ROOT/delay_${delay}ms"
    bash ../tests/ASN/stop_nodes_hardened.sh
    sleep 2
done

echo "Done. Per-delay results in $OUT_ROOT/delay_*ms/table2_results.csv"
