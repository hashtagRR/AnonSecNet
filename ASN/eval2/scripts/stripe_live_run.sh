#!/usr/bin/env bash
# stripe_live_run.sh: live check of client-side parallel striping.
# Starts the 100-node pool with the trace probe on, then runs one client
# per case with cover traffic off, sending STREAM probe traffic, and keeps
# the client's per-packet leg log plus the forward and return traces of
# every pool node. Check the output with analysis/asn_striping_check.py.
#
# Usage: stripe_live_run.sh <out-dir> [packets] [rate_per_s]
# Cases: single (1 leg), iid, round_robin, batch, latency (2 legs each),
# then paced_iid (2 legs, iid, 40 requests that each wait for their reply,
# to exercise the return path once per request).
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASN_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTS_DIR="$(cd "$ASN_DIR/../tests/ASN" && pwd)"
OUT_DIR="$(mkdir -p "${1:?usage: stripe_live_run.sh <out-dir> [packets] [rate]}" && cd "$1" && pwd)"
PACKETS="${2:-400}"
RATE="${3:-40}"

export ASN_HOPDECOY_TRACE=1
rm -f /tmp/hopdecoy_trace_*.csv
bash "$TESTS_DIR/stop_nodes_pool.sh" >/dev/null 2>&1
bash "$TESTS_DIR/start_nodes_pool.sh"

run_case() {
    local name="$1" legs="$2" policy="$3"; shift 3
    local cmd="STREAM $PACKETS $RATE" hold=$(( PACKETS / ${RATE%.*} + 4 ))
    if [ "$name" = "paced_iid" ]; then cmd="STREAM 40 $RATE 1"; hold=30; fi
    local dir="$OUT_DIR/$name"
    rm -rf "$dir"; mkdir -p "$dir/traces"
    rm -f /tmp/hopdecoy_trace_*.csv
    (
        cd "$dir" || exit 1
        { sleep 1; printf '%s\n' "$cmd"; sleep "$hold"; printf 'quit\n'; } |
            env ASN_STRIPE_LEGS="$legs" ASN_STRIPE_POLICY="$policy" ASN_COVER_OFF=1 \
                ASN_STRIPE_LOG="$dir/stripe_log.csv" "$@" "$ASN_DIR/client.exe" > client.log 2>&1
    )
    sleep 1
    cp /tmp/hopdecoy_trace_*.csv "$dir/traces/" 2>/dev/null
    printf '%s,%s,%s\n' "$name" "$legs" "$policy" > "$dir/case.csv"
    echo "$name: $(wc -l < "$dir/stripe_log.csv" 2>/dev/null || echo 0) packets logged"
}

run_case single      1 iid
run_case iid         2 iid
run_case round_robin 2 round_robin
run_case batch       2 batch       ASN_STRIPE_BATCH_MS=1000
run_case latency     2 latency     ASN_STRIPE_RTT_MS=50,100 ASN_STRIPE_WINDOW=2
run_case paced_iid   2 iid

bash "$TESTS_DIR/stop_nodes_pool.sh" >/dev/null 2>&1
cp /tmp/service_gateway_pool.log "$OUT_DIR/sg.log" 2>/dev/null
echo "done: $OUT_DIR"
