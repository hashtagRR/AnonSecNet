#!/usr/bin/env bash
# stripe_xval_run.sh: ASN cross-validation runs for the split-policy
# comparisons (preregistration C2 and C3). Starts the 100-node pool with
# per-hop exponential mixing (mix_node_hardened.exe, mean
# ASN_MIX_DELAY_MEAN_MS) and the entry-side trace probe, the SG with the
# exit-side trace probe (ASN_SG_TRACE), then runs one cell per split policy.
# Each session is a fresh client (fresh guard sets) sending Poisson STREAM
# traffic with cover off; sessions run in waves of CONCURRENCY clients, each
# on its own response port. Score with analysis/asn_xval.py.
#
# The pool is restarted every RESTART_EVERY sessions: mix nodes keep
# sessions for their TTL, and over a long run the growing session tables
# raised the entry-side timing noise from 2 ms to 12 ms (95th percentile).
#
# Traces and node logs go to TRACE_DIR on disk (default /var/tmp/asn_xval),
# not /tmp: on Debian 13 /tmp is a RAM-backed tmpfs, and a long run filled
# the memory of an 8 GB VM. A cell whose cell.csv exists is skipped, so an
# interrupted run resumes at the first unfinished cell.
#
# Usage: stripe_xval_run.sh <out-dir> [sessions] [duration_s] [concurrency] [restart_every]
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASN_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTS_DIR="$(cd "$ASN_DIR/../tests/ASN" && pwd)"
OUT_DIR="$(mkdir -p "${1:?usage: stripe_xval_run.sh <out-dir> [sessions] [duration] [concurrency]}" && cd "$1" && pwd)"
SESSIONS="${2:-120}"
DURATION="${3:-15}"
CONCURRENCY="${4:-4}"
RESTART_EVERY="${5:-24}"
TRACE_DIR="${TRACE_DIR:-/var/tmp/asn_xval}"
mkdir -p "$TRACE_DIR"
export ASN_TRACE_DIR="$TRACE_DIR"
RATE=40
DELAY_MS=25
PACKETS=$(( DURATION * RATE ))

cd "$ASN_DIR" || exit 1

start_pool() {
    bash "$TESTS_DIR/stop_nodes_pool.sh" >/dev/null 2>&1
    : > nodes_pool.pid
    for ((i = 0; i < 100; i++)); do
        p=$((9100 + i))
        ASN_HOPDECOY_TRACE=1 ASN_MIX_DELAY_MEAN_MS=$DELAY_MS ./mix_node_hardened.exe "$p" >"$TRACE_DIR/mix_node_$p.log" 2>&1 &
        echo $! >> nodes_pool.pid
    done
    ASN_SG_TRACE=1 ./service_gateway.exe >"$TRACE_DIR/service_gateway.log" 2>&1 &
    echo $! >> nodes_pool.pid
    ./cache_server.exe >"$TRACE_DIR/cache_server.log" 2>&1 &
    echo $! >> nodes_pool.pid
    for p in 9010 9012 $(seq 9100 9199); do
        for i in $(seq 1 50); do
            (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null && { exec 3<&- 3>&-; break; }
            sleep 0.2
        done
    done
}

echo "pool: hardened mix nodes, ${DELAY_MS} ms mean delay per hop, restarted every $RESTART_EVERY sessions"

run_cell() {
    local cell="$1" legs="$2" policy="$3"; shift 3
    local dir="$OUT_DIR/asn_$cell"
    if [ -f "$dir/cell.csv" ]; then echo "$cell: already done, skipped"; return; fi
    rm -rf "$dir"; mkdir -p "$dir/traces"
    rm -f "$TRACE_DIR"/hopdecoy_trace_*.csv "$TRACE_DIR"/sg_trace.csv
    local start=$(date +%s)
    for ((first = 1; first <= SESSIONS; first += CONCURRENCY)); do
        if (( (first - 1) % RESTART_EVERY == 0 )); then start_pool; fi
        local wave=()
        for ((slot = 0; slot < CONCURRENCY && first + slot <= SESSIONS; slot++)); do
            local s=$(( first + slot ))
            local sdir="$dir/s$(printf %03d $s)"
            mkdir -p "$sdir"
            (
                cd "$sdir" || exit 1
                { sleep 1; printf 'STREAM %s %s\n' "$PACKETS" "$RATE"; sleep $(( DURATION + 4 )); printf 'quit\n'; } |
                    env ASN_STRIPE_LEGS="$legs" ASN_STRIPE_POLICY="$policy" ASN_COVER_OFF=1 \
                        ASN_CLIENT_RESPONSE_PORT=$(( 9020 + slot )) ASN_STRIPE_LOG="$sdir/stripe_log.csv" "$@" \
                        timeout $(( DURATION + 40 )) "$ASN_DIR/client.exe" > client.log 2>&1
            ) &
            wave+=($!)
            sleep 0.3
        done
        # only this wave's clients: the pool processes are children of this shell too
        wait "${wave[@]}"
    done
    sleep 1
    cp "$TRACE_DIR"/hopdecoy_trace_*.csv "$TRACE_DIR"/sg_trace.csv "$dir/traces/" 2>/dev/null
    rm -f "$TRACE_DIR"/hopdecoy_trace_*.csv "$TRACE_DIR"/sg_trace.csv
    printf 'cell,legs,policy,sessions,duration_s,rate,delay_ms,concurrency,restart_every\n%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$cell" "$legs" "$policy" "$SESSIONS" "$DURATION" "$RATE" "$DELAY_MS" "$CONCURRENCY" "$RESTART_EVERY" > "$dir/cell.csv"
    echo "$cell: $SESSIONS sessions in $(( $(date +%s) - start )) s"
}

run_cell single 1 iid
run_cell rr2    2 round_robin
run_cell iid2   2 iid
run_cell batch2 2 batch ASN_STRIPE_BATCH_MS=2000

bash "$TESTS_DIR/stop_nodes_pool.sh" >/dev/null 2>&1
tail -n 2000 "$TRACE_DIR/service_gateway.log" > "$OUT_DIR/sg_tail.log" 2>/dev/null
echo "done: $OUT_DIR"
