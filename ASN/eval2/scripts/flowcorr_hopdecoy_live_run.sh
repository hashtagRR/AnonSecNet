#!/usr/bin/env bash
# flowcorr_hopdecoy_live_run.sh: drives the ASN_HOP_DECOY/ASN_POOL_MIXING
# production binaries through a live, multi-session
# run and captures real per-packet arrival traces at the sender path's
# entry (MNi, port 9040) and exit (MNiii, port 9042) hops, via mix_node.c's
# ASN_HOPDECOY_TRACE env-gated probe. Score the resulting traces with
# flowcorr_hopdecoy_score.py.
#
# Usage: flowcorr_hopdecoy_live_run.sh <mode> [out-dir]
#   mode: plain | decoy_only | hopdecoy | hopdecoy_honestmid | hopdecoy_poolmix
#   out-dir: defaults to ./hopdecoy_live (relative to cwd)
#
# Requires the matching binaries already built in ASN/ (see Makefile's
# hopdecoy/hopdecoy_hardened/hopdecoy_poolmix targets, and plain `make
# nodes`). Run from anywhere; ASN_DIR below is derived from this script's
# own location.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASN_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"   # eval2/scripts -> eval2 -> ASN

MODE="${1:?usage: flowcorr_hopdecoy_live_run.sh <mode> [out-dir]}"
OUT_DIR="$(cd "$(dirname "${2:-./hopdecoy_live}")" 2>/dev/null && pwd)/$(basename "${2:-./hopdecoy_live}")"
mkdir -p "$OUT_DIR"

cd "$ASN_DIR" || exit 1

case "$MODE" in
    plain)               MIXBIN=./mix_node.exe ;;
    decoy_only)          MIXBIN=./mix_node_hopdecoy.exe ;;
    hopdecoy_poolmix)    MIXBIN=./mix_node_hopdecoy_poolmix.exe ;;
    hopdecoy|hopdecoy_honestmid) MIXBIN=./mix_node_hopdecoy_hardened.exe ;;
    *) echo "unknown mode: $MODE" >&2; exit 1 ;;
esac
# hopdecoy_honestmid/hopdecoy_poolmix reuse the "hopdecoy" client/sender
# binary (decoy generation is identical regardless of what the mix nodes
# do with survivors), only the mix nodes' own behavior differs.
SENDER_BIN=./sender_hopdecoy.exe
[ "$MODE" = "plain" ] && SENDER_BIN=./sender.exe
[ "$MODE" = "decoy_only" ] && SENDER_BIN=./sender_hopdecoy.exe

PIDFILE="$OUT_DIR/nodes.pid"
: > "$PIDFILE"
TRACE_A="$OUT_DIR/hopdecoy_trace_9040_${MODE}.csv"
TRACE_B="$OUT_DIR/hopdecoy_trace_9042_${MODE}.csv"
rm -f /tmp/hopdecoy_trace_9040.csv /tmp/hopdecoy_trace_9042.csv

export ASN_HOPDECOY_TRACE=1
# hopdecoy_honestmid: MN1(9040)/MN3(9042) are the nodes the D1 threat
# model assumes are compromised, a real attacker controlling them has
# no reason to honestly run their own mixing delay (it only adds noise to
# their own observations). Disabling delay there (ASN_MIX_DELAY_MEAN_MS=0)
# isolates the part of the effect an attacker can't strip out by simply
# not cooperating with their own node's defense.
# Ports moved from 9030-9035 to 9040-9045 on 2026-08-22 (config.h's
# PORT_MIX_I..Z: the old range collided with CLIENT_RESPONSE_PORT).
for p in 9040 9041 9042 9043 9044 9045; do
    if [ "$MODE" = "hopdecoy_honestmid" ] && { [ "$p" = "9040" ] || [ "$p" = "9042" ]; }; then
        ASN_MIX_DELAY_MEAN_MS=0 "$MIXBIN" "$p" >"$OUT_DIR/mix_$p.log" 2>&1 &
    else
        "$MIXBIN" "$p" >"$OUT_DIR/mix_$p.log" 2>&1 &
    fi
    echo $! >> "$PIDFILE"
done
./service_gateway.exe >"$OUT_DIR/sg.log" 2>&1 &
echo $! >> "$PIDFILE"
./cache_server.exe >"$OUT_DIR/cs.log" 2>&1 &
echo $! >> "$PIDFILE"

for p in 9040 9041 9042 9043 9044 9045 9010 9012; do
    for i in $(seq 1 50); do
        (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null && { exec 3<&- 3>&-; break; }
        sleep 0.2
    done
done
echo "topology up ($MODE)"

# 20 staggered sender instances, each in its own scratch subdir (avoids
# pin-file/rate-tier-file races between concurrent instances), PUT once
# near start then idle (background cover/decoy thread keeps running) for
# ~10s. Staggered 1.5s apart: overlapping (concurrent) but externally
# ordered, so score.py can pair MN1/MN3 sessions by rank without needing
# a protocol-level session-ID change, see that script's docstring.
declare -a PIDS
N_SESSIONS="${N_SESSIONS:-20}"
for i in $(seq 1 "$N_SESSIONS"); do
    # Mode-specific dir + unconditional copy (not -n/no-clobber): the
    # documented usage pattern runs every mode into the SAME OUT_DIR in
    # sequence, and different modes need different sender binaries
    # (plain vs sender_hopdecoy.exe), a shared, no-clobber-copied dir
    # would silently keep serving the FIRST mode's binary to every
    # subsequent mode's run, corrupting the cross-condition comparison.
    DIR="$OUT_DIR/inst_${MODE}_$i"
    mkdir -p "$DIR"
    cp "$SENDER_BIN" "$DIR/sender.exe"
    (
        cd "$DIR" || exit 1
        { printf 'PUT k%d payload-instance-%d\n' "$i" "$i"; sleep 10; printf 'quit\n'; } | ./sender.exe > "sender_${i}.log" 2>&1
    ) &
    PIDS+=($!)
    sleep 1.5
done

for pid in "${PIDS[@]}"; do
    wait "$pid" 2>/dev/null
done
echo "senders done ($MODE)"

sleep 1
while read -r pid; do kill "$pid" 2>/dev/null; done < "$PIDFILE"
sleep 1

cp /tmp/hopdecoy_trace_9040.csv "$TRACE_A" 2>/dev/null
cp /tmp/hopdecoy_trace_9042.csv "$TRACE_B" 2>/dev/null
echo "done ($MODE): $(wc -l < "$TRACE_A" 2>/dev/null || echo 0) MN1 rows, $(wc -l < "$TRACE_B" 2>/dev/null || echo 0) MN3 rows"
echo "  entry trace: $TRACE_A"
echo "  exit  trace: $TRACE_B"
