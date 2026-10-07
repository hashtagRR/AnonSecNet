#!/usr/bin/env bash
# start_nodes_pool.sh: launches the M=100-node mix-node pool (ports
# 9100-9199, see common/node_pool.h::POOL_PORT_BASE/POOL_SIZE) plus SG and
# CS, for the plain (non-instrumented) client.exe / mix_node.exe demo
# path that now draws its session topology from node_pool.c instead of
# the fixed PORT_MIX_1..C constants.
#
# This is SEPARATE from start_nodes.sh, which launches the *_instrumented
# binaries used by the paper's existing benchmark pipeline (Figures 2/3/
# 5/7/8, Table 8), that pipeline is untouched by Task 1 and this script
# does not affect it. sender.exe's own paths (MNi/MNii/MNiii/MNx/MNy/MNz,
# ports 9040-9045, moved from 9030-9035 on 2026-08-22, see config.h's
# PORT_MIX_I/II/III/X/Y/Z comment for why: the old range collided with
# CLIENT_RESPONSE_PORT's own 9020-9039) are also untouched by Task 1
# itself and are launched here unchanged so sender.exe keeps working.
#
# Run from the ASN/ build directory (where the .exe binaries live).
set -u
cd "$(dirname "$0")/../../ASN" || exit 1

PIDFILE=nodes_pool.pid
: > "$PIDFILE"

# Pool nodes for client.exe's session path (MN1-3/MNa-c drawn from this
# pool). Must match common/node_pool.h: POOL_PORT_BASE=9100, POOL_SIZE=100.
POOL_BASE=9100
POOL_SIZE=100

for ((i=0; i<POOL_SIZE; i++)); do
    p=$((POOL_BASE + i))
    ./mix_node.exe "$p" >/tmp/mix_node_pool_$p.log 2>&1 &
    echo $! >> "$PIDFILE"
done

# Sender's own fixed path, unchanged, out of Task 1 scope.
SENDER_PORTS="9040 9041 9042 9043 9044 9045"
for p in $SENDER_PORTS; do
    ./mix_node.exe "$p" >/tmp/mix_node_pool_$p.log 2>&1 &
    echo $! >> "$PIDFILE"
done

./service_gateway.exe >/tmp/service_gateway_pool.log 2>&1 &
echo $! >> "$PIDFILE"

./cache_server.exe >/tmp/cache_server_pool.log 2>&1 &
echo $! >> "$PIDFILE"

# Wait for every port to accept connections before handing control back.
ALL_PORTS="$SENDER_PORTS 9010 9012"
for ((i=0; i<POOL_SIZE; i++)); do
    ALL_PORTS="$ALL_PORTS $((POOL_BASE + i))"
done
for p in $ALL_PORTS; do
    for i in $(seq 1 50); do
        (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null && { exec 3<&- 3>&-; break; }
        sleep 0.2
    done
done

echo "Started $(wc -l < "$PIDFILE") processes (100-node pool + 6 sender-path + SG + CS)."
