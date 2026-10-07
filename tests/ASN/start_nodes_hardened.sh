#!/usr/bin/env bash
# start_nodes_hardened.sh: like start_nodes.sh, but launches the
# ASN_LOOPIX_MIXING-hardened mix node / client binaries (mix_node_
# instrumented_hardened.exe) instead of the plain instrumented ones, for
# A/B benchmarking. service_gateway_instrumented.exe and cache_server.exe
# are unaffected by ASN_LOOPIX_MIXING (Part A/B only touch mix_node.c and
# client.c/sender.c), so they're reused unchanged from the plain build.
#
# Run from the ASN/ build directory (where the .exe binaries live).
set -u
cd "$(dirname "$0")/../../ASN" || exit 1

PIDFILE=nodes_hardened.pid
: > "$PIDFILE"

MIX_PORTS="9004 9005 9006 9007 9008 9009 9040 9041 9042 9043 9044 9045"

for p in $MIX_PORTS; do
    ./mix_node_instrumented_hardened.exe "$p" >/tmp/mix_node_hardened_$p.log 2>&1 &
    echo $! >> "$PIDFILE"
done

./service_gateway_instrumented.exe >/tmp/service_gateway_hardened.log 2>&1 &
echo $! >> "$PIDFILE"

./cache_server.exe >/tmp/cache_server_hardened.log 2>&1 &
echo $! >> "$PIDFILE"

# Wait for every port to accept connections before handing control back.
for p in $MIX_PORTS 9010 9012; do
    for i in $(seq 1 50); do
        (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null && { exec 3<&- 3>&-; break; }
        sleep 0.2
    done
done
