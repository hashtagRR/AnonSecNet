#!/usr/bin/env bash
# start_nodes.sh: Linux replacement for the missing start_nodes.bat.
# Launches all 12 instrumented mix nodes + SG + cache server, backgrounded,
# with PIDs recorded to nodes.pid so stop_nodes.sh can clean them up.
#
# Run from the ASN/ build directory (where the .exe binaries live).
set -u
cd "$(dirname "$0")/../../ASN" || exit 1

PIDFILE=nodes.pid
: > "$PIDFILE"

MIX_PORTS="9004 9005 9006 9007 9008 9009 9040 9041 9042 9043 9044 9045"

for p in $MIX_PORTS; do
    ./mix_node_instrumented.exe "$p" >/tmp/mix_node_$p.log 2>&1 &
    echo $! >> "$PIDFILE"
done

./service_gateway_instrumented.exe >/tmp/service_gateway.log 2>&1 &
echo $! >> "$PIDFILE"

./cache_server.exe >/tmp/cache_server.log 2>&1 &
echo $! >> "$PIDFILE"

# Wait for every port to accept connections before handing control back.
for p in $MIX_PORTS 9010 9012; do
    for i in $(seq 1 50); do
        (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null && { exec 3<&- 3>&-; break; }
        sleep 0.2
    done
done
