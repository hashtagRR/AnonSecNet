#!/usr/bin/env bash
# stop_nodes_pool.sh: kills whatever start_nodes_pool.sh started (via
# nodes_pool.pid), falling back to freeing the known ports directly.
set -u
cd "$(dirname "$0")/../../ASN" || exit 1

PIDFILE=nodes_pool.pid
if [ -f "$PIDFILE" ]; then
    while read -r pid; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null
    done < "$PIDFILE"
    rm -f "$PIDFILE"
fi

sleep 0.5

PORTS="9040 9041 9042 9043 9044 9045 9010 9012"
for ((i=0; i<100; i++)); do
    PORTS="$PORTS $((9100 + i))"
done
for p in $PORTS; do
    fuser -k "$p"/tcp >/dev/null 2>&1
done

exit 0
