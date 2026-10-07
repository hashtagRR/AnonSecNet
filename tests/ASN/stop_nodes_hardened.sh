#!/usr/bin/env bash
# stop_nodes_hardened.sh: stops whatever start_nodes_hardened.sh started.
set -u
cd "$(dirname "$0")/../../ASN" || exit 1

PIDFILE=nodes_hardened.pid
if [ -f "$PIDFILE" ]; then
    while read -r pid; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null
    done < "$PIDFILE"
    rm -f "$PIDFILE"
fi

sleep 0.5

for p in 9004 9005 9006 9007 9008 9009 9040 9041 9042 9043 9044 9045 9010 9012; do
    fuser -k "$p"/tcp >/dev/null 2>&1
done

# Best-effort cleanup: see stop_nodes.sh's matching comment.
exit 0
