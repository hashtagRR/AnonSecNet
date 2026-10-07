#!/usr/bin/env bash
# stop_nodes.sh: Linux replacement for the missing stop_nodes.bat.
# Kills whatever start_nodes.sh started (via nodes.pid), falling back to
# freeing the known node ports directly if a PID has already died or the
# pidfile is stale.
set -u
cd "$(dirname "$0")/../../ASN" || exit 1

PIDFILE=nodes.pid
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

# Best-effort cleanup: fuser exits nonzero when a port has nothing left to
# kill (the common case, since the PID-based kill above already got most
# processes), that's not a real failure, so always exit 0 rather than
# propagate fuser's exit code to callers running under `set -e`.
exit 0
