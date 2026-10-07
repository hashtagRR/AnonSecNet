#!/usr/bin/env bash
# Runs the ASN cross-validation replicates one after another into
# <out-root>/r<label>/ (labels are the confirmatory seed numbers; the ASN C
# code draws its own randomness). Resumes: finished replicates are skipped,
# and inside a replicate stripe_xval_run.sh skips finished cells.
#
# Usage: xval_replicates.sh <out-root> [first_label] [last_label]
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(mkdir -p "${1:?usage: xval_replicates.sh <out-root> [first] [last]}" && cd "$1" && pwd)"
FIRST="${2:-2026092501}"; LAST="${3:-2026092512}"
for label in $(seq "$FIRST" "$LAST"); do
    [ -f "$ROOT/r$label/done" ] && continue
    start=$(date +%s)
    "$SCRIPT_DIR/stripe_xval_run.sh" "$ROOT/r$label" 120 15 4 24 >> "$ROOT/r$label.log" 2>&1
    status=$?
    echo "exit=$status seconds=$(( $(date +%s) - start ))" >> "$ROOT/r$label.log"
    [ "$status" -eq 0 ] && touch "$ROOT/r$label/done"
done
touch "$ROOT/all.done"
