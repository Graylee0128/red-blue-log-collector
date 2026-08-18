#!/usr/bin/env bash
# Minimal Option-A forwarder template (see docs/INTERFACE_CONTRACT.md and
# GitHub issue #1). Run this on a source VM to tail a log file and POST each
# new line to the collector's /ingest/{red,blue} endpoint.
#
# This is a STARTING POINT, not a finished mapping: once the real Red/Blue
# log format is known, replace the jq payload below to send the actual
# fields (source_ip, destination, action_result, correlation_id, ...) under
# the aliases documented in docs/INTERFACE_CONTRACT.md instead of only
# {"message": line}. Requires: bash, curl, jq.
#
# Usage:
#   COLLECTOR_URL=http://collector-host:8000 INGEST_TOKEN=<token> \
#     ./forwarder-template.sh red /var/log/auth.log
set -euo pipefail

TEAM="${1:?usage: forwarder-template.sh <red|blue> <log-file>}"
LOG_FILE="${2:?usage: forwarder-template.sh <red|blue> <log-file>}"
COLLECTOR_URL="${COLLECTOR_URL:-http://localhost:8000}"
INGEST_TOKEN="${INGEST_TOKEN:-}"

if [[ "$TEAM" != "red" && "$TEAM" != "blue" ]]; then
  echo "team must be 'red' or 'blue', got: $TEAM" >&2
  exit 1
fi

auth_header=()
if [[ -n "$INGEST_TOKEN" ]]; then
  auth_header=(-H "Authorization: Bearer ${INGEST_TOKEN}")
fi

tail -n0 -F "$LOG_FILE" | while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  payload=$(jq -n --arg msg "$line" --arg src "$(hostname)" \
    '{message: $msg, source: $src, observed_at: (now | todate)}')
  if ! curl -sS -o /dev/null -w "%{http_code}\n" -X POST "$COLLECTOR_URL/ingest/$TEAM" \
      -H 'Content-Type: application/json' \
      "${auth_header[@]}" \
      -d "$payload"; then
    echo "WARN: forward failed for line: $line" >&2
  fi
done
