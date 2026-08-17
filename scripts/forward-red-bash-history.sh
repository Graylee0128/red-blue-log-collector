#!/usr/bin/env bash
# Red-team command-log forwarder for /ingest/red. Tails a file of one
# command per line, optionally prefixed with an ISO-8601 UTC timestamp
# ("2026-08-17T11:00:00Z some-command ..."), and POSTs each new line.
#
# Plain ~/.bash_history is only flushed to disk periodically (on shell
# exit, or on `history -a`), so tailing it in real time is unreliable.
# To get a live, timestamped command log instead, add this to the red
# VM's ~/.bashrc:
#
#   export PROMPT_COMMAND='echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $(history 1 | sed "s/^[ ]*[0-9]\+[ ]*//")" >> ~/red-command.log'
#
# Then run this script against ~/red-command.log.
#
# Target IP extraction is a best-effort regex over the command text (first
# IPv4 literal found). If the command uses a hostname instead of an IP, no
# destination will be set for that event -- see the correlation note in
# README.md's "Real log source forwarders" section.
#
# Usage:
#   COLLECTOR_URL=http://<collector-ip>:8000 INGEST_TOKEN=<token> \
#     ./forward-red-bash-history.sh ~/red-command.log
set -euo pipefail

LOG_FILE="${1:?usage: forward-red-bash-history.sh <log-file>}"
COLLECTOR_URL="${COLLECTOR_URL:-http://localhost:8000}"
INGEST_TOKEN="${INGEST_TOKEN:-}"

auth_header=()
if [[ -n "$INGEST_TOKEN" ]]; then
  auth_header=(-H "Authorization: Bearer ${INGEST_TOKEN}")
fi

ts_regex='^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z) (.*)$'
ip_regex='([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'

tail -n0 -F "$LOG_FILE" | while IFS= read -r line; do
  [[ -z "$line" ]] && continue

  if [[ "$line" =~ $ts_regex ]]; then
    ts="${BASH_REMATCH[1]}"
    cmd="${BASH_REMATCH[2]}"
  else
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    cmd="$line"
  fi

  target_ip=""
  if [[ "$cmd" =~ $ip_regex ]]; then
    target_ip="${BASH_REMATCH[1]}"
  fi

  payload=$(jq -n \
    --arg ts "$ts" --arg cmd "$cmd" --arg tip "$target_ip" --arg src "$(hostname)" \
    '{observed_at: $ts, command: $cmd, source: $src} + (if $tip != "" then {target_ip: $tip} else {} end)')

  if ! curl -sS -o /dev/null -w "%{http_code}\n" -X POST "$COLLECTOR_URL/ingest/red" \
      -H 'Content-Type: application/json' \
      "${auth_header[@]}" \
      -d "$payload"; then
    echo "WARN: forward failed for line: $line" >&2
  fi
done
