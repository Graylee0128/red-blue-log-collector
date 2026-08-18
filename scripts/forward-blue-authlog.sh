#!/usr/bin/env bash
# Blue-team auth-log forwarder for /ingest/blue. Tails a syslog-format
# auth log (default /var/log/auth.log on Debian/Ubuntu; pass
# /var/log/secure on RHEL/CentOS) and POSTs each new line.
#
# Lines matching common failed-auth/attack keywords are tagged
# event_type=blue.alert so the collector's hit-detection heuristic (see
# "Correlation logic" in docs/INTERFACE_CONTRACT.md) recognizes them as a
# detection instead of a benign log line. Extend $ALERT_REGEX for your
# actual attack patterns.
#
# "destination" is set to this VM's own IP (not hostname) so it can string-
# match the target IP a red-team command was pointed at -- see the
# correlation note in README.md's "Real log source forwarders" section.
#
# Usage:
#   COLLECTOR_URL=http://<collector-ip>:8000 INGEST_TOKEN=<token> \
#     ./forward-blue-authlog.sh /var/log/auth.log
set -euo pipefail

LOG_FILE="${1:-/var/log/auth.log}"
COLLECTOR_URL="${COLLECTOR_URL:-http://localhost:8000}"
INGEST_TOKEN="${INGEST_TOKEN:-}"
ALERT_REGEX="${ALERT_REGEX:-Failed password|Invalid user|authentication failure|Failed publickey|POSSIBLE BREAK-IN ATTEMPT}"

auth_header=()
if [[ -n "$INGEST_TOKEN" ]]; then
  auth_header=(-H "Authorization: Bearer ${INGEST_TOKEN}")
fi

self_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
ip_regex='from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'

tail -n0 -F "$LOG_FILE" | while IFS= read -r line; do
  [[ -z "$line" ]] && continue

  event_type="blue.log"
  if [[ "$line" =~ $ALERT_REGEX ]]; then
    event_type="blue.alert"
  fi

  attacker_ip=""
  if [[ "$line" =~ $ip_regex ]]; then
    attacker_ip="${BASH_REMATCH[1]}"
  fi

  payload=$(jq -n \
    --arg msg "$line" --arg host "$self_ip" --arg et "$event_type" --arg aip "$attacker_ip" \
    '{message: $msg, host: $host, event_type: $et} + (if $aip != "" then {attacker_ip: $aip} else {} end)')

  if ! curl -sS -o /dev/null -w "%{http_code}\n" -X POST "$COLLECTOR_URL/ingest/blue" \
      -H 'Content-Type: application/json' \
      "${auth_header[@]}" \
      -d "$payload"; then
    echo "WARN: forward failed for line: $line" >&2
  fi
done
