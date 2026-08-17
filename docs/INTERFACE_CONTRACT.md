# Interface Contract

What the Red team and Blue team need to know before they wire their systems
to this collector. This is the contract that stays stable — only
`src/rbcollector/adapters/red.py` and `src/rbcollector/adapters/blue.py`
change when a real provider schema shows up.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | Liveness + DB connectivity check |
| POST | `/ingest/red` | Accept one Red team event (any JSON object) |
| POST | `/ingest/blue` | Accept one Blue team event (any JSON object) |
| GET | `/events?team=red\|blue&limit=` | Normalized events for one team only |
| GET | `/timeline?limit=` | Merged, time-ordered Red+Blue normalized events |
| GET | `/analysis?limit=` | Correlated Red→Blue detections + latency/gap summary |

`/ingest/*` accepts **any JSON object** — there is no fixed producer schema.
The adapter looks for a set of known field names (aliases below) and falls
back to sensible defaults for anything it can't find. The full original
payload is always preserved (see [Raw payload preservation](#raw-payload-preservation)).

## What each side must send, at minimum

Neither team is required to match this exactly — the adapter aliasing below
covers common variants. But the more of these fields you send under any of
the listed aliases, the better the correlation and detection-gap analysis
will be:

- a timestamp
- a source (attacker/observer) IP or identifier
- a destination (target/host) or identifier
- an outcome/result/severity
- **`correlation_id`** — strongly recommended. If Red and Blue can both stamp
  the same `correlation_id` on the pair of events describing one action, the
  collector matches them directly instead of relying on time-window +
  IP/destination heuristics (see [Correlation logic](#correlation-logic)).

## Field aliases the adapters already understand

### Red (`POST /ingest/red`)

| Normalized field | Accepted input keys (first match wins) |
|---|---|
| `observed_at` | `observed_at`, `timestamp`, `time`, `ts` |
| `source_ip` | `source_ip`, `src_ip`, `src`, `ip` |
| `destination` | `destination`, `target`, `target_ip`, `dst_ip`, `url`, `path` |
| `action_result` | `action_result`, `result`, `outcome`, `status`, `exit_code` (default `"unknown"`) |
| `event_type` | `event_type`, `type` (default `"red.action"`) |
| `source` | `source`, `producer` (default `"red-team-api"`) |
| `actor` | `actor`, `user`, `player`, `username`, `seat_id` |
| `message` | `command`, `cmd`, `action`, `request`, `message` |
| `correlation_id` | `correlation_id`, `action_id`, `request_id`, `trace_id`, `session_id` |

### Blue (`POST /ingest/blue`)

| Normalized field | Accepted input keys (first match wins) |
|---|---|
| `observed_at` | `observed_at`, `timestamp`, `time`, `ts` |
| `source_ip` | `source_ip`, `src_ip`, `src`, `attacker_ip`, `ip` |
| `destination` | `destination`, `target`, `target_ip`, `dst_ip`, `host`, `service` |
| `action_result` | `action_result`, `result`, `outcome`, `status`, `severity` (default `"unknown"`) |
| `event_type` | `event_type`, `type` (default `"blue.event"`) |
| `source` | `source`, `producer`, `sensor` (default `"blue-team-api"`) |
| `actor` | `actor`, `analyst`, `user`, `username` |
| `message` | `message`, `alert`, `rule`, `description`, `action` |
| `correlation_id` | `correlation_id`, `action_id`, `request_id`, `trace_id`, `alert_id`, `session_id` |

Timestamp values may be an ISO 8601 string (`Z` or explicit offset), or a
Unix epoch in seconds or milliseconds. A naive (timezone-less) timestamp is
assumed UTC. A missing timestamp defaults to "now" in UTC.

## Normalized event shape

Both `/ingest/red` and `/ingest/blue` return, and `/timeline` / `/events`
list, events in this shape:

```json
{
  "event_id": "evt-<uuid4 hex>",
  "team": "red",
  "observed_at": "2026-08-17T11:00:00+08:00",
  "source_ip": "10.0.0.10",
  "destination": "10.0.0.20",
  "action_result": "ok",
  "event_type": "red.action",
  "source": "red-team-api",
  "actor": null,
  "message": "nmap -sV 10.0.0.20",
  "correlation_id": "example-1",
  "metadata": { "...": "the original request body, unmodified" }
}
```

`POST /ingest/*` wraps this as `{"inserted": true|false, "event": {...}}`.
`inserted` is `false` when an event with the same `event_id` was already
stored (idempotent replay).

## Raw payload preservation

Every ingest call is stored twice: once normalized (used for
timeline/analysis), and once as the untouched original JSON body. If an
adapter mapping turns out to be wrong, the raw payload can be reprocessed
later without having lost anything.

## Correlation logic

`GET /analysis` pairs each Red event with a Blue event and classifies it:

1. **Exact match** — same `correlation_id` on both sides.
2. **Heuristic match** (only if no `correlation_id` match) — same
   `source_ip` and `destination` (when both sides provide them), earliest
   Blue event observed within **0–30 seconds after** the Red event.
3. **No match** → `visibility_gap` (Blue never saw it).

A matched pair is a:

- **`hit`** — the matched Blue event's `event_type` or `message` contains
  `alert`, `detect`, `detection`, or `firing` (case-insensitive).
- **`detection_gap`** — matched, but nothing in the Blue event reads as a
  detection (e.g. it's a benign log line, not an alert).

`/analysis` also reports `detection_rate`, `mttd_p50_ms`, and `mttd_p95_ms`
(latency computed only over `hit` pairs).

## Example

See [`examples/red-event.json`](../examples/red-event.json) and
[`examples/blue-event.json`](../examples/blue-event.json) — a matched pair
sharing `correlation_id: "example-1"`, five seconds apart, that should
produce one `hit`. [`scripts/smoke-test.ps1`](../scripts/smoke-test.ps1)
POSTs both and asserts exactly that.
