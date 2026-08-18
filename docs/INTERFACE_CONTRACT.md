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
| GET | `/analysis?limit=&caller=public\|purple` | Correlated Red→Blue detections + latency/gap summary, clearance-filtered |
| GET | `/events/{event_id}/context?caller=public\|purple&window_minutes=` | Raw payload context window around one event, clearance-filtered |

## Authentication

`POST /ingest/red` and `POST /ingest/blue` require an `Authorization: Bearer
<token>` header whenever the collector's `INGEST_TOKEN` environment variable
is set. A missing or wrong token returns `401`. If `INGEST_TOKEN` is unset
(the local/dev default), no auth is enforced. See
[Exposing to other VMs](../README.md#exposing-to-other-vms) in the README.

`caller=purple` on `/analysis` and `/events/{event_id}/context` requires the
same bearer token — `caller` is a client-supplied query parameter, so
without this check anyone could pass `?caller=purple` and read purple-only
data. `caller=public` (the default) needs no token; it's already the
filtered/safe view. There's no separate purple-specific secret: holding the
ingest token is what "being a legitimate Red/Blue/purple consumer" means in
this collector's single-shared-secret model.

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

The `correlations` array itself is clearance-filtered: `detection_gap` and
`visibility_gap` rows carry full raw Red/Blue event detail and are dropped
entirely unless the caller passes `?caller=purple` with a valid bearer
token (see [Authentication](#authentication)) — the default `public` view
only ever sees `hit` rows. The aggregate numbers (`detection_rate`,
`mttd_*`, gap counts) are not filtered; only the per-row detail is.

## Detection rules

Each correlation row is additionally tagged with `rule_id`, `technique`
(an ATT&CK ID like `T1190`), and `severity` when the **red** side of the
pair matches one of the data-driven rules in `src/rbcollector/detections.py`
(standalone replacement for cyber's Grafana alert rules -- no
Grafana/Loki/Prometheus deployed here). All three are `null` when nothing
matched. This tagging never changes a row's `hit`/`detection_gap`/
`visibility_gap` status, only adds context to it.

## Evidence context

`GET /events/{event_id}/context` returns the raw ingest payloads (both
teams) observed within `window_minutes` (default 5) of the given event's
`observed_at`, pulled from the `raw_events` table -- not a separate
telemetry backend. `caller` decides visibility (see
`src/rbcollector/disclosure.py`): `public` always gets an empty `lines`
list (raw payloads are purple-only telemetry detail); `purple` sees
everything, but only with a valid bearer token (see
[Authentication](#authentication) -- `caller` alone isn't proof of
clearance). An unknown `event_id` is a 404, not an empty result.

## Example

See [`examples/red-event.json`](../examples/red-event.json) and
[`examples/blue-event.json`](../examples/blue-event.json) — a matched pair
sharing `correlation_id: "example-1"`, five seconds apart, that should
produce one `hit`. [`scripts/smoke-test.ps1`](../scripts/smoke-test.ps1)
POSTs both and asserts exactly that.
