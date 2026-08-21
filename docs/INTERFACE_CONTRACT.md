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
| GET | `/analysis?limit=&caller=public\|purple` | Correlated Red→Blue detections + latency/gap summary, gap rows delayed for `public` (see [Correlation logic](#correlation-logic)) |
| GET | `/blue-scores` | Blue-team patch/vulnerability check snapshots (leak-filtered, public) |
| GET | `/blue-seats` | Blue-team seat names known to exist (from seat log directory, public) |
| GET | `/red-seats` | Red-team seat names known to exist (from seat log directory, public) |
| GET | `/possible-breaches` | Heuristic pivot-detection results (public, explicitly unconfirmed) |
| POST | `/admin/clear` (requires ingest token) | Truncate all event/score tables to reset for a new exercise |
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

Both `/ingest/red` and `/ingest/blue` return, and `/events` lists, events
in this shape:

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

`GET /analysis` (`src/rbcollector/analysis.py`, `correlate()`) produces one
row per Red event, plus separate rows for autonomous Blue fixes that have
no Red event to anchor to. Three independent paths, tried in this order for
each Red event:

1. **Alert path** (`detection_method="alert"`) — same `correlation_id` on
   both sides, or a heuristic match (same `source_ip`+`destination`,
   earliest Blue event within **0–30s after** the Red event) whose
   `event_type`/`message` contains `alert`, `detect`, `detection`, or
   `firing`. This is the path for a real automated alerting/IDS system —
   this deployment currently has none wired up, so in practice this path
   never fires; every observed `hit` today comes from path 2 or 3 below.
2. **Response path** (`detection_method="response"`) — only tried when
   path 1 doesn't produce a `hit`. Looks **5 minutes forward** from the
   Red event (a separate, wider window from path 1's 30s — deliberately
   not just "path 1 with a bigger number", to avoid diluting real-time
   detection accuracy) for **both** of: (a) a Blue cmdlog line containing
   a response keyword (`chmod`, `chown`, `iptables`, `ufw`,
   `firewall-cmd`, `nft `, `drop`, `deny`, `block`, `rm -f`,
   `delete from`, `sudoers`), and (b) a `blue.remediation` event (emitted
   by `blue_score_receiver.py` when a checker.py vulnerability check
   flips fail→pass). Both signals are required — the keyword alone might
   be a typo'd command that didn't actually fix anything; the
   remediation event alone doesn't prove it's related to this Red action.
3. **No match on either path** → `visibility_gap` if there was no Blue
   event nearby at all, `detection_gap` if something matched on timing
   but wasn't recognized as a detection/response.
4. **Autonomous fixes** (`detection_method="autonomous"`, `red: null`) —
   after all Red events are processed, any `blue.remediation` event not
   already claimed by path 2 above gets its own row if a response-keyword
   cmdlog line exists within the preceding 5 minutes. This is how a Blue
   team fix that happened with **no Red action at all** still shows up.

`/analysis` also reports `detection_rate`, `mttd_p50_ms`, and `mttd_p95_ms`
(latency computed only over `hit` rows that have a Red anchor).

The `correlations` array is visibility-filtered by `src/rbcollector/disclosure.py`,
not by a fixed clearance tier: **`hit` rows are public immediately**
(detection success isn't something to hide from the audience — see the
module docstring for why this differs from cyber's model). `detection_gap`/
`visibility_gap` rows are `purple`-only for the first `GAP_REVEAL_DELAY_SECONDS`
(60s) after the Red event, then become public too — revealing "Blue hasn't
caught this yet" immediately would tip Blue off on a public battleboard.
`caller=purple` (with a valid bearer token) skips the delay entirely. The
aggregate numbers (`detection_rate`, `mttd_*`, gap counts) are never
filtered — only the per-row detail is, and only for that 60s window.
Raw evidence (`/events/{event_id}/context`) is a separate, always
`purple`-only concern — see [Evidence context](#evidence-context).

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
