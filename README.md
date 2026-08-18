# Red/Blue Log Collector

Standalone Red/Blue telemetry collector extracted from patterns already implemented in `Graylee0128/cyber`.

The goal is deliberately narrow: accept two team interfaces, preserve their raw payloads, normalize both into one correlation-friendly event contract, and expose a merged timeline for later analysis.

## What was reused from `cyber`

This repository is not a greenfield rewrite. It keeps the useful boundaries already proven in the `cyber` Purple pipeline:

- **HTTP receiver boundary** from `src/purple/receiver/server.py`
- **adapter isolation** from `src/purple/receiver/adapters.py`
- **event-id + normalization pattern** from `src/purple/receiver/core.py`
- **four-field telemetry contract** from `src/purple/telemetry_fields.py`
  - `source_ip`
  - `destination`
  - `time` → `observed_at`
  - `action_result`
- **PostgreSQL event storage + idempotency pattern** from `src/purple/store/events.py`
- **Dockerized receiver pattern** from `deploy/receiver/Dockerfile`

Cyber-range-specific concepts (exercise/scenario, Grafana webhook lifecycle, response agent, Falco rules, disclosure/visibility) were intentionally removed from this standalone collector.

## Run

```bash
docker compose up -d --build
curl http://localhost:8001/healthz
```

API docs:

```text
http://localhost:8001/docs
```

## Smoke test

```powershell
pwsh scripts/smoke-test.ps1
```

Brings the stack up, POSTs [`examples/red-event.json`](examples/red-event.json)
and [`examples/blue-event.json`](examples/blue-event.json), and asserts the
full pipeline actually produces a correlated `hit` on `/timeline` and
`/analysis` — not just a 200 on ingest.

## Red ingestion

```bash
curl -X POST http://localhost:8001/ingest/red \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $INGEST_TOKEN" \
  -d '{
    "timestamp":"2026-08-17T11:00:00+08:00",
    "src_ip":"10.0.0.10",
    "target_ip":"10.0.0.20",
    "command":"nmap -sV 10.0.0.20",
    "result":"ok"
  }'
```

## Blue ingestion

```bash
curl -X POST http://localhost:8001/ingest/blue \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $INGEST_TOKEN" \
  -d '{
    "time":"2026-08-17T11:00:05+08:00",
    "attacker_ip":"10.0.0.10",
    "host":"web-01",
    "alert":"Port scan detected",
    "severity":"high"
  }'
```

The `Authorization` header is only enforced when the collector's `INGEST_TOKEN`
environment variable is set (see [Exposing to other VMs](#exposing-to-other-vms)).
It's unset by default, so local/dev requests without a token still work.

## Query merged timeline

```bash
curl 'http://localhost:8001/timeline?limit=500'
```

Or one side only:

```bash
curl 'http://localhost:8001/events?team=red'
curl 'http://localhost:8001/events?team=blue'
```

## Grafana

```bash
docker compose up -d --build grafana
```

Open `http://<host>:3000` (default login `admin`/`admin`). The `Purple
Collector Postgres` data source is provisioned automatically from
[`deploy/grafana/provisioning/datasources/datasources.yaml`](deploy/grafana/provisioning/datasources/datasources.yaml)
and points at the `collector` Postgres above — build SQL panels against the
`normalized_events` / `raw_events` tables there.

This is **not** a drop-in for cyber's Blue SOC dashboard: that one queries
Loki/Prometheus, which this standalone stack does not run. Dashboards here
need to be built fresh against the Postgres schema.

**Disclosure boundary applies here too.** `GF_AUTH_ANONYMOUS_ENABLED=true`
means anyone who can reach `:3000` sees provisioned dashboards with no
login — and Grafana's Postgres datasource queries `normalized_events`
directly, bypassing the collector API entirely, so `require_purple_clearance`
(see [Authentication](docs/INTERFACE_CONTRACT.md#authentication)) does not
apply to it. Any panel built here must not query raw per-event detail
(`message`, `actor`, `source_ip`, `destination`, ...) without a `WHERE`
clause that keeps it to safe-to-publish rows — see the provisioned
`purple-collector-overview` dashboard's "最新藍隊偵測事件" panel for the
pattern (blue-team rows that read as a detection only; never a bare red
action, which is exactly what a `visibility_gap` is). Aggregate-only panels
(counts, distributions, timeseries) don't need this restriction.

## Exposing to other VMs

`docker-compose.yml`'s `"8001:8000"` port mapping already binds to all
interfaces on the collector host, not just `localhost` — a source VM on the
same network can already reach it once the host firewall/security group
allows the port. What's missing before doing that for real (see
[issue #1](../../issues/1)):

1. **Set a shared bearer token.** Export `INGEST_TOKEN` before `docker compose
   up` (it's passed through by `docker-compose.yml`). While unset, `/ingest/*`
   accepts unauthenticated requests (local/dev only) — anyone who can reach
   the port can write fake events. Once set, every `POST /ingest/*` call must
   send `Authorization: Bearer <token>`; requests without it get `401`.
2. **Open the port** for the source VM(s) specifically, not `0.0.0.0/0`.
3. **Ship logs from the VM.** [`scripts/forwarder-template.sh`](scripts/forwarder-template.sh)
   is a minimal starting point (tail a log file, POST each line with the
   bearer token) per issue #1's Option A. It sends `{"message": line, ...}` —
   replace that payload construction with real field mapping once the actual
   Red/Blue log format is known, using the aliases in
   [`docs/INTERFACE_CONTRACT.md`](docs/INTERFACE_CONTRACT.md).

**Not adopted (for now):** [issue #2](../../issues/2) proposed replacing this
HTTP-push model with cyber's Alloy/Loki tail-and-ship pipeline. That's a more
proven mechanism, but it also raises the open question of whether this
collector's Postgres/`/analysis` half should keep existing at all — see the
issue for the full tradeoff. Decision: keep this collector's ingestion path
as-is (bearer-token HTTP push, per Option A) since it's the smaller change and
this repo's correlation/MTTD logic doesn't have an obvious Loki equivalent.
Revisit if/when raw-log volume or multi-consumer needs (e.g. Grafana wanting
the same logs) make a shared Loki backend worth the added infra.

## Real log source forwarders

Two concrete forwarders, built on the `forwarder-template.sh` pattern, for
the actual log sources currently in use:

- [`scripts/forward-red-bash-history.sh`](scripts/forward-red-bash-history.sh)
  — red-team command log → `/ingest/red`. Plain `~/.bash_history` isn't
  reliable to tail live (it's only flushed periodically); the script's
  header comment includes a `PROMPT_COMMAND` snippet to log each command
  with a timestamp as it runs.
- [`scripts/forward-blue-authlog.sh`](scripts/forward-blue-authlog.sh) —
  `/var/log/auth.log` (Debian/Ubuntu; use `/var/log/secure` on RHEL) →
  `/ingest/blue`. Lines matching common failed-auth keywords are tagged
  `event_type=blue.alert` so they're recognized as detections.

Run each on its respective VM:

```bash
COLLECTOR_URL=http://<collector-ip>:8001 INGEST_TOKEN=<token> \
  ./scripts/forward-red-bash-history.sh ~/red-command.log

COLLECTOR_URL=http://<collector-ip>:8001 INGEST_TOKEN=<token> \
  ./scripts/forward-blue-authlog.sh /var/log/auth.log
```

**Correlation caveat:** neither source has a shared `correlation_id`, so
matching falls back to the IP/destination heuristic in
[`docs/INTERFACE_CONTRACT.md`](docs/INTERFACE_CONTRACT.md#correlation-logic).
That only works if the red-team command's target IP (extracted from the
command text) and the blue VM's own IP (used as `destination`) are the same
*string* — e.g. the red operator ran `ssh 10.0.0.20` and the blue VM's
`hostname -I` also resolves to `10.0.0.20`. If red types a hostname instead
of an IP, or the blue VM has multiple interfaces, matching will silently
miss and everything shows up as `visibility_gap` even though detection
happened. Check `/analysis` after a test action — if hits aren't showing up
despite both events being on `/timeline`, this is the first thing to check.

## Metis syslog receiver

The forwarder scripts above are for sources that can run a script and speak
HTTP. Metis's own log plane (`deploy/logship.sh`, 架構 §十一) doesn't --
collection happens on the host, not in a container, and it ships over
**rsyslog TCP**, not HTTP: `LOG_SINK=<this-collector-host>:514`.

[`src/rbcollector/syslog_receiver.py`](src/rbcollector/syslog_receiver.py) is
a small asyncio TCP server that speaks that protocol directly — it parses
Metis's RFC5424 lines (`<PRI>1 TIMESTAMP HOSTNAME APP-NAME - - [metis@1
src="<file>" role="<red|blue|host>"] MSG`), rebuilds the same ingest payload
shape the manual forwarders above construct from raw log lines, and calls
the adapters/store directly — no second network hop through the HTTP API,
and no separate deployment: it's the same image, just a different command
(the `syslog-receiver` service in `docker-compose.yml`).

```bash
docker compose up -d --build syslog-receiver
```

Host `:514` maps to the container's `:5140` — the container never needs
root/`CAP_NET_BIND_SERVICE` to bind a privileged port, Docker's own port
mapping handles that. Point Metis's `LOG_SINK` at `<this-host>:514`.

`role="host"` lines (docker-events, audit) aren't red/blue team activity —
there's no normalized_events row for those (yet); they're logged and
skipped. `role="red"`/`role="blue"` map the same way the manual forwarders
do, so the same correlation caveat above applies here too.

## Interface contract

See [`docs/INTERFACE_CONTRACT.md`](docs/INTERFACE_CONTRACT.md) for the full
field-alias table, normalized event shape, and correlation logic — this is
what to hand the Red/Blue teams instead of the source code.

## When the real interfaces arrive

Do **not** rewrite the collector. Only update:

```text
src/rbcollector/adapters/red.py
src/rbcollector/adapters/blue.py
```

The storage/API contract stays stable.

A recommended minimum producer contract is:

```json
{
  "timestamp": "2026-08-17T11:00:00+08:00",
  "source_ip": "10.0.0.10",
  "destination": "10.0.0.20",
  "action_result": "ok",
  "event_type": "red.action",
  "message": "...",
  "correlation_id": "optional-but-highly-recommended"
}
```

## Why raw events are stored separately

Adapters will change when the Red/Blue teams publish their real schemas. Keeping the producer payload in `raw_events` means a bad early mapping can be reprocessed later without losing the original evidence.
