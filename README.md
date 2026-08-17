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
curl http://localhost:8000/healthz
```

API docs:

```text
http://localhost:8000/docs
```

## Red ingestion

```bash
curl -X POST http://localhost:8000/ingest/red \
  -H 'Content-Type: application/json' \
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
curl -X POST http://localhost:8000/ingest/blue \
  -H 'Content-Type: application/json' \
  -d '{
    "time":"2026-08-17T11:00:05+08:00",
    "attacker_ip":"10.0.0.10",
    "host":"web-01",
    "alert":"Port scan detected",
    "severity":"high"
  }'
```

## Query merged timeline

```bash
curl 'http://localhost:8000/timeline?limit=500'
```

Or one side only:

```bash
curl 'http://localhost:8000/events?team=red'
curl 'http://localhost:8000/events?team=blue'
```

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
