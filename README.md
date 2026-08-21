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

## Purple Console (battleboard)

```bash
docker compose up -d --build purple-console
```

Open `http://<host>:8090`. A standalone, self-contained battleboard page
(no external JS/CSS deps beyond Google Fonts, no backend of its own) —
served by its own nginx container, separate from the collector API. This
is the only front-end in the repo now; the cyber-derived `/ui/purple/`
and `/ui/battleboard/` (a tabbed analyst console served by the collector
itself) were kept side-by-side for comparison and then removed — see
`docs/COPY_FROM_CYBER.md` if that lineage matters later.

The top stat row and the center correlation timeline are **real** —
polled from `GET /analysis?caller=purple` every 8s (set the collector API
URL and, if `INGEST_TOKEN` is configured, a bearer token in the controls
bar; both persist in `localStorage`). Everything else on the board — the
attacker/external/internal topology, the blue patch grid/score, the
red/blue shell tails — has **no backing data model yet** and stays
demo/mock, clearly labeled as such on each panel. Wiring those up for real
needs: an IP-to-role mapping (attacker vs. DMZ vs. internal), a real
scoring source, and a raw-log-tail endpoint respectively.

`caller=purple` matters here specifically because `detection_gap` /
`visibility_gap` rows are purple-clearance-only (see the disclosure note
above) — with `caller=public` (or no token when `INGEST_TOKEN` is set) the
timeline would only ever show hits, silently hiding every gap, which
defeats the point of a gap-visibility board.

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
3. **Ship logs from the VM.** The real Red/Blue log format (Metis's seat
   logs) is known now, so this collector reads it directly instead —
   see [Real log source](#real-log-source) below. A generic tail-and-POST
   forwarder script is no longer needed for that path; write one only if a
   future source can't be read directly by a host-mounted receiver.

**Not adopted (for now):** [issue #2](../../issues/2) proposed replacing this
HTTP-push model with cyber's Alloy/Loki tail-and-ship pipeline. That's a more
proven mechanism, but it also raises the open question of whether this
collector's Postgres/`/analysis` half should keep existing at all — see the
issue for the full tradeoff. Decision: keep this collector's ingestion path
as-is (bearer-token HTTP push, per Option A) since it's the smaller change and
this repo's correlation/MTTD logic doesn't have an obvious Loki equivalent.
Revisit if/when raw-log volume or multi-consumer needs (e.g. Grafana wanting
the same logs) make a shared Loki backend worth the added infra.

## Real log source

The forwarder-script approach above was written before Metis's actual log
format was known. It's superseded now: Metis writes red/blue terminal
activity straight to host files (`/var/log/metis/seat/<seat>.cmd`), and
[`seat_log_receiver.py`](src/rbcollector/seat_log_receiver.py) tails that
directory directly (bind-mounted read-only into the `seat-log-receiver`
container) — no forwarder script, no `/ingest/*` HTTP call, no bearer
token involved for this path. Team is inferred from the filename
(`red-*.cmd` vs `blue-{a,b}-*.cmd`).

[`blue_score_receiver.py`](src/rbcollector/blue_score_receiver.py) does the
same for blue-team scoring — see [Blue score receiver](#blue-score-receiver)
below.

The `/ingest/red` / `/ingest/blue` HTTP endpoints documented above still
exist and are still the right integration point for a log source Metis
*doesn't* already write to a file this collector can read (or for a future
non-Metis deployment) — just note they aren't on the current real data
path, only [`scripts/smoke-test.ps1`](scripts/smoke-test.ps1) exercises them
today.

## Blue score receiver

Metis's blue-team scoring (`blue/scoring-engine/checker.py`, 7 vulnerability
checks per seat, 5 formal + 2 hidden bonus, 20 pts each) has no API either —
it writes a `leaderboard_<target>.json` snapshot to a host directory every
time it re-checks. [`src/rbcollector/blue_score_receiver.py`](src/rbcollector/blue_score_receiver.py)
polls that directory directly (same "read Metis's own files" pattern as the
seat log receiver, issue #16), and applies the *same* leak filter
`checker.py` itself uses before pushing scores into the guest's container:
the 2 hidden bonus checks never surface via `GET /blue-scores` until all 5
formal checks pass, so this API is safe to expose publicly.

```bash
docker compose up -d --build blue-score-receiver
```

`BLUE_SCORE_DIR` needs to point at wherever `checker.py`/`auto_watch.sh` is
actually run from on the host — that isn't wired into Metis's own deploy
scripts yet (see issue #22), so the default in `docker-compose.yml` is a
placeholder, not a confirmed convention.

## Release

Image version must match semantic versioning (semver). To publish a new version:

1. Update `version` in [`pyproject.toml`](pyproject.toml):
   ```toml
   [project]
   version = "0.2.0"  # e.g., 0.1.0 → 0.2.0
   ```

2. Commit and create a git tag matching the version:
   ```bash
   git add pyproject.toml
   git commit -m "版本提升至 0.2.0"
   git tag v0.2.0      # Tag MUST start with 'v'
   git push origin main --tags
   ```

3. CI will:
   - Verify the tag version (`v0.2.0`) matches `pyproject.toml` (`0.2.0`)
   - Build and push the image with tags:
     - `ghcr.io/graylee0128/red-blue-log-collector:v0.2.0` (pinned release)
     - `ghcr.io/graylee0128/red-blue-log-collector:latest` (development/convenience)
   - Fail if versions don't match, with a clear error message

### Version mismatch

If CI fails with a version mismatch error, the tag was pushed but the image was
not built. Fix and retry:

```bash
# If tag was pushed but version is wrong:
git tag -d v0.2.0
git push origin :refs/tags/v0.2.0
# Then fix pyproject.toml and try again
```

### Consuming the image

- **Development:** Use `:latest` (always tracks main branch)
- **Production:** Use a pinned version tag (e.g. `:v0.2.0`). This repo's own
  [`docker-compose.yml`](docker-compose.yml) still builds the collector
  locally (`build: .`) rather than pulling a published tag — swap in an
  `image:` line like the one below if you're deploying the published image
  instead of building from source.

```yaml
services:
  collector:
    image: ghcr.io/graylee0128/red-blue-log-collector:v0.2.0
```

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
