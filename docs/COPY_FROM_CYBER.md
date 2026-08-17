# Copy lineage from `Graylee0128/cyber`

This repository is intentionally **copy-first**, not a greenfield rewrite.

## Copied concepts/components

The following reusable Purple-side pieces from `cyber` are the source of truth for this standalone collector design:

- `src/purple/receiver/adapters.py` → adapter boundary
- `src/purple/receiver/core.py` → pure normalization/event construction pattern
- `src/purple/store/events.py` → PostgreSQL event store + idempotent insert pattern
- `src/purple/telemetry_fields.py` → normalized telemetry field contract
- `src/purple/evaluation/latency.py` → MTTD/MTTR/containment semantics
- `src/purple/metrics/gaps.py` → hit / detection gap / visibility gap semantics
- `deploy/receiver/Dockerfile` → containerized receiver pattern

Selected original/reference files are retained under `vendor/cyber/` so the lineage remains visible.

## Pruned cyber-specific coupling

The standalone collector intentionally removes or optionalizes:

- `exercise_id`
- `scenario_id`
- Grafana firing/resolved lifecycle assumptions
- Falco-specific source assumptions
- response-agent/containment execution
- range scoring/UI/admission logic

## Standalone additions

Runtime code lives in `src/rbcollector/` and adds:

- `POST /ingest/red`
- `POST /ingest/blue`
- Red/Blue provider adapters
- raw payload preservation
- normalized event storage
- merged timeline
- basic correlation and gap/latency summary

When the real Red/Blue API contracts arrive, only `src/rbcollector/adapters/red.py` and `src/rbcollector/adapters/blue.py` should need provider-specific mapping changes.
