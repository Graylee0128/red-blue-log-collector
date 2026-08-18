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

## issue #3: purple detection/scoring line migration

Second migration pass (issue #3), after Metis took over admission/seat
provisioning and cyber's own admission/range_core stepped back. Six items,
all landed:

- `deploy/grafana/provisioning/alerting/rules.yaml` (9→11 Loki/Prometheus
  rules) → `src/rbcollector/detections.py`: same match/window/threshold
  semantics, rewritten as a declarative rule list evaluated directly
  against `normalized_events` -- no Grafana/Loki/Prometheus deployed.
  Two intentional detection gaps (account-discovery, egress-anomaly)
  carried over unchanged, not "completed".
- `src/purple/harness/waiting.py` → `tests/harness/waiting.py`: near-verbatim,
  it was already schema-agnostic.
- `src/purple/harness/schema.py` → `tests/harness/schema.py`: rewritten to
  validate `NormalizedEvent`'s shape instead of cyber's Core Event contract.
- `purple/evidence/resolver.py` + `backends.py` → `src/rbcollector/evidence.py`
  + `EventStore.context()`: collapses to one store query against this
  repo's own `raw_events` table -- no pluggable Loki backend needed.
- `disclosure/clearance.py` + `event_visibility.py` → `src/rbcollector/disclosure.py`:
  4-tier clearance (`public < blue < purple < instructor`) collapsed to 2
  (`public` vs `purple`); a correlation row's visibility is derived from
  its `hit`/`gap` status, not declared by the caller.
- `ui/purple/` + `ui/battleboard/` + `ui/assets/` → same paths here: layout
  skeleton kept, cyber-specific plumbing stripped (service-token gateway,
  Action Registry, SSE live stream, #153 Campaign Experience Layer, Range
  Core scoring). See the header comment in each `app.js` for what changed
  and why.

  **Removed since.** These three paths (and the `/ui` static mount in
  `server.py` that served them) were deleted after this migration landed
  -- kept side-by-side with `ui/purple-console/` (the standalone
  battleboard page, served separately on `:8090`) long enough to compare,
  then dropped in favor of that one. Mentioned here only so this lineage
  note doesn't point at paths that no longer exist.

Grafana/Loki/Prometheus themselves are not deployed here (deliberate --
see detections.py above). `purple/response/agent.py` (automatic
containment) was not migrated -- out of scope for this repo.

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
