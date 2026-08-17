from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Iterator

import psycopg
from psycopg.types.json import Jsonb

from rbcollector.models import NormalizedEvent

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://collector:collector@postgres:5432/collector")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS normalized_events (
  event_id TEXT PRIMARY KEY,
  team TEXT NOT NULL CHECK (team IN ('red','blue')),
  observed_at TIMESTAMPTZ NOT NULL,
  source_ip TEXT,
  destination TEXT,
  action_result TEXT,
  event_type TEXT NOT NULL,
  source TEXT NOT NULL,
  actor TEXT,
  message TEXT,
  correlation_id TEXT,
  event JSONB NOT NULL,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_events_time ON normalized_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_events_team_time ON normalized_events(team, observed_at);
CREATE INDEX IF NOT EXISTS idx_events_corr ON normalized_events(correlation_id) WHERE correlation_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_src_dst ON normalized_events(source_ip, destination);
CREATE TABLE IF NOT EXISTS raw_events (
  raw_id BIGSERIAL PRIMARY KEY,
  event_id TEXT NOT NULL REFERENCES normalized_events(event_id) ON DELETE CASCADE,
  team TEXT NOT NULL,
  payload JSONB NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""


@contextmanager
def connect() -> Iterator[psycopg.Connection]:
    conn = psycopg.connect(DATABASE_URL)
    try:
        yield conn
    finally:
        conn.close()


def ensure_schema() -> None:
    with connect() as conn:
        conn.execute(SCHEMA_SQL)
        conn.commit()


def append_event(event: NormalizedEvent, raw_payload: dict[str, Any]) -> bool:
    data = event.model_dump(mode="json")
    with connect() as conn:
        row = conn.execute(
            """
            INSERT INTO normalized_events (
              event_id, team, observed_at, source_ip, destination, action_result,
              event_type, source, actor, message, correlation_id, event
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (event_id) DO NOTHING
            RETURNING event_id
            """,
            (event.event_id, event.team, event.observed_at, event.source_ip, event.destination,
             event.action_result, event.event_type, event.source, event.actor, event.message,
             event.correlation_id, Jsonb(data)),
        ).fetchone()
        inserted = row is not None
        if inserted:
            conn.execute("INSERT INTO raw_events(event_id, team, payload) VALUES (%s,%s,%s)",
                         (event.event_id, event.team, Jsonb(raw_payload)))
        conn.commit()
        return inserted


def list_events(team: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 5000))
    with connect() as conn:
        if team:
            rows = conn.execute("SELECT event FROM normalized_events WHERE team=%s ORDER BY observed_at DESC LIMIT %s", (team, limit)).fetchall()
        else:
            rows = conn.execute("SELECT event FROM normalized_events ORDER BY observed_at DESC LIMIT %s", (limit,)).fetchall()
    return [row[0] for row in rows]


def timeline(limit: int = 500) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 5000))
    with connect() as conn:
        rows = conn.execute("SELECT event FROM normalized_events ORDER BY observed_at ASC, recorded_at ASC LIMIT %s", (limit,)).fetchall()
    return [row[0] for row in rows]
