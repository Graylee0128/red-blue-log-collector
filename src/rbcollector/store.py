from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Iterator

import psycopg
from psycopg.types.json import Jsonb

DEFAULT_DATABASE_URL = "postgresql://collector:collector@postgres:5432/collector"

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


class EventStore:
    def __init__(self, database_url: str) -> None:
        self.database_url = database_url

    @classmethod
    def from_env(cls) -> "EventStore":
        return cls(os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL))

    @contextmanager
    def _connect(self) -> Iterator[psycopg.Connection]:
        conn = psycopg.connect(self.database_url)
        try:
            yield conn
        finally:
            conn.close()

    def ping(self) -> None:
        with self._connect() as conn:
            conn.execute("SELECT 1")

    def ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(SCHEMA_SQL)
            conn.commit()

    def append(self, team: str, raw_payload: dict[str, Any], event: dict[str, Any]) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                """
                INSERT INTO normalized_events (
                  event_id, team, observed_at, source_ip, destination, action_result,
                  event_type, source, actor, message, correlation_id, event
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (event_id) DO NOTHING
                RETURNING event_id
                """,
                (
                    event.get("event_id"), team, event.get("observed_at"), event.get("source_ip"),
                    event.get("destination"), event.get("action_result"), event.get("event_type"),
                    event.get("source"), event.get("actor"), event.get("message"),
                    event.get("correlation_id"), Jsonb(event),
                ),
            ).fetchone()
            inserted = row is not None
            if inserted:
                conn.execute(
                    "INSERT INTO raw_events(event_id, team, payload) VALUES (%s,%s,%s)",
                    (event.get("event_id"), team, Jsonb(raw_payload)),
                )
            conn.commit()
            return inserted

    def list_events(self, team: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 5000))
        with self._connect() as conn:
            if team:
                rows = conn.execute(
                    "SELECT event FROM normalized_events WHERE team=%s ORDER BY observed_at ASC LIMIT %s",
                    (team, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT event FROM normalized_events ORDER BY observed_at ASC LIMIT %s",
                    (limit,),
                ).fetchall()
        return [row[0] for row in rows]
