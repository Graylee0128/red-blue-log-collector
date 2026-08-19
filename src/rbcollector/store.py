from __future__ import annotations

import os
from contextlib import contextmanager
from datetime import datetime, timedelta
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
-- 藍隊修補進度（issue #22）：checker.py 的 leaderboard_<target>.json 快照，
-- 一個 target 只留最新一筆（跟 admission_live_state 同樣的「快照不是事件
-- 串流」設計），不是 normalized_events 那種可累積、可關聯的事件。
CREATE TABLE IF NOT EXISTS blue_scores (
  target TEXT PRIMARY KEY,
  total_score INTEGER NOT NULL,
  max_score INTEGER NOT NULL,
  checks JSONB NOT NULL,
  observed_at TIMESTAMPTZ NOT NULL,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- 疑似突破（issue #21）：breach_detector.py 的啟發式 pivot 偵測結果——
-- 終端機視窗標題出現跟這個席位自己不同的 hostname，是推論不是確認過的
-- 事實。layer 是「第幾層 pivot」推論出的外網／內網（見 breach_detector.py
-- 的 find_pivot_targets() docstring），不是解析容器名稱得來的。同一個
-- (seat, target_host) 只留第一次看到的時間跟 layer，冪等寫入。
CREATE TABLE IF NOT EXISTS possible_breaches (
  id BIGSERIAL PRIMARY KEY,
  seat TEXT NOT NULL,
  target_host TEXT NOT NULL,
  layer TEXT NOT NULL CHECK (layer IN ('external','internal')),
  observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (seat, target_host)
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

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT event FROM normalized_events WHERE event_id=%s", (event_id,)
            ).fetchone()
        return row[0] if row else None

    def context(self, event_id: str, window_minutes: int = 5) -> list[dict[str, Any]] | None:
        """`event_id` 的 `observed_at` 前後 `window_minutes` 內、兩隊皆包含
        的原始 payload。`event_id` 不存在時回傳 None——跟「查得到但確實
        是空清單」要分開，不能混為一談。"""
        event = self.get_event(event_id)
        if event is None:
            return None
        observed_at = datetime.fromisoformat(str(event["observed_at"]).replace("Z", "+00:00"))
        window = timedelta(minutes=window_minutes)

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT r.team, r.payload, r.received_at, n.observed_at
                FROM raw_events r
                JOIN normalized_events n ON n.event_id = r.event_id
                WHERE n.observed_at BETWEEN %s AND %s
                ORDER BY n.observed_at ASC
                """,
                (observed_at - window, observed_at + window),
            ).fetchall()
        return [
            {
                "team": team,
                "payload": payload,
                "observed_at": row_observed_at.isoformat(),
                "received_at": received_at.isoformat(),
            }
            for team, payload, received_at, row_observed_at in rows
        ]

    def upsert_blue_score(
        self, *, target: str, total_score: int, max_score: int, checks: list[dict[str, Any]], observed_at: str
    ) -> None:
        """寫入/更新一個 target 的最新分數快照——同一個 target 只留最新一筆
        （ON CONFLICT DO UPDATE），跟 normalized_events 的 append-only 不同。"""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO blue_scores (target, total_score, max_score, checks, observed_at)
                VALUES (%s,%s,%s,%s,%s)
                ON CONFLICT (target) DO UPDATE SET
                  total_score = EXCLUDED.total_score,
                  max_score = EXCLUDED.max_score,
                  checks = EXCLUDED.checks,
                  observed_at = EXCLUDED.observed_at,
                  recorded_at = now()
                """,
                (target, total_score, max_score, Jsonb(checks), observed_at),
            )
            conn.commit()

    def list_blue_scores(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT target, total_score, max_score, checks, observed_at FROM blue_scores ORDER BY target"
            ).fetchall()
        return [
            {
                "target": target,
                "total_score": total_score,
                "max_score": max_score,
                "checks": checks,
                "observed_at": observed_at.isoformat(),
            }
            for target, total_score, max_score, checks, observed_at in rows
        ]

    def record_possible_breach(self, *, seat: str, target_host: str, layer: str) -> bool:
        """issue #21 的啟發式 pivot 偵測結果——同一個 (seat, target_host)
        只留第一次看到的時間跟 layer，重複呼叫是安全的冪等操作。回傳是不是
        新插入（前端／呼叫端目前不需要，保留跟 append() 一致的回傳慣例）。"""
        with self._connect() as conn:
            row = conn.execute(
                """
                INSERT INTO possible_breaches (seat, target_host, layer)
                VALUES (%s,%s,%s)
                ON CONFLICT (seat, target_host) DO NOTHING
                RETURNING id
                """,
                (seat, target_host, layer),
            ).fetchone()
            conn.commit()
            return row is not None

    def list_possible_breaches(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT seat, target_host, layer, observed_at FROM possible_breaches ORDER BY observed_at ASC"
            ).fetchall()
        return [
            {"seat": seat, "target_host": target_host, "layer": layer, "observed_at": observed_at.isoformat()}
            for seat, target_host, layer, observed_at in rows
        ]

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
