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
-- 藍隊席位「存在」清單（issue #22 後續）——跟 blue_scores 分開存：
-- blue_scores 只有 checker.py 真的在跑、有回報分數的席位（目前已知
-- auto_watch.sh 只監控 blue-a-*，blue-b-* 完全不會出現在 blue_scores
-- 裡），這張表是從 seat log 目錄的檔案存在與否判斷「席位真的存在」，
-- 不受計分有沒有涵蓋到影響，讓前端的分母算得準。
CREATE TABLE IF NOT EXISTS blue_seats (
  seat TEXT PRIMARY KEY,
  first_seen TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- 紅隊席位「存在」清單——跟 blue_seats 對稱設計，seat_log_receiver.py
-- 本來就在 tail *.cmd，順手記，不用另開輪詢程式。攻擊拓樸面板的左側
-- 來源格用這個當自己的真實計數，不再跟右側靶機格數綁死（issue #21
-- 後續討論）。
CREATE TABLE IF NOT EXISTS red_seats (
  seat TEXT PRIMARY KEY,
  first_seen TIMESTAMPTZ NOT NULL DEFAULT now()
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
        """`CREATE TABLE IF NOT EXISTS` 在併發下不是完全安全的——多個服務
        （collector／各 receiver）幾乎同時啟動、同時呼叫這個方法時，兩個
        connection 都可能通過「這張表還不存在」的檢查後才各自去建，系統
        目錄本身的唯一鍵約束會讓其中一個撞成 UniqueViolation（實測在
        issue #41 新增第五個 receiver 後真的撞到過）。這不是真的建表
        失敗——對方那個 session 已經建好同一張表了，rollback 後重跑一次
        整份 SCHEMA_SQL，這次 IF NOT EXISTS 會看到表已存在直接跳過。"""
        with self._connect() as conn:
            try:
                conn.execute(SCHEMA_SQL)
                conn.commit()
            except psycopg.errors.UniqueViolation:
                conn.rollback()
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

    def get_blue_score(self, target: str) -> dict[str, Any] | None:
        """單一 target 目前存的快照（upsert 前的舊值）——issue #33 的
        blue_score_receiver.py 要拿它跟新報告 diff，找出哪一項 check 剛
        從 fail 翻 pass。跟 list_blue_scores() 用同一組欄位，只是只查一筆。"""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT target, total_score, max_score, checks, observed_at FROM blue_scores WHERE target=%s",
                (target,),
            ).fetchone()
        if row is None:
            return None
        target_, total_score, max_score, checks, observed_at = row
        return {
            "target": target_,
            "total_score": total_score,
            "max_score": max_score,
            "checks": checks,
            "observed_at": observed_at.isoformat(),
        }

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

    def record_known_blue_seat(self, *, seat: str) -> bool:
        """記一個「這個藍隊席位真的存在」——只留第一次看到的時間，冪等。
        跟 upsert_blue_score 不同，這裡沒有分數可更新，看到過一次就永遠
        算數（席位不會無緣無故消失）。"""
        with self._connect() as conn:
            row = conn.execute(
                "INSERT INTO blue_seats (seat) VALUES (%s) ON CONFLICT (seat) DO NOTHING RETURNING seat",
                (seat,),
            ).fetchone()
            conn.commit()
            return row is not None

    def list_known_blue_seats(self) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT seat FROM blue_seats ORDER BY seat").fetchall()
        return [seat for (seat,) in rows]

    def record_known_red_seat(self, *, seat: str) -> bool:
        """跟 record_known_blue_seat 對稱——只留第一次看到的時間，冪等。"""
        with self._connect() as conn:
            row = conn.execute(
                "INSERT INTO red_seats (seat) VALUES (%s) ON CONFLICT (seat) DO NOTHING RETURNING seat",
                (seat,),
            ).fetchone()
            conn.commit()
            return row is not None

    def list_known_red_seats(self) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT seat FROM red_seats ORDER BY seat").fetchall()
        return [seat for (seat,) in rows]

    def update_action_result(self, event_id: str, action_result: str) -> bool:
        """issue #41：把 cmdlog 事件關聯到的離開碼寫回既有事件——這筆事件
        本身已經由 seat_log_receiver.py 寫入（action_result 預設
        "unknown"），這裡只補這一欄。event JSONB 欄位也要同步更新，不然
        /events／/timeline 回傳的完整 JSON 跟這個獨立欄位會兜不起來。
        event_id 不存在時回傳 False，不拋例外——呼叫端（exit_code_receiver.py）
        是背景輪詢，單筆事件消失或還沒寫入不該讓整輪處理中斷。"""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT event FROM normalized_events WHERE event_id=%s", (event_id,)
            ).fetchone()
            if row is None:
                return False
            event = dict(row[0])
            event["action_result"] = action_result
            conn.execute(
                "UPDATE normalized_events SET action_result=%s, event=%s WHERE event_id=%s",
                (action_result, Jsonb(event), event_id),
            )
            conn.commit()
            return True

    def clear_all(self) -> None:
        """issue #38 選項 2：一鍵清空目前所有演練資料（六張表全部
        TRUNCATE），準備下一局用。不動 host 端的 leaderboard/seat log 檔案
        ——那些不在這個容器的寫入權限範圍內（volume mount 是唯讀），是
        Metis 那邊的責任，不是這個方法要解決的範圍（見 issue #38 討論）。
        清完資料庫後，如果 host 上還留著舊檔案，seat-log-receiver／
        blue-score-receiver 下一輪輪詢還是會把舊資料重新寫回來——這是
        已知限制，要靠 Metis 那邊在開新一局時清掉自己的殘留檔案。"""
        with self._connect() as conn:
            conn.execute(
                "TRUNCATE TABLE normalized_events, raw_events, blue_scores, "
                "possible_breaches, blue_seats, red_seats RESTART IDENTITY CASCADE"
            )
            conn.commit()

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
