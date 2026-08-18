"""Endpoint-level tests for the caller/clearance boundary.

Deliberately not just unit-testing disclosure.py/evidence.py in isolation --
that's how the original gap shipped: visibility_for_correlation() was
correct and unit-tested, but server.py never called it, so /analysis leaked
purple-only rows to everyone. These tests exercise the actual routes.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

import rbcollector.server as server_module


class FakeStore:
    def __init__(self, events):
        self._events = events

    def ensure_schema(self):
        pass

    def ping(self):
        pass

    def list_events(self, team=None, limit=500):
        rows = [e for e in self._events if team is None or e["team"] == team]
        return rows[:limit]

    def context(self, event_id, window_minutes=5):
        return [] if any(e.get("event_id") == event_id for e in self._events) else None


HIT_PAIR = [
    {
        "event_id": "evt-red-1", "team": "red", "observed_at": "2026-08-17T11:00:00+00:00",
        "source_ip": "10.0.0.10", "destination": "10.0.0.20", "correlation_id": "a-1",
        "event_type": "red.action", "message": "scan",
    },
    {
        "event_id": "evt-blue-1", "team": "blue", "observed_at": "2026-08-17T11:00:05+00:00",
        "source_ip": "10.0.0.10", "destination": "10.0.0.20", "correlation_id": "a-1",
        "event_type": "blue.alert", "message": "scan detected",
    },
]

GAP_ONLY = [
    {
        "event_id": "evt-red-2", "team": "red", "observed_at": "2026-08-17T12:00:00+00:00",
        "source_ip": "10.0.0.11", "destination": "10.0.0.21", "correlation_id": "b-1",
        "event_type": "red.action", "message": "exfil",
    },
]


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("INGEST_TOKEN", "secret")
    server_module.store = FakeStore(HIT_PAIR + GAP_ONLY)
    return TestClient(server_module.app)


def test_analysis_public_default_sees_gap_rows(client):
    # 2026-08-18 起 gap 也是 public 可見（見 disclosure.py 模組
    # docstring）——Battleboard 是公開戰況板，「藍隊有沒有抓到」本身就是
    # 要秀給觀眾看的資訊。
    resp = client.get("/analysis")
    assert resp.status_code == 200
    statuses = {row["status"] for row in resp.json()["correlations"]}
    assert statuses == {"hit", "visibility_gap"}


def test_analysis_public_hides_gap_row_that_just_happened(client):
    # gap 揭露有延遲（見 disclosure.py 的 GAP_REVEAL_DELAY_SECONDS）——剛
    # 發生的紅隊行動就算比對不到藍隊事件，public 這一刻也還不該看到，不
    # 然等於把「藍隊漏了」即時洩題給藍隊照著補救。
    fresh_gap = [{
        "event_id": "evt-red-3", "team": "red", "observed_at": datetime.now(timezone.utc).isoformat(),
        "source_ip": "10.0.0.12", "destination": "10.0.0.22", "correlation_id": "c-1",
        "event_type": "red.action", "message": "just happened",
    }]
    server_module.store = FakeStore(HIT_PAIR + fresh_gap)

    public_statuses = {row["status"] for row in client.get("/analysis").json()["correlations"]}
    assert public_statuses == {"hit"}

    # purple 不受揭露延遲影響，同一時刻已經看得到。
    purple_resp = client.get("/analysis?caller=purple", headers={"Authorization": "Bearer secret"})
    purple_statuses = {row["status"] for row in purple_resp.json()["correlations"]}
    assert "visibility_gap" in purple_statuses


def test_analysis_purple_without_token_rejected(client):
    resp = client.get("/analysis?caller=purple")
    assert resp.status_code == 401


def test_analysis_purple_with_token_sees_gap_rows(client):
    resp = client.get("/analysis?caller=purple", headers={"Authorization": "Bearer secret"})
    assert resp.status_code == 200
    statuses = {row["status"] for row in resp.json()["correlations"]}
    assert "visibility_gap" in statuses


def test_event_context_purple_without_token_rejected(client):
    resp = client.get("/events/evt-red-1/context?caller=purple")
    assert resp.status_code == 401


def test_event_context_purple_with_token_accepted(client):
    resp = client.get("/events/evt-red-1/context?caller=purple", headers={"Authorization": "Bearer secret"})
    assert resp.status_code == 200


def test_event_context_public_needs_no_token(client):
    resp = client.get("/events/evt-red-1/context")
    assert resp.status_code == 200
    assert resp.json()["lines"] == []
