"""Endpoint-level tests for the caller/clearance boundary.

Deliberately not just unit-testing disclosure.py/evidence.py in isolation --
that's how the original gap shipped: visibility_for_correlation() was
correct and unit-tested, but server.py never called it, so /analysis leaked
purple-only rows to everyone. These tests exercise the actual routes.
"""
from __future__ import annotations

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


def test_analysis_public_default_hides_gap_rows(client):
    resp = client.get("/analysis")
    assert resp.status_code == 200
    statuses = {row["status"] for row in resp.json()["correlations"]}
    assert statuses == {"hit"}


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
