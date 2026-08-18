import pytest

from rbcollector.evidence import EvidenceNotFound, resolve_context

LINES = [
    {"team": "red", "payload": {"command": "nmap -sV"}, "observed_at": "2026-08-17T11:00:00+00:00", "received_at": "2026-08-17T11:00:00+00:00"},
    {"team": "blue", "payload": {"alert": "scan detected"}, "observed_at": "2026-08-17T11:00:05+00:00", "received_at": "2026-08-17T11:00:05+00:00"},
]


class FakeStore:
    """EventStore.context 的 duck-typed 替身，跟 cyber 的 FakeBackend
    同一種手法：證明 resolve_context 只依賴 `.context(event_id,
    window_minutes)` 這個介面，不綁死 Postgres。"""

    def __init__(self, known: dict[str, list[dict]]):
        self.known = known

    def context(self, event_id: str, window_minutes: int = 5):
        return self.known.get(event_id)


def test_unknown_event_id_raises():
    store = FakeStore({})
    with pytest.raises(EvidenceNotFound):
        resolve_context(store, "evt-missing", caller="purple")


def test_public_caller_gets_filtered_empty_result_not_an_error():
    store = FakeStore({"evt-1": LINES})
    bundle = resolve_context(store, "evt-1", caller="public")
    assert bundle["line_count"] == 0
    assert bundle["lines"] == []


def test_purple_caller_sees_the_raw_context():
    store = FakeStore({"evt-1": LINES})
    bundle = resolve_context(store, "evt-1", caller="purple")
    assert bundle["line_count"] == 2
    assert bundle["lines"] == LINES


def test_window_minutes_is_echoed_back():
    store = FakeStore({"evt-1": LINES})
    bundle = resolve_context(store, "evt-1", caller="purple", window_minutes=10)
    assert bundle["window_minutes"] == 10
