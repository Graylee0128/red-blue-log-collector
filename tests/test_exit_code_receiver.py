from datetime import datetime, timedelta, timezone

from rbcollector.exit_code_receiver import (
    ExitCodeCorrelator,
    correlate_exit_codes,
    find_exit_markers,
    find_last_session,
    parse_timing_file,
    slice_timing_from_offset,
)


class FakeStore:
    def __init__(self, events):
        self._events = events
        self.updates = []

    def list_events(self, team=None, limit=200):
        return [e for e in self._events if team is None or e["team"] == team]

    def update_action_result(self, event_id, action_result):
        self.updates.append((event_id, action_result))
        return True


def _build_out(session_line: str, body: bytes) -> bytes:
    return session_line.encode("utf-8") + b"\n" + body


def test_find_last_session_picks_most_recent_reconnect():
    out = (
        _build_out('Script started on 2026-08-22 10:00:00+0000 [COMMAND="bash"]', b"old session\n")
        + _build_out('Script started on 2026-08-22 10:05:00+0000 [COMMAND="bash"]', b"new session\n")
    )
    result = find_last_session(out)
    assert result is not None
    offset, ts = result
    assert ts == datetime(2026, 8, 22, 10, 5, 0, tzinfo=timezone.utc)
    # 偏移要落在第二個 "Script started on" 那行,不是第一個。
    assert out[offset:offset + len("Script started on")] == b"Script started on"


def test_find_last_session_returns_none_when_unparseable():
    assert find_last_session(b"no session header here") is None


def test_parse_timing_file_skips_malformed_lines(tmp_path):
    path = tmp_path / "seat.timing"
    path.write_text("0.5 10\ngarbage line\n1.2 20\n", encoding="utf-8")
    assert parse_timing_file(path) == [(0.5, 10), (1.2, 20)]


def test_slice_timing_from_offset_finds_containing_chunk():
    pairs = [(0.1, 10), (0.2, 10), (0.3, 10)]  # 累積位元組:10/20/30
    # offset=15 落在第二個區塊(10~20)裡,回傳從那個區塊開始。
    assert slice_timing_from_offset(pairs, 15) == [(0.2, 10), (0.3, 10)]
    assert slice_timing_from_offset(pairs, 100) == []


def test_find_exit_markers_reconstructs_timestamps_from_timing():
    session_start = datetime(2026, 8, 22, 10, 0, 0, tzinfo=timezone.utc)
    body = b"whoami output\n[[METIS_EXIT:0]]\nmore output\n[[METIS_EXIT:1]]\n"
    # 兩個 timing 區塊,第一個涵蓋到第一個 marker 之後,第二個涵蓋剩下的。
    first_marker_end = body.index(b"[[METIS_EXIT:0]]") + len(b"[[METIS_EXIT:0]]")
    pairs = [(2.0, first_marker_end), (3.0, len(body) - first_marker_end)]

    markers = find_exit_markers(body, pairs, session_start)

    assert markers == [
        (session_start + timedelta(seconds=2.0), 0),
        (session_start + timedelta(seconds=5.0), 1),
    ]


def test_correlate_exit_codes_matches_first_marker_in_window():
    t0 = datetime(2026, 8, 22, 10, 0, 0, tzinfo=timezone.utc)
    commands = [("evt-1", t0), ("evt-2", t0 + timedelta(seconds=10))]
    markers = [
        (t0 + timedelta(seconds=1), 0),   # 屬於 evt-1
        (t0 + timedelta(seconds=2), 0),   # 空白 Enter 產生的多餘標記,窗口內但不是第一個,忽略
        (t0 + timedelta(seconds=11), 127),  # 屬於 evt-2
    ]
    result = correlate_exit_codes(commands, markers)
    assert result == {"evt-1": "0", "evt-2": "127"}


def test_correlate_exit_codes_last_command_uses_grace_window():
    t0 = datetime(2026, 8, 22, 10, 0, 0, tzinfo=timezone.utc)
    commands = [("evt-1", t0)]
    markers = [(t0 + timedelta(seconds=29), 0)]
    assert correlate_exit_codes(commands, markers) == {"evt-1": "0"}
    # 超過 30 秒的寬限窗口就抓不到了。
    markers_late = [(t0 + timedelta(seconds=31), 0)]
    assert correlate_exit_codes(commands, markers_late) == {}


def test_correlate_exit_codes_no_marker_in_window_leaves_command_unresolved():
    t0 = datetime(2026, 8, 22, 10, 0, 0, tzinfo=timezone.utc)
    commands = [("evt-1", t0), ("evt-2", t0 + timedelta(seconds=5))]
    # evt-1 的窗口是 [t0, t0+5)，evt-2 是最後一句，窗口是 [t0+5, t0+35)——
    # t0+40 兩個窗口都接不到，兩句都配不到才對。
    markers = [(t0 + timedelta(seconds=40), 0)]
    assert correlate_exit_codes(commands, markers) == {}


def test_exit_code_correlator_end_to_end_updates_pending_events(tmp_path):
    seat_dir = tmp_path
    session_start_str = "2026-08-22 10:00:00+0000"
    session_start = datetime(2026, 8, 22, 10, 0, 0, tzinfo=timezone.utc)

    # 標頭本身也是 .out 的一部分、也佔 .timing 的位元組數——跟真實
    # script 錄製行為一致，不能只算 body。
    header = f'Script started on {session_start_str} [COMMAND="bash"]\n'.encode("utf-8")
    body = b"whoami output\n[[METIS_EXIT:0]]\n"
    (seat_dir / "red-01.out").write_bytes(header + body)
    (seat_dir / "red-01.timing").write_text(f"0.5 {len(header)}\n1.0 {len(body)}\n", encoding="utf-8")

    store = FakeStore([
        {
            "event_id": "evt-1", "team": "red", "source": "red-01",
            "observed_at": session_start.isoformat(), "action_result": "unknown",
        },
        # 已經解過的事件不該被重複更新。
        {
            "event_id": "evt-2", "team": "red", "source": "red-01",
            "observed_at": session_start.isoformat(), "action_result": "0",
        },
    ])
    correlator = ExitCodeCorrelator(str(seat_dir), store)
    correlator._poll_once()

    assert store.updates == [("evt-1", "0")]
