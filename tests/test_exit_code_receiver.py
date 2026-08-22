from datetime import datetime, timedelta, timezone

from rbcollector.exit_code_receiver import (
    ExitCodeCorrelator,
    correlate_exit_codes,
    find_exit_markers,
    find_last_session,
    parse_timing_file,
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
    assert parse_timing_file(path) == [(0.5, 10, True), (1.2, 20, True)]


def test_parse_timing_file_multistream_format_keeps_all_entries_with_output_flag(tmp_path):
    # 實測撞到的真實格式（issue #41 在 VM 上驗證時發現）：seat-shell.sh
    # 同時用 --log-in/--log-out/--log-timing，script（util-linux ≥2.35）
    # 因此改寫成三欄、開頭一個字母標串流，不是傳統兩欄格式——H 是
    # header、O 是 .out 寫入、I 是 .in 寫入。三種都要保留（is_output 標記
    # 是不是 O），因為 delay 是共用同一條時間軸，I／H 行的延遲也要算進
    # 經過時間，只是不貢獻 .out 的位元組位移（見 find_exit_markers()）。
    path = tmp_path / "seat.timing"
    path.write_text(
        "H 0.000000 START_TIME 2026-08-22 15:07:26+00:00\n"
        "H 0.000000 COMMAND docker exec -it red-01 bash --rcfile /tmp/.metis-exit-rc.sh -i\n"
        "O 0.265878 18\n"
        "I 6.310613 1\n"
        "O 0.003689 30\n",
        encoding="utf-8",
    )
    assert parse_timing_file(path) == [
        (0.0, 0, False),
        (0.0, 0, False),
        (0.265878, 18, True),
        (6.310613, 1, False),
        (0.003689, 30, True),
    ]


def test_find_exit_markers_reconstructs_timestamps_from_timing():
    session_start = datetime(2026, 8, 22, 10, 0, 0, tzinfo=timezone.utc)
    body = b"whoami output\n[[METIS_EXIT:0]]\nmore output\n[[METIS_EXIT:1]]\n"
    # 兩個 output 區塊,第一個涵蓋到第一個 marker 之後,第二個涵蓋剩下的。
    first_marker_end = body.index(b"[[METIS_EXIT:0]]") + len(b"[[METIS_EXIT:0]]")
    entries = [(2.0, first_marker_end, True), (3.0, len(body) - first_marker_end, True)]

    markers = find_exit_markers(body, entries, session_start)

    assert markers == [
        (session_start + timedelta(seconds=2.0), 0),
        (session_start + timedelta(seconds=5.0), 1),
    ]


def test_find_exit_markers_counts_input_stream_delay_but_not_its_bytes():
    # issue #41 實測撞到的真的 bug：I 行的延遲（使用者發呆／打字的真正
    # 間隔）如果整批跳過不算，時間軸會被壓縮到不合理的短。這裡驗證
    # I 行的延遲有算進經過時間，但它的位元組數不會被當成 .out 的位移。
    session_start = datetime(2026, 8, 22, 10, 0, 0, tzinfo=timezone.utc)
    body = b"x" * 5 + b"[[METIS_EXIT:0]]"
    entries = [
        (1.0, 5, True),   # .out 寫了 5 個位元組,經過 1 秒
        (10.0, 1, False),  # 使用者發呆/打字 10 秒才按下一個鍵(.in),不貢獻 .out 位移
        (0.5, len(body) - 5, True),  # 標記本身寫進 .out,再經過 0.5 秒
    ]
    markers = find_exit_markers(body, entries, session_start)
    # 標記時間應該是 1 + 10 + 0.5 = 11.5 秒後,不是只算 output 行的 1.5 秒。
    assert markers == [(session_start + timedelta(seconds=11.5), 0)]


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


def test_correlate_exit_codes_matches_marker_slightly_before_cmd_time():
    # issue #41 在真實 VM 上驗證時撞到的真的 bug：cmdlog.sh 的指令時間戳
    # 跟 .out/.timing 重建出來的標記時間是兩個獨立時鐘來源，實測發現同一句
    # 指令的標記時間可能比 cmd_time 早零點幾秒（"Script started on ..."
    # 只精確到整秒）。嚴格要求 marker_time >= cmd_time 會讓這種完全正常的
    # 情況永遠配不到，尤其是「最後一句指令」——沒有下一句指令的窗口起點
    # 可以救回它。
    t0 = datetime(2026, 8, 22, 10, 0, 0, tzinfo=timezone.utc)
    commands = [("evt-1", t0)]
    markers = [(t0 - timedelta(seconds=0.8), 0)]
    assert correlate_exit_codes(commands, markers) == {"evt-1": "0"}
    # 超過寬限秒數(_CLOCK_SKEW_GRACE_SECONDS=4)還是配不到。
    markers_too_early = [(t0 - timedelta(seconds=5), 0)]
    assert correlate_exit_codes(commands, markers_too_early) == {}


def test_correlate_exit_codes_grace_overlap_does_not_double_assign_marker():
    # 往前留的時鐘偏差寬限會讓相鄰兩句指令的窗口出現一小段重疊——驗證
    # 同一個標記不會同時配給前後兩句指令(每句指令都先抓自己真正的標記,
    # 重疊區只有在前一句指令自己完全沒有標記時才輪得到,這裡先驗證正常
    # 情況:兩句指令各自有自己的標記,不會互搶)。
    t0 = datetime(2026, 8, 22, 10, 0, 0, tzinfo=timezone.utc)
    commands = [("evt-1", t0), ("evt-2", t0 + timedelta(seconds=10))]
    markers = [
        (t0 + timedelta(seconds=1), 0),      # evt-1 自己的標記
        (t0 + timedelta(seconds=9), 127),    # evt-2 標記,比 cmd_time 早 1 秒(時鐘偏差)
    ]
    result = correlate_exit_codes(commands, markers)
    assert result == {"evt-1": "0", "evt-2": "127"}


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
