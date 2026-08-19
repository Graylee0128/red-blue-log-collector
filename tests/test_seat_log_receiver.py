from rbcollector.seat_log_receiver import (
    blue_payload_from_seat_log,
    get_team_from_filename,
    ingest_seat_log_line,
    parse_command_line,
    red_payload_from_seat_log,
)


class FakeStore:
    def __init__(self):
        self.appended = []

    def append(self, *, team, raw_payload, event):
        self.appended.append((team, raw_payload, event))
        return True


def test_get_team_from_filename_red():
    assert get_team_from_filename("red-01.cmd") == "red"


def test_get_team_from_filename_blue_a_and_b():
    assert get_team_from_filename("blue-a-01.cmd") == "blue"
    assert get_team_from_filename("blue-b-01.cmd") == "blue"


def test_get_team_from_filename_unrecognized_returns_none():
    assert get_team_from_filename("host-docker-events.cmd") is None


def test_parse_command_line_with_leading_timestamp():
    parsed = parse_command_line("2026-08-19T04:39:35+00:00 nmap -sV 10.0.0.20")
    assert parsed["timestamp"] == "2026-08-19T04:39:35+00:00"
    assert parsed["command"] == "nmap -sV 10.0.0.20"


def test_parse_command_line_without_timestamp_uses_whole_line():
    parsed = parse_command_line("cd vboo")
    assert parsed["timestamp"] is None
    assert parsed["command"] == "cd vboo"


def test_parse_command_line_blank_returns_none():
    assert parse_command_line("   ") is None


def test_red_payload_uses_source_key_for_seat_name():
    payload = red_payload_from_seat_log({"timestamp": None, "command": "nmap -sV 10.0.0.20"}, "red-01.cmd")
    assert payload["source"] == "red-01"
    assert payload["target_ip"] == "10.0.0.20"


def test_blue_payload_uses_source_key_for_seat_name():
    # 之前這裡誤用 "host"，BlueAdapter 的 source 候選欄位沒有 host，會被
    # destination 候選欄位撿走，畫面上看不到席位名稱——回歸測試鎖住這個修法。
    payload = blue_payload_from_seat_log({"timestamp": None, "command": "cd vboo"}, "blue-b-01.cmd")
    assert payload["source"] == "blue-b-01"
    assert "host" not in payload


def test_ingest_seat_log_line_red_source_is_seat_name():
    store = FakeStore()
    ingest_seat_log_line(store, "red", "red-01.cmd", "nmap -sV 10.0.0.20")
    assert len(store.appended) == 1
    team, raw_payload, event = store.appended[0]
    assert team == "red"
    assert event["source"] == "red-01"
    assert raw_payload["filename"] == "red-01.cmd"


def test_ingest_seat_log_line_blue_source_is_seat_name_not_destination():
    store = FakeStore()
    ingest_seat_log_line(store, "blue", "blue-b-01.cmd", "cd vboo")
    assert len(store.appended) == 1
    team, _raw_payload, event = store.appended[0]
    assert team == "blue"
    assert event["source"] == "blue-b-01"
    assert event["destination"] is None


def test_ingest_seat_log_line_blank_line_does_not_append():
    store = FakeStore()
    ingest_seat_log_line(store, "red", "red-01.cmd", "\n")
    assert store.appended == []
