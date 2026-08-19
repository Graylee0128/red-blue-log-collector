import os
from unittest.mock import patch

from rbcollector.syslog_receiver import (
    blue_payload_from_syslog,
    ingest_syslog_line,
    parse_plain_line,
    parse_syslog_line,
    red_payload_from_syslog,
)

RED_LINE = (
    '<133>1 2026-08-18T09:47:26.123456+00:00 red-host-01 metis-red-cmd - - '
    '[metis@1 src="/var/log/metis/seat/red-abc123.cmd" role="red"] nmap -sV 10.0.0.20'
)
BLUE_LINE = (
    '<134>1 2026-08-18T09:47:41.000000+00:00 blue-host-01 metis-blue-syslog - - '
    '[metis@1 src="/var/log/auth.log" role="blue"] Failed password for root from 10.0.0.10 port 5555'
)
HOST_LINE = (
    '<134>1 2026-08-18T09:47:50.000000+00:00 central metis-docker-events - - '
    '[metis@1 src="/var/log/metis/docker-events.log" role="host"] {"status":"start"}'
)
RED_LINE_WITH_TOKEN = (
    '<133>1 2026-08-18T09:47:26.123456+00:00 red-host-01 metis-red-cmd - - '
    '[metis@1 src="/var/log/metis/seat/red-abc123.cmd" role="red" token="secret123"] nmap -sV 10.0.0.20'
)


class FakeStore:
    def __init__(self):
        self.appended = []

    def append(self, *, team, raw_payload, event):
        self.appended.append((team, raw_payload, event))
        return True


def test_parse_syslog_line_extracts_role_and_msg():
    parsed = parse_syslog_line(RED_LINE)
    assert parsed["role"] == "red"
    assert parsed["hostname"] == "red-host-01"
    assert parsed["appname"] == "metis-red-cmd"
    assert parsed["msg"] == "nmap -sV 10.0.0.20"
    assert parsed["src"] == "/var/log/metis/seat/red-abc123.cmd"


def test_parse_syslog_line_rejects_garbage():
    assert parse_syslog_line("not a syslog line at all") is None


def test_red_payload_extracts_target_ip():
    parsed = parse_syslog_line(RED_LINE)
    payload = red_payload_from_syslog(parsed)
    assert payload["command"] == "nmap -sV 10.0.0.20"
    assert payload["target_ip"] == "10.0.0.20"
    assert payload["source"] == "red-host-01"


def test_red_payload_omits_target_ip_when_no_ip_in_command():
    parsed = parse_syslog_line(RED_LINE.replace("nmap -sV 10.0.0.20", "history -c"))
    payload = red_payload_from_syslog(parsed)
    assert "target_ip" not in payload


def test_blue_payload_tags_alert_and_extracts_attacker_ip():
    parsed = parse_syslog_line(BLUE_LINE)
    payload = blue_payload_from_syslog(parsed)
    assert payload["event_type"] == "blue.alert"
    assert payload["attacker_ip"] == "10.0.0.10"
    assert payload["host"] == "blue-host-01"


def test_blue_payload_defaults_to_log_when_no_alert_keyword():
    parsed = parse_syslog_line(BLUE_LINE.replace("Failed password", "session opened"))
    payload = blue_payload_from_syslog(parsed)
    assert payload["event_type"] == "blue.log"


def test_ingest_syslog_line_red_appends_to_store():
    store = FakeStore()
    ingest_syslog_line(store, RED_LINE)
    assert len(store.appended) == 1
    team, raw_payload, event = store.appended[0]
    assert team == "red"
    assert event["destination"] == "10.0.0.20"
    assert raw_payload["raw_line"] == RED_LINE
    assert raw_payload["tag"] == "metis-red-cmd"


def test_ingest_syslog_line_blue_appends_to_store():
    store = FakeStore()
    ingest_syslog_line(store, BLUE_LINE)
    assert len(store.appended) == 1
    team, _raw_payload, event = store.appended[0]
    assert team == "blue"
    assert event["source_ip"] == "10.0.0.10"


def test_ingest_syslog_line_host_role_is_skipped():
    store = FakeStore()
    ingest_syslog_line(store, HOST_LINE)
    assert store.appended == []


def test_ingest_syslog_line_ignores_blank_lines():
    store = FakeStore()
    ingest_syslog_line(store, "\n")
    ingest_syslog_line(store, "")
    assert store.appended == []


def test_ingest_syslog_line_unparsable_line_does_not_raise():
    store = FakeStore()
    ingest_syslog_line(store, "garbage, not RFC5424 at all")
    assert store.appended == []


def test_parse_plain_line_red():
    assert parse_plain_line("red: nmap -sV 10.0.0.20") == ("red", "nmap -sV 10.0.0.20")


def test_parse_plain_line_blue_case_insensitive_and_equals():
    assert parse_plain_line("BLUE = Failed password for root") == ("blue", "Failed password for root")


def test_parse_plain_line_rejects_other_text():
    assert parse_plain_line("hello there") is None
    assert parse_plain_line("purple: not a real team") is None


def test_ingest_syslog_line_accepts_plain_red_fallback():
    store = FakeStore()
    ingest_syslog_line(store, "red: nmap -sV 10.0.0.20")
    assert len(store.appended) == 1
    team, raw_payload, event = store.appended[0]
    assert team == "red"
    assert event["message"] == "nmap -sV 10.0.0.20"
    assert raw_payload["tag"] == "manual-plain-text"


def test_ingest_syslog_line_accepts_plain_blue_fallback():
    store = FakeStore()
    ingest_syslog_line(store, "blue: Failed password for root from 10.0.0.10")
    assert len(store.appended) == 1
    team, _raw_payload, event = store.appended[0]
    assert team == "blue"
    assert event["message"] == "Failed password for root from 10.0.0.10"


def test_parse_syslog_line_extracts_token():
    parsed = parse_syslog_line(RED_LINE_WITH_TOKEN)
    assert parsed["token"] == "secret123"
    assert parsed["role"] == "red"


def test_ingest_syslog_line_with_correct_token_accepts():
    # issue #28: 驗證 token
    store = FakeStore()
    with patch.dict(os.environ, {"SYSLOG_TOKEN": "secret123"}):
        ingest_syslog_line(store, RED_LINE_WITH_TOKEN)
        assert len(store.appended) == 1
        team, _raw_payload, _event = store.appended[0]
        assert team == "red"


def test_ingest_syslog_line_with_wrong_token_rejects():
    # issue #28: 驗證 token 失敗時拒絕
    store = FakeStore()
    with patch.dict(os.environ, {"SYSLOG_TOKEN": "wrong-token"}):
        ingest_syslog_line(store, RED_LINE_WITH_TOKEN)
        assert store.appended == []


def test_ingest_syslog_line_with_missing_token_when_required_rejects():
    # issue #28: 需要 token 但日誌中沒有時拒絕
    store = FakeStore()
    with patch.dict(os.environ, {"SYSLOG_TOKEN": "secret123"}):
        ingest_syslog_line(store, RED_LINE)  # 沒有 token 的日誌
        assert store.appended == []


def test_ingest_syslog_line_without_token_config_accepts_all():
    # issue #28: 沒有設置 token 時接受所有日誌（向後兼容）
    store = FakeStore()
    with patch.dict(os.environ, {}, clear=True):
        # 清除所有環境變數，模擬沒有 token 的情況
        ingest_syslog_line(store, RED_LINE)
        assert len(store.appended) == 1
        ingest_syslog_line(store, RED_LINE_WITH_TOKEN)
        assert len(store.appended) == 2
