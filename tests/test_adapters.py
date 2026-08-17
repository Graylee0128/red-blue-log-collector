from rbcollector.adapters.red import normalize as normalize_red
from rbcollector.adapters.blue import normalize as normalize_blue


def test_red_mapping():
    event = normalize_red({
        "timestamp": "2026-08-17T11:00:00+08:00",
        "src_ip": "10.0.0.10",
        "target_ip": "10.0.0.20",
        "command": "nmap -sV 10.0.0.20",
        "result": "ok",
        "correlation_id": "a-1",
    })
    assert event["team"] == "red"
    assert event["source_ip"] == "10.0.0.10"
    assert event["destination"] == "10.0.0.20"
    assert event["correlation_id"] == "a-1"


def test_blue_mapping():
    event = normalize_blue({
        "time": "2026-08-17T11:00:05+08:00",
        "attacker_ip": "10.0.0.10",
        "host": "10.0.0.20",
        "alert": "Port scan detected",
        "severity": "high",
        "correlation_id": "a-1",
    })
    assert event["team"] == "blue"
    assert event["source_ip"] == "10.0.0.10"
    assert event["destination"] == "10.0.0.20"
    assert event["correlation_id"] == "a-1"
