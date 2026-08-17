from rbcollector.analysis import summarize


def test_shared_correlation_id_produces_hit_and_latency():
    events = [
        {
            "team": "red",
            "observed_at": "2026-08-17T11:00:00+08:00",
            "source_ip": "10.0.0.10",
            "destination": "10.0.0.20",
            "correlation_id": "a-1",
            "event_type": "red.action",
            "message": "scan",
        },
        {
            "team": "blue",
            "observed_at": "2026-08-17T11:00:05+08:00",
            "source_ip": "10.0.0.10",
            "destination": "10.0.0.20",
            "correlation_id": "a-1",
            "event_type": "blue.alert",
            "message": "scan detected",
        },
    ]

    result = summarize(events)
    assert result["red_actions"] == 1
    assert result["detected"] == 1
    assert result["detection_rate"] == 1.0
    assert result["mttd_p50_ms"] == 5000
