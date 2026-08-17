from datetime import datetime, timedelta, timezone

from rbcollector.detections import classify_technique, evaluate_detections

BASE = datetime(2026, 8, 17, 11, 0, 0, tzinfo=timezone.utc)


def _red(event_id: str, offset_s: float = 0, source_ip: str = "10.0.0.10", **metadata):
    return {
        "event_id": event_id,
        "team": "red",
        "observed_at": (BASE + timedelta(seconds=offset_s)).isoformat(),
        "source_ip": source_ip,
        "event_type": "red.action",
        "message": metadata.pop("message", None),
        "metadata": metadata,
    }


def test_classify_technique_matches_metadata_flag():
    tag = classify_technique(_red("e1", sqli_suspected=True))
    assert tag == {"rule_id": "sqli-injection-burst", "technique": "T1190", "severity": "high"}


def test_classify_technique_no_match_returns_none():
    assert classify_technique(_red("e1", something_unrelated=True)) is None


def test_single_zero_threshold_event_fires():
    events = [_red("e1", sqli_suspected=True)]
    hits = evaluate_detections(events)
    assert hits["e1"]["technique"] == "T1190"


def test_below_threshold_does_not_fire():
    """ssh-brute-force 門檻是 60 秒窗內 > 10 次；同一個 source_ip 只打
    3 次不該被判定為偵測。"""
    events = [
        _red(f"e{i}", offset_s=i, source_ip="10.0.0.10", message="ssh login failed")
        for i in range(3)
    ]
    hits = evaluate_detections(events)
    assert hits == {}


def test_above_threshold_fires_for_members_within_window():
    events = [
        _red(f"e{i}", offset_s=i, source_ip="10.0.0.10", message="ssh login failed")
        for i in range(11)
    ]
    hits = evaluate_detections(events)
    # 第 11 次嘗試（索引 10）是跨過 >10 門檻的那一筆
    assert "e10" in hits
    assert hits["e10"]["rule_id"] == "ssh-brute-force"


def test_different_source_ips_bucket_independently():
    events = [_red(f"a{i}", offset_s=i, source_ip="10.0.0.10", message="ssh login failed") for i in range(5)]
    events += [_red(f"b{i}", offset_s=i, source_ip="10.0.0.20", message="ssh login failed") for i in range(5)]
    hits = evaluate_detections(events)
    # 兩個 source_ip 各自都沒跨過 >10 門檻
    assert hits == {}


def test_account_discovery_gap_preserved_below_threshold():
    """刻意留白的偵測落差：窗內掃不到 6 次 student_id 不該被判讀成
    account-discovery——搬遷時不能「順手補齊」這個判定。"""
    events = [
        _red(f"e{i}", offset_s=i, source_ip="10.0.0.10", destination="/students/token")
        for i in range(4)
    ]
    hits = evaluate_detections(events)
    assert hits == {}


def test_egress_anomaly_only_flags_metadata_read_not_credential_use():
    """刻意留白的偵測落差：ssrf_suspected=true（讀到 metadata）會命中；
    但「這樣讀到的憑證被實際使用」沒有對應信號，規則清單裡本來就沒有
    能比對到這種情況的規則——是設計上的落差，不是漏寫。"""
    tag = classify_technique(_red("e1", ssrf_suspected=True))
    assert tag["technique"] == "T1552"
    assert classify_technique(_red("e2", credentials_used=True)) is None
