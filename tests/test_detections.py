from datetime import datetime, timedelta, timezone

from rbcollector.detections import classify_technique, evaluate_detections

BASE = datetime(2026, 8, 17, 11, 0, 0, tzinfo=timezone.utc)


def _red(event_id: str, offset_s: float = 0, source_ip: str = "10.0.0.10", message: str | None = None, destination: str | None = None):
    return {
        "event_id": event_id,
        "team": "red",
        "observed_at": (BASE + timedelta(seconds=offset_s)).isoformat(),
        "source_ip": source_ip,
        "destination": destination,
        "event_type": "red.action",
        "message": message,
    }


def test_classify_technique_matches_message_keyword():
    tag = classify_technique(_red("e1", message="sqlmap -u http://10.0.0.20/product?id=1 --dbs"))
    assert tag == {"rule_id": "sqli-injection-burst", "technique": "T1190", "severity": "high"}


def test_classify_technique_no_match_returns_none():
    assert classify_technique(_red("e1", message="ls -la")) is None


def test_single_zero_threshold_event_fires():
    events = [_red("e1", message="sqlmap -u http://10.0.0.20/product?id=1 --dbs")]
    hits = evaluate_detections(events)
    assert hits["e1"]["technique"] == "T1190"


def test_manual_sqli_payload_matches_target_variant():
    tag = classify_technique(_red("e1", message="curl \"http://10.0.0.20/product?id=1' union select null,null--\""))
    assert tag == {"rule_id": "sqli-injection-burst-target", "technique": "T1190", "severity": "high"}


def test_ssh_brute_force_below_threshold_does_not_fire():
    """ssh-brute-force 門檻是 60 秒窗內 > 1 次；只呼叫一次 hydra 不該被
    判定為偵測（單次可能只是測試連線）。"""
    events = [_red("e0", message="hydra -l admin -P wordlist.txt ssh://10.0.0.10")]
    hits = evaluate_detections(events)
    assert hits == {}


def test_ssh_brute_force_above_threshold_fires_for_members_within_window():
    events = [
        _red(f"e{i}", offset_s=i, message="hydra -l admin -P wordlist.txt ssh://10.0.0.10")
        for i in range(2)
    ]
    hits = evaluate_detections(events)
    # 第 2 次呼叫（索引 1）是跨過 >1 門檻的那一筆
    assert "e1" in hits
    assert hits["e1"]["rule_id"] == "ssh-brute-force"


def test_different_source_ips_bucket_independently():
    events = [_red("a0", source_ip="10.0.0.10", message="hydra -l admin -P wordlist.txt ssh://10.0.0.10")]
    events += [_red("b0", source_ip="10.0.0.20", message="hydra -l admin -P wordlist.txt ssh://10.0.0.10")]
    hits = evaluate_detections(events)
    # 兩個 source_ip 各自都只呼叫一次，沒跨過 >1 門檻
    assert hits == {}


def test_local_privesc_matches_sudo_find():
    tag = classify_technique(_red("e1", message="sudo find / -perm -4000 -exec /bin/sh \\; -quit"))
    assert tag["technique"] == "T1548"


def test_cron_persistence_matches_crontab():
    tag = classify_technique(_red("e1", message="echo '* * * * * /tmp/backdoor.sh' >> /etc/cron.d/root-task"))
    assert tag["technique"] == "T1053"


def test_account_discovery_gap_preserved_below_threshold():
    """刻意留白的偵測落差：窗內掃不到 6 個 student_id 不該被判讀成
    account-discovery——搬遷時不能「順手補齊」這個判定。"""
    events = [
        _red(f"e{i}", offset_s=i, destination=f"/students/{i}")
        for i in range(4)
    ]
    hits = evaluate_detections(events)
    assert hits == {}


def test_account_discovery_above_threshold_fires_across_different_ids():
    """掃很多不同 id（同一路徑前綴）要落進同一個分桶——用完全比對會漏掉
    這個情境，這是這版改用 startswith 的原因。"""
    events = [
        _red(f"e{i}", offset_s=i, destination=f"/students/{i}")
        for i in range(6)
    ]
    hits = evaluate_detections(events)
    assert "e5" in hits
    assert hits["e5"]["rule_id"] == "account-discovery-target"


def test_egress_anomaly_only_flags_metadata_probe_not_credential_use():
    """刻意留白的偵測落差：打雲端 metadata endpoint 會命中；但「這樣讀到
    的憑證被實際使用」沒有對應信號，規則清單裡本來就沒有能比對到這種情況
    的規則——是設計上的落差，不是漏寫。"""
    tag = classify_technique(_red("e1", message="curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"))
    assert tag["technique"] == "T1552"
    assert classify_technique(_red("e2", message="aws s3 ls --profile stolen-creds")) is None
