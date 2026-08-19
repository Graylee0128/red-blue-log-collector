from rbcollector.analysis import summarize


def _red(observed_at: str):
    return {
        "team": "red",
        "observed_at": observed_at,
        "event_type": "red.action",
        "message": "webshell upload",
    }


def _cmdlog(observed_at: str, message: str):
    return {"team": "blue", "observed_at": observed_at, "event_type": "blue.log", "message": message}


def _remediation(observed_at: str):
    return {"team": "blue", "observed_at": observed_at, "event_type": "blue.remediation", "message": "checker.py: webshell 後門封鎖 已修復"}


# issue #33：藍隊事後應對（封鎖/修補）——獨立於 30 秒即時偵測窗口的
# 5 分鐘比對，cmdlog 關鍵字跟 checker.py 驗證過的 blue.remediation 事件
# 兩者都要出現在窗口內才算數，缺一不可。

def test_response_hit_requires_both_signals_within_five_minutes():
    events = [
        _red("2026-08-19T11:00:00+08:00"),
        _cmdlog("2026-08-19T11:03:00+08:00", "iptables -A INPUT -s 10.0.0.10 -j DROP"),
        _remediation("2026-08-19T11:03:10+08:00"),
    ]
    result = summarize(events)
    row = result["correlations"][0]
    assert row["status"] == "hit"
    assert row["detection_method"] == "response"
    assert row["latency_ms"] == 180_000  # 以 cmdlog 那筆的時間算，不是 remediation 那筆
    assert result["detected"] == 1
    assert result["detection_rate"] == 1.0


def test_response_not_counted_with_only_cmdlog_keyword():
    # 有看起來像在封鎖的指令，但 checker.py 沒有對應的 remediation 事件
    # （可能指令打錯、改錯檔案，根本沒修好）——不能只憑猜測就算數。
    events = [
        _red("2026-08-19T11:00:00+08:00"),
        _cmdlog("2026-08-19T11:03:00+08:00", "iptables -A INPUT -s 10.0.0.10 -j DROP"),
    ]
    result = summarize(events)
    assert result["correlations"][0]["status"] == "visibility_gap"
    assert result["detected"] == 0


def test_response_not_counted_with_only_remediation_event():
    # checker.py 驗證過修好了，但完全找不到對應的 cmdlog 指令——同樣不夠
    # 可靠（見 issue #33 設計討論），維持 gap。
    events = [
        _red("2026-08-19T11:00:00+08:00"),
        _remediation("2026-08-19T11:03:10+08:00"),
    ]
    result = summarize(events)
    assert result["correlations"][0]["status"] == "visibility_gap"
    assert result["detected"] == 0


def test_response_outside_five_minute_window_not_counted():
    events = [
        _red("2026-08-19T11:00:00+08:00"),
        _cmdlog("2026-08-19T11:06:00+08:00", "iptables -A INPUT -s 10.0.0.10 -j DROP"),  # 6 分鐘後
        _remediation("2026-08-19T11:06:10+08:00"),
    ]
    result = summarize(events)
    assert result["correlations"][0]["status"] == "visibility_gap"


def test_alert_within_30s_still_takes_priority_over_response_path():
    # 30 秒內已經有真的告警命中，不該再去看 5 分鐘窗口——即時偵測優先。
    events = [
        _red("2026-08-19T11:00:00+08:00"),
        {"team": "blue", "observed_at": "2026-08-19T11:00:05+08:00", "event_type": "blue.alert", "message": "sqli alert"},
        _cmdlog("2026-08-19T11:03:00+08:00", "iptables -A INPUT -s 10.0.0.10 -j DROP"),
        _remediation("2026-08-19T11:03:10+08:00"),
    ]
    result = summarize(events)
    row = result["correlations"][0]
    assert row["status"] == "hit"
    assert row["detection_method"] == "alert"
    assert row["latency_ms"] == 5_000


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
