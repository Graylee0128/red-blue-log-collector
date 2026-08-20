import json

from rbcollector.blue_score_receiver import (
    BlueScoreTailer,
    filtered_report,
    find_blue_seat_names,
    parse_leaderboard_file,
    visible_checks,
)


class FakeStore:
    def __init__(self):
        self.upserts = []
        self.known_seats = []
        self.appended_events = []  # issue #33：blue.remediation 合成事件

    def get_blue_score(self, *, target):
        # 回傳這個 target「目前存的」快照（upsert 前的舊值）——跟真的
        # EventStore 一樣，模擬 upsert 前查舊值的順序。
        for row in reversed(self.upserts):
            if row["target"] == target:
                return row
        return None

    def upsert_blue_score(self, *, target, total_score, max_score, checks, observed_at):
        self.upserts.append(
            {"target": target, "total_score": total_score, "max_score": max_score, "checks": checks, "observed_at": observed_at}
        )

    def record_known_blue_seat(self, *, seat):
        is_new = seat not in self.known_seats
        if is_new:
            self.known_seats.append(seat)
        return is_new

    def append(self, *, team, raw_payload, event):
        self.appended_events.append({"team": team, "raw_payload": raw_payload, "event": event})
        return True


def _checks(*, formal_pass: bool, hidden_pass: bool):
    formal = [
        {"id": f"vuln{i}_x", "status": "pass" if formal_pass else "fail", "score": 20 if formal_pass else 0, "max_score": 20}
        for i in range(1, 6)
    ]
    hidden = [
        {"id": "vuln6_webshell_bonus", "status": "pass" if hidden_pass else "fail", "score": 20 if hidden_pass else 0, "max_score": 20},
        {"id": "vuln7_docker_escape", "status": "pass" if hidden_pass else "fail", "score": 20 if hidden_pass else 0, "max_score": 20},
    ]
    return formal + hidden


def test_visible_checks_hides_hidden_when_formal_not_all_pass():
    checks = _checks(formal_pass=False, hidden_pass=True)  # 隱藏題「已解」但正式題沒過齊
    result = visible_checks(checks)
    ids = [c["id"] for c in result]
    assert "vuln6_webshell_bonus" not in ids
    assert "vuln7_docker_escape" not in ids
    assert len(result) == 5


def test_visible_checks_shows_hidden_when_all_formal_pass():
    checks = _checks(formal_pass=True, hidden_pass=False)
    result = visible_checks(checks)
    ids = [c["id"] for c in result]
    assert "vuln6_webshell_bonus" in ids
    assert "vuln7_docker_escape" in ids
    assert len(result) == 7


def test_visible_checks_empty_formal_list_stays_locked():
    checks = _checks(formal_pass=True, hidden_pass=True)[5:]  # 只留隱藏題，沒有正式題
    result = visible_checks(checks)
    assert result == []


def test_filtered_report_recomputes_max_score_when_locked():
    # 鎖住時就算隱藏題內部資料標了分數，彙總值也不能洩漏「還有 40 分沒公開」。
    report = {
        "target": "blue-a-01",
        "timestamp": "2026-08-19T05:09:06",
        "total_score": 20,
        "max_score": 140,
        "checks": _checks(formal_pass=False, hidden_pass=True),
    }
    result = filtered_report(report)
    assert result["max_score"] == 100  # 5 * 20，不含隱藏題
    assert len(result["checks"]) == 5


def test_filtered_report_recomputes_max_score_when_unlocked():
    report = {
        "target": "blue-a-01",
        "timestamp": "2026-08-19T05:09:06",
        "total_score": 999,  # 刻意放錯，確認 filtered_report 真的重算不是照抄
        "max_score": 999,
        "checks": _checks(formal_pass=True, hidden_pass=True),
    }
    result = filtered_report(report)
    assert result["max_score"] == 140
    assert result["total_score"] == 140
    assert len(result["checks"]) == 7


def test_parse_leaderboard_file_valid(tmp_path):
    path = tmp_path / "leaderboard_blue-a-01.json"
    report = {
        "target": "blue-a-01",
        "timestamp": "2026-08-19T05:09:06",
        "total_score": 0,
        "max_score": 140,
        "checks": _checks(formal_pass=False, hidden_pass=False),
    }
    path.write_text(json.dumps(report), encoding="utf-8")
    result = parse_leaderboard_file(path)
    assert result is not None
    assert result["target"] == "blue-a-01"
    assert len(result["checks"]) == 5  # 隱藏題已被濾掉


def test_parse_leaderboard_file_malformed_json_returns_none(tmp_path):
    path = tmp_path / "leaderboard_broken.json"
    path.write_text("{not valid json", encoding="utf-8")
    assert parse_leaderboard_file(path) is None


def test_parse_leaderboard_file_missing_fields_returns_none(tmp_path):
    path = tmp_path / "leaderboard_incomplete.json"
    path.write_text(json.dumps({"target": "blue-a-01"}), encoding="utf-8")
    assert parse_leaderboard_file(path) is None


def test_tailer_poll_once_upserts_filtered_scores(tmp_path):
    report = {
        "target": "blue-a-01",
        "timestamp": "2026-08-19T05:09:06",
        "total_score": 0,
        "max_score": 140,
        "checks": _checks(formal_pass=False, hidden_pass=True),
    }
    (tmp_path / "leaderboard_blue-a-01.json").write_text(json.dumps(report), encoding="utf-8")
    # 非 leaderboard_*.json 的檔案要被忽略，不是每個 .json 都當分數檔處理。
    (tmp_path / "checker_blue-a-01.log").write_text("not a leaderboard file", encoding="utf-8")

    store = FakeStore()
    tailer = BlueScoreTailer(str(tmp_path), store)
    tailer._poll_once()

    assert len(store.upserts) == 1
    upserted = store.upserts[0]
    assert upserted["target"] == "blue-a-01"
    assert upserted["max_score"] == 100  # 隱藏題被濾掉
    assert len(upserted["checks"]) == 5


def test_tailer_poll_once_missing_dir_does_not_raise(tmp_path):
    store = FakeStore()
    tailer = BlueScoreTailer(str(tmp_path / "does-not-exist"), store)
    tailer._poll_once()  # 不該拋例外
    assert store.upserts == []


def test_find_blue_seat_names_matches_blue_a_and_b(tmp_path):
    (tmp_path / "blue-a-01.cmd").write_text("", encoding="utf-8")
    (tmp_path / "blue-b-01.cmd").write_text("", encoding="utf-8")
    # 紅隊、非 .cmd 檔案都不該被算進去。
    (tmp_path / "red-01.cmd").write_text("", encoding="utf-8")
    (tmp_path / "blue-a-01.out").write_text("", encoding="utf-8")
    assert find_blue_seat_names(tmp_path) == ["blue-a-01", "blue-b-01"]


def test_find_blue_seat_names_missing_dir_returns_empty(tmp_path):
    assert find_blue_seat_names(tmp_path / "does-not-exist") == []


def test_tailer_poll_once_records_known_seats_even_without_score_file(tmp_path):
    # blue-b-01 存在（有 .cmd 檔）但完全沒有 leaderboard 檔案（issue #22
    # 已知限制：auto_watch.sh 沒有幫它起 checker.py）——照樣要被記成
    # 「存在」，不能因為沒有分數資料就漏記。
    score_dir = tmp_path / "scores"
    seat_dir = tmp_path / "seats"
    score_dir.mkdir()
    seat_dir.mkdir()
    (seat_dir / "blue-a-01.cmd").write_text("", encoding="utf-8")
    (seat_dir / "blue-b-01.cmd").write_text("", encoding="utf-8")

    store = FakeStore()
    tailer = BlueScoreTailer(str(score_dir), store, seat_log_dir=str(seat_dir))
    tailer._poll_once()

    assert store.known_seats == ["blue-a-01", "blue-b-01"]
    assert store.upserts == []  # 沒有 leaderboard 檔，本來就不該有分數


def test_tailer_poll_once_no_seat_log_dir_skips_seat_scan(tmp_path):
    store = FakeStore()
    tailer = BlueScoreTailer(str(tmp_path), store)  # seat_log_dir 預設 None
    tailer._poll_once()
    assert store.known_seats == []


# issue #33：check 從 fail 翻 pass 時補一筆 blue.remediation 合成事件，
# analysis.py 的事後應對比對要靠這個當「真的驗證過修好了」的客觀訊號。

def test_newly_passed_check_emits_remediation_event(tmp_path):
    path = tmp_path / "leaderboard_blue-a-01.json"

    # 第一輪：vuln1 還沒修。
    report1 = {
        "target": "blue-a-01", "timestamp": "2026-08-19T05:00:00",
        "total_score": 0, "max_score": 100,
        "checks": _checks(formal_pass=False, hidden_pass=False)[:5],
    }
    path.write_text(json.dumps(report1), encoding="utf-8")
    store = FakeStore()
    tailer = BlueScoreTailer(str(tmp_path), store)
    tailer._poll_once()
    assert store.appended_events == []  # 第一次看到這個 target，不補事件

    # 第二輪：vuln1 修好了，其他還是 fail。
    report2 = {
        "target": "blue-a-01", "timestamp": "2026-08-19T05:03:00",
        "total_score": 20, "max_score": 100,
        "checks": [
            {"id": "vuln1_x", "status": "pass", "score": 20, "max_score": 20},
            *_checks(formal_pass=False, hidden_pass=False)[1:5],
        ],
    }
    path.write_text(json.dumps(report2), encoding="utf-8")
    tailer._poll_once()

    assert len(store.appended_events) == 1
    event = store.appended_events[0]["event"]
    assert event["team"] == "blue"
    assert event["event_type"] == "blue.remediation"
    assert ".env 權限修復" in event["message"]
    assert event["source"] == "blue-a-01"


def test_check_still_fail_does_not_emit_event(tmp_path):
    path = tmp_path / "leaderboard_blue-a-01.json"
    report = {
        "target": "blue-a-01", "timestamp": "2026-08-19T05:00:00",
        "total_score": 0, "max_score": 100,
        "checks": _checks(formal_pass=False, hidden_pass=False)[:5],
    }
    path.write_text(json.dumps(report), encoding="utf-8")
    store = FakeStore()
    tailer = BlueScoreTailer(str(tmp_path), store)
    tailer._poll_once()
    tailer._poll_once()  # 兩輪都一樣，沒有新的 pass
    assert store.appended_events == []


def test_check_already_passing_stays_silent_on_repeat_poll(tmp_path):
    # 已經 pass 的題目繼續回報 pass，不該每輪都重複發事件。
    path = tmp_path / "leaderboard_blue-a-01.json"
    report = {
        "target": "blue-a-01", "timestamp": "2026-08-19T05:00:00",
        "total_score": 20, "max_score": 100,
        "checks": [
            {"id": "vuln1_x", "status": "pass", "score": 20, "max_score": 20},
            *_checks(formal_pass=False, hidden_pass=False)[1:5],
        ],
    }
    path.write_text(json.dumps(report), encoding="utf-8")
    store = FakeStore()
    tailer = BlueScoreTailer(str(tmp_path), store)
    tailer._poll_once()  # 第一次看到，不補事件（見上面的規則）
    tailer._poll_once()  # 第二次仍是 pass，同樣不該補
    assert store.appended_events == []
