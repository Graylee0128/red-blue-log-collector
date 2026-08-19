import json

from rbcollector.blue_score_receiver import (
    BlueScoreTailer,
    filtered_report,
    parse_leaderboard_file,
    visible_checks,
)


class FakeStore:
    def __init__(self):
        self.upserts = []

    def upsert_blue_score(self, *, target, total_score, max_score, checks, observed_at):
        self.upserts.append(
            {"target": target, "total_score": total_score, "max_score": max_score, "checks": checks, "observed_at": observed_at}
        )


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
