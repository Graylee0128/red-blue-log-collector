"""Reads Metis's blue-team scoring snapshots (issue #22).

Metis's blue/scoring-engine/checker.py judges 7 vulnerability-patch checks
per blue seat (5 formal + 2 hidden bonus, 20 points each, max 140) and
writes the result to a host-side leaderboard_<target>.json file every time
it re-checks (checker.py --loop). There is no HTTP API for this -- this
module polls that directory directly, the same "read Metis's own files"
pattern as seat_log_receiver.py (issue #16).

IMPORTANT -- leak filtering: checker.py's own leak-prevention (visible_checks())
only applies to the copy it pushes *into* the guest's container
(/opt/score/status.json). The host-side leaderboard_<target>.json is always
the *unfiltered* full report, including the 2 hidden bonus checks before
they're unlocked. If this receiver stored/served that file as-is, Purple
Console would leak the existence and pass/fail detail of the hidden
challenges before the blue team is supposed to see them. `visible_checks()`
below is a deliberate, comment-linked copy of checker.py's own filter --
keep it in sync with blue/scoring-engine/checker.py if that ever changes.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from .adapters import blue
from .store import EventStore

logger = logging.getLogger("rbcollector.blue_score_receiver")

DEFAULT_SCORE_DIR = "/var/lib/metis/blue-scores"
DEFAULT_SEAT_LOG_DIR = "/var/log/metis/seat"
DEFAULT_POLL_INTERVAL = 5.0  # seconds -- checker.py itself re-checks every ~10s

# 跟 seat_log_receiver.get_team_from_filename() 的藍隊判斷規則一致——
# 只認檔名，不管有沒有 checker.py 在跑。issue #22 已知限制：auto_watch.sh
# 只監控 blue-a-*，blue-b-* 完全沒有計分，所以「有計分的席位數」
# （blue_scores 表）跟「實際存在的席位數」會兜不起來，畫面上分母看起來
# 比實際席位數少。這裡額外掃 seat log 目錄找出「真的存在的席位」（檔案
# 一建立就有，不用等有人打字），跟計分資料分開存，讓前端可以把分母
# 抓對，不受 auto_watch.sh 涵蓋範圍限制。
_BLUE_SEAT_RE = re.compile(r"^blue-[ab]-.*\.cmd$")


def find_blue_seat_names(seat_dir: Path) -> list[str]:
    """掃一次 seat log 目錄，回傳看到的藍隊席位名稱（檔名去副檔名）。
    目錄不存在或掃描失敗時回傳空清單並記警告，不拋例外——這是輔助資訊，
    不該讓分數輪詢因此中斷。"""
    if not seat_dir.exists():
        logger.warning("seat log directory does not exist: %s", seat_dir)
        return []
    try:
        return sorted(p.stem for p in seat_dir.glob("blue-*.cmd") if _BLUE_SEAT_RE.match(p.name))
    except OSError:
        logger.exception("failed to scan seat log directory: %s", seat_dir)
        return []

# Mirrors checker.py's hidden bonus check ids exactly -- these are the ids
# that must not be visible until the 5 formal checks all pass.
_HIDDEN_CHECK_IDS = ("vuln6_webshell_bonus", "vuln7_docker_escape")

# 人類可讀的關卡標籤（issue #33）——取自藍隊教練手冊（vuln{N}_... 的編號
# 順序跟手冊的關卡 01-07 一致），只用來組合成 blue.remediation 事件的
# message，不影響判分本身。id 前綴比對不到就顯示原始 id，不擋流程。
_CHECK_LABELS = {
    "vuln1": ".env 權限修復",
    "vuln2": "/etc/shadow 權限修復",
    "vuln3": "sudoers 提權漏洞修復",
    "vuln4": "DB 內網憑證清除",
    "vuln5": "cron 腳本權限修復",
    "vuln6": "webshell 後門封鎖",
    "vuln7": "docker socket 逃逸修復",
}


def _check_label(check_id: str) -> str:
    prefix = check_id.split("_", 1)[0]
    return _CHECK_LABELS.get(prefix, check_id)


def _passed_check_ids(checks: list[dict[str, Any]]) -> set[str]:
    return {c["id"] for c in checks if c.get("status") == "pass" and c.get("id")}


def visible_checks(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Same rule as checker.py's visible_checks(): hidden bonus checks only
    show once every formal (non-hidden) check has status "pass"."""
    formal = [c for c in checks if c.get("id") not in _HIDDEN_CHECK_IDS]
    unlocked = bool(formal) and all(c.get("status") == "pass" for c in formal)
    hidden = [c for c in checks if c.get("id") in _HIDDEN_CHECK_IDS] if unlocked else []
    return formal + hidden


def filtered_report(report: dict[str, Any]) -> dict[str, Any]:
    """Same rule as checker.py's container_payload(): after filtering, the
    aggregate total_score/max_score must be recomputed from the filtered
    checks too -- keeping the original 140 would itself leak "there are 2
    more checks you can't see yet"."""
    checks = visible_checks(report.get("checks", []))
    return {
        **report,
        "checks": checks,
        "total_score": sum(c.get("score", 0) for c in checks),
        "max_score": sum(c.get("max_score", 0) for c in checks),
    }


def parse_leaderboard_file(path: Path) -> dict[str, Any] | None:
    """Read + filter one leaderboard_<target>.json. Returns None (logged,
    not raised) for missing/partial/corrupt files -- checker.py rewrites
    this file non-atomically every poll cycle, so reading it mid-write is
    an expected, transient race, not an error worth crashing the poller for."""
    try:
        raw = path.read_text(encoding="utf-8")
        report = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        logger.debug("skipping unreadable/partial leaderboard file %s: %s", path.name, exc)
        return None

    if "target" not in report or "checks" not in report:
        logger.warning("leaderboard file %s missing expected fields, skipping", path.name)
        return None

    return filtered_report(report)


class BlueScoreTailer:
    """Polls a directory of leaderboard_<target>.json files and upserts the
    (leak-filtered) latest snapshot per target into the store. Also, if
    seat_log_dir is given, separately scans for existing blue seats -- see
    find_blue_seat_names()'s docstring for why this is a second data source
    instead of just trusting blue_scores' own row count."""

    def __init__(
        self,
        score_dir: str,
        store: EventStore,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        seat_log_dir: str | None = None,
    ):
        self.score_dir = Path(score_dir)
        self.seat_log_dir = Path(seat_log_dir) if seat_log_dir else None
        self.store = store
        self.poll_interval = poll_interval

    def _poll_once(self) -> None:
        if not self.score_dir.exists():
            logger.warning("blue score directory does not exist: %s", self.score_dir)
        else:
            for path in sorted(self.score_dir.glob("leaderboard_*.json")):
                report = parse_leaderboard_file(path)
                if report is None:
                    continue
                try:
                    # upsert 前先拿舊快照——issue #33 要拿它跟這次的報告 diff，
                    # 找出哪一項 check 剛從 fail 翻 pass，補一筆合成事件進
                    # normalized_events。順序不能反：upsert 完再查就只會拿到
                    # 新值，diff 不出東西。
                    previous = self.store.get_blue_score(target=report["target"])
                    self.store.upsert_blue_score(
                        target=report["target"],
                        total_score=report["total_score"],
                        max_score=report["max_score"],
                        checks=report["checks"],
                        observed_at=report["timestamp"],
                    )
                    self._record_newly_passed_checks(previous, report)
                except Exception:
                    logger.exception("failed to upsert blue score for %s", path.name)

        if self.seat_log_dir is not None:
            for seat in find_blue_seat_names(self.seat_log_dir):
                try:
                    self.store.record_known_blue_seat(seat=seat)
                except Exception:
                    logger.exception("failed to record known blue seat %s", seat)

    def _record_newly_passed_checks(self, previous: dict[str, Any] | None, report: dict[str, Any]) -> None:
        """checker.py 判定某一題從 fail 翻 pass，補一筆合成的 blue.remediation
        事件進 normalized_events（issue #33）——analysis.py 的事後應對比對
        要靠這個當「真的驗證過修好了」的客觀訊號，跟 cmdlog 關鍵字猜測交叉
        比對，兩者都成立才算數，單靠其中一種都不夠可靠。

        沿用既有事件管線（adapters/blue.py 的 normalize()），不用另開資料表
        或端點——這批事件自然會出現在 /events，也會被
        analysis.py 的 correlate() 掃到。report 已經是 filtered_report() 處理
        過的（隱藏題解鎖前不出現），這裡不用重複過濾，也不會因此洩漏隱藏
        題進度。

        previous 是 None（第一次看到這個 target）時，不補任何事件——沒有
        「之前」可比較，不能把「第一次回報就是 pass」當成「剛修好」，那
        通常代表這關本來就沒被破過，不是藍隊做了什麼。
        """
        if previous is None:
            return
        old_ids = _passed_check_ids(previous["checks"])
        new_ids = _passed_check_ids(report["checks"])
        for check_id in sorted(new_ids - old_ids):
            payload = {
                "message": f"checker.py: {_check_label(check_id)} 已修復",
                "event_type": "blue.remediation",
                "source": report["target"],
                "observed_at": report["timestamp"],
            }
            try:
                event = blue.normalize(payload)
                self.store.append(team="blue", raw_payload=payload, event=event)
            except Exception:
                logger.exception("failed to record remediation event for %s/%s", report["target"], check_id)

    async def run(self) -> None:
        logger.info("blue score tailer started, monitoring %s", self.score_dir)
        while True:
            try:
                self._poll_once()
            except Exception:
                logger.exception("error in blue score tailer loop, continuing")
            await asyncio.sleep(self.poll_interval)


async def serve(
    score_dir: str = DEFAULT_SCORE_DIR,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    store: EventStore | None = None,
    seat_log_dir: str | None = DEFAULT_SEAT_LOG_DIR,
) -> None:
    store = store or EventStore.from_env()
    store.ensure_schema()
    await BlueScoreTailer(score_dir, store, poll_interval, seat_log_dir=seat_log_dir).run()


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    score_dir = os.environ.get("BLUE_SCORE_DIR", DEFAULT_SCORE_DIR)
    poll_interval = float(os.environ.get("BLUE_SCORE_POLL_INTERVAL", str(DEFAULT_POLL_INTERVAL)))
    seat_log_dir = os.environ.get("SEAT_LOG_DIR", DEFAULT_SEAT_LOG_DIR)
    asyncio.run(serve(score_dir=score_dir, poll_interval=poll_interval, seat_log_dir=seat_log_dir))


if __name__ == "__main__":
    main()
