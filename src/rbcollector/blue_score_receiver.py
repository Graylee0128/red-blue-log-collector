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
from pathlib import Path
from typing import Any

from .store import EventStore

logger = logging.getLogger("rbcollector.blue_score_receiver")

DEFAULT_SCORE_DIR = "/var/lib/metis/blue-scores"
DEFAULT_POLL_INTERVAL = 5.0  # seconds -- checker.py itself re-checks every ~10s

# Mirrors checker.py's hidden bonus check ids exactly -- these are the ids
# that must not be visible until the 5 formal checks all pass.
_HIDDEN_CHECK_IDS = ("vuln6_webshell_bonus", "vuln7_docker_escape")


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
    (leak-filtered) latest snapshot per target into the store."""

    def __init__(self, score_dir: str, store: EventStore, poll_interval: float = DEFAULT_POLL_INTERVAL):
        self.score_dir = Path(score_dir)
        self.store = store
        self.poll_interval = poll_interval

    def _poll_once(self) -> None:
        if not self.score_dir.exists():
            logger.warning("blue score directory does not exist: %s", self.score_dir)
            return

        for path in sorted(self.score_dir.glob("leaderboard_*.json")):
            report = parse_leaderboard_file(path)
            if report is None:
                continue
            try:
                self.store.upsert_blue_score(
                    target=report["target"],
                    total_score=report["total_score"],
                    max_score=report["max_score"],
                    checks=report["checks"],
                    observed_at=report["timestamp"],
                )
            except Exception:
                logger.exception("failed to upsert blue score for %s", path.name)

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
) -> None:
    store = store or EventStore.from_env()
    store.ensure_schema()
    await BlueScoreTailer(score_dir, store, poll_interval).run()


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    score_dir = os.environ.get("BLUE_SCORE_DIR", DEFAULT_SCORE_DIR)
    poll_interval = float(os.environ.get("BLUE_SCORE_POLL_INTERVAL", str(DEFAULT_POLL_INTERVAL)))
    asyncio.run(serve(score_dir=score_dir, poll_interval=poll_interval))


if __name__ == "__main__":
    main()
