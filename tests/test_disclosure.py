from datetime import datetime, timedelta, timezone

from rbcollector.disclosure import (
    GAP_REVEAL_DELAY_SECONDS,
    clearance,
    visibility_for_correlation,
    visibility_rank,
    visible_to,
)


def _iso(seconds_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()


def test_hit_is_immediately_public():
    # hit 不用等延遲，就算紅隊行動剛發生也立刻公開。
    row = {"status": "hit", "red": {"observed_at": _iso(0)}}
    assert visibility_for_correlation(row) == "public"


def test_recent_gap_stays_purple_only():
    # 2026-08-18 起 gap 也會公開，但要等 GAP_REVEAL_DELAY_SECONDS 秒——剛
    # 發生的 gap 不能立刻秀給觀眾，不然藍隊照著補救等於洩題。
    row = {"status": "detection_gap", "red": {"observed_at": _iso(5)}}
    assert visibility_for_correlation(row) == "purple"


def test_gap_becomes_public_once_delay_passes():
    row = {"status": "visibility_gap", "red": {"observed_at": _iso(GAP_REVEAL_DELAY_SECONDS + 5)}}
    assert visibility_for_correlation(row) == "public"


def test_gap_without_observed_at_fails_closed_to_purple():
    # 算不出經過多久，寧可先當成沒過延遲，不要提早洩漏。
    assert visibility_for_correlation({"status": "detection_gap"}) == "purple"


def test_purple_outranks_public():
    assert visibility_rank("purple") > visibility_rank("public")


def test_unknown_visibility_fails_closed_to_the_strictest_tier():
    assert visibility_rank("something-new") == visibility_rank("purple")


def test_unknown_caller_fails_closed_below_public():
    assert clearance("red") < clearance("public")


def test_public_caller_cannot_see_purple_content():
    assert visible_to("public", "purple") is False


def test_purple_caller_sees_everything():
    assert visible_to("purple", "public") is True
    assert visible_to("purple", "purple") is True
