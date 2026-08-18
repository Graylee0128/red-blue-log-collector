from rbcollector.disclosure import (
    clearance,
    visibility_for_correlation,
    visibility_rank,
    visible_to,
)


def test_hit_is_public():
    assert visibility_for_correlation({"status": "hit"}) == "public"


def test_detection_gap_is_purple_only():
    assert visibility_for_correlation({"status": "detection_gap"}) == "purple"


def test_visibility_gap_is_purple_only():
    assert visibility_for_correlation({"status": "visibility_gap"}) == "purple"


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
