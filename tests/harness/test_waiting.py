"""等待邏輯 —— 用假 clock 與假 fetch，不真的等。

搬自 cyber 的 `tests/harness/test_waiting.py`；`wait_for_event` 本身跟
schema 無關，搬過來不需要改行為，訊息也跟 `tests/harness/waiting.py`
一樣維持中文。"""

import pytest

from harness.waiting import EventNotSeen, wait_for_event


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def _harness(*rounds: list[dict]):
    """每次呼叫 fetch() 回傳下一輪的結果。用完後固定回最後一輪。"""
    state = list(rounds)

    def fetch():
        return state.pop(0) if len(state) > 1 else state[0]

    return fetch


EVENT = {"event_id": "evt-1", "team": "red", "event_type": "red.action"}


class TestFindsTheEvent:
    def test_returns_immediately_when_already_present(self):
        clock = FakeClock()
        got = wait_for_event(_harness([EVENT]), lambda e: True, clock=clock, sleep=lambda s: None)
        assert got == EVENT
        assert clock.t == 0

    def test_polls_until_the_event_appears(self):
        clock = FakeClock()
        fetch = _harness([], [], [EVENT])
        got = wait_for_event(
            fetch, lambda e: True, clock=clock, sleep=lambda s: clock.advance(s), poll_s=0.5
        )
        assert got == EVENT
        assert clock.t == pytest.approx(1.0)

    def test_ignores_events_that_do_not_match(self):
        other = {"event_id": "evt-other", "team": "blue", "event_type": "blue.alert"}
        got = wait_for_event(
            _harness([other, EVENT]),
            lambda e: e["event_id"] == "evt-1",
            clock=FakeClock(),
            sleep=lambda s: None,
        )
        assert got == EVENT


class TestTimeout:
    """這一組是載具的 smoke test：證明它會在事件沒出現時失敗。
    一個從不會紅的載具，比沒有載具更糟。"""

    def test_raises_when_nothing_ever_matches(self):
        clock = FakeClock()
        with pytest.raises(EventNotSeen):
            wait_for_event(
                _harness([]),
                lambda e: True,
                timeout_s=2,
                poll_s=0.5,
                clock=clock,
                sleep=lambda s: clock.advance(s),
            )

    def test_does_not_wait_forever(self):
        clock = FakeClock()
        with pytest.raises(EventNotSeen):
            wait_for_event(
                _harness([]),
                lambda e: True,
                timeout_s=2,
                poll_s=0.5,
                clock=clock,
                sleep=lambda s: clock.advance(s),
            )
        assert clock.t <= 2.5

    def test_empty_pipeline_is_called_out_specifically(self):
        """完全沒事件 ≠ 有事件但沒中。前者是管路沒通，該講清楚。"""
        clock = FakeClock()
        with pytest.raises(EventNotSeen, match="完全沒有"):
            wait_for_event(
                _harness([]), lambda e: True, timeout_s=1, clock=clock,
                sleep=lambda s: clock.advance(s),
            )

    def test_timeout_message_lists_what_was_seen(self):
        clock = FakeClock()
        noise = [{"event_id": f"evt-{i}", "team": "blue", "event_type": "blue.alert"} for i in range(3)]
        with pytest.raises(EventNotSeen) as exc:
            wait_for_event(
                _harness(noise), lambda e: False, what="attack event", timeout_s=1,
                clock=clock, sleep=lambda s: clock.advance(s),
            )
        message = str(exc.value)
        assert "attack event" in message
        assert "evt-0" in message
        assert "看到 3 筆" in message

    def test_long_event_list_is_truncated(self):
        """逾時訊息要能讀。上百筆全 dump 等於沒訊息。"""
        clock = FakeClock()
        many = [{"event_id": f"evt-{i}"} for i in range(25)]
        with pytest.raises(EventNotSeen) as exc:
            wait_for_event(
                _harness(many), lambda e: False, timeout_s=1, clock=clock,
                sleep=lambda s: clock.advance(s),
            )
        assert "另有 15 筆" in str(exc.value)
