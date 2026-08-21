from __future__ import annotations

"""等事件出現。

近乎原樣搬自 cyber 的 `src/purple/harness/waiting.py`——這個模組跟 cyber 的
Core Event schema 完全無耦合（只吃可注入的 fetch/match/clock/sleep 呼叫物件），
所以直接套用在 rbcollector 的 NormalizedEvent 形狀的 dict 上也成立。是測試
工具，不是服務：放在 `tests/` 底下，不進 `src/rbcollector/`。

這裡等的管路是非同步的（ingest -> adapter -> Postgres -> /analysis），
測試不能立刻斷言，也不能 `sleep(30)` 賭運氣。輪詢有 `timeout_s` 上限，
逾時一定拋出明確的例外，不會無窮迴圈——沒有死鎖風險。
"""

import json
import time
from typing import Any, Callable

DEFAULT_TIMEOUT_S = 30.0
DEFAULT_POLL_S = 0.5

Fetch = Callable[[], list[dict[str, Any]]]
Match = Callable[[dict[str, Any]], bool]


class EventNotSeen(AssertionError):
    """等到逾時仍沒有符合條件的事件。訊息一定要說出「看到了什麼」——
    只說「逾時」等於把人丟回去手動查，而那時候管路狀態已經變了。"""


def wait_for_event(
    fetch: Fetch,
    match: Match,
    what: str = "matching event",
    timeout_s: float = DEFAULT_TIMEOUT_S,
    poll_s: float = DEFAULT_POLL_S,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """輪詢 `fetch()` 直到有事件符合 `match`，逾時（`timeout_s`）則拋出
    `EventNotSeen`。"""
    deadline = clock() + timeout_s
    seen: list[dict[str, Any]] = []

    while True:
        seen = fetch()
        for event in seen:
            if match(event):
                return event

        if clock() >= deadline:
            raise EventNotSeen(_timeout_message(what, timeout_s, seen))

        sleep(poll_s)


def _timeout_message(what: str, timeout_s: float, seen: list[dict[str, Any]]) -> str:
    head = f"等了 {timeout_s:g}s 沒有出現 {what}。"
    if not seen:
        return head + "\n期間**完全沒有**任何事件 —— 管路可能整條沒通，不只是這一筆沒中。"

    lines = [f"{head}\n期間看到 {len(seen)} 筆事件："]
    for event in seen[:10]:
        lines.append("  - " + _summarise(event))
    if len(seen) > 10:
        lines.append(f"  … 另有 {len(seen) - 10} 筆")
    return "\n".join(lines)


def _summarise(event: dict[str, Any]) -> str:
    """挑出足以辨認事件的欄位——整包 dump 會把逾時訊息淹掉。"""
    keys = ("event_id", "team", "event_type", "source", "correlation_id", "observed_at")
    parts = [f"{k}={event[k]!r}" for k in keys if k in event]
    return ", ".join(parts) if parts else json.dumps(event, ensure_ascii=False)[:120]
