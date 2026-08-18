from __future__ import annotations

"""Evidence —— 一個事件前後的上下文窗。

取代 cyber 的 `purple/evidence/resolver.py` + `backends.py`。那兩個檔案
存在的意義是抽象出一個可替換的遙測後端（實務上是 Loki），因為 Core Event
本身不帶原始 log 行。rbcollector 沒有這個分拆：`raw_events`（見
store.py）已經存了每一筆原始 ingest payload，沒有後端可插——這個模組
只是查一次 store，再套上跟 resolver.py 同一種「呼叫者的 clearance 決定
看得到什麼」的邊界（呼叫端不能自己帶查詢語法，只能給 event_id + 身分）。
"""

from typing import Any

from rbcollector.disclosure import RAW_CONTEXT_VISIBILITY, visible_to


class EvidenceNotFound(Exception):
    """沒有這個 event_id 對應的事件。"""


def resolve_context(store: Any, event_id: str, caller: str, window_minutes: int = 5) -> dict[str, Any]:
    """`event_id` 前後 `window_minutes` 內的原始 payload，依 `caller` 的
    clearance 過濾。沒有權限的呼叫者拿到的是過濾後的空結果，不是錯誤——
    只有 event_id 不存在才會拋例外。"""
    lines = store.context(event_id, window_minutes=window_minutes)
    if lines is None:
        raise EvidenceNotFound(f"no event with event_id {event_id!r}")

    visible = lines if visible_to(caller, RAW_CONTEXT_VISIBILITY) else []
    return {
        "event_id": event_id,
        "window_minutes": window_minutes,
        "line_count": len(visible),
        "lines": visible,
    }
