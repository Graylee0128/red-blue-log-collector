from __future__ import annotations

"""可見度分級 —— 從 cyber 的 4 級 clearance（`public < blue < purple <
instructor`，`src/disclosure/clearance.py`／`event_visibility.py`）收斂成
2 級，照 issue #3 的搬遷計畫：rbcollector 沒有獨立的藍隊或教官受眾，
所以分別併入 `public` 跟 `purple`。

  public  — 一般觀眾／Battleboard：只看得到「某技法被偵測到了」，
            看不到 miss，也看不到原始遙測。
  purple  — 紫隊與教官：看得到全部，包含偵測落差與原始證據。

`purple` 刻意跟 `public` 分開——照搬遷計畫的提醒：detection_gap／
visibility_gap 絕對不能被顯示成 `public`，這正是 cyber 的
「detection.miss 只有紫隊能看」這個特性要保護的東西。
"""

from typing import Any

VISIBILITY_RANK = {"public": 0, "purple": 1}
CALLER_CLEARANCE = {"public": 0, "purple": 1}

#: 原始上下文行（evidence）屬遙測細節，只有紫隊能看，比照 cyber
#: LokiBackend.line_visibility 的預設值（"blue" 以上，這裡收斂成
#: 剩下的、最接近的那一級 "purple"）。
RAW_CONTEXT_VISIBILITY = "purple"


def visibility_rank(visibility: str) -> int:
    """未知的 visibility -> fail closed，當成最嚴格一級。"""
    return VISIBILITY_RANK.get(visibility, max(VISIBILITY_RANK.values()))


def clearance(caller: str) -> int:
    """未知的 caller -> fail closed（等級 -1，比 public 還低）。"""
    return CALLER_CLEARANCE.get(caller, -1)


def visibility_for_correlation(row: dict[str, Any]) -> str:
    """`/analysis` 一列 correlation 的可見度，由它的 status 導出——不是
    呼叫端能自報的。`hit` 可以公開展示（某件事被抓到了這件事本身是安全
    的）。gap 一定要維持 purple-only：演練進行中就跟觀眾/藍隊講「這個
    技法漏掉了」，正是 cyber 的 `detection.miss` 這一級當初要擋的洩漏。"""
    return "public" if row.get("status") == "hit" else "purple"


def visible_to(caller: str, visibility: str) -> bool:
    return clearance(caller) >= visibility_rank(visibility)
