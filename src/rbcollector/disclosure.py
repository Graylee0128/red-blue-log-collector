from __future__ import annotations

"""可見度分級 —— 從 cyber 的 4 級 clearance（`public < blue < purple <
instructor`，`src/disclosure/clearance.py`／`event_visibility.py`）收斂成
2 級，照 issue #3 的搬遷計畫：rbcollector 沒有獨立的藍隊或教官受眾，
所以分別併入 `public` 跟 `purple`。

  public  — 一般觀眾／Battleboard：`/analysis` 的 correlation 列全部看
            得到（含 miss），但看不到原始遙測（見 RAW_CONTEXT_VISIBILITY）。
  purple  — 紫隊與教官：額外看得到原始證據（evidence context）。

2026-08-18 起，correlation 的 hit/detection_gap/visibility_gap 三種狀態
不再分級——這個 repo 的 Battleboard 頁面明確定位是「全場觀眾即時戰況
板」，「這次攻擊藍隊有沒有抓到」本身就是要秀給觀眾看的資訊，不是要護著
的落差，跟 cyber 的 `detection.miss`（觀眾/藍隊本來就不該看見任一方漏了
什麼）刻意做了不同的選擇。只有原始遙測細節（evidence context）還維持
purple-only。

`hit` 立刻公開沒問題（偵測成功本身不是要藏的東西），但 gap
（detection_gap／visibility_gap）延遲 GAP_REVEAL_DELAY_SECONDS 秒才公開
——紅隊行動剛發生就把「藍隊還沒抓到」秀在公開戰況板上，等於直接洩題給
藍隊照著補救，測不出真實的偵測表現。延遲只影響「觀眾看不看得到」，不
影響 hit/gap 判定本身（那是 analysis.py 的事，不會因為延遲而改變）。
"""

from datetime import datetime, timezone
from typing import Any

VISIBILITY_RANK = {"public": 0, "purple": 1}
CALLER_CLEARANCE = {"public": 0, "purple": 1}

#: 原始上下文行（evidence）屬遙測細節，只有紫隊能看，比照 cyber
#: LokiBackend.line_visibility 的預設值（"blue" 以上，這裡收斂成
#: 剩下的、最接近的那一級 "purple"）。
RAW_CONTEXT_VISIBILITY = "purple"

#: gap 從發生到對 public 揭露之間的緩衝時間，見模組 docstring。
GAP_REVEAL_DELAY_SECONDS = 60


def visibility_rank(visibility: str) -> int:
    """未知的 visibility -> fail closed，當成最嚴格一級。"""
    return VISIBILITY_RANK.get(visibility, max(VISIBILITY_RANK.values()))


def clearance(caller: str) -> int:
    """未知的 caller -> fail closed（等級 -1，比 public 還低）。"""
    return CALLER_CLEARANCE.get(caller, -1)


def _age_seconds(observed_at: Any) -> float | None:
    """紅隊事件發生至今經過幾秒，解析失敗或沒給值時回傳 None（讓呼叫端
    fail closed，當成「還沒過延遲」處理）。"""
    if not observed_at:
        return None
    try:
        ts = datetime.fromisoformat(str(observed_at).replace("Z", "+00:00"))
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - ts).total_seconds()


def visibility_for_correlation(row: dict[str, Any]) -> str:
    """`/analysis` 一列 correlation 的可見度，由 status 跟時間共同導出——
    不是呼叫端能自報的。`hit` 立即公開；gap 要等紅隊事件過了
    GAP_REVEAL_DELAY_SECONDS 秒才公開，時間沒到、或算不出經過多久（沒給
    觀察時間），一律 fail closed 成 purple-only。"""
    if row.get("status") == "hit":
        return "public"
    age = _age_seconds((row.get("red") or {}).get("observed_at"))
    if age is not None and age >= GAP_REVEAL_DELAY_SECONDS:
        return "public"
    return "purple"


def visible_to(caller: str, visibility: str) -> bool:
    return clearance(caller) >= visibility_rank(visibility)
