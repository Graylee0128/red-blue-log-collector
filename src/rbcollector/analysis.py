from __future__ import annotations

from datetime import datetime
from statistics import median
from typing import Any

from rbcollector.detections import evaluate_detections


def correlate(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    reds = [e for e in events if e.get("team") == "red"]
    blues = [e for e in events if e.get("team") == "blue"]
    results: list[dict[str, Any]] = []

    for red in reds:
        match = _find_match(red, blues)
        if match is not None:
            latency_ms = _delta_ms(red.get("observed_at"), match.get("observed_at"))
            if _is_detection(match):
                results.append({
                    "red": red,
                    "blue": match,
                    "status": "hit",
                    "latency_ms": latency_ms,
                    "detection_method": "alert",
                })
                continue
            # 30 秒內有配對到藍隊事件，但不是告警——先記下來當 fallback。
            # 事後應對比對（issue #33）等一下如果也沒找到更好的結果，就用
            # 這筆，沿用原本 detection_gap 的行為，不因為新增這條路就讓
            # 這種情況突然沒有 blue 可以顯示。
            fallback = {"red": red, "blue": match, "status": "detection_gap", "latency_ms": latency_ms, "detection_method": None}
        else:
            fallback = {"red": red, "blue": None, "status": "visibility_gap", "latency_ms": None, "detection_method": None}

        # issue #33：30 秒即時偵測沒找到告警，不代表藍隊完全沒處理——用
        # 獨立的 5 分鐘窗口找「事後應對」（封鎖/修補），跟上面的即時偵測
        # 窗口分開算，見 _find_response_action() 的說明。
        response = _find_response_action(red, blues)
        if response is not None:
            results.append({
                "red": red,
                "blue": response,
                "status": "hit",
                "latency_ms": _delta_ms(red.get("observed_at"), response.get("observed_at")),
                "detection_method": "response",
            })
        else:
            results.append(fallback)
    return results


def summarize(events: list[dict[str, Any]]) -> dict[str, Any]:
    rows = correlate(events)

    # 資料驅動偵測規則（取代 cyber 的 Grafana 告警規則，見 detections.py）
    # 幫每一列標上紅隊事件命中的技法，不動上面已經算好的
    # hit/detection_gap/visibility_gap 判定。
    technique_hits = evaluate_detections(events)
    for row in rows:
        tag = technique_hits.get((row["red"] or {}).get("event_id"))
        row["rule_id"] = tag["rule_id"] if tag else None
        row["technique"] = tag["technique"] if tag else None
        row["severity"] = tag["severity"] if tag else None

    latencies = [r["latency_ms"] for r in rows if r["latency_ms"] is not None and r["status"] == "hit"]
    hits = sum(r["status"] == "hit" for r in rows)
    detection_gaps = sum(r["status"] == "detection_gap" for r in rows)
    visibility_gaps = sum(r["status"] == "visibility_gap" for r in rows)
    total = len(rows)
    return {
        "red_actions": total,
        "detected": hits,
        "detection_gaps": detection_gaps,
        "visibility_gaps": visibility_gaps,
        "detection_rate": (hits / total) if total else None,
        "mttd_p50_ms": round(median(latencies)) if latencies else None,
        "mttd_p95_ms": _nearest_rank(latencies, 95) if latencies else None,
        "correlations": rows,
    }


def _find_match(red: dict[str, Any], blues: list[dict[str, Any]]) -> dict[str, Any] | None:
    corr = red.get("correlation_id")
    if corr:
        for blue in blues:
            if blue.get("correlation_id") == corr:
                return blue

    red_time = _parse(red.get("observed_at"))
    best: tuple[float, dict[str, Any]] | None = None
    for blue in blues:
        if red.get("source_ip") and blue.get("source_ip") and red.get("source_ip") != blue.get("source_ip"):
            continue
        if red.get("destination") and blue.get("destination") and red.get("destination") != blue.get("destination"):
            continue
        blue_time = _parse(blue.get("observed_at"))
        if red_time is None or blue_time is None:
            continue
        delta = (blue_time - red_time).total_seconds()
        if delta < 0 or delta > 30:
            continue
        if best is None or delta < best[0]:
            best = (delta, blue)
    return best[1] if best else None


def _is_detection(event: dict[str, Any]) -> bool:
    event_type = str(event.get("event_type") or "").lower()
    message = str(event.get("message") or "").lower()
    return any(token in event_type or token in message for token in ("alert", "detect", "detection", "firing"))


# issue #33：藍隊「事後應對」（封鎖/修補）比對用的獨立時間窗，跟
# _find_match() 的 30 秒即時偵測窗口分開算——不能直接把 30 秒拉長，那樣
# 會讓「最近的藍隊事件」配對變不準，稀釋掉即時偵測的準確度（5 分鐘內
# 藍隊通常會打很多指令，隨便一句都可能被誤配對成「最近的」）。5 分鐘
# 是跟使用者對過的長度，覆蓋「發現後調查幾分鐘才動手」的實際情境。
_RESPONSE_WINDOW_SECONDS = 300

# 藍隊教練手冊列出的 7 項檢查實際修補指令（.env/shadow 權限、sudoers、
# DB 憑證、cron、iptables、docker socket）整理出的關鍵字，不是憑空編的。
# 只是「看起來像在處理」的啟發式線索，不保證真的成功——真正的驗證交給
# _is_remediation_event()，兩者都成立才算事後應對命中。
_RESPONSE_TOKENS = (
    "chmod", "chown", "iptables", "ufw", "firewall-cmd", "nft ",
    "drop", "deny", "block",
    "rm -f", "delete from", "sudoers",
)


def _is_response_action(event: dict[str, Any]) -> bool:
    message = str(event.get("message") or "").lower()
    return any(token in message for token in _RESPONSE_TOKENS)


def _is_remediation_event(event: dict[str, Any]) -> bool:
    """checker.py 驗證過的修補訊號——blue_score_receiver.py 偵測到某項
    check 從 fail 翻 pass 時，會補一筆這種事件（見該檔案的
    _record_newly_passed_checks()），不是猜的，是客觀驗證過的結果。"""
    return str(event.get("event_type") or "") == "blue.remediation"


def _find_response_action(red: dict[str, Any], blues: list[dict[str, Any]]) -> dict[str, Any] | None:
    """5 分鐘窗口內找「cmdlog 關鍵字 + checker.py 驗證」兩種訊號都成立的
    事後應對（issue #33）。只在紅隊行動之後（不含之前）的窗口內找，不是
    找「最近的任意事件」——那是 _find_match() 在做的事，這裡要更嚴格，
    因為窗口寬很多，隨便配對到不相關指令的風險更高。

    兩種訊號都要存在，單靠其中一種都不夠可靠：cmdlog 命中關鍵字只代表
    「看起來在處理」（可能打錯指令、改錯檔案，根本沒修好）；
    blue.remediation 只代表「有東西修好了」（不知道是不是跟這次紅隊行動
    有關）。兩者在同一個窗口內都出現，才有理由相信是同一次事件。

    回傳 cmdlog 那筆（不是 remediation 那筆）：它的時間點通常比
    checker.py 驗證完成的時間早，latency 算的是「藍隊開始處理」而不是
    「checker.py 確認修好」，比較符合「反應時間」的直覺。
    """
    red_time = _parse(red.get("observed_at"))
    if red_time is None:
        return None

    def _delta_in_window(blue: dict[str, Any]) -> float | None:
        if red.get("source_ip") and blue.get("source_ip") and red.get("source_ip") != blue.get("source_ip"):
            return None
        if red.get("destination") and blue.get("destination") and red.get("destination") != blue.get("destination"):
            return None
        blue_time = _parse(blue.get("observed_at"))
        if blue_time is None:
            return None
        delta = (blue_time - red_time).total_seconds()
        if delta < 0 or delta > _RESPONSE_WINDOW_SECONDS:
            return None
        return delta

    has_remediation = any(
        _delta_in_window(b) is not None for b in blues if _is_remediation_event(b)
    )
    if not has_remediation:
        return None

    best: tuple[float, dict[str, Any]] | None = None
    for candidate in blues:
        if not _is_response_action(candidate):
            continue
        delta = _delta_in_window(candidate)
        if delta is None:
            continue
        if best is None or delta < best[0]:
            best = (delta, candidate)
    return best[1] if best else None


def _parse(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _delta_ms(start: Any, end: Any) -> int | None:
    a, b = _parse(start), _parse(end)
    if a is None or b is None:
        return None
    return round((b - a).total_seconds() * 1000)


def _nearest_rank(values: list[int], percentile: int) -> int:
    ordered = sorted(values)
    import math
    rank = max(1, math.ceil((percentile / 100) * len(ordered)))
    return ordered[rank - 1]
