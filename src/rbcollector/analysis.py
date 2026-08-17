from __future__ import annotations

from datetime import datetime
from statistics import median
from typing import Any


def correlate(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    reds = [e for e in events if e.get("team") == "red"]
    blues = [e for e in events if e.get("team") == "blue"]
    results: list[dict[str, Any]] = []

    for red in reds:
        match = _find_match(red, blues)
        if match is None:
            results.append({"red": red, "blue": None, "status": "visibility_gap", "latency_ms": None})
            continue

        latency_ms = _delta_ms(red.get("observed_at"), match.get("observed_at"))
        detected = _is_detection(match)
        results.append({
            "red": red,
            "blue": match,
            "status": "hit" if detected else "detection_gap",
            "latency_ms": latency_ms,
        })
    return results


def summarize(events: list[dict[str, Any]]) -> dict[str, Any]:
    rows = correlate(events)
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
