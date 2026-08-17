from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Iterable

def first(payload: dict[str, Any], names: Iterable[str], default: Any = None) -> Any:
    for name in names:
        value = payload.get(name)
        if value not in (None, ""):
            return value
    return default

def parse_timestamp(value: Any) -> datetime:
    if value in (None, ""):
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds > 10_000_000_000:
            seconds /= 1000
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
