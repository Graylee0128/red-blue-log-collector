from __future__ import annotations

"""NormalizedEvent 契約的可執行版本。

重寫自 cyber 的 `src/purple/harness/schema.py`（那個版本驗的是 cyber 自己
的 Core Event 契約：`exercise_id`／`scenario_id`／`lifecycle`／`visibility`／
`action_id`——這些欄位在這個 repo 不存在）。這裡改成驗
`rbcollector.models.NormalizedEvent` 的形狀（見 `docs/INTERFACE_CONTRACT.md`），
並且拒絕 cyber 專屬字彙，避免以後不小心又偷偷長回來。
"""

import json
from datetime import datetime
from typing import Any

REQUIRED_FIELDS = frozenset({"event_id", "team", "observed_at", "event_type", "source"})

#: cyber Core Event 的欄位，在這裡沒有意義——出現代表測試寫成了 cyber 的
#: 事件形狀，不是 NormalizedEvent。
FORBIDDEN_FIELDS = frozenset(
    {"exercise_id", "scenario_id", "lifecycle", "visibility", "action_id", "evidence_ref", "raw", "payload", "threshold", "query", "backend"}
)

#: 不該漏進事件內容的後端字彙（這個 repo 沒有 Loki/Grafana——見
#: docs/COPY_FROM_CYBER.md 的「砍掉的耦合」清單）。
BACKEND_WORDS = ("loki", "logql", "promql", "grafana")

TEAMS = frozenset({"red", "blue"})


class SchemaViolation(AssertionError):
    """事件不符合 NormalizedEvent 契約。繼承 AssertionError，讓 pytest
    直接當成斷言失敗。"""


def assert_normalized_event(event: dict[str, Any]) -> None:
    """符合契約就靜靜通過，不符合就拋出指名問題的 SchemaViolation。"""
    _reject_forbidden(event)
    _require_fields(event)
    _check_team(event["team"])
    _check_observed_at(event["observed_at"])
    _reject_backend_vocabulary(event)


def _reject_forbidden(event: dict[str, Any]) -> None:
    present = sorted(FORBIDDEN_FIELDS & event.keys())
    if present:
        raise SchemaViolation(
            f"forbidden field(s) {', '.join(present)}: cyber Core Event 字彙，"
            f"不屬於 NormalizedEvent（見 docs/INTERFACE_CONTRACT.md）"
        )


def _require_fields(event: dict[str, Any]) -> None:
    missing = REQUIRED_FIELDS - event.keys()
    if missing:
        raise SchemaViolation(f"missing required field(s): {', '.join(sorted(missing))}")


def _check_team(value: object) -> None:
    if value not in TEAMS:
        raise SchemaViolation(f"invalid team {value!r}, expected one of {sorted(TEAMS)}")


def _check_observed_at(value: object) -> None:
    if not isinstance(value, str):
        raise SchemaViolation(f"observed_at must be an ISO-8601 string, got {type(value).__name__}")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise SchemaViolation(f"observed_at {value!r} is not ISO-8601") from exc
    if parsed.tzinfo is None:
        raise SchemaViolation(f"observed_at {value!r} has no timezone")


def _reject_backend_vocabulary(event: dict[str, Any]) -> None:
    blob = json.dumps(event, ensure_ascii=False).lower()
    for word in BACKEND_WORDS:
        if word in blob:
            raise SchemaViolation(
                f"backend vocabulary {word!r} appears in the event —— "
                f"這個 repo 沒有 Grafana/Loki，遙測細節不該漏進來"
            )
