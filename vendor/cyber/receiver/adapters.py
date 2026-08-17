"""Core Event 的外送 adapter。

下游消費者 Cyber Range Core 屬 workstream 5，目前尚不存在。外送以可插拔
adapter 隔離 —— 日後接上真正的 Core 不需改 receiver。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class CoreEventAdapter(Protocol):
    def deliver(self, core_event: dict[str, Any]) -> None:
        ...


class NoopAdapter:
    """workstream 5 尚未存在時的預設。Core Event 已落 P1 自有儲存，這裡不做事。"""

    def deliver(self, core_event: dict[str, Any]) -> None:
        return None


@dataclass
class RecordingAdapter:
    """測試用：記錄外送了哪些 Core Event。"""
    delivered: list[dict[str, Any]] = field(default_factory=list)

    def deliver(self, core_event: dict[str, Any]) -> None:
        self.delivered.append(core_event)
