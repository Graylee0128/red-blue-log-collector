from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

Team = Literal["red", "blue"]


class NormalizedEvent(BaseModel):
    """Standalone event contract derived from cyber's telemetry field contract."""

    event_id: str = Field(default_factory=lambda: "evt-" + uuid4().hex)
    team: Team
    observed_at: datetime
    source_ip: str | None = None
    destination: str | None = None
    action_result: str | None = None
    event_type: str
    source: str
    actor: str | None = None
    message: str | None = None
    correlation_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("observed_at must include timezone")
        return value

    @classmethod
    def now(cls, **kwargs: Any) -> "NormalizedEvent":
        return cls(observed_at=datetime.now(timezone.utc), **kwargs)
