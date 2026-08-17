from __future__ import annotations
from typing import Any
from rbcollector.adapters.common import first, parse_timestamp
from rbcollector.models import NormalizedEvent

class RedAdapter:
    def normalize(self, payload: dict[str, Any]) -> NormalizedEvent:
        command = first(payload, ("command","cmd","action","request","message"))
        return NormalizedEvent(
            team="red",
            observed_at=parse_timestamp(first(payload, ("observed_at","timestamp","time","ts"))),
            source_ip=first(payload, ("source_ip","src_ip","src","ip")),
            destination=first(payload, ("destination","target","target_ip","dst_ip","url","path")),
            action_result=str(first(payload, ("action_result","result","outcome","status","exit_code"), "unknown")),
            event_type=str(first(payload, ("event_type","type"), "red.action")),
            source=str(first(payload, ("source","producer"), "red-team-api")),
            actor=first(payload, ("actor","user","player","username","seat_id")),
            message=str(command) if command is not None else None,
            correlation_id=first(payload, ("correlation_id","action_id","request_id","trace_id","session_id")),
            metadata=dict(payload),
        )
