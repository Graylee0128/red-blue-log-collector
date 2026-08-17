from __future__ import annotations
from typing import Any
from rbcollector.adapters.common import first, parse_timestamp
from rbcollector.models import NormalizedEvent

class BlueAdapter:
    def normalize(self, payload: dict[str, Any]) -> NormalizedEvent:
        message = first(payload, ("message","alert","rule","description","action"))
        return NormalizedEvent(
            team="blue",
            observed_at=parse_timestamp(first(payload, ("observed_at","timestamp","time","ts"))),
            source_ip=first(payload, ("source_ip","src_ip","src","attacker_ip","ip")),
            destination=first(payload, ("destination","target","target_ip","dst_ip","host","service")),
            action_result=str(first(payload, ("action_result","result","outcome","status","severity"), "unknown")),
            event_type=str(first(payload, ("event_type","type"), "blue.event")),
            source=str(first(payload, ("source","producer","sensor"), "blue-team-api")),
            actor=first(payload, ("actor","analyst","user","username")),
            message=str(message) if message is not None else None,
            correlation_id=first(payload, ("correlation_id","action_id","request_id","trace_id","alert_id","session_id")),
            metadata=dict(payload),
        )


def normalize(payload: dict[str, Any]) -> dict[str, Any]:
    return BlueAdapter().normalize(payload).model_dump(mode="json")
