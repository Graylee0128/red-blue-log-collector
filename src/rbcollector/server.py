from __future__ import annotations

from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query

from .adapters import blue, red
from .analysis import summarize
from .auth import require_ingest_token
from .store import EventStore

app = FastAPI(title="Red/Blue Log Collector", version="0.1.0")
store = EventStore.from_env()


@app.on_event("startup")
def startup() -> None:
    store.ensure_schema()


@app.get("/healthz")
def healthz() -> dict[str, str]:
    store.ping()
    return {"status": "ok"}


def _ingest(team: Literal["red", "blue"], payload: dict[str, Any]) -> dict[str, Any]:
    adapter = red.normalize if team == "red" else blue.normalize
    try:
        event = adapter(payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    inserted = store.append(team=team, raw_payload=payload, event=event)
    return {"inserted": inserted, "event": event}


@app.post("/ingest/red", dependencies=[Depends(require_ingest_token)])
def ingest_red(payload: dict[str, Any]) -> dict[str, Any]:
    return _ingest("red", payload)


@app.post("/ingest/blue", dependencies=[Depends(require_ingest_token)])
def ingest_blue(payload: dict[str, Any]) -> dict[str, Any]:
    return _ingest("blue", payload)


@app.get("/events")
def events(team: Literal["red", "blue"] | None = None, limit: int = Query(500, ge=1, le=5000)) -> list[dict[str, Any]]:
    return store.list_events(team=team, limit=limit)


@app.get("/timeline")
def timeline(limit: int = Query(500, ge=1, le=5000)) -> list[dict[str, Any]]:
    return store.list_events(team=None, limit=limit)


@app.get("/analysis")
def analysis(limit: int = Query(5000, ge=1, le=20000)) -> dict[str, Any]:
    return summarize(store.list_events(team=None, limit=limit))
