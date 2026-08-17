from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles

from .adapters import blue, red
from .analysis import summarize
from .evidence import EvidenceNotFound, resolve_context
from .store import EventStore

app = FastAPI(title="Red/Blue Log Collector", version="0.1.0")
store = EventStore.from_env()

# 紫隊 Console／Battleboard 骨架（cyber 沿革見 docs/COPY_FROM_CYBER.md）——
# 直接從磁碟served，沒有身分驗證、沒有建置步驟。repo 根目錄是這個檔案
# 往上兩層（src/rbcollector/server.py -> repo root）；Dockerfile 把 ui/
# 跟 src/ 一起複製進容器，所以路徑解析在本機跟容器裡是一致的。用
# `is_dir()` 判斷再掛載，這樣沒有 ui/ 的 checkout／image（例如未來只發
# package 不含前端）import 時不會直接炸掉。
_UI_DIR = Path(__file__).resolve().parents[2] / "ui"
if _UI_DIR.is_dir():
    app.mount("/ui", StaticFiles(directory=_UI_DIR, html=True), name="ui")


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


@app.post("/ingest/red")
def ingest_red(payload: dict[str, Any]) -> dict[str, Any]:
    return _ingest("red", payload)


@app.post("/ingest/blue")
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


@app.get("/events/{event_id}/context")
def event_context(
    event_id: str,
    caller: Literal["public", "purple"] = "public",
    window_minutes: int = Query(5, ge=1, le=60),
) -> dict[str, Any]:
    try:
        return resolve_context(store, event_id, caller, window_minutes=window_minutes)
    except EvidenceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
