from __future__ import annotations

from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .adapters import blue, red
from .analysis import summarize
from .auth import require_ingest_token, require_purple_clearance
from .disclosure import visibility_for_correlation, visible_to
from .evidence import EvidenceNotFound, resolve_context
from .store import EventStore

app = FastAPI(title="Red/Blue Log Collector", version="0.1.0")
store = EventStore.from_env()

# Purple Console (ui/purple-console/, served separately on :8090) is a
# different origin fetching this read-only API from the browser -- no
# cookies involved, and every read endpoint already enforces its own
# clearance check (require_purple_clearance), so opening CORS here doesn't
# widen what a caller can see, only where the request is allowed to come
# from.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

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


@app.get("/blue-scores")
def blue_scores() -> list[dict[str, Any]]:
    """藍隊修補進度快照（issue #22），blue_score_receiver.py 寫入。已經是
    leak-filtered 過的資料（隱藏加分題解鎖前不會出現），可以公開讀，跟
    /events 一樣不需要 purple clearance。"""
    return store.list_blue_scores()


@app.get("/possible-breaches")
def possible_breaches() -> list[dict[str, Any]]:
    """issue #21 的啟發式 pivot 偵測結果（breach_detector.py）——終端機
    視窗標題出現不同主機名稱的推論，不是確認過的攻擊成功事件，前端顯示
    時要標示成疑似/未確認，不能跟 hit/gap 那種權威判定混在一起。layer
    （external/internal）是從 pivot 深度推論的外網/內網，不是解析容器
    名稱得來的（見 breach_detector.py 的說明）。跟 /blue-scores 一樣公開
    讀，不需要 purple clearance。"""
    return store.list_possible_breaches()


@app.get("/timeline")
def timeline(limit: int = Query(500, ge=1, le=5000)) -> list[dict[str, Any]]:
    return store.list_events(team=None, limit=limit)


@app.get("/analysis")
def analysis(
    limit: int = Query(5000, ge=1, le=20000),
    caller: Literal["public", "purple"] = "public",
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    require_purple_clearance(caller, authorization)
    result = summarize(store.list_events(team=None, limit=limit))
    # detection_gap/visibility_gap rows carry raw red/blue event detail and
    # must stay purple-only (see disclosure.py) -- summarize() itself has no
    # notion of caller, so the filter is applied here, at the boundary.
    result["correlations"] = [
        row for row in result["correlations"]
        if visible_to(caller, visibility_for_correlation(row))
    ]
    return result


@app.get("/events/{event_id}/context")
def event_context(
    event_id: str,
    caller: Literal["public", "purple"] = "public",
    window_minutes: int = Query(5, ge=1, le=60),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    require_purple_clearance(caller, authorization)
    try:
        return resolve_context(store, event_id, caller, window_minutes=window_minutes)
    except EvidenceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
