"""
Entity risk API (audit G-29): scores, risk cases and their timelines, and
user-set asset weights. Mounted at ``/api/risk``.

Admins see every entity; analysts and viewers see only entities whose signals
came from their own devices. Only admins set asset weights.
"""

from datetime import timedelta
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from lsadra.auth import require_role
from lsadra.config import RISK_THRESHOLD, RISK_WINDOW_DAYS
from lsadra.detection.risk import MAX_WEIGHT, iso_utc, parse_time, risk_mode, score_entity
from lsadra.storage.database import (
    get_asset_weight,
    get_open_risk_notable,
    get_risk_entities,
    get_risk_events,
    get_risk_notable,
    get_risk_notables,
    set_asset_weight,
    set_risk_notable_status,
)

router = APIRouter(tags=["risk"])

EntityType = Literal["host", "user"]
_READ = require_role("ADMIN", "ANALYST", "VIEWER")


def _owner_filter(user: Dict[str, Any]) -> Optional[str]:
    return None if user["role"] == "ADMIN" else user["user_id"]


def _card(entity_type: str, entity: str, owner: Optional[str]) -> Optional[Dict[str, Any]]:
    """Score card and timeline for one entity, or None if the caller may not see it."""
    events = get_risk_events(entity_type, entity)
    if owner is not None:
        events = [e for e in events if e.get("user_id") == owner]
    if not events:
        return None
    now = parse_time(events[-1]["event_time"])
    since = iso_utc(now - timedelta(days=RISK_WINDOW_DAYS))
    events = [e for e in events if e["event_time"] >= since]
    weight = get_asset_weight(entity_type, entity)
    card = score_entity(events, weight=weight, now=now)
    case = get_open_risk_notable(entity_type, entity)
    if case is not None and owner is not None and case.get("user_id") != owner:
        case = None
    return {
        "entity_type": entity_type,
        "entity": entity,
        **card,
        "threshold": RISK_THRESHOLD,
        "open_case": case,
        "timeline": events,
    }


def _entities(owner: Optional[str], limit: int) -> List[Dict[str, Any]]:
    out = []
    for row in get_risk_entities(user_id=owner, limit=limit):
        card = _card(row["entity_type"], row["entity"], owner)
        if card:
            card.pop("timeline")
            out.append(card)
    return sorted(out, key=lambda c: c["score"], reverse=True)


@router.get("/entities")
async def api_risk_entities(limit: int = Query(50, ge=1, le=200), user: dict = Depends(_READ)):
    """Entities with recent risk signals, highest score first."""
    entities = await run_in_threadpool(_entities, _owner_filter(user), limit)
    return {
        "mode": risk_mode(),
        "threshold": RISK_THRESHOLD,
        "window_days": RISK_WINDOW_DAYS,
        "entities": entities,
    }


@router.get("/timeline")
async def api_risk_timeline(
    entity_type: EntityType,
    entity: str = Query(..., min_length=1, max_length=256),
    user: dict = Depends(_READ),
):
    """One entity's score, open case and the signals behind it, oldest first."""
    card = await run_in_threadpool(_card, entity_type, entity, _owner_filter(user))
    if card is None:
        raise HTTPException(status_code=404, detail="No risk signals for this entity.")
    return card


@router.get("/cases")
async def api_risk_cases(
    status: Optional[Literal["OPEN", "CLOSED"]] = None,
    limit: int = Query(100, ge=1, le=500),
    user: dict = Depends(_READ),
):
    """Risk cases (entities that crossed the threshold), highest score first."""
    return await run_in_threadpool(get_risk_notables, _owner_filter(user), status, limit)


class CaseStatus(BaseModel):
    status: Literal["OPEN", "CLOSED"]


def _set_case_status(case_id: int, status: str, owner: Optional[str]) -> bool:
    case = get_risk_notable(case_id)
    if case is None or (owner is not None and case.get("user_id") != owner):
        return False
    return set_risk_notable_status(case_id, status)


@router.patch("/cases/{case_id}")
async def api_risk_case_status(
    case_id: int,
    req: CaseStatus,
    user: dict = Depends(require_role("ADMIN", "ANALYST")),
):
    """Close (or reopen) a risk case."""
    if not await run_in_threadpool(_set_case_status, case_id, req.status, _owner_filter(user)):
        raise HTTPException(status_code=404, detail="Risk case not found.")
    return {"status": "ok", "case_id": case_id, "case_status": req.status}


class AssetWeight(BaseModel):
    entity_type: EntityType
    entity: str = Field(..., min_length=1, max_length=256)
    weight: float = Field(..., gt=0, le=MAX_WEIGHT)
    note: str = Field("", max_length=500)


@router.put("/asset-weights")
async def api_set_asset_weight(req: AssetWeight, user: dict = Depends(require_role("ADMIN"))):
    """Set how much an asset's risk counts (1 = normal, up to 5)."""
    await run_in_threadpool(
        set_asset_weight,
        req.entity_type,
        req.entity,
        req.weight,
        req.note,
        user.get("username") or user["user_id"],
    )
    return {
        "status": "ok",
        "entity_type": req.entity_type,
        "entity": req.entity,
        "weight": req.weight,
    }
