"""
Model status and rollback endpoints (G-18, G-19), mounted at ``/api/models``.

``GET /status`` reports what the detection models are and how they were made:
model cards, per-entity baseline coverage, the latest drift measurements and
the training audit trail. ``POST /rollback`` restores the previous models.
Training itself is started from ``POST /admin/retrain`` or
``POST /api/dashboard/retrain`` (ADMIN only).
"""

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from starlette.concurrency import run_in_threadpool

from lsadra.auth import require_role

router = APIRouter(tags=["models"])


def _status(is_admin: bool) -> Dict[str, Any]:
    from lsadra.detection import model_lifecycle as lifecycle
    from lsadra.ingestion.api_ingestion import _get_orchestrator
    from lsadra.storage.database import (
        get_all_devices,
        get_drift_records,
        get_training_runs,
    )

    orch = _get_orchestrator()
    coverage = orch.baseline.coverage()
    devices = get_all_devices()
    covered = set(coverage["devices"])
    baseline = {
        "entities": coverage["entities"],
        "devices_total": len(devices),
        "devices_with_baseline": sum(1 for d in devices if d.get("id") in covered),
    }

    cards = lifecycle.read_cards(orch.model_dir)
    runs = get_training_runs(limit=10)
    if not is_admin:
        # Per-device counts and who asked are operator detail.
        for card in cards.values():
            if card:
                card.get("training_data", {}).pop("events_per_device", None)
        for run in runs:
            run.pop("requested_by", None)

    drift = {}
    for model_name in ("ensemble", "autoencoder"):
        latest: Dict[str, Any] = {}
        for rec in get_drift_records(model_name, limit=50):
            latest.setdefault(rec["feature_name"], rec)
        drift[model_name] = {
            "features": latest,
            "drifted": sorted(f for f, r in latest.items() if r.get("is_drifted")),
        }

    return {
        "trained": bool(orch._trained),
        "training_in_progress": lifecycle.is_training(),
        "retrain_cooldown_seconds": round(lifecycle.cooldown_remaining(), 1),
        "baseline_coverage": baseline,
        "model_cards": cards,
        "previous_available": bool(lifecycle.previous_store(orch.model_dir).entries()),
        "drift": drift,
        "training_runs": runs,
    }


@router.get("/status")
async def model_status(user: dict = Depends(require_role("ADMIN", "ANALYST"))):
    return await run_in_threadpool(_status, user["role"] == "ADMIN")


def _rollback(user_id: str) -> Dict[str, Any]:
    from lsadra.detection import model_lifecycle as lifecycle
    from lsadra.ingestion.api_ingestion import _get_orchestrator

    try:
        return _get_orchestrator().rollback(requested_by=user_id)
    except lifecycle.TrainingRefused as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.reason)


@router.post("/rollback")
async def model_rollback(user: dict = Depends(require_role("ADMIN"))):
    """Swap the live models with the previous ones (ADMIN only, audited)."""
    return await run_in_threadpool(_rollback, user["user_id"])
