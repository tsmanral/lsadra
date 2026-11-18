from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from starlette.concurrency import run_in_threadpool
import logging

logger = logging.getLogger(__name__)

from lsadra.auth import hash_password, require_role
from lsadra.authz import owns_device, visible_device_ids
from lsadra.ui.data_layer import (
    get_dashboard_kpis,
    get_dashboard_recent_anomalies,
    get_dashboard_metrics,
    get_dashboard_devices,
    get_dashboard_model_info,
    get_dashboard_open_incidents,
    get_events_for_user,
    get_ingestion_rate,
)
from lsadra.ui.utils.report_generator import generate_report

router = APIRouter(tags=["dashboard"])

# Off-loop rule: every handler runs its sync storage work (SQLite reads/writes,
# report rendering, model training) through ONE run_in_threadpool call, so the
# event loop is released once per request and never blocks on it.

@router.get("/kpis")
async def api_kpis(device_id: Optional[str] = None, user: dict = Depends(require_role("ADMIN", "ANALYST", "VIEWER"))):
    uid = user["user_id"] if user["role"] != "ADMIN" else None
    return await run_in_threadpool(get_dashboard_kpis, user_id=uid, device_id=device_id)

@router.get("/anomalies")
async def api_anomalies(limit: int = 50, device_id: Optional[str] = None, user: dict = Depends(require_role("ADMIN", "ANALYST", "VIEWER"))):
    uid = user["user_id"] if user["role"] != "ADMIN" else None
    return await run_in_threadpool(
        get_dashboard_recent_anomalies, limit=limit, user_id=uid, device_id=device_id
    )

def _recent_events(uid: Optional[str], limit: int) -> List[Dict[str, Any]]:
    if not uid:
        # For admin, we could return all, but the function requires user_id
        # Let's just use the database function directly for admin if needed
        from lsadra.storage.database import get_connection
        conn = get_connection()
        rows = conn.execute("SELECT * FROM normalized_events ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    return get_events_for_user(user_id=uid, limit=limit)


@router.get("/events")
async def api_events(limit: int = 1000, user: dict = Depends(require_role("ADMIN", "ANALYST", "VIEWER"))):
    uid = user["user_id"] if user["role"] != "ADMIN" else None
    return await run_in_threadpool(_recent_events, uid, limit)

def _scoped_metrics(user: dict, device_id: Optional[str], start: str, end: str) -> List[Dict]:
    """Metrics the caller may see: one owned device, or the sum over theirs."""
    if device_id:
        if not owns_device(user, device_id):
            raise HTTPException(status_code=404, detail="Device not found or access denied.")
        return get_dashboard_metrics(device_id, start, end)
    device_ids = visible_device_ids(user)
    if device_ids is None:  # ADMIN: every device
        return get_dashboard_metrics(None, start, end)
    if not device_ids:
        return []
    placeholders = ",".join("?" for _ in device_ids)
    conn = get_connection()
    try:
        rows = conn.execute(
            f"""SELECT window_start,
                      SUM(event_count) as event_count,
                      SUM(anomaly_count) as anomaly_count,
                      AVG(avg_severity) as avg_severity,
                      MAX(max_severity) as max_severity,
                      SUM(unique_ips) as unique_ips,
                      SUM(unique_users) as unique_users
               FROM metrics_5min
               WHERE window_start BETWEEN ? AND ?
                 AND device_id IN ({placeholders})
               GROUP BY window_start
               ORDER BY window_start ASC""",
            (start, end, *device_ids),
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


@router.get("/metrics")
async def api_metrics(start: str, end: str, device_id: Optional[str] = None, user: dict = Depends(require_role("ADMIN", "ANALYST", "VIEWER"))):
    return await run_in_threadpool(_scoped_metrics, user, device_id, start, end)

@router.get("/health")
async def api_dashboard_health(user: dict = Depends(require_role("ADMIN", "ANALYST", "VIEWER"))):
    """Ingestion health for dashboard tiles.

    ``events_per_second`` is measured over the last minute. Latency and drop
    rate are not measured yet, so they are ``None`` rather than made-up values.
    """
    uid = user["user_id"] if user["role"] != "ADMIN" else None

    def _health() -> Dict[str, Any]:
        kpis = get_dashboard_kpis(user_id=uid)
        return {"active_devices": kpis.get("active_devices", 0),
                "events_per_second": get_ingestion_rate(user_id=uid)}

    h = await run_in_threadpool(_health)
    return {
        "status": "HEALTHY" if h["active_devices"] > 0 else "STABLE",
        "events_per_second": h["events_per_second"],
        "avg_latency_ms": None,
        "drop_rate_pct": None,
        "active_devices": h["active_devices"],
    }

@router.get("/devices")
async def api_devices(user: dict = Depends(require_role("ADMIN", "ANALYST", "VIEWER"))):
    uid = user["user_id"] if user["role"] != "ADMIN" else None
    return await run_in_threadpool(get_dashboard_devices, user_id=uid)

def _delete_device(device_id: str, uid: Optional[str]) -> Dict[str, Any]:
    from lsadra.storage.database import get_connection
    conn = get_connection()
    try:
        # Check if device exists and belongs to user (if not admin)
        check_query = "SELECT id FROM devices WHERE id = ?"
        params = [device_id]
        if uid:
            check_query += " AND user_id = ?"
            params.append(uid)
        
        row = conn.execute(check_query, tuple(params)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Device not found or access denied.")
            
        # Delete related data in correct order to satisfy FOREIGN KEY constraints
        # 1. Anomalies (may reference incidents/events)
        conn.execute("DELETE FROM anomalies WHERE device_id = ?", (device_id,))
        # 2. Incidents (references device)
        conn.execute("DELETE FROM incidents WHERE device_id = ?", (device_id,))
        # 3. Watermarks (references device)
        conn.execute("DELETE FROM detection_watermarks WHERE device_id = ?", (device_id,))
        # 4. Heartbeats (references device)
        conn.execute("DELETE FROM device_heartbeats WHERE device_id = ?", (device_id,))
        # 5. Events (references device)
        conn.execute("DELETE FROM normalized_events WHERE device_id = ?", (device_id,))
        # 6. Aggregated Metrics
        conn.execute("DELETE FROM metrics_5min WHERE device_id = ?", (device_id,))
        
        # 7. Finally delete the device itself
        cur = conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        
        if cur.rowcount == 0:
             raise HTTPException(status_code=404, detail="Device record not found in database.")

        conn.commit()
        return {"status": "ok", "message": f"Device {device_id} and all related telemetry deleted."}
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to delete device {device_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        conn.close()


@router.delete("/devices/{device_id}")
async def api_delete_device(device_id: str, user: dict = Depends(require_role("ADMIN", "ANALYST"))):
    """Delete a device and its associated events/anomalies."""
    uid = user["user_id"] if user["role"] != "ADMIN" else None
    return await run_in_threadpool(_delete_device, device_id, uid)


def _set_device_status(device_id: str, active: bool, uid: Optional[str]) -> Dict[str, Any]:
    from lsadra.storage.database import get_connection
    conn = get_connection()
    try:
        # Check if device exists and belongs to user (if not admin)
        check_query = "SELECT id FROM devices WHERE id = ?"
        params = [device_id]
        if uid:
            check_query += " AND user_id = ?"
            params.append(uid)
        
        row = conn.execute(check_query, tuple(params)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Device not found or access denied.")
            
        status = "ONLINE" if active else "OFFLINE"
        conn.execute("UPDATE devices SET status = ? WHERE id = ?", (status, device_id))
        conn.commit()
        return {"status": "ok", "device_id": device_id, "new_status": status}
    finally:
        conn.close()


@router.post("/devices/{device_id}/status")
async def api_toggle_device_status(device_id: str, active: bool, user: dict = Depends(require_role("ADMIN", "ANALYST"))):
    """Manually activate or deactivate a device."""
    uid = user["user_id"] if user["role"] != "ADMIN" else None
    return await run_in_threadpool(_set_device_status, device_id, active, uid)


def _render_report(uid: Optional[str]) -> bytes:
    kpis = get_dashboard_kpis(user_id=uid)
    incidents = get_dashboard_open_incidents(user_id=uid)
    anomalies = get_dashboard_recent_anomalies(limit=50, user_id=uid)

    return generate_report(
        title="LSADRA Security Report",
        kpis=kpis,
        incidents=incidents,
        anomalies=anomalies,
    )


@router.get("/export")
async def api_export(user: dict = Depends(require_role("ADMIN", "ANALYST", "VIEWER"))):
    uid = user["user_id"] if user["role"] != "ADMIN" else None
    pdf_bytes = await run_in_threadpool(_render_report, uid)

    return Response(
        content=pdf_bytes, 
        media_type="application/pdf", 
        headers={"Content-Disposition": "attachment; filename=report.pdf"}
    )

from lsadra.storage.database import (
    create_user,
    get_connection,
    get_user_by_username,
    list_users,
    update_user_role,
)
from pydantic import BaseModel, Field
from typing import Literal
import sqlite3
import uuid

Role = Literal["ADMIN", "ANALYST", "VIEWER"]

@router.get("/users")
async def api_users(user: dict = Depends(require_role("ADMIN"))):
    return await run_in_threadpool(list_users)

class RoleUpdate(BaseModel):
    user_id: str
    role: Role

@router.post("/users/role")
async def api_update_role(req: RoleUpdate, user: dict = Depends(require_role("ADMIN"))):
    await run_in_threadpool(update_user_role, req.user_id, req.role)
    return {"status": "ok"}

class UserCreate(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=12, max_length=128)
    role: Role = "ANALYST"


def _create_user_account(req: "UserCreate") -> Optional[Dict[str, str]]:
    if get_user_by_username(req.username):
        return None
    uid = str(uuid.uuid4())
    try:
        create_user(uid, req.username, hash_password(req.password), req.role)
    except sqlite3.IntegrityError:
        return None
    return {"user_id": uid, "role": req.role}


@router.post("/users")
async def api_create_user(req: UserCreate, user: dict = Depends(require_role("ADMIN"))):
    """Create an account. With sign-up off (the default outside dev mode) this,
    and ``python -m lsadra.admin_cli``, are how accounts are made."""
    account = await run_in_threadpool(_create_user_account, req)
    if account is None:
        raise HTTPException(status_code=400, detail="Username already taken.")
    return {"status": "ok", **account}


def _table_counts() -> Dict[str, int]:
    conn = get_connection()
    tables = ["normalized_events", "anomalies", "incidents", "devices",
               "device_heartbeats", "metrics_5min", "model_registry",
               "threat_intel_cache", "feature_drift"]
    stats = {}
    for table in tables:
        try:
            row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            stats[table] = row[0] if row else 0
        except Exception:
            stats[table] = 0
    conn.close()
    return stats


@router.get("/stats")
async def api_stats(user: dict = Depends(require_role("ADMIN", "ANALYST", "VIEWER"))):
    return await run_in_threadpool(_table_counts)


def _model_registry() -> List[Dict[str, Any]]:
    conn = get_connection()
    rows = conn.execute(
        """SELECT model_name, model_type, version, event_count,
                  trained_at, file_path, is_stale
           FROM model_registry
           ORDER BY trained_at DESC"""
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@router.get("/models")
async def api_models(user: dict = Depends(require_role("ADMIN", "ANALYST", "VIEWER"))):
    return await run_in_threadpool(_model_registry)

from lsadra.ui.data_layer import get_dashboard_drift


def _drift_records() -> Dict[str, List[Dict]]:
    ans = {}
    for m in ["ensemble", "autoencoder"]:
        ans[m] = get_dashboard_drift(m, limit=100)
    return ans


@router.get("/drift")
async def api_drift(user: dict = Depends(require_role("ADMIN", "ANALYST", "VIEWER"))):
    return await run_in_threadpool(_drift_records)

@router.post("/run-drift")
async def api_run_drift(user: dict = Depends(require_role("ADMIN"))):
    # Drift runs over every device's data, so it is an admin action.
    from lsadra.detection.drift_detector import run as run_drift
    await run_in_threadpool(run_drift)
    return {"status": "ok"}

def _retrain() -> Dict[str, Any]:
    from lsadra.detection.detection_orchestrator import DetectionOrchestrator
    from lsadra.features.feature_extractor import build_features
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM normalized_events ORDER BY timestamp DESC LIMIT 10000"
    ).fetchall()
    conn.close()
    if not rows:
        return {"status": "error", "detail": "No events found"}
    df = build_features([dict(r) for r in rows])
    if df.empty:
        return {"status": "error", "detail": "Empty features"}
    orchestrator = DetectionOrchestrator()
    orchestrator.train(df)
    return {"status": "ok", "events": len(df)}


@router.post("/retrain")
async def api_retrain(user: dict = Depends(require_role("ADMIN"))):
    # Retraining reads every device's events and rewrites the shared models, so
    # only an admin may trigger it (same rule as POST /admin/retrain).
    return await run_in_threadpool(_retrain)

from lsadra.onboarding.agent_files import install_hashes
from lsadra.onboarding.token_manager import generate_token

@router.post("/generate-token")
async def api_generate_token(user: dict = Depends(require_role("ADMIN", "ANALYST"))):
    # Enrolling a device adds a data source, so VIEWER (read-only) may not.
    user_id = user["user_id"]
    token = await run_in_threadpool(generate_token, user_id)
    # Hashes for the install command: the command checks the installer and the
    # installer checks the agent before anything runs as root.
    return {"token": token, **await run_in_threadpool(install_hashes)}
