"""
LSADRA V3 — FastAPI server (primary V3 entrypoint).
"""

import logging
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from lsadra.auth import (
    create_access_token,
    get_current_user,
    require_role,
    verify_password,
)
from lsadra.config import CORS_ALLOWED_ORIGINS, REQUIRE_TLS
from lsadra.ingestion.api_ingestion import router as events_router
from lsadra.onboarding.device_registration import router as devices_router
from lsadra.storage.database import (
    get_all_incidents,
    get_device,
    get_incident,
    get_user_by_username,
    init_db,
    insert_heartbeat,
    touch_device,
    update_device_status,
    update_incident_status,
    assign_incident as db_assign_incident,
)
from lsadra.tls_middleware import TLSEnforcementMiddleware
from lsadra.ui.api_dashboard import router as dashboard_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle events for FastAPI."""
    logger.info("Initializing LSADRA V3 Backend...")
    init_db()
    Path("data/models").mkdir(parents=True, exist_ok=True)
    yield
    logger.info("Shutting down LSADRA V3 Backend...")


app = FastAPI(
    title="LSADRA V3 API",
    lifespan=lifespan,
)

# ── Middleware ────────────────────────────────────────────────────────────

if REQUIRE_TLS:
    app.add_middleware(TLSEnforcementMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOWED_ORIGINS,  # §6 #3: env allowlist, empty by default
    allow_credentials=False,             # agents use header tokens, not cookies
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Static Files ─────────────────────────────────────────────────────────

STATIC_DIR = Path(__file__).parent / "lsadra" / "onboarding"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

AGENT_DIR = Path(__file__).parent / "lsadra" / "endpoint_agent"
if AGENT_DIR.exists():
    app.mount("/agent", StaticFiles(directory=str(AGENT_DIR)), name="agent")


# ── Routers ──────────────────────────────────────────────────────────────

app.include_router(events_router, prefix="/api/events")
app.include_router(devices_router, prefix="/api/devices")
app.include_router(dashboard_router, prefix="/api/dashboard")


# ── Utility endpoints ───────────────────────────────────────────────────


@app.get("/", tags=["system"])
async def root():
    return {
        "service": "LSADRA V3 Core",
        "timestamp": datetime.now().isoformat(),
        "status": "online",
    }


@app.get("/api/health", tags=["health"])
async def api_health():
    return {"status": "ok", "service": "lsadra-api", "version": "5.0.0"}


# ── Auth endpoints ───────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    user_id: str


@app.post("/api/auth/login", response_model=TokenResponse, tags=["auth"])
async def login(req: LoginRequest):
    user = get_user_by_username(req.username)
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    token = create_access_token(
        user_id=user["id"],
        username=user["username"],
        role=user.get("role", "ANALYST"),
    )
    return TokenResponse(
        access_token=token,
        role=user.get("role", "ANALYST"),
        user_id=user["id"],
    )

class RegisterRequest(BaseModel):
    username: str
    password: str

@app.post("/api/auth/register", tags=["auth"])
async def register(req: RegisterRequest):
    from lsadra.storage.database import create_user
    from lsadra.auth import hash_password
    import uuid

    existing = get_user_by_username(req.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already taken.")

    role = "ADMIN" if req.username.lower() == "admin" else "ANALYST"
    uid = str(uuid.uuid4())
    create_user(uid, req.username, hash_password(req.password), role)
    return {"status": "ok", "user_id": uid, "role": role}


# ── Heartbeat endpoint ─────────────────────────────────────────────────


class HeartbeatRequest(BaseModel):
    device_id: str
    cpu_pct: Optional[float] = None
    mem_pct: Optional[float] = None
    agent_version: Optional[str] = None


@app.post("/heartbeat", tags=["heartbeat"])
async def heartbeat(req: HeartbeatRequest):
    device = get_device(req.device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Unknown device.")

    insert_heartbeat(
        device_id=req.device_id,
        cpu_pct=req.cpu_pct,
        mem_pct=req.mem_pct,
        agent_version=req.agent_version,
    )
    touch_device(req.device_id)

    if device.get("status") == "OFFLINE":
        update_device_status(req.device_id, "ONLINE")

    return {"status": "ok", "device_id": req.device_id}


# ── Incident endpoints ──────────────────────────────────────────────────


class IncidentStatusRequest(BaseModel):
    status: str
    notes: str = ""


class IncidentAssignRequest(BaseModel):
    user_id: str


@app.post("/api/incidents/{incident_id}/status", tags=["incidents"])
async def update_incident(
    incident_id: int,
    req: IncidentStatusRequest,
    user: dict = Depends(require_role("ADMIN", "ANALYST")),
):
    incident = get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")

    update_incident_status(incident_id, req.status, req.notes)
    return {"status": "ok", "incident_id": incident_id, "new_status": req.status}


@app.post("/api/incidents/{incident_id}/assign", tags=["incidents"])
async def assign_incident(
    incident_id: int,
    req: IncidentAssignRequest,
    user: dict = Depends(require_role("ADMIN", "ANALYST")),
):
    incident = get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")

    db_assign_incident(incident_id, req.user_id)
    return {"status": "ok", "incident_id": incident_id, "assigned_to": req.user_id}


@app.get("/api/incidents", tags=["incidents"])
async def list_incidents(
    status: Optional[str] = None,
    limit: int = 100,
    user: dict = Depends(require_role("ADMIN", "ANALYST", "VIEWER")),
):
    uid = user["user_id"] if user["role"] != "ADMIN" else None
    incidents = get_all_incidents(status=status, limit=limit, user_id=uid)
    return {"incidents": incidents, "count": len(incidents)}


# ── Admin endpoints ─────────────────────────────────────────────────────


@app.post("/admin/retrain", tags=["admin"])
async def retrain_models(
    background_tasks: BackgroundTasks,
    user: dict = Depends(require_role("ADMIN")),
):
    def _do_retrain():
        try:
            from lsadra.detection.detection_orchestrator import DetectionOrchestrator
            from lsadra.features.feature_extractor import build_features
            from lsadra.storage.database import get_connection

            conn = get_connection()
            rows = conn.execute(
                "SELECT * FROM normalized_events ORDER BY timestamp DESC LIMIT 10000"
            ).fetchall()
            conn.close()

            if not rows:
                return

            df = build_features([dict(r) for r in rows])
            if df.empty:
                return

            orchestrator = DetectionOrchestrator()
            orchestrator.train(df)
            logger.info("Model retrain completed.")
        except Exception:
            logger.exception("Model retrain failed.")

    background_tasks.add_task(_do_retrain)
    return {"status": "accepted", "message": "Started."}


from lsadra.ui.api_dashboard import router as dashboard_router
app.include_router(dashboard_router, prefix="/api/dashboard")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
