"""
LSADRA V3 — FastAPI server (primary V3 entrypoint).
"""

import asyncio
import logging
import sqlite3
import uuid
from collections import deque
from contextlib import asynccontextmanager, suppress
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from lsadra.auth import (
    create_access_token,
    get_current_user,
    hash_password,
    require_role,
    verify_password,
)
from lsadra.config import BENCH_SKIP_DETECTION, CORS_ALLOWED_ORIGINS, DEV_MODE, REQUIRE_TLS
from lsadra.detection.detection_worker import detection_queue
from lsadra.ingestion.api_ingestion import router as events_router
from lsadra.ingestion.api_ingestion import run_online_detection
from lsadra.onboarding.device_registration import router as devices_router
from lsadra.storage.database import (
    create_user,
    get_all_incidents,
    get_incident,
    get_user_by_username,
    init_db,
    record_heartbeat,
    update_incident_status,
    assign_incident as db_assign_incident,
)
from lsadra.tls_middleware import TLSEnforcementMiddleware
from lsadra.ui.api_dashboard import router as dashboard_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# ── Event-loop lag sampler (dev mode only; benchmarks/run_ingest_bench.py) ──
# Sleeps LOOP_LAG_INTERVAL_S and records how late the loop woke up. Any sync
# work on the loop (DB calls, inline detection) shows up as lag. Measurement
# only — it changes no request handling.
LOOP_LAG_INTERVAL_S = 0.1
_LOOP_LAG_SAMPLES: "deque[float]" = deque(maxlen=3000)  # ~5 min at 100 ms
_loop_lag_seq = 0  # total samples ever taken; lets a reader slice the tail


async def _sample_loop_lag() -> None:
    global _loop_lag_seq
    loop = asyncio.get_running_loop()
    while True:
        start = loop.time()
        await asyncio.sleep(LOOP_LAG_INTERVAL_S)
        lag_ms = max(0.0, (loop.time() - start - LOOP_LAG_INTERVAL_S) * 1000.0)
        _LOOP_LAG_SAMPLES.append(round(lag_ms, 3))
        _loop_lag_seq += 1


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle events for FastAPI."""
    logger.info("Initializing LSADRA V3 Backend...")
    init_db()
    Path("data/models").mkdir(parents=True, exist_ok=True)
    sampler = asyncio.create_task(_sample_loop_lag()) if DEV_MODE else None
    # Online detection worker: ingestion handlers only enqueue; detection runs
    # here, on one dedicated thread — never on the loop, never in a request.
    detection_queue.start(run_online_detection)
    yield
    await detection_queue.stop()
    if sampler is not None:
        sampler.cancel()
        with suppress(asyncio.CancelledError):
            await sampler
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
    body: Dict[str, Any] = {"status": "ok", "service": "lsadra-api", "version": "5.0.0"}
    if DEV_MODE:
        # Benchmark telemetry — never exposed outside dev mode.
        body["benchmark"] = {
            "loop_lag_interval_ms": LOOP_LAG_INTERVAL_S * 1000.0,
            "loop_lag_seq": _loop_lag_seq,
            "loop_lag_ms": list(_LOOP_LAG_SAMPLES),
            "detection_skipped": BENCH_SKIP_DETECTION,
        }
    return body


# ── Off-loop rule ────────────────────────────────────────────────────────
# Every async handler below runs its sync storage (and bcrypt) work through
# ONE run_in_threadpool call around a small sync function, so the event loop
# is released once per request and never blocks on SQLite or hashing.


# ── Auth endpoints ───────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    user_id: str


def _authenticated_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """User row if *password* verifies, else None (threadpool: DB read + bcrypt)."""
    user = get_user_by_username(username)
    if not user or not verify_password(password, user["password_hash"]):
        return None
    return user


@app.post("/api/auth/login", response_model=TokenResponse, tags=["auth"])
async def login(req: LoginRequest):
    user = await run_in_threadpool(_authenticated_user, req.username, req.password)
    if user is None:
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

def _create_account(username: str, password: str) -> Optional[Dict[str, str]]:
    """Create the user; None if the username is taken (threadpool: DB + bcrypt).

    On the event loop the existence check and the insert could not interleave
    with another registration; in the threadpool they can. The UNIQUE
    constraint on ``users.username`` then rejects the loser, which is mapped to
    the same "taken" answer instead of surfacing as a 500.
    """
    if get_user_by_username(username):
        return None
    role = "ADMIN" if username.lower() == "admin" else "ANALYST"
    uid = str(uuid.uuid4())
    try:
        create_user(uid, username, hash_password(password), role)
    except sqlite3.IntegrityError:
        return None
    return {"user_id": uid, "role": role}


@app.post("/api/auth/register", tags=["auth"])
async def register(req: RegisterRequest):
    account = await run_in_threadpool(_create_account, req.username, req.password)
    if account is None:
        raise HTTPException(status_code=400, detail="Username already taken.")
    return {"status": "ok", **account}


# ── Heartbeat endpoint ─────────────────────────────────────────────────


class HeartbeatRequest(BaseModel):
    device_id: str
    cpu_pct: Optional[float] = None
    mem_pct: Optional[float] = None
    agent_version: Optional[str] = None


@app.post("/heartbeat", tags=["heartbeat"])
async def heartbeat(req: HeartbeatRequest):
    # One connection, one write transaction (was four separate connect/commits).
    recorded = await run_in_threadpool(
        record_heartbeat,
        device_id=req.device_id,
        cpu_pct=req.cpu_pct,
        mem_pct=req.mem_pct,
        agent_version=req.agent_version,
    )
    if not recorded:
        raise HTTPException(status_code=404, detail="Unknown device.")

    return {"status": "ok", "device_id": req.device_id}


# ── Incident endpoints ──────────────────────────────────────────────────


class IncidentStatusRequest(BaseModel):
    status: str
    notes: str = ""


class IncidentAssignRequest(BaseModel):
    user_id: str


def _set_incident_status(incident_id: int, status: str, notes: str) -> bool:
    """False if the incident does not exist (threadpool: DB read + write)."""
    if not get_incident(incident_id):
        return False
    update_incident_status(incident_id, status, notes)
    return True


def _assign_incident(incident_id: int, user_id: str) -> bool:
    """False if the incident does not exist (threadpool: DB read + write)."""
    if not get_incident(incident_id):
        return False
    db_assign_incident(incident_id, user_id)
    return True


@app.post("/api/incidents/{incident_id}/status", tags=["incidents"])
async def update_incident(
    incident_id: int,
    req: IncidentStatusRequest,
    user: dict = Depends(require_role("ADMIN", "ANALYST")),
):
    if not await run_in_threadpool(_set_incident_status, incident_id, req.status, req.notes):
        raise HTTPException(status_code=404, detail="Incident not found.")
    return {"status": "ok", "incident_id": incident_id, "new_status": req.status}


@app.post("/api/incidents/{incident_id}/assign", tags=["incidents"])
async def assign_incident(
    incident_id: int,
    req: IncidentAssignRequest,
    user: dict = Depends(require_role("ADMIN", "ANALYST")),
):
    if not await run_in_threadpool(_assign_incident, incident_id, req.user_id):
        raise HTTPException(status_code=404, detail="Incident not found.")
    return {"status": "ok", "incident_id": incident_id, "assigned_to": req.user_id}


@app.get("/api/incidents", tags=["incidents"])
async def list_incidents(
    status: Optional[str] = None,
    limit: int = 100,
    user: dict = Depends(require_role("ADMIN", "ANALYST", "VIEWER")),
):
    uid = user["user_id"] if user["role"] != "ADMIN" else None
    incidents = await run_in_threadpool(get_all_incidents, status=status, limit=limit, user_id=uid)
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
