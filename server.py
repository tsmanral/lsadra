"""
LSADRA V3 — FastAPI server (primary V3 entrypoint).
"""

import asyncio
import logging
import sqlite3
import sys
import uuid
from collections import deque
from contextlib import asynccontextmanager, suppress
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from lsadra.auth import (
    burn_password_check,
    create_access_token,
    get_current_user,
    hash_password,
    require_role,
    verify_password,
)
from lsadra import __version__, config
from lsadra.authz import owned_incident
from lsadra.config import BENCH_SKIP_DETECTION, CORS_ALLOWED_ORIGINS, DEV_MODE, REQUIRE_TLS
from lsadra.detection.detection_worker import detection_queue
from lsadra.ingestion.api_ingestion import router as events_router
from lsadra.ingestion.api_ingestion import _authenticate_device, run_online_detection
from lsadra.jobs.scheduler import start_scheduler, stop_scheduler
from lsadra.onboarding.agent_files import AGENT_FILE, INSTALLER_FILE, agent_extra_files
from lsadra.onboarding.device_registration import router as devices_router
from lsadra.security import audit, tls, totp
from lsadra.security.filesystem import restrict_data_dir
from lsadra.security.headers import SecurityHeadersMiddleware, install_error_handlers
from lsadra.security.totp_cli import warn_if_admin_without_totp
from lsadra.security.login_throttle import login_throttle
from lsadra.security.request_ip import client_ip
from lsadra.storage.database import (
    claim_totp_step,
    create_user,
    get_all_incidents,
    get_user_by_username,
    init_db,
    record_heartbeat,
    update_incident_status,
    assign_incident as db_assign_incident,
)
from lsadra.tls_middleware import TLSEnforcementMiddleware
from lsadra.ui.alert_stream import router as alert_stream_router
from lsadra.ui.api_identity import router as identity_router
from lsadra.ui.api_dashboard import router as dashboard_router
from lsadra.ui.api_investigation import router as investigation_router

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
    previous_switch_interval = sys.getswitchinterval()
    sys.setswitchinterval(config.THREAD_SWITCH_INTERVAL_MS / 1000.0)
    if config.RESTRICT_DATA_PERMISSIONS:
        restrict_data_dir(config.DB_PATH.parent)  # G-27: 0700 / 0600, umask 077
    init_db()
    Path("data/models").mkdir(parents=True, exist_ok=True)
    tls.adopt_configured_certificate()  # fingerprint for /api/server/identity (G-8)
    await run_in_threadpool(warn_if_admin_without_totp)  # G-33
    sampler = asyncio.create_task(_sample_loop_lag()) if DEV_MODE else None
    # Online detection worker: ingestion handlers only enqueue; detection runs
    # here, on one dedicated thread — never on the loop, never in a request.
    detection_queue.start(run_online_detection)
    # Background jobs (retention, metrics, offline detection, ...) run on
    # APScheduler's own threads; read the flag at startup so tests can patch it.
    scheduler_on = config.SCHEDULER_ENABLED
    if scheduler_on:
        start_scheduler()
    yield
    if scheduler_on:
        stop_scheduler()
    await detection_queue.stop()
    if sampler is not None:
        sampler.cancel()
        with suppress(asyncio.CancelledError):
            await sampler
    sys.setswitchinterval(previous_switch_interval)
    logger.info("Shutting down LSADRA V3 Backend...")


app = FastAPI(
    title="LSADRA API",
    version=__version__,
    lifespan=lifespan,
    # G-11: the API inventory (OpenAPI schema and its pages) is dev-only.
    docs_url="/docs" if config.EXPOSE_API_DOCS else None,
    redoc_url="/redoc" if config.EXPOSE_API_DOCS else None,
    openapi_url="/openapi.json" if config.EXPOSE_API_DOCS else None,
)
install_error_handlers(app)  # G-11: generic 500 body with a request ID

# ── Middleware ────────────────────────────────────────────────────────────

if REQUIRE_TLS:
    app.add_middleware(TLSEnforcementMiddleware)

app.add_middleware(SecurityHeadersMiddleware)  # G-11: CSP, nosniff, HSTS, ...

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOWED_ORIGINS,  # §6 #3: env allowlist, empty by default
    allow_credentials=False,             # agents use header tokens, not cookies
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Static Files ─────────────────────────────────────────────────────────

# Only the two files the Linux install flow downloads are served, by exact
# path. The source folders they live in are not exposed. The dashboard shows
# each file's SHA-256 next to the install command, and the command and the
# installer check those hashes before anything runs (lsadra/onboarding/agent_files.py).


@app.get("/static/installer_linux.sh", include_in_schema=False)
async def installer_script():
    return FileResponse(INSTALLER_FILE, media_type="text/x-shellscript")


@app.get("/agent/linux_agent.py", include_in_schema=False)
async def agent_script():
    return FileResponse(AGENT_FILE, media_type="text/x-python")


@app.get("/agent/{name}", include_in_schema=False)
async def agent_extra_file(name: str):
    path = agent_extra_files().get(name)  # allow-list lookup, never a path join
    if path is None:
        raise HTTPException(status_code=404, detail="Not found.")
    return FileResponse(path, media_type="text/plain")


# ── Routers ──────────────────────────────────────────────────────────────

app.include_router(events_router, prefix="/api/events")
app.include_router(devices_router, prefix="/api/devices")
app.include_router(dashboard_router, prefix="/api/dashboard")
app.include_router(alert_stream_router)  # /ws/alerts
app.include_router(investigation_router, prefix="/api")  # incident detail, entity, feedback
app.include_router(identity_router)  # logout, TOTP, device revoke/rotate, audit (G-9, G-26, G-33)


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
    body: Dict[str, Any] = {"status": "ok", "service": "lsadra-api", "version": __version__}
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
    totp_code: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    user_id: str
    expires_in: int


def _login(username: str, password: str, totp_code: Optional[str], ip: str) -> Dict[str, Any]:
    """Run one login attempt (threadpool: DB reads, bcrypt, audit write).

    Returns the user row on success; raises HTTPException otherwise. Order
    matters: the throttle is checked before any bcrypt work (G-10), and every
    outcome is written to the audit trail (G-26).
    """
    wait = login_throttle.retry_after(username, ip)
    if wait:
        audit.record("auth.login.throttled", "denied", target=username, source_ip=ip)
        raise HTTPException(
            status_code=429,
            detail="Too many failed logins. Try again later.",
            headers={"Retry-After": str(wait)},
        )

    def _fail(reason: str, detail: Any = "Invalid credentials.") -> HTTPException:
        login_throttle.record_failure(username, ip)
        audit.record("auth.login.failure", "failure", target=username, source_ip=ip,
                     details={"reason": reason})
        if login_throttle.retry_after(username, ip):
            audit.record("auth.login.lockout", "denied", target=username, source_ip=ip)
        return HTTPException(status_code=401, detail=detail)

    user = get_user_by_username(username)
    if user is None:
        burn_password_check(password)  # same timing as a wrong password
        raise _fail("unknown_user")
    if not verify_password(password, user["password_hash"]):
        raise _fail("bad_password")
    if user.get("disabled"):
        raise _fail("disabled")

    if user.get("totp_enabled") and user.get("totp_secret"):
        if not totp_code:
            # The password was right; ask for the second factor. Not counted
            # as a failure, so a normal two-step login never trips the throttle.
            raise HTTPException(
                status_code=401,
                detail={"code": "totp_required", "message": "Enter your authenticator code."},
            )
        step = totp.verify(user["totp_secret"], totp_code, int(user.get("totp_last_step") or 0))
        if step is None or not claim_totp_step(user["id"], step):
            raise _fail("bad_totp", {"code": "totp_invalid", "message": "Invalid authenticator code."})
    elif config.ADMIN_TOTP == "required" and user.get("role") == "ADMIN":
        audit.record("auth.login.denied", "denied", target=username, source_ip=ip,
                     details={"reason": "totp_enrolment_required"})
        raise HTTPException(
            status_code=403,
            detail={
                "code": "totp_enrolment_required",
                "message": "Admin accounts need an authenticator. On the server run: "
                           "python -m lsadra.security.totp_cli enroll <username>",
            },
        )

    login_throttle.record_success(username)
    audit.record("auth.login.success", "success",
                 actor={"user_id": user["id"], "username": user["username"]},
                 target=username, source_ip=ip)
    return user


@app.post("/api/auth/login", response_model=TokenResponse, tags=["auth"])
async def login(req: LoginRequest, request: Request):
    user = await run_in_threadpool(
        _login, req.username, req.password, req.totp_code, client_ip(request)
    )
    role = user.get("role") or "ANALYST"
    token = create_access_token(
        user_id=user["id"],
        username=user["username"],
        role=role,
        token_version=int(user.get("token_version") or 0),
    )
    return TokenResponse(
        access_token=token,
        role=role,
        user_id=user["id"],
        expires_in=config.JWT_EXPIRATION_MINUTES * 60,
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
    # Self-registration never grants ADMIN, whatever the username. Admins are
    # created by an operator with shell access: python -m lsadra.admin_cli.
    role = "ANALYST"
    uid = str(uuid.uuid4())
    try:
        create_user(uid, username, hash_password(password), role)
    except sqlite3.IntegrityError:
        return None
    return {"user_id": uid, "role": role}


@app.post("/api/auth/register", tags=["auth"])
async def register(req: RegisterRequest):
    if not config.ALLOW_SIGNUP:
        raise HTTPException(
            status_code=403,
            detail="Sign-up is disabled on this server. Ask an admin to create your account.",
        )
    from lsadra.security.passwords import PasswordPolicyError, check_password_policy

    try:
        check_password_policy(req.password, req.username)  # G-10
    except PasswordPolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    account = await run_in_threadpool(_create_account, req.username, req.password)
    if account is None:
        raise HTTPException(status_code=400, detail="Username already taken.")
    return {"status": "ok", **account}


# ── Heartbeat endpoint ─────────────────────────────────────────────────


class HeartbeatRequest(BaseModel):
    # The device is identified by its X-Device-Id / X-Api-Key headers, like
    # ingestion. A device_id in the body is optional and must match them.
    device_id: Optional[str] = None
    cpu_pct: Optional[float] = None
    mem_pct: Optional[float] = None
    agent_version: Optional[str] = None


@app.post("/heartbeat", tags=["heartbeat"])
async def heartbeat(
    req: HeartbeatRequest,
    device: Dict[str, Any] = Depends(_authenticate_device),
):
    if req.device_id is not None and req.device_id != device["id"]:
        raise HTTPException(status_code=403, detail="device_id does not match the credentials.")
    # One connection, one write transaction (was four separate connect/commits).
    recorded = await run_in_threadpool(
        record_heartbeat,
        device_id=device["id"],
        cpu_pct=req.cpu_pct,
        mem_pct=req.mem_pct,
        agent_version=req.agent_version,
    )
    if not recorded:
        raise HTTPException(status_code=404, detail="Unknown device.")

    return {"status": "ok", "device_id": device["id"]}


# ── Incident endpoints ──────────────────────────────────────────────────


class IncidentStatusRequest(BaseModel):
    status: str
    notes: str = ""


class IncidentAssignRequest(BaseModel):
    user_id: str


def _set_incident_status(user: Dict[str, Any], incident_id: int, status: str, notes: str) -> bool:
    """False if the incident does not exist or is not the caller's (threadpool)."""
    if owned_incident(user, incident_id) is None:
        return False
    update_incident_status(incident_id, status, notes)
    return True


def _assign_incident(user: Dict[str, Any], incident_id: int, user_id: str) -> bool:
    """False if the incident does not exist or is not the caller's (threadpool)."""
    if owned_incident(user, incident_id) is None:
        return False
    db_assign_incident(incident_id, user_id)
    return True


@app.post("/api/incidents/{incident_id}/status", tags=["incidents"])
async def update_incident(
    incident_id: int,
    req: IncidentStatusRequest,
    user: dict = Depends(require_role("ADMIN", "ANALYST")),
):
    if not await run_in_threadpool(_set_incident_status, user, incident_id, req.status, req.notes):
        raise HTTPException(status_code=404, detail="Incident not found.")
    return {"status": "ok", "incident_id": incident_id, "new_status": req.status}


@app.post("/api/incidents/{incident_id}/assign", tags=["incidents"])
async def assign_incident(
    incident_id: int,
    req: IncidentAssignRequest,
    user: dict = Depends(require_role("ADMIN", "ANALYST")),
):
    if not await run_in_threadpool(_assign_incident, user, incident_id, req.user_id):
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
    """Start a training run in the background (ADMIN only, one at a time, cooldown).

    The candidate replaces the live models only if it passes the canary; the
    outcome is recorded in the model training audit trail
    (``GET /api/models/status``).
    """
    from lsadra.detection import model_lifecycle as lifecycle

    if lifecycle.is_training():
        raise HTTPException(status_code=409, detail="A training run is already in progress.")
    remaining = lifecycle.cooldown_remaining()
    if remaining > 0:
        raise HTTPException(
            status_code=429,
            detail="Models were trained recently; try again later.",
            headers={"Retry-After": str(int(remaining) + 1)},
        )

    def _do_retrain():
        from lsadra.ingestion.api_ingestion import _get_orchestrator

        try:
            result = _get_orchestrator().retrain(trigger="admin", requested_by=user["user_id"])
            logger.info("Model retrain finished: %s", result.get("status"))
        except lifecycle.TrainingRefused as exc:
            logger.info("Model retrain not started: %s", exc.reason)
        except Exception:
            logger.exception("Model retrain failed.")

    background_tasks.add_task(_do_retrain)
    await run_in_threadpool(audit.record, "model.retrain", actor=user)
    return {"status": "accepted", "message": "Started."}


from lsadra.ui.api_dashboard import router as dashboard_router
app.include_router(dashboard_router, prefix="/api/dashboard")

from lsadra.ui.api_models import router as models_router  # noqa: E402
app.include_router(models_router, prefix="/api/models")

if __name__ == "__main__":
    # Same listener policy as `python -m lsadra.serve` (G-8): loopback by default.
    from lsadra.serve import main as _serve

    sys.exit(_serve())
