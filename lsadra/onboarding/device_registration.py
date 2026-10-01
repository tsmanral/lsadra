"""
LSADRA V2 — Device registration API.

FastAPI router that lets endpoint agents register themselves using a
short-lived token obtained from the dashboard.
"""

import logging
import secrets
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
import bcrypt
from pydantic import BaseModel, Field, constr
from starlette.concurrency import run_in_threadpool

from lsadra.config import (
    MAX_HOSTNAME_LENGTH,
    RATE_LIMIT_MAX_KEYS,
    RATE_LIMIT_REGISTER_PER_MIN,
)
from lsadra.ratelimit import SlidingWindowRateLimiter
from lsadra.onboarding.token_manager import validate_and_consume
from lsadra.storage.database import create_device, get_device, get_devices_for_user

logger = logging.getLogger(__name__)

router = APIRouter(tags=["onboarding"])

# ── Rate limiting (per-IP) ────────────────────────────────────────────────

# Bounded LRU limiter — caps tracked client IPs so spoofed sources cannot grow
# memory without bound (§6 #5).
_ip_limiter = SlidingWindowRateLimiter(
    limit=RATE_LIMIT_REGISTER_PER_MIN, window_seconds=60, max_keys=RATE_LIMIT_MAX_KEYS
)


def _check_ip_rate(request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    if not _ip_limiter.allow(client_ip, time.time()):
        raise HTTPException(status_code=429, detail="Registration rate limit exceeded.")


# ── Pydantic schemas ─────────────────────────────────────────────────────


class RegisterRequest(BaseModel):
    """Payload sent by the installer / agent to register a device."""

    token: str = Field(..., description="Single-use registration token from the dashboard")
    hostname: constr(max_length=MAX_HOSTNAME_LENGTH) = ""  # type: ignore[valid-type]
    os_type: str = Field(..., pattern="^(linux|windows)$")
    display_name: Optional[str] = None


class RegisterResponse(BaseModel):
    """Returned to the agent after successful registration."""

    device_id: str
    api_key: str  # shown once, agent must store it
    collector_url: str
    log_paths: List[str]


class DeviceConfig(BaseModel):
    """Configuration returned to the agent on refresh."""

    device_id: str
    collector_url: str
    log_paths: List[str]


# ── Off-loop registration work ────────────────────────────────────────────
# Token consumption, bcrypt and the device insert run in the threadpool, never
# on the event loop. ``consume_token`` is a read-then-update (check-then-act):
# on the loop, registrations could not interleave inside it; in the threadpool
# they can, and one single-use token could register several devices. This lock
# keeps exactly the in-process serialization the loop used to give, for the
# milliseconds the consume takes (bcrypt stays outside it). It does not cover
# other processes — making the consume itself atomic is a storage change,
# tracked separately.
_token_consume_lock = threading.Lock()


def _register(token: str, hostname: str, os_type: str,
              display_name: Optional[str]) -> Optional[Dict[str, str]]:
    """Consume the token and create the device; None if the token is invalid."""
    with _token_consume_lock:
        token_data = validate_and_consume(token)
    if token_data is None:
        return None

    user_id: str = token_data["user_id"]
    device_id = str(uuid.uuid4())
    api_key = secrets.token_urlsafe(32)

    api_key_hash = bcrypt.hashpw(api_key.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    create_device(
        device_id=device_id,
        user_id=user_id,
        hostname=hostname,
        os_type=os_type,
        api_key_hash=api_key_hash,
        display_name=display_name,
    )
    return {"user_id": user_id, "device_id": device_id, "api_key": api_key}


# ── Endpoints ─────────────────────────────────────────────────────────────


@router.post("/register", response_model=RegisterResponse, summary="Register a new device")
async def register_device(body: RegisterRequest, request: Request) -> RegisterResponse:
    """
    Register an endpoint agent.

    1. Validates the single-use token (checks expiry + used flag).
    2. Derives ``user_id`` from the token.
    3. Generates a random ``device_id`` and API key.
    4. Stores the device with a **hashed** API key.
    5. Returns the plain-text API key once so the agent can persist it.
    """
    _check_ip_rate(request)

    registered = await run_in_threadpool(
        _register, body.token, body.hostname, body.os_type, body.display_name
    )
    if registered is None:
        raise HTTPException(status_code=400, detail="Invalid or expired registration token.")

    user_id = registered["user_id"]
    device_id = registered["device_id"]
    api_key = registered["api_key"]
    logger.info(
        "Device registered: id=%s hostname=%s user=%s",
        device_id, body.hostname, user_id,
    )

    # Default config (Linux)
    default_log_paths = ["/var/log/auth.log"] if body.os_type == "linux" else []

    return RegisterResponse(
        device_id=device_id,
        api_key=api_key,
        collector_url="/api/events/batch",
        log_paths=default_log_paths,
    )


@router.get("/config/{device_id}", response_model=DeviceConfig, summary="Get device config")
async def get_device_config(device_id: str) -> DeviceConfig:
    """
    Return the current configuration for a registered device.

    The agent can call this periodically to pick up config changes
    (e.g., new log paths, rotated API key).
    """
    device = await run_in_threadpool(get_device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found.")

    return DeviceConfig(
        device_id=device_id,
        collector_url="/api/events/batch",
        log_paths=["/var/log/auth.log"] if device["os_type"] == "linux" else [],
    )
