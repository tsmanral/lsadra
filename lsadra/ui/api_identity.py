"""Session, account, device-credential and audit endpoints (G-9, G-10, G-26, G-33).

* ``POST /api/auth/logout`` ends every session of the caller.
* ``POST /api/auth/password`` changes the caller's password (policy-checked).
* ``POST /api/auth/totp/{setup,enable,disable}`` manages the caller's
  authenticator (RFC 6238).
* ``POST /api/dashboard/users/password`` (ADMIN) resets a user's password.
* ``POST /api/dashboard/users/{id}/disable`` (ADMIN) disables or re-enables an
  account; ``.../sessions/revoke`` ends its sessions.
* ``POST /api/devices/{id}/revoke`` and ``.../rotate-key`` (ADMIN, or the
  ANALYST who owns the device) revoke a device or rotate its key with a short
  overlap.
* ``GET /api/server/identity`` gives the TLS certificate fingerprint agents pin.
* ``GET /api/dashboard/audit`` and ``.../audit/verify`` (ADMIN) read and check
  the hash-chained audit trail.

Every change is written to the audit trail. All storage and bcrypt work runs
in the threadpool.
"""

import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from lsadra import config
from lsadra.auth import create_access_token, get_current_user, hash_password, require_role, verify_password
from lsadra.security import audit, totp
from lsadra.security.passwords import PasswordPolicyError, check_password_policy
from lsadra.security.request_ip import client_ip
from lsadra.storage.database import (
    bump_token_version,
    get_device,
    get_user_by_id,
    revoke_device,
    rotate_device_key,
    set_user_disabled,
    set_user_password_hash,
    set_user_totp,
)

router = APIRouter()


def _policy(password: str, username: Optional[str]) -> None:
    try:
        check_password_policy(password, username)
    except PasswordPolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


def _fresh_token(user_id: str) -> Dict[str, Any]:
    row = get_user_by_id(user_id)
    token = create_access_token(
        user_id=row["id"], username=row["username"], role=row["role"],
        token_version=int(row.get("token_version") or 0),
    )
    return {"access_token": token, "token_type": "bearer", "role": row["role"],
            "user_id": row["id"], "expires_in": config.JWT_EXPIRATION_MINUTES * 60}


# ── Sessions ─────────────────────────────────────────────────────────────


@router.post("/api/auth/logout", tags=["auth"])
async def logout(request: Request, user: dict = Depends(get_current_user)):
    """End every session of the caller (all tokens issued so far stop working)."""
    ip = client_ip(request)

    def _do() -> None:
        bump_token_version(user["user_id"])
        audit.record("auth.logout", actor=user, target=user["username"], source_ip=ip)

    await run_in_threadpool(_do)
    return {"status": "ok"}


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


@router.post("/api/auth/password", tags=["auth"])
async def change_password(req: PasswordChange, request: Request,
                          user: dict = Depends(get_current_user)):
    ip = client_ip(request)

    def _do() -> Dict[str, Any]:
        row = get_user_by_id(user["user_id"])
        if row is None or not verify_password(req.current_password, row["password_hash"]):
            audit.record("user.password.change", "failure", actor=user,
                         target=user["username"], source_ip=ip)
            raise HTTPException(status_code=403, detail="Current password is wrong.")
        _policy(req.new_password, row["username"])
        set_user_password_hash(row["id"], hash_password(req.new_password))
        audit.record("user.password.change", actor=user, target=row["username"], source_ip=ip)
        return {"status": "ok", "detail": "Password changed. Please log in again."}

    return await run_in_threadpool(_do)


# ── TOTP ─────────────────────────────────────────────────────────────────


class TotpCode(BaseModel):
    code: str


class TotpDisable(BaseModel):
    password: str
    code: str


@router.post("/api/auth/totp/setup", tags=["auth"])
async def totp_setup(user: dict = Depends(get_current_user)):
    """Start enrolment: returns a new secret and otpauth:// URI to scan."""

    def _do() -> Dict[str, Any]:
        row = get_user_by_id(user["user_id"])
        if row.get("totp_enabled"):
            raise HTTPException(status_code=409, detail="An authenticator is already enrolled.")
        secret = totp.generate_secret()
        set_user_totp(row["id"], secret, enabled=False)
        return {"secret": secret, "otpauth_uri": totp.provisioning_uri(secret, row["username"])}

    return await run_in_threadpool(_do)


@router.post("/api/auth/totp/enable", tags=["auth"])
async def totp_enable(req: TotpCode, request: Request, user: dict = Depends(get_current_user)):
    """Confirm enrolment with a current code. Other sessions end; a new token is returned."""
    ip = client_ip(request)

    def _do() -> Dict[str, Any]:
        row = get_user_by_id(user["user_id"])
        secret = row.get("totp_secret")
        if row.get("totp_enabled") or not secret:
            raise HTTPException(status_code=409, detail="Start enrolment with /api/auth/totp/setup first.")
        if totp.verify(secret, req.code) is None:
            audit.record("user.totp.enable", "failure", actor=user, target=row["username"], source_ip=ip)
            raise HTTPException(status_code=400, detail="Invalid authenticator code.")
        set_user_totp(row["id"], secret, enabled=True)
        audit.record("user.totp.enable", actor=user, target=row["username"], source_ip=ip)
        return _fresh_token(row["id"])

    return await run_in_threadpool(_do)


@router.post("/api/auth/totp/disable", tags=["auth"])
async def totp_disable(req: TotpDisable, request: Request, user: dict = Depends(get_current_user)):
    ip = client_ip(request)

    def _do() -> Dict[str, Any]:
        row = get_user_by_id(user["user_id"])
        if not row.get("totp_enabled"):
            raise HTTPException(status_code=409, detail="No authenticator is enrolled.")
        if config.ADMIN_TOTP == "required" and row.get("role") == "ADMIN":
            raise HTTPException(status_code=403, detail="Admin accounts must keep an authenticator.")
        if not verify_password(req.password, row["password_hash"]) or totp.verify(
            row["totp_secret"], req.code, int(row.get("totp_last_step") or 0)
        ) is None:
            audit.record("user.totp.disable", "failure", actor=user, target=row["username"], source_ip=ip)
            raise HTTPException(status_code=403, detail="Password or authenticator code is wrong.")
        set_user_totp(row["id"], None, enabled=False)
        bump_token_version(row["id"])
        audit.record("user.totp.disable", actor=user, target=row["username"], source_ip=ip)
        return {"status": "ok", "detail": "Authenticator removed. Please log in again."}

    return await run_in_threadpool(_do)


# ── Account administration (ADMIN) ───────────────────────────────────────


class PasswordReset(BaseModel):
    user_id: str
    password: str


class DisableRequest(BaseModel):
    disabled: bool = True


@router.post("/api/dashboard/users/password", tags=["admin"])
async def admin_reset_password(req: PasswordReset, request: Request,
                               admin: dict = Depends(require_role("ADMIN"))):
    ip = client_ip(request)

    def _do() -> Dict[str, Any]:
        row = get_user_by_id(req.user_id)
        if row is None:
            raise HTTPException(status_code=404, detail="User not found.")
        _policy(req.password, row["username"])
        set_user_password_hash(row["id"], hash_password(req.password))
        audit.record("user.password.reset", actor=admin, target=row["username"], source_ip=ip)
        return {"status": "ok"}

    return await run_in_threadpool(_do)


@router.post("/api/dashboard/users/{user_id}/disable", tags=["admin"])
async def admin_disable_user(user_id: str, req: DisableRequest, request: Request,
                             admin: dict = Depends(require_role("ADMIN"))):
    if user_id == admin["user_id"] and req.disabled:
        raise HTTPException(status_code=400, detail="You cannot disable your own account.")
    ip = client_ip(request)

    def _do() -> Dict[str, Any]:
        row = get_user_by_id(user_id)
        if row is None or not set_user_disabled(user_id, req.disabled):
            raise HTTPException(status_code=404, detail="User not found.")
        audit.record("user.disable" if req.disabled else "user.enable", actor=admin,
                     target=row["username"], source_ip=ip)
        return {"status": "ok", "user_id": user_id, "disabled": req.disabled}

    return await run_in_threadpool(_do)


@router.post("/api/dashboard/users/{user_id}/sessions/revoke", tags=["admin"])
async def admin_revoke_sessions(user_id: str, request: Request,
                                admin: dict = Depends(require_role("ADMIN"))):
    ip = client_ip(request)

    def _do() -> Dict[str, Any]:
        row = get_user_by_id(user_id)
        if row is None or not bump_token_version(user_id):
            raise HTTPException(status_code=404, detail="User not found.")
        audit.record("user.sessions.revoke", actor=admin, target=row["username"], source_ip=ip)
        return {"status": "ok"}

    return await run_in_threadpool(_do)


# ── Device credentials ───────────────────────────────────────────────────


def _owned_device(device_id: str, user: dict) -> Dict[str, Any]:
    device = get_device(device_id)
    if device is None or (user["role"] != "ADMIN" and device.get("user_id") != user["user_id"]):
        raise HTTPException(status_code=404, detail="Device not found.")
    return device


@router.post("/api/devices/{device_id}/revoke", tags=["devices"])
async def device_revoke(device_id: str, request: Request,
                        user: dict = Depends(require_role("ADMIN", "ANALYST"))):
    """Revoke a device: its key stops working at once, and it stays revoked."""
    from lsadra.ingestion.api_ingestion import device_credential_cache

    ip = client_ip(request)

    def _do() -> Dict[str, Any]:
        _owned_device(device_id, user)
        revoke_device(device_id)
        device_credential_cache.invalidate(device_id)
        audit.record("device.revoke", actor=user, target=device_id, source_ip=ip)
        return {"status": "ok", "device_id": device_id, "new_status": "REVOKED"}

    return await run_in_threadpool(_do)


@router.post("/api/devices/{device_id}/rotate-key", tags=["devices"])
async def device_rotate_key(device_id: str, request: Request,
                            user: dict = Depends(require_role("ADMIN", "ANALYST"))):
    """Issue a new device key (shown once). The old key works for the overlap window."""
    from lsadra.ingestion.api_ingestion import device_credential_cache

    ip = client_ip(request)

    def _do() -> Dict[str, Any]:
        device = _owned_device(device_id, user)
        if device.get("status") == "REVOKED":
            raise HTTPException(status_code=409, detail="Device is revoked.")
        new_key = secrets.token_urlsafe(32)
        new_hash = bcrypt.hashpw(new_key.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        minutes = max(0, config.DEVICE_KEY_ROTATION_OVERLAP_MINUTES)
        until = datetime.utcnow() + timedelta(minutes=minutes)
        if not rotate_device_key(device_id, new_hash, until):
            raise HTTPException(status_code=409, detail="Device key could not be rotated.")
        device_credential_cache.invalidate(device_id)
        audit.record("device.key.rotate", actor=user, target=device_id, source_ip=ip,
                     details={"overlap_minutes": minutes})
        return {"device_id": device_id, "api_key": new_key,
                "previous_key_valid_until": until.isoformat() + "Z"}

    return await run_in_threadpool(_do)


# ── Server identity (for agent pinning, G-8) ─────────────────────────────


@router.get("/api/server/identity", tags=["system"])
async def server_identity(user: dict = Depends(get_current_user)):
    """The TLS certificate fingerprint agents and installers pin (any signed-in user)."""
    from lsadra.security import tls

    return {"tls": tls.ACTIVE_FINGERPRINT is not None, "cert_sha256": tls.ACTIVE_FINGERPRINT}


# ── Audit trail (ADMIN) ──────────────────────────────────────────────────


@router.get("/api/dashboard/audit", tags=["admin"])
async def audit_list(limit: int = 200, action: Optional[str] = None,
                     admin: dict = Depends(require_role("ADMIN"))):
    return {"events": await run_in_threadpool(audit.list_events, limit, action)}


@router.get("/api/dashboard/audit/verify", tags=["admin"])
async def audit_verify(admin: dict = Depends(require_role("ADMIN"))):
    intact, first_bad, checked = await run_in_threadpool(audit.verify_chain)
    head = await run_in_threadpool(audit.head_hash)
    return {"intact": intact, "first_bad_id": first_bad, "rows_checked": checked, "head_hash": head}
