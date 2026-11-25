"""First-run admin setup for the desktop app. Mounted at ``/api/setup``.

A fresh install has no account, and sign-up is off outside dev mode, so the
first admin used to need a shell (``lsadra-admin create-admin``). The desktop
app instead starts its server with ``LSADRA_SETUP_TOKEN``, a random token it
makes at each start and also gives its own window. The dashboard then shows
"create your admin account", and this router creates that one account.

Both endpoints take the token in the JSON body and refuse (403) unless:

* ``LSADRA_SETUP_TOKEN`` is set and at least 32 characters;
* the request comes straight from a loopback address (the peer itself, never
  a forwarded header);
* the token in the body matches (constant-time compare).

``POST /status`` then says whether an admin is still missing, and
``POST /admin`` creates one only while no ADMIN account exists. The check
and the insert run under one lock, so two racing requests cannot both
create an admin.

The account gets the same password policy as every other path. Each attempt
is written to the audit trail.
"""

import hmac
import threading
import uuid
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from lsadra import config
from lsadra.security import audit
from lsadra.security.tls import is_loopback

router = APIRouter(tags=["setup"])

_create_lock = threading.Lock()


class SetupStatusRequest(BaseModel):
    setup_token: str = Field(..., max_length=512)


class SetupAdminRequest(BaseModel):
    setup_token: str = Field(..., max_length=512)
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., max_length=1024)


def _enabled() -> bool:
    return len(config.SETUP_TOKEN) >= config.SETUP_TOKEN_MIN_LENGTH


def _authorize(request: Request, token: str, username: str = "") -> str:
    """The loopback peer address, or 403. Bad tokens are audited."""
    if not _enabled():
        raise HTTPException(status_code=403, detail="First-run setup is off on this server.")
    peer = request.client.host if request.client else ""
    if not is_loopback(peer):
        raise HTTPException(
            status_code=403, detail="First-run setup is only open to this computer."
        )
    if not hmac.compare_digest(token.encode(), config.SETUP_TOKEN.encode()):
        audit.record(
            "setup.admin",
            "denied",
            target=username or None,
            source_ip=peer,
            details={"reason": "bad_token"},
        )
        raise HTTPException(status_code=403, detail="The setup token is not valid.")
    return peer


def _admin_exists() -> bool:
    from lsadra.storage.database import init_db, list_users

    init_db()
    return any((u.get("role") or "").upper() == "ADMIN" for u in list_users())


def _create_first_admin(username: str, password: str, peer: str) -> Dict[str, Any]:
    from lsadra.auth import hash_password
    from lsadra.storage.database import create_user, get_user_by_username

    with _create_lock:
        if _admin_exists():
            audit.record(
                "setup.admin",
                "denied",
                target=username,
                source_ip=peer,
                details={"reason": "admin_exists"},
            )
            raise HTTPException(status_code=409, detail="An admin account already exists.")
        if get_user_by_username(username):
            raise HTTPException(status_code=409, detail="That username is taken.")
        user_id = str(uuid.uuid4())
        create_user(user_id, username, hash_password(password), "ADMIN")
    audit.record(
        "setup.admin",
        "success",
        actor={"user_id": user_id, "username": username},
        target=username,
        source_ip=peer,
    )
    return {"status": "ok", "user_id": user_id, "username": username, "role": "ADMIN"}


@router.post("/status")
async def setup_status(req: SetupStatusRequest, request: Request) -> Dict[str, bool]:
    """Whether the dashboard should offer to create the first admin."""
    await run_in_threadpool(_authorize, request, req.setup_token)
    exists = await run_in_threadpool(_admin_exists)
    return {"needs_admin": not exists}


@router.post("/admin", status_code=201)
async def setup_admin(req: SetupAdminRequest, request: Request) -> Dict[str, Any]:
    peer = await run_in_threadpool(_authorize, request, req.setup_token, req.username)
    username = req.username.strip()
    if not username:
        raise HTTPException(status_code=422, detail="Choose a username.")
    from lsadra.security.passwords import PasswordPolicyError, check_password_policy

    try:
        check_password_policy(req.password, username)
    except PasswordPolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return await run_in_threadpool(_create_first_admin, username, req.password, peer)
