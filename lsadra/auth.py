"""
LSADRA V3 — Authentication and Role-Based Access Control (RBAC).

Provides JWT creation/validation and FastAPI dependency functions
for enforcing role-based access on API endpoints.

Uses bcrypt directly (not passlib) to avoid bcrypt version
compatibility issues.
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.concurrency import run_in_threadpool

from lsadra.config import JWT_EXPIRATION_MINUTES, JWT_SECRET, TOKEN_ALGORITHM

logger = logging.getLogger(__name__)

# ── password hashing ─────────────────────────────────────────────────────


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


# A real bcrypt hash of a random value: verifying against it when the username
# does not exist keeps a failed login's timing the same either way.
_DUMMY_HASH = bcrypt.hashpw(b"lsadra-timing-equaliser", bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its bcrypt hash.

    Fails closed (G-10): anything that is not a valid bcrypt hash, such as a
    plaintext value left by a pre-V3 install, never matches. Such an account
    needs a password reset by an admin.
    """
    try:
        pwd_bytes = plain_password.encode("utf-8")
        hash_bytes = (hashed_password or "").encode("utf-8")
        if not hash_bytes.startswith(b"$2"):
            return False
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except (ValueError, TypeError):
        return False


def burn_password_check(plain_password: str) -> None:
    """Spend one bcrypt verify, for a login whose username does not exist."""
    verify_password(plain_password, _DUMMY_HASH)


# ── JWT creation ─────────────────────────────────────────────────────────

def create_access_token(
    user_id: str,
    username: str,
    role: str,
    expires_minutes: int = JWT_EXPIRATION_MINUTES,
    token_version: int = 0,
) -> str:
    """
    Create a signed JWT access token.

    Claims:
        sub: user_id, username, role, exp, iat, jti, and tv (the user's
        token_version when issued; a later bump revokes the token, G-9).
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=expires_minutes)
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "tv": int(token_version),
        "iat": now,
        "jti": uuid.uuid4().hex,
        "exp": expire,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=TOKEN_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token. Raises HTTPException on failure."""
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[TOKEN_ALGORITHM],
            options={"require": ["exp", "sub"]},
        )
        return payload
    except jwt.InvalidTokenError as e:
        logger.debug("Rejected token: %s", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── FastAPI dependencies ─────────────────────────────────────────────────

_bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> dict:
    """
    FastAPI dependency that extracts and validates the current user from
    the Authorization header.

    Returns:
        Dict with user_id, username, role.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_token(credentials.credentials)
    user = await run_in_threadpool(session_user, payload)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session is no longer valid. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def session_user(payload: dict) -> Optional[dict]:
    """The live identity behind a decoded token, or None if it was revoked (G-9).

    Reads the user row on every request (threadpool), so a logout, a role or
    password change, or disabling the account takes effect immediately rather
    than at token expiry. The role comes from the database, never from the
    token, so a demoted user cannot keep using an old token's role.
    """
    from lsadra.storage.database import get_user_by_id

    user_id = payload.get("sub")
    if not user_id:
        return None
    row = get_user_by_id(user_id)
    if row is None or row.get("disabled"):
        return None
    if int(payload.get("tv", -1)) != int(row.get("token_version") or 0):
        return None
    return {
        "user_id": row["id"],
        "username": row["username"],
        "role": row.get("role") or "VIEWER",
        "token_version": int(row.get("token_version") or 0),
    }


def require_role(*allowed_roles: str):
    """
    Return a FastAPI dependency that enforces one or more allowed roles.

    Usage::

        @router.post("/admin/retrain")
        async def retrain(user=Depends(require_role("ADMIN"))):
            ...

        @router.post("/incidents/{id}/assign")
        async def assign(user=Depends(require_role("ADMIN", "ANALYST"))):
            ...
    """

    async def _role_checker(
        current_user: dict = Depends(get_current_user),
    ) -> dict:
        if current_user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {', '.join(allowed_roles)}.",
            )
        return current_user

    return _role_checker
