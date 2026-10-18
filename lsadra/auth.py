"""
LSADRA V3 — Authentication and Role-Based Access Control (RBAC).

Provides JWT creation/validation and FastAPI dependency functions
for enforcing role-based access on API endpoints.

Uses bcrypt directly (not passlib) to avoid bcrypt version
compatibility issues.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from lsadra.config import JWT_EXPIRATION_MINUTES, JWT_SECRET, TOKEN_ALGORITHM

logger = logging.getLogger(__name__)

# ── password hashing ─────────────────────────────────────────────────────


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    try:
        pwd_bytes = plain_password.encode("utf-8")
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception:
        # Fallback: plain-text comparison for legacy V2 users
        return plain_password == hashed_password


# ── JWT creation ─────────────────────────────────────────────────────────

def create_access_token(
    user_id: str, username: str, role: str, expires_minutes: int = JWT_EXPIRATION_MINUTES
) -> str:
    """
    Create a signed JWT access token.

    Claims:
        sub: user_id, username, role, exp.
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {e}",
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
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload.",
        )

    return {
        "user_id": user_id,
        "username": payload.get("username", ""),
        "role": payload.get("role", "VIEWER"),
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
