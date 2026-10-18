"""
JWT issue/verify contract for lsadra.auth (PyJWT).

Pins the behavior the python-jose -> PyJWT swap must keep: a token we issue
round-trips with its claims; expired, tampered, unsigned (alg=none),
wrong-algorithm and claim-less tokens are all rejected with a 401.
"""

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import HTTPException

from lsadra.auth import create_access_token, decode_token
from lsadra.config import JWT_SECRET


def _expect_401(token: str) -> None:
    with pytest.raises(HTTPException) as exc:
        decode_token(token)
    assert exc.value.status_code == 401


def _future() -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=5)


def test_round_trip_keeps_claims():
    payload = decode_token(create_access_token("u-1", "alice", "ANALYST"))
    assert payload["sub"] == "u-1"
    assert payload["username"] == "alice"
    assert payload["role"] == "ANALYST"
    assert payload["exp"] > datetime.now(timezone.utc).timestamp()


def test_expired_token_rejected():
    _expect_401(create_access_token("u-1", "alice", "ANALYST", expires_minutes=-1))


def test_tampered_signature_rejected():
    token = create_access_token("u-1", "alice", "VIEWER")
    head, body, sig = token.split(".")
    _expect_401(f"{head}.{body}.{sig[::-1]}")


def test_wrong_secret_rejected():
    forged = jwt.encode({"sub": "u-1", "role": "ADMIN", "exp": _future()}, "x" * 48)
    _expect_401(forged)


def test_unsigned_alg_none_rejected():
    forged = jwt.encode({"sub": "u-1", "role": "ADMIN", "exp": _future()}, None, algorithm="none")
    _expect_401(forged)


def test_other_hmac_algorithm_rejected():
    forged = jwt.encode(
        {"sub": "u-1", "role": "ADMIN", "exp": _future()}, JWT_SECRET * 2, algorithm="HS512"
    )
    _expect_401(forged)


@pytest.mark.parametrize("missing", ["sub", "exp"])
def test_required_claim_missing_rejected(missing):
    claims = {"sub": "u-1", "role": "ADMIN", "exp": _future()}
    del claims[missing]
    _expect_401(jwt.encode(claims, JWT_SECRET, algorithm="HS256"))


def test_garbage_rejected():
    _expect_401("not-a-jwt")
