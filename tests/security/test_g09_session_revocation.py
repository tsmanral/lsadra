"""
G-9 — Sessions and device credentials must be revocable at once.

Attacker story: with 8-hour JWTs that carried their own role and were never
checked against the account, a stolen dashboard token kept working after the
victim logged out, after an admin demoted or disabled the account, and until
expiry. A device whose key leaked could only be stopped by deleting it, which
also destroyed its history.

Secure behavior pinned here: tokens last 60 minutes by default; every request
re-reads the account, so logout, a role change, a password change or disabling
the account ends earlier tokens immediately, and the role used is the stored
one; the live alert socket applies the same check; a revoked device is refused
whatever key it sends and stays revoked; a rotated device key keeps working
only for the overlap window. SYNTHETIC data only.
"""

from datetime import datetime, timedelta

import bcrypt
import pytest
from fastapi import HTTPException

from lsadra import config
from lsadra.auth import create_access_token, decode_token
from lsadra.storage import database as db
from tests.security._identity_support import (  # noqa: F401 — fixture
    OTHER_STRONG_PASSWORD,
    STRONG_PASSWORD,
    bearer,
    identity_env,
    login,
    make_user,
)


def test_default_session_lifetime_is_60_minutes():
    assert config.JWT_EXPIRATION_MINUTES == 60
    payload = decode_token(create_access_token("u", "u.demo", "ANALYST"))
    assert payload["exp"] - payload["iat"] == 3600
    assert payload["tv"] == 0 and payload["jti"]


def test_logout_revokes_the_token(identity_env):
    client = identity_env
    make_user()
    token = login(client).json()["access_token"]
    assert client.get("/api/incidents", headers=bearer(token)).status_code == 200

    assert client.post("/api/auth/logout", headers=bearer(token)).status_code == 200
    # LOAD-BEARING: the same, unexpired token is refused after logout.
    assert client.get("/api/incidents", headers=bearer(token)).status_code == 401


def test_role_change_takes_effect_immediately(identity_env):
    client = identity_env
    make_user("root.demo", role="ADMIN")
    uid = make_user("victim.demo", role="ADMIN")
    token = login(client, "victim.demo").json()["access_token"]
    assert client.get("/api/dashboard/users", headers=bearer(token)).status_code == 200

    db.update_user_role(uid, "VIEWER")
    # The old token is revoked outright (token_version bumped) ...
    assert client.get("/api/dashboard/users", headers=bearer(token)).status_code == 401
    # ... and a new one carries only the stored role.
    fresh = login(client, "victim.demo").json()["access_token"]
    assert client.get("/api/dashboard/users", headers=bearer(fresh)).status_code == 403


def test_forged_role_claim_is_ignored(identity_env):
    client = identity_env
    uid = make_user("viewer.demo", role="VIEWER")
    token = create_access_token(uid, "viewer.demo", "ADMIN", token_version=0)
    assert client.get("/api/dashboard/users", headers=bearer(token)).status_code == 403


def test_disabled_account_is_locked_out(identity_env):
    client = identity_env
    uid = make_user()
    token = login(client).json()["access_token"]
    db.set_user_disabled(uid, True)
    assert client.get("/api/incidents", headers=bearer(token)).status_code == 401
    assert login(client).status_code == 401


def test_password_change_ends_other_sessions(identity_env):
    client = identity_env
    make_user()
    token = login(client).json()["access_token"]
    r = client.post("/api/auth/password", headers=bearer(token),
                    json={"current_password": STRONG_PASSWORD, "new_password": OTHER_STRONG_PASSWORD})
    assert r.status_code == 200
    assert client.get("/api/incidents", headers=bearer(token)).status_code == 401
    assert login(client, password=OTHER_STRONG_PASSWORD).status_code == 200


def test_token_for_deleted_or_unknown_user_is_refused(identity_env):
    client = identity_env
    token = create_access_token("usr-ghost", "ghost.demo", "ADMIN")
    assert client.get("/api/incidents", headers=bearer(token)).status_code == 401


def test_ws_handshake_refuses_a_revoked_token(identity_env):
    from lsadra.ui.alert_stream import authenticate_handshake

    client = identity_env
    uid = make_user()
    token = login(client).json()["access_token"]
    assert authenticate_handshake(token)["user_id"] == uid
    db.bump_token_version(uid)
    assert authenticate_handshake(token) is None


# ── devices ───────────────────────────────────────────────────────────────

_KEY = "synthetic-device-key-0001"


@pytest.fixture
def device(identity_env):
    owner = make_user("owner.demo")
    stored = bcrypt.hashpw(_KEY.encode(), bcrypt.gensalt()).decode()
    db.create_device("dev-demo-01", owner, "host.demo", "linux", stored)
    return identity_env, owner


def _auth(key):
    from lsadra.ingestion.api_ingestion import _authenticate_device

    return _authenticate_device(x_device_id="dev-demo-01", x_api_key=key)


def test_revoked_device_is_refused_and_stays_revoked(device):
    client, _ = device
    assert _auth(_KEY)["id"] == "dev-demo-01"  # also warms the credential cache
    token = login(client, "owner.demo").json()["access_token"]
    assert client.post("/api/devices/dev-demo-01/revoke", headers=bearer(token)).status_code == 200

    with pytest.raises(HTTPException) as exc:
        _auth(_KEY)  # LOAD-BEARING: the correct (and cached) key no longer works
    assert exc.value.status_code == 401

    db.update_device_status("dev-demo-01", "ONLINE")  # offline/online jobs, toggles
    db.record_heartbeat("dev-demo-01")
    assert db.get_device("dev-demo-01")["status"] == "REVOKED"


def test_only_the_owner_or_an_admin_can_revoke(device):
    client, _ = device
    make_user("stranger.demo")
    token = login(client, "stranger.demo").json()["access_token"]
    assert client.post("/api/devices/dev-demo-01/revoke", headers=bearer(token)).status_code == 404
    assert db.get_device("dev-demo-01")["status"] != "REVOKED"


def test_key_rotation_overlap_then_expiry(device):
    client, _ = device
    token = login(client, "owner.demo").json()["access_token"]
    r = client.post("/api/devices/dev-demo-01/rotate-key", headers=bearer(token))
    assert r.status_code == 200
    new_key = r.json()["api_key"]
    assert _auth(new_key)["id"] == "dev-demo-01"
    assert _auth(_KEY)["id"] == "dev-demo-01"  # inside the overlap window

    from lsadra.ingestion.api_ingestion import device_credential_cache

    conn = db.get_connection()
    conn.execute("UPDATE devices SET previous_key_expires_at = ? WHERE id = 'dev-demo-01'",
                 ((datetime.utcnow() - timedelta(seconds=1)).isoformat(),))
    conn.commit()
    conn.close()
    device_credential_cache.invalidate()
    with pytest.raises(HTTPException):
        _auth(_KEY)
    assert _auth(new_key)["id"] == "dev-demo-01"
