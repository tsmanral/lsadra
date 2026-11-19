"""
G-33 — Optional TOTP second factor, required for admins when configured.

Attacker story: a dashboard exposed beyond localhost was protected by a
password alone, so one phished or reused admin password handed over the whole
deployment.

Secure behavior pinned here: the RFC 6238 implementation matches the RFC test
vector; an account with an enrolled authenticator cannot log in without a
current code; a code cannot be replayed; wrong codes count toward the login
throttle; with LSADRA_ADMIN_TOTP=required an admin without an authenticator is
refused; enrolment needs a valid code and ends earlier sessions.
SYNTHETIC data only.
"""

import base64

from lsadra import config
from lsadra.security import totp
from lsadra.storage import database as db
from tests.security._identity_support import (  # noqa: F401 — fixture
    bearer,
    identity_env,
    login,
    make_user,
)


def test_rfc6238_sha1_vector():
    secret = base64.b32encode(b"12345678901234567890").decode()
    # RFC 6238 Appendix B, T = 59 s: 94287082 (8 digits) -> 287082 (6 digits)
    assert totp.code_at(secret, 59 // 30) == "287082"
    assert totp.verify(secret, "287082", now=59) == 1


def _enrolled(client, username="analyst.demo", role="ANALYST"):
    uid = make_user(username, role=role)
    secret = totp.generate_secret()
    db.set_user_totp(uid, secret, enabled=True)
    return uid, secret


def test_login_requires_a_code_once_enrolled(identity_env):
    client = identity_env
    _, secret = _enrolled(client)
    r = login(client)
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "totp_required"
    assert "access_token" not in r.json()

    code = totp.code_at(secret, totp.current_step())
    assert login(client, totp_code=code).status_code == 200
    # LOAD-BEARING: the same code cannot be used twice.
    assert login(client, totp_code=code).status_code == 401


def test_wrong_codes_count_toward_the_throttle(identity_env):
    client = identity_env
    _enrolled(client)
    for _ in range(config.LOGIN_MAX_FAILURES_PER_USER):
        assert login(client, totp_code="000000").status_code == 401
    assert login(client, totp_code="000000").status_code == 429


def test_required_mode_blocks_admin_without_authenticator(identity_env, monkeypatch):
    client = identity_env
    monkeypatch.setattr(config, "ADMIN_TOTP", "required")
    make_user("root.demo", role="ADMIN")
    r = login(client, "root.demo")
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "totp_enrolment_required"
    make_user("analyst.demo")
    assert login(client).status_code == 200  # only admins are forced


def test_enrolment_flow_needs_a_valid_code_and_ends_old_sessions(identity_env):
    client = identity_env
    make_user()
    token = login(client).json()["access_token"]
    setup = client.post("/api/auth/totp/setup", headers=bearer(token)).json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/")
    assert client.post("/api/auth/totp/enable", headers=bearer(token),
                       json={"code": "000000"}).status_code == 400
    code = totp.code_at(setup["secret"], totp.current_step())
    r = client.post("/api/auth/totp/enable", headers=bearer(token), json={"code": code})
    assert r.status_code == 200
    new_token = r.json()["access_token"]
    assert client.get("/api/incidents", headers=bearer(token)).status_code == 401
    assert client.get("/api/incidents", headers=bearer(new_token)).status_code == 200
