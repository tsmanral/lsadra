"""
G-10 — Password policy, login throttling, no plaintext fallback.

Attacker story: any password was accepted (one character, "password1"), a
stored value that was not a bcrypt hash was compared as plaintext, and the
login route let anyone try passwords as fast as bcrypt allowed, per account and
across accounts.

Secure behavior pinned here: passwords need 12+ characters, at most 72 bytes,
not the username and not on the bundled common-password list; verify_password
never matches a non-bcrypt stored value; after 5 failures for one username (or
20 from one IP) in 15 minutes the login route answers 429 with Retry-After and
does not run bcrypt; unknown usernames cost the same bcrypt as wrong passwords.
SYNTHETIC data only.
"""

import pytest

from lsadra import config
from lsadra.auth import verify_password
from lsadra.security.passwords import PasswordPolicyError, check_password_policy
from tests.security._identity_support import (  # noqa: F401 — fixture
    OTHER_STRONG_PASSWORD,
    STRONG_PASSWORD,
    bearer,
    identity_env,
    login,
    make_user,
)


@pytest.mark.parametrize(
    "bad",
    [
        "short",
        "elevenchars",
        "a" * 20,
        "password1234",
        "Q1W2E3" + "R4T5Y6",  # split so secret scanners skip it
        "x" * 40 + "é" * 20,
    ],
)
def test_policy_rejects_weak_passwords(bad):
    with pytest.raises(PasswordPolicyError):
        check_password_policy(bad)


def test_policy_rejects_the_username():
    with pytest.raises(PasswordPolicyError):
        check_password_policy("Analyst.Demo.01", "analyst.demo.01")


def test_policy_accepts_a_long_uncommon_passphrase():
    check_password_policy(STRONG_PASSWORD, "analyst.demo")


def test_plaintext_fallback_is_gone():
    # LOAD-BEARING: a legacy plaintext "hash" equal to the password must not match.
    assert verify_password("legacy-plaintext-pw", "legacy-plaintext-pw") is False
    assert verify_password("anything", "") is False


def test_admin_password_reset_enforces_policy(identity_env):
    client = identity_env
    make_user("root.demo", role="ADMIN")
    uid = make_user("analyst.demo")
    token = login(client, "root.demo").json()["access_token"]
    weak = client.post(
        "/api/dashboard/users/password",
        headers=bearer(token),
        json={"user_id": uid, "password": "password1"},
    )
    assert weak.status_code == 422
    ok = client.post(
        "/api/dashboard/users/password",
        headers=bearer(token),
        json={"user_id": uid, "password": "violet-ember-canyon-09"},
    )
    assert ok.status_code == 200


def test_admin_create_user_enforces_policy(identity_env):
    client = identity_env
    make_user("root.demo", role="ADMIN")
    token = login(client, "root.demo").json()["access_token"]
    weak = client.post(
        "/api/dashboard/users",
        headers=bearer(token),
        json={"username": "new.demo", "password": "password" + "1234"},
    )
    assert weak.status_code == 422
    from lsadra.storage.database import get_user_by_username

    assert get_user_by_username("new.demo") is None
    ok = client.post(
        "/api/dashboard/users",
        headers=bearer(token),
        json={"username": "new.demo", "password": OTHER_STRONG_PASSWORD},
    )
    assert ok.status_code == 200, ok.text


def test_signup_and_admin_cli_enforce_policy(identity_env, monkeypatch):
    client = identity_env
    monkeypatch.setattr(config, "ALLOW_SIGNUP", True)
    weak = client.post(
        "/api/auth/register", json={"username": "self.demo", "password": "password" + "1234"}
    )
    assert weak.status_code == 422
    from lsadra.admin_cli import create_admin

    with pytest.raises(ValueError):
        create_admin("boot.demo", "password" + "1234")


def test_username_lockout_returns_429_without_running_bcrypt(identity_env, monkeypatch):
    client = identity_env
    make_user()
    for _ in range(config.LOGIN_MAX_FAILURES_PER_USER):
        assert login(client, password="wrong-password-xyz").status_code == 401

    import server

    calls = []
    real = server.verify_password
    monkeypatch.setattr(server, "verify_password", lambda p, h: calls.append(1) or real(p, h))
    r = login(client)  # even the RIGHT password is throttled now
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) > 0
    assert calls == []  # LOAD-BEARING: throttled before any bcrypt work


def test_ip_limit_stops_password_spraying(identity_env, monkeypatch):
    client = identity_env
    monkeypatch.setattr(config, "LOGIN_MAX_FAILURES_PER_IP", 3)
    for i in range(3):
        assert login(client, f"user{i}.demo", "wrong-password-xyz").status_code == 401
    assert login(client, "fresh.demo", "wrong-password-xyz").status_code == 429


def test_success_clears_the_username_counter(identity_env):
    client = identity_env
    make_user()
    for _ in range(config.LOGIN_MAX_FAILURES_PER_USER - 1):
        login(client, password="wrong-password-xyz")
    assert login(client).status_code == 200
    assert login(client, password="wrong-password-xyz").status_code == 401  # not yet locked


def test_unknown_user_still_spends_a_bcrypt_check(identity_env, monkeypatch):
    import server

    calls = []
    monkeypatch.setattr(server, "burn_password_check", lambda p: calls.append(p))
    assert login(identity_env, "nobody.demo", "whatever-password").status_code == 401
    assert calls == ["whatever-password"]
