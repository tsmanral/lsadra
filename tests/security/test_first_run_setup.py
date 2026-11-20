"""First-run admin setup (/api/setup) for the desktop app.

The endpoint creates an ADMIN without a shell, so it must stay closed unless
the server was started with a setup token, and even then only for a loopback
client that presents the token, and only while no admin exists.
"""

import secrets
import threading

import pytest

from tests.fixtures import setup_test_db

# Generated per run so no credential-shaped literal sits in the repository.
TEST_PASSWORD = secrets.token_urlsafe(16)
TOKEN = secrets.token_hex(32)


@pytest.fixture(autouse=True)
def _db(tmp_path):
    setup_test_db(tmp_path)


@pytest.fixture
def token(monkeypatch):
    from lsadra import config

    monkeypatch.setattr(config, "SETUP_TOKEN", TOKEN)
    return TOKEN


def _client(host="127.0.0.1"):
    from fastapi.testclient import TestClient

    from server import app

    return TestClient(app, client=(host, 50000))


def _body(token, username="owner.demo", password=None):
    return {"setup_token": token, "username": username, "password": password or TEST_PASSWORD}


def _status(client, token):
    return client.post("/api/setup/status", json={"setup_token": token})


def _role(username):
    from lsadra.storage.database import get_user_by_username

    user = get_user_by_username(username)
    return user and user["role"]


def test_setup_is_off_without_a_token():
    client = _client()
    assert _status(client, "").status_code == 403
    r = client.post("/api/setup/admin", json=_body(""))
    assert r.status_code == 403
    assert _role("owner.demo") is None


def test_short_token_does_not_turn_setup_on(monkeypatch):
    from lsadra import config

    monkeypatch.setattr(config, "SETUP_TOKEN", "x" * 31)
    r = _client().post("/api/setup/admin", json=_body("x" * 31))
    assert r.status_code == 403
    assert _role("owner.demo") is None


def test_first_admin_is_created_and_can_log_in(token):
    client = _client()
    assert _status(client, token).json() == {"needs_admin": True}
    r = client.post("/api/setup/admin", json=_body(token))
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "ADMIN"
    assert _status(client, token).json() == {"needs_admin": False}
    login = client.post(
        "/api/auth/login", json={"username": "owner.demo", "password": TEST_PASSWORD}
    )
    assert login.status_code == 200, login.text
    assert login.json()["role"] == "ADMIN"


def test_wrong_token_is_refused_and_audited(token):
    from lsadra.security.audit import list_events

    wrong = secrets.token_hex(32)
    assert _status(_client(), wrong).status_code == 403
    r = _client().post("/api/setup/admin", json=_body(wrong))
    assert r.status_code == 403
    assert _role("owner.demo") is None
    events = list_events(action="setup.admin")
    assert events and events[0]["outcome"] == "denied"


def test_only_loopback_clients(token):
    for host in ["192.0.2.10", "203.0.113.7", "testclient"]:
        r = _client(host).post("/api/setup/admin", json=_body(token))
        assert r.status_code == 403, host
        assert _status(_client(host), token).status_code == 403
    assert _role("owner.demo") is None


def test_forwarded_header_cannot_fake_loopback(token, monkeypatch):
    from lsadra import config

    monkeypatch.setattr(config, "TRUSTED_PROXY_IPS", {"192.0.2.1"})
    r = _client("192.0.2.1").post(
        "/api/setup/admin", json=_body(token), headers={"X-Forwarded-For": "127.0.0.1"}
    )
    assert r.status_code == 403
    assert _role("owner.demo") is None


def test_no_second_admin_once_one_exists(token):
    from lsadra.admin_cli import create_admin

    create_admin("existing.demo", TEST_PASSWORD)
    client = _client()
    assert _status(client, token).json() == {"needs_admin": False}
    r = client.post("/api/setup/admin", json=_body(token))
    assert r.status_code == 409
    assert _role("owner.demo") is None


def test_password_policy_applies(token):
    r = _client().post("/api/setup/admin", json=_body(token, password="x" * 5))
    assert r.status_code == 422
    assert _role("owner.demo") is None


def test_racing_requests_create_one_admin(token):
    client = _client()
    results = []

    def attempt(i):
        r = client.post("/api/setup/admin", json=_body(token, username=f"owner{i}.demo"))
        results.append(r.status_code)

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == [201, 409, 409, 409, 409]
    from lsadra.storage.database import list_users

    assert [u["role"] for u in list_users()].count("ADMIN") == 1
