"""P0 access-control regressions from the November 2026 standards audit (G-1..G-4).

Each test pins one secure behaviour and fails on the code before the fix:

* sign-up is closed by default outside dev mode, and an admin can still add users;
* a JWT secret copied from the docs, or a short one, stops the server from booting;
* incidents, metrics and device config are scoped to the caller's own devices;
* read-only and analyst roles cannot reach admin-only or enrolment actions;
* device-facing routes need the device's own key, not just its id;
* only the two install files are served, and the install command verifies them;
* every route outside a short public list refuses a request with no credentials.

All users, hosts and addresses are synthetic (``*.demo``, RFC 5737).
"""

import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.fixtures import setup_test_db

# Generated per run so no credential-shaped literal sits in the repository.
TEST_PASSWORD = secrets.token_urlsafe(16)

_REPO_ROOT = Path(__file__).resolve().parents[2]

ALICE_KEY = "alice-device-key-synthetic"
BOB_KEY = "bob-device-key-synthetic"


@pytest.fixture(autouse=True)
def _db(tmp_path):
    setup_test_db(tmp_path)


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from server import app

    return TestClient(app)


def _user(user_id, username, role):
    from lsadra.auth import create_access_token, hash_password
    from lsadra.storage.database import create_user

    create_user(user_id, username, hash_password(TEST_PASSWORD), role)
    return {"Authorization": f"Bearer {create_access_token(user_id, username, role)}"}


def _device(device_id, user_id, key):
    import bcrypt

    from lsadra.storage.database import create_device

    hashed = bcrypt.hashpw(key.encode(), bcrypt.gensalt(4)).decode()
    create_device(device_id, user_id, f"{device_id}.demo", "linux", hashed)


def _incident(device_id):
    from lsadra.storage.database import create_incident

    return create_incident(
        device_id=device_id,
        source_ip="192.0.2.10",
        attack_type="Brute Force",
        severity_label="HIGH",
        first_seen="2026-11-18T00:00:00",
    )


@pytest.fixture
def tenants():
    """Two analysts with one device and one incident each, plus an admin."""
    alice = _user("u-alice", "alice.demo", "ANALYST")
    bob = _user("u-bob", "bob.demo", "ANALYST")
    admin = _user("u-admin", "admin.demo", "ADMIN")
    viewer = _user("u-viewer", "viewer.demo", "VIEWER")
    _device("dev-alice", "u-alice", ALICE_KEY)
    _device("dev-bob", "u-bob", BOB_KEY)
    return {
        "alice": alice,
        "bob": bob,
        "admin": admin,
        "viewer": viewer,
        "alice_incident": _incident("dev-alice"),
    }


# ── G-1: sign-up ─────────────────────────────────────────────────────────


def _config_value(env_overrides, expr):
    env = {k: v for k, v in os.environ.items()
           if k not in ("LSADRA_DEV_MODE", "LSADRA_JWT_SECRET", "LSADRA_ALLOW_SIGNUP")}
    env.update(env_overrides)
    r = subprocess.run(
        [sys.executable, "-c", f"import lsadra.config as c; print({expr})"],
        capture_output=True, text=True, env=env, cwd=str(_REPO_ROOT),
    )
    return r


STRONG_SECRET = secrets.token_urlsafe(48)


def test_signup_is_closed_by_default_outside_dev_mode():
    r = _config_value({"LSADRA_JWT_SECRET": STRONG_SECRET}, "c.ALLOW_SIGNUP")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "False"


def test_signup_can_be_opened_explicitly():
    r = _config_value(
        {"LSADRA_JWT_SECRET": STRONG_SECRET, "LSADRA_ALLOW_SIGNUP": "true"}, "c.ALLOW_SIGNUP"
    )
    assert r.stdout.strip() == "True", r.stderr


def test_register_refused_when_signup_closed(client, monkeypatch):
    from lsadra import config

    monkeypatch.setattr(config, "ALLOW_SIGNUP", False)
    r = client.post("/api/auth/register",
                    json={"username": "mallory.demo", "password": TEST_PASSWORD})
    assert r.status_code == 403
    from lsadra.storage.database import get_user_by_username

    assert get_user_by_username("mallory.demo") is None


def test_admin_can_create_accounts_and_others_cannot(client, tenants):
    body = {"username": "carol.demo", "password": TEST_PASSWORD, "role": "VIEWER"}
    assert client.post("/api/dashboard/users", json=body, headers=tenants["bob"]).status_code == 403
    r = client.post("/api/dashboard/users", json=body, headers=tenants["admin"])
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "VIEWER"
    bad_role = {**body, "username": "dave.demo", "role": "ROOT"}
    assert client.post("/api/dashboard/users", json=bad_role, headers=tenants["admin"]).status_code == 422


def test_role_update_rejects_unknown_roles(client, tenants):
    r = client.post("/api/dashboard/users/role",
                    json={"user_id": "u-bob", "role": "SUPERUSER"}, headers=tenants["admin"])
    assert r.status_code == 422


# ── G-2: JWT secret ──────────────────────────────────────────────────────


@pytest.mark.parametrize("secret", ["changeme-in-production", "CHANGEME", "short-secret"])
def test_weak_jwt_secret_refused_outside_dev_mode(secret):
    r = _config_value({"LSADRA_JWT_SECRET": secret}, "1")
    assert r.returncode != 0, "server booted with a guessable JWT secret"
    assert "LSADRA_JWT_SECRET is not safe" in r.stderr


def test_strong_jwt_secret_accepted():
    r = _config_value({"LSADRA_JWT_SECRET": STRONG_SECRET}, "1")
    assert r.returncode == 0, r.stderr


def test_env_example_ships_no_usable_secret():
    text = (_REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    line = next(ln for ln in text.splitlines() if ln.startswith("LSADRA_JWT_SECRET="))
    assert line.strip() == "LSADRA_JWT_SECRET="


# ── G-3: object- and function-level authorization ───────────────────────


def test_analyst_cannot_change_another_users_incident(client, tenants):
    from lsadra.storage.database import get_incident

    inc = tenants["alice_incident"]
    r = client.post(f"/api/incidents/{inc}/status",
                    json={"status": "RESOLVED"}, headers=tenants["bob"])
    assert r.status_code == 404
    assert get_incident(inc)["status"] == "OPEN"

    r = client.post(f"/api/incidents/{inc}/assign",
                    json={"user_id": "u-bob"}, headers=tenants["bob"])
    assert r.status_code == 404
    assert get_incident(inc).get("assigned_to") in (None, "")


def test_owner_and_admin_can_change_incident(client, tenants):
    inc = tenants["alice_incident"]
    r = client.post(f"/api/incidents/{inc}/status",
                    json={"status": "INVESTIGATING"}, headers=tenants["alice"])
    assert r.status_code == 200, r.text
    r = client.post(f"/api/incidents/{inc}/status",
                    json={"status": "RESOLVED"}, headers=tenants["admin"])
    assert r.status_code == 200, r.text


def test_metrics_scoped_to_callers_devices(client, tenants):
    from lsadra.storage.database import get_connection

    conn = get_connection()
    conn.execute(
        "INSERT INTO metrics_5min (device_id, window_start, event_count) VALUES (?, ?, ?)",
        ("dev-alice", "2026-11-18T00:00:00", 7),
    )
    conn.commit()
    conn.close()
    window = {"start": "2026-11-17T00:00:00", "end": "2026-11-19T00:00:00"}

    r = client.get("/api/dashboard/metrics", params={**window, "device_id": "dev-alice"},
                   headers=tenants["bob"])
    assert r.status_code == 404

    r = client.get("/api/dashboard/metrics", params=window, headers=tenants["bob"])
    assert r.status_code == 200
    assert r.json() == []

    r = client.get("/api/dashboard/metrics", params=window, headers=tenants["alice"])
    assert [row["event_count"] for row in r.json()] == [7]


def test_viewer_cannot_mint_registration_tokens(client, tenants):
    assert client.post("/api/dashboard/generate-token", headers=tenants["viewer"]).status_code == 403
    r = client.post("/api/dashboard/generate-token", headers=tenants["alice"])
    assert r.status_code == 200
    assert len(r.json()["agent_sha256"]) == 64


@pytest.mark.parametrize("path", ["/api/dashboard/retrain", "/api/dashboard/run-drift"])
def test_global_model_actions_are_admin_only(client, tenants, path):
    assert client.post(path, headers=tenants["alice"]).status_code == 403


def test_heartbeat_requires_the_device_key(client, tenants):
    from lsadra.storage.database import get_latest_heartbeat

    r = client.post("/heartbeat", json={"device_id": "dev-alice"})
    assert r.status_code in (401, 422)
    r = client.post("/heartbeat", json={"device_id": "dev-alice"},
                    headers={"X-Device-Id": "dev-alice", "X-Api-Key": "wrong-key"})
    assert r.status_code == 401
    assert get_latest_heartbeat("dev-alice") is None

    # Bob's own key cannot speak for Alice's device.
    r = client.post("/heartbeat", json={"device_id": "dev-alice"},
                    headers={"X-Device-Id": "dev-bob", "X-Api-Key": BOB_KEY})
    assert r.status_code == 403
    assert get_latest_heartbeat("dev-alice") is None

    r = client.post("/heartbeat", json={"cpu_pct": 12.5},
                    headers={"X-Device-Id": "dev-alice", "X-Api-Key": ALICE_KEY})
    assert r.status_code == 200, r.text
    assert get_latest_heartbeat("dev-alice") is not None


def test_device_config_requires_the_device_key(client, tenants):
    assert client.get("/api/devices/config/dev-alice").status_code in (401, 422)
    r = client.get("/api/devices/config/dev-alice",
                   headers={"X-Device-Id": "dev-bob", "X-Api-Key": BOB_KEY})
    assert r.status_code == 404
    r = client.get("/api/devices/config/dev-alice",
                   headers={"X-Device-Id": "dev-alice", "X-Api-Key": ALICE_KEY})
    assert r.status_code == 200


# Routes that must answer without credentials. Everything else must refuse.
PUBLIC_ROUTES = {
    "/", "/api/health", "/api/auth/login", "/api/auth/register",
    "/api/devices/register", "/static/installer_linux.sh", "/agent/linux_agent.py",
    "/agent/{name}",  # serves only the allow-listed extra agent files, tested below
    "/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json",
}


def _http_routes(app):
    """(path, methods, param names) for every HTTP route, including routers
    mounted with include_router. Newer FastAPI keeps included routers as one
    lazy entry in app.routes, so those are expanded through their contexts."""
    from fastapi.routing import APIRoute

    for route in app.routes:
        contexts = getattr(route, "effective_route_contexts", None)
        if callable(contexts):
            for ctx in contexts():
                if getattr(ctx, "methods", None):
                    yield ctx.path, set(ctx.methods), list(ctx.param_convertors)
        elif isinstance(route, APIRoute):
            yield route.path, set(route.methods), list(route.param_convertors)


def test_every_non_public_route_refuses_anonymous_requests(client):
    from server import app

    checked = 0
    for route_path, methods, params in _http_routes(app):
        if route_path in PUBLIC_ROUTES:
            continue
        path = route_path
        for name in params:
            path = path.replace("{" + name + "}", "1")
        for method in sorted(methods - {"HEAD", "OPTIONS"}):
            r = client.request(method, path, json={})
            assert r.status_code in (401, 403, 422), (
                f"{method} {route_path} answered {r.status_code} without credentials"
            )
            checked += 1
    assert checked >= 25, f"only {checked} routes checked; did the app fail to load its routers?"


# ── G-4: install files and command ──────────────────────────────────────


@pytest.mark.parametrize("path", [
    "/static/device_registration.py", "/static/token_manager.py", "/static/__init__.py",
    "/agent/__init__.py", "/agent/windows_agent_design.md",
])
def test_source_folders_are_not_served(client, path):
    assert client.get(path).status_code == 404


def test_install_files_are_served_with_matching_hashes(client):
    import hashlib

    from lsadra.onboarding.agent_files import install_hashes

    hashes = install_hashes()
    inst = client.get("/static/installer_linux.sh")
    agent = client.get("/agent/linux_agent.py")
    assert inst.status_code == agent.status_code == 200
    assert hashlib.sha256(inst.content).hexdigest() == hashes["installer_sha256"]
    assert hashlib.sha256(agent.content).hexdigest() == hashes["agent_sha256"]


def test_install_command_verifies_before_running_as_root():
    from lsadra.onboarding.agent_files import install_hashes, linux_install_command

    cmd = linux_install_command("https://203.0.113.5:8000", "tok123")
    hashes = install_hashes()
    assert "| sudo" not in cmd and "| bash" not in cmd
    assert cmd.index("sha256sum -c") < cmd.index("sudo bash")
    assert hashes["installer_sha256"] in cmd
    assert f"--agent-sha256 {hashes['agent_sha256']}" in cmd
    assert "--allow-insecure-http" not in cmd
    assert "--allow-insecure-http" in linux_install_command("http://192.0.2.5:8000", "tok123")


def _run_installer(*args):
    return subprocess.run(
        ["bash", str(_REPO_ROOT / "lsadra" / "onboarding" / "installer_linux.sh"), *args],
        capture_output=True, text=True,
    )


@pytest.mark.skipif(sys.platform == "win32" or shutil.which("bash") is None,
                    reason="installer is a Linux shell script")
def test_installer_refuses_without_agent_hash_or_over_plain_http():
    r = _run_installer("--token", "tok123", "--server", "https://203.0.113.5:8000")
    assert r.returncode != 0 and "--agent-sha256" in r.stdout

    r = _run_installer("--token", "tok123", "--server", "http://192.0.2.5:8000",
                       "--agent-sha256", "0" * 64)
    assert r.returncode != 0 and "plain HTTP" in r.stdout


def test_extra_agent_files_are_served_only_from_the_allow_list(client, tmp_path, monkeypatch):
    """Optional agent files (e.g. posture checks) are served and pinned by hash;
    any other name, including traversal attempts, is refused."""
    import hashlib

    import server
    from lsadra.onboarding import agent_files

    extra = tmp_path / "posture.py"
    extra.write_text("# synthetic posture module\n", encoding="utf-8")
    monkeypatch.setattr(server, "agent_extra_files", lambda: {"posture.py": extra})
    monkeypatch.setattr(agent_files, "agent_extra_files", lambda: {"posture.py": extra})

    r = client.get("/agent/posture.py")
    assert r.status_code == 200
    sha = hashlib.sha256(r.content).hexdigest()
    cmd = agent_files.linux_install_command("https://203.0.113.5:8000", "tok123")
    assert f"--file posture.py={sha}" in cmd

    for name in ("config.py", "..%2Fconfig.py", "%2e%2e%2fserver.py", "__init__.py"):
        assert client.get(f"/agent/{name}").status_code == 404, name

