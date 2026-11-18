"""Admin role is never granted by self-registration; operators create admins.

Regression: /api/auth/register used to make any account whose username was
"admin" (any case) an ADMIN, so on a fresh install whoever registered that name
first got full control. Admins are now created with ``python -m lsadra.admin_cli``.
"""

import pytest

from tests.fixtures import setup_test_db


@pytest.fixture(autouse=True)
def _db(tmp_path):
    setup_test_db(tmp_path)


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from server import app

    return TestClient(app)


@pytest.mark.parametrize("name", ["admin", "Admin", "ADMIN"])
def test_registering_admin_username_does_not_grant_admin(client, name):
    r = client.post("/api/auth/register", json={"username": name, "password": "synthetic-pass-123"})
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "ANALYST"

    from lsadra.storage.database import get_user_by_username

    assert get_user_by_username(name)["role"] == "ANALYST"


def test_cli_creates_first_admin_who_can_log_in(client):
    from lsadra.admin_cli import create_admin

    create_admin("ops.demo", "synthetic-pass-123")
    r = client.post("/api/auth/login", json={"username": "ops.demo", "password": "synthetic-pass-123"})
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "ADMIN"


def test_cli_rejects_short_password_and_duplicates():
    from lsadra.admin_cli import create_admin

    with pytest.raises(ValueError):
        create_admin("ops.demo", "short")
    create_admin("ops.demo", "synthetic-pass-123")
    with pytest.raises(ValueError):
        create_admin("ops.demo", "synthetic-pass-456")


def test_cli_promotes_existing_user(client):
    client.post("/api/auth/register", json={"username": "analyst.demo", "password": "synthetic-pass-123"})
    from lsadra.admin_cli import main
    from lsadra.storage.database import get_user_by_username

    assert main(["promote", "--username", "analyst.demo"]) == 0
    assert get_user_by_username("analyst.demo")["role"] == "ADMIN"
    assert main(["promote", "--username", "nobody.demo"]) == 1


def test_cli_without_server_settings_prints_hint_not_traceback(tmp_path):
    """Without LSADRA_JWT_SECRET or dev mode the settings module refuses to load;
    the CLI must explain that in one line and exit non-zero."""
    import os
    import subprocess
    import sys
    from pathlib import Path

    env = {k: v for k, v in os.environ.items()
           if k not in ("LSADRA_DEV_MODE", "LSADRA_JWT_SECRET")}
    root = Path(__file__).resolve().parents[2]
    r = subprocess.run(
        [sys.executable, "-m", "lsadra.admin_cli", "promote", "--username", "x.demo"],
        cwd=root, env=env, capture_output=True, text=True, timeout=60,
    )
    assert r.returncode == 2
    assert "LSADRA_JWT_SECRET" in r.stderr and "LSADRA_DEV_MODE" in r.stderr
    assert "Traceback" not in r.stderr
