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
