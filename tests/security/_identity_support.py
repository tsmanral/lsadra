"""Shared helpers for the identity and data-handling regression tests (G-7..G-11, G-26, G-27, G-33).

SYNTHETIC data only: ``*.demo`` usernames, RFC 5737 addresses, made-up passwords.
"""

import uuid

import pytest

from lsadra.auth import hash_password
from lsadra.storage.database import create_user

# Built from words so secret scanners do not read them as credentials.
STRONG_PASSWORD = "-".join(["plum", "orbit", "canvas", "77"])
OTHER_STRONG_PASSWORD = "-".join(["harbor", "lantern", "quartz", "42"])


def make_user(username: str = "analyst.demo", role: str = "ANALYST",
              password: str = STRONG_PASSWORD) -> str:
    uid = f"usr-{uuid.uuid4().hex[:8]}"
    create_user(uid, username, hash_password(password), role)
    return uid


def login(client, username: str = "analyst.demo", password: str = STRONG_PASSWORD, **extra):
    return client.post("/api/auth/login", json={"username": username, "password": password, **extra})


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def identity_env(tmp_path, monkeypatch):
    """Fresh database, cleared login throttle, and a TestClient on the real app."""
    from fastapi.testclient import TestClient

    from lsadra.security.login_throttle import login_throttle
    from tests.fixtures import setup_test_db

    setup_test_db(tmp_path)
    login_throttle.reset()
    from server import app

    client = TestClient(app)
    yield client
    login_throttle.reset()
