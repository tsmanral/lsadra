"""
LSADRA V3 — API endpoint tests.

Tests for FastAPI endpoints including health, auth, heartbeat,
incident management, and admin retrain.
"""

import pytest
from unittest.mock import patch, MagicMock

from tests.fixtures import setup_test_db


@pytest.fixture(autouse=True)
def _test_db(tmp_path):
    """Set up a temporary test database for each test."""
    setup_test_db(tmp_path)


@pytest.fixture
def client():
    """Create a FastAPI test client."""
    from fastapi.testclient import TestClient
    from server import app
    return TestClient(app)


class TestHealthEndpoints:
    """Tests for health check endpoints."""

    def test_root_health(self, client):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "online"
        assert data["service"] == "LSADRA V3 Core"

    def test_api_health(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["service"] == "lsadra-api"
        from lsadra import __version__
        assert response.json()["version"] == __version__


class TestAuthEndpoints:
    """Tests for authentication endpoints."""

    def test_login_no_user(self, client):
        response = client.post("/api/auth/login", json={
            "username": "nonexistent",
            "password": "test",
        })
        assert response.status_code == 401

    def test_login_success(self, client):
        # Create a user first
        from lsadra.auth import hash_password
        from lsadra.storage.database import create_user

        create_user("test-id", "testuser", hash_password("testpass"), "ANALYST")

        response = client.post("/api/auth/login", json={
            "username": "testuser",
            "password": "testpass",
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["role"] == "ANALYST"


class TestHeartbeatEndpoint:
    """Tests for the heartbeat endpoint."""

    def test_heartbeat_unknown_device(self, client):
        response = client.post("/heartbeat", json={
            "device_id": "nonexistent",
        })
        assert response.status_code == 404

    def test_heartbeat_success(self, client):
        # Create user and device
        from lsadra.storage.database import create_user, create_device

        create_user("user-1", "testuser", "hash", "ANALYST")
        create_device("device-1", "user-1", "test-host", "linux", "apikey")

        response = client.post("/heartbeat", json={
            "device_id": "device-1",
            "cpu_pct": 45.2,
            "mem_pct": 67.8,
            "agent_version": "3.0.0",
        })
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


class TestIncidentEndpoints:
    """Tests for incident management endpoints."""

    def test_incident_status_no_auth(self, client):
        response = client.post("/api/incidents/1/status", json={
            "status": "RESOLVED",
        })
        assert response.status_code == 401

    def test_admin_retrain_no_auth(self, client):
        response = client.post("/admin/retrain")
        assert response.status_code == 401

    def test_admin_retrain_analyst_forbidden(self, client):
        # Create analyst user and get token
        from lsadra.auth import create_access_token, hash_password
        from lsadra.storage.database import create_user

        create_user("analyst-1", "analyst", hash_password("pass"), "ANALYST")
        token = create_access_token("analyst-1", "analyst", "ANALYST")

        response = client.post(
            "/admin/retrain",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403

    def test_admin_retrain_admin_accepted(self, client):
        from lsadra.auth import create_access_token, hash_password
        from lsadra.storage.database import create_user

        create_user("admin-1", "admin", hash_password("pass"), "ADMIN")
        token = create_access_token("admin-1", "admin", "ADMIN")

        response = client.post(
            "/admin/retrain",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "accepted"
