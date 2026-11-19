"""
§6 #12 — IDOR on /api/dashboard/export PDF report.

Attacker story: any authenticated non-admin (ANALYST/VIEWER) could hit
GET /api/dashboard/export and receive a PDF built from ALL users'
KPIs / open incidents / recent anomalies, because the endpoint called the
data-layer functions with no user_id scoping.

Secure behavior pinned here: a non-admin caller must have their own user_id
propagated to every report data source (user-scoped report); an ADMIN caller
must propagate user_id=None (sees everything). Asserted at the data/query
layer by patching the three data-layer calls and inspecting the user_id kwarg.
Reverting the fix (uid always None) makes the non-admin assertions fail.
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


def _make_token(user_id: str, username: str, role: str) -> str:
    """Create a real user row + signed bearer token for the given role."""
    from lsadra.auth import create_access_token, hash_password
    from lsadra.storage.database import create_user

    # Synthetic credentials only.
    create_user(user_id, username, hash_password("test-secret-abc123"), role)
    return create_access_token(user_id, username, role)


class TestExportIdorScoping:
    """GET /api/dashboard/export must scope report data to the caller."""

    def _patched_export(self, client, token):
        """
        Call the export endpoint with the three data-layer functions and the
        report generator patched. Returns (response, kpis_mock, incidents_mock,
        anomalies_mock) so callers can inspect how each was invoked.
        """
        with patch("lsadra.api.dashboard.get_dashboard_kpis",
                   return_value={}) as kpis_mock, \
             patch("lsadra.api.dashboard.get_dashboard_open_incidents",
                   return_value=[]) as incidents_mock, \
             patch("lsadra.api.dashboard.get_dashboard_recent_anomalies",
                   return_value=[]) as anomalies_mock, \
             patch("lsadra.api.dashboard.generate_report",
                   return_value=b"%PDF-1.4 test") as report_mock:
            response = client.get(
                "/api/dashboard/export",
                headers={"Authorization": f"Bearer {token}"},
            )
            report_mock.assert_called_once()
        return response, kpis_mock, incidents_mock, anomalies_mock

    def test_non_admin_export_is_scoped_to_caller(self, client):
        """A non-admin's report must query only their own user_id."""
        token = _make_token("analyst-1", "analyst", "ANALYST")

        response, kpis_mock, incidents_mock, anomalies_mock = \
            self._patched_export(client, token)

        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"

        # SECURE: every data source scoped to the caller's own user_id.
        assert kpis_mock.call_args.kwargs["user_id"] == "analyst-1"
        assert incidents_mock.call_args.kwargs["user_id"] == "analyst-1"
        assert anomalies_mock.call_args.kwargs["user_id"] == "analyst-1"
        # Anomalies still bounded to the dashboard limit.
        assert anomalies_mock.call_args.kwargs["limit"] == 50

    def test_viewer_export_is_scoped_to_caller(self, client):
        """VIEWER is also non-admin and must be scoped identically."""
        token = _make_token("viewer-1", "viewer", "VIEWER")

        response, kpis_mock, incidents_mock, anomalies_mock = \
            self._patched_export(client, token)

        assert response.status_code == 200
        assert kpis_mock.call_args.kwargs["user_id"] == "viewer-1"
        assert incidents_mock.call_args.kwargs["user_id"] == "viewer-1"
        assert anomalies_mock.call_args.kwargs["user_id"] == "viewer-1"

    def test_admin_export_sees_all(self, client):
        """An ADMIN caller must propagate user_id=None (unscoped, sees all)."""
        token = _make_token("admin-1", "admin", "ADMIN")

        response, kpis_mock, incidents_mock, anomalies_mock = \
            self._patched_export(client, token)

        assert response.status_code == 200
        assert kpis_mock.call_args.kwargs["user_id"] is None
        assert incidents_mock.call_args.kwargs["user_id"] is None
        assert anomalies_mock.call_args.kwargs["user_id"] is None

    def test_export_requires_auth(self, client):
        """No token -> 401 (endpoint is guarded)."""
        response = client.get("/api/dashboard/export")
        assert response.status_code == 401
