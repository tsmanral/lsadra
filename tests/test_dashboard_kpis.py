"""Dashboard KPI and health endpoints, as a non-admin user would call them.

Regression for the Command Center failing for every non-admin user: the
user-scoped incident counts joined ``devices`` and used unqualified ``status``
and ``severity_label`` columns, which SQLite rejects as ambiguous because
``devices`` has a ``status`` column too. ``/api/dashboard/health`` reused the
same query, and returned hardcoded throughput numbers on top of that.
"""

from datetime import datetime, timedelta

import pytest

from tests.fixtures import setup_test_db

ANALYST_ID = "user-analyst-1"
OTHER_ID = "user-other-1"
DEVICE_ID = "device-analyst-1"
OTHER_DEVICE_ID = "device-other-1"


@pytest.fixture(autouse=True)
def _test_db(tmp_path):
    setup_test_db(tmp_path)
    from lsadra.api.data_layer import get_dashboard_kpis

    # Streamlit's cache would otherwise carry results across tests and databases.
    get_dashboard_kpis.clear()
    yield
    get_dashboard_kpis.clear()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from server import app

    return TestClient(app)


def _seed():
    from lsadra.storage.database import (
        create_device,
        create_incident,
        create_user,
        insert_events_batch,
        update_incident_status,
    )

    create_user(ANALYST_ID, "analyst.demo", "x", "ANALYST")
    create_user(OTHER_ID, "other.demo", "x", "ANALYST")
    create_user("admin-1", "admin.demo", "x", "ADMIN")  # sessions need a stored user (G-9)
    create_device(DEVICE_ID, ANALYST_ID, "demo-host-01", "linux", "x")
    create_device(OTHER_DEVICE_ID, OTHER_ID, "demo-host-02", "linux", "x")

    now = datetime.utcnow().isoformat()
    create_incident(DEVICE_ID, "192.0.2.10", "brute_force", "CRITICAL", now)
    create_incident(DEVICE_ID, "192.0.2.11", "port_scan", "MEDIUM", now)
    closed = create_incident(DEVICE_ID, "192.0.2.12", "port_scan", "LOW", now)
    update_incident_status(closed, "RESOLVED")
    # Another user's incident must never be counted for the analyst.
    create_incident(OTHER_DEVICE_ID, "198.51.100.5", "brute_force", "CRITICAL", now)

    def ev(device, user, ts):
        return {
            "timestamp": ts,
            "device_id": device,
            "user_id": user,
            "host": "demo-host",
            "effective_username": "svc.demo",
            "source_ip": "192.0.2.10",
            "event_type": "auth_failure",
            "raw_message": "synthetic event",
            "attributes": {},
        }

    recent = (datetime.utcnow() - timedelta(seconds=5)).isoformat()
    old = (datetime.utcnow() - timedelta(hours=2)).isoformat()
    insert_events_batch(
        [ev(DEVICE_ID, ANALYST_ID, recent) for _ in range(30)]
        + [ev(DEVICE_ID, ANALYST_ID, old) for _ in range(10)]
        + [ev(OTHER_DEVICE_ID, OTHER_ID, recent) for _ in range(60)]
    )


def _auth(user_id, username, role):
    from lsadra.auth import create_access_token

    return {"Authorization": f"Bearer {create_access_token(user_id, username, role)}"}


def test_kpis_for_non_admin_user(client):
    _seed()
    r = client.get("/api/dashboard/kpis", headers=_auth(ANALYST_ID, "analyst.demo", "ANALYST"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["open_incidents"] == 2
    assert body["critical_incidents"] == 1
    assert body["closed_incidents"] == 1
    assert body["total_devices"] == 1
    assert body["total_events_24h"] == 40


def test_kpis_for_admin_see_everything(client):
    _seed()
    r = client.get("/api/dashboard/kpis", headers=_auth("admin-1", "admin.demo", "ADMIN"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["open_incidents"] == 3
    assert body["critical_incidents"] == 2
    assert body["total_devices"] == 2


def test_health_for_non_admin_reports_measured_rate(client):
    _seed()
    r = client.get("/api/dashboard/health", headers=_auth(ANALYST_ID, "analyst.demo", "ANALYST"))
    assert r.status_code == 200, r.text
    body = r.json()
    # 30 of the analyst's events fall in the last 60 s; the other user's don't count.
    assert body["events_per_second"] == pytest.approx(30 / 60, abs=0.01)
    # Not measured yet: reported as unknown, never as a made-up number.
    assert body["avg_latency_ms"] is None
    assert body["drop_rate_pct"] is None


def test_health_with_no_events_reports_zero(client):
    from lsadra.storage.database import create_device, create_user

    create_user(ANALYST_ID, "analyst.demo", "x", "ANALYST")
    create_device(DEVICE_ID, ANALYST_ID, "demo-host-01", "linux", "x")
    r = client.get("/api/dashboard/health", headers=_auth(ANALYST_ID, "analyst.demo", "ANALYST"))
    assert r.status_code == 200, r.text
    assert r.json()["events_per_second"] == 0
