"""Investigation endpoints never show one user's data to another.

``/api/incidents/{id}``, ``/api/entity`` and ``/api/feedback`` are new, so this
pins their scoping from the start: a non-admin sees only data from devices it
owns, and something that belongs to someone else answers exactly like
something that does not exist (404), so ids cannot be probed. Also pins that
playbook commands are never filled in with log-derived text.

All data is synthetic (``*.demo`` users, RFC 5737 addresses).
"""

from datetime import datetime, timezone

import pytest

from tests.fixtures import setup_test_db

OWNER, INTRUDER = "user-owner-1", "user-intruder-1"
DEVICE = "device-owner-1"
INTRUDER_DEVICE = "device-intruder-1"
SRC = "203.0.113.66"
# A user name crafted to break out of a shell command if it were interpolated.
EVIL_USER = 'x"; rm -rf ~ #'


@pytest.fixture(autouse=True)
def _test_db(tmp_path):
    setup_test_db(tmp_path)


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from server import app

    return TestClient(app)


def _headers(uid, name):
    from lsadra.auth import create_access_token
    from lsadra.storage.database import create_user

    create_user(uid, name, "x", "ANALYST")
    return {"Authorization": f"Bearer {create_access_token(uid, name, 'ANALYST')}"}


@pytest.fixture
def world():
    from lsadra.storage.database import create_device, create_incident, insert_anomaly, insert_event

    owner, intruder = _headers(OWNER, "owner.demo"), _headers(INTRUDER, "intruder.demo")
    create_device(DEVICE, OWNER, "secret-host.demo", "linux", "x")
    create_device(INTRUDER_DEVICE, INTRUDER, "intruder-host.demo", "linux", "x")
    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    inc = create_incident(DEVICE, SRC, "Unauthorized Privilege Escalation", "CRITICAL", now, "AD_ELEVATION_RESPONSE")
    ev = insert_event({
        "timestamp": now, "device_id": DEVICE, "user_id": OWNER, "host": "secret-host.demo",
        "effective_username": EVIL_USER, "source_ip": SRC, "event_type": "priv_esc",
        "raw_message": "synthetic secret line", "attributes": {},
    })
    alert = insert_anomaly({
        "event_id": ev, "device_id": DEVICE, "user_id": OWNER, "source_ip": SRC,
        "severity_score": 0.95, "severity_label": "CRITICAL", "is_anomaly": True,
        "threat_type": "Privilege Escalation", "incident_id": inc,
    })
    return {"owner": owner, "intruder": intruder, "inc": inc, "alert": alert}


def test_other_users_incident_is_indistinguishable_from_missing(client, world):
    theirs = client.get(f"/api/incidents/{world['inc']}", headers=world["intruder"])
    missing = client.get("/api/incidents/987654", headers=world["intruder"])
    assert theirs.status_code == missing.status_code == 404
    assert theirs.json() == missing.json()


@pytest.mark.parametrize("q", [SRC, "secret-host.demo", DEVICE, EVIL_USER, "inc_{inc}"])
def test_entity_lookup_does_not_leak_other_users_data(client, world, q):
    q = q.format(inc=world["inc"])
    r = client.get("/api/entity", params={"q": q}, headers=world["intruder"])
    assert r.status_code == 404
    assert "secret" not in r.text


def test_feedback_cannot_label_or_read_other_users_alerts(client, world):
    r = client.post("/api/feedback", json={"alert_id": world["alert"], "label": "false_positive"},
                    headers=world["intruder"])
    assert r.status_code == 404

    ok = client.post("/api/feedback", json={"alert_id": world["alert"], "label": "true_positive", "note": "mine"},
                     headers=world["owner"])
    assert ok.status_code == 201
    assert client.get("/api/feedback", headers=world["intruder"]).json()["total"] == 0
    assert client.get("/api/feedback", headers=world["owner"]).json()["total"] == 1


def test_playbook_commands_never_contain_log_values(client, world):
    body = client.get(f"/api/incidents/{world['inc']}", headers=world["owner"]).json()
    assert EVIL_USER in body["entities"]["users"]  # shown as data...
    commands = [s["command"] for s in body["playbook"]["steps"] if s["command"]]
    assert commands, "expected at least one suggested command"
    for cmd in commands:  # ...but never spliced into a command
        assert EVIL_USER not in cmd
        assert SRC not in cmd
        assert "secret-host.demo" not in cmd
    assert any("<USERNAME>" in c for c in commands)
