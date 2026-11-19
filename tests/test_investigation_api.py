"""Investigation API behind the incident drill-down, Investigate, Response and
Feedback pages (``lsadra/ui/api_investigation.py``).

Seeds two analysts with one device each. Everything is synthetic: ``*.demo``
users, RFC 5737 addresses.
"""

from datetime import datetime, timezone

import pytest

from tests.fixtures import setup_test_db

ANALYST_ID = "user-analyst-1"
OTHER_ID = "user-other-1"
ADMIN_ID = "user-admin-1"
VIEWER_ID = "user-viewer-1"
DEVICE_ID = "device-analyst-1"
OTHER_DEVICE_ID = "device-other-1"
ATTACKER = "203.0.113.7"
OTHER_ATTACKER = "198.51.100.5"


@pytest.fixture(autouse=True)
def _test_db(tmp_path):
    setup_test_db(tmp_path)


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from server import app

    return TestClient(app)


def _token(user_id, username, role):
    from lsadra.auth import create_access_token
    from lsadra.storage.database import create_user

    create_user(user_id, username, "x", role)
    return {"Authorization": f"Bearer {create_access_token(user_id, username, role)}"}


@pytest.fixture
def seeded():
    """Two analysts, one incident each, three alerts on the analyst's incident."""
    from lsadra.storage.database import (
        create_device,
        create_incident,
        insert_anomaly,
        insert_event,
    )

    headers = {
        "analyst": _token(ANALYST_ID, "analyst.demo", "ANALYST"),
        "other": _token(OTHER_ID, "other.demo", "ANALYST"),
        "admin": _token(ADMIN_ID, "admin.demo", "ADMIN"),
        "viewer": _token(VIEWER_ID, "viewer.demo", "VIEWER"),
    }
    create_device(DEVICE_ID, ANALYST_ID, "web-01.demo", "linux", "x")
    create_device(OTHER_DEVICE_ID, OTHER_ID, "db-01.demo", "linux", "x")

    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    inc = create_incident(DEVICE_ID, ATTACKER, "SSH Brute Force", "HIGH", now, "BRUTE_FORCE_RESPONSE")
    other_inc = create_incident(OTHER_DEVICE_ID, OTHER_ATTACKER, "Port Scan", "LOW", now)

    alert_ids = []
    for i in range(3):
        ev = insert_event({
            "timestamp": now, "device_id": DEVICE_ID, "user_id": ANALYST_ID,
            "host": "web-01.demo", "effective_username": "svc.demo",
            "source_ip": ATTACKER, "event_type": "auth_failure",
            "raw_message": f"Failed password for svc.demo from {ATTACKER} port 22 ssh2 #{i}",
            "attributes": {"source_type": "ssh"},
        })
        alert_ids.append(insert_anomaly({
            "event_id": ev, "device_id": DEVICE_ID, "user_id": ANALYST_ID,
            "source_ip": ATTACKER, "severity_score": 0.5 + i * 0.2, "severity_label": "HIGH",
            "is_anomaly": True, "threat_type": "SSH Brute Force", "attack_type": "SSH Brute Force",
            "mitre_technique": "T1110", "narrative": f"**[HIGH]** **SSH Brute Force** from **{ATTACKER}**.",
            "incident_id": inc,
        }))
    other_ev = insert_event({
        "timestamp": now, "device_id": OTHER_DEVICE_ID, "user_id": OTHER_ID,
        "host": "db-01.demo", "effective_username": "dba.demo", "source_ip": OTHER_ATTACKER,
        "event_type": "conn", "raw_message": "synthetic", "attributes": {},
    })
    other_alert = insert_anomaly({
        "event_id": other_ev, "device_id": OTHER_DEVICE_ID, "user_id": OTHER_ID,
        "source_ip": OTHER_ATTACKER, "severity_score": 0.2, "severity_label": "LOW",
        "is_anomaly": True, "threat_type": "Port Scan", "incident_id": other_inc,
    })
    return {"headers": headers, "inc": inc, "other_inc": other_inc,
            "alerts": alert_ids, "other_alert": other_alert}


# ── Incident drill-down ──────────────────────────────────────────────────


def test_incident_detail_returns_alerts_entities_and_playbook(client, seeded):
    r = client.get(f"/api/incidents/{seeded['inc']}", headers=seeded["headers"]["analyst"])
    assert r.status_code == 200
    body = r.json()
    assert body["incident"]["attack_type"] == "SSH Brute Force"
    assert body["incident"]["device_hostname"] == "web-01.demo"
    assert body["alert_total"] == 3
    assert [a["id"] for a in body["alerts"]] == seeded["alerts"]  # oldest first
    assert body["alerts"][0]["raw_message"].startswith("Failed password")
    assert body["alerts"][0]["narrative"].startswith("**[HIGH]**")
    assert body["risk_score"] == 90  # max severity 0.9
    assert body["entities"]["source_ips"] == [ATTACKER]
    assert body["entities"]["users"] == ["svc.demo"]
    assert body["entities"]["mitre_techniques"] == ["T1110"]
    assert body["playbook"]["name"] == "BRUTE_FORCE_RESPONSE"
    assert [s["id"] for s in body["playbook"]["steps"]] == list(range(1, len(body["playbook"]["steps"]) + 1))


def test_incident_without_playbook_gets_general_triage(client, seeded):
    r = client.get(f"/api/incidents/{seeded['other_inc']}", headers=seeded["headers"]["other"])
    assert r.status_code == 200
    assert r.json()["playbook"]["name"] == "GENERIC_TRIAGE"


def test_admin_sees_any_incident(client, seeded):
    r = client.get(f"/api/incidents/{seeded['other_inc']}", headers=seeded["headers"]["admin"])
    assert r.status_code == 200


def test_unknown_incident_is_404(client, seeded):
    assert client.get("/api/incidents/999999", headers=seeded["headers"]["admin"]).status_code == 404


def test_incident_list_route_still_works(client, seeded):
    r = client.get("/api/incidents", headers=seeded["headers"]["analyst"])
    assert r.status_code == 200
    assert [i["id"] for i in r.json()["incidents"]] == [seeded["inc"]]


# ── Entity lookup ────────────────────────────────────────────────────────


def test_entity_lookup_by_ip(client, seeded):
    r = client.get("/api/entity", params={"q": ATTACKER}, headers=seeded["headers"]["analyst"])
    assert r.status_code == 200
    body = r.json()
    assert body["type"] == "IP"
    assert body["alert_count"] == 3
    assert body["event_count"] == 3
    assert body["risk_score"] == 90
    assert [i["id"] for i in body["related_incidents"]] == [seeded["inc"]]
    assert "web-01.demo" in body["affected_hosts"]
    assert {"type": "User", "target": "svc.demo"} in body["relationships"]


def test_entity_lookup_by_user_and_host(client, seeded):
    h = seeded["headers"]["analyst"]
    user = client.get("/api/entity", params={"q": "svc.demo"}, headers=h).json()
    assert user["type"] == "User" and user["alert_count"] == 3
    host = client.get("/api/entity", params={"q": "web-01.demo"}, headers=h).json()
    assert host["type"] == "Host" and host["alert_count"] == 3


@pytest.mark.parametrize("fmt", ["inc_{}", "INC-{}", "{}", "#{}"])
def test_entity_lookup_resolves_incident_ids(client, seeded, fmt):
    r = client.get("/api/entity", params={"q": fmt.format(seeded["inc"])},
                   headers=seeded["headers"]["analyst"])
    assert r.status_code == 200
    assert r.json() == {"entity": fmt.format(seeded["inc"]), "type": "Incident", "incident_id": seeded["inc"]}


def test_entity_with_no_activity_is_404_not_made_up(client, seeded):
    r = client.get("/api/entity", params={"q": "192.0.2.250"}, headers=seeded["headers"]["analyst"])
    assert r.status_code == 404


# ── Feedback ─────────────────────────────────────────────────────────────


def test_feedback_round_trip_and_totals(client, seeded):
    h = seeded["headers"]["analyst"]
    a1, a2, _ = seeded["alerts"]
    assert client.post("/api/feedback", json={"alert_id": a1, "label": "true_positive", "note": "confirmed"}, headers=h).status_code == 201
    assert client.post("/api/feedback", json={"alert_id": a2, "label": "false_positive", "note": "scheduled job"}, headers=h).status_code == 201

    body = client.get("/api/feedback", headers=h).json()
    assert body["total"] == 2
    assert body["true_positives"] == 1
    assert body["false_positives"] == 1
    assert body["precision"] == 0.5
    newest = body["items"][0]
    assert newest["alert_id"] == a2
    assert newest["analyst_note"] == "scheduled job"
    assert newest["threat_type"] == "SSH Brute Force"
    assert newest["incident_id"] == seeded["inc"]
    assert newest["source_type"] == "ssh"


def test_feedback_empty_has_no_precision(client, seeded):
    body = client.get("/api/feedback", headers=seeded["headers"]["analyst"]).json()
    assert body == {"items": [], "total": 0, "true_positives": 0, "false_positives": 0, "precision": None}


def test_feedback_rejects_unknown_label(client, seeded):
    r = client.post("/api/feedback", json={"alert_id": seeded["alerts"][0], "label": "needs_review"},
                    headers=seeded["headers"]["analyst"])
    assert r.status_code == 422


def test_feedback_on_missing_alert_is_404(client, seeded):
    r = client.post("/api/feedback", json={"alert_id": 424242, "label": "true_positive"},
                    headers=seeded["headers"]["analyst"])
    assert r.status_code == 404


def test_viewer_cannot_label(client, seeded):
    r = client.post("/api/feedback", json={"alert_id": seeded["alerts"][0], "label": "true_positive"},
                    headers=seeded["headers"]["viewer"])
    assert r.status_code == 403


def test_endpoints_require_login(client, seeded):
    assert client.get(f"/api/incidents/{seeded['inc']}").status_code == 401
    assert client.get("/api/entity", params={"q": ATTACKER}).status_code == 401
    assert client.get("/api/feedback").status_code == 401
