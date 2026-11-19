"""
/api/risk (audit G-29): scores, timelines, cases and asset weights, scoped so a
non-admin sees only entities whose signals came from their own devices.
"""

import pytest
from fastapi.testclient import TestClient

from tests.fixtures import setup_test_db

ALICE, BOB = "user-alice-demo", "user-bob-demo"


@pytest.fixture
def client(tmp_path):
    setup_test_db(tmp_path)
    from server import app

    return TestClient(app)


def _token(user_id, username, role):
    from lsadra.auth import create_access_token, hash_password
    from lsadra.storage.database import create_user

    create_user(user_id, username, hash_password("synthetic-pass-123"), role)  # synthetic
    return {"Authorization": f"Bearer {create_access_token(user_id, username, role)}"}


def _seed():
    from lsadra.storage.database import create_risk_notable, insert_risk_events

    def sig(entity, owner, t, rule, tactic, level="high", points=24.0):
        return {"entity_type": "host", "entity": entity, "device_id": f"dev-{entity}",
                "user_id": owner, "event_id": int(t[11:13]), "source": "rule", "rule_id": rule,
                "title": rule, "level": level, "technique_id": "T1110.001",
                "tactics": [tactic], "base_score": points, "event_time": t}

    insert_risk_events([
        sig("alice-host", ALICE, "2026-01-15T01:00:00+00:00", "a", "Credential Access"),
        sig("alice-host", ALICE, "2026-01-15T02:00:00+00:00", "b", "Persistence"),
        sig("bob-host", BOB, "2026-01-15T03:00:00+00:00", "c", "Collection", "low", 4.0),
    ])
    return {
        "alice": create_risk_notable("host", "alice-host", "dev-alice-host", ALICE, 75.0,
                                     ["Credential Access", "Persistence"], 2, "shadow",
                                     "2026-01-15T01:00:00+00:00", "2026-01-15T02:00:00+00:00"),
        "bob": create_risk_notable("host", "bob-host", "dev-bob-host", BOB, 71.0,
                                   ["Collection"], 1, "shadow",
                                   "2026-01-15T03:00:00+00:00", "2026-01-15T03:00:00+00:00"),
    }


def test_requires_authentication(client):
    assert client.get("/api/risk/entities").status_code == 401
    assert client.get("/api/risk/cases").status_code == 401


def test_admin_sees_every_entity_highest_score_first(client):
    _seed()
    admin = _token("user-admin-demo", "admin.demo", "ADMIN")
    body = client.get("/api/risk/entities", headers=admin).json()
    assert body["mode"] == "shadow" and body["threshold"] == 70
    assert [e["entity"] for e in body["entities"]] == ["alice-host", "bob-host"]
    assert body["entities"][0]["tactics"] == ["Credential Access", "Persistence"]


def test_non_admin_sees_only_their_own_entities_and_cases(client):
    cases = _seed()
    alice = _token(ALICE, "alice.demo", "ANALYST")
    body = client.get("/api/risk/entities", headers=alice).json()
    assert [e["entity"] for e in body["entities"]] == ["alice-host"]
    assert [c["id"] for c in client.get("/api/risk/cases", headers=alice).json()] == [cases["alice"]]
    r = client.get("/api/risk/timeline", params={"entity_type": "host", "entity": "bob-host"},
                   headers=alice)
    assert r.status_code == 404
    r = client.patch(f"/api/risk/cases/{cases['bob']}", json={"status": "CLOSED"}, headers=alice)
    assert r.status_code == 404


def test_timeline_lists_the_signals_and_the_open_case(client):
    cases = _seed()
    alice = _token(ALICE, "alice.demo", "VIEWER")
    body = client.get("/api/risk/timeline", params={"entity_type": "host", "entity": "alice-host"},
                      headers=alice).json()
    assert [e["rule_id"] for e in body["timeline"]] == ["a", "b"]
    assert body["open_case"]["id"] == cases["alice"]
    assert body["tactics"] == ["Credential Access", "Persistence"]
    r = client.get("/api/risk/timeline", params={"entity_type": "router", "entity": "x"},
                   headers=alice)
    assert r.status_code == 422


def test_analyst_closes_own_case_viewer_cannot(client):
    cases = _seed()
    viewer = _token("user-viewer-demo", "viewer.demo", "VIEWER")
    assert client.patch(f"/api/risk/cases/{cases['alice']}", json={"status": "CLOSED"},
                        headers=viewer).status_code == 403
    alice = _token(ALICE, "alice.demo", "ANALYST")
    r = client.patch(f"/api/risk/cases/{cases['alice']}", json={"status": "CLOSED"}, headers=alice)
    assert r.status_code == 200
    assert client.get("/api/risk/cases", params={"status": "OPEN"}, headers=alice).json() == []


def test_only_admin_sets_asset_weights_within_range(client):
    from lsadra.storage.database import get_asset_weight

    _seed()
    alice = _token(ALICE, "alice.demo", "ANALYST")
    admin = _token("user-admin-demo", "admin.demo", "ADMIN")
    payload = {"entity_type": "host", "entity": "alice-host", "weight": 3, "note": "file server"}
    assert client.put("/api/risk/asset-weights", json=payload, headers=alice).status_code == 403
    assert client.put("/api/risk/asset-weights", json=payload, headers=admin).status_code == 200
    assert get_asset_weight("host", "alice-host") == 3.0
    for bad in (0, -1, 6):
        r = client.put("/api/risk/asset-weights", json=dict(payload, weight=bad), headers=admin)
        assert r.status_code == 422
    before = client.get("/api/risk/entities", headers=admin).json()["entities"][0]
    assert before["weight"] == 3.0
