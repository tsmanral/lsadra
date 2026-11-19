"""Contract: entity risk storage (audit G-29).

Covers: insert_risk_events, get_risk_events, get_risk_entities, get_asset_weight,
set_asset_weight, get_open_risk_notable, create_risk_notable, update_risk_notable,
set_risk_notable_status, get_risk_notables, get_risk_notable.
"""

import sqlite3

import pytest

from tests.storage._support import DEVICE_ID, USER_ID


def _sig(entity="demo-host-01", t="2026-01-15T02:00:00+00:00", etype="host", **kw):
    row = {"entity_type": etype, "entity": entity, "device_id": DEVICE_ID, "user_id": USER_ID,
           "event_id": 1, "source": "rule", "rule_id": "lsadra-auth-brute-force",
           "title": "SSH brute force", "level": "high", "technique_id": "T1110.001",
           "tactics": ["Credential Access"], "base_score": 24.0, "event_time": t}
    row.update(kw)
    return row


def test_risk_events_round_trip_in_time_order(db):
    assert db.insert_risk_events([]) == 0
    assert db.insert_risk_events([
        _sig(t="2026-01-15T03:00:00+00:00", rule_id="b"),
        _sig(t="2026-01-15T01:00:00+00:00", rule_id="a"),
        _sig(entity="other-host"),
        _sig(etype="user", entity="bob.demo"),
    ]) == 4
    got = db.get_risk_events("host", "demo-host-01")
    assert [g["rule_id"] for g in got] == ["a", "b"]
    assert got[0]["tactics"] == ["Credential Access"] and got[0]["base_score"] == 24.0
    assert [g["rule_id"] for g in db.get_risk_events(
        "host", "demo-host-01", since="2026-01-15T02:00:00")] == ["b"]
    assert [g["rule_id"] for g in db.get_risk_events("host", "demo-host-01", limit=1)] == ["b"]
    assert len(db.get_risk_events("user", "bob.demo")) == 1


def test_risk_entities_lists_recent_entities_per_owner(db):
    db.insert_risk_events([
        _sig(t="2026-01-15T01:00:00+00:00"),
        _sig(entity="other-host", user_id="someone-else", t="2026-01-15T05:00:00+00:00"),
    ])
    got = db.get_risk_entities()
    assert [g["entity"] for g in got] == ["other-host", "demo-host-01"]
    assert [g["entity"] for g in db.get_risk_entities(user_id=USER_ID)] == ["demo-host-01"]
    assert db.get_risk_entities(since="2026-01-16") == []
    assert len(db.get_risk_entities(limit=1)) == 1


def test_asset_weight_defaults_to_one_and_can_be_replaced(db):
    assert db.get_asset_weight("host", "dc-01") == 1.0
    db.set_asset_weight("host", "dc-01", 3.0, note="domain controller", updated_by="admin")
    assert db.get_asset_weight("host", "dc-01") == 3.0
    db.set_asset_weight("host", "dc-01", 2.5)
    assert db.get_asset_weight("host", "dc-01") == 2.5
    assert db.get_asset_weight("user", "dc-01") == 1.0


@pytest.mark.parametrize("weight", [0, -1, 5.5])
def test_asset_weight_must_be_within_range(db, weight):
    with pytest.raises(sqlite3.IntegrityError):
        db.set_asset_weight("host", "dc-01", weight)


def test_risk_notable_lifecycle(db):
    assert db.get_open_risk_notable("host", "demo-host-01") is None
    nid = db.create_risk_notable("host", "demo-host-01", DEVICE_ID, USER_ID, 72.5,
                                 ["Credential Access"], 3, "shadow",
                                 "2026-01-15T01:00:00+00:00", "2026-01-15T02:00:00+00:00")
    case = db.get_open_risk_notable("host", "demo-host-01")
    assert case["id"] == nid and case["tactics"] == ["Credential Access"] and case["status"] == "OPEN"
    db.update_risk_notable(nid, 88.0, ["Credential Access", "Persistence"], 5,
                           "2026-01-15T04:00:00+00:00")
    case = db.get_risk_notable(nid)
    assert case["score"] == 88.0 and case["tactics"] == ["Credential Access", "Persistence"]
    assert case["signal_count"] == 5 and case["last_seen"] == "2026-01-15T04:00:00+00:00"
    assert db.set_risk_notable_status(nid, "CLOSED") is True
    assert db.get_open_risk_notable("host", "demo-host-01") is None
    assert db.set_risk_notable_status(9999, "CLOSED") is False
    with pytest.raises(ValueError):
        db.set_risk_notable_status(nid, "DELETED")
    assert db.get_risk_notable(9999) is None


def test_risk_notables_listing_filters_and_orders_by_score(db):
    low = db.create_risk_notable("host", "a", DEVICE_ID, USER_ID, 71.0, [], 1, "shadow", "t", "t")
    high = db.create_risk_notable("user", "b", DEVICE_ID, "other", 95.0, [], 1, "alert", "t", "t")
    db.set_risk_notable_status(low, "CLOSED")
    assert [n["id"] for n in db.get_risk_notables()] == [high, low]
    assert [n["id"] for n in db.get_risk_notables(user_id=USER_ID)] == [low]
    assert [n["id"] for n in db.get_risk_notables(status="OPEN")] == [high]
    assert len(db.get_risk_notables(limit=1)) == 1
