"""Contract: anomalies and incidents.

Covers: insert_anomaly, get_anomalies_for_user, get_anomalies_for_device,
get_anomalies_for_incident, get_recent_anomalies, update_anomaly_incident,
create_incident, get_incident, get_open_incident, update_incident_last_seen,
update_incident_status, assign_incident, get_open_incidents, get_all_incidents.
"""

import json
import sqlite3
from datetime import datetime

import pytest

from tests.storage._support import DEVICE_ID, USER_ID, make_event

ANOMALY_KEYS = {
    "id",
    "event_id",
    "device_id",
    "user_id",
    "source_ip",
    "layer1_score",
    "layer2_score",
    "layer2_votes",
    "layer3_score",
    "severity_score",
    "severity_label",
    "is_anomaly",
    "threat_type",
    "attack_type",
    "mitre_technique",
    "mitre_confidence",
    "narrative",
    "shap_values",
    "incident_id",
    "is_synthetic",
    "created_at",
}
INCIDENT_KEYS = {
    "id",
    "device_id",
    "source_ip",
    "attack_type",
    "status",
    "assigned_to",
    "severity_label",
    "anomaly_count",
    "first_seen",
    "last_seen",
    "resolved_at",
    "notes",
    "created_at",
    "playbook",
}
IP = "192.0.2.10"


def _anomaly(**overrides):
    a = {
        "device_id": DEVICE_ID,
        "user_id": USER_ID,
        "source_ip": IP,
        "severity_score": 0.9,
        "severity_label": "HIGH",
        "is_anomaly": True,
        "attack_type": "brute_force",
        "shap_values": {"failed_logins": 0.4},
    }
    a.update(overrides)
    return a


def _incident(db, **overrides):
    args = dict(
        device_id=DEVICE_ID,
        source_ip=IP,
        attack_type="brute_force",
        severity_label="HIGH",
        first_seen="2026-01-01T00:00:00",
    )
    args.update(overrides)
    return db.create_incident(**args)


# ── anomalies ──────────────────────────────────────────────────────────────


def test_insert_anomaly_returns_id_and_round_trips(seeded):
    event_id = seeded.insert_event(make_event())
    aid = seeded.insert_anomaly(_anomaly(event_id=event_id, mitre_technique="T1110"))
    assert isinstance(aid, int) and aid > 0
    [a] = seeded.get_anomalies_for_device(DEVICE_ID)
    assert set(a) == ANOMALY_KEYS
    assert a["id"] == aid and a["event_id"] == event_id
    assert a["mitre_technique"] == "T1110"
    assert json.loads(a["shap_values"]) == {"failed_logins": 0.4}
    assert a["is_anomaly"] == 1 and a["is_synthetic"] == 0
    assert a["incident_id"] is None


def test_insert_anomaly_empty_dict_stores_defaults(db, sql):
    aid = db.insert_anomaly({})
    assert aid > 0
    [row] = sql("SELECT * FROM anomalies WHERE id=?", (aid,))
    assert row["shap_values"] == "{}"
    assert row["is_synthetic"] == 0
    assert row["device_id"] is None and row["is_anomaly"] is None
    assert row["created_at"]


def test_insert_anomaly_unknown_incident_violates_foreign_key(seeded):
    with pytest.raises(sqlite3.IntegrityError):
        seeded.insert_anomaly(_anomaly(incident_id=9999))


def test_get_anomalies_for_user_filters_synthetic(seeded):
    seeded.insert_anomaly(_anomaly())
    seeded.insert_anomaly(_anomaly(is_synthetic=True))
    real = seeded.get_anomalies_for_user(USER_ID)
    assert len(real) == 1 and real[0]["is_synthetic"] == 0
    assert len(seeded.get_anomalies_for_user(USER_ID, synthetic=True)) == 1
    assert seeded.get_anomalies_for_user("nobody") == []


def test_get_anomalies_for_user_orders_newest_first_with_limit(seeded, sql):
    old = seeded.insert_anomaly(_anomaly())
    sql("UPDATE anomalies SET created_at='2000-01-01 00:00:00' WHERE id=?", (old,))
    new = seeded.insert_anomaly(_anomaly())
    assert [a["id"] for a in seeded.get_anomalies_for_user(USER_ID)] == [new, old]
    assert [a["id"] for a in seeded.get_anomalies_for_user(USER_ID, limit=1)] == [new]


def test_get_anomalies_for_device_filters_and_limits(seeded):
    for _ in range(3):
        seeded.insert_anomaly(_anomaly())
    seeded.insert_anomaly(_anomaly(device_id="other-device"))  # anomalies.device_id has no FK
    assert len(seeded.get_anomalies_for_device(DEVICE_ID)) == 3
    assert len(seeded.get_anomalies_for_device(DEVICE_ID, limit=2)) == 2
    assert len(seeded.get_anomalies_for_device("other-device")) == 1


def test_get_recent_anomalies_only_returns_is_anomaly_rows(seeded):
    hit = seeded.insert_anomaly(_anomaly(is_anomaly=True))
    seeded.insert_anomaly(_anomaly(is_anomaly=False))
    recent = seeded.get_recent_anomalies()
    assert [a["id"] for a in recent] == [hit]
    assert set(recent[0]) == ANOMALY_KEYS
    assert seeded.get_recent_anomalies(limit=0) == []


def test_update_anomaly_incident_links_and_join_exposes_event_fields(seeded):
    event_id = seeded.insert_event(make_event(effective_username="svc-x", host="h-x"))
    aid = seeded.insert_anomaly(_anomaly(event_id=event_id))
    unlinked = seeded.insert_anomaly(_anomaly())  # no event → LEFT JOIN nulls
    iid = _incident(seeded)
    assert seeded.update_anomaly_incident(aid, iid) is None
    seeded.update_anomaly_incident(unlinked, iid)
    rows = seeded.get_anomalies_for_incident(iid)
    assert [r["id"] for r in rows] == [aid, unlinked]
    assert set(rows[0]) == ANOMALY_KEYS | {"raw_message", "effective_username", "host"}
    assert (rows[0]["raw_message"], rows[0]["effective_username"], rows[0]["host"]) == (
        "synthetic event",
        "svc-x",
        "h-x",
    )
    assert rows[1]["raw_message"] is None
    assert seeded.get_anomalies_for_incident(9999) == []


# ── incidents ──────────────────────────────────────────────────────────────


def test_create_incident_defaults(seeded):
    iid = _incident(seeded, playbook="contain-host")
    assert isinstance(iid, int) and iid > 0
    inc = seeded.get_incident(iid)
    assert set(inc) == INCIDENT_KEYS
    assert inc["status"] == "OPEN"
    assert inc["anomaly_count"] == 1
    assert inc["first_seen"] == inc["last_seen"] == "2026-01-01T00:00:00"
    assert inc["playbook"] == "contain-host"
    assert inc["assigned_to"] is None and inc["resolved_at"] is None


def test_create_incident_playbook_defaults_to_null(seeded):
    assert seeded.get_incident(_incident(seeded))["playbook"] is None


def test_get_incident_missing_returns_none(db):
    assert db.get_incident(9999) is None


def test_get_open_incident_matches_key_status_and_window(seeded):
    iid = _incident(seeded, first_seen="2026-01-01T12:00:00")
    assert (
        seeded.get_open_incident(DEVICE_ID, IP, "brute_force", "2026-01-01T00:00:00")["id"] == iid
    )
    # outside the window
    assert seeded.get_open_incident(DEVICE_ID, IP, "brute_force", "2026-01-02T00:00:00") is None
    # different grouping key
    assert seeded.get_open_incident(DEVICE_ID, "198.51.100.1", "brute_force", "2026-01-01") is None
    # closed incidents are not "open"
    seeded.update_incident_status(iid, "RESOLVED")
    assert seeded.get_open_incident(DEVICE_ID, IP, "brute_force", "2026-01-01T00:00:00") is None


def test_update_incident_last_seen_bumps_anomaly_count(seeded):
    iid = _incident(seeded)
    assert seeded.update_incident_last_seen(iid, "2026-01-01T01:00:00") is None
    seeded.update_incident_last_seen(iid, "2026-01-01T02:00:00")
    inc = seeded.get_incident(iid)
    assert inc["last_seen"] == "2026-01-01T02:00:00"
    assert inc["anomaly_count"] == 3


@pytest.mark.parametrize("closing_status", ["RESOLVED", "FALSE_POSITIVE"])
def test_update_incident_status_closing_sets_resolved_at(seeded, closing_status):
    iid = _incident(seeded)
    assert seeded.update_incident_status(iid, closing_status, "done") is None
    inc = seeded.get_incident(iid)
    assert inc["status"] == closing_status and inc["notes"] == "done"
    datetime.fromisoformat(inc["resolved_at"])


def test_update_incident_status_reopen_keeps_resolved_at_and_overwrites_notes(seeded):
    iid = _incident(seeded)
    seeded.update_incident_status(iid, "RESOLVED", "first")
    resolved_at = seeded.get_incident(iid)["resolved_at"]
    seeded.update_incident_status(iid, "OPEN")
    inc = seeded.get_incident(iid)
    assert inc["status"] == "OPEN"
    assert inc["resolved_at"] == resolved_at  # COALESCE keeps the old value
    assert inc["notes"] == ""  # notes default "" overwrites


def test_assign_incident_sets_assignee_and_investigating(seeded):
    iid = _incident(seeded)
    assert seeded.assign_incident(iid, USER_ID) is None
    inc = seeded.get_incident(iid)
    assert inc["assigned_to"] == USER_ID and inc["status"] == "INVESTIGATING"


def test_assign_incident_unknown_user_violates_foreign_key(seeded):
    iid = _incident(seeded)
    with pytest.raises(sqlite3.IntegrityError):
        seeded.assign_incident(iid, "ghost")


def test_get_open_incidents_excludes_closed_and_orders_by_last_seen(seeded):
    a = _incident(seeded, first_seen="2026-01-01T00:00:00")
    b = _incident(seeded, first_seen="2026-01-02T00:00:00", attack_type="exfil")
    c = _incident(seeded, first_seen="2026-01-03T00:00:00", attack_type="persistence")
    seeded.assign_incident(a, USER_ID)
    seeded.update_incident_status(c, "RESOLVED")
    open_ = seeded.get_open_incidents()
    assert [i["id"] for i in open_] == [b, a]
    assert all(set(i) == INCIDENT_KEYS for i in open_)
    assert len(seeded.get_open_incidents(limit=1)) == 1


def test_get_all_incidents_filters_by_status_and_owner(seeded):
    seeded.create_user("user-2", "other", "synthetic-hash")
    seeded.create_device("dev-2", "user-2", "h2", "linux", "k2")
    mine = _incident(seeded)
    theirs = _incident(seeded, device_id="dev-2", first_seen="2026-01-02T00:00:00")
    seeded.update_incident_status(theirs, "RESOLVED")

    assert [i["id"] for i in seeded.get_all_incidents()] == [theirs, mine]
    assert [i["id"] for i in seeded.get_all_incidents(status="RESOLVED")] == [theirs]
    assert [i["id"] for i in seeded.get_all_incidents(user_id=USER_ID)] == [mine]
    assert seeded.get_all_incidents(status="RESOLVED", user_id=USER_ID) == []
    assert len(seeded.get_all_incidents(limit=1)) == 1
    assert all(set(i) == INCIDENT_KEYS for i in seeded.get_all_incidents(user_id="user-2"))
