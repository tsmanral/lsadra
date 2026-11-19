"""
Scheduled scans raise alerts (roadmap W5).

Pins: a lateral movement finding is stored in ``anomalies`` with its rule ID,
ATT&CK technique and tactic, linked to an incident, published to ``/ws/alerts``
and added to entity risk; one address alerts once per window; accounts named
only by failed logins get no user risk; cross-source activity raises an open
incident's severity one step, once, and never alerts on its own.
SYNTHETIC data only (*.demo users, RFC 5737 addresses).
"""

import logging
from datetime import datetime, timedelta, timezone

import pytest

import lsadra.config as config
from lsadra.detection import scan_alerts
from lsadra.jobs import scheduler
from lsadra.ui.alert_stream import alert_hub
from tests.storage._support import DEVICE_ID, USER_ID, make_event
from tests.storage.conftest import db, seeded, sql  # noqa: F401 — shared fixtures

IP = "203.0.113.77"


def _ts(**ago) -> str:
    return (datetime.now(timezone.utc) - timedelta(**ago)).isoformat()


@pytest.fixture
def published(monkeypatch):
    sent = []
    monkeypatch.setattr(alert_hub, "publish", sent.append)
    return sent


@pytest.fixture
def lateral(seeded):  # noqa: F811
    """One address logging in to three accounts on two devices, inside the window."""
    seeded.create_device("dev-2", USER_ID, "host-2", "linux", "synthetic-key-hash")
    seeded.insert_events_batch([
        make_event(timestamp=_ts(minutes=2), source_ip=IP, effective_username="ana.demo",
                   event_type="auth_success"),
        make_event(timestamp=_ts(minutes=3), source_ip=IP, effective_username="ben.demo",
                   event_type="auth_success"),
        make_event(timestamp=_ts(minutes=4), source_ip=IP, effective_username="cy.demo",
                   event_type="auth_failure", device_id="dev-2", host="host-2"),
    ])
    return seeded


def _alerts(sql):  # noqa: F811
    return sql("SELECT * FROM anomalies WHERE rule_id = 'lsadra-lateral-remote-services'")


def test_lateral_movement_scan_stores_an_attributed_alert(lateral, sql, published):  # noqa: F811
    scheduler._run_lateral_movement_scan()
    rows = _alerts(sql)
    assert len(rows) == 1
    row = rows[0]
    assert row["source_ip"] == IP
    assert row["mitre_technique"] == "T1021"
    assert "Lateral Movement" in row["mitre_tactics"]
    assert row["rule_version"] >= 1
    assert row["severity_label"] == "HIGH" and row["is_anomaly"]
    assert row["device_id"] == DEVICE_ID
    assert row["user_id"] is None  # spans owners: admins only
    assert "ana.demo" in row["narrative"] and "dev-2" in row["narrative"]


def test_lateral_movement_alert_opens_an_incident_and_is_published(lateral, sql, published):  # noqa: F811
    scheduler._run_lateral_movement_scan()
    row = _alerts(sql)[0]
    assert row["incident_id"]
    incident = sql("SELECT * FROM incidents WHERE id = ?", (row["incident_id"],))[0]
    assert incident["source_ip"] == IP and incident["attack_type"] == "Lateral Movement"
    assert len(published) == 1
    assert published[0]["anomaly_id"] == row["id"]
    assert published[0]["mitre_technique"] == "T1021"


def test_one_address_alerts_once_per_window(lateral, sql, published):  # noqa: F811
    for _ in range(3):
        scheduler._run_lateral_movement_scan()
    assert len(_alerts(sql)) == 1
    assert len(published) == 1


def test_an_alert_older_than_the_window_does_not_suppress_a_new_one(lateral, sql, published):  # noqa: F811
    scheduler._run_lateral_movement_scan()
    sql("UPDATE anomalies SET created_at = datetime('now', '-2 hours')")
    scheduler._run_lateral_movement_scan()
    assert len(_alerts(sql)) == 2


def test_lateral_movement_adds_risk_to_hosts_and_actor_accounts(lateral, published, monkeypatch):
    monkeypatch.setattr(config, "RISK_MODE", "shadow")
    scheduler._run_lateral_movement_scan()
    hosts = lateral.get_risk_events("host", "host-1") + lateral.get_risk_events("host", "host-2")
    assert {e["rule_id"] for e in hosts} == {"lsadra-lateral-remote-services"}
    assert lateral.get_risk_events("user", "ana.demo")
    assert lateral.get_risk_events("user", "ben.demo")
    # cy.demo only appears in a failed login: the target, not the actor.
    assert not lateral.get_risk_events("user", "cy.demo")


def test_risk_off_records_nothing(lateral, published, monkeypatch):
    monkeypatch.setattr(config, "RISK_MODE", "off")
    scheduler._run_lateral_movement_scan()
    assert not lateral.get_risk_events("host", "host-1")


def test_no_finding_no_alert(seeded, sql, published):  # noqa: F811
    seeded.insert_events_batch([
        make_event(timestamp=_ts(minutes=2), source_ip=IP, effective_username="ana.demo"),
    ])
    scheduler._run_lateral_movement_scan()
    assert not _alerts(sql) and not published


def test_narrative_escapes_log_controlled_names(seeded, sql, published):  # noqa: F811
    names = ["**bold**.demo", "[x](http://198.51.100.1).demo", "ok.demo"]
    seeded.insert_events_batch([
        make_event(timestamp=_ts(minutes=2), source_ip=IP, effective_username=n,
                   event_type="auth_success") for n in names
    ])
    scheduler._run_lateral_movement_scan()
    narrative = _alerts(sql)[0]["narrative"]
    # Markdown specials arrive backslash-escaped (explainability.sanitize).
    assert r"\*\*bold\*\*.demo" in narrative
    assert r"\[x\]" in narrative


# ── cross-source corroboration ──────────────────────────────────────────────

def _multi_source(db):  # noqa: F811
    db.insert_events_batch([
        make_event(timestamp=_ts(minutes=1), source_ip=IP, event_type="ssh_login"),
        make_event(timestamp=_ts(minutes=1), source_ip=IP, event_type="connection"),
    ])


def test_cross_source_alone_raises_nothing(seeded, sql, published):  # noqa: F811
    _multi_source(seeded)
    scheduler._run_cross_source_correlation()
    assert not sql("SELECT * FROM anomalies") and not published


def test_cross_source_raises_an_open_incident_one_step_once(seeded, sql, caplog):  # noqa: F811
    _multi_source(seeded)
    inc = seeded.create_incident(DEVICE_ID, IP, "SSH Brute Force", "MEDIUM", _ts(minutes=5))
    other = seeded.create_incident(DEVICE_ID, "198.51.100.200", "SSH Brute Force", "MEDIUM",
                                   _ts(minutes=5))
    with caplog.at_level(logging.WARNING, logger=scan_alerts.logger.name):
        for _ in range(3):
            scheduler._run_cross_source_correlation()
    rows = {r["id"]: r for r in sql("SELECT * FROM incidents")}
    assert rows[inc]["severity_label"] == "HIGH"  # one step, not three
    assert rows[inc]["cross_source_at"]
    assert rows[other]["severity_label"] == "MEDIUM" and rows[other]["cross_source_at"] is None
    assert caplog.text.count(f"Incident {inc} from {IP} raised MEDIUM -> HIGH") == 1


def test_cross_source_leaves_closed_incidents_alone(seeded, sql):  # noqa: F811
    _multi_source(seeded)
    inc = seeded.create_incident(DEVICE_ID, IP, "SSH Brute Force", "LOW", _ts(minutes=5))
    seeded.update_incident_status(inc, "RESOLVED")
    scheduler._run_cross_source_correlation()
    assert sql("SELECT severity_label FROM incidents WHERE id = ?", (inc,))[0]["severity_label"] == "LOW"


def test_critical_incidents_stay_critical(seeded, sql):  # noqa: F811
    _multi_source(seeded)
    inc = seeded.create_incident(DEVICE_ID, IP, "SSH Brute Force", "CRITICAL", _ts(minutes=5))
    scheduler._run_cross_source_correlation()
    assert sql("SELECT severity_label FROM incidents WHERE id = ?", (inc,))[0]["severity_label"] == "CRITICAL"
