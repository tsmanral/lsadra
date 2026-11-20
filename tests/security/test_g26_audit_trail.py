"""
G-26 — Hash-chained audit trail that LSADRA itself watches.

Attacker story: nothing recorded logins, failed logins, role changes or
device revocations, so a takeover of the dashboard left no trace, and an
attacker with database access could rewrite history unnoticed.

Secure behavior pinned here: logins (success, failure, lockout), logout and
device revocation are recorded with actor, target and source IP; each row
chains to the previous by SHA-256 and verify_chain finds the first altered
row; the table refuses UPDATE and early DELETE; a lockout and a broken chain
are raised as LSADRA alerts (T1110, T1070). SYNTHETIC data only.
"""

import sqlite3

import pytest

from lsadra import config
from lsadra.security import audit
from lsadra.storage import database as db
from tests.security._identity_support import (  # noqa: F401 — fixture
    bearer,
    identity_env,
    login,
    make_user,
)


def _actions():
    return [e["action"] for e in reversed(audit.list_events(100))]


def test_logins_and_logout_are_recorded(identity_env):
    client = identity_env
    make_user()
    login(client, password="wrong-password-xyz")
    token = login(client).json()["access_token"]
    client.post("/api/auth/logout", headers=bearer(token))
    assert _actions() == ["auth.login.failure", "auth.login.success", "auth.logout"]
    failure = audit.list_events(100, "auth.login.failure")[0]
    assert failure["target"] == "analyst.demo" and failure["source_ip"]
    assert failure["details"]["reason"] == "bad_password"


def test_chain_verifies_and_detects_tampering(identity_env):
    for i in range(5):
        audit.record("test.event", target=f"t{i}")
    assert audit.verify_chain() == (True, None, 5)

    conn = db.get_connection()
    conn.execute("DROP TRIGGER audit_events_no_update")  # an attacker with file access
    conn.execute("UPDATE audit_events SET target = 'rewritten' WHERE id = 3")
    conn.commit()
    conn.close()
    intact, first_bad, _ = audit.verify_chain()
    assert (intact, first_bad) == (False, 3)


def test_rows_cannot_be_updated_or_deleted_early(identity_env):
    audit.record("test.event")
    conn = db.get_connection()
    try:
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("UPDATE audit_events SET outcome = 'success'")
        with pytest.raises(sqlite3.DatabaseError, match="365 days"):
            conn.execute("DELETE FROM audit_events")
    finally:
        conn.close()


def test_lockout_raises_an_alert(identity_env):
    client = identity_env
    make_user()
    for _ in range(config.LOGIN_MAX_FAILURES_PER_USER):
        login(client, password="wrong-password-xyz")
    rows = [a for a in db.get_recent_anomalies(50) if a["device_id"] == audit.SELF_DEVICE_ID]
    assert len(rows) == 1
    assert rows[0]["mitre_technique"] == "T1110"
    assert "auth.login.lockout" in _actions()


def test_scheduled_check_alerts_on_a_broken_chain(identity_env):
    from lsadra.jobs import scheduler

    audit.record("test.event")
    audit.record("test.event")
    conn = db.get_connection()
    conn.execute("DROP TRIGGER audit_events_no_update")
    conn.execute("UPDATE audit_events SET action = 'x' WHERE id = 1")
    conn.commit()
    conn.close()
    scheduler._audit_break_reported = None
    scheduler._run_audit_chain_check()
    scheduler._run_audit_chain_check()  # reported once per break
    rows = [a for a in db.get_recent_anomalies(50) if a.get("mitre_technique") == "T1070"]
    assert len(rows) == 1 and rows[0]["severity_label"] == "CRITICAL"


def test_device_revocation_is_audited(identity_env):
    client = identity_env
    owner = make_user("owner.demo")
    db.create_device("dev-demo-02", owner, "host.demo", "linux", "$2b$12$" + "x" * 53)
    token = login(client, "owner.demo").json()["access_token"]
    client.post("/api/devices/dev-demo-02/revoke", headers=bearer(token))
    event = audit.list_events(10, "device.revoke")[0]
    assert event["actor_name"] == "owner.demo" and event["target"] == "dev-demo-02"


def test_admin_grant_is_audited_and_alerted(identity_env):
    client = identity_env
    make_user("root.demo", role="ADMIN")
    target = make_user("analyst.demo")
    token = login(client, "root.demo").json()["access_token"]
    client.post(
        "/api/dashboard/users/role",
        headers=bearer(token),
        json={"user_id": target, "role": "ADMIN"},
    )
    assert {"user.role.change", "user.role.grant_admin"} <= set(_actions())
    assert any(a.get("mitre_technique") == "T1098" for a in db.get_recent_anomalies(50))
