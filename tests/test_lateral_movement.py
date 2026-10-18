"""
Rule engine lateral-movement check: the 30-minute window.

Pins that detect_lateral_movement only counts events inside its window. It
used to compare stored ISO timestamps against SQLite datetime('now', ...),
which put every event from the current day inside the window. SYNTHETIC data
only (RFC 5737 addresses, made-up usernames).
"""

from datetime import datetime, timedelta, timezone

from lsadra.detection.rule_engine import detect_lateral_movement
from tests.storage._support import make_event
from tests.storage.conftest import db, seeded  # noqa: F401 — shared fixtures

IP = "203.0.113.50"


def _stored_ts(**ago) -> str:
    # Exactly what ingestion stores: isoformat() of a UTC-aware timestamp.
    return (datetime.now(timezone.utc) - timedelta(**ago)).isoformat()


def _logins(*minutes_ago: int):
    return [
        make_event(
            timestamp=_stored_ts(minutes=m),
            source_ip=IP,
            effective_username=f"user{i}.demo",
            event_type="ssh_login",
        )
        for i, m in enumerate(minutes_ago)
    ]


def _detect(db):  # noqa: F811
    conn = db.get_connection()
    try:
        return detect_lateral_movement(conn, IP)
    finally:
        conn.close()


def test_three_users_inside_the_window_is_flagged(seeded):  # noqa: F811
    seeded.insert_events_batch(_logins(1, 10, 25))
    alert = _detect(seeded)
    assert alert is not None
    assert alert["type"] == "LATERAL_MOVEMENT"
    assert "3 users" in alert["reason"]


def test_events_older_than_the_window_are_not_counted(seeded):  # noqa: F811
    # Two users in the window and one 45 minutes ago. Under the old comparison
    # all three counted (same day), which raised a false alert.
    seeded.insert_events_batch(_logins(1, 10, 45))
    assert _detect(seeded) is None


def test_old_events_alone_are_not_flagged(seeded):  # noqa: F811
    seeded.insert_events_batch(_logins(40, 50, 59))
    assert _detect(seeded) is None
