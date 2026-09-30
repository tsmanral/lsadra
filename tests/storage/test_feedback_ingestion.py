"""Contract: analyst feedback and ingestion stats (the V4 additions).

Covers: store_feedback, get_false_positive_patterns, get_fp_rate_by_source_type,
update_ingestion_stats, get_ingestion_stats. Supersedes tests/test_db_v4.py.

Each function accepts an optional caller-owned connection (``db_conn``); when
given, the function uses it and must NOT close it. Both paths are pinned.
"""

import json
import sqlite3
from datetime import datetime

import pytest

FEEDBACK_KEYS = {
    "id",
    "alert_id",
    "label",
    "analyst_note",
    "fp_pattern",
    "suggested_thresholds",
    "source_type",
    "created_at",
}
STATS_KEYS = {"id", "source_type", "events_count", "parse_errors", "last_event", "updated_at"}


def _fp(db, source="ssh_log", conn=None, alert_id=1, label="false_positive"):
    db.store_feedback(
        conn,
        alert_id,
        label,
        "synthetic note",
        "monitoring_automation",
        {"failed_logins_last_5min": 12},
        source,
    )


# ── feedback ───────────────────────────────────────────────────────────────


def test_store_feedback_then_get_false_positive_patterns(db):
    assert _fp(db) is None
    fps = db.get_false_positive_patterns()
    assert isinstance(fps, list) and len(fps) == 1
    fp = fps[0]
    assert set(fp) == FEEDBACK_KEYS
    assert (fp["alert_id"], fp["label"], fp["source_type"]) == (1, "false_positive", "ssh_log")
    assert fp["fp_pattern"] == "monitoring_automation"
    assert json.loads(fp["suggested_thresholds"]) == {"failed_logins_last_5min": 12}


def test_get_false_positive_patterns_excludes_true_positives_and_limits(db):
    for i in range(3):
        _fp(db, alert_id=i)
    _fp(db, alert_id=99, label="true_positive")
    fps = db.get_false_positive_patterns()
    assert len(fps) == 3 and all(f["label"] == "false_positive" for f in fps)
    assert len(db.get_false_positive_patterns(limit=2)) == 2


def test_get_false_positive_patterns_empty(db):
    assert db.get_false_positive_patterns() == []


def test_store_feedback_rejects_unknown_label(db):
    with pytest.raises(sqlite3.IntegrityError):
        _fp(db, label="maybe")


def test_store_feedback_does_not_require_an_existing_alert(db):
    # Documented design choice (002_v4_schema.sql): no FK on alert_id.
    _fp(db, alert_id=123456)
    assert db.get_false_positive_patterns()[0]["alert_id"] == 123456


def test_feedback_functions_use_and_do_not_close_caller_connection(db):
    conn = db.get_connection()
    try:
        _fp(db, conn=conn)
        assert len(db.get_false_positive_patterns(conn)) == 1
        assert db.get_fp_rate_by_source_type(conn) == {"ssh_log": 1.0}
        conn.execute("SELECT 1")  # still open
    finally:
        conn.close()


def test_get_fp_rate_by_source_type(db):
    assert db.get_fp_rate_by_source_type() == {}
    _fp(db, source="ssh_log")
    _fp(db, source="ssh_log", label="true_positive")
    _fp(db, source="ssh_log", label="true_positive")
    _fp(db, source="network_flow", label="true_positive")
    db.store_feedback(None, 5, "false_positive", "", "", {}, None)  # NULL source ignored
    rates = db.get_fp_rate_by_source_type()
    assert rates == {"ssh_log": round(1 / 3, 4), "network_flow": 0.0}
    assert all(isinstance(v, float) for v in rates.values())


# ── ingestion stats ────────────────────────────────────────────────────────


def test_update_then_get_ingestion_stats(db):
    # The single assertion formerly in tests/test_db_v4.py, plus shape.
    assert db.update_ingestion_stats(None, "ssh_log", events=100, errors=2) is None
    db.update_ingestion_stats(None, "network_flow", events=50, errors=0)
    stats = db.get_ingestion_stats()
    assert any(s["source_type"] == "ssh_log" for s in stats), "ssh_log missing from stats"
    assert [s["source_type"] for s in stats] == ["ssh_log", "network_flow"]  # events_count DESC
    ssh = stats[0]
    assert set(ssh) == STATS_KEYS
    assert (ssh["events_count"], ssh["parse_errors"]) == (100, 2)
    datetime.fromisoformat(ssh["last_event"])
    datetime.fromisoformat(ssh["updated_at"])


def test_update_ingestion_stats_accumulates_on_conflict(db):
    db.update_ingestion_stats(None, "ssh_log", events=10, errors=1)
    db.update_ingestion_stats(None, "ssh_log", events=5, errors=3)
    [row] = db.get_ingestion_stats()
    assert (row["events_count"], row["parse_errors"]) == (15, 4)


def test_update_ingestion_stats_zero_events_keeps_last_event(db):
    db.update_ingestion_stats(None, "ssh_log", events=0, errors=1)
    assert db.get_ingestion_stats()[0]["last_event"] is None
    db.update_ingestion_stats(None, "ssh_log", events=3, errors=0)
    last_event = db.get_ingestion_stats()[0]["last_event"]
    assert last_event is not None
    db.update_ingestion_stats(None, "ssh_log", events=0, errors=2)
    row = db.get_ingestion_stats()[0]
    assert row["last_event"] == last_event
    assert row["parse_errors"] == 3


def test_ingestion_stats_with_caller_connection(db):
    conn = db.get_connection()
    try:
        db.update_ingestion_stats(conn, "syslog", 7, 0)
        assert [s["events_count"] for s in db.get_ingestion_stats(conn)] == [7]
        conn.execute("SELECT 1")  # still open
    finally:
        conn.close()


def test_get_ingestion_stats_empty(db):
    assert db.get_ingestion_stats() == []
