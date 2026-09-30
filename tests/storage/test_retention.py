"""Contract: retention cleanup.

Covers: cleanup_old_data.
"""

import sqlite3
from datetime import datetime, timedelta

import pytest

import lsadra.storage.database as database
from tests.storage._support import DEVICE_ID, make_event

OLD = "2000-01-01T00:00:00"
OLD_SQL = "2000-01-01 00:00:00"


@pytest.fixture(autouse=True)
def _fixed_retention(monkeypatch):
    # database.py binds RETENTION_DAYS at import; pin it so an env override
    # (LSADRA_RETENTION_DAYS) cannot change what these tests mean.
    monkeypatch.setattr(database, "RETENTION_DAYS", 30)


def _count(sql, table):
    return sql(f"SELECT COUNT(*) AS n FROM {table}")[0]["n"]


def test_cleanup_old_data_with_nothing_old_returns_zero(seeded, sql):
    seeded.insert_event(make_event(timestamp=datetime.utcnow().isoformat()))
    assert seeded.cleanup_old_data() == 0
    assert _count(sql, "normalized_events") == 1


def test_cleanup_old_data_empty_db_returns_zero(db):
    assert db.cleanup_old_data() == 0


def test_cleanup_old_data_deletes_old_rows_across_tables_and_returns_event_count(seeded, sql):
    recent_ts = (datetime.utcnow() - timedelta(days=1)).isoformat()
    seeded.insert_events_batch([make_event(timestamp=OLD), make_event(timestamp=OLD)])
    seeded.insert_event(make_event(timestamp=recent_ts))

    old_anomaly = seeded.insert_anomaly({"device_id": DEVICE_ID, "is_anomaly": True})
    sql("UPDATE anomalies SET created_at=? WHERE id=?", (OLD_SQL, old_anomaly))
    seeded.insert_anomaly({"device_id": DEVICE_ID, "is_anomaly": True})

    seeded.insert_heartbeat(DEVICE_ID)
    sql("UPDATE device_heartbeats SET timestamp=?", (OLD_SQL,))
    seeded.insert_heartbeat(DEVICE_ID)

    seeded.upsert_metrics_5min(DEVICE_ID, OLD, 1, 0, 0.0, 0.0, 0, 0)
    seeded.upsert_metrics_5min(DEVICE_ID, recent_ts, 1, 0, 0.0, 0.0, 0, 0)

    seeded.insert_drift_record("m", "f", 0.1, False)
    sql("UPDATE feature_drift SET measured_at=?", (OLD_SQL,))
    seeded.insert_drift_record("m", "f", 0.2, False)

    deleted = seeded.cleanup_old_data()
    assert isinstance(deleted, int)
    assert deleted == 2  # only the normalized_events count is reported
    for table in (
        "normalized_events",
        "anomalies",
        "device_heartbeats",
        "metrics_5min",
        "feature_drift",
    ):
        assert _count(sql, table) == 1, table


def test_cleanup_old_data_keeps_non_retention_tables(seeded, sql):
    seeded.insert_event(make_event(timestamp=OLD))
    seeded.update_ingestion_stats(None, "ssh_log", 1, 0)
    seeded.cleanup_old_data()
    assert seeded.get_device(DEVICE_ID) is not None
    assert _count(sql, "ingestion_stats") == 1


@pytest.mark.xfail(
    strict=True,
    raises=sqlite3.IntegrityError,
    reason=(
        "Current behavior: cleanup_old_data() deletes normalized_events before "
        "anomalies, and anomalies.event_id REFERENCES normalized_events(id) with "
        "PRAGMA foreign_keys=ON, so any expired event that has an anomaly makes "
        "the whole cleanup raise 'FOREIGN KEY constraint failed' and delete "
        "nothing. The failing call also leaves its connection (and write lock) "
        "open until GC. Storage fix is out of scope for the contract suite."
    ),
)
def test_cleanup_old_data_removes_expired_event_that_has_an_anomaly(seeded, sql):
    event_id = seeded.insert_event(make_event(timestamp=OLD))
    aid = seeded.insert_anomaly({"event_id": event_id, "device_id": DEVICE_ID, "is_anomaly": True})
    sql("UPDATE anomalies SET created_at=? WHERE id=?", (OLD_SQL, aid))
    assert seeded.cleanup_old_data() == 1
    assert _count(sql, "normalized_events") == 0
    assert _count(sql, "anomalies") == 0
