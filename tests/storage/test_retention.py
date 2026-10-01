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


def test_cleanup_old_data_removes_expired_event_that_has_an_anomaly(seeded, sql):
    event_id = seeded.insert_event(make_event(timestamp=OLD))
    aid = seeded.insert_anomaly({"event_id": event_id, "device_id": DEVICE_ID, "is_anomaly": True})
    sql("UPDATE anomalies SET created_at=? WHERE id=?", (OLD_SQL, aid))
    assert seeded.cleanup_old_data() == 1
    assert _count(sql, "normalized_events") == 0
    assert _count(sql, "anomalies") == 0


def _expired_event_with_incident_anomalies(seeded, sql, n_anomalies):
    event_id = seeded.insert_event(make_event(timestamp=OLD))
    incident_id = seeded.create_incident(DEVICE_ID, "192.0.2.10", "brute_force", "HIGH", OLD)
    for _ in range(n_anomalies):
        aid = seeded.insert_anomaly(
            {
                "event_id": event_id,
                "device_id": DEVICE_ID,
                "is_anomaly": True,
                "incident_id": incident_id,
            }
        )
        sql("UPDATE anomalies SET created_at=? WHERE id=?", (OLD_SQL, aid))
    return event_id, incident_id


def test_cleanup_old_data_fk_order_many_expired_events_with_anomalies_and_incidents(seeded, sql):
    # Regression (FK order): anomalies.event_id -> normalized_events(id) and
    # anomalies.incident_id -> incidents(id). Several expired events, each with
    # several anomalies grouped into an incident, must all go in one pass.
    expired = [_expired_event_with_incident_anomalies(seeded, sql, n) for n in (1, 2, 3)]
    recent_ts = (datetime.utcnow() - timedelta(days=1)).isoformat()
    live_event = seeded.insert_event(make_event(timestamp=recent_ts))
    live_anomaly = seeded.insert_anomaly(
        {"event_id": live_event, "device_id": DEVICE_ID, "is_anomaly": True}
    )

    assert seeded.cleanup_old_data() == len(expired)

    assert [r["id"] for r in sql("SELECT id FROM normalized_events")] == [live_event]
    assert [r["id"] for r in sql("SELECT id FROM anomalies")] == [live_anomaly]
    # Incidents are outside the retention scope and are only ever a parent here.
    assert _count(sql, "incidents") == len(expired)
    for _, incident_id in expired:
        assert seeded.get_incident(incident_id) is not None
        assert seeded.get_anomalies_for_incident(incident_id) == []


def test_cleanup_old_data_keeps_expired_event_still_referenced_by_retained_anomaly(seeded, sql):
    # A back-filled log line: the event's own timestamp is past retention, but the
    # anomaly raised on it is recent. Deleting the event would violate the FK;
    # deleting the anomaly would drop a finding inside its retention window. The
    # event is kept until its anomaly ages out.
    event_id = seeded.insert_event(make_event(timestamp=OLD))
    aid = seeded.insert_anomaly({"event_id": event_id, "device_id": DEVICE_ID, "is_anomaly": True})
    seeded.insert_event(make_event(timestamp=OLD))  # expired, unreferenced -> deleted

    assert seeded.cleanup_old_data() == 1
    assert [r["id"] for r in sql("SELECT id FROM normalized_events")] == [event_id]
    assert [r["id"] for r in sql("SELECT id FROM anomalies")] == [aid]

    sql("UPDATE anomalies SET created_at=? WHERE id=?", (OLD_SQL, aid))
    assert seeded.cleanup_old_data() == 1
    assert _count(sql, "normalized_events") == 0
    assert _count(sql, "anomalies") == 0


def test_cleanup_old_data_is_one_transaction_rolled_back_on_failure(seeded, sql):
    event_id = seeded.insert_event(make_event(timestamp=OLD))
    aid = seeded.insert_anomaly({"event_id": event_id, "device_id": DEVICE_ID, "is_anomaly": True})
    sql("UPDATE anomalies SET created_at=? WHERE id=?", (OLD_SQL, aid))
    seeded.insert_drift_record("m", "f", 0.1, False)
    sql("UPDATE feature_drift SET measured_at=?", (OLD_SQL,))
    # Test-DB-only trigger: make the LAST retention DELETE fail.
    sql(
        "CREATE TRIGGER fail_drift_delete BEFORE DELETE ON feature_drift "
        "BEGIN SELECT RAISE(ABORT, 'injected retention failure'); END"
    )

    with pytest.raises(sqlite3.IntegrityError, match="injected retention failure"):
        seeded.cleanup_old_data()

    # Nothing from the earlier DELETEs in the same call survived.
    assert _count(sql, "normalized_events") == 1
    assert _count(sql, "anomalies") == 1
    assert _count(sql, "feature_drift") == 1
    # And the write lock was released: the next writer is not blocked.
    sql("DROP TRIGGER fail_drift_delete")
    assert seeded.cleanup_old_data() == 1
