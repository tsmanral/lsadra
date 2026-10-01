"""Contract: connection lifecycle on failure.

Every public storage function that opens its own connection must close it (and
roll back any open transaction) when a statement raises. Otherwise the
connection — and, after a partial write, the database write lock — lives until
garbage collection, and every other writer waits out the busy timeout.

Covers: every public function in lsadra.storage.database (uniform helper), plus
a real-SQLite lock probe after a failed batch insert.
"""

import inspect
import sqlite3
from datetime import datetime, timedelta

import pytest

import lsadra.storage.database as database
from tests.storage._support import DEVICE_ID, USER_ID, make_event


class _FailingConnection:
    """Stands in for sqlite3.Connection: every statement raises; lifecycle is recorded."""

    def __init__(self):
        self.closed = False
        self.rolled_back = False

    def _fail(self, *_args, **_kwargs):
        raise sqlite3.OperationalError("injected failure")

    execute = executemany = executescript = cursor = commit = _fail

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


_EXPIRES = datetime.utcnow() + timedelta(hours=1)

# One representative call per public function. get_connection is the factory
# itself (the caller owns what it returns), so it is the only exclusion.
CALLS = {
    "init_db": (),
    "create_user": (USER_ID, "alice", "h"),
    "get_user_by_username": ("alice",),
    "get_user_by_id": (USER_ID,),
    "update_user_role": (USER_ID, "ADMIN"),
    "list_users": (),
    "create_device": (DEVICE_ID, USER_ID, "host", "linux", "k"),
    "get_device": (DEVICE_ID,),
    "get_devices_for_user": (USER_ID,),
    "get_all_devices": (),
    "touch_device": (DEVICE_ID,),
    "update_device_status": (DEVICE_ID, "ONLINE"),
    "increment_device_event_count": (DEVICE_ID,),
    "store_token": ("tok", USER_ID, _EXPIRES),
    "consume_token": ("tok",),
    "insert_event": (make_event(),),
    "insert_events_batch": ([make_event()],),
    "get_events_since": (DEVICE_ID, 0),
    "get_events_for_user": (USER_ID,),
    "get_event_count_for_device": (DEVICE_ID,),
    "get_watermark": (DEVICE_ID,),
    "set_watermark": (DEVICE_ID, 1),
    "insert_anomaly": ({"device_id": DEVICE_ID},),
    "get_anomalies_for_user": (USER_ID,),
    "get_anomalies_for_device": (DEVICE_ID,),
    "get_anomalies_for_incident": (1,),
    "get_recent_anomalies": (),
    "update_anomaly_incident": (1, 1),
    "create_incident": (DEVICE_ID, "192.0.2.1", "brute_force", "HIGH", "2026-01-01T00:00:00"),
    "get_incident": (1,),
    "get_open_incident": (DEVICE_ID, "192.0.2.1", "brute_force", "2026-01-01T00:00:00"),
    "update_incident_last_seen": (1, "2026-01-01T00:00:00"),
    "update_incident_status": (1, "RESOLVED"),
    "assign_incident": (1, USER_ID),
    "get_open_incidents": (),
    "get_all_incidents": (),
    "insert_heartbeat": (DEVICE_ID,),
    "record_heartbeat": (DEVICE_ID,),
    "get_latest_heartbeat": (DEVICE_ID,),
    "register_model": ("m", "ensemble", "/m"),
    "get_latest_model": ("m",),
    "mark_model_stale": ("m",),
    "upsert_metrics_5min": (DEVICE_ID, "2026-01-01T00:00:00", 1, 0, 0.0, 0.0, 0, 0),
    "get_metrics_timeseries": (DEVICE_ID, "2026", "2027"),
    "upsert_threat_intel": ("198.51.100.7", 1),
    "get_threat_intel": ("198.51.100.7",),
    "get_expiring_threat_intel": (),
    "upsert_ip_geolocation": ("198.51.100.7", 1.0, 2.0),
    "get_unresolved_ips": (),
    "insert_drift_record": ("m", "f", 0.1, False),
    "get_drift_records": ("m",),
    "cleanup_old_data": (),
    "store_feedback": (None, 1, "false_positive", "", "", {}, "ssh_log"),
    "get_false_positive_patterns": (None,),
    "get_fp_rate_by_source_type": (None,),
    "update_ingestion_stats": (None, "ssh_log", 1, 0),
    "get_ingestion_stats": (None,),
}

# Functions that accept a caller-owned connection as their first argument.
BORROWING = {
    "store_feedback",
    "get_false_positive_patterns",
    "get_fp_rate_by_source_type",
    "update_ingestion_stats",
    "get_ingestion_stats",
}


def _public_functions():
    return {
        name
        for name, fn in inspect.getmembers(database, inspect.isfunction)
        if fn.__module__ == database.__name__ and not name.startswith("_")
    }


def test_lifecycle_table_covers_every_public_function():
    assert set(CALLS) == _public_functions() - {"get_connection"}


@pytest.mark.parametrize("name", sorted(CALLS))
def test_owned_connection_is_rolled_back_and_closed_on_exception(name, monkeypatch):
    opened = []

    def fake_get_connection():
        conn = _FailingConnection()
        opened.append(conn)
        return conn

    monkeypatch.setattr(database, "get_connection", fake_get_connection)
    with pytest.raises(sqlite3.OperationalError, match="injected failure"):
        getattr(database, name)(*CALLS[name])
    assert len(opened) == 1, "expected exactly one connection to be opened"
    assert opened[0].closed, f"{name} leaked its connection on exception"
    assert opened[0].rolled_back, f"{name} did not roll back on exception"


@pytest.mark.parametrize("name", sorted(BORROWING))
def test_borrowed_connection_is_left_to_the_caller(name, monkeypatch):
    def no_connection():
        raise AssertionError("must not open a connection when one is passed in")

    monkeypatch.setattr(database, "get_connection", no_connection)
    borrowed = _FailingConnection()
    with pytest.raises(sqlite3.OperationalError, match="injected failure"):
        getattr(database, name)(borrowed, *CALLS[name][1:])
    assert not borrowed.closed and not borrowed.rolled_back


def _write_lock_is_free(path):
    probe = sqlite3.connect(str(path), timeout=0.2)
    try:
        probe.execute("BEGIN IMMEDIATE")
        probe.rollback()
        return True
    except sqlite3.OperationalError as exc:
        if "locked" in str(exc):
            return False
        raise
    finally:
        probe.close()


def test_failed_batch_insert_releases_the_write_lock(seeded, sql):
    # Row 1 is valid and gets written inside the open transaction; row 2 violates
    # the devices FK, so the call raises with a pending write (= the write lock).
    batch = [make_event(), make_event(device_id="ghost-device")]
    with pytest.raises(sqlite3.IntegrityError) as excinfo:
        seeded.insert_events_batch(batch)
    # excinfo keeps the failing frame (and any connection it still holds) alive,
    # exactly like a logged-but-retained exception in a long-running server.
    assert excinfo.value is not None
    assert _write_lock_is_free(seeded.DB_PATH), "write lock still held after the exception"
    # A second writer proceeds immediately, and the failed batch left nothing behind.
    assert seeded.insert_event(make_event()) > 0
    assert sql("SELECT COUNT(*) AS n FROM normalized_events")[0]["n"] == 1
