"""Contract: normalized events and detection watermarks.

Covers: insert_event, insert_events_batch, get_events_since,
get_events_for_user, get_event_count_for_device, get_watermark, set_watermark.
"""

import gc
import json
import sqlite3
from datetime import datetime

import pytest

from tests.storage._support import DEVICE_ID, USER_ID, make_event, transactions

EVENT_KEYS = {
    "id",
    "timestamp",
    "device_id",
    "user_id",
    "host",
    "effective_username",
    "source_ip",
    "event_type",
    "raw_message",
    "attributes",
    "is_synthetic",
}


# ── insert_event ───────────────────────────────────────────────────────────


def test_insert_event_returns_rowid_and_round_trips(seeded):
    row_id = seeded.insert_event(make_event(attributes={"port": 22}))
    assert isinstance(row_id, int) and row_id > 0
    [ev] = seeded.get_events_since(DEVICE_ID, 0)
    assert set(ev) == EVENT_KEYS
    assert ev["id"] == row_id
    # attributes are stored as a JSON string, not decoded on read
    assert isinstance(ev["attributes"], str)
    assert json.loads(ev["attributes"]) == {"port": 22}
    assert ev["is_synthetic"] == 0


def test_insert_event_defaults_missing_attributes_to_empty_json(seeded):
    ev = make_event()
    del ev["attributes"]
    seeded.insert_event(ev)
    assert seeded.get_events_since(DEVICE_ID, 0)[0]["attributes"] == "{}"


def test_insert_event_ids_are_monotonic(seeded):
    ids = [seeded.insert_event(make_event()) for _ in range(3)]
    assert ids == sorted(ids) and len(set(ids)) == 3


def test_insert_event_missing_required_column_raises(seeded):
    ev = make_event()
    del ev["raw_message"]  # NOT NULL
    with pytest.raises(sqlite3.IntegrityError):
        seeded.insert_event(ev)


def test_insert_event_unknown_device_violates_foreign_key(seeded):
    with pytest.raises(sqlite3.IntegrityError):
        seeded.insert_event(make_event(device_id="ghost"))


# ── insert_events_batch ────────────────────────────────────────────────────


def test_insert_events_batch_returns_count_inserted(seeded):
    assert seeded.insert_events_batch([make_event(), make_event(), make_event()]) == 3
    assert seeded.get_event_count_for_device(DEVICE_ID) == 3


def test_insert_events_batch_empty_list_returns_zero(seeded):
    assert seeded.insert_events_batch([]) == 0
    assert seeded.get_event_count_for_device(DEVICE_ID) == 0


def test_insert_events_batch_is_all_or_nothing_on_failure(seeded):
    bad = make_event()
    del bad["event_type"]  # NOT NULL, fails mid-batch
    with pytest.raises(sqlite3.IntegrityError):
        seeded.insert_events_batch([make_event(), bad, make_event()])
    # The failing call never commits; its connection is only released on GC,
    # at which point the open transaction rolls back.
    gc.collect()
    assert seeded.get_event_count_for_device(DEVICE_ID) == 0


# ── reads ──────────────────────────────────────────────────────────────────


def test_get_events_since_filters_by_device_and_id_ascending_with_limit(seeded):
    seeded.create_device("dev-2", USER_ID, "h2", "linux", "k2")
    ids = [seeded.insert_event(make_event()) for _ in range(5)]
    seeded.insert_event(make_event(device_id="dev-2"))
    after_first = seeded.get_events_since(DEVICE_ID, ids[0])
    assert [e["id"] for e in after_first] == ids[1:]
    assert [e["id"] for e in seeded.get_events_since(DEVICE_ID, 0, limit=2)] == ids[:2]
    assert seeded.get_events_since(DEVICE_ID, ids[-1]) == []


def test_get_events_for_user_filters_synthetic_and_orders_newest_first(seeded):
    seeded.insert_event(make_event(timestamp="2026-01-01T00:00:00"))
    seeded.insert_event(make_event(timestamp="2026-01-03T00:00:00"))
    seeded.insert_event(make_event(timestamp="2026-01-02T00:00:00", is_synthetic=True))
    real = seeded.get_events_for_user(USER_ID)
    assert [e["timestamp"] for e in real] == ["2026-01-03T00:00:00", "2026-01-01T00:00:00"]
    synthetic = seeded.get_events_for_user(USER_ID, synthetic=True)
    assert [e["timestamp"] for e in synthetic] == ["2026-01-02T00:00:00"]
    assert len(seeded.get_events_for_user(USER_ID, limit=1)) == 1
    assert seeded.get_events_for_user("nobody") == []


def test_get_event_count_for_device(seeded):
    assert seeded.get_event_count_for_device(DEVICE_ID) == 0
    seeded.insert_events_batch([make_event() for _ in range(4)])
    assert seeded.get_event_count_for_device(DEVICE_ID) == 4
    assert seeded.get_event_count_for_device("ghost") == 0


# ── watermarks ─────────────────────────────────────────────────────────────


def test_get_watermark_defaults_to_zero(db):
    assert db.get_watermark("never-run") == 0


def test_set_watermark_inserts_then_updates(seeded, sql):
    assert seeded.set_watermark(DEVICE_ID, 10) is None
    assert seeded.get_watermark(DEVICE_ID) == 10
    seeded.set_watermark(DEVICE_ID, 25)
    assert seeded.get_watermark(DEVICE_ID) == 25
    rows = sql("SELECT * FROM detection_watermarks")
    assert len(rows) == 1
    datetime.fromisoformat(rows[0]["last_run_at"])  # ISO timestamp recorded


def test_set_watermark_unknown_device_violates_foreign_key(db):
    with pytest.raises(sqlite3.IntegrityError):
        db.set_watermark("ghost", 1)


# ── insert_events_batch transaction shape (S2-3) ───────────────────────────


def test_insert_events_batch_is_one_transaction(seeded, traced):
    assert seeded.insert_events_batch([make_event() for _ in range(50)]) == 50
    assert len(traced) == 1
    assert transactions(traced[0]) == ["BEGIN", "COMMIT"]
