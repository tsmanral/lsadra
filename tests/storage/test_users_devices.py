"""Contract: users, devices, registration tokens, device heartbeats.

Covers: create_user, get_user_by_username, get_user_by_id, update_user_role,
list_users, create_device, get_device, get_devices_for_user, get_all_devices,
touch_device, update_device_status, increment_device_event_count, store_token,
consume_token, insert_heartbeat, get_latest_heartbeat.
"""

import sqlite3
from datetime import datetime, timedelta

import pytest

from tests.storage._support import DEVICE_ID, USER_ID

USER_KEYS = {"id", "username", "password_hash", "role", "created_at"}
DEVICE_KEYS = {
    "id",
    "user_id",
    "hostname",
    "os_type",
    "display_name",
    "api_key_hash",
    "status",
    "event_count",
    "created_at",
    "last_seen_at",
}


# ── users ──────────────────────────────────────────────────────────────────


def test_create_user_then_lookup_by_username_and_id(db):
    assert db.create_user("u-9", "bob", "synthetic-hash", "ADMIN") is None
    by_name = db.get_user_by_username("bob")
    assert isinstance(by_name, dict)
    assert set(by_name) == USER_KEYS
    assert (by_name["id"], by_name["username"], by_name["role"]) == ("u-9", "bob", "ADMIN")
    assert by_name["password_hash"] == "synthetic-hash"
    assert by_name["created_at"]
    assert db.get_user_by_id("u-9") == by_name


def test_create_user_defaults_role_to_analyst(db):
    db.create_user("u-2", "carol", "synthetic-hash")
    assert db.get_user_by_id("u-2")["role"] == "ANALYST"


def test_user_lookups_return_none_when_missing(db):
    assert db.get_user_by_username("nobody") is None
    assert db.get_user_by_id("nobody") is None


def test_create_user_duplicate_username_raises_integrity_error(db):
    db.create_user("u-1", "dup", "synthetic-hash")
    with pytest.raises(sqlite3.IntegrityError):
        db.create_user("u-2", "dup", "synthetic-hash")


def test_update_user_role(db):
    db.create_user("u-3", "dave", "synthetic-hash")
    assert db.update_user_role("u-3", "VIEWER") is None
    assert db.get_user_by_id("u-3")["role"] == "VIEWER"


def test_update_user_role_on_missing_user_is_a_silent_noop(db):
    db.update_user_role("ghost", "ADMIN")
    assert db.get_user_by_id("ghost") is None


def test_list_users_returns_all_without_password_hash(db):
    assert db.list_users() == []
    db.create_user("u-a", "a", "synthetic-hash")
    db.create_user("u-b", "b", "synthetic-hash", "ADMIN")
    users = db.list_users()
    assert isinstance(users, list) and len(users) == 2
    for u in users:
        assert set(u) == {"id", "username", "role", "created_at"}
    assert {u["id"] for u in users} == {"u-a", "u-b"}


# ── devices ────────────────────────────────────────────────────────────────


def test_create_device_then_get_device_with_defaults(seeded):
    dev = seeded.get_device(DEVICE_ID)
    assert isinstance(dev, dict)
    assert set(dev) == DEVICE_KEYS
    assert dev["user_id"] == USER_ID
    assert dev["status"] == "BASELINING"
    assert dev["event_count"] == 0
    assert dev["display_name"] is None
    assert dev["last_seen_at"] is None


def test_create_device_stores_display_name(seeded):
    assert (
        seeded.create_device("dev-2", USER_ID, "h2", "windows", "k2", display_name="Laptop") is None
    )
    assert seeded.get_device("dev-2")["display_name"] == "Laptop"


def test_create_device_for_unknown_user_violates_foreign_key(db):
    with pytest.raises(sqlite3.IntegrityError):
        db.create_device("dev-x", "no-such-user", "h", "linux", "k")


def test_get_device_missing_returns_none(db):
    assert db.get_device("nope") is None


def test_get_devices_for_user_filters_by_owner(seeded):
    seeded.create_user("user-2", "other", "synthetic-hash")
    seeded.create_device("dev-2", USER_ID, "h2", "linux", "k2")
    seeded.create_device("dev-3", "user-2", "h3", "linux", "k3")
    mine = seeded.get_devices_for_user(USER_ID)
    assert isinstance(mine, list)
    assert {d["id"] for d in mine} == {DEVICE_ID, "dev-2"}
    assert all(set(d) == DEVICE_KEYS for d in mine)
    assert seeded.get_devices_for_user("nobody") == []


def test_get_all_devices_returns_every_device(seeded):
    seeded.create_user("user-2", "other", "synthetic-hash")
    seeded.create_device("dev-3", "user-2", "h3", "linux", "k3")
    devices = seeded.get_all_devices()
    assert {d["id"] for d in devices} == {DEVICE_ID, "dev-3"}
    assert all(set(d) == DEVICE_KEYS for d in devices)


def test_get_all_devices_empty(db):
    assert db.get_all_devices() == []


def test_touch_device_sets_last_seen_to_iso_utc(seeded):
    before = datetime.utcnow() - timedelta(seconds=5)
    assert seeded.touch_device(DEVICE_ID) is None
    seen = datetime.fromisoformat(seeded.get_device(DEVICE_ID)["last_seen_at"])
    assert before <= seen <= datetime.utcnow() + timedelta(seconds=5)


def test_update_device_status(seeded):
    assert seeded.update_device_status(DEVICE_ID, "ONLINE") is None
    assert seeded.get_device(DEVICE_ID)["status"] == "ONLINE"


def test_increment_device_event_count_returns_running_total(seeded):
    assert seeded.increment_device_event_count(DEVICE_ID) == 1
    assert seeded.increment_device_event_count(DEVICE_ID, 10) == 11
    assert seeded.get_device(DEVICE_ID)["event_count"] == 11


def test_increment_device_event_count_missing_device_returns_zero(db):
    assert db.increment_device_event_count("ghost", 5) == 0


# ── registration tokens ────────────────────────────────────────────────────


def test_consume_token_is_single_use(seeded, sql):
    expires = datetime.utcnow() + timedelta(hours=1)
    assert seeded.store_token("tok-1", USER_ID, expires) is None
    data = seeded.consume_token("tok-1")
    assert isinstance(data, dict)
    assert set(data) == {"token", "user_id", "expires_at", "used"}
    assert data["user_id"] == USER_ID
    assert data["expires_at"] == expires.isoformat()
    # The returned row is the pre-consumption snapshot (used still 0) ...
    assert data["used"] == 0
    # ... while the stored row is now marked used, so a replay is refused.
    assert sql("SELECT used FROM registration_tokens WHERE token='tok-1'")[0]["used"] == 1
    assert seeded.consume_token("tok-1") is None


def test_consume_token_expired_returns_none_and_is_not_marked_used(seeded, sql):
    seeded.store_token("tok-old", USER_ID, datetime.utcnow() - timedelta(seconds=1))
    assert seeded.consume_token("tok-old") is None
    assert sql("SELECT used FROM registration_tokens WHERE token='tok-old'")[0]["used"] == 0


def test_consume_token_unknown_returns_none(db):
    assert db.consume_token("never-issued") is None


def test_store_token_for_unknown_user_violates_foreign_key(db):
    with pytest.raises(sqlite3.IntegrityError):
        db.store_token("tok-x", "ghost", datetime.utcnow() + timedelta(hours=1))


# ── heartbeats ─────────────────────────────────────────────────────────────


def test_insert_heartbeat_then_latest(seeded):
    assert seeded.insert_heartbeat(DEVICE_ID, 12.5, 40.0, "1.2.3") is None
    hb = seeded.get_latest_heartbeat(DEVICE_ID)
    assert isinstance(hb, dict)
    assert set(hb) == {"id", "device_id", "timestamp", "cpu_pct", "mem_pct", "agent_version"}
    assert (hb["cpu_pct"], hb["mem_pct"], hb["agent_version"]) == (12.5, 40.0, "1.2.3")


def test_insert_heartbeat_optional_fields_default_to_null(seeded):
    seeded.insert_heartbeat(DEVICE_ID)
    hb = seeded.get_latest_heartbeat(DEVICE_ID)
    assert (hb["cpu_pct"], hb["mem_pct"], hb["agent_version"]) == (None, None, None)


def test_get_latest_heartbeat_orders_by_timestamp(seeded, sql):
    seeded.insert_heartbeat(DEVICE_ID, agent_version="old")
    sql("UPDATE device_heartbeats SET timestamp='2000-01-01 00:00:00'")
    seeded.insert_heartbeat(DEVICE_ID, agent_version="new")
    assert seeded.get_latest_heartbeat(DEVICE_ID)["agent_version"] == "new"


def test_get_latest_heartbeat_missing_returns_none(db):
    assert db.get_latest_heartbeat("ghost") is None
