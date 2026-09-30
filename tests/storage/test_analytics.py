"""Contract: analytics-side tables — model registry, 5-min metrics, threat-intel
cache, IP geolocation, feature drift.

Covers: register_model, get_latest_model, mark_model_stale, upsert_metrics_5min,
get_metrics_timeseries, upsert_threat_intel, get_threat_intel,
get_expiring_threat_intel, upsert_ip_geolocation, get_unresolved_ips,
insert_drift_record, get_drift_records.
"""

import json
from datetime import datetime

import pytest

from tests.storage._support import DEVICE_ID, make_event

MODEL_KEYS = {
    "id",
    "model_name",
    "model_type",
    "file_path",
    "version",
    "trained_at",
    "event_count",
    "metrics",
    "is_stale",
    "created_at",
}
METRICS_KEYS = {
    "id",
    "device_id",
    "window_start",
    "event_count",
    "anomaly_count",
    "avg_severity",
    "max_severity",
    "unique_ips",
    "unique_users",
    "created_at",
}
TI_KEYS = {
    "ip_address",
    "abuse_score",
    "country_code",
    "isp",
    "domain",
    "is_tor",
    "total_reports",
    "last_reported",
    "raw_response",
    "queried_at",
    "expires_at",
}
DRIFT_KEYS = {"id", "model_name", "feature_name", "psi_value", "is_drifted", "measured_at"}


# ── model registry ─────────────────────────────────────────────────────────


def test_register_model_then_get_latest_model(db):
    reg_id = db.register_model("ensemble-v", "ensemble", "/models/a.pkl", 500, {"f1": 0.9})
    assert isinstance(reg_id, int) and reg_id > 0
    m = db.get_latest_model("ensemble-v")
    assert set(m) == MODEL_KEYS
    assert (m["id"], m["model_type"], m["file_path"], m["event_count"]) == (
        reg_id,
        "ensemble",
        "/models/a.pkl",
        500,
    )
    assert json.loads(m["metrics"]) == {"f1": 0.9}
    assert m["version"] == 1
    assert m["is_stale"] == 0
    datetime.fromisoformat(m["trained_at"])


def test_register_model_defaults(db):
    db.register_model("ae", "autoencoder", "/models/ae.pt")
    m = db.get_latest_model("ae")
    assert m["event_count"] == 0 and json.loads(m["metrics"]) == {}


def test_get_latest_model_unknown_returns_none(db):
    assert db.get_latest_model("nope") is None


def test_mark_model_stale_single_registration(db):
    db.register_model("m", "ensemble", "/a")
    assert db.mark_model_stale("m") is None
    assert db.get_latest_model("m")["is_stale"] == 1


def test_mark_model_stale_unknown_model_is_noop(db):
    db.mark_model_stale("nope")
    assert db.get_latest_model("nope") is None


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "Current behavior: register_model() never sets `version` (schema default 1), "
        "so every registration of a name is version 1 and get_latest_model() — "
        "ORDER BY version DESC LIMIT 1 — returns an arbitrary row (observed: the "
        "FIRST registration). Storage fix is out of scope for the contract suite."
    ),
)
def test_get_latest_model_returns_most_recent_registration(db):
    db.register_model("m", "ensemble", "/first")
    db.register_model("m", "ensemble", "/second")
    assert db.get_latest_model("m")["file_path"] == "/second"


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "Current behavior: mark_model_stale() targets version = MAX(version), and "
        "all registrations are version 1, so it marks EVERY registration of the "
        "model stale, not just the latest. Storage fix is out of scope."
    ),
)
def test_mark_model_stale_marks_only_latest_registration(db, sql):
    db.register_model("m", "ensemble", "/first")
    db.register_model("m", "ensemble", "/second")
    db.mark_model_stale("m")
    stale = {
        r["file_path"]: r["is_stale"] for r in sql("SELECT file_path, is_stale FROM model_registry")
    }
    assert stale == {"/first": 0, "/second": 1}


# ── metrics_5min ───────────────────────────────────────────────────────────


def test_upsert_metrics_5min_inserts_then_updates_same_window(db):
    assert db.upsert_metrics_5min(DEVICE_ID, "2026-01-01T00:00:00", 10, 1, 0.2, 0.5, 3, 2) is None
    db.upsert_metrics_5min(DEVICE_ID, "2026-01-01T00:00:00", 20, 4, 0.4, 0.9, 5, 3)
    rows = db.get_metrics_timeseries(DEVICE_ID, "2026-01-01T00:00:00", "2026-01-01T00:00:00")
    assert len(rows) == 1
    r = rows[0]
    assert set(r) == METRICS_KEYS
    assert (
        r["event_count"],
        r["anomaly_count"],
        r["avg_severity"],
        r["max_severity"],
        r["unique_ips"],
        r["unique_users"],
    ) == (20, 4, 0.4, 0.9, 5, 3)


def test_get_metrics_timeseries_range_is_inclusive_ordered_and_device_scoped(db):
    for ws in (
        "2026-01-01T00:10:00",
        "2026-01-01T00:00:00",
        "2026-01-01T00:05:00",
        "2026-01-01T00:15:00",
    ):
        db.upsert_metrics_5min(DEVICE_ID, ws, 1, 0, 0.0, 0.0, 0, 0)
    db.upsert_metrics_5min("other", "2026-01-01T00:05:00", 1, 0, 0.0, 0.0, 0, 0)
    rows = db.get_metrics_timeseries(DEVICE_ID, "2026-01-01T00:00:00", "2026-01-01T00:10:00")
    assert [r["window_start"] for r in rows] == [
        "2026-01-01T00:00:00",
        "2026-01-01T00:05:00",
        "2026-01-01T00:10:00",
    ]
    assert db.get_metrics_timeseries("ghost", "2026", "2027") == []


# ── threat intel cache ─────────────────────────────────────────────────────


def test_upsert_then_get_threat_intel(db):
    assert (
        db.upsert_threat_intel(
            "198.51.100.7",
            87,
            "ZZ",
            "isp",
            "example.test",
            is_tor=True,
            total_reports=4,
            raw_response='{"k":1}',
        )
        is None
    )
    ti = db.get_threat_intel("198.51.100.7")
    assert set(ti) == TI_KEYS
    assert (ti["abuse_score"], ti["country_code"], ti["is_tor"], ti["total_reports"]) == (
        87,
        "ZZ",
        1,
        4,
    )
    assert datetime.fromisoformat(ti["expires_at"]) > datetime.fromisoformat(ti["queried_at"])


def test_upsert_threat_intel_overwrites_existing_entry(db):
    db.upsert_threat_intel("198.51.100.7", 10)
    db.upsert_threat_intel("198.51.100.7", 99, country_code="YY")
    ti = db.get_threat_intel("198.51.100.7")
    assert (ti["abuse_score"], ti["country_code"], ti["is_tor"]) == (99, "YY", 0)


def test_get_threat_intel_missing_or_expired_returns_none(db):
    assert db.get_threat_intel("203.0.113.1") is None
    db.upsert_threat_intel("203.0.113.2", 50, cache_hours=0)  # expires now
    assert db.get_threat_intel("203.0.113.2") is None


def test_get_expiring_threat_intel_returns_entries_within_one_hour(db):
    db.upsert_threat_intel("203.0.113.1", 1, cache_hours=24)
    db.upsert_threat_intel("203.0.113.2", 2, cache_hours=0)
    db.upsert_threat_intel("203.0.113.3", 3, cache_hours=-2)
    expiring = db.get_expiring_threat_intel()
    assert [e["ip_address"] for e in expiring] == ["203.0.113.3", "203.0.113.2"]  # expires_at ASC
    assert all(set(e) == TI_KEYS for e in expiring)
    assert len(db.get_expiring_threat_intel(limit=1)) == 1


# ── IP geolocation ─────────────────────────────────────────────────────────


def test_get_unresolved_ips_lists_distinct_event_ips_without_geo(seeded):
    seeded.insert_events_batch(
        [
            make_event(source_ip="198.51.100.1"),
            make_event(source_ip="198.51.100.1"),
            make_event(source_ip="198.51.100.2"),
            make_event(source_ip=""),
            make_event(source_ip=None),
        ]
    )
    unresolved = seeded.get_unresolved_ips()
    assert isinstance(unresolved, list) and all(isinstance(ip, str) for ip in unresolved)
    assert sorted(unresolved) == ["198.51.100.1", "198.51.100.2"]
    assert len(seeded.get_unresolved_ips(limit=1)) == 1

    assert seeded.upsert_ip_geolocation("198.51.100.1", 1.5, 2.5, "City", "ZZ") is None
    assert seeded.get_unresolved_ips() == ["198.51.100.2"]


def test_upsert_ip_geolocation_overwrites(db, sql):
    db.upsert_ip_geolocation("198.51.100.1", 1.0, 2.0)
    db.upsert_ip_geolocation("198.51.100.1", 3.0, 4.0, "C", "YY")
    [row] = sql("SELECT * FROM ip_geolocation")
    assert (row["latitude"], row["longitude"], row["city"], row["country"]) == (3.0, 4.0, "C", "YY")
    datetime.fromisoformat(row["resolved_at"])


def test_get_unresolved_ips_empty(db):
    assert db.get_unresolved_ips() == []


# ── feature drift ──────────────────────────────────────────────────────────


def test_insert_then_get_drift_records(db, sql):
    assert db.insert_drift_record("m", "f1", 0.05, False) is None
    db.insert_drift_record("m", "f2", 0.31, True)
    db.insert_drift_record("other", "f1", 0.5, True)
    sql("UPDATE feature_drift SET measured_at='2000-01-01 00:00:00' WHERE feature_name='f1'")
    records = db.get_drift_records("m")
    assert [r["feature_name"] for r in records] == ["f2", "f1"]  # measured_at DESC
    assert all(set(r) == DRIFT_KEYS for r in records)
    assert records[0]["is_drifted"] == 1 and records[0]["psi_value"] == 0.31
    assert len(db.get_drift_records("m", limit=1)) == 1
    assert db.get_drift_records("nope") == []
