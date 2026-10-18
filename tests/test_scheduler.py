"""
Background scheduler activation (M1, after Sprint 2).

Pins: the app lifespan starts and stops the scheduler (behind
LSADRA_SCHEDULER_ENABLED); every job runs one instance at a time with missed
runs coalesced; retention runs on an interval with an early first run; IP
geolocation (third-party egress) only runs when opted in; the time-window jobs
compare against the format timestamps are stored in. SYNTHETIC data only.
"""

import logging
from datetime import datetime, timedelta, timezone

import pytest

import lsadra.config as config
from lsadra.jobs import scheduler
from tests.storage._support import make_event
from tests.storage.conftest import db, seeded, sql  # noqa: F401 — shared fixtures

CORE_JOBS = {
    "metrics_aggregation",
    "device_offline_check",
    "threat_intel_refresh",
    "drift_detection",
    "data_cleanup",
    "cross_source_correlation",
    "lateral_movement_scan",
    "ingestion_health_check",
}


@pytest.fixture
def running(monkeypatch):
    """Start the real scheduler; always stop it, so no thread outlives a test."""

    def start(geo: bool = False):
        monkeypatch.setattr(config, "GEO_RESOLUTION_ENABLED", geo)
        scheduler.start_scheduler()
        return scheduler._scheduler

    yield start
    scheduler.stop_scheduler()


def test_start_registers_the_core_jobs_without_geo_by_default(running):
    sched = running()
    assert sched.running
    assert {job.id for job in sched.get_jobs()} == CORE_JOBS


def test_geo_resolution_runs_only_when_opted_in(running):
    sched = running(geo=True)
    assert {job.id for job in sched.get_jobs()} == CORE_JOBS | {"geo_resolution"}


def test_every_job_is_single_instance_and_coalesced(running):
    for job in running().get_jobs():
        assert job.max_instances == 1, job.id
        assert job.coalesce is True, job.id


def test_retention_runs_on_an_interval_with_an_early_first_run(running, monkeypatch):
    before = datetime.now(timezone.utc)
    job = running().get_job("data_cleanup")
    assert job.trigger.interval == timedelta(minutes=config.RETENTION_INTERVAL_MINUTES)
    first = job.next_run_time
    assert before + timedelta(seconds=30) <= first <= before + timedelta(minutes=2)


def test_start_is_idempotent_and_stop_clears_it(running):
    sched = running()
    scheduler.start_scheduler()
    assert scheduler._scheduler is sched
    scheduler.stop_scheduler()
    assert scheduler._scheduler is None
    assert not sched.running
    scheduler.stop_scheduler()  # stopping twice is harmless


@pytest.mark.parametrize("enabled", [True, False])
def test_lifespan_starts_and_stops_the_scheduler_behind_the_flag(enabled, monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    import server
    from tests.fixtures import setup_test_db

    setup_test_db(tmp_path)
    calls = []
    monkeypatch.setattr(config, "SCHEDULER_ENABLED", enabled)
    monkeypatch.setattr(server, "start_scheduler", lambda: calls.append("start"))
    monkeypatch.setattr(server, "stop_scheduler", lambda: calls.append("stop"))

    with TestClient(server.app) as client:
        assert client.get("/api/health").status_code == 200
        assert calls == (["start"] if enabled else [])
    assert calls == (["start", "stop"] if enabled else [])


def test_data_cleanup_job_runs_bounded_retention(seeded, sql, monkeypatch):  # noqa: F811
    monkeypatch.setattr(seeded, "RETENTION_DAYS", 30)
    monkeypatch.setattr(seeded, "RETENTION_BATCH_SIZE", 2)
    monkeypatch.setattr(seeded.time, "sleep", lambda _s: None)
    seeded.insert_events_batch([make_event(timestamp="2000-01-01T00:00:00") for _ in range(5)])

    scheduler._run_data_cleanup()

    assert sql("SELECT COUNT(*) AS n FROM normalized_events")[0]["n"] == 0


def _stored_ts(**ago) -> str:
    # Exactly what ingestion stores: isoformat() of a UTC-aware timestamp.
    return (datetime.now(timezone.utc) - timedelta(**ago)).isoformat()


def test_iso_cutoff_compares_correctly_with_stored_timestamps():
    cutoff = scheduler._iso_cutoff(minutes=10)
    assert _stored_ts(minutes=1) >= cutoff
    assert _stored_ts(minutes=20) < cutoff


def test_cross_source_correlation_ignores_events_outside_its_window(seeded, caplog):  # noqa: F811
    # Two source types from one IP, but 20 minutes ago: outside the 10 min window.
    # (SQLite's datetime('now', ...) used to match every event from the same day.)
    ip = "198.51.100.7"
    seeded.insert_events_batch(
        [
            make_event(timestamp=_stored_ts(minutes=20), source_ip=ip, event_type="ssh_login"),
            make_event(timestamp=_stored_ts(minutes=20), source_ip=ip, event_type="connection"),
        ]
    )
    with caplog.at_level(logging.INFO, logger=scheduler.logger.name):
        scheduler._run_cross_source_correlation()
    assert ip not in caplog.text


def test_cross_source_correlation_reports_recent_multi_source_activity(seeded, caplog):  # noqa: F811
    ip = "198.51.100.8"
    seeded.insert_events_batch(
        [
            make_event(timestamp=_stored_ts(minutes=1), source_ip=ip, event_type="ssh_login"),
            make_event(timestamp=_stored_ts(minutes=1), source_ip=ip, event_type="connection"),
        ]
    )
    with caplog.at_level(logging.INFO, logger=scheduler.logger.name):
        scheduler._run_cross_source_correlation()
    assert f"Cross-source correlation: {ip} active in 2 source types" in caplog.text
    assert "job failed" not in caplog.text


def test_lateral_movement_scan_only_considers_ips_inside_its_window(seeded, monkeypatch):  # noqa: F811
    scanned = []
    monkeypatch.setattr(
        "lsadra.detection.rule_engine.detect_lateral_movement",
        lambda conn, ip: scanned.append(ip),
    )
    seeded.insert_events_batch(
        [
            make_event(timestamp=_stored_ts(minutes=5), source_ip="198.51.100.9"),
            make_event(timestamp=_stored_ts(minutes=45), source_ip="198.51.100.10"),
        ]
    )
    scheduler._run_lateral_movement_scan()
    assert scanned == ["198.51.100.9"]


@pytest.mark.parametrize(
    "job",
    [
        "_run_metrics_aggregation",
        "_run_device_offline_check",
        "_run_threat_intel_refresh",
        "_run_drift_detection",
        "_run_data_cleanup",
        "_run_cross_source_correlation",
        "_run_lateral_movement_scan",
        "_run_ingestion_health_check",
    ],
)
def test_each_core_job_runs_cleanly_against_a_real_database(job, seeded, caplog):  # noqa: F811
    # Activation means these now run for real: none may fail on a fresh schema.
    seeded.insert_event(make_event(timestamp=_stored_ts(minutes=1)))
    with caplog.at_level(logging.ERROR):
        getattr(scheduler, job)()
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR], caplog.text
