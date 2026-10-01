"""
Detection off the ingestion request path (M1 Sprint 2, S2-1).

Pins: ingestion only enqueues; one worker runs detection on its own thread;
duplicates coalesce per device; a full queue is a 503 + Retry-After with
nothing stored; the worker survives a failing run and shuts down cleanly;
BENCH_SKIP_DETECTION bypasses the queue. SYNTHETIC data only.
"""

import asyncio
import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lsadra.detection.detection_worker import DetectionQueue, detection_queue
from tests.fixtures import setup_test_db

REPO_ROOT = Path(__file__).resolve().parents[1]
API_KEY = "demo-key-not-a-secret"
BATCH = {"events": [{"schema_version": "1", "timestamp": "2026-03-15T14:30:00Z",
                     "event_type": "auth_failure"}]}


@pytest.fixture(autouse=True)
def _isolated(tmp_path):
    setup_test_db(tmp_path)
    detection_queue.reset()
    yield
    detection_queue.reset()


def _device() -> dict:
    """Fresh device per test (the per-device rate limiter is process-global)."""
    from lsadra.storage.database import create_device, create_user

    user_id, device_id = f"u-{uuid.uuid4().hex[:8]}", f"dev-{uuid.uuid4().hex[:8]}"
    create_user(user_id, f"{user_id}.demo", "hash", "ANALYST")
    create_device(device_id, user_id, "demo-host-01", "linux", API_KEY)
    return {"X-Device-Id": device_id, "X-API-Key": API_KEY}


def _client():
    from fastapi.testclient import TestClient
    from server import app
    return TestClient(app, raise_server_exceptions=False)


def _enqueue(q: DetectionQueue, device_id: str) -> None:
    assert q.reserve(device_id)
    q.commit(device_id)


async def _until(predicate, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached in time")
        await asyncio.sleep(0.01)


# ── queue semantics ──────────────────────────────────────────────────────


def test_size_below_one_is_rejected():
    # asyncio.Queue(0) would be unbounded; the bound must never silently vanish.
    with pytest.raises(ValueError):
        DetectionQueue(0)


def test_env_size_below_one_refuses_to_boot():
    env = {**os.environ, "LSADRA_DEV_MODE": "true", "LSADRA_DETECTION_QUEUE_SIZE": "0"}
    proc = subprocess.run([sys.executable, "-c", "import lsadra.config"], cwd=REPO_ROOT,
                          env=env, capture_output=True, text=True, timeout=60)
    assert proc.returncode != 0
    assert "LSADRA_DETECTION_QUEUE_SIZE" in proc.stderr


def test_enqueue_coalesces_per_device_fifo_by_first_enqueue():
    q = DetectionQueue(4)
    for dev in ("a", "b", "a", "c", "b", "a"):
        _enqueue(q, dev)
    assert q.depth == 3
    assert [q._queue.get_nowait() for _ in range(3)] == ["a", "b", "c"]
    assert q.stats["coalesced"] == 3


def test_full_queue_refuses_new_devices_but_admits_pending_ones():
    q = DetectionQueue(2)
    _enqueue(q, "a")
    _enqueue(q, "b")
    assert q.reserve("c") is False          # new device, no slot
    assert q.reserve("a") is True           # already pending: coalesces, no slot used
    q.commit("a")
    assert q.depth == 2 and q.stats["rejected"] == 1


def test_release_returns_an_unused_slot():
    q = DetectionQueue(1)
    assert q.reserve("a")
    q.release("a")                          # write failed
    assert q.depth == 0 and q.reserve("b")  # slot is free again


def test_commit_without_reservation_is_a_bug():
    with pytest.raises(RuntimeError):
        DetectionQueue(1).commit("a")


def test_batch_committed_during_a_run_schedules_another_run():
    q = DetectionQueue(1)
    _enqueue(q, "a")
    assert q.reserve("a")                   # handler for "a" mid-write ...
    q._take(q._queue.get_nowait())          # ... while the worker takes "a"
    assert q.reserve("b") is False          # "a" still holds its slot
    q.commit("a")                           # the write lands: "a" is queued again
    assert q.depth == 1 and q._queue.get_nowait() == "a"


# ── worker ───────────────────────────────────────────────────────────────


def test_worker_runs_once_per_device_per_drain_on_its_own_thread():
    calls = []

    def run(device_id):
        calls.append((device_id, threading.current_thread().name))

    async def scenario():
        q = DetectionQueue(8)
        for dev in ("a", "a", "b", "a", "b"):
            _enqueue(q, dev)
        q.start(run)
        await _until(lambda: q.stats["runs"] == 2)
        await asyncio.sleep(0.05)
        await q.stop()
        return q

    q = asyncio.run(scenario())
    assert [dev for dev, _ in calls] == ["a", "b"]
    assert all(name.startswith("lsadra-detect") for _, name in calls)
    assert threading.main_thread().name not in {name for _, name in calls}
    assert q.depth == 0


def test_worker_survives_an_orchestrator_exception(caplog):
    calls = []

    def run(device_id):
        calls.append(device_id)
        if device_id == "bad":
            raise RuntimeError("model exploded")

    async def scenario():
        q = DetectionQueue(8)
        _enqueue(q, "bad")
        _enqueue(q, "good")
        q.start(run)
        await _until(lambda: q.stats["runs"] == 1 and q.stats["failures"] == 1)
        alive = q.running
        _enqueue(q, "bad")                   # still accepting and draining afterwards
        await _until(lambda: q.stats["failures"] == 2)
        await q.stop()
        return alive

    with caplog.at_level("ERROR"):
        assert asyncio.run(scenario()) is True
    assert calls == ["bad", "good", "bad"]
    assert "Online detection failed for device bad" in caplog.text


def test_shutdown_cancels_cleanly_and_waits_for_the_in_flight_run():
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()

    def run(device_id):
        entered.set()
        release.wait(5)
        finished.set()

    async def scenario():
        q = DetectionQueue(4)
        _enqueue(q, "a")
        q.start(run)
        await _until(entered.is_set)
        task = q._task
        threading.Timer(0.2, release.set).start()
        await q.stop(timeout=5)
        return q, task

    q, task = asyncio.run(scenario())
    assert task.cancelled() and not q.running
    assert finished.is_set()                 # the run was not torn down mid-write
    # A later lifespan (new loop) can start again and drains what is pending.
    seen = []

    async def again():
        _enqueue(q, "b")
        q.start(seen.append)
        await _until(lambda: seen == ["b"])
        await q.stop()

    asyncio.run(again())


def test_idle_worker_stops_immediately():
    async def scenario():
        q = DetectionQueue(4)
        q.start(lambda d: None)
        t0 = time.monotonic()
        await q.stop()
        return time.monotonic() - t0, q

    elapsed, q = asyncio.run(scenario())
    assert elapsed < 2 and not q.running


# ── ingestion endpoints ──────────────────────────────────────────────────


def test_ingest_enqueues_and_never_runs_detection_inline():
    headers = _device()
    with patch("lsadra.ingestion.api_ingestion._get_orchestrator") as get_orch:
        response = _client().post("/api/events/batch", json=BATCH, headers=headers)
    assert response.status_code == 200, response.text
    get_orch.assert_not_called()             # no worker in this client: nothing ran
    assert detection_queue.depth == 1


def test_handler_returns_while_detection_is_still_running_end_to_end():
    """Real lifespan + worker: the response must not wait for a slow detection run."""
    from fastapi.testclient import TestClient
    from server import app

    headers = _device()
    started, release = threading.Event(), threading.Event()
    seen = {}

    def slow_run(device_id):
        seen["device"], seen["thread"] = device_id, threading.current_thread().name
        started.set()
        release.wait(10)

    orchestrator = MagicMock()
    orchestrator.run_for_new_events.side_effect = slow_run
    with patch("lsadra.ingestion.api_ingestion._get_orchestrator", return_value=orchestrator):
        with TestClient(app) as client:
            try:
                response = client.post("/api/events/batch", json=BATCH, headers=headers)
                assert response.status_code == 200, response.text
                assert started.wait(5), "worker never ran detection"
                assert not release.is_set()  # detection still running, response already back
                health = client.get("/api/health")
                assert health.status_code == 200  # loop free while detection runs
            finally:
                release.set()
    assert seen["device"] == headers["X-Device-Id"]
    assert seen["thread"].startswith("lsadra-detect")
    orchestrator.run_for_new_events.assert_called_once_with(device_id=headers["X-Device-Id"])


@pytest.mark.parametrize("path,body", [
    ("/api/events/batch", BATCH),
    ("/api/events/raw", {"lines": [{"raw_line": "Mar 15 14:30:00 demo-host sshd[1]: test"}]}),
])
def test_full_queue_is_503_with_retry_after_and_nothing_stored(path, body):
    from lsadra.storage.database import get_events_since

    blocker = _device()["X-Device-Id"]
    headers = _device()
    full = DetectionQueue(1)
    _enqueue(full, blocker)
    with patch("lsadra.ingestion.api_ingestion.detection_queue", full), \
         patch("lsadra.ingestion.api_ingestion.insert_events_batch") as insert:
        response = _client().post(path, json=body, headers=headers)
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "5"
    insert.assert_not_called()
    assert get_events_since(headers["X-Device-Id"], after_id=0) == []
    assert full.stats["rejected"] == 1


def test_full_queue_still_admits_a_device_already_pending():
    headers = _device()
    full = DetectionQueue(1)
    _enqueue(full, headers["X-Device-Id"])
    with patch("lsadra.ingestion.api_ingestion.detection_queue", full):
        response = _client().post("/api/events/batch", json=BATCH, headers=headers)
    assert response.status_code == 200, response.text
    assert full.depth == 1 and full.stats["coalesced"] == 1


def test_failed_write_releases_the_reservation():
    headers = _device()
    q = DetectionQueue(1)
    with patch("lsadra.ingestion.api_ingestion.detection_queue", q), \
         patch("lsadra.ingestion.api_ingestion.insert_events_batch",
               side_effect=RuntimeError("database is locked")):
        response = _client().post("/api/events/batch", json=BATCH, headers=headers)
    assert response.status_code == 500
    assert q.depth == 0 and q._slots == {}


def test_bench_skip_detection_bypasses_the_queue():
    headers = _device()
    full = DetectionQueue(1)
    _enqueue(full, "someone-else")
    with patch("lsadra.ingestion.api_ingestion.BENCH_SKIP_DETECTION", True), \
         patch("lsadra.ingestion.api_ingestion.detection_queue", full):
        response = _client().post("/api/events/batch", json=BATCH, headers=headers)
    assert response.status_code == 200, response.text   # full queue never consulted
    assert full.stats == {"admitted": 1, "coalesced": 0, "rejected": 0, "runs": 0, "failures": 0}
