"""
API handlers never block the event loop on storage (M1 Sprint 2, S2-4).

Pins: while a handler's sync storage call is stuck (a 300 ms sleep injected
into it), a concurrent ``GET /api/health`` on the same event loop still answers
fast — the call runs in the threadpool, not on the loop. Detection admission is
still taken on the loop *before* the off-loop write and settled on the loop
after it. Moving check-then-act handlers off the loop does not let concurrent
requests double-spend a registration token or turn a duplicate username into a
500. SYNTHETIC data only.
"""

import asyncio
import threading
import time
import uuid
from datetime import datetime, timedelta
from unittest.mock import patch

import httpx
import pytest

from lsadra.detection.detection_worker import DetectionQueue, detection_queue
from tests.fixtures import setup_test_db

API_KEY = "demo-key-not-a-secret"
BATCH = {"events": [{"schema_version": "1", "timestamp": "2026-03-15T14:30:00Z",
                     "event_type": "auth_failure"}]}
RAW = {"lines": [{"raw_line": "Mar 15 14:30:00 demo-host sshd[1]: test"}]}
SLOW_S = 0.3
HEALTH_BUDGET_MS = 50.0


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


def _bearer(role: str) -> dict:
    from lsadra.auth import create_access_token

    return {"Authorization": "Bearer " + create_access_token("u-demo", "demo.user", role)}


def _client(client_ip: str = "192.0.2.10") -> httpx.AsyncClient:
    from server import app

    # In-process ASGI: the handler and /api/health share this test's event loop.
    transport = httpx.ASGITransport(app=app, client=(client_ip, 40000))
    return httpx.AsyncClient(transport=transport, base_url="http://lsadra.test")


def _slowed(real, started: threading.Event):
    def slow(*args, **kwargs):
        started.set()
        time.sleep(SLOW_S)  # stands in for a long SQLite write / lock wait
        return real(*args, **kwargs)
    return slow


async def _health_latency_while(request_coro, started: threading.Event):
    """Start *request_coro*; once its storage call is stuck, time /api/health."""
    async with _client() as client:
        slow_request = asyncio.ensure_future(request_coro(client))
        deadline = time.monotonic() + 5
        while not started.is_set():
            if slow_request.done() or time.monotonic() > deadline:
                raise AssertionError(f"slow storage call never started: {slow_request}")
            await asyncio.sleep(0.005)
        t0 = time.perf_counter()
        health = await client.get("/api/health")
        health_ms = (time.perf_counter() - t0) * 1000.0
        slow_request_done_during_health = slow_request.done()
        response = await slow_request
    return health, health_ms, slow_request_done_during_health, response


# ── the loop stays free while a handler's storage call is slow ───────────


def _case(name):
    """(patch target, real callable, request coroutine factory) per handler."""
    import lsadra.ingestion.api_ingestion as ingestion
    import lsadra.onboarding.device_registration as registration
    import lsadra.ui.api_dashboard as dashboard
    import server

    if name == "events/batch":
        headers = _device()
        return ("lsadra.ingestion.api_ingestion.store_batch_and_touch", ingestion.store_batch_and_touch,
                lambda c: c.post("/api/events/batch", json=BATCH, headers=headers))
    if name == "events/raw":
        headers = _device()
        return ("lsadra.ingestion.api_ingestion.store_batch_and_touch", ingestion.store_batch_and_touch,
                lambda c: c.post("/api/events/raw", json=RAW, headers=headers))
    if name == "heartbeat":
        device_id = _device()["X-Device-Id"]
        return ("server.record_heartbeat", server.record_heartbeat,
                lambda c: c.post("/heartbeat", json={"device_id": device_id}))
    if name == "auth/login":
        return ("server.get_user_by_username", server.get_user_by_username,
                lambda c: c.post("/api/auth/login", json={"username": "nobody", "password": "x"}))
    if name == "incidents":
        headers = _bearer("ANALYST")
        return ("server.get_all_incidents", server.get_all_incidents,
                lambda c: c.get("/api/incidents", headers=headers))
    if name == "dashboard/kpis":
        # ADMIN: the non-admin KPI query fails on main too (ambiguous column), unrelated here.
        headers = _bearer("ADMIN")
        return ("lsadra.ui.api_dashboard.get_dashboard_kpis", dashboard.get_dashboard_kpis,
                lambda c: c.get("/api/dashboard/kpis", headers=headers))
    if name == "devices/config":
        device_id = _device()["X-Device-Id"]
        return ("lsadra.onboarding.device_registration.get_device", registration.get_device,
                lambda c: c.get(f"/api/devices/config/{device_id}"))
    raise KeyError(name)


EXPECTED_STATUS = {
    "events/batch": 200, "events/raw": 200, "heartbeat": 200, "auth/login": 401,
    "incidents": 200, "dashboard/kpis": 200, "devices/config": 200,
}


@pytest.mark.parametrize("name", sorted(EXPECTED_STATUS))
def test_slow_storage_call_does_not_block_health(name):
    target, real, request = _case(name)
    started = threading.Event()
    with patch(target, _slowed(real, started)):
        health, health_ms, done_early, response = asyncio.run(
            _health_latency_while(request, started)
        )
    assert response.status_code == EXPECTED_STATUS[name], response.text
    assert health.status_code == 200
    # Health answered while the slow handler was still inside its storage call.
    assert not done_early, "the slow request finished before /api/health — nothing was measured"
    assert health_ms < HEALTH_BUDGET_MS, (
        f"/api/health took {health_ms:.1f} ms while {name}'s storage call slept "
        f"{SLOW_S * 1000:.0f} ms — the handler is blocking the event loop"
    )


# ── detection admission still precedes the (off-loop) write ──────────────


@pytest.mark.parametrize("path,body", [("/api/events/batch", BATCH), ("/api/events/raw", RAW)])
def test_detection_admission_precedes_the_off_loop_write(path, body):
    import lsadra.ingestion.api_ingestion as ingestion

    headers = _device()
    q = DetectionQueue(4)
    calls = []  # (step, thread name)
    real_reserve, real_commit, real_store = q.reserve, q.commit, ingestion.store_batch_and_touch

    def reserve(device_id):
        calls.append(("reserve", threading.current_thread().name))
        return real_reserve(device_id)

    def commit(device_id):
        calls.append(("commit", threading.current_thread().name))
        return real_commit(device_id)

    def store(device_id, rows):
        calls.append(("store", threading.current_thread().name))
        # The reservation is already held while the rows are being written.
        assert device_id in q._slots and q._slots[device_id] == 1
        return real_store(device_id, rows)

    async def scenario():
        loop_thread = threading.current_thread().name
        async with _client() as client:
            response = await client.post(path, json=body, headers=headers)
        return loop_thread, response

    with patch.object(q, "reserve", reserve), patch.object(q, "commit", commit), \
         patch("lsadra.ingestion.api_ingestion.detection_queue", q), \
         patch("lsadra.ingestion.api_ingestion.store_batch_and_touch", store):
        loop_thread, response = asyncio.run(scenario())

    assert response.status_code == 200, response.text
    assert [step for step, _ in calls] == ["reserve", "store", "commit"]
    threads = dict(calls)
    # The queue is loop-only state; the write is not on the loop.
    assert threads["reserve"] == threads["commit"] == loop_thread
    assert threads["store"] != loop_thread
    assert q.depth == 1


def test_failed_off_loop_write_releases_on_the_loop():
    headers = _device()
    q = DetectionQueue(1)
    released = []
    real_release = q.release

    def release(device_id):
        released.append(threading.current_thread().name)
        return real_release(device_id)

    async def scenario():
        async with _client() as client:
            return threading.current_thread().name, await client.post(
                "/api/events/batch", json=BATCH, headers=headers)

    with patch.object(q, "release", release), \
         patch("lsadra.ingestion.api_ingestion.detection_queue", q), \
         patch("lsadra.ingestion.api_ingestion.store_batch_and_touch",
               side_effect=RuntimeError("database is locked")):
        with pytest.raises(RuntimeError):  # ASGITransport re-raises the app error
            asyncio.run(scenario())

    assert len(released) == 1
    assert q.depth == 0 and q._slots == {}


# ── check-then-act handlers keep their in-process guarantees ─────────────


class _SlowClock(datetime):
    """Widens consume_token's read-then-update window (its utcnow() sits between them)."""

    @classmethod
    def utcnow(cls):
        time.sleep(0.05)
        return datetime.utcnow()


def test_concurrent_registrations_cannot_double_spend_one_token():
    from lsadra.storage.database import create_user, store_token

    create_user("u-reg", "reg.demo", "hash", "ANALYST")
    store_token("demo-token-not-a-secret", "u-reg", datetime.utcnow() + timedelta(hours=1))
    body = {"token": "demo-token-not-a-secret", "hostname": "demo-host-01", "os_type": "linux"}

    async def scenario():
        # 4 ≤ the per-IP registration limit (5/min); a TEST-NET address of its own.
        async with _client("198.51.100.77") as client:
            return await asyncio.gather(
                *(client.post("/api/devices/register", json=body) for _ in range(4)))

    with patch("lsadra.storage.database.datetime", _SlowClock):
        responses = asyncio.run(scenario())

    codes = sorted(r.status_code for r in responses)
    assert codes == [200, 400, 400, 400], [r.text for r in responses]


def test_concurrent_signups_for_one_username_are_one_200_and_400s_never_500():
    async def scenario():
        async with _client() as client:
            return await asyncio.gather(*(
                client.post("/api/auth/register", json={"username": "race.demo", "password": "pw-demo"})
                for _ in range(4)))

    responses = asyncio.run(scenario())
    codes = sorted(r.status_code for r in responses)
    assert codes == [200, 400, 400, 400], [r.text for r in responses]
    assert all(r.json()["detail"] == "Username already taken." for r in responses if r.status_code == 400)
