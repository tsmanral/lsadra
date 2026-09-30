"""Contract: concurrent writers (N threads inserting event batches).

The storage layer opens one connection per call with sqlite3's default 5 s busy
timeout and no writer serialization. Under enough concurrent batch writers the
waiters exceed that timeout and ``insert_events_batch`` raises
``sqlite3.OperationalError: database is locked``, losing the batch.

Two tests:
  * moderate concurrency (well under the timeout) must succeed — this passes on
    current code and pins that the per-call model is safe at low contention;
  * high contention must also succeed — it FAILS on current code and is a strict
    xfail. When Sprint 2 lands a real write model (single-writer queue, longer
    busy timeout, ...) it will XPASS, and strict mode forces the marker's removal.

The high-contention load is self-calibrating: it measures this machine's
single-thread batch cost first and sizes each batch so that the serialized
write time of all threads is ~3x the busy timeout. By pigeonhole, at least one
waiter must then exceed the timeout, so the failure is deterministic regardless
of runner speed, while wall time stays ~timeout (timed-out waiters give up).
"""

import math
import sqlite3
import threading
import time

import pytest

from tests.storage._support import DEVICE_ID, make_event

BUSY_TIMEOUT_S = 5.0  # sqlite3.connect() default; pinned in test_schema.py
CONTENTION_THREADS = 32
SERIAL_LOAD_FACTOR = 3.0  # serialized write time / busy timeout
MAX_BATCH_ROWS = 200_000


def _batch(n):
    # Tiny rows keep the temp DB small; one shared list keeps memory flat.
    return [make_event(raw_message="m", attributes={}, source_ip=None) for _ in range(n)]


def _run_writers(db, n_threads, batches_per_thread, batch):
    """Start n_threads writers together; return (ok_batches, lock_errors, other_errors)."""
    barrier = threading.Barrier(n_threads)
    lock = threading.Lock()
    ok, lock_errors, other_errors = [0], [], []

    def worker():
        barrier.wait()
        for _ in range(batches_per_thread):
            try:
                db.insert_events_batch(batch)
                with lock:
                    ok[0] += 1
            except sqlite3.OperationalError as exc:
                with lock:
                    (lock_errors if "locked" in str(exc) else other_errors).append(repr(exc))
            except Exception as exc:  # noqa: BLE001 — surfaced below as a hard failure
                with lock:
                    other_errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return ok[0], lock_errors, other_errors


def _row_count(sql):
    return sql("SELECT COUNT(*) AS n FROM normalized_events")[0]["n"]


def test_moderate_concurrent_batch_writers_do_not_lock(seeded, sql):
    n_threads, batches, size = 8, 10, 100
    ok, lock_errors, other_errors = _run_writers(seeded, n_threads, batches, _batch(size))
    assert other_errors == []
    assert lock_errors == []
    assert ok == n_threads * batches
    assert _row_count(sql) == n_threads * batches * size


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "Current code: per-call connections, default 5 s busy timeout, no writer "
        "serialization. 32 threads each writing one batch sized so serialized "
        "write time is ~3x the timeout -> waiters exceed 5 s and "
        "insert_events_batch raises 'database is locked' (batch lost). Sprint 2 "
        "write-model input; do not fix storage in the contract suite."
    ),
)
def test_high_contention_batch_writers_do_not_lock(seeded, sql):
    # Calibrate: single-thread cost per row on this machine (warm run).
    probe = _batch(5_000)
    seeded.insert_events_batch(probe)
    t0 = time.perf_counter()
    seeded.insert_events_batch(probe)
    per_row = (time.perf_counter() - t0) / len(probe)
    target_batch_s = SERIAL_LOAD_FACTOR * BUSY_TIMEOUT_S / (CONTENTION_THREADS - 1)
    size = min(MAX_BATCH_ROWS, max(5_000, math.ceil(target_batch_s / per_row)))
    baseline_rows = _row_count(sql)

    started = time.perf_counter()
    ok, lock_errors, other_errors = _run_writers(seeded, CONTENTION_THREADS, 1, _batch(size))
    elapsed = time.perf_counter() - started

    if other_errors:  # anything but a lock error is a real failure, not the xfail
        pytest.fail(f"unexpected writer errors: {other_errors[:3]}")
    # Failed batches must not leave partial rows behind.
    assert _row_count(sql) - baseline_rows == ok * size
    assert lock_errors == [], (
        f"{len(lock_errors)}/{CONTENTION_THREADS} writers hit 'database is locked' "
        f"(batch={size} rows, ~{size * per_row:.3f}s single-thread, "
        f"{ok} batches committed, wall {elapsed:.1f}s)"
    )
    assert ok == CONTENTION_THREADS
