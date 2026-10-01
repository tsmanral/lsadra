"""Contract: concurrent writers (N threads inserting event batches).

The storage layer opens one connection per call with no writer serialization.
A writer that cannot get the write lock within the busy timeout raises
``sqlite3.OperationalError: database is locked`` and loses its batch.

History of the high-contention case (same load both times: 32 threads, each
batch sized so the serialized write time of all threads is ~15 s):
  * Sprint 1 (kickoff C): sqlite3's default 5 s busy timeout -> 17-20/32
    writers hit ``database is locked`` (strict xfail).
  * Sprint 2 S2-3: ``get_connection()`` sets a 30 s busy timeout,
    ``synchronous=NORMAL`` and no longer re-issues the WAL pragma, and
    ``insert_events_batch`` is one ``executemany`` -> all 32 commit. Marker
    removed. Measured first-lock threshold (Windows dev box, Python 3.14,
    C's sweep: threads x batch size, 1 batch/thread, fresh DB per point,
    threads 8..1024, 3 runs; range = first locking thread count across runs):
      batch rows | before (5 s)  | after (30 s)
      100        | 128-160       | 1024 in 2/3 runs, none <=1024 in 1/3
      1,000      | 96-128        | 1024 in 1/3 runs, none <=1024 in 2/3
      5,000      | 64            | 768-1024
      20,000     | 32            | 256
    i.e. the lock now appears only once the queued writers' wall time
    approaches the 30 s timeout.

Two tests:
  * moderate concurrency (well under the timeout) must succeed;
  * high contention (C's load, sized against the *old* 5 s timeout) must also
    succeed — the regression pin for S2-3. It does not claim unlimited
    concurrency: by pigeonhole, any load whose serialized write time exceeds
    the busy timeout still locks (single-writer queue is a separate decision).

The high-contention load is self-calibrating: it measures this machine's
single-thread batch cost first and sizes each batch so that the serialized
write time of all threads is ~SERIAL_LOAD_S, independent of runner speed.
"""

import math
import sqlite3
import threading
import time

import pytest

from tests.storage._support import DEVICE_ID, make_event

CONTENTION_THREADS = 32
# C's load: 3x the old 5 s default timeout. Kept fixed so the pin means "the
# load that locked in Sprint 1 no longer does"; half the current timeout.
SERIAL_LOAD_S = 15.0
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


def test_high_contention_batch_writers_do_not_lock(seeded, sql):
    assert seeded.BUSY_TIMEOUT_S >= 2 * SERIAL_LOAD_S, "load must stay well under the timeout"
    # Calibrate: single-thread cost per row on this machine (warm run).
    probe = _batch(5_000)
    seeded.insert_events_batch(probe)
    t0 = time.perf_counter()
    seeded.insert_events_batch(probe)
    per_row = (time.perf_counter() - t0) / len(probe)
    target_batch_s = SERIAL_LOAD_S / (CONTENTION_THREADS - 1)
    size = min(MAX_BATCH_ROWS, max(5_000, math.ceil(target_batch_s / per_row)))
    baseline_rows = _row_count(sql)

    started = time.perf_counter()
    ok, lock_errors, other_errors = _run_writers(seeded, CONTENTION_THREADS, 1, _batch(size))
    elapsed = time.perf_counter() - started

    if other_errors:  # anything but a lock error is a different failure
        pytest.fail(f"unexpected writer errors: {other_errors[:3]}")
    # Failed batches must not leave partial rows behind.
    assert _row_count(sql) - baseline_rows == ok * size
    assert lock_errors == [], (
        f"{len(lock_errors)}/{CONTENTION_THREADS} writers hit 'database is locked' "
        f"(batch={size} rows, ~{size * per_row:.3f}s single-thread, "
        f"{ok} batches committed, wall {elapsed:.1f}s)"
    )
    assert ok == CONTENTION_THREADS
