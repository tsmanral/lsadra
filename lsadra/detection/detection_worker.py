"""
Online detection off the ingestion request path (M1 Sprint 2, D6).

Ingestion handlers never run detection. They hand the device id to the
process-wide :data:`detection_queue`; one worker task, started and stopped by
``server.py``'s lifespan, drains it and runs the synchronous orchestrator on a
single dedicated thread, so the event loop is never blocked by ML work.

Admission protocol — every call below runs on the event-loop thread:

``reserve(device_id)``
    Before the batch is written. ``False`` means the queue is full: the handler
    answers 503 + ``Retry-After`` and writes nothing, so the client's retry of
    the whole batch can never duplicate events.
``commit(device_id)``
    After the rows are committed: schedules detection for the device.
``release(device_id)``
    The write failed: gives the reservation back.

Capacity counts *distinct devices*. A device holds one slot from its first
reservation until the worker takes it off the queue; further batches for it
coalesce into that slot, so a device never waits in the queue twice. Because
every committed device already holds a slot, the bounded ``asyncio.Queue`` can
never be full at ``commit`` time. Order is FIFO by first commit.

The worker removes a device from the pending set *before* running detection, so
a batch committed during a run schedules one more run and no committed event is
left unscheduled. The orchestrator's per-device throttle
(``DETECTION_THROTTLE_SECONDS``) still applies inside ``run_for_new_events``,
exactly as it did when detection ran inline.
"""

from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from typing import Callable, Dict, Optional, Set

from lsadra.config import DETECTION_QUEUE_SIZE

logger = logging.getLogger(__name__)

DetectionRun = Callable[[str], None]


class DetectionQueue:
    """Bounded, per-device-coalescing queue plus its single detection worker."""

    def __init__(self, maxsize: int) -> None:
        if maxsize < 1:
            # asyncio.Queue(0) is *unbounded*; never let a bad setting mean that.
            raise ValueError(f"detection queue size must be >= 1, got {maxsize}")
        self.maxsize = maxsize
        self._queue: "asyncio.Queue[str]" = asyncio.Queue(maxsize)
        # device_id → handlers between reserve() and commit()/release().
        # Key presence == the device holds a slot.
        self._slots: Dict[str, int] = {}
        self._queued: Set[str] = set()  # devices in _queue, not yet taken
        self._task: Optional["asyncio.Task[None]"] = None
        self._executor: Optional[ThreadPoolExecutor] = None
        self.stats: Dict[str, int] = {
            "admitted": 0, "coalesced": 0, "rejected": 0, "runs": 0, "failures": 0,
        }

    # ── admission (request handlers) ─────────────────────────────────────

    def reserve(self, device_id: str) -> bool:
        """Admit one batch for *device_id*; ``False`` when the queue is full."""
        if device_id in self._slots:
            self._slots[device_id] += 1
            self.stats["coalesced"] += 1
            return True
        if len(self._slots) >= self.maxsize:
            self.stats["rejected"] += 1
            return False
        self._slots[device_id] = 1
        self.stats["admitted"] += 1
        return True

    def commit(self, device_id: str) -> None:
        """The reserved batch is committed: schedule detection for the device."""
        self._end_reservation(device_id)
        if device_id not in self._queued:
            self._queued.add(device_id)
            self._queue.put_nowait(device_id)  # cannot raise: slot already held

    def release(self, device_id: str) -> None:
        """The reserved batch was not written: return the slot if unused."""
        self._end_reservation(device_id)
        if self._slots[device_id] == 0 and device_id not in self._queued:
            del self._slots[device_id]

    def _end_reservation(self, device_id: str) -> None:
        if self._slots.get(device_id, 0) < 1:
            raise RuntimeError(f"no open detection reservation for device {device_id!r}")
        self._slots[device_id] -= 1

    def _take(self, device_id: str) -> None:
        """Worker took *device_id*: later batches need (and get) a new entry."""
        self._queued.discard(device_id)
        if self._slots.get(device_id) == 0:
            del self._slots[device_id]
        # else: a handler for this device is mid-write; its commit() re-queues.

    @property
    def depth(self) -> int:
        """Devices waiting for a detection run."""
        return len(self._queued)

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    # ── worker lifecycle (server lifespan) ───────────────────────────────

    def start(self, run: DetectionRun) -> None:
        """Start the worker on the running loop. *run* executes on its thread."""
        if self.running:
            raise RuntimeError("detection worker already running")
        # asyncio.Queue binds to the loop that first waits on it; a new lifespan
        # (new loop) gets a fresh queue carrying over anything still pending.
        old, self._queue = self._queue, asyncio.Queue(self.maxsize)
        while not old.empty():
            self._queue.put_nowait(old.get_nowait())
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="lsadra-detect")
        self._task = asyncio.get_running_loop().create_task(
            self._drain(run, self._executor), name="lsadra-detection-worker"
        )
        logger.info("Detection worker started (queue size %d).", self.maxsize)

    async def stop(self, timeout: float = 30.0) -> None:
        """Cancel the worker; wait up to *timeout* s for an in-flight run."""
        task, self._task = self._task, None
        executor, self._executor = self._executor, None
        if task is not None:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        if executor is not None:
            # A run already on the thread cannot be interrupted; let it finish
            # off the loop rather than tear the process down mid-write.
            waiter = asyncio.get_running_loop().run_in_executor(None, executor.shutdown, True)
            try:
                await asyncio.wait_for(waiter, timeout)
            except asyncio.TimeoutError:
                logger.warning("Detection run still in flight after %.0fs at shutdown.", timeout)
        if self._queued:
            logger.warning(
                "Detection worker stopped with %d device(s) pending; their events are "
                "stored and are picked up on the device's next batch.", len(self._queued),
            )
        logger.info("Detection worker stopped (%s).", self.stats)

    async def _drain(self, run: DetectionRun, executor: ThreadPoolExecutor) -> None:
        loop = asyncio.get_running_loop()
        while True:
            device_id = await self._queue.get()
            self._take(device_id)
            try:
                await loop.run_in_executor(executor, run, device_id)
                self.stats["runs"] += 1
            except Exception:
                # One device's failure must never stop detection for the rest.
                self.stats["failures"] += 1
                logger.exception("Online detection failed for device %s", device_id)

    # ── tests ────────────────────────────────────────────────────────────

    def reset(self) -> None:
        """Drop all pending state (test isolation only; worker must be stopped)."""
        if self.running:
            raise RuntimeError("stop the detection worker before reset()")
        self._queue = asyncio.Queue(self.maxsize)
        self._slots.clear()
        self._queued.clear()
        for key in self.stats:
            self.stats[key] = 0


detection_queue = DetectionQueue(DETECTION_QUEUE_SIZE)
