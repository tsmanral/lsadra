"""
Opt-in per-request tracing for the benchmark server (``run_ingest_bench.py --trace``).

Installed by ``_bench_server.py`` before uvicorn starts; product code is not
changed. It wraps, from the outside:

* the ASGI app, for ``POST /api/events/batch``: server-side start/end of each
  request, keyed by the harness's ``x-bench-request-id`` header;
* ``get_device`` and ``_checkpw`` (device auth) and ``store_batch_and_touch``
  (storage, recorded with when its threadpool call actually started);
* the online-detection entry point, for when each detection run started and
  ended;
* Python's garbage collector (``gc.callbacks``), for every collection and how
  long it took. A collection holds the GIL, so every thread waits it out.

Records go to a JSON-lines file as they happen. Times are ``time.time()``, the
same clock the harness reads, so the harness can line requests up with
detection runs and collections.
"""

from __future__ import annotations

import contextvars
import gc
import json
import threading
import time
from typing import Any, Dict, Optional

_current: "contextvars.ContextVar[Optional[Dict[str, Any]]]" = contextvars.ContextVar(
    "bench_trace_request", default=None
)


class _Sink:
    def __init__(self, path: str) -> None:
        self._file = open(path, "a", encoding="utf-8", buffering=1)
        self._lock = threading.Lock()

    def write(self, record: Dict[str, Any]) -> None:
        line = json.dumps(record, separators=(",", ":"))
        with self._lock:
            self._file.write(line + "\n")


def _timed(sink: _Sink, name: str, fn):
    def wrapper(*args, **kwargs):
        started = time.time()
        try:
            return fn(*args, **kwargs)
        finally:
            ended = time.time()
            req = _current.get()
            if req is not None:
                req.setdefault("calls", []).append(
                    [name, round(started, 6), round(ended, 6), threading.current_thread().name]
                )
            elif name == "checkpw":  # background refresh-ahead re-verify
                sink.write({"kind": "refresh", "t0": started, "t1": ended})

    return wrapper


def install(path: str, server_module: Any) -> Any:
    """Patch the core for tracing; returns the ASGI app to serve."""
    import lsadra.ingestion.api_ingestion as ingestion

    sink = _Sink(path)
    ingestion.get_device = _timed(sink, "get_device", ingestion.get_device)
    ingestion._checkpw = _timed(sink, "checkpw", ingestion._checkpw)
    ingestion.store_batch_and_touch = _timed(sink, "store", ingestion.store_batch_and_touch)

    detect = server_module.run_online_detection

    def traced_detection(device_id: str) -> None:
        started = time.time()
        try:
            detect(device_id)
        finally:
            sink.write({"kind": "detection", "t0": started, "t1": time.time()})

    server_module.run_online_detection = traced_detection

    gc_started: Dict[str, float] = {}

    def on_gc(phase: str, info: Dict[str, Any]) -> None:
        if phase == "start":
            gc_started["t"] = time.time()
        elif "t" in gc_started:
            sink.write({"kind": "gc", "gen": info.get("generation"),
                        "t0": gc_started.pop("t"), "t1": time.time()})

    gc.callbacks.append(on_gc)

    app = server_module.app

    async def traced_app(scope, receive, send):
        if not (scope["type"] == "http" and scope["method"] == "POST"
                and scope["path"] == "/api/events/batch"):
            await app(scope, receive, send)
            return
        req_id = None
        for key, value in scope.get("headers", []):
            if key == b"x-bench-request-id":
                req_id = value.decode("latin-1")
        record: Dict[str, Any] = {"kind": "request", "id": req_id, "t0": time.time()}
        token = _current.set(record)

        async def traced_send(message):
            if message["type"] == "http.response.start":
                record["status"] = message["status"]
                record["t1"] = time.time()
            await send(message)

        try:
            await app(scope, receive, traced_send)
        finally:
            _current.reset(token)
            record.setdefault("t1", time.time())
            sink.write(record)

    return traced_app
