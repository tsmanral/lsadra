#!/usr/bin/env python3
"""
LSADRA ingest benchmark — measures today's stack, changes nothing.

For each detection mode (on / off) and repetition it:

1. starts the real core in a subprocess (``_bench_server.py``: dev mode, a
   throwaway temp data dir, uvicorn defaults);
2. logs in and registers the largest device fleet through the real onboarding
   API (``scripts/seed_demo.py``);
3. warms up: one full batch per device, sequentially (with detection on this
   includes the one-off cold model training — reported, not measured);
4. for each ``--devices`` count, offers a rising ladder of rates through
   ``POST /api/events/batch`` (open loop, ``seed_demo.drive_rate``) and records
   per step: sustained events/s, p50/p95/p99 request latency, server RSS
   (psutil, sampled every 0.5 s) and event-loop lag p50/p99 (the dev-mode
   sampler in ``server.py``, read from ``/api/health``). The ladder for a
   device count stops at the first degraded step (rule in the output JSON).
   Before each step, after the server settles, every device in the step makes
   one authenticated ``GET /api/events/stats`` (unmeasured), so a settle longer
   than the device-auth cache TTL does not start the step on a cold cache; the
   server then settles again, so the background re-verifies those reads may
   queue finish before the step starts.
   Where each device in a step sends less often than every half cache TTL,
   the harness first waits half a TTL so every re-warm read renews its entry.

Detection-off runs set ``LSADRA_BENCH_SKIP_DETECTION=true`` (dev-mode-only
switch) so storage cost and detection cost can be told apart.

The harness is single-threaded (one asyncio loop) so it takes at most one core
from the server. Run it on an otherwise idle machine.

    python benchmarks/run_ingest_bench.py                      # full baseline
    python benchmarks/run_ingest_bench.py --detection off --devices 1 \\
        --rates 50 --duration 5 --repeats 1 --output out.json  # quick check
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import seed_demo  # noqa: E402

SCHEMA = "lsadra.ingest-bench/1"
DEFAULT_DEVICES = [1, 10, 20]
RATE_LADDER = [25, 50, 100, 250, 500, 750, 1000, 1500, 2000]
DEFAULT_PACE = 0.95  # fraction of the per-device ingest limiter a step may use
# Pinned payload set: the four original corpus files. Pinned so the workload —
# and the baseline — does not shift when new corpus files land.
BASELINE_SCENARIOS = (
    "ssh_bruteforce",
    "persistence_new_service",
    "data_movement_offhours",
    "benign_background",
)

# A step is "degraded" — and the ladder for that device count stops — when any
# of these hold. They are stopping rules for the sweep, not pass/fail gates.
DEGRADED_SUSTAINED_FRACTION = 0.90  # sustained < 90% of offered
DEFAULT_STOP_P99_MS = 1000.0
DEFAULT_STOP_LOOP_LAG_P99_MS = 500.0
# Reasons that mean the core no longer keeps up (vs. keeps up, but slowly).
THROUGHPUT_REASONS = {
    "sustained<90%_offered", "requests_429", "requests_error",
    "requests_skipped_backpressure", "requests_abandoned",
}
IDLE_LAG_SECONDS = 5.0  # no-load loop-lag sample taken after warm-up
SETTLE_TIMEOUT_S = 600.0  # max wait for a backlog to drain between steps
SETTLE_LAG_MS = 50.0
SETTLE_CPU_PCT = 25.0  # server process CPU (% of one core) considered idle
# Must match the server's LSADRA_DEVICE_AUTH_CACHE_TTL_SECONDS (lsadra/config.py);
# the server subprocess inherits this environment, so both read the same value.
AUTH_CACHE_TTL_S = float(os.getenv("LSADRA_DEVICE_AUTH_CACHE_TTL_SECONDS", "60"))
# A cache hit past this fraction of the TTL queues a background re-verify
# (REFRESH_AFTER_FRACTION in lsadra/ingestion/credential_cache.py).
AUTH_REFRESH_AFTER_FRACTION = 0.5
LOG_MARKERS = ["Online detection:", "Auto-training models", "all layers trained", "Traceback"]


# ── machine / environment ────────────────────────────────────────────────


def _cpu_model() -> str:
    if sys.platform == "win32":
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
            )
            return str(winreg.QueryValueEx(key, "ProcessorNameString")[0]).strip()
        except OSError:
            pass
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text(errors="replace").splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    return platform.processor() or "unknown"


def machine_spec() -> Dict[str, Any]:
    try:
        import uvloop  # noqa: F401

        uvloop_ok = sys.platform != "win32"
    except ImportError:
        uvloop_ok = False
    return {
        "cpu": _cpu_model(),
        "cpu_physical_cores": psutil.cpu_count(logical=False),
        "cpu_logical_cores": psutil.cpu_count(logical=True),
        "ram_gb": round(psutil.virtual_memory().total / 2**30, 1),
        "os": platform.platform(),
        "python": platform.python_version(),
        # uvicorn's default loop="auto" picks uvloop when importable (never on Windows).
        "server_event_loop": "uvloop" if uvloop_ok else "asyncio",
    }


def git_commit() -> Dict[str, Any]:
    def _git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
        ).stdout.strip()

    # Tracked changes only: an untracked file (a stray worktree copy, a result
    # JSON) does not change the code under test.
    dirty = bool(_git("status", "--porcelain", "--untracked-files=no"))
    return {"sha": _git("rev-parse", "HEAD") or None, "dirty": dirty}


# ── server lifecycle ─────────────────────────────────────────────────────


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class BenchServer:
    """The real core in a subprocess on a throwaway data dir."""

    def __init__(self, skip_detection: bool, boot_timeout: float = 180.0,
                 trace: bool = False) -> None:
        self.skip_detection = skip_detection
        self.boot_timeout = boot_timeout
        self.port = _free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self._tmp = tempfile.TemporaryDirectory(prefix="lsadra-bench-")
        self.data_dir = Path(self._tmp.name)
        self.proc: Optional[subprocess.Popen] = None
        self.boot_s: Optional[float] = None
        self._log = None
        self.trace_path: Optional[Path] = self.data_dir / "trace.jsonl" if trace else None
        self._trace_offset = 0

    def read_trace(self) -> List[Dict[str, Any]]:
        """Trace records written since the previous call (``--trace`` only)."""
        if self.trace_path is None or not self.trace_path.exists():
            return []
        with open(self.trace_path, "rb") as fh:
            fh.seek(self._trace_offset)
            data = fh.read()
        end = data.rfind(b"\n") + 1  # leave a half-written last line for next time
        self._trace_offset += end
        return [json.loads(line) for line in data[:end].splitlines() if line.strip()]

    def start(self) -> None:
        env = dict(os.environ)
        env.update(
            {
                "LSADRA_DEV_MODE": "true",
                "LSADRA_JWT_SECRET": secrets.token_urlsafe(32),
                "LSADRA_BENCH_SKIP_DETECTION": "true" if self.skip_detection else "false",
                "PYTHONUNBUFFERED": "1",
            }
        )
        self._log = open(self.data_dir / "server.log", "wb")
        started = time.perf_counter()
        self.proc = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).with_name("_bench_server.py")),
                "--port",
                str(self.port),
                "--data-dir",
                str(self.data_dir),
                *(["--trace-file", str(self.trace_path)] if self.trace_path else []),
            ],
            cwd=self.data_dir,
            env=env,
            stdout=self._log,
            stderr=subprocess.STDOUT,
        )
        deadline = started + self.boot_timeout
        while time.perf_counter() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"server exited during boot:\n{self.log_tail()}")
            try:
                if requests.get(f"{self.url}/api/health", timeout=2).status_code == 200:
                    self.boot_s = time.perf_counter() - started
                    return
            except requests.RequestException:
                pass
            time.sleep(0.25)
        raise RuntimeError(f"server not healthy after {self.boot_timeout}s:\n{self.log_tail()}")

    def health(self) -> Dict[str, Any]:
        return requests.get(f"{self.url}/api/health", timeout=600).json()

    def cpu_seconds(self) -> float:
        assert self.proc is not None
        try:
            times = psutil.Process(self.proc.pid).cpu_times()
            return times.user + times.system
        except psutil.Error:
            return 0.0

    def cpu_percent(self, interval: float) -> float:
        """Server CPU over *interval* seconds, as % of one core (can exceed 100)."""
        assert self.proc is not None
        try:
            proc = psutil.Process(self.proc.pid)
            proc.cpu_percent(None)
            time.sleep(interval)
            return proc.cpu_percent(None)
        except psutil.Error:
            return 0.0

    def rss_bytes(self) -> int:
        assert self.proc is not None
        try:
            root = psutil.Process(self.proc.pid)
            procs = [root, *root.children(recursive=True)]
            return sum(p.memory_info().rss for p in procs)
        except psutil.Error:
            return 0

    def db_bytes(self) -> int:
        total = 0
        for path in self.data_dir.glob("bench.db*"):
            try:
                total += path.stat().st_size
            except FileNotFoundError:  # SQLite may drop -wal/-shm between glob and stat
                pass
        return total

    def log_tail(self, lines: int = 40) -> str:
        try:
            text = (self.data_dir / "server.log").read_text(errors="replace")
        except OSError:
            return ""
        return "\n".join(text.splitlines()[-lines:])

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=20)
        if self._log is not None:
            self._log.close()
        try:
            self._tmp.cleanup()
        except OSError:  # Windows may hold the SQLite file a moment longer
            time.sleep(1.0)
            self._tmp.cleanup()


# ── measurement ──────────────────────────────────────────────────────────


def _pct(values: List[float], q: float) -> Optional[float]:
    value = seed_demo.percentile(values, q)
    return None if value is None else round(value, 2)


def loop_lag_since(health: Dict[str, Any], seq_before: int) -> Dict[str, Any]:
    bench = health["benchmark"]
    new = bench["loop_lag_seq"] - seq_before
    tail: List[float] = bench["loop_lag_ms"]
    samples = tail[-new:] if 0 < new <= len(tail) else (tail if new > 0 else [])
    return {
        "samples": len(samples),
        "truncated": new > len(tail),
        "p50": _pct(samples, 50),
        "p99": _pct(samples, 99),
        "max": round(max(samples), 2) if samples else None,
    }


async def _sample_rss(server: BenchServer, out: List[int], stop: asyncio.Event) -> None:
    while not stop.is_set():
        out.append(server.rss_bytes())
        try:
            await asyncio.wait_for(stop.wait(), timeout=0.5)
        except asyncio.TimeoutError:
            pass


async def _drive_with_rss(
    server: BenchServer,
    creds: List[seed_demo.DeviceCred],
    cycler: seed_demo.PayloadCycler,
    rate: float,
    duration: float,
    rss: List[int],
    request_id_prefix: Optional[str] = None,
) -> seed_demo.RateResult:
    stop = asyncio.Event()
    sampler = asyncio.create_task(_sample_rss(server, rss, stop))
    try:
        return await seed_demo.drive_rate(
            server.url, creds, cycler, rate, duration, request_id_prefix=request_id_prefix
        )
    finally:
        stop.set()
        await sampler


def run_step(
    server: BenchServer,
    creds: List[seed_demo.DeviceCred],
    cycler: seed_demo.PayloadCycler,
    rate: float,
    duration: float,
) -> Dict[str, Any]:
    # Health reads bracket the step outside the measured window; everything in
    # between runs on this one thread's event loop.
    seq_before = server.health()["benchmark"]["loop_lag_seq"]
    rss: List[int] = []
    server.read_trace()  # drop records from before the step (re-warm, settle)
    prefix = secrets.token_hex(4) if server.trace_path else None
    cpu_before, wall_before = server.cpu_seconds(), time.perf_counter()
    result = asyncio.run(_drive_with_rss(server, creds, cycler, rate, duration, rss, prefix))
    cpu_used, wall = server.cpu_seconds() - cpu_before, time.perf_counter() - wall_before
    health = server.health()
    step = seed_demo.summarize_rate(result)
    step["server_cpu_cores_avg"] = round(cpu_used / wall, 2) if wall > 0 else None
    step["loop_lag_ms"] = loop_lag_since(health, seq_before)
    step["rss_mb"] = {
        "max": round(max(rss) / 2**20, 1) if rss else None,
        "end": round(server.rss_bytes() / 2**20, 1),
    }
    step["db_mb_end"] = round(server.db_bytes() / 2**20, 1)
    if server.trace_path:
        step["trace"] = summarize_trace(result, server.read_trace())
    return step


TRACE_SLOW_MS = 150.0  # a request at least this slow gets a cause in the trace summary
TRACE_TOP = 5


def _overlap_ms(t0: float, t1: float, spans: List[Dict[str, Any]]) -> float:
    return sum(max(0.0, min(t1, s["t1"]) - max(t0, s["t0"])) for s in spans) * 1000.0


def summarize_trace(result: seed_demo.RateResult, records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Line each request up with what the server was doing while it ran.

    Per request: server time (ASGI start to response start), time in device
    lookup, inline bcrypt and storage, time before storage started (body parse,
    auth, threadpool queue), garbage collection and detection running at the
    same time, and the part of the client's latency spent outside the server
    (connect, send, receive, client loop). The slowest requests are listed.
    """
    by_id = {r["id"]: r for r in records if r["kind"] == "request" and r.get("id")}
    gcs = [r for r in records if r["kind"] == "gc"]
    runs = [r for r in records if r["kind"] == "detection"]

    rows = []
    for rec in result.records:
        srv = by_id.get(rec.request_id)
        row: Dict[str, Any] = {"id": rec.request_id, "latency_ms": round(rec.latency_s * 1e3, 1)}
        if srv is not None:
            calls = srv.get("calls", [])

            def spent(name: str) -> float:
                return sum(c[2] - c[1] for c in calls if c[0] == name) * 1e3

            store = [c for c in calls if c[0] == "store"]
            server_ms = (srv["t1"] - srv["t0"]) * 1e3
            row.update({
                "server_ms": round(server_ms, 1),
                "outside_server_ms": round(rec.latency_s * 1e3 - server_ms, 1),
                "get_device_ms": round(spent("get_device"), 1),
                "bcrypt_inline_ms": round(spent("checkpw"), 1),
                "before_store_ms": round((store[0][1] - srv["t0"]) * 1e3, 1) if store else None,
                "store_ms": round(spent("store"), 1),
                "gc_ms": round(_overlap_ms(srv["t0"], srv["t1"], gcs), 1),
                "gc_gen2_ms": round(_overlap_ms(
                    srv["t0"], srv["t1"], [g for g in gcs if g.get("gen") == 2]), 1),
                "detection_overlap_ms": round(_overlap_ms(srv["t0"], srv["t1"], runs), 1),
            })
        rows.append(row)
    rows.sort(key=lambda r: r["latency_ms"], reverse=True)

    def cause(row: Dict[str, Any]) -> str:
        if "server_ms" not in row:
            return "untraced"
        parts = {
            "bcrypt_inline": row["bcrypt_inline_ms"],
            "gc": row["gc_ms"],
            "outside_server": row["outside_server_ms"],
            "store": row["store_ms"],
            "get_device": row["get_device_ms"],
        }
        name, value = max(parts.items(), key=lambda kv: kv[1])
        if value < 0.5 * row["latency_ms"]:
            return "detection_overlap" if row["detection_overlap_ms"] > 0 else "mixed"
        return name

    slow = [r for r in rows if r["latency_ms"] >= TRACE_SLOW_MS]
    causes: Dict[str, int] = {}
    for row in slow:
        causes[cause(row)] = causes.get(cause(row), 0) + 1
    gc_ms = [(g["t1"] - g["t0"]) * 1e3 for g in gcs]
    run_ms = [(r["t1"] - r["t0"]) * 1e3 for r in runs]
    return {
        "requests_traced": sum(1 for r in rows if "server_ms" in r),
        "slow_requests": len(slow),
        "slow_causes": causes,
        "slowest": [dict(r, cause=cause(r)) for r in rows[:TRACE_TOP]],
        "gc": {
            "collections": len(gcs),
            "gen2": sum(1 for g in gcs if g.get("gen") == 2),
            "max_ms": round(max(gc_ms), 1) if gc_ms else None,
            "total_ms": round(sum(gc_ms), 1),
        },
        "detection": {
            "runs": len(runs),
            "busy_ms": round(sum(run_ms), 1),
            "max_run_ms": round(max(run_ms), 1) if run_ms else None,
        },
        "auth_refreshes": sum(1 for r in records if r["kind"] == "refresh"),
    }


def degraded_reasons(step: Dict[str, Any], stop_p99_ms: float, stop_lag_ms: float) -> List[str]:
    reasons = []
    if step["sustained_ev_s"] < DEGRADED_SUSTAINED_FRACTION * step["offered_ev_s"]:
        reasons.append("sustained<90%_offered")
    p99 = step["latency_ms"]["p99"]
    if p99 is None or p99 > stop_p99_ms:
        reasons.append("latency_p99")
    lag = step["loop_lag_ms"]["p99"]
    if lag is not None and lag > stop_lag_ms:
        reasons.append("loop_lag_p99")
    for key in ("requests_429", "requests_error", "requests_skipped_backpressure",
                "requests_abandoned"):
        if step[key]:
            reasons.append(key)
    return reasons


def ladder_for(devices: int, explicit: Optional[List[float]]) -> List[float]:
    ceiling = seed_demo.max_rate_for(devices, seed_demo.SERVER_MAX_EVENTS_PER_BATCH, DEFAULT_PACE)
    if explicit:
        return [r for r in explicit if r <= ceiling]
    return [float(r) for r in RATE_LADDER if r < ceiling] + [ceiling]


def settle(server: BenchServer, timeout: float = SETTLE_TIMEOUT_S) -> float:
    """
    Wait until the server has worked off any backlog from the previous step.

    A client-side timeout does not stop the server processing that request, so
    after a degraded step the next one would otherwise start against a busy
    core. Quiet = the last ~2 s of loop-lag samples all under SETTLE_LAG_MS.
    """
    started = time.perf_counter()
    while time.perf_counter() - started < timeout:
        # CPU catches backlog the loop never sees (bcrypt auth runs in the threadpool).
        busy = server.cpu_percent(1.0)
        recent = server.health()["benchmark"]["loop_lag_ms"][-20:]
        if busy < SETTLE_CPU_PCT and len(recent) == 20 and max(recent) < SETTLE_LAG_MS:
            break
    return round(time.perf_counter() - started, 2)


def log_counts(server: BenchServer) -> Dict[str, int]:
    """Occurrences of detection-path log lines — shows what the server spent time on."""
    try:
        text = (server.data_dir / "server.log").read_text(errors="replace")
    except OSError:
        return {}
    return {marker: text.count(marker) for marker in LOG_MARKERS}


def warm_up(server: BenchServer, creds: List[seed_demo.DeviceCred],
            cycler: seed_demo.PayloadCycler) -> float:
    """One full batch per device, sequentially — pays cold model training once."""
    started = time.perf_counter()
    for device_id, api_key in creds:
        resp = requests.post(
            f"{server.url}/api/events/batch",
            json={"events": cycler.next_batch(seed_demo.SERVER_MAX_EVENTS_PER_BATCH)},
            headers={"x-device-id": device_id, "x-api-key": api_key},
            timeout=600,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"warm-up batch failed: {resp.status_code} {resp.text[:200]}")
    return time.perf_counter() - started


def rewarm_auth(server: BenchServer, creds: List[seed_demo.DeviceCred]) -> float:
    """One authenticated read per device, so the step starts on a warm credential cache.

    Settling can outlast the device-auth cache TTL; without this, every device
    pays a fresh bcrypt verify in the first second of the step, which measures a
    restart rather than steady load. ``/api/events/stats`` authenticates exactly
    like ``/batch`` but stores nothing, enqueues no detection and is not rate
    limited, so it uses none of the step's per-device budget.
    """
    started = time.perf_counter()
    for device_id, api_key in creds:
        resp = requests.get(
            f"{server.url}/api/events/stats",
            headers={"x-device-id": device_id, "x-api-key": api_key},
            timeout=60,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"auth re-warm failed: {resp.status_code} {resp.text[:200]}")
    return time.perf_counter() - started


def needs_fresh_auth(devices: int, rate: float) -> bool:
    """
    True when each device in the step sends less often than every half cache TTL.

    Then a re-warm read can land on an entry younger than half its TTL (no
    background re-verify is queued) and the device's next batch, more than half
    a TTL later, can find it expired and pay bcrypt inline. Which devices hit
    that depends only on where the previous step left each entry's age, so the
    step would measure that phase, not ingestion. Steady agents (every few
    seconds) never see it: their hits past half the TTL renew the entry.
    """
    if AUTH_CACHE_TTL_S <= 0:
        return False
    interval_s = devices * seed_demo.SERVER_MAX_EVENTS_PER_BATCH / rate
    return interval_s > AUTH_CACHE_TTL_S * AUTH_REFRESH_AFTER_FRACTION


def wait_for_refreshable_auth() -> float:
    """
    Right after a settle, sleep until every cached device entry is past half its TTL.

    No device request runs during a settle, and the settle waits out any
    background re-verify, so no entry was verified later than the moment it
    ended. Half a TTL (plus a margin) later, the re-warm read either queues a
    background re-verify for each entry or finds it expired and verifies it
    inline; either way every entry starts the step freshly verified.
    """
    wait = AUTH_CACHE_TTL_S * AUTH_REFRESH_AFTER_FRACTION + 1.0
    time.sleep(wait)
    return wait


def run_once(detection: bool, repetition: int, args: argparse.Namespace) -> Dict[str, Any]:
    label = f"detection={'on' if detection else 'off'} rep={repetition}"
    print(f"[{label}] starting server", flush=True)
    server = BenchServer(skip_detection=not detection, trace=args.trace)
    run: Dict[str, Any] = {"detection": "on" if detection else "off", "repetition": repetition}
    try:
        server.start()
        run["server_boot_s"] = round(server.boot_s or 0.0, 2)
        skipped = server.health()["benchmark"]["detection_skipped"]
        if skipped == detection:  # disconfirming check: the switch must have taken effect
            raise RuntimeError(f"server reports detection_skipped={skipped} for {label}")

        seeder = seed_demo.DemoSeeder(server.url)
        seeder.authenticate(seed_demo.DEFAULT_USERNAME, seed_demo.DEFAULT_PASSWORD)
        assert seeder.jwt
        started = time.perf_counter()
        creds = seed_demo.register_devices(
            server.url, seeder.jwt, max(args.devices), "bench-host", spread_source_ips=True
        )
        run["registration_s"] = round(time.perf_counter() - started, 2)

        cycler = seed_demo.PayloadCycler(
            seed_demo.load_corpus(list(BASELINE_SCENARIOS)), shift_to_now=True
        )
        run["warmup_s"] = round(warm_up(server, creds, cycler), 2)
        run["rss_mb_after_warmup"] = round(server.rss_bytes() / 2**20, 1)
        # Sampler floor with no load: on Windows the loop's sleep wake-up follows
        # the ~15.6 ms system timer, so single-digit-ms lag here is timer noise.
        seq_before = server.health()["benchmark"]["loop_lag_seq"]
        time.sleep(IDLE_LAG_SECONDS)
        run["loop_lag_idle_ms"] = loop_lag_since(server.health(), seq_before)
        print(f"[{label}] boot {run['server_boot_s']}s, registration "
              f"{run['registration_s']}s, warm-up {run['warmup_s']}s", flush=True)

        run["configs"] = []
        for devices in args.devices:
            config: Dict[str, Any] = {"devices": devices, "steps": []}
            for rate in ladder_for(devices, args.rates):
                settle_s = settle(server)
                # Low rates send few 100-event batches; stretch the step so every
                # percentile rests on at least --min-requests samples.
                batch = seed_demo.SERVER_MAX_EVENTS_PER_BATCH
                duration = max(args.duration, args.min_requests * batch / rate)
                fresh_wait_s = 0.0
                if needs_fresh_auth(devices, rate):
                    fresh_wait_s = wait_for_refreshable_auth()
                rewarm_s = rewarm_auth(server, creds[:devices])
                # A re-warm hit past half the cache TTL queues a background
                # bcrypt re-verify; let those finish before measuring.
                settle_s += settle(server)
                step = run_step(server, creds[:devices], cycler, rate, duration)
                step["settle_before_s"] = round(settle_s, 2)
                step["auth_rewarm_s"] = round(rewarm_s, 2)
                step["auth_fresh_wait_s"] = round(fresh_wait_s, 2)
                step["degraded"] = degraded_reasons(step, args.stop_p99_ms, args.stop_loop_lag_ms)
                config["steps"].append(step)
                lat, lag = step["latency_ms"], step["loop_lag_ms"]
                print(
                    f"[{label}] devices={devices} offered={step['offered_ev_s']:g} "
                    f"sustained={step['sustained_ev_s']:g} p50/p95/p99="
                    f"{lat['p50']}/{lat['p95']}/{lat['p99']}ms lag p50/p99="
                    f"{lag['p50']}/{lag['p99']}ms rss={step['rss_mb']['max']}MB "
                    f"{'DEGRADED ' + ','.join(step['degraded']) if step['degraded'] else ''}",
                    flush=True,
                )
                if args.stop_on == "any" and step["degraded"]:
                    break
                if set(step["degraded"]) & THROUGHPUT_REASONS:
                    break
            healthy = [s for s in config["steps"] if not s["degraded"]]
            config["max_healthy_sustained_ev_s"] = (
                max(s["sustained_ev_s"] for s in healthy) if healthy else None
            )
            run["configs"].append(config)
        run["server_log_counts"] = log_counts(server)
    except Exception:
        tail = server.log_tail()
        if tail:
            print(f"[{label}] server log tail:\n{tail}", file=sys.stderr)
        raise
    finally:
        server.stop()
    return run


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="LSADRA ingest benchmark (measure only).")
    parser.add_argument("--detection", choices=["on", "off", "both"], default="both")
    parser.add_argument("--repeats", type=int, default=2, help="runs per detection mode")
    parser.add_argument("--devices", type=int, nargs="+", default=DEFAULT_DEVICES)
    parser.add_argument(
        "--rates", type=float, nargs="+", default=None,
        help="explicit offered rates (ev/s); default: a ladder up to each fleet's limiter ceiling",
    )
    parser.add_argument("--duration", type=float, default=15.0, help="seconds per step")
    parser.add_argument(
        "--min-requests", type=int, default=12,
        help="lengthen low-rate steps so each sends at least this many batches (default 12)",
    )
    parser.add_argument(
        "--stop-on", choices=["any", "throughput"], default="any",
        help=(
            "end a device count's ladder at the first degraded step (any, default) or only "
            "once the core stops keeping up (throughput) — maps the throughput ceiling "
            "past the point where latency already failed"
        ),
    )
    parser.add_argument(
        "--trace", action="store_true",
        help="record per-request server timings, detection runs and garbage collections, "
             "and add a per-step summary of what the slowest requests waited on",
    )
    parser.add_argument("--stop-p99-ms", type=float, default=DEFAULT_STOP_P99_MS)
    parser.add_argument("--stop-loop-lag-ms", type=float, default=DEFAULT_STOP_LOOP_LAG_P99_MS)
    parser.add_argument(
        "--output", default=None,
        help="result JSON path (default benchmarks/baseline-<UTC date>.json)",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.repeats < 1 or args.duration <= 0 or min(args.devices) < 1:
        print("error: --repeats >= 1, --duration > 0, --devices >= 1", file=sys.stderr)
        return 2
    now = datetime.now(timezone.utc)
    output = Path(args.output) if args.output else (
        Path(__file__).with_name(f"baseline-{now:%Y-%m-%d}.json")
    )
    modes = {"on": [True], "off": [False], "both": [True, False]}[args.detection]

    report: Dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at": now.isoformat(timespec="seconds"),
        "git": git_commit(),
        "machine": machine_spec(),
        "command": " ".join([Path(sys.executable).name, *sys.argv]),
        "params": {
            "detection": args.detection,
            "repeats": args.repeats,
            "devices": args.devices,
            "rates": args.rates,
            "step_duration_s": args.duration,
            "trace": args.trace,
            "min_requests_per_step": args.min_requests,
            "batch_size": seed_demo.SERVER_MAX_EVENTS_PER_BATCH,
            "pace": DEFAULT_PACE,
            "per_device_limit_batches_per_min": seed_demo.SERVER_EVENTS_REQUESTS_PER_MIN,
            "payloads": "demo/corpus scenarios below, cycled in timestamp order, "
                        "stamped at send time",
            "scenarios": list(BASELINE_SCENARIOS),
        },
        "degraded_rule": {
            "sustained_below_fraction_of_offered": DEGRADED_SUSTAINED_FRACTION,
            "latency_p99_ms_above": args.stop_p99_ms,
            "loop_lag_p99_ms_above": args.stop_loop_lag_ms,
            "any_429_error_skipped_or_abandoned": True,
            "ladder_stops_on": args.stop_on,
        },
        "runs": [],
    }
    for repetition in range(1, args.repeats + 1):
        for detection in modes:
            report["runs"].append(run_once(detection, repetition, args))

    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
