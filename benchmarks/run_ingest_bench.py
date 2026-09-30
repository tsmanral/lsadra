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

    return {"sha": _git("rev-parse", "HEAD") or None, "dirty": bool(_git("status", "--porcelain"))}


# ── server lifecycle ─────────────────────────────────────────────────────


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class BenchServer:
    """The real core in a subprocess on a throwaway data dir."""

    def __init__(self, skip_detection: bool, boot_timeout: float = 180.0) -> None:
        self.skip_detection = skip_detection
        self.boot_timeout = boot_timeout
        self.port = _free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self._tmp = tempfile.TemporaryDirectory(prefix="lsadra-bench-")
        self.data_dir = Path(self._tmp.name)
        self.proc: Optional[subprocess.Popen] = None
        self.boot_s: Optional[float] = None
        self._log = None

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
        return sum(
            p.stat().st_size for p in self.data_dir.glob("bench.db*") if p.is_file()
        )

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
) -> seed_demo.RateResult:
    stop = asyncio.Event()
    sampler = asyncio.create_task(_sample_rss(server, rss, stop))
    try:
        return await seed_demo.drive_rate(server.url, creds, cycler, rate, duration)
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
    cpu_before, wall_before = server.cpu_seconds(), time.perf_counter()
    result = asyncio.run(_drive_with_rss(server, creds, cycler, rate, duration, rss))
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
    return step


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


def run_once(detection: bool, repetition: int, args: argparse.Namespace) -> Dict[str, Any]:
    label = f"detection={'on' if detection else 'off'} rep={repetition}"
    print(f"[{label}] starting server", flush=True)
    server = BenchServer(skip_detection=not detection)
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
                step = run_step(server, creds[:devices], cycler, rate, duration)
                step["settle_before_s"] = settle_s
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
