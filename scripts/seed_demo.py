#!/usr/bin/env python3
"""
LSADRA — demo corpus seeder (demo/test mode, layer 2).

Replays the labeled synthetic corpus in ``demo/corpus/`` through the **real**
HTTP surface of a running LSADRA core:

    /api/auth/register  ->  /api/auth/login  ->  /api/dashboard/generate-token
    ->  /api/devices/register  ->  /api/events/batch  (which runs detection)

Nothing is written to the database directly. That is the point: seeding a demo
exercises onboarding, JWT auth, device API-key auth, batch validation, the
per-device rate limiter and the online detection path exactly as a real agent
would, so "it works in demo mode" is evidence about the product and not about
the seeder.

Typical use (dev mode, empty database)::

    LSADRA_DEV_MODE=true python server.py          # terminal 1
    python scripts/seed_demo.py                    # terminal 2

Corpus timestamps are synthetic January-2026 values; by default
(``--shift-to-now``) they are shifted forward so the newest event lands at "now"
and the dashboard's recent-activity views are populated.

Rate mode (M1 load driver, used by ``benchmarks/run_ingest_bench.py``)::

    python scripts/seed_demo.py --rate 500 --duration 30 --devices 10

registers N demo devices and replays the corpus in a loop at a fixed offered
rate (events/s, open loop, spread round-robin across devices) for the given
duration, then prints throughput and request-latency percentiles. The per-device
ingest limiter (60 batches/min) caps each device at 100 events/s, so rates above
that need more devices. One-shot replay stays the default.

This script only ever creates clearly-synthetic data (``demo-host-NN`` hosts,
``*.demo`` users, RFC5737/RFC3849 documentation IPs). Do not point it at a
production deployment.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:  # pragma: no cover - dependency is in requirements.txt
    print("error: `requests` is required (pip install -r requirements.txt)", file=sys.stderr)
    raise SystemExit(2)

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_DIR = REPO_ROOT / "demo" / "corpus"

# Server-side limits we must stay under (lsadra/config.py). Kept as literals so
# the seeder can run against a remote core without importing the package.
SERVER_MAX_EVENTS_PER_BATCH = 100
SERVER_EVENTS_REQUESTS_PER_MIN = 60  # POST /api/events/batch, per device
SERVER_REGISTER_PER_MIN = 5  # POST /api/devices/register, per client IP

DEFAULT_URL = "http://127.0.0.1:8000"
DEFAULT_USERNAME = "demo.admin"
DEFAULT_PASSWORD = "demo-only-not-a-secret"
DEFAULT_HOSTNAME = "demo-host-seeder"


class SeedError(RuntimeError):
    """Fatal seeding problem with an actionable message."""


# ── Corpus loading ────────────────────────────────────────────────────────


def load_corpus(scenarios: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """
    Load every ``*.jsonl`` scenario file into one timestamp-ordered list.

    Args:
        scenarios: optional scenario stems (file name without ``.jsonl``) to
            restrict the replay to.

    Returns:
        Events sorted ascending by ``timestamp``.
    """
    if not CORPUS_DIR.is_dir():
        raise SeedError(f"corpus directory not found: {CORPUS_DIR}")

    files = sorted(CORPUS_DIR.glob("*.jsonl"))
    if scenarios:
        wanted = set(scenarios)
        files = [f for f in files if f.stem in wanted]
        missing = wanted - {f.stem for f in files}
        if missing:
            raise SeedError(f"unknown scenario(s): {', '.join(sorted(missing))}")
    if not files:
        raise SeedError(f"no .jsonl scenario files in {CORPUS_DIR}")

    events: List[Dict[str, Any]] = []
    for path in files:
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SeedError(f"{path.name}:{lineno}: invalid JSON — {exc}") from exc

    events.sort(key=lambda e: e["timestamp"])
    return events


def _parse_ts(value: str) -> datetime:
    """Parse an RFC3339 timestamp, tolerating a trailing ``Z``."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def time_shift(events: List[Dict[str, Any]], anchor: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """
    Shift the whole corpus forward so its newest event sits at *anchor* (now).

    Relative spacing is preserved, which is what the detection stack keys on —
    a brute-force burst stays a burst.
    """
    if not events:
        return events
    anchor = anchor or datetime.now(timezone.utc)
    newest = max(_parse_ts(e["timestamp"]) for e in events)
    delta: timedelta = anchor - newest

    shifted = []
    for event in events:
        moved = dict(event)
        moved["timestamp"] = (_parse_ts(event["timestamp"]) + delta).isoformat()
        shifted.append(moved)
    return shifted


def to_ingest_payload(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map a corpus event onto the ``/api/events/batch`` event (contract v1).

    Corpus events already conform to ``docs/contracts/event-schema.v1.json``;
    ``schema_version`` is sent through (the core requires it). The ground-truth
    label rides along inside ``attributes`` so the seeded database stays
    self-describing for evaluation and the M1 benchmark harness.
    """
    return {
        "schema_version": event["schema_version"],
        "timestamp": event["timestamp"],
        "host": event.get("host", ""),
        "effective_username": event.get("effective_username", ""),
        "source_ip": event.get("source_ip"),
        "event_type": event["event_type"],
        "raw_message": event.get("raw_message", ""),
        "attributes": event.get("attributes", {}),
    }


def chunked(items: List[Any], size: int) -> Iterable[List[Any]]:
    """Yield *items* in lists of at most *size*."""
    for start in range(0, len(items), size):
        yield items[start : start + size]


# ── HTTP client ───────────────────────────────────────────────────────────


class _SourceAddressAdapter(HTTPAdapter):
    """Bind outgoing connections to one local IP (loopback aliases for a fleet)."""

    def __init__(self, source_ip: str, **kwargs: Any) -> None:
        self._source_address = (source_ip, 0)
        super().__init__(**kwargs)

    def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
        kwargs["source_address"] = self._source_address
        super().init_poolmanager(*args, **kwargs)


class DemoSeeder:
    """Drives one demo seeding run against a live core server."""

    def __init__(
        self,
        base_url: str,
        timeout: float = 15.0,
        ingest_timeout: float = 180.0,
        source_ip: Optional[str] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        # Ingestion runs detection synchronously inside the request (M1 moves
        # this to a worker queue). A cold first batch trains/loads models and
        # can take well over a minute, so it gets its own generous timeout —
        # a client timeout here would abandon a request the server completes.
        self.ingest_timeout = ingest_timeout
        self.session = requests.Session()
        if source_ip:
            adapter = _SourceAddressAdapter(source_ip)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
        self.jwt: Optional[str] = None
        self.device_id: Optional[str] = None
        self.api_key: Optional[str] = None

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def check_health(self) -> None:
        """Fail fast with a useful message when the core is not reachable."""
        try:
            resp = self.session.get(self._url("/api/health"), timeout=self.timeout)
        except requests.RequestException as exc:
            raise SeedError(
                f"cannot reach {self.base_url} — start the core first "
                f"(LSADRA_DEV_MODE=true python server.py). Underlying error: {exc}"
            ) from exc
        if resp.status_code != 200:
            raise SeedError(f"/api/health returned {resp.status_code}: {resp.text[:200]}")

    def authenticate(self, username: str, password: str) -> None:
        """Log in, registering the demo user first if it does not exist yet."""
        resp = self.session.post(
            self._url("/api/auth/login"),
            json={"username": username, "password": password},
            timeout=self.timeout,
        )
        if resp.status_code == 401:
            reg = self.session.post(
                self._url("/api/auth/register"),
                json={"username": username, "password": password},
                timeout=self.timeout,
            )
            if reg.status_code != 200:
                raise SeedError(
                    f"could not create demo user {username!r}: "
                    f"{reg.status_code} {reg.text[:200]}"
                )
            resp = self.session.post(
                self._url("/api/auth/login"),
                json={"username": username, "password": password},
                timeout=self.timeout,
            )
        if resp.status_code != 200:
            raise SeedError(f"login failed: {resp.status_code} {resp.text[:200]}")

        self.jwt = resp.json()["access_token"]

    def register_device(
        self, hostname: str, os_type: str = "linux", wait_on_limit: bool = False
    ) -> None:
        """Mint a single-use registration token, then onboard the demo device.

        With ``wait_on_limit`` a 429 from the per-IP registration limiter is
        waited out (up to ~90 s) instead of being fatal — used by ``--devices``.
        """
        if not self.jwt:
            raise SeedError("register_device() called before authenticate()")

        headers = {"Authorization": f"Bearer {self.jwt}"}
        attempts = 7 if wait_on_limit else 1
        for attempt in range(attempts):
            token_resp = self.session.post(
                self._url("/api/dashboard/generate-token"), headers=headers, timeout=self.timeout
            )
            if token_resp.status_code != 200:
                raise SeedError(
                    f"generate-token failed: {token_resp.status_code} {token_resp.text[:200]}"
                )
            token = token_resp.json()["token"]

            reg_resp = self.session.post(
                self._url("/api/devices/register"),
                json={
                    "token": token,
                    "hostname": hostname,
                    "os_type": os_type,
                    "display_name": "LSADRA demo device (synthetic data)",
                },
                timeout=self.timeout,
            )
            if reg_resp.status_code != 429 or attempt == attempts - 1:
                break
            print("  registration rate limited (5/min per IP) — waiting 15 s")
            time.sleep(15.0)
        if reg_resp.status_code == 429:
            raise SeedError(
                "device registration was rate limited (5/min per IP) — wait a minute and retry"
            )
        if reg_resp.status_code != 200:
            raise SeedError(f"device registration failed: {reg_resp.status_code} {reg_resp.text[:200]}")

        data = reg_resp.json()
        self.device_id = data["device_id"]
        self.api_key = data["api_key"]  # returned exactly once, by design

    def send_batch(self, events: List[Dict[str, Any]]) -> int:
        """POST one batch; returns the number of events the core accepted."""
        if not (self.device_id and self.api_key):
            raise SeedError("send_batch() called before register_device()")

        resp = self.session.post(
            self._url("/api/events/batch"),
            json={"events": events},
            headers={"x-device-id": self.device_id, "x-api-key": self.api_key},
            timeout=self.ingest_timeout,
        )
        if resp.status_code == 429:
            raise SeedError(
                "ingestion rate limit hit — lower --batch-size or raise --pace"
            )
        if resp.status_code != 200:
            raise SeedError(f"ingest failed: {resp.status_code} {resp.text[:300]}")
        return int(resp.json().get("events_accepted", 0))


# ── Rate mode (M1 load driver) ────────────────────────────────────────────
# Single-threaded: one asyncio loop issues every request, so the load generator
# never competes with the server for more than one core. Open loop: batches go
# out on a fixed schedule whether or not earlier ones have returned, so a slow
# server shows up as latency and a stretched completion window (no coordinated
# omission), not as a silently lowered offered rate.

DeviceCred = Tuple[str, str]  # (device_id, api_key)

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost"}


def _can_bind(ip: str) -> bool:
    """True if a local socket can bind to *ip* (i.e. that loopback address exists)."""
    import socket

    with socket.socket() as sock:
        try:
            sock.bind((ip, 0))
        except OSError:
            return False
    return True


def register_devices(
    base_url: str,
    jwt: str,
    count: int,
    hostname_prefix: str = DEFAULT_HOSTNAME,
    os_type: str = "linux",
    spread_source_ips: bool = False,
) -> List[DeviceCred]:
    """
    Register *count* demo devices through the real onboarding API.

    Registration is limited to 5/min per client IP. With ``spread_source_ips``
    (loopback targets only) each group of 4 devices registers from its own
    127.0.0.N source address — a fleet of N hosts, which is what the limiter
    models — instead of waiting the window out.
    """
    from urllib.parse import urlparse

    if spread_source_ips and urlparse(base_url).hostname not in _LOOPBACK_HOSTS:
        raise SeedError("--spread-source-ips only works against a loopback core URL")

    per_ip = SERVER_REGISTER_PER_MIN - 1
    creds: List[DeviceCred] = []
    for index in range(count):
        source_ip = None
        if spread_source_ips:
            candidate = f"127.0.0.{1 + index // per_ip}"
            # Linux and Windows route all of 127/8; macOS has only 127.0.0.1
            # unless aliases are added — then fall back to waiting out the limiter.
            source_ip = candidate if _can_bind(candidate) else None
        seeder = DemoSeeder(base_url, source_ip=source_ip)
        seeder.jwt = jwt
        seeder.register_device(f"{hostname_prefix}-{index:02d}", os_type, wait_on_limit=True)
        assert seeder.device_id and seeder.api_key
        creds.append((seeder.device_id, seeder.api_key))
    return creds


class PayloadCycler:
    """Endless stream of ingest payloads built from the corpus, in order."""

    def __init__(self, events: List[Dict[str, Any]], shift_to_now: bool = True) -> None:
        if not events:
            raise SeedError("empty corpus — nothing to replay")
        self._payloads = [to_ingest_payload(e) for e in events]
        self._shift_to_now = shift_to_now
        self._next = 0

    def next_batch(self, size: int) -> List[Dict[str, Any]]:
        """Next *size* payloads; with shift-to-now they are stamped at send time."""
        now = datetime.now(timezone.utc)
        batch = []
        for offset in range(size):
            payload = dict(self._payloads[self._next % len(self._payloads)])
            self._next += 1
            if self._shift_to_now:
                payload["timestamp"] = (now + timedelta(microseconds=offset)).isoformat()
            batch.append(payload)
        return batch


@dataclass
class RequestRecord:
    """One POST /api/events/batch as seen by the client."""

    sent_at_s: float  # seconds after the run started
    latency_s: float
    status: int  # HTTP status; 0 = transport error / client timeout
    events_sent: int
    events_accepted: int


@dataclass
class RateResult:
    """Raw outcome of one fixed-rate run."""

    offered_rate: float
    devices: int
    batch_size: int
    scheduled_batches: int
    nominal_duration_s: float
    records: List[RequestRecord] = field(default_factory=list)
    skipped_backpressure: int = 0  # scheduled but not sent: in-flight cap reached
    abandoned: int = 0  # still in flight when the drain timeout expired
    max_schedule_lag_ms: float = 0.0  # how late the client itself sent (self-check)


async def drive_rate(
    base_url: str,
    creds: List[DeviceCred],
    cycler: PayloadCycler,
    rate: float,
    duration: float,
    batch_size: int = SERVER_MAX_EVENTS_PER_BATCH,
    request_timeout: float = 120.0,
    max_in_flight: int = 256,
    drain_timeout: float = 120.0,
) -> RateResult:
    """Offer *rate* events/s for *duration* s, round-robin across *creds*."""
    import httpx  # in requirements.txt; imported lazily so one-shot mode never needs it

    interval = batch_size / rate
    scheduled = max(1, int(round(duration * rate / batch_size)))
    result = RateResult(
        offered_rate=rate,
        devices=len(creds),
        batch_size=batch_size,
        scheduled_batches=scheduled,
        nominal_duration_s=scheduled * interval,
    )
    limits = httpx.Limits(max_connections=max_in_flight, max_keepalive_connections=max_in_flight)
    in_flight: "set[asyncio.Task[None]]" = set()

    async with httpx.AsyncClient(
        base_url=base_url.rstrip("/"), timeout=request_timeout, limits=limits
    ) as client:
        started = time.perf_counter()

        async def send(device_index: int, batch: List[Dict[str, Any]]) -> None:
            device_id, api_key = creds[device_index]
            t_send = time.perf_counter()
            try:
                resp = await client.post(
                    "/api/events/batch",
                    json={"events": batch},
                    headers={"x-device-id": device_id, "x-api-key": api_key},
                )
                status = resp.status_code
                accepted = int(resp.json().get("events_accepted", 0)) if status == 200 else 0
            except httpx.HTTPError:
                status, accepted = 0, 0
            result.records.append(
                RequestRecord(
                    sent_at_s=t_send - started,
                    latency_s=time.perf_counter() - t_send,
                    status=status,
                    events_sent=len(batch),
                    events_accepted=accepted,
                )
            )

        for k in range(scheduled):
            target = started + k * interval
            delay = target - time.perf_counter()
            if delay > 0:
                await asyncio.sleep(delay)
            result.max_schedule_lag_ms = max(
                result.max_schedule_lag_ms, (time.perf_counter() - target) * 1000.0
            )
            if len(in_flight) >= max_in_flight:
                result.skipped_backpressure += 1
                continue
            task = asyncio.create_task(send(k % len(creds), cycler.next_batch(batch_size)))
            in_flight.add(task)
            task.add_done_callback(in_flight.discard)

        # Hold the run open for the full nominal window (the last batch goes out
        # one interval before it ends), then drain whatever is still in flight.
        remaining = started + result.nominal_duration_s - time.perf_counter()
        if remaining > 0:
            await asyncio.sleep(remaining)
        if in_flight:
            _, pending = await asyncio.wait(set(in_flight), timeout=drain_timeout)
            for task in pending:
                task.cancel()
            result.abandoned = len(pending)
    return result


def percentile(values: List[float], q: float) -> Optional[float]:
    """Linear-interpolated percentile (q in 0..100); None for no data."""
    if not values:
        return None
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q / 100.0
    lo = int(pos)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


def summarize_rate(result: RateResult) -> Dict[str, Any]:
    """Client-side numbers for one run: throughput, outcome counts, latency."""
    records = result.records
    ok = [r for r in records if r.status == 200]
    accepted = sum(r.events_accepted for r in records)
    last_done = max((r.sent_at_s + r.latency_s for r in records), default=0.0)
    # Sustained = accepted events over the longer of the schedule and the time
    # the server actually needed to finish them; a server that falls behind
    # stretches the window and its sustained rate drops below the offered rate.
    window = max(result.nominal_duration_s, last_done)
    lat_ms = [r.latency_s * 1000.0 for r in ok]

    def _r(value: Optional[float]) -> Optional[float]:
        return None if value is None else round(value, 2)

    return {
        "offered_ev_s": round(result.offered_rate, 2),
        "devices": result.devices,
        "batch_size": result.batch_size,
        "window_s": round(window, 3),
        "requests_scheduled": result.scheduled_batches,
        "requests_ok": len(ok),
        "requests_429": sum(1 for r in records if r.status == 429),
        "requests_error": sum(1 for r in records if r.status not in (200, 429)),
        "requests_skipped_backpressure": result.skipped_backpressure,
        "requests_abandoned": result.abandoned,
        "events_accepted": accepted,
        "sustained_ev_s": round(accepted / window, 2) if window > 0 else 0.0,
        "latency_ms": {
            "p50": _r(percentile(lat_ms, 50)),
            "p95": _r(percentile(lat_ms, 95)),
            "p99": _r(percentile(lat_ms, 99)),
            "max": _r(max(lat_ms) if lat_ms else None),
        },
        "client_max_schedule_lag_ms": round(result.max_schedule_lag_ms, 2),
    }


def max_rate_for(devices: int, batch_size: int, pace: float) -> float:
    """Highest offered rate (ev/s) the per-device ingest limiter admits at *pace*."""
    return devices * batch_size * SERVER_EVENTS_REQUESTS_PER_MIN * pace / 60.0


def seed_rate(args: argparse.Namespace) -> int:
    """Rate mode: register N devices, offer --rate ev/s for --duration s."""
    ceiling = max_rate_for(args.devices, args.batch_size, args.pace)
    if args.rate > ceiling:
        raise SeedError(
            f"--rate {args.rate:g} exceeds what {args.devices} device(s) may send under the "
            f"ingest limiter at --pace {args.pace:g} ({ceiling:g} ev/s); add --devices"
        )
    events = load_corpus(args.scenarios)
    cycler = PayloadCycler(events, shift_to_now=args.shift_to_now)

    seeder = DemoSeeder(args.url)
    seeder.check_health()
    seeder.authenticate(args.username, args.password)
    assert seeder.jwt
    creds = register_devices(
        args.url, seeder.jwt, args.devices, args.hostname, args.os_type, args.spread_source_ips
    )
    print(f"devices: registered {len(creds)}; offering {args.rate:g} ev/s for {args.duration:g} s")

    result = asyncio.run(
        drive_rate(args.url, creds, cycler, args.rate, args.duration, args.batch_size,
                   request_timeout=args.ingest_timeout)
    )
    print(json.dumps(summarize_rate(result), indent=2))
    return 0


# ── Orchestration ─────────────────────────────────────────────────────────


def seed(args: argparse.Namespace) -> int:
    """Run the full demo seeding flow. Returns a process exit code."""
    events = load_corpus(args.scenarios)
    print(f"corpus: {len(events)} events from {CORPUS_DIR.relative_to(REPO_ROOT)}")

    labels: Dict[str, int] = {}
    for event in events:
        label = event.get("attributes", {}).get("ground_truth", {}).get("label", "unlabeled")
        labels[label] = labels.get(label, 0) + 1
    print("  ground truth: " + ", ".join(f"{k}={v}" for k, v in sorted(labels.items())))

    if args.shift_to_now:
        events = time_shift(events)

    if args.dry_run:
        shifted = "time-shifted" if args.shift_to_now else "left at corpus timestamps"
        print(f"dry run — corpus parsed and {shifted}, nothing sent")
        return 0

    seeder = DemoSeeder(args.url, ingest_timeout=args.ingest_timeout)
    seeder.check_health()
    print(f"core: {args.url} reachable")

    seeder.authenticate(args.username, args.password)
    print(f"auth: logged in as {args.username}")

    seeder.register_device(args.hostname, args.os_type)
    print(f"device: registered {seeder.device_id} ({args.hostname})")

    payloads = [to_ingest_payload(e) for e in events]
    batches = list(chunked(payloads, args.batch_size))

    # Stay under the per-device request limiter (60 batch requests/min) with a
    # safety margin, so a demo seed never trips the very defense it exercises.
    min_interval = 60.0 / (SERVER_EVENTS_REQUESTS_PER_MIN * args.pace)

    accepted = 0
    for index, batch in enumerate(batches, 1):
        started = time.monotonic()
        accepted += seeder.send_batch(batch)
        print(f"  batch {index}/{len(batches)}: {accepted}/{len(payloads)} events accepted")
        if index < len(batches):
            time.sleep(max(0.0, min_interval - (time.monotonic() - started)))

    print(f"ingested: {accepted} events (detection ran online per batch)")
    print("done — open the dashboard; alerts should be present.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Seed a running LSADRA core with the labeled synthetic demo corpus.",
    )
    parser.add_argument("--url", default=DEFAULT_URL, help=f"core base URL (default {DEFAULT_URL})")
    parser.add_argument("--username", default=DEFAULT_USERNAME, help="demo dashboard user")
    parser.add_argument("--password", default=DEFAULT_PASSWORD, help="demo dashboard password")
    parser.add_argument("--hostname", default=DEFAULT_HOSTNAME, help="hostname to register")
    parser.add_argument("--os-type", default="linux", choices=["linux", "windows"])
    parser.add_argument(
        "--scenarios",
        nargs="*",
        help="restrict replay to these corpus stems (default: all)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=None,
        help=(
            f"events per request (server max {SERVER_MAX_EVENTS_PER_BATCH}; "
            f"default 50 one-shot, {SERVER_MAX_EVENTS_PER_BATCH} with --rate)"
        ),
    )
    parser.add_argument(
        "--pace",
        type=float,
        default=None,
        help=(
            "fraction of the per-device request-rate limit to use "
            "(default 0.8 one-shot, 0.95 with --rate)"
        ),
    )
    parser.add_argument(
        "--shift-to-now",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "move corpus timestamps to the present (one-shot: newest event lands at now; "
            "--rate: each event is stamped at send time). Default on"
        ),
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=None,
        help="rate mode: offered load in events/s across all devices (open loop)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=None,
        help="rate mode: seconds to sustain --rate (default 30)",
    )
    parser.add_argument(
        "--devices",
        type=int,
        default=1,
        help="rate mode: demo devices to register and spread the load over (default 1)",
    )
    parser.add_argument(
        "--spread-source-ips",
        action="store_true",
        help=(
            "rate mode, loopback core only: register devices from 127.0.0.N aliases so "
            "the 5/min-per-IP registration limiter does not serialize a large fleet"
        ),
    )
    parser.add_argument(
        "--ingest-timeout",
        type=float,
        default=180.0,
        help="seconds to wait for a batch (detection runs inline; default 180)",
    )
    parser.add_argument("--dry-run", action="store_true", help="parse and shift only; send nothing")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    rate_mode = args.rate is not None

    if args.batch_size is None:
        args.batch_size = SERVER_MAX_EVENTS_PER_BATCH if rate_mode else 50
    if args.pace is None:
        args.pace = 0.95 if rate_mode else 0.8

    if not 1 <= args.batch_size <= SERVER_MAX_EVENTS_PER_BATCH:
        print(
            f"error: --batch-size must be 1..{SERVER_MAX_EVENTS_PER_BATCH}", file=sys.stderr
        )
        return 2
    if not 0 < args.pace <= 1:
        print("error: --pace must be in (0, 1]", file=sys.stderr)
        return 2
    if not rate_mode and (
        args.duration is not None or args.devices != 1 or args.spread_source_ips
    ):
        print(
            "error: --duration, --devices and --spread-source-ips need --rate", file=sys.stderr
        )
        return 2
    if rate_mode:
        if args.duration is None:
            args.duration = 30.0
        if args.rate <= 0 or args.duration <= 0 or args.devices < 1:
            print("error: --rate and --duration must be > 0, --devices >= 1", file=sys.stderr)
            return 2
        if args.dry_run:
            print("error: --dry-run is one-shot only", file=sys.stderr)
            return 2

    try:
        return seed_rate(args) if rate_mode else seed(args)
    except SeedError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
