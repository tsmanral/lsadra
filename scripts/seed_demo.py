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

Corpus timestamps are synthetic January-2026 values; they are shifted forward so
the newest event lands at "now" and the dashboard's recent-activity views are
populated.

This script only ever creates clearly-synthetic data (``demo-host-NN`` hosts,
``*.demo`` users, RFC5737/RFC3849 documentation IPs). Do not point it at a
production deployment.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    import requests
except ImportError:  # pragma: no cover - dependency is in requirements.txt
    print("error: `requests` is required (pip install -r requirements.txt)", file=sys.stderr)
    raise SystemExit(2)

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_DIR = REPO_ROOT / "demo" / "corpus"

# Server-side limits we must stay under (lsadra/config.py). Kept as literals so
# the seeder can run against a remote core without importing the package.
SERVER_MAX_EVENTS_PER_BATCH = 100
SERVER_EVENTS_REQUESTS_PER_MIN = 60  # POST /api/events/batch, per device

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
    Map a corpus event onto the ``/api/events/batch`` NormalizedEvent shape.

    ``schema_version`` is a contract field, not an ingestion field; the
    ground-truth label rides along inside ``attributes`` so the seeded database
    stays self-describing for evaluation and the M1 benchmark harness.
    """
    return {
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


class DemoSeeder:
    """Drives one demo seeding run against a live core server."""

    def __init__(self, base_url: str, timeout: float = 15.0, ingest_timeout: float = 180.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        # Ingestion runs detection synchronously inside the request (M1 moves
        # this to a worker queue). A cold first batch trains/loads models and
        # can take well over a minute, so it gets its own generous timeout —
        # a client timeout here would abandon a request the server completes.
        self.ingest_timeout = ingest_timeout
        self.session = requests.Session()
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

    def register_device(self, hostname: str, os_type: str = "linux") -> None:
        """Mint a single-use registration token, then onboard the demo device."""
        if not self.jwt:
            raise SeedError("register_device() called before authenticate()")

        headers = {"Authorization": f"Bearer {self.jwt}"}
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

    events = time_shift(events)

    if args.dry_run:
        print("dry run — corpus parsed and time-shifted, nothing sent")
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
        default=50,
        help=f"events per request (server max {SERVER_MAX_EVENTS_PER_BATCH})",
    )
    parser.add_argument(
        "--pace",
        type=float,
        default=0.8,
        help="fraction of the server request-rate limit to use (default 0.8)",
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

    if not 1 <= args.batch_size <= SERVER_MAX_EVENTS_PER_BATCH:
        print(
            f"error: --batch-size must be 1..{SERVER_MAX_EVENTS_PER_BATCH}", file=sys.stderr
        )
        return 2
    if not 0 < args.pace <= 1:
        print("error: --pace must be in (0, 1]", file=sys.stderr)
        return 2

    try:
        return seed(args)
    except SeedError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
