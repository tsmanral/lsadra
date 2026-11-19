"""
Runtime intel tier: the local, gitignored ``intel_runtime.db`` (ADR 0004).

Everything here comes from sources the operator turned on, on this machine:
keyless list feeds (abuse.ch Feodo Tracker, Spamhaus DROP, Tor exit list) and
the optional keyed AbuseIPDB lookup. None of it is committed or shipped in a
release asset, because these sources forbid or restrict redistribution.

IP ranges are stored as 16-byte big-endian blobs (IPv4 mapped into IPv6), so
one indexed range query matches both single IPs and CIDR blocks.
"""

from __future__ import annotations

import ipaddress
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

_SCHEMA = """
CREATE TABLE IF NOT EXISTS feed_state (
    feed_id        TEXT PRIMARY KEY,
    url            TEXT,
    etag           TEXT,
    last_modified  TEXT,
    fetched_at     TEXT,
    changed_at     TEXT,
    records        INTEGER DEFAULT 0,
    status         TEXT,
    error          TEXT
);
CREATE TABLE IF NOT EXISTS indicator (
    feed_id    TEXT NOT NULL,
    value      TEXT NOT NULL,       -- IP or CIDR as published
    net_start  BLOB NOT NULL,
    net_end    BLOB NOT NULL,
    label      TEXT,                -- e.g. malware family, SBL id
    first_seen TEXT,
    last_seen  TEXT,
    PRIMARY KEY (feed_id, value)
);
CREATE INDEX IF NOT EXISTS idx_indicator_range ON indicator(net_start, net_end);
CREATE TABLE IF NOT EXISTS abuseipdb_cache (
    ip_address    TEXT PRIMARY KEY,
    abuse_score   INTEGER,
    country_code  TEXT,
    isp           TEXT,
    domain        TEXT,
    is_tor        INTEGER,
    total_reports INTEGER,
    last_reported TEXT,
    queried_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL
);
"""

_init_lock = threading.Lock()
_initialised: set = set()


def _db_path() -> Path:
    from lsadra.config import INTEL_RUNTIME_DB

    return Path(INTEL_RUNTIME_DB)


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        key = str(path)
        if key not in _initialised:
            with _init_lock:
                conn.executescript(_SCHEMA)
                _initialised.add(key)
        yield conn
    finally:
        conn.close()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ip_bytes(addr: ipaddress._BaseAddress) -> bytes:
    if addr.version == 4:
        addr = ipaddress.IPv6Address(b"\x00" * 10 + b"\xff\xff" + addr.packed)
    return addr.packed


def parse_range(value: str) -> Optional[Tuple[bytes, bytes]]:
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None
    return ip_bytes(net.network_address), ip_bytes(net.broadcast_address)


# ── Feeds ────────────────────────────────────────────────────────────────


def get_feed_state(feed_id: str) -> Optional[Dict[str, Any]]:
    with connect() as conn:
        r = conn.execute("SELECT * FROM feed_state WHERE feed_id = ?", (feed_id,)).fetchone()
        return dict(r) if r else None


def all_feed_states() -> List[Dict[str, Any]]:
    with connect() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM feed_state ORDER BY feed_id")]


def record_feed_result(feed_id: str, url: str, status: str, error: str = "",
                       etag: str = "", last_modified: str = "") -> None:
    with connect() as conn:
        conn.execute(
            """INSERT INTO feed_state (feed_id, url, etag, last_modified, fetched_at, status, error)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(feed_id) DO UPDATE SET
                 url = excluded.url,
                 etag = COALESCE(NULLIF(excluded.etag, ''), feed_state.etag),
                 last_modified = COALESCE(NULLIF(excluded.last_modified, ''),
                                          feed_state.last_modified),
                 fetched_at = excluded.fetched_at,
                 status = excluded.status,
                 error = excluded.error""",
            (feed_id, url, etag, last_modified, _now(), status, error),
        )
        conn.commit()


def replace_feed(feed_id: str, url: str, entries: Iterable[Tuple[str, str]],
                 etag: str = "", last_modified: str = "") -> int:
    """Atomically replace a feed's indicators with ``(value, label)`` entries."""
    now = _now()
    rows = []
    for value, label in entries:
        rng = parse_range(value)
        if rng is None:
            continue
        rows.append((feed_id, value.strip(), rng[0], rng[1], label or "", now, now))
    with connect() as conn:
        old_first_seen = dict(conn.execute(
            "SELECT value, first_seen FROM indicator WHERE feed_id = ?", (feed_id,)
        ).fetchall())
        rows = [r[:5] + (old_first_seen.get(r[1], now), now) for r in rows]
        conn.execute("DELETE FROM indicator WHERE feed_id = ?", (feed_id,))
        conn.executemany(
            "INSERT OR REPLACE INTO indicator VALUES (?, ?, ?, ?, ?, ?, ?)", rows
        )
        conn.execute(
            """INSERT INTO feed_state (feed_id, url, etag, last_modified, fetched_at,
                                       changed_at, records, status, error)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'ok', '')
               ON CONFLICT(feed_id) DO UPDATE SET
                 url = excluded.url, etag = excluded.etag,
                 last_modified = excluded.last_modified, fetched_at = excluded.fetched_at,
                 changed_at = excluded.changed_at, records = excluded.records,
                 status = 'ok', error = ''""",
            (feed_id, url, etag, last_modified, now, now, len(rows)),
        )
        conn.commit()
    return len(rows)


def match_ip(ip: str) -> List[Dict[str, Any]]:
    """Every feed indicator whose IP or range contains ``ip``."""
    try:
        b = ip_bytes(ipaddress.ip_address(ip))
    except ValueError:
        return []
    with connect() as conn:
        rows = conn.execute(
            """SELECT i.feed_id, i.value, i.label, i.first_seen, i.last_seen, f.changed_at
               FROM indicator i LEFT JOIN feed_state f ON f.feed_id = i.feed_id
               WHERE i.net_start <= ? AND i.net_end >= ?
               ORDER BY i.feed_id, i.value""",
            (b, b),
        ).fetchall()
        return [dict(r) for r in rows]


# ── AbuseIPDB cache ──────────────────────────────────────────────────────


def get_abuse(ip: str) -> Optional[Dict[str, Any]]:
    with connect() as conn:
        r = conn.execute(
            "SELECT * FROM abuseipdb_cache WHERE ip_address = ? AND expires_at > ?",
            (ip, _now()),
        ).fetchone()
        if not r:
            return None
        d = dict(r)
        d["is_tor"] = bool(d.get("is_tor"))
        return d


def put_abuse(ip: str, data: Dict[str, Any], cache_hours: int) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    with connect() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO abuseipdb_cache VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ip,
                int(data.get("abuseConfidenceScore") or 0),
                data.get("countryCode") or "",
                data.get("isp") or "",
                data.get("domain") or "",
                1 if data.get("isTor") else 0,
                int(data.get("totalReports") or 0),
                data.get("lastReportedAt") or "",
                now.isoformat(),
                (now + timedelta(hours=cache_hours)).isoformat(),
            ),
        )
        conn.commit()


def expiring_abuse(limit: int = 50) -> List[str]:
    cutoff = (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0).isoformat()
    with connect() as conn:
        return [r[0] for r in conn.execute(
            "SELECT ip_address FROM abuseipdb_cache WHERE expires_at <= ? "
            "ORDER BY expires_at LIMIT ?", (cutoff, limit)
        )]
