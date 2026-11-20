"""
Runtime-tier fetchers (ADR 0004). Nothing here runs unless the operator opts in.

Keyless list feeds, enabled with ``LSADRA_INTEL_FEEDS`` (comma-separated):

- ``feodo``         abuse.ch Feodo Tracker botnet C2 IP blocklist (CC0).
- ``spamhaus_drop`` Spamhaus DROP, IPv4 and IPv6 ("Don't Route Or Peer"
                    hijacked or criminal netblocks; free use, no redistribution).
- ``tor_exits``     Tor Project bulk exit list.

Each fetch is a conditional GET (If-None-Match / If-Modified-Since), so an
unchanged list costs one small 304 response. Results go only to the local
``intel_runtime.db``.

The keyed source is AbuseIPDB, used only when ``LSADRA_ABUSEIPDB_API_KEY`` is
set. A lookup sends the IP address to AbuseIPDB, so it never happens without
that key.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from lsadra.intel import runtime

logger = logging.getLogger(__name__)

USER_AGENT = "lsadra-intel/1 (+https://github.com/tsmanral/lsadra)"


def _parse_feodo(body: bytes) -> Iterable[Tuple[str, str]]:
    for row in json.loads(body):
        ip = row.get("ip_address")
        if ip:
            yield ip, row.get("malware") or "botnet C2"


def _parse_spamhaus(body: bytes) -> Iterable[Tuple[str, str]]:
    for line in body.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("type") == "metadata" or "cidr" not in row:
            continue
        yield row["cidr"], row.get("sblid") or "DROP"


def _parse_tor(body: bytes) -> Iterable[Tuple[str, str]]:
    for line in body.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            yield line, "tor-exit"


@dataclass(frozen=True)
class Feed:
    feed_id: str
    name: str
    url: str
    parse: Callable[[bytes], Iterable[Tuple[str, str]]]
    category: str  # what a match means, shown to analysts


FEEDS: Dict[str, Feed] = {
    f.feed_id: f
    for f in (
        Feed(
            "feodo",
            "abuse.ch Feodo Tracker",
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            _parse_feodo,
            "botnet_c2",
        ),
        Feed(
            "spamhaus_drop_v4",
            "Spamhaus DROP (IPv4)",
            "https://www.spamhaus.org/drop/drop_v4.json",
            _parse_spamhaus,
            "hijacked_netblock",
        ),
        Feed(
            "spamhaus_drop_v6",
            "Spamhaus DROP (IPv6)",
            "https://www.spamhaus.org/drop/drop_v6.json",
            _parse_spamhaus,
            "hijacked_netblock",
        ),
        Feed(
            "tor_exits",
            "Tor exit nodes",
            "https://check.torproject.org/torbulkexitlist",
            _parse_tor,
            "tor_exit",
        ),
    )
}

# Names accepted in LSADRA_INTEL_FEEDS -> feed ids.
ALIASES: Dict[str, List[str]] = {
    "feodo": ["feodo"],
    "spamhaus_drop": ["spamhaus_drop_v4", "spamhaus_drop_v6"],
    "tor_exits": ["tor_exits"],
}


def enabled_feed_ids(names: Optional[Iterable[str]] = None) -> List[str]:
    if names is None:
        from lsadra.config import INTEL_FEEDS

        names = INTEL_FEEDS
    ids: List[str] = []
    for n in names:
        for fid in ALIASES.get(n.strip().lower(), []):
            if fid not in ids:
                ids.append(fid)
        if n.strip().lower() not in ALIASES:
            logger.warning("Unknown intel feed %r ignored (known: %s)", n, sorted(ALIASES))
    return ids


def update_feed(feed: Feed, client) -> Dict[str, object]:
    """Conditional GET + replace. ``client`` is an httpx.Client."""
    state = runtime.get_feed_state(feed.feed_id) or {}
    headers = {"User-Agent": USER_AGENT}
    if state.get("etag"):
        headers["If-None-Match"] = state["etag"]
    if state.get("last_modified"):
        headers["If-Modified-Since"] = state["last_modified"]
    try:
        r = client.get(feed.url, headers=headers)
        if r.status_code == 304:
            runtime.record_feed_result(feed.feed_id, feed.url, "not_modified")
            return {"feed": feed.feed_id, "status": "not_modified"}
        r.raise_for_status()
        entries = list(feed.parse(r.content))
        if not entries:
            raise ValueError("feed returned no indicators; keeping the previous copy")
        n = runtime.replace_feed(
            feed.feed_id,
            feed.url,
            entries,
            etag=r.headers.get("ETag", ""),
            last_modified=r.headers.get("Last-Modified", ""),
        )
        return {"feed": feed.feed_id, "status": "ok", "records": n}
    except Exception as exc:  # network, HTTP, or parse failure: keep the old data
        logger.warning("Intel feed %s update failed: %s", feed.feed_id, exc)
        runtime.record_feed_result(feed.feed_id, feed.url, "error", error=str(exc)[:300])
        return {"feed": feed.feed_id, "status": "error", "error": str(exc)[:300]}


def update_feeds(
    names: Optional[Iterable[str]] = None, client=None, only_if_due: bool = False
) -> List[Dict[str, object]]:
    """Update every enabled feed (or ``names``). Returns one result per feed."""
    from lsadra.config import INTEL_FEED_REFRESH_HOURS

    ids = enabled_feed_ids(names)
    if not ids:
        return []
    own_client = client is None
    if own_client:
        import httpx

        client = httpx.Client(timeout=60.0, follow_redirects=True)
    try:
        results = []
        for fid in ids:
            if only_if_due:
                st = runtime.get_feed_state(fid) or {}
                last = st.get("fetched_at")
                if last and datetime.fromisoformat(last) > datetime.now(timezone.utc) - timedelta(
                    hours=INTEL_FEED_REFRESH_HOURS
                ):
                    continue
            results.append(update_feed(FEEDS[fid], client))
        return results
    finally:
        if own_client:
            client.close()


# ── AbuseIPDB (keyed, opt-in) ────────────────────────────────────────────


async def query_abuseipdb(ip: str, client=None) -> Optional[dict]:
    """Look ``ip`` up on AbuseIPDB and cache it. None without a key or on failure."""
    from lsadra.config import ABUSEIPDB_API_KEY, THREAT_INTEL_CACHE_HOURS

    cached = runtime.get_abuse(ip)
    if cached:
        return cached
    if not ABUSEIPDB_API_KEY:
        return None
    import httpx

    own = client is None
    if own:
        client = httpx.AsyncClient(timeout=10.0)
    try:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
            params={"ipAddress": ip, "maxAgeInDays": "90"},
        )
        r.raise_for_status()
        data = r.json().get("data", {})
        runtime.put_abuse(ip, data, THREAT_INTEL_CACHE_HOURS)
        return runtime.get_abuse(ip)
    except Exception as exc:
        logger.warning("AbuseIPDB lookup failed for %s: %s", ip, type(exc).__name__)
        return None
    finally:
        if own:
            await client.aclose()
