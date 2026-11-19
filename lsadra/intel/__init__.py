"""
LSADRA threat intelligence, in two tiers (ADR 0004).

- Bundled tier (``bundle``): signed, hash-verified SQLite shipped in the
  package. CISA KEV and MITRE ATT&CK. Works offline with zero API keys.
- Runtime tier (``runtime``, ``feeds``, ``geo``): local, gitignored data the
  operator turns on. Keyless IP list feeds, optional AbuseIPDB, and a local
  ``.mmdb`` geolocation file.

Nothing here invents a score. When no source knows an IP, the answer says so.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, Optional

from lsadra.intel import bundle, feeds, geo, runtime

__all__ = ["lookup_ip", "lookup_ip_async", "status", "ip_scope", "legacy_view"]


# Networks to treat as public even though they are reserved. Empty in
# production; the test suite adds the RFC 5737 / RFC 3849 documentation ranges
# so synthetic data exercises the public-IP paths.
TREAT_AS_PUBLIC: tuple = ()


def is_public(addr) -> bool:
    return addr.is_global or any(addr in net for net in TREAT_AS_PUBLIC
                                 if net.version == addr.version)


def ip_scope(ip: str) -> Optional[str]:
    """'public', 'private', or 'reserved'; None if ``ip`` is not an IP address."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except (ValueError, AttributeError):
        return None
    if is_public(addr):
        return "public"
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return "private"
    return "reserved"


def _verdict(feed_hits, abuse, sources_checked) -> Dict[str, str]:
    categories = {h["category"] for h in feed_hits}
    if categories & {"botnet_c2", "hijacked_netblock"}:
        return {"level": "malicious", "reason": "listed on a blocklist feed"}
    if abuse and abuse.get("abuse_score", 0) >= 75:
        return {"level": "malicious", "reason": "AbuseIPDB confidence >= 75"}
    if "tor_exit" in categories:
        return {"level": "suspicious", "reason": "Tor exit node"}
    if abuse and abuse.get("abuse_score", 0) >= 25:
        return {"level": "suspicious", "reason": "AbuseIPDB confidence >= 25"}
    if sources_checked:
        return {"level": "not_listed",
                "reason": f"not listed in {len(sources_checked)} enabled source(s)"}
    return {"level": "unknown", "reason": "no IP reputation source is enabled"}


def lookup_ip(ip: str) -> Dict[str, Any]:
    """Everything known locally about ``ip``. Makes no network requests."""
    ip = (ip or "").strip()
    scope = ip_scope(ip)
    if scope is None:
        return {"ip": ip, "valid": False}
    ip = str(ipaddress.ip_address(ip))
    result: Dict[str, Any] = {"ip": ip, "valid": True, "scope": scope}
    if scope != "public":
        result.update(geo=None, feed_matches=[], abuseipdb=None, sources_checked=[],
                      verdict={"level": "internal", "reason": f"{scope} address"})
        return result

    enabled = [fid for fid in feeds.enabled_feed_ids()
               if (runtime.get_feed_state(fid) or {}).get("records")]
    hits = []
    for h in runtime.match_ip(ip):
        f = feeds.FEEDS.get(h["feed_id"])
        hits.append({
            "feed": h["feed_id"],
            "name": f.name if f else h["feed_id"],
            "category": f.category if f else "listed",
            "indicator": h["value"],
            "label": h["label"],
            "first_seen": h["first_seen"],
            "list_updated": h["changed_at"],
        })
    abuse = runtime.get_abuse(ip)
    checked = list(enabled)
    if abuse:
        checked.append("abuseipdb")
    result.update(
        geo=geo.lookup(ip),
        feed_matches=hits,
        abuseipdb=abuse,
        sources_checked=checked,
        verdict=_verdict(hits, abuse, checked),
    )
    return result


async def lookup_ip_async(ip: str, allow_remote: bool = False) -> Dict[str, Any]:
    """``lookup_ip`` plus an AbuseIPDB query when allowed and a key is configured."""
    res = lookup_ip(ip)
    if allow_remote and res.get("scope") == "public" and res.get("abuseipdb") is None:
        if await feeds.query_abuseipdb(res["ip"]):
            res = lookup_ip(ip)
    return res


def legacy_view(res: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The flat dict the narrative builder reads (abuse_score, country_code, ...).

    Returns None when nothing real is known, so callers never show a made-up 0.
    """
    if not res.get("valid") or res.get("scope") != "public":
        return None
    abuse = res.get("abuseipdb") or {}
    g = res.get("geo") or {}
    hits = res.get("feed_matches") or []
    if not (abuse or g or hits):
        return None
    out: Dict[str, Any] = {"ip_address": res["ip"]}
    if abuse:
        out.update({k: abuse.get(k) for k in
                    ("abuse_score", "isp", "domain", "total_reports", "last_reported")})
    out["country_code"] = abuse.get("country_code") or g.get("country_code", "")
    out["is_tor"] = bool(abuse.get("is_tor")) or any(h["category"] == "tor_exit" for h in hits)
    out["feed_matches"] = [f"{h['name']}: {h['label']}" for h in hits]
    return out


def status() -> Dict[str, Any]:
    from lsadra.config import ABUSEIPDB_API_KEY

    states = {s["feed_id"]: s for s in runtime.all_feed_states()}
    enabled = feeds.enabled_feed_ids()
    return {
        "bundled": bundle.status(),
        "runtime": {
            "feeds": [
                {
                    "feed": fid,
                    "name": feeds.FEEDS[fid].name,
                    "enabled": fid in enabled,
                    "records": (states.get(fid) or {}).get("records", 0),
                    "fetched_at": (states.get(fid) or {}).get("fetched_at"),
                    "changed_at": (states.get(fid) or {}).get("changed_at"),
                    "status": (states.get(fid) or {}).get("status", "never_fetched"),
                    "error": (states.get(fid) or {}).get("error") or None,
                }
                for fid in feeds.FEEDS
            ],
            "abuseipdb": {"configured": bool(ABUSEIPDB_API_KEY)},
        },
        "geo": geo.status(),
    }
