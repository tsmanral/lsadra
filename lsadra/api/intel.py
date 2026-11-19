"""
Threat intel API (/api/intel), backed by lsadra.intel (ADR 0004 two tiers).

Every answer comes from a real source: the signed bundle, the local runtime
DB, the local geolocation file, or AbuseIPDB when the operator configured a
key. Nothing is simulated; unknown is reported as unknown.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from starlette.concurrency import run_in_threadpool

from lsadra import intel
from lsadra.auth import require_role
from lsadra.intel import bundle, feeds

router = APIRouter(tags=["intel"])

_ANY_ROLE = require_role("ADMIN", "ANALYST", "VIEWER")


@router.get("/status")
async def intel_status(user: dict = Depends(_ANY_ROLE)) -> Dict[str, Any]:
    return await run_in_threadpool(intel.status)


@router.get("/ip/{ip}")
async def intel_ip(
    ip: str,
    remote: bool = Query(False, description="Also ask AbuseIPDB (needs a configured key)"),
    user: dict = Depends(_ANY_ROLE),
) -> Dict[str, Any]:
    if intel.ip_scope(ip) is None:
        raise HTTPException(status_code=422, detail="Not an IP address.")
    # Only analysts and admins may cause an outbound query with the operator's key.
    allow_remote = remote and user["role"] in ("ADMIN", "ANALYST")
    if allow_remote:
        return await intel.lookup_ip_async(ip, allow_remote=True)
    return await run_in_threadpool(intel.lookup_ip, ip)


@router.get("/cve/{cve_id}")
async def intel_cve(cve_id: str, user: dict = Depends(_ANY_ROLE)) -> Dict[str, Any]:
    row = await run_in_threadpool(bundle.lookup_cve, cve_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Not in the CISA KEV catalog.")
    return row


@router.get("/kev")
async def intel_kev(
    q: str = Query("", max_length=100),
    limit: int = Query(25, ge=1, le=200),
    user: dict = Depends(_ANY_ROLE),
) -> List[Dict[str, Any]]:
    return await run_in_threadpool(bundle.search_kev, q, limit)


@router.get("/technique/{technique_id}")
async def intel_technique(technique_id: str, user: dict = Depends(_ANY_ROLE)) -> Dict[str, Any]:
    row = await run_in_threadpool(bundle.lookup_technique, technique_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Unknown ATT&CK technique.")
    return row


def _flagged_ips(user_id: Optional[str], limit: int) -> List[Dict[str, Any]]:
    from lsadra.storage.database import get_connection

    sql = """SELECT source_ip AS ip, COUNT(*) AS anomalies,
                    MAX(severity_score) AS max_severity, MAX(created_at) AS last_seen
             FROM anomalies
             WHERE is_anomaly = 1 AND source_ip IS NOT NULL AND source_ip != ''"""
    params: list = []
    if user_id:
        sql += " AND user_id = ?"
        params.append(user_id)
    sql += " GROUP BY source_ip ORDER BY anomalies DESC, last_seen DESC LIMIT 1000"
    conn = get_connection()
    try:
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()
    out = []
    for r in rows:
        if intel.ip_scope(r["ip"]) != "public":
            continue
        info = intel.lookup_ip(r["ip"])
        r["country_code"] = (info.get("geo") or {}).get("country_code") or (
            (info.get("abuseipdb") or {}).get("country_code") or "")
        r["verdict"] = info["verdict"]["level"]
        r["feed_matches"] = len(info.get("feed_matches") or [])
        r["abuse_score"] = (info.get("abuseipdb") or {}).get("abuse_score")
        out.append(r)
        if len(out) >= limit:
            break
    return out


@router.get("/flagged-ips")
async def intel_flagged_ips(
    limit: int = Query(20, ge=1, le=100),
    user: dict = Depends(_ANY_ROLE),
) -> List[Dict[str, Any]]:
    """Public source IPs seen in anomalies, with local enrichment. Scoped to the
    caller's own anomalies unless they are an admin."""
    uid = None if user["role"] == "ADMIN" else user["user_id"]
    return await run_in_threadpool(_flagged_ips, uid, limit)


@router.post("/feeds/refresh")
async def intel_feeds_refresh(user: dict = Depends(require_role("ADMIN"))) -> Dict[str, Any]:
    ids = feeds.enabled_feed_ids()
    if not ids:
        raise HTTPException(status_code=409,
                            detail="No intel feeds enabled. Set LSADRA_INTEL_FEEDS.")
    return {"results": await run_in_threadpool(feeds.update_feeds)}
