"""
LSADRA — investigation API for the React dashboard.

Real-data endpoints behind pages that used to show canned values:

* ``GET  /api/incidents/{id}``  incident drill-down: the incident, every alert
  in it (with narrative and raw log line), the entities involved and the
  response playbook.
* ``GET  /api/entity?q=...``    entity profile for an IP, user name, host or
  incident id: risk, alerts, related incidents and related entities.
* ``GET  /api/feedback``        analyst true/false-positive labels and totals.
* ``POST /api/feedback``        record a label for one alert.

Scoping rule: an ADMIN sees everything; any other role sees only data from
devices it owns (``devices.user_id``). Something that exists but belongs to
another user answers 404, the same as something that does not exist, so ids
cannot be probed.

Off-loop rule (as in ``api_dashboard``): each handler runs its SQLite work in
one ``run_in_threadpool`` call.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from lsadra.auth import require_role
from lsadra.detection.playbooks import get_playbook
from lsadra.storage.database import get_connection, store_feedback

router = APIRouter(tags=["investigation"])

ALL_ROLES = ("ADMIN", "ANALYST", "VIEWER")
MAX_ALERTS = 500
MAX_ENTITY_ALERTS = 200
MAX_RAW_EVENTS = 25

_INCIDENT_RE = re.compile(r"^(?:inc[_-]?|#)?(\d{1,12})$", re.IGNORECASE)


def _scope(user: Dict[str, Any]) -> Optional[str]:
    """The owner id to filter by, or None for an admin (sees everything)."""
    return None if user["role"] == "ADMIN" else user["user_id"]


def _risk(score: Optional[float]) -> Optional[int]:
    if score is None:
        return None
    return int(round(max(0.0, min(float(score), 1.0)) * 100))


def _distinct(values) -> List[str]:
    seen: Dict[str, None] = {}
    for v in values:
        if v not in (None, ""):
            seen.setdefault(str(v), None)
    return list(seen)


_ALERT_COLUMNS = """
    a.id, a.created_at, a.device_id, a.source_ip, a.severity_score,
    a.severity_label, a.threat_type, a.attack_type, a.mitre_technique,
    a.narrative, a.incident_id,
    e.timestamp AS event_time, e.host, e.effective_username, e.event_type,
    e.raw_message
"""


def _alert_row(r: Dict[str, Any]) -> Dict[str, Any]:
    d = dict(r)
    d["risk_score"] = _risk(d.get("severity_score"))
    return d


# ── Incident drill-down ──────────────────────────────────────────────────


def _incident_detail(incident_id: int, uid: Optional[str]) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    try:
        sql = (
            "SELECT i.*, d.hostname AS device_hostname, d.os_type AS device_os, "
            "u.username AS assigned_username "
            "FROM incidents i "
            "LEFT JOIN devices d ON d.id = i.device_id "
            "LEFT JOIN users u ON u.id = i.assigned_to "
            "WHERE i.id = ?"
        )
        params: List[Any] = [incident_id]
        if uid:
            sql += " AND d.user_id = ?"
            params.append(uid)
        row = conn.execute(sql, tuple(params)).fetchone()
        if not row:
            return None
        incident = dict(row)

        alerts = [
            _alert_row(r)
            for r in conn.execute(
                f"SELECT {_ALERT_COLUMNS} FROM anomalies a "  # noqa: S608 - constant SQL fragments, every value bound as ?
                "LEFT JOIN normalized_events e ON e.id = a.event_id "
                "WHERE a.incident_id = ? ORDER BY a.created_at ASC, a.id ASC LIMIT ?",
                (incident_id, MAX_ALERTS),
            ).fetchall()
        ]
        total_alerts = conn.execute(
            "SELECT COUNT(*) FROM anomalies WHERE incident_id = ?", (incident_id,)
        ).fetchone()[0]
    finally:
        conn.close()

    scores = [a["severity_score"] for a in alerts if a.get("severity_score") is not None]
    techniques = _distinct(a.get("mitre_technique") for a in alerts)
    playbook = get_playbook(incident.get("playbook"))
    return {
        "incident": incident,
        "risk_score": _risk(max(scores)) if scores else None,
        "alerts": alerts,
        "alert_total": total_alerts,
        "alerts_truncated": total_alerts > len(alerts),
        "entities": {
            "source_ips": _distinct([incident.get("source_ip")] + [a.get("source_ip") for a in alerts]),
            "users": _distinct(a.get("effective_username") for a in alerts),
            "hosts": _distinct(
                [incident.get("device_hostname")] + [a.get("host") for a in alerts]
            ),
            "mitre_techniques": techniques,
        },
        "playbook": playbook,
    }


@router.get("/incidents/{incident_id}")
async def api_incident_detail(incident_id: int, user: dict = Depends(require_role(*ALL_ROLES))):
    detail = await run_in_threadpool(_incident_detail, incident_id, _scope(user))
    if detail is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return detail


# ── Entity lookup ────────────────────────────────────────────────────────


def _classify(q: str, alerts: List[Dict[str, Any]], is_device: bool) -> str:
    try:
        ipaddress.ip_address(q)
        return "IP"
    except ValueError:
        pass
    if is_device or any(a.get("host") == q for a in alerts):
        return "Host"
    return "User"


def _entity(q: str, uid: Optional[str]) -> Optional[Dict[str, Any]]:
    m = _INCIDENT_RE.match(q)
    if m:
        detail = _incident_detail(int(m.group(1)), uid)
        if detail is None:
            return None
        return {"entity": q, "type": "Incident", "incident_id": detail["incident"]["id"]}

    conn = get_connection()
    try:
        own = " AND d.user_id = ?" if uid else ""
        own_params: List[Any] = [uid] if uid else []

        device_row = conn.execute(
            "SELECT d.id, d.hostname FROM devices d WHERE (d.id = ? OR d.hostname = ?)" + own,  # noqa: S608 - constant SQL fragments, every value bound as ?
            tuple([q, q] + own_params),
        ).fetchone()
        device_ids = [device_row["id"]] if device_row else []

        match = "(a.source_ip = ? OR e.effective_username = ? OR e.host = ?"
        params: List[Any] = [q, q, q]
        if device_ids:
            match += " OR a.device_id = ?"
            params.append(device_ids[0])
        match += ")"

        alerts = [
            _alert_row(r)
            for r in conn.execute(
                f"SELECT {_ALERT_COLUMNS} FROM anomalies a "  # noqa: S608 - constant SQL fragments, every value bound as ?
                "LEFT JOIN normalized_events e ON e.id = a.event_id "
                "JOIN devices d ON d.id = a.device_id "
                f"WHERE a.is_anomaly = 1 AND {match}{own} "
                "ORDER BY a.created_at DESC LIMIT ?",
                tuple(params + own_params + [MAX_ENTITY_ALERTS]),
            ).fetchall()
        ]

        ev_match = "(e.source_ip = ? OR e.effective_username = ? OR e.host = ?"
        ev_params: List[Any] = [q, q, q]
        if device_ids:
            ev_match += " OR e.device_id = ?"
            ev_params.append(device_ids[0])
        ev_match += ")"
        ev_from = "FROM normalized_events e JOIN devices d ON d.id = e.device_id "
        event_total = conn.execute(
            f"SELECT COUNT(*) {ev_from} WHERE {ev_match}{own}",
            tuple(ev_params + own_params),
        ).fetchone()[0]
        raw_events = [
            dict(r)
            for r in conn.execute(
                "SELECT e.id, e.timestamp, e.device_id, e.host, e.effective_username, "
                f"e.source_ip, e.event_type, e.raw_message {ev_from} "
                f"WHERE {ev_match}{own} ORDER BY e.timestamp DESC LIMIT ?",
                tuple(ev_params + own_params + [MAX_RAW_EVENTS]),
            ).fetchall()
        ]

        incident_ids = _distinct(a.get("incident_id") for a in alerts)
        incidents: List[Dict[str, Any]] = []
        if incident_ids:
            marks = ",".join("?" for _ in incident_ids)
            incidents = [
                dict(r)
                for r in conn.execute(
                    "SELECT id, attack_type, severity_label, status, first_seen, last_seen "  # noqa: S608 - constant SQL fragments, every value bound as ?
                    f"FROM incidents WHERE id IN ({marks}) ORDER BY last_seen DESC",
                    tuple(int(i) for i in incident_ids),
                ).fetchall()
            ]
    finally:
        conn.close()

    if not alerts and not event_total and not device_row:
        return None

    kind = _classify(q, alerts, bool(device_row))
    scores = [a["severity_score"] for a in alerts if a.get("severity_score") is not None]
    times = sorted(_distinct([a.get("created_at") for a in alerts] + [e.get("timestamp") for e in raw_events]))

    hosts = _distinct([a.get("host") for a in alerts] + [e.get("host") for e in raw_events])
    users = _distinct([a.get("effective_username") for a in alerts] + [e.get("effective_username") for e in raw_events])
    ips = _distinct([a.get("source_ip") for a in alerts] + [e.get("source_ip") for e in raw_events])
    relationships = (
        [{"type": "Host", "target": h} for h in hosts if h != q]
        + [{"type": "User", "target": u} for u in users if u != q]
        + [{"type": "IP", "target": i} for i in ips if i != q]
    )

    return {
        "entity": q,
        "type": kind,
        "risk_score": _risk(max(scores)) if scores else 0,
        "alert_count": len(alerts),
        "alerts_truncated": len(alerts) >= MAX_ENTITY_ALERTS,
        "event_count": event_total,
        "first_seen": times[0] if times else None,
        "last_seen": times[-1] if times else None,
        "affected_hosts": hosts,
        "affected_users": users,
        "source_ips": ips,
        "relationships": relationships[:24],
        "related_incidents": incidents,
        "alerts": alerts,
        "recent_events": raw_events,
    }


@router.get("/entity")
async def api_entity(
    q: str = Query(..., min_length=1, max_length=256),
    user: dict = Depends(require_role(*ALL_ROLES)),
):
    q = q.strip()
    if not q:
        raise HTTPException(status_code=422, detail="Empty query.")
    result = await run_in_threadpool(_entity, q, _scope(user))
    if result is None:
        raise HTTPException(status_code=404, detail="No activity on record for this entity.")
    return result


# ── Analyst feedback ─────────────────────────────────────────────────────


class FeedbackRequest(BaseModel):
    alert_id: int = Field(..., ge=1)
    label: Literal["true_positive", "false_positive"]
    note: str = Field("", max_length=2000)


def _feedback(uid: Optional[str], limit: int) -> Dict[str, Any]:
    conn = get_connection()
    try:
        join = (
            "FROM alerts_feedback f "
            "LEFT JOIN anomalies a ON a.id = f.alert_id "
            "LEFT JOIN devices d ON d.id = a.device_id "
        )
        where = " WHERE d.user_id = ?" if uid else ""
        params: List[Any] = [uid] if uid else []
        rows = conn.execute(
            "SELECT f.id, f.alert_id, f.label, f.analyst_note, f.fp_pattern, "
            "f.source_type, f.created_at, a.threat_type, a.severity_label, "
            f"a.source_ip, a.incident_id {join}{where} "
            "ORDER BY f.created_at DESC, f.id DESC LIMIT ?",
            tuple(params + [limit]),
        ).fetchall()
        counts = conn.execute(
            "SELECT COUNT(*) AS total, "
            "COALESCE(SUM(CASE WHEN f.label = 'true_positive' THEN 1 ELSE 0 END), 0) AS tp, "
            "COALESCE(SUM(CASE WHEN f.label = 'false_positive' THEN 1 ELSE 0 END), 0) AS fp "
            f"{join}{where}",
            tuple(params),
        ).fetchone()
    finally:
        conn.close()
    total, tp, fp = int(counts["total"]), int(counts["tp"]), int(counts["fp"])
    return {
        "items": [dict(r) for r in rows],
        "total": total,
        "true_positives": tp,
        "false_positives": fp,
        # Share of labelled alerts that analysts confirmed as real threats.
        "precision": round(tp / total, 4) if total else None,
    }


@router.get("/feedback")
async def api_feedback(
    limit: int = Query(200, ge=1, le=1000),
    user: dict = Depends(require_role(*ALL_ROLES)),
):
    return await run_in_threadpool(_feedback, _scope(user), limit)


def _record_feedback(req: FeedbackRequest, uid: Optional[str]) -> bool:
    from lsadra.explainability.narrative_builder import analyze_false_positive

    conn = get_connection()
    try:
        sql = (
            "SELECT a.id, a.threat_type, e.attributes FROM anomalies a "
            "LEFT JOIN normalized_events e ON e.id = a.event_id "
            "LEFT JOIN devices d ON d.id = a.device_id WHERE a.id = ?"
        )
        params: List[Any] = [req.alert_id]
        if uid:
            sql += " AND d.user_id = ?"
            params.append(uid)
        row = conn.execute(sql, tuple(params)).fetchone()
    finally:
        conn.close()
    if not row:
        return False

    source_type = None
    try:
        attrs = json.loads(row["attributes"] or "{}")
        if isinstance(attrs, dict):
            source_type = attrs.get("source_type")
    except (TypeError, ValueError):
        pass

    fp_pattern, thresholds = "", {}
    if req.label == "false_positive":
        analysis = analyze_false_positive({"type": row["threat_type"] or "UNKNOWN"}, req.note)
        fp_pattern = str(analysis.get("pattern") or "")
        thresholds = analysis.get("suggested_threshold_change") or {}

    store_feedback(None, req.alert_id, req.label, req.note, fp_pattern, thresholds, source_type)
    return True


@router.post("/feedback", status_code=201)
async def api_record_feedback(req: FeedbackRequest, user: dict = Depends(require_role("ADMIN", "ANALYST"))):
    if not await run_in_threadpool(_record_feedback, req, _scope(user)):
        raise HTTPException(status_code=404, detail="Alert not found.")
    return {"status": "ok", "alert_id": req.alert_id, "label": req.label}
