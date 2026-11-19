"""
Alerts from the scheduler's database scans (roadmap W5).

The event pipeline (``detection_orchestrator``) looks at one device's new
events at a time. Two patterns only show up across devices and log sources, so
the scheduler finds them with SQL instead:

- **Lateral movement** (rule ``lsadra-lateral-remote-services``, ATT&CK T1021):
  one source address reaches 3 or more users or devices inside the window.
  :func:`raise_lateral_movement` turns a finding into a stored alert, links it
  to an incident, publishes it to ``/ws/alerts`` and adds a risk signal to
  every host and account it touched. One address raises one alert per window:
  while an earlier alert for it is younger than the window, later scans see
  the same evidence and stay quiet.
- **Cross-source corroboration**: an address active in two or more log-source
  families. That alone is ordinary (an admin who logs in over SSH also makes
  network connections), so it never alerts by itself. When the address already
  has an open incident, :func:`corroborate_cross_source` raises that incident's
  severity one step, once per incident. The per-event rules apply the same
  elevation to new matches (``rule_engine._apply_cross_source``); this covers
  incidents opened before the second source showed up.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from lsadra.detection.rule_engine import LATERAL_RULE_ID, RULES
from lsadra.detection.severity import apply_rule_floor
from lsadra.explainability.sanitize import clean_field

logger = logging.getLogger(__name__)

#: Accounts named by failed logins are usually the target, not the actor
#: (same rule as lsadra/detection/risk.py), so they get no user risk.
_FAILED_LOGIN_TYPES = ("auth_failure",)
_MAX_NAMED = 5  # entities spelled out in a narrative before "and N more"


def _created_at_cutoff(minutes: int) -> str:
    """``anomalies.created_at`` format (SQLite CURRENT_TIMESTAMP, UTC)."""
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _named(values: List[str]) -> str:
    shown = ", ".join(clean_field(v, max_len=64) for v in values[:_MAX_NAMED])
    extra = len(values) - _MAX_NAMED
    return f"{shown} and {extra} more" if extra > 0 else shown


def _touched(
    conn: sqlite3.Connection, ip: str, since_iso: str
) -> Tuple[List[Tuple[str, str]], List[str]]:
    """(device_id, host) pairs and the accounts *ip* used, inside the window."""
    devices = conn.execute(
        """SELECT DISTINCT device_id, COALESCE(host, '') FROM normalized_events
           WHERE source_ip = ? AND timestamp >= ? AND device_id IS NOT NULL
           ORDER BY device_id, 2""",
        (ip, since_iso),
    ).fetchall()
    placeholders = ",".join("?" for _ in _FAILED_LOGIN_TYPES)
    users = conn.execute(
        f"""SELECT DISTINCT effective_username FROM normalized_events
            WHERE source_ip = ? AND timestamp >= ?
              AND effective_username IS NOT NULL AND effective_username != ''
              AND event_type NOT IN ({placeholders})
            ORDER BY effective_username""",
        (ip, since_iso, *_FAILED_LOGIN_TYPES),
    ).fetchall()
    return [(str(d[0]), str(d[1])) for d in devices], [str(u[0]) for u in users]


def _record_risk(alert: Dict[str, Any], devices: List[Tuple[str, str]], users: List[str]) -> None:
    """Add the alert as a risk signal to every host and account it touched."""
    from lsadra.detection.risk import record, risk_mode

    mode = risk_mode()
    if mode == "off":
        return
    hit = {
        "rule_id": alert["rule_id"], "title": alert["threat_type"],
        "level": alert["level"], "technique": alert["mitre_technique"],
        "tactics": list(alert["mitre_tactics"]),
    }
    common = {"event_id": None, "created_at": alert["created_at"], "is_anomaly": True,
              "event_type": "lateral_movement", "rule_hits": [hit]}
    results: List[Dict[str, Any]] = []
    for device_id, host in devices:
        results.append(dict(common, device_id=device_id, host=host or device_id,
                            effective_username=""))
    for user in users:
        # No host: the signal belongs to the account alone.
        results.append(dict(common, device_id="", host="", effective_username=user))
    if results:
        record(results, mode)


def raise_lateral_movement(
    conn: sqlite3.Connection, finding: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Store, link and publish one lateral movement finding.

    *finding* is what ``rule_engine.detect_lateral_movement`` returned.
    Returns the stored alert, or ``None`` when this address already alerted in
    the current window.
    """
    from lsadra.detection.incident_manager import IncidentManager
    from lsadra.storage.database import get_recent_rule_alert, insert_anomaly
    from lsadra.ui.alert_stream import alert_hub

    rule = RULES[LATERAL_RULE_ID]
    ip = str(finding["ip"])
    window = int(finding.get("window_minutes") or 30)
    if get_recent_rule_alert(rule.id, ip, _created_at_cutoff(window)):
        return None

    since_iso = (datetime.utcnow() - timedelta(minutes=window)).isoformat()
    devices, users = _touched(conn, ip, since_iso)
    device_ids = sorted({d for d, _ in devices})
    score, label = apply_rule_floor(0.0, "LOW", finding.get("severity") or "HIGH")
    narrative = (
        f"Address {clean_field(ip, max_len=64)} reached "
        f"{int(finding.get('unique_users') or len(users))} account(s) and "
        f"{int(finding.get('unique_devices') or len(device_ids))} device(s) in {window} minutes"
    )
    if users:
        narrative += f". Accounts used: {_named(users)}"
    if device_ids:
        narrative += f". Devices: {_named(device_ids)}"
    narrative += f". Rule {rule.id} v{rule.version}, ATT&CK {finding.get('mitre_id', 'T1021')}."

    alert: Dict[str, Any] = {
        "event_id": None,
        # Incidents group by (device, address, type): the first device keeps
        # repeat findings for one address on one incident.
        "device_id": device_ids[0] if device_ids else None,
        "user_id": None,  # spans devices and owners: admins see it live
        "source_ip": ip,
        "severity_score": score,
        "severity_label": label,
        "is_anomaly": True,
        "threat_type": rule.title,
        "attack_type": rule.title,
        "mitre_technique": finding.get("mitre_id", "T1021"),
        "mitre_confidence": rule.confidence,
        "mitre_tactics": list(finding.get("mitre_tactics") or []),
        "rule_id": rule.id,
        "rule_version": rule.version,
        "level": finding.get("level") or rule.level,
        "narrative": narrative,
        "shap_values": {},
    }
    alert["anomaly_id"] = insert_anomaly(alert)
    alert["created_at"] = _now_iso()
    try:
        alert["incident_id"] = IncidentManager().process_anomaly(alert)
    except Exception:
        logger.exception("Could not link the lateral movement alert for %s to an incident", ip)
    alert_hub.publish(alert)  # never raises
    try:
        _record_risk(alert, devices, users)
    except Exception:
        logger.exception("Entity risk scoring failed for the lateral movement alert for %s", ip)
    logger.warning("Lateral movement alert %s raised for %s: %s",
                   alert["anomaly_id"], ip, finding.get("reason", ""))
    return alert


def corroborate_cross_source(ip: str, source_count: int) -> List[Dict[str, Any]]:
    """Raise each open incident from *ip* one severity step (once per incident)."""
    from lsadra.storage.database import elevate_cross_source_incidents

    changed = elevate_cross_source_incidents(ip, _now_iso())
    for inc in changed:
        logger.warning(
            "Incident %s from %s raised %s -> %s: the address is active in %d log sources.",
            inc["id"], ip, inc["old"], inc["new"], source_count,
        )
    return changed
