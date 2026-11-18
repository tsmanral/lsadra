"""Hash-chained audit trail, watched by LSADRA's own detection (G-26).

Every security-relevant action (logins, logouts, throttling, role and password
changes, account disable, TOTP enrolment, device revoke and key rotation,
retrain, backup and restore) is appended to ``audit_events``. Each row stores
the SHA-256 of the previous row's hash plus its own canonical content, so an
edit or a deleted row in the middle of the log breaks the chain, and
:func:`verify_chain` reports the first row that does not match. SQL triggers
(migration 005) refuse any UPDATE and any DELETE younger than 365 days.

Self-monitoring: a few events are also raised as LSADRA alerts (an anomaly
row plus a live /ws/alerts push to admins), so the product watches its own
control plane: a login lockout (ATT&CK T1110), a grant of the ADMIN role
(T1098), and a broken audit chain (T1565.001 / T1070).

Writing an audit row must never break the action it records: failures are
logged and swallowed. A broken chain is surfaced by the scheduled verify.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64
SELF_DEVICE_ID = "lsadra-server"

# action -> (threat_type, attack_type, MITRE technique, severity label, score)
_SELF_ALERTS = {
    "auth.login.lockout": (
        "Repeated failed logins to LSADRA", "brute_force", "T1110", "HIGH", 0.8),
    "user.role.grant_admin": (
        "ADMIN role granted on LSADRA", "privilege_change", "T1098", "MEDIUM", 0.5),
    "audit.chain.broken": (
        "LSADRA audit log was altered", "log_tampering", "T1070", "CRITICAL", 0.95),
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _row_hash(prev_hash: str, row: Dict[str, Any]) -> str:
    canonical = json.dumps(
        [
            row["ts"], row["actor_id"], row["actor_name"], row["action"],
            row["target"], row["outcome"], row["source_ip"], row["details"],
        ],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def record(
    action: str,
    outcome: str = "success",
    *,
    actor: Optional[Dict[str, Any]] = None,
    target: Optional[str] = None,
    source_ip: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Optional[int]:
    """Append one audit row; returns its id, or None if the write failed.

    *actor* is the current-user dict (``user_id``/``username``) or None.
    Runs synchronously (one short write transaction): call it from the
    threadpool, as every handler here does for storage work.
    """
    from lsadra.storage.database import get_connection

    row = {
        "ts": _now(),
        "actor_id": (actor or {}).get("user_id"),
        "actor_name": (actor or {}).get("username"),
        "action": action,
        "target": target,
        "outcome": outcome,
        "source_ip": source_ip,
        "details": json.dumps(details or {}, sort_keys=True, separators=(",", ":")),
    }
    try:
        conn = get_connection()
        try:
            # IMMEDIATE takes the write lock before reading the chain head, so two
            # writers can never both link to the same previous row.
            conn.execute("BEGIN IMMEDIATE")
            last = conn.execute(
                "SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = last[0] if last else GENESIS_HASH
            digest = _row_hash(prev_hash, row)
            cur = conn.execute(
                """INSERT INTO audit_events
                   (ts, actor_id, actor_name, action, target, outcome, source_ip,
                    details, prev_hash, hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (row["ts"], row["actor_id"], row["actor_name"], action, target,
                 outcome, source_ip, row["details"], prev_hash, digest),
            )
            conn.commit()
            row_id = cur.lastrowid
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()
    except Exception:
        logger.exception("Could not write audit event %s", action)
        return None
    if action in _SELF_ALERTS:
        raise_self_alert(action, target=target, source_ip=source_ip, details=details)
    return row_id


def verify_chain() -> Tuple[bool, Optional[int], int]:
    """``(intact, first_bad_id, rows_checked)`` for the whole audit log.

    The oldest remaining row anchors the chain (older rows may have aged out);
    every later row must link to its predecessor and hash to its stored value.
    """
    from lsadra.storage.database import get_connection

    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT id, ts, actor_id, actor_name, action, target, outcome,
                      source_ip, details, prev_hash, hash
               FROM audit_events ORDER BY id"""
        ).fetchall()
    finally:
        conn.close()
    expected_prev: Optional[str] = None
    for r in rows:
        r = dict(r)
        if expected_prev is not None and r["prev_hash"] != expected_prev:
            return False, r["id"], len(rows)
        if _row_hash(r["prev_hash"], r) != r["hash"]:
            return False, r["id"], len(rows)
        expected_prev = r["hash"]
    return True, None, len(rows)


def head_hash() -> str:
    """Hash of the newest audit row (record it elsewhere to anchor the chain)."""
    from lsadra.storage.database import get_connection

    conn = get_connection()
    try:
        row = conn.execute("SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    finally:
        conn.close()
    return row[0] if row else GENESIS_HASH


def list_events(limit: int = 200, action: Optional[str] = None) -> list:
    from lsadra.storage.database import get_connection

    limit = max(1, min(int(limit), 1000))
    conn = get_connection()
    try:
        if action:
            rows = conn.execute(
                "SELECT * FROM audit_events WHERE action = ? ORDER BY id DESC LIMIT ?",
                (action, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["details"] = json.loads(d.get("details") or "{}")
        except ValueError:
            pass
        out.append(d)
    return out


def raise_self_alert(
    action: str,
    *,
    target: Optional[str] = None,
    source_ip: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Record a self-monitoring finding as an anomaly and push it to admins."""
    spec = _SELF_ALERTS.get(action)
    if spec is None:
        return
    threat_type, attack_type, technique, label, score = spec
    narrative = f"{threat_type}" + (f" (target: {target})" if target else "")
    if source_ip:
        narrative += f" from {source_ip}"
    narrative += ". Raised by LSADRA's audit trail."
    anomaly = {
        "device_id": SELF_DEVICE_ID,
        "user_id": None,            # no owner: only admins receive it live
        "source_ip": source_ip,
        "severity_score": score,
        "severity_label": label,
        "is_anomaly": True,
        "threat_type": threat_type,
        "attack_type": attack_type,
        "mitre_technique": technique,
        "narrative": narrative,
        "shap_values": {},
    }
    try:
        from lsadra.storage.database import insert_anomaly
        from lsadra.ui.alert_stream import alert_hub

        anomaly["id"] = insert_anomaly(anomaly)
        anomaly["created_at"] = _now()
        alert_hub.publish(anomaly)
    except Exception:
        logger.exception("Could not raise self-monitoring alert for %s", action)
