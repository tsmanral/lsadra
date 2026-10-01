"""
LSADRA V3+V4 — SQLite storage layer.

Manages the database lifecycle via migrations, provides CRUD helpers for
users, devices, events, anomalies, incidents, heartbeats, model registry,
metrics, threat intel, and feature drift.

V4 additions (all new functions — none of the V3 functions modified):
  - store_feedback()
  - get_false_positive_patterns()
  - get_fp_rate_by_source_type()
  - update_ingestion_stats()
  - get_ingestion_stats()
"""

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from lsadra.config import DB_PATH, RETENTION_DAYS

logger = logging.getLogger(__name__)

# ── connection helper ──────────────────────────────────────────────────────


def get_connection() -> sqlite3.Connection:
    """Return a connection to the V3 SQLite database (the caller must close it)."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
    except BaseException:
        conn.close()
        raise
    return conn


@contextmanager
def _connection(
    borrowed: Optional[sqlite3.Connection] = None,
) -> Iterator[sqlite3.Connection]:
    """Scope one storage call's connection; every public function goes through here.

    * Owned (``borrowed is None``): open via :func:`get_connection`; on any
      exception roll back the open transaction, and always close — so a failed
      call can never keep a connection, or the database write lock, alive until
      garbage collection.
    * Borrowed: yield the caller's connection untouched; its lifecycle (commit,
      rollback, close) stays with the caller.

    Commit stays explicit in each function: this helper changes when a
    connection is released, not what a transaction contains.
    """
    if borrowed is not None:
        yield borrowed
        return
    conn = get_connection()
    try:
        yield conn
    except BaseException:
        try:
            conn.rollback()
        except sqlite3.Error:
            logger.warning("Rollback failed while handling a storage error", exc_info=True)
        raise
    finally:
        conn.close()


# ── schema bootstrap (migration-based) ────────────────────────────────────


def init_db() -> None:
    """Run all pending migrations to bring the schema up to date."""
    from lsadra.storage.migration_runner import run_migrations

    logger.info("Initializing V3 database at %s", DB_PATH)
    with _connection() as conn:
        run_migrations(conn)
    logger.info("V3 database schema ready.")


# ══════════════════════════════════════════════════════════════════════════
#  CRUD: users
# ══════════════════════════════════════════════════════════════════════════


def create_user(
    user_id: str,
    username: str,
    password_hash: str,
    role: str = "ANALYST",
) -> None:
    """Insert a new dashboard user."""
    with _connection() as conn:
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)",
            (user_id, username, password_hash, role),
        )
        conn.commit()


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Return a user row or *None*."""
    with _connection() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Return a user by ID."""
    with _connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def update_user_role(user_id: str, role: str) -> None:
    """Update a user's role."""
    with _connection() as conn:
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        conn.commit()


def list_users() -> List[Dict[str, Any]]:
    """Return all users."""
    with _connection() as conn:
        rows = conn.execute("SELECT id, username, role, created_at FROM users").fetchall()
        return [dict(r) for r in rows]


# ══════════════════════════════════════════════════════════════════════════
#  CRUD: devices
# ══════════════════════════════════════════════════════════════════════════


def create_device(
    device_id: str,
    user_id: str,
    hostname: str,
    os_type: str,
    api_key_hash: str,
    display_name: Optional[str] = None,
) -> None:
    """Register a new endpoint device."""
    with _connection() as conn:
        conn.execute(
            """INSERT INTO devices
               (id, user_id, hostname, os_type, display_name, api_key_hash)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (device_id, user_id, hostname, os_type, display_name, api_key_hash),
        )
        conn.commit()


def get_device(device_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a device by its ID."""
    with _connection() as conn:
        row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        return dict(row) if row else None


def get_devices_for_user(user_id: str) -> List[Dict[str, Any]]:
    """Return all devices belonging to a user."""
    with _connection() as conn:
        rows = conn.execute(
            "SELECT * FROM devices WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_all_devices() -> List[Dict[str, Any]]:
    """Return all registered devices."""
    with _connection() as conn:
        rows = conn.execute("SELECT * FROM devices ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]


def touch_device(device_id: str) -> None:
    """Update *last_seen_at* for a device."""
    with _connection() as conn:
        conn.execute(
            "UPDATE devices SET last_seen_at = ? WHERE id = ?",
            (datetime.utcnow().isoformat(), device_id),
        )
        conn.commit()


def update_device_status(device_id: str, status: str) -> None:
    """Update device status (BASELINING | ONLINE | OFFLINE)."""
    with _connection() as conn:
        conn.execute("UPDATE devices SET status = ? WHERE id = ?", (status, device_id))
        conn.commit()


def increment_device_event_count(device_id: str, count: int = 1) -> int:
    """Increment the event_count for a device and return new total."""
    with _connection() as conn:
        conn.execute(
            "UPDATE devices SET event_count = event_count + ? WHERE id = ?",
            (count, device_id),
        )
        conn.commit()
        row = conn.execute(
            "SELECT event_count FROM devices WHERE id = ?", (device_id,)
        ).fetchone()
        return dict(row)["event_count"] if row else 0


# ══════════════════════════════════════════════════════════════════════════
#  CRUD: registration tokens
# ══════════════════════════════════════════════════════════════════════════


def store_token(token: str, user_id: str, expires_at: datetime) -> None:
    """Persist a new registration token."""
    with _connection() as conn:
        conn.execute(
            "INSERT INTO registration_tokens (token, user_id, expires_at) VALUES (?, ?, ?)",
            (token, user_id, expires_at.isoformat()),
        )
        conn.commit()


def consume_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Validate and consume a registration token.

    Returns the token row (with ``user_id``) if valid, else *None*.
    """
    with _connection() as conn:
        row = conn.execute(
            "SELECT * FROM registration_tokens WHERE token = ?", (token,)
        ).fetchone()

        if row is None:
            return None

        data = dict(row)
        now = datetime.utcnow()
        expires = datetime.fromisoformat(data["expires_at"])

        if data["used"] or now > expires:
            return None

        conn.execute("UPDATE registration_tokens SET used = 1 WHERE token = ?", (token,))
        conn.commit()
        return data


# ══════════════════════════════════════════════════════════════════════════
#  CRUD: normalized events
# ══════════════════════════════════════════════════════════════════════════


def insert_event(event: Dict[str, Any]) -> int:
    """Insert a single normalized event and return its row ID."""
    with _connection() as conn:
        cur = conn.execute(
            """INSERT INTO normalized_events
               (timestamp, device_id, user_id, host, effective_username,
                source_ip, event_type, raw_message, attributes, is_synthetic)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.get("timestamp"),
                event.get("device_id"),
                event.get("user_id"),
                event.get("host"),
                event.get("effective_username"),
                event.get("source_ip"),
                event.get("event_type"),
                event.get("raw_message"),
                json.dumps(event.get("attributes", {})),
                event.get("is_synthetic", False),
            ),
        )
        row_id = cur.lastrowid
        conn.commit()
        return row_id or 0


def insert_events_batch(events: List[Dict[str, Any]]) -> int:
    """Bulk-insert normalized events. Returns count inserted."""
    with _connection() as conn:
        cur = conn.cursor()
        for ev in events:
            cur.execute(
                """INSERT INTO normalized_events
                   (timestamp, device_id, user_id, host, effective_username,
                    source_ip, event_type, raw_message, attributes, is_synthetic)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ev.get("timestamp"),
                    ev.get("device_id"),
                    ev.get("user_id"),
                    ev.get("host"),
                    ev.get("effective_username"),
                    ev.get("source_ip"),
                    ev.get("event_type"),
                    ev.get("raw_message"),
                    json.dumps(ev.get("attributes", {})),
                    ev.get("is_synthetic", False),
                ),
            )
        conn.commit()
        return len(events)


def get_events_since(
    device_id: str, after_id: int, limit: int = 500
) -> List[Dict[str, Any]]:
    """Fetch events for a device newer than *after_id*."""
    with _connection() as conn:
        rows = conn.execute(
            """SELECT * FROM normalized_events
               WHERE device_id = ? AND id > ?
               ORDER BY id ASC LIMIT ?""",
            (device_id, after_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def get_events_for_user(
    user_id: str, synthetic: bool = False, limit: int = 5000
) -> List[Dict[str, Any]]:
    """Fetch events belonging to a user."""
    with _connection() as conn:
        rows = conn.execute(
            """SELECT * FROM normalized_events
               WHERE user_id = ? AND is_synthetic = ?
               ORDER BY timestamp DESC LIMIT ?""",
            (user_id, int(synthetic), limit),
        ).fetchall()
        return [dict(r) for r in rows]


def get_event_count_for_device(device_id: str) -> int:
    """Return total event count for a device."""
    with _connection() as conn:
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM normalized_events WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        return dict(row)["cnt"] if row else 0


# ══════════════════════════════════════════════════════════════════════════
#  CRUD: detection watermarks
# ══════════════════════════════════════════════════════════════════════════


def get_watermark(device_id: str) -> int:
    """Return the last processed event ID for online detection."""
    with _connection() as conn:
        row = conn.execute(
            "SELECT last_processed_id FROM detection_watermarks WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        return dict(row)["last_processed_id"] if row else 0


def set_watermark(device_id: str, last_id: int) -> None:
    """Update the detection watermark for a device."""
    with _connection() as conn:
        conn.execute(
            """INSERT INTO detection_watermarks (device_id, last_processed_id, last_run_at)
               VALUES (?, ?, ?)
               ON CONFLICT(device_id) DO UPDATE SET
                   last_processed_id = excluded.last_processed_id,
                   last_run_at       = excluded.last_run_at""",
            (device_id, last_id, datetime.utcnow().isoformat()),
        )
        conn.commit()


# ══════════════════════════════════════════════════════════════════════════
#  CRUD: anomalies (V3)
# ══════════════════════════════════════════════════════════════════════════


def insert_anomaly(anomaly: Dict[str, Any]) -> int:
    """Persist a V3 detection result."""
    with _connection() as conn:
        cur = conn.execute(
            """INSERT INTO anomalies
               (event_id, device_id, user_id, source_ip,
                layer1_score, layer2_score, layer2_votes, layer3_score,
                severity_score, severity_label,
                is_anomaly, threat_type, attack_type,
                mitre_technique, mitre_confidence,
                narrative, shap_values, incident_id, is_synthetic)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                anomaly.get("event_id"),
                anomaly.get("device_id"),
                anomaly.get("user_id"),
                anomaly.get("source_ip"),
                anomaly.get("layer1_score"),
                anomaly.get("layer2_score"),
                anomaly.get("layer2_votes"),
                anomaly.get("layer3_score"),
                anomaly.get("severity_score"),
                anomaly.get("severity_label"),
                anomaly.get("is_anomaly"),
                anomaly.get("threat_type"),
                anomaly.get("attack_type"),
                anomaly.get("mitre_technique"),
                anomaly.get("mitre_confidence"),
                anomaly.get("narrative"),
                json.dumps(anomaly.get("shap_values", {})),
                anomaly.get("incident_id"),
                anomaly.get("is_synthetic", False),
            ),
        )
        row_id = cur.lastrowid
        conn.commit()
        return row_id or 0


def get_anomalies_for_user(
    user_id: str, synthetic: bool = False, limit: int = 200
) -> List[Dict[str, Any]]:
    """Return anomalies belonging to a user."""
    with _connection() as conn:
        rows = conn.execute(
            """SELECT * FROM anomalies
               WHERE user_id = ? AND is_synthetic = ?
               ORDER BY created_at DESC LIMIT ?""",
            (user_id, int(synthetic), limit),
        ).fetchall()
        return [dict(r) for r in rows]


def get_anomalies_for_device(
    device_id: str, limit: int = 200
) -> List[Dict[str, Any]]:
    """Return anomalies for a specific device."""
    with _connection() as conn:
        rows = conn.execute(
            """SELECT * FROM anomalies
               WHERE device_id = ?
               ORDER BY created_at DESC LIMIT ?""",
            (device_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def get_anomalies_for_incident(incident_id: int) -> List[Dict[str, Any]]:
    """Return all anomalies linked to an incident."""
    with _connection() as conn:
        rows = conn.execute(
            """SELECT a.*, e.raw_message, e.effective_username, e.host
               FROM anomalies a
               LEFT JOIN normalized_events e ON a.event_id = e.id
               WHERE a.incident_id = ?
               ORDER BY a.created_at ASC""",
            (incident_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_recent_anomalies(limit: int = 100) -> List[Dict[str, Any]]:
    """Return the most recent anomalies across all devices."""
    with _connection() as conn:
        rows = conn.execute(
            """SELECT * FROM anomalies
               WHERE is_anomaly = 1
               ORDER BY created_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def update_anomaly_incident(anomaly_id: int, incident_id: int) -> None:
    """Link an anomaly to an incident."""
    with _connection() as conn:
        conn.execute(
            "UPDATE anomalies SET incident_id = ? WHERE id = ?",
            (incident_id, anomaly_id),
        )
        conn.commit()


# ══════════════════════════════════════════════════════════════════════════
#  CRUD: incidents
# ══════════════════════════════════════════════════════════════════════════


def create_incident(
    device_id: str,
    source_ip: str,
    attack_type: str,
    severity_label: str,
    first_seen: str,
    playbook: Optional[str] = None,
) -> int:
    """Create a new incident. Returns the incident ID."""
    with _connection() as conn:
        cur = conn.execute(
            """INSERT INTO incidents
               (device_id, source_ip, attack_type, severity_label, first_seen, last_seen, playbook)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (device_id, source_ip, attack_type, severity_label, first_seen, first_seen, playbook),
        )
        incident_id = cur.lastrowid
        conn.commit()
        return incident_id or 0


def get_incident(incident_id: int) -> Optional[Dict[str, Any]]:
    """Fetch an incident by ID."""
    with _connection() as conn:
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return dict(row) if row else None


def get_open_incident(
    device_id: str, source_ip: str, attack_type: str, window_start: str
) -> Optional[Dict[str, Any]]:
    """Find an open incident matching the grouping key within the time window."""
    with _connection() as conn:
        row = conn.execute(
            """SELECT * FROM incidents
               WHERE device_id = ? AND source_ip = ? AND attack_type = ?
                 AND status IN ('OPEN', 'INVESTIGATING')
                 AND last_seen >= ?
               ORDER BY last_seen DESC LIMIT 1""",
            (device_id, source_ip, attack_type, window_start),
        ).fetchone()
        return dict(row) if row else None


def update_incident_last_seen(incident_id: int, last_seen: str) -> None:
    """Update last_seen and bump anomaly_count for an incident."""
    with _connection() as conn:
        conn.execute(
            """UPDATE incidents
               SET last_seen = ?, anomaly_count = anomaly_count + 1
               WHERE id = ?""",
            (last_seen, incident_id),
        )
        conn.commit()


def update_incident_status(incident_id: int, status: str, notes: str = "") -> None:
    """Update incident status (OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE)."""
    with _connection() as conn:
        resolved_at = datetime.utcnow().isoformat() if status in ("RESOLVED", "FALSE_POSITIVE") else None
        conn.execute(
            """UPDATE incidents
               SET status = ?, notes = ?, resolved_at = COALESCE(?, resolved_at)
               WHERE id = ?""",
            (status, notes, resolved_at, incident_id),
        )
        conn.commit()


def assign_incident(incident_id: int, user_id: str) -> None:
    """Assign an incident to a user."""
    with _connection() as conn:
        conn.execute(
            "UPDATE incidents SET assigned_to = ?, status = 'INVESTIGATING' WHERE id = ?",
            (user_id, incident_id),
        )
        conn.commit()


def get_open_incidents(limit: int = 100) -> List[Dict[str, Any]]:
    """Return open/investigating incidents."""
    with _connection() as conn:
        rows = conn.execute(
            """SELECT * FROM incidents
               WHERE status IN ('OPEN', 'INVESTIGATING')
               ORDER BY last_seen DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_all_incidents(
    status: Optional[str] = None, limit: int = 200, user_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Return incidents, optionally filtered by status and user_id."""
    with _connection() as conn:
        query = "SELECT i.* FROM incidents i"
        params: List[Any] = []
        
        if user_id:
            query += " JOIN devices d ON i.device_id = d.id"
            
        conditions = []
        if status:
            conditions.append("i.status = ?")
            params.append(status)
        if user_id:
            conditions.append("d.user_id = ?")
            params.append(user_id)
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
            
        query += " ORDER BY i.last_seen DESC LIMIT ?"
        params.append(limit)
        
        rows = conn.execute(query, tuple(params)).fetchall()
        return [dict(r) for r in rows]


# ══════════════════════════════════════════════════════════════════════════
#  CRUD: device heartbeats
# ══════════════════════════════════════════════════════════════════════════


def insert_heartbeat(
    device_id: str,
    cpu_pct: Optional[float] = None,
    mem_pct: Optional[float] = None,
    agent_version: Optional[str] = None,
) -> None:
    """Record a heartbeat from a device."""
    with _connection() as conn:
        conn.execute(
            """INSERT INTO device_heartbeats (device_id, cpu_pct, mem_pct, agent_version)
               VALUES (?, ?, ?, ?)""",
            (device_id, cpu_pct, mem_pct, agent_version),
        )
        conn.commit()


def get_latest_heartbeat(device_id: str) -> Optional[Dict[str, Any]]:
    """Return the most recent heartbeat for a device."""
    with _connection() as conn:
        row = conn.execute(
            """SELECT * FROM device_heartbeats
               WHERE device_id = ?
               ORDER BY timestamp DESC LIMIT 1""",
            (device_id,),
        ).fetchone()
        return dict(row) if row else None


# ══════════════════════════════════════════════════════════════════════════
#  CRUD: model registry
# ══════════════════════════════════════════════════════════════════════════


def register_model(
    model_name: str,
    model_type: str,
    file_path: str,
    event_count: int = 0,
    metrics: Optional[dict] = None,
) -> int:
    """Register a trained model as the next version of *model_name*.

    ``version`` is 1 + the highest version already registered under the same
    ``model_name`` — the key ``get_latest_model`` and ``mark_model_stale`` look
    up by. The version is computed inside the INSERT itself, so two concurrent
    registrations cannot read the same MAX. Returns the registry ID.
    """
    with _connection() as conn:
        cur = conn.execute(
            """INSERT INTO model_registry
               (model_name, model_type, file_path, version, trained_at, event_count, metrics)
               SELECT ?, ?, ?, COALESCE(MAX(version), 0) + 1, ?, ?, ?
               FROM model_registry WHERE model_name = ?""",
            (
                model_name,
                model_type,
                file_path,
                datetime.utcnow().isoformat(),
                event_count,
                json.dumps(metrics or {}),
                model_name,
            ),
        )
        reg_id = cur.lastrowid
        conn.commit()
        return reg_id or 0


def get_latest_model(model_name: str) -> Optional[Dict[str, Any]]:
    """Get the most recent model entry for a given name.

    Highest ``version`` wins; among equal versions (rows registered before
    versions incremented all carry the schema default 1) the newest row wins.
    ``mark_model_stale`` uses the same ordering.
    """
    with _connection() as conn:
        row = conn.execute(
            """SELECT * FROM model_registry
               WHERE model_name = ?
               ORDER BY version DESC, id DESC LIMIT 1""",
            (model_name,),
        ).fetchone()
        return dict(row) if row else None


def mark_model_stale(model_name: str) -> None:
    """Flag the latest registration of a model (and only that one) as stale."""
    with _connection() as conn:
        conn.execute(
            """UPDATE model_registry SET is_stale = TRUE
               WHERE id = (SELECT id FROM model_registry
                           WHERE model_name = ?
                           ORDER BY version DESC, id DESC LIMIT 1)""",
            (model_name,),
        )
        conn.commit()


# ══════════════════════════════════════════════════════════════════════════
#  CRUD: metrics_5min
# ══════════════════════════════════════════════════════════════════════════


def upsert_metrics_5min(
    device_id: str,
    window_start: str,
    event_count: int,
    anomaly_count: int,
    avg_severity: float,
    max_severity: float,
    unique_ips: int,
    unique_users: int,
) -> None:
    """Insert or update a 5-minute metrics window."""
    with _connection() as conn:
        conn.execute(
            """INSERT INTO metrics_5min
               (device_id, window_start, event_count, anomaly_count,
                avg_severity, max_severity, unique_ips, unique_users)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(device_id, window_start) DO UPDATE SET
                   event_count   = excluded.event_count,
                   anomaly_count = excluded.anomaly_count,
                   avg_severity  = excluded.avg_severity,
                   max_severity  = excluded.max_severity,
                   unique_ips    = excluded.unique_ips,
                   unique_users  = excluded.unique_users""",
            (device_id, window_start, event_count, anomaly_count,
             avg_severity, max_severity, unique_ips, unique_users),
        )
        conn.commit()


def get_metrics_timeseries(
    device_id: str, start: str, end: str
) -> List[Dict[str, Any]]:
    """Return metrics_5min rows for a device within a time range."""
    with _connection() as conn:
        rows = conn.execute(
            """SELECT * FROM metrics_5min
               WHERE device_id = ? AND window_start BETWEEN ? AND ?
               ORDER BY window_start ASC""",
            (device_id, start, end),
        ).fetchall()
        return [dict(r) for r in rows]


# ══════════════════════════════════════════════════════════════════════════
#  CRUD: threat intelligence cache
# ══════════════════════════════════════════════════════════════════════════


def upsert_threat_intel(
    ip_address: str,
    abuse_score: int,
    country_code: str = "",
    isp: str = "",
    domain: str = "",
    is_tor: bool = False,
    total_reports: int = 0,
    last_reported: str = "",
    raw_response: str = "",
    cache_hours: int = 24,
) -> None:
    """Cache a threat intelligence lookup."""
    now = datetime.utcnow()
    expires = now + timedelta(hours=cache_hours)
    with _connection() as conn:
        conn.execute(
            """INSERT INTO threat_intel_cache
               (ip_address, abuse_score, country_code, isp, domain, is_tor,
                total_reports, last_reported, raw_response, queried_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(ip_address) DO UPDATE SET
                   abuse_score   = excluded.abuse_score,
                   country_code  = excluded.country_code,
                   isp           = excluded.isp,
                   domain        = excluded.domain,
                   is_tor        = excluded.is_tor,
                   total_reports = excluded.total_reports,
                   last_reported = excluded.last_reported,
                   raw_response  = excluded.raw_response,
                   queried_at    = excluded.queried_at,
                   expires_at    = excluded.expires_at""",
            (ip_address, abuse_score, country_code, isp, domain, is_tor,
             total_reports, last_reported, raw_response,
             now.isoformat(), expires.isoformat()),
        )
        conn.commit()


def get_threat_intel(ip_address: str) -> Optional[Dict[str, Any]]:
    """Return cached threat intel for an IP, or None if expired/missing."""
    with _connection() as conn:
        row = conn.execute(
            """SELECT * FROM threat_intel_cache
               WHERE ip_address = ? AND expires_at > ?""",
            (ip_address, datetime.utcnow().isoformat()),
        ).fetchone()
        return dict(row) if row else None


def get_expiring_threat_intel(limit: int = 50) -> List[Dict[str, Any]]:
    """Return threat intel entries that are about to expire."""
    with _connection() as conn:
        cutoff = (datetime.utcnow() + timedelta(hours=1)).isoformat()
        rows = conn.execute(
            """SELECT * FROM threat_intel_cache
               WHERE expires_at <= ?
               ORDER BY expires_at ASC LIMIT ?""",
            (cutoff, limit),
        ).fetchall()
        return [dict(r) for r in rows]


# ══════════════════════════════════════════════════════════════════════════
#  CRUD: IP geolocation
# ══════════════════════════════════════════════════════════════════════════


def upsert_ip_geolocation(
    ip_address: str,
    latitude: float,
    longitude: float,
    city: str = "",
    country: str = "",
) -> None:
    """Cache a geolocation result."""
    with _connection() as conn:
        conn.execute(
            """INSERT INTO ip_geolocation (ip_address, latitude, longitude, city, country, resolved_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(ip_address) DO UPDATE SET
                   latitude = excluded.latitude,
                   longitude = excluded.longitude,
                   city = excluded.city,
                   country = excluded.country,
                   resolved_at = excluded.resolved_at""",
            (ip_address, latitude, longitude, city, country, datetime.utcnow().isoformat()),
        )
        conn.commit()


def get_unresolved_ips(limit: int = 50) -> List[str]:
    """Return IPs from events that don't yet have a geolocation entry."""
    with _connection() as conn:
        rows = conn.execute(
            """SELECT DISTINCT ne.source_ip
               FROM normalized_events ne
               LEFT JOIN ip_geolocation geo ON ne.source_ip = geo.ip_address
               WHERE ne.source_ip IS NOT NULL AND ne.source_ip != ''
                 AND geo.ip_address IS NULL
               LIMIT ?""",
            (limit,),
        ).fetchall()
        return [r[0] for r in rows]


# ══════════════════════════════════════════════════════════════════════════
#  CRUD: feature drift
# ══════════════════════════════════════════════════════════════════════════


def insert_drift_record(
    model_name: str, feature_name: str, psi_value: float, is_drifted: bool
) -> None:
    """Record a PSI drift measurement."""
    with _connection() as conn:
        conn.execute(
            """INSERT INTO feature_drift (model_name, feature_name, psi_value, is_drifted)
               VALUES (?, ?, ?, ?)""",
            (model_name, feature_name, psi_value, is_drifted),
        )
        conn.commit()


def get_drift_records(model_name: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Return recent drift measurements for a model."""
    with _connection() as conn:
        rows = conn.execute(
            """SELECT * FROM feature_drift
               WHERE model_name = ?
               ORDER BY measured_at DESC LIMIT ?""",
            (model_name, limit),
        ).fetchall()
        return [dict(r) for r in rows]


# ══════════════════════════════════════════════════════════════════════════
#  Retention cleanup
# ══════════════════════════════════════════════════════════════════════════


def cleanup_old_data() -> int:
    """Delete rows older than RETENTION_DAYS. Returns the number of events deleted.

    All deletes run in one transaction (one commit; any failure rolls back every
    table) in foreign-key-safe order. The only FK into ``normalized_events`` is
    ``anomalies.event_id`` (migration 001), so anomalies go first. An expired
    event still referenced by a *retained* anomaly (e.g. a back-filled log line
    whose anomaly is recent) is kept until that anomaly ages out — deleting it
    would violate the FK, deleting the anomaly early would drop a finding inside
    its retention window. ``incidents`` are not part of retention; they are only
    ever the parent side (``anomalies.incident_id``), so they impose no ordering.
    """
    cutoff = (datetime.utcnow() - timedelta(days=RETENTION_DAYS)).isoformat()
    with _connection() as conn:
        conn.execute("DELETE FROM anomalies WHERE created_at < ?", (cutoff,))
        cur = conn.execute(
            """DELETE FROM normalized_events
               WHERE timestamp < ?
                 AND id NOT IN (SELECT event_id FROM anomalies WHERE event_id IS NOT NULL)""",
            (cutoff,),
        )
        events_deleted = cur.rowcount
        conn.execute("DELETE FROM device_heartbeats WHERE timestamp < ?", (cutoff,))
        conn.execute("DELETE FROM metrics_5min WHERE window_start < ?", (cutoff,))
        conn.execute("DELETE FROM feature_drift WHERE measured_at < ?", (cutoff,))
        conn.commit()
        logger.info("Retention cleanup: removed %d events older than %s", events_deleted, cutoff)
        return events_deleted


# ══════════════════════════════════════════════════════════════════════════
#  V4 ADDITIONS: feedback and ingestion stats
# ══════════════════════════════════════════════════════════════════════════

# [V4 ENHANCEMENT — gap: analyst feedback loop]


def store_feedback(
    db_conn: Optional[sqlite3.Connection],
    alert_id: int,
    label: str,
    analyst_note: str,
    fp_pattern: str,
    suggested_thresholds: Dict[str, Any],
    source_type: str,
) -> None:
    """
    Persist analyst feedback to the alerts_feedback table.

    [V4 ENHANCEMENT — gap: analyst feedback loop]

    Args:
        db_conn:              Optional existing DB connection (creates new if None).
        alert_id:             anomalies.id of the alert being labelled.
        label:                'true_positive' or 'false_positive'.
        analyst_note:         Free-text analyst note.
        fp_pattern:           FP pattern from analyze_false_positive().
        suggested_thresholds: Dict of suggested threshold changes (stored as JSON).
        source_type:          Source type of the triggering event.
    """
    with _connection(db_conn) as conn:
        conn.execute(
            """INSERT INTO alerts_feedback
               (alert_id, label, analyst_note, fp_pattern,
                suggested_thresholds, source_type)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                alert_id, label, analyst_note, fp_pattern,
                json.dumps(suggested_thresholds), source_type,
            ),
        )
        conn.commit()


def get_false_positive_patterns(
    db_conn: Optional[sqlite3.Connection] = None, limit: int = 50
) -> List[Dict[str, Any]]:
    """
    Retrieve recent false-positive labels with their pattern analysis.

    [V4 ENHANCEMENT — gap: analyst feedback loop]

    Args:
        db_conn: Optional existing connection.
        limit:   Maximum rows to return.

    Returns:
        List of feedback dicts for FP-labelled alerts.
    """
    with _connection(db_conn) as conn:
        rows = conn.execute(
            """SELECT * FROM alerts_feedback
               WHERE label = 'false_positive'
               ORDER BY created_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_fp_rate_by_source_type(
    db_conn: Optional[sqlite3.Connection] = None,
) -> Dict[str, float]:
    """
    Calculate the false-positive rate per ingestion source type.

    SQL: COUNT(FP) / COUNT(total) GROUP BY source_type

    [V4 ENHANCEMENT — gap: analyst feedback loop]

    Args:
        db_conn: Optional existing connection.

    Returns:
        Dict mapping source_type → fp_rate (0.0 – 1.0).
    """
    with _connection(db_conn) as conn:
        rows = conn.execute(
            """SELECT source_type,
                      COUNT(CASE WHEN label = 'false_positive' THEN 1 END) AS fp_count,
                      COUNT(*) AS total_count
               FROM alerts_feedback
               WHERE source_type IS NOT NULL
               GROUP BY source_type"""
        ).fetchall()
        result: Dict[str, float] = {}
        for row in rows:
            d = dict(row)
            total = d.get("total_count", 0) or 1
            result[d["source_type"]] = round(d.get("fp_count", 0) / total, 4)
        return result


def update_ingestion_stats(
    db_conn: Optional[sqlite3.Connection],
    source_type: str,
    events: int,
    errors: int,
) -> None:
    """
    Upsert ingestion statistics for a source type.

    [V4 ENHANCEMENT — gap: ingestion health monitoring]

    Args:
        db_conn:     Optional existing connection.
        source_type: Ingestion source identifier.
        events:      Number of successfully parsed events.
        errors:      Number of parse errors.
    """
    with _connection(db_conn) as conn:
        now = datetime.utcnow().isoformat()
        conn.execute(
            """INSERT INTO ingestion_stats
               (source_type, events_count, parse_errors, last_event, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(source_type) DO UPDATE SET
                   events_count = events_count + excluded.events_count,
                   parse_errors = parse_errors + excluded.parse_errors,
                   last_event   = CASE WHEN excluded.events_count > 0
                                       THEN excluded.last_event
                                       ELSE last_event END,
                   updated_at   = excluded.updated_at""",
            (source_type, events, errors, now if events > 0 else None, now),
        )
        conn.commit()


def get_ingestion_stats(
    db_conn: Optional[sqlite3.Connection] = None,
) -> List[Dict[str, Any]]:
    """
    Return ingestion health stats per source type for the dashboard.

    [V4 ENHANCEMENT — gap: ingestion health monitoring]

    Args:
        db_conn: Optional existing connection.

    Returns:
        List of stats dicts: source_type, events_count, parse_errors,
        last_event, updated_at.
    """
    with _connection(db_conn) as conn:
        rows = conn.execute(
            "SELECT * FROM ingestion_stats ORDER BY events_count DESC"
        ).fetchall()
        return [dict(r) for r in rows]


# ── direct-run bootstrap ─────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    init_db()
