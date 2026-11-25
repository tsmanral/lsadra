"""
Dashboard data layer.

Read queries behind the dashboard API (lsadra/api/dashboard.py), each
memoised for a few seconds so several widgets asking at once cost one
database round trip.
"""

import copy
import functools
import json
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


def _ttl_cache(ttl: int):
    """Memoise results per argument tuple for ``ttl`` seconds."""

    def decorator(fn):
        store: Dict[Any, Any] = {}
        lock = threading.Lock()

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            key = (args, tuple(sorted(kwargs.items())))
            now = time.monotonic()
            with lock:
                hit = store.get(key)
                if hit is not None and now - hit[0] < ttl:
                    # Hand out a copy so a caller that mutates the result
                    # cannot poison the cache.
                    return copy.deepcopy(hit[1])
            value = fn(*args, **kwargs)
            with lock:
                store[key] = (now, value)
                if len(store) > 256:  # bound memory: drop the oldest entries
                    for stale in sorted(store, key=lambda k: store[k][0])[:64]:
                        store.pop(stale, None)
            return copy.deepcopy(value)

        wrapper.clear = store.clear
        return wrapper

    return decorator


_cache_data = _ttl_cache

from lsadra.storage.database import (
    get_all_devices,
    get_all_incidents,
    get_anomalies_for_device,
    get_anomalies_for_incident,
    get_anomalies_for_user,
    get_connection,
    get_devices_for_user,
    get_drift_records,
    get_events_for_user,
    get_latest_model,
    get_metrics_timeseries,
    get_open_incidents,
    get_recent_anomalies,
    get_threat_intel,
)

logger = logging.getLogger(__name__)


@_cache_data(ttl=30)
def get_dashboard_metrics(device_id: Optional[str], start: str, end: str) -> List[Dict]:
    """Query metrics_5min for a device within a time range."""
    if not device_id:
        # Aggregate across all devices
        conn = get_connection()
        rows = conn.execute(
            """SELECT window_start,
                      SUM(event_count) as event_count,
                      SUM(anomaly_count) as anomaly_count,
                      AVG(avg_severity) as avg_severity,
                      MAX(max_severity) as max_severity,
                      SUM(unique_ips) as unique_ips,
                      SUM(unique_users) as unique_users
               FROM metrics_5min
               WHERE window_start BETWEEN ? AND ?
               GROUP BY window_start
               ORDER BY window_start ASC""",
            (start, end),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    return get_metrics_timeseries(device_id, start, end)


@_cache_data(ttl=15)
def get_dashboard_incidents(status: Optional[str] = None, limit: int = 100) -> List[Dict]:
    """Get incidents for the dashboard, optionally filtered."""
    if status:
        return get_all_incidents(status=status, limit=limit)
    return get_all_incidents(limit=limit)


@_cache_data(ttl=15)
def get_dashboard_open_incidents(user_id: Optional[str] = None) -> List[Dict]:
    """Get currently open incidents."""
    if not user_id:
        return get_open_incidents(limit=200)

    conn = get_connection()
    rows = conn.execute(
        """SELECT i.* FROM incidents i
           JOIN devices d ON i.device_id = d.id
           WHERE i.status IN ('OPEN', 'INVESTIGATING') AND d.user_id = ?
           ORDER BY i.last_seen DESC LIMIT 200""",
        (user_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@_cache_data(ttl=30)
def get_incident_anomalies(incident_id: int) -> List[Dict]:
    """Get anomalies for a specific incident with event details."""
    return get_anomalies_for_incident(incident_id)


@_cache_data(ttl=15)
def get_dashboard_recent_anomalies(
    limit: int = 50, user_id: Optional[str] = None, device_id: Optional[str] = None
) -> List[Dict]:
    """Get recent anomalies across all devices."""
    conn = get_connection()
    query = "SELECT * FROM anomalies WHERE is_anomaly = 1"
    params = []

    if user_id:
        query += " AND user_id = ?"
        params.append(user_id)
    if device_id:
        query += " AND device_id = ?"
        params.append(device_id)

    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, tuple(params)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@_cache_data(ttl=30)
def get_shap_for_anomaly(anomaly_id: int) -> Dict[str, float]:
    """Read SHAP values from the anomalies table for a specific anomaly."""
    conn = get_connection()
    row = conn.execute("SELECT shap_values FROM anomalies WHERE id = ?", (anomaly_id,)).fetchone()
    conn.close()
    if row and row[0]:
        try:
            return json.loads(row[0])
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}


@_cache_data(ttl=60)
def get_dashboard_devices(user_id: Optional[str] = None) -> List[Dict]:
    """Get all registered devices."""
    if not user_id:
        return get_all_devices()
    return get_devices_for_user(user_id)


@_cache_data(ttl=60)
def get_dashboard_model_info(model_name: str) -> Optional[Dict]:
    """Get the latest model registry entry."""
    return get_latest_model(model_name)


@_cache_data(ttl=60)
def get_dashboard_drift(model_name: str, limit: int = 50) -> List[Dict]:
    """Get recent drift measurements for a model."""
    return get_drift_records(model_name, limit)


INGEST_RATE_WINDOW_SECONDS = 60


def get_ingestion_rate(
    user_id: Optional[str] = None, window_seconds: int = INGEST_RATE_WINDOW_SECONDS
) -> float:
    """Events per second over the last ``window_seconds``, by event timestamp.

    Agents ship events as they happen, so the event timestamp is a close proxy
    for arrival time. Not cached: the health tile polls it and wants it live.
    """
    cutoff = (datetime.utcnow() - timedelta(seconds=window_seconds)).isoformat()
    query = "SELECT COUNT(*) FROM normalized_events WHERE timestamp > ?"
    params: List[Any] = [cutoff]
    if user_id:
        query += " AND user_id = ?"
        params.append(user_id)
    conn = get_connection()
    try:
        row = conn.execute(query, tuple(params)).fetchone()
    finally:
        conn.close()
    count = row[0] if row else 0
    return round(count / window_seconds, 2)


@_cache_data(ttl=30)
def get_dashboard_kpis(
    user_id: Optional[str] = None, device_id: Optional[str] = None
) -> Dict[str, Any]:
    """Compute high-level KPIs for the dashboard overview."""
    conn = get_connection()
    try:
        # Total events (last 24h)
        cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()

        event_query = "SELECT COUNT(*) FROM normalized_events WHERE timestamp > ?"
        event_params = [cutoff]
        if user_id:
            event_query += " AND user_id = ?"
            event_params.append(user_id)
        if device_id:
            event_query += " AND device_id = ?"
            event_params.append(device_id)

        event_row = conn.execute(event_query, tuple(event_params)).fetchone()
        total_events_24h = event_row[0] if event_row else 0

        # Total anomalies (last 24h)
        anomaly_query = "SELECT COUNT(*) FROM anomalies WHERE created_at > ? AND is_anomaly = 1"
        anomaly_params = [cutoff]
        if user_id:
            anomaly_query += " AND user_id = ?"
            anomaly_params.append(user_id)
        if device_id:
            anomaly_query += " AND device_id = ?"
            anomaly_params.append(device_id)

        anomaly_row = conn.execute(anomaly_query, tuple(anomaly_params)).fetchone()
        total_anomalies_24h = anomaly_row[0] if anomaly_row else 0

        # Open incidents
        incident_query = "SELECT i.* FROM incidents i"
        incident_params = []
        where_clauses = ["i.status IN ('OPEN', 'INVESTIGATING')"]

        if user_id:
            incident_query += " JOIN devices d ON i.device_id = d.id"
            where_clauses.append("d.user_id = ?")
            incident_params.append(user_id)
        if device_id:
            where_clauses.append("i.device_id = ?")
            incident_params.append(device_id)

        final_incident_query = f"{incident_query} WHERE {' AND '.join(where_clauses)}"
        open_incidents = conn.execute(
            f"SELECT COUNT(*) FROM ({final_incident_query})", tuple(incident_params)
        ).fetchone()[0]

        # Critical incidents
        critical_clauses = [
            "i.severity_label = 'CRITICAL'",
            "i.status IN ('OPEN', 'INVESTIGATING')",
        ]
        critical_params = []
        crit_query = "SELECT i.* FROM incidents i"
        if user_id:
            crit_query += " JOIN devices d ON i.device_id = d.id"
            critical_clauses.append("d.user_id = ?")
            critical_params.append(user_id)
        if device_id:
            critical_clauses.append("i.device_id = ?")
            critical_params.append(device_id)

        final_crit_query = f"{crit_query} WHERE {' AND '.join(critical_clauses)}"
        critical_incidents = conn.execute(
            f"SELECT COUNT(*) FROM ({final_crit_query})", tuple(critical_params)
        ).fetchone()[0]

        # Closed incidents
        closed_clauses = ["i.status IN ('RESOLVED', 'FALSE_POSITIVE')"]
        closed_params = []
        cl_query = "SELECT i.* FROM incidents i"
        if user_id:
            cl_query += " JOIN devices d ON i.device_id = d.id"
            closed_clauses.append("d.user_id = ?")
            closed_params.append(user_id)
        if device_id:
            closed_clauses.append("i.device_id = ?")
            closed_params.append(device_id)

        final_closed_query = f"{cl_query} WHERE {' AND '.join(closed_clauses)}"
        closed_incidents = conn.execute(
            f"SELECT COUNT(*) FROM ({final_closed_query})", tuple(closed_params)
        ).fetchone()[0]

        # Active devices
        threshold = (datetime.utcnow() - timedelta(minutes=5)).isoformat()
        device_query = "SELECT COUNT(*) FROM devices WHERE last_seen_at > ?"
        device_params = [threshold]
        if user_id:
            device_query += " AND user_id = ?"
            device_params.append(user_id)

        device_row = conn.execute(device_query, tuple(device_params)).fetchone()
        active_devices = device_row[0] if device_row else 0

        # Total devices
        total_query = "SELECT COUNT(*) FROM devices"
        total_params = []
        if user_id:
            total_query += " WHERE user_id = ?"
            total_params.append(user_id)

        total_row = conn.execute(total_query, tuple(total_params)).fetchone()
        total_devices = total_row[0] if total_row else 0

        return {
            "total_events_24h": total_events_24h,
            "total_anomalies_24h": total_anomalies_24h,
            "open_incidents": open_incidents,
            "closed_incidents": closed_incidents,
            "critical_incidents": critical_incidents,
            "active_devices": active_devices,
            "total_devices": total_devices,
        }
    finally:
        conn.close()
