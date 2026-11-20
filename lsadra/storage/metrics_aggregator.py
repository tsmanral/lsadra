"""
LSADRA V3 — Metrics pre-aggregation.

Aggregates event and anomaly counts into 5-minute windows in the
``metrics_5min`` table. Designed to be called by the background scheduler.
"""

import logging
from datetime import datetime, timedelta

from lsadra.config import METRICS_AGGREGATION_INTERVAL_MINUTES
from lsadra.storage.database import get_connection, upsert_metrics_5min

logger = logging.getLogger(__name__)


def run() -> int:
    """
    Aggregate metrics for the most recent 5-minute window across all devices.

    Returns the number of device windows processed.
    """
    interval = METRICS_AGGREGATION_INTERVAL_MINUTES
    now = datetime.utcnow()

    # Align to the most recent 5-minute boundary
    minute = (now.minute // interval) * interval
    window_end = now.replace(minute=minute, second=0, microsecond=0)
    window_start = window_end - timedelta(minutes=interval)

    ws = window_start.isoformat()
    we = window_end.isoformat()

    conn = get_connection()
    try:
        # Get all devices with events in this window
        device_rows = conn.execute(
            """SELECT DISTINCT device_id FROM normalized_events
               WHERE timestamp BETWEEN ? AND ? AND device_id IS NOT NULL""",
            (ws, we),
        ).fetchall()

        count = 0
        for dr in device_rows:
            device_id = dr[0]

            # Event count
            event_row = conn.execute(
                """SELECT COUNT(*) as cnt FROM normalized_events
                   WHERE device_id = ? AND timestamp BETWEEN ? AND ?""",
                (device_id, ws, we),
            ).fetchone()
            event_count = event_row[0] if event_row else 0

            # Anomaly stats
            anomaly_row = conn.execute(
                """SELECT
                       COUNT(*) as cnt,
                       COALESCE(AVG(severity_score), 0) as avg_sev,
                       COALESCE(MAX(severity_score), 0) as max_sev
                   FROM anomalies
                   WHERE device_id = ? AND created_at BETWEEN ? AND ?
                     AND is_anomaly = 1""",
                (device_id, ws, we),
            ).fetchone()
            anomaly_count = anomaly_row[0] if anomaly_row else 0
            avg_severity = float(anomaly_row[1]) if anomaly_row else 0.0
            max_severity = float(anomaly_row[2]) if anomaly_row else 0.0

            # Unique IPs and users
            unique_row = conn.execute(
                """SELECT
                       COUNT(DISTINCT source_ip) as ips,
                       COUNT(DISTINCT effective_username) as users
                   FROM normalized_events
                   WHERE device_id = ? AND timestamp BETWEEN ? AND ?""",
                (device_id, ws, we),
            ).fetchone()
            unique_ips = unique_row[0] if unique_row else 0
            unique_users = unique_row[1] if unique_row else 0

            upsert_metrics_5min(
                device_id=device_id,
                window_start=ws,
                event_count=event_count,
                anomaly_count=anomaly_count,
                avg_severity=avg_severity,
                max_severity=max_severity,
                unique_ips=unique_ips,
                unique_users=unique_users,
            )
            count += 1

        if count:
            logger.info(
                "Metrics aggregation: %d device windows processed for %s → %s",
                count,
                ws,
                we,
            )
        return count

    finally:
        conn.close()
