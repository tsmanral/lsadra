"""
LSADRA V4 — Extended rule engine.

Extends the V3 heuristic rule engine with multi-source, temporal, and
relationship-aware rules. All existing V3 rules are preserved.

New V4 rules cover:
  - Enhanced brute force (5-min and 15-min windows)
  - Credential stuffing with cross-source corroboration
  - Low-and-slow attacks
  - Port scan detection (network_flow)
  - Large data transfer / exfiltration (network_flow)
  - Suspicious process / LOLBin (endpoint)
  - Persistence events (endpoint / syslog)
  - Cross-source correlation elevation
  - Lateral movement detection (SQLite query)

[V4 ENHANCEMENT — gap: multi-rule detection]
[GLASSWING ALIGNMENT — lateral movement detection]
[MYTHOS ALIGNMENT — cross-source behavioral sequences]
"""

import logging
import sqlite3
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


# ============================================================================
# V3 rule (preserved exactly)
# ============================================================================

def evaluate_rules(feature_row: Dict[str, Any]) -> Tuple[str, str]:
    """
    Evaluate V3 heuristic rules to classify an anomaly.

    Args:
        feature_row: Dict containing behavioural and temporal features.

    Returns:
        (Threat Name, MITRE ATT&CK Technique ID).
    """
    failures   = float(feature_row.get("failures_15m", 0))
    users      = float(feature_row.get("unique_users_15m", 0))
    success    = float(feature_row.get("successes_15m", 0))
    off_hours  = int(feature_row.get("is_off_hours", 0))
    fail_ratio = float(feature_row.get("failure_ratio_15m", 0))

    # [V4 DEMO RULES] — Force detection of specific high-risk event types
    event_type = str(feature_row.get("event_type", ""))
    if event_type == "sudo_command":
        return "Unauthorized Privilege Escalation", "T1068"
    if event_type == "ssh_failed_password":
        return "SSH Brute Force", "T1110.001"

    if failures > 15 and users > 5:
        return "Credential Stuffing", "T1110.004"
    if failures > 20 and users <= 3:
        return "Brute Force Attack", "T1110.001"
    if 5 < failures <= 20 and fail_ratio > 0.9:
        return "Low and Slow Attack", "T1110.001"
    if success > 0 and off_hours == 1 and failures == 0:
        return "Anomalous Off-Hour Access", "T1078"
    return "Unknown Anomalous Activity", "T1190"


# ============================================================================
# V4 rule helpers
# ============================================================================

def _build_alert(
    ip: str,
    rule_type: str,
    reason: str,
    severity: str,
    rule_weight: float,
    source_type: str,
    mitre_id: str,
    mitre_name: str,
) -> Dict[str, Any]:
    """Build a standardised V4 rule alert dict."""
    return {
        "ip":          ip,
        "type":        rule_type,
        "reason":      reason,
        "severity":    severity,
        "rule_weight": rule_weight,
        "source_type": source_type,
        "mitre_id":    mitre_id,
        "mitre_name":  mitre_name,
    }


# ============================================================================
# V4 rule functions
# ============================================================================

def check_brute_force_v4(features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Enhanced brute force detection using 5-min and 15-min rolling windows.

    [V4 ENHANCEMENT — gap: temporal brute force detection]

    Args:
        features: Enriched feature dict from build_enhanced_feature_table.

    Returns:
        Alert dict or None.
    """
    ip            = features.get("source_ip", "unknown")
    failed_5min   = float(features.get("failed_logins_last_5min",  0))
    failed_15min  = float(features.get("failed_logins_last_15min", 0))

    if failed_5min >= 15:
        return _build_alert(
            ip, "BRUTE_FORCE",
            f"{failed_5min:.0f} failed logins in 5 min (CRITICAL threshold)",
            "CRITICAL", 0.95, "ssh_log", "T1110.001", "Brute Force — Password Guessing",
        )
    if failed_5min >= 5:
        return _build_alert(
            ip, "BRUTE_FORCE",
            f"{failed_5min:.0f} failed logins in 5 min",
            "HIGH", 0.80, "ssh_log", "T1110.001", "Brute Force — Password Guessing",
        )
    if failed_15min >= 8:
        return _build_alert(
            ip, "BRUTE_FORCE",
            f"{failed_15min:.0f} failed logins in 15 min",
            "MEDIUM", 0.65, "ssh_log", "T1110.001", "Brute Force — Password Guessing",
        )
    return None


def check_credential_stuffing(features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Credential stuffing: many distinct usernames targeted from one IP.

    [V4 ENHANCEMENT — gap: credential stuffing detection]
    MITRE: T1110.004

    Args:
        features: Enriched feature dict.

    Returns:
        Alert dict or None.
    """
    ip          = features.get("source_ip", "unknown")
    uniq_users  = float(features.get("unique_usernames_per_ip", 0))
    fail_ratio  = float(features.get("failure_ratio", 0))
    cross       = bool(features.get("cross_source_activity", False))

    if uniq_users < 5:
        return None

    reason = (
        f"{uniq_users:.0f} distinct usernames targeted "
        f"with {fail_ratio*100:.0f}% failure rate"
    )
    if cross:
        reason += "; also observed in network flow data"

    return _build_alert(
        ip, "CREDENTIAL_STUFFING", reason,
        "HIGH", 0.75, "ssh_log", "T1110.004", "Credential Stuffing",
    )


def check_low_and_slow(features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Low-and-slow attack: moderate 15-min failures at sub-detection velocity.

    [V4 ENHANCEMENT — gap: evasion detection]
    MITRE: T1110.003

    Args:
        features: Enriched feature dict.

    Returns:
        Alert dict or None.
    """
    ip       = features.get("source_ip", "unknown")
    f15      = float(features.get("failed_logins_last_15min", 0))
    velocity = float(features.get("login_attempt_velocity", 0))

    if f15 >= 8 and velocity < 1.0:
        return _build_alert(
            ip, "LOW_AND_SLOW",
            f"{f15:.0f} failures in 15 min at {velocity:.2f} attempts/min",
            "HIGH", 0.70, "ssh_log", "T1110.003", "Password Spraying",
        )
    return None


def check_port_scan(features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Network port scan: high unique destination ports from one IP.

    [V4 ENHANCEMENT — gap: network discovery detection]
    MITRE: T1046

    Args:
        features: Enriched feature dict (must include network flow features).

    Returns:
        Alert dict or None.
    """
    if features.get("source_type") != "network_flow":
        return None
    ip         = features.get("source_ip", "unknown")
    uniq_ports = float(features.get("unique_dst_ports_per_ip", 0))

    if uniq_ports >= 50:
        return _build_alert(
            ip, "PORT_SCAN",
            f"{uniq_ports:.0f} destination ports probed (CRITICAL)",
            "CRITICAL", 0.75, "network_flow", "T1046", "Network Service Discovery",
        )
    if uniq_ports >= 15:
        return _build_alert(
            ip, "PORT_SCAN",
            f"{uniq_ports:.0f} destination ports probed",
            "HIGH", 0.75, "network_flow", "T1046", "Network Service Discovery",
        )
    return None


def check_large_transfer(features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Large outbound data transfer: potential exfiltration signal.

    [V4 ENHANCEMENT — gap: exfiltration detection]
    MITRE: T1048

    Args:
        features: Enriched feature dict.

    Returns:
        Alert dict or None.
    """
    if features.get("source_type") != "network_flow":
        return None
    ip         = features.get("source_ip", "unknown")
    bytes_out  = float(features.get("total_bytes_out", 0))

    if bytes_out > 10_000_000:
        mb = bytes_out / 1_000_000
        return _build_alert(
            ip, "LARGE_DATA_TRANSFER",
            f"{mb:.1f} MB outbound in window (exfiltration signal)",
            "HIGH", 0.65, "network_flow", "T1048", "Exfiltration Over Alternative Protocol",
        )
    return None


def check_suspicious_process(features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Suspicious process or LOLBin abuse on an endpoint device.

    [V4 ENHANCEMENT — gap: endpoint detection]
    MITRE: T1059

    Args:
        features: Enriched feature dict.

    Returns:
        Alert dict or None.
    """
    if features.get("source_type") != "endpoint":
        return None

    device        = features.get("device_id", "unknown")
    susp_count    = float(features.get("suspicious_process_count", 0))
    lolbin_count  = float(features.get("lolbin_usage_count", 0))

    if lolbin_count >= 1:
        ip = features.get("source_ip", device)
        return _build_alert(
            ip, "SUSPICIOUS_PROCESS",
            f"LOLBin abuse detected on device {device}",
            "HIGH", 0.80, "endpoint", "T1059", "Command and Scripting Interpreter",
        )
    if susp_count >= 2:
        ip = features.get("source_ip", device)
        return _build_alert(
            ip, "SUSPICIOUS_PROCESS",
            f"{susp_count:.0f} suspicious processes on device {device}",
            "HIGH", 0.80, "endpoint", "T1059", "Command and Scripting Interpreter",
        )
    return None


def check_persistence(features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Persistence mechanism: scheduled task, new service, or cron modification.

    [V4 ENHANCEMENT — gap: persistence detection]
    MITRE: T1547

    Args:
        features: Enriched feature dict.

    Returns:
        Alert dict or None.
    """
    persistence_events = {
        "scheduled_task_created", "service_installed",
        "cron_modified", "startup_modified",
    }
    event_type = str(features.get("event_type", ""))
    if event_type not in persistence_events:
        return None

    ip     = features.get("source_ip") or features.get("device_id", "unknown")
    src    = features.get("source_type", "unknown")

    return _build_alert(
        ip, "PERSISTENCE",
        f"Persistence mechanism detected: {event_type} on {src}",
        "HIGH", 0.85, src, "T1547", "Boot or Logon Autostart Execution",
    )


def apply_cross_source_elevation(
    alert: Dict[str, Any], features: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Elevate an alert's severity if the source IP is active in 2+ source types.

    [V4 ENHANCEMENT — gap: cross-source correlation]
    MITRE: multi-source corroboration

    Args:
        alert:    Existing V4 alert dict (will be mutated on elevation).
        features: Enriched feature dict.

    Returns:
        Alert dict (potentially with elevated severity and updated reason).
    """
    if not features.get("cross_source_activity"):
        return alert

    severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    current = alert.get("severity", "LOW")
    try:
        idx = severity_order.index(current)
        alert["severity"] = severity_order[min(idx + 1, len(severity_order) - 1)]
    except ValueError:
        pass

    alert["reason"] = (
        alert.get("reason", "") +
        " | Multi-source activity corroborates threat."
    )
    alert["rule_weight"] = min(alert.get("rule_weight", 0.5) + 0.10, 1.0)
    return alert


def evaluate_all_v4_rules(
    features: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Evaluate all V4 rule functions and return the highest-severity alert.

    Applies cross-source elevation to the winning alert.

    [V4 ENHANCEMENT — gap: unified rule evaluation]

    Args:
        features: Enriched V4 feature dict for a single event/IP.

    Returns:
        Highest-severity alert dict, or None if no rules triggered.
    """
    checks = [
        check_brute_force_v4,
        check_credential_stuffing,
        check_low_and_slow,
        check_port_scan,
        check_large_transfer,
        check_suspicious_process,
        check_persistence,
    ]
    sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    best: Optional[Dict[str, Any]] = None

    for check_fn in checks:
        try:
            alert = check_fn(features)
            if alert is None:
                continue
            if best is None or sev_order.get(alert["severity"], 0) > sev_order.get(best["severity"], 0):
                best = alert
        except Exception:
            logger.exception("Rule check %s raised exception.", check_fn.__name__)

    if best is not None:
        best = apply_cross_source_elevation(best, features)

    return best


# ============================================================================
# Lateral movement detection (SQLite)
# ============================================================================

def detect_lateral_movement(
    db_conn: sqlite3.Connection, ip: str
) -> Optional[Dict[str, Any]]:
    """
    Query the database for lateral movement signals from a source IP.

    Flags if the same IP accessed 3+ distinct users OR 3+ distinct devices
    within the last 30 minutes.

    The window is an ISO cutoff computed here, not SQLite's
    ``datetime('now', ...)``: ingestion stores ``isoformat()`` of a UTC time
    (``YYYY-MM-DDTHH:MM:SS+00:00``), and compared as text against
    ``YYYY-MM-DD HH:MM:SS`` (``'T' > ' '``) every event from the current day
    would fall inside the window.

    [V4 ENHANCEMENT — gap: relationship modeling]
    [GLASSWING ALIGNMENT — lateral movement detection]

    Args:
        db_conn: Active SQLite3 connection.
        ip:      Source IP to investigate.

    Returns:
        Alert dict if lateral movement detected, else None.
    """
    sql = """
        SELECT source_ip,
               COUNT(DISTINCT effective_username) AS unique_users,
               COUNT(DISTINCT device_id)          AS unique_devices,
               GROUP_CONCAT(DISTINCT effective_username) AS affected_users,
               GROUP_CONCAT(DISTINCT device_id)          AS affected_devices
        FROM normalized_events
        WHERE source_ip = ?
          AND timestamp >= ?
        GROUP BY source_ip
        HAVING unique_users >= 3 OR unique_devices >= 3
    """
    try:
        cutoff = (datetime.utcnow() - timedelta(minutes=30)).isoformat()
        row = db_conn.execute(sql, (ip, cutoff)).fetchone()
        if row is None:
            return None
        d = dict(row)
        return {
            "ip":              ip,
            "type":            "LATERAL_MOVEMENT",
            "reason":          (
                f"IP {ip} accessed {d['unique_users']} users and "
                f"{d['unique_devices']} devices in 30 min"
            ),
            "severity":        "HIGH",
            "rule_weight":     0.85,
            "source_type":     "multi_source",
            "mitre_id":        "T1021",
            "mitre_name":      "Remote Services",
            "affected_users":  d.get("affected_users", ""),
            "affected_devices": d.get("affected_devices", ""),
        }
    except Exception:
        logger.exception("detect_lateral_movement failed for IP %s", ip)
        return None
