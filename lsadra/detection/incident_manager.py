"""
LSADRA V3 — Incident management system.

Groups related anomalies into incidents using the composite key
(device_id, source_ip, attack_type) within a configurable time window.
Prevents duplicate incident creation for correlated events (e.g., 15 failed
logins from the same IP produce 1 incident, not 15).
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from lsadra.config import INCIDENT_WINDOW_MINUTES
from lsadra.storage.database import (
    create_incident,
    get_open_incident,
    update_anomaly_incident,
    update_incident_last_seen,
)

logger = logging.getLogger(__name__)


class IncidentManager:
    """
    Manages the lifecycle of security incidents.

    When an anomaly is detected, the incident manager either:
    - Attaches it to an existing open incident (if one exists for the same
      device + source IP + attack type within the time window), or
    - Creates a new incident and links the anomaly to it.
    """

    def __init__(self, window_minutes: int = INCIDENT_WINDOW_MINUTES):
        self.window_minutes = window_minutes

    def process_anomaly(self, anomaly: Dict[str, Any]) -> int:
        """
        Process a detected anomaly — create or update an incident.

        Args:
            anomaly: Dict with at least: anomaly_id, device_id, source_ip,
                     attack_type (or threat_type), severity_label, created_at.

        Returns:
            The incident ID the anomaly was linked to.
        """
        device_id = anomaly.get("device_id", "")
        source_ip = anomaly.get("source_ip", "")
        attack_type = anomaly.get("attack_type") or anomaly.get("threat_type", "Unknown")
        severity_label = anomaly.get("severity_label", "LOW")
        anomaly_id = anomaly.get("anomaly_id", 0)
        created_at = anomaly.get("created_at", datetime.utcnow().isoformat())

        # Calculate window boundary
        window_start = (datetime.utcnow() - timedelta(minutes=self.window_minutes)).isoformat()

        # Try to find an existing open incident
        existing = get_open_incident(
            device_id=device_id,
            source_ip=source_ip,
            attack_type=attack_type,
            window_start=window_start,
        )

        if existing:
            incident_id = existing["id"]
            update_incident_last_seen(incident_id, created_at)
            logger.info(
                "Anomaly %d linked to existing incident %d (%s from %s)",
                anomaly_id,
                incident_id,
                attack_type,
                source_ip,
            )
        else:
            # [V4 DEMO ENHANCEMENT] — Auto-assign playbooks based on attack type
            playbook_map = {
                "Unauthorized Privilege Escalation": "AD_ELEVATION_RESPONSE",
                "SSH Brute Force": "BRUTE_FORCE_RESPONSE",
                "Ransomware Activity": "RANSOMWARE_RESPONSE",
            }
            assigned_playbook = playbook_map.get(attack_type)

            incident_id = create_incident(
                device_id=device_id,
                source_ip=source_ip,
                attack_type=attack_type,
                severity_label=severity_label,
                first_seen=created_at,
                playbook=assigned_playbook,
            )
            logger.info(
                "New incident %d created: %s from %s on device %s",
                incident_id,
                attack_type,
                source_ip,
                device_id,
            )

        # Link the anomaly row to the incident
        if anomaly_id:
            update_anomaly_incident(anomaly_id, incident_id)

        return incident_id
