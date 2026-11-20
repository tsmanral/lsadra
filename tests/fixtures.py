"""
LSADRA V3 — Test fixtures.

Provides reusable mock objects and test data for the test suite.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import numpy as np
import pandas as pd
import pytest


# ── Mock LogEvent ─────────────────────────────────────────────────────────


@dataclass
class MockLogEvent:
    """Mock normalized log event for testing."""

    id: int = 1
    timestamp: str = "2026-03-15T14:30:00"
    device_id: str = "test-device-001"
    user_id: str = "test-user-001"
    host: str = "test-host"
    effective_username: str = "admin"
    source_ip: str = "192.168.1.100"
    event_type: str = "auth_failure"
    raw_message: str = "Failed password for admin from 192.168.1.100 port 22 ssh2"
    attributes: Dict[str, Any] = field(default_factory=dict)
    is_synthetic: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "device_id": self.device_id,
            "user_id": self.user_id,
            "host": self.host,
            "effective_username": self.effective_username,
            "source_ip": self.source_ip,
            "event_type": self.event_type,
            "raw_message": self.raw_message,
            "attributes": self.attributes,
            "is_synthetic": self.is_synthetic,
        }


# ── Mock AnomalyRecord ───────────────────────────────────────────────────


@dataclass
class MockAnomalyRecord:
    """Mock anomaly detection result for testing."""

    anomaly_id: int = 1
    event_id: int = 1
    device_id: str = "test-device-001"
    user_id: str = "test-user-001"
    source_ip: str = "192.168.1.100"
    layer1_score: float = 4.5
    layer2_score: float = 0.85
    layer2_votes: int = 3
    layer3_score: float = 0.12
    severity_score: float = 0.75
    severity_label: str = "HIGH"
    is_anomaly: bool = True
    threat_type: str = "Brute Force Attack"
    attack_type: str = "Brute Force Attack"
    mitre_technique: str = "T1110.001"
    narrative: str = "Test anomaly narrative"
    created_at: str = "2026-03-15T14:30:00"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_id": self.anomaly_id,
            "event_id": self.event_id,
            "device_id": self.device_id,
            "user_id": self.user_id,
            "source_ip": self.source_ip,
            "layer1_score": self.layer1_score,
            "layer2_score": self.layer2_score,
            "layer2_votes": self.layer2_votes,
            "layer3_score": self.layer3_score,
            "severity_score": self.severity_score,
            "severity_label": self.severity_label,
            "is_anomaly": self.is_anomaly,
            "threat_type": self.threat_type,
            "attack_type": self.attack_type,
            "mitre_technique": self.mitre_technique,
            "narrative": self.narrative,
            "created_at": self.created_at,
        }


# ── Pre-built feature matrix ─────────────────────────────────────────────


def make_feature_matrix(n_rows: int = 10, n_features: int = 8) -> pd.DataFrame:
    """
    Create a pre-built feature matrix for testing.

    Returns a DataFrame with 10 rows and 8 feature columns matching
    the FEATURE_COLS from the feature extractor, plus metadata.
    """
    np.random.seed(42)
    data = {
        "id": list(range(1, n_rows + 1)),
        "timestamp": [
            (datetime(2026, 3, 15, 14, 0, 0) + timedelta(minutes=i)).isoformat()
            for i in range(n_rows)
        ],
        "device_id": ["test-device-001"] * n_rows,
        "user_id": ["test-user-001"] * n_rows,
        "host": ["test-host"] * n_rows,
        "effective_username": ["admin"] * n_rows,
        "source_ip": ["192.168.1.100"] * n_rows,
        "event_type": ["auth_failure"] * n_rows,
        "raw_message": ["test message"] * n_rows,
        "is_synthetic": [False] * n_rows,
        # Feature columns
        "hour_sin": np.random.uniform(-1, 1, n_rows),
        "hour_cos": np.random.uniform(-1, 1, n_rows),
        "is_off_hours": np.random.randint(0, 2, n_rows).astype(float),
        "is_weekend": np.random.randint(0, 2, n_rows).astype(float),
        "time_since_last_event_ip": np.random.uniform(0, 3600, n_rows),
        "unique_users_15m": np.random.randint(1, 10, n_rows).astype(float),
        "failures_15m": np.random.randint(0, 30, n_rows).astype(float),
        "successes_15m": np.random.randint(0, 10, n_rows).astype(float),
        "failure_ratio_15m": np.random.uniform(0, 1, n_rows),
    }
    return pd.DataFrame(data)


# ── Mock IncidentManager ─────────────────────────────────────────────────


def make_mock_incident_manager(pre_seeded_incidents: int = 3) -> MagicMock:
    """
    Create a mock IncidentManager with pre-seeded open incidents.

    The mock's process_anomaly returns incrementing incident IDs.
    """
    manager = MagicMock()
    manager.window_minutes = 15

    # Pre-seed some open incidents
    incidents = []
    for i in range(1, pre_seeded_incidents + 1):
        incidents.append(
            {
                "id": i,
                "device_id": "test-device-001",
                "source_ip": f"192.168.1.{100 + i}",
                "attack_type": "Brute Force Attack",
                "status": "OPEN",
                "severity_label": "HIGH",
                "anomaly_count": 1,
                "first_seen": "2026-03-15T14:00:00",
                "last_seen": "2026-03-15T14:30:00",
            }
        )

    manager.get_open_incidents = MagicMock(return_value=incidents)

    # process_anomaly returns incrementing IDs
    _counter = [pre_seeded_incidents]

    def _process(anomaly):
        _counter[0] += 1
        return _counter[0]

    manager.process_anomaly = MagicMock(side_effect=_process)
    return manager


# ── Mock httpx response for AbuseIPDB ────────────────────────────────────


def make_mock_abuseipdb_response(confidence_score: int = 85) -> MagicMock:
    """
    Create a mock httpx response simulating an AbuseIPDB API response.
    """
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "ipAddress": "203.0.113.50",
            "abuseConfidenceScore": confidence_score,
            "countryCode": "US",
            "isp": "Test ISP",
            "domain": "test.example.com",
            "isTor": False,
            "totalReports": 42,
            "lastReportedAt": "2026-03-14T12:00:00+00:00",
        }
    }
    mock_response.raise_for_status = MagicMock()
    return mock_response


# ── Test database setup helper ───────────────────────────────────────────


def setup_test_db(tmp_path):
    """
    Configure LSADRA to use a temporary test database.

    Must be called before any database operations in a test.
    Patches the DB_PATH at the module level in both config and database modules.
    """
    import lsadra.config as config
    import lsadra.storage.database as db_module

    test_db_path = tmp_path / "test_sentinel.db"
    test_model_dir = tmp_path / "models"
    test_model_dir.mkdir(parents=True, exist_ok=True)

    # Patch config
    config.DB_PATH = test_db_path
    config.MODEL_DIR = test_model_dir
    config.DATA_DIR = tmp_path

    # Also patch the DB_PATH used inside the database module (it imports at top)
    db_module.DB_PATH = test_db_path

    from lsadra.storage.database import init_db

    init_db()
