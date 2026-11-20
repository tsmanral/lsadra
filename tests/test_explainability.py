"""
LSADRA V3 — Explainability tests.

Tests for SHAP aggregation, narrative builder, and threat intelligence.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from tests.fixtures import make_mock_abuseipdb_response, setup_test_db


@pytest.fixture(autouse=True)
def _test_db(tmp_path):
    setup_test_db(tmp_path)


class TestShapAggregator:
    """Tests for the SHAP aggregator."""

    def test_aggregate_empty(self):
        from lsadra.explainability.shap_aggregator import ShapAggregator

        result = ShapAggregator.aggregate([])
        assert result == {}

    def test_aggregate_single_model(self):
        from lsadra.explainability.shap_aggregator import ShapAggregator

        shap_dicts = [{"failures_15m": 0.5, "hour_sin": 0.2}]
        result = ShapAggregator.aggregate(shap_dicts)
        assert result["failures_15m"] == pytest.approx(0.5, abs=0.01)
        assert result["hour_sin"] == pytest.approx(0.2, abs=0.01)

    def test_aggregate_weighted(self):
        from lsadra.explainability.shap_aggregator import ShapAggregator

        shap_dicts = [
            {"failures_15m": 0.3},
            {"failures_15m": 0.9},
        ]
        result = ShapAggregator.aggregate_weighted(shap_dicts, model_weights=[1.0, 3.0])
        # Weighted: (0.3*0.25 + 0.9*0.75) = 0.075 + 0.675 = 0.75
        assert result["failures_15m"] == pytest.approx(0.75, abs=0.01)

    def test_dominant_group(self):
        from lsadra.explainability.shap_aggregator import ShapAggregator

        shap_dict = {
            "failures_15m": 0.8,
            "successes_15m": 0.3,
            "hour_sin": 0.1,
        }
        group = ShapAggregator.dominant_group(shap_dict)
        assert group == "Behavioral"

    def test_group_breakdown(self):
        from lsadra.explainability.shap_aggregator import ShapAggregator

        shap_dict = {
            "failures_15m": 0.5,
            "hour_sin": 0.3,
            "hour_cos": 0.2,
        }
        breakdown = ShapAggregator.group_breakdown(shap_dict)
        assert "Behavioral" in breakdown
        assert "Temporal" in breakdown
        assert breakdown["Temporal"] == pytest.approx(0.5, abs=0.01)

    def test_mitre_confidence(self):
        from lsadra.explainability.shap_aggregator import ShapAggregator

        shap_dict = {
            "failures_15m": 0.8,
            "unique_users_15m": 0.3,
            "time_since_last_event_ip": 0.1,
            "hour_sin": 0.05,
        }
        confidence = ShapAggregator.mitre_confidence(shap_dict, "T1110.001")
        assert 0.0 <= confidence <= 1.0
        # Behavioral + Velocity features dominate → high confidence for brute force
        assert confidence > 0.5


class TestNarrativeBuilder:
    """Tests for the narrative builder."""

    def test_basic_narrative(self):
        from lsadra.explainability.narrative_builder import NarrativeBuilder

        narrative = NarrativeBuilder.build(
            threat_type="Brute Force Attack",
            mitre_id="T1110.001",
            row_data={"source_ip": "1.2.3.4", "effective_username": "admin", "device_id": "d1"},
            layer1_z=5.0,
            layer2_score=0.8,
            layer3_error=0.1,
        )
        assert "Brute Force Attack" in narrative
        assert "T1110.001" in narrative
        assert "1.2.3.4" in narrative

    def test_narrative_with_severity(self):
        from lsadra.explainability.narrative_builder import NarrativeBuilder

        sev_ctx = {
            "severity_score": 0.85,
            "severity_label": "CRITICAL",
            "urgency": "Immediate action required.",
        }
        narrative = NarrativeBuilder.build(
            threat_type="Brute Force Attack",
            mitre_id="T1110.001",
            row_data={"source_ip": "1.2.3.4"},
            severity_context=sev_ctx,
        )
        assert "CRITICAL" in narrative
        assert "0.85" in narrative

    def test_narrative_with_features(self):
        from lsadra.explainability.narrative_builder import NarrativeBuilder

        narrative = NarrativeBuilder.build(
            threat_type="Brute Force Attack",
            mitre_id="T1110.001",
            row_data={
                "source_ip": "1.2.3.4",
                "failures_15m": 25,
                "unique_users_15m": 3,
                "is_off_hours": 1,
            },
        )
        assert "25 failed logins" in narrative
        assert "off-hours" in narrative


class TestThreatIntel:
    """Tests for threat intelligence functionality."""

    def test_mock_abuseipdb_response(self):
        mock = make_mock_abuseipdb_response(confidence_score=85)
        data = mock.json()["data"]
        assert data["abuseConfidenceScore"] == 85
        assert data["countryCode"] == "US"
        assert data["totalReports"] == 42

    def test_get_ip_reputation_not_cached(self):
        from lsadra.explainability.threat_intel import get_ip_reputation

        result = get_ip_reputation("203.0.113.50")
        assert result["ip"] == "203.0.113.50"
        assert result.get("status") == "not_queried"

    def test_threat_intel_cache(self):
        from lsadra.storage.database import upsert_threat_intel, get_threat_intel

        upsert_threat_intel(
            ip_address="10.0.0.1",
            abuse_score=75,
            country_code="CN",
            isp="Test ISP",
            cache_hours=24,
        )

        cached = get_threat_intel("10.0.0.1")
        assert cached is not None
        assert cached["abuse_score"] == 75
        assert cached["country_code"] == "CN"
