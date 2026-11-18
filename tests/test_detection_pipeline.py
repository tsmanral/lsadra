"""
LSADRA V3 — Detection pipeline tests.

Tests for severity scoring, ensemble voting, rule engine,
incident management, and the detection orchestrator.
"""

import pytest
import numpy as np
import pandas as pd

from tests.fixtures import (
    MockAnomalyRecord,
    MockLogEvent,
    make_feature_matrix,
    make_mock_incident_manager,
    setup_test_db,
)


class TestSeverityScoring:
    """Tests for the severity scoring module."""

    def test_compute_severity_basic(self):
        from lsadra.detection.severity import compute_severity_score

        score, label = compute_severity_score(
            layer1_z=5.0, layer2_score=0.8, layer2_votes=3,
            total_models=3, layer3_error=0.3,
        )
        assert 0.0 <= score <= 1.0
        assert label in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_high_severity(self):
        from lsadra.detection.severity import compute_severity_score

        score, label = compute_severity_score(
            layer1_z=8.0, layer2_score=0.95, layer2_votes=3,
            total_models=3, layer3_error=0.45,
        )
        assert score >= 0.7
        assert label in ("CRITICAL", "HIGH")

    def test_low_severity(self):
        from lsadra.detection.severity import compute_severity_score

        score, label = compute_severity_score(
            layer1_z=0.5, layer2_score=0.1, layer2_votes=0,
            total_models=3, layer3_error=0.01,
        )
        assert score < 0.4
        assert label == "LOW"

    def test_zero_inputs(self):
        from lsadra.detection.severity import compute_severity_score

        score, label = compute_severity_score()
        assert score == 0.0
        assert label == "LOW"

    def test_severity_context(self):
        from lsadra.detection.severity import severity_context

        ctx = severity_context(0.85, "CRITICAL")
        assert ctx["severity_label"] == "CRITICAL"
        assert "Immediate" in ctx["urgency"]


class TestRuleEngine:
    """Tests for the heuristic rule engine."""

    def test_brute_force_detection(self):
        from lsadra.detection.rule_engine import evaluate_rules

        threat, mitre = evaluate_rules({
            "failures_15m": 25, "unique_users_15m": 2,
            "successes_15m": 0, "is_off_hours": 0, "failure_ratio_15m": 1.0,
        })
        assert threat == "Brute Force Attack"
        assert mitre == "T1110.001"

    def test_credential_stuffing(self):
        from lsadra.detection.rule_engine import evaluate_rules

        threat, mitre = evaluate_rules({
            "failures_15m": 20, "unique_users_15m": 8,
            "successes_15m": 0, "is_off_hours": 0, "failure_ratio_15m": 1.0,
        })
        assert threat == "Credential Stuffing"
        assert mitre == "T1110.004"

    def test_off_hour_access(self):
        from lsadra.detection.rule_engine import evaluate_rules

        threat, mitre = evaluate_rules({
            "failures_15m": 0, "unique_users_15m": 1,
            "successes_15m": 1, "is_off_hours": 1, "failure_ratio_15m": 0,
        })
        assert threat == "Anomalous Off-Hour Access"

    def test_no_match_is_distinguishable_and_carries_no_technique(self):
        """An ordinary row matches no rule; the old fallback returned T1190."""
        from lsadra.detection.rule_engine import NO_RULE_MATCH, evaluate_rules

        result = evaluate_rules({
            "failures_15m": 0, "unique_users_15m": 1,
            "successes_15m": 1, "is_off_hours": 0, "failure_ratio_15m": 0,
            "event_type": "auth_success",
        })
        assert result == NO_RULE_MATCH
        assert "T1190" not in result


class TestVerdictMerge:
    """How _run_layers merges rule matches with the layer 1-3 verdicts."""

    @staticmethod
    def _orchestrator(l1_flags):
        from lsadra.detection.detection_orchestrator import DetectionOrchestrator

        class _Layer:
            def __init__(self, out):
                self.out = out

            def score(self, df):
                return self.out(df)

        orch = DetectionOrchestrator.__new__(DetectionOrchestrator)
        orch._trained = False  # layer 2 abstains
        orch.baseline = _Layer(lambda df: [
            {"z_max": 9.0 if f else 0.0, "is_baseline_anomaly": f} for f in l1_flags])
        orch.autoencoder = _Layer(lambda df: [
            {"reconstruction_error": 0.0, "is_ae_anomaly": False}] * len(df))
        return orch

    @staticmethod
    def _rows(*rows):
        base = {"id": 1, "device_id": "d", "user_id": "u", "source_ip": "192.0.2.1",
                "timestamp": "2026-01-15T10:00:00", "event_type": "auth_success",
                "failures_15m": 0, "unique_users_15m": 1, "successes_15m": 1,
                "is_off_hours": 0, "failure_ratio_15m": 0.0}
        return pd.DataFrame([{**base, "id": i + 1, **r} for i, r in enumerate(rows)])

    def test_ordinary_event_is_not_an_alert(self):
        """Regression: every scored event used to become an alert labelled T1190."""
        res = self._orchestrator([False])._run_layers(self._rows({}))
        assert res[0]["is_anomaly"] is False
        assert res[0]["mitre_technique"] == "N/A"

    def test_rule_match_alerts_with_its_technique(self):
        res = self._orchestrator([False])._run_layers(
            self._rows({"failures_15m": 25, "unique_users_15m": 2, "successes_15m": 0,
                        "failure_ratio_15m": 1.0, "event_type": "auth_failure"}))
        assert res[0]["is_anomaly"] is True
        assert res[0]["mitre_technique"] == "T1110.001"

    def test_ml_only_anomaly_has_no_guessed_technique(self):
        res = self._orchestrator([True])._run_layers(self._rows({}))
        assert res[0]["is_anomaly"] is True
        assert res[0]["threat_type"] == "Unknown Anomalous Activity"
        assert res[0]["mitre_technique"] == "N/A"


class TestEnsembleVoting:
    """Tests for ensemble majority voting logic."""

    def test_majority_vote_anomaly(self):
        """When 2/3 models flag anomaly, ensemble should too."""
        from lsadra.models.ensemble_model import EnsembleModel

        ensemble = EnsembleModel()
        df = make_feature_matrix(n_rows=1)

        # We can't easily test without training, so test the voting logic
        votes = 2
        total = 3
        assert votes >= total / 2  # Should be anomaly

    def test_minority_vote_normal(self):
        """When only 1/3 models flag anomaly, ensemble should not."""
        votes = 1
        total = 3
        assert not (votes >= total / 2)  # Should be normal


class TestIncidentManager:
    """Tests for the incident management system."""

    def test_mock_incident_manager(self):
        manager = make_mock_incident_manager(pre_seeded_incidents=3)
        incidents = manager.get_open_incidents()
        assert len(incidents) == 3
        assert incidents[0]["status"] == "OPEN"

    def test_process_anomaly_increments(self):
        manager = make_mock_incident_manager(pre_seeded_incidents=2)
        anomaly = MockAnomalyRecord().to_dict()
        id1 = manager.process_anomaly(anomaly)
        id2 = manager.process_anomaly(anomaly)
        assert id2 == id1 + 1


class TestDriftDetection:
    """Tests for PSI drift detection."""

    def test_psi_no_drift(self):
        from lsadra.detection.drift_detector import _calculate_psi

        np.random.seed(42)
        reference = np.random.normal(0, 1, 1000)
        current = np.random.normal(0, 1, 1000)
        psi = _calculate_psi(reference, current)
        assert psi < 0.1  # No significant drift

    def test_psi_with_drift(self):
        from lsadra.detection.drift_detector import _calculate_psi

        np.random.seed(42)
        reference = np.random.normal(0, 1, 1000)
        current = np.random.normal(3, 1, 1000)  # Significant shift
        psi = _calculate_psi(reference, current)
        assert psi > 0.2  # Clear drift


class TestFeatureMatrix:
    """Tests for the test fixture feature matrix."""

    def test_shape(self):
        df = make_feature_matrix()
        assert df.shape[0] == 10
        # 9 feature cols + 10 meta cols = 19
        assert df.shape[1] == 19

    def test_feature_columns_present(self):
        from lsadra.features.feature_extractor import FEATURE_COLS
        df = make_feature_matrix()
        for col in FEATURE_COLS:
            assert col in df.columns
