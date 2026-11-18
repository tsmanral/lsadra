"""
LSADRA V2 — Attack classifier.

Maps ML-flagged anomalies to specific threat types via the rule engine.
"""

from typing import Any, Dict, Tuple

from lsadra.detection.rule_engine import NO_RULE_MATCH, UNMAPPED_ANOMALY, evaluate_rules


class AttackClassifier:
    """Classify anomalies using heuristic rules when ML flags them."""

    @staticmethod
    def classify(is_anomaly: bool, feature_row: Dict[str, Any]) -> Tuple[str, str]:
        """
        Returns (Threat Name, MITRE Technique ID) or ("None", "N/A")
        if not an anomaly.
        """
        if not is_anomaly:
            return NO_RULE_MATCH
        result = evaluate_rules(feature_row)
        return UNMAPPED_ANOMALY if result == NO_RULE_MATCH else result
