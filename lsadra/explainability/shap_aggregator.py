"""
LSADRA V3 — SHAP aggregator (refactored).

Provides weighted SHAP value aggregation across ensemble sub-models,
with feature group analysis and MITRE confidence estimation.
"""

from typing import Any, Dict, List, Optional

FEATURE_GROUPS: Dict[str, List[str]] = {
    "Temporal": ["hour_sin", "hour_cos", "is_off_hours", "is_weekend"],
    "Velocity": ["time_since_last_event_ip"],
    "Behavioral": ["failures_15m", "successes_15m", "failure_ratio_15m", "unique_users_15m"],
}

# MITRE technique → feature groups that most contribute to detection
MITRE_FEATURE_MAP: Dict[str, List[str]] = {
    "T1110.001": ["Behavioral", "Velocity"],  # Brute Force
    "T1110.004": ["Behavioral", "Velocity"],  # Credential Stuffing
    "T1078": ["Temporal"],  # Valid Accounts (off-hours)
    "T1190": ["Behavioral", "Temporal"],  # Exploit Public-Facing App
}


class ShapAggregator:
    """
    Aggregate per-model SHAP explanations into weighted group-level
    importance scores used by the narrative builder.
    """

    @staticmethod
    def aggregate_weighted(
        shap_dicts: List[Dict[str, float]],
        model_weights: Optional[List[float]] = None,
    ) -> Dict[str, float]:
        """
        Weighted average of SHAP values across models.

        Args:
            shap_dicts: List of per-model SHAP value dicts.
            model_weights: Optional list of weights (one per model).
                           Defaults to equal weighting.

        Returns:
            Aggregated per-feature importance scores, sorted descending.
        """
        if not shap_dicts:
            return {}

        n = len(shap_dicts)
        if model_weights is None:
            model_weights = [1.0 / n] * n
        else:
            total = sum(model_weights)
            model_weights = [w / total for w in model_weights]

        all_features = set()
        for d in shap_dicts:
            all_features.update(d.keys())

        agg: Dict[str, float] = {}
        for feat in all_features:
            weighted_sum = sum(abs(d.get(feat, 0.0)) * w for d, w in zip(shap_dicts, model_weights))
            agg[feat] = weighted_sum

        return dict(sorted(agg.items(), key=lambda kv: kv[1], reverse=True))

    @staticmethod
    def aggregate(shap_dicts: List[Dict[str, float]]) -> Dict[str, float]:
        """Average SHAP values across models (backward-compatible)."""
        return ShapAggregator.aggregate_weighted(shap_dicts)

    @staticmethod
    def dominant_group(shap_dict: Dict[str, float]) -> str:
        """Determine which feature group contributes most to the anomaly."""
        group_scores: Dict[str, float] = {}
        for gname, feats in FEATURE_GROUPS.items():
            group_scores[gname] = sum(abs(shap_dict.get(f, 0.0)) for f in feats)

        if not group_scores:
            return "Unknown"

        return max(group_scores, key=group_scores.get)  # type: ignore[arg-type]

    @staticmethod
    def group_breakdown(shap_dict: Dict[str, float]) -> Dict[str, float]:
        """Return per-group total SHAP importance scores."""
        breakdown: Dict[str, float] = {}
        for gname, feats in FEATURE_GROUPS.items():
            breakdown[gname] = sum(abs(shap_dict.get(f, 0.0)) for f in feats)
        return dict(sorted(breakdown.items(), key=lambda kv: kv[1], reverse=True))

    @staticmethod
    def mitre_confidence(shap_dict: Dict[str, float], mitre_id: str) -> float:
        """
        Estimate confidence (0–1) that the MITRE technique assignment is
        correct based on how much the relevant feature groups contributed.

        Args:
            shap_dict: Aggregated SHAP values.
            mitre_id: MITRE ATT&CK technique ID.

        Returns:
            Confidence score between 0.0 and 1.0.
        """
        relevant_groups = MITRE_FEATURE_MAP.get(mitre_id, [])
        if not relevant_groups or not shap_dict:
            return 0.5  # default moderate confidence

        total_importance = sum(abs(v) for v in shap_dict.values())
        if total_importance == 0:
            return 0.5

        relevant_importance = sum(
            sum(abs(shap_dict.get(f, 0.0)) for f in FEATURE_GROUPS.get(g, []))
            for g in relevant_groups
        )

        confidence = relevant_importance / total_importance
        return min(max(confidence, 0.0), 1.0)
