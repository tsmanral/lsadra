"""
LSADRA V4 — Dynamic severity scoring.

Extends the existing V3 compute_severity_score() with a V4-native
calculate_dynamic_severity() that incorporates multi-source feature
signals, SHAP values, rule weights, and threat intel scores.

All V3 functions are preserved unchanged.

[V4 ENHANCEMENT — gap: dynamic severity]
[DESIGN CHOICE] Additive scoring formula is deterministic and auditable —
no ML models, no external dependencies required.
"""

import logging
from typing import Any, Dict, Optional, Tuple

from lsadra.config import SEVERITY_THRESHOLDS

logger = logging.getLogger(__name__)

# Weights for each detection layer in the V3 composite score
_LAYER_WEIGHTS = {
    "layer1_z": 0.25,
    "layer2_score": 0.35,
    "layer3_error": 0.20,
    "vote_ratio": 0.20,
}

_Z_SCORE_MAX = 10.0
_AE_ERROR_MAX = 0.5


# ============================================================================
# V3 functions (preserved exactly)
# ============================================================================


def compute_severity_score(
    layer1_z: float = 0.0,
    layer2_score: float = 0.0,
    layer2_votes: int = 0,
    total_models: int = 3,
    layer3_error: float = 0.0,
) -> Tuple[float, str]:
    """
    Compute a composite severity score and label (V3, preserved).

    Args:
        layer1_z:      Max z-score from statistical baseline (Layer 1).
        layer2_score:  Averaged anomaly score from ensemble (Layer 2).
        layer2_votes:  Number of ensemble sub-models voting anomaly.
        total_models:  Total sub-models in the ensemble.
        layer3_error:  Reconstruction error from autoencoder (Layer 3).

    Returns:
        Tuple of (severity_score: float [0–1], severity_label: str).
    """
    norm_z = min(abs(layer1_z) / _Z_SCORE_MAX, 1.0)
    norm_ensemble = min(abs(layer2_score), 1.0)
    norm_ae = min(abs(layer3_error) / _AE_ERROR_MAX, 1.0)
    vote_ratio = layer2_votes / max(total_models, 1)

    score = (
        _LAYER_WEIGHTS["layer1_z"] * norm_z
        + _LAYER_WEIGHTS["layer2_score"] * norm_ensemble
        + _LAYER_WEIGHTS["layer3_error"] * norm_ae
        + _LAYER_WEIGHTS["vote_ratio"] * vote_ratio
    )
    score = max(0.0, min(score, 1.0))
    return score, _score_to_label(score)


def _score_to_label(score: float) -> str:
    """Map a severity score to a label using configured thresholds."""
    if score >= SEVERITY_THRESHOLDS.get("CRITICAL", 0.9):
        return "CRITICAL"
    elif score >= SEVERITY_THRESHOLDS.get("HIGH", 0.7):
        return "HIGH"
    elif score >= SEVERITY_THRESHOLDS.get("MEDIUM", 0.4):
        return "MEDIUM"
    return "LOW"


_LABEL_ORDER = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def apply_rule_floor(score: float, label: str, rule_severity: Optional[str]) -> Tuple[float, str]:
    """
    Raise a layer-based severity to at least the matched rule's severity.

    A brute force burst is HIGH whatever the anomaly layers think of it, so the
    rule's level sets a floor; it never lowers what the layers found.
    """
    if not rule_severity or rule_severity not in _LABEL_ORDER:
        return score, label
    if _LABEL_ORDER.index(rule_severity) <= _LABEL_ORDER.index(label):
        return score, label
    floor = SEVERITY_THRESHOLDS.get(rule_severity, 0.0) if rule_severity != "LOW" else 0.0
    return max(score, floor), rule_severity


def severity_context(score: float, label: str) -> Dict[str, Any]:
    """
    Build a severity context dict for use in narratives and SHAP.

    Returns:
        Dict with severity_score, severity_label, urgency_description.
    """
    urgency_map = {
        "CRITICAL": "Immediate action required — active exploitation likely.",
        "HIGH": "Urgent investigation recommended — strong anomaly detected.",
        "MEDIUM": "Review recommended — moderate anomaly indicators present.",
        "LOW": "Low-priority — minor anomaly detected, possible false positive.",
    }
    return {
        "severity_score": round(score, 4),
        "severity_label": label,
        "urgency": urgency_map.get(label, "Unknown severity level."),
    }


# ============================================================================
# V4: Dynamic severity scoring
# ============================================================================


def calculate_dynamic_severity(
    features: Dict[str, Any],
    shap_values: Optional[Dict[str, float]],
    rule_alert: Dict[str, Any],
    threat_intel_score: float = 0.0,
    cross_source_corroboration: bool = False,
) -> Tuple[str, float, str]:
    """
    Compute a dynamic severity score incorporating V4 multi-source signals.

    Formula::

        score = (
            min(failed_logins_last_5min / 20, 1.0) * 0.20
            + min(login_attempt_velocity  / 10, 1.0) * 0.20
            + (max(shap_values.values()) if shap_values else 0.0)  * 0.15
            + rule_alert.get('rule_weight', 0.5)                   * 0.25
            + threat_intel_score                                    * 0.10
            + (0.10 if cross_source_corroboration else 0.0)
        )

    Mapping::

        >= 0.75 → CRITICAL
        >= 0.50 → HIGH
        >= 0.25 → MEDIUM
        else    → LOW

    [V4 ENHANCEMENT — gap: dynamic severity]
    [DESIGN CHOICE] Deterministic formula with plain-English breakdown
    enables analyst audit without black-box opacity.

    Args:
        features:                  Enriched V4 feature dict.
        shap_values:               Dict of feature → SHAP value (may be None).
        rule_alert:                V4 rule alert dict (must contain rule_weight).
        threat_intel_score:        Normalised AbuseIPDB score [0, 1].
        cross_source_corroboration: True if IP is active in 2+ source types.

    Returns:
        (severity_label, numeric_score, plain_english_explanation)
    """
    failed_5min = min(float(features.get("failed_logins_last_5min", 0)) / 20, 1.0)
    velocity = min(float(features.get("login_attempt_velocity", 0)) / 10, 1.0)
    shap_signal = _max_shap(shap_values)
    rule_weight = float(rule_alert.get("rule_weight", 0.5))
    ti_score = max(0.0, min(float(threat_intel_score), 1.0))
    cross_bonus = 0.10 if cross_source_corroboration else 0.0

    login_contrib = failed_5min * 0.20
    vel_contrib = velocity * 0.20
    shap_contrib = shap_signal * 0.15
    rule_contrib = rule_weight * 0.25
    ti_contrib = ti_score * 0.10

    score = login_contrib + vel_contrib + shap_contrib + rule_contrib + ti_contrib + cross_bonus
    score = max(0.0, min(score, 1.0))

    label = _v4_score_to_label(score)
    explanation = _build_explanation(
        score,
        label,
        rule_contrib,
        login_contrib,
        vel_contrib,
        shap_contrib,
        ti_contrib,
        cross_bonus,
    )

    return label, round(score, 4), explanation


def _max_shap(shap_values: Optional[Dict[str, float]]) -> float:
    """Return the maximum absolute SHAP value, or 0.0 if None/empty."""
    if not shap_values:
        return 0.0
    try:
        return min(max(abs(v) for v in shap_values.values()), 1.0)
    except (ValueError, TypeError):
        return 0.0


def _v4_score_to_label(score: float) -> str:
    """Map V4 score to severity label (different thresholds from V3)."""
    if score >= 0.75:
        return "CRITICAL"
    if score >= 0.50:
        return "HIGH"
    if score >= 0.25:
        return "MEDIUM"
    return "LOW"


def _build_explanation(
    score: float,
    label: str,
    rule_contrib: float,
    login_contrib: float,
    vel_contrib: float,
    shap_contrib: float,
    ti_contrib: float,
    cross_bonus: float,
) -> str:
    """Build a plain-English explanation of the severity score components."""
    parts = []
    if rule_contrib > 0:
        parts.append(f"rule weight {rule_contrib:.2f}")
    if login_contrib > 0:
        parts.append(f"login volume {login_contrib:.2f}")
    if vel_contrib > 0:
        parts.append(f"velocity {vel_contrib:.2f}")
    if shap_contrib > 0:
        parts.append(f"SHAP signal {shap_contrib:.2f}")
    if ti_contrib > 0:
        parts.append(f"threat intel {ti_contrib:.2f}")
    if cross_bonus > 0:
        parts.append("cross-source corroboration +0.10")

    detail = " + ".join(parts) if parts else "no contributing signals"
    return f"Score {score:.2f} ({label}): {detail}"
