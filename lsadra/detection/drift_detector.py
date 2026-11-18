"""
LSADRA V3 — Feature drift detector.

Calculates Population Stability Index (PSI) between a reference distribution
(training data) and the current data window. When PSI exceeds the configured
threshold, the corresponding model is flagged as stale in the model registry.
"""

import logging
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from lsadra.config import PSI_DRIFT_THRESHOLD
from lsadra.features.feature_extractor import FEATURE_COLS
from lsadra.storage.database import (
    insert_drift_record,
    mark_model_stale,
)

logger = logging.getLogger(__name__)


def _calculate_psi(
    reference: np.ndarray, current: np.ndarray, n_bins: int = 10
) -> float:
    """
    Calculate Population Stability Index between two 1-D distributions.

    PSI < 0.1  → no significant shift
    PSI 0.1–0.2 → moderate shift
    PSI > 0.2  → significant shift (drift)
    """
    eps = 1e-6

    # Create bins from the reference distribution
    breakpoints = np.percentile(reference, np.linspace(0, 100, n_bins + 1))
    breakpoints = np.unique(breakpoints)
    if len(breakpoints) < 2:
        return 0.0

    ref_counts, _ = np.histogram(reference, bins=breakpoints)
    cur_counts, _ = np.histogram(current, bins=breakpoints)

    ref_pct = ref_counts / max(len(reference), 1) + eps
    cur_pct = cur_counts / max(len(current), 1) + eps

    psi = float(np.sum((cur_pct - ref_pct) * np.log(cur_pct / ref_pct)))
    return max(psi, 0.0)  # PSI is non-negative


def detect_drift(
    reference_df: pd.DataFrame,
    current_df: pd.DataFrame,
    model_name: str = "ensemble",
    threshold: float = PSI_DRIFT_THRESHOLD,
    features: Optional[List[str]] = None,
) -> Dict[str, float]:
    """
    Detect feature drift between reference and current data.

    Args:
        reference_df: Training/reference feature DataFrame.
        current_df: Recent/current feature DataFrame.
        model_name: Name of the model to associate drift records with.
        threshold: PSI threshold above which a feature is considered drifted.
        features: Optional list of feature columns. Defaults to FEATURE_COLS.

    Returns:
        Dict mapping feature_name → PSI value for drifted features.
    """
    features = features or list(FEATURE_COLS)
    drifted: Dict[str, float] = {}

    if reference_df.empty or current_df.empty:
        logger.info("Skipping drift detection — insufficient data.")
        return drifted

    for feat in features:
        if feat not in reference_df.columns or feat not in current_df.columns:
            continue

        ref_values = reference_df[feat].dropna().values.astype(float)
        cur_values = current_df[feat].dropna().values.astype(float)

        if len(ref_values) < 10 or len(cur_values) < 10:
            continue

        psi = _calculate_psi(ref_values, cur_values)
        is_drifted = psi > threshold

        # Record the measurement
        insert_drift_record(model_name, feat, psi, is_drifted)

        if is_drifted:
            drifted[feat] = psi
            logger.warning(
                "Feature drift detected: %s (PSI=%.4f > %.4f) for model '%s'",
                feat, psi, threshold, model_name,
            )

    # If any feature has drifted, mark the model as stale
    if drifted:
        mark_model_stale(model_name)
        logger.warning(
            "Model '%s' marked as stale — %d features drifted.", model_name, len(drifted)
        )

    return drifted


def detect_drift_from_reference(
    reference: Dict[str, Any],
    current_df: pd.DataFrame,
    threshold: float = PSI_DRIFT_THRESHOLD,
) -> Dict[str, float]:
    """PSI of each feature in *current_df* against stored training quantiles (G-19).

    Records a measurement per feature for both ML models and marks both stale
    when any feature drifts. A sudden jump right after a retrain can also mean
    the training data was poisoned, so the warning says so: review the latest
    training run before retraining again.
    """
    from lsadra.detection.model_lifecycle import psi_against_reference

    drifted: Dict[str, float] = {}
    for feat, ref in (reference.get("features") or {}).items():
        if feat not in current_df.columns:
            continue
        values = pd.to_numeric(current_df[feat], errors="coerce").dropna().to_numpy(dtype=float)
        if len(values) < 10:
            continue
        psi = psi_against_reference(ref, values)
        is_drifted = psi > threshold
        for model_name in ("ensemble", "autoencoder"):
            insert_drift_record(model_name, feat, psi, is_drifted)
        if is_drifted:
            drifted[feat] = psi

    if drifted:
        for model_name in ("ensemble", "autoencoder"):
            mark_model_stale(model_name)
        logger.warning(
            "Feature drift against the training reference: %s. Either the environment "
            "changed or recent training data was poisoned; review the latest training run "
            "(GET /api/models/status) before retraining or roll back.",
            ", ".join(f"{k}={v:.3f}" for k, v in sorted(drifted.items())),
        )
    return drifted


def _recent_feature_window(hours: int) -> pd.DataFrame:
    """Features of events from the last *hours* hours (bounded by TRAINING_MAX_EVENTS)."""
    from lsadra import config
    from lsadra.features.feature_extractor import build_features
    from lsadra.storage.database import get_recent_events

    events = get_recent_events(config.TRAINING_MAX_EVENTS)
    if not events:
        return pd.DataFrame()
    cutoff = pd.Timestamp.now(tz="UTC") - pd.Timedelta(hours=hours)
    recent = []
    for ev in events:
        ts = pd.to_datetime(ev.get("timestamp"), errors="coerce", utc=True)
        if not pd.isna(ts) and ts >= cutoff:
            recent.append(ev)
    recent.reverse()  # oldest first, as build_features expects
    return build_features(recent)


def run(
    reference_df: Optional[pd.DataFrame] = None,
    current_df: Optional[pd.DataFrame] = None,
) -> Dict[str, float]:
    """
    Scheduled entry point for drift detection.

    With DataFrames supplied, compares them directly. Without, compares the
    last ``LSADRA_DRIFT_WINDOW_HOURS`` of events against the reference
    quantiles stored (and verified) when the live models were trained.
    """
    if reference_df is not None and current_df is not None:
        results = detect_drift(reference_df, current_df, model_name="ensemble")
        detect_drift(reference_df, current_df, model_name="autoencoder")
        return results

    from lsadra import config
    from lsadra.detection.model_lifecycle import load_reference

    reference = load_reference()
    if not reference:
        logger.info("Drift detection skipped — no verified training reference yet.")
        return {}
    current = _recent_feature_window(config.DRIFT_WINDOW_HOURS)
    if current.empty:
        logger.info("Drift detection skipped — no events in the last %d h.",
                    config.DRIFT_WINDOW_HOURS)
        return {}
    return detect_drift_from_reference(reference, current)
