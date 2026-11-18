"""
LSADRA V2 — Adversarial robustness experiments.

Skeleton for evasion and poisoning experiments that test the detection
stack's resilience to adversarial manipulation.
"""

import logging
from typing import Any, Dict

import numpy as np
import pandas as pd

from lsadra.detection.detection_orchestrator import DetectionOrchestrator
from lsadra.features.feature_extractor import FEATURE_COLS

logger = logging.getLogger(__name__)


def run_evasion_experiments(
    orchestrator: DetectionOrchestrator,
    attack_df: pd.DataFrame,
    perturbation_budget: float = 0.1,
) -> Dict[str, Any]:
    """
    Test evasion: perturb attack samples within a budget and check
    whether detection degrades.

    Args:
        orchestrator: Trained detection orchestrator.
        attack_df: Feature DataFrame of known-attack samples.
        perturbation_budget: Maximum relative change per feature (fraction).

    Returns:
        Dict with baseline detection rate and post-perturbation rate.
    """
    original = orchestrator.run_batch(attack_df)
    orig_detected = sum(1 for d in original if d["is_anomaly"])

    # Perturb features
    perturbed = attack_df.copy()
    for col in FEATURE_COLS:
        if col in perturbed.columns:
            noise = np.random.uniform(
                -perturbation_budget, perturbation_budget, size=len(perturbed)
            )
            perturbed[col] = perturbed[col] * (1 + noise)

    after = orchestrator.run_batch(perturbed)
    after_detected = sum(1 for d in after if d["is_anomaly"])

    result = {
        "original_detected": orig_detected,
        "perturbed_detected": after_detected,
        "total": len(attack_df),
        "evasion_success_rate": 1 - (after_detected / max(orig_detected, 1)),
    }
    logger.info("Evasion experiment: %s", result)
    return result


def run_poisoning_experiments(
    orchestrator: DetectionOrchestrator,
    clean_train_df: pd.DataFrame,
    poison_fraction: float = 0.05,
) -> Dict[str, Any]:
    """
    Test poisoning: inject a fraction of adversarial samples into training
    data and measure impact on detection rates.

    This is a **skeleton** — a full implementation would use a more
    sophisticated poisoning strategy.
    """
    n_poison = int(len(clean_train_df) * poison_fraction)
    poison_rows = clean_train_df.sample(n=n_poison, replace=True).copy()

    for col in FEATURE_COLS:
        if col in poison_rows.columns:
            poison_rows[col] = poison_rows[col] * np.random.uniform(3, 10, size=n_poison)

    combined = pd.concat([clean_train_df, poison_rows], ignore_index=True)

    # Re-train with poisoned data (the canary gate may reject the candidate)
    training = orchestrator.train(combined, trigger="other")

    # Evaluate on the original attack set (placeholder)
    result = {
        "clean_train_size": len(clean_train_df),
        "poison_fraction": poison_fraction,
        "poison_samples": n_poison,
        "training_status": training.get("status"),
        "note": "Re-run benchmark after poisoning to measure impact.",
    }
    logger.info("Poisoning experiment: %s", result)
    return result
