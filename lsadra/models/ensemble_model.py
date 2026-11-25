"""
LSADRA V3 — Classical unsupervised ensemble (Layer 2).

Combines Isolation Forest, LOF, and One-Class SVM predictions via
majority voting with averaged anomaly scores.
Supports persistence via ``save()`` and ``load()`` using joblib, verified
against the models folder manifest before loading (G-17).
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from lsadra.config import MODEL_DIR
from lsadra.models.base_model import BaseAnomalyDetector
from lsadra.models.isolation_forest import IsolationForestModel
from lsadra.models.local_outlier_factor import LOFModel
from lsadra.models.one_class_svm import OneClassSVMModel

logger = logging.getLogger(__name__)


class EnsembleModel:
    """Majority-vote ensemble over multiple base anomaly detectors."""

    def __init__(self) -> None:
        self.name = "ensemble"
        self.models: List[BaseAnomalyDetector] = [
            IsolationForestModel(),
            LOFModel(),
            OneClassSVMModel(),
        ]

    def train(self, df: pd.DataFrame) -> None:
        """Train every base model."""
        for m in self.models:
            m.train(df)
        logger.info("Ensemble Layer-2 trained (%d models).", len(self.models))

    def predict(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Predict with majority voting.

        Returns list of dicts per row with:
            ``is_anomaly``, ``anomaly_score`` (avg), ``votes``, ``details``.
        """
        if df.empty:
            return []

        all_preds = [m.predict(df) for m in self.models]
        n = len(df)
        results: List[Dict[str, Any]] = []

        for i in range(n):
            votes = sum(1 for mp in all_preds if mp[i]["is_anomaly"])
            avg_score = float(np.mean([mp[i]["anomaly_score"] for mp in all_preds]))
            details = [
                {
                    "model": self.models[j].name,
                    "is_anomaly": all_preds[j][i]["is_anomaly"],
                    "score": all_preds[j][i]["anomaly_score"],
                }
                for j in range(len(self.models))
            ]
            results.append(
                {
                    "is_anomaly": votes >= len(self.models) / 2,
                    "anomaly_score": avg_score,
                    "votes": votes,
                    "total_models": len(self.models),
                    "details": details,
                    "model_name": "Ensemble_Voting",
                }
            )

        return results

    # ── persistence ───────────────────────────────────────────────────────

    def _model_path(self) -> Path:
        """Return the default file path for this ensemble's persisted state."""
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        return MODEL_DIR / "ensemble.joblib"

    def save(self, path: Optional[Path] = None) -> Path:
        """Persist the ensemble (its base models are pickled inside it)."""
        from lsadra.models.integrity import ModelStore

        target = path or self._model_path()
        ModelStore(target.parent).save_joblib(target.name, self)
        logger.info("Ensemble saved to %s", target)
        return target

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "EnsembleModel":
        """Load a persisted ensemble, or a fresh one if none verifies.

        The file is deserialized only after its hash matches the folder's
        authenticated manifest. A missing, unlisted or modified file is never
        loaded; the caller gets an untrained ensemble and models retrain.
        """
        from lsadra.models.integrity import ModelIntegrityError, ModelStore

        target = path or (MODEL_DIR / "ensemble.joblib")
        if not target.exists():
            logger.info("No persisted ensemble found at %s — creating fresh.", target)
            return cls()

        try:
            model = ModelStore(target.parent).load_joblib(target.name)
        except ModelIntegrityError as exc:
            logger.warning("Refusing to load ensemble from %s: %s — creating fresh.", target, exc)
            return cls()
        except Exception:
            logger.exception("Failed to load ensemble from %s — creating fresh.", target)
            return cls()
        if not isinstance(model, cls):
            logger.warning("%s does not hold an ensemble — creating fresh.", target)
            return cls()
        logger.info("Ensemble loaded from %s", target)
        return model
