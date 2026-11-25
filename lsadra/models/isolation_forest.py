"""
LSADRA V2 — Isolation Forest detector (Layer 2).
"""

from typing import Any, Dict, List

import pandas as pd
from sklearn.ensemble import IsolationForest

from lsadra.models.base_model import BaseAnomalyDetector
from lsadra.config import ENSEMBLE_CONTAMINATION


class IsolationForestModel(BaseAnomalyDetector):
    """Isolation Forest anomaly detector."""

    def __init__(self, contamination: float = ENSEMBLE_CONTAMINATION):
        super().__init__("Isolation_Forest")
        self.model = IsolationForest(contamination=contamination, random_state=42, n_jobs=-1)

    def train(self, df: pd.DataFrame) -> None:
        self.model.fit(df[self.features])
        self.is_fitted = True

    def predict(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        if not self.is_fitted:
            raise RuntimeError(f"{self.name} is not fitted.")
        X = df[self.features]
        preds = self.model.predict(X)
        scores = -self.model.score_samples(X)
        return [
            {"is_anomaly": bool(p == -1), "anomaly_score": float(s), "model_name": self.name}
            for p, s in zip(preds, scores)
        ]
