"""
ECOD shadow scorer (ADR 0007, Phase 1).

ECOD (Li et al., "ECOD: Unsupervised Outlier Detection Using Empirical
Cumulative Distribution Functions", TKDE 2022) scores a row by how far into
the tails of each feature's training distribution its values fall:

    O(x) = max(sum_j -log F_j(x_j), sum_j -log (1 - F_j(x_j-)), sum_j skew-chosen tail)

It has no hyperparameters. The fitted state is, per feature, the sorted
distinct training values with their cumulative counts, kept as plain JSON and
signed with the other model files (no pickle).

It runs in **shadow mode**: ``DetectionOrchestrator._run_layers`` adds its
score and verdict to every result but never lets it raise or suppress an
alert. On the detection bench it is the strongest single scorer (see
``benchmarks/detection/results/phase1-challengers-2026-11-18.md``).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import numpy as np

from lsadra.features.model_features import MODEL_FEATURE_NAMES

#: Distinct values kept per feature; above this the column is stored as quantiles.
MAX_DISTINCT = 2000
FORMAT_VERSION = 1


class ECODModel:
    """Empirical-CDF tail scorer with a training-quantile alert threshold."""

    def __init__(self, target_fpr: float = 0.001) -> None:
        self.target_fpr = target_fpr
        self.n: int = 0
        self.values: List[np.ndarray] = []  # per feature: sorted distinct values
        self.cum: List[np.ndarray] = []  # per feature: count of training values <= values[k]
        self.skew_sign: np.ndarray = np.zeros(0)
        self.threshold: Optional[float] = None
        self.features: List[str] = list(MODEL_FEATURE_NAMES)

    @property
    def is_fitted(self) -> bool:
        return self.n > 0

    # ── fit / score ──────────────────────────────────────────────────────

    def fit(self, X: np.ndarray) -> "ECODModel":
        X = np.asarray(X, dtype=float)
        n, d = X.shape
        if n == 0:
            raise ValueError("ECOD needs at least one training row")
        self.n = n
        self.values, self.cum = [], []
        for j in range(d):
            vals, counts = np.unique(X[:, j], return_counts=True)
            cum = np.cumsum(counts)
            if len(vals) > MAX_DISTINCT:
                # Keep evenly spaced ranks plus both extremes.
                idx = np.unique(np.r_[np.linspace(0, len(vals) - 1, MAX_DISTINCT).astype(int)])
                vals, cum = vals[idx], cum[idx]
            self.values.append(vals)
            self.cum.append(cum.astype(float))
        mu, sd = X.mean(axis=0), X.std(axis=0)
        safe = np.where(sd > 0, sd, 1.0)
        skew = np.where(sd > 0, ((X - mu) ** 3).mean(axis=0) / safe**3, 0.0)
        self.skew_sign = np.sign(skew)
        train_scores = self.score(X)
        self.threshold = float(np.quantile(train_scores, 1.0 - self.target_fpr))
        return self

    def _tails(self, X: np.ndarray):
        n = float(self.n)
        left = np.empty_like(X, dtype=float)
        right = np.empty_like(X, dtype=float)
        for j in range(X.shape[1]):
            vals, cum = self.values[j], self.cum[j]
            # F(x) = share of training values <= x
            k = np.searchsorted(vals, X[:, j], side="right")
            left[:, j] = np.where(k > 0, cum[np.maximum(k - 1, 0)], 0.0) / n
            # 1 - F(x-) = share of training values >= x
            k2 = np.searchsorted(vals, X[:, j], side="left")
            below = np.where(k2 > 0, cum[np.maximum(k2 - 1, 0)], 0.0)
            right[:, j] = (n - below) / n
        eps = 1.0 / (n + 1.0)
        return -np.log(np.clip(left, eps, 1.0)), -np.log(np.clip(right, eps, 1.0))

    def score(self, X: np.ndarray) -> np.ndarray:
        X = np.asarray(X, dtype=float)
        if not self.is_fitted or len(X) == 0:
            return np.zeros(len(X))
        nl, nr = self._tails(X)
        auto = np.where(self.skew_sign < 0, nl, nr)
        return np.maximum.reduce([nl.sum(axis=1), nr.sum(axis=1), auto.sum(axis=1)])

    def predict(self, X: np.ndarray) -> List[Dict[str, Any]]:
        scores = self.score(X)
        thr = self.threshold if self.threshold is not None else float("inf")
        return [{"ecod_score": float(s), "is_ecod_anomaly": bool(s > thr)} for s in scores]

    # ── persistence (plain JSON) ─────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "format": "lsadra-ecod",
            "version": FORMAT_VERSION,
            "features": self.features,
            "n": self.n,
            "target_fpr": self.target_fpr,
            "threshold": self.threshold,
            "skew_sign": [float(s) for s in self.skew_sign],
            "values": [[float(v) for v in vals] for vals in self.values],
            "cum": [[float(c) for c in cum] for cum in self.cum],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ECODModel":
        if data.get("format") != "lsadra-ecod" or data.get("version") != FORMAT_VERSION:
            raise ValueError("not an ECOD model file of a supported version")
        if list(data.get("features", [])) != list(MODEL_FEATURE_NAMES):
            raise ValueError("ECOD model was trained on a different feature set")
        m = cls(target_fpr=float(data["target_fpr"]))
        m.n = int(data["n"])
        m.threshold = None if data.get("threshold") is None else float(data["threshold"])
        m.skew_sign = np.asarray(data["skew_sign"], dtype=float)
        m.values = [np.asarray(v, dtype=float) for v in data["values"]]
        m.cum = [np.asarray(c, dtype=float) for c in data["cum"]]
        if not (len(m.values) == len(m.cum) == len(m.skew_sign) == len(MODEL_FEATURE_NAMES)):
            raise ValueError("ECOD model file is inconsistent")
        return m
