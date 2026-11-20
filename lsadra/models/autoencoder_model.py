"""
LSADRA — Layer 3: Lightweight autoencoder anomaly detector.

Trains a small feed-forward autoencoder on normal feature vectors with
scikit-learn's ``MLPRegressor`` (fit X -> X), and scores with a plain numpy
forward pass. High reconstruction error signals an anomaly.

The network is the same shape the PyTorch version had (input -> mid -> latent
-> mid -> input, ReLU on every hidden layer, linear output, Adam, batch 64), so
the layer behaves the same. PyTorch itself is no longer needed: importing it
cost about 900 MB of server RSS on Linux for a model whose weights are 4 KB
(M1 D8 memory limit is 600 MB).

Persistence is plain JSON (weights as nested lists plus normalisation and
threshold), written and verified through the signed models-folder manifest
(G-17). Nothing is unpickled when the model loads.
"""

import logging
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from lsadra.config import (
    AUTOENCODER_EPOCHS,
    AUTOENCODER_LATENT_DIM,
    AUTOENCODER_LR,
    AUTOENCODER_PERCENTILE_THRESHOLD,
    MODEL_DIR,
)
from lsadra.features.feature_extractor import FEATURE_COLS

logger = logging.getLogger(__name__)

STATE_FORMAT = "lsadra-autoencoder/1"


def _hidden_sizes(input_dim: int, latent_dim: int) -> tuple:
    """Encoder input -> mid -> latent, mirrored by the decoder."""
    mid = max((input_dim + latent_dim) // 2, latent_dim + 1)
    return (mid, latent_dim, mid)


def _forward(weights: List[np.ndarray], biases: List[np.ndarray], x: np.ndarray) -> np.ndarray:
    """ReLU on every hidden layer, linear output (MLPRegressor's own forward)."""
    h = x
    last = len(weights) - 1
    for i, (w, b) in enumerate(zip(weights, biases)):
        h = h @ w + b
        if i < last:
            np.maximum(h, 0.0, out=h)
    return h


# ── Model wrapper ─────────────────────────────────────────────────────────


class AutoencoderModel:
    """
    Autoencoder-based anomaly detector (Layer 3).

    Trains on normal data.  At prediction time, observations whose
    reconstruction error exceeds the *AUTOENCODER_PERCENTILE_THRESHOLD*-th
    percentile of training errors are flagged as anomalous.
    """

    def __init__(
        self,
        latent_dim: int = AUTOENCODER_LATENT_DIM,
        epochs: int = AUTOENCODER_EPOCHS,
        lr: float = AUTOENCODER_LR,
        threshold_pct: float = AUTOENCODER_PERCENTILE_THRESHOLD,
    ):
        self.name = "autoencoder"
        self.latent_dim = latent_dim
        self.epochs = epochs
        self.lr = lr
        self.threshold_pct = threshold_pct
        self.features = list(FEATURE_COLS)

        self._weights: List[np.ndarray] = []
        self._biases: List[np.ndarray] = []
        self._threshold: float = 0.0
        self._mean: Any = None
        self._std: Any = None
        self.is_fitted: bool = False

    # ── training ──────────────────────────────────────────────────────────

    def train(self, df: pd.DataFrame) -> None:
        """
        Train the autoencoder on feature data (presumed normal).

        Determines the anomaly threshold from training reconstruction errors.
        """
        from sklearn.exceptions import ConvergenceWarning
        from sklearn.neural_network import MLPRegressor

        X = df[self.features].values.astype(np.float64)
        # Normalise
        self._mean = X.mean(axis=0)
        self._std = X.std(axis=0) + 1e-9
        X_norm = (X - self._mean) / self._std

        net = MLPRegressor(
            hidden_layer_sizes=_hidden_sizes(X.shape[1], self.latent_dim),
            activation="relu",
            solver="adam",
            alpha=0.0,  # torch Adam had no weight decay
            batch_size=min(64, len(X_norm)),
            learning_rate_init=self.lr,
            max_iter=self.epochs,
            shuffle=True,
            tol=0.0,
            n_iter_no_change=self.epochs + 1,  # always run every epoch
            random_state=0,
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ConvergenceWarning)
            net.fit(X_norm, X_norm)

        self._weights = [np.asarray(w, dtype=np.float64) for w in net.coefs_]
        self._biases = [np.asarray(b, dtype=np.float64) for b in net.intercepts_]

        # Determine threshold from training errors
        errors = self._errors(X_norm)
        self._threshold = float(np.percentile(errors, self.threshold_pct))
        self.is_fitted = True
        logger.info(
            "Autoencoder trained (%d epochs). Threshold (p%d): %.6f",
            self.epochs,
            int(self.threshold_pct),
            self._threshold,
        )

    def _errors(self, X_norm: np.ndarray) -> np.ndarray:
        recon = _forward(self._weights, self._biases, X_norm)
        return ((recon - X_norm) ** 2).mean(axis=1)

    # ── scoring ───────────────────────────────────────────────────────────

    def score(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Score each row by reconstruction error.

        Returns list of dicts with ``reconstruction_error`` and ``is_ae_anomaly``.
        """
        if not self.is_fitted:
            return [{"reconstruction_error": 0.0, "is_ae_anomaly": False}] * len(df)

        X = df[self.features].values.astype(np.float64)
        errors = self._errors((X - self._mean) / self._std)

        return [
            {
                "reconstruction_error": float(e),
                "is_ae_anomaly": bool(e > self._threshold),
            }
            for e in errors
        ]

    # ── persistence (JSON through the signed manifest) ────────────────────

    def _model_path(self) -> Path:
        """Return the default file path for persisted autoencoder state."""
        from lsadra.detection.model_lifecycle import AUTOENCODER_FILE

        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        return MODEL_DIR / AUTOENCODER_FILE

    def save(self, path: Optional[Path] = None) -> Path:
        """Save the autoencoder state (weights + normalisation + threshold)."""
        if not self.is_fitted:
            logger.warning("Cannot save autoencoder — not trained.")
            return path or self._model_path()

        from lsadra.models.integrity import ModelStore

        target = path or self._model_path()
        state = {
            "format": STATE_FORMAT,
            "features": list(self.features),
            "weights": [w.tolist() for w in self._weights],
            "biases": [b.tolist() for b in self._biases],
            "threshold": float(self._threshold),
            "mean": np.asarray(self._mean, dtype=np.float64).tolist(),
            "std": np.asarray(self._std, dtype=np.float64).tolist(),
            "latent_dim": int(self.latent_dim),
            "threshold_pct": float(self.threshold_pct),
            "epochs": int(self.epochs),
            "lr": float(self.lr),
        }
        ModelStore(target.parent).save_json(target.name, state)
        logger.info("Autoencoder saved to %s", target)
        return target

    def load(self, path: Optional[Path] = None) -> bool:
        """
        Load persisted autoencoder state.

        Returns True if loaded successfully, False otherwise (including when
        the file does not verify against the manifest or its shapes do not
        form a valid network for the current feature set).
        """
        from lsadra.models.integrity import ModelIntegrityError, ModelStore

        target = path or self._model_path()
        if not target.exists():
            logger.info("No persisted autoencoder found at %s", target)
            return False

        try:
            state = ModelStore(target.parent).load_json(target.name)
            weights, biases, mean, std, threshold = self._validate(state)
        except ModelIntegrityError as exc:
            logger.warning("Refusing to load autoencoder from %s: %s", target, exc)
            return False
        except Exception as exc:  # noqa: BLE001 - malformed file: retrain instead
            logger.warning("Ignoring unusable autoencoder state in %s: %s", target, exc)
            return False

        self._weights, self._biases = weights, biases
        self._mean, self._std = mean, std
        self._threshold = threshold
        self.latent_dim = int(state.get("latent_dim", self.latent_dim))
        self.is_fitted = True
        logger.info("Autoencoder loaded from %s", target)
        return True

    def _validate(self, state: Any):
        """Check a loaded JSON state holds a well-formed network; raise if not."""
        if not isinstance(state, dict) or state.get("format") != STATE_FORMAT:
            raise ValueError("unknown autoencoder state format")
        if state.get("features") != self.features:
            raise ValueError("feature set changed since the model was trained")

        def arr(value: Any, ndim: int) -> np.ndarray:
            a = np.asarray(value, dtype=np.float64)
            if a.ndim != ndim or not np.all(np.isfinite(a)):
                raise ValueError("bad array in autoencoder state")
            return a

        weights = [arr(w, 2) for w in state["weights"]]
        biases = [arr(b, 1) for b in state["biases"]]
        dim = len(self.features)
        if not weights or len(weights) != len(biases):
            raise ValueError("weights and biases do not match")
        prev = dim
        for w, b in zip(weights, biases):
            if w.shape[0] != prev or b.shape[0] != w.shape[1]:
                raise ValueError("layer shapes do not chain")
            prev = w.shape[1]
        if prev != dim:
            raise ValueError("output layer does not reconstruct the input")
        mean, std = arr(state["mean"], 1), arr(state["std"], 1)
        if mean.shape[0] != dim or std.shape[0] != dim or np.any(std <= 0):
            raise ValueError("bad normalisation in autoencoder state")
        threshold = float(state["threshold"])
        if not np.isfinite(threshold):
            raise ValueError("bad threshold in autoencoder state")
        return weights, biases, mean, std, threshold
