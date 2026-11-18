"""
LSADRA V3 — Layer 3: Lightweight autoencoder anomaly detector.

Trains a small feed-forward autoencoder on normal feature vectors using
PyTorch (CPU only).  High reconstruction error signals an anomaly.
Supports persistence via ``torch.save`` / ``torch.load``. The saved state holds
only tensors and plain numbers, is verified against the models folder manifest,
and is loaded with ``weights_only=True`` (G-17).
"""

import logging
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

# Only import torch if available — graceful degradation
try:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset

    _HAS_TORCH = True
except ImportError:
    _HAS_TORCH = False
    logger.warning("PyTorch not installed; AutoencoderModel will be a no-op stub.")


# ── PyTorch network ──────────────────────────────────────────────────────

if _HAS_TORCH:

    class _AENet(nn.Module):
        """Simple symmetric autoencoder."""

        def __init__(self, input_dim: int, latent_dim: int):
            super().__init__()
            mid = max((input_dim + latent_dim) // 2, latent_dim + 1)
            self.encoder = nn.Sequential(
                nn.Linear(input_dim, mid),
                nn.ReLU(),
                nn.Linear(mid, latent_dim),
                nn.ReLU(),
            )
            self.decoder = nn.Sequential(
                nn.Linear(latent_dim, mid),
                nn.ReLU(),
                nn.Linear(mid, input_dim),
            )

        def forward(self, x: "torch.Tensor") -> "torch.Tensor":
            return self.decoder(self.encoder(x))


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

        self._net: Any = None
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
        if not _HAS_TORCH:
            logger.warning("Skipping autoencoder training — PyTorch not available.")
            return

        X = df[self.features].values.astype(np.float32)
        # Normalise
        self._mean = X.mean(axis=0)
        self._std = X.std(axis=0) + 1e-9
        X_norm = (X - self._mean) / self._std

        tensor = torch.tensor(X_norm)
        loader = DataLoader(TensorDataset(tensor, tensor), batch_size=64, shuffle=True)

        input_dim = X.shape[1]
        self._net = _AENet(input_dim, self.latent_dim)
        optimiser = torch.optim.Adam(self._net.parameters(), lr=self.lr)
        criterion = nn.MSELoss()

        self._net.train()
        for epoch in range(self.epochs):
            total_loss = 0.0
            for xb, _ in loader:
                out = self._net(xb)
                loss = criterion(out, xb)
                optimiser.zero_grad()
                loss.backward()
                optimiser.step()
                total_loss += loss.item()

        # Determine threshold from training errors
        self._net.eval()
        with torch.no_grad():
            recon = self._net(tensor)
            errors = ((recon - tensor) ** 2).mean(dim=1).numpy()
        self._threshold = float(np.percentile(errors, self.threshold_pct))
        self.is_fitted = True
        logger.info(
            "Autoencoder trained (%d epochs). Threshold (p%d): %.6f",
            self.epochs, int(self.threshold_pct), self._threshold,
        )

    # ── scoring ───────────────────────────────────────────────────────────

    def score(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Score each row by reconstruction error.

        Returns list of dicts with ``reconstruction_error`` and ``is_ae_anomaly``.
        """
        if not self.is_fitted or not _HAS_TORCH:
            return [{"reconstruction_error": 0.0, "is_ae_anomaly": False}] * len(df)

        X = df[self.features].values.astype(np.float32)
        X_norm = (X - self._mean) / self._std
        tensor = torch.tensor(X_norm)

        self._net.eval()
        with torch.no_grad():
            recon = self._net(tensor)
            errors = ((recon - tensor) ** 2).mean(dim=1).numpy()

        return [
            {
                "reconstruction_error": float(e),
                "is_ae_anomaly": bool(e > self._threshold),
            }
            for e in errors
        ]

    # ── persistence (torch-specific) ──────────────────────────────────────

    def _model_path(self) -> Path:
        """Return the default file path for persisted autoencoder state."""
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        return MODEL_DIR / "autoencoder.pt"

    def save(self, path: Optional[Path] = None) -> Path:
        """Save the autoencoder state (network weights + normalization params)."""
        if not _HAS_TORCH or self._net is None:
            logger.warning("Cannot save autoencoder — not trained or torch unavailable.")
            return self._model_path()

        from lsadra.models.integrity import ModelStore

        target = path or self._model_path()
        state = {
            "net_state_dict": self._net.state_dict(),
            "threshold": float(self._threshold),
            "mean": torch.as_tensor(np.asarray(self._mean, dtype=np.float32)),
            "std": torch.as_tensor(np.asarray(self._std, dtype=np.float32)),
            "latent_dim": int(self.latent_dim),
            "input_dim": int(self._net.encoder[0].in_features),
            "threshold_pct": float(self.threshold_pct),
            "epochs": int(self.epochs),
            "lr": float(self.lr),
        }
        ModelStore(target.parent).save_torch(target.name, state)
        logger.info("Autoencoder saved to %s", target)
        return target

    def load(self, path: Optional[Path] = None) -> bool:
        """
        Load persisted autoencoder state.

        Returns True if loaded successfully, False otherwise (including when
        the file does not verify against the manifest).
        """
        if not _HAS_TORCH:
            logger.warning("Cannot load autoencoder — torch not available.")
            return False

        from lsadra.models.integrity import ModelIntegrityError, ModelStore

        target = path or self._model_path()
        if not target.exists():
            logger.info("No persisted autoencoder found at %s", target)
            return False

        try:
            state = ModelStore(target.parent).load_torch(target.name)
            input_dim = int(state["input_dim"])
            latent_dim = int(state["latent_dim"])
            net = _AENet(input_dim, latent_dim)
            net.load_state_dict(state["net_state_dict"])
            net.eval()
            self.latent_dim = latent_dim
            self._net = net
            self._threshold = float(state["threshold"])
            self._mean = np.asarray(state["mean"], dtype=np.float32)
            self._std = np.asarray(state["std"], dtype=np.float32)
            self.is_fitted = True
            logger.info("Autoencoder loaded from %s", target)
            return True
        except ModelIntegrityError as exc:
            logger.warning("Refusing to load autoencoder from %s: %s", target, exc)
            return False
        except Exception:
            logger.exception("Failed to load autoencoder from %s", target)
            return False
