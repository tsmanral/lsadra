"""
LSADRA V3 — Abstract base class for anomaly detectors.

Adds ``save()`` and ``load()`` methods for model persistence via joblib. Files
go through :class:`lsadra.models.integrity.ModelStore`, so a load only
deserializes bytes that match the folder's authenticated manifest (G-17).
"""

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

from lsadra.config import MODEL_DIR
from lsadra.features.feature_extractor import FEATURE_COLS

logger = logging.getLogger(__name__)


class BaseAnomalyDetector(ABC):
    """Interface that all Layer-2 / Layer-3 detectors must implement."""

    def __init__(self, name: str):
        self.name = name
        self.features: List[str] = list(FEATURE_COLS)
        self.is_fitted: bool = False

    @abstractmethod
    def train(self, df: pd.DataFrame) -> None:
        """Train on feature data (assumed mostly normal)."""
        ...

    @abstractmethod
    def predict(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Score each row.

        Returns list of dicts with at least:
            ``is_anomaly`` (bool), ``anomaly_score`` (float), ``model_name`` (str).
        """
        ...

    # ── persistence ───────────────────────────────────────────────────────

    def _model_path(self) -> Path:
        """Return the default file path for this model's persisted state."""
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        return MODEL_DIR / f"{self.name}.joblib"

    def save(self, path: Path | None = None) -> Path:
        """
        Persist the model to disk using joblib, recording it in the manifest.

        Args:
            path: Optional custom path. Defaults to ``data/models/<name>.joblib``.

        Returns:
            The path the model was saved to.
        """
        from lsadra.models.integrity import ModelStore

        target = path or self._model_path()
        ModelStore(target.parent).save_joblib(target.name, self)
        logger.info("Model '%s' saved to %s", self.name, target)
        return target

    @classmethod
    def load(cls, path: Path) -> "BaseAnomalyDetector":
        """
        Load a persisted model from disk after verifying it against the manifest.

        Args:
            path: Path to the .joblib file.

        Returns:
            The deserialized model instance.

        Raises:
            ModelIntegrityError: the file is not listed in an authenticated
                manifest or its hash does not match.
        """
        from lsadra.models.integrity import ModelStore

        path = Path(path)
        model = ModelStore(path.parent).load_joblib(path.name)
        if not isinstance(model, cls):
            raise TypeError(f"{path.name} does not hold a {cls.__name__}")
        logger.info("Model '%s' loaded from %s", model.name, path)
        return model
