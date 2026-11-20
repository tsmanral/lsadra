"""
LSADRA V2 — SHAP explainer (carried from V1, adapted for V2 interfaces).
"""

import logging
from typing import Any, Dict, List

import pandas as pd

logger = logging.getLogger(__name__)

try:
    import shap

    _HAS_SHAP = True
except ImportError:
    _HAS_SHAP = False
    logger.warning("shap not installed; ShapExplainer will return empty explanations.")


class ShapExplainer:
    """Generate per-instance SHAP feature importance explanations."""

    def __init__(self, model: Any, background_data: pd.DataFrame, is_tree_based: bool = False):
        self.model = model
        self._explainer: Any = None

        if not _HAS_SHAP:
            return

        if is_tree_based:
            self._explainer = shap.TreeExplainer(model)
        else:
            bg = (
                shap.kmeans(background_data, min(50, len(background_data)))
                if len(background_data) > 50
                else background_data
            )

            def _scorer(X: Any) -> Any:
                if hasattr(model, "score_samples"):
                    return -model.score_samples(X)
                return model.predict(X)

            self._explainer = shap.KernelExplainer(_scorer, bg)

    def explain(self, instance: pd.Series) -> Dict[str, float]:
        """Return a dict mapping feature names to SHAP values for one instance."""
        if self._explainer is None:
            return {}
        try:
            df = pd.DataFrame([instance])
            vals = self._explainer.shap_values(df)
            if isinstance(vals, list):
                vals = vals[0]
            if len(vals.shape) > 1:
                vals = vals[0]
            return dict(
                sorted(
                    zip(df.columns, (float(v) for v in vals)),
                    key=lambda kv: abs(kv[1]),
                    reverse=True,
                )
            )
        except Exception as exc:
            logger.error("SHAP failed: %s", exc)
            return {}

    def top_features(self, instance: pd.Series, k: int = 3) -> List[str]:
        """Return the top *k* feature names by absolute SHAP value."""
        return list(self.explain(instance).keys())[:k]
