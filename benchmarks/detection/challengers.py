"""
Challenger models for the detection bench (Phase 1 of ADR 0007).

Scores candidate layers next to the shipped ones on the same stream, so a
replacement is chosen on numbers before any of it reaches ``lsadra/``:

``ch_iforest``
    Isolation Forest over the wider feature set below, exported to ONNX and
    scored with ONNX Runtime (the bench checks the ONNX scores match sklearn).
``ch_ecod``
    ECOD (empirical-CDF outlier detection, Li et al. 2022): per feature, the
    tail probability of a value under the training distribution; a row's
    score is the summed negative log tail probability. Parameter-free and
    stored as plain quantile tables, so it needs no pickle and no model file.
``ch_unsup``
    The mean of the two, each rank-normalised against the training scores.
``ch_lgbm``
    LightGBM classifier. Positives are attack events of *other* attack
    instances (leave-one-instance-out), negatives are training-period benign
    events, so no event is ever scored by a model that saw it. Benign test
    events are scored by the model trained on every instance.

Feature set: the nine V3 features, the numeric rule features (endpoint
signals, auth bursts, network fan-out, cross-source) and a one-hot of the
canonical event type. Nothing here reads labels except ``ch_lgbm`` training.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

CHALLENGER_KEYS = ["ch_iforest", "ch_ecod", "ch_unsup", "ch_lgbm"]

_NUMERIC_RULE_COLS = [
    "failed_logins_last_5min", "login_attempts_last_5min", "login_attempt_velocity",
    "unique_dst_ports_10min", "bytes_out_to_dest_30min", "dest_is_global",
    "cross_source_activity", "known_lolbin", "suspicious_cmdline", "encoded_command",
    "unusual_parent", "artifact_in_user_writable_dir", "artifact_in_hidden_dir",
    "windows_artifact", "registry_autostart_key", "registry_service_key",
]


def feature_names() -> List[str]:
    from lsadra.detection.event_types import EVENT_TYPES
    from lsadra.features.feature_extractor import FEATURE_COLS

    return list(FEATURE_COLS) + _NUMERIC_RULE_COLS + [f"et_{t}" for t in sorted(EVENT_TYPES)]


def feature_matrix(df: pd.DataFrame) -> np.ndarray:
    """Float32 matrix in ``feature_names()`` order (rule features computed here)."""
    from lsadra.features.feature_extractor import FEATURE_COLS
    from lsadra.features.rule_features import build_rule_features

    if df.empty:
        return np.zeros((0, len(feature_names())), dtype=np.float32)
    rf = build_rule_features(df.reset_index(drop=True))
    cols = [pd.to_numeric(rf[c], errors="coerce").fillna(0.0).astype(float).to_numpy()
            for c in list(FEATURE_COLS) + _NUMERIC_RULE_COLS]
    et = rf["canonical_event_type"].astype(str).to_numpy()
    for name in feature_names()[len(cols):]:
        cols.append((et == name[3:]).astype(float))
    return np.column_stack(cols).astype(np.float32)


# ── ECOD ─────────────────────────────────────────────────────────────────


class ECOD:
    """ECOD with skewness-chosen tails, stored as sorted training columns."""

    def fit(self, X: np.ndarray) -> "ECOD":
        self.sorted_ = np.sort(X, axis=0)
        n = len(X)
        mu, sd = X.mean(axis=0), X.std(axis=0)
        skew = np.where(sd > 0, ((X - mu) ** 3).mean(axis=0) / np.where(sd > 0, sd, 1) ** 3, 0.0)
        self.skew_sign_ = np.sign(skew)
        self.n_ = n
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        n = self.n_
        left = np.empty_like(X, dtype=float)
        right = np.empty_like(X, dtype=float)
        for j in range(X.shape[1]):
            col = self.sorted_[:, j]
            left[:, j] = np.searchsorted(col, X[:, j], side="right") / n
            right[:, j] = (n - np.searchsorted(col, X[:, j], side="left")) / n
        eps = 1.0 / (n + 1)
        nl = -np.log(np.clip(left, eps, 1.0))
        nr = -np.log(np.clip(right, eps, 1.0))
        auto = np.where(self.skew_sign_ < 0, nl, nr)
        # Max over left-tail, right-tail and skew-chosen sums (the ECOD paper's O).
        return np.maximum.reduce([nl.sum(axis=1), nr.sum(axis=1), auto.sum(axis=1)])


# ── Isolation Forest via ONNX ────────────────────────────────────────────


def _iforest_onnx(X_train: np.ndarray, seed: int):
    from onnxruntime import InferenceSession
    from skl2onnx import to_onnx
    from sklearn.ensemble import IsolationForest

    model = IsolationForest(n_estimators=200, random_state=seed).fit(X_train)
    onx = to_onnx(model, X_train[:1], target_opset={"": 17, "ai.onnx.ml": 3})
    sess = InferenceSession(onx.SerializeToString(), providers=["CPUExecutionProvider"])
    out_name = [o.name for o in sess.get_outputs() if o.name.lower().startswith("score")][0]

    def score(X: np.ndarray) -> np.ndarray:
        # ONNX "scores" are sklearn decision_function: lower = more anomalous.
        return -sess.run([out_name], {sess.get_inputs()[0].name: X})[0].ravel()

    probe = X_train[: min(200, len(X_train))]
    diff = float(np.max(np.abs(score(probe) - (-model.decision_function(probe)))))
    return score, {"onnx_bytes": len(onx.SerializeToString()), "max_abs_diff_vs_sklearn": round(diff, 6)}


def _rank_normalise(train_scores: np.ndarray, scores: np.ndarray) -> np.ndarray:
    ref = np.sort(train_scores)
    return np.searchsorted(ref, scores, side="right") / max(len(ref), 1)


# ── LightGBM, leave one attack instance out ──────────────────────────────


def _lgbm(seed: int):
    import lightgbm as lgb

    return lgb.LGBMClassifier(
        n_estimators=200, learning_rate=0.05, num_leaves=31, min_child_samples=10,
        subsample=0.8, subsample_freq=1, colsample_bytree=0.8,
        class_weight="balanced", random_state=seed, verbose=-1, n_jobs=1,
    )


def score_challengers(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
    labels: Dict[int, Dict[str, Any]],
    seed: int,
    keys: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Fit the challengers and score *test_df*.

    *labels* maps event id to ``{"role", "instance"}``. Returns
    ``{"scores": {event_id: {key: score}}, "info": {...}}``.
    """
    keys = list(keys or CHALLENGER_KEYS)
    train_df = train_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)
    X_tr = feature_matrix(train_df)
    X_te = feature_matrix(test_df)
    tr_ids = train_df["id"].astype(int).tolist()
    te_ids = test_df["id"].astype(int).tolist()
    benign_tr = np.array([labels.get(i, {}).get("role") == "negative" for i in tr_ids])
    X_fit = X_tr[benign_tr] if benign_tr.any() else X_tr

    out: Dict[int, Dict[str, float]] = {i: {} for i in te_ids}
    info: Dict[str, Any] = {"features": len(feature_names()), "train_rows": int(len(X_fit))}

    if "ch_iforest" in keys or "ch_unsup" in keys:
        if_score, if_info = _iforest_onnx(X_fit, seed)
        info["iforest"] = if_info
        s_if = if_score(X_te)
    if "ch_ecod" in keys or "ch_unsup" in keys:
        ecod = ECOD().fit(X_fit)
        s_ec = ecod.score(X_te)
    if "ch_unsup" in keys:
        s_un = 0.5 * (_rank_normalise(if_score(X_fit), s_if) + _rank_normalise(ecod.score(X_fit), s_ec))
    for k, arr in (("ch_iforest", locals().get("s_if")), ("ch_ecod", locals().get("s_ec")),
                   ("ch_unsup", locals().get("s_un"))):
        if k in keys and arr is not None:
            for i, v in zip(te_ids, arr):
                out[i][k] = float(v)

    if "ch_lgbm" in keys:
        roles = [labels.get(i, {}) for i in te_ids]
        pos_idx = np.array([r.get("role") == "positive" for r in roles])
        instances = sorted({r.get("instance") for r in roles if r.get("role") == "positive"})
        inst_arr = np.array([r.get("instance") for r in roles], dtype=object)
        X_neg = X_tr[benign_tr]

        def fit(exclude: Optional[str]):
            keep = pos_idx & (inst_arr != exclude) if exclude else pos_idx
            X = np.vstack([X_neg, X_te[keep]])
            y = np.r_[np.zeros(len(X_neg)), np.ones(int(keep.sum()))]
            return _lgbm(seed).fit(X, y)

        lg = np.full(len(te_ids), np.nan)
        if instances and len(X_neg):
            full = fit(None)
            not_pos = ~pos_idx
            lg[not_pos] = full.predict_proba(X_te[not_pos])[:, 1]
            for inst in instances:
                sel = pos_idx & (inst_arr == inst)
                lg[sel] = fit(inst).predict_proba(X_te[sel])[:, 1]
            info["lgbm_instances"] = len(instances)
        for i, v in zip(te_ids, lg):
            if not np.isnan(v):
                out[i]["ch_lgbm"] = float(v)
    return {"scores": out, "info": info}
