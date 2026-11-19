"""
Input matrix for the Phase 1 models (ADR 0007).

Today's ensemble sees the nine V3 features only. The Phase 1 scorers also see
the numeric rule features (authentication bursts, network fan-out, endpoint
signals, cross-source corroboration) and a one-hot of the canonical event
type, 56 columns in all, in a fixed order so a saved model and the live
pipeline always agree.
"""

from __future__ import annotations

from typing import List

import numpy as np
import pandas as pd

from lsadra.detection.event_types import EVENT_TYPES
from lsadra.features.feature_extractor import FEATURE_COLS
from lsadra.features.rule_features import RULE_FEATURE_COLS, build_rule_features

NUMERIC_RULE_COLS: List[str] = [
    "failed_logins_last_5min", "login_attempts_last_5min", "login_attempt_velocity",
    "unique_dst_ports_10min", "bytes_out_to_dest_30min", "dest_is_global",
    "cross_source_activity", "known_lolbin", "suspicious_cmdline", "encoded_command",
    "unusual_parent", "artifact_in_user_writable_dir", "artifact_in_hidden_dir",
    "windows_artifact", "registry_autostart_key", "registry_service_key",
]

EVENT_TYPE_COLS: List[str] = [f"et_{name}" for name in sorted(EVENT_TYPES)]

MODEL_FEATURE_NAMES: List[str] = list(FEATURE_COLS) + NUMERIC_RULE_COLS + EVENT_TYPE_COLS


def model_feature_matrix(df: pd.DataFrame) -> np.ndarray:
    """Float matrix in ``MODEL_FEATURE_NAMES`` order.

    *df* is ``build_features`` output; rule features are computed here unless
    they are already present (as inside ``_run_layers``).
    """
    if df.empty:
        return np.zeros((0, len(MODEL_FEATURE_NAMES)))
    if not all(c in df.columns for c in RULE_FEATURE_COLS):
        df = build_rule_features(df)
    cols = []
    for c in list(FEATURE_COLS) + NUMERIC_RULE_COLS:
        if c in df.columns:
            cols.append(pd.to_numeric(df[c], errors="coerce").fillna(0.0).astype(float).to_numpy())
        else:
            cols.append(np.zeros(len(df)))
    et = df["canonical_event_type"].astype(str).to_numpy()
    for name in EVENT_TYPE_COLS:
        cols.append((et == name[3:]).astype(float))
    return np.column_stack(cols)
