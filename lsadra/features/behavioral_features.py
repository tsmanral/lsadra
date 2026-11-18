"""
LSADRA V2 — Behavioral feature extraction.

Derives per-IP and per-user behavioral metrics using rolling time windows:
login velocity, failure ratios, username diversity, etc.
"""

import numpy as np
import pandas as pd

from lsadra.features.timestamps import parse_event_timestamps


def extract_behavioral_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Append behavioral feature columns to *df*.

    Expects at least ``timestamp``, ``source_ip``, ``effective_username``,
    and ``event_type`` columns.
    """
    required = {"timestamp", "source_ip", "effective_username", "event_type"}
    if df.empty or not required.issubset(df.columns):
        return df

    df = df.copy()
    df["timestamp"] = parse_event_timestamps(df["timestamp"])
    
    # Ensure source_ip and effective_username are strings and handle NaNs
    df["source_ip"] = df["source_ip"].fillna("127.0.0.1").astype(str)
    df["effective_username"] = df["effective_username"].fillna("unknown").astype(str)
    
    df = df.sort_values("timestamp")

    # Binary success / failure indicators
    df["is_failure"] = df["event_type"].str.contains("failed|failure", case=False, na=False).astype(int)
    df["is_success"] = df["event_type"].str.contains("accepted|success", case=False, na=False).astype(int)

    # Map usernames to numeric IDs for rolling operations
    df["username_id"] = pd.factorize(df["effective_username"])[0]

    # Set timestamp as index for rolling
    df_idx = df.set_index("timestamp").copy()

    # ── unique users per IP in 15-min window ──────────────────────────────
    def _count_unique(arr: np.ndarray) -> float:
        return float(len(np.unique(arr[~np.isnan(arr)])))

    user_div = (
        df_idx.groupby("source_ip")["username_id"]
        .rolling("15min")
        .apply(_count_unique, raw=True)
        .reset_index(name="unique_users_15m")
    )

    # ── failures / successes in 15-min window ─────────────────────────────
    activity = (
        df_idx.groupby("source_ip")
        .rolling("15min")
        .agg({"is_failure": "sum", "is_success": "sum"})
        .reset_index()
        .rename(columns={"is_failure": "failures_15m", "is_success": "successes_15m"})
    )

    # Merge back via merge_asof (sorted on timestamp)
    df = pd.merge_asof(
        df.sort_values("timestamp"),
        user_div.sort_values("timestamp"),
        on="timestamp",
        by="source_ip",
    )
    df = pd.merge_asof(
        df.sort_values("timestamp"),
        activity.sort_values("timestamp"),
        on="timestamp",
        by="source_ip",
    )

    # Derived ratio
    df["failure_ratio_15m"] = df["failures_15m"] / (
        df["failures_15m"] + df["successes_15m"] + 1e-9
    )

    return df
