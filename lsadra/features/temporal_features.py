"""
LSADRA V2 — Temporal feature extraction.

Derives time-of-day, day-of-week, cyclic encodings, and off-hours / weekend
indicators from event timestamps.
"""

import numpy as np
import pandas as pd

from lsadra.features.timestamps import parse_event_timestamps


def extract_temporal_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Append temporal feature columns to *df*.

    Expects a ``timestamp`` column (or convertible to datetime).
    """
    if df.empty or "timestamp" not in df.columns:
        return df

    df = df.copy()
    df["timestamp"] = parse_event_timestamps(df["timestamp"])

    df["hour"] = df["timestamp"].dt.hour
    df["minute"] = df["timestamp"].dt.minute
    df["day_of_week"] = df["timestamp"].dt.dayofweek

    # Cyclic encoding (handles 23:59 → 00:00 smoothly)
    df["hour_sin"] = np.sin(2 * np.pi * df["hour"] / 24.0)
    df["hour_cos"] = np.cos(2 * np.pi * df["hour"] / 24.0)

    # Binary flags
    df["is_off_hours"] = df["hour"].apply(lambda h: 1 if (h < 6 or h >= 22) else 0)
    df["is_weekend"] = df["day_of_week"].apply(lambda d: 1 if d >= 5 else 0)

    # Time delta from previous event on the same IP
    df = df.sort_values("timestamp")
    if "source_ip" in df.columns:
        df["time_since_last_event_ip"] = (
            df.groupby("source_ip")["timestamp"].diff().dt.total_seconds().fillna(0)
        )

    return df
