"""
LSADRA V4 — Enhanced feature extraction orchestrator.

Extends the V3 feature pipeline with temporal, relationship, network-flow,
and endpoint-specific features computed via pandas rolling windows and groupby.

[V4 ENHANCEMENT — gap: temporal + relationship features]
[GLASSWING ALIGNMENT — multi-source unified schema]
[MYTHOS ALIGNMENT — cross-source behavioral sequences]

All existing V3 features and the build_features() function are preserved.
"""

import logging
import sqlite3
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import pandas as pd

from lsadra.features.temporal_features import extract_temporal_features
from lsadra.features.behavioral_features import extract_behavioral_features

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# V3 feature columns (unchanged)
# ---------------------------------------------------------------------------
FEATURE_COLS: List[str] = [
    "hour_sin",
    "hour_cos",
    "is_off_hours",
    "is_weekend",
    "time_since_last_event_ip",
    "unique_users_15m",
    "failures_15m",
    "successes_15m",
    "failure_ratio_15m",
]

META_COLS: List[str] = [
    "id",
    "timestamp",
    "device_id",
    "user_id",
    "host",
    "effective_username",
    "source_ip",
    "event_type",
    "raw_message",
    "attributes",
    "is_synthetic",
]

# ---------------------------------------------------------------------------
# V4 additional feature columns
# ---------------------------------------------------------------------------
V4_FEATURE_COLS: List[str] = [
    # Temporal
    "failed_logins_last_5min",
    "failed_logins_last_15min",
    "login_attempt_velocity",
    "time_since_last_event",
    # Relationship
    "unique_usernames_per_ip",
    "unique_ips_per_username",
    "failure_ratio",
    "cross_source_activity",
    # Network
    "unique_dst_ports_per_ip",
    "total_bytes_out",
    "connection_frequency",
    # Endpoint
    "suspicious_process_count",
    "lolbin_usage_count",
    "unique_processes_spawned",
]


# ============================================================================
# V3 entry point (preserved exactly)
# ============================================================================

def build_features(raw_events: List[Dict[str, Any]]) -> pd.DataFrame:
    """
    Convert a list of normalized event dicts into a feature DataFrame.

    Preserves V3 interface exactly for backward compatibility.

    Args:
        raw_events: List of dicts with at least *timestamp*, *source_ip*,
                    *effective_username*, *event_type*.

    Returns:
        DataFrame with metadata columns + V3 feature columns, NaN-filled to 0.
    """
    if not raw_events:
        return pd.DataFrame()

    df = pd.DataFrame(raw_events)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    df = extract_temporal_features(df)
    df = extract_behavioral_features(df)
    df.fillna(0, inplace=True)

    for col in FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0.0

    available_meta = [c for c in META_COLS if c in df.columns]
    return df[available_meta + FEATURE_COLS]


# ============================================================================
# V4 enhanced entry point
# ============================================================================

def build_enhanced_feature_table(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute all V4 temporal, relationship, and source-specific features
    on top of existing V3 base features.

    Accepts a unified event DataFrame (from IngestionManager) and returns
    an enriched DataFrame with all V4 feature columns appended.

    Gracefully degrades: if any feature group raises, it is skipped
    and the function continues with the remaining groups.

    [V4 ENHANCEMENT — gap: temporal + relationship features]

    Args:
        df: DataFrame of unified V4 events with at minimum:
            timestamp, source_ip, username, event_type, source_type,
            success, device_id.

    Returns:
        Enriched DataFrame with V4 feature columns appended.
    """
    if df.empty:
        return df

    df = df.copy()
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    for extractor, name in [
        (_add_temporal_features,      "temporal"),
        (_add_relationship_features,  "relationship"),
        (_add_network_features,       "network"),
        (_add_endpoint_features,      "endpoint"),
    ]:
        try:
            df = extractor(df)
        except Exception:
            logger.exception(
                "[V4 ENHANCEMENT] Feature group '%s' failed — skipping.", name
            )

    for col in V4_FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0.0

    df.fillna(0, inplace=True)
    return df


# ---------------------------------------------------------------------------
# Temporal features
# ---------------------------------------------------------------------------

def _add_temporal_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add rolling-window temporal features per source_ip.

    [V4 ENHANCEMENT — gap: temporal intelligence]
    """
    df = df.sort_values("timestamp").copy()

    # Flag failed authentication events
    df["_is_failure"] = ~df["success"].astype(bool)
    df["_attempt"]    = 1

    # Rolling counts — compute per group then concat back
    # [DESIGN CHOICE] pandas 2.x groupby().apply() returns a DataFrame when
    # the applied function returns a Series, so we use a concat approach instead.
    failed_5m_parts  = []
    failed_15m_parts = []
    velocity_parts   = []

    for ip, group in df.groupby("source_ip", group_keys=False):
        failed_5m_parts.append(_rolling_count(group, "_is_failure", "5min"))
        failed_15m_parts.append(_rolling_count(group, "_is_failure", "15min"))
        velocity_parts.append(_rolling_count(group, "_attempt", "5min"))

    if failed_5m_parts:
        df["failed_logins_last_5min"]  = pd.concat(failed_5m_parts).reindex(df.index).fillna(0)
        df["failed_logins_last_15min"] = pd.concat(failed_15m_parts).reindex(df.index).fillna(0)
        df["_attempts_5m"]             = pd.concat(velocity_parts).reindex(df.index).fillna(0)
    else:
        df["failed_logins_last_5min"]  = 0
        df["failed_logins_last_15min"] = 0
        df["_attempts_5m"]             = 0

    # Login attempt velocity (attempts per minute over 5-min window)
    df["login_attempt_velocity"] = df["_attempts_5m"] / 5.0

    # Time since last event per source_ip
    df["time_since_last_event"] = df.groupby("source_ip")["timestamp"].diff().dt.total_seconds()

    return df.drop(columns=["_is_failure", "_attempt", "_attempts_5m"], errors="ignore")


def _rolling_count(group: pd.DataFrame, col: str, window: str) -> pd.Series:
    """Compute a time-based rolling sum for a boolean or integer column.

    Returns a Series aligned to the original group index.
    """
    if group.empty or col not in group.columns:
        return pd.Series(0, index=group.index, dtype=float)
    g = group.set_index("timestamp")
    rolled = g[col].astype(float).rolling(window, min_periods=0).sum()
    # Reset to original index
    rolled.index = group.index
    return rolled


# ---------------------------------------------------------------------------
# Relationship features
# ---------------------------------------------------------------------------

def _add_relationship_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add cross-entity relationship features per source_ip and username.

    [V4 ENHANCEMENT — gap: relationship modeling]
    [MYTHOS ALIGNMENT — cross-source behavioral sequences]
    """
    # Unique usernames per IP
    uniq_users = (
        df.groupby("source_ip")["username"]
        .transform(lambda s: s.nunique())
    )
    df["unique_usernames_per_ip"] = uniq_users

    # Unique IPs per username
    uniq_ips = (
        df.groupby("username", dropna=False)["source_ip"]
        .transform(lambda s: s.nunique())
    )
    df["unique_ips_per_username"] = uniq_ips

    # Failure ratio per source_ip
    ip_total   = df.groupby("source_ip")["success"].transform("count")
    ip_failure = df.groupby("source_ip")["success"].transform(
        lambda s: (~s.astype(bool)).sum()
    )
    # [DESIGN CHOICE] pandas 2.0 removed `mode.use_inf_as_na` — replace inf directly
    ratio = (ip_failure / ip_total.clip(lower=1))
    df["failure_ratio"] = ratio.replace([float("inf"), float("-inf")], float("nan")).fillna(0.0)

    # Cross-source activity: same source_ip in 2+ source_types
    cross = (
        df.groupby("source_ip")["source_type"]
        .transform(lambda s: s.nunique() >= 2)
    )
    df["cross_source_activity"] = cross.astype(int)

    return df


# ---------------------------------------------------------------------------
# Network flow features
# ---------------------------------------------------------------------------

def _add_network_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add network-flow specific features from 'network_flow' source events.

    [V4 ENHANCEMENT — gap: network behavioral analysis]
    """
    net_mask = df.get("source_type", pd.Series("", index=df.index)) == "network_flow"

    df["unique_dst_ports_per_ip"] = 0.0
    df["total_bytes_out"] = 0.0
    df["connection_frequency"] = 0.0

    if not net_mask.any():
        return df

    net_df = df[net_mask].copy()

    # Unique destination ports per source_ip (10-min window approximation)
    port_series = pd.Series(index=net_df.index, dtype=float)
    for ip, grp in net_df.groupby("source_ip"):
        port_vals = grp["extra"].apply(
            lambda e: e.get("dst_port", 0) if isinstance(e, dict) else 0
        )
        port_series.loc[grp.index] = float(port_vals.nunique())
    df.loc[net_mask, "unique_dst_ports_per_ip"] = port_series

    # Total bytes out per source_ip (30-min window)
    bytes_series = pd.Series(index=net_df.index, dtype=float)
    for ip, grp in net_df.groupby("source_ip"):
        total = grp["extra"].apply(
            lambda e: e.get("bytes", 0) if isinstance(e, dict) else 0
        ).sum()
        bytes_series.loc[grp.index] = float(total)
    df.loc[net_mask, "total_bytes_out"] = bytes_series

    # Connection frequency (connections per minute)
    conn_series = pd.Series(index=net_df.index, dtype=float)
    for ip, grp in net_df.groupby("source_ip"):
        if len(grp) < 2:
            conn_series.loc[grp.index] = float(len(grp))
            continue
        time_span_min = max(
            (grp["timestamp"].max() - grp["timestamp"].min()).total_seconds() / 60,
            1,
        )
        rate = float(len(grp)) / time_span_min
        conn_series.loc[grp.index] = rate
    df.loc[net_mask, "connection_frequency"] = conn_series

    return df


# ---------------------------------------------------------------------------
# Endpoint features
# ---------------------------------------------------------------------------

def _add_endpoint_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add endpoint-specific features from 'endpoint' source events.

    [V4 ENHANCEMENT — gap: endpoint behavioral analysis]
    """
    ep_mask = df.get("source_type", pd.Series("", index=df.index)) == "endpoint"

    df["suspicious_process_count"] = 0.0
    df["lolbin_usage_count"]       = 0.0
    df["unique_processes_spawned"] = 0.0

    if not ep_mask.any():
        return df

    ep_df = df[ep_mask].copy()

    def _flag(extra_dict: Any, key: str) -> bool:
        return bool(extra_dict.get(key, False)) if isinstance(extra_dict, dict) else False

    # Suspicious process count per device_id
    susp_series = pd.Series(index=ep_df.index, dtype=float)
    for dev, grp in ep_df.groupby("device_id"):
        count = grp["extra"].apply(lambda e: _flag(e, "suspicious_cmdline")).sum()
        susp_series.loc[grp.index] = float(count)
    df.loc[ep_mask, "suspicious_process_count"] = susp_series

    # LOLBin usage count per device_id
    lol_series = pd.Series(index=ep_df.index, dtype=float)
    for dev, grp in ep_df.groupby("device_id"):
        count = grp["extra"].apply(lambda e: _flag(e, "known_lolbin")).sum()
        lol_series.loc[grp.index] = float(count)
    df.loc[ep_mask, "lolbin_usage_count"] = lol_series

    # Unique processes spawned per device_id (15-min window approximated by full window)
    proc_series = pd.Series(index=ep_df.index, dtype=float)
    for dev, grp in ep_df.groupby("device_id"):
        procs = grp["extra"].apply(
            lambda e: e.get("process_name", "") if isinstance(e, dict) else ""
        )
        proc_series.loc[grp.index] = float(procs.nunique())
    df.loc[ep_mask, "unique_processes_spawned"] = proc_series

    return df


# ============================================================================
# Entity timeline builder
# ============================================================================

def build_entity_timeline(
    db_conn: sqlite3.Connection,
    identifier: str,
    id_type: str = "ip",
    window_minutes: int = 30,
    source_types: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieve ordered event history for a single entity from SQLite.

    Supports cross-source timelines (same IP across SSH, network, endpoint).

    [V4 ENHANCEMENT — gap: temporal intelligence]
    [MYTHOS ALIGNMENT — cross-source behavioral sequences]

    Args:
        db_conn:        Active SQLite3 connection.
        identifier:     The entity value to query (IP, username, or device_id).
        id_type:        Column to filter on: "ip" | "username" | "device_id".
        window_minutes: How far back to look (default: 30 min).
        source_types:   Optional list of source_types to restrict results.

    Returns:
        List of event dicts ordered ascending by timestamp.
    """
    col_map = {"ip": "source_ip", "username": "effective_username", "device_id": "device_id"}
    col = col_map.get(id_type, "source_ip")

    cutoff = (datetime.utcnow() - timedelta(minutes=window_minutes)).isoformat()

    try:
        query = f"""
            SELECT id, timestamp, device_id, effective_username,
                   source_ip, event_type, raw_message, attributes
            FROM normalized_events
            WHERE {col} = ?
              AND timestamp >= ?
        """
        params: List[Any] = [identifier, cutoff]

        if source_types:
            placeholders = ",".join("?" * len(source_types))
            query += f" AND event_type IN ({placeholders})"
            params.extend(source_types)

        query += " ORDER BY timestamp ASC LIMIT 500"
        rows = db_conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        logger.exception("build_entity_timeline failed for %s=%s", id_type, identifier)
        return []
