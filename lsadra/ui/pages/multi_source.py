"""
LSADRA V4 — Multi-Source Activity Overview Page.

Provides a unified view across all ingestion sources including ingestion
health, cross-source IP tracking, network flow summaries, and endpoint
enrichment signals.

[Capability: multi-source visibility]
[V4 ENHANCEMENT — gap: multi-source ingestion]
"""

import pandas as pd
import streamlit as st
from datetime import datetime, timedelta

from lsadra.storage.database import (
    get_connection,
    get_ingestion_stats,
)


# ---------------------------------------------------------------------------
# Source type colour mapping
# ---------------------------------------------------------------------------
_SOURCE_COLORS = {
    "ssh_log":       "#4A9EFF",
    "syslog":        "#10B981",
    "windows_event": "#F59E0B",
    "network_flow":  "#8B5CF6",
    "endpoint":      "#EF4444",
    "unknown":       "#6B7280",
}


def render():
    """Render the V4 Multi-Source Activity Overview page."""
    st.title("🌐 Multi-Source Activity")
    st.caption(
        "Ingestion health, cross-source IP tracking, network flow "
        "intelligence, and endpoint enrichment signals."
    )

    tab1, tab2, tab3, tab4 = st.tabs([
        "📡 Ingestion Health",
        "🔗 Cross-Source IPs",
        "🌊 Network Flows",
        "💻 Endpoint Summary",
    ])

    with tab1:
        _render_ingestion_health()

    with tab2:
        _render_cross_source_ips()

    with tab3:
        _render_network_summary()

    with tab4:
        _render_endpoint_summary()


# ============================================================================
# Tab 1: Ingestion Health Panel
# ============================================================================

def _render_ingestion_health():
    """
    Section 1: Ingestion health panel.

    Shows last event time per source_type, events-per-hour bar chart,
    and highlights sources with zero recent events in red.

    [V4 ENHANCEMENT — gap: ingestion health monitoring]
    """
    st.subheader("📡 Ingestion Health")

    stats = get_ingestion_stats()

    if not stats:
        st.warning("No ingestion statistics available yet. Start ingesting events.")
        return

    # KPI grid
    cols = st.columns(len(stats) if len(stats) <= 5 else 5)
    cutoff_30m = datetime.utcnow() - timedelta(minutes=30)

    for i, row in enumerate(stats[:5]):
        src  = row.get("source_type", "?")
        evts = row.get("events_count", 0)
        errs = row.get("parse_errors", 0)
        last = row.get("last_event") or ""
        color = _SOURCE_COLORS.get(src, "#6B7280")

        # Check silence
        silent = True
        if last:
            try:
                last_dt = datetime.fromisoformat(str(last)[:19])
                silent = last_dt < cutoff_30m
            except ValueError:
                pass

        status_icon = "🔴" if silent else "🟢"
        with cols[i % 5]:
            st.markdown(
                f"<div style='background:{color}22;border-left:4px solid {color};"
                f"padding:10px;border-radius:6px;margin-bottom:8px'>"
                f"<strong>{status_icon} {src}</strong><br>"
                f"Events: {evts:,} | Errors: {errs}<br>"
                f"<small>Last: {str(last)[:16] or 'Never'}</small></div>",
                unsafe_allow_html=True,
            )

    # Events per hour bar chart (derived from normalized_events)
    st.divider()
    st.markdown("#### Events per Hour by Source Type (last 12h)")
    _render_events_per_hour_chart()

    # Alert silenced sources
    silenced = [r.get("source_type") for r in stats if _is_source_silent(r)]
    if silenced:
        st.error(
            f"⚠️ Sources with no events in the last 30 minutes: "
            f"**{', '.join(silenced)}** — agent/collector may be down."
        )


def _is_source_silent(row: dict) -> bool:
    """Return True if the source has had no events in the last 30 min."""
    last = row.get("last_event")
    if not last:
        return True
    try:
        return datetime.fromisoformat(str(last)[:19]) < datetime.utcnow() - timedelta(minutes=30)
    except ValueError:
        return True


def _render_events_per_hour_chart():
    """Draw an events-per-hour bar chart from normalized_events."""
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT
                   strftime('%Y-%m-%d %H:00', timestamp) AS hour,
                   event_type,
                   COUNT(*) AS cnt
               FROM normalized_events
               WHERE timestamp >= datetime('now', '-12 hours')
               GROUP BY hour, event_type
               ORDER BY hour ASC"""
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        st.info("No recent event data for chart.")
        return

    df = pd.DataFrame([dict(r) for r in rows])
    df["source_type"] = df["event_type"].apply(_infer_source_type)
    pivot = df.groupby(["hour", "source_type"])["cnt"].sum().unstack(fill_value=0)
    st.bar_chart(pivot, use_container_width=True)


# ============================================================================
# Tab 2: Cross-Source IP Tracker
# ============================================================================

def _render_cross_source_ips():
    """
    Section 2: Cross-source IP tracker.

    Shows IPs with events in SSH, Network, and Endpoint logs.
    Highlights IPs active in 3+ sources.

    [Capability: multi-source visibility]
    """
    st.subheader("🔗 Cross-Source IP Tracker")

    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT
                   source_ip,
                   SUM(CASE WHEN event_type LIKE 'ssh%' OR event_type LIKE 'session%' THEN 1 ELSE 0 END) AS ssh_events,
                   SUM(CASE WHEN event_type IN ('connection','firewall_deny') THEN 1 ELSE 0 END) AS net_events,
                   SUM(CASE WHEN event_type IN ('process_create','file_write','dll_load') THEN 1 ELSE 0 END) AS ep_events,
                   MIN(timestamp) AS first_seen,
                   MAX(timestamp) AS last_seen
               FROM normalized_events
               WHERE timestamp >= datetime('now', '-60 minutes')
                 AND source_ip IS NOT NULL
               GROUP BY source_ip
               ORDER BY (ssh_events + net_events + ep_events) DESC
               LIMIT 50"""
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        st.info("No cross-source IP data in the last 60 minutes.")
        return

    df = pd.DataFrame([dict(r) for r in rows])
    df["active_sources"] = (
        (df["ssh_events"] > 0).astype(int)
        + (df["net_events"] > 0).astype(int)
        + (df["ep_events"] > 0).astype(int)
    )

    # Highlight IPs in 3+ sources
    high_risk = df[df["active_sources"] >= 3]
    if not high_risk.empty:
        st.warning(f"⚠️ {len(high_risk)} IP(s) active across 3+ source types:")
        st.dataframe(high_risk, use_container_width=True, hide_index=True)
        st.divider()

    st.markdown("#### All Cross-Source IPs")
    st.dataframe(df, use_container_width=True, hide_index=True)


# ============================================================================
# Tab 3: Network Flow Summary
# ============================================================================

def _render_network_summary():
    """Section 3: Network flow summary — top talkers and scanned ports."""
    st.subheader("🌊 Network Flow Summary")

    conn = get_connection()
    try:
        top_talkers = conn.execute(
            """SELECT source_ip,
                      COUNT(*) AS connections,
                      MIN(timestamp) AS first_seen,
                      MAX(timestamp) AS last_seen
               FROM normalized_events
               WHERE event_type IN ('connection','firewall_deny')
                 AND timestamp >= datetime('now', '-60 minutes')
                 AND source_ip IS NOT NULL
               GROUP BY source_ip
               ORDER BY connections DESC LIMIT 20"""
        ).fetchall()
    finally:
        conn.close()

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### 🔝 Top Talking IPs (connections)")
        if top_talkers:
            st.dataframe(
                pd.DataFrame([dict(r) for r in top_talkers]),
                use_container_width=True, hide_index=True,
            )
        else:
            st.info("No network flow events recently.")

    with col2:
        st.markdown("#### 🔍 Top Scanned Destination Ports")
        _render_top_ports()


def _render_top_ports():
    """Show the most-scanned destination ports from raw event data."""
    conn = get_connection()
    try:
        # Port data is stored in attributes JSON; use a simple count proxy
        rows = conn.execute(
            """SELECT raw_message, COUNT(*) AS cnt
               FROM normalized_events
               WHERE event_type = 'firewall_deny'
                 AND timestamp >= datetime('now', '-60 minutes')
               GROUP BY raw_message
               ORDER BY cnt DESC LIMIT 15"""
        ).fetchall()
    finally:
        conn.close()

    if rows:
        import re
        port_counts = {}
        for row in rows:
            m = re.search(r"DPT=(\d+)", str(row[0]))
            if m:
                port_counts[m.group(1)] = port_counts.get(m.group(1), 0) + dict(row)["cnt"]
        if port_counts:
            df = pd.DataFrame(
                sorted(port_counts.items(), key=lambda x: -x[1])[:15],
                columns=["dst_port", "scan_count"],
            )
            st.bar_chart(df.set_index("dst_port"), use_container_width=True)
            return
    st.info("No port scan data available.")


# ============================================================================
# Tab 4: Endpoint Summary
# ============================================================================

def _render_endpoint_summary():
    """Section 4: Endpoint suspicious process and LOLBin summary."""
    st.subheader("💻 Endpoint Summary")

    conn = get_connection()
    try:
        ep_rows = conn.execute(
            """SELECT raw_message, device_id, event_type, timestamp
               FROM normalized_events
               WHERE event_type IN ('process_create','dll_load','registry_write')
                 AND timestamp >= datetime('now', '-60 minutes')
               ORDER BY timestamp DESC LIMIT 100"""
        ).fetchall()
    finally:
        conn.close()

    if not ep_rows:
        st.info("No endpoint telemetry events in the last 60 minutes.")
        return

    df = pd.DataFrame([dict(r) for r in ep_rows])

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### 🚨 Recent Endpoint Events")
        st.dataframe(
            df[["timestamp", "device_id", "event_type"]].head(30),
            use_container_width=True, hide_index=True,
        )

    with col2:
        st.markdown("#### 📊 Event Type Distribution")
        type_counts = df.groupby("event_type").size().reset_index(name="count")
        st.bar_chart(type_counts.set_index("event_type"), use_container_width=True)

    st.markdown(f"**Total endpoint events in window:** {len(df)}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _infer_source_type(event_type: str) -> str:
    """Infer source_type from event_type string."""
    et = str(event_type).lower()
    if "ssh" in et or "session" in et:
        return "ssh_log"
    if "connection" in et or "firewall" in et:
        return "network_flow"
    if "process" in et or "file" in et or "dll" in et or "registry" in et:
        return "endpoint"
    if "windows" in et or "logon" in et:
        return "windows_event"
    if "cron" in et or "service" in et or "kernel" in et or "sudo" in et:
        return "syslog"
    return "unknown"
