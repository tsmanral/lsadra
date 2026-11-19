"""
LSADRA V4 — Analyst Investigation Page.

Provides a structured investigation interface where analysts can generate
full case files for incidents, explore entity timelines, and assess
cross-source activity — all powered by pure template logic from
narrative_builder.py. No LLM required.

[Capability: structured investigation interface]
[Capability: analyst case file generation]
"""

import streamlit as st
import pandas as pd

from lsadra import intel
from lsadra.storage.database import (
    get_connection,
    get_all_incidents,
)
from lsadra.features.feature_extractor import build_entity_timeline
from lsadra.explainability.narrative_builder import (
    generate_investigative_summary,
    get_confidence_level,
    format_timeline_text,
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
    """Render the V4 Analyst Investigation page."""
    st.title("🔍 Analyst Investigation")
    st.caption(
        "Generate structured case files, explore entity timelines, and "
        "assess multi-source threat context — powered by pure-template reasoning."
    )

    tab1, tab2, tab3 = st.tabs([
        "📋 Case File Generator",
        "⏱️ Entity Timeline",
        "🌐 Cross-Source Activity",
    ])

    with tab1:
        _render_case_file()

    with tab2:
        _render_entity_timeline()

    with tab3:
        _render_cross_source_panel()


# ============================================================================
# Tab 1: Case File Generator
# ============================================================================

def _render_case_file():
    """Section 1 & 2: Incident selector and investigation report."""
    st.subheader("📋 Generate Investigation Report")

    incidents = get_all_incidents(limit=100)
    if not incidents:
        st.info("No incidents found. Ingest some events first.")
        return

    options = {
        f"#{i['id']} — {i.get('attack_type','?')} | {i.get('source_ip','?')} | {i.get('severity_label','?')}": i
        for i in incidents
    }
    selected_label = st.selectbox("Select Incident", list(options.keys()), key="inv_incident")
    incident = options[selected_label]

    col1, col2 = st.columns([1, 3])
    with col1:
        generate_btn = st.button("🚀 Generate Report", use_container_width=True, key="inv_gen_btn")
    with col2:
        ip = incident.get("source_ip", "")
        st.caption(f"IP: `{ip}` | Status: `{incident.get('status','?')}`")

    if not generate_btn:
        return

    with st.spinner("Building investigation report..."):
        conn = get_connection()
        try:
            ip = incident.get("source_ip", "")
            timeline = build_entity_timeline(
                conn, ip, id_type="ip", window_minutes=60
            )
            similar = _get_similar_incidents(ip, incident["id"])
            ti = intel.legacy_view(intel.lookup_ip(ip)) if ip else None

            report = generate_investigative_summary(
                ip=ip,
                incident_data=incident,
                entity_timeline=timeline,
                similar_past_incidents=similar,
                threat_intel=ti,
            )
        finally:
            conn.close()

    # ── Confidence badge ───────────────────────────────────────────────
    confidence_level, confidence_text = get_confidence_level(
        features={},
        rule_alert=incident,
        threat_intel=ti if ti else None,
        timeline=timeline,
    )
    _render_confidence_badge(confidence_level, confidence_text)

    st.divider()
    st.markdown(report)

    # ── Recommended actions expansion ─────────────────────────────────
    with st.expander("✅ View Recommended Actions"):
        from lsadra.explainability.narrative_builder import _get_recommendations
        attack = incident.get("attack_type", "")
        recs = _get_recommendations(attack)
        for i, rec in enumerate(recs, 1):
            st.write(f"{i}. {rec}")


def _get_similar_incidents(ip: str, exclude_id: int) -> list:
    """Query past incidents with the same source IP."""
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT * FROM incidents
               WHERE source_ip = ? AND id != ?
               ORDER BY last_seen DESC LIMIT 5""",
            (ip, exclude_id),
        ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []
    finally:
        conn.close()


# ============================================================================
# Tab 2: Entity Timeline Viewer
# ============================================================================

def _render_entity_timeline():
    """Section 3: Entity timeline viewer."""
    st.subheader("⏱️ Entity Timeline Viewer")
    st.caption("View the chronological event history for an IP, username, or device.")

    col1, col2, col3 = st.columns(3)
    with col1:
        id_type = st.selectbox(
            "Entity Type", ["ip", "username", "device_id"],
            key="inv_id_type"
        )
    with col2:
        identifier = st.text_input("Entity Value", placeholder="e.g. 192.168.1.100", key="inv_id_val")
    with col3:
        window = st.slider("Window (minutes)", 5, 120, 30, key="inv_window")

    if not identifier:
        st.info("Enter an entity value to load its timeline.")
        return

    conn = get_connection()
    try:
        events = build_entity_timeline(
            conn, identifier.strip(), id_type=id_type, window_minutes=window
        )
    finally:
        conn.close()

    if not events:
        st.warning(f"No events found for {id_type}=`{identifier}` in the last {window} minutes.")
        return

    st.success(f"Found **{len(events)}** events in the last {window} minutes.")

    df = pd.DataFrame(events)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")

    # Colour-code source_type column
    if "source_type" in df.columns:
        source_col = df.pop("source_type")
        df.insert(1, "source_type", source_col)

    display_cols = [c for c in [
        "timestamp", "source_type", "event_type",
        "effective_username", "source_ip", "device_id",
    ] if c in df.columns]

    st.dataframe(
        df[display_cols] if display_cols else df,
        use_container_width=True,
        hide_index=True,
    )

    # Mini summary
    st.markdown(f"**Timeline summary:**\n\n{format_timeline_text(events)}")


# ============================================================================
# Tab 3: Cross-Source Activity Panel
# ============================================================================

def _render_cross_source_panel():
    """Section 4: Cross-source activity for the same IP."""
    st.subheader("🌐 Cross-Source Activity Panel")
    st.caption("Investigate the same source IP across all ingestion sources simultaneously.")

    ip_query = st.text_input("Source IP to investigate", key="inv_cross_ip")

    if not ip_query:
        _render_recent_multi_source_ips()
        return

    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT event_type, effective_username, device_id,
                      timestamp, raw_message
               FROM normalized_events
               WHERE source_ip = ?
               ORDER BY timestamp DESC LIMIT 200""",
            (ip_query.strip(),),
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        st.info(f"No events found for IP `{ip_query}`.")
        return

    df = pd.DataFrame([dict(r) for r in rows])

    # Infer source_type from event_type for display
    df["source_type"] = df["event_type"].apply(_infer_source_type)

    for src_type in df["source_type"].unique():
        src_df = df[df["source_type"] == src_type]
        color  = _SOURCE_COLORS.get(src_type, "#6B7280")
        st.markdown(
            f"<span style='background:{color};color:#fff;padding:2px 8px;"
            f"border-radius:4px;font-size:0.8em'>{src_type}</span> "
            f"**{len(src_df)} events**",
            unsafe_allow_html=True,
        )
        display_cols = [c for c in ["timestamp", "event_type", "effective_username", "device_id"]
                        if c in src_df.columns]
        st.dataframe(src_df[display_cols].head(25), use_container_width=True, hide_index=True)


def _render_recent_multi_source_ips():
    """Show IPs that appear in 2+ source types as a quick-start."""
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT source_ip, COUNT(DISTINCT event_type) AS type_count
               FROM normalized_events
               WHERE timestamp >= datetime('now', '-60 minutes')
                 AND source_ip IS NOT NULL
               GROUP BY source_ip
               HAVING type_count >= 2
               ORDER BY type_count DESC LIMIT 20""",
        ).fetchall()
    finally:
        conn.close()

    if rows:
        st.markdown("### Recently active multi-source IPs")
        df = pd.DataFrame([dict(r) for r in rows])
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No multi-source IPs detected in the last 60 minutes.")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _render_confidence_badge(level: str, text: str) -> None:
    """Render a colour-coded confidence badge."""
    colour = {"HIGH": "#10B981", "MEDIUM": "#F59E0B", "LOW": "#EF4444"}.get(level, "#6B7280")
    st.markdown(
        f"<div style='background:{colour};color:#fff;padding:8px 14px;"
        f"border-radius:6px;margin-bottom:12px'>"
        f"<strong>Confidence: {level}</strong> — {text}</div>",
        unsafe_allow_html=True,
    )


def _infer_source_type(event_type: str) -> str:
    """Infer source_type from event_type string."""
    et = str(event_type).lower()
    if "ssh" in et or "session" in et:
        return "ssh_log"
    if "connection" in et or "firewall" in et or "port" in et:
        return "network_flow"
    if "process" in et or "file" in et or "dll" in et or "registry" in et:
        return "endpoint"
    if "windows" in et or "logon" in et:
        return "windows_event"
    if "cron" in et or "service" in et or "kernel" in et or "sudo" in et:
        return "syslog"
    return "unknown"
