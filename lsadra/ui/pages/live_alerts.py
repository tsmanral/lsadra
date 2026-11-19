"""
LSADRA V3+V4 — Live Alerts page.

Real-time view of recent anomalies with severity badges, auto-refresh,
incident linkage, and clickable KPI drill-downs.

V4 additions (additive only — existing layout and logic preserved):
  - Alert narrative (from generate_alert_narrative()) per alert
  - Severity score + explanation (from calculate_dynamic_severity())
  - Source type badge per alert
  - "Mark as False Positive" button with FP analysis inline

[V4 ENHANCEMENT — gap: dynamic severity]
[Capability: human-readable incident narrative]
"""

import html

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from lsadra.storage.database import (
    get_connection,
    store_feedback,
)
from lsadra.ui.components.auto_refresh import auto_refresh_toggle
from lsadra.ui.components.chart_theme import apply_soc_theme, get_severity_color, SEVERITY_COLORS
from lsadra.ui.components.kpi_card import kpi_card
from lsadra.ui.components.severity_badge import severity_badge
from lsadra.ui.components.sidebar_filters import severity_filter
from lsadra.ui.data_layer import get_dashboard_kpis, get_dashboard_recent_anomalies


def render():
    """Render the Live Alerts page."""
    st.title("🚨 Live Alerts")

    # Sidebar
    auto_refresh_toggle(default_interval=15, key="alerts_refresh")
    selected_severity = severity_filter(key="alerts_severity")

    # KPIs with drill-down buttons
    kpis = get_dashboard_kpis()
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        kpi_card("Events (24h)", f"{kpis['total_events_24h']:,}", icon="📨", color="#4A9EFF")
        if st.button("Details", key="la_drill_events", use_container_width=True):
            st.session_state["la_drill"] = "events"
    with c2:
        kpi_card("Anomalies (24h)", f"{kpis['total_anomalies_24h']:,}", icon="⚡", color="#FF8C00")
        if st.button("Details", key="la_drill_anomalies", use_container_width=True):
            st.session_state["la_drill"] = "anomalies"
    with c3:
        kpi_card("Open Incidents", kpis["open_incidents"], icon="📋", color="#FFD700")
        if st.button("Details", key="la_drill_incidents", use_container_width=True):
            st.session_state["la_drill"] = "incidents"
    with c4:
        kpi_card("Critical", kpis["critical_incidents"], icon="🔴", color="#FF4444")

    # ── KPI Drill-Down Panel ──────────────────────────────────────────────
    drill = st.session_state.get("la_drill")
    if drill:
        st.divider()
        _render_drill(drill)
        if st.button("✖ Close", key="la_close_drill"):
            del st.session_state["la_drill"]
            st.rerun()

    st.divider()

    # ── Alert Timeline (mini chart) ───────────────────────────────────────
    anomalies = get_dashboard_recent_anomalies(limit=200)
    if selected_severity:
        anomalies = [a for a in anomalies if a.get("severity_label") in selected_severity]

    if anomalies:
        df = pd.DataFrame(anomalies)
        if "created_at" in df.columns:
            df["hour"] = pd.to_datetime(df["created_at"]).dt.strftime("%Y-%m-%d %H:00")
            hourly = df.groupby(["hour", "severity_label"]).size().reset_index(name="count")

            if not hourly.empty:
                fig = go.Figure()
                for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                    sev_data = hourly[hourly["severity_label"] == sev]
                    if not sev_data.empty:
                        fig.add_trace(go.Bar(
                            x=sev_data["hour"],
                            y=sev_data["count"],
                            name=sev,
                            marker_color=SEVERITY_COLORS.get(sev, "#888"),
                        ))
                fig.update_layout(barmode="stack")
                apply_soc_theme(fig, title="Alert Volume (by severity)")
                fig.update_layout(
                    xaxis_title="Time",
                    yaxis_title="Alerts",
                    legend=dict(orientation="h", yanchor="bottom", y=1.02),
                    height=280,
                )
                st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # ── Alert Feed ────────────────────────────────────────────────────────
    if not anomalies:
        st.success("No anomalies detected 🎉")
        return

    st.subheader(f"Recent Alerts ({len(anomalies)})")

    for a in anomalies:
        sev      = a.get("severity_label", "LOW")
        threat   = a.get("threat_type", "Unknown")
        ts       = a.get("created_at", "")
        score    = a.get("severity_score", 0)
        alert_id = a.get("id", 0)

        with st.expander(
            f"{_sev_icon(sev)} **{threat}** — {sev} ({score:.2f}) — {ts}",
            expanded=False,
        ):
            severity_badge(sev, score)

            # ── V4 ADDITION: source_type badge ────────────────────────
            _render_source_badge(a)

            # ── V3 narrative (preserved) ──────────────────────────────
            narrative = a.get("narrative", "")

            # ── V4 ADDITION: enhanced narrative ──────────────────────
            # [Capability: human-readable incident narrative]
            v4_narrative = _try_build_v4_narrative(a)
            if v4_narrative:
                st.markdown("**LSADRA V4 Narrative:**")
                st.info(v4_narrative)
            elif narrative and narrative != "No narrative available.":
                st.markdown(narrative)
            else:
                st.info("Narrative will be generated when ML models are trained.")

            # ── V4 ADDITION: dynamic severity explanation ─────────────
            # [V4 ENHANCEMENT — gap: dynamic severity]
            _render_severity_explanation(a)

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Baseline Z", f"{a.get('layer1_score', 0):.2f}")
            c2.metric("Ensemble", f"{a.get('layer2_score', 0):.2f}")
            c3.metric("AE Error", f"{a.get('layer3_score', 0):.4f}")
            c4.metric("Severity", f"{score:.2f}")

            st.caption(
                f"MITRE: {a.get('mitre_technique', 'N/A')} | "
                f"Device: `{str(a.get('device_id', ''))[:8]}...` | "
                f"IP: {a.get('source_ip', 'N/A')} | "
                f"Incident: #{a.get('incident_id', 'N/A')}"
            )

            # ── V4 ADDITION: False Positive button ────────────────────
            # [Capability: adaptive feedback reasoning]
            _render_fp_button(alert_id, a)


# ============================================================================
# V4 additions (helper functions)
# ============================================================================

def _render_source_badge(a: dict) -> None:
    """Render a coloured source_type badge if source info is available."""
    _SOURCE_COLORS = {
        "ssh_log":       "#4A9EFF",
        "syslog":        "#10B981",
        "windows_event": "#F59E0B",
        "network_flow":  "#8B5CF6",
        "endpoint":      "#EF4444",
    }
    # Try to infer source type from attributes JSON if available
    source_type = a.get("source_type", "")
    if not source_type:
        event_type = a.get("threat_type", a.get("attack_type", "")).lower()
        if "brute" in event_type or "ssh" in event_type:
            source_type = "ssh_log"
        elif "port" in event_type or "transfer" in event_type:
            source_type = "network_flow"
        elif "process" in event_type or "lolbin" in event_type:
            source_type = "endpoint"

    if source_type:
        color = _SOURCE_COLORS.get(source_type, "#6B7280")
        st.markdown(
            f"<span style='background:{color};color:#fff;padding:2px 8px;"
            f"border-radius:12px;font-size:0.75em'>{source_type}</span>",
            unsafe_allow_html=True,
        )


def _try_build_v4_narrative(a: dict) -> str:
    """
    Attempt to build a V4 narrative from anomaly data.

    [Capability: human-readable incident narrative]
    Gracefully degrades — returns empty string on any failure.
    """
    try:
        from lsadra.explainability.narrative_builder import generate_alert_narrative
        import json

        rule_alert = {
            "type":        _infer_rule_type(a),
            "severity":    a.get("severity_label", "MEDIUM"),
            "rule_weight": a.get("severity_score", 0.5) or 0.5,
            "reason":      a.get("threat_type", ""),
            "mitre_id":    a.get("mitre_technique", ""),
            "mitre_name":  a.get("attack_type", ""),
        }
        features = {
            "source_ip":               a.get("source_ip"),
            "device_id":               a.get("device_id"),
            "failed_logins_last_5min": 0,
            "login_attempt_velocity":  0,
            "unique_usernames_per_ip": 0,
            "failure_ratio":           0,
        }
        shap_raw = a.get("shap_values", "{}")
        try:
            shap = json.loads(shap_raw) if isinstance(shap_raw, str) else shap_raw
        except (ValueError, TypeError):
            shap = {}

        return generate_alert_narrative(features, rule_alert, shap_values=shap or None)
    except Exception:
        return ""


def _render_severity_explanation(a: dict) -> None:
    """
    Render a V4 dynamic severity score explanation.

    [V4 ENHANCEMENT — gap: dynamic severity]
    """
    try:
        from lsadra.detection.severity import calculate_dynamic_severity
        import json

        shap_raw = a.get("shap_values", "{}")
        try:
            shap = json.loads(shap_raw) if isinstance(shap_raw, str) else shap_raw
        except (ValueError, TypeError):
            shap = {}

        features = {
            "failed_logins_last_5min": 0,
            "login_attempt_velocity":  0,
        }
        rule_alert = {"rule_weight": a.get("severity_score", 0.5) or 0.5}
        label, score, explanation = calculate_dynamic_severity(
            features=features,
            shap_values=shap or None,
            rule_alert=rule_alert,
        )
        st.caption(f"🔢 **V4 Score**: {explanation}")
    except Exception:
        pass


def _render_fp_button(alert_id: int, a: dict) -> None:
    """
    Render the 'Mark as False Positive' button and inline FP analysis.

    [Capability: adaptive feedback reasoning]
    """
    fp_key  = f"fp_btn_{alert_id}"
    res_key = f"fp_res_{alert_id}"
    note_key = f"fp_note_{alert_id}"

    if st.button("🚩 Mark as False Positive", key=fp_key, help="Flag this alert as a false positive"):
        st.session_state[res_key] = True

    if st.session_state.get(res_key):
        note = st.text_input("Analyst note (optional):", key=note_key)

        if st.button("✅ Confirm FP", key=f"fp_confirm_{alert_id}"):
            _submit_fp(alert_id, a, note)
        _show_fp_analysis(a)


def _submit_fp(alert_id: int, a: dict, note: str) -> None:
    """Submit a false-positive label and show analysis."""
    try:
        from lsadra.explainability.narrative_builder import analyze_false_positive

        fp_result = analyze_false_positive(
            original_alert={"type": _infer_rule_type(a), "features": {}, **a},
            analyst_note=note,
        )
        store_feedback(
            db_conn=None,
            alert_id=alert_id,
            label="false_positive",
            analyst_note=note,
            fp_pattern=fp_result.get("pattern", ""),
            suggested_thresholds=fp_result.get("suggested_threshold_change", {}),
            source_type=a.get("source_type", ""),
        )
        st.success(f"✅ Alert #{alert_id} marked as False Positive. Pattern: `{fp_result.get('pattern')}`")
        st.json(fp_result)
    except Exception as exc:
        st.error(f"Failed to store feedback: {exc}")


def _show_fp_analysis(a: dict) -> None:
    """Show FP analysis inline without committing."""
    try:
        from lsadra.explainability.narrative_builder import analyze_false_positive
        fp_result = analyze_false_positive(
            original_alert={"type": _infer_rule_type(a), "features": {}, **a},
        )
        st.info(
            f"**FP Pattern suggestion:** {fp_result.get('pattern', 'N/A')} "
            f"(confidence: {fp_result.get('confidence', '?')}) — "
            f"{fp_result.get('missing_context', '')}"
        )
    except Exception:
        pass


def _infer_rule_type(a: dict) -> str:
    """Infer V4 rule type from anomaly record."""
    threat = str(a.get("threat_type", a.get("attack_type", ""))).upper()
    if "BRUTE" in threat:
        return "BRUTE_FORCE"
    if "STUFFING" in threat or "CREDENTIAL" in threat:
        return "CREDENTIAL_STUFFING"
    if "LOW" in threat and "SLOW" in threat:
        return "LOW_AND_SLOW"
    if "LATERAL" in threat:
        return "LATERAL_MOVEMENT"
    if "PORT" in threat or "SCAN" in threat:
        return "PORT_SCAN"
    if "TRANSFER" in threat or "EXFIL" in threat:
        return "LARGE_DATA_TRANSFER"
    if "PROCESS" in threat or "LOLBIN" in threat:
        return "SUSPICIOUS_PROCESS"
    return "UNKNOWN"


def _sev_icon(label: str) -> str:
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(label, "⚪")


# ============================================================================
# V3 KPI drill-down (preserved exactly)
# ============================================================================

def _render_drill(drill: str):
    """Render KPI drill-down panels."""
    conn = get_connection()

    if drill == "events":
        st.subheader("📨 Recent Events")
        rows = conn.execute(
            """SELECT timestamp, host, effective_username, source_ip, event_type
               FROM normalized_events
               ORDER BY timestamp DESC LIMIT 100"""
        ).fetchall()
        if rows:
            st.dataframe([dict(r) for r in rows], use_container_width=True, hide_index=True)
        else:
            st.info("No events yet.")

    elif drill == "anomalies":
        st.subheader("⚡ Recent Anomalies")
        rows = conn.execute(
            """SELECT created_at, threat_type, severity_label, severity_score,
                      mitre_technique, source_ip
               FROM anomalies WHERE is_anomaly = 1
               ORDER BY created_at DESC LIMIT 50"""
        ).fetchall()
        if rows:
            st.dataframe([dict(r) for r in rows], use_container_width=True, hide_index=True)
        else:
            st.info("No anomalies yet.")

    elif drill == "incidents":
        st.subheader("📋 Open Incidents")
        rows = conn.execute(
            """SELECT id, attack_type, severity_label,
                      status, first_seen, source_ip, anomaly_count
               FROM incidents WHERE status IN ('OPEN', 'INVESTIGATING')
               ORDER BY anomaly_count DESC LIMIT 50"""
        ).fetchall()
        if rows:
            st.dataframe([dict(r) for r in rows], use_container_width=True, hide_index=True)
        else:
            st.success("No open incidents!")

    conn.close()
