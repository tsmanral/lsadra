"""
LSADRA V3 — Model Analytics page.

Displays model registry info, drift detection results, training
metadata, and provides a manual retrain button.
"""

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from lsadra.storage.database import get_connection
from lsadra.ui.components.chart_theme import PALETTE, apply_soc_theme
from lsadra.ui.components.kpi_card import kpi_card
from lsadra.ui.data_layer import get_dashboard_drift, get_dashboard_model_info


def render():
    """Render the Model Analytics page."""
    st.title("🧠 Model Analytics")

    # ── Model Registry ────────────────────────────────────────────────────
    st.subheader("Model Registry")

    conn = get_connection()
    model_rows = conn.execute(
        """SELECT model_name, model_type, version, event_count,
                  trained_at, file_path, is_stale
           FROM model_registry
           ORDER BY trained_at DESC"""
    ).fetchall()
    conn.close()

    if model_rows:
        for row in model_rows:
            row = dict(row)
            name = row.get("model_name", "unknown")
            stale = row.get("is_stale", False)
            stale_icon = "⚠️ STALE" if stale else "✅ Current"
            status_color = "#FF4444" if stale else "#10B981"

            with st.expander(f"**{name.title()}** — {stale_icon}", expanded=True):
                c1, c2, c3, c4 = st.columns(4)
                with c1:
                    kpi_card("Type", row.get("model_type", "?"), icon="🔧", color="#4A9EFF")
                with c2:
                    kpi_card("Training Events", f"{row.get('event_count', 0):,}", icon="📊", color="#10B981")
                with c3:
                    trained_at = row.get("trained_at", "N/A")
                    display_time = trained_at[:16] if trained_at and trained_at != "N/A" else "N/A"
                    kpi_card("Trained At", display_time, icon="🕐", color="#7C3AED")
                with c4:
                    kpi_card("Status", stale_icon.split(" ")[1], icon=stale_icon.split(" ")[0], color=status_color)

                # Analyst-friendly model descriptions
                model_descriptions = {
                    "ensemble": "Isolation Forest + LOF + One-Class SVM majority-vote ensemble for multi-perspective anomaly detection.",
                    "autoencoder": "PyTorch neural network autoencoder that detects anomalies via reconstruction error patterns.",
                }
                desc = model_descriptions.get(name, "Machine learning model for anomaly detection.")
                st.info(f"**Algorithm:** {desc}")
                st.caption(f"Version: {row.get('version', '?')} | Last trained on {row.get('event_count', 0):,} events")
    else:
        st.warning(
            "No models registered yet. Models are automatically trained when a device "
            "exceeds the baseline event threshold (200 events). Use the **Retrain** button "
            "below to trigger training manually."
        )

    st.divider()

    # ── Feature Drift Detection (PSI) ─────────────────────────────────────
    st.subheader("Feature Drift (PSI)")

    models_to_check = ["ensemble", "autoencoder"]
    has_drift_data = False

    for model_name in models_to_check:
        drift_records = get_dashboard_drift(model_name, limit=100)
        if drift_records:
            has_drift_data = True
            st.markdown(f"**{model_name.title()}**")
            df = pd.DataFrame(drift_records)

            latest = df.sort_values("measured_at", ascending=False).drop_duplicates("feature_name")

            fig = go.Figure()
            colors = [
                "#FF4444" if r["is_drifted"] else "#10B981"
                for _, r in latest.iterrows()
            ]
            fig.add_trace(go.Bar(
                x=latest["feature_name"],
                y=latest["psi_value"],
                marker_color=colors,
                text=[f"{v:.4f}" for v in latest["psi_value"]],
                textposition="outside",
            ))

            from lsadra.config import PSI_DRIFT_THRESHOLD
            fig.add_hline(
                y=PSI_DRIFT_THRESHOLD,
                line_dash="dash",
                line_color="#FFD700",
                annotation_text=f"Threshold ({PSI_DRIFT_THRESHOLD})",
            )

            apply_soc_theme(fig, title=f"PSI Drift - {model_name.title()}")
            fig.update_layout(xaxis_title="Feature", yaxis_title="PSI Value")
            st.plotly_chart(fig, use_container_width=True)

    if not has_drift_data:
        st.info(
            "No drift data available yet. Drift detection runs daily via the background "
            "scheduler. Click **Run Drift Detection** below to trigger it manually."
        )

    st.divider()

    # ── Model Management ──────────────────────────────────────────────────
    st.subheader("Model Management")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("##### 🔄 Manual Retrain")
        st.caption("Retrain all ML models on the latest event data from the database.")
        if st.button("🚀 Retrain Models Now", use_container_width=True, type="primary"):
            with st.spinner("Training models... this may take a moment."):
                try:
                    from lsadra.detection import model_lifecycle as lifecycle
                    from lsadra.detection.detection_orchestrator import DetectionOrchestrator

                    # Same controls as the API: one run at a time, cooldown,
                    # clean training data and the canary before promotion.
                    result = DetectionOrchestrator().retrain(trigger="other")
                    if result.get("status") == "promoted":
                        st.success(f"✅ Models retrained on {result.get('events', 0):,} events!")
                        st.rerun()
                    elif result.get("status") == "rejected":
                        st.warning("The new models failed the canary check; the current models were kept.")
                    else:
                        st.warning(f"Not retrained: {result.get('detail', result.get('status'))}")
                except lifecycle.TrainingRefused as e:
                    st.warning(e.reason)
                except Exception as e:
                    st.error(f"Retrain failed: {e}")

    with col2:
        st.markdown("##### 📐 Run Drift Detection")
        st.caption("Manually run PSI drift detection against the current model baselines.")
        if st.button("📊 Run Drift Detection Now", use_container_width=True):
            with st.spinner("Running drift detection..."):
                try:
                    from lsadra.detection.drift_detector import run as run_drift
                    run_drift()
                    st.success("✅ Drift detection complete! Refresh to see results.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Drift detection failed: {e}")

    # ── Model Performance Summary ─────────────────────────────────────────
    st.divider()
    st.subheader("Detection Pipeline Summary")

    conn = get_connection()
    total_events = conn.execute("SELECT COUNT(*) FROM normalized_events").fetchone()[0]
    total_anomalies = conn.execute("SELECT COUNT(*) FROM anomalies WHERE is_anomaly = 1").fetchone()[0]
    total_incidents = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    conn.close()

    detection_rate = (total_anomalies / total_events * 100) if total_events > 0 else 0
    grouping_ratio = (total_incidents / total_anomalies) if total_anomalies > 0 else 0

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        kpi_card("Total Events", f"{total_events:,}", icon="📨", color="#4A9EFF")
    with c2:
        kpi_card("Total Anomalies", f"{total_anomalies:,}", icon="⚡", color="#FF8C00")
    with c3:
        kpi_card("Detection Rate", f"{detection_rate:.1f}%", icon="🎯", color="#7C3AED")
    with c4:
        kpi_card("Grouping Ratio", f"{grouping_ratio:.2f}", icon="📋", color="#10B981")
