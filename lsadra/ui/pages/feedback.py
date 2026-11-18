"""
LSADRA V4 — Feedback and Threshold Tuning Page.

Allows analysts to review false-positive patterns, inspect FP rates by
source type, and apply suggested threshold changes derived from the
analyze_false_positive() decision tree.

[Capability: adaptive feedback reasoning]
[V4 ENHANCEMENT — gap: analyst feedback loop]
"""

import json

import pandas as pd
import streamlit as st

from lsadra.storage.database import (
    get_false_positive_patterns,
    get_fp_rate_by_source_type,
    get_connection,
)


def render():
    """Render the V4 Feedback and Threshold Tuning page."""
    st.title("📊 Feedback & Threshold Tuning")
    st.caption(
        "Review analyst false-positive patterns, FP rates by source, and "
        "apply suggested threshold adjustments — all driven by local analysis "
        "with zero external dependencies."
    )

    tab1, tab2, tab3 = st.tabs([
        "🚩 False Positive Review",
        "📉 FP Rate by Source",
        "⚙️ Threshold Tuning",
    ])

    with tab1:
        _render_fp_review()

    with tab2:
        _render_fp_rate_chart()

    with tab3:
        _render_threshold_tuning()


# ============================================================================
# Tab 1: Recent False Positives
# ============================================================================

def _render_fp_review():
    """
    Section 1: Recent false positives table with FP pattern analysis.

    [Capability: adaptive feedback reasoning]
    """
    st.subheader("🚩 Recent False Positives")

    fps = get_false_positive_patterns(limit=50)

    if not fps:
        st.success("No false positives flagged yet. Great work, or start ingesting events!")
        return

    df = pd.DataFrame(fps)

    # Parse suggested_thresholds JSON for display
    if "suggested_thresholds" in df.columns:
        df["suggested_thresholds"] = df["suggested_thresholds"].apply(
            _safe_json_parse
        )

    display_cols = [c for c in [
        "created_at", "alert_id", "label", "fp_pattern",
        "source_type", "analyst_note", "suggested_thresholds",
    ] if c in df.columns]

    st.dataframe(df[display_cols], use_container_width=True, hide_index=True)

    st.divider()

    # Recurring pattern summary
    st.subheader("🔁 Recurring FP Pattern Summary")
    if "fp_pattern" in df.columns:
        pattern_counts = df["fp_pattern"].value_counts().reset_index()
        pattern_counts.columns = ["pattern", "count"]
        if not pattern_counts.empty:
            st.bar_chart(pattern_counts.set_index("pattern"), use_container_width=True)
            st.markdown(
                "**Most common patterns:**\n"
                + "\n".join(
                    f"- `{row['pattern']}` — {row['count']} occurrence(s)"
                    for _, row in pattern_counts.head(5).iterrows()
                )
            )
        else:
            st.info("No pattern data available yet.")
    else:
        st.info("No pattern column in feedback records.")


# ============================================================================
# Tab 2: FP Rate by Source Type
# ============================================================================

def _render_fp_rate_chart():
    """
    Section 2: FP rate per ingestion source type.

    [V4 ENHANCEMENT — gap: analyst feedback loop]
    """
    st.subheader("📉 False Positive Rate by Source Type")

    fp_rates = get_fp_rate_by_source_type()

    if not fp_rates:
        st.info("No feedback data available yet. Mark some alerts as False Positive.")
        return

    df = pd.DataFrame(
        [{"source_type": k, "fp_rate": v} for k, v in fp_rates.items()]
    ).sort_values("fp_rate", ascending=False)

    st.bar_chart(df.set_index("source_type"), use_container_width=True)

    # Highlight high FP sources
    high_fp = df[df["fp_rate"] > 0.30]
    if not high_fp.empty:
        sources = ", ".join(high_fp["source_type"].tolist())
        st.warning(
            f"⚠️ High FP rate (>30%) detected in: **{sources}**. "
            "Consider adjusting detection thresholds."
        )

    st.dataframe(df, use_container_width=True, hide_index=True)


# ============================================================================
# Tab 3: Threshold Tuning
# ============================================================================

def _render_threshold_tuning():
    """
    Section 3: Suggested threshold changes from analyze_false_positive().

    Allows applying threshold suggestions stored in alerts_feedback.

    [Capability: adaptive feedback reasoning]
    [V4 ENHANCEMENT — gap: analyst feedback loop]
    """
    st.subheader("⚙️ Suggested Threshold Changes")

    fps = get_false_positive_patterns(limit=100)
    if not fps:
        st.info("No false-positive feedback available yet.")
        return

    # Collect all non-empty threshold suggestions
    suggestions: dict = {}
    for fp in fps:
        raw = fp.get("suggested_thresholds", "{}")
        parsed = _safe_json_parse(raw)
        if isinstance(parsed, dict) and parsed:
            for feature, val in parsed.items():
                if feature not in suggestions:
                    suggestions[feature] = []
                suggestions[feature].append(val)

    if not suggestions:
        st.info("No threshold suggestions have been generated yet.")
        return

    # Compute median suggestion per feature
    import statistics
    summary_rows = []
    for feature, values in suggestions.items():
        try:
            nums = [float(v) for v in values if v is not None]
            if nums:
                summary_rows.append({
                    "feature":          feature,
                    "suggested_value":  round(statistics.median(nums), 2),
                    "suggestion_count": len(nums),
                    "min":              round(min(nums), 2),
                    "max":              round(max(nums), 2),
                })
        except (ValueError, TypeError):
            continue

    if not summary_rows:
        st.info("No numeric threshold suggestions found.")
        return

    df = pd.DataFrame(summary_rows).sort_values("suggestion_count", ascending=False)
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.divider()
    st.markdown("#### Apply a Threshold Suggestion")
    st.caption(
        "Applying a threshold stores it in the configuration database. "
        "The detection engine will use updated thresholds on the next run."
    )

    if not df.empty:
        selected_feature = st.selectbox(
            "Select feature threshold to update",
            df["feature"].tolist(),
            key="fb_feat_select",
        )
        row = df[df["feature"] == selected_feature].iloc[0]
        new_val = st.number_input(
            f"New threshold for `{selected_feature}`",
            value=float(row["suggested_value"]),
            key="fb_new_val",
        )

        if st.button("✅ Apply Threshold", key="fb_apply_btn"):
            _apply_threshold(selected_feature, new_val)


def _apply_threshold(feature: str, value: float) -> None:
    """
    Store a threshold update in the database config table.

    [DESIGN CHOICE] Thresholds are stored in the DB so they survive restarts
    without requiring config file changes. The detection engine reads from DB.
    """
    try:
        conn = get_connection()
        # Store in a simple key-value config table if it exists,
        # or log for manual application otherwise.
        conn.execute(
            """CREATE TABLE IF NOT EXISTS config_overrides (
               key TEXT PRIMARY KEY,
               value TEXT,
               updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )"""
        )
        conn.execute(
            """INSERT INTO config_overrides (key, value) VALUES (?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value,
               updated_at = CURRENT_TIMESTAMP""",
            (f"threshold_{feature}", str(value)),
        )
        conn.commit()
        conn.close()
        st.success(f"✅ Threshold for `{feature}` updated to **{value}**.")
        st.info(
            "This suggestion has been saved. "
            "Restart the detection engine or wait for the next scheduled run."
        )
    except Exception as exc:
        st.error(f"Failed to apply threshold: {exc}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_json_parse(raw: object) -> object:
    """Safely parse a JSON string; return the original value on failure."""
    if isinstance(raw, (dict, list)):
        return raw
    if not raw or raw == "{}":
        return {}
    try:
        return json.loads(str(raw))
    except (ValueError, TypeError):
        return str(raw)
