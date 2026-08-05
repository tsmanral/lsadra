"""
LSADRA V3 — Admin page.

User management, system configuration, and diagnostic tools.
Available only to ADMIN role users.
"""

import uuid

import streamlit as st

from lsadra.auth import hash_password
from lsadra.storage.database import (
    create_user,
    get_anomalies_for_user,
    get_connection,
    list_users,
    update_user_role,
)
from lsadra.ui.components.kpi_card import kpi_card


def render():
    """Render the Admin page."""
    st.title("🛠️ Administration")

    user = st.session_state.get("user")
    if user and user.get("role") != "ADMIN":
        st.warning("⚠️ This page requires ADMIN privileges.")
        return

    tab1, tab2, tab3 = st.tabs(["👥 User Management", "⚙️ System Status", "🧪 Testing"])

    # ── Tab 1: User Management ───────────────────────────────────────────
    with tab1:
        st.subheader("Existing Users")
        users = list_users()
        if users:
            user_data = []
            for u in users:
                user_data.append({
                    "Username": u.get("username", ""),
                    "Role": u.get("role", "ANALYST"),
                    "Created": u.get("created_at", ""),
                    "ID": u.get("id", "")[:8] + "…",
                })
            st.dataframe(user_data, use_container_width=True)

            # Role management
            st.subheader("Change User Role")
            user_options = {u["username"]: u["id"] for u in users}
            selected_user = st.selectbox("User", list(user_options.keys()), key="admin_role_user")
            new_role = st.selectbox("New Role", ["ADMIN", "ANALYST", "VIEWER"], key="admin_role_select")
            if st.button("Update Role", key="admin_role_btn"):
                update_user_role(user_options[selected_user], new_role)
                st.success(f"Updated {selected_user} to {new_role}.")
                st.rerun()
        else:
            st.info("No users found.")

        st.divider()

        # Create user
        st.subheader("Create New User")
        c1, c2, c3 = st.columns(3)
        with c1:
            new_username = st.text_input("Username", key="admin_new_user")
        with c2:
            new_password = st.text_input("Password", type="password", key="admin_new_pass")
        with c3:
            new_role = st.selectbox("Role", ["ANALYST", "ADMIN", "VIEWER"], key="admin_new_role")

        if st.button("Create User", key="admin_create_btn"):
            if new_username and new_password:
                try:
                    uid = str(uuid.uuid4())
                    create_user(uid, new_username, hash_password(new_password), new_role)
                    st.success(f"User '{new_username}' created as {new_role}.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed: {e}")

    # ── Tab 2: System Status ─────────────────────────────────────────────
    with tab2:
        st.subheader("Database Statistics")
        conn = get_connection()
        tables = ["normalized_events", "anomalies", "incidents", "devices",
                   "device_heartbeats", "metrics_5min", "model_registry",
                   "threat_intel_cache", "feature_drift"]

        cols = st.columns(3)
        for i, table in enumerate(tables):
            try:
                row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
                count = row[0] if row else 0
            except Exception:
                count = "N/A"
            with cols[i % 3]:
                kpi_card(table, count, icon="🗄️", color="#4A9EFF")
        conn.close()

        st.divider()

        # TLS status
        from lsadra.config import REQUIRE_TLS
        if REQUIRE_TLS:
            st.success("🔒 TLS enforcement is **enabled**.")
        else:
            st.warning("⚠️ TLS enforcement is **disabled**. Set `LSADRA_REQUIRE_TLS=true` for production.")

    # ── Tab 3: Testing ───────────────────────────────────────────────────
    with tab3:
        st.subheader("Synthetic Data View")
        if st.session_state.get("user"):
            user_id = st.session_state.user["id"]
            show_synthetic = st.toggle("Show synthetic data", value=False)
            anomalies = get_anomalies_for_user(user_id, synthetic=show_synthetic)

            if anomalies:
                st.dataframe(
                    [
                        {
                            "Time": a.get("created_at", ""),
                            "Threat": a.get("threat_type", ""),
                            "MITRE": a.get("mitre_technique", ""),
                            "Severity": a.get("severity_label", ""),
                            "Score": f"{a.get('severity_score', 0):.2f}",
                            "Anomaly": a.get("is_anomaly", False),
                        }
                        for a in anomalies
                    ],
                    use_container_width=True,
                )
            else:
                st.info("No data to show.")
