"""
LSADRA V3+V4 — Streamlit SOC Dashboard.

Navigation root that manages session state, sidebar navigation,
and routes to all V3 + V4 dashboard pages.

Pages:
    V3:
    1. 🔑 Login / Register
    2. 🚨 Live Alerts — real-time anomaly feed
    3. 📊 Analytics — event trends, severity breakdown
    4. 🖥️ Device Behavior — per-device analytics
    5. 🧠 Model Analytics — model registry, drift detection
    6. 🔍 Threat Intel — AbuseIPDB reputation data
    7. 🔌 Connect My Device — token generation
    8. 🛠️ Admin — user management, system status
    V4 (new):
    9. 🔎 Investigate — case file generator + entity timeline
   10. 🌐 Multi-Source — ingestion health + cross-source tracker
   11. 📊 Feedback — FP review + threshold tuning

Usage::

    streamlit run lsadra/ui/dashboard.py
"""

import html
import uuid
from datetime import datetime

import streamlit as st

from lsadra.onboarding.token_manager import generate_token
from lsadra.storage.database import (
    create_user,
    get_anomalies_for_user,
    get_devices_for_user,
    get_events_for_user,
    get_user_by_username,
    init_db,
)
from lsadra.ui.data_layer import get_dashboard_kpis

# ── initialise DB ─────────────────────────────────────────────────────────
init_db()

# ── session state ─────────────────────────────────────────────────────────
if "user" not in st.session_state:
    st.session_state.user = None
if "page" not in st.session_state:
    st.session_state.page = "Live Alerts"


# ── sidebar navigation ───────────────────────────────────────────────────

def _sidebar():
    if st.session_state.user:
        role = st.session_state.user.get("role", "ANALYST")
        role_badge = {"ADMIN": "🔧", "ANALYST": "🔬", "VIEWER": "👁️"}.get(role, "👤")

        st.sidebar.markdown(
            f"""
            <div style="
                background: linear-gradient(135deg, #1A1F2E, #1E2536);
                padding: 1rem;
                border-radius: 8px;
                margin-bottom: 1rem;
                border-left: 3px solid #4A9EFF;
            ">
                <div style="color:#E0E0E0;font-weight:600;">
                    {role_badge} {st.session_state.user['username']}
                </div>
                <div style="color:#8899AA;font-size:0.8rem;">{role}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        pages = [
            "🚨 Live Alerts",
            "📊 Analytics",
            "🖥️ Device Behavior",
            "🧠 Model Analytics",
            "🔍 Threat Intel",
            "🔌 Connect My Device",
            # ─ V4 NEW PAGES ─
            "🔎 Investigate",
            "🌐 Multi-Source",
            "📊 Feedback",
        ]

        if role == "ADMIN":
            pages.append("🛠️ Admin")

        selected = st.sidebar.radio("Navigation", pages, label_visibility="collapsed")
        st.session_state.page = selected

        # Report download
        st.sidebar.divider()
        if st.sidebar.button("📄 Export Report", use_container_width=True):
            _generate_pdf_report()

        st.sidebar.divider()
        if st.sidebar.button("🚪 Logout", use_container_width=True):
            st.session_state.user = None
            st.session_state.page = "Login"
            st.rerun()


def _generate_pdf_report():
    """Generate and offer a PDF report for download."""
    try:
        from lsadra.ui.data_layer import (
            get_dashboard_kpis,
            get_dashboard_open_incidents,
            get_dashboard_recent_anomalies,
        )
        from lsadra.ui.utils.report_generator import generate_report

        kpis = get_dashboard_kpis()
        incidents = get_dashboard_open_incidents()
        anomalies = get_dashboard_recent_anomalies(limit=50)

        pdf_bytes = generate_report(
            title="LSADRA Security Report",
            kpis=kpis,
            incidents=incidents,
            anomalies=anomalies,
        )

        if pdf_bytes:
            st.sidebar.download_button(
                label="⬇️ Download PDF",
                data=pdf_bytes,
                file_name=f"lsadra_report_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.pdf",
                mime="application/pdf",
            )
        else:
            st.sidebar.error("PDF generation failed. Install fpdf2.")
    except Exception as e:
        st.sidebar.error(f"Report error: {e}")


# ── pages ─────────────────────────────────────────────────────────────────

def page_login():
    st.markdown(
        """
        <div style="text-align:center;padding:2rem 0;">
            <h1 style="color:#4A9EFF;">🛡️ LSADRA</h1>
            <p style="color:#8899AA;">Enterprise SIEM Platform — V3</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_spacer1, col_form, col_spacer2 = st.columns([1, 2, 1])
    with col_form:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("Login", use_container_width=True):
                user = get_user_by_username(username)
                if user:
                    # Try bcrypt first, then plain-text fallback
                    from lsadra.auth import verify_password
                    if verify_password(password, user["password_hash"]):
                        st.session_state.user = user
                        st.session_state.page = "🚨 Live Alerts"
                        st.rerun()
                    else:
                        st.error("Invalid credentials.")
                else:
                    st.error("Invalid credentials.")
        with col2:
            if st.button("Register", use_container_width=True):
                from lsadra.config import ALLOW_SIGNUP
                if not ALLOW_SIGNUP:
                    st.error("Sign-up is disabled. Ask an admin to create your account.")
                elif username and password:
                    try:
                        from lsadra.auth import hash_password
                        uid = str(uuid.uuid4())
                        create_user(uid, username, hash_password(password), "ANALYST")
                        st.success("Account created! Please log in.")
                    except Exception as e:
                        st.error(f"Registration failed: {e}")


def page_connect():
    st.title("🔌 Connect My Device")
    user_id = st.session_state.user["id"]

    st.markdown(
        """
        Add a new device to your LSADRA workspace.
        Generate a **one-time registration token** below, then run the
        installer on your target machine.
        """
    )

    if st.button("Generate Token"):
        token = generate_token(user_id)
        st.session_state["last_token"] = token

    if "last_token" in st.session_state:
        token = st.session_state["last_token"]
        st.success(f"Token: `{token}`  *(valid for 15 minutes, single use)*")

        try:
            import socket
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
        except Exception:
            local_ip = "127.0.0.1"

        from lsadra.config import REQUIRE_TLS
        from lsadra.onboarding.agent_files import linux_install_command

        scheme = "https" if REQUIRE_TLS else "http"
        server_address = f"{scheme}://{local_ip}:8000"

        st.subheader("Linux")
        st.code(linux_install_command(server_address, token), language="bash")
        st.caption(
            "The command checks the installer's SHA-256 before running it, and the "
            "installer checks the agent's. Over plain HTTP it needs "
            "--allow-insecure-http: use that only on a trusted local network."
        )

        st.subheader("Windows")
        st.code(
            f'python windows_agent_simulator.py',
            language="bash",
        )


# ── main ──────────────────────────────────────────────────────────────────

def main():
    st.set_page_config(
        page_title="LSADRA V4",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Custom CSS for dark SOC theme
    st.markdown(
        """
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

            .stApp {
                font-family: 'Inter', sans-serif;
            }
            .block-container {
                padding-top: 1rem;
            }
            [data-testid="stSidebar"] {
                background: linear-gradient(180deg, #0E1117 0%, #1A1F2E 100%);
            }
            .stMetric {
                background: #1A1F2E;
                padding: 0.5rem;
                border-radius: 8px;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )

    _sidebar()

    if not st.session_state.user:
        page_login()
        return

    page = st.session_state.page

    if "Live Alerts" in page:
        from lsadra.ui.pages.live_alerts import render
        render()
    elif "Analytics" in page and "Model" not in page:
        from lsadra.ui.pages.analytics import render
        render()
    elif "Device Behavior" in page:
        from lsadra.ui.pages.device_behavior import render
        render()
    elif "Model Analytics" in page:
        from lsadra.ui.pages.model_analytics import render
        render()
    elif "Threat Intel" in page:
        from lsadra.ui.pages.threat_intel import render
        render()
    elif "Connect My Device" in page:
        page_connect()
    elif "Investigate" in page:
        # [V4 ENHANCEMENT — gap: analyst investigation interface]
        from lsadra.ui.pages.investigate import render
        render()
    elif "Multi-Source" in page:
        # [V4 ENHANCEMENT — gap: multi-source visibility]
        from lsadra.ui.pages.multi_source import render
        render()
    elif "Feedback" in page:
        # [V4 ENHANCEMENT — gap: analyst feedback loop]
        from lsadra.ui.pages.feedback import render
        render()
    elif "Admin" in page:
        from lsadra.ui.pages.admin import render
        render()
    else:
        from lsadra.ui.pages.live_alerts import render
        render()


if __name__ == "__main__":
    main()
