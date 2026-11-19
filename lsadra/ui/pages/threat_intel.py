"""
LSADRA — Threat Intelligence page (Streamlit).

Shows what the two intel tiers (ADR 0004) actually know: the signed bundle
(CISA KEV, MITRE ATT&CK), the local runtime feeds, optional AbuseIPDB, and
local geolocation. Nothing is simulated; an unknown IP is shown as unknown.
"""

import asyncio

import streamlit as st

from lsadra import intel
from lsadra.intel import bundle
from lsadra.storage.database import get_connection
from lsadra.ui.components.chart_theme import apply_soc_theme
from lsadra.ui.components.kpi_card import kpi_card

_VERDICT_COLOR = {
    "malicious": "#FF4444",
    "suspicious": "#FFD700",
    "not_listed": "#10B981",
    "internal": "#4A9EFF",
    "unknown": "#8899AA",
}


def _render_status():
    s = intel.status()
    b = s["bundled"]
    with st.expander("Intel sources", expanded=False):
        if b.get("available"):
            st.success(f"Bundled intel {b['file']} verified (signed by {b['signed_by']}).")
            for src in b["sources"]:
                st.caption(f"{src['name']} {src['version']}: {src['records']} records "
                           f"({src['license']})")
        else:
            st.error(f"Bundled intel unavailable: {b.get('error')}")
        feeds = [f for f in s["runtime"]["feeds"] if f["enabled"]]
        if feeds:
            for f in feeds:
                st.caption(f"{f['name']}: {f['records']} indicators, {f['status']}, "
                           f"fetched {f['fetched_at'] or 'never'}")
        else:
            st.caption("No IP reputation feeds enabled (LSADRA_INTEL_FEEDS).")
        st.caption("AbuseIPDB: " + ("configured" if s["runtime"]["abuseipdb"]["configured"]
                                    else "not configured"))
        g = s["geo"]
        st.caption(f"Geolocation: {g['database_type']} ({g['build_date']}). {g['attribution']}"
                   if g.get("available") else "Geolocation: no local database.")


def _render_ip(res):
    if not res.get("valid"):
        st.warning("That is not an IP address.")
        return
    verdict = res["verdict"]
    geo = res.get("geo") or {}
    abuse = res.get("abuseipdb") or {}
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        kpi_card("Verdict", verdict["level"].replace("_", " ").title(), icon="⚠️",
                 color=_VERDICT_COLOR.get(verdict["level"], "#8899AA"))
    with c2:
        kpi_card("Country", geo.get("country_code") or abuse.get("country_code") or "Unknown",
                 icon="🌍", color="#4A9EFF")
    with c3:
        kpi_card("Feed matches", len(res.get("feed_matches") or []), icon="📋", color="#7C3AED")
    with c4:
        score = abuse.get("abuse_score")
        kpi_card("AbuseIPDB", score if score is not None else "Not queried", icon="📊",
                 color="#7C3AED")
    st.caption(verdict["reason"])
    if res.get("feed_matches"):
        st.dataframe(res["feed_matches"], use_container_width=True, hide_index=True)
    st.json(res)


def render():
    """Render the Threat Intelligence page."""
    st.title("🔍 Threat Intelligence")
    _render_status()

    # ── IP lookup ─────────────────────────────────────────────────────────
    st.subheader("IP Lookup")
    col1, col2, col3 = st.columns([3, 1, 1])
    with col1:
        ip_input = st.text_input("IP address", placeholder="e.g. 198.51.100.7")
    with col2:
        remote = st.checkbox("Ask AbuseIPDB", value=False,
                             help="Sends the IP to AbuseIPDB. Needs LSADRA_ABUSEIPDB_API_KEY.")
    with col3:
        st.write("")
        lookup_btn = st.button("🔎 Lookup", use_container_width=True)
    if lookup_btn and ip_input:
        res = asyncio.run(intel.lookup_ip_async(ip_input.strip(), allow_remote=remote))
        _render_ip(res)

    st.divider()

    # ── KEV search ────────────────────────────────────────────────────────
    st.subheader("Known Exploited Vulnerabilities (CISA KEV)")
    q = st.text_input("Search CVE, vendor or product", key="kev_q")
    rows = bundle.search_kev(q, limit=50)
    if rows:
        st.dataframe(
            [{"CVE": r["cve_id"], "Vendor": r["vendor"], "Product": r["product"],
              "Name": r["name"], "Added": r["date_added"],
              "Ransomware": "Yes" if r["known_ransomware_use"] else ""} for r in rows],
            use_container_width=True, hide_index=True,
        )
    else:
        st.info("No KEV entries match (or the bundled intel is unavailable).")

    st.divider()

    # ── Flagged external IPs ──────────────────────────────────────────────
    st.subheader("External IPs in Anomalies")
    conn = get_connection()
    ip_rows = conn.execute(
        """SELECT source_ip, COUNT(*) as anomaly_count,
                  MAX(severity_score) as max_severity,
                  MAX(created_at) as last_seen
           FROM anomalies
           WHERE is_anomaly = 1 AND source_ip IS NOT NULL AND source_ip != ''
           GROUP BY source_ip
           ORDER BY anomaly_count DESC LIMIT 200"""
    ).fetchall()
    conn.close()
    ips = [dict(r) for r in ip_rows if intel.ip_scope(r["source_ip"]) == "public"][:20]

    if ips:
        import plotly.graph_objects as go

        fig = go.Figure(data=[go.Bar(
            x=[r["source_ip"] for r in ips],
            y=[r["anomaly_count"] for r in ips],
            marker_color=["#FF4444" if (r["max_severity"] or 0) > 0.7 else "#FFD700"
                          if (r["max_severity"] or 0) > 0.4 else "#4A9EFF" for r in ips],
            text=[r["anomaly_count"] for r in ips],
            textposition="outside",
        )])
        apply_soc_theme(fig, title="Top Anomalous External IPs")
        fig.update_layout(xaxis_title="Source IP", yaxis_title="Anomaly Count")
        st.plotly_chart(fig, use_container_width=True)
        st.dataframe(
            [{"IP": r["source_ip"], "Anomalies": r["anomaly_count"],
              "Verdict": intel.lookup_ip(r["source_ip"])["verdict"]["level"],
              "Last seen": r["last_seen"]} for r in ips],
            use_container_width=True, hide_index=True,
        )
    else:
        st.info("No external anomalous IPs detected yet.")
