"""
LSADRA V3 — PDF report generator.

Generates downloadable PDF security reports from dashboard data
using fpdf2.
"""

import io
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def generate_report(
    title: str = "LSADRA Security Report",
    kpis: Optional[Dict[str, Any]] = None,
    incidents: Optional[List[Dict]] = None,
    anomalies: Optional[List[Dict]] = None,
) -> bytes:
    """
    Generate a PDF security report.

    Args:
        title: Report title.
        kpis: KPI summary dict.
        incidents: List of incident dicts.
        anomalies: List of anomaly dicts.

    Returns:
        PDF file bytes.
    """
    try:
        from fpdf import FPDF
    except ImportError:
        logger.error("fpdf2 not installed. Install with: pip install fpdf2")
        return b""

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # ── Title page ────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 24)
    pdf.cell(0, 20, title, ln=True, align="C")

    pdf.set_font("Helvetica", "", 12)
    pdf.cell(0, 10, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", ln=True, align="C")
    pdf.ln(10)

    # ── KPI Summary ──────────────────────────────────────────────────────
    if kpis:
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "Executive Summary", ln=True)
        pdf.ln(5)

        pdf.set_font("Helvetica", "", 11)
        kpi_items = [
            ("Events (24h)", kpis.get("total_events_24h", 0)),
            ("Anomalies (24h)", kpis.get("total_anomalies_24h", 0)),
            ("Open Incidents", kpis.get("open_incidents", 0)),
            ("Critical Incidents", kpis.get("critical_incidents", 0)),
            ("Active Devices", kpis.get("active_devices", 0)),
            ("Total Devices", kpis.get("total_devices", 0)),
        ]
        for label, value in kpi_items:
            pdf.cell(80, 8, f"  {label}:", ln=False)
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 8, str(value), ln=True)
            pdf.set_font("Helvetica", "", 11)

        pdf.ln(10)

    # ── Incidents ─────────────────────────────────────────────────────────
    if incidents:
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, f"Incidents ({len(incidents)})", ln=True)
        pdf.ln(5)

        # Table header
        pdf.set_font("Helvetica", "B", 9)
        col_widths = [15, 35, 30, 25, 30, 55]
        headers = ["ID", "Attack Type", "Severity", "Status", "First Seen", "Source IP"]
        for w, h in zip(col_widths, headers):
            pdf.cell(w, 7, h, border=1)
        pdf.ln()

        # Table rows
        pdf.set_font("Helvetica", "", 8)
        for inc in incidents[:50]:  # Limit to 50 rows
            pdf.cell(col_widths[0], 6, str(inc.get("id", "")), border=1)
            pdf.cell(col_widths[1], 6, str(inc.get("attack_type", ""))[:20], border=1)
            pdf.cell(col_widths[2], 6, str(inc.get("severity_label", "")), border=1)
            pdf.cell(col_widths[3], 6, str(inc.get("status", "")), border=1)
            pdf.cell(col_widths[4], 6, str(inc.get("first_seen", ""))[:16], border=1)
            pdf.cell(col_widths[5], 6, str(inc.get("source_ip", "")), border=1)
            pdf.ln()

        pdf.ln(10)

    # ── Recent Anomalies ─────────────────────────────────────────────────
    if anomalies:
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, f"Recent Anomalies ({len(anomalies)})", ln=True)
        pdf.ln(5)

        pdf.set_font("Helvetica", "B", 9)
        col_widths = [30, 25, 25, 25, 85]
        headers = ["Threat Type", "Severity", "MITRE", "Score", "Time"]
        for w, h in zip(col_widths, headers):
            pdf.cell(w, 7, h, border=1)
        pdf.ln()

        pdf.set_font("Helvetica", "", 8)
        for a in anomalies[:50]:
            pdf.cell(col_widths[0], 6, str(a.get("threat_type", ""))[:18], border=1)
            pdf.cell(col_widths[1], 6, str(a.get("severity_label", "")), border=1)
            pdf.cell(col_widths[2], 6, str(a.get("mitre_technique", "")), border=1)
            pdf.cell(col_widths[3], 6, f"{a.get('severity_score', 0):.2f}", border=1)
            pdf.cell(col_widths[4], 6, str(a.get("created_at", ""))[:25], border=1)
            pdf.ln()

    # ── Footer ────────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_font("Helvetica", "I", 10)
    pdf.cell(0, 10, "LSADRA V3 - Confidential Security Report", align="C")

    return bytes(pdf.output())
