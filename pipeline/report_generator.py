"""
Pipeline Stage 8: Investigation & Executive Report Generator
Produces structured CSV exports and executive PDF Threat Intelligence reports.
"""

import io
import csv
from datetime import datetime, timezone
from typing import List, Dict, Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether


class ReportGenerator:
    """Generates CSV and PDF reports from analyzed threat intelligence data."""

    def __init__(self):
        pass

    def export_csv(self, alerts: List[Dict[str, Any]]) -> str:
        """Returns CSV string containing full enriched alert triage dataset."""
        output = io.StringIO()
        fieldnames = [
            "Alert ID", "Triage Status", "Risk Score", "Risk Level",
            "Rule Title", "MITRE Tactic", "MITRE Technique",
            "Source IP", "Target Host", "Target User",
            "Threat Classification", "Threat Actor", "Abuse Score",
            "Country", "City", "ISP / ASN", "Evidence Logs",
            "Recommended Action", "Analyst Notes"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for a in alerts:
            ti = a.get("threat_intel", {})
            mitre = a.get("mitre_attack", {})
            writer.writerow({
                "Alert ID": a.get("alert_id", ""),
                "Triage Status": a.get("triage_status", "OPEN"),
                "Risk Score": a.get("risk_score", 0),
                "Risk Level": a.get("risk_level", "INFO"),
                "Rule Title": a.get("title", ""),
                "MITRE Tactic": mitre.get("tactic", ""),
                "MITRE Technique": f"{mitre.get('technique_id', '')} - {mitre.get('technique_name', '')}",
                "Source IP": a.get("source_ip", ""),
                "Target Host": a.get("dest_ip", ""),
                "Target User": a.get("target_user", ""),
                "Threat Classification": ti.get("threat_classification", "N/A"),
                "Threat Actor": ti.get("threat_actor") or "Unattributed",
                "Abuse Score": f"{ti.get('abuse_confidence_score', 0)}%",
                "Country": ti.get("country_name", ""),
                "City": ti.get("city", ""),
                "ISP / ASN": f"{ti.get('isp', '')} ({ti.get('asn', '')})",
                "Evidence Logs": a.get("evidence_count", 1),
                "Recommended Action": a.get("recommended_action", ""),
                "Analyst Notes": a.get("analyst_notes", "")
            })

        return output.getvalue()

    def export_pdf(self, alerts: List[Dict[str, Any]], stats: Dict[str, Any], output_path: str):
        """Builds a multi-page, executive Threat Intelligence & Incident Response PDF report."""
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40
        )
        story = []
        styles = getSampleStyleSheet()

        # Custom Palette
        c_primary = colors.HexColor("#0F172A") # Deep Slate Navy
        c_accent = colors.HexColor("#0284C7")  # Cyber Blue
        c_critical = colors.HexColor("#DC2626")# Crimson
        c_high = colors.HexColor("#EA580C")    # Amber Orange
        c_text = colors.HexColor("#1E293B")
        c_subtext = colors.HexColor("#64748B")

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=c_primary
        )

        sub_style = ParagraphStyle(
            "SubTitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=c_subtext
        )

        h2_style = ParagraphStyle(
            "Heading2",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=17,
            textColor=c_primary,
            spaceBefore=12,
            spaceAfter=6
        )

        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=c_text
        )

        badge_style = ParagraphStyle(
            "Badge",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.white
        )

        # 1. Header Banner & Classification
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        story.append(Paragraph("AEGIS THREAT INTELLIGENCE & DETECTION ANALYTICS", title_style))
        story.append(Spacer(1, 4))
        story.append(Paragraph(f"INCIDENT TRIAGE & EXECUTIVE THREAT ASSESSMENT REPORT | GENERATED: {now_str} | TLP:AMBER", sub_style))
        story.append(Spacer(1, 8))
        story.append(HRFlowable(width="100%", thickness=1.5, color=c_accent, spaceBefore=4, spaceAfter=14))

        # 2. Executive Summary Metrics Box
        crit_count = sum(1 for a in alerts if a.get("risk_level") == "CRITICAL")
        high_count = sum(1 for a in alerts if a.get("risk_level") == "HIGH")
        med_count = sum(1 for a in alerts if a.get("risk_level") == "MEDIUM")
        unique_attackers = len(set(a.get("source_ip") for a in alerts if a.get("source_ip")))

        exec_summary_text = (
            f"During automated threat analysis, <b>{len(alerts)} prioritized security alerts</b> were generated from "
            f"<b>{stats.get('valid_records', len(alerts))} normalized log events</b>. "
            f"The engine flagged <b>{crit_count} Critical-priority</b> and <b>{high_count} High-priority</b> security incidents "
            f"emanating from <b>{unique_attackers} unique external source IP addresses</b>. "
            "Threat intelligence correlation confirmed known adversary infrastructure, active weaponized botnets, and credential stuffing vectors."
        )
        story.append(Paragraph(exec_summary_text, body_style))
        story.append(Spacer(1, 10))

        # KPI Metrics Table
        kpi_data = [
            [
                Paragraph("<b>Total Alerts</b>", body_style),
                Paragraph("<b>Critical Risk</b>", body_style),
                Paragraph("<b>High Risk</b>", body_style),
                Paragraph("<b>Medium Risk</b>", body_style),
                Paragraph("<b>Attacker IPs</b>", body_style)
            ],
            [
                Paragraph(f"<font size=14><b>{len(alerts)}</b></font>", body_style),
                Paragraph(f"<font size=14 color='#DC2626'><b>{crit_count}</b></font>", body_style),
                Paragraph(f"<font size=14 color='#EA580C'><b>{high_count}</b></font>", body_style),
                Paragraph(f"<font size=14 color='#D97706'><b>{med_count}</b></font>", body_style),
                Paragraph(f"<font size=14 color='#0284C7'><b>{unique_attackers}</b></font>", body_style)
            ]
        ]
        kpi_table = Table(kpi_data, colWidths=[105, 105, 105, 105, 110])
        kpi_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER')
        ]))
        story.append(kpi_table)
        story.append(Spacer(1, 14))

        # 3. Top Malicious Indicators of Compromise (IoC Table)
        story.append(Paragraph("PRIORITIZED INDICATORS OF COMPROMISE (IoC)", h2_style))
        ioc_header = ["Source IP", "Attribution / Classification", "Location", "Abuse Score", "Risk Level"]
        ioc_rows = [ioc_header]

        seen_ips = set()
        for a in alerts[:6]:
            ip = a.get("source_ip")
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            ti = a.get("threat_intel", {})
            loc = f"{ti.get('city', '')}, {ti.get('country_code', '')}"
            ioc_rows.append([
                Paragraph(f"<b>{ip}</b>", body_style),
                Paragraph(ti.get("threat_classification", "External Host")[:35], body_style),
                Paragraph(loc, body_style),
                Paragraph(f"<b>{ti.get('abuse_confidence_score', 0)}%</b>", body_style),
                Paragraph(f"<b>{a.get('risk_level', 'MEDIUM')}</b>", body_style)
            ])

        ioc_table = Table(ioc_rows, colWidths=[100, 180, 100, 75, 75])
        ioc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ]))
        story.append(ioc_table)
        story.append(Spacer(1, 14))

        # 4. Detailed Alerts & MITRE ATT&CK Investigation
        story.append(Paragraph("SECURITY ALERTS & INVESTIGATION FINDINGS", h2_style))

        for idx, alert in enumerate(alerts[:8], start=1):
            mitre = alert.get("mitre_attack", {})
            ti = alert.get("threat_intel", {})
            sev = alert.get("risk_level", "MEDIUM")
            sev_color = "#DC2626" if sev == "CRITICAL" else ("#EA580C" if sev == "HIGH" else "#D97706")

            alert_header_text = (
                f"<b>[{alert.get('alert_id')}] {alert.get('title')}</b> — "
                f"<font color='{sev_color}'><b>RISK SCORE: {alert.get('risk_score')}/100 ({sev})</b></font>"
            )

            details_data = [
                [
                    Paragraph(alert_header_text, body_style),
                    Paragraph(f"Status: <b>{alert.get('triage_status', 'OPEN')}</b>", body_style)
                ],
                [
                    Paragraph(
                        f"<b>Attacker IP:</b> {alert.get('source_ip')} ({ti.get('country_name', 'Unknown')})<br/>"
                        f"<b>Target:</b> {alert.get('dest_ip')} | User: <i>{alert.get('target_user')}</i><br/>"
                        f"<b>Evidence:</b> {alert.get('evidence_count')} matching logs",
                        body_style
                    ),
                    Paragraph(
                        f"<b>MITRE Tactic:</b> {mitre.get('tactic', 'N/A')}<br/>"
                        f"<b>Technique:</b> {mitre.get('technique_id', 'N/A')} ({mitre.get('technique_name', 'N/A')})<br/>"
                        f"<b>Action:</b> {alert.get('recommended_action')}",
                        body_style
                    )
                ]
            ]

            alert_table = Table(details_data, colWidths=[310, 220])
            alert_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))

            story.append(KeepTogether([alert_table, Spacer(1, 8)]))

        # 5. Remediation Playbook Recommendations
        story.append(Spacer(1, 6))
        story.append(Paragraph("RECOMMENDED INCIDENT CONTAINMENT ACTIONS", h2_style))
        recs = [
            "1. <b>Network Perimeter Firewall:</b> Block all inbound and outbound traffic to identified C2 and brute-force IPs at the border firewall.",
            "2. <b>Account Hygiene:</b> Force immediate password resets and session terminations for compromised accounts (e.g., svc_api, root).",
            "3. <b>Endpoint Isolation:</b> Isolate hosts exhibiting high egress volume (exfiltration) and C2 beaconing signatures for memory forensic analysis.",
            "4. <b>MFA Enforcement:</b> Ensure Multi-Factor Authentication is universally enforced across all external-facing VPN and SSH gateways."
        ]
        for r in recs:
            story.append(Paragraph(r, body_style))
            story.append(Spacer(1, 3))

        doc.build(story)
        print(f"Executive Threat Intelligence PDF created at: {output_path}")
