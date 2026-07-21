# app/security/report_generator.py
# Generates PDF incident reports using reportlab
# pip install reportlab

import io
import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)

# Dark theme colors (used in borders/accents)
CYAN    = colors.HexColor("#00d4ff")
GREEN   = colors.HexColor("#00ff88")
RED     = colors.HexColor("#ff3355")
ORANGE  = colors.HexColor("#ff6600")
YELLOW  = colors.HexColor("#ffcc00")
DARK    = colors.HexColor("#0d1117")
DARKGRAY= colors.HexColor("#1a2535")
GRAY    = colors.HexColor("#5a7a9a")
WHITE   = colors.white
BLACK   = colors.black

def _sev_color(severity: str):
    return {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": GREEN}.get(severity, GRAY)

def _make_styles():
    base = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle("title", fontSize=22, textColor=DARK,
                                fontName="Helvetica-Bold", spaceAfter=4, alignment=TA_LEFT),
        "subtitle": ParagraphStyle("subtitle", fontSize=11, textColor=GRAY,
                                   fontName="Helvetica", spaceAfter=16),
        "section": ParagraphStyle("section", fontSize=13, textColor=DARK,
                                  fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=6),
        "body": ParagraphStyle("body", fontSize=10, textColor=colors.HexColor("#333333"),
                               fontName="Helvetica", spaceAfter=6, leading=15),
        "mono": ParagraphStyle("mono", fontSize=9, textColor=colors.HexColor("#1a1a2e"),
                               fontName="Courier", spaceAfter=4, leading=13,
                               backColor=colors.HexColor("#f4f4f8")),
        "label": ParagraphStyle("label", fontSize=8, textColor=GRAY,
                                fontName="Helvetica-Bold", spaceAfter=2),
        "value": ParagraphStyle("value", fontSize=10, textColor=DARK,
                                fontName="Helvetica", spaceAfter=6),
        "action": ParagraphStyle("action", fontSize=10, textColor=colors.HexColor("#1a4a1a"),
                                 fontName="Helvetica", spaceAfter=4, leading=14,
                                 leftIndent=10),
        "footer": ParagraphStyle("footer", fontSize=8, textColor=GRAY,
                                 fontName="Helvetica", alignment=TA_CENTER),
    }
    return styles


def generate_incident_report(incident: dict) -> bytes:
    """
    Generate a PDF report for a single incident.
    Returns PDF as bytes (for API streaming).
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm
    )

    S = _make_styles()
    story = []
    proof = incident.get("proof") or {}
    ai    = proof.get("ai_analysis") or {}
    kc    = proof.get("kill_chain") or {}
    conf  = proof.get("confidence") or {}
    persona = proof.get("persona") or {}
    if_result = proof.get("isolation_forest") or {}
    fatigue   = proof.get("alert_fatigue") or {}
    geo       = proof.get("geolocation") or {}
    intel     = proof.get("threat_intel") or {}

    sev_color = _sev_color(incident.get("severity", "LOW"))

    # ── HEADER ──────────────────────────────────────────────
    story.append(Paragraph("AI THREAT DISRUPTION SYSTEM", S["title"]))
    story.append(Paragraph("Automated Incident Report — Confidential", S["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=2, color=CYAN, spaceAfter=12))

    # ── INCIDENT SUMMARY TABLE ───────────────────────────────
    summary_data = [
        ["INCIDENT ID",   f"#{incident.get('incident_id', '—')}",
         "GENERATED",      datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["SOURCE IP",     incident.get("src_ip", "—"),
         "SEVERITY",       incident.get("severity", "—")],
        ["TYPE",          incident.get("incident_type", "—"),
         "RISK SCORE",     str(incident.get("risk_score", "—"))],
        ["STATUS",        incident.get("mitigation_status", "MONITORING"),
         "CONFIDENCE",     f"{conf.get('confidence_pct', 0)}% ({conf.get('confidence_label', '—')})"],
    ]

    tbl = Table(summary_data, colWidths=[3.5*cm, 5.5*cm, 3.5*cm, 5.5*cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), colors.HexColor("#f8f9fa")),
        ("BACKGROUND",   (0,0), (0,-1), colors.HexColor("#e8edf2")),
        ("BACKGROUND",   (2,0), (2,-1), colors.HexColor("#e8edf2")),
        ("FONTNAME",     (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME",     (2,0), (2,-1), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,-1), 9),
        ("TEXTCOLOR",    (0,0), (0,-1), GRAY),
        ("TEXTCOLOR",    (2,0), (2,-1), GRAY),
        ("GRID",         (0,0), (-1,-1), 0.5, colors.HexColor("#d0d8e0")),
        ("PADDING",      (0,0), (-1,-1), 8),
        ("TEXTCOLOR",    (1,1), (1,1), CYAN),   # Source IP cyan
        ("FONTNAME",     (1,1), (1,1), "Courier-Bold"),
        ("TEXTCOLOR",    (3,1), (3,1), sev_color),
        ("FONTNAME",     (3,1), (3,1), "Helvetica-Bold"),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 16))

    # ── AI THREAT ANALYSIS ───────────────────────────────────
    story.append(Paragraph("AI THREAT ANALYSIS", S["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=CYAN, spaceAfter=8))

    ai_powered = ai.get("ai_powered", False)
    ai_label = "Claude AI Powered" if ai_powered else "Rule-Based Fallback"
    story.append(Paragraph(f"Analysis Mode: {ai_label}", S["label"]))

    narrative = ai.get("threat_narrative", "No AI analysis available.")
    story.append(Paragraph(narrative, S["body"]))

    if ai.get("analyst_note"):
        story.append(Paragraph(f"Analyst Note: {ai['analyst_note']}", S["mono"]))

    if ai.get("threat_actor_assessment"):
        story.append(Paragraph(f"Threat Actor Assessment: {ai['threat_actor_assessment']}", S["body"]))

    story.append(Spacer(1, 10))

    # ── IMMEDIATE ACTIONS ────────────────────────────────────
    actions = ai.get("immediate_actions", [])
    if actions:
        story.append(Paragraph("IMMEDIATE ACTIONS REQUIRED", S["section"]))
        story.append(HRFlowable(width="100%", thickness=1, color=GREEN, spaceAfter=8))
        for i, action in enumerate(actions, 1):
            story.append(Paragraph(f"{i}. {action}", S["action"]))
        story.append(Spacer(1, 10))

    # ── KILL CHAIN ────────────────────────────────────────────
    story.append(Paragraph("KILL CHAIN ANALYSIS", S["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=ORANGE, spaceAfter=8))

    kc_data = [
        ["Current Stage",   kc.get("current_stage", "—")],
        ["Progression",     f"{kc.get('kill_chain_progression_pct', 0)}% through kill chain"],
        ["Predicted Next",  ", ".join(kc.get("predicted_next_stages", [])) or "—"],
        ["Urgency",         kc.get("current_stage_urgency", "—")],
        ["Recommendation",  kc.get("recommendation", "—")],
    ]
    if ai.get("predicted_next_move"):
        kc_data.append(["AI Prediction", ai["predicted_next_move"]])

    kc_tbl = Table(kc_data, colWidths=[5*cm, 13*cm])
    kc_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (0,-1), colors.HexColor("#e8edf2")),
        ("FONTNAME",    (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("TEXTCOLOR",   (0,0), (0,-1), GRAY),
        ("GRID",        (0,0), (-1,-1), 0.5, colors.HexColor("#d0d8e0")),
        ("PADDING",     (0,0), (-1,-1), 7),
        ("TEXTCOLOR",   (1,0), (1,0), ORANGE),
        ("FONTNAME",    (1,0), (1,0), "Helvetica-Bold"),
    ]))
    story.append(kc_tbl)
    story.append(Spacer(1, 14))

    # ── EVIDENCE SIGNALS ─────────────────────────────────────
    signals_triggered = conf.get("signals_triggered", [])
    signals_missed    = conf.get("signals_missed", [])

    story.append(Paragraph("EVIDENCE SIGNALS", S["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=CYAN, spaceAfter=8))
    story.append(Paragraph(
        f"Confidence: {conf.get('confidence_pct', 0)}% — "
        f"{len(signals_triggered)} of {len(signals_triggered)+len(signals_missed)} signals triggered",
        S["body"]
    ))

    if signals_triggered:
        sig_data = [["SIGNAL", "WEIGHT", "STATUS"]]
        for s in signals_triggered:
            sig_data.append([s.get("name",""), str(s.get("weight","")), "TRIGGERED"])
        for s in signals_missed:
            sig_data.append([s.get("name",""), "—", "NOT TRIGGERED"])

        sig_tbl = Table(sig_data, colWidths=[9*cm, 3*cm, 6*cm])
        sig_tbl.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,0), DARKGRAY),
            ("TEXTCOLOR",   (0,0), (-1,0), WHITE),
            ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 9),
            ("GRID",        (0,0), (-1,-1), 0.5, colors.HexColor("#d0d8e0")),
            ("PADDING",     (0,0), (-1,-1), 6),
            ("BACKGROUND",  (0,1), (-1, len(signals_triggered)), colors.HexColor("#efffef")),
            ("TEXTCOLOR",   (2,1), (2, len(signals_triggered)), GREEN),
            ("FONTNAME",    (2,1), (2, len(signals_triggered)), "Helvetica-Bold"),
        ]))
        story.append(sig_tbl)
    story.append(Spacer(1, 14))

    # ── GEOLOCATION & THREAT INTEL ───────────────────────────
    if geo or intel:
        story.append(Paragraph("THREAT INTELLIGENCE", S["section"]))
        story.append(HRFlowable(width="100%", thickness=1, color=RED, spaceAfter=8))

        intel_rows = []
        if geo and not geo.get("is_private"):
            intel_rows += [
                ["Country",  f"{geo.get('country','—')} ({geo.get('country_code','—')})"],
                ["City",     geo.get("city", "—")],
                ["ISP",      geo.get("isp", "—")],
            ]
        if intel:
            abuse = intel.get("abuseipdb") or {}
            otx   = intel.get("alienvault") or {}
            if isinstance(abuse, dict) and "abuse_confidence_score" in abuse:
                intel_rows.append(["AbuseIPDB Score", f"{abuse['abuse_confidence_score']}% confidence"])
                intel_rows.append(["Total Reports",   str(abuse.get("total_reports", 0))])
            if isinstance(otx, dict) and "pulse_count" in otx:
                intel_rows.append(["OTX Pulse Count", str(otx.get("pulse_count", 0))])
            known = intel.get("is_known_malicious", False)
            intel_rows.append(["Known Malicious", "YES" if known else "NO"])

        if intel_rows:
            intel_tbl = Table(intel_rows, colWidths=[5*cm, 13*cm])
            intel_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#e8edf2")),
                ("FONTNAME",   (0,0), (0,-1), "Helvetica-Bold"),
                ("FONTSIZE",   (0,0), (-1,-1), 9),
                ("TEXTCOLOR",  (0,0), (0,-1), GRAY),
                ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#d0d8e0")),
                ("PADDING",    (0,0), (-1,-1), 7),
            ]))
            story.append(intel_tbl)
        story.append(Spacer(1, 14))

    # ── MITIGATION DETAILS ───────────────────────────────────
    story.append(Paragraph("MITIGATION DETAILS", S["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=GREEN, spaceAfter=8))

    before = proof.get("before") or {}
    after  = proof.get("after") or {}

    mit_data = [["METRIC", "BEFORE", "AFTER"]]
    all_keys = set(list(before.keys()) + list(after.keys()))
    for key in sorted(all_keys):
        b_val = str(round(before.get(key, "—"), 2)) if isinstance(before.get(key), float) else str(before.get(key, "—"))
        a_val = str(round(after.get(key, "—"), 2)) if isinstance(after.get(key), float) else str(after.get(key, "—"))
        mit_data.append([key, b_val, a_val])

    if len(mit_data) > 1:
        mit_tbl = Table(mit_data, colWidths=[7*cm, 5.5*cm, 5.5*cm])
        mit_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), DARKGRAY),
            ("TEXTCOLOR",  (0,0), (-1,0), WHITE),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 9),
            ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#d0d8e0")),
            ("PADDING",    (0,0), (-1,-1), 6),
            ("BACKGROUND", (2,1), (2,-1), colors.HexColor("#efffef")),
        ]))
        story.append(mit_tbl)

    story.append(Spacer(1, 20))

    # ── FOOTER ───────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=1, color=DARKGRAY, spaceAfter=8))
    story.append(Paragraph(
        f"Generated by AI Threat Disruption System | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | CONFIDENTIAL",
        S["footer"]
    ))

    doc.build(story)
    return buffer.getvalue()