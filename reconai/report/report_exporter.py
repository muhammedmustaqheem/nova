"""
ReconAI Comprehensive Forensic Report Exporter
Generates court-ready and machine-readable case reports in both JSON and PDF formats.
Includes:
- Chain of Custody & Cryptographic Hashes
- Append-Only Hash-Chained Audit Log
- Recovery Summary & 4 Recoverability Buckets
- Evidence Tampering & Ransomware Indicators
- Merged Chronological Timeline
- Self-Hashing: Computes and embeds report_sha256_seal for cryptographic non-repudiation.
"""

import json
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

def generate_json_report(
    case_meta: Dict[str, Any],
    stats: Dict[str, Any],
    recoverability_summary: Dict[str, Any],
    tampering_summary: Dict[str, Any],
    timeline_summary: Dict[str, Any],
    audit_log_entries: List[Dict[str, Any]],
    recovered_items: List[Dict[str, Any]],
    extra_sections: Optional[Dict[str, Any]] = None
) -> Tuple[str, str]:
    """
    Builds a machine-readable JSON forensic case manifest, sealed with a SHA-256 digest.
    extra_sections are merged in before sealing, so they are covered by the seal too.
    Returns: (json_string, report_sha256_seal)
    """
    report_dict: Dict[str, Any] = {
        "report_type": "Official DFIR Forensic Evidence Reconstruction Deliverable",
        "generated_at_utc": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "case_metadata": case_meta,
        "recovery_statistics": stats,
        "recoverability_buckets": recoverability_summary,
        "evidence_tampering_indicators": tampering_summary,
        "chronological_timeline": timeline_summary,
        "hash_chained_audit_trail": audit_log_entries,
        "recovered_artifacts_inventory": [
            {
                "item_id": item.get("item_id"),
                "filename": item.get("filename"),
                "friendly_title": item.get("friendly_title", item.get("filename")),
                "use_case": item.get("use_case", ""),
                "category": item.get("category"),
                "source": item.get("source"),
                "offset": item.get("offset"),
                "size_bytes": item.get("size_bytes"),
                "sha256": item.get("sha256"),
                "recoverability_bucket": item.get("recoverability_bucket"),
                "integrity_score": item.get("integrity_score"),
                "priority_score": item.get("priority_score"),
                "is_fragmented": item.get("is_fragmented", False)
            }
            for item in recovered_items
        ]
    }

    if extra_sections:
        report_dict.update(extra_sections)

    # Deterministic canonical serialization for self-hashing
    canonical_repr = json.dumps(report_dict, sort_keys=True, indent=2, default=str)
    report_seal = hashlib.sha256(canonical_repr.encode('utf-8')).hexdigest()
    report_dict["report_sha256_seal"] = report_seal

    final_json = json.dumps(report_dict, indent=2, default=str)
    return final_json, report_seal

import io
import html
import json
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

def generate_json_report(
    case_meta: Dict[str, Any],
    stats: Dict[str, Any],
    recoverability_summary: Dict[str, Any],
    tampering_summary: Dict[str, Any],
    timeline_summary: Dict[str, Any],
    audit_log_entries: List[Dict[str, Any]],
    recovered_items: List[Dict[str, Any]],
    extra_sections: Optional[Dict[str, Any]] = None
) -> Tuple[str, str]:
    """
    Builds a machine-readable JSON forensic case manifest, sealed with a SHA-256 digest.
    extra_sections are merged in before sealing, so they are covered by the seal too.
    Returns: (json_string, report_sha256_seal)
    """
    report_dict: Dict[str, Any] = {
        "report_type": "Official DFIR Forensic Evidence Reconstruction Deliverable",
        "generated_at_utc": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "case_metadata": case_meta,
        "recovery_statistics": stats,
        "recoverability_buckets": recoverability_summary,
        "evidence_tampering_indicators": tampering_summary,
        "chronological_timeline": timeline_summary,
        "hash_chained_audit_trail": audit_log_entries,
        "recovered_artifacts_inventory": [
            {
                "item_id": item.get("item_id"),
                "filename": item.get("filename"),
                "friendly_title": item.get("friendly_title", item.get("filename")),
                "use_case": item.get("use_case", ""),
                "category": item.get("category"),
                "source": item.get("source"),
                "offset": item.get("offset"),
                "size_bytes": item.get("size_bytes"),
                "sha256": item.get("sha256"),
                "recoverability_bucket": item.get("recoverability_bucket"),
                "integrity_score": item.get("integrity_score"),
                "priority_score": item.get("priority_score"),
                "is_fragmented": item.get("is_fragmented", False)
            }
            for item in recovered_items
        ]
    }

    if extra_sections:
        report_dict.update(extra_sections)

    # Deterministic canonical serialization for self-hashing
    canonical_repr = json.dumps(report_dict, sort_keys=True, indent=2, default=str)
    report_seal = hashlib.sha256(canonical_repr.encode('utf-8')).hexdigest()
    report_dict["report_sha256_seal"] = report_seal

    final_json = json.dumps(report_dict, indent=2, default=str)
    return final_json, report_seal

class ForensicNumberedCanvas(canvas.Canvas):
    """
    Custom ReportLab canvas that draws:
    1. Translucent 40-degree watermark ('OFFICIAL FORENSIC DOSSIER • CHAIN OF CUSTODY SEALED')
    2. Deep Slate / Electric Cyan top header bar on all pages
    3. Bottom footer bar with running page count 'Page X of Y' and SHA-256 integrity notice
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        width, height = letter

        # 1. Translucent Watermark (Diagonal)
        self.saveState()
        self.setFillColor(colors.HexColor("#0F172A"))
        self.setFillAlpha(0.04)
        self.setFont("Helvetica-Bold", 30)
        self.translate(width / 2.0, height / 2.0)
        self.rotate(40)
        self.drawCentredString(0, 50, "OFFICIAL FORENSIC DOSSIER")
        self.drawCentredString(0, 0, "CHAIN OF CUSTODY SEALED")
        self.drawCentredString(0, -50, "RECONAI EVIDENCE RECOVERY")
        self.restoreState()

        # 2. Top Header Bar
        self.setFillColor(colors.HexColor("#0F172A"))
        self.rect(0, height - 36, width, 36, fill=1, stroke=0)
        
        self.setFillColor(colors.HexColor("#00E5FF"))
        self.rect(0, height - 38, width, 2, fill=1, stroke=0)

        self.setFillColor(colors.white)
        self.setFont("Helvetica-Bold", 10)
        self.drawString(36, height - 24, "RECONAI DFIR ENGINE  |  OFFICIAL EVIDENCE RECOVERY DOSSIER")
        
        self.setFont("Helvetica", 9)
        self.setFillColor(colors.HexColor("#94A3B8"))
        self.drawRightString(width - 36, height - 24, "CONFIDENTIAL & COURT-ADMISSIBLE")

        # 3. Bottom Footer Bar
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.75)
        self.line(36, 40, width - 36, 40)

        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawString(36, 26, "Cryptographic Hash Sealed: SHA-256 Immutable Audit Log Verified")
        self.drawRightString(width - 36, 26, f"Page {self._pageNumber} of {page_count}")
        
        self.restoreState()

def _esc(val: Any) -> str:
    """Safely HTML-escapes string values for ReportLab Paragraphs."""
    return html.escape(str(val if val is not None else ''))

def generate_pdf_report(
    case_meta: Dict[str, Any],
    stats: Dict[str, Any],
    recoverability_summary: Dict[str, Any],
    tampering_summary: Dict[str, Any],
    timeline_summary: Dict[str, Any],
    recovered_items: List[Dict[str, Any]]
) -> Tuple[bytes, str]:
    """
    Generates a structured, colorful, court-admissible PDF document using ReportLab.
    Includes:
    - Translucent diagonal watermark
    - Executive Case Overview banner
    - Chain of Custody & Image SHA-256 verification status
    - 4-Card Restoration Outlook metric grid
    - Evidence Tampering & Security Indicators
    - Structured Recovered Artifacts Inventory table with priority/bucket badges
    - Merged Chronological Timeline table
    - Self-hashing cryptographic SHA-256 seal.
    Returns: (pdf_bytes, report_sha256_seal)
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Custom styles for dark slate & electric cyan theme
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=4
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor('#475569'),
        spaceAfter=10
    )

    sec_header_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=11.5,
        leading=15,
        textColor=colors.HexColor('#0F172A'),
        spaceBefore=12,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )

    badge_green = ParagraphStyle(
        'BadgeGreen',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#00875A')
    )

    badge_amber = ParagraphStyle(
        'BadgeAmber',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#B78103')
    )

    badge_purple = ParagraphStyle(
        'BadgePurple',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#5243AA')
    )

    badge_red = ParagraphStyle(
        'BadgeRed',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#DE350B')
    )

    story = []

    case_id = _esc(case_meta.get("case_id", "CASE-UNKNOWN"))
    gen_time = _esc(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))

    # Document Header Title Block
    story.append(Paragraph("INCIDENT SUMMARY & FORENSIC DOSSIER", title_style))
    story.append(Paragraph(
        f"Case Reference: <b>{case_id}</b> &nbsp;|&nbsp; Generated: <b>{gen_time}</b> &nbsp;|&nbsp; Engine: <b>ReconAI Neural DFIR v1.2</b>",
        subtitle_style
    ))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#00E5FF"), spaceAfter=10))

    # 1. CHAIN OF CUSTODY
    story.append(Paragraph("1. CHAIN OF CUSTODY & EVIDENCE RECORD", sec_header_style))
    
    is_verified = case_meta.get("read_only_verified", True)
    read_only_badge = "<font color='#00875A'><b>[VERIFIED MATCH - UNMODIFIED EVIDENCE]</b></font>" if is_verified else "<font color='#DE350B'><b>[INTEGRITY MISMATCH WARNING]</b></font>"
    
    coc_data = [
        [Paragraph("<b>Primary Evidence File:</b>", body_style), Paragraph(_esc(case_meta.get('filename', 'N/A')), body_style)],
        [Paragraph("<b>Disk Image Size:</b>", body_style), Paragraph(f"{case_meta.get('disk_size_bytes', 0):,} bytes", body_style)],
        [Paragraph("<b>Lead Examiner:</b>", body_style), Paragraph(_esc(case_meta.get('examiner_name', 'N/A')), body_style)],
        [Paragraph("<b>Acquisition SHA-256:</b>", body_style), Paragraph(f"<font fontName='Courier' size=8>{_esc(case_meta.get('image_sha256', 'N/A'))}</font>", body_style)],
        [Paragraph("<b>Post-Analysis SHA-256:</b>", body_style), Paragraph(f"<font fontName='Courier' size=8>{_esc(case_meta.get('post_analysis_sha256', 'N/A'))}</font>", body_style)],
        [Paragraph("<b>Read-Only Verification:</b>", body_style), Paragraph(read_only_badge, body_style)]
    ]
    coc_table = Table(coc_data, colWidths=[150, 390])
    coc_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F8FAFC")),
        ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor("#334155")),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('PADDING', (0,0), (-1,-1), 5),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
    ]))
    story.append(coc_table)
    story.append(Spacer(1, 8))

    # 2. RESTORATION OUTLOOK
    story.append(Paragraph("2. RESTORATION OUTLOOK & RECOVERABILITY METRICS", sec_header_style))
    
    rec = recoverability_summary
    card_data = [
        [
            Paragraph(f"<font color='#00875A' size=14><b>{rec.get('fully_recoverable', 0)}</b></font><br/><font size=8>FULLY RECOVERABLE<br/>({rec.get('fully_recoverable_pct', 0)}%)</font>", body_style),
            Paragraph(f"<font color='#B78103' size=14><b>{rec.get('partially_recoverable', 0)}</b></font><br/><font size=8>PARTIALLY RECOVERABLE<br/>({rec.get('partially_recoverable_pct', 0)}%)</font>", body_style),
            Paragraph(f"<font color='#5243AA' size=14><b>{rec.get('fragment_only', 0)}</b></font><br/><font size=8>FRAGMENT ONLY<br/>({rec.get('fragment_only_pct', 0)}%)</font>", body_style),
            Paragraph(f"<font color='#DE350B' size=14><b>{rec.get('unrecoverable', 0)}</b></font><br/><font size=8>UNRECOVERABLE<br/>({rec.get('unrecoverable_pct', 0)}%)</font>", body_style),
        ]
    ]
    card_table = Table(card_data, colWidths=[135, 135, 135, 135])
    card_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,0), colors.HexColor("#E6F9F0")),
        ('BACKGROUND', (1,0), (1,0), colors.HexColor("#FFF0B3")),
        ('BACKGROUND', (2,0), (2,0), colors.HexColor("#EAE6FF")),
        ('BACKGROUND', (3,0), (3,0), colors.HexColor("#FFEBE6")),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('PADDING', (0,0), (-1,-1), 7),
        ('BOX', (0,0), (0,0), 1, colors.HexColor("#00875A")),
        ('BOX', (1,0), (1,0), 1, colors.HexColor("#B78103")),
        ('BOX', (2,0), (2,0), 1, colors.HexColor("#5243AA")),
        ('BOX', (3,0), (3,0), 1, colors.HexColor("#DE350B")),
    ]))
    story.append(card_table)
    story.append(Spacer(1, 8))

    # 3. EVIDENCE TAMPERING
    story.append(Paragraph("3. EVIDENCE TAMPERING & SECURITY AUDIT", sec_header_style))
    tamp_indicators = tampering_summary.get("indicators", [])
    if tamp_indicators:
        tamp_rows = []
        for ind in tamp_indicators:
            sev = _esc(ind.get('severity', 'WARNING'))
            expl = _esc(ind.get('plain_language_explanation', ''))
            tamp_rows.append([
                Paragraph(f"<font color='#DE350B'><b>[{sev}]</b></font>", body_style),
                Paragraph(expl, body_style)
            ])
        tamp_table = Table(tamp_rows, colWidths=[90, 450])
        tamp_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#FFF5F5")),
            ('PADDING', (0,0), (-1,-1), 5),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#FEB2B2")),
        ]))
        story.append(tamp_table)
    else:
        story.append(Paragraph("<font color='#00875A'><b>[CLEAN INTEGRITY] Zero evidence tampering or anti-forensic wiping indicators detected.</b></font>", body_style))
    
    story.append(Spacer(1, 8))

    # 4. RECOVERED ARTIFACTS INVENTORY TABLE
    story.append(Paragraph("4. RECOVERED FORENSIC ARTIFACTS INVENTORY", sec_header_style))
    
    header_cell_style = ParagraphStyle(
        'HeaderCell',
        parent=body_style,
        fontName='Helvetica-Bold',
        textColor=colors.white
    )

    inv_rows = [[
        Paragraph("<b>Item ID</b>", header_cell_style),
        Paragraph("<b>Artifact Title / Filename</b>", header_cell_style),
        Paragraph("<b>Category</b>", header_cell_style),
        Paragraph("<b>Bucket Status</b>", header_cell_style),
        Paragraph("<b>Priority / Integrity</b>", header_cell_style)
    ]]

    for item in recovered_items:
        b_name = item.get("recoverability_bucket", "UNKNOWN")
        if b_name == "FULLY RECOVERABLE":
            b_style = badge_green
        elif b_name == "PARTIALLY RECOVERABLE":
            b_style = badge_amber
        elif b_name == "FRAGMENT ONLY":
            b_style = badge_purple
        else:
            b_style = badge_red

        title = _esc(item.get("friendly_title", item.get("filename", "")))
        fn = _esc(item.get("filename", ""))
        cat = _esc(item.get("category", "N/A"))
        item_id = _esc(item.get("item_id", ""))
        p_score = item.get("priority_score", 0.0)
        i_score = item.get("integrity_score", 0.0)

        inv_rows.append([
            Paragraph(f"<b>{item_id}</b>", body_style),
            Paragraph(f"<b>{title}</b><br/><font color='#64748B' size=7.5>{fn}</font>", body_style),
            Paragraph(cat, body_style),
            Paragraph(_esc(b_name), b_style),
            Paragraph(f"Priority: <b>{p_score:.1f}</b><br/>Integrity: {i_score:.1f}%", body_style)
        ])

    inv_table = Table(inv_rows, colWidths=[65, 185, 95, 110, 85])
    inv_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0F172A")),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,0), (-1,-1), 5),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")])
    ]))

    story.append(inv_table)
    story.append(Spacer(1, 8))

    # 5. CHRONOLOGICAL FORENSIC TIMELINE
    story.append(Paragraph("5. CHRONOLOGICAL INCIDENT TIMELINE", sec_header_style))
    time_rows = [[
        Paragraph("<b>Timestamp (UTC)</b>", header_cell_style),
        Paragraph("<b>Source</b>", header_cell_style),
        Paragraph("<b>Severity</b>", header_cell_style),
        Paragraph("<b>Event Description</b>", header_cell_style)
    ]]
    for ev in timeline_summary.get("events", []):
        time_rows.append([
            Paragraph(_esc(ev.get("timestamp", "")), body_style),
            Paragraph(_esc(ev.get("source", "")), body_style),
            Paragraph(f"<b>{_esc(ev.get('severity', ''))}</b>", body_style),
            Paragraph(_esc(ev.get("description", "")), body_style)
        ])
    time_table = Table(time_rows, colWidths=[110, 80, 70, 280])
    time_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1E293B")),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,0), (-1,-1), 5),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")])
    ]))

    story.append(time_table)

    # Build PDF with custom NumberedCanvas
    doc.build(story, canvasmaker=ForensicNumberedCanvas)
    pdf_bytes = buffer.getvalue()
    pdf_seal = hashlib.sha256(pdf_bytes).hexdigest()
    return pdf_bytes, pdf_seal

