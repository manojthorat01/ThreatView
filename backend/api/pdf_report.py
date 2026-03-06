from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import io

# ThreatView color palette
DARK_BG = colors.HexColor('#0a0e1a')
CARD_BG = colors.HexColor('#111827')
BORDER = colors.HexColor('#1f2937')
INDIGO = colors.HexColor('#6366f1')
RED = colors.HexColor('#ef4444')
AMBER = colors.HexColor('#f59e0b')
GREEN = colors.HexColor('#10b981')
GRAY = colors.HexColor('#9ca3af')
WHITE = colors.HexColor('#f1f5f9')
LIGHT_GRAY = colors.HexColor('#d1d5db')

def generate_threat_report(stats: dict, indicators: list) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch
    )

    styles = getSampleStyleSheet()
    elements = []

    # ── Title Block ──
    title_style = ParagraphStyle('title', fontSize=28, textColor=INDIGO, spaceAfter=6, alignment=TA_CENTER, fontName='Helvetica-Bold')
    sub_style = ParagraphStyle('sub', fontSize=11, textColor=GRAY, spaceAfter=4, alignment=TA_CENTER)
    date_style = ParagraphStyle('date', fontSize=10, textColor=GRAY, spaceAfter=20, alignment=TA_CENTER)

    elements.append(Spacer(1, 0.3*inch))
    elements.append(Paragraph("🛡️ ThreatView", title_style))
    elements.append(Paragraph("Weekly Threat Landscape Report", sub_style))
    elements.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%B %d, %Y at %H:%M UTC')}", date_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=INDIGO, spaceAfter=20))

    # ── Executive Summary ──
    section_style = ParagraphStyle('section', fontSize=14, textColor=WHITE, spaceAfter=10, spaceBefore=16, fontName='Helvetica-Bold')
    body_style = ParagraphStyle('body', fontSize=10, textColor=LIGHT_GRAY, spaceAfter=6, leading=16)

    elements.append(Paragraph("Executive Summary", section_style))

    total = stats.get('total_indicators', 0)
    sources = stats.get('by_source', [])
    otx_count = next((s['count'] for s in sources if s['source'] == 'otx'), 0)
    abuse_count = next((s['count'] for s in sources if s['source'] == 'abuseipdb'), 0)
    top_countries = stats.get('top_countries', [])
    top_country = top_countries[0]['country'] if top_countries else 'Unknown'
    threat_types = stats.get('by_threat_type', [])
    top_threat = max(threat_types, key=lambda x: x['count'])['type'] if threat_types else 'Unknown'

    summary = f"""
    During this reporting period, ThreatView ingested and analyzed <b>{total:,} threat indicators</b> 
    from {len(sources)} active threat intelligence feeds. The platform identified {otx_count:,} indicators 
    from AlienVault OTX and flagged {abuse_count:,} malicious IP addresses via AbuseIPDB. 
    The most prevalent threat category was <b>{top_threat}</b>, with the majority of attack 
    origins traced to <b>{top_country}</b>. Immediate attention is recommended for all 
    high-confidence indicators listed in this report.
    """
    elements.append(Paragraph(summary.strip(), body_style))
    elements.append(Spacer(1, 0.15*inch))

    # ── Key Metrics Table ──
    elements.append(Paragraph("Key Metrics", section_style))

    metrics_data = [
        ['Metric', 'Value', 'Status'],
        ['Total Threat Indicators', f"{total:,}", 'ACTIVE'],
        ['AlienVault OTX Indicators', f"{otx_count:,}", 'INGESTED'],
        ['AbuseIPDB Malicious IPs', f"{abuse_count:,}", 'BLOCKED'],
        ['Top Attack Origin', top_country, 'MONITORED'],
        ['Primary Threat Type', top_threat.upper(), 'TRACKED'],
        ['Data Sources Active', str(len(sources)), 'ONLINE'],
    ]

    metrics_table = Table(metrics_data, colWidths=[3*inch, 2*inch, 1.5*inch])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), INDIGO),
        ('TEXTCOLOR', (0,0), (-1,0), WHITE),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 10),
        ('BACKGROUND', (0,1), (-1,-1), CARD_BG),
        ('TEXTCOLOR', (0,1), (-1,-1), LIGHT_GRAY),
        ('FONTSIZE', (0,1), (-1,-1), 9),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [CARD_BG, colors.HexColor('#1a2235')]),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER),
        ('ALIGN', (1,0), (-1,-1), 'CENTER'),
        ('ALIGN', (0,0), (0,-1), 'LEFT'),
        ('PADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('TEXTCOLOR', (2,1), (2,-1), GREEN),
        ('FONTNAME', (2,1), (2,-1), 'Helvetica-Bold'),
    ]))
    elements.append(metrics_table)
    elements.append(Spacer(1, 0.15*inch))

    # ── Threats by Type ──
    elements.append(Paragraph("Threat Category Breakdown", section_style))

    if threat_types:
        threat_data = [['Threat Category', 'Indicator Count', 'Percentage']]
        total_threats = sum(t['count'] for t in threat_types)
        for t in sorted(threat_types, key=lambda x: x['count'], reverse=True):
            pct = (t['count'] / total_threats * 100) if total_threats > 0 else 0
            threat_data.append([t['type'].upper(), str(t['count']), f"{pct:.1f}%"])

        threat_table = Table(threat_data, colWidths=[3*inch, 2*inch, 1.5*inch])
        threat_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#4f46e5')),
            ('TEXTCOLOR', (0,0), (-1,0), WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 10),
            ('BACKGROUND', (0,1), (-1,-1), CARD_BG),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [CARD_BG, colors.HexColor('#1a2235')]),
            ('TEXTCOLOR', (0,1), (-1,-1), LIGHT_GRAY),
            ('FONTSIZE', (0,1), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, BORDER),
            ('ALIGN', (1,0), (-1,-1), 'CENTER'),
            ('ALIGN', (0,0), (0,-1), 'LEFT'),
            ('PADDING', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ]))
        elements.append(threat_table)
        elements.append(Spacer(1, 0.15*inch))

    # ── Top Attack Origins ──
    elements.append(Paragraph("Top Attack Origin Countries", section_style))

    if top_countries:
        country_data = [['Country', 'Indicator Count', 'Risk Level']]
        max_count = top_countries[0]['count'] if top_countries else 1
        for c in top_countries[:8]:
            pct = c['count'] / max_count
            risk = 'CRITICAL' if pct > 0.7 else 'HIGH' if pct > 0.4 else 'MEDIUM'
            country_data.append([c['country'], str(c['count']), risk])

        country_table = Table(country_data, colWidths=[3*inch, 2*inch, 1.5*inch])
        country_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#dc2626')),
            ('TEXTCOLOR', (0,0), (-1,0), WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 10),
            ('BACKGROUND', (0,1), (-1,-1), CARD_BG),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [CARD_BG, colors.HexColor('#1a2235')]),
            ('TEXTCOLOR', (0,1), (-1,-1), LIGHT_GRAY),
            ('FONTSIZE', (0,1), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, BORDER),
            ('ALIGN', (1,0), (-1,-1), 'CENTER'),
            ('ALIGN', (0,0), (0,-1), 'LEFT'),
            ('PADDING', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10),
            ('TEXTCOLOR', (2,1), (2,-1), RED),
            ('FONTNAME', (2,1), (2,-1), 'Helvetica-Bold'),
        ]))
        elements.append(country_table)
        elements.append(Spacer(1, 0.15*inch))

    # ── Recent IoCs ──
    elements.append(Paragraph("Recent High-Confidence Indicators of Compromise", section_style))

    high_conf = [i for i in indicators if i.get('confidence', 0) >= 75][:15]
    if not high_conf:
        high_conf = indicators[:15]

    if high_conf:
        ioc_data = [['Indicator', 'Type', 'Threat', 'Source', 'Confidence']]
        for ind in high_conf:
            val = str(ind.get('value', ''))
            if len(val) > 35:
                val = val[:32] + '...'
            ioc_data.append([
                val,
                ind.get('type', ''),
                ind.get('threat_type', '').upper(),
                ind.get('source', ''),
                f"{ind.get('confidence', 0):.0f}%"
            ])

        ioc_table = Table(ioc_data, colWidths=[2.2*inch, 0.8*inch, 1*inch, 1*inch, 0.8*inch])
        ioc_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#b45309')),
            ('TEXTCOLOR', (0,0), (-1,0), WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 9),
            ('BACKGROUND', (0,1), (-1,-1), CARD_BG),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [CARD_BG, colors.HexColor('#1a2235')]),
            ('TEXTCOLOR', (0,1), (-1,-1), LIGHT_GRAY),
            ('FONTSIZE', (0,1), (-1,-1), 8),
            ('FONTNAME', (0,1), (0,-1), 'Courier'),
            ('TEXTCOLOR', (0,1), (0,-1), colors.HexColor('#a5b4fc')),
            ('GRID', (0,0), (-1,-1), 0.5, BORDER),
            ('ALIGN', (1,0), (-1,-1), 'CENTER'),
            ('ALIGN', (0,0), (0,-1), 'LEFT'),
            ('PADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ]))
        elements.append(ioc_table)

    # ── Footer ──
    elements.append(Spacer(1, 0.3*inch))
    elements.append(HRFlowable(width="100%", thickness=1, color=BORDER, spaceAfter=10))
    footer_style = ParagraphStyle('footer', fontSize=8, textColor=GRAY, alignment=TA_CENTER)
    elements.append(Paragraph("This report was automatically generated by ThreatView — Threat Intelligence Platform", footer_style))
    elements.append(Paragraph("Data sourced from AlienVault OTX and AbuseIPDB. For internal use only.", footer_style))

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()
