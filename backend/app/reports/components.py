from reportlab.platypus import Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing, Rect, String, Group, Wedge, Polygon, Line
from app.reports.styles import get_styles, Colors

STYLES = get_styles()

def get_accent_for_metric(label):
    l = str(label).lower()
    if "total" in l: return Colors.ORION_BLUE
    if "critical" in l: return Colors.CRITICAL_TEXT
    if "high" in l: return Colors.HIGH_TEXT
    if "medium" in l: return Colors.MEDIUM_TEXT
    if "low" in l: return Colors.LOW_TEXT
    if "info" in l: return Colors.INFO_TEXT
    if "risk" in l: return Colors.PURPLE_ACCENT
    if "endpoint" in l: return Colors.CYAN_ACCENT
    return Colors.SLATE_400

def create_metric_card(label, value):
    """Returns a premium two-row table acting as a metric card with a colored top border."""
    accent = get_accent_for_metric(label)
    
    data = [
        [Paragraph(f"<font color='{Colors.SLATE_500.hexval()}'><b>{str(label).upper()}</b></font>", STYLES['OrionBody'])],
        [Paragraph(f"<font size=20 color='{Colors.NAVY.hexval()}'><b>{value}</b></font>", STYLES['OrionBody'])]
    ]
    t = Table(data, colWidths=[110])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), Colors.WHITE),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOX', (0,0), (-1,-1), 1, Colors.SLATE_200),
        ('LINEABOVE', (0,0), (-1,0), 3, accent),
        ('TOPPADDING', (0,0), (-1,0), 12),
        ('BOTTOMPADDING', (0,-1), (-1,-1), 16),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
    ]))
    return t

def create_metric_grid(metrics):
    """metrics is a list of tuples: (label, value). Returns a table grid."""
    cards = [create_metric_card(l, v) for l, v in metrics]
    
    # We want a 4-column layout
    rows = []
    current_row = []
    for c in cards:
        current_row.append(c)
        if len(current_row) == 4:
            rows.append(current_row)
            current_row = []
    if current_row:
        while len(current_row) < 4:
            current_row.append("")
        rows.append(current_row)
    
    t = Table(rows, colWidths=[115, 115, 115, 115])
    t.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 15),
        ('RIGHTPADDING', (0,0), (-1,-1), 15),
    ]))
    return t

def get_severity_colors(severity):
    sev = str(severity).upper()
    if sev == "CRITICAL": return Colors.CRITICAL_TEXT, Colors.CRITICAL_BG, Colors.CRITICAL_BORDER
    if sev == "HIGH": return Colors.HIGH_TEXT, Colors.HIGH_BG, Colors.HIGH_BORDER
    if sev == "MEDIUM": return Colors.MEDIUM_TEXT, Colors.MEDIUM_BG, Colors.MEDIUM_BORDER
    if sev == "LOW": return Colors.LOW_TEXT, Colors.LOW_BG, Colors.LOW_BORDER
    return Colors.INFO_TEXT, Colors.INFO_BG, Colors.INFO_BORDER

def create_severity_badge(severity):
    text_c, bg_c, border_c = get_severity_colors(severity)
    
    t = Table([[Paragraph(f"<font color='{text_c.hexval()}'><b>{str(severity).upper()}</b></font>", STYLES['OrionBody'])]], colWidths=[80])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), bg_c),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOX', (0,0), (-1,-1), 1, border_c),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    return t

def create_evidence_box(evidence_text):
    """Creates a dark navy monospace container for raw evidence with a cyan/blue left border."""
    s = str(evidence_text or "")
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    s = s.replace('"', "&quot;").replace("'", "&apos;")
    escaped_text = s.replace("\n", "<br/>")
    
    p = Paragraph(f"<font color='{Colors.SLATE_200.hexval()}'>{escaped_text}</font>", STYLES['OrionCode'])
    
    t = Table([["EVIDENCE"], [p]], colWidths=[468]) 
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), Colors.DEEP_NAVY),
        ('TEXTCOLOR', (0,0), (-1,0), Colors.CYAN_ACCENT),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 9),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('TOPPADDING', (0,0), (-1,0), 10),
        ('BOX', (0,0), (-1,-1), 1, Colors.SLATE_800),
        ('LINEBEFORE', (0,0), (0,-1), 3, Colors.CYAN_ACCENT),
        ('BOTTOMPADDING', (0,1), (-1,1), 10),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    return t

def create_remediation_card(remediation_text):
    """Creates a distinct remediation card with a pale blue background."""
    s = str(remediation_text or "")
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    s = s.replace('"', "&quot;").replace("'", "&apos;")
    escaped_text = s.replace("\n", "<br/>")
    
    p = Paragraph(f"<font color='{Colors.NAVY.hexval()}'>{escaped_text}</font>", STYLES['OrionBody'])
    t = Table([["RECOMMENDED REMEDIATION"], [p]], colWidths=[468])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), Colors.LOW_BG),
        ('TEXTCOLOR', (0,0), (-1,0), Colors.ORION_BLUE),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 10),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('TOPPADDING', (0,0), (-1,0), 10),
        ('BOX', (0,0), (-1,-1), 1, Colors.LOW_BORDER),
        ('BOTTOMPADDING', (0,1), (-1,1), 10),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    return t

def create_data_table(headers, rows, col_widths=None):
    """Generic premium table with dark navy headers."""
    def _safe_para(val, style=STYLES['OrionBody']):
        s = str(val)
        s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        s = s.replace('"', "&quot;").replace("'", "&apos;")
        return Paragraph(s, style)

    data = []
    # Headers
    if headers and headers[0]:
        header_row = [Paragraph(f"<font color='{Colors.WHITE.hexval()}'><b>{str(h).upper()}</b></font>", STYLES['OrionBody']) for h in headers]
        data.append(header_row)
        header_bg = Colors.DARK_NAVY
    else:
        # No visible header row
        header_bg = Colors.WHITE
    
    # Rows
    for r in rows:
        data.append([_safe_para(cell) if not isinstance(cell, Paragraph) and not isinstance(cell, Table) else cell for cell in r])
        
    t = Table(data, colWidths=col_widths, repeatRows=1 if (headers and headers[0]) else 0)
    
    styles = [
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('LINEBELOW', (0,0), (-1,-1), 0.5, Colors.SLATE_200),
    ]
    
    if headers and headers[0]:
        styles.extend([
            ('BACKGROUND', (0,0), (-1,0), header_bg),
            ('LINEBELOW', (0,0), (-1,0), 1, Colors.SLATE_300),
        ])
        
    t.setStyle(TableStyle(styles))
    return t

def create_horizontal_bar_chart(distribution):
    """Creates a horizontal severity distribution chart that fits in a 234pt column."""
    d = Drawing(200, 150)
    
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    colors_map = {
        "CRITICAL": Colors.CRITICAL_TEXT,
        "HIGH": Colors.HIGH_TEXT,
        "MEDIUM": Colors.MEDIUM_TEXT,
        "LOW": Colors.LOW_TEXT,
        "INFO": Colors.INFO_TEXT
    }
    
    max_val = max(list(distribution.values()) + [1])
    
    y = 120
    for sev in severities:
        val = distribution.get(sev.lower(), 0)
        # Label
        d.add(String(0, y, sev, fontName="Helvetica-Bold", fontSize=10, fillColor=Colors.NAVY))
        # Bar - constrain max width to 110 so it fits in the column
        bar_width = (val / max_val) * 110
        if val > 0:
            d.add(Rect(60, y-2, bar_width, 10, fillColor=colors_map[sev], strokeColor=None))
        else:
            d.add(Line(60, y+3, 80, y+3, strokeColor=Colors.SLATE_300, strokeWidth=1))
            
        # Value
        d.add(String(60 + bar_width + 10 if val > 0 else 90, y, str(val), fontName="Helvetica-Bold", fontSize=10, fillColor=Colors.SLATE_700))
        y -= 25
        
    return d

def create_risk_gauge(score):
    """Creates a premium semi-circular risk gauge (donut shape)."""
    d = Drawing(200, 120)
    g = Group()
    g.translate(100, 20)
    
    # Fill colors
    fill_color = Colors.LOW_TEXT
    if score >= 90: fill_color = Colors.CRITICAL_TEXT
    elif score >= 70: fill_color = Colors.HIGH_TEXT
    elif score >= 40: fill_color = Colors.MEDIUM_TEXT
    
    # Outer Background Arc (Gray)
    g.add(Wedge(0, 0, 80, 0, 180, fillColor=Colors.SLATE_200, strokeColor=None))
    
    # Outer Filled Arc (Colored based on score)
    angle = 180 - (score / 100.0 * 180)
    if score > 0:
        g.add(Wedge(0, 0, 80, angle, 180, fillColor=fill_color, strokeColor=None))
    
    # Inner Cutout to create the donut effect
    g.add(Wedge(0, 0, 60, 0, 180, fillColor=Colors.WHITE, strokeColor=None))
    
    # Base line
    g.add(Line(-80, 0, 80, 0, strokeColor=Colors.WHITE, strokeWidth=2))
    
    # Score Text
    g.add(String(0, 10, f"{score:.1f}", textAnchor="middle", fontName="Helvetica-Bold", fontSize=28, fillColor=Colors.NAVY))
    
    risk_label = "INFO"
    if score >= 90: risk_label = "CRITICAL RISK"
    elif score >= 70: risk_label = "HIGH RISK"
    elif score >= 40: risk_label = "MEDIUM RISK"
    elif score > 0: risk_label = "LOW RISK"
    
    g.add(String(0, -15, risk_label, textAnchor="middle", fontName="Helvetica-Bold", fontSize=12, fillColor=fill_color))
    
    d.add(g)
    return d
