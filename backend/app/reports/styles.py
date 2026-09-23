from reportlab.lib.colors import HexColor
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import os

# ---------------------------------------------------------
# Colors
# ---------------------------------------------------------
class Colors:
    DEEP_NAVY = HexColor("#0b1220")
    DARK_NAVY = HexColor("#111827")
    ORION_BLUE = HexColor("#2563eb")
    ELECTRIC_BLUE = HexColor("#3b82f6")
    CYAN_ACCENT = HexColor("#06b6d4")
    PURPLE_ACCENT = HexColor("#7c3aed")
    
    NAVY = HexColor("#0f172a")
    SLATE_900 = HexColor("#0f172a")
    SLATE_800 = HexColor("#1e293b")
    SLATE_700 = HexColor("#334155")
    SLATE_600 = HexColor("#475569")
    SLATE_500 = HexColor("#64748b")
    SLATE_400 = HexColor("#94a3b8")
    SLATE_300 = HexColor("#cbd5e1")
    SLATE_200 = HexColor("#e2e8f0")
    SLATE_100 = HexColor("#f1f5f9")
    SLATE_50 = HexColor("#f8fafc")
    WHITE = HexColor("#ffffff")

    CRITICAL_BG = HexColor("#fef2f2")
    CRITICAL_TEXT = HexColor("#dc2626")
    CRITICAL_BORDER = HexColor("#f87171")

    HIGH_BG = HexColor("#fff7ed")
    HIGH_TEXT = HexColor("#ea580c")
    HIGH_BORDER = HexColor("#fb923c")

    MEDIUM_BG = HexColor("#fffbeb")
    MEDIUM_TEXT = HexColor("#d97706")
    MEDIUM_BORDER = HexColor("#fcd34d")

    LOW_BG = HexColor("#f0f9ff")
    LOW_TEXT = HexColor("#2563eb")
    LOW_BORDER = HexColor("#7dd3fc")

    INFO_BG = HexColor("#f8fafc")
    INFO_TEXT = HexColor("#64748b")
    INFO_BORDER = HexColor("#cbd5e1")

# ---------------------------------------------------------
# Fonts
# ---------------------------------------------------------
def register_fonts():
    # Attempt to register standard professional fonts if available
    font_paths = {
        'SegoeUI': 'C:/Windows/Fonts/segoeui.ttf',
        'SegoeUI-Bold': 'C:/Windows/Fonts/segoeuib.ttf',
        'Consolas': 'C:/Windows/Fonts/consola.ttf',
        'Consolas-Bold': 'C:/Windows/Fonts/consolab.ttf'
    }
    
    font_names = {'Regular': 'Helvetica', 'Bold': 'Helvetica-Bold', 'Mono': 'Courier', 'Mono-Bold': 'Courier-Bold'}
    
    try:
        if os.path.exists(font_paths['SegoeUI']):
            pdfmetrics.registerFont(TTFont('SegoeUI', font_paths['SegoeUI']))
            font_names['Regular'] = 'SegoeUI'
        if os.path.exists(font_paths['SegoeUI-Bold']):
            pdfmetrics.registerFont(TTFont('SegoeUI-Bold', font_paths['SegoeUI-Bold']))
            font_names['Bold'] = 'SegoeUI-Bold'
        if os.path.exists(font_paths['Consolas']):
            pdfmetrics.registerFont(TTFont('Consolas', font_paths['Consolas']))
            font_names['Mono'] = 'Consolas'
        if os.path.exists(font_paths['Consolas-Bold']):
            pdfmetrics.registerFont(TTFont('Consolas-Bold', font_paths['Consolas-Bold']))
            font_names['Mono-Bold'] = 'Consolas-Bold'
    except Exception:
        pass
        
    return font_names

FONT_MAP = register_fonts()

# ---------------------------------------------------------
# Styles
# ---------------------------------------------------------
def get_styles():
    styles = getSampleStyleSheet()
    
    regular_font = FONT_MAP['Regular']
    bold_font = FONT_MAP['Bold']
    mono_font = FONT_MAP['Mono']
    
    # Base Body Text
    styles.add(ParagraphStyle(
        name='OrionBody',
        parent=styles['BodyText'],
        fontName=regular_font,
        fontSize=10,
        leading=14,
        textColor=Colors.SLATE_700,
        spaceAfter=10
    ))
    
    # Cover Styles
    styles.add(ParagraphStyle(
        name='CoverTitle',
        fontName=bold_font,
        fontSize=36,
        leading=42,
        textColor=Colors.WHITE,
        spaceAfter=40,
        alignment=TA_LEFT
    ))
    
    styles.add(ParagraphStyle(
        name='CoverSubtitle',
        fontName=bold_font,
        fontSize=18,
        leading=24,
        textColor=Colors.CYAN_ACCENT,
        spaceAfter=10,
        alignment=TA_LEFT
    ))
    
    styles.add(ParagraphStyle(
        name='CoverLabel',
        fontName=regular_font,
        fontSize=12,
        leading=16,
        textColor=Colors.SLATE_400,
        spaceAfter=4,
        alignment=TA_LEFT
    ))

    styles.add(ParagraphStyle(
        name='CoverValue',
        fontName=bold_font,
        fontSize=14,
        leading=18,
        textColor=Colors.WHITE,
        spaceAfter=18,
        alignment=TA_LEFT
    ))
    
    # Headings
    styles.add(ParagraphStyle(
        name='OrionH1',
        parent=styles['Heading1'],
        fontName=bold_font,
        fontSize=22,
        leading=28,
        textColor=Colors.NAVY,
        spaceBefore=24,
        spaceAfter=16
    ))
    
    styles.add(ParagraphStyle(
        name='OrionH2',
        parent=styles['Heading2'],
        fontName=bold_font,
        fontSize=14,
        leading=18,
        textColor=Colors.SLATE_700,
        spaceBefore=16,
        spaceAfter=12
    ))
    
    # Findings Styles
    styles.add(ParagraphStyle(
        name='FindingHeaderID',
        fontName=bold_font,
        fontSize=14,
        leading=18,
        textColor=Colors.CYAN_ACCENT,
        spaceAfter=4,
        spaceBefore=16
    ))
    
    styles.add(ParagraphStyle(
        name='FindingHeaderTitle',
        fontName=bold_font,
        fontSize=18,
        leading=24,
        textColor=Colors.NAVY,
        spaceAfter=12
    ))
    
    styles.add(ParagraphStyle(
        name='FindingSectionLabel',
        fontName=bold_font,
        fontSize=11,
        leading=15,
        textColor=Colors.SLATE_500,
        spaceBefore=16,
        spaceAfter=8,
        textTransform='uppercase'
    ))

    # Code / Evidence
    styles.add(ParagraphStyle(
        name='OrionCode',
        fontName=mono_font,
        fontSize=8.5,
        leading=11,
        textColor=Colors.SLATE_200,
        spaceAfter=0,
        wordWrap='CJK',
        leftIndent=4,
        rightIndent=4
    ))
    
    styles.add(ParagraphStyle(
        name='OrionCodeBlack',
        fontName=mono_font,
        fontSize=8.5,
        leading=11,
        textColor=Colors.NAVY,
        spaceAfter=0,
        wordWrap='CJK'
    ))
    
    return styles
