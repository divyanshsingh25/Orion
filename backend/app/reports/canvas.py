from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from app.reports.styles import Colors, FONT_MAP

class NumberedCanvas(canvas.Canvas):
    """
    A canvas that enables running headers, footers, and Page X of Y functionality.
    """
    def __init__(self, *args, **kwargs):
        self.target_url = kwargs.pop('target_url', 'Target')
        canvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        """Add page info to each page (page x of y)"""
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_decorations(self, page_count):
        if self._pageNumber <= 1:
            return

        self.saveState()
        self.setFont(FONT_MAP['Regular'], 9)
        self.setFillColor(Colors.SLATE_500)
        self.setStrokeColor(Colors.SLATE_200)
        self.setLineWidth(0.5)

        # Header
        self.setFont(FONT_MAP['Bold'], 10)
        self.setFillColor(Colors.DARK_NAVY)
        self.drawString(72, 750, "ORION SECURITY ASSESSMENT")
        
        self.setFont(FONT_MAP['Regular'], 9)
        self.setFillColor(Colors.SLATE_500)
        self.drawRightString(self._pagesize[0] - 72, 750, "CONFIDENTIAL")
        
        # Cyan accent line
        self.setStrokeColor(Colors.CYAN_ACCENT)
        self.setLineWidth(1)
        self.line(72, 742, self._pagesize[0] - 72, 742)

        # Footer
        self.setStrokeColor(Colors.ORION_BLUE)
        self.setLineWidth(0.5)
        self.line(72, 50, self._pagesize[0] - 72, 50)
        
        self.setFont(FONT_MAP['Regular'], 9)
        self.setFillColor(Colors.SLATE_500)
        self.drawString(72, 35, "ORION SECURITY ASSESSMENT")
        self.drawCentredString(self._pagesize[0] / 2.0, 35, str(self.target_url))
        self.drawRightString(self._pagesize[0] - 72, 35, f"Page {self._pageNumber} of {page_count}")
        
        self.restoreState()
