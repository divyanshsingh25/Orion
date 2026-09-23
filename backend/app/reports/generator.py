from reportlab.platypus import SimpleDocTemplate
from reportlab.lib.pagesizes import letter

from app.reports.builder import ReportBuilder
from app.reports.canvas import NumberedCanvas

class ReportGenerator:
    @staticmethod
    def generate_pdf(payload: dict, output_path: str):
        target = payload.get('scan_info', {}).get('target', 'Target')
        
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        builder = ReportBuilder(payload)
        story = builder.build()
        
        def draw_cover_background(canvas, doc):
            import os
            from reportlab.lib.utils import ImageReader
            
            canvas.saveState()
            
            from pathlib import Path
            cover_img_path = Path(__file__).resolve().parent / "assets" / "cover.jpg"
            
            if cover_img_path.exists():
                # Draw the image to fit the exact page size
                img = ImageReader(str(cover_img_path))
                canvas.drawImage(img, 0, 0, width=doc.pagesize[0], height=doc.pagesize[1], mask='auto')
            else:
                from app.reports.styles import Colors
                canvas.setFillColor(Colors.DEEP_NAVY)
                canvas.rect(0, 0, doc.pagesize[0], doc.pagesize[1], fill=1, stroke=0)
            
            canvas.restoreState()
        
        doc.build(
            story,
            onFirstPage=draw_cover_background,
            canvasmaker=lambda *args, **kwargs: NumberedCanvas(*args, target_url=target, **kwargs)
        )
