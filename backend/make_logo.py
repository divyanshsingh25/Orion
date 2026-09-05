from reportlab.graphics.shapes import Drawing, String, Group, Circle, Polygon
from reportlab.graphics import renderPM
from reportlab.lib import colors

# Shield-like shape (simplified as a hexagon/shield)
d = Drawing(100, 100)
g = Group()

# Shield polygon
shield = Polygon(
    [10, 80, 50, 95, 90, 80, 90, 40, 50, 5, 10, 40],
    fillColor=colors.HexColor("#0ea5e9"),
    strokeColor=None
)
g.add(shield)

# Inner text
g.add(String(50, 42, "O", textAnchor="middle", fontSize=48, fillColor=colors.white, fontName="Helvetica-Bold"))

d.add(g)
renderPM.drawToFile(d, "orion_logo.png", "PNG")
print("Logo created!")
