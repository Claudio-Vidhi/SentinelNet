# ponytail: costruzione minimale di un .vsdx (Visio) usando solo la stdlib.
# Un .vsdx e' semplicemente uno zip OPC (le stesse regole dei .docx/.xlsx) con
# parti XML. Non usiamo librerie esterne: zipfile + xml.sax.saxutils.escape
# bastano per generare una pagina con forme rettangolari (dispositivi) e forme
# 1-D (collegamenti) posizionate secondo le coordinate ricevute dal frontend.
#
# Limite noto: le forme 1-D qui sono semplici linee con BeginX/Y - EndX/Y (non
# connettori "incollati" agli shape endpoint di Visio), sufficiente per una
# esportazione leggibile ed editabile ma senza il glue automatico che si
# otterrebbe ricreando il disegno a mano in Visio. La vera prova di fedeltà è
# aprire il file in Visio.

import io
import zipfile
from xml.sax.saxutils import escape

# Fattore di scala: le coordinate vis.js (pixel canvas) vengono compresse in
# pollici Visio. Un valore piccolo tiene il disegno in una pagina ragionevole.
_SCALE = 0.02
_PAGE_W_IN = 11.0
_PAGE_H_IN = 8.5
_MIN_MARGIN_IN = 0.5


def _hex_to_rgb_fraction(hex_color: str):
    """'#RRGGBB' -> 'r,g,b' con valori 0-255 (formato colore Visio ARGB non serve, RGB va bene)."""
    h = (hex_color or "#6A5FC1").lstrip("#")
    if len(h) != 6:
        h = "6A5FC1"
    try:
        r = int(h[0:2], 16); g = int(h[2:4], 16); b = int(h[4:6], 16)
    except ValueError:
        r, g, b = (106, 95, 193)
    return f"#{r:02X}{g:02X}{b:02X}"


def _compute_layout(nodes):
    """Scala coordinate canvas -> pollici Visio, con asse Y invertito (Visio: Y cresce verso l'alto)."""
    if not nodes:
        return {}, _PAGE_W_IN, _PAGE_H_IN
    xs = [n["x"] for n in nodes]
    ys = [n["y"] for n in nodes]
    min_x, max_x = min(xs), max(xs)
    min_y, max_y = min(ys), max(ys)
    span_x = max((max_x - min_x) * _SCALE, 1.0)
    span_y = max((max_y - min_y) * _SCALE, 1.0)
    page_w = span_x + 2 * _MIN_MARGIN_IN
    page_h = span_y + 2 * _MIN_MARGIN_IN

    positions = {}
    for n in nodes:
        px = (n["x"] - min_x) * _SCALE + _MIN_MARGIN_IN
        # Inverti Y: canvas cresce verso il basso, Visio verso l'alto.
        py = (max_y - n["y"]) * _SCALE + _MIN_MARGIN_IN
        positions[n["id"]] = (px, py)
    return positions, page_w, page_h


def build_vsdx(nodes, edges) -> bytes:
    """Costruisce un .vsdx in memoria a partire da nodi/archi già posizionati.

    nodes: [{id, label, model, ip, x, y}, ...]
    edges: [{source, target, label, color}, ...]
    Ritorna i byte del file zip (.vsdx).
    """
    positions, page_w, page_h = _compute_layout(nodes)
    shapes_xml = []
    connects_xml = []
    shape_id = 1
    id_by_node = {}

    box_w, box_h = 1.6, 0.6  # dimensioni fisse dei rettangoli dispositivo, in pollici

    for n in nodes:
        px, py = positions.get(n["id"], (1.0, 1.0))
        sid = shape_id
        id_by_node[n["id"]] = sid
        shape_id += 1
        label = n.get("label") or n.get("ip") or str(n["id"])
        model = n.get("model") or ""
        ip = n.get("ip") or n["id"]
        text = "\n".join(filter(None, [label, model, ip]))
        shapes_xml.append(f'''
        <Shape ID="{sid}" Type="Shape" LineStyle="3" FillStyle="3" TextStyle="3">
          <Cell N="PinX" V="{px:.4f}"/>
          <Cell N="PinY" V="{py:.4f}"/>
          <Cell N="Width" V="{box_w:.4f}"/>
          <Cell N="Height" V="{box_h:.4f}"/>
          <Cell N="LocPinX" V="{box_w/2:.4f}"/>
          <Cell N="LocPinY" V="{box_h/2:.4f}"/>
          <Cell N="FillForegnd" V="#E8E4FB"/>
          <Cell N="LineColor" V="#6A5FC1"/>
          <Cell N="LineWeight" V="0.01"/>
          <Section N="Geometry" IX="0">
            <Row T="MoveTo" IX="1"><Cell N="X" V="0"/><Cell N="Y" V="0"/></Row>
            <Row T="LineTo" IX="2"><Cell N="X" V="{box_w:.4f}"/><Cell N="Y" V="0"/></Row>
            <Row T="LineTo" IX="3"><Cell N="X" V="{box_w:.4f}"/><Cell N="Y" V="{box_h:.4f}"/></Row>
            <Row T="LineTo" IX="4"><Cell N="X" V="0"/><Cell N="Y" V="{box_h:.4f}"/></Row>
            <Row T="LineTo" IX="5"><Cell N="X" V="0"/><Cell N="Y" V="0"/></Row>
          </Section>
          <Text>{escape(text)}</Text>
        </Shape>''')

    for e in edges:
        src = id_by_node.get(e.get("source"))
        dst = id_by_node.get(e.get("target"))
        if src is None or dst is None:
            continue
        spx, spy = positions[e["source"]]
        dpx, dpy = positions[e["target"]]
        sid = shape_id
        shape_id += 1
        color = _hex_to_rgb_fraction(e.get("color"))
        label = e.get("label") or ""
        # Coordinate locali relative al bounding box della forma 1-D stessa.
        x0, y0 = spx + box_w / 2, spy + box_h / 2
        x1, y1 = dpx + box_w / 2, dpy + box_h / 2
        w = x1 - x0
        h = y1 - y0
        shapes_xml.append(f'''
        <Shape ID="{sid}" Type="Shape" LineStyle="3" TextStyle="3">
          <Cell N="PinX" V="{x0:.4f}"/>
          <Cell N="PinY" V="{y0:.4f}"/>
          <Cell N="Width" V="{w if w else 0.001:.4f}"/>
          <Cell N="Height" V="{h if h else 0.001:.4f}"/>
          <Cell N="LocPinX" V="0"/>
          <Cell N="LocPinY" V="0"/>
          <Cell N="LineColor" V="{color}"/>
          <Cell N="LineWeight" V="0.02"/>
          <Section N="Geometry" IX="0">
            <Row T="MoveTo" IX="1"><Cell N="X" V="0"/><Cell N="Y" V="0"/></Row>
            <Row T="LineTo" IX="2"><Cell N="X" V="{w:.4f}"/><Cell N="Y" V="{h:.4f}"/></Row>
          </Section>
          <Text>{escape(label)}</Text>
        </Shape>''')

    page_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<PageContents xmlns="http://schemas.microsoft.com/office/visio/2012/main" xml:space="preserve">
  <Shapes>{"".join(shapes_xml)}
  </Shapes>
</PageContents>'''

    content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/visio/document.xml" ContentType="application/vnd.ms-visio.drawing.main+xml"/>
  <Override PartName="/visio/pages/pages.xml" ContentType="application/vnd.ms-visio.pages+xml"/>
  <Override PartName="/visio/pages/page1.xml" ContentType="application/vnd.ms-visio.page+xml"/>
</Types>'''

    root_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.microsoft.com/visio/2010/relationships/document" Target="visio/document.xml"/>
</Relationships>'''

    document_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<VisioDocument xmlns="http://schemas.microsoft.com/office/visio/2012/main" xml:space="preserve">
  <PageSheet/>
</VisioDocument>'''

    document_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.microsoft.com/visio/2010/relationships/pages" Target="pages/pages.xml"/>
</Relationships>'''

    pages_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Pages xmlns="http://schemas.microsoft.com/office/visio/2012/main"
       xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <Page ID="0" Name="SentinelNet Map">
    <PageSheet>
      <Cell N="PageWidth" V="{page_w:.4f}"/>
      <Cell N="PageHeight" V="{page_h:.4f}"/>
    </PageSheet>
    <Rel r:id="rId1"/>
  </Page>
</Pages>'''

    pages_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.microsoft.com/visio/2010/relationships/page" Target="page1.xml"/>
</Relationships>'''

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("visio/document.xml", document_xml)
        z.writestr("visio/_rels/document.xml.rels", document_rels)
        z.writestr("visio/pages/pages.xml", pages_xml)
        z.writestr("visio/pages/_rels/pages.xml.rels", pages_rels)
        z.writestr("visio/pages/page1.xml", page_xml)
    return buf.getvalue()


if __name__ == "__main__":
    # Validazione minima: 2 nodi finti + 1 arco -> vsdx apribile come zip e XML valido.
    import xml.dom.minidom as minidom

    fake_nodes = [
        {"id": "10.0.0.1", "label": "SW-CORE-1", "model": "C9300", "ip": "10.0.0.1", "x": 0, "y": 0},
        {"id": "10.0.0.2", "label": "SW-ACCESS-2", "model": "C2960", "ip": "10.0.0.2", "x": 300, "y": 150},
    ]
    fake_edges = [
        {"source": "10.0.0.1", "target": "10.0.0.2", "label": "Po1", "color": "#FFB84D"},
    ]
    data = build_vsdx(fake_nodes, fake_edges)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        required = [
            "[Content_Types].xml", "_rels/.rels", "visio/document.xml",
            "visio/_rels/document.xml.rels", "visio/pages/pages.xml",
            "visio/pages/_rels/pages.xml.rels", "visio/pages/page1.xml",
        ]
        names = z.namelist()
        for part in required:
            assert part in names, f"Parte mancante: {part}"
        for part in required:
            if part.endswith(".xml"):
                minidom.parseString(z.read(part))  # solleva se XML non valido
    print(f"OK: vsdx valido, {len(data)} bytes, {len(names)} parti.")
