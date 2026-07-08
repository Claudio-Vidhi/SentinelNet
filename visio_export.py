# ponytail: costruzione minimale di un .vsdx (Visio) usando solo la stdlib.
# Un .vsdx e' semplicemente uno zip OPC (le stesse regole dei .docx/.xlsx) con
# parti XML. Non usiamo librerie esterne: zipfile + xml.sax.saxutils.escape
# bastano per generare una pagina con forme rettangolari (dispositivi), forme
# 1-D (collegamenti) e — per la mappa minimalista — le PRIMITIVE registrate
# dal frontend (polilinee ortogonali, etichette di porta, pillole Po/vPC,
# contenitori Sede), cosi' il .vsdx replica fedelmente il disegno dell'app.
#
# Limite noto: le forme 1-D qui sono semplici linee (non connettori "incollati"
# agli shape endpoint di Visio), sufficiente per una esportazione leggibile ed
# editabile ma senza il glue automatico.

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
    """'#RRGGBB' -> '#RRGGBB' normalizzato (fallback al viola di default)."""
    h = (hex_color or "#6A5FC1").lstrip("#")
    if len(h) != 6:
        h = "6A5FC1"
    try:
        r = int(h[0:2], 16); g = int(h[2:4], 16); b = int(h[4:6], 16)
    except ValueError:
        r, g, b = (106, 95, 193)
    return f"#{r:02X}{g:02X}{b:02X}"


def _pt(px: float) -> float:
    """Dimensione testo: pixel canvas -> punti, coerente con la scala geometrica
    (px * _SCALE pollici * 72 pt/pollice)."""
    return max(px * _SCALE * 72, 4.0)


def _collect_bounds(nodes, primitives):
    xs, ys = [], []
    for n in nodes:
        w = float(n.get("w") or 80.0); h = float(n.get("h") or 30.0)
        xs += [n["x"] - w / 2, n["x"] + w / 2]
        ys += [n["y"] - h / 2, n["y"] + h / 2]
    if primitives:
        for ln in primitives.get("lines", []) + primitives.get("polys", []):
            for p in ln.get("points", []):
                xs.append(p[0]); ys.append(p[1])
        for r in primitives.get("rects", []):
            xs += [r["x"], r["x"] + r["w"]]
            ys += [r["y"], r["y"] + r["h"]]
        for t in primitives.get("texts", []):
            xs.append(t["x"]); ys.append(t["y"])
    if not xs:
        return 0.0, 0.0, 1.0, 1.0
    return min(xs), min(ys), max(xs), max(ys)


def build_vsdx(nodes, edges, primitives=None, connectors=None) -> bytes:
    """Costruisce un .vsdx in memoria.

    nodes: [{id, label, model, ip, x, y, [w, h, fill, border]}, ...]
    edges: [{source, target, label, color}, ...]  (mappa classica)
    primitives: dict opzionale registrato dal frontend (mappa minimalista):
      lines: [{points:[[x,y],...], color, alpha, width, dash}]
      polys: [{points, fill, alpha}]
      rects: [{x, y, w, h, fill, alpha}]
      texts: [{x, y, text, color, size, bold, w}]
    connectors: lista opzionale di cavi strutturati (mappa minimalista):
      [{from, to, points:[[x,y],...], color, width, dash}]
      Ogni cavo diventa UNA forma 1-D continua, INCOLLATA (glue) ai connection
      point dei riquadri dispositivo; i riquadri espongono i punti di aggancio
      come quadratini colorati sul perimetro (figli del gruppo, quindi si
      muovono col dispositivo) e come Connection section per il glue dinamico.
    Tutte le coordinate sono in pixel canvas vis.js (Y verso il basso).
    Ritorna i byte del file zip (.vsdx).
    """
    connectors = connectors or []
    min_x, min_y, max_x, max_y = _collect_bounds(nodes, primitives)
    for c in connectors:
        for p in c.get("points", []):
            min_x = min(min_x, p[0]); max_x = max(max_x, p[0])
            min_y = min(min_y, p[1]); max_y = max(max_y, p[1])
    page_w = max((max_x - min_x) * _SCALE, 1.0) + 2 * _MIN_MARGIN_IN
    page_h = max((max_y - min_y) * _SCALE, 1.0) + 2 * _MIN_MARGIN_IN

    # Trasformazione canvas -> pollici Visio (asse Y invertito).
    def tx(x): return (x - min_x) * _SCALE + _MIN_MARGIN_IN
    def ty(y): return (max_y - y) * _SCALE + _MIN_MARGIN_IN

    shapes_xml = []
    shape_id = 1

    def next_id():
        nonlocal shape_id
        sid = shape_id
        shape_id += 1
        return sid

    def char_section(size_pt, color, bold=False):
        return (f'<Section N="Character"><Row IX="0">'
                f'<Cell N="Size" V="{size_pt/72:.4f}" U="PT"/>'
                f'<Cell N="Color" V="{_hex_to_rgb_fraction(color)}"/>'
                f'<Cell N="Style" V="{1 if bold else 0}"/>'
                f'</Row></Section>')

    # --- Punti di aggancio per nodo (dai connettori strutturati) --------------
    # Ogni estremita' di cavo diventa un connection point sul riquadro del
    # dispositivo (con quadratino colorato visibile) a cui il cavo e' incollato.
    node_by_id = {n["id"]: n for n in nodes}
    node_anchors = {}   # id -> [ {lx, ly (pollici, locali Y-su), color} ]
    anchor_index = {}   # (id, round(x), round(y)) -> indice riga Connection

    def _register_anchor(node_id, pt, color):
        n = node_by_id.get(node_id)
        if not n:
            return None
        key = (node_id, round(pt[0]), round(pt[1]))
        if key in anchor_index:
            return anchor_index[key]
        w_px = float(n.get("w") or 80.0); h_px = float(n.get("h") or 30.0)
        # Coordinate locali del riquadro (origine in basso a sinistra, Y su).
        lx = (pt[0] - (n["x"] - w_px / 2)) * _SCALE
        ly = ((n["y"] + h_px / 2) - pt[1]) * _SCALE
        lst = node_anchors.setdefault(node_id, [])
        anchor_index[key] = len(lst)
        lst.append({"lx": lx, "ly": ly, "color": color})
        return anchor_index[key]

    conn_glue = []   # (connettore) -> {sid dopo emissione, from/to id, idx aggancio}
    for c in connectors:
        pts = c.get("points") or []
        if len(pts) < 2:
            continue
        color = c.get("color") or "#78909c"
        conn_glue.append({
            "c": c,
            "from_idx": _register_anchor(c.get("from"), pts[0], color),
            "to_idx": _register_anchor(c.get("to"), pts[-1], color),
        })

    # --- Riquadri dispositivo -------------------------------------------------
    positions = {}
    node_shape_id = {}
    sq = 5 * _SCALE  # lato del quadratino di aggancio (5px canvas)
    for n in nodes:
        w_px = float(n.get("w") or 80.0); h_px = float(n.get("h") or 30.0)
        box_w = max(w_px * _SCALE, 0.3); box_h = max(h_px * _SCALE, 0.15)
        px, py = tx(n["x"]), ty(n["y"])
        positions[n["id"]] = (px, py)
        sid = next_id()
        node_shape_id[n["id"]] = sid
        parts = [n.get("label") or n.get("ip") or str(n["id"]),
                 n.get("model") or "", n.get("ip") or ""]
        text = "\n".join(p for p in parts if p)
        fill = _hex_to_rgb_fraction(n.get("fill") or "#E8E4FB")
        border = _hex_to_rgb_fraction(n.get("border") or "#6A5FC1")

        anchors = node_anchors.get(n["id"]) or []
        # Connection section: un punto per estremita' di cavo sul bordo, in
        # coordinate locali -> i connettori incollati seguono il riquadro.
        conn_rows = "".join(
            f'<Row IX="{i}"><Cell N="X" V="{a["lx"]:.4f}"/><Cell N="Y" V="{a["ly"]:.4f}"/></Row>'
            for i, a in enumerate(anchors))
        conn_section = f'<Section N="Connection">{conn_rows}</Section>' if anchors else ''
        # Quadratini di aggancio: FIGLI del gruppo (coordinate locali), quindi
        # seguono il dispositivo quando l'utente lo trascina in Visio. Come
        # nell'app sono appena DENTRO il bordo del riquadro (inset verso il
        # centro sul lato d'aggancio).
        children = []
        inset = 3.5 * _SCALE
        for a in anchors:
            csid = next_id()
            cx_l, cy_l = a["lx"], a["ly"]
            if cx_l <= 0.02:            cx_l += inset
            elif cx_l >= box_w - 0.02:  cx_l -= inset
            if cy_l <= 0.02:            cy_l += inset
            elif cy_l >= box_h - 0.02:  cy_l -= inset
            children.append(f'''
            <Shape ID="{csid}" Type="Shape">
              <Cell N="PinX" V="{cx_l:.4f}"/>
              <Cell N="PinY" V="{cy_l:.4f}"/>
              <Cell N="Width" V="{sq:.4f}"/>
              <Cell N="Height" V="{sq:.4f}"/>
              <Cell N="LocPinX" V="{sq/2:.4f}"/>
              <Cell N="LocPinY" V="{sq/2:.4f}"/>
              <Cell N="FillForegnd" V="{_hex_to_rgb_fraction(a["color"])}"/>
              <Cell N="LinePattern" V="0"/>
              <Section N="Geometry" IX="0">
                <Row T="MoveTo" IX="1"><Cell N="X" V="0"/><Cell N="Y" V="0"/></Row>
                <Row T="LineTo" IX="2"><Cell N="X" V="{sq:.4f}"/><Cell N="Y" V="0"/></Row>
                <Row T="LineTo" IX="3"><Cell N="X" V="{sq:.4f}"/><Cell N="Y" V="{sq:.4f}"/></Row>
                <Row T="LineTo" IX="4"><Cell N="X" V="0"/><Cell N="Y" V="{sq:.4f}"/></Row>
                <Row T="LineTo" IX="5"><Cell N="X" V="0"/><Cell N="Y" V="0"/></Row>
              </Section>
            </Shape>''')
        shape_type = "Group" if children else "Shape"
        # DisplayMode=1: il riquadro del gruppo dietro ai membri, cosi' i
        # quadratini di aggancio (figli) restano visibili sopra il riempimento.
        group_cells = '<Cell N="DisplayMode" V="1"/>' if children else ''
        children_xml = f'<Shapes>{"".join(children)}</Shapes>' if children else ''
        shapes_xml.append(f'''
        <Shape ID="{sid}" Type="{shape_type}">
          <Cell N="PinX" V="{px:.4f}"/>
          <Cell N="PinY" V="{py:.4f}"/>
          <Cell N="Width" V="{box_w:.4f}"/>
          <Cell N="Height" V="{box_h:.4f}"/>
          <Cell N="LocPinX" V="{box_w/2:.4f}"/>
          <Cell N="LocPinY" V="{box_h/2:.4f}"/>
          <Cell N="FillForegnd" V="{fill}"/>
          <Cell N="LineColor" V="{border}"/>
          <Cell N="LineWeight" V="0.01"/>
          {group_cells}
          {char_section(_pt(12), "#1a2430")}
          {conn_section}
          <Section N="Geometry" IX="0">
            <Row T="MoveTo" IX="1"><Cell N="X" V="0"/><Cell N="Y" V="0"/></Row>
            <Row T="LineTo" IX="2"><Cell N="X" V="{box_w:.4f}"/><Cell N="Y" V="0"/></Row>
            <Row T="LineTo" IX="3"><Cell N="X" V="{box_w:.4f}"/><Cell N="Y" V="{box_h:.4f}"/></Row>
            <Row T="LineTo" IX="4"><Cell N="X" V="0"/><Cell N="Y" V="{box_h:.4f}"/></Row>
            <Row T="LineTo" IX="5"><Cell N="X" V="0"/><Cell N="Y" V="0"/></Row>
          </Section>
          <Text>{escape(text)}</Text>
          {children_xml}
        </Shape>''')

    # --- Percorso generico (polilinea/poligono) in coordinate pagina ---------
    def path_shape(points, line_color=None, line_w_px=1.5, dash=False,
                   fill=None, fill_alpha=1.0, closed=False):
        pts = [(tx(p[0]), ty(p[1])) for p in points]
        xs = [p[0] for p in pts]; ys = [p[1] for p in pts]
        x0, y0 = min(xs), min(ys)
        w = max(max(xs) - x0, 0.01); h = max(max(ys) - y0, 0.01)
        sid = next_id()
        rows = []
        for i, (x, y) in enumerate(pts):
            t = "MoveTo" if i == 0 else "LineTo"
            rows.append(f'<Row T="{t}" IX="{i+1}"><Cell N="X" V="{x-x0:.4f}"/><Cell N="Y" V="{y-y0:.4f}"/></Row>')
        cells = [
            f'<Cell N="PinX" V="{x0:.4f}"/>', f'<Cell N="PinY" V="{y0:.4f}"/>',
            f'<Cell N="Width" V="{w:.4f}"/>', f'<Cell N="Height" V="{h:.4f}"/>',
            '<Cell N="LocPinX" V="0"/>', '<Cell N="LocPinY" V="0"/>',
        ]
        if line_color:
            cells.append(f'<Cell N="LineColor" V="{_hex_to_rgb_fraction(line_color)}"/>')
            cells.append(f'<Cell N="LineWeight" V="{max(line_w_px * _SCALE, 0.008):.4f}"/>')
            if dash:
                cells.append('<Cell N="LinePattern" V="2"/>')
        else:
            cells.append('<Cell N="LinePattern" V="0"/>')
        geo_cells = ''
        if fill:
            cells.append(f'<Cell N="FillForegnd" V="{_hex_to_rgb_fraction(fill)}"/>')
            if fill_alpha < 1.0:
                cells.append(f'<Cell N="FillForegndTrans" V="{1.0 - fill_alpha:.3f}"/>')
        else:
            geo_cells = '<Cell N="NoFill" V="1"/>'
        shapes_xml.append(f'''
        <Shape ID="{sid}" Type="Shape">
          {''.join(cells)}
          <Section N="Geometry" IX="0">
            {geo_cells}
            {''.join(rows)}
          </Section>
        </Shape>''')

    def text_shape(cx, cy, text, color, size_px, bold, w_px):
        sid = next_id()
        w = max((w_px or len(text) * size_px * 0.6) * _SCALE, 0.1)
        h = max(size_px * 1.4 * _SCALE, 0.08)
        pt = _pt(size_px)
        shapes_xml.append(f'''
        <Shape ID="{sid}" Type="Shape">
          <Cell N="PinX" V="{tx(cx):.4f}"/>
          <Cell N="PinY" V="{ty(cy):.4f}"/>
          <Cell N="Width" V="{w:.4f}"/>
          <Cell N="Height" V="{h:.4f}"/>
          <Cell N="LocPinX" V="{w/2:.4f}"/>
          <Cell N="LocPinY" V="{h/2:.4f}"/>
          <Cell N="LinePattern" V="0"/>
          <Cell N="FillPattern" V="0"/>
          {char_section(pt, color, bold)}
          <Text>{escape(text)}</Text>
        </Shape>''')

    # --- Cavi: connettori 1-D CONTINUI incollati ai connection point ----------
    # Veri connettori (Begin/End + glue) cosi' l'utente puo' manipolare la
    # mappa in Visio: spostando un dispositivo i cavi restano agganciati e si
    # stirano (la geometria e' espressa in FORMULE relative a Width/Height).
    # NIENTE ObjType=2: il routing automatico di Visio riposizionava i cavi in
    # modo imprevedibile al minimo tocco di un'etichetta; senza, il percorso
    # ortogonale resta quello dell'app e si deforma solo proporzionalmente.
    connects_xml = []
    for g in conn_glue:
        c = g["c"]
        pts = [(tx(p[0]), ty(p[1])) for p in c["points"]]
        xs = [p[0] for p in pts]; ys = [p[1] for p in pts]
        x0, y0 = min(xs), min(ys)
        w = max(max(xs) - x0, 0.01); h = max(max(ys) - y0, 0.01)
        sid = next_id()
        rows = []
        for i, (x, y) in enumerate(pts):
            fx = (x - x0) / w; fy = (y - y0) / h
            rows.append(
                f'<Row T="{"MoveTo" if i == 0 else "LineTo"}" IX="{i+1}">'
                f'<Cell N="X" V="{x-x0:.4f}" F="Width*{fx:.6f}"/>'
                f'<Cell N="Y" V="{y-y0:.4f}" F="Height*{fy:.6f}"/></Row>')
        dash_cell = '<Cell N="LinePattern" V="2"/>' if c.get("dash") else ''
        shapes_xml.append(f'''
        <Shape ID="{sid}" Type="Shape">
          <Cell N="BeginX" V="{pts[0][0]:.4f}"/>
          <Cell N="BeginY" V="{pts[0][1]:.4f}"/>
          <Cell N="EndX" V="{pts[-1][0]:.4f}"/>
          <Cell N="EndY" V="{pts[-1][1]:.4f}"/>
          <Cell N="PinX" V="{x0:.4f}"/>
          <Cell N="PinY" V="{y0:.4f}"/>
          <Cell N="Width" V="{w:.4f}"/>
          <Cell N="Height" V="{h:.4f}"/>
          <Cell N="LocPinX" V="0"/>
          <Cell N="LocPinY" V="0"/>
          <Cell N="LineColor" V="{_hex_to_rgb_fraction(c.get("color"))}"/>
          <Cell N="LineWeight" V="{max(float(c.get("width", 1.8)) * _SCALE, 0.008):.4f}"/>
          {dash_cell}
          <Section N="Geometry" IX="0">
            <Cell N="NoFill" V="1"/>
            {''.join(rows)}
          </Section>
        </Shape>''')
        # Glue: BeginX/EndX -> Connections.Xn dei riquadri (FromPart 9=inizio,
        # 12=fine; ToPart 100+i = i-esimo connection point della forma).
        for cell, part, node_key, idx_key in (("BeginX", 9, "from", "from_idx"),
                                              ("EndX", 12, "to", "to_idx")):
            nid = node_shape_id.get(c.get(node_key))
            idx = g.get(idx_key)
            if nid is not None and idx is not None:
                connects_xml.append(
                    f'<Connect FromSheet="{sid}" FromCell="{cell}" FromPart="{part}" '
                    f'ToSheet="{nid}" ToCell="Connections.X{idx+1}" ToPart="{100+idx}"/>')

    if primitives:
        # Ordine di disegno = ordine del canvas: poligoni/rettangoli/linee/testi
        # arrivano già sequenziati dal registratore; si mantiene la z-order
        # relativa disegnando prima i riempimenti, poi le linee, poi i testi
        # (i riquadri dispositivo sono già stati emessi per primi, come sul
        # canvas dove vis.js disegna i nodi prima dell'overlay... in realtà
        # l'overlay è sopra i nodi, quindi l'ordine qui coincide).
        for p in primitives.get("polys", []):
            if len(p.get("points", [])) > 2:
                path_shape(p["points"], fill=p.get("fill"),
                           fill_alpha=float(p.get("alpha", 1.0)), closed=True)
        for r in primitives.get("rects", []):
            pts = [[r["x"], r["y"]], [r["x"] + r["w"], r["y"]],
                   [r["x"] + r["w"], r["y"] + r["h"]], [r["x"], r["y"] + r["h"]],
                   [r["x"], r["y"]]]
            path_shape(pts, fill=r.get("fill"), fill_alpha=float(r.get("alpha", 1.0)), closed=True)
        for ln in primitives.get("lines", []):
            if len(ln.get("points", [])) > 1:
                path_shape(ln["points"], line_color=ln.get("color") or "#78909c",
                           line_w_px=float(ln.get("width", 1.5)),
                           dash=bool(ln.get("dash")))
        for t in primitives.get("texts", []):
            if t.get("text"):
                text_shape(t["x"], t["y"], t["text"], t.get("color") or "#455a64",
                           float(t.get("size", 10)), bool(t.get("bold")),
                           float(t.get("w") or 0))
    else:
        # Mappa classica: una linea retta per arco, con etichetta.
        for e in edges:
            if e.get("source") not in positions or e.get("target") not in positions:
                continue
            spx, spy = positions[e["source"]]
            dpx, dpy = positions[e["target"]]
            sid = next_id()
            color = _hex_to_rgb_fraction(e.get("color"))
            label = e.get("label") or ""
            w = dpx - spx
            h = dpy - spy
            shapes_xml.append(f'''
        <Shape ID="{sid}" Type="Shape">
          <Cell N="PinX" V="{spx:.4f}"/>
          <Cell N="PinY" V="{spy:.4f}"/>
          <Cell N="Width" V="{max(abs(w), 0.01):.4f}"/>
          <Cell N="Height" V="{max(abs(h), 0.01):.4f}"/>
          <Cell N="LocPinX" V="0"/>
          <Cell N="LocPinY" V="0"/>
          <Cell N="LineColor" V="{color}"/>
          <Cell N="LineWeight" V="0.02"/>
          <Section N="Geometry" IX="0">
            <Cell N="NoFill" V="1"/>
            <Row T="MoveTo" IX="1"><Cell N="X" V="0"/><Cell N="Y" V="0"/></Row>
            <Row T="LineTo" IX="2"><Cell N="X" V="{w:.4f}"/><Cell N="Y" V="{h:.4f}"/></Row>
          </Section>
          <Text>{escape(label)}</Text>
        </Shape>''')

    connects_block = f'\n  <Connects>{"".join(connects_xml)}</Connects>' if connects_xml else ''
    page_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<PageContents xmlns="http://schemas.microsoft.com/office/visio/2012/main" xml:space="preserve">
  <Shapes>{"".join(shapes_xml)}
  </Shapes>{connects_block}
</PageContents>'''

    # Visio (desktop e online) considera "danneggiato" un pacchetto senza le
    # parti standard: docProps (core/app/custom) e visio/windows.xml, oltre a un
    # document.xml conforme (PageSheet NON è un figlio valido di VisioDocument).
    content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/visio/document.xml" ContentType="application/vnd.ms-visio.drawing.main+xml"/>
  <Override PartName="/visio/pages/pages.xml" ContentType="application/vnd.ms-visio.pages+xml"/>
  <Override PartName="/visio/pages/page1.xml" ContentType="application/vnd.ms-visio.page+xml"/>
  <Override PartName="/visio/windows.xml" ContentType="application/vnd.ms-visio.windows+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
  <Override PartName="/docProps/custom.xml" ContentType="application/vnd.openxmlformats-officedocument.custom-properties+xml"/>
</Types>'''

    root_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.microsoft.com/visio/2010/relationships/document" Target="visio/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
  <Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties" Target="docProps/custom.xml"/>
</Relationships>'''

    document_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<VisioDocument xmlns="http://schemas.microsoft.com/office/visio/2012/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xml:space="preserve"/>'''

    document_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.microsoft.com/visio/2010/relationships/pages" Target="pages/pages.xml"/>
  <Relationship Id="rId2" Type="http://schemas.microsoft.com/visio/2010/relationships/windows" Target="windows.xml"/>
</Relationships>'''

    windows_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Windows xmlns="http://schemas.microsoft.com/office/visio/2012/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" ClientWidth="1600" ClientHeight="900" xml:space="preserve">
  <Window ID="0" WindowType="Drawing" WindowState="1073741824" ContainerType="Page" Page="0" ViewScale="1" ViewCenterX="{page_w/2:.4f}" ViewCenterY="{page_h/2:.4f}"/>
</Windows>'''

    core_props = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>SentinelNet Map</dc:title>
  <dc:creator>SentinelNet</dc:creator>
</cp:coreProperties>'''

    app_props = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>Microsoft Visio</Application>
</Properties>'''

    custom_props = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="IsMetric"><vt:bool>false</vt:bool></property>
</Properties>'''

    pages_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Pages xmlns="http://schemas.microsoft.com/office/visio/2012/main"
       xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <Page ID="0" NameU="Page-1" Name="SentinelNet Map">
    <PageSheet>
      <Cell N="PageWidth" V="{page_w:.4f}"/>
      <Cell N="PageHeight" V="{page_h:.4f}"/>
      <Cell N="PageScale" V="1" U="IN_F"/>
      <Cell N="DrawingScale" V="1" U="IN_F"/>
      <Cell N="DrawingSizeType" V="3"/>
      <Cell N="DrawingScaleType" V="0"/>
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
        z.writestr("docProps/core.xml", core_props)
        z.writestr("docProps/app.xml", app_props)
        z.writestr("docProps/custom.xml", custom_props)
        z.writestr("visio/document.xml", document_xml)
        z.writestr("visio/windows.xml", windows_xml)
        z.writestr("visio/_rels/document.xml.rels", document_rels)
        z.writestr("visio/pages/pages.xml", pages_xml)
        z.writestr("visio/pages/_rels/pages.xml.rels", pages_rels)
        z.writestr("visio/pages/page1.xml", page_xml)
    return buf.getvalue()


if __name__ == "__main__":
    # Validazione minima: nodi + arco classico E primitive minimaliste ->
    # vsdx apribile come zip e XML valido.
    import xml.dom.minidom as minidom

    fake_nodes = [
        {"id": "10.0.0.1", "label": "SW-CORE-1", "model": "C9300", "ip": "10.0.0.1",
         "x": 0, "y": 0, "w": 160, "h": 60, "fill": "#dbeefa", "border": "#5a7a94"},
        {"id": "10.0.0.2", "label": "SW-ACCESS-2", "model": "C2960", "ip": "10.0.0.2",
         "x": 400, "y": 200, "w": 160, "h": 60},
    ]
    fake_edges = [
        {"source": "10.0.0.1", "target": "10.0.0.2", "label": "Po1", "color": "#FFB84D"},
    ]
    fake_prims = {
        "lines": [],
        "polys": [{"points": [[230, 90], [260, 90], [260, 120], [230, 120], [230, 90]],
                   "fill": "#8B4513", "alpha": 0.16}],
        "rects": [{"x": 200, "y": 60, "w": 30, "h": 14, "fill": "#ffffff", "alpha": 1}],
        "texts": [{"x": 215, "y": 67, "text": "po1", "color": "#8B4513",
                   "size": 10, "bold": True, "w": 24}],
    }
    fake_conns = [
        {"from": "10.0.0.1", "to": "10.0.0.2",
         "points": [[80, 0], [240, 0], [240, 200], [320, 200]],
         "color": "#8B4513", "width": 1.8, "dash": False},
        {"from": "10.0.0.1", "to": "10.0.0.2",
         "points": [[80, 11], [251, 11], [251, 211], [320, 211]],
         "color": "#8B4513", "width": 1.8, "dash": False},
    ]
    for prims, conns in ((None, None), (fake_prims, fake_conns)):
        data = build_vsdx(fake_nodes, fake_edges, prims, conns)
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()
            required = [
                "[Content_Types].xml", "_rels/.rels", "visio/document.xml",
                "visio/_rels/document.xml.rels", "visio/pages/pages.xml",
                "visio/pages/_rels/pages.xml.rels", "visio/pages/page1.xml",
                "visio/windows.xml", "docProps/core.xml", "docProps/app.xml",
                "docProps/custom.xml",
            ]
            for part in required:
                assert part in names, f"Parte mancante: {part}"
                minidom.parseString(z.read(part))  # solleva se XML non valido
            if conns:
                page = z.read("visio/pages/page1.xml").decode()
                assert '<Connects>' in page and 'Connections.X1' in page
                assert 'ObjType' not in page  # niente routing automatico
                assert page.count('Type="Group"') == 2  # riquadri con quadratini
        print(f"OK ({'primitives' if prims else 'classic'}): vsdx valido, {len(data)} bytes.")
