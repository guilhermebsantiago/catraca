"""Outline text with Atkinson Hyperlegible Next and Mono (SIL OFL 1.1).

Shaping is done by HarfBuzz (kerning included) and outlines come from
fontTools, so every asset carries its text as paths and renders the same
everywhere, including GitHub's image proxy. The fonts are downloaded from the
google/fonts repository into build/.fonts on first use.
"""
import os
import urllib.request

import uharfbuzz as hb
from fontTools.pens.boundsPen import BoundsPen
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, ".fonts")
SOURCES = {
    "sans": "https://raw.githubusercontent.com/google/fonts/main/ofl/atkinsonhyperlegiblenext/AtkinsonHyperlegibleNext%5Bwght%5D.ttf",
    "mono": "https://raw.githubusercontent.com/google/fonts/main/ofl/atkinsonhyperlegiblemono/AtkinsonHyperlegibleMono%5Bwght%5D.ttf",
}
_fonts = {}

def _load(family):
    if family not in _fonts:
        os.makedirs(CACHE, exist_ok=True)
        path = os.path.join(CACHE, family + ".ttf")
        if not os.path.exists(path):
            urllib.request.urlretrieve(SOURCES[family], path)
        _fonts[family] = (TTFont(path), hb.Face(hb.Blob.from_file_path(path)))
    return _fonts[family]

def _num(v, nd):
    s = f"{v:.{nd}f}"
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s

def shape(text, family="sans", wght=600, size=100.0, tracking=0):
    """Glyph names and pen positions (in px) for text; tracking in 1/1000 em."""
    tt, face = _load(family)
    font = hb.Font(face)
    font.set_variations({"wght": wght})
    buf = hb.Buffer()
    buf.add_str(text)
    buf.guess_segment_properties()
    hb.shape(font, buf, {"kern": True, "liga": True})
    scale = size / tt["head"].unitsPerEm
    order = tt.getGlyphOrder()
    pen_x, glyphs = 0, []
    n = len(buf.glyph_infos)
    for i, (info, pos) in enumerate(zip(buf.glyph_infos, buf.glyph_positions)):
        glyphs.append((order[info.codepoint], (pen_x + pos.x_offset) * scale, pos.y_offset * scale))
        pen_x += pos.x_advance + (tracking if i < n - 1 else 0)
    return glyphs, pen_x * scale

def text_path(text, x=0.0, y=0.0, family="sans", wght=600, size=100.0, tracking=0, nd=2):
    """(path data, advance width) with the baseline at y."""
    tt, _ = _load(family)
    gs = tt.getGlyphSet(location={"wght": wght})
    scale = size / tt["head"].unitsPerEm
    glyphs, width = shape(text, family, wght, size, tracking)
    parts = []
    for name, gx, gy in glyphs:
        pen = SVGPathPen(gs, ntos=lambda v: _num(v, nd))
        gs[name].draw(TransformPen(pen, (scale, 0, 0, -scale, x + gx, y - gy)))
        parts.append(pen.getCommands())
    return "".join(parts), width

def ink_bounds(text, family="sans", wght=600, size=100.0, tracking=0):
    """Ink box (left, top, right, bottom) relative to the pen origin, y down."""
    tt, _ = _load(family)
    gs = tt.getGlyphSet(location={"wght": wght})
    scale = size / tt["head"].unitsPerEm
    glyphs, _ = shape(text, family, wght, size, tracking)
    box = None
    for name, gx, gy in glyphs:
        bp = BoundsPen(gs)
        gs[name].draw(bp)
        if bp.bounds is None:
            continue
        x0, y0, x1, y1 = bp.bounds
        b = (gx + x0 * scale, -(y1 * scale) - gy, gx + x1 * scale, -(y0 * scale) - gy)
        box = b if box is None else (min(box[0], b[0]), min(box[1], b[1]), max(box[2], b[2]), max(box[3], b[3]))
    return box

def x_height(size, family="sans"):
    tt, _ = _load(family)
    return tt["OS/2"].sxHeight * size / tt["head"].unitsPerEm

class GlyphBook:
    """Text as <use> references to glyph outlines defined once per file.

    Keeps text-heavy SVGs small: each glyph is outlined once, in font units,
    and every occurrence is a reference.
    """
    def __init__(self):
        self.glyphs = {}

    def _id(self, family, wght, name):
        safe = "".join(ch if ch.isalnum() else "_" for ch in name)
        return f"{family[0]}{wght}-{safe}"

    def text(self, text, x, y, size, fill, family="sans", wght=400, tracking=0, anchor="start"):
        tt, _ = _load(family)
        upem = tt["head"].unitsPerEm
        glyphs, width = shape(text, family, wght, upem, tracking)   # positions in font units
        k = size / upem
        if anchor == "middle":
            x -= width * k / 2
        elif anchor == "end":
            x -= width * k
        gs = None
        uses = []
        for name, gx, gy in glyphs:
            gid = self._id(family, wght, name)
            if gid not in self.glyphs:
                gs = gs or tt.getGlyphSet(location={"wght": wght})
                pen = SVGPathPen(gs, ntos=lambda v: _num(v, 0))
                gs[name].draw(TransformPen(pen, (1, 0, 0, -1, 0, 0)))
                self.glyphs[gid] = pen.getCommands()
            if self.glyphs[gid]:
                uses.append(f'<use href="#{gid}" x="{_num(gx, 0)}"/>')
        return (f'<g fill="{fill}" transform="translate({_num(x, 2)} {_num(y, 2)}) scale({_num(k, 5)})">'
                + "".join(uses) + "</g>"), width * k

    def defs(self):
        return "<defs>" + "".join(f'<path id="{i}" d="{d}"/>' for i, d in self.glyphs.items() if d) + "</defs>"
