"""Mark, wordmark and lockups.

Proportions (m = the mark's module, its arm width):
- Wordmark: "catraca" in Atkinson Hyperlegible Next SemiBold (600), tracking
  -20/1000 em, outlined.
- Horizontal lockup: the hub's diameter (3m) equals the x-height; the axis
  sits on the middle of the x-height; the gap from the tip of the right arm to
  the "c" is the hub's radius (1.5m).
- Stacked lockup: the mark at twice that module, centered on its bounding box
  over the word, 3m (of the word's module) above the x-height.
"""
from geometry import mark_bounds, mark_path, num
from typeset import ink_bounds, text_path, x_height

WORD = "catraca"
WGHT = 600
TRACK = -20
XH_RATIO = 496 / 1000  # Atkinson Hyperlegible Next x-height / em

def size_for_module(m):
    """Font size whose x-height equals the hub diameter, 3m."""
    return 3 * m / XH_RATIO

def wordmark_parts(x_ink_left, baseline, size):
    ink = ink_bounds(WORD, wght=WGHT, size=size, tracking=TRACK)
    d, _ = text_path(WORD, x=x_ink_left - ink[0], y=baseline, wght=WGHT, size=size, tracking=TRACK)
    return d, (x_ink_left, baseline + ink[1], x_ink_left + ink[2] - ink[0], baseline + ink[3])

def horizontal(m, ox=0.0, oy=0.0):
    """Paths and box for the horizontal lockup with its top-left corner at (ox, oy)."""
    l, t, r, b = mark_bounds(m)
    ax, ay = ox - l, oy - t
    size = size_for_module(m)
    baseline = ay + 1.5 * m
    word, wbox = wordmark_parts(ax + r + 1.5 * m, baseline, size)
    return dict(mark=mark_path(ax, ay, m), word=word,
                box=(ox, oy, wbox[2], ay + b), axis=(ax, ay), size=size, baseline=baseline)

def stacked(m, ox=0.0, oy=0.0, mark_scale=2.0):
    size = size_for_module(m)
    ink = ink_bounds(WORD, wght=WGHT, size=size, tracking=TRACK)
    word_w = ink[2] - ink[0]
    M = m * mark_scale
    l, t, r, b = mark_bounds(M)
    mark_w = r - l
    width = max(word_w, mark_w)
    cx = ox + width / 2
    ax = cx - (l + r) / 2
    ay = oy - t
    xh_top = ay + b + 3 * m
    baseline = xh_top + 3 * m
    word, wbox = wordmark_parts(cx - word_w / 2, baseline, size)
    return dict(mark=mark_path(ax, ay, M), word=word,
                box=(ox, oy, ox + width, wbox[3]), axis=(ax, ay), size=size, baseline=baseline)

def svg_doc(box, body, label, pad=0.0):
    x0, y0, x1, y1 = box
    x0, y0, x1, y1 = x0 - pad, y0 - pad, x1 + pad, y1 + pad
    w, h = x1 - x0, y1 - y0
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{num(x0)} {num(y0)} {num(w)} {num(h)}" '
            f'width="{num(w)}" height="{num(h)}" role="img" aria-label="{label}">'
            f'<title>{label}</title>{body}</svg>\n')

def mark_svg(fill, size=24):
    # 24-unit grid, m = 4, axis at (9.5, 12): the bounding box is centered.
    k = size / 24
    body = f'<path fill="{fill}" d="{mark_path(9.5 * k, 12 * k, 4 * k)}"/>'
    return svg_doc((0, 0, size, size), body, "Catraca")

def lockup_svg(kind, fill, m=12):
    L = horizontal(m) if kind == "horizontal" else stacked(m)
    body = f'<g fill="{fill}"><path d="{L["mark"]}"/><path d="{L["word"]}"/></g>'
    return svg_doc(L["box"], body, "Catraca")

def wordmark_svg(fill, m=12):
    size = size_for_module(m)
    ink = ink_bounds(WORD, wght=WGHT, size=size, tracking=TRACK)
    d, box = wordmark_parts(0, -ink[1], size)
    return svg_doc(box, f'<path fill="{fill}" d="{d}"/>', "Catraca")
