"""Build Catraca's identity assets into docs/brand.

    pip install fonttools uharfbuzz pillow
    python build.py          # SVGs, tokens.css, tokens.json; prints contrast ratios
    npm install
    node render.mjs          # optimizes the SVGs, renders the PNGs (Edge, or BROWSER_CHANNEL=chrome)
    python build.py --png    # palette-quantizes the PNGs (flat color, no visible change)

The committed SVGs are the deliverables; this script keeps their geometry,
outlined text and colors exact and consistent with each other.
"""
import json
import math
import os

from color import contrast, hex_oklch, lin_to_oklab, hex_to_lin
from geometry import mark_bounds, mark_path, num
from graphics import THEMES, lane, legend
from logos import horizontal, lockup_svg, mark_svg, wordmark_svg
from palette import ACTION_COLORS as A, ACTIONS, NEUTRALS as N, NEUTRALS_DARK as ND
from typeset import GlyphBook

OUT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAGLINE = "Anti-abuse engine for platforms that send email"
# Decisions as they leave the rotor: mostly allow, as on a healthy platform.
STREAM = "aaaafaaaaasBaaaaataaaaaaahaaaaaaabaaaaaafaaaasHaaaaaataaaaabaaaa"

def write(rel, text):
    path = os.path.join(OUT, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(f"{os.path.getsize(path):>7}  {rel}")

def doc(w, h, body, title, book=None):
    defs = book.defs() if book and book.glyphs else ""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {num(w)} {num(h)}" width="{num(w)}" '
            f'height="{num(h)}" role="img" aria-label="{title}"><title>{title}</title>{defs}{body}</svg>\n')

# Logos -----------------------------------------------------------------------

def logos():
    for tone, fill in (("on-light", N["ink"]), ("on-dark", N["paper"])):
        write(f"logo/mark-{tone}.svg", mark_svg(fill))
        write(f"logo/horizontal-{tone}.svg", lockup_svg("horizontal", fill))
        write(f"logo/stacked-{tone}.svg", lockup_svg("stacked", fill))
        write(f"logo/wordmark-{tone}.svg", wordmark_svg(fill))

def favicon():
    # The mark alone at m = 4.4 on the 24 grid (10% larger than mark.svg, so it
    # fills a 16 px tab icon), ink on light browser chrome, paper on dark.
    m = 4.4
    l, t, r, b = mark_bounds(m)
    ax = 12 - (l + r) / 2
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
           f'<style>path{{fill:{N["ink"]}}}@media (prefers-color-scheme:dark){{path{{fill:{N["paper"]}}}}}</style>'
           f'<path d="{mark_path(ax, 12, m)}"/></svg>\n')
    write("favicon.svg", svg)

def app_icon():
    # Paper rotor on an ink tile with 22.5% corners; the mark's bounding box is
    # centered and is 62% of the tile's height.
    size = 512
    m = size * 0.62 / (2 * mark_bounds(1)[3])
    l, t, r, b = mark_bounds(m)
    ax = size / 2 - (l + r) / 2
    body = (f'<rect width="{size}" height="{size}" rx="{num(size * 0.225)}" fill="{N["ink"]}"/>'
            f'<path fill="{N["paper"]}" d="{mark_path(ax, size / 2, m)}"/>')
    write("icon.svg", doc(size, size, body, "Catraca"))

# Banner and social preview ----------------------------------------------------

def banner(theme):
    T = THEMES[theme]
    book = GlyphBook()
    W, H, m, pad = 1600, 400, 24, 120
    l, t, r, b = mark_bounds(m)
    group_h = -t + 2.25 * m + 2.5 * m       # lockup top to the legend's baseline
    L = horizontal(m, ox=pad, oy=(H - group_h) / 2)
    ax, ay = L["axis"]
    stream, ly = lane(theme, ax, ay, m, 0, W, STREAM)
    word_x = ax + 4.5 * m
    tag, _ = book.text(TAGLINE, W - pad, L["baseline"], 30, T["text2"], anchor="end")
    leg, _ = legend(book, theme, word_x, ly + 2.5 * m, 20, gap=28)
    body = (f'<rect width="{W}" height="{H}" rx="16" fill="{T["bg"]}"/>{stream}'
            f'<path fill="{T["fg"]}" d="{L["word"]}"/>{tag}{leg}')
    write(f"readme-banner-{theme}.svg", doc(W, H, body, "Catraca: " + TAGLINE.lower(), book))

def social(theme="dark"):
    T = THEMES[theme]
    book = GlyphBook()
    W, H, m, pad = 1280, 640, 30, 96
    L = horizontal(m, ox=pad, oy=128)
    ax, ay = L["axis"]
    stream, ly = lane(theme, ax, ay, m, 0, W, STREAM)
    x0 = ax + 4.5 * m
    h1, _ = book.text("Anti-abuse engine for", x0, ly + 112, 46, T["fg"], wght=500, tracking=-10)
    h2, _ = book.text("platforms that send email", x0, ly + 170, 46, T["fg"], wght=500, tracking=-10)
    leg, _ = legend(book, theme, x0, H - 72, 21)
    body = (f'<rect width="{W}" height="{H}" fill="{T["bg"]}"/>{stream}'
            f'<path fill="{T["fg"]}" d="{L["word"]}"/>{h1}{h2}{leg}')
    write("social-preview.svg", doc(W, H, body, "Catraca: " + TAGLINE.lower(), book))

# Figures for brand.md ---------------------------------------------------------

def construction():
    book = GlyphBook()
    u, ox, oy = 18, 64, 40                   # px per grid unit, grid origin
    W, H = ox + 24 * u + 300, oy + 24 * u + 64
    ax, ay, m = ox + 9.5 * u, oy + 12 * u, 4 * u
    ink, steel, rail = N["ink"], N["steel"], N["rail"]
    g = [f'<rect width="{W}" height="{H}" rx="12" fill="{N["paper"]}"/>']
    grid = "".join(f'M{num(ox + i * u)} {oy}v{24 * u}M{ox} {num(oy + i * u)}h{24 * u}' for i in range(25))
    g.append(f'<path stroke="{rail}" d="{grid}"/>')
    g.append(f'<rect x="{ox}" y="{oy}" width="{24 * u}" height="{24 * u}" fill="none" stroke="{steel}"/>')
    g.append(f'<path fill="{ink}" fill-opacity=".09" d="{mark_path(ax, ay, m)}"/>')
    g.append(f'<circle cx="{num(ax)}" cy="{num(ay)}" r="{num(3 * m)}" fill="none" stroke="{steel}" stroke-width="1.25" stroke-dasharray="4 4"/>')
    g.append(f'<g fill="none" stroke="{ink}" stroke-width="1.5"><circle cx="{num(ax)}" cy="{num(ay)}" r="{num(1.5 * m)}"/>'
             f'<circle cx="{num(ax)}" cy="{num(ay)}" r="{num(0.5 * m)}"/><path d="{mark_path(ax, ay, m, bore=False)}"/></g>')
    axes = "".join(f'M{num(ax)} {num(ay)}L{num(ax + math.cos(math.radians(a)) * 3 * m)} '
                   f'{num(ay + math.sin(math.radians(a)) * 3 * m)}' for a in (0, 120, 240))
    g.append(f'<path stroke="{ink}" stroke-dasharray="2 3" d="{axes}"/><circle cx="{num(ax)}" cy="{num(ay)}" r="3" fill="{ink}"/>')
    ra = 2.1 * m
    x2, y2 = ax + ra * math.cos(math.radians(120)), ay + ra * math.sin(math.radians(120))
    g.append(f'<path fill="none" stroke="{ink}" stroke-width="1.25" d="M{num(ax + ra)} {num(ay)}A{num(ra)} {num(ra)} 0 0 1 {num(x2)} {num(y2)}"/>')
    g.append(book.text("120°", ax + ra * 0.5 + 12, ay + ra * 0.866 + 16, 15, ink, family="mono")[0])
    # arm width, measured across the right arm
    dx = ax + 2.25 * m
    g.append(f'<path stroke="{ink}" stroke-width="1.25" d="M{num(dx - 5)} {num(ay - 0.5 * m)}h10M{num(dx - 5)} {num(ay + 0.5 * m)}h10M{num(dx)} {num(ay - 0.5 * m)}v{num(m)}"/>')
    g.append(book.text("m", dx, ay - 0.5 * m - 10, 15, ink, family="mono", anchor="middle")[0])
    g.append(book.text("0", ox, oy + 24 * u + 28, 14, steel, family="mono")[0])
    g.append(book.text("24", ox + 24 * u, oy + 24 * u + 28, 14, steel, family="mono", anchor="end")[0])
    tx, y = ox + 24 * u + 40, oy + 20
    for k, v in (("m", "module, the arm width"), ("3m", "hub diameter"), ("1m", "bore diameter"),
                 ("3m", "reach, from axis to tip"), ("120°", "between arms"),
                 ("0°", "rest: an arm points right"), ("24", "grid units, m = 4"), ("9.5, 12", "axis on the grid")):
        g.append(book.text(k, tx, y, 16, ink, family="mono", wght=600)[0])
        g.append(book.text(v, tx, y + 22, 15, steel, family="mono")[0])
        y += 54
    write("construction.svg", doc(W, H, "".join(g), "Construction of the Catraca mark", book))

def clearspace():
    m, pad = 12, 40
    c = 3 * m                                # one hub diameter
    L0 = horizontal(m)
    x0, y0, x1, y1 = L0["box"]
    W, H = x1 - x0 + 2 * (c + pad), y1 - y0 + 2 * (c + pad)
    L = horizontal(m, ox=pad + c, oy=pad + c)
    x0, y0, x1, y1 = L["box"]
    steel = N["steel"]
    hubs = "".join(f'<circle cx="{num(cx)}" cy="{num(cy)}" r="{num(c / 2)}"/>'
                   for cx, cy in ((x0 - c / 2, y0 - c / 2), (x1 + c / 2, y1 + c / 2)))
    g = (f'<rect width="{num(W)}" height="{num(H)}" rx="12" fill="{N["paper"]}"/>'
         f'<rect x="{num(x0 - c)}" y="{num(y0 - c)}" width="{num(x1 - x0 + 2 * c)}" height="{num(y1 - y0 + 2 * c)}" '
         f'fill="{N["mist"]}" stroke="{steel}" stroke-dasharray="4 4"/>'
         f'<rect x="{num(x0)}" y="{num(y0)}" width="{num(x1 - x0)}" height="{num(y1 - y0)}" fill="{N["paper"]}"/>'
         f'<g fill="none" stroke="{steel}">{hubs}</g>'
         f'<g fill="{N["ink"]}"><path d="{L["mark"]}"/><path d="{L["word"]}"/></g>')
    write("clear-space.svg", doc(W, H, g, "Clear space around the horizontal lockup: one hub"))

def palette_figure():
    book = GlyphBook()
    W, H = 1200, 600
    g = []
    for col, theme in enumerate(("light", "dark")):
        T = THEMES[theme]
        x0 = col * W / 2
        g.append(f'<rect x="{num(x0)}" width="{num(W / 2)}" height="{H}" fill="{T["bg"]}"/>')
        nx = x0 + 48
        names = (("paper", "mist", "rail", "steel", "graphite", "ink") if theme == "light"
                 else ("ink", "ink-2", "ink-3", "steel-2", "paper-2", "paper"))
        for i, name in enumerate(names):
            hx = N.get(name) or ND[name]
            x = nx + i * 86
            g.append(f'<rect x="{num(x)}" y="48" width="76" height="56" rx="6" fill="{hx}" stroke="{T["rail"]}"/>')
            g.append(book.text(name, x, 128, 13, T["fg"], family="mono")[0])
            g.append(book.text(hx.lower(), x, 147, 12, T["muted"], family="mono")[0])
        y = 208
        for name in ACTIONS + ("shadow",):
            c = A[name][theme]
            if name == "shadow":
                g.append(f'<circle cx="{num(nx + 12)}" cy="{y - 6}" r="10" fill="none" stroke="{c["mark"]}" '
                         f'stroke-width="2.5" stroke-dasharray="3.4 2.9"/>')
            else:
                g.append(f'<circle cx="{num(nx + 12)}" cy="{y - 6}" r="12" fill="{c["mark"]}"/>')
            g.append(book.text(name, nx + 40, y, 20, T["fg"], wght=500)[0])
            badge, w = book.text(name, nx + 182, y - 3, 15, c["text"], family="mono")
            g.append(f'<rect x="{num(nx + 170)}" y="{y - 23}" width="{num(w + 24)}" height="30" rx="6" fill="{c["tint"]}"/>{badge}')
            g.append(book.text(f'{c["mark"].lower()}  {c["text"].lower()}  {c["tint"].lower()}', nx + 300, y - 2, 13,
                               T["muted"], family="mono")[0])
            y += 62
    write("palette.svg", doc(W, H, "".join(g), "Catraca palette, light and dark", book))

# Tokens ---------------------------------------------------------------------------

FONT_SANS = '"Atkinson Hyperlegible Next", ui-sans-serif, system-ui, sans-serif'
FONT_MONO = '"Atkinson Hyperlegible Mono", ui-monospace, "Cascadia Mono", Menlo, Consolas, monospace'
TYPE_SCALE = {"12": 12, "14": 14, "16": 16, "18": 18, "21": 21, "24": 24, "36": 36, "48": 48, "72": 72}
MOTION = {
    "ease-turn": "cubic-bezier(0.6, 0, 0.2, 1.2)",   # the ratchet: a push, then a click past the detent (~3 deg)
    "ease-out": "cubic-bezier(0.2, 0, 0, 1)",        # things arriving, panels opening
    "ease-in": "cubic-bezier(0.4, 0, 1, 1)",         # things leaving
    "duration-click": "120ms",
    "duration-turn": "320ms",
    "duration-pitch": "480ms",                       # one event moving one place along the lane
    "duration-fade": "200ms",
}
ANSI16 = {"allow": "green (32)", "flag": "blue (34)", "throttle": "yellow (33)", "hold": "magenta (35)",
          "block": "red (31)", "shadow": "bright black (90), or dim (2) on the action color"}
ORDER = ["ink", "ink-2", "ink-3", "graphite", "steel", "steel-2", "rail", "mist", "paper-2", "paper"]

def xterm256(hx):
    """Nearest xterm-256 color (cube and gray ramp, 16-255) in OKLab."""
    levels = [0, 95, 135, 175, 215, 255]
    cands = {}
    for i in range(216):
        r, g, b = levels[i // 36], levels[(i // 6) % 6], levels[i % 6]
        cands[16 + i] = f"#{r:02X}{g:02X}{b:02X}"
    for i in range(24):
        v = 8 + 10 * i
        cands[232 + i] = f"#{v:02X}{v:02X}{v:02X}"
    target = lin_to_oklab(*hex_to_lin(hx))
    return min(cands, key=lambda k: math.dist(target, lin_to_oklab(*hex_to_lin(cands[k]))))

def theme_vars(theme, indent="  "):
    if theme == "light":
        base = {"bg": "var(--ct-paper)", "surface": "var(--ct-mist)", "line": "var(--ct-rail)",
                "text": "var(--ct-ink)", "text-2": "var(--ct-graphite)", "text-muted": "var(--ct-steel)",
                "mark": "var(--ct-ink)"}
    else:
        base = {"bg": "var(--ct-ink)", "surface": "var(--ct-ink-2)", "line": "var(--ct-ink-3)",
                "text": "var(--ct-paper-2)", "text-2": "var(--ct-steel-2)", "text-muted": "var(--ct-steel-2)",
                "mark": "var(--ct-paper)"}
    lines = [f"{indent}--ct-{k}: {v};" for k, v in base.items()]
    for name in ACTIONS + ("shadow",):
        c = A[name][theme]
        lines += [f"{indent}--ct-{name}: {c['mark']};", f"{indent}--ct-{name}-text: {c['text']};",
                  f"{indent}--ct-{name}-tint: {c['tint']};"]
    return "\n".join(lines)

def tokens_css():
    allc = {**N, **ND}
    prim = "\n".join(f"  --ct-{k}: {allc[k]};" for k in ORDER)
    sizes = "\n".join(f"  --ct-size-{k}: {v / 16:g}rem;" for k, v in TYPE_SCALE.items())
    motion = "\n".join(f"  --ct-{k}: {v};" for k, v in MOTION.items())
    css = f"""/* Catraca design tokens. Generated by docs/brand/build/build.py; see docs/brand.md. */

:root {{
  color-scheme: light dark;

  /* Neutrals: steel. Color is reserved for decisions. */
{prim}

  /* Type: Atkinson Hyperlegible Next and Mono (SIL OFL 1.1) */
  --ct-font-sans: {FONT_SANS};
  --ct-font-mono: {FONT_MONO};
{sizes}
  --ct-weight-regular: 400;
  --ct-weight-medium: 500;
  --ct-weight-semibold: 600;
  --ct-tracking-wordmark: -0.02em;
  --ct-tracking-display: -0.01em;
  --ct-leading-body: 1.5;
  --ct-leading-code: 1.6;
  --ct-leading-display: 1.1;

  /* Motion: the rotor turns one way, a third of a turn per passage */
  --ct-turn: 120deg;
{motion}

  /* Light theme (default): surfaces, text, and per action a mark, text and tint */
{theme_vars("light")}
}}

@media (prefers-color-scheme: dark) {{
  :root:not([data-theme="light"]) {{
{theme_vars("dark", "    ")}
  }}
}}

:root[data-theme="dark"] {{
{theme_vars("dark")}
}}

@media (prefers-reduced-motion: reduce) {{
  :root {{
    --ct-duration-click: 0ms;
    --ct-duration-turn: 0ms;
    --ct-duration-pitch: 0ms;
  }}
}}
"""
    write("tokens.css", css)

def tokens_json():
    def color(hx, desc=None):
        d = {"$type": "color", "$value": hx}
        if desc:
            d["$description"] = desc
        return d
    allc = {**N, **ND}
    actions = {}
    for theme in ("light", "dark"):
        bg = N["paper"] if theme == "light" else N["ink"]
        actions[theme] = {}
        for name in ACTIONS + ("shadow",):
            c = A[name][theme]
            actions[theme][name] = {
                "mark": color(c["mark"], f"fills, lines, chart marks: {contrast(c['mark'], bg):.2f}:1 on bg"),
                "text": color(c["text"], f"text: {contrast(c['text'], bg):.2f}:1 on bg, "
                                         f"{contrast(c['text'], c['tint']):.2f}:1 on tint"),
                "tint": color(c["tint"], "badge background"),
            }
    data = {
        "$description": "Catraca design tokens. Generated by docs/brand/build/build.py; see docs/brand.md.",
        "color": {
            "neutral": {k: color(allc[k]) for k in ORDER},
            "theme": {
                "light": {"bg": color(N["paper"]), "surface": color(N["mist"]), "line": color(N["rail"]),
                          "text": color(N["ink"]), "text-2": color(N["graphite"]), "text-muted": color(N["steel"]),
                          "mark": color(N["ink"])},
                "dark": {"bg": color(N["ink"]), "surface": color(ND["ink-2"]), "line": color(ND["ink-3"]),
                         "text": color(ND["paper-2"]), "text-2": color(ND["steel-2"]),
                         "text-muted": color(ND["steel-2"]), "mark": color(N["paper"])},
            },
            "action": actions,
        },
        "terminal": {
            name: {"truecolor": {"light": A[name]["light"]["text"], "dark": A[name]["dark"]["text"]},
                   "ansi256": {"light": xterm256(A[name]["light"]["text"]), "dark": xterm256(A[name]["dark"]["text"])},
                   "ansi16": ANSI16[name]}
            for name in ACTIONS + ("shadow",)
        },
        "font": {
            "sans": {"$type": "fontFamily", "$value": ["Atkinson Hyperlegible Next", "ui-sans-serif", "system-ui", "sans-serif"]},
            "mono": {"$type": "fontFamily", "$value": ["Atkinson Hyperlegible Mono", "ui-monospace", "Cascadia Mono", "Menlo", "Consolas", "monospace"]},
            "wordmark": {"family": "Atkinson Hyperlegible Next", "weight": 600, "tracking": "-0.02em", "case": "lower"},
            "size": {k: {"$type": "dimension", "$value": f"{v}px"} for k, v in TYPE_SCALE.items()},
        },
        "motion": {
            "turn": {"$type": "number", "$value": 120,
                     "$description": "degrees per passage, always in the direction of travel"},
            **{k: ({"$type": "cubicBezier", "$value": [float(x) for x in v[len("cubic-bezier("):-1].split(",")]}
                   if k.startswith("ease") else {"$type": "duration", "$value": v})
               for k, v in MOTION.items()},
        },
    }
    write("tokens.json", json.dumps(data, indent=2, ensure_ascii=False) + "\n")

def report():
    allc = {**N, **ND}
    print("\nNeutrals                 paper   mist    ink  ink-2")
    for k in ORDER:
        v = allc[k]
        print(f"  {k:9} {v}  {contrast(v, N['paper']):5.2f}  {contrast(v, N['mist']):5.2f}  "
              f"{contrast(v, N['ink']):5.2f}  {contrast(v, ND['ink-2']):5.2f}")
    for theme, bg in (("light", N["paper"]), ("dark", N["ink"])):
        print(f"\nActions, {theme}: mark on bg, text on bg / on tint")
        for name in ACTIONS + ("shadow",):
            c = A[name][theme]
            L, C, h = hex_oklch(c["mark"])
            print(f"  {name:8} {c['mark']} {contrast(c['mark'], bg):.2f} (L {L:.3f})  {c['text']} "
                  f"{contrast(c['text'], bg):.2f} / {contrast(c['text'], c['tint']):.2f}  tint {c['tint']}  "
                  f"xterm {xterm256(c['text'])}")

def quantize_pngs():
    from PIL import Image
    for name in ("social-preview.png", "icon-512.png", "icon-192.png"):
        path = os.path.join(OUT, name)
        im = Image.open(path)
        method = Image.Quantize.FASTOCTREE if im.mode == "RGBA" else Image.Quantize.MEDIANCUT
        im.quantize(colors=256, method=method, dither=Image.Dither.NONE).save(path, optimize=True)
        print(f"{os.path.getsize(path):>7}  {name}")

if __name__ == "__main__":
    import sys
    if "--png" in sys.argv:
        quantize_pngs()
        sys.exit()
    logos()
    favicon()
    app_icon()
    banner("light")
    banner("dark")
    social()
    construction()
    clearspace()
    palette_figure()
    tokens_css()
    tokens_json()
    report()
