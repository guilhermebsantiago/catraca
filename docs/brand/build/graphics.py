"""The lane: events come in from the left as open rings, pass the rotor one at
a time and leave as decisions, filled with the color of their action. A
shadow match is a dashed ring, in the color of what the rule would have done,
around a decision it did not change.
"""
import math

from geometry import mark_path, num
from palette import ACTION_COLORS as A, NEUTRALS as N, NEUTRALS_DARK as ND

THEMES = {
    "light": dict(bg=N["paper"], fg=N["ink"], rail=N["rail"], ring=N["steel"], text2=N["graphite"],
                  muted=N["steel"]),
    "dark": dict(bg=N["ink"], fg=ND["paper-2"], rail=ND["ink-3"], ring=ND["steel-2"],
                 text2=ND["steel-2"], muted=ND["steel-2"]),
}
CODES = {"a": "allow", "f": "flag", "t": "throttle", "h": "hold", "b": "block"}

def _arm_left_boundary(ax, ay, M, angle, y):
    """Leftmost x on the horizontal line y inside the arm at `angle` (a capsule)."""
    t = math.radians(angle)
    ux, uy = math.cos(t), math.sin(t)
    x0, y0 = ax, ay
    x1, y1 = ax + ux * 2.5 * M, ay + uy * 2.5 * M
    def inside(x):
        vx, vy = x - x0, y - y0
        k = max(0.0, min(1.0, (vx * (x1 - x0) + vy * (y1 - y0)) / ((x1 - x0) ** 2 + (y1 - y0) ** 2)))
        px, py = x0 + k * (x1 - x0), y0 + k * (y1 - y0)
        return math.hypot(x - px, y - py) <= 0.5 * M
    x = ax - 4 * M
    step = M / 400
    while not inside(x):
        x += step
    return x

def lane(theme, ax, ay, M, x_min, x_max, decided, dot=0.3, pitch=1.0, offset=2.25, rotor=True):
    """The lane under a rotor at (ax, ay) with module M.

    The down-left arm (120 degrees) holds the lane; in motion the rotor turns
    counterclockwise, so the arm under the hub moves with the traffic.
    decided: codes nearest the rotor first; a, f, t, h, b are actions and
    "s" followed by an upper-case code is a shadow match on an allowed event
    ("sB": a shadow block rule matched).
    """
    T = THEMES[theme]
    r, p = dot * M, pitch * M
    ly = ay + offset * M
    sw = max(1.5, M * 0.08)
    out = [f'<path stroke="{T["rail"]}" stroke-width="{num(max(1.0, M * 0.05))}" '
           f'd="M{num(x_min)} {num(ly)}H{num(x_max)}"/>']
    # Waiting events: open rings, queued against the arm.
    x = _arm_left_boundary(ax, ay, M, 120, ly) - 0.14 * M - r
    rings = []
    while x + r > x_min:
        rings.append(f'<circle cx="{num(x)}" cy="{num(ly)}" r="{num(r - sw / 2)}"/>')
        x -= p
    out.append(f'<g fill="none" stroke="{T["ring"]}" stroke-width="{num(sw)}">{"".join(rings)}</g>')
    if rotor:
        out.append(f'<path fill="{T["fg"]}" d="{mark_path(ax, ay, M)}"/>')
    # Decisions: the first is still in the sector, being carried through.
    x = ax + 0.6 * M
    i, dots = 0, []
    while i < len(decided) and x - r < x_max:
        c = decided[i]
        if c == "s":
            would = CODES[decided[i + 1].lower()]
            rr = r + 0.2 * M
            dash = 2 * math.pi * rr / 14
            dots.append(f'<circle cx="{num(x)}" cy="{num(ly)}" r="{num(r)}" fill="{A["allow"][theme]["mark"]}"/>'
                        f'<circle cx="{num(x)}" cy="{num(ly)}" r="{num(rr)}" fill="none" '
                        f'stroke="{A[would][theme]["mark"]}" stroke-width="{num(sw)}" '
                        f'stroke-dasharray="{num(dash * 0.55)} {num(dash * 0.45)}"/>')
            i += 2
        else:
            dots.append(f'<circle cx="{num(x)}" cy="{num(ly)}" r="{num(r)}" fill="{A[CODES[c]][theme]["mark"]}"/>')
            i += 1
        x += p
    out.append("".join(dots))
    return "".join(out), ly

def legend(book, theme, x, y, size, gap=None, items=("allow", "flag", "throttle", "hold", "block", "shadow")):
    """Swatches and names in Atkinson Hyperlegible Mono, baseline at y."""
    T = THEMES[theme]
    r = size * 0.32
    sw = max(1.5, size * 0.1)
    gap = gap if gap is not None else size * 1.5
    cy = y - size * 0.33
    out, cx = [], x
    for name in items:
        if name == "shadow":
            dash = 2 * math.pi * (r - sw / 2) / 8
            out.append(f'<circle cx="{num(cx + r)}" cy="{num(cy)}" r="{num(r - sw / 2)}" fill="none" '
                       f'stroke="{A["shadow"][theme]["mark"]}" stroke-width="{num(sw)}" '
                       f'stroke-dasharray="{num(dash * 0.55)} {num(dash * 0.45)}"/>')
        else:
            out.append(f'<circle cx="{num(cx + r)}" cy="{num(cy)}" r="{num(r)}" fill="{A[name][theme]["mark"]}"/>')
        t, w = book.text(name, cx + 2 * r + size * 0.5, y, size, T["text2"], family="mono")
        out.append(t)
        cx += 2 * r + size * 0.5 + w + gap
    return "".join(out), cx - gap
