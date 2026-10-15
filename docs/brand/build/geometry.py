"""The Catraca mark: a tripod turnstile rotor seen from above.

Everything is a multiple of one module, m (the arm width):

    hub       circle, diameter 3m
    bore      circle, diameter 1m (the ring left around it is 1m thick)
    arms      width 1m, round ends, reaching 3m from the axis
    angles    0, 120 and 240 degrees (screen coordinates, y down), so at rest
              one arm points right, along the direction of travel

On the 24-unit grid of mark.svg, m = 4 and the axis sits at (9.5, 12), which
centers the bounding box (19 x 21.32) in the square.
"""
import math

def num(v, nd=2):
    s = f"{v:.{nd}f}"
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s

def mark_path(cx, cy, m, bore=True, turn=0.0, nd=2):
    """Path data for the rotor with its axis at (cx, cy), module m, rotated by `turn` degrees."""
    R, h, E = 1.5 * m, 0.5 * m, 3.0 * m
    d = math.sqrt(R * R - h * h)          # where an arm edge leaves the hub
    p = lambda x, y: f"{num(x, nd)} {num(y, nd)}"
    out = []
    first = None
    for i, a in enumerate((0, 120, 240)):
        t = math.radians(a + turn)
        ux, uy = math.cos(t), math.sin(t)
        px, py = -uy, ux
        at = lambda s, o: (cx + ux * s + px * o, cy + uy * s + py * o)
        A, B, C, D = at(d, -h), at(E - h, -h), at(E - h, h), at(d, h)
        if i == 0:
            first = A
            out.append("M" + p(*A))
        else:
            out.append(f"A{num(R, nd)} {num(R, nd)} 0 0 1 " + p(*A))
        out.append("L" + p(*B))
        out.append(f"A{num(h, nd)} {num(h, nd)} 0 0 1 " + p(*C))
        out.append("L" + p(*D))
    out.append(f"A{num(R, nd)} {num(R, nd)} 0 0 1 " + p(*first) + "Z")
    if bore:
        r = 0.5 * m
        out.append(f"M{p(cx, cy - r)}a{num(r, nd)} {num(r, nd)} 0 0 0 0 {num(2 * r, nd)}"
                   f"a{num(r, nd)} {num(r, nd)} 0 0 0 0 {num(-2 * r, nd)}Z")
    return "".join(out)

def mark_bounds(m):
    """Bounding box of the rotor at rest, relative to its axis: (left, top, right, bottom)."""
    reach = 3.0 * m
    cap = 0.5 * m
    left = -(reach - cap) * 0.5 - cap
    half_h = (reach - cap) * math.sin(math.radians(60)) + cap
    return left, -half_h, reach, half_h
