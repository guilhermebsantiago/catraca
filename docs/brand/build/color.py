"""Color maths: OKLCH to sRGB, WCAG contrast, and color-vision deficiency
simulation (Machado, Oliveira and Fernandes 2009, severity 1.0) for checking
that the action colors stay apart.
"""
import math
def oklch_to_srgb(L, C, h):
    a = C*math.cos(math.radians(h)); b = C*math.sin(math.radians(h))
    l_ = L + 0.3963377774*a + 0.2158037573*b
    m_ = L - 0.1055613458*a - 0.0638541728*b
    s_ = L - 0.0894841775*a - 1.2914855480*b
    l, m, s = l_**3, m_**3, s_**3
    r = 4.0767416621*l - 3.3077115913*m + 0.2309699292*s
    g = -1.2684380046*l + 2.6097574011*m - 0.3413193965*s
    bb = -0.0041960863*l - 0.7034186147*m + 1.7076147010*s
    return r, g, bb
def in_gamut(rgb): return all(-1e-4 <= c <= 1+1e-4 for c in rgb)
def enc(c):
    c = min(max(c, 0), 1)
    return 12.92*c if c <= 0.0031308 else 1.055*c**(1/2.4) - 0.055
def dec(c): return c/12.92 if c <= 0.04045 else ((c+0.055)/1.055)**2.4
def oklch(L, C, h):
    """hex, reducing chroma until in gamut"""
    while True:
        rgb = oklch_to_srgb(L, C, h)
        if in_gamut(rgb) or C <= 0: break
        C -= 0.002
    return '#' + ''.join(f'{round(enc(c)*255):02X}' for c in rgb)
def hex_to_lin(hx):
    hx = hx.lstrip('#'); return [dec(int(hx[i:i+2], 16)/255) for i in (0, 2, 4)]
def lum(hx):
    r, g, b = hex_to_lin(hx); return 0.2126*r + 0.7152*g + 0.0722*b
def contrast(a, b):
    la, lb = sorted((lum(a), lum(b)), reverse=True); return (la+0.05)/(lb+0.05)
def lin_to_oklab(r, g, b):
    l = 0.4122214708*r + 0.5363325363*g + 0.0514459929*b
    m = 0.2119034982*r + 0.6806995451*g + 0.1073969566*b
    s = 0.0883024619*r + 0.2817188376*g + 0.6299787005*b
    l_, m_, s_ = [math.copysign(abs(v)**(1/3), v) for v in (l, m, s)]
    return (0.2104542553*l_ + 0.7936177850*m_ - 0.0040720468*s_,
            1.9779984951*l_ - 2.4285922050*m_ + 0.4505937099*s_,
            0.0259040371*l_ + 0.7827717662*m_ - 0.8086757660*s_)
def hex_oklch(hx):
    L, a, b = lin_to_oklab(*hex_to_lin(hx))
    return L, math.hypot(a, b), math.degrees(math.atan2(b, a)) % 360
# Machado et al. 2009, severity 1.0
CVD = {
 'protan': [[0.152286,1.052583,-0.204868],[0.114503,0.786281,0.099216],[-0.003882,-0.048116,1.051998]],
 'deutan': [[0.367322,0.860646,-0.227968],[0.280085,0.672501,0.047413],[-0.011820,0.042940,0.968881]],
 'tritan': [[1.255528,-0.076749,-0.178779],[-0.078411,0.930809,0.147602],[0.004733,0.691367,0.303900]],
}
def simulate(hx, kind):
    r, g, b = hex_to_lin(hx); M = CVD[kind]
    return [min(max(M[i][0]*r + M[i][1]*g + M[i][2]*b, 0), 1) for i in range(3)]
def de_ok(hx1, hx2, kind=None):
    a = hex_to_lin(hx1) if kind is None else simulate(hx1, kind)
    b = hex_to_lin(hx2) if kind is None else simulate(hx2, kind)
    A = lin_to_oklab(*a); B = lin_to_oklab(*b)
    return math.dist(A, B)
