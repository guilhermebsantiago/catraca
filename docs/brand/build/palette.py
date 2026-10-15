"""Catraca's palette, defined in OKLCH and converted to sRGB hex.

Neutrals are a cool steel gray (hue ~245). Color is reserved for decisions:
each action has a mark color (fills, lines, chart marks; >= 3:1 on the theme
background), a text color (>= 4.5:1 on the background and on its tint) and a
tint (badge background). Light and dark themes have their own steps, chosen so
that all five action marks stay apart under protanopia and deuteranopia
(all pairs, OKLab delta E x100 >= 11, Machado 2009 at severity 1.0).
"""
from color import oklch

NEUTRAL = {
    "ink":      (0.205, 0.014, 245),
    "graphite": (0.385, 0.018, 245),
    "steel":    (0.530, 0.020, 245),
    "rail":     (0.895, 0.009, 240),
    "mist":     (0.957, 0.006, 240),
    "paper":    (0.984, 0.004, 235),
}
# Extra neutrals for the dark theme: raised surfaces, lines, text.
NEUTRAL_DARK = {
    "ink-2":   (0.245, 0.015, 245),   # raised surfaces
    "ink-3":   (0.330, 0.016, 245),   # lines
    "steel-2": (0.705, 0.018, 245),   # muted text
    "paper-2": (0.950, 0.006, 240),   # text, a little softer than paper
}
ACTIONS = ("allow", "flag", "throttle", "hold", "block")
# (L, C) per theme and role; hue per action.
ACTION_SPEC = {
    "allow":    dict(h=166, light=dict(mark=(0.630, 0.150), text=(0.505, 0.115), tint=(0.955, 0.030)),
                            dark=dict(mark=(0.670, 0.150), text=(0.760, 0.140), tint=(0.280, 0.040))),
    "flag":     dict(h=257, light=dict(mark=(0.610, 0.160), text=(0.520, 0.150), tint=(0.955, 0.022)),
                            dark=dict(mark=(0.660, 0.150), text=(0.760, 0.120), tint=(0.280, 0.045))),
    "throttle": dict(h=70,  light=dict(mark=(0.630, 0.150), text=(0.530, 0.120), tint=(0.955, 0.035)),
                            dark=dict(mark=(0.670, 0.150), text=(0.790, 0.140), tint=(0.280, 0.040))),
    "hold":     dict(h=302, light=dict(mark=(0.500, 0.160), text=(0.500, 0.160), tint=(0.955, 0.025)),
                            dark=dict(mark=(0.545, 0.170), text=(0.760, 0.120), tint=(0.280, 0.050))),
    "block":    dict(h=26,  light=dict(mark=(0.510, 0.200), text=(0.510, 0.200), tint=(0.955, 0.025)),
                            dark=dict(mark=(0.560, 0.200), text=(0.750, 0.140), tint=(0.280, 0.060))),
    # Shadow is a mode, not an action: a neutral used for its label and for
    # the dashed outlines that show what a shadow rule would have done.
    "shadow":   dict(h=245, light=dict(mark=(0.600, 0.020), text=(0.530, 0.020), tint=(0.950, 0.006)),
                            dark=dict(mark=(0.560, 0.020), text=(0.705, 0.018), tint=(0.280, 0.012))),
}

def build():
    neutral = {k: oklch(*v) for k, v in NEUTRAL.items()}
    neutral_dark = {k: oklch(*v) for k, v in NEUTRAL_DARK.items()}
    actions = {
        name: {theme: {role: oklch(L, C, spec["h"]) for role, (L, C) in spec[theme].items()}
               for theme in ("light", "dark")}
        for name, spec in ACTION_SPEC.items()
    }
    return neutral, neutral_dark, actions

NEUTRALS, NEUTRALS_DARK, ACTION_COLORS = build()
