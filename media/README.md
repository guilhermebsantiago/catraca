# Media

Catraca's launch video and README animation, made with
[Remotion](https://www.remotion.dev) from what the
[demo scenario](../examples/demo) recorded against a real `catraca serve`.

| file in `docs/media` | |
|---|---|
| `catraca.mp4` | the launch video: 1920 × 1080, 30 fps, about 45 s, no sound |
| `catraca-720p.mp4` | the same at 1280 × 720 |
| `catraca-poster.png` | its end card, as a poster frame |
| `lane.gif`, `lane-dark.gif` | the rotor and the lane as a seamless loop, 800 px wide, for the README in light and dark themes |

## What is real

Every request, answer, header, webhook and command output on screen is read
from `examples/demo/out/scenario.json` (`src/data.ts`). JSON is laid out
for the panels (`src/video/json.ts`) by changing whitespace only: keys keep
their order and values their text; long strings wrap like in an editor. The
one panel that leaves fields out, the webhook body, says which.

The lane plays the live decisions in the order Catraca made them, with
long runs left out: the burst's first 96 allowed sends and its last 39
throttled ones. The throttle countdown is shortened on screen (the answer
said `Retry-After: 60`). The README loop and the end card repeat a window of
those decisions. The opening scene (traffic stopping on a paused account) is
an illustration, not product output.

## Reproduce

Requires Go and Node 22 or later. From the repository root:

```sh
go run ./examples/demo           # 1. play the scenario: writes examples/demo/out
cd media
npm ci                           # 2. Remotion, React, TypeScript
npx remotion browser ensure      #    downloads Chrome Headless Shell once
npm run render                   # 3. writes everything in docs/media
```

`npm run render -- video`, `-- poster` or `-- gif` renders one part.
Rendering takes about three minutes. No system ffmpeg is needed: the script
uses the one Remotion bundles (`npx remotion ffmpeg`). It renders a
near-lossless master from PNG frames, then encodes H.264 (BT.709, limited
range, `+faststart`) at CRF 21 for 1080p and 22 for 720p, and palettes the
GIFs with one 96-color palette, no dithering. It fails if a video is over
8 MB or a GIF over 2.5 MB.

A new demo run changes ids, times and latencies; re-render after it so the
video and `examples/demo/out` agree, and commit both.

To preview and scrub: `npm run studio`. `npm run typecheck` checks the code.

## Layout

| path | |
|---|---|
| `src/brand.ts` | palette, motion tokens and easings from [docs/brand.md](../docs/brand.md); the mark's geometry, ported from `docs/brand/build/geometry.py` |
| `src/wordmark.ts` | the outlined wordmark, taken from `docs/brand/logo/horizontal-on-dark.svg` |
| `src/lane/sim.ts` | the lane as a pure function of time: one passage every 480 ms, a 320 ms ratchet turn of 120°, throttle countdowns, blocks bouncing off the arm, holds stepping into a bay, dashed shadow rings |
| `src/lane/Lane.tsx`, `src/lane/period.ts` | drawing it; the window of decisions the loops repeat |
| `src/LaneLoop.tsx` | the README loop (25 fps; one period of 13.04 s, so it loops exactly) |
| `src/video/` | the video: `timeline.ts` (scene times follow the lane), `Launch.tsx` (scenes), `ui.tsx` (panels, terminal), `json.ts` |
| `scripts/render.mjs` | the render pipeline |
| `public/fonts/` | Atkinson Hyperlegible Next and Mono, variable, self-hosted, with their licenses |

## Licenses

The fonts are by the Braille Institute with Applied Design Works under the
SIL Open Font License 1.1 (`public/fonts/OFL-*.txt`). Remotion has its own
license: free for individuals and small teams, a company license above
that; see [remotion.dev/license](https://www.remotion.dev/license). The
rendered files in `docs/media` are part of Catraca, under Apache-2.0.
