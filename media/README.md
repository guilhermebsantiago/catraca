# Media

Catraca's launch video and README animation, made with
[Remotion](https://www.remotion.dev) and [Motion](https://motion.dev) from
what the [demo scenario](../examples/demo) recorded against a real
`catraca serve`, with a score synthesized from code.

| file in `docs/media` | |
|---|---|
| `catraca.mp4` | the launch video: 1920 × 1080, 60 fps, 64 s, with its score (AAC, 192 kb/s) |
| `catraca-720p.mp4` | the same at 1280 × 720 |
| `catraca-poster.png` | its end card, as a poster frame |
| `lane.gif`, `lane-dark.gif` | the rotor and the lane as a seamless loop, 800 px wide, for the README in light and dark themes |

## What is real

Every request, answer, header, webhook and rule on screen is read from
`examples/demo/out/scenario.json` (`src/data.ts`) or from
`examples/demo/rules.yaml`. Panels show a few members of each recorded
answer, with their recorded values; a signature is cut short with an
ellipsis. The latencies in the decisions panel are each decision's own
`latency_us`. The numbers scene quotes [docs/benchmark.md](../docs/benchmark.md).

The lane plays the live decisions in the order Catraca made them, with runs
left out: sends 5 to 96 of the burst (the counter counts through them), the
39 throttled sends after the first, the allowed sends after the hold, and
the feedback and key-leak events, which the panels show instead. The
throttle countdown is shortened on screen (the answer said
`Retry-After: 60`). In the gate scene, the labels arriving one by one and
the interval narrowing with them are an illustration of the Wilson bound;
where it ends, `[0.911, 0.997]` on 60 labels, is what `catraca report`
printed. The README loop and the end card repeat a window of those
decisions. The opening scene (traffic stopping on a paused account, the two
rates climbing) is an illustration, not product output.

## The score

`scripts/score.mjs` synthesizes the music from code: oscillators, noise,
filters, a reverb and a limiter written in plain JavaScript, no samples, the
noise seeded so every run writes the same `public/audio/score.wav` (48 kHz,
stereo, 64 s, about −14 LUFS). It is part of Catraca, under Apache-2.0.

At 125 BPM one beat is 480 ms, the lane's pitch, so every decision clicks
on a beat and every scene starts on a bar (`src/video/timeline.ts`). The
hits the picture follows are in the script's `CUES` table: the tape stop
when traffic stops, the drop on the mark, the filter closing for the
throttle's countdown, the complaints, the block, the drum roll into the
gate and the promotion on drop 2. Move a cue there and in the timeline
together.

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
No system ffmpeg is needed: the script uses the one Remotion bundles
(`npx remotion ffmpeg`). For the video it first runs `scripts/score.mjs`,
renders a silent near-lossless master from PNG frames, then encodes H.264
(BT.709, limited range, `+faststart`) at CRF 22 for 1080p and 23 for 720p
with the score as AAC. It palettes the GIFs with one 96-color palette, no
dithering. It fails if a video is over 8 MB or a GIF over 2.5 MB.

A new demo run changes ids, times and latencies; re-render after it so the
video and `examples/demo/out` agree, and commit both.

To preview and scrub with sound: `npm run score` once, then
`npm run studio`. `npm run typecheck` checks the code.

## Layout

| path | |
|---|---|
| `src/brand.ts` | palette, motion tokens and easings from [docs/brand.md](../docs/brand.md); the mark's geometry, ported from `docs/brand/build/geometry.py` |
| `src/motion.ts` | Motion's springs, staggers and easings, sampled per frame (its `animate()` runs on the browser's clock, which a render cannot use) |
| `src/wordmark.ts` | the outlined wordmark, taken from `docs/brand/logo/horizontal-on-dark.svg` |
| `src/lane/sim.ts` | the lane as a pure function of time: one passage every 480 ms, a 320 ms ratchet turn of 120°, throttle countdowns, blocks bouncing off the arm, holds stepping into a bay, dashed shadow rings |
| `src/lane/Lane.tsx`, `src/lane/period.ts` | drawing it; the window of decisions the loops repeat |
| `src/LaneLoop.tsx` | the README loop (25 fps; one period of 13.04 s, so it loops exactly) |
| `src/video/` | the video: `timeline.ts` (the beat grid, scenes on bars, the lane's clicks on beats), `Launch.tsx` (scenes), `kit.tsx` (words rising out of masks, panels, chips, counters) |
| `scripts/score.mjs` | the score |
| `scripts/render.mjs` | the render pipeline |
| `public/fonts/` | Atkinson Hyperlegible Next and Mono, variable, self-hosted, with their licenses |

## Licenses

The fonts are by the Braille Institute with Applied Design Works under the
SIL Open Font License 1.1 (`public/fonts/OFL-*.txt`). Motion is under the MIT
license. Remotion has its own
license: free for individuals and small teams, a company license above
that; see [remotion.dev/license](https://www.remotion.dev/license). The
score and the rendered files in `docs/media` are part of Catraca, under
Apache-2.0.
