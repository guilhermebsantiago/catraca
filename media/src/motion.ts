// Motion (motion.dev) as pure functions of time. Its animate() runs on the
// browser's clock, which a renderer cannot use; its generators and easings
// are deterministic, so every frame is sampled from them on its own.

import {anticipate, backOut, circOut, cubicBezier, spring, stagger} from 'motion';
import {clamp01} from './brand';

type SpringOptions = {visualDuration?: number; bounce?: number; stiffness?: number; damping?: number; mass?: number};

const springs = new Map<string, ReturnType<typeof spring>>();

// A spring from 0 to 1 that starts at `from` (ms), sampled at t.
export function springAt(t: number, from: number, o: SpringOptions = {}): number {
	if (t <= from) return 0;
	const key = JSON.stringify(o);
	let g = springs.get(key);
	if (!g) {
		g = spring({keyframes: [0, 1], visualDuration: 0.5, bounce: 0.2, ...o});
		springs.set(key, g);
	}
	return g.next(t - from).value as number;
}

// Presets: a soft settle for text and panels, a lively one for chips and
// hits, a firm one for the camera.
export const SOFT = {visualDuration: 0.55, bounce: 0.12};
export const POP = {visualDuration: 0.45, bounce: 0.38};
export const FIRM = {visualDuration: 0.8, bounce: 0};

// Delays (ms) for n items, from Motion's stagger.
export function delays(n: number, each: number, from: 'first' | 'center' | 'last' = 'first'): number[] {
	const f = stagger(each / 1000, {from});
	return Array.from({length: n}, (_, i) => f(i, n) * 1000);
}

const easeExpo = cubicBezier(0.16, 1, 0.3, 1);

// Progress of a tween from `from` over `ms`, with one of Motion's easings.
export const tween = (t: number, from: number, ms: number, ease: (p: number) => number = easeExpo) =>
	ease(clamp01((t - from) / ms));

export {anticipate, backOut, circOut, easeExpo};
