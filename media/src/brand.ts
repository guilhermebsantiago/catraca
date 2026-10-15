// Catraca's identity, from docs/brand.md and docs/brand/tokens.json.

export type Action = 'allow' | 'flag' | 'throttle' | 'hold' | 'block';
export type Theme = 'light' | 'dark';

export const ACTIONS: Action[] = ['allow', 'flag', 'throttle', 'hold', 'block'];

export const NEUTRAL = {
	ink: '#12181D',
	ink2: '#1B2127',
	ink3: '#2F363D',
	graphite: '#3C454D',
	steel: '#636D77',
	steel2: '#97A1AB',
	rail: '#D7DDE2',
	mist: '#EDF1F4',
	paper2: '#EBEFF2',
	paper: '#F7FAFC',
};

type Swatch = {mark: string; text: string; tint: string};

export const ACTION_COLORS: Record<Theme, Record<Action | 'shadow', Swatch>> = {
	light: {
		allow: {mark: '#04A177', text: '#077757', tint: '#DEF7EB'},
		flag: {mark: '#3D82E1', text: '#2767BD', tint: '#E8F1FE'},
		throttle: {mark: '#BC7802', text: '#955E02', tint: '#FEEDDA'},
		hold: {mark: '#7546AD', text: '#7546AD', tint: '#F3EDFF'},
		block: {mark: '#BE111E', text: '#BE111E', tint: '#FEEBE9'},
		shadow: {mark: '#77828C', text: '#636D77', tint: '#EBEFF2'},
	},
	dark: {
		allow: {mark: '#07AF81', text: '#3DCD9C', tint: '#132F24'},
		flag: {mark: '#5292EC', text: '#7FB3FD', tint: '#1A293F'},
		throttle: {mark: '#CC8305', text: '#F3A949', tint: '#362512'},
		hold: {mark: '#8451C1', text: '#BF9EF1', tint: '#2D233D'},
		block: {mark: '#D02C2E', text: '#FA887F', tint: '#421C19'},
		shadow: {mark: '#6B7680', text: '#97A1AB', tint: '#242A2F'},
	},
};

// Surfaces and text per theme, as in docs/brand/build/graphics.py.
export const THEMES = {
	light: {
		bg: NEUTRAL.paper,
		surface: NEUTRAL.mist,
		fg: NEUTRAL.ink,
		rail: NEUTRAL.rail,
		ring: NEUTRAL.steel,
		text2: NEUTRAL.graphite,
		muted: NEUTRAL.steel,
	},
	dark: {
		bg: NEUTRAL.ink,
		surface: NEUTRAL.ink2,
		fg: NEUTRAL.paper2,
		rail: NEUTRAL.ink3,
		ring: NEUTRAL.steel2,
		text2: NEUTRAL.steel2,
		muted: NEUTRAL.steel2,
	},
};

export const FONT_SANS = '"Atkinson Hyperlegible Next", sans-serif';
export const FONT_MONO = '"Atkinson Hyperlegible Mono", monospace';

// Motion tokens (ms).
export const MOTION = {
	turn: 320,
	click: 120,
	pitch: 480,
	fade: 200,
};

// cubic-bezier easing, solved for x by Newton's method with a bisection
// fallback, like CSS.
export function bezier(x1: number, y1: number, x2: number, y2: number) {
	const cx = 3 * x1;
	const bx = 3 * (x2 - x1) - cx;
	const ax = 1 - cx - bx;
	const cy = 3 * y1;
	const by = 3 * (y2 - y1) - cy;
	const ay = 1 - cy - by;
	const sx = (s: number) => ((ax * s + bx) * s + cx) * s;
	const sy = (s: number) => ((ay * s + by) * s + cy) * s;
	const dx = (s: number) => (3 * ax * s + 2 * bx) * s + cx;
	return (x: number) => {
		if (x <= 0) return 0;
		if (x >= 1) return 1;
		let s = x;
		for (let i = 0; i < 8; i++) {
			const e = sx(s) - x;
			if (Math.abs(e) < 1e-6) return sy(s);
			const d = dx(s);
			if (Math.abs(d) < 1e-6) break;
			s -= e / d;
		}
		let lo = 0;
		let hi = 1;
		s = x;
		for (let i = 0; i < 40; i++) {
			const v = sx(s);
			if (Math.abs(v - x) < 1e-7) break;
			if (v < x) lo = s;
			else hi = s;
			s = (lo + hi) / 2;
		}
		return sy(s);
	};
}

export const easeTurn = bezier(0.6, 0, 0.2, 1.2);
export const easeOut = bezier(0.2, 0, 0, 1);
export const easeIn = bezier(0.4, 0, 1, 1);
export const easeInOut = bezier(0.45, 0, 0.25, 1);

export const clamp01 = (v: number) => Math.min(1, Math.max(0, v));

const fmt = (v: number) => {
	const s = v.toFixed(2);
	return s.includes('.') ? s.replace(/0+$/, '').replace(/\.$/, '') : s;
};

// The rotor with its axis at (cx, cy) and module m, at rest (one arm
// pointing right). Port of mark_path in docs/brand/build/geometry.py.
export function markPath(cx: number, cy: number, m: number, bore = true): string {
	const R = 1.5 * m;
	const h = 0.5 * m;
	const E = 3.0 * m;
	const d = Math.sqrt(R * R - h * h);
	const p = (x: number, y: number) => `${fmt(x)} ${fmt(y)}`;
	const out: string[] = [];
	let first: [number, number] = [0, 0];
	[0, 120, 240].forEach((a, i) => {
		const t = (a * Math.PI) / 180;
		const ux = Math.cos(t);
		const uy = Math.sin(t);
		const px = -uy;
		const py = ux;
		const at = (s: number, o: number): [number, number] => [cx + ux * s + px * o, cy + uy * s + py * o];
		const A = at(d, -h);
		const B = at(E - h, -h);
		const C = at(E - h, h);
		const D = at(d, h);
		if (i === 0) {
			first = A;
			out.push('M' + p(...A));
		} else {
			out.push(`A${fmt(R)} ${fmt(R)} 0 0 1 ` + p(...A));
		}
		out.push('L' + p(...B));
		out.push(`A${fmt(h)} ${fmt(h)} 0 0 1 ` + p(...C));
		out.push('L' + p(...D));
	});
	out.push(`A${fmt(R)} ${fmt(R)} 0 0 1 ` + p(...first) + 'Z');
	if (bore) {
		const r = 0.5 * m;
		out.push(`M${p(cx, cy - r)}a${fmt(r)} ${fmt(r)} 0 0 0 0 ${fmt(2 * r)}a${fmt(r)} ${fmt(r)} 0 0 0 0 ${fmt(-2 * r)}Z`);
	}
	return out.join('');
}

// Leftmost x, relative to the axis and in modules, of the down-left arm
// (120 degrees) on the lane, 2.25 modules under the axis. Port of
// _arm_left_boundary in docs/brand/build/graphics.py.
export function armLeftBoundary(offset = 2.25): number {
	const t = (120 * Math.PI) / 180;
	const x1 = Math.cos(t) * 2.5;
	const y1 = Math.sin(t) * 2.5;
	const inside = (x: number) => {
		const k = Math.max(0, Math.min(1, (x * x1 + offset * y1) / (x1 * x1 + y1 * y1)));
		return Math.hypot(x - k * x1, offset - k * y1) <= 0.5;
	};
	let x = -4;
	while (!inside(x)) x += 1 / 400;
	return x;
}

// The wordmark "catraca", outlined from Atkinson Hyperlegible Next SemiBold
// in docs/brand/logo/horizontal-on-dark.svg. In that file the mark has
// m = 12 with its axis at (21, 31.98), and the word starts at x = 75.
export const LOCKUP = {
	width: 302.98,
	height: 63.96,
	m: 12,
	axis: [21, 31.98] as const,
};
