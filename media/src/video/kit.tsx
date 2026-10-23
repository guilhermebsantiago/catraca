// Kinetic pieces for the launch video: words that rise out of a mask, panels
// that settle on a spring, chips that pop on a beat. Every value is a pure
// function of t (ms), sampled from Motion's springs and easings.

import React from 'react';
import {ACTION_COLORS, Action, FONT_MONO, FONT_SANS, NEUTRAL, clamp01, easeIn} from '../brand';
import {POP, SOFT, delays, springAt, tween} from '../motion';

const C = ACTION_COLORS.dark;

// How far in (0..1) and out (0..1) something is that enters at `from` on a
// spring and leaves at `to` on an ease-in.
export function life(t: number, from: number, to = Infinity, o = SOFT, outMs = 280) {
	const inP = springAt(t, from, o);
	const outP = to === Infinity ? 0 : easeIn(clamp01((t - to) / outMs));
	return {inP, outP, visible: t >= from && outP < 1};
}

export type Part = string | {text: string; color?: string; mono?: boolean; weight?: number};

// A line of words, each rising out of its own mask in turn; they leave the
// same way, upwards.
export const Words: React.FC<{
	t: number;
	from: number;
	to?: number;
	parts: Part[];
	size?: number;
	color?: string;
	weight?: number;
	each?: number; // ms between words
	style?: React.CSSProperties;
	lineHeight?: number;
}> = ({t, from, to = Infinity, parts, size = 92, color = NEUTRAL.paper2, weight = 600, each = 55, style, lineHeight = 1.12}) => {
	if (t < from || (to !== Infinity && t > to + 900)) return null;
	const words: {text: string; color: string; mono: boolean; weight: number}[] = [];
	for (const p of parts) {
		const o = typeof p === 'string' ? {text: p} : p;
		// Words break at plain spaces only; a no-break space keeps a phrase whole.
		for (const w of o.text.split(/(?<= )/)) {
			if (w.trim()) words.push({text: w.trim(), color: o.color ?? color, mono: o.mono ?? false, weight: o.weight ?? weight});
		}
	}
	const ds = delays(words.length, each);
	const outDs = delays(words.length, each * 0.4);
	return (
		<div style={{position: 'absolute', fontFamily: FONT_SANS, fontSize: size, lineHeight, letterSpacing: '-0.01em', ...style}}>
			{words.map((w, i) => {
				const p = springAt(t, from + ds[i], SOFT);
				const q = to === Infinity ? 0 : easeIn(clamp01((t - to - outDs[i]) / 260));
				const y = (1 - p) * 105 - q * 105;
				return (
					<React.Fragment key={i}>
					<span
						style={{
							display: 'inline-block',
							overflow: 'hidden',
							verticalAlign: 'top',
							// Room for descenders inside the mask.
							padding: '0 0.04em 0.12em',
							margin: '0 -0.04em -0.12em',
						}}
					>
						<span
							style={{
								display: 'inline-block',
								translate: `0 ${y}%`,
								color: w.color,
								fontWeight: w.weight,
								fontFamily: w.mono ? FONT_MONO : undefined,
								fontSize: w.mono ? '0.88em' : undefined,
							}}
						>
							{w.text}
						</span>
					</span>
					{i < words.length - 1 ? ' ' : null}
					</React.Fragment>
				);
			})}
		</div>
	);
};

// "01 / new account", in the mono, above a scene's headline.
export const Kicker: React.FC<{t: number; from: number; to?: number; n: string; label: string; x: number; y: number}> = ({t, from, to, n, label, x, y}) => {
	const l = life(t, from, to);
	if (!l.visible) return null;
	const w = clamp01(l.inP);
	return (
		<div
			style={{
				position: 'absolute',
				left: x,
				top: y,
				display: 'flex',
				alignItems: 'center',
				gap: 16,
				fontFamily: FONT_MONO,
				fontSize: 28,
				color: NEUTRAL.steel2,
				opacity: w * (1 - l.outP),
				translate: `${(1 - l.inP) * -24}px 0`,
			}}
		>
			<span style={{color: NEUTRAL.paper2}}>{n}</span>
			<span style={{display: 'inline-block', width: 48 * w, height: 2, background: NEUTRAL.ink3}} />
			<span>{label}</span>
		</div>
	);
};

// A panel that settles in on a spring and drops away when it leaves.
export const Panel: React.FC<{
	t: number;
	from: number;
	to?: number;
	x: number;
	y: number;
	w: number;
	h?: number;
	title?: React.ReactNode;
	status?: React.ReactNode;
	children?: React.ReactNode;
	accent?: string; // the border, when the panel is about a decision
	accentFrom?: number;
}> = (p) => {
	const l = life(p.t, p.from, p.to);
	if (!l.visible) return null;
	const a = p.accent && p.accentFrom !== undefined ? tween(p.t, p.accentFrom, 300) : 0;
	return (
		<div
			style={{
				position: 'absolute',
				left: p.x,
				top: p.y,
				width: p.w,
				height: p.h,
				opacity: clamp01(l.inP * 1.4) * (1 - l.outP),
				translate: `0 ${(1 - l.inP) * 46 + l.outP * 24}px`,
				scale: `${0.96 + 0.04 * l.inP}`,
				transformOrigin: '50% 100%',
				background: NEUTRAL.ink2,
				border: `2px solid ${a > 0 ? mixHex(NEUTRAL.ink3, p.accent!, a) : NEUTRAL.ink3}`,
				borderRadius: 18,
				overflow: 'hidden',
				boxShadow: '0 30px 80px rgba(0,0,0,0.35)',
			}}
		>
			{p.title !== undefined ? (
				<div
					style={{
						display: 'flex',
						justifyContent: 'space-between',
						alignItems: 'center',
						height: 64,
						padding: '0 30px',
						borderBottom: `2px solid ${NEUTRAL.ink3}`,
						fontFamily: FONT_MONO,
						fontSize: 24,
						color: NEUTRAL.paper2,
						whiteSpace: 'nowrap',
					}}
				>
					<div>{p.title}</div>
					<div style={{color: NEUTRAL.steel2}}>{p.status}</div>
				</div>
			) : null}
			<div style={{padding: '22px 30px', fontFamily: FONT_MONO, fontSize: 26, lineHeight: 1.55, color: NEUTRAL.paper2}}>{p.children}</div>
		</div>
	);
};

// One member of a recorded answer, as JSON: "key": value. An action is set
// in its color on its tint, with its name, as the brand asks.
export const Field: React.FC<{k: string; v: unknown; t?: number; from?: number; dim?: boolean; last?: boolean}> = ({k, v, t, from, dim, last}) => {
	const shown = t === undefined || from === undefined ? 1 : tween(t, from, 300);
	const s = typeof v === 'string' ? JSON.stringify(v) : JSON.stringify(v);
	const isAction = k === 'action' && typeof v === 'string' && v in C;
	return (
		<div style={{opacity: shown * (dim ? 0.45 : 1), translate: `${(1 - shown) * 16}px 0`, whiteSpace: 'nowrap'}}>
			<span style={{color: NEUTRAL.steel2}}>{JSON.stringify(k)}</span>
			<span style={{color: '#6B7680'}}>: </span>
			{isAction ? (
				<span style={{color: C[v as Action].text, background: C[v as Action].tint, borderRadius: 8, padding: '2px 8px', margin: '0 -8px'}}>{s}</span>
			) : (
				<span style={{color: NEUTRAL.paper2}}>{s}</span>
			)}
			{last ? null : <span style={{color: '#6B7680'}}>,</span>}
		</div>
	);
};

// An action named in its color.
export const ActionWord: React.FC<{a: Action; mono?: boolean}> = ({a, mono = true}) => (
	<span style={{color: C[a].text, fontFamily: mono ? FONT_MONO : undefined, fontSize: mono ? '0.9em' : undefined}}>{a}</span>
);

export const Code: React.FC<{children: React.ReactNode}> = ({children}) => (
	<span style={{fontFamily: FONT_MONO, fontSize: '0.88em', color: NEUTRAL.paper2}}>{children}</span>
);

// A chip that pops in on a beat: a dot in the action's color and its name.
export const Chip: React.FC<{t: number; from: number; to?: number; a: Action | 'shadow'; label?: string; size?: number}> = ({t, from, to, a, label, size = 44}) => {
	const l = life(t, from, to, POP);
	if (!l.visible) return null;
	const c = C[a];
	const d = size * 0.5;
	return (
		<div
			style={{
				display: 'inline-flex',
				alignItems: 'center',
				gap: size * 0.32,
				padding: `${size * 0.22}px ${size * 0.5}px ${size * 0.22}px ${size * 0.36}px`,
				borderRadius: 999,
				background: c.tint,
				fontFamily: FONT_MONO,
				fontSize: size,
				color: c.text,
				opacity: clamp01(l.inP * 2) * (1 - l.outP),
				scale: `${0.6 + 0.4 * l.inP}`,
				translate: `0 ${l.outP * -20}px`,
			}}
		>
			<svg width={d} height={d} viewBox="0 0 20 20">
				{a === 'shadow' ? (
					<circle cx={10} cy={10} r={8} fill="none" stroke={c.mark} strokeWidth={2.6} strokeDasharray="3.6 2.7" />
				) : (
					<circle cx={10} cy={10} r={9} fill={c.mark} />
				)}
			</svg>
			{label ?? a}
		</div>
	);
};

// A number that counts to its value, blurred while it moves fast.
export const Counter: React.FC<{value: number; prev?: number; speed?: number; decimals?: number; style?: React.CSSProperties}> = ({value, speed = 0, decimals = 0, style}) => (
	<span style={{fontVariantNumeric: 'tabular-nums', filter: speed > 0.5 ? `blur(${Math.min(6, speed * 0.4)}px)` : undefined, ...style}}>
		{value.toLocaleString('en-US', {minimumFractionDigits: decimals, maximumFractionDigits: decimals})}
	</span>
);

export function mixHex(a: string, b: string, p: number): string {
	const pa = [1, 3, 5].map((i) => parseInt(a.slice(i, i + 2), 16));
	const pb = [1, 3, 5].map((i) => parseInt(b.slice(i, i + 2), 16));
	return '#' + pa.map((v, i) => Math.round(v + (pb[i] - v) * clamp01(p)).toString(16).padStart(2, '0')).join('');
}
