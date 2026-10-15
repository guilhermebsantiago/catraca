import React from 'react';
import {ACTION_COLORS, Action, FONT_MONO, FONT_SANS, NEUTRAL, clamp01, easeIn, easeOut} from '../brand';
import {Line, Token, layout} from './json';

const C = ACTION_COLORS.dark;
export const ACTION_NAMES = new Set(['allow', 'flag', 'throttle', 'hold', 'block']);

// Opacity and offset of something shown from `from` to `to` (ms), arriving
// on ease-out and leaving on ease-in.
export function presence(t: number, from: number, to = Infinity, inMs = 450, outMs = 300) {
	const a = easeOut(clamp01((t - from) / inMs));
	const b = to === Infinity ? 0 : easeIn(clamp01((t - to) / outMs));
	return {opacity: a * (1 - b), dy: (1 - a) * 18 - b * 10, visible: a * (1 - b) > 0.001};
}

export const Appear: React.FC<{
	t: number;
	from: number;
	to?: number;
	style?: React.CSSProperties;
	children: React.ReactNode;
	inMs?: number;
}> = ({t, from, to, style, children, inMs}) => {
	const p = presence(t, from, to, inMs);
	if (!p.visible) return null;
	return (
		<div style={{position: 'absolute', ...style, opacity: p.opacity, transform: `translateY(${p.dy}px)`}}>{children}</div>
	);
};

export const Kicker: React.FC<{n: string; children: React.ReactNode}> = ({n, children}) => (
	<div style={{fontFamily: FONT_MONO, fontSize: 24, color: NEUTRAL.steel2, letterSpacing: '0.01em'}}>
		<span style={{color: NEUTRAL.paper2}}>{n}</span>
		<span style={{margin: '0 14px', color: NEUTRAL.ink3}}>/</span>
		{children}
	</div>
);

export const Headline: React.FC<{children: React.ReactNode; size?: number}> = ({children, size = 64}) => (
	<div
		style={{
			fontFamily: FONT_SANS,
			fontWeight: 600,
			fontSize: size,
			lineHeight: 1.1,
			letterSpacing: '-0.01em',
			color: NEUTRAL.paper2,
		}}
	>
		{children}
	</div>
);

export const Sub: React.FC<{children: React.ReactNode; width?: number}> = ({children, width = 1500}) => (
	<div style={{fontFamily: FONT_SANS, fontSize: 30, lineHeight: 1.4, color: NEUTRAL.steel2, maxWidth: width}}>{children}</div>
);

// Inline code in running text.
export const Code: React.FC<{children: React.ReactNode; color?: string}> = ({children, color}) => (
	<span style={{fontFamily: FONT_MONO, fontSize: '0.9em', color: color ?? NEUTRAL.paper2}}>{children}</span>
);

// An action named in its color, as the brand asks: never color alone.
export const ActionWord: React.FC<{a: Action; mono?: boolean}> = ({a, mono = true}) => (
	<span style={{color: C[a].text, fontFamily: mono ? FONT_MONO : undefined, fontSize: mono ? '0.9em' : undefined}}>{a}</span>
);

export const Note: React.FC<{children: React.ReactNode}> = ({children}) => (
	<div style={{fontFamily: FONT_SANS, fontSize: 22, color: NEUTRAL.steel2, display: 'flex', alignItems: 'center', gap: 12}}>
		<svg width={18} height={18} viewBox="0 0 18 18">
			<circle cx={9} cy={9} r={7.5} fill="none" stroke={NEUTRAL.steel2} strokeWidth={1.5} />
			<path d="M9 8v5M9 5.2v.1" stroke={NEUTRAL.steel2} strokeWidth={1.8} strokeLinecap="round" />
		</svg>
		<span>{children}</span>
	</div>
);

const TOKEN_COLOR: Record<Token['kind'], string> = {
	key: NEUTRAL.steel2,
	str: NEUTRAL.paper2,
	num: NEUTRAL.paper2,
	lit: NEUTRAL.paper2,
	punct: '#6B7680',
};

const PACK = ['id', 'event_id', 'mode', 'retry_after', 'latency_us', 'ruleset_version', 'effects', 'action', 'kind', 'source'];

export type PanelProps = {
	x: number;
	y: number;
	w: number;
	h?: number;
	title: React.ReactNode;
	status?: React.ReactNode;
	value?: unknown;
	lines?: Line[];
	fontSize?: number;
	// Keys whose lines are lit; the rest are dimmed. Empty: all lit.
	hot?: string[];
	hotFrom?: number; // ms; before it, every line is lit
	pack?: string[]; // keys that may share a line (default PACK)
	// When the content last changed, ms: the body dips and comes back.
	pulse?: number;
	t: number;
	from: number;
	to?: number;
	children?: React.ReactNode;
};

export const Panel: React.FC<PanelProps> = (p) => {
	const pr = presence(p.t, p.from, p.to);
	if (!pr.visible) return null;
	const fs = p.fontSize ?? 22;
	const charW = fs * 0.632;
	const padX = 28;
	const chars = Math.floor((p.w - padX * 2) / charW);
	const lines = p.lines ?? (p.value !== undefined ? layout(p.value, {width: chars, pack: p.pack ?? PACK}) : []);
	const hot = new Set(p.hot ?? []);
	const lit = hot.size === 0 ? 1 : easeOut(clamp01((p.t - (p.hotFrom ?? p.from + 600)) / 400));
	return (
		<div
			style={{
				position: 'absolute',
				left: p.x,
				top: p.y,
				width: p.w,
				height: p.h,
				opacity: pr.opacity,
				transform: `translateY(${pr.dy}px)`,
				background: NEUTRAL.ink2,
				border: `1px solid ${NEUTRAL.ink3}`,
				borderRadius: 14,
				overflow: 'hidden',
			}}
		>
			<div
				style={{
					display: 'flex',
					justifyContent: 'space-between',
					alignItems: 'center',
					height: 50,
					padding: `0 ${padX}px`,
					borderBottom: `1px solid ${NEUTRAL.ink3}`,
					fontFamily: FONT_MONO,
					fontSize: 20,
					color: NEUTRAL.paper2,
					whiteSpace: 'nowrap',
				}}
			>
				<div>{p.title}</div>
				<div style={{color: NEUTRAL.steel2}}>{p.status}</div>
			</div>
			<div
				style={{
					padding: `16px ${padX}px`,
					fontFamily: FONT_MONO,
					fontSize: fs,
					lineHeight: 1.42,
					whiteSpace: 'pre',
					opacity: p.pulse !== undefined && p.pulse > p.from + 100 ? 0.3 + 0.7 * easeOut(clamp01((p.t - p.pulse) / 260)) : 1,
				}}
			>
				{lines.map((l, i) => {
					const isHot = hot.size === 0 || l.keys.some((k) => hot.has(k));
					const op = isHot ? 1 : 1 - 0.55 * lit;
					return (
						<div key={i} style={{paddingLeft: l.indent * 2 * charW, opacity: op}}>
							{l.tokens.map((tk, j) => (
								<TokenSpan key={j} tk={tk} />
							))}
						</div>
					);
				})}
				{p.children}
			</div>
		</div>
	);
};

const TokenSpan: React.FC<{tk: Token}> = ({tk}) => {
	const raw = tk.kind === 'str' ? tk.text.replace(/^"|"$/g, '') : '';
	if (tk.kind === 'str' && tk.key === 'action' && ACTION_NAMES.has(raw)) {
		const a = raw as Action;
		return (
			<span style={{color: C[a].text, background: C[a].tint, borderRadius: 6, padding: '2px 6px', margin: '0 -6px'}}>
				{tk.text}
			</span>
		);
	}
	return <span style={{color: TOKEN_COLOR[tk.kind]}}>{tk.text}</span>;
};

// A terminal: commands after a prompt, then their output.
export type TermLine = {text: string; kind: 'cmd' | 'out' | 'dim' | 'hot' | 'blank'; at?: number};

export const Terminal: React.FC<{
	x: number;
	y: number;
	w: number;
	h?: number;
	title: string;
	lines: TermLine[];
	t: number;
	from: number;
	to?: number;
	fontSize?: number;
	children?: React.ReactNode;
	bodyRef?: React.Ref<HTMLDivElement>;
}> = (p) => {
	const pr = presence(p.t, p.from, p.to);
	if (!pr.visible) return null;
	const fs = p.fontSize ?? 21;
	return (
		<div
			style={{
				position: 'absolute',
				left: p.x,
				top: p.y,
				width: p.w,
				height: p.h,
				opacity: pr.opacity,
				transform: `translateY(${pr.dy}px)`,
				background: NEUTRAL.ink2,
				border: `1px solid ${NEUTRAL.ink3}`,
				borderRadius: 14,
				overflow: 'hidden',
			}}
		>
			<div
				style={{
					height: 50,
					display: 'flex',
					alignItems: 'center',
					padding: '0 28px',
					borderBottom: `1px solid ${NEUTRAL.ink3}`,
					fontFamily: FONT_MONO,
					fontSize: 20,
					color: NEUTRAL.steel2,
				}}
			>
				{p.title}
			</div>
			<div style={{position: 'relative', padding: '16px 28px', fontFamily: FONT_MONO, fontSize: fs, lineHeight: 1.45, whiteSpace: 'pre'}}>
				{p.lines.map((l, i) => {
					const shown = l.at === undefined ? 1 : easeOut(clamp01((p.t - l.at) / 250));
					if (shown <= 0) return <div key={i}>{' '}</div>;
					const color =
						l.kind === 'cmd' ? NEUTRAL.paper2 : l.kind === 'hot' ? NEUTRAL.paper : l.kind === 'dim' ? '#6B7680' : NEUTRAL.steel2;
					return (
						<div
							key={i}
							style={{
								color,
								opacity: shown,
								fontWeight: l.kind === 'hot' ? 600 : 400,
								whiteSpace: l.kind === 'cmd' ? 'pre-wrap' : 'pre',
								paddingLeft: l.kind === 'cmd' ? '2ch' : 0,
								textIndent: l.kind === 'cmd' ? '-2ch' : 0,
							}}
						>
							{l.kind === 'cmd' ? <span style={{color: '#6B7680'}}>$ </span> : null}
							{l.kind === 'cmd' ? <Args text={l.text} /> : l.text || ' '}
						</div>
					);
				})}
				{p.children}
			</div>
		</div>
	);
};


// A command line that wraps between arguments only, never inside one.
const Args: React.FC<{text: string}> = ({text}) => {
	const parts = text.match(/"[^"]*"|\S+/g) ?? [];
	return (
		<>
			{parts.map((a, i) => (
				<React.Fragment key={i}>
					<span style={{whiteSpace: 'nowrap'}}>{a}</span>
					{i < parts.length - 1 ? ' ' : null}
				</React.Fragment>
			))}
		</>
	);
};

// A header whose value is broken into lines of at most `width` characters,
// for values such as signatures that have no spaces to wrap at.
export const Header: React.FC<{name: string; value: string; width: number; size?: number}> = ({name, value, width, size = 18}) => {
	const lines: string[] = [];
	const parts = value.split(/(?<=,)/);
	let head = '';
	if (name.length + 2 + value.length <= width) {
		head = value;
		parts.length = 0;
	} else if (parts.length > 1 && name.length + 2 + parts[0].length <= width) {
		head = parts.shift()!;
	}
	for (const part of parts) {
		for (let i = 0; i < part.length; i += width - 2) lines.push(part.slice(i, i + width - 2));
	}
	return (
		<div style={{fontSize: size, lineHeight: 1.45, color: NEUTRAL.steel2, whiteSpace: 'pre'}}>
			{name}:{head ? <span style={{color: NEUTRAL.paper2}}>{' ' + head}</span> : null}
			{lines.map((l, i) => (
				<div key={i} style={{color: NEUTRAL.paper2, paddingLeft: '2ch'}}>
					{l}
				</div>
			))}
		</div>
	);
};
