// The launch video: 1920 x 1080, 60 fps, dark theme, cut to its music
// (scripts/score.mjs, 125 BPM). Every request, answer, webhook and number on
// screen is what examples/demo recorded from a real `catraca serve`
// (src/data.ts) or what docs/benchmark.md measured; the lane plays the
// decisions it made, each one clicking on a beat. The opening (traffic
// stopping on a paused account) is an illustration.

import React from 'react';
import {Audio} from '@remotion/media';
import {AbsoluteFill, Sequence, staticFile, useCurrentFrame} from 'remotion';
import {ACTION_COLORS, FONT_MONO, FONT_SANS, LOCKUP, MOTION, NEUTRAL, THEMES, clamp01, easeIn, easeInOut, easeOut, easeTurn, markPath} from '../brand';
import {S, phase, step, toItem} from '../data';
import {Lane} from '../lane/Lane';
import {GEOMETRY, scheduleAt} from '../lane/sim';
import {FIRM, POP, SOFT, circOut, springAt, tween} from '../motion';
import {WORDMARK_PATH} from '../wordmark';
import {ActionWord, Chip, Counter, Field, Kicker, Panel, Words, life, mixHex} from './kit';
import {
	BAR,
	BEAT,
	DURATION_MS,
	FPS,
	HEIGHT,
	LANE,
	SCENES,
	WIDTH,
	at,
	beat,
	burstCount,
	complaintRounds,
	laneData,
	laneSlots,
	signupAccount,
	slot,
} from './timeline';

const C = ACTION_COLORS.dark;
const T = THEMES.dark;
const X = 120; // side margin
const RX = 1060; // the right column
const RW = 740;
const KICK_Y = 92;
const HEAD_Y = 146;
const SUB_Y = 384;
const HEAD_W = 900;
const LANE_Y = LANE.ay + GEOMETRY.offset * LANE.m; // the rail
const BOTTOM_Y = 820;
const DIM = '#6B7680';
// A no-break space: Words keeps the phrase on one line.
const NBSP = String.fromCharCode(160);

const f = (ms: number) => Math.round((ms * FPS) / 1000);

// `at` (ms) renders one moment instead of following the timeline: the poster.
export const Launch: React.FC<{at?: number; music?: boolean}> = ({at, music = true}) => {
	const frame = useCurrentFrame();
	const t = at ?? (frame * 1000) / FPS;
	const scene = (name: string, from: number, to: number, el: React.ReactNode) => (
		<Sequence name={name} from={f(from)} durationInFrames={f(to - from)} layout="none">
			{el}
		</Sequence>
	);
	return (
		<AbsoluteFill style={{background: T.bg, fontFamily: FONT_SANS, color: NEUTRAL.paper2}}>
			{music && at === undefined ? <Audio src={staticFile('audio/score.wav')} /> : null}
			<Backdrop t={t} />
			{at === undefined ? (
				<>
					{scene('Problem', 0, SCENES.logo, <Problem t={t} />)}
					{scene('Logo', SCENES.logo - 200, SCENES.ask + 100, <Logo t={t} />)}
					{scene('Lane', SCENES.logo + 3000, SCENES.gate + 800, <MainLane t={t} />)}
					{scene('Ask', SCENES.ask, SCENES.burst + 400, <Ask t={t} />)}
					{scene('Burst', SCENES.rule, SCENES.complaints + 400, <Burst t={t} />)}
					{scene('Complaints', SCENES.complaints, SCENES.leak + 1800, <Complaints t={t} />)}
					{scene('Leak', SCENES.leak, SCENES.shadow + 400, <Leak t={t} />)}
					{scene('Shadow', SCENES.shadow, SCENES.numbers, <Shadow t={t} />)}
					{scene('Gate', SCENES.gate - 200, SCENES.numbers + 400, <Gate t={t} />)}
					{scene('Numbers', SCENES.numbers, SCENES.close + 600, <Numbers t={t} />)}
					{scene('Close', SCENES.close - 200, DURATION_MS, <Close t={t} />)}
				</>
			) : (
				<Close t={t} />
			)}
			<Vignette />
		</AbsoluteFill>
	);
};

// --- Backdrop ------------------------------------------------------------------

// A grid of faint dots one lane module apart, drifting with the traffic. It
// lifts a little on the downbeats while the drums play, and a wave runs
// through it from the three hits: the mark, the promotion, the end.
const PULSE = [
	[SCENES.logo, at(22)],
	[SCENES.promote, at(32)],
];

const Backdrop: React.FC<{t: number}> = ({t}) => {
	const s = 48;
	const dx = -((t * 0.012) % s);
	const waves = [
		{at: SCENES.logo, x: LOGO.ax, y: LOGO.ay},
		{at: SCENES.promote, x: X + 60, y: 536},
		{at: SCENES.final, x: 512, y: 352},
	];
	const bar = t % BAR;
	const pulse = PULSE.some(([a, b]) => t >= a && t < b) ? 0.22 * Math.exp(-bar / 260) : 0;
	const dots: React.ReactNode[] = [];
	for (let j = 0; j * s < HEIGHT + s; j++) {
		for (let i = 0; i * s < WIDTH + 2 * s; i++) {
			const x = i * s + s / 2 + dx;
			const y = j * s + s / 2;
			let b = pulse;
			for (const w of waves) {
				const age = t - w.at;
				if (age < 0 || age > 1800) continue;
				const d = Math.hypot(x - w.x, y - w.y) - age * 1.5;
				b += Math.exp(-(d * d) / (2 * 70 * 70)) * Math.exp(-age / 700) * 0.9;
			}
			dots.push(<circle key={`${i}-${j}`} cx={x} cy={y} r={1.6 + 1.2 * clamp01(b)} fill={mixHex(NEUTRAL.ink3, NEUTRAL.steel2, clamp01(b))} />);
		}
	}
	return (
		<svg width={WIDTH} height={HEIGHT} style={{position: 'absolute'}}>
			<defs>
				<radialGradient id="glow" cx="30%" cy="55%" r="70%">
					<stop offset="0%" stopColor="#1B2228" />
					<stop offset="100%" stopColor={T.bg} stopOpacity={0} />
				</radialGradient>
			</defs>
			<rect width={WIDTH} height={HEIGHT} fill="url(#glow)" />
			<g opacity={0.6}>{dots}</g>
		</svg>
	);
};

const Vignette: React.FC = () => (
	<AbsoluteFill style={{background: 'radial-gradient(ellipse at 50% 50%, rgba(0,0,0,0) 55%, rgba(5,8,10,0.55) 100%)', pointerEvents: 'none'}} />
);

// --- 1. The problem ------------------------------------------------------------

const P = {m: 48, decel: 640};

const Problem: React.FC<{t: number}> = ({t}) => {
	if (t > SCENES.logo) return null;
	const {m, decel} = P;
	const stop = SCENES.stop;
	const v = m / MOTION.pitch;
	const after = Math.max(0, Math.min(t - stop, decel));
	const shift = v * (Math.min(t, stop) + after - (after * after) / (2 * decel));
	const r = 0.3 * m;
	const sw = 3;
	const n = 16;
	const gap = 0.42 * m;
	const L = (n - 1) * gap;
	const clusterAtStop = 1180;
	const c0 = clusterAtStop - v * (stop + decel / 2) - L / 2;
	const xs: {x: number; burst: boolean}[] = [];
	const ph = ((c0 % m) + m) % m;
	for (let k = -80; k < 60; k++) {
		const x = k * m + ph;
		if (x > c0 - 0.8 * m && x < c0 + L + 0.8 * m) continue;
		xs.push({x, burst: false});
	}
	for (let i = 0; i < n; i++) xs.push({x: c0 + i * gap, burst: true});
	const lit = tween(t, 3840 + 150, 500);
	const paused = tween(t, stop + decel * 0.5, 500);
	const fadeIn = tween(t, 0, 900);
	// The music stops with the traffic; a bar later everything leaves.
	const outP = tween(t, 10700, 700, easeIn);
	const label = life(t, 4300, 7400);
	return (
		<AbsoluteFill style={{opacity: fadeIn * (1 - outP), scale: `${1 + 0.05 * outP}`}}>
			<svg width={WIDTH} height={HEIGHT} style={{position: 'absolute'}}>
				<path stroke={T.rail} strokeWidth={2.4} d={`M0 ${LANE_Y}H${WIDTH}`} />
				{xs.map(({x: x0, burst}, i) => {
					const x = x0 + shift;
					if (x < -30 || x > WIDTH + 30) return null;
					const stroke = burst ? mixHex(T.ring, NEUTRAL.paper, lit) : T.ring;
					return (
						<circle
							key={i}
							cx={x}
							cy={LANE_Y}
							r={r - sw / 2}
							fill={T.bg}
							stroke={stroke}
							strokeWidth={sw}
							opacity={1 - 0.5 * paused}
						/>
					);
				})}
				{label.visible ? (
					<text
						x={c0 + shift + L / 2}
						y={LANE_Y + 70}
						textAnchor="middle"
						fontFamily={FONT_MONO}
						fontSize={28}
						fill={NEUTRAL.paper2}
						opacity={clamp01(label.inP) * (1 - label.outP)}
					>
						one account, bursting
					</text>
				) : null}
			</svg>
			<Paused t={t} from={stop + 360} />
			<Climb t={t} />
			<Words t={t} from={480} to={3450} parts={['You send email for thousands of customers.']} size={96} style={{left: X, top: 200, width: 1100}} />
			<Words
				t={t}
				from={3840}
				to={5450}
				parts={['One of them ', {text: 'is an abuser.', color: NEUTRAL.paper}]}
				size={96}
				color={NEUTRAL.steel2}
				style={{left: X, top: 200, width: 1100}}
			/>
			<Words t={t} from={5760} to={7380} parts={['Bounces climb.']} size={96} style={{left: X, top: 200, width: 900}} />
			<Words t={t} from={6240} to={7380} parts={['Complaints climb.']} size={96} style={{left: X, top: 306, width: 900}} />
			<Words t={t} from={7680} to={10500} parts={['Your provider pauses sending']} size={96} color={NEUTRAL.steel2} style={{left: X, top: 200, width: 1700}} />
			<Words t={t} from={9600} to={10500} parts={['for ', {text: 'every customer.', color: NEUTRAL.paper}]} size={96} color={NEUTRAL.steel2} style={{left: X, top: 306, width: 1700}} each={90} />
		</AbsoluteFill>
	);
};

const Paused: React.FC<{t: number; from: number}> = ({t, from}) => {
	const l = life(t, from, Infinity, POP);
	if (!l.visible) return null;
	return (
		<div
			style={{
				position: 'absolute',
				right: X,
				top: LANE_Y - 92,
				display: 'flex',
				alignItems: 'center',
				gap: 16,
				fontFamily: FONT_MONO,
				fontSize: 30,
				color: NEUTRAL.paper2,
				opacity: clamp01(l.inP * 1.5),
				scale: `${0.85 + 0.15 * l.inP}`,
			}}
		>
			<svg width={22} height={26} viewBox="0 0 16 18">
				<rect x={1} y={1} width={4.5} height={16} rx={1.5} fill={NEUTRAL.paper2} />
				<rect x={10.5} y={1} width={4.5} height={16} rx={1.5} fill={NEUTRAL.paper2} />
			</svg>
			sending paused for everyone
		</div>
	);
};

// Two rates climbing past the provider's limit (an illustration).
const Climb: React.FC<{t: number}> = ({t}) => {
	const charts = [
		{label: 'bounce rate', from: 5760, y: 230},
		{label: 'complaint rate', from: 6240, y: 440},
	];
	return (
		<>
			{charts.map((c, i) => {
				const l = life(t, c.from, 7380);
				if (!l.visible) return null;
				const w = 700;
				const h = 150;
				const limit = 46;
				const draw = tween(t, c.from + 150, 1250, easeInOut);
				const pts: string[] = [];
				const N = 60;
				for (let k = 0; k <= N * draw; k++) {
					const u = k / N;
					const y = h - 8 - (h - 20) * Math.pow(u, 2.3) + 5 * Math.sin(u * 19 + i * 2) * (1 - u);
					pts.push(`${(u * w).toFixed(1)},${y.toFixed(1)}`);
				}
				const last = pts[pts.length - 1]?.split(',').map(Number) ?? [0, h];
				const over = last[1] < limit;
				return (
					<div
						key={c.label}
						style={{position: 'absolute', left: RX + 40, top: c.y, width: w, opacity: clamp01(l.inP * 1.4) * (1 - l.outP), translate: `0 ${(1 - l.inP) * 30}px`}}
					>
						<div style={{fontFamily: FONT_MONO, fontSize: 26, color: NEUTRAL.steel2, marginBottom: 8}}>{c.label}</div>
						<svg width={w} height={h} style={{overflow: 'visible'}}>
							<path d={`M0 ${h}H${w}`} stroke={NEUTRAL.ink3} strokeWidth={2} />
							<path d={`M0 ${limit}H${w}`} stroke={NEUTRAL.steel} strokeWidth={2} strokeDasharray="8 8" />
							<text x={w} y={limit - 12} textAnchor="end" fontFamily={FONT_MONO} fontSize={20} fill={NEUTRAL.steel2}>
								provider limit
							</text>
							<polyline points={pts.join(' ')} fill="none" stroke={NEUTRAL.paper2} strokeWidth={4} strokeLinejoin="round" strokeLinecap="round" />
							{pts.length > 1 ? <circle cx={last[0]} cy={last[1]} r={over ? 9 : 6} fill={over ? NEUTRAL.paper : NEUTRAL.paper2} /> : null}
						</svg>
					</div>
				);
			})}
		</>
	);
};

// --- 2. The mark ---------------------------------------------------------------

const LOGO = (() => {
	const s = 3.6;
	const w = LOCKUP.width * s;
	const h = LOCKUP.height * s;
	const x0 = (WIDTH - w) / 2;
	const y0 = 340;
	return {s, w, h, x0, y0, ax: x0 + LOCKUP.axis[0] * s, ay: y0 + LOCKUP.axis[1] * s, m: LOCKUP.m * s};
})();

const Logo: React.FC<{t: number}> = ({t}) => {
	const from = SCENES.logo;
	if (t < from || t >= SCENES.ask) return null;
	const {s, x0, y0} = LOGO;
	const appear = springAt(t, from, POP);
	// The ratchet clicks a third of a turn on the next bar.
	const turnAt = from + 4 * BEAT - MOTION.turn;
	const turn = t < turnAt + MOTION.turn ? -120 * easeTurn(clamp01((t - turnAt) / MOTION.turn)) : 0;
	// Then the mark drops onto the lane.
	const move = tween(t, SCENES.ask - 720, 720, easeInOut);
	const ax = LOGO.ax + (LANE.ax - LOGO.ax) * move;
	const ay = LOGO.ay + (LANE.ay - LOGO.ay) * move;
	const m = LOGO.m + (LANE.m - LOGO.m) * move;
	const word = springAt(t, from + 240, SOFT) * (1 - tween(t, SCENES.ask - 1000, 420, easeIn));
	const wordX = x0 + 75 * s;
	const wordW = (LOCKUP.width - 75) * s + 20;
	return (
		<AbsoluteFill>
			<svg width={WIDTH} height={HEIGHT} style={{position: 'absolute'}}>
				<defs>
					<clipPath id="word">
						<rect x={wordX - 20} y={y0 - 20} width={Math.max(0, wordW * word)} height={LOGO.h + 40} />
					</clipPath>
				</defs>
				<g clipPath="url(#word)">
					<g transform={`translate(${x0 + (1 - word) * -80} ${y0}) scale(${s})`}>
						<path fill={T.fg} d={WORDMARK_PATH} />
					</g>
				</g>
				<g
					opacity={clamp01((t - from) / 60)}
					transform={`translate(${ax} ${ay}) scale(${0.55 + 0.45 * appear}) rotate(${turn}) translate(${-ax} ${-ay})`}
				>
					<path fill={T.fg} d={markPath(ax, ay, m)} />
				</g>
			</svg>
			<Words
				t={t}
				from={from + 4 * BEAT}
				to={SCENES.ask - 1000}
				parts={['Anti-abuse engine for platforms that send email.']}
				size={52}
				weight={500}
				color={NEUTRAL.steel2}
				each={45}
				style={{left: 0, width: WIDTH, top: y0 + LOGO.h + 56, textAlign: 'center'}}
			/>
		</AbsoluteFill>
	);
};

// --- The lane, from the mark to the gate --------------------------------------

// Camera pushes toward the rotor at the decisions that stop traffic.
function camera(t: number) {
	const push = (from: number, to: number, amp: number) => amp * springAt(t, from, FIRM) * (1 - springAt(t, to, FIRM));
	const th = slot('throttle');
	const hold = slot('hold');
	const block = slot('block');
	const z = 1 + push(th.start, th.click + 120, 0.16) + push(hold.click - 160, hold.click + 1300, 0.08) + push(block.start - 200, block.click + 1500, 0.14);
	const away = tween(t, SCENES.gate - 300, 700, easeIn);
	return {z: z * (1 - 0.12 * away), dy: 220 * away, opacity: 1 - away};
}

const MainLane: React.FC<{t: number}> = ({t}) => {
	const cam = camera(t);
	if (cam.opacity <= 0) return null;
	const reveal = 2100 * tween(t, SCENES.ask - 560, 1300, circOut);
	const th = slot('throttle');
	const label = t > th.start - 100 && t < th.turnStart + 100 ? `Retry-After: ${step('throttle').response_headers?.['Retry-After']}` : undefined;
	const {ax, ay} = LANE;
	return (
		<svg width={WIDTH} height={HEIGHT} style={{position: 'absolute', opacity: cam.opacity}}>
			<g transform={`translate(${ax} ${ay + cam.dy}) scale(${cam.z}) translate(${-ax} ${-ay})`}>
				<Lane
					slots={laneSlots}
					t={t}
					theme="dark"
					ax={ax}
					ay={ay}
					m={LANE.m}
					width={WIDTH}
					railFrom={ax - reveal}
					railTo={ax + reveal}
					rotorOpacity={t >= SCENES.ask ? 1 : 0}
					dim={(x) => clamp01((reveal - Math.abs(x - ax)) / 90)}
					countdownLabel={label}
					labelFont={FONT_MONO}
					labelSize={26}
				/>
			</g>
		</svg>
	);
};

// A scene's kicker, headline and line under it.
const Heading: React.FC<{
	t: number;
	from: number;
	to: number;
	n?: string;
	kicker?: string;
	title: string;
	sub?: React.ComponentProps<typeof Words>['parts'];
	width?: number;
	lines?: number; // of the headline
}> = ({t, from, to, n, kicker, title, sub, width = HEAD_W, lines = 2}) => (
	<>
		{n && kicker ? <Kicker t={t} from={from} to={to} n={n} label={kicker} x={X} y={KICK_Y} /> : null}
		<Words t={t} from={from + 60} to={to} parts={[title]} size={92} style={{left: X, top: HEAD_Y, width}} />
		{sub ? (
			<Words t={t} from={from + 420} to={to} parts={sub} size={40} weight={400} color={NEUTRAL.steel2} each={30} style={{left: X, top: SUB_Y - (2 - lines) * 104, width: HEAD_W}} />
		) : null}
	</>
);

// --- 3. Catraca asks before every send ------------------------------------------

const Ask: React.FC<{t: number}> = ({t}) => {
	const from = SCENES.ask;
	const to = SCENES.burst - 260;
	const legend = ['allow', 'flag', 'throttle', 'hold', 'block'] as const;
	return (
		<>
			<Heading t={t} from={from} to={to} title="Catraca asks before every send." sub={['Self-hosted, in the path of each send.']} />
			<Feed t={t} from={slot('flow').click + 100} to={SCENES.rule - 200} />
			<div style={{position: 'absolute', left: 0, width: WIDTH, top: BOTTOM_Y + 20, display: 'flex', justifyContent: 'center', gap: 28}}>
				{legend.map((a, i) => (
					<Chip key={a} t={t} from={SCENES.legend + i * BEAT} to={to} a={a} size={42} />
				))}
			</div>
		</>
	);
};

// The latest decisions, newest on top, as the rotor makes them.
const Feed: React.FC<{t: number; from: number; to: number}> = ({t, from, to}) => {
	const rowH = 58;
	const shown = 5;
	const done = laneSlots.filter((s) => s.click <= t && laneData[s.index].phase === 'flow');
	const newest = done[done.length - 1];
	const p = newest ? springAt(t, newest.click, SOFT) : 1;
	const rows = done.slice(-shown - 1).reverse();
	return (
		<Panel t={t} from={from} to={to} x={RX} y={HEAD_Y} w={RW} h={rowH * shown + 64 + 44} title="POST /v1/decide" status="decisions">
			<div style={{position: 'relative', height: rowH * shown, overflow: 'hidden'}}>
				{rows.map((s, i) => {
					const e = laneData[s.index];
					const y = (i - 1 + p) * rowH;
					const op = i === 0 ? p : i === shown ? 1 - p : 1;
					return (
						<div
							key={s.index}
							style={{position: 'absolute', left: 0, right: 0, top: y, height: rowH, display: 'flex', alignItems: 'center', gap: 24, opacity: op, fontSize: 28}}
						>
							<span style={{color: NEUTRAL.paper2, width: 230}}>{e.account_id}</span>
							<span style={{width: 150}}>
								<ActionWord a={e.action} mono={false} />
							</span>
							<span style={{color: NEUTRAL.steel2, marginLeft: 'auto'}}>
								{e.latency_us} <span style={{color: DIM}}>µs</span>
							</span>
						</div>
					);
				})}
			</div>
		</Panel>
	);
};

// --- 4. A new account bursts ----------------------------------------------------

const RULE = [
	[{k: '- id: '}, {v: 'new-account-burst'}],
	[{k: '  when: '}, {v: 'event.type == "send"'}],
	[{o: '    && '}, {v: 'account.age_hours < 24'}],
	[{o: '    && '}, {v: 'account.sends_1m > 100'}],
	[{k: '  action: '}, {a: 'throttle'}],
] as const;

const Burst: React.FC<{t: number}> = ({t}) => {
	const from = SCENES.burst;
	const to = SCENES.complaints - 260;
	const th = slot('throttle');
	const total = S.burst.allow + S.burst.throttle;
	const n = burstCount(t);
	const nPrev = burstCount(t - 1000 / FPS);
	const met = n > 100;
	const typeFrom = SCENES.rule + 200;
	const chars = Math.floor(Math.max(0, t - typeFrom) / 11);
	let used = 0;
	const answered = th.start + 160;
	const counter = life(t, from + 300, to);
	return (
		<>
			<Heading
				t={t}
				from={from}
				to={to}
				n="01"
				kicker="new account"
				title="A brand-new account bursts."
				sub={[{text: signupAccount, mono: true, color: NEUTRAL.paper2}, ` signs up and sends ${total} emails in a minute.`]}
			/>
			<Panel t={t} from={SCENES.rule} to={to} x={RX} y={HEAD_Y} w={RW} h={500} title="rules.yaml" status="CEL" accent={C.throttle.mark} accentFrom={th.start}>
				{RULE.map((line, i) => {
					const parts = line.map((p) => ('k' in p ? p.k : 'o' in p ? p.o : 'v' in p ? p.v : p.a));
					const len = parts.join('').length;
					const visible = Math.max(0, Math.min(len, chars - used));
					used += len;
					let left = visible;
					const mark = i === 1 || i === 2 ? (t >= from ? '✓' : '') : i === 3 && t >= from ? (met ? '✓' : `${n}`) : '';
					return (
						<div key={i} style={{display: 'flex', whiteSpace: 'pre', height: 40, alignItems: 'center'}}>
							{line.map((p, j) => {
								const text = parts[j].slice(0, Math.max(0, left));
								left -= parts[j].length;
								const color = 'k' in p ? NEUTRAL.steel2 : 'o' in p ? DIM : 'a' in p ? C.throttle.text : NEUTRAL.paper2;
								const lit = 'a' in p ? tween(t, th.start, 300) : 0;
								return (
									<span key={j} style={{color, background: lit > 0 ? `rgba(54,37,18,${lit})` : undefined, borderRadius: 8, padding: lit > 0 ? '0 8px' : 0}}>
										{text}
									</span>
								);
							})}
							{visible < len && visible > 0 ? <span style={{color: NEUTRAL.paper2}}>▍</span> : null}
							<span style={{marginLeft: 'auto', color: met && i === 3 ? NEUTRAL.paper : NEUTRAL.steel2, opacity: mark ? 1 : 0}}>{mark}</span>
						</div>
					);
				})}
				<div style={{height: 2, background: NEUTRAL.ink3, margin: '18px 0 14px', opacity: tween(t, answered, 300)}} />
				<Field k="action" v="throttle" t={t} from={answered} />
				<Field k="retry_after" v={60} t={t} from={answered + 120} />
				<Field k="latency_us" v={laneData[th.index].latency_us} t={t} from={answered + 240} last />
			</Panel>
			{counter.visible ? (
				<div style={{position: 'absolute', left: X, top: BOTTOM_Y - 10, opacity: clamp01(counter.inP * 1.4) * (1 - counter.outP), translate: `0 ${(1 - counter.inP) * 30}px`}}>
					<div style={{fontFamily: FONT_MONO, fontSize: 28, color: NEUTRAL.steel2}}>account.sends_1m</div>
					<div style={{display: 'flex', alignItems: 'baseline', gap: 22, fontFamily: FONT_MONO}}>
						<Counter value={n} speed={n - nPrev} style={{fontSize: 120, fontWeight: 600, color: NEUTRAL.paper2, minWidth: 260}} />
						<span style={{fontSize: 44, color: met ? NEUTRAL.paper2 : DIM}}>{met ? '> 100' : '≤ 100'}</span>
					</div>
				</div>
			) : null}
		</>
	);
};

// --- 5. Complaints ---------------------------------------------------------------

const Complaints: React.FC<{t: number}> = ({t}) => {
	const from = SCENES.complaints;
	const to = SCENES.leak - 260;
	const hold = slot('hold');
	// The rate climbs with each complaint; the 4th takes it past 0.3%.
	const level = complaintRounds.reduce((acc, r) => acc + 0.205 * springAt(t, r.arrive, POP), 0);
	const limit = 0.75;
	const held = tween(t, hold.click, 300);
	const barW = RW - 60;
	const bay = life(t, hold.click + 300, SCENES.leak + 1400);
	return (
		<>
			<Heading
				t={t}
				from={from}
				to={to}
				n="02"
				kicker="complaints"
				title="Complaints come back."
				sub={['Signed feedback arrives at ', {text: `POST${NBSP}/v1/feedback.`, mono: true, color: NEUTRAL.paper2}]}
			/>
			<Panel t={t} from={from + 120} to={to} x={RX} y={HEAD_Y} w={RW} h={500} title="acct_fernway" status="complaints, 24 h" accent={C.hold.mark} accentFrom={hold.click}>
				<div style={{display: 'flex', gap: 18, height: 56, alignItems: 'center'}}>
					{complaintRounds.map((r) => {
						const p = springAt(t, r.arrive, POP);
						return (
							<div key={r.n} style={{opacity: clamp01(p * 2), translate: `${(1 - p) * 260}px 0`, display: 'flex', alignItems: 'center', gap: 10, color: NEUTRAL.paper2}}>
								<Envelope />
								<span>#{r.n}</span>
							</div>
						);
					})}
				</div>
				<div style={{position: 'relative', height: 70, marginTop: 14}}>
					<div style={{position: 'absolute', top: 28, left: 0, width: barW, height: 14, borderRadius: 7, background: NEUTRAL.ink3}} />
					<div
						style={{
							position: 'absolute',
							top: 28,
							left: 0,
							width: barW * Math.min(1, level),
							height: 14,
							borderRadius: 7,
							background: mixHex(NEUTRAL.paper2, C.hold.mark, held),
						}}
					/>
					<div style={{position: 'absolute', top: 14, left: barW * limit, width: 3, height: 42, background: NEUTRAL.steel2}} />
					<div style={{position: 'absolute', top: -14, left: barW * limit - 40, fontSize: 22, color: NEUTRAL.steel2}}>0.3%</div>
				</div>
				<div style={{fontSize: 24, color: NEUTRAL.steel2, margin: '10px 0 6px'}}>next send after complaint</div>
				<div style={{display: 'flex', gap: 30}}>
					{complaintRounds.map((r) => {
						const p = springAt(t, r.decided, POP);
						return (
							<div key={r.n} style={{opacity: clamp01(p * 2), scale: `${0.7 + 0.3 * p}`, display: 'flex', gap: 10, fontSize: 28}}>
								<span style={{color: DIM}}>{r.n}</span>
								<ActionWord a={r.action} mono={false} />
							</div>
						);
					})}
				</div>
				<div style={{marginTop: 18}}>
					<Field k="rule_id" v="complaint-rate-high" t={t} from={hold.click + 150} last />
				</div>
				<div style={{fontSize: 22, color: NEUTRAL.steel2, opacity: tween(t, hold.click + 300, 300)}}>Spam complaint rate above 0.3% in the last 24 hours</div>
			</Panel>
			{bay.visible ? (
				<div
					style={{
						position: 'absolute',
						left: LANE.ax + (GEOMETRY.sector + 3.4) * LANE.m,
						top: LANE_Y + GEOMETRY.bayDrop * LANE.m - 20,
						fontFamily: FONT_MONO,
						fontSize: 28,
						color: C.hold.text,
						opacity: clamp01(bay.inP * 1.4) * (1 - bay.outP),
						translate: `${(1 - bay.inP) * -20}px 0`,
					}}
				>
					hold <span style={{color: NEUTRAL.steel2}}>· waiting for a person</span>
				</div>
			) : null}
		</>
	);
};

const Envelope: React.FC = () => (
	<svg width={34} height={26} viewBox="0 0 34 26">
		<rect x={1.5} y={1.5} width={31} height={23} rx={4} fill="none" stroke={NEUTRAL.paper2} strokeWidth={2.4} />
		<path d="M3 4l14 10L31 4" fill="none" stroke={NEUTRAL.paper2} strokeWidth={2.4} strokeLinejoin="round" />
	</svg>
);

// --- 6. A key leaks ----------------------------------------------------------------

const Leak: React.FC<{t: number}> = ({t}) => {
	const from = SCENES.leak;
	const to = SCENES.shadow - 260;
	const leak = step('key_leak');
	const block = slot('block');
	const blockStep = step('block');
	const hookAt = at21();
	const req = leak.request as {type: string; account_id: string; api_key_id: string; leak: {source: string; url: string}};
	const hook = S.hook;
	const sig = hook.headers['Catraca-Signature'];
	return (
		<>
			<Heading
				t={t}
				from={from}
				to={to}
				n="03"
				kicker="leaked key"
				title="A key leaks."
				lines={1}
				sub={['Reported by GitHub secret scanning, or at ', {text: `POST${NBSP}/v1/events.`, mono: true, color: NEUTRAL.paper2}]}
			/>
			<Panel t={t} from={from + 120} to={block.click - 200} x={RX} y={HEAD_Y} w={RW} h={360} title={`${leak.method} ${leak.path}`} status={`${leak.status} ${leak.status_text}`}>
				<Field k="type" v={req.type} />
				<Field k="account_id" v={req.account_id} />
				<Field k="api_key_id" v={req.api_key_id} />
				<Field k="source" v={req.leak.source} last />
				<div style={{fontSize: 21, color: NEUTRAL.steel2, marginTop: 8}}>{req.leak.url}</div>
			</Panel>
			<Panel t={t} from={block.click} to={hookAt - 200} x={RX} y={HEAD_Y} w={RW} h={360} title="POST /v1/decide" status="200 OK" accent={C.block.mark} accentFrom={block.click}>
				<Field k="api_key_id" v={req.api_key_id} />
				<Field k="action" v={(blockStep.response as {decision: {action: string}}).decision.action} />
				<Field k="rule_id" v="leaked-key-send" />
				<Field k="effects" v={['revoke_key']} last />
			</Panel>
			<Packet t={t} from={hookAt - 330} to={hookAt} />
			<Panel
				t={t}
				from={hookAt}
				to={to}
				x={RX}
				y={HEAD_Y}
				w={RW}
				h={400}
				title={`webhook  ${hook.method} ${hook.path}`}
				status={<span style={{color: NEUTRAL.paper2}}>✓ signed</span>}
			>
				<Field k="effect" v={hook.body.effect} />
				<Field k="account_id" v={hook.body.account_id} />
				<Field k="api_key_id" v={hook.body.api_key_id} last />
				<div style={{fontSize: 21, color: NEUTRAL.steel2, marginTop: 14, lineHeight: 1.5}}>
					Catraca-Signature: <span style={{color: NEUTRAL.paper2}}>{sig.slice(0, 32)}…</span>
					<br />
					signature.Verify: <span style={{color: NEUTRAL.paper2}}>{hook.verified}</span>
				</div>
			</Panel>
		</>
	);
};

const at21 = () => SCENES.leak + 8 * BEAT;

// The webhook leaving the rotor for the platform.
const Packet: React.FC<{t: number; from: number; to: number}> = ({t, from, to}) => {
	if (t < from || t > to + 200) return null;
	const p = easeInOut(clamp01((t - from) / (to - from)));
	const x0 = LANE.ax;
	const y0 = LANE.ay;
	const x1 = RX;
	const y1 = HEAD_Y + 180;
	const cx = (x0 + x1) / 2;
	const cy = y0 - 300;
	const pt = (u: number) => [(1 - u) * (1 - u) * x0 + 2 * (1 - u) * u * cx + u * u * x1, (1 - u) * (1 - u) * y0 + 2 * (1 - u) * u * cy + u * u * y1];
	const trail = Array.from({length: 12}, (_, i) => Math.max(0, p - i * 0.03));
	const fade = 1 - clamp01((t - to) / 200);
	return (
		<svg width={WIDTH} height={HEIGHT} style={{position: 'absolute'}}>
			{trail.map((u, i) => {
				const [x, y] = pt(u);
				return <circle key={i} cx={x} cy={y} r={9 - i * 0.6} fill={NEUTRAL.paper} opacity={fade * (1 - i / 12) * 0.9} />;
			})}
		</svg>
	);
};

// --- 7. Shadow mode -----------------------------------------------------------------

const Shadow: React.FC<{t: number}> = ({t}) => {
	const from = SCENES.shadow;
	const to = SCENES.gate - 260;
	const s1 = slot('shadow1');
	const first = step('shadow_first');
	const sh = (first.response as {decision: {shadow: {rule_id: string; action: string; mode: string}[]}}).decision.shadow[0];
	const note = life(t, s1.click + 200, to);
	return (
		<>
			<Kicker t={t} from={from} to={SCENES.numbers - 300} n="04" label="shadow mode" x={X} y={KICK_Y} />
			<Words t={t} from={from + 60} to={to} parts={['Shadow first.']} size={92} style={{left: X, top: HEAD_Y, width: HEAD_W}} />
			<Words
				t={t}
				from={from + 420}
				to={to}
				parts={['A new rule records what it would do. The action stays ', {text: 'allow.', color: C.allow.text}]}
				size={40}
				weight={400}
				color={NEUTRAL.steel2}
				each={30}
				style={{left: X, top: HEAD_Y + 120, width: 860}}
			/>
			<Panel t={t} from={s1.click + 100} to={to} x={RX} y={HEAD_Y} w={RW} h={420} title="POST /v1/decide" status="200 OK">
				<Field k="action" v="allow" />
				<div style={{color: NEUTRAL.steel2}}>
					"shadow"<span style={{color: DIM}}>: [{'{'}</span>
				</div>
				<div style={{paddingLeft: 36}}>
					<Field k="rule_id" v={sh.rule_id} />
					<Field k="action" v={sh.action} />
					<Field k="mode" v={sh.mode} last />
				</div>
				<div style={{color: DIM}}>{'}]'}</div>
			</Panel>
			{note.visible ? (
				<div
					style={{
						position: 'absolute',
						left: X,
						top: BOTTOM_Y + 30,
						display: 'flex',
						alignItems: 'center',
						gap: 18,
						fontFamily: FONT_MONO,
						fontSize: 30,
						color: NEUTRAL.steel2,
						opacity: clamp01(note.inP * 1.4) * (1 - note.outP),
						translate: `0 ${(1 - note.inP) * 24}px`,
					}}
				>
					<svg width={40} height={40} viewBox="0 0 40 40">
						<circle cx={20} cy={20} r={8} fill={C.allow.mark} />
						<circle cx={20} cy={20} r={16} fill="none" stroke={C.flag.mark} strokeWidth={3} strokeDasharray="5.1 2.1" />
					</svg>
					<span>
						<span style={{color: NEUTRAL.paper2}}>signup-farm-ip</span> would <ActionWord a="flag" mono={false} />, not enforced
					</span>
				</div>
			) : null}
		</>
	);
};

// --- 8. The gate ----------------------------------------------------------------------

function wilson(k: number, n: number, z = 1.96) {
	if (n <= 0) return {lo: 0, hi: 1, p: 0};
	const p = k / n;
	const z2 = z * z;
	const d = 1 + z2 / n;
	const c = p + z2 / (2 * n);
	const r = z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n));
	return {lo: (c - r) / d, hi: (c + r) / d, p};
}

const reportRow = (id: string) => {
	const line = S.cli.report.stdout.split('\n').find((l) => l.startsWith(id + ' ')) ?? '';
	const [, mode, matches, labeled, tp, fp, precision, ciLo, ciHi, status] = line.trim().split(/\s+/);
	return {
		id,
		mode,
		matches: Number(matches),
		labeled: Number(labeled),
		tp: Number(tp),
		fp: Number(fp),
		precision: Number(precision),
		lo: Number(ciLo.replace(/[[,]/g, '')),
		hi: Number(ciHi.replace(/]/g, '')),
		status,
	};
};

const Gate: React.FC<{t: number}> = ({t}) => {
	const from = SCENES.gate;
	const to = SCENES.numbers - 300;
	if (t < from - 100) return null;
	const farm = reportRow('signup-farm-ip');
	const short = reportRow('shortener-links-new-account');
	// Labels arrive faster and faster with the drum roll; one of them is a
	// false positive. The bound narrows as they come.
	const labelFrom = from + 300;
	const labelTo = SCENES.promote - 240;
	const u = easeIn(clamp01((t - labelFrom) / (labelTo - labelFrom)));
	const n = 1 + (farm.labeled - 1) * u;
	const k = n - farm.fp * clamp01(n - 1);
	const w = n >= farm.labeled ? {lo: farm.lo, hi: farm.hi, p: farm.precision} : wilson(k, n);
	const passed = t >= SCENES.promote;
	const close = tween(t, SCENES.promote, MOTION.fade, easeOut);
	const panelX = X;
	const panelW = WIDTH - 2 * X;
	const chartX = 640;
	const chartW = panelW - chartX - 80;
	const xOf = (v: number) => chartX + v * chartW;
	const rowY = [150, 330];
	const shortIn = life(t, from + 4 * BEAT, to);
	const r = 18;
	const dash = (2 * Math.PI * (r + 10)) / 14;
	return (
		<>
			<Words t={t} from={from} to={to} parts={['Enforce when precision proves it.']} size={92} style={{left: X, top: HEAD_Y, width: 1700}} />
			<Panel
				t={t}
				from={from + 200}
				to={to}
				x={panelX}
				y={300}
				w={panelW}
				h={560}
				title={
					<span>
						<span style={{color: DIM}}>$ </span>catraca report
					</span>
				}
				status="gate: 30 labels, Wilson 95% lower bound ≥ 0.90"
			>
				<svg width={panelW - 60} height={440} style={{position: 'absolute', left: 30, top: 86, overflow: 'visible'}}>
					{[0, 0.25, 0.5, 0.75, 1].map((v) => (
						<g key={v}>
							<path d={`M${xOf(v)} 40V420`} stroke={NEUTRAL.ink3} strokeWidth={2} />
							<text x={xOf(v)} y={28} textAnchor="middle" fontFamily={FONT_MONO} fontSize={22} fill={DIM}>
								{v.toFixed(2)}
							</text>
						</g>
					))}
					<path d={`M${xOf(0.9)} 40V420`} stroke={NEUTRAL.paper2} strokeWidth={3} strokeDasharray="10 8" />
					<text x={xOf(0.9)} y={28} textAnchor="middle" fontFamily={FONT_MONO} fontSize={22} fill={NEUTRAL.paper2}>
						0.90
					</text>
					<CI y={rowY[0]} lo={w.lo} hi={w.hi} p={w.p} xOf={xOf} />
					{shortIn.visible ? (
						<g opacity={clamp01(shortIn.inP * 1.4)}>
							<CI y={rowY[1]} lo={short.lo} hi={short.hi} p={short.precision} xOf={xOf} grow={clamp01(shortIn.inP)} />
						</g>
					) : null}
					{/* Promotion: the one moment a dashed ring closes into a solid one. */}
					<g transform={`translate(30 ${rowY[0]})`}>
						<circle r={r * 0.62} fill={C.allow.mark} />
						<circle
							r={r + 10}
							fill="none"
							stroke={C.flag.mark}
							strokeWidth={4}
							strokeDasharray={close >= 1 ? undefined : `${dash * (0.55 + 0.45 * close)} ${dash * 0.45 * (1 - close)}`}
							transform={`rotate(${-90 + 40 * close})`}
						/>
					</g>
				</svg>
				<div style={{position: 'absolute', left: 120, top: 86 + rowY[0] - 40, fontSize: 30, lineHeight: 1.35}}>
					<div style={{color: NEUTRAL.paper2}}>{farm.id}</div>
					<div style={{fontSize: 24, color: NEUTRAL.steel2}}>
						{passed ? (
							<span style={{color: NEUTRAL.paper}}>
								passes [{farm.lo.toFixed(3)}, {farm.hi.toFixed(3)}] · shadow → enforce
							</span>
						) : (
							<>
								{farm.mode} · <Counter value={Math.floor(n)} /> labeled · {w.p.toFixed(3)}
							</>
						)}
					</div>
				</div>
				{shortIn.visible ? (
					<div style={{position: 'absolute', left: 120, top: 86 + rowY[1] - 40, fontSize: 30, lineHeight: 1.35, opacity: clamp01(shortIn.inP * 1.4)}}>
						<div style={{color: NEUTRAL.paper2}}>{short.id}</div>
						<div style={{fontSize: 24, color: NEUTRAL.steel2}}>
							{short.mode} · {short.fp} of {short.labeled} reversed · retire
						</div>
					</div>
				) : null}
			</Panel>
		</>
	);
};

// A confidence interval as a bar, and the precision as a dot on it.
const CI: React.FC<{y: number; lo: number; hi: number; p: number; xOf: (v: number) => number; grow?: number}> = ({y, lo, hi, p, xOf, grow = 1}) => {
	const mid = (lo + hi) / 2;
	const a = mid + (lo - mid) * grow;
	const b = mid + (hi - mid) * grow;
	return (
		<g>
			<rect x={xOf(a)} y={y - 9} width={Math.max(4, xOf(b) - xOf(a))} height={18} rx={9} fill={NEUTRAL.steel} opacity={0.75} />
			<circle cx={xOf(p)} cy={y} r={13} fill={NEUTRAL.paper} />
		</g>
	);
};

// --- 9. Numbers and the rest ------------------------------------------------------------

const STATS = [
	{value: 3.5, decimals: 1, unit: 'µs', caption: 'one decision in the engine'},
	{value: 8000, decimals: 0, unit: 'req/s', caption: 'over HTTP, p99 1.27 ms, in-memory counters'},
	{value: 2.97, decimals: 2, unit: 'ms', caption: 'p99 at 1,000 req/s with Redis counters'},
];

const FEATURES = ['CEL rules', 'shadow mode', 'precision gate', 'audit log and labels', 'signed webhooks', 'durable outbox', 'SES and useSend feedback', 'GitHub secret scanning'];

const Numbers: React.FC<{t: number}> = ({t}) => {
	const from = SCENES.numbers;
	const to = SCENES.features - 200;
	const featTo = SCENES.close - 520;
	return (
		<>
			<Words t={t} from={from} to={to} parts={['Fast enough to sit in the path of every send.']} size={80} style={{left: X, top: HEAD_Y, width: 1700}} />
			{STATS.map((s, i) => {
				const start = from + (i * 2 + 1) * BEAT;
				const l = life(t, start, to, POP);
				if (!l.visible) return null;
				const v = s.value * tween(t, start, 700);
				return (
					<div
						key={i}
						style={{
							position: 'absolute',
							left: X + i * 580,
							top: 420,
							width: 540,
							opacity: clamp01(l.inP * 1.5) * (1 - l.outP),
							translate: `0 ${(1 - l.inP) * 50 - l.outP * 20}px`,
						}}
					>
						<div style={{fontFamily: FONT_MONO, fontWeight: 600, fontSize: 104, color: NEUTRAL.paper, display: 'flex', alignItems: 'baseline', gap: 16}}>
							<Counter value={v} decimals={s.decimals} />
							<span style={{fontSize: 44, color: NEUTRAL.steel2, fontWeight: 400}}>{s.unit}</span>
						</div>
						<div style={{height: 3, width: 120 * clamp01(l.inP), background: NEUTRAL.steel, margin: '14px 0 18px'}} />
						<div style={{fontSize: 34, lineHeight: 1.3, color: NEUTRAL.steel2}}>{s.caption}</div>
					</div>
				);
			})}
			{(() => {
				const l = life(t, from + 6 * BEAT, to);
				return l.visible ? (
					<div style={{position: 'absolute', left: X, top: 880, fontFamily: FONT_MONO, fontSize: 24, color: DIM, opacity: l.inP * (1 - l.outP)}}>
						Ryzen 5 7600X, one machine · docs/benchmark.md
					</div>
				) : null;
			})()}
			<div style={{position: 'absolute', left: 140, right: 140, top: 330, display: 'flex', flexWrap: 'wrap', justifyContent: 'center', gap: '30px 26px'}}>
				{FEATURES.map((name, i) => {
					const l = life(t, SCENES.features + i * (BEAT / 4), featTo + i * 25, POP);
					if (!l.visible) return null;
					return (
						<div
							key={name}
							style={{
								fontFamily: FONT_MONO,
								fontSize: 46,
								color: NEUTRAL.paper2,
								padding: '16px 32px',
								border: `2px solid ${NEUTRAL.ink3}`,
								background: NEUTRAL.ink2,
								borderRadius: 999,
								opacity: clamp01(l.inP * 2) * (1 - l.outP),
								scale: `${0.7 + 0.3 * l.inP}`,
								translate: `0 ${l.outP * -24}px`,
							}}
						>
							{name}
						</div>
					);
				})}
			</div>
		</>
	);
};

// --- 10. Close ----------------------------------------------------------------------------

// The flow and shadow phases' real decisions, repeated: calm traffic, a flag
// and dashed rings, one per beat, settling on the final hit.
const CLOSE_SEQ = [...phase('flow'), ...phase('shadow')].map((e) => toItem(e));
const CLOSE_FIRST = Math.round(SCENES.close / BEAT) - 18;
const CLOSE_LAST = Math.round(SCENES.final / BEAT);
const CLOSE_SLOTS = scheduleAt(
	Array.from({length: CLOSE_LAST - CLOSE_FIRST + 1}, (_, i) => ({item: CLOSE_SEQ[i % CLOSE_SEQ.length], click: beat(CLOSE_FIRST + i)})),
);
// The poster: the end card, after the last decision has settled.
export const POSTER_AT = SCENES.final + 2400;

const Close: React.FC<{t: number}> = ({t}) => {
	const from = SCENES.close;
	if (t < from - 200) return null;
	const s = 3.2;
	const m = LOCKUP.m * s;
	const w = LOCKUP.width * s;
	const x0 = (WIDTH - w) / 2 - 30;
	const y0 = 250;
	const ax = x0 + LOCKUP.axis[0] * s;
	const ay = y0 + LOCKUP.axis[1] * s;
	const inP = tween(t, from - 60, 600);
	const word = springAt(t, from + 240, SOFT);
	const textX = x0 + 75 * s;
	const lineY = ay + GEOMETRY.offset * m;
	const wordX = x0 + 75 * s;
	const wordW = (LOCKUP.width - 75) * s + 20;
	const links = life(t, from + 3 * BEAT, Infinity, SOFT);
	return (
		<AbsoluteFill style={{opacity: inP}}>
			<svg width={WIDTH} height={HEIGHT} style={{position: 'absolute'}}>
				<defs>
					<clipPath id="closeword">
						<rect x={wordX - 20} y={y0 - 20} width={Math.max(0, wordW * word)} height={LOCKUP.height * s + 40} />
					</clipPath>
				</defs>
				<Lane slots={CLOSE_SLOTS} t={t} theme="dark" ax={ax} ay={ay} m={m} width={WIDTH} />
				<g clipPath="url(#closeword)">
					<g transform={`translate(${x0 + (1 - word) * -80} ${y0}) scale(${s})`}>
						<path fill={T.fg} d={WORDMARK_PATH} />
					</g>
				</g>
			</svg>
			<Words
				t={t}
				from={from + 2 * BEAT}
				parts={['Anti-abuse engine for platforms that send email']}
				size={46}
				weight={500}
				each={40}
				style={{left: textX, top: lineY + 70, width: 1300}}
			/>
			{links.visible ? (
				<div
					style={{
						position: 'absolute',
						left: textX,
						top: lineY + 160,
						fontFamily: FONT_MONO,
						fontSize: 26,
						color: NEUTRAL.steel2,
						lineHeight: 1.8,
						opacity: clamp01(links.inP * 1.4),
						translate: `0 ${(1 - links.inP) * 24}px`,
					}}
				>
					<div>Open source · Apache-2.0</div>
					<div style={{color: NEUTRAL.paper2, fontSize: 30}}>github.com/guilhermebsantiago/catraca</div>
					<div style={{color: NEUTRAL.paper2, fontSize: 30}}>catraca.guilhermebs.com.br</div>
				</div>
			) : null}
		</AbsoluteFill>
	);
};
