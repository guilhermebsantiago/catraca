// The launch video: 1920 x 1080, 30 fps, dark theme. Every request, answer,
// webhook and command output on screen is what examples/demo recorded from a
// real `catraca serve` (src/data.ts); the lane plays the decisions it made.

import React from 'react';
import {AbsoluteFill, useCurrentFrame} from 'remotion';
import {ACTION_COLORS, Action, FONT_MONO, FONT_SANS, LOCKUP, MOTION, NEUTRAL, THEMES, clamp01, easeInOut, easeOut} from '../brand';
import {S, phase, step, toItem} from '../data';
import {Lane} from '../lane/Lane';
import {GEOMETRY, schedule} from '../lane/sim';
import {WORDMARK_PATH} from '../wordmark';
import {FPS, HEIGHT, LANE, SCENES, WIDTH, complaintRounds, laneSlots, slot} from './timeline';
import {ActionWord, Appear, Code, Header, Headline, Kicker, Note, Panel, Sub, TermLine, Terminal, presence} from './ui';

const C = ACTION_COLORS.dark;
const T = THEMES.dark;
const X = 96; // side margins
const INNER = WIDTH - 2 * X;
const PANEL_Y = 552;
const PANEL_H = HEIGHT - PANEL_Y - 56;
const GAP = 24;
// Request on the left, answer on the right: wide enough for a rule's reason.
const LEFT_W = 560;
const RIGHT_X = X + LEFT_W + GAP;
const RIGHT_W = INNER - LEFT_W - GAP;
// Characters of 18 px mono that fit across a panel of width w.
const headerChars = (w: number) => Math.floor((w - 56) / (18 * 0.632));
// Annotations on the lane, right of the rotor.
const LANE_NOTE = {left: 520, top: 330};

// `at` (ms) renders one moment instead of following the timeline: the poster.
export const Launch: React.FC<{at?: number}> = ({at}) => {
	const frame = useCurrentFrame();
	const t = at ?? (frame * 1000) / FPS;
	return (
		<AbsoluteFill style={{background: T.bg, fontFamily: FONT_SANS, color: NEUTRAL.paper2}}>
			<Problem t={t} />
			<MainLane t={t} />
			<Ask t={t} />
			<Burst t={t} />
			<Complaints t={t} />
			<Leak t={t} />
			<Shadow t={t} />
			<Report t={t} />
			<Close t={t} />
		</AbsoluteFill>
	);
};

// --- 1. The problem -----------------------------------------------------------

const P1 = {lane: 800, m: 38, stop: 2700, decel: 800};

const Problem: React.FC<{t: number}> = ({t}) => {
	if (t > SCENES.s2 + 600) return null;
	const out = presence(t, -1000, SCENES.s2 - 420, 1, 400);
	const fadeIn = easeOut(clamp01(t / 500));
	const {m, stop, decel} = P1;
	const v = m / MOTION.pitch;
	const after = Math.max(0, Math.min(t - stop, decel));
	const shift = v * (Math.min(t, stop) + after - (after * after) / (2 * decel));
	// Customers' mail at an even pace, and one account's burst in the middle.
	const r = 0.3 * m;
	const sw = 3;
	const n = 16;
	const gap = 0.42 * m;
	const L = (n - 1) * gap;
	const clusterAtStop = 1040;
	const c0 = clusterAtStop - v * (stop + decel / 2) - L / 2;
	const xs: {x: number; burst: boolean}[] = [];
	const phase = ((c0 % m) + m) % m;
	for (let k = -60; k < 80; k++) {
		const x = k * m + phase;
		if (x > c0 - 0.8 * m && x < c0 + L + 0.8 * m) continue;
		xs.push({x, burst: false});
	}
	for (let i = 0; i < n; i++) xs.push({x: c0 + i * gap, burst: true});
	const paused = easeOut(clamp01((t - stop - decel * 0.6) / 400));
	const label = presence(t, 1000, Infinity, 500);
	return (
		<AbsoluteFill style={{opacity: out.opacity * fadeIn}}>
			<svg width={WIDTH} height={HEIGHT} style={{position: 'absolute'}}>
				<path stroke={T.rail} strokeWidth={2} d={`M0 ${P1.lane}H${WIDTH}`} />
				{xs.map(({x: x0, burst}, i) => {
					const x = x0 + shift;
					if (x < -20 || x > WIDTH + 20) return null;
					return (
						<circle
							key={i}
							cx={x}
							cy={P1.lane}
							r={r - sw / 2}
							fill={T.bg}
							stroke={burst ? NEUTRAL.paper2 : T.ring}
							strokeWidth={sw}
							opacity={1 - 0.45 * paused}
						/>
					);
				})}
				<g opacity={label.opacity * (1 - 0.3 * paused)}>
					<text
						x={c0 + shift + L / 2}
						y={P1.lane + 58}
						textAnchor="middle"
						fontFamily={FONT_MONO}
						fontSize={22}
						fill={NEUTRAL.paper2}
					>
						one account, bursting
					</text>
				</g>
			</svg>
			<Appear t={t} from={stop + decel * 0.6} style={{left: WIDTH - X - 600, top: P1.lane - 72, width: 600}}>
				<div
					style={{
						display: 'flex',
						justifyContent: 'flex-end',
						alignItems: 'center',
						gap: 12,
						fontFamily: FONT_MONO,
						fontSize: 24,
						color: NEUTRAL.paper2,
					}}
				>
					<svg width={16} height={18} viewBox="0 0 16 18">
						<rect x={1} y={1} width={4.5} height={16} rx={1.5} fill={NEUTRAL.paper2} />
						<rect x={10.5} y={1} width={4.5} height={16} rx={1.5} fill={NEUTRAL.paper2} />
					</svg>
					sending paused for everyone
				</div>
			</Appear>
			<Appear t={t} from={300} style={{left: X, top: 280, width: 1500}}>
				<Headline size={62}>Providers pause sending when bounce or complaint rates&nbsp;climb.</Headline>
			</Appear>
			<Appear t={t} from={1450} style={{left: X, top: 460, width: 1560}}>
				<div style={{fontFamily: FONT_SANS, fontWeight: 600, fontSize: 62, lineHeight: 1.1, letterSpacing: '-0.01em', color: NEUTRAL.steel2}}>
					On a shared sending account, one abuser can get it paused for <span style={{color: NEUTRAL.paper2}}>every&nbsp;customer.</span>
				</div>
			</Appear>
		</AbsoluteFill>
	);
};

// --- The lane through scenes 2 to 6 ---------------------------------------

const MainLane: React.FC<{t: number}> = ({t}) => {
	if (t < SCENES.s2 - 100 || t > SCENES.report + 800) return null;
	const inP = easeOut(clamp01((t - SCENES.s2 - 30) / 600));
	const outP = easeInOut(clamp01((t - SCENES.report + 250) / 450));
	const th = slot('throttle');
	const label = t > th.start - 200 && t < th.turnStart + 100 ? `Retry-After: ${step('throttle').response_headers?.['Retry-After']}` : undefined;
	return (
		<svg width={WIDTH} height={HEIGHT} style={{position: 'absolute', opacity: inP * (1 - outP)}}>
			<Lane
				slots={laneSlots}
				t={t}
				theme="dark"
				ax={LANE.ax}
				ay={LANE.ay}
				m={LANE.m}
				width={WIDTH}
				countdownLabel={label}
				labelFont={FONT_MONO}
				labelSize={22}
			/>
		</svg>
	);
};

// Text block of scenes 2 to 6.
const Heading: React.FC<{
	t: number;
	from: number;
	to: number;
	n: string;
	kicker: string;
	title: React.ReactNode;
	sub: React.ReactNode;
}> = ({t, from, to, n, kicker, title, sub}) => {
	// The outgoing heading has left before the next one arrives.
	const out = to - HEADING_OUT;
	return (
		<>
			<Appear t={t} from={from + 60} to={out} style={{left: X, top: 50}}>
				<Kicker n={n}>{kicker}</Kicker>
			</Appear>
			<Appear t={t} from={from + 120} to={out} style={{left: X, top: 86, width: INNER}}>
				<Headline>{title}</Headline>
			</Appear>
			<Appear t={t} from={from + 220} to={out} style={{left: X, top: 166, width: INNER}}>
				<Sub>{sub}</Sub>
			</Appear>
		</>
	);
};
const HEADING_OUT = 320;

const status = (e: {status: number; status_text: string}) => `${e.status} ${e.status_text}`;

const LaneNote: React.FC<{t: number; from: number; to: number; children: React.ReactNode}> = ({t, from, to, children}) => (
	<Appear t={t} from={from} to={to} style={LANE_NOTE}>
		<Note>{children}</Note>
	</Appear>
);

// --- 2. Catraca asks before every send ----------------------------------------

const Ask: React.FC<{t: number}> = ({t}) => {
	const from = SCENES.s2 + 200;
	const to = SCENES.s3;
	if (t < from - 10 || t > to + 400) return null;
	const allow = step('allow');
	return (
		<>
			<Heading
				t={t}
				from={from}
				to={to}
				n="01"
				kicker="every send"
				title="Catraca asks before every send."
				sub={
					<>
						Self-hosted, in the path of each send. It answers in milliseconds with <ActionWord a="allow" />,{' '}
						<ActionWord a="flag" />, <ActionWord a="throttle" />, <ActionWord a="hold" /> or <ActionWord a="block" />, and the rules
						behind it.
					</>
				}
			/>
			<Panel
				t={t}
				from={from + 900}
				to={to}
				x={X}
				y={PANEL_Y}
				w={LEFT_W}
				h={360}
				title={`${allow.method} ${allow.path}`}
				status="request"
				value={allow.request}
				fontSize={20}
			/>
			<Panel
				t={t}
				from={from + 1300}
				to={to}
				x={RIGHT_X}
				y={PANEL_Y}
				w={RIGHT_W}
				h={360}
				title="response"
				status={status(allow)}
				value={allow.response}
				fontSize={21}
				hot={['action']}
				hotFrom={from + 2200}
			/>
		</>
	);
};

// --- 3. A new account bursts ------------------------------------------------------

const DemoNote: React.FC<{t: number; from: number; to: number; rule: string; action: Action}> = ({t, from, to, rule, action}) => (
	<LaneNote t={t} from={from} to={to}>
		Demo ruleset: <Code>{rule}</Code> enforced to show a <ActionWord a={action} mono={false} />. The starter ruleset ships it in shadow.
	</LaneNote>
);

const Burst: React.FC<{t: number}> = ({t}) => {
	const from = SCENES.s3;
	const to = SCENES.s4;
	if (t < from - 10 || t > to + 400) return null;
	const th = step('throttle');
	const total = S.burst.allow + S.burst.throttle;
	const thSlot = slot('throttle');
	// Send 100, the last one allowed, until send 101 reaches the arm.
	const before = t < thSlot.start;
	const cur = before ? step('burst_100') : th;
	const n = before ? S.burst.first_throttle_at - 1 : S.burst.first_throttle_at;
	return (
		<>
			<Heading
				t={t}
				from={from}
				to={to}
				n="02"
				kicker="new account"
				title="A brand-new account bursts."
				sub={
					<>
						<Code>acct_x7q2</Code> signs up and sends {total} emails in a minute. From send {S.burst.first_throttle_at},{' '}
						<Code>new-account-burst</Code> answers <ActionWord a="throttle" />, with a <Code>Retry-After</Code>.
					</>
				}
			/>
			<DemoNote t={t} from={from + 500} to={to} rule="new-account-burst" action="throttle" />
			<Panel
				t={t}
				from={from + 700}
				to={to}
				x={X}
				y={PANEL_Y}
				w={LEFT_W}
				h={PANEL_H}
				title={`${cur.method} ${cur.path}`}
				status={`send ${n} of ${total}`}
				value={cur.request}
				fontSize={20}
				pulse={thSlot.start}
			/>
			<Panel
				t={t}
				from={from + 1000}
				to={to}
				x={RIGHT_X}
				y={PANEL_Y}
				w={RIGHT_W}
				h={PANEL_H}
				title="response"
				status={
					before ? (
						status(cur)
					) : (
						<>
							{status(th)} <span style={{color: NEUTRAL.ink3}}>·</span>{' '}
							<span style={{color: C.throttle.text}}>Retry-After: {th.response_headers?.['Retry-After']}</span>
						</>
					)
				}
				value={cur.response}
				fontSize={21}
				pulse={thSlot.start}
				hot={before ? [] : ['action', 'rule_id', 'reason', 'retry_after']}
				hotFrom={thSlot.start + 500}
			/>
		</>
	);
};

// --- 4. Complaints ------------------------------------------------------------------

const Complaints: React.FC<{t: number}> = ({t}) => {
	const from = SCENES.s4;
	const to = SCENES.s5;
	if (t < from - 10 || t > to + 400) return null;
	const holdSlot = slot('hold');
	// The latest complaint that has arrived, and the latest send decided.
	const arrived = Math.max(1, complaintRounds.filter((r) => t >= r.arrive).length);
	const decided = Math.max(1, complaintRounds.filter((r) => t >= r.decided).length);
	const fb = step(`complaint_${arrived}`);
	const sendN = step(`complaint_send_${decided}`);
	const held = t >= holdSlot.click;
	return (
		<>
			<Heading
				t={t}
				from={from}
				to={to}
				n="03"
				kicker="complaints"
				title="Complaints come back."
				sub={
					<>
						Signed feedback arrives at <Code>POST /v1/feedback</Code>. The newsletter's {ordinal(heldAfter)} complaint takes it past 0.3% in
						24 hours: its next send is <ActionWord a="hold" />, waiting for a person.
					</>
				}
			/>
			<ComplaintStrip t={t} from={from + 300} to={to} />
			<Appear t={t} from={from + 500} to={to} style={{left: LANE_NOTE.left, top: LANE_NOTE.top + 46}}>
				<Note>
					Demo ruleset: <Code>complaint-rate-high</Code> enforced to show a <ActionWord a="hold" mono={false} />. The starter ruleset ships it
					in shadow.
				</Note>
			</Appear>
			<Panel
				t={t}
				from={from + 500}
				to={to}
				x={X}
				y={PANEL_Y}
				w={LEFT_W}
				h={PANEL_H}
				title={`${fb.method} ${fb.path}`}
				status={`#${arrived}  ${status(fb)}`}
				value={fb.request}
				fontSize={20}
				pulse={complaintRounds[arrived - 1].arrive}
			>
				<div style={{marginTop: 12}}>
					<Header name="Catraca-Signature" value={fb.request_headers?.['Catraca-Signature'] ?? ''} width={headerChars(LEFT_W)} />
				</div>
			</Panel>
			<Panel
				t={t}
				from={complaintRounds[0].decided - 300}
				to={to}
				x={RIGHT_X}
				y={PANEL_Y}
				w={RIGHT_W}
				h={PANEL_H}
				title={`POST /v1/decide  acct_fernway, next send ${decided}`}
				status={status(sendN)}
				value={sendN.response}
				fontSize={21}
				pulse={complaintRounds[decided - 1].decided}
				hot={held ? ['action', 'rule_id', 'reason'] : []}
				hotFrom={holdSlot.click + 200}
			/>
		</>
	);
};

// The complaint after which the newsletter's next send was held.
const heldAfter = S.complaints.findIndex((c) => c.next_send_action === 'hold') + 1;
const ordinal = (n: number) => `${n}${['th', 'st', 'nd', 'rd'][n % 100 > 10 && n % 100 < 14 ? 0 : n % 10] ?? 'th'}`;

// Four complaints, and what the newsletter's next send got after each.
const ComplaintStrip: React.FC<{t: number; from: number; to: number}> = ({t, from, to}) => {
	const pr = presence(t, from, to);
	if (!pr.visible) return null;
	return (
		<div
			style={{
				position: 'absolute',
				left: LANE_NOTE.left,
				top: LANE_NOTE.top - 4,
				opacity: pr.opacity,
				transform: `translateY(${pr.dy}px)`,
				display: 'flex',
				gap: 34,
				alignItems: 'baseline',
				fontFamily: FONT_MONO,
				fontSize: 22,
				color: NEUTRAL.steel2,
			}}
		>
			<span>complaint</span>
			{complaintRounds.map((r) => {
				const arrived = easeOut(clamp01((t - r.arrive) / 250));
				const decided = easeOut(clamp01((t - r.decided) / 200));
				const a = r.action as Action;
				return (
					<span key={r.n} style={{opacity: 0.25 + 0.75 * arrived, display: 'inline-flex', gap: 10, alignItems: 'baseline'}}>
						<span style={{color: NEUTRAL.paper2}}>{r.n}</span>
						<span style={{color: '#6B7680'}}>next send</span>
						<span style={{color: C[a].text, opacity: decided, minWidth: 70}}>{a}</span>
					</span>
				);
			})}
		</div>
	);
};

// --- 5. A key leaks ------------------------------------------------------------------

const LEAK_LEFT_W = 720;

const Leak: React.FC<{t: number}> = ({t}) => {
	const from = SCENES.s5;
	const to = SCENES.s6;
	if (t < from - 10 || t > to + 400) return null;
	const leak = step('key_leak');
	const block = step('block');
	const blockSlot = slot('block');
	const hookAt = blockSlot.click + 700;
	const hook = S.hook;
	const shown = ['effect', 'decision_id', 'account_id', 'api_key_id', 'action', 'rule_ids'];
	const omitted = Object.keys(hook.body).filter((k) => !shown.includes(k));
	return (
		<>
			<Heading
				t={t}
				from={from}
				to={to}
				n="04"
				kicker="leaked key"
				title="A key leaks."
				sub={
					<>
						Reported once, at <Code>POST /v1/events</Code> or by GitHub secret scanning. The next send with it is{' '}
						<ActionWord a="block" />, and your platform gets a signed <Code>revoke_key</Code> webhook.
					</>
				}
			/>
			<Panel
				t={t}
				from={from + 300}
				to={hookAt - 100}
				x={X}
				y={PANEL_Y}
				w={LEAK_LEFT_W}
				h={PANEL_H}
				title={`${leak.method} ${leak.path}`}
				status={status(leak)}
				value={leak.request}
				fontSize={20}
			/>
			<Panel
				t={t}
				from={hookAt}
				to={to}
				x={X}
				y={PANEL_Y}
				w={LEAK_LEFT_W}
				h={PANEL_H}
				title={`webhook  ${hook.method} ${hook.path}`}
				status={<span style={{color: C.allow.text}}>{`signature.Verify: ${hook.verified}`}</span>}
				value={pick(hook.body, shown)}
				pack={['account_id', 'api_key_id', 'action', 'rule_ids']}
				fontSize={20}
				hot={['effect', 'api_key_id']}
				hotFrom={hookAt + 500}
			>
				<div style={{color: '#6B7680', fontSize: 18, marginTop: 2}}>{`// and ${omitted.join(', ')}`}</div>
				<div style={{marginTop: 10}}>
					<Header name="Catraca-Signature" value={hook.headers['Catraca-Signature']} width={headerChars(LEAK_LEFT_W)} />
					<Header name="Catraca-Idempotency-Key" value={hook.headers['Catraca-Idempotency-Key']} width={headerChars(LEAK_LEFT_W)} />
				</div>
			</Panel>
			<Panel
				t={t}
				from={blockSlot.start - 300}
				to={to}
				x={X + LEAK_LEFT_W + GAP}
				y={PANEL_Y}
				w={INNER - LEAK_LEFT_W - GAP}
				h={PANEL_H}
				title={`POST /v1/decide  from ${String((block.request as {ip: string}).ip)}`}
				status={status(block)}
				value={block.response}
				fontSize={20}
				hot={['action', 'rule_id', 'reason', 'effects']}
				hotFrom={blockSlot.click}
			/>
		</>
	);
};

// The listed members of a recorded object, in their recorded order; the
// panel says which ones it leaves out.
function pick(o: Record<string, unknown>, keys: string[]) {
	const out: Record<string, unknown> = {};
	for (const [k, v] of Object.entries(o)) if (keys.includes(k)) out[k] = v;
	return out;
}

// --- 6. Shadow mode -------------------------------------------------------------------

const quote = (a: string) => (/[\s"']/.test(a) ? `"${a}"` : a);

const Shadow: React.FC<{t: number}> = ({t}) => {
	const from = SCENES.s6;
	const to = SCENES.close;
	if (t < from - 10 || t > to + 400) return null;
	const tp = S.cli.label_tp;
	const fp = S.cli.label_fp;
	const s1 = slot('shadow1');
	const s3 = slot('shadow3');
	const first = step('shadow_first');
	const lines: TermLine[] = [
		{kind: 'dim', text: '# the newest match was a throwaway account', at: s3.click + 100},
		{kind: 'cmd', text: tp.args.map(quote).join(' '), at: s3.click + 250},
		{kind: 'out', text: tp.stdout.trim(), at: s3.click + 600},
		{kind: 'blank', text: ''},
		{kind: 'dim', text: '# this one was a real customer', at: s3.click + 950},
		{kind: 'cmd', text: fp.args.map(quote).join(' '), at: s3.click + 1100},
		{kind: 'out', text: fp.stdout.trim(), at: s3.click + 1450},
	];
	return (
		<>
			<Heading
				t={t}
				from={from}
				to={to}
				n="05"
				kicker="shadow mode"
				title="Shadow first. Enforce when precision proves it."
				sub={
					<>
						A new rule only records what it would do: the dashed rings. Reviewers label its matches, and <Code>catraca report</Code>{' '}
						measures its precision against a Wilson 95% lower bound.
					</>
				}
			/>
			<LaneNote t={t} from={slot('shadow1').click} to={SCENES.report}>
				<Code>signup-farm-ip</Code> runs in shadow: it would <ActionWord a="flag" mono={false} /> these signups, and the action stays{' '}
				<ActionWord a="allow" mono={false} />.
			</LaneNote>
			<Panel
				t={t}
				from={from + 600}
				to={s3.click - 650}
				x={X}
				y={PANEL_Y}
				w={LEFT_W}
				h={PANEL_H}
				title={`${first.method} ${first.path}`}
				status="signup"
				value={first.request}
				fontSize={20}
			/>
			<Panel
				t={t}
				from={s1.click - 150}
				to={s3.click - 650}
				x={RIGHT_X}
				y={PANEL_Y}
				w={RIGHT_W}
				h={PANEL_H}
				title="response"
				status={status(first)}
				value={first.response}
				fontSize={21}
				hot={['action', 'shadow', 'rule_id', 'mode']}
				hotFrom={s1.click + 300}
			/>
			<Terminal t={t} from={s3.click - 350} to={SCENES.report - 200} x={X} y={PANEL_Y} w={INNER} h={PANEL_H} title="reviewer" lines={lines} fontSize={22} />
		</>
	);
};

// --- 6b. The report -------------------------------------------------------------------

const Report: React.FC<{t: number}> = ({t}) => {
	const from = SCENES.report;
	const to = SCENES.close;
	if (t < from - 10 || t > to + 400) return null;
	const rep = S.cli.report;
	const out = rep.stdout.replace(/\s+$/, '').split('\n');
	const promoteAt = from + 1300;
	const retireAt = from + 2800;
	const rowOf = (id: string) => (l: string) => l.startsWith(id + ' ') || l.startsWith(`  ${id}:`);
	const isPromote = rowOf('signup-farm-ip');
	const isRetire = rowOf('shortener-links-new-account');
	const lines: TermLine[] = [
		{kind: 'cmd', text: rep.args.map(quote).join(' ')},
		...out.map((l): TermLine => {
			if (isPromote(l) && t > promoteAt) return {kind: 'hot', text: l};
			if (isRetire(l) && t > retireAt) return {kind: 'hot', text: l};
			if (l.startsWith('Ruleset') || l.startsWith('Gate')) return {kind: 'dim', text: l};
			return {kind: 'out', text: l};
		}),
	];
	const fs = 21;
	const lh = fs * 1.45;
	const top = 272;
	const promoteLine = lines.findIndex((l) => l.text.startsWith('  signup-farm-ip:'));
	const retireLine = lines.findIndex((l) => l.text.startsWith('  shortener-links-new-account:'));
	const retireRow = S.cli.report.stdout.split('\n').find(isRetire) ?? '';
	const [, , , labeled, , fpCount] = retireRow.split(/\s+/);
	const rowY = (i: number) => top + 50 + 16 + i * lh + lh / 2;
	const close = easeOut(clamp01((t - (promoteAt + 900)) / MOTION.fade));
	const ringIn = easeOut(clamp01((t - promoteAt) / 300));
	const retireIn = easeOut(clamp01((t - retireAt) / 300));
	const pr = presence(t, from + 200, to);
	const r = 11;
	const dash = (2 * Math.PI * (r + 6)) / 14;
	const annX = WIDTH - X - 360;
	return (
		<>
			<Terminal t={t} from={from + 200} to={to} x={X} y={top} w={INNER} h={HEIGHT - top - 56} title="reviewer" lines={lines} fontSize={fs} />
			<svg width={WIDTH} height={HEIGHT} style={{position: 'absolute', opacity: pr.opacity, transform: `translateY(${pr.dy}px)`}}>
				{/* Promotion: the one moment a dashed ring closes into a solid one. */}
				<g opacity={ringIn} transform={`translate(${annX} ${rowY(promoteLine)})`}>
					<circle r={r} fill={C.allow.mark} />
					<circle
						r={r + 6}
						fill="none"
						stroke={C.flag.mark}
						strokeWidth={3}
						strokeDasharray={close >= 1 ? undefined : `${dash * (0.55 + 0.45 * close)} ${dash * 0.45 * (1 - close)}`}
					/>
					<text x={34} y={8} fontFamily={FONT_MONO} fontSize={22} fill={NEUTRAL.paper2}>
						{close > 0.5 ? 'shadow → enforce' : 'shadow'}
					</text>
				</g>
				<g opacity={retireIn} transform={`translate(${annX} ${rowY(retireLine)})`}>
					<circle r={r} fill={C.flag.mark} />
					<text x={34} y={8} fontFamily={FONT_MONO} fontSize={22} fill={NEUTRAL.steel2}>
						{`${fpCount} of ${labeled} reversed`}
					</text>
				</g>
			</svg>
		</>
	);
};

// --- 7. Close -------------------------------------------------------------------------

const CLOSE_START = SCENES.close - 16000;
// The flow and shadow phases' real decisions, repeated: calm traffic, a flag,
// and dashed rings, nothing held, throttled or blocked on the end card.
const CLOSE_SEQ = [...phase('flow'), ...phase('shadow')].map((e) => toItem(e));
const CLOSE_SLOTS = schedule(Array.from({length: 4}, () => CLOSE_SEQ).flat(), CLOSE_START);
// The lane settles just after a click, with the rotor at rest, and the last
// second is still.
const SETTLE = (() => {
	const target = SCENES.end - 1300;
	const s = [...CLOSE_SLOTS].reverse().find((x) => x.item.action !== 'block' && x.click <= target);
	return s ? s.click : target;
})();
// The poster: the end card once its text is in, a moment after a decision
// has settled: its color in, the rotor at rest (it rests 160 ms between turns).
export const POSTER_AT = (() => {
	const s = CLOSE_SLOTS.filter((x) => x.click < SCENES.close + 2600 && x.item.shadow).pop();
	return s ? Math.max(s.click + 150, SCENES.close + 1900) : SCENES.close + 2600;
})();
const closeClock = (t: number) => {
	if (t <= SETTLE) return t;
	const d = Math.min(t - SETTLE, 600);
	return SETTLE + 150 * easeOut(d / 600);
};

const Close: React.FC<{t: number}> = ({t}) => {
	const from = SCENES.close;
	if (t < from - 10) return null;
	const s = 3.2;
	const m = LOCKUP.m * s;
	const w = LOCKUP.width * s;
	const x0 = (WIDTH - w) / 2 - 30;
	const y0 = 268;
	const ax = x0 + LOCKUP.axis[0] * s;
	const ay = y0 + LOCKUP.axis[1] * s;
	const pr = presence(t, from + 100, Infinity, 700);
	const wordIn = easeOut(clamp01((t - from - 300) / 700));
	const textX = x0 + 75 * s;
	const lineY = ay + GEOMETRY.offset * m;
	return (
		<AbsoluteFill style={{opacity: pr.opacity}}>
			<svg width={WIDTH} height={HEIGHT} style={{position: 'absolute'}}>
				<Lane slots={CLOSE_SLOTS} t={closeClock(t)} theme="dark" ax={ax} ay={ay} m={m} width={WIDTH} />
				<g opacity={wordIn} transform={`translate(${x0} ${y0 + (1 - wordIn) * 8}) scale(${s})`}>
					<path fill={T.fg} d={WORDMARK_PATH} />
				</g>
			</svg>
			<Appear t={t} from={from + 700} style={{left: textX, top: lineY + 74}}>
				<div style={{fontFamily: FONT_SANS, fontWeight: 500, fontSize: 46, letterSpacing: '-0.01em', color: NEUTRAL.paper2}}>
					Anti-abuse engine for platforms that send email
				</div>
			</Appear>
			<Appear t={t} from={from + 1200} style={{left: textX, top: lineY + 166}}>
				<div style={{fontFamily: FONT_MONO, fontSize: 26, color: NEUTRAL.steel2, lineHeight: 1.8}}>
					<div>Open source · Apache-2.0</div>
					<div style={{color: NEUTRAL.paper2, fontSize: 30}}>github.com/guilhermebsantiago/catraca</div>
					<div style={{color: NEUTRAL.paper2, fontSize: 30}}>catraca.guilhermebs.com.br</div>
				</div>
			</Appear>
		</AbsoluteFill>
	);
};
