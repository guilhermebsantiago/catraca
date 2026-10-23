// The launch video's clock. It is cut to its music (scripts/score.mjs):
// 125 BPM, so one beat is the lane's 480 ms pitch and every decision clicks
// on a beat. Scenes start on bars; the lane plays the demo's live decisions
// in the order Catraca made them, with runs left out (most of the burst's
// sends, the throttles after the first, and the allowed sends at the end of
// the complaints phase).

import {LaneEntry, S, phase, toItem} from '../data';
import {LaneItem, Slot, scheduleAt, slotOf} from '../lane/sim';

export const FPS = 60;
export const WIDTH = 1920;
export const HEIGHT = 1080;

export const BEAT = 480;
export const BAR = 4 * BEAT;
// Bar n, beat b (both from 1), in ms.
export const at = (bar: number, beat = 1) => (bar - 1) * BAR + (beat - 1) * BEAT;
// Beat g counted from 0.
export const beat = (g: number) => g * BEAT;

export const DURATION_MS = 64000;
export const DURATION_FRAMES = Math.round((DURATION_MS * FPS) / 1000);

export const SCENES = {
	problem: 0,
	stop: at(5, 3), // traffic stops with the music
	logo: at(7),
	ask: at(9),
	legend: at(11),
	rule: at(12),
	burst: at(13),
	complaints: at(16),
	leak: at(19),
	shadow: at(22),
	gate: at(24),
	promote: at(26),
	numbers: at(27),
	features: at(29),
	close: at(30),
	final: at(32),
	end: DURATION_MS,
};

// Lane geometry from the logo on: the rotor's axis and module, px.
export const LANE = {ax: 470, ay: 600, m: 48};

const item = (e: LaneEntry, tag?: string): LaneItem => toItem(e, tag);

function laneEntries() {
	const flow = phase('flow');
	const burst = phase('burst');
	const complaints = phase('complaints');
	const leak = phase('leak');
	const shadow = phase('shadow');

	const signup = burst[0];
	const sends = burst.filter((e) => e.account_id === signup.account_id && e.type === 'send');
	const firstThrottle = sends.findIndex((e) => e.action === 'throttle');
	const holdAt = complaints.findIndex((e) => e.action === 'hold');
	const blockAt = leak.findIndex((e) => e.action === 'block');

	const out: {item: LaneItem; click: number; e: LaneEntry}[] = [];
	const put = (g: number, it: LaneItem, e: LaneEntry) => out.push({item: it, click: beat(g), e});
	flow.forEach((e, i) => put(33 + i, item(e, i === 0 ? 'flow' : e.action === 'flag' ? 'flag' : undefined), e));
	put(47, item(signup, 'signup'), signup);
	// Sends 1 to 4, then 97 to 100; send 101 is the first throttled. Its
	// countdown fills bar 15 and it passes on bar 16.
	sends.slice(0, 4).forEach((e, i) => put(48 + i, item(e, `send${i + 1}`), e));
	sends.slice(firstThrottle - 4, firstThrottle).forEach((e, i) => put(52 + i, item(e, `send${firstThrottle - 3 + i}`), e));
	put(60, {...item(sends[firstThrottle], 'throttle'), wait: BAR}, sends[firstThrottle]);
	complaints.slice(0, holdAt + 1).forEach((e, i) => put(61 + i, item(e, i === holdAt ? 'hold' : `c${i}`), e));
	leak.forEach((e, i) => put(73 + i, item(e, i === 0 ? 'leak' : i === blockAt ? 'block' : undefined), e));
	let n = 0;
	shadow.forEach((e, i) => put(85 + i, item(e, e.shadow?.length ? `shadow${++n}` : undefined), e));
	return {entries: out, sends, firstThrottle};
}

const built = laneEntries();
export const laneSlots: Slot[] = scheduleAt(built.entries);
export const slot = (tag: string) => slotOf(laneSlots, tag);
// The recorded decision behind each slot.
export const laneData: LaneEntry[] = built.entries.map((x) => x.e);
export const signupAccount = built.sends[0].account_id;

// What the burst's counter shows: account.sends_1m after each send passes.
export const burstCount = (t: number) => {
	let n = 0;
	for (const s of laneSlots) {
		const m = s.item.tag?.match(/^send(\d+)$/);
		if (m && t >= s.click) n = Number(m[1]);
	}
	const th = slot('throttle');
	if (t >= th.start) n = built.firstThrottle + 1;
	// Between send 4 and send 97, the run left out, counted through.
	const a = slot('send4').click;
	const b = slot(`send${built.firstThrottle - 3}`).click;
	if (t > a && t < b) n = Math.max(n, Math.floor(4 + ((t - a) / (b - a)) * (built.firstThrottle - 4 - 4)));
	return n;
};
export const firstThrottleAt = S.burst.first_throttle_at;

// Complaint n arrives a beat before the newsletter's n-th send is decided.
export const complaintRounds = (() => {
	const fern = laneSlots.filter((s) => /^c\d+$|^hold$/.test(s.item.tag ?? '') && laneData[s.index].account_id === 'acct_fernway');
	return fern.map((s, i) => ({n: i + 1, arrive: s.click - BEAT, decided: s.click, action: S.complaints[i].next_send_action}));
})();
