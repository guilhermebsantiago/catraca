// The launch video's clock. One lane runs through scenes 2 to 6, playing the
// demo's live decisions in the order Catraca made them; each scene starts
// when its first event reaches the rotor, so the story and the lane stay in
// step. Long runs of identical decisions are left out (the burst's first 96
// allowed sends and its last 39 throttled ones), which the scenes say.

import {LaneEntry, S, phase, toItem} from '../data';
import {LaneItem, schedule, scheduleEnd, slotOf} from '../lane/sim';

export const FPS = 30;
export const WIDTH = 1920;
export const HEIGHT = 1080;

// Lane geometry for scenes 2 to 6.
export const LANE = {ax: 318, ay: 370, m: 38};

const THROTTLE_WAIT = 1700;

const item = (e: LaneEntry, tag?: string): LaneItem => {
	const it = toItem(e, tag);
	if (it.action === 'throttle') it.wait = THROTTLE_WAIT;
	return it;
};

function laneItems() {
	const flow = phase('flow');
	const burst = phase('burst');
	const complaints = phase('complaints');
	const leak = phase('leak');
	const shadow = phase('shadow');

	const signup = burst[0];
	const sends = burst.filter((e) => e.account_id === signup.account_id && e.type === 'send');
	const firstThrottle = sends.findIndex((e) => e.action === 'throttle');
	const after = burst.filter((e) => e.account_id !== signup.account_id);

	let shadowN = 0;
	const items: LaneItem[] = [
		...flow.map((e, i) => item(e, i === 0 ? 'flow' : undefined)),
		item(signup, 'burst'),
		...sends.slice(firstThrottle - 4, firstThrottle).map((e) => item(e)),
		item(sends[firstThrottle], 'throttle'),
		...after.map((e) => item(e)),
		...complaints.map((e, i) => item(e, i === 0 ? 'complaints' : e.action === 'hold' ? 'hold' : undefined)),
		...leak.map((e, i) => item(e, i === 0 ? 'leak' : e.action === 'block' ? 'block' : undefined)),
		...shadow.map((e) => item(e, e.shadow?.length ? `shadow${++shadowN}` : undefined)),
	];
	const shadowStart = items.length - shadow.length;
	// Events still waiting when the lane leaves the screen.
	const tail = shadow.slice(1, 7).map((e) => ({...item(e), tag: undefined}));
	return {items: [...items, ...tail], shadowStart};
}

const built = laneItems();
export const LANE_T0 = 4850; // the first passage starts
export const laneSlots = schedule(built.items, LANE_T0);

export const slot = (tag: string) => slotOf(laneSlots, tag);

// Complaint rounds: complaint n arrives as the event before the
// newsletter's n-th send starts passing.
export const complaintRounds = (() => {
	const c = phase('complaints');
	const base = laneSlots.indexOf(slot('complaints'));
	const rounds: {arrive: number; decided: number; action: string; n: number}[] = [];
	c.forEach((e, i) => {
		if (e.account_id !== 'acct_fernway') return;
		const n = rounds.length;
		const s = laneSlots[base + i];
		rounds.push({arrive: laneSlots[base + i - 1].start, decided: s.click, action: S.complaints[n].next_send_action, n: n + 1});
	});
	return rounds;
})();

const lead = 350;
export const SCENES = (() => {
	const s2 = 4350;
	const s3 = slot('burst').start - lead;
	const s4 = slot('complaints').start - lead;
	const s5 = slot('leak').start - lead;
	const s6 = laneSlots[built.shadowStart].start - lead;
	// The reviewer's two labels need a moment on screen before the report.
	const report = slot('shadow3').click + 2700;
	const close = report + 5500;
	const end = close + 4700;
	return {s1: 0, s2, s3, s4, s5, s6, report, close, end};
})();

export const DURATION_FRAMES = Math.ceil((SCENES.end * FPS) / 1000);


export const laneEnd = scheduleEnd(laneSlots);
