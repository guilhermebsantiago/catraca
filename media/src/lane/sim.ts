// The lane, per docs/brand.md (Motion): events arrive from the left as open
// rings, queue against the rotor's down-left arm and pass one at a time.
// The rotor is a ratchet: a third of a turn per passage, counterclockwise, on
// the turn easing. Every position here is a pure function of time, so any
// frame can be rendered on its own.

import {Action, MOTION, armLeftBoundary, clamp01, easeIn, easeInOut, easeOut, easeTurn} from '../brand';

export type LaneItem = {
	// 'none' passes without a decision (an open ring, used before Catraca
	// is in the picture).
	action: Action | 'none';
	// A shadow rule matched: what it would have done (dashed ring).
	shadow?: Action;
	// For throttle: how long the countdown lasts on screen, ms.
	wait?: number;
	// Lets scenes find the slot of a particular event.
	tag?: string;
	// When the dashed ring closes into a solid one (promotion), ms.
	promoteAt?: number;
};

export type Slot = {
	item: LaneItem;
	index: number;
	// When the event becomes the head of the queue's turn: for a throttle,
	// the countdown starts; for a block, it meets the arm.
	start: number;
	turnStart: number; // passes only
	click: number; // the instant the event takes its color
	next: number;
	stepStart: number; // the queue behind moves up one place
	stepEnd: number;
};

export const GEOMETRY = {
	offset: 2.25, // lane under the axis, in modules
	dot: 0.3, // event radius, in modules
	head: armLeftBoundary(2.25) - 0.14 - 0.3, // head of the queue, from the axis
	sector: 0.6, // where a passed event is at the click, from the axis
	bayDrop: 1.4, // how far under the lane the hold bay is
};

const TURN = MOTION.turn;
const PITCH = MOTION.pitch;

export function schedule(items: LaneItem[], t0: number): Slot[] {
	const slots: Slot[] = [];
	let cursor = t0;
	items.forEach((item, index) => {
		if (item.action === 'block') {
			slots.push({
				item,
				index,
				start: cursor,
				turnStart: NaN,
				click: cursor + MOTION.click,
				next: cursor + PITCH,
				stepStart: cursor + MOTION.fade,
				stepEnd: cursor + PITCH,
			});
			cursor += PITCH;
			return;
		}
		const wait = item.action === 'throttle' ? (item.wait ?? 1500) : 0;
		const turnStart = cursor + wait;
		slots.push({
			item,
			index,
			start: cursor,
			turnStart,
			click: turnStart + TURN,
			next: turnStart + PITCH,
			stepStart: turnStart + TURN / 2,
			stepEnd: turnStart + PITCH,
		});
		cursor = turnStart + PITCH;
	});
	return slots;
}

export const scheduleEnd = (slots: Slot[]) => (slots.length ? slots[slots.length - 1].next : 0);

// Rotor angle in degrees (SVG, so negative is counterclockwise on screen).
export function rotorAngle(slots: Slot[], t: number): number {
	let turns = 0;
	let give = 0;
	for (const s of slots) {
		if (s.start > t) break;
		if (s.item.action === 'block') {
			const p = clamp01((t - s.start) / MOTION.click);
			if (p > 0 && p < 1) give += -2 * Math.sin(Math.PI * p);
			continue;
		}
		turns += easeTurn(clamp01((t - s.turnStart) / TURN));
	}
	// The rotor looks the same every third of a turn, so only the turn in
	// progress is drawn: every rest pose is the mark at 0 degrees, pixel for
	// pixel, which keeps loops seamless.
	return -120 * (turns - Math.floor(turns)) + give;
}

export type Dot = {
	key: number;
	x: number; // in modules from the axis
	y: number; // in modules from the lane
	// 0: an open ring; 1: filled with the action's color.
	fill: number;
	action: Action | 'none';
	opacity: number;
	shadow?: Action;
	shadowIn: number; // 0..1, the dashed ring appearing
	promoted: number; // 0..1, the dashed ring closing
	countdown?: number; // throttle: 0..1 of the wait elapsed
	held: boolean;
};

// Hermite curve from a (still) to b, arriving with velocity vb (modules per
// unit of p), so a passed event joins the steady stream without a jolt.
function hermite(a: number, b: number, vb: number, p: number) {
	const p2 = p * p;
	const p3 = p2 * p;
	return (2 * p3 - 3 * p2 + 1) * a + (-2 * p3 + 3 * p2) * b + (p3 - p2) * vb;
}

export type DotOptions = {
	// Visible range, in modules from the axis.
	minX: number;
	maxX: number;
	// How long a held event stays in the bay, ms (Infinity: until the end).
	bayLife?: number;
};

export function dots(slots: Slot[], t: number, o: DotOptions): Dot[] {
	const out: Dot[] = [];
	const v = 1 / PITCH; // modules per ms downstream
	const {head, sector} = GEOMETRY;
	// Queue steps completed before t, with the one in progress as a fraction.
	let steps = 0;
	for (const s of slots) {
		if (s.stepStart > t) break;
		steps += easeInOut(clamp01((s.stepEnd - s.stepStart > 0 ? (t - s.stepStart) / (s.stepEnd - s.stepStart) : 1)));
	}
	let held = 0;
	for (const s of slots) {
		const it = s.item;
		const base: Dot = {
			key: s.index,
			x: 0,
			y: 0,
			fill: 0,
			action: it.action,
			opacity: 1,
			shadow: it.shadow,
			shadowIn: 0,
			promoted: 0,
			held: false,
		};
		if (t < s.start) {
			// Waiting: queued behind the events that have not left yet.
			const k = s.index - Math.min(steps, s.index);
			const x = head - k;
			if (x < o.minX - 1) break; // everything after is further left
			out.push({...base, x});
			continue;
		}
		if (it.action === 'block') {
			const give = clamp01((t - s.start) / MOTION.click);
			const drop = clamp01((t - s.click) / MOTION.fade);
			if (drop >= 1) continue;
			out.push({
				...base,
				x: head + 0.12 * Math.sin(Math.PI * give),
				y: 0.9 * easeIn(drop),
				fill: give,
				opacity: 1 - easeIn(drop),
			});
			continue;
		}
		let x: number;
		if (t < s.turnStart) {
			x = head;
			base.countdown = clamp01((t - s.start) / (s.turnStart - s.start));
		} else if (t < s.click) {
			const p = (t - s.turnStart) / TURN;
			x = hermite(head, sector, v * TURN, p);
		} else {
			x = sector + v * (t - s.click);
		}
		const sinceClick = t - s.click;
		const fill = it.action === 'none' ? 0 : clamp01(sinceClick / MOTION.click);
		const shadowIn = it.shadow ? easeOut(clamp01(sinceClick / MOTION.fade)) : 0;
		const promoted = it.promoteAt !== undefined ? easeOut(clamp01((t - it.promoteAt) / MOTION.fade)) : 0;
		if (it.action === 'hold' && sinceClick > 0) {
			// Carried through, then steps out of the lane into the bay.
			const out0 = s.click + 60;
			const p = easeOut(clamp01((t - out0) / TURN));
			const xLane = sector + v * Math.max(0, Math.min(t, out0) - s.click);
			const life = o.bayLife ?? Infinity;
			const fade = clamp01((t - (s.click + life)) / MOTION.fade);
			if (fade >= 1) continue;
			const bayX = sector + 1.7 + held * 0.9;
			held++;
			out.push({
				...base,
				x: xLane + (bayX - xLane) * p,
				y: GEOMETRY.bayDrop * p,
				fill,
				shadowIn,
				promoted,
				held: true,
				opacity: 1 - fade,
			});
			continue;
		}
		if (x > o.maxX + 1) continue;
		out.push({...base, x, fill, shadowIn, promoted});
	}
	return out;
}

// The first slot with a tag.
export function slotOf(slots: Slot[], tag: string): Slot {
	const s = slots.find((x) => x.item.tag === tag);
	if (!s) throw new Error(`no slot tagged ${tag}`);
	return s;
}
