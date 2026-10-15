// A window of the demo's real decisions, in the order Catraca made them:
// calm traffic with each kind of decision once. The README loop and the
// video's closing scene repeat it.

import {phase, toItem} from '../data';
import {LaneItem} from './sim';

export function period(throttleWait: number): LaneItem[] {
	const flow = phase('flow');
	const burst = phase('burst');
	const complaints = phase('complaints');
	const leak = phase('leak');
	const shadow = phase('shadow');
	const firstThrottle = burst.find((e) => e.action === 'throttle');
	const holdAt = complaints.findIndex((e) => e.action === 'hold');
	const blockAt = leak.findIndex((e) => e.action === 'block');
	const shadowAt = shadow.findIndex((e) => e.shadow?.length);
	const seq = [
		...flow.slice(0, 9), // allows and the shortener flag
		...complaints.slice(holdAt - 2, holdAt + 2), // the newsletter account held
		...flow.slice(9, 12),
		firstThrottle,
		...leak.slice(blockAt - 1, blockAt + 3), // the leaked key blocked
		...shadow.slice(shadowAt, shadowAt + 3), // a farm signup, shadow flag
	];
	if (seq.some((e) => e === undefined) || holdAt < 2 || blockAt < 1 || shadowAt < 0) {
		throw new Error('the README window is out of range of scenario.json');
	}
	return seq.map((e) => {
		const it = toItem(e!);
		if (it.action === 'throttle') it.wait = throttleWait;
		return it;
	});
}
