// What the demo scenario recorded (examples/demo/out/scenario.json): real
// requests and answers from `catraca serve`, its webhook and its command line.
// Regenerate it with `go run ./examples/demo` from the repository root.

import scenario from '../../examples/demo/out/scenario.json';
import {Action} from './brand';
import {LaneItem} from './lane/sim';

export type Exchange = {
	method: string;
	path: string;
	request_headers?: Record<string, string>;
	request?: unknown;
	status: number;
	status_text: string;
	response_headers?: Record<string, string>;
	response: unknown;
};

export type LaneEntry = {
	seq: number;
	phase: string;
	type: string;
	account_id: string;
	api_key_id?: string;
	decision_id: string;
	action: Action;
	retry_after?: number;
	rules?: string[];
	shadow?: {rule_id: string; action: Action}[];
	latency_us: number;
};

type Command = {args: string[]; stdout: string; exit: number};

type Scenario = {
	note: string;
	generated_at: string;
	catraca_version: string;
	ruleset_version: string;
	history: Record<string, number>;
	steps: Record<string, Exchange>;
	burst: Record<string, number>;
	complaints: {complaints: number; next_send_action: Action; next_send_decision_id: string}[];
	hook: {
		method: string;
		path: string;
		headers: Record<string, string>;
		body: Record<string, unknown>;
		verified: string;
		status: number;
	};
	labels: Record<string, number>;
	cli: Record<string, Command>;
	lane: LaneEntry[];
};

export const S = scenario as unknown as Scenario;

export const step = (name: string): Exchange => {
	const e = S.steps[name];
	if (!e) throw new Error(`no step ${name} in scenario.json`);
	return e;
};

// Decisions the lane shows: sends and account events. Feedback and key_leak
// events are decided too, but they are not traffic passing the turnstile;
// the scenes show them in their panels instead.
export const laneEntries = S.lane.filter((e) => e.type === 'send' || e.type === 'account');

export const phase = (name: string) => laneEntries.filter((e) => e.phase === name);

export const toItem = (e: LaneEntry, tag?: string): LaneItem => ({
	action: e.action,
	shadow: e.shadow?.[0]?.action,
	tag: tag ?? `seq${e.seq}`,
});
