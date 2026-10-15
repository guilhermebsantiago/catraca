// The README animation: the rotor and the lane, as a seamless loop. The
// events are a window of the demo's real decisions, in the order Catraca
// made them, repeated: the loop is one period of that sequence.

import React from 'react';
import {AbsoluteFill, useCurrentFrame, useVideoConfig} from 'remotion';
import {ACTION_COLORS, FONT_MONO, THEMES, Theme} from './brand';
import {Lane} from './lane/Lane';
import {period} from './lane/period';
import {schedule, scheduleEnd} from './lane/sim';

const THROTTLE_WAIT = 1520; // a whole number of 40 ms GIF frames

const PERIODS = 6;
const items = Array.from({length: PERIODS}, () => period(THROTTLE_WAIT)).flat();
const slots = schedule(items, 0);
export const LOOP_MS = scheduleEnd(slots) / PERIODS;
// Render the fourth period: by then the lane is full in both directions.
const LOOP_START = 3 * LOOP_MS;

export const LOOP_SIZE = {width: 800, height: 240};

// `periods` shifts the clock by whole loops; a seamless loop looks the same
// (used to check that it is).
export const LaneLoop: React.FC<{theme: Theme; periods?: number}> = ({theme, periods = 0}) => {
	const frame = useCurrentFrame();
	const {fps} = useVideoConfig();
	const T = THEMES[theme];
	const t = LOOP_START + periods * LOOP_MS + (frame * 1000) / fps;
	const m = 24;
	const ax = 168;
	const ay = 86;
	const legend: [string, string | null][] = [
		['allow', ACTION_COLORS[theme].allow.mark],
		['flag', ACTION_COLORS[theme].flag.mark],
		['throttle', ACTION_COLORS[theme].throttle.mark],
		['hold', ACTION_COLORS[theme].hold.mark],
		['block', ACTION_COLORS[theme].block.mark],
		['shadow', null],
	];
	return (
		<AbsoluteFill style={{background: T.bg}}>
			<svg width={LOOP_SIZE.width} height={LOOP_SIZE.height} viewBox={`0 0 ${LOOP_SIZE.width} ${LOOP_SIZE.height}`}>
				<Lane slots={slots} t={t} theme={theme} ax={ax} ay={ay} m={m} width={LOOP_SIZE.width} bayLife={LOOP_MS * 0.6} />
			</svg>
			<div
				style={{
					position: 'absolute',
					left: 0,
					right: 0,
					bottom: 16,
					display: 'flex',
					justifyContent: 'center',
					gap: 22,
					fontFamily: FONT_MONO,
					fontSize: 15,
					color: T.text2,
				}}
			>
				{legend.map(([name, color]) => (
					<span key={name} style={{display: 'flex', alignItems: 'center', gap: 7}}>
						<svg width={12} height={12} viewBox="0 0 12 12">
							{color ? (
								<circle cx={6} cy={6} r={5.5} fill={color} />
							) : (
								<circle
									cx={6}
									cy={6}
									r={4.75}
									fill="none"
									stroke={ACTION_COLORS[theme].shadow.mark}
									strokeWidth={1.5}
									strokeDasharray="2.1 1.6"
								/>
							)}
						</svg>
						{name}
					</span>
				))}
			</div>
		</AbsoluteFill>
	);
};

