import React from 'react';
import {Composition, Still} from 'remotion';
import './fonts';
import {LOOP_MS, LOOP_SIZE, LaneLoop} from './LaneLoop';
import {Launch, POSTER_AT} from './video/Launch';
import {DURATION_FRAMES, FPS, HEIGHT, WIDTH} from './video/timeline';

const GIF_FPS = 25;
const loopFrames = Math.round((LOOP_MS * GIF_FPS) / 1000);

export const Root: React.FC = () => (
	<>
		<Composition id="Launch" component={Launch} durationInFrames={DURATION_FRAMES} fps={FPS} width={WIDTH} height={HEIGHT} />
		<Still id="Poster" component={Launch} defaultProps={{at: POSTER_AT}} width={WIDTH} height={HEIGHT} />
		<Composition
			id="LaneLight"
			component={LaneLoop}
			defaultProps={{theme: 'light' as const}}
			durationInFrames={loopFrames}
			fps={GIF_FPS}
			width={LOOP_SIZE.width}
			height={LOOP_SIZE.height}
		/>
		<Composition
			id="LaneDark"
			component={LaneLoop}
			defaultProps={{theme: 'dark' as const}}
			durationInFrames={loopFrames}
			fps={GIF_FPS}
			width={LOOP_SIZE.width}
			height={LOOP_SIZE.height}
		/>
	</>
);
