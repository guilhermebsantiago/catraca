// Atkinson Hyperlegible Next and Mono (SIL OFL 1.1), self-hosted from
// public/fonts. Both are variable from 200 to 800.
import {loadFont} from '@remotion/fonts';
import {staticFile} from 'remotion';

export const fontsLoaded = Promise.all([
	loadFont({
		family: 'Atkinson Hyperlegible Next',
		url: staticFile('fonts/AtkinsonHyperlegibleNext-wght.ttf'),
		weight: '200 800',
		format: 'truetype',
	}),
	loadFont({
		family: 'Atkinson Hyperlegible Mono',
		url: staticFile('fonts/AtkinsonHyperlegibleMono-wght.ttf'),
		weight: '200 800',
		format: 'truetype',
	}),
]);
