// Renders docs/media from the demo's recorded output (examples/demo/out):
//
//   catraca.mp4         1920x1080, 60 fps, H.264, with its score (AAC)
//   catraca-720p.mp4    1280x720, from the same master
//   catraca-poster.png  the end card
//   lane.gif            the README loop, light
//   lane-dark.gif       the README loop, dark
//
// Usage, from media/:  npm run render  [-- video | poster | gif ...]
//
// Everything goes through Remotion's CLI and the ffmpeg it bundles, so no
// system ffmpeg is needed. Intermediate files live in a temporary directory.
// The score (scripts/score.mjs) is synthesized first and muxed in as is.

import {spawnSync} from 'node:child_process';
import {mkdirSync, mkdtempSync, readdirSync, rmSync, statSync} from 'node:fs';
import {createRequire} from 'node:module';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = path.resolve(root, '..', 'docs', 'media');
const cli = path.join(path.dirname(createRequire(import.meta.url).resolve('@remotion/cli/package.json')), 'remotion-cli.js');
const entry = 'src/index.ts';

// Final encode: chosen so the 1080p video stays well under 8 MB while text
// stays crisp. The master is near-lossless.
const MASTER_CRF = '8';
const CRF_1080 = '22';
const CRF_720 = '23';
const AUDIO_KBPS = '192k';
const MAX_MP4 = 8 * 1024 * 1024;
const MAX_GIF = 2.5 * 1024 * 1024;

const remotion = (...args) => {
	console.log(`\n> remotion ${args.join(' ')}`);
	const r = spawnSync(process.execPath, [cli, ...args], {cwd: root, stdio: 'inherit'});
	if (r.status !== 0) throw new Error(`remotion ${args[0]} failed (exit ${r.status})`);
};

const size = (f) => statSync(f).size;
const mb = (n) => `${(n / 1024 / 1024).toFixed(2)} MB`;

const wanted = new Set(process.argv.slice(2));
const want = (k) => wanted.size === 0 || wanted.has(k);

mkdirSync(out, {recursive: true});
const tmp = mkdtempSync(path.join(tmpdir(), 'catraca-media-'));
const report = [];

try {
	if (want('video')) {
		const score = path.join(root, 'public', 'audio', 'score.wav');
		console.log('\n> node scripts/score.mjs');
		const r = spawnSync(process.execPath, [path.join(root, 'scripts', 'score.mjs')], {cwd: root, stdio: 'inherit'});
		if (r.status !== 0) throw new Error(`score.mjs failed (exit ${r.status})`);
		const master = path.join(tmp, 'master.mp4');
		// PNG frames (Remotion's default for video is JPEG) keep text edges
		// clean. The master is silent; the score goes in at the final encode.
		remotion('render', entry, 'Launch', master, '--codec=h264', `--crf=${MASTER_CRF}`, '--image-format=png', '--color-space=bt709', '--muted', '--log=error');
		// Limited-range BT.709, the way browsers and players expect H.264.
		const color = 'out_color_matrix=bt709:out_range=tv';
		const h264 = ['-c:v', 'libx264', '-preset', 'veryslow', '-tune', 'animation', '-color_range', 'tv', '-colorspace', 'bt709', '-color_primaries', 'bt709', '-color_trc', 'bt709', '-movflags', '+faststart'];
		const aac = ['-map', '0:v', '-map', '1:a', '-c:a', 'aac', '-b:a', AUDIO_KBPS, '-shortest'];
		const v1080 = path.join(out, 'catraca.mp4');
		remotion('ffmpeg', '-y', '-hide_banner', '-loglevel', 'error', '-i', master, '-i', score, '-vf', `scale=${color},format=yuv420p`, ...h264, ...aac, '-crf', CRF_1080, v1080);
		const v720 = path.join(out, 'catraca-720p.mp4');
		remotion('ffmpeg', '-y', '-hide_banner', '-loglevel', 'error', '-i', master, '-i', score, '-vf', `scale=1280:720:flags=lanczos:${color},format=yuv420p`, ...h264, ...aac, '-crf', CRF_720, v720);
		report.push(['catraca.mp4', size(v1080), MAX_MP4], ['catraca-720p.mp4', size(v720), MAX_MP4]);
	}
	if (want('poster')) {
		const poster = path.join(out, 'catraca-poster.png');
		remotion('still', entry, 'Poster', poster, '--log=error');
		report.push(['catraca-poster.png', size(poster)]);
	}
	if (want('gif')) {
		for (const [id, name] of [
			['LaneLight', 'lane.gif'],
			['LaneDark', 'lane-dark.gif'],
		]) {
			const dir = path.join(tmp, id);
			remotion('render', entry, id, dir, '--sequence', '--image-format=png', '--log=error');
			const frames = readdirSync(dir).filter((f) => f.endsWith('.png')).sort();
			const m = frames[0].match(/^(.*?)(\d+)\.png$/);
			if (!m) throw new Error(`unexpected frame names in ${dir}: ${frames[0]}`);
			const pattern = path.join(dir, `${m[1]}%0${m[2].length}d.png`);
			const gif = path.join(out, name);
			// One palette for the whole loop, no dithering: the art is flat color.
			const filter = 'split[a][b];[a]palettegen=max_colors=96:stats_mode=full[p];[b][p]paletteuse=dither=none:diff_mode=rectangle';
			remotion('ffmpeg', '-y', '-hide_banner', '-loglevel', 'error', '-framerate', '25', '-start_number', String(Number(m[2])), '-i', pattern, '-vf', filter, '-loop', '0', gif);
			report.push([name, size(gif), MAX_GIF]);
		}
	}
} finally {
	rmSync(tmp, {recursive: true, force: true});
}

console.log('\nWrote docs/media:');
let over = false;
for (const [name, n, max] of report) {
	const flag = max && n > max ? `  over ${mb(max)}` : '';
	over ||= Boolean(flag);
	console.log(`  ${name.padEnd(20)} ${mb(n)}${flag}`);
}
if (over) process.exitCode = 1;
