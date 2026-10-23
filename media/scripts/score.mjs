// The launch video's score, synthesized from code: no samples, no downloads,
// and the same file on every run (the noise is seeded).
//
//   public/audio/score.wav   48 kHz, stereo, 16-bit, 64.000 s
//
// Usage, from media/:  node scripts/score.mjs
//
// The video is cut to this clock. At 125 BPM a beat is 480 ms, the lane's
// pitch, so the kicks land on rotor clicks. Every hit the picture follows is
// in CUES and every part in ARRANGEMENT: move one and re-run.

import {mkdirSync, writeFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(root, 'public', 'audio', 'score.wav');

// --- Clock -------------------------------------------------------------------

const SR = 48000;
const BPM = 125;
const BEAT = 60 / BPM; // 0.48 s: one passage on the lane
const BAR = 4 * BEAT; // 1.92 s
const LENGTH = 64; // s
const N = LENGTH * SR;

// Bar n and beat b, both from 1, plus s sixteenths, in seconds. A sixteenth
// is 5760 samples, so every grid time is a whole sample.
const at = (bar, beat = 1, s = 0) => (bar - 1) * BAR + (beat - 1) * BEAT + (s * BEAT) / 4;
const idx = (t) => Math.round(t * SR);

// What the picture is cut to.
const CUES = {
	riser: at(4), // a soft riser under the traffic, into the stop
	tapeStop: at(5, 3), // traffic stops: the music winds down to a halt
	tapeStopLength: 0.6,
	drone: at(6), // near silence: a low drone and the tail
	reverse: at(6, 3), // a reversed cymbal swells into the logo
	logo: at(7), // impact, the drop, the rotor's first click
	click: at(8), // the rotor's second click
	actions: [at(11, 1), at(11, 2), at(11, 3), at(11, 4), at(12, 1)], // allow, flag, throttle, hold, block
	build: at(13),
	throttle: at(15), // the bed closes to a countdown
	release: at(16), // and opens again
	complaints: [at(16, 2), at(17, 1), at(17, 4), at(18, 3)], // every 3 beats, against the bar
	hold: at(18, 4),
	block: at(20), // a thunk; kick and bass sit out two beats
	blockBack: at(20, 3),
	webhook: at(21),
	breakdown: at(22),
	roll: at(24),
	gap: at(25, 4, 2), // the last 8th before drop 2 is silent
	drop: at(26),
	endCard: at(30),
	final: at(32),
	silence: 63.7, // the final chord's tail is gone
};

// MIDI notes, F minor. Pad voicings sit around F3–F4 and move by step; the
// bass plays roots in octave 2 so the kick keeps the sub to itself.
const CHORDS = {
	Fm: {pad: [53, 56, 60, 63], root: 41},
	Db: {pad: [49, 53, 56, 60], root: 37},
	Ab: {pad: [51, 56, 60, 63], root: 44},
	Eb: {pad: [51, 55, 58, 65], root: 39},
	Gb: {pad: [49, 54, 58, 65], root: 42}, // the dark turn: bII, Phrygian
};
const LOGO_CHORD = [41, 48, 53, 56, 60, 65];
const HOLD_CHORD = [51, 56, 58, 63, 70]; // Eb sus4
const FINAL_CHORD = [41, 48, 53, 56, 60, 67, 72]; // Fm(add9)
// The five action stabs, rising: Fm voicings over bar 11, Db on bar 12.
const STABS = [
	[65, 68, 72],
	[68, 72, 75],
	[72, 75, 77],
	[75, 77, 80],
	[77, 80, 85],
];
const SCALE = [65, 67, 68, 70, 72, 73, 75, 77]; // F aeolian, for the build
const BLIP = [79, 80]; // G5 to Ab5: a minor second, a little tense

// One row per bar.
//   kick 'soft' (muffled) or 'full'    hats 'soft', 'groove', 'roll', 'air' or 'end'
//   bass 'roll', 'dark' or 'end'        arp  'pulse', 'groove', 'rise' or 'filtered'
const groove = {kick: 'full', clap: true, hats: 'groove', bass: 'roll', arp: 'groove'};
const dark = {...groove, bass: 'dark'};
const ARRANGEMENT = [
	{chord: 'Fm', arp: 'pulse', sub: true}, // 1  intro
	{chord: 'Fm', arp: 'pulse', sub: true}, // 2
	{chord: 'Db', arp: 'pulse', sub: true, kick: 'soft', hats: 'soft', rim: true}, // 3
	{chord: 'Db', arp: 'pulse', sub: true, kick: 'soft', hats: 'soft', rim: true}, // 4  riser
	{chord: 'Eb', arp: 'pulse', sub: true, kick: 'soft', hats: 'soft', rim: true}, // 5  tape stop on beat 3
	{}, // 6  drone and tail
	{...groove, chord: 'Fm', clap: false}, // 7  logo: the drop
	{...groove, chord: 'Db', clap: false}, // 8
	{...groove, chord: 'Ab'}, // 9  groove A
	{...groove, chord: 'Eb'}, // 10
	{...groove, chord: 'Fm'}, // 11 action stabs
	{...groove, chord: 'Db'}, // 12
	{...groove, chord: 'Ab', hats: 'roll', arp: 'rise'}, // 13 build
	{...groove, chord: 'Eb', hats: 'roll', arp: 'rise'}, // 14
	{...groove, chord: 'Fm'}, // 15 throttle
	{...groove, chord: 'Db'}, // 16 complaints
	{...groove, chord: 'Ab'}, // 17
	{...groove, chord: 'Eb'}, // 18 hold
	{...dark, chord: 'Fm'}, // 19 darker
	{...dark, chord: 'Gb'}, // 20 block
	{...dark, chord: 'Ab'}, // 21 webhook
	{chord: 'Db', hats: 'air', arp: 'filtered'}, // 22 breakdown: shadow mode
	{chord: 'Db', hats: 'air', arp: 'filtered'}, // 23
	{chord: 'Eb', hats: 'air', arp: 'filtered'}, // 24 riser, snare roll
	{chord: 'Eb', hats: 'air', arp: 'filtered'}, // 25
	{...groove, chord: 'Fm', lead: true}, // 26 drop 2
	{...groove, chord: 'Db', lead: true}, // 27
	{...groove, chord: 'Ab', lead: true}, // 28
	{...groove, chord: 'Eb', lead: true}, // 29
	{chord: 'Db', kick: 'full', hats: 'end', bass: 'end'}, // 30 end card
	{chord: 'Eb', kick: 'full', hats: 'end'}, // 31
	{}, // 32 final chord
];

// Parts that sit out between two times.
const MUTES = [{parts: ['kick', 'bass'], from: CUES.block, to: CUES.blockBack}];
const muted = (part, t) => MUTES.some((m) => m.parts.includes(part) && t >= m.from - 1e-9 && t < m.to - 1e-9);

// Filter and level automation, [time, value]: frequencies move
// exponentially, gains linearly.
const PAD_CUT = [[0, 280], [at(3), 550], [at(5, 3), 2600], [at(7), 3200], [at(22), 1300], [at(24), 1300], [at(26), 4500], [at(30), 3600], [at(32), 1600]];
const PAD_GAIN = [[0, 0], [at(2, 3), 0.8], [at(3), 0.85], [at(5), 1], [at(7), 0.9], [at(22), 1.1], [at(26), 0.95], [at(30), 0.9]];
const ARP_CUT = [[0, 700], [at(3), 1000], [at(5, 3), 2400], [at(7), 3600], [at(22), 1000], [at(24), 1000], [at(26), 5200], [at(30), 3800]];
// The whole bed: closed to a countdown through the throttle bar, and closing
// slowly under the end card.
const BED_CUT = [
	[0, 20000],
	[CUES.throttle, 20000],
	[CUES.throttle + 0.16, 400],
	[CUES.release - 0.002, 400],
	[CUES.release + 0.09, 20000],
	[CUES.endCard, 20000],
	[CUES.final, 1500],
	[CUES.final + 0.01, 20000],
];

// Mix, in linear gain before the master.
const LEVEL = {kick: 0.9, clap: 1.6, hat: 0.3, rim: 0.22, bass: 0.7, pad: 0.2, arp: 0.42, lead: 0.26, reverb: 0.33};
const TARGET_LUFS = -14;
const CEILING = -1.6; // dBFS, inter-sample peaks included

// --- Building blocks ------------------------------------------------------------

// mulberry32: seeded, so every render writes the same file.
function rng(seed) {
	let a = seed >>> 0;
	return () => {
		a = (a + 0x6d2b79f5) >>> 0;
		let t = a;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}
const rand = rng(0xca7aca);
const noise = () => rand() * 2 - 1;

const TAU = 2 * Math.PI;
const mtof = (m) => 440 * Math.pow(2, (m - 69) / 12);
const db = (v) => Math.pow(10, v / 20);
const tanG = (hz) => Math.tan((Math.PI * Math.min(hz, 0.45 * SR)) / SR);
const stereo = (n = N) => [new Float32Array(n), new Float32Array(n)];
// Equal-power pan, unity in the center.
const panGains = (p) => [Math.SQRT2 * Math.cos(((p + 1) * Math.PI) / 4), Math.SQRT2 * Math.sin(((p + 1) * Math.PI) / 4)];
// A short linear fade over the last m samples of n, so one-shots never end on a step.
const tailFade = (n, len, m = 480) => (n > len - m ? Math.max(0, (len - n) / m) : 1);

// PolyBLEP residual: takes the step out of a naive saw or square so it
// doesn't alias.
function blep(t, dt) {
	if (t < dt) {
		t /= dt;
		return t + t - t * t - 1;
	}
	if (t > 1 - dt) {
		t = (t - 1) / dt;
		return t * t + t + t + 1;
	}
	return 0;
}

// Zero-delay-feedback state variable filter (Simper). g = tanG(hz), k = 1/Q.
// Cutoff can move every sample without zipper noise.
class SVF {
	constructor() {
		this.s1 = 0;
		this.s2 = 0;
		this.low = 0;
		this.band = 0;
		this.high = 0;
	}
	tick(x, g, k) {
		const a1 = 1 / (1 + g * (g + k));
		const a2 = g * a1;
		const a3 = g * a2;
		const v3 = x - this.s2;
		const v1 = a1 * this.s1 + a2 * v3;
		const v2 = this.s2 + a2 * this.s1 + a3 * v3;
		this.s1 = 2 * v1 - this.s1;
		this.s2 = 2 * v2 - this.s2;
		this.low = v2;
		this.band = v1;
		this.high = x - k * v1 - v2;
		return v2;
	}
}

// Automation keys sampled for every output sample.
function automation(keys, linear = false) {
	const out = new Float32Array(N);
	let j = 0;
	for (let i = 0; i < N; i++) {
		const t = i / SR;
		while (j < keys.length - 1 && t >= keys[j + 1][0]) j++;
		if (t <= keys[0][0] || j === keys.length - 1) {
			out[i] = keys[j][1];
			continue;
		}
		const [t0, v0] = keys[j];
		const [t1, v1] = keys[j + 1];
		const u = (t - t0) / (t1 - t0);
		out[i] = linear ? v0 + (v1 - v0) * u : v0 * Math.pow(v1 / v0, u);
	}
	return out;
}

// --- Instruments ----------------------------------------------------------------
// Each writes into a stereo buffer at an absolute time; `send` is the reverb.

// Kick: a sine falling from 160 to 45 Hz in about 60 ms, a short hold and a
// 100 ms decay, with a 3 ms click on top. It starts at phase 0 on the beat's
// exact sample. Muffled: through two 240 Hz lowpasses, the intro's kick.
function kick(bus, t0, vel, muffled = false) {
	const i0 = idx(t0);
	const len = Math.round(0.5 * SR);
	const lpA = 1 - Math.exp((-TAU * 240) / SR);
	const clickA = 1 - Math.exp((-TAU * 5000) / SR);
	let ph = 0;
	let lp1 = 0;
	let lp2 = 0;
	let click = 0;
	for (let n = 0; n < len && i0 + n < N; n++) {
		const t = n / SR;
		ph += (45 + 115 * Math.exp(-t / 0.02)) / SR;
		const env = t < 0.03 ? 1 : Math.exp(-(t - 0.03) / 0.1);
		let v = Math.sin(TAU * ph) * env * tailFade(n, len, 960);
		if (t < 0.003) {
			click += clickA * (noise() - click);
			v += 0.35 * click * (1 - t / 0.003);
		}
		v = Math.tanh(1.8 * v) / Math.tanh(1.8);
		if (muffled) {
			lp1 += lpA * (v - lp1);
			lp2 += lpA * (lp1 - lp2);
			v = lp2 * 1.4;
		}
		bus[0][i0 + n] += v * vel;
		bus[1][i0 + n] += v * vel;
	}
}

// Clap: three bandpassed noise bursts 11 ms apart and a short tail, with
// slightly different noise left and right.
function clap(bus, send, t0, vel, sendAmt = 0.22) {
	const i0 = idx(t0);
	const len = Math.round(0.4 * SR);
	const bl = new SVF();
	const br = new SVF();
	const hl = new SVF();
	const hr = new SVF();
	const g = tanG(1250);
	const k = 1 / 1.4;
	const gh = tanG(650);
	for (let n = 0; n < len && i0 + n < N; n++) {
		const t = n / SR;
		let env = 0;
		for (const o of [0, 0.011, 0.022]) if (t >= o) env = Math.max(env, Math.min(1, (t - o) / 0.0003) * Math.exp(-(t - o) / 0.0045));
		if (t >= 0.022) env = Math.max(env, 0.5 * Math.exp(-(t - 0.022) / 0.08));
		const c = noise();
		bl.tick(0.75 * c + 0.25 * noise(), g, k);
		br.tick(0.75 * c + 0.25 * noise(), g, k);
		hl.tick(bl.band * k, gh, 1.4);
		hr.tick(br.band * k, gh, 1.4);
		const a = env * vel * tailFade(n, len);
		const l = hl.high * a;
		const r = hr.high * a;
		bus[0][i0 + n] += l;
		bus[1][i0 + n] += r;
		send[0][i0 + n] += l * sendAmt;
		send[1][i0 + n] += r * sendAmt;
	}
}

// 808-style metal for hats and crashes: six square waves at inharmonic
// ratios, highpassed, rendered once; each hit reads it from a random offset.
const METAL = (() => {
	const len = 4 * SR;
	const out = new Float32Array(len);
	const fs = [205.3, 304.4, 369.6, 522.7, 540.0, 800.0].map((f) => f * 1.1);
	const ph = fs.map(() => rand());
	const h1 = new SVF();
	const h2 = new SVF();
	const lp = new SVF();
	const gh = tanG(6800);
	const gl = tanG(10500);
	let sum = 0;
	for (let i = 0; i < len; i++) {
		let v = 0;
		for (let j = 0; j < 6; j++) {
			const dt = fs[j] / SR;
			ph[j] += dt;
			if (ph[j] >= 1) ph[j] -= 1;
			const p2 = ph[j] + 0.5 >= 1 ? ph[j] - 0.5 : ph[j] + 0.5;
			v += (ph[j] < 0.5 ? 1 : -1) + blep(ph[j], dt) - blep(p2, dt);
		}
		h1.tick(v, gh, 1.3);
		h2.tick(h1.high, gh, 1.3);
		out[i] = lp.tick(h2.high, gl, 1.2);
		sum += out[i] * out[i];
	}
	const g = 0.35 / Math.sqrt(sum / len);
	for (let i = 0; i < len; i++) out[i] *= g;
	return out;
})();

// Hat: closed (22 ms) or open (130 ms, choked at 240 ms), with a little
// bandpassed noise for air.
function hat(bus, t0, vel, open = false, p = 0) {
	const i0 = idx(t0);
	const tau = open ? 0.13 : 0.022;
	const len = Math.round((open ? 0.24 : 0.12) * SR);
	const o = Math.floor(rand() * (METAL.length - len - 1));
	const [gl, gr] = panGains(p);
	const air = new SVF();
	const ga = tanG(7500);
	for (let n = 0; n < len && i0 + n < N; n++) {
		const t = n / SR;
		const env = Math.min(1, t / 0.0004) * Math.exp(-t / tau) * tailFade(n, len, 600);
		air.tick(noise(), ga, 1);
		const v = (METAL[o + n] + 0.25 * air.band) * env * vel;
		bus[0][i0 + n] += v * gl;
		bus[1][i0 + n] += v * gr;
	}
}

// A sum of damped sines, each starting at phase 0 so the attack has no step.
function partials(bus, t0, vel, parts, len, p = 0) {
	const i0 = idx(t0);
	const L = Math.round(len * SR);
	const [gl, gr] = panGains(p);
	for (let n = 0; n < L && i0 + n < N; n++) {
		const t = n / SR;
		let v = 0;
		for (const [f, tau, a] of parts) v += a * Math.sin(TAU * f * t) * Math.exp(-t / tau);
		v *= vel * tailFade(n, L, 120);
		bus[0][i0 + n] += v * gl;
		bus[1][i0 + n] += v * gr;
	}
}

// Rim: a clicky wooden tick.
const rim = (bus, t0, vel, p) => partials(bus, t0, vel, [[1700, 0.006, 1], [3150, 0.003, 0.45], [520, 0.01, 0.35]], 0.06, p);

// Snare: a falling body tone and bandpassed noise.
function snare(bus, send, t0, vel, tau = 0.12, sendAmt = 0.3) {
	const i0 = idx(t0);
	const len = Math.round(Math.min(0.5, 5 * tau + 0.05) * SR);
	const bp = new SVF();
	const hp = new SVF();
	const g = tanG(2800);
	const gh = tanG(1400);
	let ph = 0;
	for (let n = 0; n < len && i0 + n < N; n++) {
		const t = n / SR;
		ph += (175 + 60 * Math.exp(-t / 0.01)) / SR;
		const body = Math.sin(TAU * ph) * Math.exp(-t / 0.05) * 0.55 + Math.sin(TAU * 330 * t) * Math.exp(-t / 0.03) * 0.25;
		bp.tick(noise(), g, 1.1);
		hp.tick(bp.band * 1.1, gh, 1.4);
		const v = (body + hp.high * 1.2 * Math.exp(-t / tau) * Math.min(1, t / 0.0005)) * vel * tailFade(n, len);
		bus[0][i0 + n] += v;
		bus[1][i0 + n] += v;
		send[0][i0 + n] += v * sendAmt;
		send[1][i0 + n] += v * sendAmt;
	}
}

// Bass: a saw through a resonant lowpass that opens on each note, with a
// sine at the fundamental for weight. Mono.
function bassNote(bus, t0, dur, midi, vel, {cut = 190, env = 1500, k = 0.7, drive = 1.3} = {}) {
	const i0 = idx(t0);
	const rel = 0.025;
	const len = Math.round((dur + rel) * SR);
	const dt = mtof(midi) / SR;
	const flt = new SVF();
	let ph = 0;
	const norm = Math.tanh(drive);
	for (let n = 0; n < len && i0 + n < N; n++) {
		const t = n / SR;
		ph += dt;
		if (ph >= 1) ph -= 1;
		const saw = 2 * ph - 1 - blep(ph, dt);
		const a = Math.min(1, t / 0.003) * (t < dur ? 1 : Math.max(0, 1 - (t - dur) / rel));
		flt.tick(saw, tanG(cut + env * vel * Math.exp(-t / 0.045)), k);
		const v = (Math.tanh(drive * (flt.low * 0.8 + Math.sin(TAU * ph) * 0.6)) / norm) * a * vel;
		bus[0][i0 + n] += v;
		bus[1][i0 + n] += v;
	}
}

// Pluck: two detuned saws (or squares) through a lowpass that snaps shut.
function pluck(bus, t0, midi, vel, {cut = 3000, decay = 0.16, square = false, p = 0, detune = 6, len = 0.5, k = 0.9} = {}) {
	const i0 = idx(t0);
	const L = Math.round(len * SR);
	const f = mtof(midi);
	const d = Math.pow(2, detune / 1200);
	const dts = [(f * d) / SR, f / d / SR];
	const phs = [rand(), rand()];
	const [gl, gr] = panGains(p);
	const flt = new SVF();
	for (let n = 0; n < L && i0 + n < N; n++) {
		const t = n / SR;
		let v = 0;
		for (let j = 0; j < 2; j++) {
			const dt = dts[j];
			let q = phs[j] + dt;
			if (q >= 1) q -= 1;
			phs[j] = q;
			if (square) {
				const q2 = q + 0.5 >= 1 ? q - 0.5 : q + 0.5;
				v += (q < 0.5 ? 1 : -1) + blep(q, dt) - blep(q2, dt);
			} else {
				v += 2 * q - 1 - blep(q, dt);
			}
		}
		flt.tick(v * 0.5, tanG(150 + cut * (0.2 + 0.8 * Math.exp(-t / 0.07)) * (0.6 + 0.4 * vel)), k);
		const a = Math.min(1, t / 0.002) * Math.exp(-t / decay) * tailFade(n, L, 960) * vel;
		bus[0][i0 + n] += flt.low * a * gl;
		bus[1][i0 + n] += flt.low * a * gr;
	}
}

// Supersaw: seven saws a few cents apart, spread across the stereo field.
// `env(t)` shapes it from the note's start.
const SAW_CENTS = [-19, -12, -5, 0, 5, 12, 19];
const SAW_PAN = [-0.85, 0.55, -0.3, 0, 0.3, -0.55, 0.85];
function supersaw(buf, i0, len, midi, vel, env) {
	const f = mtof(midi);
	const n = SAW_CENTS.length;
	const dts = new Float64Array(n);
	const phs = new Float64Array(n);
	const gl = new Float64Array(n);
	const gr = new Float64Array(n);
	for (let j = 0; j < n; j++) {
		dts[j] = (f * Math.pow(2, SAW_CENTS[j] / 1200)) / SR;
		phs[j] = rand();
		const [l, r] = panGains(SAW_PAN[j]);
		const g = ((SAW_CENTS[j] === 0 ? 1 : 0.8) * vel) / Math.sqrt(n);
		gl[j] = l * g;
		gr[j] = r * g;
	}
	const [L, R] = buf;
	const end = Math.min(L.length, i0 + len);
	for (let i = i0; i < end; i++) {
		let l = 0;
		let r = 0;
		for (let j = 0; j < n; j++) {
			let p = phs[j] + dts[j];
			if (p >= 1) p -= 1;
			phs[j] = p;
			const s = 2 * p - 1 - blep(p, dts[j]);
			l += s * gl[j];
			r += s * gr[j];
		}
		const a = env((i - i0) / SR);
		L[i] += l * a;
		R[i] += r * a;
	}
}

// Raised-cosine attack, sustain, exponential release with a short fade at the end.
const padEnv = (sus, attack, release) => (t) => {
	let a = t < attack ? 0.5 - 0.5 * Math.cos((Math.PI * t) / attack) : 1;
	if (t > sus) {
		const r = t - sus;
		a *= Math.exp((-5 * r) / release) * Math.min(1, Math.max(0, (release - r) / 0.02));
	}
	return a;
};

// A supersaw chord as a one-shot: raw voices into a clip, then a lowpass on
// its own curve, then into the bus and the reverb.
function chordShot(bus, send, t0, notes, vel, {attack = 0.006, hold = 0, decay = 1.2, cut = () => 3000, k = 1.2, sendAmt = 0.4, length = 3}) {
	const i0 = idx(t0);
	const L = Math.min(N - i0, Math.round(length * SR));
	const clip = stereo(L);
	const env = (t) => {
		const a = t < attack ? 0.5 - 0.5 * Math.cos((Math.PI * t) / attack) : 1;
		return a * (t < attack + hold ? 1 : Math.exp(-(t - attack - hold) / decay));
	};
	for (const m of notes) supersaw(clip, 0, L, m, vel / Math.sqrt(notes.length), env);
	const fl = new SVF();
	const fr = new SVF();
	for (let n = 0; n < L; n++) {
		const g = tanG(cut(n / SR));
		const f = tailFade(n, L, 1440);
		const l = fl.tick(clip[0][n], g, k) * f;
		const r = fr.tick(clip[1][n], g, k) * f;
		bus[0][i0 + n] += l;
		bus[1][i0 + n] += r;
		send[0][i0 + n] += l * sendAmt;
		send[1][i0 + n] += r * sendAmt;
	}
}

// Stab: a short bright chord, one per action word.
function stab(bus, send, t0, notes, vel) {
	chordShot(bus, send, t0, notes, vel, {attack: 0.003, decay: 0.16, cut: (t) => 500 + 5200 * Math.exp(-t / 0.09), k: 1, sendAmt: 0.35, length: 0.7});
}

// Sub boom: a sine falling from f0 to f1, for impacts.
function boom(bus, t0, vel, {tau = 0.8, f0 = 72, f1 = 33} = {}) {
	const i0 = idx(t0);
	const len = Math.min(N - i0, Math.round(5 * tau * SR));
	let ph = 0;
	for (let n = 0; n < len; n++) {
		const t = n / SR;
		ph += (f1 + (f0 - f1) * Math.exp(-t / 0.15)) / SR;
		const v = (Math.tanh(1.5 * Math.sin(TAU * ph) * Math.min(1, t / 0.002) * Math.exp(-t / tau)) / Math.tanh(1.5)) * vel * tailFade(n, len, 2400);
		bus[0][i0 + n] += v;
		bus[1][i0 + n] += v;
	}
}

// Cymbal material: metal and noise, different left and right, band-limited
// to 3.8–9 kHz so it shimmers without hiss. `env(t, u)` shapes it; `cut(u)`
// moves the lowpass (u: 0..1 through the clip).
function cymbal(bus, send, i0, len, vel, env, sendAmt, cut = () => 9000) {
	const oL = Math.floor(rand() * (METAL.length - len - 1));
	const oR = Math.floor(rand() * (METAL.length - len - 1));
	const f = [new SVF(), new SVF(), new SVF(), new SVF()];
	const gh = tanG(3800);
	for (let n = 0; n < len && i0 + n < N; n++) {
		const u = n / len;
		const g = tanG(cut(u));
		const a = env(n / SR, u) * vel;
		f[0].tick(0.6 * METAL[(oL + n) % METAL.length] + 0.5 * noise(), gh, 1.3);
		f[2].tick(0.6 * METAL[(oR + n) % METAL.length] + 0.5 * noise(), gh, 1.3);
		const l = f[1].tick(f[0].high, g, 1.2);
		const r = f[3].tick(f[2].high, g, 1.2);
		bus[0][i0 + n] += l * a;
		bus[1][i0 + n] += r * a;
		send[0][i0 + n] += l * a * sendAmt;
		send[1][i0 + n] += r * a * sendAmt;
	}
}

function crash(bus, send, t0, vel, tau = 0.9) {
	const len = Math.round(4 * tau * SR);
	cymbal(bus, send, idx(t0), len, vel, (t, u) => Math.min(1, t / 0.001) * (0.55 * Math.exp(-t / 0.06) + 0.45 * Math.exp(-t / tau)) * Math.min(1, (1 - u) * 20), 0.25);
}

// Reversed cymbal: swells up and stops dead on the hit.
function reverseCymbal(bus, send, t0, t1, vel) {
	const len = idx(t1) - idx(t0);
	const span = t1 - t0;
	cymbal(bus, send, idx(t0), len, vel, (t) => Math.exp(-(span - t) / 0.28) * Math.min(1, (span - t) / 0.003), 0.15, (u) => 2000 * Math.pow(4, u));
}

// Riser: noise through a bandpass sweeping up, getting louder.
function riser(bus, send, t0, t1, vel, {f0 = 300, f1 = 3000, q = 2.5, sendAmt = 0.25} = {}) {
	const i0 = idx(t0);
	const len = idx(t1) - i0;
	const fl = new SVF();
	const fr = new SVF();
	const k = 1 / q;
	for (let n = 0; n < len && i0 + n < N; n++) {
		const u = n / len;
		const g = tanG(f0 * Math.pow(f1 / f0, u));
		const c = noise();
		fl.tick(0.6 * c + 0.4 * noise(), g, k);
		fr.tick(0.6 * c + 0.4 * noise(), g, k);
		const a = vel * u * u * tailFade(n, len, 720);
		bus[0][i0 + n] += fl.band * k * a;
		bus[1][i0 + n] += fr.band * k * a;
		send[0][i0 + n] += fl.band * k * a * sendAmt;
		send[1][i0 + n] += fr.band * k * a * sendAmt;
	}
}

// The rotor's ratchet: a dry tick at the detent, and a smaller one 28 ms
// later as it settles back (the turn overshoots about 3 degrees).
function ratchet(bus, t0, vel) {
	const parts = [[2350, 0.009, 0.8], [3900, 0.005, 0.5], [6100, 0.0025, 0.25], [880, 0.014, 0.45]];
	partials(bus, t0, vel, parts, 0.08);
	partials(bus, t0 + 0.028, vel * 0.42, parts, 0.08);
}

// Throttle countdown: a soft woodblock tick.
const tick = (bus, t0, vel) => partials(bus, t0, vel, [[2200, 0.015, 1], [3500, 0.008, 0.4]], 0.09);

// Complaint arriving: two tones, a minor second apart.
function blip(bus, send, t0, vel, p) {
	const tone = (start, len, f, a) => {
		const i0 = idx(start);
		const L = Math.round(len * SR);
		const [gl, gr] = panGains(p);
		for (let n = 0; n < L && i0 + n < N; n++) {
			const t = n / SR;
			const e = Math.min(1, t / 0.003) * Math.exp(-t / (len * 0.45)) * tailFade(n, L, 360) * a * vel;
			const v = (Math.sin(TAU * f * t) + 0.12 * Math.sin(3 * TAU * f * t)) * e;
			bus[0][i0 + n] += v * gl;
			bus[1][i0 + n] += v * gr;
			send[0][i0 + n] += v * gl * 0.3;
			send[1][i0 + n] += v * gr * 0.3;
		}
	};
	tone(t0, 0.09, mtof(BLIP[0]), 0.8);
	tone(t0 + 0.085, 0.2, mtof(BLIP[1]), 1);
}

// Block: a dry, low thunk.
function thunk(bus, t0, vel) {
	const i0 = idx(t0);
	const len = Math.round(0.35 * SR);
	const lp = new SVF();
	const g = tanG(450);
	let ph = 0;
	for (let n = 0; n < len && i0 + n < N; n++) {
		const t = n / SR;
		ph += (48 + 50 * Math.exp(-t / 0.03)) / SR;
		lp.tick(noise(), g, 1);
		const v = (Math.sin(TAU * ph) * Math.exp(-t / 0.09) + lp.low * 0.6 * Math.exp(-t / 0.015)) * vel * tailFade(n, len, 960);
		bus[0][i0 + n] += v;
		bus[1][i0 + n] += v;
	}
}

// Webhook out: a short whoosh up, and a quiet chirp.
function whoosh(bus, send, t0, vel) {
	riser(bus, send, t0, t0 + 0.32, vel, {f0: 900, f1: 7000, q: 1.8, sendAmt: 0.35});
	const i0 = idx(t0);
	const len = Math.round(0.3 * SR);
	let ph = 0;
	for (let n = 0; n < len && i0 + n < N; n++) {
		const u = n / len;
		ph += (600 * Math.pow(4, u)) / SR;
		const v = Math.sin(TAU * ph) * u * u * 0.25 * vel * tailFade(n, len, 480);
		bus[0][i0 + n] += v;
		bus[1][i0 + n] += v;
	}
}

// A long sine with a slow fade in and out (the intro's sub, bar 6's drone).
function drone(bus, t0, t1, midi, vel, fadeIn, fadeOut) {
	const i0 = idx(t0);
	const len = idx(t1) - i0;
	const f = mtof(midi);
	const lp = new SVF();
	const g = tanG(170);
	let ph = 0;
	for (let n = 0; n < len; n++) {
		const t = n / SR;
		ph += f / SR;
		if (ph >= 1) ph -= 1;
		const a = Math.min(1, t / fadeIn) * Math.min(1, (len - n) / (fadeOut * SR)) * vel;
		// An octave of saw, lowpassed, gives it a little grain.
		lp.tick(2 * ((2 * ph) % 1) - 1, g, 1.2);
		const v = (Math.sin(TAU * ph) + 0.25 * lp.low) * a;
		bus[0][i0 + n] += v;
		bus[1][i0 + n] += v;
	}
}

// --- Effects ----------------------------------------------------------------------

function lowpassBus(bus, cut, k) {
	for (const ch of bus) {
		const f = new SVF();
		for (let i = 0; i < N; i++) ch[i] = f.tick(ch[i], tanG(cut[i]), k);
	}
}

// Ping-pong: the left line takes the input and the right line's repeat, the
// right line takes the left's. Each repeat loses lows and highs.
function pingPong(bus, time, fb, wet) {
	const D = idx(time);
	const dl = new Float64Array(D);
	const dr = new Float64Array(D);
	const lpA = 1 - Math.exp((-TAU * 3200) / SR);
	const hpA = 1 - Math.exp((-TAU * 280) / SR);
	let w = 0;
	let lpL = 0;
	let hpL = 0;
	let lpR = 0;
	let hpR = 0;
	for (let i = 0; i < N; i++) {
		const yl = dl[w];
		const yr = dr[w];
		lpR += lpA * (yr - lpR);
		hpR += hpA * (lpR - hpR);
		lpL += lpA * (yl - lpL);
		hpL += hpA * (lpL - hpL);
		dl[w] = (bus[0][i] + bus[1][i]) * 0.5 + fb * (lpR - hpR);
		dr[w] = lpL - hpL;
		if (++w >= D) w = 0;
		bus[0][i] += wet * yl;
		bus[1][i] += wet * yr;
	}
}

// Sidechain: each kick pulls a bus down by `depth` in 3 ms and lets it back
// over about 200 ms, so the kick has the low end to itself.
function duck(kicks, depth) {
	const g = new Float32Array(N).fill(1);
	const a = Math.round(0.003 * SR);
	const len = Math.round(0.4 * SR);
	for (const [t, d] of kicks) {
		const i0 = idx(t);
		for (let n = 0; n < len && i0 + n < N; n++) {
			const v = 1 - depth * d * (n < a ? n / a : Math.exp(-(n - a) / (0.07 * SR)));
			if (v < g[i0 + n]) g[i0 + n] = v;
		}
	}
	return g;
}

// Tape stop: from t0 the read head slows linearly to a halt over `length`
// (pitch and level fall with it); then silence until `resume`.
function tapeStop(bus, t0, length, resume) {
	const i0 = idx(t0);
	const span = idx(t0 + length) - i0;
	const ir = idx(resume);
	for (const ch of bus) {
		const src = ch.slice(i0, i0 + span + 4);
		for (let i = i0; i < ir; i++) {
			if (i - i0 >= span) {
				ch[i] = 0;
				continue;
			}
			const u = (i - i0) / span;
			const pos = span * (u - (u * u) / 2);
			const j = Math.floor(pos);
			const f = pos - j;
			const y0 = src[Math.max(0, j - 1)];
			const y1 = src[j];
			const y2 = src[j + 1];
			const y3 = src[j + 2];
			// Catmull-Rom between y1 and y2.
			const v = y1 + 0.5 * f * (y2 - y0 + f * (2 * y0 - 5 * y1 + 4 * y2 - y3 + f * (3 * (y1 - y2) + y3 - y0)));
			ch[i] = v * Math.pow(1 - u, 0.7);
		}
	}
}

// Freeverb (Jezar's tunings, scaled to 48 kHz): eight damped combs and four
// allpasses per side, the right side detuned by 23 samples.
function freeverb(inL, inR, room = 0.84, damp = 0.4) {
	const scale = SR / 44100;
	const make = (spread) => ({
		combs: [1116, 1188, 1277, 1356, 1422, 1491, 1557, 1617].map((t) => ({buf: new Float64Array(Math.round((t + spread) * scale)), i: 0, store: 0})),
		aps: [556, 441, 341, 225].map((t) => ({buf: new Float64Array(Math.round((t + spread) * scale)), i: 0})),
	});
	const sides = [make(0), make(23)];
	const fb = room * 0.28 + 0.7;
	const out = stereo();
	for (let i = 0; i < N; i++) {
		const x = (inL[i] + inR[i]) * 0.015;
		for (let c = 0; c < 2; c++) {
			const s = sides[c];
			let acc = 0;
			for (const cb of s.combs) {
				const y = cb.buf[cb.i];
				cb.store = y * (1 - damp) + cb.store * damp;
				cb.buf[cb.i] = x + cb.store * fb;
				if (++cb.i >= cb.buf.length) cb.i = 0;
				acc += y;
			}
			for (const ap of s.aps) {
				const b = ap.buf[ap.i];
				ap.buf[ap.i] = acc + b * 0.5;
				if (++ap.i >= ap.buf.length) ap.i = 0;
				acc = b - acc;
			}
			out[c][i] = acc * 3;
		}
	}
	return out;
}

// --- Master -----------------------------------------------------------------------

// Integrated loudness, ITU-R BS.1770-4: K-weighting, 400 ms blocks every
// 100 ms, absolute gate at -70 LUFS and relative gate at -10 LU.
function lufs(L, R) {
	const kw = (x) => {
		const y = new Float64Array(N);
		const st = [
			[1.53512485958697, -2.69169618940638, 1.19839281085285, -1.69065929318241, 0.73248077421585],
			[1, -2, 1, -1.99004745483398, 0.99007225036621],
		];
		let src = x;
		for (const [b0, b1, b2, a1, a2] of st) {
			let x1 = 0;
			let x2 = 0;
			let y1 = 0;
			let y2 = 0;
			for (let i = 0; i < N; i++) {
				const v = b0 * src[i] + b1 * x1 + b2 * x2 - a1 * y1 - a2 * y2;
				x2 = x1;
				x1 = src[i];
				y2 = y1;
				y1 = v;
				y[i] = v;
			}
			src = Float64Array.from(y);
		}
		return src;
	};
	const kl = kw(L);
	const kr = kw(R);
	const block = 0.4 * SR;
	const hop = 0.1 * SR;
	const z = [];
	for (let s = 0; s + block <= N; s += hop) {
		let sum = 0;
		for (let i = s; i < s + block; i++) sum += kl[i] * kl[i] + kr[i] * kr[i];
		z.push(sum / block);
	}
	const loud = (v) => -0.691 + 10 * Math.log10(v);
	const abs = z.filter((v) => loud(v) > -70);
	const rel = loud(abs.reduce((a, b) => a + b, 0) / abs.length) - 10;
	const gated = abs.filter((v) => loud(v) > rel);
	return loud(gated.reduce((a, b) => a + b, 0) / gated.length);
}

// Per-sample peak including inter-sample peaks, estimated at 1/4, 1/2 and
// 3/4 between samples with a 16-tap Hann-windowed sinc.
function truePeaks(L, R) {
	const taps = 8;
	const fr = [0.25, 0.5, 0.75].map((f) => {
		const h = [];
		for (let k = -taps + 1; k <= taps; k++) {
			const x = k - f;
			const w = 0.5 + 0.5 * Math.cos((Math.PI * x) / taps);
			h.push(x === 0 ? 1 : (Math.sin(Math.PI * x) / (Math.PI * x)) * w);
		}
		return h;
	});
	const out = new Float32Array(N);
	for (const x of [L, R]) {
		for (let i = 0; i < N; i++) {
			let m = Math.abs(x[i]);
			if (i >= taps && i < N - taps - 1) {
				for (const h of fr) {
					let v = 0;
					for (let k = 0; k < h.length; k++) v += h[k] * x[i - taps + 1 + k];
					if (Math.abs(v) > m) m = Math.abs(v);
				}
			}
			if (m > out[i]) out[i] = m;
		}
	}
	return out;
}

// Look-ahead limiter: the gain needed at each sample, a 5 ms running minimum
// ahead of it, a 5 ms average so the gain ramps instead of stepping, and a
// 120 ms release. The average of minima never exceeds what a peak needs.
function limit(L, R, ceiling) {
	const la = Math.round(0.005 * SR);
	const peaks = truePeaks(L, R);
	const need = new Float32Array(N);
	for (let i = 0; i < N; i++) need[i] = peaks[i] > ceiling ? ceiling / peaks[i] : 1;
	const mins = new Float32Array(N);
	const dq = new Int32Array(N);
	let h = 0;
	let tl = 0;
	for (let i = N - 1; i >= 0; i--) {
		while (tl > h && need[dq[tl - 1]] >= need[i]) tl--;
		dq[tl++] = i;
		while (dq[h] > i + la - 1) h++;
		mins[i] = need[dq[h]];
	}
	const rel = Math.exp(-1 / (0.12 * SR));
	let sum = la; // the window starts on gain 1
	let g = 1;
	for (let i = 0; i < N; i++) {
		sum += mins[i] - (i >= la ? mins[i - la] : 1);
		const s = sum / la;
		g = s < g ? s : rel * g + (1 - rel) * s;
		L[i] *= g;
		R[i] *= g;
	}
}

// --- Render -----------------------------------------------------------------------

const started = performance.now();

const kickBus = stereo();
const drums = stereo();
const bass = stereo();
const pad = stereo();
const arp = stereo();
const music = stereo(); // bed one-shots: risers, stabs, the roll, the hold swell
const bedSend = stereo();
const post = stereo(); // cues outside the bed: they skip the tape stop and the bed filter
const postSend = stereo();
const kicks = [];

const arpCut = automation(ARP_CUT);
const ARP_GROOVE = [0, null, 2, 1, null, 3, 0, null, 2, null, 4, 3, null, 2, 1, null];
const ARP_PULSE = [0, 2, 1, 2, 0, 3, 1, 2];
const BASS_ROLL = [null, 0, 0, 12];
const BASS_DARK = [null, null, 0, 0, null, null, 0, 0, null, null, 0, 12, null, 0, 7, 0];
const tone = (chord, i) => (i < 4 ? chord.pad[i] + 12 : chord.pad[i - 4] + 24);
const jitter = () => 0.9 + 0.2 * rand();

ARRANGEMENT.forEach((row, b0) => {
	const bar = b0 + 1;
	const chord = row.chord && CHORDS[row.chord];
	if (row.kick) {
		for (let beat = 1; beat <= 4; beat++) {
			const t = at(bar, beat);
			if (muted('kick', t)) continue;
			const full = row.kick === 'full';
			kick(kickBus, t, full ? LEVEL.kick : LEVEL.kick * 0.35, !full);
			kicks.push([t, full ? 1 : 0.3]);
		}
	}
	if (row.clap) for (const beat of [2, 4]) clap(drums, bedSend, at(bar, beat), LEVEL.clap);
	if (row.rim) for (const s of [3, 6, 11, 14]) rim(drums, at(bar, 1, s), LEVEL.rim * jitter(), 0.35);
	if (row.hats) {
		for (let s = 0; s < 16; s++) {
			const t = at(bar, 1, s);
			const q = s % 4;
			const p = q % 2 ? 0.25 : -0.15;
			const v = LEVEL.hat * jitter();
			if (row.hats === 'soft') hat(drums, t, v * [0.45, 0.2, 0.35, 0.2][q] * (bar === 5 ? 1.3 : 1), false, p);
			else if (row.hats === 'air') hat(drums, t, v * [0.3, 0.12, 0.22, 0.12][q] * (bar >= 24 ? 1.4 : 1), false, p);
			else if (q === 2) hat(drums, t, v * (row.hats === 'end' ? 0.5 : 0.65), true, 0.1);
			else if (row.hats === 'roll') {
				const u = (t - CUES.build) / (2 * BAR);
				hat(drums, t, v * [0.6, 0.35, 0, 0.45][q] * (0.5 + 1.3 * u), false, p);
			} else if (row.hats === 'end' && q !== 0) continue;
			else hat(drums, t, v * [0.6, 0.3, 0, 0.4][q], false, p);
		}
	}
	if (row.bass) {
		for (let s = 0; s < 16; s++) {
			const off = row.bass === 'dark' ? BASS_DARK[s] : BASS_ROLL[s % 4];
			const t = at(bar, 1, s);
			if (off === null || muted('bass', t)) continue;
			if (row.bass === 'dark') {
				bassNote(bass, t, (BEAT / 4) * 0.75, chord.root + off, LEVEL.bass * 0.95, {cut: 120, env: 950, k: 0.35, drive: 2.2});
			} else {
				const vel = [0, 0.75, 1, 0.8][s % 4] * (row.bass === 'end' ? 0.8 : 1);
				bassNote(bass, t, (BEAT / 4) * 0.75, chord.root + off, LEVEL.bass * vel);
			}
		}
	}
	if (row.arp === 'pulse') {
		ARP_PULSE.forEach((i, s) => {
			const t = at(bar, 1, 2 * s);
			pluck(arp, t, tone(chord, i), LEVEL.arp * (s % 2 ? 0.5 : 0.75) * jitter(), {cut: arpCut[idx(t)], decay: 0.2, p: s % 2 ? 0.2 : -0.2});
		});
	} else if (row.arp === 'groove' || row.arp === 'filtered') {
		ARP_GROOVE.forEach((i, s) => {
			if (i === null) return;
			const t = at(bar, 1, s);
			pluck(arp, t, tone(chord, i), LEVEL.arp * (s % 2 ? 0.55 : 0.8) * jitter(), {cut: arpCut[idx(t)], p: s % 2 ? 0.25 : -0.25});
		});
	} else if (row.arp === 'rise') {
		// A burst of sends counting up: one scale step per beat.
		for (let beat = 1; beat <= 4; beat++) {
			const k = Math.round((at(bar) - CUES.build) / BAR) * 4 + beat - 1;
			[0, 0, 12, 0].forEach((o, s) => {
				const t = at(bar, beat, s);
				pluck(arp, t, SCALE[k] + o, LEVEL.arp * (0.45 + (0.5 * k) / 7) * (s ? 0.8 : 1), {cut: 1500 + (3500 * k) / 7, decay: 0.12, p: s % 2 ? 0.3 : -0.3});
			});
		}
	}
	if (row.lead) {
		ARP_GROOVE.forEach((i, s) => {
			if (i === null) return;
			const t = at(bar, 1, s);
			pluck(arp, t, tone(chord, i) + 12, LEVEL.lead * (s % 2 ? 0.6 : 0.9), {cut: 2400, decay: 0.2, square: true, p: s % 2 ? -0.4 : 0.4, detune: 9});
		});
	}
});

// Pad: one note per run of bars on the same chord.
const runs = [];
ARRANGEMENT.forEach((row, b0) => {
	const last = runs[runs.length - 1];
	if (!row.chord) return;
	if (last && last.chord === row.chord && last.end === b0 + 1) last.end++;
	else runs.push({chord: row.chord, start: b0 + 1, end: b0 + 2});
});
for (const r of runs) {
	const t0 = at(r.start);
	const sus = at(r.end) - t0;
	const intro = r.start <= 5;
	const release = r.end === 32 ? 0.12 : 0.6;
	const env = padEnv(sus, intro ? 1.2 : 0.12, release);
	for (const m of CHORDS[r.chord].pad) supersaw(pad, idx(t0), Math.round((sus + release) * SR), m, 1 / 2, env);
}

// Intro sub, a pedal F under bars 1–5 (the tape stop takes it down too).
drone(music, 0, CUES.tapeStop + 0.4, 29, 0.16, at(2), 0.05);

// Cues.
riser(music, bedSend, CUES.riser, CUES.tapeStop + 0.3, 0.2, {f0: 300, f1: 2600, q: 2.5, sendAmt: 0.25});
drone(post, CUES.drone - 0.25, CUES.logo, 29, 0.035, 0.5, 0.02);
reverseCymbal(post, postSend, CUES.reverse, CUES.logo, 0.55);
boom(post, CUES.logo, 0.85);
crash(post, postSend, CUES.logo, 0.5);
chordShot(post, postSend, CUES.logo, LOGO_CHORD, 0.5, {decay: 0.9, cut: (t) => 900 + 5000 * Math.exp(-t / 0.35), sendAmt: 0.5, length: 3});
ratchet(post, CUES.logo, 0.8);
ratchet(post, CUES.click, 0.8);
CUES.actions.forEach((t, j) => stab(music, bedSend, t, STABS[j], 0.6 + 0.06 * j));
riser(music, bedSend, CUES.throttle - BAR, CUES.throttle, 0.25, {f0: 500, f1: 5000, q: 2, sendAmt: 0.2});
for (let beat = 0; beat < 4; beat++) tick(post, CUES.throttle + beat * BEAT, 0.3);
CUES.complaints.forEach((t, j) => blip(post, postSend, t, 0.45, j % 2 ? 0.3 : -0.3));
chordShot(music, bedSend, CUES.hold, HOLD_CHORD, 0.45, {attack: 0.7, hold: 0.3, decay: 0.7, cut: (t) => 700 * Math.pow(5, Math.min(1, t / 1.1)), sendAmt: 0.5, length: 4});
thunk(post, CUES.block, 0.7);
whoosh(post, postSend, CUES.webhook, 0.8);
riser(music, bedSend, CUES.roll, CUES.gap, 0.28, {f0: 300, f1: 4500, q: 3, sendAmt: 0.3});
// The roll: 8ths through bar 24, 16ths, then 32nds up to the gap.
const roll = [];
for (let s = 0; s < 8; s++) roll.push(CUES.roll + (s * BEAT) / 2);
for (let s = 0; s < 8; s++) roll.push(CUES.roll + BAR + (s * BEAT) / 4);
for (let s = 0; CUES.roll + BAR + 2 * BEAT + (s * BEAT) / 8 < CUES.gap - 1e-6; s++) roll.push(CUES.roll + BAR + 2 * BEAT + (s * BEAT) / 8);
roll.forEach((t, j) => {
	const u = j / (roll.length - 1);
	snare(music, bedSend, t, 0.12 + 0.4 * u * u, 0.12 - 0.07 * u, 0.3);
});
boom(post, CUES.drop, 0.6);
crash(post, postSend, CUES.drop, 0.55);
chordShot(post, postSend, CUES.final, FINAL_CHORD, 0.6, {decay: 1.1, cut: (t) => 900 + 4500 * Math.exp(-t / 0.6), sendAmt: 0.6, length: CUES.silence - CUES.final});
boom(post, CUES.final, 0.5, {tau: 1});
ratchet(post, CUES.final, 0.8);

// --- Mix --------------------------------------------------------------------------

const busRms = {};
const rms = (bus, t0, t1) => {
	let s = 0;
	for (let i = idx(t0); i < idx(t1); i++) s += bus[0][i] * bus[0][i] + bus[1][i] * bus[1][i];
	return 10 * Math.log10(s / (2 * (idx(t1) - idx(t0))) + 1e-20);
};

pingPong(arp, 0.75 * BEAT, 0.35, 0.3);

const padCut = automation(PAD_CUT);
const padGain = automation(PAD_GAIN, true);
for (let i = 0; i < N; i++) padCut[i] *= 1 + 0.18 * Math.sin((TAU * 0.11 * i) / SR);
lowpassBus(pad, padCut, 0.9);

const dPad = duck(kicks, 0.55);
const dBass = duck(kicks, 0.8);
const dArp = duck(kicks, 0.35);
for (const [name, bus] of Object.entries({kick: kickBus, drums, bass, arp, music})) busRms[name] = rms(bus, at(9), at(13));

// The bed (everything the tape stop and the bed filter act on) goes into
// `drums`; its reverb send into `bedSend`.
const bed = drums;
for (let c = 0; c < 2; c++) {
	for (let i = 0; i < N; i++) {
		const p = pad[c][i] * padGain[i] * LEVEL.pad * dPad[i];
		const a = arp[c][i] * dArp[i];
		bed[c][i] += kickBus[c][i] + bass[c][i] * dBass[i] + p + a + music[c][i];
		bedSend[c][i] += p * 0.3 + a * 0.18;
	}
}
busRms.pad = rms([pad[0].map((v, i) => v * padGain[i] * LEVEL.pad), pad[1].map((v, i) => v * padGain[i] * LEVEL.pad)], at(9), at(13));

const bedCut = automation(BED_CUT);
lowpassBus(bed, bedCut, 1.1);
lowpassBus(bedSend, bedCut, 1.1);
tapeStop(bed, CUES.tapeStop, CUES.tapeStopLength, CUES.logo);
tapeStop(bedSend, CUES.tapeStop, CUES.tapeStopLength, CUES.logo);

// Reverb: 20 ms predelay, nothing under 200 Hz or over 7 kHz going in.
const revIn = stereo();
const pre = Math.round(0.02 * SR);
for (let c = 0; c < 2; c++) {
	const hp = new SVF();
	const lp = new SVF();
	const gh = tanG(200);
	const gl = tanG(7000);
	for (let i = 0; i < N; i++) {
		const x = i >= pre ? bedSend[c][i - pre] + postSend[c][i - pre] : 0;
		hp.tick(x, gh, 1.4);
		revIn[c][i] = lp.tick(hp.high, gl, 1.4);
	}
}
const wet = freeverb(revIn[0], revIn[1], 0.84, 0.4);

const L = new Float32Array(N);
const R = new Float32Array(N);
for (let i = 0; i < N; i++) {
	L[i] = bed[0][i] + post[0][i] + wet[0][i] * LEVEL.reverb;
	R[i] = bed[1][i] + post[1][i] + wet[1][i] * LEVEL.reverb;
}
busRms.reverb = rms(wet, at(9), at(13));

// Mono under 140 Hz, and no DC.
{
	const hs = new SVF();
	const g = tanG(140);
	const dcA = 1 - (TAU * 18) / SR;
	let xl = 0;
	let yl = 0;
	let xr = 0;
	let yr = 0;
	for (let i = 0; i < N; i++) {
		const m = (L[i] + R[i]) * 0.5;
		hs.tick((L[i] - R[i]) * 0.5, g, 1.4);
		const l = m + hs.high;
		const r = m - hs.high;
		yl = l - xl + dcA * yl;
		xl = l;
		yr = r - xr + dcA * yr;
		xr = r;
		L[i] = yl;
		R[i] = yr;
	}
}

for (let i = 0; i < N; i++) if (!Number.isFinite(L[i]) || !Number.isFinite(R[i])) throw new Error(`not a number at sample ${i}`);

// Glue: bring it to -20 LUFS, 2:1 over -21 dBFS RMS with a soft knee, 10 ms
// attack and 150 ms release, then a soft saturation on the peaks.
{
	const g0 = db(-20 - lufs(L, R));
	const thr = -21;
	const ratio = 2;
	const knee = 6;
	const aA = Math.exp(-1 / (0.01 * SR));
	const aR = Math.exp(-1 / (0.15 * SR));
	const aRms = Math.exp(-1 / (0.005 * SR));
	let ms = 0;
	let gr = 0;
	for (let i = 0; i < N; i++) {
		const l = L[i] * g0;
		const r = R[i] * g0;
		ms = aRms * ms + (1 - aRms) * Math.max(l * l, r * r);
		const over = 10 * Math.log10(ms + 1e-12) - thr;
		let want = 0;
		if (2 * over > knee) want = over * (1 - 1 / ratio);
		else if (2 * over > -knee) want = ((1 - 1 / ratio) * (over + knee / 2) ** 2) / (2 * knee);
		gr = want > gr ? aA * gr + (1 - aA) * want : aR * gr + (1 - aR) * want;
		const g = db(-gr);
		L[i] = Math.tanh(1.2 * l * g) / 1.2;
		R[i] = Math.tanh(1.2 * r * g) / 1.2;
	}
}

// Loudness: gain, limit, measure, correct; the limiter takes a little
// loudness away, so a few rounds.
const ceiling = db(CEILING);
let gain = db(TARGET_LUFS - lufs(L, R));
let outL;
let outR;
let loud;
for (let round = 0; round < 4; round++) {
	outL = L.map((v) => v * gain);
	outR = R.map((v) => v * gain);
	limit(outL, outR, ceiling);
	loud = lufs(outL, outR);
	if (Math.abs(loud - TARGET_LUFS) < 0.1) break;
	gain *= db(TARGET_LUFS - loud);
}

// The gap before drop 2, and the end: true silence.
{
	const g0 = idx(CUES.gap);
	const g1 = idx(CUES.drop);
	const f = Math.round(0.004 * SR);
	const s0 = idx(CUES.silence - 1.1);
	const s1 = idx(CUES.silence);
	for (let i = g0; i < g1; i++) {
		const v = i < g0 + f ? 1 - (i - g0) / f : i >= g1 - 96 ? (i - (g1 - 96)) / 96 : 0;
		outL[i] *= v;
		outR[i] *= v;
	}
	for (let i = s0; i < N; i++) {
		const v = i < s1 ? 0.5 + 0.5 * Math.cos((Math.PI * (i - s0)) / (s1 - s0)) : 0;
		outL[i] *= v;
		outR[i] *= v;
	}
}

// --- Write --------------------------------------------------------------------------

// 16-bit PCM with TPDF dither; digital silence stays silent.
function writeWav(file, l, r) {
	const buf = Buffer.alloc(44 + N * 4);
	buf.write('RIFF', 0, 'ascii');
	buf.writeUInt32LE(36 + N * 4, 4);
	buf.write('WAVEfmt ', 8, 'ascii');
	buf.writeUInt32LE(16, 16);
	buf.writeUInt16LE(1, 20);
	buf.writeUInt16LE(2, 22);
	buf.writeUInt32LE(SR, 24);
	buf.writeUInt32LE(SR * 4, 28);
	buf.writeUInt16LE(4, 32);
	buf.writeUInt16LE(16, 34);
	buf.write('data', 36, 'ascii');
	buf.writeUInt32LE(N * 4, 40);
	const q = (v) => (v === 0 ? 0 : Math.max(-32768, Math.min(32767, Math.round(v * 32767 + rand() - rand()))));
	for (let i = 0; i < N; i++) {
		buf.writeInt16LE(q(l[i]), 44 + i * 4);
		buf.writeInt16LE(q(r[i]), 46 + i * 4);
	}
	mkdirSync(path.dirname(file), {recursive: true});
	writeFileSync(file, buf);
}

writeWav(OUT, outL, outR);

const tp = truePeaks(outL, outR).reduce((m, v) => Math.max(m, v), 0);
console.log(`wrote ${path.relative(root, OUT)}: ${LENGTH} s, ${SR} Hz, stereo, 16-bit`);
console.log(`  loudness ${loud.toFixed(1)} LUFS, true peak ${(20 * Math.log10(tp)).toFixed(2)} dBTP (estimate)`);
console.log(`  bus RMS, bars 9-12: ${Object.entries(busRms).map(([k, v]) => `${k} ${v.toFixed(1)}`).join(', ')} dBFS`);
console.log(`  ${((performance.now() - started) / 1000).toFixed(1)} s`);
