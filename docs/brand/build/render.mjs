// Optimize the SVGs written by build.py and render the PNG assets from them.
//   npm install && node render.mjs [--preview]
// Uses a headless Edge by default; set BROWSER_CHANNEL=chrome to use Chrome.
import { chromium } from 'playwright-core';
import { optimize } from 'svgo';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const brand = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// 1. Optimize every SVG except the favicon, whose media query must stay as written.
const svgs = ['.', 'logo']
  .flatMap((dir) => readdirSync(path.join(brand, dir)).filter((f) => f.endsWith('.svg')).map((f) => path.join(dir, f)))
  .filter((f) => f !== path.join('.', 'favicon.svg'));
for (const rel of svgs) {
  const file = path.join(brand, rel);
  const before = readFileSync(file, 'utf8');
  const { data } = optimize(before, {
    path: file,
    floatPrecision: 2,
    plugins: [{ name: 'preset-default', params: { overrides: { removeUnknownsAndDefaults: { keepRoleAttr: true } } } }],
  });
  writeFileSync(file, data + '\n');
  console.log(`${String(Buffer.byteLength(data)).padStart(7)}  ${rel}`);
}

// 2. Render the PNGs.
const jobs = [
  ['social-preview.svg', 'social-preview.png', 1280, 640],
  ['icon.svg', 'icon-512.png', 512, 512],
  ['icon.svg', 'icon-192.png', 192, 192],
];
if (process.argv.includes('--preview')) {
  // Not committed: full-size renders for checking the banners by eye.
  jobs.push(
    ['readme-banner-light.svg', 'build/.preview/readme-banner-light.png', 1600, 400],
    ['readme-banner-dark.svg', 'build/.preview/readme-banner-dark.png', 1600, 400],
  );
}
const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'msedge', headless: true });
for (const [src, out, w, h] of jobs) {
  const svg = readFileSync(path.join(brand, src), 'utf8');
  const page = await browser.newPage({ viewport: { width: w, height: h } });
  await page.setContent(
    `<!doctype html><style>html,body{margin:0;background:transparent}svg{display:block;width:${w}px;height:${h}px}</style>${svg}`,
  );
  await page.screenshot({ path: path.join(brand, out), omitBackground: true });
  await page.close();
  console.log(`rendered ${out}`);
}
await browser.close();
