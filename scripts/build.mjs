#!/usr/bin/env node
/*
 * Builds dist/header-analyzer.html: the whole app in one self-contained file that
 * opens by double-click, offline, in any modern browser.
 *
 * Stylesheet and scripts are inlined, the icon becomes a data: URI, and the
 * page's Content-Security-Policy pins the exact SHA-256 of each inline block
 * instead of allowing 'self', so nothing else can ever run in the page.
 * No dependencies: Node's standard library only.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => readFileSync(join(ROOT, p), 'utf8');
const sha256 = (s) => `'sha256-${createHash('sha256').update(s, 'utf8').digest('base64')}'`;

function fail(message) {
  console.error(`build: ${message}`);
  process.exit(1);
}

let html = read('index.html');
const pkg = JSON.parse(read('package.json'));

// Nothing in the code may close the element early or open an HTML comment.
const escapeJs = (s) => s.replace(/<\/(script)/gi, '<\\/$1').replace(/<!--/g, '<\\!--');
const SCRIPT_TAG = /[ \t]*<script src="([^"]+)"><\/script>\n?/g;

// The script in <head> (the theme, applied before the first paint) stays
// there as its own inline block.
const headEnd = html.indexOf('</head>');
const headTags = [...html.slice(0, headEnd).matchAll(SCRIPT_TAG)];
if (headTags.length !== 1) fail('expected exactly one <script src> in <head>');
const headJs = `\n${escapeJs(read(headTags[0][1]))}  `;
html = html.replace(headTags[0][0], () => `  <script>${headJs}</script>\n`);

// The body scripts, in page order, concatenated into one classic script.
const scriptTags = [...html.matchAll(SCRIPT_TAG)];
if (!scriptTags.length) fail('no <script src> found in the body of index.html');
const js = escapeJs(scriptTags.map(([, src]) => `/* ${src} */\n${read(src)}`).join('\n'));
if (!js.includes(`VERSION = '${pkg.version}'`)) fail(`engine VERSION does not match package.json (${pkg.version})`);

const css = read('assets/styles.css');
if (/<\/style/i.test(css)) fail('stylesheet contains </style');
const icon = 'data:image/svg+xml;base64,' + Buffer.from(read('assets/icon.svg')).toString('base64');

html = html.replace(/[ \t]*<script src="[^"]+"><\/script>\n?/g, '');
html = html.replace('</body>', () => `  <script>\n${js}\n  </script>\n</body>`);

const styleTag = '<link rel="stylesheet" href="assets/styles.css">';
if (!html.includes(styleTag)) fail('stylesheet link not found');
html = html.replace(styleTag, () => `<style>\n${css}\n</style>`);

const iconTag = '<link rel="icon" href="assets/icon.svg" type="image/svg+xml">';
if (!html.includes(iconTag)) fail('icon link not found');
html = html.replace(iconTag, () => `<link rel="icon" href="${icon}" type="image/svg+xml">`);

// Pin the inline blocks by hash. The hash covers the exact element content.
const inlineJs = `\n${js}\n  `;
const inlineCss = `\n${css}\n`;
const csp = [
  "default-src 'none'",
  `script-src ${sha256(headJs)} ${sha256(inlineJs)}`,
  `style-src ${sha256(inlineCss)}`,
  "img-src data:",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');
const cspMeta = /<meta http-equiv="Content-Security-Policy" content="[^"]+">/;
if (!cspMeta.test(html)) fail('CSP meta not found');
html = html.replace(cspMeta, () => `<meta http-equiv="Content-Security-Policy" content="${csp}">`);
html = html.replace(/\s*<!-- The app never talks to the network[\s\S]*?-->/, '\n  <!-- The app never talks to the network: everything it analyses stays in this tab. -->');

// Sanity: the hashes must describe what is actually in the file.
// Each script runs from its opening tag to the next </script>: the code holds
// only escaped "<\/script", so the first unescaped one ends the element.
const headBody = html.match(/<head>[\s\S]*?<script>([\s\S]*?)<\/script>/)[1];
const scriptBody = html.match(/<body>[\s\S]*?<script>([\s\S]*?)<\/script>/)[1];
const styleBody = html.match(/<style>([\s\S]*?)<\/style>/)[1];
if (headBody !== headJs || scriptBody !== inlineJs || styleBody !== inlineCss) fail('inline content does not match its hash');
if (/src="(?!data:)|href="(?!#|data:)/.test(html.replace(/<script>[\s\S]*?<\/script>/g, ''))) fail('a reference to an external file remains');

mkdirSync(join(ROOT, 'dist'), { recursive: true });
writeFileSync(join(ROOT, 'dist', 'header-analyzer.html'), html);
console.log(`build: dist/header-analyzer.html (${(Buffer.byteLength(html) / 1024).toFixed(1)} KB), Header Analyzer ${pkg.version}`);
