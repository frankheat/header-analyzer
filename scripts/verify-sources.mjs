// Fetches every document cited in src/core/sources.js and checks that each
// quoted passage is still there, word for word: the passages a text fragment
// highlights, and the line ranges code citations point at.
//
//   npm run verify-sources            check every citation
//   npm run verify-sources -- cs-     only ids starting with "cs-"
//
// Needs network access; it is not part of `npm test`. A few sites refuse
// non-browser clients: those are reported as unreachable, to check by hand.
import { loadSources } from './sources.mjs';

const sources = loadSources();
const { DOCS, CITES, SPLIT_ABOVE } = sources.raw;
const filter = process.argv[2] || '';

/** Raw text of a GitHub blob (markdown or code) instead of its rendered page. */
function rawUrl(url) {
  const m = url.match(/^https:\/\/github\.com\/([^/]+)\/([^/]+)\/blob\/(.+)$/);
  return m ? `https://raw.githubusercontent.com/${m[1]}/${m[2]}/${m[3]}` : url;
}

const BLOCK_TAG = /<\/?(p|div|li|ul|ol|dl|dt|dd|tr|td|th|table|h[1-6]|pre|section|article|header|footer|blockquote|br|summary|details|figure|figcaption)\b[^>]*>/gi;

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', rsquo: '’', lsquo: '‘', ldquo: '“', rdquo: '”', ndash: '–', mdash: '\u2014', hellip: '…', para: '¶' };

/** The visible text of a page, close enough to what a text fragment searches. */
function pageText(body, isHtml) {
  let t = body;
  if (isHtml) {
    // Block elements separate words; inline ones (a, code, span…) do not.
    t = t.replace(/<(script|style|noscript|template|svg)\b[\s\S]*?<\/\1>/gi, ' ')
      .replace(BLOCK_TAG, ' ')
      .replace(/<[^>]+>/g, '')
      .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
      .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)))
      .replace(/&([a-z]+);/gi, (m, n) => ENTITIES[n.toLowerCase()] ?? m);
  } else {
    // Markdown as GitHub renders it: no link targets, emphasis or code ticks.
    t = t.replace(/!\[[^\]]*\]\([^)]*\)/g, '').replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
      .replace(/\*\*|`/g, '').replace(/^#+\s*/gm, '').replace(/\|/g, ' ');
  }
  return t.replace(/\s+/g, ' ').toLowerCase();
}

const norm = (s) => s.replace(/\s+/g, ' ').trim().toLowerCase();

const cache = new Map();
/** `attempt` > 0 fetches again: some sites now and then serve a different variant. */
async function fetchText(url, attempt = 0) {
  const key = `${attempt} ${url}`;
  if (!cache.has(key)) {
    cache.set(key, fetch(url, { headers: { 'user-agent': 'Mozilla/5.0 (header-analyzer verify-sources)' }, redirect: 'follow' })
      .then(async (r) => (r.ok ? r.text() : Promise.reject(new Error(`HTTP ${r.status}`)))));
  }
  return cache.get(key);
}

const ATTEMPTS = 3;

let failed = 0;
let unreachable = 0;
let checked = 0;
for (const [id, [docId, quote]] of Object.entries(CITES)) {
  if (!id.startsWith(filter)) continue;
  const [, base] = DOCS[docId];
  const url = rawUrl(base);
  let problem = null;
  let reached = false;
  for (let attempt = 0; attempt < ATTEMPTS; attempt++) {
    let body;
    try {
      body = await fetchText(url, attempt);
    } catch (e) {
      problem = `could not be fetched (${e.message})`;
      continue;
    }
    reached = true;
    problem = check(quote, body, url === base);
    if (!problem) break;
  }
  if (!reached) {
    unreachable++;
    console.log(`?  ${id}: ${base} ${problem}; check it in a browser`);
    continue;
  }
  checked++;
  if (problem) {
    failed++;
    console.log(`✗  ${id}: ${problem}\n   ${sources.cite(id).url}`);
  }
}

/** Why `body` does not support `quote`, or null when it does. */
function check(quote, body, isHtml) {
  let problem = null;
  if (typeof quote === 'object' && quote.lines) {
    const [a, z] = quote.lines.slice(1).split('-L').map(Number);
    const chunk = body.split('\n').slice(a - 1, z).join('\n');
    const missing = quote.has.filter((h) => !chunk.includes(h));
    if (missing.length) problem = `lines ${quote.lines} no longer contain ${missing.join(' / ')}`;
  } else {
    const text = pageText(body, isHtml);
    if (typeof quote === 'object') {
      const i = text.indexOf(norm(quote.s));
      if (i === -1) problem = `start not found: "${quote.s}"`;
      else if (text.indexOf(norm(quote.e), i) === -1) problem = `end not found after start: "${quote.e}"`;
    } else if (!text.includes(norm(quote))) {
      problem = `passage not found: "${quote}"`;
    } else if (quote.split(/\s+/).length > SPLIT_ABOVE) {
      const words = quote.split(/\s+/);
      if (text.indexOf(norm(words.slice(0, 5).join(' '))) !== text.indexOf(norm(quote))) {
        problem = 'the first words of the passage occur earlier in the page, so the highlight would start there';
      }
    }
  }
  return problem;
}

console.log(`\n${checked} citations checked, ${failed} failed, ${unreachable} unreachable.`);
process.exit(failed ? 1 : 0);
