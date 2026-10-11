'use strict';
/* The public entry point: reports, exports, robustness, and the UI's safety rules. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { HL, ROOT, Severity: S } = require('./helpers');
const isContingentFinding = (f) => HL.models.isContingent(f);
require('node:vm').runInThisContext(fs.readFileSync(path.join(ROOT, 'src/ui/samples.js'), 'utf8'));

const { analyze, findingList } = HL.engine;

const CLEAN = [
  'HTTP/1.1 200 OK',
  "Content-Security-Policy: default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
  'Strict-Transport-Security: max-age=63072000; includeSubDomains',
  'X-Frame-Options: DENY',
  'X-Content-Type-Options: nosniff',
  'Cross-Origin-Opener-Policy: same-origin',
  'Referrer-Policy: no-referrer',
  'Cache-Control: no-store',
  'Permissions-Policy: attribution-reporting=(), browsing-topics=(), ch-ua-high-entropy-values=(), private-state-token-issuance=(), private-state-token-redemption=(), storage-access=(), camera=(), microphone=(), geolocation=()',
  // The rest of OWASP's recommended set (Secure Headers Project), each LOW when absent.
  'Cross-Origin-Embedder-Policy: require-corp',
  'Cross-Origin-Resource-Policy: same-origin',
  'X-Permitted-Cross-Domain-Policies: none',
  'Clear-Site-Data: "cache", "cookies", "storage"',
  'X-DNS-Prefetch-Control: off',
  '', '',
].join('\r\n');

test('empty and blank input report "empty"', () => {
  for (const t of ['', '   \n', null, undefined, 42]) assert.equal(analyze(t, 'basic').error, 'empty');
});

test('text with no header fields is a readable error, not an exception', () => {
  const r = analyze('hello world\nthis is not http', 'basic');
  assert.equal(r.ok, false);
  assert.match(r.error, /No HTTP header fields/);
});

test('a clean response under basic has no issue', () => {
  const r = analyze(CLEAN, 'basic');
  assert.ok(r.ok);
  const issues = r.results.flatMap((x) => x.findings).filter((f) => f.severity >= S.LOW);
  assert.deepEqual(issues.map((f) => f.title), []);
  assert.equal(r.results.length, 18);
});

test('summary separates settled from to-confirm and marks an unconfirmed top', () => {
  const text = CLEAN.replace('\r\n\r\n', '\r\nAccess-Control-Allow-Origin: https://a.example\r\nAccess-Control-Allow-Credentials: true\r\n\r\n');
  const r = analyze(text, 'basic');
  assert.equal(r.summary.worstName, 'LOW');
  assert.equal(r.summary.worstIsContingent, true);
  assert.equal(r.summary.toConfirm.LOW, 2);                    // the origin and the credentials
  assert.equal(r.summary.settled.LOW, 0);
});

test('the first response is analysed, after any 100 Continue', () => {
  const r = analyze('HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\n\r\nHTTP/1.1 200 OK\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n', 'basic');
  assert.equal(r.status.code, 200);
  assert.equal(r.results.find((x) => x.key === 'x-frame-options').value, 'DENY');
  assert.equal(r.responses, undefined);
});

test('the profile id is validated', () => {
  assert.equal(analyze(CLEAN, 'nonsense').profile.id, 'basic');
  assert.equal(analyze(CLEAN, 'extended').profile.id, 'extended');
});

// ------------------------------------------------------------- robustness
function rng(seed) {
  let s = seed >>> 0;
  return () => { s ^= s << 13; s ^= s >>> 17; s ^= s << 5; return (s >>> 0) / 4294967296; };
}

test('fuzz: no input makes the engine throw or report an internal error', () => {
  const rand = rng(0xC0FFEE);
  const alphabet = ' \t\r\n:;,="\'()*?-_./\\@%:#abcHTPXSOs0123456789é‘�\u0000{}[]<>|';
  const names = ['Content-Security-Policy', 'Strict-Transport-Security', 'Permissions-Policy', 'Cross-Origin-Opener-Policy',
    'Cross-Origin-Embedder-Policy', 'X-Frame-Options', 'Cache-Control', 'Clear-Site-Data', 'Referrer-Policy', 'Origin-Agent-Cluster',
    'Access-Control-Allow-Origin', 'Access-Control-Allow-Credentials', 'X-Content-Type-Options', 'Server', 'X-XSS-Protection'];
  const piece = (n) => Array.from({ length: n }, () => alphabet[Math.floor(rand() * alphabet.length)]).join('');
  for (let i = 0; i < 3000; i++) {
    const lines = ['HTTP/1.1 200 OK'];
    const count = 1 + Math.floor(rand() * 6);
    for (let k = 0; k < count; k++) lines.push(`${names[Math.floor(rand() * names.length)]}: ${piece(Math.floor(rand() * 60))}`);
    const text = rand() < 0.1 ? piece(200) : lines.join(rand() < 0.5 ? '\r\n' : '\n') + '\r\n\r\n';
    for (const p of ['basic', 'extended']) {
      const r = analyze(text, p);
      assert.notEqual(r.error, 'internal', `${JSON.stringify(text)}\n${r.detail}`);
      if (r.ok) {
        for (const res of r.results) {
          for (const f of res.findings) {
            // HIGH is the top of the scale, reserved for CORS null + credentials (RULES.md).
            assert.ok(f.severity <= S.HIGH, `${f.title}\n${JSON.stringify(text)}`);
            if (f.severity === S.HIGH) assert.ok(f.title.includes('null with credentials'), f.title);
          }
        }
        findingList(r);
        findingList(r, { show: 'confirmed' });
        findingList(r, { show: 'toConfirm' });
      }
    }
  }
});

test('large input stays fast', () => {
  const big = 'HTTP/1.1 200 OK\r\n' + `Content-Security-Policy: script-src ${'https://a.example '.repeat(20000)}\r\n`
    + 'X-Filler: x\r\n'.repeat(20000) + '\r\n';
  const t = Date.now();
  assert.ok(analyze(big, 'extended').ok);
  assert.ok(Date.now() - t < 3000, `${Date.now() - t} ms`);
});

// --------------------------------------------------------------- UI safety
test('the interface never injects HTML or evaluates strings', () => {
  for (const file of fs.readdirSync(path.join(ROOT, 'src', 'ui'))) {
    const src = fs.readFileSync(path.join(ROOT, 'src', 'ui', file), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');   // code only, not comments
    for (const sink of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'srcdoc']) {
      assert.ok(!src.includes(sink), `${file} uses ${sink}`);
    }
  }
});

test('the interface never makes a network request', () => {
  for (const file of fs.readdirSync(path.join(ROOT, 'src'), { recursive: true })) {
    if (!file.endsWith('.js')) continue;
    const src = fs.readFileSync(path.join(ROOT, 'src', file), 'utf8');
    for (const api of ['fetch(', 'XMLHttpRequest', 'WebSocket', 'sendBeacon', 'EventSource', 'importScripts', 'FileReader', '.text()', 'createObjectURL', 'type="file"']) {
      assert.ok(!src.includes(api), `${file} uses ${api}`);
    }
  }
});

test('the scale is HIGH, MEDIUM, LOW and OK', () => {
  assert.deepEqual(Object.keys(S), ['OK', 'LOW', 'MEDIUM', 'HIGH']);
  assert.deepEqual([...HL.models.SEVERITY_NAMES], ['OK', 'LOW', 'MEDIUM', 'HIGH']);
});

test('the page CSP forbids connections and inline script', () => {
  const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
  const csp = html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)[1];
  assert.ok(csp.includes("default-src 'none'"));
  assert.ok(!csp.includes('unsafe-inline') && !csp.includes('unsafe-eval'));
  assert.ok(!/connect-src/.test(csp));
  assert.ok(!/<script>[^<]/.test(html), 'inline script in index.html');
  assert.ok(!/ on[a-z]+="/.test(html), 'inline event handler in index.html');
  assert.ok(!html.includes('type="file"'), 'the page must not open files');
});

// ------------------------------------------------------------ findings list
const { Status } = HL.models;
const STATUSES = new Set(['Missing', 'Misconfigured', 'Duplicated', 'Deprecated']);
const LINE = /^([A-Za-z0-9-]+): (Missing|Misconfigured|Duplicated|Deprecated)\. (.+)\.$/;

function everyFindingEverywhere() {
  const out = [];
  const texts = HL.samples ? HL.samples.map((s) => s.text) : [];
  const extra = [
    'HTTP/1.1 200 OK\r\nX-Nothing: x\r\n\r\n',
    'HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=1\r\nStrict-Transport-Security: max-age=2\r\nX-Frame-Options:\r\nExpect-CT: max-age=1\r\n\r\n',
    "HTTP/1.1 200 OK\r\nContent-Security-Policy: script-src * 'unsafe-inline' 'unsafe-eval' data: blob: http://a.example *.com *.github.io https://*.googleapis.com unpkg.com 'nonce-short' 'unsafe-hashes' self; script-src x; style-src 'unsafe-inline'; object-src 'self'; base-uri *; frame-ancestors *; default-src *; form-action *; scirpt-src x; referrer x; img-src 'none' x 'bogus'\r\n\r\n",
  ];
  for (const text of [...texts, ...extra]) {
    for (const p of ['basic', 'extended']) {
      const r = analyze(text, p);
      if (r.ok) for (const res of r.results) for (const f of res.findings) out.push([res.name, f]);
    }
  }
  return out;
}

test('every finding that is not OK has a list status and, unless unlisted, a brief', () => {
  for (const [header, f] of everyFindingEverywhere()) {
    if (f.severity === S.OK) continue;
    assert.ok(f.status === Status.NONE || STATUSES.has(f.status), `${header}: ${f.title} → ${f.status}`);
    if (f.status === Status.NONE) continue;
    assert.ok(f.brief, `${header}: ${f.title} has no brief`);
    assert.ok(!f.brief.endsWith('.'), `brief ends with a period: ${f.brief}`);
    assert.ok(f.brief.length <= 72, `brief too long (${f.brief.length}): ${f.brief}`);
  }
});

test('every list line has the exact form "<Header>: <status>. <brief>."', () => {
  for (const s of HL.samples || []) {
    for (const o of [{}, { show: 'confirmed' }, { show: 'toConfirm' }]) {
      for (const l of HL.engine.findingList(analyze(s.text, 'extended'), o)) {
        assert.match(l.text, LINE);
        assert.equal(l.text, `${l.header}: ${l.status}. ${l.brief}.`);
      }
    }
  }
});

test('the list: statuses, ordering, options, one line per header', () => {
  const text = 'HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=1\r\nStrict-Transport-Security: max-age=2\r\nX-XSS-Protection: 1\r\nExpect-CT: max-age=1\r\nCache-Control: max-age=600\r\n\r\n';
  const r = analyze(text, 'extended');
  const list = HL.engine.findingList(r);
  const texts = list.map((l) => l.text);
  assert.ok(texts.includes('Content-Security-Policy: Missing. No defence in depth against XSS.'));
  assert.ok(texts.includes('Strict-Transport-Security: Misconfigured. max-age=1 is below the 2-year minimum; includeSubDomains is not set; preload is not set (to confirm); and 1 more.'));
  assert.ok(texts.includes('X-XSS-Protection: Deprecated. Enables the obsolete XSS filter.'));
  assert.ok(texts.includes('Expect-CT: Deprecated. Obsolete, ignored by browsers.'));
  assert.ok(texts.includes('Cache-Control: Misconfigured. Shared caches may store the response (to confirm).'));
  assert.ok(!texts.some((t) => t.startsWith('ETag:')));                            // absent ETag is correct: never listed
  assert.ok(texts.includes('Origin-Agent-Cluster: Missing. Origin keying is not requested.'));
  assert.ok(!HL.engine.findingList(r, { show: 'confirmed' }).some((l) => l.items.some((it) => it.toConfirm)));
  const pending = HL.engine.findingList(r, { show: 'toConfirm' });
  assert.ok(pending.length && pending.every((l) => l.toConfirm && l.items.every((it) => it.toConfirm)));
  // Every header listed under All appears under Confirmed, To confirm, or both.
  const split = new Set([...HL.engine.findingList(r, { show: 'confirmed' }), ...pending].map((l) => l.header));
  assert.deepEqual(new Set(list.map((l) => l.header)), split);
  assert.throws(() => HL.engine.findingList(r, { show: 'bogus' }));
  assert.equal(new Set(texts).size, texts.length);
  const ranks = list.map((l) => S[l.severity]);
  assert.deepEqual(ranks, [...ranks].sort((a, b) => b - a));
});

test('empty is Misconfigured, absent is Missing, facts are never listed', () => {
  const r = analyze("HTTP/1.1 200 OK\r\nX-Frame-Options:\r\nContent-Security-Policy: script-src 'nonce-abcdefghijklmnopqrstuvwx' 'strict-dynamic' https: 'unsafe-inline'\r\n\r\n", 'basic');
  const texts = HL.engine.findingList(r).map((l) => l.text);
  assert.ok(texts.includes('X-Frame-Options: Misconfigured. Empty value, so browsers ignore the header.'));
  assert.ok(texts.includes('Referrer-Policy: Missing. Referrer leakage depends on browser defaults.'));
  assert.ok(!texts.some((t) => t.includes('fallback') || t.includes('allowlist entries')));
});

test('the list for a single misconfiguration', () => {
  const r = analyze(CLEAN.replace('X-Frame-Options: DENY', 'X-Frame-Options: SAMEORIGIN'), 'basic');
  assert.deepEqual(findingList(r).map((l) => l.text), ['X-Frame-Options: Misconfigured. SAMEORIGIN instead of DENY (to confirm).']);
});

test('every header appears at most once, whatever the options', () => {
  const texts = [...(HL.samples || []).map((x) => x.text),
    "HTTP/1.1 200 OK\r\nContent-Security-Policy: script-src * 'unsafe-inline' 'unsafe-eval' data:; object-src 'self'; base-uri *\r\nContent-Security-Policy: default-src *\r\n\r\n"];
  for (const t of texts) {
    for (const p of ['basic', 'extended']) {
      for (const o of [{}, { show: 'confirmed' }, { show: 'toConfirm' }]) {
        const headers = HL.engine.findingList(analyze(t, p), o).map((l) => l.header);
        assert.equal(new Set(headers).size, headers.length, headers.join(', '));
      }
    }
  }
});

test('a merged line: status of the most severe problem, briefs joined, the rest counted', () => {
  const r = analyze("HTTP/1.1 200 OK\r\nContent-Security-Policy: script-src * 'unsafe-inline' 'unsafe-eval' data:; object-src 'self'; base-uri *\r\n\r\n", 'basic');
  const csp = HL.engine.findingList(r).find((l) => l.header === 'Content-Security-Policy');
  assert.equal(csp.status, 'Misconfigured');
  assert.equal(csp.severity, 'MEDIUM');
  assert.ok(csp.brief.startsWith("'unsafe-inline' allowed for scripts in script-src; "));   // MEDIUMs keep report order
  assert.ok(csp.items.every((it, k) => k === 0 || S[it.severity] <= S[csp.items[k - 1].severity]));
  assert.match(csp.brief, /; and \d+ more$/);
  assert.equal(csp.brief.split('; ').length, 4);                   // three briefs + "and N more"
  assert.ok(csp.items.length > 3);
  assert.equal(csp.items[0].severity, 'MEDIUM');

  const dup = HL.engine.findingList(analyze('HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\nX-Content-Type-Options: nosniff\r\n\r\n', 'basic'))
    .find((l) => l.header === 'X-Content-Type-Options');
  assert.equal(dup.text, 'X-Content-Type-Options: Duplicated. Sent 2 times with the same value.');

  const coop = HL.engine.findingList(analyze('HTTP/1.1 200 OK\r\nCross-Origin-Opener-Policy: same-origin\r\nCross-Origin-Opener-Policy: same-origin\r\n\r\n', 'basic'))
    .find((l) => l.header === 'Cross-Origin-Opener-Policy');
  assert.equal(coop.text, 'Cross-Origin-Opener-Policy: Misconfigured. More than one value, so no policy is applied; sent 2 times with the same value.');
});

test('a line is unconfirmed only when its top severity is reached by to-confirm findings alone', () => {
  const r = analyze('HTTP/1.1 200 OK\r\nCache-Control: max-age=600\r\n\r\n', 'basic');
  const cc = HL.engine.findingList(r).find((l) => l.header === 'Cache-Control');
  assert.equal(cc.toConfirm, true);
  assert.ok(cc.text.endsWith('(to confirm).'));
});

test('every element the interface looks up by id exists in the page', () => {
  const app = fs.readFileSync(path.join(ROOT, 'src', 'ui', 'app.js'), 'utf8');
  const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
  const ids = new Set([...app.matchAll(/\$\('([A-Za-z0-9_-]+)'\)/g)].map((m) => m[1]));
  assert.ok(app.length > 1000 && ids.size > 5, 'app.js looks empty');
  const created = new Set([...app.matchAll(/\bid: '([A-Za-z0-9_-]+)'/g)].map((m) => m[1]));   // built by the script
  for (const id of ids) {
    assert.ok(html.includes(`id="${id}"`) || created.has(id), `no element with id "${id}" in index.html or app.js`);
  }
});

test('the em dash is not used anywhere in the project', () => {
  const skip = new Set(['node_modules', '.git', 'dist']);
  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    if (skip.has(e.name)) return [];
    const p = path.join(dir, e.name);
    return e.isDirectory() ? walk(p) : [p];
  });
  for (const file of walk(ROOT)) {
    if (!/\.(js|mjs|html|css|md|json|yml|svg)$/.test(file) && !file.endsWith('LICENSE')) continue;
    const lines = fs.readFileSync(file, 'utf8').split('\n');
    lines.forEach((line, i) => assert.ok(!line.includes(String.fromCharCode(0x2014)), `${path.relative(ROOT, file)}:${i + 1}`));
  }
});

// ------------------------------------------------- headers that protect pages
// OWASP Cheat Sheet: XFO gives no security on a redirect or JSON API, CSP and
// COOP may be meaningless on a REST API. Their absence there is a check.
const PAGE_ONLY = ['content-security-policy', 'x-frame-options', 'cross-origin-opener-policy'];
const pageOnly = (text) => Object.fromEntries(analyze(text, 'basic').results
  .filter((r) => PAGE_ONLY.includes(r.key)).map((r) => [r.key, r.findings[0]]));

test('on a JSON response, missing CSP, X-Frame-Options and COOP become checks', () => {
  const fs = pageOnly('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}');
  for (const key of PAGE_ONLY) {
    const f = fs[key];
    assert.ok(isContingentFinding(f), key);
    assert.equal(f.recommendation, '');
    assert.ok(f.verify.includes('application/json') && f.verify.includes('?'), key);
  }
  assert.equal(fs['content-security-policy'].severity, S.MEDIUM);  // severity unchanged
  assert.equal(fs['cross-origin-opener-policy'].severity, S.LOW);
});

test('on a redirect the same three become checks; on a 304 they do not', () => {
  const redirect = pageOnly('HTTP/1.1 302 Found\r\nLocation: /x\r\n\r\n');
  for (const key of PAGE_ONLY) assert.ok(redirect[key].verify.includes('302 redirect'), key);
  const notModified = pageOnly('HTTP/1.1 304 Not Modified\r\nETag: "x"\r\n\r\n');
  for (const key of PAGE_ONLY) assert.equal(notModified[key].verify, '', key);
});

test('on an HTML page, or with no Content-Type, the findings stay settled', () => {
  for (const text of ['HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n',
    'HTTP/1.1 200 OK\r\nX-Nothing: x\r\n\r\n', 'HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\n\r\n']) {
    const fs = pageOnly(text);
    for (const key of PAGE_ONLY) assert.ok(!isContingentFinding(fs[key]) && fs[key].recommendation, `${key} ${text}`);
  }
});

test('only those three headers change on a non-page response', () => {
  const json = analyze('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n', 'basic');
  const html = analyze('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n', 'basic');
  for (const r of json.results) {
    if (PAGE_ONLY.includes(r.key) || r.key === 'content-type') continue;
    const h = html.results.find((x) => x.key === r.key);
    assert.deepEqual(r.findings.map((f) => [f.severity, f.verify]), h.findings.map((f) => [f.severity, f.verify]), r.key);
  }
});

test('X-DNS-Prefetch-Control asks about both OWASP conditions', () => {
  const f = analyze('HTTP/1.1 200 OK\r\nX-Nothing: x\r\n\r\n', 'basic').results.find((r) => r.key === 'x-dns-prefetch-control').findings[0];
  assert.ok(f.verify.includes('do not control'));              // Cheat Sheet
  assert.ok(f.verify.includes('sensitive or personal data'));   // Secure Headers Project
  assert.ok(f.verify.includes('HTML injection'));
});
