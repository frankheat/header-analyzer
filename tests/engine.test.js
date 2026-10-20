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
  assert.equal(r.results.length, 17);
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

// ------------------------------------------------------------ the two modes
// The user says what the response is; nothing is guessed from it.
const byKey = (report) => Object.fromEntries(report.results.map((r) => [r.key, r]));
const BARE = 'HTTP/1.1 200 OK\r\nX-Nothing: x\r\n\r\n';

test('Web page is the default mode, and an unknown mode falls back to it', () => {
  assert.equal(analyze(BARE, 'basic').mode.id, 'page');
  assert.equal(analyze(BARE, 'basic', 'nonsense').mode.id, 'page');
  assert.equal(analyze(BARE, 'basic', 'api').mode.id, 'api');
});

test('in Web page mode a JSON or redirect response is still judged as a page', () => {
  for (const text of ['HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}', 'HTTP/1.1 302 Found\r\nLocation: /x\r\n\r\n']) {
    const r = byKey(analyze(text, 'basic', 'page'));
    for (const key of ['content-security-policy', 'x-frame-options', 'cross-origin-opener-policy']) {
      const f = r[key].findings[0];
      assert.ok(!isContingentFinding(f) && f.recommendation, `${key} ${text}`);
    }
    assert.equal(r['content-security-policy'].findings[0].severity, S.MEDIUM);
  }
});

test('no check in Web page mode asks whether the response is a page or an API', () => {
  const r = analyze('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n', 'extended', 'page');
  for (const res of r.results) {
    for (const f of res.findings) assert.ok(!/web page\?|REST|an API/.test(f.verify), `${res.key}: ${f.verify}`);
  }
});

test('REST API + Basic shows exactly the headers of the OWASP REST Security Cheat Sheet', () => {
  const keys = new Set(analyze(BARE, 'basic', 'api').results.map((r) => r.key));
  const expected = ['cache-control', 'content-security-policy', 'content-type', 'strict-transport-security',
    'x-content-type-options', 'x-frame-options', 'permissions-policy', 'referrer-policy'];
  for (const k of expected) assert.ok(keys.has(k), k);
  for (const k of keys) assert.ok(HL.profiles.REST_BASIC.has(k), k);
});

test('REST API + Extended keeps the same headers as Web page + Extended', () => {
  const page = analyze(BARE, 'extended', 'page').results.map((r) => r.key);
  const api = analyze(BARE, 'extended', 'api').results.map((r) => r.key);
  assert.deepEqual(new Set(api), new Set(page));
});

test('REST API: the cheat sheet headers that every API response needs are settled LOW when missing', () => {
  const r = byKey(analyze(BARE, 'basic', 'api'));
  for (const key of ['content-type', 'x-frame-options']) {
    const f = r[key].findings[0];
    assert.equal(f.severity, S.LOW, key);
    assert.ok(!isContingentFinding(f) && f.recommendation, key);
  }
  const fa = r['content-security-policy'].findings[0];
  assert.equal(fa.severity, S.LOW);                       // LOW, not the page's MEDIUM
  assert.match(fa.recommendation, /frame-ancestors 'none'/);
  assert.equal(r['strict-transport-security'].findings[0].severity, S.MEDIUM);  // as in page mode
});

test('REST API: the defence-in-depth headers are checks about whether HTML can come back', () => {
  const r = byKey(analyze(BARE, 'basic', 'api'));
  const checks = [r['content-security-policy'].findings[1], r['permissions-policy'].findings[0], r['referrer-policy'].findings[0]];
  for (const f of checks) {
    assert.ok(isContingentFinding(f), f.title);
    assert.ok(f.verify.startsWith('Can this API return HTML'), f.title);
    assert.ok(f.sources.includes('rest-dd-uncertain'), f.title);
  }
});

test('REST API: Cache-Control keeps the page rules, a check on user data, citing the REST cheat sheet', () => {
  const missing = byKey(analyze(BARE, 'basic', 'api'))['cache-control'].findings[0];
  assert.ok(isContingentFinding(missing));
  assert.ok(missing.verify.startsWith('Does this response carry data belonging to a signed-in user?'));
  assert.ok(missing.sources.includes('rest-cc'));
  const shared = byKey(analyze('HTTP/1.1 200 OK\r\nCache-Control: public, max-age=3600\r\n\r\n', 'basic', 'api'))['cache-control'].findings[0];
  assert.equal(shared.severity, S.MEDIUM);
  assert.ok(isContingentFinding(shared) && shared.sources.includes('rest-cc'));
  const page = byKey(analyze('HTTP/1.1 200 OK\r\nCache-Control: public, max-age=3600\r\n\r\n', 'basic', 'page'))['cache-control'].findings[0];
  assert.ok(!page.sources.includes('rest-cc'));
});

test('REST API: the CSP is read for frame-ancestors and default-src only', () => {
  const r = byKey(analyze("HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n\r\n", 'basic', 'api'));
  const fs = r['content-security-policy'].findings;
  assert.equal(fs.length, 2);
  assert.ok(fs.every((f) => f.severity === S.OK));
  const self = byKey(analyze("HTTP/1.1 200 OK\r\nContent-Security-Policy: frame-ancestors 'self'\r\n\r\n", 'basic', 'api'));
  assert.equal(self['content-security-policy'].findings[0].severity, S.LOW);
  assert.match(self['content-security-policy'].findings[0].title, /frame-ancestors 'self'/);
});

test('REST API: X-Frame-Options must be DENY, Referrer-Policy no-referrer, Cache-Control no-store', () => {
  const r = byKey(analyze('HTTP/1.1 200 OK\r\nX-Frame-Options: SAMEORIGIN\r\nReferrer-Policy: strict-origin\r\nCache-Control: private\r\n\r\n', 'basic', 'api'));
  assert.equal(r['x-frame-options'].findings[0].severity, S.LOW);
  assert.ok(!isContingentFinding(r['x-frame-options'].findings[0]));
  assert.equal(r['referrer-policy'].findings[0].severity, S.LOW);
  assert.equal(r['cache-control'].findings[0].severity, S.LOW);
  const ok = byKey(analyze('HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nCache-Control: no-store\r\n\r\n', 'basic', 'api'));
  for (const key of ['x-frame-options', 'referrer-policy', 'cache-control']) assert.equal(ok[key].findings[0].severity, S.OK, key);
});

test('REST API: Permissions-Policy is OK only when every feature it names is closed', () => {
  const closed = byKey(analyze('HTTP/1.1 200 OK\r\nPermissions-Policy: camera=(), geolocation=()\r\n\r\n', 'basic', 'api'));
  assert.equal(closed['permissions-policy'].findings[0].severity, S.OK);
  const open = byKey(analyze('HTTP/1.1 200 OK\r\nPermissions-Policy: camera=*, geolocation=(self), usb=()\r\n\r\n', 'basic', 'api'));
  const f = open['permissions-policy'].findings[0];
  assert.equal(f.severity, S.LOW);
  assert.ok(isContingentFinding(f));
  assert.match(f.title, /camera, geolocation$/);
});

test('REST API: Content-Type text/html is a check; no charset is asked of JSON', () => {
  const html = byKey(analyze('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n', 'basic', 'api'));
  assert.ok(isContingentFinding(html['content-type'].findings[0]));
  const js = byKey(analyze('HTTP/1.1 200 OK\r\nContent-Type: Application/JavaScript; charset=utf-8\r\n\r\n', 'basic', 'api'));
  assert.ok(isContingentFinding(js['content-type'].findings[0]));
  assert.ok(js['content-type'].findings[0].verify.startsWith('Is the body really JavaScript?'));
  const json = byKey(analyze('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n', 'basic', 'api'));
  assert.equal(json['content-type'].findings[0].severity, S.OK);
});

test('REST API: headers that only act on a document are not applicable', () => {
  const r = byKey(analyze(BARE, 'extended', 'api'));
  for (const key of ['cross-origin-opener-policy', 'cross-origin-embedder-policy', 'origin-agent-cluster', 'x-dns-prefetch-control']) {
    assert.equal(r[key].findings.length, 1, key);
    assert.equal(r[key].findings[0].severity, S.OK, key);
    assert.match(r[key].findings[0].title, /not applicable to an API response/);
  }
});

test('REST API: X-XSS-Protection stays a deprecated LOW, explained for an API', () => {
  const api = byKey(analyze('HTTP/1.1 200 OK\r\nX-XSS-Protection: 1; mode=block\r\n\r\n', 'extended', 'api'))['x-xss-protection'].findings[0];
  assert.equal(api.severity, S.LOW);
  assert.match(api.description, /An API response is not rendered/);
  const page = byKey(analyze('HTTP/1.1 200 OK\r\nX-XSS-Protection: 1; mode=block\r\n\r\n', 'basic', 'page'))['x-xss-protection'].findings[0];
  assert.doesNotMatch(page.description, /API/);
});

test('REST API: X-Frame-Options next to a permissive frame-ancestors says it is replaced', () => {
  const r = byKey(analyze('HTTP/1.1 200 OK\r\nContent-Security-Policy: frame-ancestors *\r\nX-Frame-Options: DENY\r\n\r\n', 'basic', 'api'));
  assert.ok(r['x-frame-options'].findings.some((f) => /replaced by the CSP/.test(f.title)));
});

test('the API sample selects REST API mode; the others leave the mode alone', () => {
  const api = HL.samples.find((s) => s.id === 'api');
  assert.equal(api.mode, 'api');
  assert.ok(HL.samples.filter((s) => s.id !== 'api').every((s) => !s.mode));
  const r = analyze(api.text, 'basic', api.mode);
  assert.ok(r.ok && r.results.some((x) => x.key === 'access-control-allow-origin' && x.findings.some((f) => f.severity > S.OK)));
});

test('REST API: a missing CORP asks about GET requests with user data and cookies', () => {
  const f = byKey(analyze(BARE, 'extended', 'api'))['cross-origin-resource-policy'].findings[0];
  assert.ok(isContingentFinding(f));
  assert.ok(f.verify.startsWith('Does this endpoint answer GET requests with user data, authenticated by cookies?'));
  assert.ok(f.sources.includes('webdev-corp-api'));
});

test('X-DNS-Prefetch-Control asks about both OWASP conditions', () => {
  const f = analyze('HTTP/1.1 200 OK\r\nX-Nothing: x\r\n\r\n', 'basic').results.find((r) => r.key === 'x-dns-prefetch-control').findings[0];
  assert.ok(f.verify.includes('do not control'));              // Cheat Sheet
  assert.ok(f.verify.includes('personal or sensitive data'));   // Secure Headers Project
  assert.ok(f.verify.includes('input from users'));             // where HTML injection happens
  assert.ok(f.verify.startsWith('Does the page show'));        // Web page mode: it is a page
});
