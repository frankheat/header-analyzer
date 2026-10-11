'use strict';
/* The CSP engine (src/core/csp.js), checked against CSP Level 3 semantics. */
const test = require('node:test');
const assert = require('node:assert/strict');
const { HL, Severity: S, isContingent } = require('./helpers');

const evaluate = (p) => HL.csp.evaluateCsp(p);
const titles = (p) => evaluate(p).map((f) => f.title);
const flagged = (p, sub) => titles(p).some((t) => t.includes(sub));
function severityOf(p, sub) {
  const m = evaluate(p).filter((f) => f.title.includes(sub));
  assert.ok(m.length, `no finding matching ${sub} in ${JSON.stringify(titles(p))}`);
  return Math.max(...m.map((f) => f.severity));
}

// Clean under every check: a hash, so no nonce-freshness question either.
const HASH = "'sha256-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG='";
const STRICT = `default-src 'none'; script-src ${HASH} 'strict-dynamic'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests`;
const NONCE = "'nonce-abcdefghijklmnopqrstuvwx'";

test('a strict hash-based policy is clean', () => {
  assert.deepEqual(evaluate(STRICT), []);
  assert.deepEqual(evaluate(STRICT.replace('script-src', 'Script-Src')), []);
});

test("Google's recommended nonce policy: only fallbacks noted and the nonce question asked", () => {
  const p = `script-src ${NONCE} 'strict-dynamic' https: http: 'unsafe-inline'; object-src 'none'; base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests`;
  const fs = evaluate(p);
  assert.deepEqual(fs.filter((f) => f.severity > S.OK).map((f) => f.title), []);   // nothing to report
  const check = fs.find((f) => f.title.includes('nonce must change'));
  assert.ok(check.severity === S.OK && check.verify.includes('twice'));              // a check, not a finding
  assert.ok(flagged(p, "'unsafe-inline' is a fallback for old browsers"));
  assert.ok(flagged(p, "allowlist entries are ignored under 'strict-dynamic'"));
  assert.ok(!flagged(p, 'overly broad source'));
});

test("'unsafe-inline' is switched off by a nonce or a hash even without 'strict-dynamic'", () => {
  assert.ok(!flagged(`script-src 'unsafe-inline' ${NONCE}`, "script-src: 'unsafe-inline'\u0000"));
  assert.equal(severityOf(`script-src 'unsafe-inline' ${HASH}`, "'unsafe-inline'"), S.OK);
  assert.equal(severityOf("script-src 'unsafe-inline'", "'unsafe-inline'"), S.MEDIUM);
});

test('host allowlist still applies next to a nonce without strict-dynamic', () => {
  assert.ok(flagged(`script-src ${NONCE} https:`, "overly broad source 'https:'"));
});

// Structure
test('missing script-src and default-src', () => assert.ok(flagged("img-src 'self'", 'Missing script-src and default-src')));

test('missing semicolon is detected and does not look like a policy comma', () => {
  assert.equal(severityOf("default-src 'self' script-src 'none'", 'Possible missing semicolon'), S.LOW);
  assert.ok(!flagged("default-src 'none'; object-src 'none', script-src 'self'", 'missing semicolon'));
});

for (const kw of ['unsafe-inline', 'unsafe-eval', 'unsafe-hashes', 'strict-dynamic', 'none', 'self']) {
  test(`unquoted keyword ${kw} is reported`, () => {
    assert.equal(severityOf(`script-src ${kw}`, `Keyword '${kw}'`), S.LOW);
  });
}

for (const v of ['nonce-abc123', 'sha256-abc123', 'sha384-abc123', 'sha512-abc123']) {
  test(`unquoted nonce/hash ${v} is reported`, () => assert.ok(flagged(`script-src ${v}`, 'missing its single quotes')));
}

test('an unknown quoted keyword is reported; a quoted nonce is not', () => {
  assert.ok(flagged("script-src 'unsafe_inline'", 'Unrecognised source expression'));
  assert.ok(!flagged(`script-src ${NONCE}`, 'Unrecognised'));
  assert.ok(!flagged("script-src 'wasm-unsafe-eval' 'report-sample'", 'Unrecognised'));
});

test('a duplicate directive: the first wins and the second is reported', () => {
  const p = "script-src 'unsafe-inline'; script-src 'self'";
  assert.ok(flagged(p, "Directive 'script-src' appears more than once"));
  assert.ok(flagged(p, "script-src: 'unsafe-inline'"));          // the first is what applies
  assert.ok(!flagged("script-src 'self'; script-src 'unsafe-inline'", "script-src: 'unsafe-inline'"));
});

test('an unknown directive is reported with a suggestion', () => {
  const f = evaluate("scirpt-src 'self'").find((x) => x.title.includes("'scirpt-src'"));
  assert.ok(f && f.description.includes("'script-src'"));
});

test('a non-ASCII directive is skipped as the spec skips it', () => {
  const p = "script-src ‘self’; object-src 'none'";
  assert.ok(flagged(p, 'non-ASCII'));
  assert.ok(flagged(p, 'Missing script-src and default-src'));
});

test("'none' combined with other sources is noted", () => assert.ok(flagged("img-src 'none' https://a.example", "'none' in 'img-src' is combined")));

// script-src
for (const [src, sev] of [['*', S.MEDIUM], ['http:', S.MEDIUM], ['https:', S.MEDIUM]]) {
  test(`script-src ${src} is overly broad`, () => assert.equal(severityOf(`script-src ${src}`, 'overly broad source'), sev));
}

test("'unsafe-eval' is MEDIUM and not cancelled by strict-dynamic", () => {
  assert.equal(severityOf("script-src 'unsafe-eval'", "'unsafe-eval'"), S.MEDIUM);
  assert.ok(flagged(`script-src ${NONCE} 'strict-dynamic' 'unsafe-eval'`, "'unsafe-eval'"));
});

test("'unsafe-hashes' matters only with a hash", () => {
  assert.equal(severityOf(`script-src 'unsafe-hashes' ${HASH}`, "'unsafe-hashes'"), S.LOW);
  assert.equal(severityOf("script-src 'unsafe-hashes'", "'unsafe-hashes'"), S.OK);
});

test("'strict-dynamic' alone blocks everything: informational", () => {
  assert.equal(severityOf("script-src 'strict-dynamic'", 'without a nonce or hash'), S.OK);
  assert.ok(!flagged(`script-src 'strict-dynamic' ${HASH}`, 'without a nonce or hash'));
});

test('data: is MEDIUM, blob: is LOW', () => {
  assert.equal(severityOf('script-src data:', "'data:' URI scheme"), S.MEDIUM);
  assert.equal(severityOf('script-src blob:', "'blob:' URI scheme"), S.LOW);
});

for (const w of ['*.com', '*.net', '*.org', '*.io', '*.co', 'https://*.dev', '*.co.uk']) {
  test(`TLD wildcard ${w} is MEDIUM`, () => assert.equal(severityOf(`script-src ${w}`, 'wildcard over a whole top-level domain'), S.MEDIUM));
}

for (const host of ['https://ajax.googleapis.com', 'https://cdnjs.cloudflare.com', 'code.jquery.com', 'https://www.google-analytics.com/', 'accounts.google.com:443', 'https://unpkg.com']) {
  test(`known bypass host ${host}`, () => assert.equal(severityOf(`script-src ${host}`, 'known CSP bypass host'), S.MEDIUM));
}

for (const src of ['https://*.googleapis.com', '*.jsdelivr.net', 'https://*.cloudflare.com']) {
  test(`bypass via wildcard ${src}`, () => assert.ok(flagged(`script-src ${src}`, 'known CSP bypass via wildcard')));
}

for (const src of ['*.github.io', 'https://*.herokuapp.com', '*.amazonaws.com']) {
  test(`wildcard over user content ${src}`, () => assert.ok(flagged(`script-src ${src}`, 'anyone can publish on')));
}

test('an ordinary host is not flagged; a plaintext one is, unless upgraded', () => {
  assert.deepEqual(evaluate(STRICT.replace("'strict-dynamic'", 'https://cdn.example.com')), []);
  assert.ok(flagged("script-src http://cdn.example.com", 'over plain HTTP'));
  assert.ok(!flagged("script-src http://cdn.example.com; upgrade-insecure-requests", 'over plain HTTP'));
});

test('nonce length: under 22 characters is LOW', () => {
  assert.equal(severityOf("script-src 'nonce-tooshort'", 'shorter than 128 bits'), S.LOW);
  assert.ok(!flagged("script-src 'nonce-abcdefghijklmnopqrstuv'", 'shorter than 128 bits'));
});

test('a nonce always raises the freshness check, as an OK note', () => {
  const f = evaluate(`script-src ${NONCE}`).find((x) => x.title.includes('nonce must change'));
  assert.ok(!isContingent(f) && f.severity === S.OK && f.verify.includes('twice'));
});

test('script-src-elem and script-src-attr are evaluated through their fallbacks', () => {
  assert.ok(flagged("script-src 'self'; script-src-attr 'unsafe-inline'", "script-src-attr: 'unsafe-inline'"));
  assert.ok(flagged("script-src-elem 'unsafe-inline'; default-src 'self'", "script-src-elem: 'unsafe-inline'"));
  assert.ok(!flagged("script-src-elem 'self'", 'Missing script-src and default-src'));
  // reached by both routes, reported once
  assert.equal(titles("script-src 'unsafe-inline'").filter((t) => t === "script-src: 'unsafe-inline'").length, 1);
});

// Other directives
test('style-src unsafe-inline is LOW with images and fonts restricted, OK with a nonce', () => {
  assert.equal(severityOf("default-src 'none'; style-src 'unsafe-inline'", "style-src: 'unsafe-inline'"), S.LOW);
  assert.ok(!flagged(`style-src 'unsafe-inline' ${NONCE}`, "style-src: 'unsafe-inline'\u0000"));
  assert.equal(severityOf(`style-src 'unsafe-inline' ${NONCE}`, "'unsafe-inline'"), S.OK);
});

test('object-src: missing, permissive, none and empty', () => {
  assert.ok(flagged("script-src 'self'", 'Missing object-src'));
  assert.equal(severityOf("default-src 'none'; object-src 'self'", 'Permissive object-src'), S.LOW);
  assert.ok(!flagged(STRICT, 'object-src'));
  assert.ok(!flagged("default-src 'self'; object-src", 'Permissive object-src'));
});

test('base-uri, frame-ancestors, default-src, form-action', () => {
  assert.equal(severityOf("script-src 'self'", 'Missing base-uri'), S.LOW);              // no nonce or hash to defeat
  assert.equal(severityOf(`script-src ${NONCE}`, 'Missing base-uri'), S.MEDIUM);         // CSP Evaluator: defeats the nonce
  // A hash pins the content, so a moved URL changes nothing; with 'strict-dynamic'
  // a hashed script's relative loads are trusted wherever <base> points them.
  assert.equal(severityOf(`script-src ${HASH}`, 'Missing base-uri'), S.LOW);
  assert.equal(severityOf(`script-src ${HASH} 'strict-dynamic'`, 'Missing base-uri'), S.MEDIUM);
  assert.equal(severityOf(STRICT.replace("base-uri 'none'", 'base-uri *'), 'Permissive base-uri'), S.MEDIUM);
  assert.equal(severityOf("script-src 'self'", 'Missing frame-ancestors'), S.LOW);
  for (const fa of ['*', 'https:', 'http:']) assert.equal(severityOf(STRICT.replace("frame-ancestors 'none'", `frame-ancestors ${fa}`), 'Permissive frame-ancestors'), S.MEDIUM);
  assert.equal(severityOf("script-src 'self'", 'Missing default-src'), S.LOW);
  assert.equal(severityOf(STRICT.replace("default-src 'none'", 'default-src *'), 'Permissive default-src'), S.LOW);
  assert.equal(severityOf(STRICT.replace("default-src 'none'", 'default-src https:'), "Permissive default-src 'https:'"), S.LOW);
  assert.equal(severityOf("script-src 'self'", 'Missing form-action'), S.LOW);
  assert.ok(flagged(STRICT.replace("form-action 'self'", 'form-action *'), 'Permissive form-action'));
  assert.equal(severityOf("script-src 'self'", 'Missing upgrade-insecure-requests'), S.LOW);
});

for (const d of ['reflected-xss', 'referrer', 'block-all-mixed-content', 'prefetch-src', 'plugin-types', 'navigate-to']) {
  test(`obsolete directive ${d}`, () => assert.equal(severityOf(`${STRICT}; ${d} x`, `Obsolete CSP directive: ${d}`), S.LOW));
}

test('fallback to default-src is labelled', () => {
  assert.ok(flagged("default-src 'unsafe-inline'", "script-src (from default-src): 'unsafe-inline'"));
  assert.ok(flagged("default-src 'unsafe-inline'", "style-src (from default-src): 'unsafe-inline'"));
  assert.ok(!flagged("default-src 'unsafe-eval'; script-src 'self'", "'unsafe-eval'"));
});

// Several policies
test('several policies: absences intersect, weaknesses union, no duplicates', () => {
  assert.ok(!flagged("script-src 'unsafe-inline', object-src 'none'", 'Missing object-src'));
  assert.ok(flagged("script-src 'self', style-src 'self'", 'Missing object-src'));
  assert.ok(flagged("script-src 'unsafe-inline', object-src 'none'", "'unsafe-inline'"));
  assert.ok(flagged("script-src 'unsafe-eval', script-src 'self'", "'unsafe-eval'"));
  assert.equal(titles("script-src 'unsafe-eval', script-src 'unsafe-eval'").filter((t) => t.includes("'unsafe-eval'")).length, 1);
  assert.ok(flagged('script-src *, script-src https:', 'overly broad source'));
  assert.ok(flagged(`script-src unsafe-inline, ${STRICT}`, "Keyword 'unsafe-inline'"));
  const t = titles("script-src 'self', script-src 'self'");
  assert.equal(t.length, new Set(t).size);
  assert.ok(flagged("script-src 'self', object-src 'none'", '2 policies are enforced together'));
});

test('empty policy segments are ignored', () => {
  assert.deepEqual(evaluate(`${STRICT}, ,`), evaluate(STRICT));
});

test('every CSP finding has a list status and a short brief', () => {
  const policies = [STRICT, "script-src 'unsafe-inline'", "default-src 'self' script-src 'none'", 'script-src *, script-src https:',
    "scirpt-src 'self'; script-src ‘self’", "script-src 'strict-dynamic'", "script-src 'unsafe-hashes'", `script-src 'unsafe-hashes' ${HASH}`,
    "script-src *.co.uk *.jsdelivr.net *.github.io unpkg.com http://a.example blob: data: 'nonce-x' self nonce-x 'bogus'",
    "img-src 'none' x; style-src 'unsafe-inline'; object-src 'self'; base-uri *; frame-ancestors *; default-src https:; form-action *; referrer x"];
  for (const p of policies) {
    for (const f of evaluate(p)) {
      if (f.status === '') continue;
      assert.ok(f.brief && f.brief.length <= 72 && !f.brief.endsWith('.'), `${p}: ${f.title}: "${f.brief}"`);
    }
  }
});

test('no CSP weakness weighs more than having no CSP at all (MEDIUM)', () => {
  const policies = ["script-src * 'unsafe-inline' 'unsafe-eval' data: https: http: *.com unpkg.com *.github.io",
    "default-src *; base-uri *; frame-ancestors *; form-action *; object-src *", "img-src 'self'"];
  for (const p of policies) for (const f of evaluate(p)) assert.ok(f.severity <= S.MEDIUM, `${p}: ${f.title}`);
});

test("style 'unsafe-inline' is MEDIUM only when CSS can send what it reads to any origin", () => {
  const t = "'unsafe-inline'";
  assert.equal(severityOf(`style-src ${t}`, 'style-src: '), S.MEDIUM);                                   // no default-src: images go anywhere
  assert.equal(severityOf(`default-src 'self'; style-src ${t}`, 'style-src: '), S.LOW);                   // channel closed
  assert.equal(severityOf(`default-src 'self'; img-src *; style-src ${t}`, 'style-src: '), S.MEDIUM);
  assert.equal(severityOf(`default-src 'self'; font-src https:; style-src ${t}`, 'style-src: '), S.MEDIUM);
  assert.equal(severityOf(`default-src 'self'; img-src *.com; style-src ${t}`, 'style-src: '), S.MEDIUM);
  assert.equal(severityOf(`default-src 'self'; img-src 'self' https://cdn.example; style-src ${t}`, 'style-src: '), S.LOW);
  assert.equal(severityOf(`default-src * ${t}`, 'style-src (from default-src): '), S.MEDIUM);
});
