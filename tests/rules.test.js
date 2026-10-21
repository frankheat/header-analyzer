'use strict';
/* Orchestration, profiles, duplicates and correlations. */
const test = require('node:test');
const assert = require('node:assert/strict');
const {
  HL, Severity: S, analyze, resultFor, findingsFor, severityFor, absent, has, worstSeverity, isContingent,
} = require('./helpers');

const { PROFILES } = HL.profiles;

test('every registry header is reported when nothing is skipped', () => {
  assert.deepEqual(new Set(Object.keys(analyze(['X-Frame-Options: DENY']))), new Set(HL.rules.SECURITY_HEADERS.map((h) => h[0])));
});

// The absence of every header in the profiles, as decided (RULES.md):
// a severity is a deviation from OWASP/ASVS; null means absence is correct.
const ABSENCE = {
  'content-security-policy': S.MEDIUM, 'strict-transport-security': S.MEDIUM, 'x-frame-options': S.MEDIUM,
  'x-content-type-options': S.LOW, 'cross-origin-opener-policy': S.LOW, 'permissions-policy': S.LOW,
  'referrer-policy': S.LOW, 'cross-origin-embedder-policy': S.LOW, 'cross-origin-resource-policy': S.LOW,
  'x-permitted-cross-domain-policies': S.LOW, 'cache-control': S.LOW, 'clear-site-data': S.LOW,
  'x-dns-prefetch-control': S.LOW, 'origin-agent-cluster': S.LOW,
  'access-control-allow-origin': null, 'access-control-allow-credentials': null, 'service-worker-allowed': null,
  'content-disposition': null, 'pragma': null, 'expires': null, 'etag': null, 'x-download-options': null,
  'x-xss-protection': null, 'expect-ct': null, 'content-type': null,
};
const CONTINGENT_ABSENCE = new Set(['cache-control', 'clear-site-data', 'x-dns-prefetch-control']);

test('the absence table covers every header in the registry', () => {
  assert.deepEqual(new Set(Object.keys(ABSENCE)), new Set(HL.rules.SECURITY_HEADERS.map((h) => h[0])));
});

for (const [key, expected] of Object.entries(ABSENCE)) {
  test(`missing ${key} → ${expected === null ? 'OK' : S[expected] || expected}`, () => {
    const r = absent(key);
    if (expected === null) {
      assert.equal(worstSeverity(r), S.OK);
      return;
    }
    assert.equal(worstSeverity(r), expected);
    const f = r.findings[0];
    assert.ok(f.title.startsWith('Missing '));
    assert.equal(f.status, 'Missing');
    assert.equal(isContingent(f), CONTINGENT_ABSENCE.has(key));
    assert.ok(isContingent(f) ? f.verify : f.recommendation);
  });
}

test('the same absence grades apply in both profiles', () => {
  for (const p of [PROFILES.basic, PROFILES.extended]) {
    const r = analyze(['X-Nothing: x'], p);
    for (const [key, sev] of Object.entries(ABSENCE)) if (key in r) assert.equal(worstSeverity(r[key]), sev === null ? S.OK : sev, `${p.id} ${key}`);
  }
});

test('a header whose absence is correct says why, without a severity', () => {
  for (const key of ['service-worker-allowed', 'content-disposition', 'pragma', 'expires', 'etag', 'x-download-options']) {
    const f = absent(key).findings[0];
    assert.equal(f.severity, S.OK);
    assert.equal(f.status, '');
    assert.ok(f.description.startsWith('Not sent'));
  }
});

test('a missing X-Frame-Options is LOW when CSP frame-ancestors already restricts framing', () => {
  const xfo = (csp) => analyze([`Content-Security-Policy: ${csp}`])['x-frame-options'];
  for (const fa of ["'none'", "'self'", 'https://partner.example']) {
    const r = xfo(`default-src 'self'; frame-ancestors ${fa}`);
    assert.equal(worstSeverity(r), S.LOW, fa);
    assert.ok(r.findings[0].brief.includes('frame-ancestors'));
  }
  for (const fa of ['*', 'https:', '*.com']) assert.equal(worstSeverity(xfo(`frame-ancestors ${fa}`)), S.MEDIUM, fa);
  assert.equal(worstSeverity(xfo("default-src 'self'")), S.MEDIUM);
  // an unusable value weighs as absence, so it follows the same rule
  assert.equal(worstSeverity(analyze(["Content-Security-Policy: frame-ancestors 'none'", 'X-Frame-Options: ALLOWALL'])['x-frame-options']), S.LOW);
});

test('an absent header is not present and has a null value', () => {
  const r = absent('x-frame-options');
  assert.equal(r.value, null);
  assert.equal(r.present, false);
});

for (const value of ['', '   ']) {
  test(`empty value ${JSON.stringify(value)} is present but empty`, () => {
    const r = resultFor('X-Frame-Options', value);
    assert.ok(r.present && has(r.findings, 'present but empty'));
  });
}

for (const [key, canonical] of HL.rules.SECURITY_HEADERS) {
  test(`empty ${canonical} weighs the same as absent`, () => {
    assert.equal(worstSeverity(resultFor(canonical, '')), worstSeverity(absent(key)));
  });
}

const ABSENCE_IS_CORRECT = ['X-XSS-Protection', 'Expect-CT', 'Access-Control-Allow-Origin',
  'Access-Control-Allow-Credentials', 'Content-Type'];
for (const header of ABSENCE_IS_CORRECT) {
  test(`${header} is not reported as missing, absent or empty`, () => {
    assert.deepEqual(absent(header.toLowerCase()).findings, []);
    assert.deepEqual(resultFor(header, '').findings, []);
  });
}

// ------------------------------------------------------------------ profiles
test('the basic profile skips the extended-only headers and keeps the core ones', () => {
  const r = analyze(['X-Nothing: x'], PROFILES.basic);
  for (const k of ['origin-agent-cluster', 'service-worker-allowed', 'content-disposition', 'pragma', 'expires', 'etag', 'x-download-options']) assert.ok(!(k in r), k);
  for (const k of ['permissions-policy', 'x-dns-prefetch-control', 'x-xss-protection', 'expect-ct', 'content-type', 'access-control-allow-origin', 'access-control-allow-credentials']) assert.ok(k in r, k);
  assert.equal(Object.keys(r).length, 17);
});

test('the extended profile checks more headers, asks about preload and expects DNS prefetch control', () => {
  const basic = analyze(['X-Nothing: x'], PROFILES.basic);
  const ext = analyze(['X-Nothing: x'], PROFILES.extended);
  assert.ok(Object.keys(basic).every((k) => k in ext));
  assert.ok(Object.keys(ext).length > Object.keys(basic).length);
  assert.ok(has(findingsFor('Strict-Transport-Security', 'max-age=63072000; includeSubDomains', PROFILES.extended), 'preload is not declared'));
  assert.equal(worstSeverity(ext['x-dns-prefetch-control']), S.LOW);
  assert.equal(worstSeverity(basic['x-dns-prefetch-control']), S.LOW);
});

test('profiles are frozen and an unknown id falls back to basic', () => {
  assert.ok(Object.isFrozen(PROFILES) && Object.isFrozen(PROFILES.basic) && Object.isFrozen(PROFILES.basic.hsts));
  assert.equal(HL.profiles.getProfile('custom').id, 'basic');
  assert.equal(HL.profiles.getProfile('__proto__').id, 'basic');
  assert.equal(HL.profiles.getProfile(undefined).id, 'basic');
});

// --------------------------------------------------------------- duplicates
const dup = (r) => {
  const found = r.findings.filter((f) => f.title.includes('times'));
  assert.equal(found.length, 1, JSON.stringify(found.map((f) => f.title)));
  return found[0];
};

test('a single occurrence produces no duplicate finding', () => {
  assert.ok(!resultFor('X-Frame-Options', 'DENY').findings.some((f) => f.title.includes('times')));
});

test('identical duplicates collapse and are LOW', () => {
  const r = analyze(['Strict-Transport-Security: max-age=63072000; includeSubDomains', 'Strict-Transport-Security: max-age=63072000; includeSubDomains'])['strict-transport-security'];
  assert.equal(r.value, 'max-age=63072000; includeSubDomains');
  assert.equal(dup(r).severity, S.LOW);
  assert.ok(dup(r).description.includes('identical'));
  assert.equal(worstSeverity(r), S.LOW);
});

test('conflicting first-wins duplicates are LOW and list every value', () => {
  const r = analyze(['Strict-Transport-Security: max-age=1', 'Strict-Transport-Security: max-age=2', 'Strict-Transport-Security: max-age=3'])['strict-transport-security'];
  const f = dup(r);
  assert.equal(f.severity, S.LOW);
  assert.ok(f.title.includes('sent 3 times') && f.title.includes('conflicting values'));
  for (const v of ['max-age=1', 'max-age=2', 'max-age=3']) assert.ok(f.description.includes(v));
  assert.equal(r.value, 'max-age=1');
});

for (const [header, a, b] of [
  ['Cache-Control', 'max-age=600', 'must-revalidate'], ['Content-Security-Policy', "default-src 'none'", "frame-ancestors 'none'"],
  ['Clear-Site-Data', '"cache"', '"cookies"'], ['Permissions-Policy', 'camera=()', 'microphone=()'], ['Pragma', 'no-cache', 'no-transform'],
]) {
  test(`joined duplicates of ${header} are not a conflict and combine`, () => {
    const r = analyze([`${header}: ${a}`, `${header}: ${b}`])[header.toLowerCase()];
    assert.equal(r.value, `${a}, ${b}`);
    const f = dup(r);
    assert.equal(f.severity, S.LOW);
    assert.ok(!f.title.includes('conflicting') && f.description.includes('combine') && f.recommendation === '');
  });
}

test('a repeated identical joined value carries a recommendation', () => {
  assert.notEqual(dup(analyze(['Cache-Control: no-store', 'Cache-Control: no-store'])['cache-control']).recommendation, '');
});

test('Referrer-Policy across occurrences keeps the last valid token', () => {
  const both = analyze(['Referrer-Policy: unsafe-url', 'Referrer-Policy: no-referrer'])['referrer-policy'];
  assert.equal(worstSeverity(both), S.LOW);                     // the duplicate itself; no-referrer applies
  assert.ok(!both.findings.some((f) => f.title.includes('full URL')));
  assert.equal(worstSeverity(analyze(['Referrer-Policy: no-referrer', 'Referrer-Policy: bogus'])['referrer-policy']), S.LOW);
});

test('X-Frame-Options conflicts are resolved by its own checker', () => {
  const r = analyze(['X-Frame-Options: SAMEORIGIN', 'X-Frame-Options: DENY'])['x-frame-options'];
  assert.equal(r.value, 'SAMEORIGIN, DENY');
  assert.ok(has(r.findings, 'blocks framing by contradicting itself'));
  assert.equal(worstSeverity(analyze(['X-Frame-Options: bogus', 'X-Frame-Options: garbage'])['x-frame-options']), worstSeverity(absent('x-frame-options')));
});

for (const [a, b] of [['same-origin', 'same-origin'], ['same-origin', 'unsafe-none']]) {
  test(`duplicate COOP (${a}, ${b}) leaves the response without COOP`, () => {
    const r = analyze([`Cross-Origin-Opener-Policy: ${a}`, `Cross-Origin-Opener-Policy: ${b}`])['cross-origin-opener-policy'];
    const invalid = r.findings.filter((f) => f.title.includes('not applied'));
    assert.equal(invalid.length, 1);
    assert.equal(invalid[0].severity, S.LOW);                       // the severity of an absent COOP
    assert.ok(!r.findings.some((f) => f.severity === S.OK));
  });
}

test('two ACAO headers combine into a value that matches no origin (Fetch "get")', () => {
  const r = analyze(['Access-Control-Allow-Origin: *', 'Access-Control-Allow-Origin: *'])['access-control-allow-origin'];
  assert.ok(has(r.findings, 'lists more than one origin'));
});

// ------------------------------------------------------------- correlations
const cors = (origin, credentials = 'true', profile) => {
  const lines = [];
  if (origin !== null) lines.push(`Access-Control-Allow-Origin: ${origin}`);
  if (credentials !== null) lines.push(`Access-Control-Allow-Credentials: ${credentials}`);
  return analyze(lines.length ? lines : ['X-Nothing: x'], profile)['access-control-allow-credentials'];
};

test('null origin with credentials is HIGH (ZAP 40040: High)', () => {
  const r = cors('null');
  assert.equal(worstSeverity(r), S.HIGH);
  assert.ok(has(r.findings, 'null with credentials enabled'));
});

test('wildcard with credentials is functional, and the wildcard is still graded on its own row', () => {
  assert.equal(worstSeverity(cors('*')), S.OK);
  assert.ok(cors('*').findings.find((f) => f.title.includes('the request fails')).recommendation.includes('Do not echo back'));
  assert.equal(worstSeverity(analyze(['Access-Control-Allow-Origin: *', 'Access-Control-Allow-Credentials: true'])['access-control-allow-origin']), S.LOW);
});

test('a specific origin with credentials is LOW: OWASP recommends it, reflection is the check', () => {
  const r = cors('https://app.example.com');
  assert.equal(worstSeverity(r), S.LOW);
  const f = r.findings.find((x) => x.severity === S.LOW);
  assert.ok(isContingent(f) && f.description.includes('echoes back') && f.verify.includes('does not come back'));
  assert.ok(f.verify.includes('it is HIGH'));                  // the worst case is stated in the check
});

test('credentials without an origin, or with an unusable one, have no effect', () => {
  assert.ok(has(cors(null).findings, 'has no effect'));
  assert.ok(has(cors('https://a.example.com, https://b.example.com').findings, 'not usable'));
  assert.ok(has(cors('NULL').findings, 'matches nothing'));
});

for (const credentials of ['false', 'FALSE', 'yes', '1', 'TRUE', 'True']) {
  test(`nothing is reported unless credentials are exactly "true" (got ${credentials})`, () => {
    assert.equal(worstSeverity(cors('null', credentials)), S.OK);
  });
}

test('padding is tolerated around true', () => assert.equal(worstSeverity(cors('null', '  true  ')), S.HIGH));

test('no credentials header: no verdict', () => {
  assert.deepEqual(analyze(['Access-Control-Allow-Origin: null'])['access-control-allow-credentials'].findings, []);
});

for (const [origin, graded] of [['null', 1], ['https://app.example.com', 1], ['*', 0], [null, 0]]) {
  test(`credentials carry a single verdict (origin ${origin})`, () => {
    const fs = cors(origin).findings;
    assert.equal(fs.filter((f) => f.severity > S.OK).length, graded);
    assert.equal(fs.filter((f) => !f.title.startsWith('Access-Control-Allow-Credentials: true')).length, 1);
  });
}

const framing = (xfo, fa) => {
  const lines = [];
  if (xfo) lines.push(`X-Frame-Options: ${xfo}`);
  if (fa) lines.push(`Content-Security-Policy: default-src 'self'; frame-ancestors ${fa}`);
  return analyze(lines.length ? lines : ['X-Nothing: x']);
};

test('a permissive frame-ancestors stops X-Frame-Options from reading as clean', () => {
  const r = framing('DENY', '*');
  assert.equal(worstSeverity(r['x-frame-options']), S.OK);          // a note: the exposure is graded on CSP
  assert.ok(has(r['x-frame-options'].findings, 'replaced by the CSP'));
  assert.equal(worstSeverity(r['content-security-policy']), S.MEDIUM);
  for (const s of ["'none'", "'self'"]) assert.equal(worstSeverity(framing('DENY', s)['x-frame-options']), S.OK);
  assert.ok(!has(framing(null, '*')['x-frame-options'].findings, 'replaced by the CSP'));
});

test('a report-only CSP is called out on the CSP row', () => {
  const only = analyze(["Content-Security-Policy-Report-Only: default-src 'self'"])['content-security-policy'];
  assert.ok(has(only.findings, 'Only a report-only policy is present'));
  assert.equal(worstSeverity(only), S.MEDIUM);   // still missing
  const both = analyze(["Content-Security-Policy: default-src 'self'", "Content-Security-Policy-Report-Only: default-src 'none'"])['content-security-policy'];
  assert.ok(has(both.findings, 'report-only policy is also being tested'));
});

test('the extended profile holds exactly its 25 headers', () => {
  const ext = Object.keys(analyze(['X-Nothing: x'], PROFILES.extended)).sort();
  assert.deepEqual(ext, [
    'access-control-allow-credentials', 'access-control-allow-origin', 'cache-control', 'clear-site-data',
    'content-disposition', 'content-security-policy', 'content-type', 'cross-origin-embedder-policy', 'cross-origin-opener-policy',
    'cross-origin-resource-policy', 'etag', 'expect-ct', 'expires', 'origin-agent-cluster', 'permissions-policy',
    'pragma', 'referrer-policy', 'service-worker-allowed', 'strict-transport-security', 'x-content-type-options',
    'x-dns-prefetch-control', 'x-download-options', 'x-frame-options', 'x-permitted-cross-domain-policies',
    'x-xss-protection',
  ]);
});

// ------------------------------------------------------------------ Content-Type charset
const charsetOf = (value) => resultFor('Content-Type', value).findings;

test('Content-Type: HTML without a charset is LOW, settled: a <meta charset> does not replace the header', () => {
  for (const v of ['text/html', 'TEXT/HTML', 'text/html; charset=', 'text/html; charset=""', 'text/html; boundary=x']) {
    const fs = charsetOf(v);
    assert.equal(fs.length, 1, v);
    assert.equal(fs[0].severity, S.LOW, v);
    assert.equal(fs[0].status, HL.models.Status.MISCONFIGURED, v);
    assert.equal(fs[0].verify, '', v);
    assert.match(fs[0].recommendation, /charset=utf-8/, v);
    assert.match(fs[0].description, /meta charset/, v);
  }
});

test('Content-Type: a declared charset, or a type that is not HTML, is fine', () => {
  for (const v of ['text/html; charset=utf-8', 'text/html;charset=UTF-8', 'text/html; charset="utf-8"',
    'text/html; foo=bar; charset=iso-8859-1', 'application/json', 'image/png', 'text/plain', 'not a type']) {
    assert.ok(charsetOf(v).every((f) => f.severity === S.OK), v);
  }
});

test('Content-Type: several values resolve as Fetch "extract a MIME type" does', () => {
  // The last valid type wins and keeps an earlier charset for the same essence.
  assert.equal(charsetOf('text/html; charset=utf-8, text/html').every((f) => f.severity === S.OK), true);
  assert.ok(charsetOf('text/plain; charset=utf-8, text/html').some((f) => f.severity === S.LOW));
  assert.ok(charsetOf('text/html, */*').some((f) => f.severity === S.LOW));
  assert.ok(charsetOf('text/html; charset=utf-8, application/json').every((f) => f.severity <= S.LOW));
});

test('Content-Type: a charset browsers do not recognise counts as no charset', () => {
  for (const v of ['text/html; charset=foo', 'text/html; charset=utf-9', 'text/html; charset=utf_8', 'text/html; charset="unicode-2"']) {
    const fs = charsetOf(v);
    assert.equal(fs.length, 1, v);
    assert.equal(fs[0].severity, S.LOW, v);
    assert.match(fs[0].brief, /Unrecognised charset/, v);
    assert.equal(fs[0].verify, '', v);
  }
  // Labels from the WHATWG Encoding Standard, matched without case.
  for (const v of ['UTF8', 'latin1', 'Shift_JIS', 'iso-2022-jp', 'utf-16le', 'x-user-defined', 'unicode-1-1-utf-8', 'csiso2022kr']) {
    assert.ok(charsetOf(`text/html; charset=${v}`).every((f) => f.severity === S.OK), v);
  }
});

test('Content-Type: parameters are read as MIME Sniffing "parse a MIME type" reads them', () => {
  const ok = (v) => charsetOf(v).every((f) => f.severity === S.OK);
  assert.ok(ok('text/html; charset="utf-8"; x=y'));
  assert.ok(ok('text/html; charset="utf-8"trailing'));          // text after the closing quote is dropped
  assert.ok(ok('text/html; charset="ut\\f-8"'));                 // escapes are resolved
  assert.ok(ok('text/html; charset=; charset=utf-8'));           // an empty unquoted value is skipped
  assert.ok(!ok('text/html; charset=""; charset=utf-8'));        // an empty quoted value counts, and the first wins
  assert.ok(!ok('text/html; charset=foo; charset=utf-8'));       // the first occurrence wins
  assert.ok(ok('text /html'));                                   // not a valid type: not graded as HTML
});

// ------------------------------------------------------------------ RULES.md citations
test('RULES.md cites only known passages, and its citation list is up to date', async () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const rules = fs.readFileSync(path.join(__dirname, '..', 'RULES.md'), 'utf8');
  const ids = new Set(HL.sources.ids);
  for (const [, id] of rules.matchAll(/\]\[([^\]]+)\]/g)) assert.ok(ids.has(id), `RULES.md cites unknown source ${id}`);
  const { citationBlock, render, loadSources } = await import('../scripts/sources.mjs');
  assert.equal(render(rules, citationBlock(loadSources())), rules, 'run npm run sources');
});

test('CORS: credentials for a plain-HTTP origin are MEDIUM, settled; for https, LOW to confirm', () => {
  const run = (origin) => analyze([`Access-Control-Allow-Origin: ${origin}`, 'Access-Control-Allow-Credentials: true'])['access-control-allow-credentials'].findings;
  const http = run('http://app.example');
  assert.equal(worstSeverity({ findings: http }), S.MEDIUM);
  assert.ok(http.every((f) => !HL.models.isContingent(f)));
  const https = run('https://app.example');
  assert.equal(worstSeverity({ findings: https }), S.LOW);
  assert.ok(https.some((f) => HL.models.isContingent(f)));
});

test('Pragma never replaces Cache-Control: a missing Cache-Control says so when Pragma is sent', () => {
  for (const profile of [PROFILES.basic, PROFILES.extended]) {
    const withPragma = analyze(['Pragma: no-cache'], profile)['cache-control'].findings[0];
    assert.match(withPragma.description, /Pragma does not stand in for Cache-Control/);
    assert.ok(withPragma.sources.includes('rfc9111-pragma-response'));
    const without = analyze(['X-Nothing: x'], profile)['cache-control'].findings[0];
    assert.doesNotMatch(without.description, /Pragma/);
    assert.equal(withPragma.severity, without.severity);
  }
  // Pragma itself stays a note, never a finding (duplicates aside).
  const pragma = analyze(['Cache-Control: no-store', 'Pragma: no-cache'], PROFILES.extended).pragma.findings;
  assert.ok(pragma.every((f) => f.severity === S.OK));
});
