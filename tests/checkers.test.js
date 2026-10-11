'use strict';
/* Table-driven tests for the per-header checkers in src/core/rules.js. */
const test = require('node:test');
const assert = require('node:assert/strict');
const {
  Severity: S, isIssue, isContingent, analyze, findingsFor, severityFor, absent, has, withHsts,
  PP_TRACKING, PP_CLOSED, worstSeverity, HL,
} = require('./helpers');

const CASES = [
  // --- Strict-Transport-Security (absent: MEDIUM)
  ['Strict-Transport-Security', 'max-age=63072000; includeSubDomains', S.OK],
  ['Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload', S.OK],
  ['Strict-Transport-Security', 'MAX-AGE=63072000; INCLUDESUBDOMAINS', S.OK],
  ['Strict-Transport-Security', 'max-age = 63072000; includeSubDomains', S.OK],
  ['Strict-Transport-Security', 'max-age=00063072000; includeSubDomains', S.OK],
  ['Strict-Transport-Security', 'max-age=99999999999999999999999; includeSubDomains', S.OK],
  ['Strict-Transport-Security', 'max-age=63072000', S.LOW],                    // no includeSubDomains
  ['Strict-Transport-Security', 'max-age=31536000; includeSubDomains', S.LOW], // below 2 years
  ['Strict-Transport-Security', 'max-age=300; includeSubDomains', S.LOW],
  ['Strict-Transport-Security', 'max-age=0; includeSubDomains', S.MEDIUM],     // as absent
  ['Strict-Transport-Security', 'includeSubDomains', S.MEDIUM],                // invalid: as absent
  // --- X-Frame-Options (absent: MEDIUM)
  ['X-Frame-Options', 'DENY', S.OK],
  ['X-Frame-Options', 'deny', S.OK],
  ['X-Frame-Options', 'SAMEORIGIN', S.LOW],
  ['X-Frame-Options', 'ALLOW-FROM https://example.com', S.MEDIUM],
  ['X-Frame-Options', 'ALLOWALL', S.MEDIUM],
  ['X-Frame-Options', 'DENY, DENY', S.OK],
  ['X-Frame-Options', 'DENY, SAMEORIGIN', S.LOW],                              // contradiction
  ['X-Frame-Options', 'SAMEORIGIN, bogus', S.LOW],
  ['X-Frame-Options', 'bogus, garbage', S.MEDIUM],
  // --- X-Content-Type-Options (absent: LOW)
  ['X-Content-Type-Options', 'nosniff', S.OK],
  ['X-Content-Type-Options', 'NOSNIFF', S.OK],
  ['X-Content-Type-Options', 'sniff', S.LOW],
  ['X-Content-Type-Options', 'nosniff, foo', S.OK],
  ['X-Content-Type-Options', 'nosniff, nosniff', S.OK],
  ['X-Content-Type-Options', 'foo, nosniff', S.LOW],
  ['X-Content-Type-Options', '"nosniff"', S.LOW],
  // --- Cross-Origin-Opener-Policy (absent: LOW)
  ['Cross-Origin-Opener-Policy', 'same-origin', S.OK],
  ['Cross-Origin-Opener-Policy', 'same-origin-allow-popups', S.LOW],
  ['Cross-Origin-Opener-Policy', 'noopener-allow-popups', S.LOW],
  ['Cross-Origin-Opener-Policy', 'unsafe-none', S.LOW],
  ['Cross-Origin-Opener-Policy', 'same-origin; report-to="coop"', S.OK],
  ['Cross-Origin-Opener-Policy', 'bogus', S.LOW],
  ['Cross-Origin-Opener-Policy', 'same-origin-plus-COEP', S.LOW],
  ['Cross-Origin-Opener-Policy', 'same-origin;', S.LOW],
  ['Cross-Origin-Opener-Policy', 'same origin', S.LOW],
  ['Cross-Origin-Opener-Policy', 'same-origin, same-origin', S.LOW],
  ['Cross-Origin-Opener-Policy', 'Same-Origin', S.LOW],                         // tokens compare case-sensitively
  // --- Cross-Origin-Embedder-Policy (absent: LOW)
  ['Cross-Origin-Embedder-Policy', 'require-corp', S.OK],
  ['Cross-Origin-Embedder-Policy', 'credentialless', S.OK],
  ['Cross-Origin-Embedder-Policy', 'require-corp; report-to="coep"', S.OK],
  ['Cross-Origin-Embedder-Policy', 'unsafe-none', S.LOW],
  ['Cross-Origin-Embedder-Policy', 'bogus', S.LOW],
  ['Cross-Origin-Embedder-Policy', 'require-corp;', S.LOW],
  ['Cross-Origin-Embedder-Policy', 'require-corp, require-corp', S.LOW],
  ['Cross-Origin-Embedder-Policy', 'Require-Corp', S.LOW],
  // --- Cross-Origin-Resource-Policy (absent: LOW)
  ['Cross-Origin-Resource-Policy', 'same-origin', S.OK],
  ['Cross-Origin-Resource-Policy', 'same-site', S.OK],
  ['Cross-Origin-Resource-Policy', 'cross-origin', S.LOW],
  ['Cross-Origin-Resource-Policy', 'bogus', S.LOW],
  ['Cross-Origin-Resource-Policy', 'Same-Origin', S.LOW],
  // --- Referrer-Policy (absent: LOW)
  ['Referrer-Policy', 'no-referrer', S.OK],
  ['Referrer-Policy', 'strict-origin', S.OK],
  ['Referrer-Policy', 'strict-origin-when-cross-origin', S.OK],
  ['Referrer-Policy', 'origin', S.LOW],
  ['Referrer-Policy', 'origin-when-cross-origin', S.LOW],
  ['Referrer-Policy', 'same-origin', S.OK],
  ['Referrer-Policy', 'no-referrer-when-downgrade', S.LOW],
  ['Referrer-Policy', 'unsafe-url', S.LOW],
  ['Referrer-Policy', 'always', S.LOW],
  ['Referrer-Policy', 'bogus', S.LOW],
  ['Referrer-Policy', 'no-referrer, strict-origin-when-cross-origin', S.OK],
  ['Referrer-Policy', 'bogus, no-referrer', S.OK],
  ['Referrer-Policy', 'no-referrer,', S.OK],
  ['Referrer-Policy', 'strict-origin-when-cross-origin, unsafe-url', S.LOW],
  ['Referrer-Policy', 'unsafe-url, bogus', S.LOW],
  // --- X-Permitted-Cross-Domain-Policies (absent: LOW)
  ['X-Permitted-Cross-Domain-Policies', 'none', S.OK],
  ['X-Permitted-Cross-Domain-Policies', 'master-only', S.OK],
  ['X-Permitted-Cross-Domain-Policies', 'all', S.MEDIUM],                      // grants more than the plugin default
  ['X-Permitted-Cross-Domain-Policies', 'by-content-type', S.MEDIUM],
  ['X-Permitted-Cross-Domain-Policies', 'by-ftp-filename', S.MEDIUM],
  ['X-Permitted-Cross-Domain-Policies', 'bogus', S.LOW],
  // --- Clear-Site-Data (absent: LOW, to confirm)
  ['Clear-Site-Data', '"*"', S.OK],
  ['Clear-Site-Data', '"cache", "cookies", "storage"', S.OK],
  ['Clear-Site-Data', '"cookies"', S.LOW],
  ['Clear-Site-Data', '*', S.LOW],
  ['Clear-Site-Data', 'cookies', S.LOW],
  ['Clear-Site-Data', '"COOKIES"', S.LOW],
  ['Clear-Site-Data', '"bogus", "cookies"', S.LOW],
  // --- Permissions-Policy (absent: LOW)
  ['Permissions-Policy', PP_CLOSED, S.OK],
  ['Permissions-Policy', 'geolocation=()', S.LOW],
  ['Permissions-Policy', PP_CLOSED + ', camera=*', S.LOW],
  // --- Origin-Agent-Cluster (absent: LOW)
  ['Origin-Agent-Cluster', '?1', S.OK],
  ['Origin-Agent-Cluster', '?0', S.LOW],
  ['Origin-Agent-Cluster', '1', S.LOW],                                         // invalid: as absent
  ['Origin-Agent-Cluster', '?1;x', S.OK],
  // --- CORS (absence is correct)
  ['Access-Control-Allow-Origin', 'https://trusted.example.com', S.LOW],
  ['Access-Control-Allow-Origin', '*', S.LOW],
  ['Access-Control-Allow-Origin', 'null', S.MEDIUM],
  ['Access-Control-Allow-Origin', 'NULL', S.OK],                                 // matches no origin
  ['Access-Control-Allow-Origin', 'https://a.example.com, https://b.example.com', S.OK],
  ['Access-Control-Allow-Origin', 'http://app.example.com', S.LOW],
  ['Access-Control-Allow-Origin', 'http://localhost:3000', S.LOW],
  ['Access-Control-Allow-Origin', 'HTTP://APP.EXAMPLE.COM', S.LOW],
  ['Access-Control-Allow-Credentials', 'false', S.OK],
  ['Access-Control-Allow-Credentials', 'true', S.OK],                           // no ACAO: no effect
  // --- X-DNS-Prefetch-Control (absent: LOW, to confirm)
  ['X-DNS-Prefetch-Control', 'off', S.OK],
  ['X-DNS-Prefetch-Control', 'on', S.LOW],
  // --- Extended-only headers
  ['Service-Worker-Allowed', '/', S.LOW],
  ['Service-Worker-Allowed', '/app/', S.OK],
  ['Content-Disposition', 'attachment; filename=x.pdf', S.OK],
  ['Content-Disposition', 'inline', S.OK],
  ['Content-Disposition', 'bogus', S.OK],
  ['Pragma', 'no-cache', S.OK],
  ['Expires', '0', S.OK],
  ['Expires', '-1', S.OK],
  ['Expires', 'Wed, 21 Oct 2026 07:28:00 GMT', S.OK],
  ['ETag', 'W/"abc"', S.OK],
  ['ETag', '"abc"', S.OK],
  ['X-Download-Options', 'noopen', S.LOW],                                       // obsolete IE header
  ['X-Download-Options', 'open', S.LOW],
  // --- Deprecated
  ['X-XSS-Protection', '0', S.OK],
  ['X-XSS-Protection', '1; mode=block', S.LOW],
  ['X-XSS-Protection', '1', S.LOW],
  ['X-XSS-Protection', '1; report=/x', S.LOW],
  ['X-XSS-Protection', '0; mode=block', S.OK],
  ['X-XSS-Protection', 'report=1; mode=block', S.LOW],
  ['X-XSS-Protection', 'banana', S.LOW],
  ['Expect-CT', 'max-age=86400, enforce', S.LOW],
];

for (const [header, value, expected] of CASES) {
  test(`${header}: ${value.slice(0, 60)} → ${expected}`, () => {
    assert.equal(severityFor(header, value), expected);
  });
}

function* everyFinding() {
  for (const [h, v] of CASES) yield [`${h}: ${v}`, findingsFor(h, v)];
  for (const r of Object.values(analyze(['X-Nothing: x']))) yield [`missing ${r.name}`, r.findings];
}

test('a finding never carries both a check and a recommendation', () => {
  for (const [where, fs] of everyFinding()) for (const f of fs) assert.ok(!(f.verify && f.recommendation), `${where}: ${f.title}`);
});

test('every check asks something the reader can answer', () => {
  for (const [where, fs] of everyFinding()) {
    for (const f of fs) {
      if (!f.verify) continue;
      assert.ok(f.verify.length > 80, `${where}: ${f.title}`);
      assert.ok(f.verify.includes('?') || f.verify.startsWith('Replay') || f.verify.startsWith('Request'), `${where}: ${f.title}`);
    }
  }
});

test('every present header produces at least one finding', () => {
  for (const [h, v] of CASES) assert.ok(findingsFor(h, v).length, `${h}: ${v}`);
});

test('a settled finding claims the response is enough', () => {
  assert.equal(findingsFor('Strict-Transport-Security', 'max-age=300')[0].verify, '');
  assert.equal(absent('content-security-policy').findings[0].verify, '');
});

// ------------------------------------------------------------------ HSTS
test('HSTS reports each problem separately', () => {
  const fs = findingsFor('Strict-Transport-Security', 'max-age=300');
  assert.ok(has(fs, 'max-age too short') && has(fs, 'missing includeSubDomains'));
});

test('HSTS threshold follows the profile', () => {
  assert.equal(severityFor('Strict-Transport-Security', 'max-age=600; includeSubDomains', withHsts({ minMaxAge: 300 })), S.OK);
});

test('HSTS preload is only asked about when the profile asks', () => {
  const v = 'max-age=63072000; includeSubDomains';
  assert.equal(severityFor('Strict-Transport-Security', v), S.OK);
  assert.ok(has(findingsFor('Strict-Transport-Security', v, withHsts({ requirePreload: true })), 'preload is not declared'));
});

for (const [value, title] of [
  ['max-age=63072000; includeSubDomains', 'preload is not declared'],
  ['max-age=63072000; includeSubDomains; preload', 'not the same as being on the list'],
]) {
  test(`HSTS preload is contingent either way: ${title}`, () => {
    const f = findingsFor('Strict-Transport-Security', value, withHsts({ requirePreload: true })).find((x) => x.title.includes('preload'));
    assert.equal(f.severity, S.LOW);
    assert.ok(isContingent(f));
    assert.ok(f.verify.includes('hstspreload.org'));
  });
}

for (const value of ['max-age=63072000; includeSubDomainss', 'max-age=63072000; xincludeSubDomains', 'max-age=63072000; report-uri=https://x/includeSubDomains']) {
  test(`HSTS only accepts the real directive name: ${value}`, () => {
    assert.ok(has(findingsFor('Strict-Transport-Security', value), 'missing includeSubDomains'));
  });
}

for (const [value, reason] of [
  ['max-age=1; max-age=63072000', 'appears more than once'],
  ['max-age=63072000; includeSubDomains; includeSubDomains', 'appears more than once'],
  ['max-age=63072000; includeSubDomains=true', 'must not be given a value'],
  ['max-age=63072000; preload=1', 'must not be given a value'],
  ['max-age=63072000; includeSubDomains=', 'must not be given a value'],   // "=" with no value
  ['max-age=63072000; preload=', 'must not be given a value'],
  ['max-age=forever', 'must be a number of seconds'],
  ['max-age=-1', 'must be a number of seconds'],
  ['max-age=', 'must be a number of seconds'],
  ['includeSubDomains', 'required max-age directive is missing'],
]) {
  test(`a non-conforming HSTS header is graded as absent: ${value}`, () => {
    const fs = findingsFor('Strict-Transport-Security', value);
    assert.equal(fs[0].severity, worstSeverity(absent('strict-transport-security')));
    assert.ok(has(fs, 'the header is not valid') && has(fs, reason));
  });
}

test('HSTS names the offending directive as it is spelled', () => {
  assert.ok(has(findingsFor('Strict-Transport-Security', 'max-age=1; includeSubDomains=true'), 'includeSubDomains must not be given a value'));
});

test('HSTS ignores unrecognised directives and accepts a quoted max-age', () => {
  assert.equal(severityFor('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; some-future-directive'), S.OK);
  assert.equal(severityFor('Strict-Transport-Security', 'max-age="63072000"; includeSubDomains'), S.OK);
});

for (const value of ['max-age=0', 'max-age=0; includeSubDomains']) {
  test(`HSTS max-age=0 is the only verdict: ${value}`, () => {
    const fs = findingsFor('Strict-Transport-Security', value);
    assert.equal(fs.length, 1);
    assert.ok(has(fs, 'revokes HSTS protection'));
  });
}

test('HSTS max-age=0 tracks the absent severity', () => {
  assert.equal(severityFor('Strict-Transport-Security', 'max-age=0'), worstSeverity(absent('strict-transport-security')));
});

test('missing includeSubDomains is settled and names the cookie mechanism', () => {
  const f = findingsFor('Strict-Transport-Security', 'max-age=63072000').find((x) => x.title.includes('includeSubDomains'));
  assert.equal(f.severity, S.LOW);
  assert.ok(!isContingent(f));
  assert.ok(f.description.includes('no subdomains at all is not exempt'));
  assert.ok(f.description.includes('Domain=example.com'));
});

// --------------------------------------------------------- X-Frame-Options
for (const value of ['ALLOW-FROM https://partner.example', 'ALLOWALL', 'bogus']) {
  test(`an X-Frame-Options value no browser applies weighs like absence: ${value}`, () => {
    const fs = findingsFor('X-Frame-Options', value);
    assert.equal(fs[0].severity, worstSeverity(absent('x-frame-options')));
    assert.ok(fs[0].title.includes('framable by anyone'));
  });
}

for (const value of ['DENY, SAMEORIGIN', 'SAMEORIGIN, bogus', 'ALLOWALL, DENY', 'DENY,']) {
  test(`an X-Frame-Options contradiction is LOW, never graded as framable: ${value}`, () => {
    const fs = findingsFor('X-Frame-Options', value);
    assert.equal(fs[0].severity, S.LOW);
    assert.ok(fs[0].title.includes('contradicting itself'));
  });
}

test('SAMEORIGIN asks whether the page needs framing', () => {
  const f = findingsFor('X-Frame-Options', 'SAMEORIGIN')[0];
  assert.ok(isContingent(f));
  assert.ok(f.verify.includes('DENY costs nothing'));
  assert.ok(f.description.includes('every containing document'));
});

// ------------------------------------------------------------------ nosniff
test('nosniff is read from the first value only and not in quoted form', () => {
  assert.equal(severityFor('X-Content-Type-Options', 'nosniff , x'), S.OK);
  assert.notEqual(severityFor('X-Content-Type-Options', 'x, nosniff'), S.OK);
  assert.notEqual(severityFor('X-Content-Type-Options', '"nosniff"'), S.OK);
});

test('nosniff off tracks the absent severity and says what is left on', () => {
  assert.equal(severityFor('X-Content-Type-Options', 'sniff'), worstSeverity(absent('x-content-type-options')));
  const f = findingsFor('X-Content-Type-Options', 'sniff')[0];
  assert.ok(f.title.includes('leaves MIME sniffing on') && f.description.includes('uploaded'));
});

// -------------------------------------------------------------- COOP / COEP
for (const value of ['same-origin; report-to="coop-endpoint"', 'same-origin;report-to=coop', 'same-origin; report-to="a;b"']) {
  test(`COOP parameters do not change the policy: ${value}`, () => {
    assert.equal(severityFor('Cross-Origin-Opener-Policy', value), S.OK);
  });
}

for (const [value, reason] of [
  ['bogus', 'is not a policy browsers recognize'],
  ['restrict-properties', 'is not a policy browsers recognize'],
  ['same-origin-plus-COEP', 'cannot be set through this header'],
  ['same origin', 'is not a valid header value'],
  ['"same-origin"', 'is not a valid header value'],
  ['same-origin;', 'is not a valid header value'],
  ['same-origin; =x', 'is not a valid header value'],
]) {
  test(`COOP value a browser cannot apply is graded as absent: ${value}`, () => {
    const fs = findingsFor('Cross-Origin-Opener-Policy', value);
    assert.equal(fs[0].severity, worstSeverity(absent('cross-origin-opener-policy')));
    assert.ok(has(fs, 'the header is not applied') && has(fs, reason));
  });
}

test('COOP explains case-sensitivity when the wrong case is used', () => {
  assert.ok(findingsFor('Cross-Origin-Opener-Policy', 'Same-Origin')[0].description.includes('case-sensitive'));
});

test('COOP same-origin-plus-COEP says how to get it', () => {
  assert.ok(findingsFor('Cross-Origin-Opener-Policy', 'same-origin-plus-COEP')[0].recommendation.includes('require-corp'));
});

for (const value of ['same-origin-allow-popups', 'noopener-allow-popups']) {
  test(`COOP ${value} reaches the worklist and asks about window.open()`, () => {
    const f = findingsFor('Cross-Origin-Opener-Policy', value)[0];
    assert.ok(isIssue(f.severity));
    assert.ok(f.description.includes('window.opener'));
    assert.ok(f.verify.includes('window.open()') && f.verify.includes('same-origin'));
  });
}

test('COOP unusable value follows the absent severity', () => {
  assert.equal(severityFor('Cross-Origin-Opener-Policy', 'bogus'), worstSeverity(absent('cross-origin-opener-policy')));
});

test('COEP not having it fails safe; credentialless is not weaker', () => {
  assert.ok(findingsFor('Cross-Origin-Embedder-Policy', 'unsafe-none')[0].description.includes('fails safe'));
  const f = findingsFor('Cross-Origin-Embedder-Policy', 'credentialless')[0];
  assert.equal(f.recommendation, '');
  assert.ok(f.description.includes('not a weaker one'));
  assert.ok(findingsFor('Cross-Origin-Embedder-Policy', 'require-corp')[0].description.includes('Cross-Origin-Opener-Policy: same-origin'));
});

// -------------------------------------------------------- Permissions-Policy
const pp = (v) => findingsFor('Permissions-Policy', v);
const ppAxis = (v, axis) => pp(v).filter((f) => f.title.includes(axis));

test('Permissions-Policy is graded on two axes, both LOW and to confirm', () => {
  const issues = pp('payment=()').filter((f) => isIssue(f.severity));
  assert.equal(issues.length, 2);
  assert.ok(issues.some((f) => f.title.includes('an XSS on this origin')));
  assert.ok(issues.some((f) => f.title.includes('reachable by an embedded document')));
  for (const f of issues) assert.ok(f.severity === S.LOW && isContingent(f));
});

for (const feature of ['camera', 'microphone', 'geolocation']) {
  test(`(self) does not close ${feature} to an XSS`, () => {
    assert.ok(has(pp(`${feature}=(self)`), 'an XSS on this origin'));
  });
}

test('(self) does close the tracking features to an embed', () => {
  assert.equal(ppAxis(PP_TRACKING.map((f) => `${f}=(self)`).join(', '), 'embedded document').length, 0);
});

for (const feature of PP_TRACKING) {
  test(`tracking feature ${feature} is reported when left open`, () => {
    const embed = ppAxis(PP_TRACKING.filter((f) => f !== feature).map((f) => `${f}=()`).join(', '), 'embedded document');
    assert.equal(embed.length, 1);
    assert.ok(embed[0].title.endsWith(feature));
  });
}

test('the embed finding is not diluted with harmless features', () => {
  const f = ppAxis('payment=()', 'embedded document')[0];
  for (const noise of ['gamepad', 'picture-in-picture', 'deferred-fetch-minimal']) {
    assert.ok(!f.title.includes(noise) && f.description.includes(noise));
  }
});

test('an absent policy weighs the same as one that closes nothing', () => {
  assert.equal(worstSeverity(absent('permissions-policy')), Math.max(...pp('payment=()').filter((f) => isIssue(f.severity)).map((f) => f.severity)));
  const f = absent('permissions-policy').findings[0];
  assert.ok(f.description.includes('browsing-topics') && f.description.includes('camera'));
  assert.ok(f.recommendation.includes('storage-access=()') && f.recommendation.includes('camera=()'));
});

for (const [value, reason] of [
  ['Camera=(), Microphone=()', 'lowercase'], ['camera=(),', 'ends with a comma'],
  ['camera=() microphone=()', 'not followed by a comma'], ['camera=(self', 'closing parenthesis'],
  ['camera=("https://a.example)', 'closing quote'], ["camera 'none'; microphone 'none'", 'not followed by a comma'],
]) {
  test(`an unparseable Permissions-Policy is graded as absent: ${value}`, () => {
    const fs = pp(value);
    assert.equal(fs.length, 1);
    assert.ok(fs[0].title.includes('the header is not valid') && fs[0].title.includes(reason));
    assert.equal(fs[0].severity, worstSeverity(absent('permissions-policy')));
  });
}

for (const value of ['camera=5, microphone=()', 'camera, microphone=()', 'camera=?1, microphone=()', 'camera=bogus, microphone=()']) {
  test(`a member of the wrong form is dropped alone: ${value}`, () => {
    const fs = pp(value);
    const note = fs.find((f) => f.title.includes('dropped by the browser'));
    assert.equal(note.severity, S.LOW);
    assert.ok(note.title.includes('camera'));
    const xss = fs.find((f) => f.title.includes('could ask for'));
    assert.ok(xss.title.includes('camera') && !xss.title.includes('microphone'));
  });
}

test('parameters do not hide the allowlist', () => {
  assert.deepEqual(pp('camera=*;report-to=endpoint').map((f) => f.title), pp('camera=*').map((f) => f.title));
  assert.ok(!has(pp('camera=();report-to=endpoint'), 'could ask for camera'));
});

test('an origin must be quoted to count', () => {
  const embed = (fs) => fs.find((f) => f.title.includes('embedded document'));
  assert.ok(!embed(pp('storage-access=(self https://a.example)')).title.includes('storage-access'));
  assert.ok(embed(pp('storage-access=(self "https://a.example")')).title.includes('storage-access'));
});

test('delegation to a named origin for one-click features is reported and asks', () => {
  for (const feature of ['camera', 'microphone', 'geolocation']) {
    const fs = pp(`${feature}=("https://ads.example")`);
    const d = fs.find((f) => f.title.includes('handed to another origin'));
    assert.equal(d.severity, S.LOW);
    assert.ok(d.title.includes('https://ads.example') && isContingent(d) && d.recommendation === '');
    assert.ok(!has(fs, `could ask for ${feature}`));
  }
  assert.ok(has(pp('camera=(self "https://ads.example")'), 'handed to another origin'));
  for (const v of ['camera=*', 'camera=(* "https://ads.example")']) assert.ok(!has(pp(v), 'handed to another origin'));
  for (const v of ['payment=("https://checkout.example")', 'camera=()', 'camera=(self)']) assert.ok(!has(pp(v), 'handed to another origin'));
});

test('a repeated directive keeps the last', () => {
  assert.ok(!has(pp('camera=*, camera=()'), 'opened to any origin'));
  assert.ok(has(pp('camera=(), camera=*'), 'opened to any origin: camera'));
});

test('a wildcard is read from the allowlist, not by substring', () => {
  assert.equal(severityFor('Permissions-Policy', PP_CLOSED + ', x-payment=*'), S.OK);
  assert.equal(severityFor('Permissions-Policy', PP_CLOSED + ', payment=*'), S.LOW);
  assert.equal(severityFor('Permissions-Policy', PP_CLOSED + ', payment=(self)'), S.OK);
  assert.equal(severityFor('Permissions-Policy', PP_CLOSED + ', payment=("https://a.example,https://b.example")'), S.OK);
});

// ------------------------------------------------------------ Cache-Control
const CACHE = [
  ['no-store', S.OK], ['private', S.LOW], ['private, max-age=600', S.LOW], ['no-cache', S.LOW],
  ['max-age=0, must-revalidate', S.LOW], ['surrogate-control=xyz', S.LOW],
  // Grants a shared cache more than heuristic caching would: MEDIUM.
  ['max-age=600', S.MEDIUM], ['s-maxage=600', S.MEDIUM], ['public, max-age=600', S.MEDIUM],
  ['no-cache="Set-Cookie"', S.MEDIUM], ['private="X-Custom"', S.MEDIUM],
];
for (const [value, expected] of CACHE) {
  test(`Cache-Control: ${value} → ${expected}`, () => assert.equal(severityFor('Cache-Control', value), expected));
}

test('every caching verdict but no-store carries the same single question', () => {
  const checks = new Set();
  for (const [v, sev] of CACHE) {
    const f = findingsFor('Cache-Control', v)[0];
    assert.equal(isContingent(f), sev !== S.OK);
    if (sev !== S.OK) checks.add(f.verify);
  }
  checks.add(absent('cache-control').findings[0].verify);
  assert.equal(checks.size, 1);
  const q = [...checks][0];
  for (const w of ['session cookie', 'Authorization header', 'public', 's-maxage', 'must-revalidate']) assert.ok(q.includes(w));
});

test('a token merely containing a directive name is unrecognised; quoted commas do not split', () => {
  assert.ok(has(findingsFor('Cache-Control', 'x-no-store-hack'), 'no directive a cache understands'));
  assert.ok(findingsFor('Cache-Control', 'no-cache="X-A,X-B"')[0].description.includes('X-A,X-B'));
  assert.equal(severityFor('Cache-Control', 'max-age=600, zzz-bogus'), S.MEDIUM);
});

// ----------------------------------------------------------- Clear-Site-Data
test('Clear-Site-Data: quotes are part of the value; unknown types are skipped', () => {
  assert.ok(findingsFor('Clear-Site-Data', '*')[0].title.includes('clears nothing'));
  for (const v of ['cookies', '"COOKIES"', '"bogus"', 'cache, cookies']) assert.ok(findingsFor('Clear-Site-Data', v)[0].title.includes('clears nothing'));
  const f = findingsFor('Clear-Site-Data', '"bogus", "cookies"')[0];
  assert.ok(f.title.includes('missing directives') && !f.title.includes('"cookies"'));
  assert.equal(severityFor('Clear-Site-Data', '"cache", "cookies", "storage", "executionContexts", "prefetchCache", "prerenderCache"'), S.OK);
  for (const v of ['"prefetchCache"', '"prerenderCache"', '"clientHints"']) assert.ok(findingsFor('Clear-Site-Data', v)[0].title.includes('missing directives'));
});

test('every Clear-Site-Data verdict asks whether the session ends here', () => {
  for (const f of [absent('clear-site-data').findings[0], findingsFor('Clear-Site-Data', '*')[0], findingsFor('Clear-Site-Data', '"cookies"')[0]]) {
    assert.ok(isContingent(f) && f.verify.includes('ends a session'));
  }
  assert.ok(!isContingent(findingsFor('Clear-Site-Data', '"*"')[0]));
  assert.equal(worstSeverity(absent('clear-site-data')), S.LOW);
  assert.equal(severityFor('Clear-Site-Data', '*'), S.LOW);
});

// ----------------------------------------------------------------- CORS etc
test('ACAO single origin: LOW to confirm, and the check names the replay', () => {
  const f = findingsFor('Access-Control-Allow-Origin', 'https://app.example.com')[0];
  assert.equal(f.severity, S.LOW);
  assert.ok(isContingent(f));
  for (const w of ['Origin: https://an-origin-you-made-up.example', 'comes back', 'nothing here', 'https://app.example.com']) assert.ok(f.verify.includes(w));
});

test('ACAO wildcard names the case that matters', () => {
  const f = findingsFor('Access-Control-Allow-Origin', '*')[0];
  assert.ok(f.description.includes("not by an attacker's server") && f.verify.includes('reachable'));
});

test('X-XSS-Protection reads the flag, not any digit', () => {
  assert.ok(has(findingsFor('X-XSS-Protection', '1'), 'enables the deprecated XSS filter'));
  assert.ok(findingsFor('X-XSS-Protection', '1; mode=block')[0].description.includes('observable from another origin'));
  assert.equal(severityFor('X-XSS-Protection', '0;'), S.OK);
});

test('Content-Disposition type is the first token', () => {
  assert.equal(severityFor('Content-Disposition', 'attachment; filename="inline.pdf"'), S.OK);
  assert.equal(severityFor('Content-Disposition', 'attachmentx'), S.OK);
});

test('Referrer-Policy: unrecognised value explains the fallback and tracks absence', () => {
  const f = findingsFor('Referrer-Policy', 'bogus')[0];
  assert.ok(f.description.includes('falls back to its own default') && f.recommendation.includes('no-referrer-when-downgrade'));
  assert.equal(severityFor('Referrer-Policy', 'bogus, nonsense'), worstSeverity(absent('referrer-policy')));
  const m = absent('referrer-policy').findings[0];
  assert.ok(m.description.includes('strict-origin-when-cross-origin') && m.description.includes('does not control'));
});

for (const value of ['origin', 'origin-when-cross-origin']) {
  test(`Referrer-Policy ${value} asks for a check`, () => {
    const f = findingsFor('Referrer-Policy', value)[0];
    assert.ok(isIssue(f.severity) && isContingent(f) && f.verify.includes('plain-HTTP'));
  });
}

test('every finding the table produces has a list status and a short brief', () => {
  for (const [where, fs] of everyFinding()) {
    for (const f of fs) {
      if (f.severity === S.OK || f.status === '') continue;
      assert.ok(['Missing', 'Misconfigured', 'Duplicated', 'Deprecated'].includes(f.status), `${where}: ${f.title}`);
      assert.ok(f.brief && f.brief.length <= 72 && !f.brief.endsWith('.'), `${where}: ${f.title}: "${f.brief}"`);
    }
  }
});

// ------------------------------------------------------------ grading rules
// A value never weighs more than the header's absence (a weak policy is not
// worse than none) unless it grants more than the browser default. These are
// the only two headers where that happens.
const GRANTS_MORE_THAN_DEFAULT = new Set([
  'cache-control',                       // public / max-age: a shared cache may now store it
  'x-permitted-cross-domain-policies',   // all / by-content-type: plugins may now load policies
]);

test('a value never weighs more than the absence of its header (except where it grants more)', () => {
  const absence = Object.fromEntries(HL.rules.SECURITY_HEADERS.map(([key, , sev]) => [key, sev]));
  for (const [header, value] of CASES) {
    const key = header.toLowerCase();
    if (absence[key] === null || GRANTS_MORE_THAN_DEFAULT.has(key)) continue;
    assert.ok(severityFor(header, value) <= absence[key], `${header}: ${value}`);
  }
});

test('the exceptions really are the only headers that exceed their absence', () => {
  const absence = Object.fromEntries(HL.rules.SECURITY_HEADERS.map(([key, , sev]) => [key, sev]));
  for (const key of GRANTS_MORE_THAN_DEFAULT) {
    const header = HL.rules.SECURITY_HEADERS.find(([k]) => k === key)[1];
    const cases = [...CASES, ...CACHE.map(([v]) => ['Cache-Control', v])];
    assert.ok(cases.some(([h, v]) => h === header && severityFor(h, v) > absence[key]), key);
  }
});

test('a note (OK) is never listed and never counted as a problem', () => {
  for (const [header, value] of CASES) {
    const report = HL.engine.analyze(`HTTP/1.1 200 OK\r\n${header}: ${value}\r\n\r\n`, 'extended');
    for (const line of HL.engine.findingList(report)) {
      assert.ok(line.items.every((it) => it.severity !== 'OK'), `${header}: ${value}`);
    }
    for (const r of report.results) {
      if (r.findings.every((f) => f.severity === S.OK)) assert.equal(worstSeverity(r), S.OK);
    }
    assert.equal(report.summary.settled.OK + report.summary.toConfirm.OK, 0);
  }
});

// ------------------------------------------------------------------ sources
// Every finding that explains, recommends or asks something carries the
// passages that back it, and every passage resolves to a citation.
const EXTRA_RESPONSES = [
  "Content-Security-Policy: script-src 'nonce-abc' 'strict-dynamic' https: 'unsafe-inline' 'unsafe-hashes' 'sha256-x'; object-src https:; base-uri *; frame-ancestors *; default-src *; form-action *; style-src 'unsafe-inline'",
  "Content-Security-Policy: script-src *.com *.googleapis.com *.github.io ajax.googleapis.com http://cdn.example.com blob: data: 'unsafe-eval' 'self' self 'nonce' 'unknown' 'none'; scirpt-src x; script-src y; prefetch-src x; navigate-to x; plugin-types x; reflected-xss x; referrer x; disown-opener x; require-sri-for x; block-all-mixed-content",
  "Content-Security-Policy: default-src https:; script-src 'strict-dynamic'\r\nContent-Security-Policy: object-src 'none'",
  'Content-Security-Policy-Report-Only: default-src none',
  "Content-Security-Policy: frame-ancestors *\r\nX-Frame-Options: DENY",
  "Access-Control-Allow-Origin: null\r\nAccess-Control-Allow-Credentials: true",
  "Access-Control-Allow-Origin: https://a.example\r\nAccess-Control-Allow-Credentials: true",
  "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true",
  "Access-Control-Allow-Origin: NULL\r\nAccess-Control-Allow-Credentials: true",
  "Access-Control-Allow-Origin: a, b\r\nAccess-Control-Allow-Credentials: true",
  'Access-Control-Allow-Credentials: true',
  'Strict-Transport-Security: max-age=1\r\nStrict-Transport-Security: max-age=2\r\nX-Frame-Options: DENY\r\nX-Frame-Options: DENY',
  'Cross-Origin-Resource-Policy: same-origin\r\nCross-Origin-Resource-Policy: same-origin\r\nExpect-CT: a\r\nExpect-CT: b',
  'X-Permitted-Cross-Domain-Policies: none-this-response',
  'Origin-Agent-Cluster: ?0',
  'Content-Type: text/html; charset=foo',
  'Content-Type: application/json',
  'X-Nothing: x',
];

function allFindings() {
  const texts = [
    ...CASES.map(([h, v]) => `HTTP/1.1 200 OK\r\n${h}: ${v}\r\n\r\n`),
    ...CACHE.map(([v]) => `HTTP/1.1 200 OK\r\nCache-Control: ${v}\r\n\r\n`),
    ...EXTRA_RESPONSES.map((t) => `HTTP/1.1 200 OK\r\n${t}\r\n\r\n`),
    'HTTP/1.1 302 Found\r\nX-Nothing: x\r\n\r\n',
  ];
  const out = [];
  for (const t of texts) {
    for (const p of ['basic', 'extended']) out.push(...HL.engine.analyze(t, p).results.flatMap((r) => r.findings));
  }
  return out;
}

test('every finding that says something cites the passages behind it', () => {
  for (const f of allFindings()) {
    if (!f.description && !f.verify && !f.recommendation) continue;
    assert.ok(f.sources.length > 0, `${f.title} has no source`);
    for (const id of f.sources) assert.ok(HL.sources.cite(id).quote, id);
  }
});

test('every citation links to a highlighted passage or a pinned line range', () => {
  for (const id of HL.sources.ids) {
    const c = HL.sources.cite(id);
    assert.match(c.url, /^https:\/\/[^\s#]+#(:~:text=[^\s#]+|L\d+-L\d+)$/, id);
    assert.ok(c.title && c.quote, id);
    if (c.url.includes('github.com') && c.url.includes('#L')) assert.match(c.url, /\/blob\/[0-9a-f]{40}\//, `${id} is pinned to a commit`);
    // A text directive term must not carry an unescaped '-', ',' or '&'.
    const directive = c.url.split(':~:text=')[1];
    if (directive) for (const termText of directive.split(',')) assert.doesNotMatch(termText, /[-&]/, id);
  }
});

test('every citation is used by a finding or by RULES.md', () => {
  const used = new Set(allFindings().flatMap((f) => f.sources));
  const rules = require('node:fs').readFileSync(require('node:path').join(__dirname, '..', 'RULES.md'), 'utf8');
  for (const id of HL.sources.ids) assert.ok(used.has(id) || rules.includes(`][${id}]`), `${id} is never cited`);
});
