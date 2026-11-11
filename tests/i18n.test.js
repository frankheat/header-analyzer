'use strict';
/* The Italian interface: the same verdicts as English, every string translated. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { HL, ROOT } = require('./helpers');
const CASES = require('./cases');
require('node:vm').runInThisContext(fs.readFileSync(path.join(ROOT, 'src/ui/samples.js'), 'utf8'));

const IT = HL.i18n.localized('it');
const TEXT_FIELDS = ['title', 'description', 'brief', 'recommendation', 'verify', 'confirmIf', 'excludeIf'];
const CORPUS = [
  ...HL.samples.map((s) => s.text),
  'HTTP/1.1 200 OK\r\nX-Nothing: x\r\n\r\n',
  "HTTP/1.1 200 OK\r\nContent-Security-Policy: script-src * 'unsafe-inline' 'unsafe-eval' data: blob: http://a.example *.com *.github.io https://*.googleapis.com unpkg.com 'nonce-short' 'unsafe-hashes' self; script-src x; style-src 'unsafe-inline'; object-src 'self'; base-uri *; frame-ancestors *; default-src *; form-action *; scirpt-src x; referrer x; img-src 'none' x 'bogus'\r\n\r\n",
  'HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=1\r\nStrict-Transport-Security: max-age=2\r\nX-Frame-Options:\r\nExpect-CT: max-age=1\r\n\r\n',
  ...CASES.map(([h, v]) => `HTTP/1.1 200 OK\r\n${h}: ${v}\r\n\r\n`),
];

function* reports() {
  for (const text of CORPUS) for (const p of ['basic', 'extended']) for (const m of ['page', 'api']) {
    yield [HL.engine.analyze(text, p, m), IT.engine.analyze(text, p, m), `${p}/${m}: ${text.slice(17, 80)}`];
  }
}

test('English stays the default: HL itself is the English namespace', () => {
  assert.equal(HL.i18n.localized('en'), HL);
  assert.equal(HL.i18n.localized('xx'), HL);
  assert.equal(HL.i18n.localized('it'), IT);                       // built once
});

test('Italian reaches the same verdicts: same findings, severities, sources and checks', () => {
  for (const [en, it, where] of reports()) {
    assert.equal(it.ok, en.ok, where);
    if (!en.ok) continue;
    assert.deepEqual(it.summary, en.summary, where);
    assert.deepEqual(it.results.map((r) => r.key), en.results.map((r) => r.key), where);
    en.results.forEach((r, i) => {
      const fi = it.results[i].findings;
      assert.equal(fi.length, r.findings.length, `${where} ${r.key}`);
      r.findings.forEach((f, k) => {
        const g = fi[k];
        for (const key of ['severity', 'status', 'header']) assert.equal(g[key], f[key], `${where} ${f.title}`);
        assert.deepEqual(g.sources, f.sources, `${where} ${f.title}`);
        for (const key of TEXT_FIELDS) assert.equal(!!g[key], !!f[key], `${where} ${f.title}: ${key}`);
      });
    });
  }
});

test('every Italian text is translated', () => {
  // English function words, outside quoted values: a sign of a string left untranslated.
  const ENGLISH = /\b(the|is|and|with|this|not|which|that|are|from|only|any|does|must|cannot)\b/;
  const seen = new Set();
  for (const [, it, where] of reports()) {
    for (const n of it.notes || []) seen.add([where, n]);
    if (!it.ok) { seen.add([where, it.error]); continue; }
    for (const r of it.results) for (const f of r.findings) for (const key of TEXT_FIELDS) if (f[key]) seen.add([where, f[key]]);
  }
  for (const [where, text] of seen) {
    // Quoted values and hyphenated tokens (must-revalidate) are not prose; an
    // apostrophe after a letter is Italian (dell'utente), not a quote.
    const prose = text.replace(/(?<![\p{L}])'[^']*'|"[^"]*"|“[^”]*”/gu, '').replace(/[\w.]+(?:-[\w.]+)+/g, '').replace(/\b(ALLOW-FROM|all)\b/g, '');
    assert.ok(!ENGLISH.test(prose), `${where}: ${text}`);
    assert.ok(!text.includes('\u2014'), `${where}: ${text}`);
  }
});

test('the copied list uses the statuses of the report template', () => {
  const r = IT.engine.analyze('HTTP/1.1 200 OK\r\nX-Frame-Options:\r\nX-XSS-Protection: 1\r\n\r\n', 'basic', 'page');
  const texts = IT.engine.findingList(r).map((l) => l.text);
  assert.ok(texts.some((t) => /^Content-Security-Policy: Assente\. /.test(t)));
  assert.ok(texts.some((t) => /^X-Frame-Options: Configurazione non corretta\. /.test(t)));
  assert.ok(texts.some((t) => /^X-XSS-Protection: Deprecato\. /.test(t)));
  const pending = IT.engine.findingList(IT.engine.analyze('HTTP/1.1 200 OK\r\nCache-Control: max-age=60\r\n\r\n', 'basic', 'page'), { show: 'toConfirm' });
  assert.ok(pending.every((l) => l.text.includes('(da confermare)')));
});

test('the interface has every key in both languages', () => {
  const src = fs.readFileSync(path.join(ROOT, 'src/ui/app.js'), 'utf8');
  const start = src.indexOf('const UI_TEXT = {');
  const UI_TEXT = new Function(src.slice(start, src.indexOf('\n  };\n', start) + 5) + ' return UI_TEXT;')();
  const keys = (lang) => Object.keys(UI_TEXT[lang]).sort();
  assert.deepEqual(keys('it'), keys('en'));
  for (const key of keys('en')) assert.equal(typeof UI_TEXT.it[key], typeof UI_TEXT.en[key], key);
  const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
  for (const [, key] of html.matchAll(/data-i18n="([a-zA-Z]+)"/g)) assert.ok(keys('en').includes(key), key);
  for (const [, pairs] of html.matchAll(/data-i18n-attr="([^"]+)"/g)) {
    for (const pair of pairs.split(';')) assert.ok(keys('en').includes(pair.split(':')[1].trim()), pair);
  }
  for (const s of HL.samples) for (const lang of HL.i18n.LANGS) assert.ok(s.label[lang].name && s.label[lang].detail, `${s.id} ${lang}`);
});

test('the first visit follows the browser language; a saved choice wins', () => {
  const src = fs.readFileSync(path.join(ROOT, 'src/ui/app.js'), 'utf8');
  const fn = src.slice(src.indexOf('  function initialLang()'), src.indexOf('  /** The engine in the current language. */'));
  const initialLang = (language, languages, saved) => new Function('navigator', 'storage', 'HL', `${fn}; return initialLang();`)(
    { language, languages }, { get: () => saved }, { i18n: HL.i18n });
  assert.equal(initialLang('it-IT', ['en-US', 'en', 'it'], null), 'it');   // Chrome in Italian, English first for websites
  assert.equal(initialLang('en-US', ['it-IT', 'en'], null), 'it');
  assert.equal(initialLang('it', undefined, null), 'it');
  assert.equal(initialLang('en-US', ['en-US'], null), 'en');
  assert.equal(initialLang('fr-FR', ['fr-FR'], null), 'en');
  assert.equal(initialLang('it-IT', ['it'], 'en'), 'en');
  assert.equal(initialLang('en-US', ['en-US'], 'it'), 'it');
  assert.equal(initialLang('it-IT', ['it'], 'xx'), 'it');                   // an unknown saved value is ignored
});
