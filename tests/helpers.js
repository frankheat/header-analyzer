'use strict';
/*
 * Loads the engine exactly as the page does (the classic scripts listed in
 * index.html, in that order) and exposes the helpers the tests share.
 */
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.join(__dirname, '..');

function coreScripts() {
  const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
  return [...html.matchAll(/<script src="([^"]+)"><\/script>/g)]
    .map((m) => m[1])
    .filter((src) => src.startsWith('src/core/'));
}

if (!globalThis.HeaderAnalyzer || !globalThis.HeaderAnalyzer.engine) {
  for (const src of coreScripts()) {
    vm.runInThisContext(fs.readFileSync(path.join(ROOT, src), 'utf8'), { filename: src });
  }
}
const HL = globalThis.HeaderAnalyzer;
const { Severity, worstSeverity, isContingent, isIssue } = HL.models;

// Every built-in header and the HSTS defaults: the
// equivalent of the original tool's empty configuration.
const ALL = Object.freeze({
  id: 'test', name: 'Test',
  skip: new Set(),
  hsts: { minMaxAge: 63072000, requireIncludeSubdomains: true, requirePreload: false },
});

function withHsts(hsts) {
  return { ...ALL, hsts: { ...ALL.hsts, ...hsts } };
}

function buildResponse(lines, status = 'HTTP/1.1 200 OK') {
  return [status, ...lines].join('\r\n') + '\r\n\r\n';
}

/** Full pipeline on header lines; results keyed by lowercase header name. */
function analyze(lines, profile = ALL) {
  const parsed = HL.parser.parseResponse(buildResponse(Array.isArray(lines) ? lines : [lines]));
  const headers = HL.parser.headerMap(parsed.response);
  const results = HL.rules.analyzeHeaders(headers, profile);
  return Object.fromEntries(results.map((r) => [r.key, r]));
}

const resultFor = (header, value, profile) => analyze([`${header}: ${value}`], profile)[header.toLowerCase()];
const findingsFor = (header, value, profile) => resultFor(header, value, profile).findings;
const severityFor = (header, value, profile) => worstSeverity(resultFor(header, value, profile));
const absent = (key, profile) => analyze(['X-Nothing: x'], profile)[key];
const has = (findings, sub) => findings.some((f) => f.title.includes(sub));

const PP_TRACKING = [
  'attribution-reporting', 'browsing-topics', 'ch-ua-high-entropy-values',
  'private-state-token-issuance', 'private-state-token-redemption', 'storage-access',
];
const PP_ONE_CLICK = ['camera', 'microphone', 'geolocation'];
const PP_CLOSED = [...PP_TRACKING, ...PP_ONE_CLICK].map((f) => `${f}=()`).join(', ');

module.exports = {
  HL, ROOT, Severity, worstSeverity, isContingent, isIssue,
  ALL, withHsts, buildResponse, analyze, resultFor, findingsFor, severityFor, absent, has,
  PP_TRACKING, PP_ONE_CLICK, PP_CLOSED, coreScripts,
};
