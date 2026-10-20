/*
 * Header Analyzer: the two fixed profiles.
 *
 * Profiles are not user-editable by design: a report is only comparable with
 * another if both were produced by the same rules. A profile chooses which
 * headers are in scope and a few thresholds; it never changes how a header is
 * read, and it cannot change a severity the engine derives from the response.
 */
(function (HL) {
  'use strict';

  // Clear-Site-Data belongs on a logout, not on every response, so it is a
  // check for Extended only (RULES.md notes the deviation from Basic's sources).
  const EXTENDED_ONLY = [
    'clear-site-data', 'origin-agent-cluster', 'service-worker-allowed', 'content-disposition',
    'pragma', 'expires', 'etag', 'x-download-options',
  ];

  const PROFILES = Object.freeze({
    basic: Object.freeze({
      id: 'basic',
      name: 'Basic',
      summary: 'The core security headers: the standard review.',
      skip: Object.freeze(new Set(EXTENDED_ONLY)),
      hsts: Object.freeze({
        minMaxAge: 63072000,           // OWASP: two years
        requireIncludeSubdomains: true,
        requirePreload: false,
      }),
    }),
    extended: Object.freeze({
      id: 'extended',
      name: 'Extended',
      summary: 'Every header the analyzer knows, including legacy and deprecated ones.',
      skip: Object.freeze(new Set()),
      hsts: Object.freeze({
        minMaxAge: 63072000,
        requireIncludeSubdomains: true,
        requirePreload: true,
      }),
    }),
  });

  const DEFAULT_PROFILE = 'basic';

  function getProfile(id) {
    return Object.prototype.hasOwnProperty.call(PROFILES, id) ? PROFILES[id] : PROFILES[DEFAULT_PROFILE];
  }

  /*
   * What the response is, chosen by the user and never guessed: a web page, or
   * a call to a REST API read by a browser. The mode changes how headers are
   * judged; in REST API mode Basic keeps exactly the headers of the OWASP REST
   * Security Cheat Sheet, while Extended keeps every header.
   */
  const REST_BASIC = Object.freeze(new Set([
    'cache-control', 'content-security-policy', 'content-type', 'strict-transport-security',
    'x-content-type-options', 'x-frame-options', 'permissions-policy', 'referrer-policy',
    'access-control-allow-origin', 'access-control-allow-credentials',
  ]));

  const MODES = Object.freeze({
    page: Object.freeze({ id: 'page', name: 'Web page' }),
    api: Object.freeze({ id: 'api', name: 'REST API' }),
  });

  const DEFAULT_MODE = 'page';

  function getMode(id) {
    return Object.prototype.hasOwnProperty.call(MODES, id) ? MODES[id] : MODES[DEFAULT_MODE];
  }

  /** Whether `key` is evaluated under this profile and mode. */
  function inScope(key, profile, mode) {
    if (mode.id === 'api' && profile.id === 'basic') return REST_BASIC.has(key);
    return !profile.skip.has(key);
  }

  HL.profiles = Object.freeze({ PROFILES, DEFAULT_PROFILE, getProfile, MODES, DEFAULT_MODE, getMode, REST_BASIC, inScope });
})(globalThis.HeaderAnalyzer = globalThis.HeaderAnalyzer || {});
