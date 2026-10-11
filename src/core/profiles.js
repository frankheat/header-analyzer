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

  const EXTENDED_ONLY = [
    'origin-agent-cluster', 'service-worker-allowed', 'content-disposition',
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

  HL.profiles = Object.freeze({ PROFILES, DEFAULT_PROFILE, getProfile });
})(globalThis.HeaderAnalyzer = globalThis.HeaderAnalyzer || {});
