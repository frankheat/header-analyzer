'use strict';
/* Header values and the severity each must get: shared by the checker tests and the language tests. */
const { Severity: S, PP_CLOSED } = require('./helpers');

module.exports = [
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
