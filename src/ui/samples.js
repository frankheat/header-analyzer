/*
 * Header Analyzer: sample responses for the Samples menu. All synthetic.
 */
(function (HL) {
  'use strict';

  const CRLF = '\r\n';
  const join = (lines) => lines.join(CRLF) + CRLF;

  HL.samples = Object.freeze([
    {
      id: 'hardened',
      name: 'Hardened site',
      detail: 'Strict CSP, HSTS, isolation headers',
      text: join([
        'HTTP/2 200',
        'content-type: text/html; charset=utf-8',
        "content-security-policy: script-src 'nonce-r4nd0mB4se64N0nceV4lue' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
        'strict-transport-security: max-age=63072000; includeSubDomains; preload',
        'x-frame-options: DENY',
        'x-content-type-options: nosniff',
        'referrer-policy: strict-origin-when-cross-origin',
        'cross-origin-opener-policy: same-origin',
        'cross-origin-embedder-policy: require-corp',
        'cross-origin-resource-policy: same-origin',
        'permissions-policy: attribution-reporting=(), browsing-topics=(), ch-ua-high-entropy-values=(), private-state-token-issuance=(), private-state-token-redemption=(), storage-access=(), camera=(), microphone=(), geolocation=()',
        'cache-control: no-store',
        'x-permitted-cross-domain-policies: none',
        'x-dns-prefetch-control: off',
        'origin-agent-cluster: ?1',
        '',
        '<!doctype html>',
      ]),
    },
    {
      id: 'legacy',
      name: 'Legacy application',
      detail: 'Weak CSP, ALLOW-FROM, reflected CORS',
      text: join([
        'HTTP/1.1 200 OK',
        'Date: Thu, 08 Oct 2026 09:12:44 GMT',
        'Server: Apache/2.4.41 (Ubuntu)',
        'X-Powered-By: PHP/7.4.3',
        'Content-Type: application/json',
        "Content-Security-Policy: default-src 'self' script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com; img-src *",
        'Strict-Transport-Security: max-age=31536000',
        'X-Frame-Options: ALLOW-FROM https://partner.example',
        'X-XSS-Protection: 1; mode=block',
        "Feature-Policy: camera 'none'; microphone 'none'",
        "Permissions-Policy: camera 'none'; microphone 'none'",
        'Referrer-Policy: no-referrer-when-downgrade',
        'Cache-Control: max-age=600',
        'Access-Control-Allow-Origin: https://app.example.com',
        'Access-Control-Allow-Credentials: true',
        'Set-Cookie: session=synthetic; Path=/',
        '',
        '{"status":"ok"}',
      ]),
    },
  ]);
})(globalThis.HeaderAnalyzer = globalThis.HeaderAnalyzer || {});
