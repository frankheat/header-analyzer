/*
 * Header Analyzer: the sources behind every claim.
 *
 * Each citation names a document and the exact passage that supports a claim.
 * Its link is a text fragment (#:~:text=…, URL Fragment Text Directives), so
 * the browser scrolls to the passage and highlights it; code is linked by line
 * range on a pinned commit, which GitHub highlights the same way. Quotes are
 * verbatim: `npm run verify-sources` fetches every document and checks that
 * each passage is still there.
 */
(function (HL) {
  'use strict';

  const OBS = 'https://github.com/mdn/mdn-http-observatory/blob/093035e33568f9e5a6ef85a2afb1b9c92df296e3/src/grader/charts.js';
  const CSPE = 'https://github.com/google/csp-evaluator/blob/ad530f3ae5473f9e03c8bf500ee0ada8d9e9b822/checks/security_checks.ts';
  const ZAPSRC = 'https://github.com/zaproxy/zap-extensions/blob/b769b254cef350eca913dd563e8fea0562256635/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/CorsScanRule.java';
  const CHROMIUM = 'https://github.com/chromium/chromium/blob/34221eca1b60aa7cb82cd8b22893bda4a3b2117a/services/network/public/cpp/permissions_policy/permissions_policy_features.json5';
  const MDN = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/';
  const RFC = 'https://www.rfc-editor.org/rfc/';

  // id: [title, url]
  const DOCS = {
    cs: ['OWASP HTTP Headers Cheat Sheet', 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'],
    bp: ['OWASP Secure Headers Project, Best Practices', 'https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md'],
    asvs3: ['OWASP ASVS 5.0, V3 Web Frontend Security', 'https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md'],
    asvs14: ['OWASP ASVS 5.0, V14 Data Protection', 'https://github.com/OWASP/ASVS/blob/master/5.0/en/0x23-V14-Data-Protection.md'],
    obs: ['Mozilla HTTP Observatory, score table', OBS],
    cspe: ['Google CSP Evaluator, security checks', CSPE],
    zapcors: ['OWASP ZAP, CORS scan rule source', ZAPSRC],
    csp3: ['W3C Content Security Policy Level 3', 'https://www.w3.org/TR/CSP3/'],
    strictcsp: ['web.dev, Mitigate XSS with a strict CSP', 'https://web.dev/articles/strict-csp'],
    fetch: ['WHATWG Fetch Standard', 'https://fetch.spec.whatwg.org/'],
    htmlxfo: ['WHATWG HTML Standard, X-Frame-Options', 'https://html.spec.whatwg.org/multipage/speculative-loading.html'],
    htmlorigin: ['WHATWG HTML Standard, Origin', 'https://html.spec.whatwg.org/multipage/browsers.html'],
    htmldoc: ['WHATWG HTML Standard, Document lifecycle', 'https://html.spec.whatwg.org/multipage/document-lifecycle.html'],
    htmlparse: ['WHATWG HTML Standard, Parsing', 'https://html.spec.whatwg.org/multipage/parsing.html'],
    mimesniff: ['WHATWG MIME Sniffing Standard', 'https://mimesniff.spec.whatwg.org/'],
    encoding: ['WHATWG Encoding Standard', 'https://encoding.spec.whatwg.org/'],
    referrer: ['W3C Referrer Policy', 'https://www.w3.org/TR/referrer-policy/'],
    pp: ['W3C Permissions Policy', 'https://www.w3.org/TR/permissions-policy/'],
    csd: ['W3C Clear Site Data', 'https://www.w3.org/TR/clear-site-data/'],
    mixed: ['W3C Mixed Content', 'https://www.w3.org/TR/mixed-content/'],
    sw: ['W3C Service Workers', 'https://w3c.github.io/ServiceWorker/'],
    rfc6266: ['RFC 6266, Content-Disposition', RFC + 'rfc6266.html'],
    rfc6797: ['RFC 6797, HTTP Strict Transport Security', RFC + 'rfc6797.html'],
    rfc9110: ['RFC 9110, HTTP Semantics', RFC + 'rfc9110.html'],
    rfc9111: ['RFC 9111, HTTP Caching', RFC + 'rfc9111.html'],
    rfc9112: ['RFC 9112, HTTP/1.1', RFC + 'rfc9112.html'],
    rfc9651: ['RFC 9651, Structured Field Values', RFC + 'rfc9651.html'],
    hstspreload: ['hstspreload.org', 'https://hstspreload.org/'],
    shp: ['OWASP Secure Headers Project, Headers', 'https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/01_headers.md'],
    chromium: ['Chromium, Permissions Policy features', CHROMIUM],
    permissions: ['W3C Permissions', 'https://www.w3.org/TR/permissions/'],
    mediacapture: ['W3C Media Capture and Streams', 'https://www.w3.org/TR/mediacapture-streams/'],
    geolocation: ['W3C Geolocation', 'https://www.w3.org/TR/geolocation/'],
    attribution: ['Attribution Reporting API', 'https://wicg.github.io/attribution-reporting-api/'],
    adobe: ['Adobe, Cross Domain Configuration', 'https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/xdomain.html'],
    ie8: ['Microsoft, IE8 Security Part V: Comprehensive Protection', 'https://learn.microsoft.com/en-us/archive/blogs/ie/ie8-security-part-v-comprehensive-protection'],
    ieEnd: ['Microsoft, Internet Explorer 11 end of support', 'https://learn.microsoft.com/en-us/lifecycle/announcements/internet-explorer-11-end-of-support-windows-10'],
    sonar: ['Sonar, Encoding Differentials: Why Charset Matters', 'https://www.sonarsource.com/blog/encoding-differentials-why-charset-matters/'],
    mdnExpectCt: ['MDN, Expect-CT', MDN + 'Expect-CT'],
    mdnXxp: ['MDN, X-XSS-Protection', MDN + 'X-XSS-Protection'],
    mdnXdns: ['MDN, X-DNS-Prefetch-Control', MDN + 'X-DNS-Prefetch-Control'],
    chromeDocDomain: ['Chrome for Developers, document.domain setter deprecation', 'https://developer.chrome.com/blog/document-domain-setter-deprecation'],
    mdnDocDomain: ['MDN, Document.domain', 'https://developer.mozilla.org/en-US/docs/Web/API/Document/domain'],
    mdnPragma: ['MDN, Pragma', MDN + 'Pragma'],
    mdnOac: ['MDN, Origin-Agent-Cluster', MDN + 'Origin-Agent-Cluster'],
    mdnCoep: ['MDN, Cross-Origin-Embedder-Policy', MDN + 'Cross-Origin-Embedder-Policy'],
    mdnSetCookie: ['MDN, Set-Cookie', MDN + 'Set-Cookie'],
    mdnCorp: ['MDN, Cross-Origin Resource Policy (CORP)', 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cross-Origin_Resource_Policy'],
    sessionCs: ['OWASP Session Management Cheat Sheet', 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'],
    rest: ['OWASP REST Security Cheat Sheet', 'https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html'],
    asvs4: ['OWASP ASVS 5.0, V4 API and Web Service', 'https://github.com/OWASP/ASVS/blob/master/5.0/en/0x13-V4-API-and-Web-Service.md'],
    webdevHeaders: ['web.dev, Security headers quick reference', 'https://web.dev/articles/security-headers'],
    orb: ['Opaque Response Blocking (ORB) explainer, WHATWG Fetch', 'https://github.com/annevk/orb/blob/main/README.md'],
    mdnAcao: ['MDN, Access-Control-Allow-Origin', MDN + 'Access-Control-Allow-Origin'],
    mdnXpcdp: ['MDN, X-Permitted-Cross-Domain-Policies', MDN + 'X-Permitted-Cross-Domain-Policies'],
    mdnObjectSrc: ['MDN, CSP object-src', MDN + 'Content-Security-Policy/object-src'],
    owaspRr: ['OWASP Risk Rating Methodology', 'https://owasp.org/www-community/OWASP_Risk_Rating_Methodology'],
    mdnBamc: ['MDN, CSP block-all-mixed-content', MDN + 'Content-Security-Policy/block-all-mixed-content'],
    mdnPrefetch: ['MDN, CSP prefetch-src', MDN + 'Content-Security-Policy/prefetch-src'],
    csCsp: ['OWASP Content Security Policy Cheat Sheet', 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html'],
    psCorsHttp: ['PortSwigger, CORS: unencrypted origin trusted', 'https://portswigger.net/kb/issues/00200602_cross-origin-resource-sharing-unencrypted-origin-trusted'],
    psHsts: ['PortSwigger, Strict transport security not enforced', 'https://portswigger.net/kb/issues/01000300_strict-transport-security-not-enforced'],
    psCache: ['PortSwigger, Cacheable HTTPS response', 'https://portswigger.net/kb/issues/00700100_cacheable-https-response'],
    psBlindCss: ['PortSwigger Research, Blind CSS Exfiltration', 'https://portswigger.net/research/blind-css-exfiltration'],
    psReferer: ['PortSwigger, Cross-domain Referer leakage', 'https://portswigger.net/kb/issues/00500400_cross-domain-referer-leakage'],
  };

  // ZAP alert pages: [alert id, alert name]; each is cited for its risk rating.
  const ZAP = {
    '10015': 'Re-examine Cache-control Directives',
    '10020-1': 'Missing Anti-clickjacking Header',
    '10020-4': 'X-Frame-Options Setting Malformed',
    '10021': 'X-Content-Type-Options Header Missing',
    '10035-1': 'Strict-Transport-Security Header Not Set',
    '10035-2': 'Strict-Transport-Security Disabled',
    '10035-3': 'Strict-Transport-Security Multiple Header Entries (Non-compliant with Spec)',
    '10038-1': 'Content Security Policy (CSP) Header Not Set',
    '10038-3': 'Content Security Policy (CSP) Report-Only Header Found',
    '10055-3': 'CSP: Notices',
    '10055-4': 'CSP: Wildcard Directive',
    '10055-5': 'CSP: script-src unsafe-inline',
    '10055-6': 'CSP: style-src unsafe-inline',
    '10055-7': 'CSP: script-src unsafe-hashes',
    '10055-10': 'CSP: script-src unsafe-eval',
    '10055-13': 'CSP: Failure to Define Directive with No Fallback',
    '10063-1': 'Permissions Policy Header Not Set',
    '20016-1': 'Cross-Domain Misconfiguration - Adobe - Read',
    '40040-2': 'CORS Misconfiguration',
    '40040-3': 'CORS Misconfiguration',
    '90004-1': 'Cross-Origin-Resource-Policy Header Missing or Invalid',
    '90004-2': 'Cross-Origin-Embedder-Policy Header Missing or Invalid',
    '90004-3': 'Cross-Origin-Opener-Policy Header Missing or Invalid',
  };
  const ZAP_RISK = {
    '10015': 'Informational', '10020-1': 'Medium', '10020-4': 'Medium', '10021': 'Low', '10035-1': 'Low', '10035-2': 'Low', '10055-7': 'Medium',
    '10035-3': 'Low', '10038-1': 'Medium', '10038-3': 'Informational', '10055-3': 'Low', '10055-4': 'Medium',
    '10055-5': 'Medium', '10055-6': 'Medium', '10055-10': 'Medium', '10055-13': 'Medium', '10063-1': 'Low',
    '20016-1': 'High', '40040-2': 'Medium', '40040-3': 'High', '90004-1': 'Low', '90004-2': 'Low', '90004-3': 'Low',
  };

  /*
   * id: [doc, quote]
   *   quote is the verbatim passage, highlighted whole;
   *   or {s, e, show}: highlighted from s to e (s and e verbatim), shown as `show`;
   *   or {lines, has, show} for code: the line range, which must contain `has`.
   */
  const CITES = {
    // ---------------------------------------------------- OWASP HTTP Headers Cheat Sheet
    'cs-xfo-fa': ['cs', 'Content Security Policy (CSP) frame-ancestors directive obsoletes X-Frame-Options for supporting browsers'],
    'cs-xfo-api': ['cs', 'If the HTTP response is a redirect or an API returning JSON data, X-Frame-Options does not provide any security.'],
    'cs-xfo-rec': ['cs', 'Do not allow displaying of the page in a frame.'],
    'cs-xxp-warn': ['cs', 'in some cases, this header can create XSS vulnerabilities in otherwise safe websites'],
    'cs-xxp-rec': ['cs', 'Do not set this header or explicitly turn it off.'],
    'cs-xcto': ['cs', "This header is used to block browsers' MIME type sniffing, which can transform non-executable MIME types into executable MIME types (MIME Confusion Attacks)."],
    'cs-rp-default': ['cs', 'Modern browsers default to strict-origin-when-cross-origin'],
    'cs-rp-rec': ['cs', 'Set the header explicitly rather than relying on browser defaults.'],
    'cs-ct-charset': ['cs', 'the charset attribute is necessary to prevent XSS in HTML pages'],
    'cs-cc-nostore': ['cs', 'Use no-store for sensitive responses to prohibit storage in compliant HTTP caches.'],
    'cs-cc-private': ['cs', 'note that private caches may still persist the response'],
    'cs-cc-nocache': ['cs', 'Be aware that no-cache does not prevent caching; it allows caches to store responses.'],
    'cs-cc-default': ['cs', 'Avoid relying on default caching behavior for sensitive or protected content.'],
    'cs-hsts-rec': ['cs', 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload'],
    'cs-expectct': ['cs', 'Do not use it. Mozilla recommends avoiding it, and removing it from existing code if possible.'],
    'cs-csp-api': ['cs', 'might be meaningless in the response of a REST API that returns content that is not going to be rendered'],
    'cs-acao-rec': ['cs', 'If you use it, set specific origins instead of *.'],
    'cs-acao-public': ['cs', 'for a public API that should be accessible from any origin, it might be necessary to allow'],
    'cs-coop-api': ['cs', 'it may not make sense to be applied to REST APIs or clients that are not browsers'],
    'cs-coop-rec': ['cs', 'Isolates the browsing context exclusively to same-origin documents.'],
    'cs-coop-spectre': ['cs', 'This mechanism protects against attacks like Spectre which can cross the security boundary established by Same Origin Policy (SOP) for resources in the same browsing context group.'],
    'cs-coep': ['cs', "prevents a document from loading any cross-origin resources that don't explicitly grant the document permission (using CORP or CORS)"],
    'cs-corp': ['cs', "It is a robust defense against attacks like Spectre, as it allows browsers to block a given response before it enters an attacker's process."],
    'cs-pp-rec': ['cs', 'Set it and disable all the features that your site does not need or allow them only to the authorized domains'],
    'cs-pp-example': ['cs', 'This example is disabling geolocation, camera, and microphone for all domains.'],
    'cs-xdns': ['cs', 'If you do not control links on your website, you might want to set off as a value to disable DNS prefetch to avoid leaking information to those domains.'],
    'cs-xdns-nonstd': ['cs', 'it is not standard or fully supported and implementation may vary among browsers'],
    'cs-download': ['cs', 'Use Content-Disposition: attachment to force download instead of inline rendering.'],

    // ---------------------------------------------------- OWASP Secure Headers Project
    'bp-hsts': ['bp', { s: 'Strict-Transport-Security', e: 'max-age=63072000; includeSubDomains', show: 'Strict-Transport-Security: max-age=63072000; includeSubDomains' }],
    'bp-xfo': ['bp', { s: 'X-Frame-Options', e: 'deny', show: 'X-Frame-Options: deny' }],
    'bp-xcto': ['bp', { s: 'X-Content-Type-Options', e: 'nosniff', show: 'X-Content-Type-Options: nosniff' }],
    'bp-xpcdp': ['bp', { s: 'X-Permitted-Cross-Domain-Policies', e: 'none', show: 'X-Permitted-Cross-Domain-Policies: none' }],
    'bp-rp': ['bp', { s: 'Referrer-Policy', e: 'no-referrer', show: 'Referrer-Policy: no-referrer' }],
    'bp-coep': ['bp', { s: 'Cross-Origin-Embedder-Policy', e: 'require-corp', show: 'Cross-Origin-Embedder-Policy: require-corp' }],
    'bp-coop': ['bp', { s: 'Cross-Origin-Opener-Policy', e: 'same-origin', show: 'Cross-Origin-Opener-Policy: same-origin' }],
    'bp-corp': ['bp', { s: 'Cross-Origin-Resource-Policy', e: 'same-origin', show: 'Cross-Origin-Resource-Policy: same-origin' }],
    'bp-csp': ['bp', "default-src 'self'; form-action 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests"],
    'bp-cc': ['bp', 'no-store, max-age=0'],
    'bp-csd-logout': ['bp', 'set it to the logout function when possible'],
    'bp-csd-time': ['bp', 'The header Clear-Site-Data will cause the browser to take additional processing time for the HTTP response'],
    'bp-xdns-pii': ['bp', 'Return sensitive or private content (commonly called PII).'],
    'bp-xdns-inj': ['bp', 'Prone to HTML injection where an attacker can inject a tag'],
    'bp-cors-mirror': ['bp', 'Never take the value of the request header Origin to add it into the response header Access-Control-Allow-Origin (mirroring)'],
    'bp-cors-star-cred': ['bp', 'The value *, for the response header Access-Control-Allow-Origin, cannot be used when the response header Access-Control-Allow-Credentials is allowed (true).'],
    'bp-cors-public': ['bp', 'Your endpoints are expected to be consumed, by a browser, from any origins without any authentication.'],
    'bp-cors-auth': ['bp', 'Your endpoints are expected to be consumed, by a browser, from a specific collection of origins with authentication.'],
    'bp-cache': ['bp', 'So, the browser will store a copy of the file (here a PDF one) into its cache storage for a certain amount of time.'],
    'bp-upload': ['bp', 'If such a feature allows uploading of HTML files (also applies for SVG files) then it can be used, as a vector, to store an HTML file containing JavaScript code.'],

    // ---------------------------------------------------- OWASP ASVS 5.0
    'asvs-3.4.1': ['asvs3', 'A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well.'],
    'asvs-3.4.2': ['asvs3', 'is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins'],
    'asvs-3.4.2-star': ['asvs3', "When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information."],
    'asvs-3.4.3': ['asvs3', "As a minimum, a global policy must be used which includes the directives object-src 'none' and base-uri 'none' and defines either an allowlist or uses nonces or hashes."],
    'asvs-3.4.4': ['asvs3', "Verify that all HTTP responses contain an 'X-Content-Type-Options: nosniff' header field."],
    'asvs-3.4.5': ['asvs3', 'Verify that the application sets a referrer policy to prevent leakage of technically sensitive data to third-party services'],
    'asvs-3.4.6': ['asvs3', 'Verify that the web application uses the frame-ancestors directive of the Content-Security-Policy header field for every HTTP response'],
    'asvs-3.4.6-xfo': ['asvs3', 'Note that the X-Frame-Options header field, although supported by browsers, is obsolete and may not be relied upon.'],
    'asvs-3.4.8': ['asvs3', 'include the Cross‑Origin‑Opener‑Policy header field with the same-origin directive or the same-origin-allow-popups directive as required'],
    'asvs-14.3.1': ['asvs14', "The 'Clear-Site-Data' HTTP response header field may be able to help with this"],
    'asvs-14.3.2': ['asvs14', 'Verify that the application sets sufficient anti-caching HTTP response header fields (i.e., Cache-Control: no-store) so that sensitive data is not cached in browsers.'],

    // ---------------------------------------------------- Mozilla HTTP Observatory
    'obs-csp-absent': ['obs', { lines: 'L204-L209', has: ['Expectation.CspNotImplemented', 'modifier: -25'], show: 'CspNotImplemented, modifier: -25' }],
    'obs-csp-inline': ['obs', { lines: 'L168-L173', has: ['Expectation.CspImplementedWithUnsafeInline', 'modifier: -20'], show: 'CspImplementedWithUnsafeInline, modifier: -20' }],
    'obs-csp-eval': ['obs', { lines: 'L158-L163', has: ['Expectation.CspImplementedWithUnsafeEval', 'modifier: -10'], show: 'CspImplementedWithUnsafeEval, modifier: -10' }],
    'obs-csp-style': ['obs', { lines: 'L133-L138', has: ['Expectation.CspImplementedWithUnsafeInlineInStyleSrcOnly', 'modifier: 0'], show: 'CspImplementedWithUnsafeInlineInStyleSrcOnly, modifier: 0' }],
    'obs-hsts-absent': ['obs', { lines: 'L575-L580', has: ['Expectation.HstsNotImplemented', 'modifier: -20'], show: 'HstsNotImplemented, modifier: -20' }],
    'obs-hsts-short': ['obs', { lines: 'L563-L568', has: ['Expectation.HstsImplementedMaxAgeLessThanSixMonths', 'modifier: -10'], show: 'HstsImplementedMaxAgeLessThanSixMonths, modifier: -10' }],
    'obs-xfo-absent': ['obs', { lines: 'L783-L788', has: ['Expectation.XFrameOptionsNotImplemented', 'modifier: -20'], show: 'XFrameOptionsNotImplemented, modifier: -20' }],
    'obs-xfo-csp': ['obs', { lines: 'L751-L756', has: ['Expectation.XFrameOptionsImplementedViaCsp', 'modifier: 5'], show: 'XFrameOptionsImplementedViaCsp, modifier: 5' }],
    'obs-xcto-absent': ['obs', { lines: 'L725-L730', has: ['Expectation.XContentTypeOptionsNotImplemented', 'modifier: -5'], show: 'XContentTypeOptionsNotImplemented, modifier: -5' }],
    'obs-rp-absent': ['obs', { lines: 'L503-L508', has: ['Expectation.ReferrerPolicyNotImplemented', 'modifier: 0'], show: 'ReferrerPolicyNotImplemented, modifier: 0' }],
    'obs-rp-unsafe': ['obs', { lines: 'L515-L520', has: ['Expectation.ReferrerPolicyUnsafe', 'modifier: -5'], show: 'ReferrerPolicyUnsafe, modifier: -5' }],
    'obs-coop-absent': ['obs', { lines: 'L966-L971', has: ['Expectation.CoopNotImplemented', 'modifier: 0'], show: 'CoopNotImplemented, modifier: 0' }],
    'obs-cors-public': ['obs', { lines: 'L367-L372', has: ['Expectation.CrossOriginResourceSharingImplementedWithPublicAccess', 'modifier: 0'], show: 'CrossOriginResourceSharingImplementedWithPublicAccess, modifier: 0' }],

    // ---------------------------------------------------- Google CSP Evaluator
    'cspe-schemes': ['cspe', { lines: 'L124-L143', has: ["' allows the execution of '", 'Severity.HIGH'], show: 'checkPlainUrlSchemes: data:, http: or https: in script-src, Severity.HIGH' }],
    'cspe-wildcard': ['cspe', { lines: 'L155-L170', has: ["should not allow '*' as source", 'Severity.HIGH'], show: "checkWildcards: should not allow '*' as source, Severity.HIGH" }],
    'cspe-bypass': ['cspe', { lines: 'L319-L336', has: ["' is known to host'", 'which allow to bypass this CSP.', 'Severity.HIGH'], show: 'checkScriptAllowlistBypass: known to host JSONP endpoints or Angular libraries which allow to bypass this CSP, Severity.HIGH' }],
    'cspe-base-uri': ['cspe', { lines: 'L221-L240', has: ['Missing base-uri allows the injection of base tags.', 'Severity.HIGH'], show: 'Missing base-uri allows the injection of base tags (for a policy with nonces, or hashes with strict-dynamic), Severity.HIGH' }],
    'cspe-object': ['cspe', { lines: 'L180-L193', has: ['export function checkMissingObjectSrcDirective', 'Severity.HIGH'], show: 'checkMissingObjectSrcDirective, Severity.HIGH' }],
    'cspe-script': ['cspe', { lines: 'L199-L206', has: ['export function checkMissingScriptSrcDirective', 'Severity.HIGH'], show: 'checkMissingScriptSrcDirective, Severity.HIGH' }],
    'cspe-deprecated': ['cspe', { lines: 'L471-L507', has: ['Directive.REFLECTED_XSS', 'Directive.REFERRER', 'Directive.DISOWN_OPENER', 'Directive.PREFETCH_SRC'], show: 'checkDeprecatedDirective: reflected-xss, referrer, disown-opener, prefetch-src' }],
    'cspe-http': ['cspe', { lines: 'L565-L580', has: ["'Allow only resources downloaded over HTTPS.'", 'Severity.MEDIUM'], show: 'checkSrcHttp: Allow only resources downloaded over HTTPS, Severity.MEDIUM' }],

    // ---------------------------------------------------- OWASP ZAP (code)
    'zap-cors-risk': ['zapcors', { lines: 'L116-L124', has: ['acaoVal.contains("null")', 'risk = acacVal.isEmpty() ? Alert.RISK_MEDIUM : Alert.RISK_HIGH;'], show: 'A null, arbitrary or plain-HTTP origin is Medium, and High when credentials are allowed' }],

    // ---------------------------------------------------- CSP Level 3
    'csp3-dup': ['csp3', 'If policy’s directive set contains a directive whose name is directive name, continue.'],
    'csp3-ascii': ['csp3', 'If token is an empty string, or if token is not an ASCII string, continue.'],
    'csp3-inline-nonce': ['csp3', 'If expression matches the nonce-source or hash-source grammar, return "Does Not Allow".'],
    'csp3-inline-sd': ['csp3', { s: 'If type is "script", "script attribute" or "navigation"', e: 'return "Does Not Allow".', show: 'If type is "script", "script attribute" or "navigation" and expression matches the keyword-source "\'strict-dynamic\'", return "Does Not Allow".' }],
    'csp3-nonce-128': ['csp3', 'The generated value SHOULD be at least 128 bits long (before encoding)'],
    'csp3-nonce-unique': ['csp3', 'the server MUST generate a unique value each time it transmits a policy'],
    'csp3-base': ['csp3', 'However, if an attacker can inject a base element, then an otherwise safe page can be subverted when relative URLs are resolved.'],
    'csp3-fa-xfo': ['csp3', { s: 'If a resource is delivered with a policy that includes a directive named frame-ancestors', e: 'will be ignored, per HTML’s processing model.', show: 'If a resource is delivered with a policy that includes a directive named frame-ancestors and whose disposition is "enforce", then the X-Frame-Options header will be ignored, per HTML’s processing model.' }],
    'csp3-fa-nofallback': ['csp3', 'frame-ancestors will not fall back to the default-src directive’s value if one is specified'],
    'csp3-default': ['csp3', 'when default-src is set, every fetch directive that isn’t explicitly set will fall back to the value default-src specifies'],
    'csp3-form': ['csp3', 'The form-action directive restricts the URLs which can be used as the target of a form submissions from a given context.'],
    'csp3-strict': ['csp3', 'enforcing the following set of CSP directives has been identified as an effective and deployable mitigation against XSS'],
    'csp3-exfil': ['csp3', 'Note that a policy which lacks the default-src directive cannot mitigate exfiltration'],
    'csp3-keywords': ['csp3', 'keyword-source = "\'self\'" / "\'unsafe-inline\'" / "\'unsafe-eval\'"'],
    'csp3-none': ['csp3', 'serialized-source-list = ( source-expression *( required-ascii-whitespace source-expression ) ) / "\'none\'"'],
    'csp3-split': ['csp3', 'For each token returned by strictly splitting serialized on the U+003B SEMICOLON character (;):'],
    'csp3-list': ['csp3', 'A serialized CSP list is an ASCII string consisting of a comma-delimited series of serialized CSPs'],
    'csp3-registry': ['csp3', 'The Content Security Policy Directive registry should be updated with the following directives and references'],
    'csp3-nonce-grammar': ['csp3', 'nonce-source = "\'nonce-" base64-value "\'"'],
    'csp3-sd-ignores': ['csp3', 'host-source and scheme-source expressions, as well as the "\'unsafe-inline\'" and "\'self\' keyword-sources will be ignored when loading script.'],
    'csp3-wildcard': ['csp3', 'If host to ASCII lowercase ends with remaining, then return "Matches".'],
    'csp3-schemes': ['csp3', 'The source expression matching has been changed to require explicit presence of any non-HTTP(S) scheme'],
    'csp3-each': ['csp3', 'When the user agent receives a Content-Security-Policy header field, it MUST parse and enforce each serialized CSP it contains'],
    'csp3-unsafe-hashes': ['csp3', 'will now allow event handlers, style attributes and javascript: navigation targets to match hashes'],
    'strictcsp-fallback': ['strictcsp', 'Setting fallbacks doesn\'t reduce the security of your policy in modern browsers'],
    'strictcsp-https': ['strictcsp', 'All browsers that support strict-dynamic ignore the https: fallback, so this won\'t reduce the strength of the policy.'],

    // ---------------------------------------------------- Fetch, HTML, MIME, Encoding
    'fetch-nosniff': ['fetch', 'If values[0] is an ASCII case-insensitive match for "nosniff", then return true.'],
    'fetch-corp': ['fetch', 'If policy is neither `same-origin`, `same-site`, nor `cross-origin`, then set policy to null.'],
    'fetch-cors-null': ['fetch', 'Let origin be the result of getting `Access-Control-Allow-Origin` from response’s header list.'],
    'fetch-cors-origin': ['fetch', 'If the result of byte-serializing a request origin with request is not origin, then return failure.'],
    'fetch-cors-star': ['fetch', 'If request’s credentials mode is not "include" and origin is `*`, then return success.'],
    'fetch-cors-cred': ['fetch', 'If credentials is `true`, then return success.'],
    'fetch-get': ['fetch', 'Return the values of all headers in list whose name is a byte-case-insensitive match for name, separated from each other by 0x2C 0x20, in order.'],
    'fetch-mime': ['fetch', 'To extract a MIME type from a header list headers, run these steps. They return failure or a MIME type.'],
    'mimesniff-type': ['mimesniff', 'If type is the empty string or does not solely contain HTTP token code points, then return failure.'],
    'encoding-label': ['encoding', 'If label is an ASCII case-insensitive match for any of the labels listed in the table below, then return the corresponding encoding; otherwise return failure.'],
    'html-xfo-multi': ['htmlxfo', 'If xFrameOptions\'s size is greater than 1, and xFrameOptions contains any of "deny", "allowall", or "sameorigin", then return false.'],
    'html-xfo-csp': ['htmlxfo', "If policy's directive set contains a frame-ancestors directive, then return true."],
    'html-xfo-several-invalid': ['htmlxfo', 'This means it contains multiple invalid values, which we treat the same way as if the header was omitted entirely.'],
    'html-xfo-sameorigin': ['htmlxfo', "If containerDocument's origin is not same origin with destinationOrigin, then return false."],
    'html-coep-compat': ['htmlorigin', 'An embedder policy value is compatible with cross-origin isolation if it is "credentialless" or "require-corp".'],
    'html-xfo-invalid': ['htmlxfo', 'These are treated as if the header were omitted entirely.'],
    'html-xfo-allowfrom': ['htmlxfo', 'variant of the header, but that is not to be implemented'],
    'html-coop-plus': ['htmlorigin', 'cannot be directly set via the `Cross-Origin-Opener-Policy` header, but results from a combination of setting both'],
    'html-oac': ['htmldoc', 'Let requestsOAC be true if oacHeader is not null and oacHeader[0] is the boolean true; otherwise false.'],
    'html-docdomain': ['htmlorigin', 'Avoid using the document.domain setter. It undermines the security protections provided by the same-origin policy.'],
    'html-charset-transport': ['htmlparse', 'If the transport layer specifies a character encoding, and it is supported, return that encoding with the confidence certain.'],
    'html-charset-1024': ['htmlparse', 'The authoring conformance requirements for character encoding declarations limit them to only appearing in the first 1024 bytes.'],
    'referrer-last': ['referrer', 'For each token in policy-tokens, if token is a referrer policy and token is not the empty string, then set policy to token.'],
    'pp-dict': ['pp', 'Member Values of any other form will cause the entire Dictionary Member to be ignored by the processing steps.'],
    'pp-empty': ['pp', 'If parsed header is null, return an empty ordered map.'],
    'pp-default': ['pp', 'Every policy-controlled feature has a default allowlist.'],
    'csd-subset': ['csd', 'so many that it’s not entirely clear which of them would be safe to clear as a response to a logout action'],
    'csd-grammar': ['csd', 'Clear-Site-Data = 1#( quoted-string )'],
    'csd-unknown': ['csd', 'User agents MUST ignore unknown types when parsing the header.'],
    'csd-logout': ['csd', 'when the user signs out of the application, or deletes their account'],
    'mixed-script': ['mixed', 'A request for the script http://example.com/script.js is mixed content. As script requests are blockable, the user agent will return a network error rather than loading the resource.'],
    'sw-allowed': ['sw', 'Servers can remove the path restriction by setting a Service-Worker-Allowed header on the service worker script.'],

    // ---------------------------------------------------- RFCs
    'rfc6797-invalid': ['rfc6797', { s: 'The UA MUST ignore any STS header fields not conforming to the', e: 'Response Header Field").', show: 'The UA MUST ignore any STS header fields not conforming to the grammar specified in Section 6.1 ("Strict-Transport-Security HTTP Response Header Field").' }],
    'rfc6797-first': ['rfc6797', { s: 'If a UA receives more than one STS header field in an HTTP', e: 'only the first such header field.', show: 'If a UA receives more than one STS header field in an HTTP response message over secure transport, then the UA MUST process only the first such header field.' }],
    'rfc6797-zero': ['rfc6797', { s: 'If the max-age header field value token has a value of zero, the', e: 'UA MUST remove its cached HSTS Policy information', show: 'If the max-age header field value token has a value of zero, the UA MUST remove its cached HSTS Policy information' }],
    'rfc6266-unknown': ['rfc6266', { s: 'Unknown or unhandled disposition types SHOULD be handled by', e: 'recipients the same way as "attachment"', show: 'Unknown or unhandled disposition types SHOULD be handled by recipients the same way as "attachment"' }],
    'rfc9110-combine': ['rfc9110', 'A recipient MAY combine multiple field lines within a field section that have the same field name into one field line, without changing the semantics of the message'],
    'rfc9110-etag': ['rfc9110', 'An entity tag is an opaque validator for differentiating between multiple representations of the same resource'],
    'rfc9110-etag-privacy': ['rfc9110', 'An entity tag can be abused in ways that create privacy risks.'],
    'rfc9111-auth': ['rfc9111', 'A shared cache MUST NOT use a cached response to a request with an Authorization header field'],
    'rfc9111-auth-directives': ['rfc9111', 'In this specification, the following response directives have such an effect: must-revalidate (Section 5.2.2.2), public (Section 5.2.2.9), and s-maxage (Section 5.2.2.10).'],
    'rfc9111-heuristic': ['rfc9111', 'a cache MAY assign a heuristic expiration time when an explicit time is not specified'],
    'rfc9111-private': ['rfc9111', 'The unqualified private response directive indicates that a shared cache MUST NOT store the response'],
    'rfc9111-pragma': ['rfc9111', 'As a result, this specification deprecates Pragma.'],
    'rfc9111-pragma-response': ['rfc9111', 'Because the meaning of "Pragma: no-cache" in responses was never specified, it does not provide a reliable replacement for "Cache-Control: no-cache" in them.'],
    'mdn-pragma': ['mdnPragma', 'The Pragma header is not specified for HTTP responses and is therefore not a reliable replacement for the HTTP/1.1 Cache-Control header'],
    'rfc9111-expires': ['rfc9111', 'If a response includes a Cache-Control header field with the max-age directive (Section 5.2.2.1), a recipient MUST ignore the Expires header field.'],
    'rfc9112-ws': ['rfc9112', 'No whitespace is allowed between the field name and colon.'],
    'rfc9112-fold': ['rfc9112', 'This specification deprecates such line folding except within the "message/http" media type'],
    'rfc9651-fail': ['rfc9651', 'When parsing fails, the entire field is ignored'],

    // ---------------------------------------------------- Permissions Policy defaults
    'chromium-topics': ['chromium', { lines: 'L144-L146', has: ['"browsing-topics"', '"EnableForAll"'], show: 'browsing-topics: feature_default "EnableForAll"' }],
    'chromium-uach': ['chromium', { lines: 'L220-L222', has: ['"ch-ua-high-entropy-values"', '"EnableForAll"'], show: 'ch-ua-high-entropy-values: feature_default "EnableForAll"' }],
    'chromium-pst-issuance': ['chromium', { lines: 'L485-L487', has: ['"private-state-token-issuance"', '"EnableForAll"'], show: 'private-state-token-issuance: feature_default "EnableForAll"' }],
    'chromium-pst-redemption': ['chromium', { lines: 'L558-L560', has: ['"private-state-token-redemption"', '"EnableForAll"'], show: 'private-state-token-redemption: feature_default "EnableForAll"' }],
    'chromium-storage-access': ['chromium', { lines: 'L532-L534', has: ['"storage-access"', '"EnableForAll"'], show: 'storage-access: feature_default "EnableForAll"' }],
    'chromium-gamepad': ['chromium', { lines: 'L361-L363', has: ['"gamepad"', '"EnableForAll"'], show: 'gamepad: feature_default "EnableForAll"' }],
    'chromium-pip': ['chromium', { lines: 'L480-L482', has: ['"picture-in-picture"', '"EnableForAll"'], show: 'picture-in-picture: feature_default "EnableForAll"' }],
    'chromium-deferred': ['chromium', { lines: 'L299-L301', has: ['"deferred-fetch-minimal"', '"EnableForAll"'], show: 'deferred-fetch-minimal: feature_default "EnableForAll"' }],
    'chromium-default-self': ['chromium', { lines: 'L32-L33', has: ['feature_default: {', 'default: "EnableForSelf",'], show: 'feature_default: default "EnableForSelf"' }],
    'attribution-default': ['attribution', 'This specification defines a policy-controlled feature identified by the string "attribution-reporting". Its default allowlist is *.'],
    'mediacapture-default': ['mediacapture', 'This specification defines two policy-controlled features identified by the strings "camera" and "microphone". Both have a default allowlist of "self".'],
    'geolocation-default': ['geolocation', 'This specification defines a policy-controlled feature identified by the token string "geolocation". Its default allowlist is \'self\'.'],
    'permissions-delegation': ['permissions', 'Most powerful features grant permission to the top-level origin and delegate access to the requesting document via Permissions Policy. This is known as permission delegation.'],

    // ---------------------------------------------------- Others
    'shp-deprecated': ['shp', { s: 'Feature-Policy', e: 'Pragma', show: 'Deprecated: Feature-Policy, Expect-CT, Public-Key-Pins, X-XSS-Protection, Pragma' }],
    'adobe-default': ['adobe', 'By default, when requested content is not from the same origin as the requesting document, Acrobat and Adobe Reader automatically attempt to load a server-based policy file from that domain to get permission for such access.'],
    'adobe-master': ['adobe', 'The use of non-master policy files require a site to have a meta-policy of “by-content-type” or “all”.'],
    'adobe-invalid': ['adobe', 'An invalid meta-policy was specified in an X-Permitted-Cross-Domain-Policies HTTP header. It has been ignored.'],
    'ie8-xdo': ['ie8', 'When the new X-Download-Options header is present with the value noopen, the user is prevented from opening a file download directly'],
    'ie-end': ['ieEnd', 'On June 15, 2022, the Internet Explorer 11 (IE11) desktop application ended support'],
    'hstspreload-base': ['hstspreload', 'Serve an HSTS header on the base domain for HTTPS requests'],
    'hstspreload-subdomains': ['hstspreload', 'HSTS preloading applies to all subdomains, including internal subdomains that are not publicly accessible.'],
    'hstspreload-min': ['hstspreload', 'The max-age must be at least 31536000 seconds (1 year).'],
    'hstspreload-token': ['hstspreload', 'If a site sends the preload directive in an HSTS header, it is considered to be requesting inclusion in the preload list and may be submitted via the form on this site.'],
    'sonar-detect': ['sonar', 'A single occurrence of one of these escape sequences is usually enough to convince the auto-detection algorithm that the HTTP response body is encoded with ISO-2022-JP.'],
    'mdn-expectct': ['mdnExpectCt', 'Only Google Chrome and other Chromium-based browsers implemented Expect-CT, and Chromium has deprecated the header from version 107, because Chromium now enforces CT by default.'],
    'mdn-xxp-pages': ['mdnXxp', 'stopped pages from loading when they detected reflected cross-site scripting'],
    'mdn-xxp-warn': ['mdnXxp', 'in some cases, X-XSS-Protection can create XSS vulnerabilities in otherwise safe websites'],
    'mdn-xxp-block': ['mdnXxp', 'though this approach might be vulnerable to side-channel attacks if the website is embeddable in an'],
    'mdn-xdns-nonstd': ['mdnXdns', 'Non-standard: This feature is not standardized.'],
    // REST API mode: the OWASP REST Security Cheat Sheet is the reference.
    'session-csd': ['sessionCs', 'This can be achieved by returning the Clear-Site-Data response header'],
    'rest-stateless': ['rest', 'Stateful services are out of scope of this Cheat Sheet'],
    'rest-scope': ['rest', 'The following headers should be included in all API responses that may be consumed by browser clients'],
    'rest-cc': ['rest', 'Instructs compliant private and shared HTTP caches not to store the response or reuse it for another request'],
    'rest-fa': ['rest', 'For an API response, there is no requirement to be framed in any of those elements.'],
    'rest-fa-dnd': ['rest', 'This header protects against drag-and-drop style clickjacking attacks.'],
    'rest-ct': ['rest', 'This must be specified as per the type of content returned by an API call.'],
    'rest-ct-js': ['rest', 'Ensure sending intended content type headers in your response matching your body content e.g. application/json and not application/javascript.'],
    'mimesniff-js': ['mimesniff', 'A JavaScript MIME type is any MIME type whose essence is one of the following'],
    'rest-ct-guess': ['rest', 'If not specified or if specified incorrectly, a browser might attempt to guess the content type of the response.'],
    'rest-xfo': ['rest', 'Still recommended for compatibility with older browsers that do not support CSP Level 2.'],
    'rest-dd': ['rest', 'The headers below are only intended to provide additional security when responses are rendered as HTML.'],
    'rest-dd-uncertain': ['rest', { s: 'However, if there is any uncertainty about the function of the headers', e: 'as part of a defense-in-depth approach', show: 'if there is any uncertainty about the function of the headers, or the types of information that the API returns (or may return in future), then it is recommended to include them as part of a defense-in-depth approach' }],
    'rest-csp-dd': ['rest', 'The majority of CSP functionality only affects pages rendered as HTML.'],
    'rest-rp': ['rest', 'Non-HTML responses should not trigger additional requests.'],
    'rest-pp': ['rest', 'When browsers heed this header, it is used to control browser features via directives.'],
    'rest-cors': ['rest', 'Be as specific as possible and as general as necessary when setting the origins of cross-domain calls.'],
    'asvs-4.1.1': ['asvs4', { s: 'Verify that every HTTP response with a message body contains a Content-Type header field', e: 'that matches the actual content of the response', show: 'Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response' }],
    'webdev-corp-api': ['webdevHeaders', { s: 'You should apply this to resources that include sensitive information about the user', e: 'intended to be called only from the same origin', show: 'You should apply this to resources that include sensitive information about the user, or responses of an API that is intended to be called only from the same origin.' }],
    'webdev-corp-all': ['webdevHeaders', 'All resources are recommended to send this header to indicate whether they allow being loaded by other websites.'],
    'orb-blocklist': ['orb', 'An opaque-blocklisted MIME type is an HTML MIME type, JSON MIME type, or XML MIME type.'],
    'mdn-corp-xssi': ['mdnCorp', 'to mitigate speculative side-channel attacks, like Spectre, as well as Cross-Site Script Inclusion attacks'],
    'mdn-corp-nocors': ['mdnCorp', 'The policy is only effective for no-cors requests'],
    'mdn-coep-doc': ['mdnCoep', "configures the current document's policy for loading and embedding cross-origin resources"],
    'mdn-oac-doc': ['mdnOac', 'is used to request that the associated Document should be placed in an origin-keyed agent cluster'],
    'mdn-samesite-lax': ['mdnSetCookie', { s: 'and for cross-site requests that meet both of the following criteria', e: 'The request uses a safe method', show: 'Lax: send the cookie for same-site requests, and for cross-site requests only on a top-level navigation with a safe method' }],
    'mdn-samesite-default': ['mdnSetCookie', 'Some browsers use Lax as the default value if SameSite is not specified'],
    'fetch-method-get': ['fetch', { s: 'A request has an associated method', e: 'GET', show: 'A request has an associated method. Unless stated otherwise it is GET.' }],
    'mdn-xdns-doc': ['mdnXdns', 'links that the user may choose to follow as well as URLs for items referenced by the document'],
    'mdn-object-src': ['mdnObjectSrc', 'Therefore it is recommended to restrict this fetch-directive'],
    'owasp-rr-critical': ['owaspRr', { s: 'Overall Risk Severity', e: 'Critical', show: 'Overall Risk Severity: Critical only where impact is HIGH and likelihood is HIGH' }],
    'mdn-bamc': ['mdnBamc', 'Warning: This directive is marked as obsolete in the specification.'],
    'mdn-prefetch': ['mdnPrefetch', 'Non-standard: This feature is not standardized.'],
    'cscsp-plugin-types': ['csCsp', 'plugin-types has been removed from the CSP specification.'],
    'chrome-docdomain-115': ['chromeDocDomain', 'Starting in Chrome 115, websites will be unable to set document.domain: Chrome will make document.domain immutable.'],
    'chrome-docdomain-opt-out': ['chromeDocDomain', 'When you send this header, your document can continue to set document.domain even after it becomes immutable by default.'],
    'mdn-docdomain-oac': ['mdnDocDomain', 'If used on an origin-isolated page, i.e., one that uses the Origin-Agent-Cluster HTTP header'],
    'mdn-docdomain-shared': ['mdnDocDomain', 'Similar problems occur with shared hosting sites that give each customer a different subdomain.'],
    'mdn-oac-hint': ['mdnOac', 'Origin-keyed agent clusters should not be viewed as a security feature'],
    'mdn-oac-ignored': ['mdnOac', 'Values other than ?1 are ignored (e.g., the ?0 structured field for false).'],
    'mdn-acao-null': ['mdnAcao', 'Note: The value null should not be used.'],
    'mdn-xpcdp-none': ['mdnXpcdp', 'No policy files are allowed anywhere on the target server, including in a master policy file.'],
    'mdn-xpcdp-ntr': ['mdnXpcdp', 'Indicates that the current document should not be used as a policy file despite other headers or its content.'],
    'mdn-xpcdp': ['mdnXpcdp', 'Some security testing tools will still check for the presence of a X-Permitted-Cross-Domain-Policies: none header because it can mitigate the risk of an overly-permissive policy file added to your site by accident or through malicious actions.'],
    'ps-cors-http': ['psCorsHttp', 'If a site allows interaction from an origin that uses unencrypted HTTP communications, then it is vulnerable to an attacker who is in a position to view and modify a user\'s unencrypted network traffic.'],
    'ps-css-csp': ['psBlindCss', 'Imagine you\'ve got a blind HTML injection vulnerability but you can\'t get XSS because of the site\'s CSP'],
    'ps-css-attr': ['psBlindCss', 'Attribute selectors are an extremely powerful way to extract data.'],
    'ps-hsts': ['psHsts', { s: 'Typical severity', e: 'Low', show: 'Typical severity: Low' }],
    'ps-cache': ['psCache', { s: 'Typical severity', e: 'Information', show: 'Typical severity: Information' }],
    'ps-referer': ['psReferer', { s: 'Typical severity', e: 'Information', show: 'Typical severity: Information' }],
  };

  for (const id of Object.keys(ZAP)) {
    DOCS['zap-' + id] = [`OWASP ZAP alert ${id}, ${ZAP[id]}`, `https://www.zaproxy.org/docs/alerts/${id}/`];
    CITES['zap-' + id] = ['zap-' + id, { s: 'Risk', e: ZAP_RISK[id], show: `Risk: ${ZAP_RISK[id]}` }];
  }

  const SPLIT_ABOVE = 20;

  /** Percent-encode a text directive term (URL Fragment Text Directives §3.3.1). */
  function term(s) {
    return encodeURIComponent(s).replace(/-/g, '%2D');
  }

  /** Very long passages are linked by their first and last words, so the URL stays short. */
  function directive(quote) {
    if (typeof quote === 'object') return term(quote.s) + ',' + term(quote.e);
    const words = quote.split(/\s+/);
    if (words.length <= SPLIT_ABOVE) return term(quote);
    return term(words.slice(0, 5).join(' ')) + ',' + term(words.slice(-5).join(' '));
  }

  function build(id) {
    const [docId, quote] = CITES[id];
    const [title, base] = DOCS[docId];
    if (typeof quote === 'object' && quote.lines) {
      return Object.freeze({ id, title, url: `${base}#${quote.lines}`, quote: quote.show });
    }
    return Object.freeze({
      id,
      title,
      url: `${base}#:~:text=${directive(quote)}`,
      quote: typeof quote === 'object' ? quote.show : quote,
    });
  }

  const BUILT = Object.freeze(Object.fromEntries(Object.keys(CITES).map((id) => [id, build(id)])));

  /** The citation for `id`; an unknown id is a programming error. */
  function cite(id) {
    if (!Object.prototype.hasOwnProperty.call(BUILT, id)) throw new Error(`Unknown source: ${id}`);
    return BUILT[id];
  }

  HL.sources = Object.freeze({
    cite,
    ids: Object.freeze(Object.keys(BUILT)),
    // For scripts/verify-sources.mjs: the raw entries, to check against the documents.
    raw: Object.freeze({ DOCS, CITES, SPLIT_ABOVE }),
  });
})(globalThis.HeaderAnalyzer = globalThis.HeaderAnalyzer || {});
