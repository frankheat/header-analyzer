# Header Analyzer: Rules Reference

Every check Header Analyzer runs, the condition that triggers it, the severity it
carries, and why. This file is kept in lockstep with `src/core/`: a change to a
rule changes this file in the same commit.

**Every claim links to its source.** A link opens the source scrolled to the
exact passage, highlighted (a [text fragment](https://developer.mozilla.org/en-US/docs/Web/URI/Reference/Fragment/Text_fragments));
code is linked by line range on a pinned commit. The same citations appear in
the app under each finding (*Sources*). The full list, with every quoted
passage, is at the end of this file; `npm run verify-sources` fetches every
document and checks that each passage is still there, word for word.

Where Header Analyzer grades something differently from a source, the row says so.

---

## How severities are decided

### The scale

| Severity | Meaning |
|---|---|
| HIGH | A protection is defeated in a way any web page can exploit |
| MEDIUM | A meaningful gap: a core protection is missing or does not hold |
| LOW | A deviation from an OWASP or ASVS recommendation with limited impact |
| **OK** | The check passed. Not a severity: never listed, never counted |

An **OK** result can still carry a note: a fact worth explaining (for example
`'unsafe-inline'` kept as a fallback next to a nonce) or a check to run (the
nonce must change on every response). Notes appear in the header's detail,
without a badge.

### Sources

| Source | Used for |
|---|---|
| [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) | **Primary source for Basic**: recommended values, deprecated headers, where a header applies |
| [OWASP Secure Headers Project: Best Practices](https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md) | **Primary source for Basic**: recommended configuration, CORS configurations, when X-DNS-Prefetch-Control and Clear-Site-Data apply |
| [OWASP ZAP alerts](https://www.zaproxy.org/docs/alerts/) | The baseline: OWASP's scanner assigns a standard risk to each header issue |
| [OWASP ASVS 5.0](https://github.com/OWASP/ASVS/tree/master/5.0/en) (V3.4, V14.3) | Arbitration: the verification level (L1 = every application) of each requirement |
| [Mozilla HTTP Observatory](https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring) ([score table](https://github.com/mdn/mdn-http-observatory/blob/093035e33568f9e5a6ef85a2afb1b9c92df296e3/src/grader/charts.js)) | Arbitration: the relative weight of each header |
| [Google CSP Evaluator](https://github.com/google/csp-evaluator/blob/ad530f3ae5473f9e03c8bf500ee0ada8d9e9b822/checks/security_checks.ts) | Which CSP weaknesses matter, and when |
| [PortSwigger issue definitions](https://portswigger.net/kb/issues) | Cross-check against the practice of professional testers |
| [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) | The scale itself: severity = impact × likelihood |
| RFC 6797, 9110, 9111, 9112, 9651; W3C CSP3, Referrer Policy, Permissions Policy, Clear Site Data; WHATWG Fetch, HTML, MIME Sniffing, Encoding | How a browser reads each header |

### Rules

1. **Threshold.** A deviation from an OWASP or ASVS recommendation is at least
   LOW. Something OWASP would rate a mere note (a fact, not a deviation) is OK.
2. **Monotonicity.** A value never weighs more than the header's absence (a weak
   policy is not worse than none), and a value a browser ignores weighs exactly
   as its absence. The only exceptions are values that grant *more* than the
   browser default: `Cache-Control` making a response storable by shared caches,
   and `X-Permitted-Cross-Domain-Policies` allowing policy files. Content-Type is
   outside this rule: only its charset on HTML is graded, and its absence is not
   graded at all.
3. **"To confirm" never inflates.** The severity is what the response shows. The
   worst case a check could reveal is stated in the check itself.
4. **HIGH is the top of the scale.** On the OWASP Risk Rating, [Critical needs
   high impact *and* high likelihood][owasp-rr-critical]; a header cannot show
   what data an endpoint returns, so no finding could ever reach it, and the
   level is not part of the scale. Only CORS `null` with credentials is HIGH
   ([ZAP rates it High][zap-40040-3], [for a null origin with
   credentials][zap-cors-risk]).
5. **Every header in a profile is checked, present or absent.** Absence is
   either a severity or OK, never skipped.

These rules are enforced by tests (`tests/checkers.test.js`,
`tests/csp.test.js`, `tests/engine.test.js`), which also require every finding
that explains, recommends or asks something to cite its sources.

---

## Profiles

Profiles are fixed: they choose which headers are in scope and a few
thresholds, never how a header is read. Following the OWASP HTTP Headers Cheat
Sheet, the primary source for Basic, Basic also checks Expect-CT (the Cheat
Sheet says ["Do not use it"][cs-expectct]) and the [charset][cs-ct-charset] of
an HTML Content-Type.

| | Basic | Extended |
|---|:-:|:-:|
| Headers checked | 17 | 25 |
| HSTS minimum max-age | 63072000 s ([2 years, OWASP][cs-hsts-rec]) | 63072000 s |
| HSTS includeSubDomains required | yes | yes |
| HSTS preload | not asked | LOW, to confirm |

Extended adds Clear-Site-Data, Origin-Agent-Cluster, Service-Worker-Allowed,
Content-Disposition, Pragma, Expires, ETag and X-Download-Options, and so also
reports leftover legacy headers.

*Deviation:* Clear-Site-Data is checked in Extended only. The OWASP Secure
Headers Project says to [set it to the logout function][bp-csd-logout], and
[ASVS 14.3.1][asvs-14.3.1] and the [Session Management Cheat Sheet][session-csd]
ask for it when a session ends. It belongs on that one response, not on every
response, so in Basic it would ask the same question of almost every response
analysed, nearly always to answer no. The same holds in both modes.

### Modes: Web page or REST API

A second, independent choice says what the response is. It is always the
user's: nothing in the response (its Content-Type, its status) is used to
guess it.

- **Web page.** The response is a page a browser displays. Every rule in the
  sections below applies, and no check asks whether it is a page.
- **REST API.** The response is a call to an API read by a browser, judged on
  the [OWASP REST Security Cheat Sheet][rest-scope]. With Basic, only the
  headers of that cheat sheet are checked; with Extended, the same 25 headers
  as in Web page mode, each with the criterion for an API response. See
  [REST API mode](#rest-api-mode).

---

## Findings list

Besides the detailed report, the findings can be copied as one line per header:

```
<Header>: <status>. <brief description>.
```

| Status | Meaning |
|---|---|
| Missing | The header is not present. |
| Misconfigured | The header is present, but its configuration is not secure (an empty value counts here: it is present, and browsers ignore it). |
| Duplicated | The header is returned more than once. |
| Deprecated | The header uses an obsolete or no longer recommended feature (X-XSS-Protection, Expect-CT, X-Download-Options, X-Frame-Options ALLOW-FROM, obsolete CSP directives). |

- **Listed:** every finding with a severity. OK notes never are.
- **All / Confirmed / To confirm:** the copy menu chooses what the list holds:
  every finding, only those the response settles, or only those that need a
  check (each ending with "(to confirm)"). A header with both kinds
  appears under Confirmed and under To confirm, each time with the findings of
  that kind.
- **Several problems in one header:** each header appears once. The line takes the
  status of its most severe problem (on a tie: Missing, then Misconfigured, then
  Deprecated, then Duplicated). The short descriptions are joined with `; ` from most
  to least severe; at most three are shown, and the rest are counted as "and N more".
  The detailed row of the header lists every problem.
- **Order:** by the most severe problem of each header.
- **Once per header:** in each of the three lists a header has at most one line.

The **Copy findings** button, next to the result filters, puts the chosen list
on the clipboard as a bulleted list, and says how many lines it copied. Where
the page may not write to the clipboard, the list opens in a dialog, already
selected, to copy by hand.

---

## Reading the response

- **One response.** The first response in the text is analysed; everything
  after its header section is body and is ignored. Informational 1xx responses
  in front of it (`100 Continue`, as `curl -i` prints them) are skipped.
- **Request in front.** A request followed by its response (Burp "copy
  request and response") is skipped up to the first status line. A request
  with no response is an error that says so.
- **Field lines** (RFC 9112 §5): `name ":" OWS value OWS`. A line with an
  invalid name, or with no colon, is discarded as a browser discards it, and
  noted. [Whitespace before the colon is forbidden][rfc9112-ws]; it is read
  leniently and noted. `obs-fold` continuations, [deprecated by RFC
  9112][rfc9112-fold], are joined with SP and noted. Bare LF is accepted; a
  stray CR is replaced with SP. HTTP/2 pseudo-headers (`:status`) are read for
  the status and are not headers.
- **Limit.** Inputs over 5 MB are refused.

---

## Absent headers

| Header | Absent | Why |
|---|---|---|
| Content-Security-Policy | **MEDIUM** | [ZAP 10038-1 Medium][zap-10038-1]; [ASVS 3.4.3][asvs-3.4.3] (L2); [Observatory −25][obs-csp-absent] |
| Strict-Transport-Security | **MEDIUM** | [ASVS 3.4.1][asvs-3.4.1] is L1 and [Observatory −20][obs-hsts-absent]. *Deviation:* [ZAP][zap-10035-1] and [PortSwigger][ps-hsts] rate it Low; Header Analyzer follows ASVS: impact high (SSL stripping) × likelihood low (needs a network position) |
| X-Frame-Options, no CSP `frame-ancestors` | **MEDIUM** | [ZAP 10020-1 "Missing Anti-clickjacking Header" Medium][zap-10020-1]; [Observatory −20][obs-xfo-absent] |
| X-Frame-Options, CSP `frame-ancestors` restricts framing | **LOW** | [frame-ancestors replaces XFO][csp3-fa-xfo] in current browsers ([ASVS 3.4.6][asvs-3.4.6] asks for it; [Observatory +5][obs-xfo-csp]); OWASP still recommends XFO [for browsers without frame-ancestors][cs-xfo-fa] |
| X-Content-Type-Options | **LOW** | [ZAP 10021 Low][zap-10021]; [Observatory −5][obs-xcto-absent]; [ASVS 3.4.4][asvs-3.4.4] (L2) |
| Referrer-Policy | **LOW** | [ASVS 3.4.5][asvs-3.4.5] (L2); [Observatory 0][obs-rp-absent]: browsers [default to `strict-origin-when-cross-origin`][cs-rp-default], though OWASP says to [set it explicitly][cs-rp-rec] |
| Cross-Origin-Opener-Policy | **LOW** | [ZAP 90004-3 Low][zap-90004-3]; [ASVS 3.4.8][asvs-3.4.8] (L3); [Observatory 0][obs-coop-absent] |
| Permissions-Policy | **LOW** | [ZAP 10063-1 Low][zap-10063-1]; OWASP: [disable what the site does not need][cs-pp-rec] |
| Cross-Origin-Embedder-Policy, Cross-Origin-Resource-Policy | **LOW** | [ZAP 90004-2][zap-90004-2] and [90004-1][zap-90004-1] Low; OWASP recommends [COEP][cs-coep] and [CORP][cs-corp] |
| X-Permitted-Cross-Domain-Policies | **LOW** | OWASP [recommends `none`][bp-xpcdp]; without it Adobe clients [still consult a policy file][adobe-default] |
| Cache-Control | **LOW**, to confirm | [ZAP 10015][zap-10015] and [PortSwigger][ps-cache]: Informational; [ASVS 14.3.2][asvs-14.3.2] (L2) for sensitive data: whether it is sensitive is the check |
| Clear-Site-Data | **LOW**, to confirm | [ASVS 14.3.1][asvs-14.3.1]; OWASP: [on the logout function][bp-csd-logout]. Only a session-ending response needs it, which is the check |
| X-DNS-Prefetch-Control | **LOW**, to confirm | The check asks both OWASP conditions: [links to domains you do not control][cs-xdns] (Cheat Sheet), or a response that [returns sensitive or private content][bp-xdns-pii] or is [prone to HTML injection][bp-xdns-inj] (Secure Headers Project) |
| Origin-Agent-Cluster (Extended) | **LOW** | An available isolation opt-in left unused: [`?1` stops this page relaxing its origin with document.domain][mdn-docdomain-oac], which [same-site pages on other subdomains can abuse][mdn-docdomain-shared]. Chrome and Edge [already block it by default][chrome-docdomain-115]; MDN warns the process separation [is not a security feature][mdn-oac-hint] |
| Service-Worker-Allowed (Extended) | OK | Absence keeps the [path restriction][sw-allowed]: the safest state |
| Content-Disposition (Extended) | OK | Only needed [on downloads][cs-download] |
| Pragma, Expires (Extended) | OK | [Pragma is deprecated][rfc9111-pragma] and [Expires yields to max-age][rfc9111-expires] (RFC 9111). Pragma sent alongside a correct Cache-Control is harmless; when Cache-Control is missing, its finding adds that Pragma does not replace it |
| ETag (Extended) | OK | [A cache validator][rfc9110-etag]; absence weakens nothing |
| X-Download-Options (Extended), Expect-CT, X-XSS-Protection | OK | Deprecated: absence is correct |
| Content-Type | OK | Not graded: only the charset of an HTML response is checked |
| Access-Control-Allow-Origin, Access-Control-Allow-Credentials | OK | No CORS headers: [the CORS check fails][fetch-cors-null], same-origin only |

An **empty** value is graded as the header's absence: browsers ignore it.

### Duplicate headers

Occurrences are combined the way browsers combine them.

| Strategy | Headers | Result |
|---|---|---|
| join (`, `) | CSP, Referrer-Policy, X-Frame-Options, Cache-Control, Clear-Site-Data, Permissions-Policy, Pragma, COOP, COEP, CORP, X-Content-Type-Options, Access-Control-Allow-Origin, Access-Control-Allow-Credentials, Content-Type, Origin-Agent-Cluster, Service-Worker-Allowed | **LOW** (Duplicated). [RFC 9110 lets a recipient combine them][rfc9110-combine], and Fetch [always does][fetch-get]; the joined value is then checked like any other: which is how two COOP or CORP headers are caught cancelling each other out |
| first wins | HSTS ([RFC 6797: only the first][rfc6797-first]; [ZAP 10035-3 Low][zap-10035-3]) and headers no standard defines a resolution for | **LOW** (Duplicated), noting whether the values conflict |

Where the combined value breaks the header, its own check grades that effect.

---

## Content-Security-Policy

Absent: **MEDIUM**. Parsed per CSP3 §2.2.1; comma-separated policies are
[each enforced][csp3-each] (a resource must pass all). Across policies, an
absence is reported only if no policy declares it; any other finding if any
policy carries it.

No weakness exceeds MEDIUM, the weight of having no CSP; ZAP rates most CSP
weaknesses Medium ([10055-4][zap-10055-4], [-5][zap-10055-5], [-10][zap-10055-10]).

### Scripts

Evaluated through the CSP3 fallback lists (`script-src-elem` → `script-src` →
`default-src`, `script-src-attr` → `script-src` → `default-src`, `script-src` →
`default-src` for eval). Titles name the directive that applied.

| Condition | Severity | Why |
|---|---|---|
| No script-src, script-src-elem or default-src | **MEDIUM** | Scripts are unrestricted, as with no CSP; [CSP Evaluator HIGH][cspe-script] |
| `'unsafe-inline'` without nonce, hash or `'strict-dynamic'` | **MEDIUM** | [ZAP 10055-5 Medium][zap-10055-5]; [Observatory −20][obs-csp-inline] |
| `'unsafe-eval'` | **MEDIUM** | [ZAP 10055-10 Medium][zap-10055-10]; [Observatory −10][obs-csp-eval]; not cancelled by `'strict-dynamic'` |
| `*`, `http:`, `https:`, `data:` | **MEDIUM** | [ZAP 10055-4 Medium][zap-10055-4]; CSP Evaluator HIGH for [wildcards][cspe-wildcard] and [these schemes][cspe-schemes] |
| Wildcard over a TLD (`*.com`, `*.co.uk`) | **MEDIUM** | [`*.` matches every host that ends with the rest][csp3-wildcard]: any domain the attacker registers |
| Known bypass host (JSONP / any-library CDNs: ajax.googleapis.com, cdnjs.cloudflare.com, cdn.jsdelivr.net, unpkg.com, …) or wildcard over one | **MEDIUM** | [CSP Evaluator allowlist bypass, HIGH][cspe-bypass] |
| Wildcard over a domain anyone can publish on (`*.github.io`, `*.herokuapp.com`, …) | **MEDIUM** | [The wildcard matches every subdomain][csp3-wildcard], the attacker's included |
| `blob:`, `filesystem:` | LOW | [A scheme must be listed to be allowed][csp3-schemes], so listing it allows it; creating the URL needs script already running |
| `http://` host source without upgrade-insecure-requests | LOW | On an HTTPS page [the script is blocked as mixed content][mixed-script]; it can only be swapped on a page served over plain HTTP. *Deviation:* [CSP Evaluator `checkSrcHttp` rates it MEDIUM][cspe-http] |
| `'unsafe-hashes'` with a hash | LOW | [Narrow: handlers matching a hash][csp3-unsafe-hashes]. *Deviation:* [ZAP 10055-7 Medium][zap-10055-7] |
| Nonce under 22 base64 characters (< 128 bits) | LOW | [CSP3 asks for 128 bits][csp3-nonce-128] |
| `'unsafe-inline'` next to a nonce/hash or `'strict-dynamic'` | OK (note) | [A nonce or hash][csp3-inline-nonce], or [`'strict-dynamic'`][csp3-inline-sd], switches it off (CSP3 §6.7.3.2): a fallback for old browsers that [does not reduce security][strictcsp-fallback] |
| `'strict-dynamic'` with a nonce/hash: host, scheme and `'self'` entries | OK (note) | [Ignored by CSP3 browsers][csp3-sd-ignores]; [`https:` is the recommended fallback][strictcsp-https] |
| `'strict-dynamic'` with no nonce or hash | OK (note) | [Allowlists are ignored][csp3-sd-ignores] and nothing is trusted: blocks every script, not a weakness |
| `'unsafe-hashes'` with no hash | OK (note) | [Only widens what hashes match][csp3-unsafe-hashes]: no effect |
| Any nonce | OK (check) | [Must be unique per response][csp3-nonce-unique]; one response cannot show it |

### Other directives

| Condition | Severity | Why |
|---|---|---|
| base-uri missing, policy uses a nonce, or a hash with `'strict-dynamic'` | **MEDIUM** | [An injected `<base>` redirects nonced scripts][csp3-base]; [CSP Evaluator HIGH][cspe-base-uri] for exactly these. A hash alone pins the content, which a moved URL cannot change |
| base-uri missing, otherwise | LOW | [ASVS 3.4.3][asvs-3.4.3] asks for base-uri. *Deviation:* [ZAP 10055-13][zap-10055-13] rates a missing no-fallback directive Medium |
| base-uri allows `*`, `http:`, `https:`, `data:` | **MEDIUM** | [Same effect as the nonce bypass][csp3-base] |
| frame-ancestors allows `*`, `http:`, `https:` or a TLD wildcard | **MEDIUM** | Clickjacking, as with no protection; [ASVS 3.4.6][asvs-3.4.6] |
| frame-ancestors missing | LOW | [ASVS 3.4.6][asvs-3.4.6] (L2); it [does not fall back to default-src][csp3-fa-nofallback]. *Deviation:* [ZAP 10055-13 Medium][zap-10055-13] |
| object-src missing (no default-src) or not `'none'` | LOW | [ASVS 3.4.3][asvs-3.4.3] (L2) and [OWASP][bp-csp] ask for `'none'`, and [MDN recommends restricting it][mdn-object-src]. *Deviation:* [CSP Evaluator rates a missing object-src HIGH][cspe-object] |
| default-src missing or permissive | LOW | Every type [without its own directive falls back to it][csp3-default], and without it a policy [cannot mitigate exfiltration][csp3-exfil]; script impact is graded through the fallback |
| form-action missing or permissive | LOW | [It restricts form targets][csp3-form] and is in [OWASP's recommended policy][bp-csp]; needs an injection. *Deviation:* [ZAP 10055-13 Medium][zap-10055-13] |
| style `'unsafe-inline'` without nonce/hash, and img-src or font-src (or their default-src fallback) reaches any origin, or neither is set | **MEDIUM** | Where [the CSP stops script but allows styles][ps-css-csp], [attribute selectors extract values][ps-css-attr] (CSRF tokens, form fields) through background images or fonts, and [without default-src nothing stops that request][csp3-exfil]: an injection becomes token theft. [ZAP 10055-6 Medium][zap-10055-6] |
| style `'unsafe-inline'` without nonce/hash, images and fonts restricted | LOW | Only restyling is left (hiding content, fake messages). [Observatory 0 for style-only][obs-csp-style]. *Deviation:* [ZAP 10055-6 Medium][zap-10055-6] |
| upgrade-insecure-requests missing | LOW | Part of [OWASP's recommended policy][bp-csp] |
| Missing `;`, keyword without quotes, unknown directive, duplicate directive (first wins), non-ASCII directive, `'none'` combined with sources, invalid quoted source | LOW | [ZAP "CSP: Notices" Low][zap-10055-3]; CSP3: [split on `;`][csp3-split], [keywords are quoted][csp3-keywords], [nonces too][csp3-nonce-grammar], [a repeated directive is skipped][csp3-dup], [non-ASCII is skipped][csp3-ascii], [`'none'` stands alone][csp3-none] |
| Obsolete directive (block-all-mixed-content, prefetch-src, navigate-to, plugin-types, reflected-xss, referrer, disown-opener, require-sri-for) | LOW, Deprecated | [MDN: block-all-mixed-content obsolete][mdn-bamc]; [prefetch-src non-standard][mdn-prefetch]; [plugin-types removed][cscsp-plugin-types]; [CSP Evaluator: deprecated directives][cspe-deprecated]; navigate-to and require-sri-for are absent from [CSP3's directive registry][csp3-registry] |
| Several policies in one value | OK (note) | [Each is enforced][csp3-each] ([a comma-separated list][csp3-list]) |
| Only Content-Security-Policy-Report-Only is sent | OK, with a note on the CSP row (the CSP itself is graded as absent) | [ZAP 10038-3 Informational][zap-10038-3] |

---

## Strict-Transport-Security

Absent: **MEDIUM**. RFC 6797 §6.1.

| Condition | Severity | Why |
|---|---|---|
| Not valid (repeated directive, valued includeSubDomains/preload, missing or non-numeric max-age) | **MEDIUM** | [Ignored in full][rfc6797-invalid]: as absent ([Observatory −20][obs-hsts-absent]) |
| `max-age=0` | **MEDIUM** | [Deletes the policy][rfc6797-zero]: as absent. *Deviation:* [ZAP 10035-2 Low][zap-10035-2] |
| max-age below the 2-year profile minimum | LOW | [ASVS 3.4.1 asks ≥ 1 year][asvs-3.4.1], [OWASP Cheat Sheet 2 years][cs-hsts-rec], [hstspreload.org 1 year][hstspreload-min]; [Observatory −10 only below 6 months][obs-hsts-short] |
| No includeSubDomains | LOW | [ASVS 3.4.1 from L2][asvs-3.4.1]; [OWASP][bp-hsts] |
| Extended: preload not declared, or declared | LOW, to confirm | [OWASP Cheat Sheet recommends preload][cs-hsts-rec]; [the token only requests inclusion][hstspreload-token], so list membership is the check |

## X-Frame-Options

Absent: **MEDIUM**, or **LOW** when CSP frame-ancestors restricts framing.
Read as HTML reads it: a set of lowercased values. Invalid values weigh as
absence, following the same frame-ancestors rule.

| Condition | Severity |
|---|---|
| `DENY` | OK ([OWASP][cs-xfo-rec]) |
| `SAMEORIGIN` | LOW, to confirm: [allows a same-origin parent][html-xfo-sameorigin]; [OWASP recommends DENY][bp-xfo] |
| `ALLOW-FROM …` | as absent: [not to be implemented][html-xfo-allowfrom], so [treated as omitted][html-xfo-invalid] ([ZAP 10020-4 Medium][zap-10020-4]); Deprecated |
| Any other single value, or several unusable values | as absent ([single][html-xfo-invalid], [several][html-xfo-several-invalid]) |
| Several values, at least one usable | LOW: [the browser blocks the frame][html-xfo-multi] |
| Present while a permissive CSP frame-ancestors replaces it | OK (note: [XFO is ignored][html-xfo-csp]; the exposure is graded on CSP) |

## X-Content-Type-Options

Absent: **LOW**. Fetch's *determine nosniff*: [only the first value counts][fetch-nosniff].

| Condition | Severity |
|---|---|
| First value `nosniff` | OK ([OWASP][cs-xcto], [Secure Headers][bp-xcto]) |
| Anything else (including `"nosniff"` or `x, nosniff`) | LOW (as absent) |

## Cross-Origin-Opener-Policy

Absent: **LOW**. A structured field item (RFC 9651), compared case-sensitively;
[a value that fails to parse is ignored][rfc9651-fail].

| Condition | Severity |
|---|---|
| `same-origin` (with or without parameters) | OK ([OWASP][cs-coop-rec], [Secure Headers][bp-coop]) |
| `same-origin-allow-popups`, `noopener-allow-popups` | LOW, to confirm: [OWASP recommends same-origin][cs-coop-rec]; [ASVS 3.4.8 accepts allow-popups][asvs-3.4.8] |
| `unsafe-none`, more than one value, unparseable, unknown or wrong-case token, `same-origin-plus-COEP` ([cannot be set directly][html-coop-plus]) | LOW (as absent) |

## Cross-Origin-Embedder-Policy

Absent: **LOW**.

| Condition | Severity |
|---|---|
| `require-corp`, `credentialless` | OK: [both qualify for cross-origin isolation][html-coep-compat] ([Secure Headers][bp-coep]) |
| `unsafe-none`, unknown, wrong case, unparseable, more than one value | LOW (as absent) |

## Cross-Origin-Resource-Policy

Absent: **LOW**. [Compared byte for byte][fetch-corp].

| Condition | Severity |
|---|---|
| `same-origin`, `same-site` | OK ([OWASP][cs-corp], [Secure Headers][bp-corp]) |
| `cross-origin` | LOW, to confirm (is it meant to be embedded?) |
| Anything else, including two copies joined by a comma | LOW (as absent) |

## Permissions-Policy

Absent: **LOW** ([ZAP 10063-1][zap-10063-1]). An RFC 9651 dictionary, graded
on each feature's [default allowlist][pp-default].

| Condition | Severity |
|---|---|
| Does not parse (Feature-Policy syntax, uppercase names, trailing comma) | LOW (as absent): [the policy is empty][pp-empty] |
| A member that is not `*`, `self`, a quoted origin or a list of those | LOW: [that member is ignored][pp-dict] |
| A `self`-default feature widened to `*` | LOW: [features default to self][chromium-default-self] |
| camera, microphone or geolocation delegated to a named origin | LOW, to confirm: [the grant goes to the top-level origin][permissions-delegation] |
| Tracking features reachable by embedded documents | LOW, to confirm: their default is every origin ([Topics][chromium-topics], [Attribution Reporting][attribution-default], [UA high-entropy hints][chromium-uach], Private State Tokens [issuance][chromium-pst-issuance] and [redemption][chromium-pst-redemption], [Storage Access][chromium-storage-access]; also [gamepad][chromium-gamepad], [picture-in-picture][chromium-pip] and [deferred-fetch-minimal][chromium-deferred], not reported) |
| camera, microphone or geolocation reachable by an XSS on this origin | LOW, to confirm: their default is self ([camera, microphone][mediacapture-default], [geolocation][geolocation-default]); [the OWASP Cheat Sheet example closes exactly these][cs-pp-example] |
| None of the above | OK |

## Referrer-Policy

Absent: **LOW**. [The last recognised token wins][referrer-last].

| Effective policy | Severity |
|---|---|
| `no-referrer`, `same-origin`, `strict-origin`, `strict-origin-when-cross-origin` | OK ([Secure Headers][bp-rp], [Cheat Sheet][cs-rp-default]) |
| `origin`, `origin-when-cross-origin` | LOW, to confirm (plain-HTTP destinations?) |
| `no-referrer-when-downgrade`, `unsafe-url` | LOW: [Observatory −5][obs-rp-unsafe]; [PortSwigger Information][ps-referer] |
| No recognised token | LOW (as absent) |

## Cache-Control

Absent: **LOW**, to confirm. When the response carries Pragma instead, in any
profile, the finding adds that [Pragma's meaning in a response was never
specified][rfc9111-pragma-response], so it [does not replace
Cache-Control][mdn-pragma]. Every verdict except `no-store` asks one question:
does the response carry a signed-in user's data, and is the user identified by
a cookie or by an Authorization header ([RFC 9111 §3.5][rfc9111-auth])?

| Condition | Severity |
|---|---|
| `no-store` | OK ([Cheat Sheet][cs-cc-nostore], [ASVS 14.3.2][asvs-14.3.2], [Secure Headers][bp-cc]) |
| `private` ([shared caches must not store it][rfc9111-private], [private ones still may][cs-cc-private]), `no-cache` ([does not prevent caching][cs-cc-nocache]), `max-age=0` with must-/proxy-revalidate, no directive a cache understands ([heuristic caching][rfc9111-heuristic], [OWASP: do not rely on defaults][cs-cc-default]) | LOW, to confirm |
| Storable by shared caches (`max-age`, `s-maxage`, `public`, qualified `private=`/`no-cache=`) | **MEDIUM**, to confirm: grants more than the default; impact high (one user's data served to another) × likelihood low. [public, s-maxage and must-revalidate][rfc9111-auth-directives] even reopen shared caching of Authorization requests |

## Clear-Site-Data (Extended)

Absent: **LOW**, to confirm (does this response end a session?
[Logout, account deletion][csd-logout]). Values are [quoted strings][csd-grammar]
compared with their quotes; [unknown types are ignored][csd-unknown].

| Condition | Severity |
|---|---|
| `"*"`, or `"cache"`, `"cookies"` and `"storage"` together | OK |
| Some known types, not all three | LOW, to confirm: [a subset can be deliberate][csd-subset], and the header [costs processing time][bp-csd-time] |
| No known type (unquoted `*` or `cookies`): clears nothing | LOW, to confirm |

## X-Permitted-Cross-Domain-Policies

Absent: **LOW**.

| Condition | Severity |
|---|---|
| `none`, `master-only` | OK ([none][mdn-xpcdp-none]) |
| `none-this-response` | LOW (as absent): [it only covers this response][mdn-xpcdp-ntr], no site-wide meta-policy |
| `all`, `by-content-type`, `by-ftp-filename` | **MEDIUM**, to confirm: [allows non-master policy files][adobe-master] ([ZAP 20016-1 rates a permissive policy High][zap-20016-1]; [MDN][mdn-xpcdp]) |
| Anything else | LOW (as absent): [ignored][adobe-invalid] |

## X-DNS-Prefetch-Control

Absent: **LOW**, to confirm, in both profiles. The header is [not
standard][cs-xdns-nonstd] ([MDN][mdn-xdns-nonstd]).

The check asks whether the page shows any of the OWASP conditions: [links to
sites you do not control][cs-xdns], [sensitive or personal data][bp-xdns-pii],
or input from users, which is what makes it [prone to HTML
injection][bp-xdns-inj]. Any of them: the finding stands. None: nothing here.

| Condition | Severity |
|---|---|
| `off` | OK |
| Anything else | LOW, to confirm (as absent) |

## Access-Control-Allow-Origin

Absent: OK. Fetch [compares the value byte for byte][fetch-cors-origin].

| Condition | Severity | Why |
|---|---|---|
| `null` | **MEDIUM** | [ZAP 40040-2 Medium][zap-40040-2] [without credentials][zap-cors-risk]; [MDN: null should not be used][mdn-acao-null] |
| `*` | LOW, to confirm | [ASVS 3.4.2: no sensitive data with `*`][asvs-3.4.2-star]; OWASP: [fine for a public API][cs-acao-public], [public without authentication][bp-cors-public], otherwise [set specific origins][cs-acao-rec]; [Observatory 0][obs-cors-public]. *Deviation:* [ZAP rates `*` Medium][zap-cors-risk] |
| One https origin | LOW, to confirm | [ASVS 3.4.2: fixed or allowlisted][asvs-3.4.2]; [never mirrored][bp-cors-mirror]: the check replays a made-up Origin |
| An `http://` origin | LOW; **MEDIUM** with credentials (see below) | [PortSwigger "unencrypted origin trusted"][ps-cors-http]. *Deviation:* [ZAP rates it Medium without credentials][zap-cors-risk] |
| `NULL` (other casing), or a list of origins | OK (note) | [Matches no origin][fetch-cors-origin]: nobody gets access |

## Access-Control-Allow-Credentials

Absent: OK. [Only the exact value `true`][fetch-cors-cred] enables
credentials; the verdict depends on Access-Control-Allow-Origin.

| Allowed origin, with credentials `true` | Severity | Why |
|---|---|---|
| `null` | **HIGH** | [ZAP 40040-3 High][zap-40040-3] [with credentials][zap-cors-risk]; any page can obtain the null origin ([MDN][mdn-acao-null]) and read authenticated responses |
| One `http://` origin | **MEDIUM** | [Anyone on that origin's network path can inject into it][ps-cors-http] and read authenticated responses: impact high × likelihood low. [ZAP rates it High][zap-cors-risk] |
| One https origin | LOW, to confirm | [The "restricted with authentication" configuration OWASP recommends][bp-cors-auth]; HIGH if [the origin is mirrored][bp-cors-mirror], which the check settles |
| `*`, none, a list or `NULL` | OK (note) | [`*` never passes with credentials][fetch-cors-star] ([OWASP][bp-cors-star-cred]); the others [match no origin][fetch-cors-origin] |
| Credentials not `true` | OK | |

## Origin-Agent-Cluster (Extended)

Absent: **LOW**.

| Condition | Severity |
|---|---|
| `?1` | OK |
| `?0` | LOW: in Chrome and Edge [it re-enables document.domain][chrome-docdomain-opt-out], which [they otherwise block][chrome-docdomain-115]; other browsers [ignore it][mdn-oac-ignored] and [act only on `?1`][html-oac] |
| Anything else | LOW (as absent) |

## Service-Worker-Allowed (Extended)

| Condition | Severity |
|---|---|
| Absent | OK |
| `/` | LOW, to confirm: [it removes the path restriction][sw-allowed] for the whole site |
| Any other path | OK (note) |

## Content-Type

Only one thing is checked: whether an HTML response declares its character
encoding. The OWASP Cheat Sheet: ["the charset attribute is necessary to
prevent XSS in HTML pages"][cs-ct-charset]. Without one, Chrome and Firefox
detect the encoding from the bytes, and [a single injected ISO-2022-JP escape
sequence is usually enough][sonar-detect] to switch the whole page to that
encoding, where escaping applied by the server can stop working.

The value is read as [Fetch "extract a MIME type"][fetch-mime] reads it: every
value of the header in order, the last valid type wins and keeps an earlier
charset for the same type; an empty `charset=` counts as none; [a type with
whitespace around the slash is not valid][mimesniff-type]. A charset counts
only if it is one of the 228 labels the WHATWG Encoding Standard defines
([matched trimmed and case-insensitive][encoding-label]): `utf8` and `latin1`
are recognised, `utf_8` or `foo` are not.

| Condition | Severity |
|---|---|
| `text/html` with a `charset` the browser recognises | OK: [the transport encoding is used][html-charset-transport] |
| `text/html` with an unrecognised `charset` | LOW, Misconfigured, to confirm: browsers discard it and guess, as if none were declared |
| `text/html` without a `charset` | LOW, Misconfigured, to confirm: the page itself can declare it with `<meta charset>` [in its first 1024 bytes][html-charset-1024], or a UTF-8 byte order mark, which a header-only review cannot see |
| Any other type, an unparseable value, or no Content-Type | OK, not graded |

## Content-Disposition, Pragma, Expires, ETag (Extended)

Absent or present with any value: OK, with a note where there is something to
explain: `inline` ([attachment is what keeps uploads from rendering][bp-upload]),
an unknown disposition type ([handled as attachment][rfc6266-unknown]), legacy
caching headers ([Pragma deprecated][rfc9111-pragma], [Expires ignored next to
max-age][rfc9111-expires]), ETag ([which can even be abused for
tracking][rfc9110-etag-privacy]).

## Deprecated headers

| Header | Condition | Severity |
|---|---|---|
| X-XSS-Protection | `0` (with or without directives) | OK: [OWASP: off or not set][cs-xxp-rec] |
| X-XSS-Protection | `1`, `1; mode=block`, anything else | LOW, Deprecated: [can create XSS][cs-xxp-warn] ([MDN][mdn-xxp-warn]); `mode=block` [is open to side channels][mdn-xxp-block]; [OWASP lists it as deprecated][shp-deprecated] |
| Expect-CT | Any value | LOW, Deprecated: [OWASP: "do not use"][cs-expectct]; [only Chromium implemented it, deprecated from version 107][mdn-expectct] |
| X-Download-Options (Extended) | Any value, `noopen` included | LOW, Deprecated: [an Internet Explorer 8 feature][ie8-xdo]; [Internet Explorer 11 support ended in 2022][ie-end] |

---

## REST API mode

The response is a call to an API read by a browser. The cheat sheet's table is
for exactly that: headers that ["should be included in all API responses that
may be consumed by browser clients"][rest-scope]. Headers are read, and duplicates resolved, as in Web page mode; what
changes is the criterion.

### Every API response (Basic and Extended)

| Header | Expected | Missing or wrong | Why |
|---|---|---|---|
| Content-Security-Policy | `frame-ancestors 'none'` | **LOW** | [An API response never needs to be framed][rest-fa]; it [protects against drag-and-drop clickjacking][rest-fa-dnd]; [ASVS 3.4.6][asvs-3.4.6]. *Deviation:* in Web page mode missing anti-framing is MEDIUM. Here the attack needs an endpoint answering GET, cookies a cross-site frame still sends, and the user dragging data out, so it is graded LOW. A `frame-ancestors` naming sites is LOW too |
| Content-Type | the type of the body | **LOW** | [Must be specified as per the content returned][rest-ct], or [a browser might guess it][rest-ct-guess]; [ASVS 4.1.1][asvs-4.1.1]. An invalid value is LOW as well. No charset is asked of `application/json`: ASVS 4.1.1 asks for it on text and XML types |
| Content-Type `text/html` | | LOW, to confirm | Is the body really HTML? If not, this stands |
| Content-Type of a [JavaScript MIME type][mimesniff-js] | | LOW, to confirm | The cheat sheet: [application/json and not application/javascript][rest-ct-js]. Another site can run it with `<script src>` ([Cross-Site Script Inclusion][mdn-corp-xssi]). Is the body really JavaScript? If not, this stands |
| Cache-Control | `no-store` | as in Web page mode: a check on whether the response carries a signed-in user's data | The cheat sheet asks for no-store, [not stored by private or shared caches][rest-cc], on every API response. *Deviation:* the tool asks for it where the response carries a user's data, as in Web page mode, because a cached public response exposes no one |
| Strict-Transport-Security | as in Web page mode | as in Web page mode | Same rules, same severities |
| X-Content-Type-Options | `nosniff` | as in Web page mode | Same rules |
| X-Frame-Options | `DENY` | **LOW** | [Still recommended for browsers without CSP Level 2][rest-xfo]. `SAMEORIGIN` is LOW: [no API response needs framing][rest-fa]. *Deviation:* the OWASP HTTP Headers Cheat Sheet says it [does not provide any security][cs-xfo-api] on a JSON API; the REST Security Cheat Sheet, the reference for this mode, still recommends it. Next to a `frame-ancestors` that lets any site frame the response, a note says browsers [ignore this header][csp3-fa-xfo], as in Web page mode |

In this mode the CSP is read for two directives only: `frame-ancestors` (above)
and `default-src` (below). [Most of what a CSP does only affects pages rendered
as HTML][rest-csp-dd], and the OWASP HTTP Headers Cheat Sheet notes that a CSP
[might be meaningless][cs-csp-api] on a response that is not rendered, so the
script, style and other directive checks of Web page mode are not run.

### Defence in depth (Basic and Extended)

These headers are [only intended to provide additional security when responses
are rendered as HTML][rest-dd], and are recommended [if there is any
uncertainty about the types of information the API returns][rest-dd-uncertain].
Missing or wrong, each is **LOW, to confirm**, with the same check: can this API
return HTML, now or in a later version? Never: nothing here. It can, or you
cannot be sure: the finding stands.

| Header | Expected | Why |
|---|---|---|
| Content-Security-Policy | `default-src 'none'` | [Most CSP functionality only affects pages rendered as HTML][rest-csp-dd] |
| Permissions-Policy | every feature it names closed with `()`, as in the cheat sheet's example; it need not name them all | [Controls browser features][rest-pp]. A feature it allows (`self`, `*`, an origin) is LOW, to confirm, and the title names it |
| Referrer-Policy | `no-referrer` | [Non-HTML responses should not trigger additional requests][rest-rp] |

CORS headers keep their Web page rules; the cheat sheet asks to [be as specific
as possible][rest-cors] with allowed origins.

### Other headers (Extended only)

| Header | In REST API mode | Why |
|---|---|---|
| Cross-Origin-Opener-Policy | OK, not applicable | Acts on windows; OWASP: [may not make sense for REST APIs][cs-coop-api] |
| Cross-Origin-Embedder-Policy | OK, not applicable | [A document's policy for loading cross-origin resources][mdn-coep-doc] |
| Origin-Agent-Cluster | OK, not applicable | [Places a Document in an origin-keyed agent cluster][mdn-oac-doc] |
| X-DNS-Prefetch-Control | OK, not applicable | Prefetching acts on [links and items referenced by the document][mdn-xdns-doc] |
| Cross-Origin-Resource-Policy | missing: **LOW, to confirm** (see below); present: as in Web page mode | [Recommended for API responses called only from the same origin][webdev-corp-api] |
| X-XSS-Protection | as in Web page mode: `1` is LOW, deprecated | The filter [stopped pages from loading][mdn-xxp-pages]; an API response is not rendered, so the description says the risk is gone and an obsolete header is what is left |
| Every other header | as in Web page mode | Clear-Site-Data stays a check: a logout is often an API call. The REST Security Cheat Sheet does not name it because [stateful services are out of its scope][rest-stateless]; [ASVS 14.3.1][asvs-14.3.1] and the [Session Management Cheat Sheet][session-csd] ask for it when a session ends, API or page |

### Cross-Origin-Resource-Policy on an API

CORP acts when another site loads a resource [in no-cors mode][mdn-corp-nocors],
with a tag such as `<script>` or `<img>`. With `same-origin` the browser drops
the response before the other site's page gets it. It mitigates [Spectre-style
attacks and Cross-Site Script Inclusion][mdn-corp-xssi]. On an API with a
signed-in user's data, three attacks are possible without it:

- **Reading the data through `<script>`.** An endpoint that returns JavaScript
  with the user's data (a configuration file, an old JSONP API) is included by
  another site with `<script src>`; the browser runs it in that site's page,
  which reads the data. The browser's own blocking of opaque JSON responses does
  not apply here, because the response is valid JavaScript.
- **Reading memory with Spectre.** `<img src>` pointed at a JSON endpoint pulls
  the response into the other site's process, where a Spectre attack can read
  it. CORP keeps it out.
- **Telling whether the user is signed in.** `<script src>` on an endpoint that
  answers 200 when signed in and 401 otherwise fires `onload` or `onerror`;
  CORP makes it fail every time.

None of this works unless the tag's request is answered with the user's data:

- a tag's request uses [GET][fetch-method-get], so an endpoint that only
  accepts POST cannot be reached this way;
- an `Authorization` header is never added to it, so an API authenticated that
  way answers as for an anonymous user;
- a cookie set with `SameSite=Lax` or `Strict` is [not sent on a cross-site
  subresource request][mdn-samesite-lax]. Without the attribute, [some browsers
  apply Lax by default][mdn-samesite-default] and others send the cookie.

Browsers that implement opaque response blocking already withhold a response
whose type is [HTML, JSON or XML][orb-blocklist] from such a tag, when its
Content-Type is right: the REST Security Cheat Sheet's own rules (the [right
Content-Type][rest-ct-js], `nosniff`) make that work. That protection is a browser feature, though,
not something the API asks for: it depends on the browser or WebView at the
other end, and it does not cover other types (a file, an image). CORP asks for
it explicitly, from every browser and for every type, and [all resources are
recommended to send it][webdev-corp-all]. The tool keeps it as defence in depth.

Hence the check: does this endpoint answer GET requests with user data,
authenticated by cookies? If it does, the finding stands.

---

## Citations

Every passage the app and this file cite, in full. Each link opens the source
with the passage highlighted.

<!-- sources:start: generated by `npm run sources` from src/core/sources.js; do not edit by hand -->

- `adobe-default`: [Adobe, Cross Domain Configuration][adobe-default]: “By default, when requested content is not from the same origin as the requesting document, Acrobat and Adobe Reader automatically attempt to load a server-based policy file from that domain to get permission for such access.”
- `adobe-invalid`: [Adobe, Cross Domain Configuration][adobe-invalid]: “An invalid meta-policy was specified in an X-Permitted-Cross-Domain-Policies HTTP header. It has been ignored.”
- `adobe-master`: [Adobe, Cross Domain Configuration][adobe-master]: “The use of non-master policy files require a site to have a meta-policy of “by-content-type” or “all”.”
- `asvs-14.3.1`: [OWASP ASVS 5.0, V14 Data Protection][asvs-14.3.1]: “The 'Clear-Site-Data' HTTP response header field may be able to help with this”
- `asvs-14.3.2`: [OWASP ASVS 5.0, V14 Data Protection][asvs-14.3.2]: “Verify that the application sets sufficient anti-caching HTTP response header fields (i.e., Cache-Control: no-store) so that sensitive data is not cached in browsers.”
- `asvs-3.4.1`: [OWASP ASVS 5.0, V3 Web Frontend Security][asvs-3.4.1]: “A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well.”
- `asvs-3.4.2`: [OWASP ASVS 5.0, V3 Web Frontend Security][asvs-3.4.2]: “is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins”
- `asvs-3.4.2-star`: [OWASP ASVS 5.0, V3 Web Frontend Security][asvs-3.4.2-star]: “When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information.”
- `asvs-3.4.3`: [OWASP ASVS 5.0, V3 Web Frontend Security][asvs-3.4.3]: “As a minimum, a global policy must be used which includes the directives object-src 'none' and base-uri 'none' and defines either an allowlist or uses nonces or hashes.”
- `asvs-3.4.4`: [OWASP ASVS 5.0, V3 Web Frontend Security][asvs-3.4.4]: “Verify that all HTTP responses contain an 'X-Content-Type-Options: nosniff' header field.”
- `asvs-3.4.5`: [OWASP ASVS 5.0, V3 Web Frontend Security][asvs-3.4.5]: “Verify that the application sets a referrer policy to prevent leakage of technically sensitive data to third-party services”
- `asvs-3.4.6`: [OWASP ASVS 5.0, V3 Web Frontend Security][asvs-3.4.6]: “Verify that the web application uses the frame-ancestors directive of the Content-Security-Policy header field for every HTTP response”
- `asvs-3.4.6-xfo`: [OWASP ASVS 5.0, V3 Web Frontend Security][asvs-3.4.6-xfo]: “Note that the X-Frame-Options header field, although supported by browsers, is obsolete and may not be relied upon.”
- `asvs-3.4.8`: [OWASP ASVS 5.0, V3 Web Frontend Security][asvs-3.4.8]: “include the Cross‑Origin‑Opener‑Policy header field with the same-origin directive or the same-origin-allow-popups directive as required”
- `asvs-4.1.1`: [OWASP ASVS 5.0, V4 API and Web Service][asvs-4.1.1]: “Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response”
- `attribution-default`: [Attribution Reporting API][attribution-default]: “This specification defines a policy-controlled feature identified by the string "attribution-reporting". Its default allowlist is *.”
- `bp-cache`: [OWASP Secure Headers Project, Best Practices][bp-cache]: “So, the browser will store a copy of the file (here a PDF one) into its cache storage for a certain amount of time.”
- `bp-cc`: [OWASP Secure Headers Project, Best Practices][bp-cc]: “no-store, max-age=0”
- `bp-coep`: [OWASP Secure Headers Project, Best Practices][bp-coep]: “Cross-Origin-Embedder-Policy: require-corp”
- `bp-coop`: [OWASP Secure Headers Project, Best Practices][bp-coop]: “Cross-Origin-Opener-Policy: same-origin”
- `bp-corp`: [OWASP Secure Headers Project, Best Practices][bp-corp]: “Cross-Origin-Resource-Policy: same-origin”
- `bp-cors-auth`: [OWASP Secure Headers Project, Best Practices][bp-cors-auth]: “Your endpoints are expected to be consumed, by a browser, from a specific collection of origins with authentication.”
- `bp-cors-mirror`: [OWASP Secure Headers Project, Best Practices][bp-cors-mirror]: “Never take the value of the request header Origin to add it into the response header Access-Control-Allow-Origin (mirroring)”
- `bp-cors-public`: [OWASP Secure Headers Project, Best Practices][bp-cors-public]: “Your endpoints are expected to be consumed, by a browser, from any origins without any authentication.”
- `bp-cors-star-cred`: [OWASP Secure Headers Project, Best Practices][bp-cors-star-cred]: “The value *, for the response header Access-Control-Allow-Origin, cannot be used when the response header Access-Control-Allow-Credentials is allowed (true).”
- `bp-csd-logout`: [OWASP Secure Headers Project, Best Practices][bp-csd-logout]: “set it to the logout function when possible”
- `bp-csd-time`: [OWASP Secure Headers Project, Best Practices][bp-csd-time]: “The header Clear-Site-Data will cause the browser to take additional processing time for the HTTP response”
- `bp-csp`: [OWASP Secure Headers Project, Best Practices][bp-csp]: “default-src 'self'; form-action 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests”
- `bp-hsts`: [OWASP Secure Headers Project, Best Practices][bp-hsts]: “Strict-Transport-Security: max-age=63072000; includeSubDomains”
- `bp-rp`: [OWASP Secure Headers Project, Best Practices][bp-rp]: “Referrer-Policy: no-referrer”
- `bp-upload`: [OWASP Secure Headers Project, Best Practices][bp-upload]: “If such a feature allows uploading of HTML files (also applies for SVG files) then it can be used, as a vector, to store an HTML file containing JavaScript code.”
- `bp-xcto`: [OWASP Secure Headers Project, Best Practices][bp-xcto]: “X-Content-Type-Options: nosniff”
- `bp-xdns-inj`: [OWASP Secure Headers Project, Best Practices][bp-xdns-inj]: “Prone to HTML injection where an attacker can inject a tag”
- `bp-xdns-pii`: [OWASP Secure Headers Project, Best Practices][bp-xdns-pii]: “Return sensitive or private content (commonly called PII).”
- `bp-xfo`: [OWASP Secure Headers Project, Best Practices][bp-xfo]: “X-Frame-Options: deny”
- `bp-xpcdp`: [OWASP Secure Headers Project, Best Practices][bp-xpcdp]: “X-Permitted-Cross-Domain-Policies: none”
- `chrome-docdomain-115`: [Chrome for Developers, document.domain setter deprecation][chrome-docdomain-115]: “Starting in Chrome 115, websites will be unable to set document.domain: Chrome will make document.domain immutable.”
- `chrome-docdomain-opt-out`: [Chrome for Developers, document.domain setter deprecation][chrome-docdomain-opt-out]: “When you send this header, your document can continue to set document.domain even after it becomes immutable by default.”
- `chromium-default-self`: [Chromium, Permissions Policy features][chromium-default-self]: “feature_default: default "EnableForSelf"”
- `chromium-deferred`: [Chromium, Permissions Policy features][chromium-deferred]: “deferred-fetch-minimal: feature_default "EnableForAll"”
- `chromium-gamepad`: [Chromium, Permissions Policy features][chromium-gamepad]: “gamepad: feature_default "EnableForAll"”
- `chromium-pip`: [Chromium, Permissions Policy features][chromium-pip]: “picture-in-picture: feature_default "EnableForAll"”
- `chromium-pst-issuance`: [Chromium, Permissions Policy features][chromium-pst-issuance]: “private-state-token-issuance: feature_default "EnableForAll"”
- `chromium-pst-redemption`: [Chromium, Permissions Policy features][chromium-pst-redemption]: “private-state-token-redemption: feature_default "EnableForAll"”
- `chromium-storage-access`: [Chromium, Permissions Policy features][chromium-storage-access]: “storage-access: feature_default "EnableForAll"”
- `chromium-topics`: [Chromium, Permissions Policy features][chromium-topics]: “browsing-topics: feature_default "EnableForAll"”
- `chromium-uach`: [Chromium, Permissions Policy features][chromium-uach]: “ch-ua-high-entropy-values: feature_default "EnableForAll"”
- `cs-acao-public`: [OWASP HTTP Headers Cheat Sheet][cs-acao-public]: “for a public API that should be accessible from any origin, it might be necessary to allow”
- `cs-acao-rec`: [OWASP HTTP Headers Cheat Sheet][cs-acao-rec]: “If you use it, set specific origins instead of *.”
- `cs-cc-default`: [OWASP HTTP Headers Cheat Sheet][cs-cc-default]: “Avoid relying on default caching behavior for sensitive or protected content.”
- `cs-cc-nocache`: [OWASP HTTP Headers Cheat Sheet][cs-cc-nocache]: “Be aware that no-cache does not prevent caching; it allows caches to store responses.”
- `cs-cc-nostore`: [OWASP HTTP Headers Cheat Sheet][cs-cc-nostore]: “Use no-store for sensitive responses to prohibit storage in compliant HTTP caches.”
- `cs-cc-private`: [OWASP HTTP Headers Cheat Sheet][cs-cc-private]: “note that private caches may still persist the response”
- `cs-coep`: [OWASP HTTP Headers Cheat Sheet][cs-coep]: “prevents a document from loading any cross-origin resources that don't explicitly grant the document permission (using CORP or CORS)”
- `cs-coop-api`: [OWASP HTTP Headers Cheat Sheet][cs-coop-api]: “it may not make sense to be applied to REST APIs or clients that are not browsers”
- `cs-coop-rec`: [OWASP HTTP Headers Cheat Sheet][cs-coop-rec]: “Isolates the browsing context exclusively to same-origin documents.”
- `cs-coop-spectre`: [OWASP HTTP Headers Cheat Sheet][cs-coop-spectre]: “This mechanism protects against attacks like Spectre which can cross the security boundary established by Same Origin Policy (SOP) for resources in the same browsing context group.”
- `cs-corp`: [OWASP HTTP Headers Cheat Sheet][cs-corp]: “It is a robust defense against attacks like Spectre, as it allows browsers to block a given response before it enters an attacker's process.”
- `cs-csp-api`: [OWASP HTTP Headers Cheat Sheet][cs-csp-api]: “might be meaningless in the response of a REST API that returns content that is not going to be rendered”
- `cs-ct-charset`: [OWASP HTTP Headers Cheat Sheet][cs-ct-charset]: “the charset attribute is necessary to prevent XSS in HTML pages”
- `cs-download`: [OWASP HTTP Headers Cheat Sheet][cs-download]: “Use Content-Disposition: attachment to force download instead of inline rendering.”
- `cs-expectct`: [OWASP HTTP Headers Cheat Sheet][cs-expectct]: “Do not use it. Mozilla recommends avoiding it, and removing it from existing code if possible.”
- `cs-hsts-rec`: [OWASP HTTP Headers Cheat Sheet][cs-hsts-rec]: “Strict-Transport-Security: max-age=63072000; includeSubDomains; preload”
- `cs-pp-example`: [OWASP HTTP Headers Cheat Sheet][cs-pp-example]: “This example is disabling geolocation, camera, and microphone for all domains.”
- `cs-pp-rec`: [OWASP HTTP Headers Cheat Sheet][cs-pp-rec]: “Set it and disable all the features that your site does not need or allow them only to the authorized domains”
- `cs-rp-default`: [OWASP HTTP Headers Cheat Sheet][cs-rp-default]: “Modern browsers default to strict-origin-when-cross-origin”
- `cs-rp-rec`: [OWASP HTTP Headers Cheat Sheet][cs-rp-rec]: “Set the header explicitly rather than relying on browser defaults.”
- `cs-xcto`: [OWASP HTTP Headers Cheat Sheet][cs-xcto]: “This header is used to block browsers' MIME type sniffing, which can transform non-executable MIME types into executable MIME types (MIME Confusion Attacks).”
- `cs-xdns`: [OWASP HTTP Headers Cheat Sheet][cs-xdns]: “If you do not control links on your website, you might want to set off as a value to disable DNS prefetch to avoid leaking information to those domains.”
- `cs-xdns-nonstd`: [OWASP HTTP Headers Cheat Sheet][cs-xdns-nonstd]: “it is not standard or fully supported and implementation may vary among browsers”
- `cs-xfo-api`: [OWASP HTTP Headers Cheat Sheet][cs-xfo-api]: “If the HTTP response is a redirect or an API returning JSON data, X-Frame-Options does not provide any security.”
- `cs-xfo-fa`: [OWASP HTTP Headers Cheat Sheet][cs-xfo-fa]: “Content Security Policy (CSP) frame-ancestors directive obsoletes X-Frame-Options for supporting browsers”
- `cs-xfo-rec`: [OWASP HTTP Headers Cheat Sheet][cs-xfo-rec]: “Do not allow displaying of the page in a frame.”
- `cs-xxp-rec`: [OWASP HTTP Headers Cheat Sheet][cs-xxp-rec]: “Do not set this header or explicitly turn it off.”
- `cs-xxp-warn`: [OWASP HTTP Headers Cheat Sheet][cs-xxp-warn]: “in some cases, this header can create XSS vulnerabilities in otherwise safe websites”
- `cscsp-plugin-types`: [OWASP Content Security Policy Cheat Sheet][cscsp-plugin-types]: “plugin-types has been removed from the CSP specification.”
- `csd-grammar`: [W3C Clear Site Data][csd-grammar]: “Clear-Site-Data = 1#( quoted-string )”
- `csd-logout`: [W3C Clear Site Data][csd-logout]: “when the user signs out of the application, or deletes their account”
- `csd-subset`: [W3C Clear Site Data][csd-subset]: “so many that it’s not entirely clear which of them would be safe to clear as a response to a logout action”
- `csd-unknown`: [W3C Clear Site Data][csd-unknown]: “User agents MUST ignore unknown types when parsing the header.”
- `csp3-ascii`: [W3C Content Security Policy Level 3][csp3-ascii]: “If token is an empty string, or if token is not an ASCII string, continue.”
- `csp3-base`: [W3C Content Security Policy Level 3][csp3-base]: “However, if an attacker can inject a base element, then an otherwise safe page can be subverted when relative URLs are resolved.”
- `csp3-default`: [W3C Content Security Policy Level 3][csp3-default]: “when default-src is set, every fetch directive that isn’t explicitly set will fall back to the value default-src specifies”
- `csp3-dup`: [W3C Content Security Policy Level 3][csp3-dup]: “If policy’s directive set contains a directive whose name is directive name, continue.”
- `csp3-each`: [W3C Content Security Policy Level 3][csp3-each]: “When the user agent receives a Content-Security-Policy header field, it MUST parse and enforce each serialized CSP it contains”
- `csp3-exfil`: [W3C Content Security Policy Level 3][csp3-exfil]: “Note that a policy which lacks the default-src directive cannot mitigate exfiltration”
- `csp3-fa-nofallback`: [W3C Content Security Policy Level 3][csp3-fa-nofallback]: “frame-ancestors will not fall back to the default-src directive’s value if one is specified”
- `csp3-fa-xfo`: [W3C Content Security Policy Level 3][csp3-fa-xfo]: “If a resource is delivered with a policy that includes a directive named frame-ancestors and whose disposition is "enforce", then the X-Frame-Options header will be ignored, per HTML’s processing model.”
- `csp3-form`: [W3C Content Security Policy Level 3][csp3-form]: “The form-action directive restricts the URLs which can be used as the target of a form submissions from a given context.”
- `csp3-inline-nonce`: [W3C Content Security Policy Level 3][csp3-inline-nonce]: “If expression matches the nonce-source or hash-source grammar, return "Does Not Allow".”
- `csp3-inline-sd`: [W3C Content Security Policy Level 3][csp3-inline-sd]: “If type is "script", "script attribute" or "navigation" and expression matches the keyword-source "'strict-dynamic'", return "Does Not Allow".”
- `csp3-keywords`: [W3C Content Security Policy Level 3][csp3-keywords]: “keyword-source = "'self'" / "'unsafe-inline'" / "'unsafe-eval'"”
- `csp3-list`: [W3C Content Security Policy Level 3][csp3-list]: “A serialized CSP list is an ASCII string consisting of a comma-delimited series of serialized CSPs”
- `csp3-nonce-128`: [W3C Content Security Policy Level 3][csp3-nonce-128]: “The generated value SHOULD be at least 128 bits long (before encoding)”
- `csp3-nonce-grammar`: [W3C Content Security Policy Level 3][csp3-nonce-grammar]: “nonce-source = "'nonce-" base64-value "'"”
- `csp3-nonce-unique`: [W3C Content Security Policy Level 3][csp3-nonce-unique]: “the server MUST generate a unique value each time it transmits a policy”
- `csp3-none`: [W3C Content Security Policy Level 3][csp3-none]: “serialized-source-list = ( source-expression *( required-ascii-whitespace source-expression ) ) / "'none'"”
- `csp3-registry`: [W3C Content Security Policy Level 3][csp3-registry]: “The Content Security Policy Directive registry should be updated with the following directives and references”
- `csp3-schemes`: [W3C Content Security Policy Level 3][csp3-schemes]: “The source expression matching has been changed to require explicit presence of any non-HTTP(S) scheme”
- `csp3-sd-ignores`: [W3C Content Security Policy Level 3][csp3-sd-ignores]: “host-source and scheme-source expressions, as well as the "'unsafe-inline'" and "'self' keyword-sources will be ignored when loading script.”
- `csp3-split`: [W3C Content Security Policy Level 3][csp3-split]: “For each token returned by strictly splitting serialized on the U+003B SEMICOLON character (;):”
- `csp3-strict`: [W3C Content Security Policy Level 3][csp3-strict]: “enforcing the following set of CSP directives has been identified as an effective and deployable mitigation against XSS”
- `csp3-unsafe-hashes`: [W3C Content Security Policy Level 3][csp3-unsafe-hashes]: “will now allow event handlers, style attributes and javascript: navigation targets to match hashes”
- `csp3-wildcard`: [W3C Content Security Policy Level 3][csp3-wildcard]: “If host to ASCII lowercase ends with remaining, then return "Matches".”
- `cspe-base-uri`: [Google CSP Evaluator, security checks][cspe-base-uri]: “Missing base-uri allows the injection of base tags (for a policy with nonces, or hashes with strict-dynamic), Severity.HIGH”
- `cspe-bypass`: [Google CSP Evaluator, security checks][cspe-bypass]: “checkScriptAllowlistBypass: known to host JSONP endpoints or Angular libraries which allow to bypass this CSP, Severity.HIGH”
- `cspe-deprecated`: [Google CSP Evaluator, security checks][cspe-deprecated]: “checkDeprecatedDirective: reflected-xss, referrer, disown-opener, prefetch-src”
- `cspe-http`: [Google CSP Evaluator, security checks][cspe-http]: “checkSrcHttp: Allow only resources downloaded over HTTPS, Severity.MEDIUM”
- `cspe-object`: [Google CSP Evaluator, security checks][cspe-object]: “checkMissingObjectSrcDirective, Severity.HIGH”
- `cspe-schemes`: [Google CSP Evaluator, security checks][cspe-schemes]: “checkPlainUrlSchemes: data:, http: or https: in script-src, Severity.HIGH”
- `cspe-script`: [Google CSP Evaluator, security checks][cspe-script]: “checkMissingScriptSrcDirective, Severity.HIGH”
- `cspe-wildcard`: [Google CSP Evaluator, security checks][cspe-wildcard]: “checkWildcards: should not allow '*' as source, Severity.HIGH”
- `encoding-label`: [WHATWG Encoding Standard][encoding-label]: “If label is an ASCII case-insensitive match for any of the labels listed in the table below, then return the corresponding encoding; otherwise return failure.”
- `fetch-corp`: [WHATWG Fetch Standard][fetch-corp]: “If policy is neither `same-origin`, `same-site`, nor `cross-origin`, then set policy to null.”
- `fetch-cors-cred`: [WHATWG Fetch Standard][fetch-cors-cred]: “If credentials is `true`, then return success.”
- `fetch-cors-null`: [WHATWG Fetch Standard][fetch-cors-null]: “Let origin be the result of getting `Access-Control-Allow-Origin` from response’s header list.”
- `fetch-cors-origin`: [WHATWG Fetch Standard][fetch-cors-origin]: “If the result of byte-serializing a request origin with request is not origin, then return failure.”
- `fetch-cors-star`: [WHATWG Fetch Standard][fetch-cors-star]: “If request’s credentials mode is not "include" and origin is `*`, then return success.”
- `fetch-get`: [WHATWG Fetch Standard][fetch-get]: “Return the values of all headers in list whose name is a byte-case-insensitive match for name, separated from each other by 0x2C 0x20, in order.”
- `fetch-method-get`: [WHATWG Fetch Standard][fetch-method-get]: “A request has an associated method. Unless stated otherwise it is GET.”
- `fetch-mime`: [WHATWG Fetch Standard][fetch-mime]: “To extract a MIME type from a header list headers, run these steps. They return failure or a MIME type.”
- `fetch-nosniff`: [WHATWG Fetch Standard][fetch-nosniff]: “If values[0] is an ASCII case-insensitive match for "nosniff", then return true.”
- `geolocation-default`: [W3C Geolocation][geolocation-default]: “This specification defines a policy-controlled feature identified by the token string "geolocation". Its default allowlist is 'self'.”
- `hstspreload-min`: [hstspreload.org][hstspreload-min]: “The max-age must be at least 31536000 seconds (1 year).”
- `hstspreload-token`: [hstspreload.org][hstspreload-token]: “If a site sends the preload directive in an HSTS header, it is considered to be requesting inclusion in the preload list and may be submitted via the form on this site.”
- `html-charset-1024`: [WHATWG HTML Standard, Parsing][html-charset-1024]: “The authoring conformance requirements for character encoding declarations limit them to only appearing in the first 1024 bytes.”
- `html-charset-transport`: [WHATWG HTML Standard, Parsing][html-charset-transport]: “If the transport layer specifies a character encoding, and it is supported, return that encoding with the confidence certain.”
- `html-coep-compat`: [WHATWG HTML Standard, Origin][html-coep-compat]: “An embedder policy value is compatible with cross-origin isolation if it is "credentialless" or "require-corp".”
- `html-coop-plus`: [WHATWG HTML Standard, Origin][html-coop-plus]: “cannot be directly set via the `Cross-Origin-Opener-Policy` header, but results from a combination of setting both”
- `html-docdomain`: [WHATWG HTML Standard, Origin][html-docdomain]: “Avoid using the document.domain setter. It undermines the security protections provided by the same-origin policy.”
- `html-oac`: [WHATWG HTML Standard, Document lifecycle][html-oac]: “Let requestsOAC be true if oacHeader is not null and oacHeader[0] is the boolean true; otherwise false.”
- `html-xfo-allowfrom`: [WHATWG HTML Standard, X-Frame-Options][html-xfo-allowfrom]: “variant of the header, but that is not to be implemented”
- `html-xfo-csp`: [WHATWG HTML Standard, X-Frame-Options][html-xfo-csp]: “If policy's directive set contains a frame-ancestors directive, then return true.”
- `html-xfo-invalid`: [WHATWG HTML Standard, X-Frame-Options][html-xfo-invalid]: “These are treated as if the header were omitted entirely.”
- `html-xfo-multi`: [WHATWG HTML Standard, X-Frame-Options][html-xfo-multi]: “If xFrameOptions's size is greater than 1, and xFrameOptions contains any of "deny", "allowall", or "sameorigin", then return false.”
- `html-xfo-sameorigin`: [WHATWG HTML Standard, X-Frame-Options][html-xfo-sameorigin]: “If containerDocument's origin is not same origin with destinationOrigin, then return false.”
- `html-xfo-several-invalid`: [WHATWG HTML Standard, X-Frame-Options][html-xfo-several-invalid]: “This means it contains multiple invalid values, which we treat the same way as if the header was omitted entirely.”
- `ie-end`: [Microsoft, Internet Explorer 11 end of support][ie-end]: “On June 15, 2022, the Internet Explorer 11 (IE11) desktop application ended support”
- `ie8-xdo`: [Microsoft, IE8 Security Part V: Comprehensive Protection][ie8-xdo]: “When the new X-Download-Options header is present with the value noopen, the user is prevented from opening a file download directly”
- `mdn-acao-null`: [MDN, Access-Control-Allow-Origin][mdn-acao-null]: “Note: The value null should not be used.”
- `mdn-bamc`: [MDN, CSP block-all-mixed-content][mdn-bamc]: “Warning: This directive is marked as obsolete in the specification.”
- `mdn-coep-doc`: [MDN, Cross-Origin-Embedder-Policy][mdn-coep-doc]: “configures the current document's policy for loading and embedding cross-origin resources”
- `mdn-corp-nocors`: [MDN, Cross-Origin Resource Policy (CORP)][mdn-corp-nocors]: “The policy is only effective for no-cors requests”
- `mdn-corp-xssi`: [MDN, Cross-Origin Resource Policy (CORP)][mdn-corp-xssi]: “to mitigate speculative side-channel attacks, like Spectre, as well as Cross-Site Script Inclusion attacks”
- `mdn-docdomain-oac`: [MDN, Document.domain][mdn-docdomain-oac]: “If used on an origin-isolated page, i.e., one that uses the Origin-Agent-Cluster HTTP header”
- `mdn-docdomain-shared`: [MDN, Document.domain][mdn-docdomain-shared]: “Similar problems occur with shared hosting sites that give each customer a different subdomain.”
- `mdn-expectct`: [MDN, Expect-CT][mdn-expectct]: “Only Google Chrome and other Chromium-based browsers implemented Expect-CT, and Chromium has deprecated the header from version 107, because Chromium now enforces CT by default.”
- `mdn-oac-doc`: [MDN, Origin-Agent-Cluster][mdn-oac-doc]: “is used to request that the associated Document should be placed in an origin-keyed agent cluster”
- `mdn-oac-hint`: [MDN, Origin-Agent-Cluster][mdn-oac-hint]: “Origin-keyed agent clusters should not be viewed as a security feature”
- `mdn-oac-ignored`: [MDN, Origin-Agent-Cluster][mdn-oac-ignored]: “Values other than ?1 are ignored (e.g., the ?0 structured field for false).”
- `mdn-object-src`: [MDN, CSP object-src][mdn-object-src]: “Therefore it is recommended to restrict this fetch-directive”
- `mdn-pragma`: [MDN, Pragma][mdn-pragma]: “The Pragma header is not specified for HTTP responses and is therefore not a reliable replacement for the HTTP/1.1 Cache-Control header”
- `mdn-prefetch`: [MDN, CSP prefetch-src][mdn-prefetch]: “Non-standard: This feature is not standardized.”
- `mdn-samesite-default`: [MDN, Set-Cookie][mdn-samesite-default]: “Some browsers use Lax as the default value if SameSite is not specified”
- `mdn-samesite-lax`: [MDN, Set-Cookie][mdn-samesite-lax]: “Lax: send the cookie for same-site requests, and for cross-site requests only on a top-level navigation with a safe method”
- `mdn-xdns-doc`: [MDN, X-DNS-Prefetch-Control][mdn-xdns-doc]: “links that the user may choose to follow as well as URLs for items referenced by the document”
- `mdn-xdns-nonstd`: [MDN, X-DNS-Prefetch-Control][mdn-xdns-nonstd]: “Non-standard: This feature is not standardized.”
- `mdn-xpcdp`: [MDN, X-Permitted-Cross-Domain-Policies][mdn-xpcdp]: “Some security testing tools will still check for the presence of a X-Permitted-Cross-Domain-Policies: none header because it can mitigate the risk of an overly-permissive policy file added to your site by accident or through malicious actions.”
- `mdn-xpcdp-none`: [MDN, X-Permitted-Cross-Domain-Policies][mdn-xpcdp-none]: “No policy files are allowed anywhere on the target server, including in a master policy file.”
- `mdn-xpcdp-ntr`: [MDN, X-Permitted-Cross-Domain-Policies][mdn-xpcdp-ntr]: “Indicates that the current document should not be used as a policy file despite other headers or its content.”
- `mdn-xxp-block`: [MDN, X-XSS-Protection][mdn-xxp-block]: “though this approach might be vulnerable to side-channel attacks if the website is embeddable in an”
- `mdn-xxp-pages`: [MDN, X-XSS-Protection][mdn-xxp-pages]: “stopped pages from loading when they detected reflected cross-site scripting”
- `mdn-xxp-warn`: [MDN, X-XSS-Protection][mdn-xxp-warn]: “in some cases, X-XSS-Protection can create XSS vulnerabilities in otherwise safe websites”
- `mediacapture-default`: [W3C Media Capture and Streams][mediacapture-default]: “This specification defines two policy-controlled features identified by the strings "camera" and "microphone". Both have a default allowlist of "self".”
- `mimesniff-js`: [WHATWG MIME Sniffing Standard][mimesniff-js]: “A JavaScript MIME type is any MIME type whose essence is one of the following”
- `mimesniff-type`: [WHATWG MIME Sniffing Standard][mimesniff-type]: “If type is the empty string or does not solely contain HTTP token code points, then return failure.”
- `mixed-script`: [W3C Mixed Content][mixed-script]: “A request for the script http://example.com/script.js is mixed content. As script requests are blockable, the user agent will return a network error rather than loading the resource.”
- `obs-coop-absent`: [Mozilla HTTP Observatory, score table][obs-coop-absent]: “CoopNotImplemented, modifier: 0”
- `obs-cors-public`: [Mozilla HTTP Observatory, score table][obs-cors-public]: “CrossOriginResourceSharingImplementedWithPublicAccess, modifier: 0”
- `obs-csp-absent`: [Mozilla HTTP Observatory, score table][obs-csp-absent]: “CspNotImplemented, modifier: -25”
- `obs-csp-eval`: [Mozilla HTTP Observatory, score table][obs-csp-eval]: “CspImplementedWithUnsafeEval, modifier: -10”
- `obs-csp-inline`: [Mozilla HTTP Observatory, score table][obs-csp-inline]: “CspImplementedWithUnsafeInline, modifier: -20”
- `obs-csp-style`: [Mozilla HTTP Observatory, score table][obs-csp-style]: “CspImplementedWithUnsafeInlineInStyleSrcOnly, modifier: 0”
- `obs-hsts-absent`: [Mozilla HTTP Observatory, score table][obs-hsts-absent]: “HstsNotImplemented, modifier: -20”
- `obs-hsts-short`: [Mozilla HTTP Observatory, score table][obs-hsts-short]: “HstsImplementedMaxAgeLessThanSixMonths, modifier: -10”
- `obs-rp-absent`: [Mozilla HTTP Observatory, score table][obs-rp-absent]: “ReferrerPolicyNotImplemented, modifier: 0”
- `obs-rp-unsafe`: [Mozilla HTTP Observatory, score table][obs-rp-unsafe]: “ReferrerPolicyUnsafe, modifier: -5”
- `obs-xcto-absent`: [Mozilla HTTP Observatory, score table][obs-xcto-absent]: “XContentTypeOptionsNotImplemented, modifier: -5”
- `obs-xfo-absent`: [Mozilla HTTP Observatory, score table][obs-xfo-absent]: “XFrameOptionsNotImplemented, modifier: -20”
- `obs-xfo-csp`: [Mozilla HTTP Observatory, score table][obs-xfo-csp]: “XFrameOptionsImplementedViaCsp, modifier: 5”
- `orb-blocklist`: [Opaque Response Blocking (ORB) explainer, WHATWG Fetch][orb-blocklist]: “An opaque-blocklisted MIME type is an HTML MIME type, JSON MIME type, or XML MIME type.”
- `owasp-rr-critical`: [OWASP Risk Rating Methodology][owasp-rr-critical]: “Overall Risk Severity: Critical only where impact is HIGH and likelihood is HIGH”
- `permissions-delegation`: [W3C Permissions][permissions-delegation]: “Most powerful features grant permission to the top-level origin and delegate access to the requesting document via Permissions Policy. This is known as permission delegation.”
- `pp-default`: [W3C Permissions Policy][pp-default]: “Every policy-controlled feature has a default allowlist.”
- `pp-dict`: [W3C Permissions Policy][pp-dict]: “Member Values of any other form will cause the entire Dictionary Member to be ignored by the processing steps.”
- `pp-empty`: [W3C Permissions Policy][pp-empty]: “If parsed header is null, return an empty ordered map.”
- `ps-cache`: [PortSwigger, Cacheable HTTPS response][ps-cache]: “Typical severity: Information”
- `ps-cors-http`: [PortSwigger, CORS: unencrypted origin trusted][ps-cors-http]: “If a site allows interaction from an origin that uses unencrypted HTTP communications, then it is vulnerable to an attacker who is in a position to view and modify a user's unencrypted network traffic.”
- `ps-css-attr`: [PortSwigger Research, Blind CSS Exfiltration][ps-css-attr]: “Attribute selectors are an extremely powerful way to extract data.”
- `ps-css-csp`: [PortSwigger Research, Blind CSS Exfiltration][ps-css-csp]: “Imagine you've got a blind HTML injection vulnerability but you can't get XSS because of the site's CSP”
- `ps-hsts`: [PortSwigger, Strict transport security not enforced][ps-hsts]: “Typical severity: Low”
- `ps-referer`: [PortSwigger, Cross-domain Referer leakage][ps-referer]: “Typical severity: Information”
- `referrer-last`: [W3C Referrer Policy][referrer-last]: “For each token in policy-tokens, if token is a referrer policy and token is not the empty string, then set policy to token.”
- `rest-cc`: [OWASP REST Security Cheat Sheet][rest-cc]: “Instructs compliant private and shared HTTP caches not to store the response or reuse it for another request”
- `rest-cors`: [OWASP REST Security Cheat Sheet][rest-cors]: “Be as specific as possible and as general as necessary when setting the origins of cross-domain calls.”
- `rest-csp-dd`: [OWASP REST Security Cheat Sheet][rest-csp-dd]: “The majority of CSP functionality only affects pages rendered as HTML.”
- `rest-ct`: [OWASP REST Security Cheat Sheet][rest-ct]: “This must be specified as per the type of content returned by an API call.”
- `rest-ct-guess`: [OWASP REST Security Cheat Sheet][rest-ct-guess]: “If not specified or if specified incorrectly, a browser might attempt to guess the content type of the response.”
- `rest-ct-js`: [OWASP REST Security Cheat Sheet][rest-ct-js]: “Ensure sending intended content type headers in your response matching your body content e.g. application/json and not application/javascript.”
- `rest-dd`: [OWASP REST Security Cheat Sheet][rest-dd]: “The headers below are only intended to provide additional security when responses are rendered as HTML.”
- `rest-dd-uncertain`: [OWASP REST Security Cheat Sheet][rest-dd-uncertain]: “if there is any uncertainty about the function of the headers, or the types of information that the API returns (or may return in future), then it is recommended to include them as part of a defense-in-depth approach”
- `rest-fa`: [OWASP REST Security Cheat Sheet][rest-fa]: “For an API response, there is no requirement to be framed in any of those elements.”
- `rest-fa-dnd`: [OWASP REST Security Cheat Sheet][rest-fa-dnd]: “This header protects against drag-and-drop style clickjacking attacks.”
- `rest-pp`: [OWASP REST Security Cheat Sheet][rest-pp]: “When browsers heed this header, it is used to control browser features via directives.”
- `rest-rp`: [OWASP REST Security Cheat Sheet][rest-rp]: “Non-HTML responses should not trigger additional requests.”
- `rest-scope`: [OWASP REST Security Cheat Sheet][rest-scope]: “The following headers should be included in all API responses that may be consumed by browser clients”
- `rest-stateless`: [OWASP REST Security Cheat Sheet][rest-stateless]: “Stateful services are out of scope of this Cheat Sheet”
- `rest-xfo`: [OWASP REST Security Cheat Sheet][rest-xfo]: “Still recommended for compatibility with older browsers that do not support CSP Level 2.”
- `rfc6266-unknown`: [RFC 6266, Content-Disposition][rfc6266-unknown]: “Unknown or unhandled disposition types SHOULD be handled by recipients the same way as "attachment"”
- `rfc6797-first`: [RFC 6797, HTTP Strict Transport Security][rfc6797-first]: “If a UA receives more than one STS header field in an HTTP response message over secure transport, then the UA MUST process only the first such header field.”
- `rfc6797-invalid`: [RFC 6797, HTTP Strict Transport Security][rfc6797-invalid]: “The UA MUST ignore any STS header fields not conforming to the grammar specified in Section 6.1 ("Strict-Transport-Security HTTP Response Header Field").”
- `rfc6797-zero`: [RFC 6797, HTTP Strict Transport Security][rfc6797-zero]: “If the max-age header field value token has a value of zero, the UA MUST remove its cached HSTS Policy information”
- `rfc9110-combine`: [RFC 9110, HTTP Semantics][rfc9110-combine]: “A recipient MAY combine multiple field lines within a field section that have the same field name into one field line, without changing the semantics of the message”
- `rfc9110-etag`: [RFC 9110, HTTP Semantics][rfc9110-etag]: “An entity tag is an opaque validator for differentiating between multiple representations of the same resource”
- `rfc9110-etag-privacy`: [RFC 9110, HTTP Semantics][rfc9110-etag-privacy]: “An entity tag can be abused in ways that create privacy risks.”
- `rfc9111-auth`: [RFC 9111, HTTP Caching][rfc9111-auth]: “A shared cache MUST NOT use a cached response to a request with an Authorization header field”
- `rfc9111-auth-directives`: [RFC 9111, HTTP Caching][rfc9111-auth-directives]: “In this specification, the following response directives have such an effect: must-revalidate (Section 5.2.2.2), public (Section 5.2.2.9), and s-maxage (Section 5.2.2.10).”
- `rfc9111-expires`: [RFC 9111, HTTP Caching][rfc9111-expires]: “If a response includes a Cache-Control header field with the max-age directive (Section 5.2.2.1), a recipient MUST ignore the Expires header field.”
- `rfc9111-heuristic`: [RFC 9111, HTTP Caching][rfc9111-heuristic]: “a cache MAY assign a heuristic expiration time when an explicit time is not specified”
- `rfc9111-pragma`: [RFC 9111, HTTP Caching][rfc9111-pragma]: “As a result, this specification deprecates Pragma.”
- `rfc9111-pragma-response`: [RFC 9111, HTTP Caching][rfc9111-pragma-response]: “Because the meaning of "Pragma: no-cache" in responses was never specified, it does not provide a reliable replacement for "Cache-Control: no-cache" in them.”
- `rfc9111-private`: [RFC 9111, HTTP Caching][rfc9111-private]: “The unqualified private response directive indicates that a shared cache MUST NOT store the response”
- `rfc9112-fold`: [RFC 9112, HTTP/1.1][rfc9112-fold]: “This specification deprecates such line folding except within the "message/http" media type”
- `rfc9112-ws`: [RFC 9112, HTTP/1.1][rfc9112-ws]: “No whitespace is allowed between the field name and colon.”
- `rfc9651-fail`: [RFC 9651, Structured Field Values][rfc9651-fail]: “When parsing fails, the entire field is ignored”
- `session-csd`: [OWASP Session Management Cheat Sheet][session-csd]: “This can be achieved by returning the Clear-Site-Data response header”
- `shp-deprecated`: [OWASP Secure Headers Project, Headers][shp-deprecated]: “Deprecated: Feature-Policy, Expect-CT, Public-Key-Pins, X-XSS-Protection, Pragma”
- `sonar-detect`: [Sonar, Encoding Differentials: Why Charset Matters][sonar-detect]: “A single occurrence of one of these escape sequences is usually enough to convince the auto-detection algorithm that the HTTP response body is encoded with ISO-2022-JP.”
- `strictcsp-fallback`: [web.dev, Mitigate XSS with a strict CSP][strictcsp-fallback]: “Setting fallbacks doesn't reduce the security of your policy in modern browsers”
- `strictcsp-https`: [web.dev, Mitigate XSS with a strict CSP][strictcsp-https]: “All browsers that support strict-dynamic ignore the https: fallback, so this won't reduce the strength of the policy.”
- `sw-allowed`: [W3C Service Workers][sw-allowed]: “Servers can remove the path restriction by setting a Service-Worker-Allowed header on the service worker script.”
- `webdev-corp-all`: [web.dev, Security headers quick reference][webdev-corp-all]: “All resources are recommended to send this header to indicate whether they allow being loaded by other websites.”
- `webdev-corp-api`: [web.dev, Security headers quick reference][webdev-corp-api]: “You should apply this to resources that include sensitive information about the user, or responses of an API that is intended to be called only from the same origin.”
- `zap-10015`: [OWASP ZAP alert 10015, Re-examine Cache-control Directives][zap-10015]: “Risk: Informational”
- `zap-10020-1`: [OWASP ZAP alert 10020-1, Missing Anti-clickjacking Header][zap-10020-1]: “Risk: Medium”
- `zap-10020-4`: [OWASP ZAP alert 10020-4, X-Frame-Options Setting Malformed][zap-10020-4]: “Risk: Medium”
- `zap-10021`: [OWASP ZAP alert 10021, X-Content-Type-Options Header Missing][zap-10021]: “Risk: Low”
- `zap-10035-1`: [OWASP ZAP alert 10035-1, Strict-Transport-Security Header Not Set][zap-10035-1]: “Risk: Low”
- `zap-10035-2`: [OWASP ZAP alert 10035-2, Strict-Transport-Security Disabled][zap-10035-2]: “Risk: Low”
- `zap-10035-3`: [OWASP ZAP alert 10035-3, Strict-Transport-Security Multiple Header Entries (Non-compliant with Spec)][zap-10035-3]: “Risk: Low”
- `zap-10038-1`: [OWASP ZAP alert 10038-1, Content Security Policy (CSP) Header Not Set][zap-10038-1]: “Risk: Medium”
- `zap-10038-3`: [OWASP ZAP alert 10038-3, Content Security Policy (CSP) Report-Only Header Found][zap-10038-3]: “Risk: Informational”
- `zap-10055-10`: [OWASP ZAP alert 10055-10, CSP: script-src unsafe-eval][zap-10055-10]: “Risk: Medium”
- `zap-10055-13`: [OWASP ZAP alert 10055-13, CSP: Failure to Define Directive with No Fallback][zap-10055-13]: “Risk: Medium”
- `zap-10055-3`: [OWASP ZAP alert 10055-3, CSP: Notices][zap-10055-3]: “Risk: Low”
- `zap-10055-4`: [OWASP ZAP alert 10055-4, CSP: Wildcard Directive][zap-10055-4]: “Risk: Medium”
- `zap-10055-5`: [OWASP ZAP alert 10055-5, CSP: script-src unsafe-inline][zap-10055-5]: “Risk: Medium”
- `zap-10055-6`: [OWASP ZAP alert 10055-6, CSP: style-src unsafe-inline][zap-10055-6]: “Risk: Medium”
- `zap-10055-7`: [OWASP ZAP alert 10055-7, CSP: script-src unsafe-hashes][zap-10055-7]: “Risk: Medium”
- `zap-10063-1`: [OWASP ZAP alert 10063-1, Permissions Policy Header Not Set][zap-10063-1]: “Risk: Low”
- `zap-20016-1`: [OWASP ZAP alert 20016-1, Cross-Domain Misconfiguration - Adobe - Read][zap-20016-1]: “Risk: High”
- `zap-40040-2`: [OWASP ZAP alert 40040-2, CORS Misconfiguration][zap-40040-2]: “Risk: Medium”
- `zap-40040-3`: [OWASP ZAP alert 40040-3, CORS Misconfiguration][zap-40040-3]: “Risk: High”
- `zap-90004-1`: [OWASP ZAP alert 90004-1, Cross-Origin-Resource-Policy Header Missing or Invalid][zap-90004-1]: “Risk: Low”
- `zap-90004-2`: [OWASP ZAP alert 90004-2, Cross-Origin-Embedder-Policy Header Missing or Invalid][zap-90004-2]: “Risk: Low”
- `zap-90004-3`: [OWASP ZAP alert 90004-3, Cross-Origin-Opener-Policy Header Missing or Invalid][zap-90004-3]: “Risk: Low”
- `zap-cors-risk`: [OWASP ZAP, CORS scan rule source][zap-cors-risk]: “A null, arbitrary or plain-HTTP origin is Medium, and High when credentials are allowed”

[adobe-default]: https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/xdomain.html#:~:text=By%20default%2C%20when%20requested%20content,get%20permission%20for%20such%20access.
[adobe-invalid]: https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/xdomain.html#:~:text=An%20invalid%20meta%2Dpolicy%20was%20specified%20in%20an%20X%2DPermitted%2DCross%2DDomain%2DPolicies%20HTTP%20header.%20It%20has%20been%20ignored.
[adobe-master]: https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/xdomain.html#:~:text=The%20use%20of%20non%2Dmaster%20policy%20files%20require%20a%20site%20to%20have%20a%20meta%2Dpolicy%20of%20%E2%80%9Cby%2Dcontent%2Dtype%E2%80%9D%20or%20%E2%80%9Call%E2%80%9D.
[asvs-14.3.1]: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x23-V14-Data-Protection.md#:~:text=The%20'Clear%2DSite%2DData'%20HTTP%20response%20header%20field%20may%20be%20able%20to%20help%20with%20this
[asvs-14.3.2]: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x23-V14-Data-Protection.md#:~:text=Verify%20that%20the%20application%20sets,is%20not%20cached%20in%20browsers.
[asvs-3.4.1]: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md#:~:text=A%20maximum%20age%20of%20at,to%20all%20subdomains%20as%20well.
[asvs-3.4.2]: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md#:~:text=is%20a%20fixed%20value%20by,an%20allowlist%20of%20trusted%20origins
[asvs-3.4.2-star]: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md#:~:text=When%20'Access%2DControl%2DAllow%2DOrigin%3A%20*'%20needs%20to%20be%20used%2C%20verify%20that%20the%20response%20does%20not%20include%20any%20sensitive%20information.
[asvs-3.4.3]: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md#:~:text=As%20a%20minimum%2C%20a%20global,or%20uses%20nonces%20or%20hashes.
[asvs-3.4.4]: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md#:~:text=Verify%20that%20all%20HTTP%20responses%20contain%20an%20'X%2DContent%2DType%2DOptions%3A%20nosniff'%20header%20field.
[asvs-3.4.5]: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md#:~:text=Verify%20that%20the%20application%20sets%20a%20referrer%20policy%20to%20prevent%20leakage%20of%20technically%20sensitive%20data%20to%20third%2Dparty%20services
[asvs-3.4.6]: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md#:~:text=Verify%20that%20the%20web%20application%20uses%20the%20frame%2Dancestors%20directive%20of%20the%20Content%2DSecurity%2DPolicy%20header%20field%20for%20every%20HTTP%20response
[asvs-3.4.6-xfo]: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md#:~:text=Note%20that%20the%20X%2DFrame%2DOptions%20header%20field%2C%20although%20supported%20by%20browsers%2C%20is%20obsolete%20and%20may%20not%20be%20relied%20upon.
[asvs-3.4.8]: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md#:~:text=include%20the%20Cross%E2%80%91Origin%E2%80%91Opener%E2%80%91Policy%20header%20field%20with%20the%20same%2Dorigin%20directive%20or%20the%20same%2Dorigin%2Dallow%2Dpopups%20directive%20as%20required
[asvs-4.1.1]: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x13-V4-API-and-Web-Service.md#:~:text=Verify%20that%20every%20HTTP%20response%20with%20a%20message%20body%20contains%20a%20Content%2DType%20header%20field,that%20matches%20the%20actual%20content%20of%20the%20response
[attribution-default]: https://wicg.github.io/attribution-reporting-api/#:~:text=This%20specification%20defines%20a%20policy%2Dcontrolled%20feature%20identified%20by%20the%20string%20%22attribution%2Dreporting%22.%20Its%20default%20allowlist%20is%20*.
[bp-cache]: https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md#:~:text=So%2C%20the%20browser%20will%20store,a%20certain%20amount%20of%20time.
[bp-cc]: https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md#:~:text=no%2Dstore%2C%20max%2Dage%3D0
[bp-coep]: https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md#:~:text=Cross%2DOrigin%2DEmbedder%2DPolicy,require%2Dcorp
[bp-coop]: https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md#:~:text=Cross%2DOrigin%2DOpener%2DPolicy,same%2Dorigin
[bp-corp]: https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md#:~:text=Cross%2DOrigin%2DResource%2DPolicy,same%2Dorigin
[bp-cors-auth]: https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md#:~:text=Your%20endpoints%20are%20expected%20to%20be%20consumed%2C%20by%20a%20browser%2C%20from%20a%20specific%20collection%20of%20origins%20with%20authentication.
[bp-cors-mirror]: https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md#:~:text=Never%20take%20the%20value%20of%20the%20request%20header%20Origin%20to%20add%20it%20into%20the%20response%20header%20Access%2DControl%2DAllow%2DOrigin%20(mirroring)
[bp-cors-public]: https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md#:~:text=Your%20endpoints%20are%20expected%20to%20be%20consumed%2C%20by%20a%20browser%2C%20from%20any%20origins%20without%20any%20authentication.
[bp-cors-star-cred]: https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md#:~:text=The%20value%20*%2C%20for%20the%20response%20header%20Access%2DControl%2DAllow%2DOrigin%2C%20cannot%20be%20used%20when%20the%20response%20header%20Access%2DControl%2DAllow%2DCredentials%20is%20allowed%20(true).
[bp-csd-logout]: https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md#:~:text=set%20it%20to%20the%20logout%20function%20when%20possible
[bp-csd-time]: https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md#:~:text=The%20header%20Clear%2DSite%2DData%20will%20cause%20the%20browser%20to%20take%20additional%20processing%20time%20for%20the%20HTTP%20response
[bp-csp]: https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md#:~:text=default%2Dsrc%20'self'%3B%20form%2Daction%20'self'%3B%20base%2Duri%20'self'%3B%20object%2Dsrc%20'none'%3B%20frame%2Dancestors%20'none'%3B%20upgrade%2Dinsecure%2Drequests
[bp-hsts]: https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md#:~:text=Strict%2DTransport%2DSecurity,max%2Dage%3D63072000%3B%20includeSubDomains
[bp-rp]: https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md#:~:text=Referrer%2DPolicy,no%2Dreferrer
[bp-upload]: https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md#:~:text=If%20such%20a%20feature%20allows,HTML%20file%20containing%20JavaScript%20code.
[bp-xcto]: https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md#:~:text=X%2DContent%2DType%2DOptions,nosniff
[bp-xdns-inj]: https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md#:~:text=Prone%20to%20HTML%20injection%20where%20an%20attacker%20can%20inject%20a%20tag
[bp-xdns-pii]: https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md#:~:text=Return%20sensitive%20or%20private%20content%20(commonly%20called%20PII).
[bp-xfo]: https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md#:~:text=X%2DFrame%2DOptions,deny
[bp-xpcdp]: https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md#:~:text=X%2DPermitted%2DCross%2DDomain%2DPolicies,none
[chrome-docdomain-115]: https://developer.chrome.com/blog/document-domain-setter-deprecation#:~:text=Starting%20in%20Chrome%20115%2C%20websites%20will%20be%20unable%20to%20set%20document.domain%3A%20Chrome%20will%20make%20document.domain%20immutable.
[chrome-docdomain-opt-out]: https://developer.chrome.com/blog/document-domain-setter-deprecation#:~:text=When%20you%20send%20this%20header%2C%20your%20document%20can%20continue%20to%20set%20document.domain%20even%20after%20it%20becomes%20immutable%20by%20default.
[chromium-default-self]: https://github.com/chromium/chromium/blob/34221eca1b60aa7cb82cd8b22893bda4a3b2117a/services/network/public/cpp/permissions_policy/permissions_policy_features.json5#L32-L33
[chromium-deferred]: https://github.com/chromium/chromium/blob/34221eca1b60aa7cb82cd8b22893bda4a3b2117a/services/network/public/cpp/permissions_policy/permissions_policy_features.json5#L299-L301
[chromium-gamepad]: https://github.com/chromium/chromium/blob/34221eca1b60aa7cb82cd8b22893bda4a3b2117a/services/network/public/cpp/permissions_policy/permissions_policy_features.json5#L361-L363
[chromium-pip]: https://github.com/chromium/chromium/blob/34221eca1b60aa7cb82cd8b22893bda4a3b2117a/services/network/public/cpp/permissions_policy/permissions_policy_features.json5#L480-L482
[chromium-pst-issuance]: https://github.com/chromium/chromium/blob/34221eca1b60aa7cb82cd8b22893bda4a3b2117a/services/network/public/cpp/permissions_policy/permissions_policy_features.json5#L485-L487
[chromium-pst-redemption]: https://github.com/chromium/chromium/blob/34221eca1b60aa7cb82cd8b22893bda4a3b2117a/services/network/public/cpp/permissions_policy/permissions_policy_features.json5#L558-L560
[chromium-storage-access]: https://github.com/chromium/chromium/blob/34221eca1b60aa7cb82cd8b22893bda4a3b2117a/services/network/public/cpp/permissions_policy/permissions_policy_features.json5#L532-L534
[chromium-topics]: https://github.com/chromium/chromium/blob/34221eca1b60aa7cb82cd8b22893bda4a3b2117a/services/network/public/cpp/permissions_policy/permissions_policy_features.json5#L144-L146
[chromium-uach]: https://github.com/chromium/chromium/blob/34221eca1b60aa7cb82cd8b22893bda4a3b2117a/services/network/public/cpp/permissions_policy/permissions_policy_features.json5#L220-L222
[cs-acao-public]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=for%20a%20public%20API%20that%20should%20be%20accessible%20from%20any%20origin%2C%20it%20might%20be%20necessary%20to%20allow
[cs-acao-rec]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=If%20you%20use%20it%2C%20set%20specific%20origins%20instead%20of%20*.
[cs-cc-default]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=Avoid%20relying%20on%20default%20caching%20behavior%20for%20sensitive%20or%20protected%20content.
[cs-cc-nocache]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=Be%20aware%20that%20no%2Dcache%20does%20not%20prevent%20caching%3B%20it%20allows%20caches%20to%20store%20responses.
[cs-cc-nostore]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=Use%20no%2Dstore%20for%20sensitive%20responses%20to%20prohibit%20storage%20in%20compliant%20HTTP%20caches.
[cs-cc-private]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=note%20that%20private%20caches%20may%20still%20persist%20the%20response
[cs-coep]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=prevents%20a%20document%20from%20loading%20any%20cross%2Dorigin%20resources%20that%20don't%20explicitly%20grant%20the%20document%20permission%20(using%20CORP%20or%20CORS)
[cs-coop-api]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=it%20may%20not%20make%20sense%20to%20be%20applied%20to%20REST%20APIs%20or%20clients%20that%20are%20not%20browsers
[cs-coop-rec]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=Isolates%20the%20browsing%20context%20exclusively%20to%20same%2Dorigin%20documents.
[cs-coop-spectre]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=This%20mechanism%20protects%20against%20attacks,the%20same%20browsing%20context%20group.
[cs-corp]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=It%20is%20a%20robust%20defense,it%20enters%20an%20attacker's%20process.
[cs-csp-api]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=might%20be%20meaningless%20in%20the%20response%20of%20a%20REST%20API%20that%20returns%20content%20that%20is%20not%20going%20to%20be%20rendered
[cs-ct-charset]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=the%20charset%20attribute%20is%20necessary%20to%20prevent%20XSS%20in%20HTML%20pages
[cs-download]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=Use%20Content%2DDisposition%3A%20attachment%20to%20force%20download%20instead%20of%20inline%20rendering.
[cs-expectct]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=Do%20not%20use%20it.%20Mozilla%20recommends%20avoiding%20it%2C%20and%20removing%20it%20from%20existing%20code%20if%20possible.
[cs-hsts-rec]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=Strict%2DTransport%2DSecurity%3A%20max%2Dage%3D63072000%3B%20includeSubDomains%3B%20preload
[cs-pp-example]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=This%20example%20is%20disabling%20geolocation%2C%20camera%2C%20and%20microphone%20for%20all%20domains.
[cs-pp-rec]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=Set%20it%20and%20disable%20all,only%20to%20the%20authorized%20domains
[cs-rp-default]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=Modern%20browsers%20default%20to%20strict%2Dorigin%2Dwhen%2Dcross%2Dorigin
[cs-rp-rec]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=Set%20the%20header%20explicitly%20rather%20than%20relying%20on%20browser%20defaults.
[cs-xcto]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=This%20header%20is%20used%20to,MIME%20types%20(MIME%20Confusion%20Attacks).
[cs-xdns]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=If%20you%20do%20not%20control,leaking%20information%20to%20those%20domains.
[cs-xdns-nonstd]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=it%20is%20not%20standard%20or%20fully%20supported%20and%20implementation%20may%20vary%20among%20browsers
[cs-xfo-api]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=If%20the%20HTTP%20response%20is%20a%20redirect%20or%20an%20API%20returning%20JSON%20data%2C%20X%2DFrame%2DOptions%20does%20not%20provide%20any%20security.
[cs-xfo-fa]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=Content%20Security%20Policy%20(CSP)%20frame%2Dancestors%20directive%20obsoletes%20X%2DFrame%2DOptions%20for%20supporting%20browsers
[cs-xfo-rec]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=Do%20not%20allow%20displaying%20of%20the%20page%20in%20a%20frame.
[cs-xxp-rec]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=Do%20not%20set%20this%20header%20or%20explicitly%20turn%20it%20off.
[cs-xxp-warn]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#:~:text=in%20some%20cases%2C%20this%20header%20can%20create%20XSS%20vulnerabilities%20in%20otherwise%20safe%20websites
[cscsp-plugin-types]: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html#:~:text=plugin%2Dtypes%20has%20been%20removed%20from%20the%20CSP%20specification.
[csd-grammar]: https://www.w3.org/TR/clear-site-data/#:~:text=Clear%2DSite%2DData%20%3D%201%23(%20quoted%2Dstring%20)
[csd-logout]: https://www.w3.org/TR/clear-site-data/#:~:text=when%20the%20user%20signs%20out%20of%20the%20application%2C%20or%20deletes%20their%20account
[csd-subset]: https://www.w3.org/TR/clear-site-data/#:~:text=so%20many%20that%20it%E2%80%99s%20not,response%20to%20a%20logout%20action
[csd-unknown]: https://www.w3.org/TR/clear-site-data/#:~:text=User%20agents%20MUST%20ignore%20unknown%20types%20when%20parsing%20the%20header.
[csp3-ascii]: https://www.w3.org/TR/CSP3/#:~:text=If%20token%20is%20an%20empty%20string%2C%20or%20if%20token%20is%20not%20an%20ASCII%20string%2C%20continue.
[csp3-base]: https://www.w3.org/TR/CSP3/#:~:text=However%2C%20if%20an%20attacker%20can,when%20relative%20URLs%20are%20resolved.
[csp3-default]: https://www.w3.org/TR/CSP3/#:~:text=when%20default%2Dsrc%20is%20set%2C%20every%20fetch%20directive%20that%20isn%E2%80%99t%20explicitly%20set%20will%20fall%20back%20to%20the%20value%20default%2Dsrc%20specifies
[csp3-dup]: https://www.w3.org/TR/CSP3/#:~:text=If%20policy%E2%80%99s%20directive%20set%20contains%20a%20directive%20whose%20name%20is%20directive%20name%2C%20continue.
[csp3-each]: https://www.w3.org/TR/CSP3/#:~:text=When%20the%20user%20agent%20receives%20a%20Content%2DSecurity%2DPolicy%20header%20field%2C%20it%20MUST%20parse%20and%20enforce%20each%20serialized%20CSP%20it%20contains
[csp3-exfil]: https://www.w3.org/TR/CSP3/#:~:text=Note%20that%20a%20policy%20which%20lacks%20the%20default%2Dsrc%20directive%20cannot%20mitigate%20exfiltration
[csp3-fa-nofallback]: https://www.w3.org/TR/CSP3/#:~:text=frame%2Dancestors%20will%20not%20fall%20back%20to%20the%20default%2Dsrc%20directive%E2%80%99s%20value%20if%20one%20is%20specified
[csp3-fa-xfo]: https://www.w3.org/TR/CSP3/#:~:text=If%20a%20resource%20is%20delivered%20with%20a%20policy%20that%20includes%20a%20directive%20named%20frame%2Dancestors,will%20be%20ignored%2C%20per%20HTML%E2%80%99s%20processing%20model.
[csp3-form]: https://www.w3.org/TR/CSP3/#:~:text=The%20form%2Daction%20directive%20restricts%20the,submissions%20from%20a%20given%20context.
[csp3-inline-nonce]: https://www.w3.org/TR/CSP3/#:~:text=If%20expression%20matches%20the%20nonce%2Dsource%20or%20hash%2Dsource%20grammar%2C%20return%20%22Does%20Not%20Allow%22.
[csp3-inline-sd]: https://www.w3.org/TR/CSP3/#:~:text=If%20type%20is%20%22script%22%2C%20%22script%20attribute%22%20or%20%22navigation%22,return%20%22Does%20Not%20Allow%22.
[csp3-keywords]: https://www.w3.org/TR/CSP3/#:~:text=keyword%2Dsource%20%3D%20%22'self'%22%20%2F%20%22'unsafe%2Dinline'%22%20%2F%20%22'unsafe%2Deval'%22
[csp3-list]: https://www.w3.org/TR/CSP3/#:~:text=A%20serialized%20CSP%20list%20is%20an%20ASCII%20string%20consisting%20of%20a%20comma%2Ddelimited%20series%20of%20serialized%20CSPs
[csp3-nonce-128]: https://www.w3.org/TR/CSP3/#:~:text=The%20generated%20value%20SHOULD%20be%20at%20least%20128%20bits%20long%20(before%20encoding)
[csp3-nonce-grammar]: https://www.w3.org/TR/CSP3/#:~:text=nonce%2Dsource%20%3D%20%22'nonce%2D%22%20base64%2Dvalue%20%22'%22
[csp3-nonce-unique]: https://www.w3.org/TR/CSP3/#:~:text=the%20server%20MUST%20generate%20a%20unique%20value%20each%20time%20it%20transmits%20a%20policy
[csp3-none]: https://www.w3.org/TR/CSP3/#:~:text=serialized%2Dsource%2Dlist%20%3D%20(%20source%2Dexpression%20*(%20required%2Dascii%2Dwhitespace%20source%2Dexpression%20)%20)%20%2F%20%22'none'%22
[csp3-registry]: https://www.w3.org/TR/CSP3/#:~:text=The%20Content%20Security%20Policy%20Directive%20registry%20should%20be%20updated%20with%20the%20following%20directives%20and%20references
[csp3-schemes]: https://www.w3.org/TR/CSP3/#:~:text=The%20source%20expression%20matching%20has%20been%20changed%20to%20require%20explicit%20presence%20of%20any%20non%2DHTTP(S)%20scheme
[csp3-sd-ignores]: https://www.w3.org/TR/CSP3/#:~:text=host%2Dsource%20and%20scheme%2Dsource%20expressions%2C%20as%20well%20as%20the%20%22'unsafe%2Dinline'%22%20and%20%22'self'%20keyword%2Dsources%20will%20be%20ignored%20when%20loading%20script.
[csp3-split]: https://www.w3.org/TR/CSP3/#:~:text=For%20each%20token%20returned%20by%20strictly%20splitting%20serialized%20on%20the%20U%2B003B%20SEMICOLON%20character%20(%3B)%3A
[csp3-strict]: https://www.w3.org/TR/CSP3/#:~:text=enforcing%20the%20following%20set%20of%20CSP%20directives%20has%20been%20identified%20as%20an%20effective%20and%20deployable%20mitigation%20against%20XSS
[csp3-unsafe-hashes]: https://www.w3.org/TR/CSP3/#:~:text=will%20now%20allow%20event%20handlers%2C%20style%20attributes%20and%20javascript%3A%20navigation%20targets%20to%20match%20hashes
[csp3-wildcard]: https://www.w3.org/TR/CSP3/#:~:text=If%20host%20to%20ASCII%20lowercase%20ends%20with%20remaining%2C%20then%20return%20%22Matches%22.
[cspe-base-uri]: https://github.com/google/csp-evaluator/blob/ad530f3ae5473f9e03c8bf500ee0ada8d9e9b822/checks/security_checks.ts#L221-L240
[cspe-bypass]: https://github.com/google/csp-evaluator/blob/ad530f3ae5473f9e03c8bf500ee0ada8d9e9b822/checks/security_checks.ts#L319-L336
[cspe-deprecated]: https://github.com/google/csp-evaluator/blob/ad530f3ae5473f9e03c8bf500ee0ada8d9e9b822/checks/security_checks.ts#L471-L507
[cspe-http]: https://github.com/google/csp-evaluator/blob/ad530f3ae5473f9e03c8bf500ee0ada8d9e9b822/checks/security_checks.ts#L565-L580
[cspe-object]: https://github.com/google/csp-evaluator/blob/ad530f3ae5473f9e03c8bf500ee0ada8d9e9b822/checks/security_checks.ts#L180-L193
[cspe-schemes]: https://github.com/google/csp-evaluator/blob/ad530f3ae5473f9e03c8bf500ee0ada8d9e9b822/checks/security_checks.ts#L124-L143
[cspe-script]: https://github.com/google/csp-evaluator/blob/ad530f3ae5473f9e03c8bf500ee0ada8d9e9b822/checks/security_checks.ts#L199-L206
[cspe-wildcard]: https://github.com/google/csp-evaluator/blob/ad530f3ae5473f9e03c8bf500ee0ada8d9e9b822/checks/security_checks.ts#L155-L170
[encoding-label]: https://encoding.spec.whatwg.org/#:~:text=If%20label%20is%20an%20ASCII,corresponding%20encoding%3B%20otherwise%20return%20failure.
[fetch-corp]: https://fetch.spec.whatwg.org/#:~:text=If%20policy%20is%20neither%20%60same%2Dorigin%60%2C%20%60same%2Dsite%60%2C%20nor%20%60cross%2Dorigin%60%2C%20then%20set%20policy%20to%20null.
[fetch-cors-cred]: https://fetch.spec.whatwg.org/#:~:text=If%20credentials%20is%20%60true%60%2C%20then%20return%20success.
[fetch-cors-null]: https://fetch.spec.whatwg.org/#:~:text=Let%20origin%20be%20the%20result%20of%20getting%20%60Access%2DControl%2DAllow%2DOrigin%60%20from%20response%E2%80%99s%20header%20list.
[fetch-cors-origin]: https://fetch.spec.whatwg.org/#:~:text=If%20the%20result%20of%20byte%2Dserializing%20a%20request%20origin%20with%20request%20is%20not%20origin%2C%20then%20return%20failure.
[fetch-cors-star]: https://fetch.spec.whatwg.org/#:~:text=If%20request%E2%80%99s%20credentials%20mode%20is%20not%20%22include%22%20and%20origin%20is%20%60*%60%2C%20then%20return%20success.
[fetch-get]: https://fetch.spec.whatwg.org/#:~:text=Return%20the%20values%20of%20all,by%200x2C%200x20%2C%20in%20order.
[fetch-method-get]: https://fetch.spec.whatwg.org/#:~:text=A%20request%20has%20an%20associated%20method,GET
[fetch-mime]: https://fetch.spec.whatwg.org/#:~:text=To%20extract%20a%20MIME%20type%20from%20a%20header%20list%20headers%2C%20run%20these%20steps.%20They%20return%20failure%20or%20a%20MIME%20type.
[fetch-nosniff]: https://fetch.spec.whatwg.org/#:~:text=If%20values%5B0%5D%20is%20an%20ASCII%20case%2Dinsensitive%20match%20for%20%22nosniff%22%2C%20then%20return%20true.
[geolocation-default]: https://www.w3.org/TR/geolocation/#:~:text=This%20specification%20defines%20a%20policy%2Dcontrolled%20feature%20identified%20by%20the%20token%20string%20%22geolocation%22.%20Its%20default%20allowlist%20is%20'self'.
[hstspreload-min]: https://hstspreload.org/#:~:text=The%20max%2Dage%20must%20be%20at%20least%2031536000%20seconds%20(1%20year).
[hstspreload-token]: https://hstspreload.org/#:~:text=If%20a%20site%20sends%20the,the%20form%20on%20this%20site.
[html-charset-1024]: https://html.spec.whatwg.org/multipage/parsing.html#:~:text=The%20authoring%20conformance%20requirements%20for%20character%20encoding%20declarations%20limit%20them%20to%20only%20appearing%20in%20the%20first%201024%20bytes.
[html-charset-transport]: https://html.spec.whatwg.org/multipage/parsing.html#:~:text=If%20the%20transport%20layer%20specifies%20a%20character%20encoding%2C%20and%20it%20is%20supported%2C%20return%20that%20encoding%20with%20the%20confidence%20certain.
[html-coep-compat]: https://html.spec.whatwg.org/multipage/browsers.html#:~:text=An%20embedder%20policy%20value%20is%20compatible%20with%20cross%2Dorigin%20isolation%20if%20it%20is%20%22credentialless%22%20or%20%22require%2Dcorp%22.
[html-coop-plus]: https://html.spec.whatwg.org/multipage/browsers.html#:~:text=cannot%20be%20directly%20set%20via%20the%20%60Cross%2DOrigin%2DOpener%2DPolicy%60%20header%2C%20but%20results%20from%20a%20combination%20of%20setting%20both
[html-docdomain]: https://html.spec.whatwg.org/multipage/browsers.html#:~:text=Avoid%20using%20the%20document.domain%20setter.%20It%20undermines%20the%20security%20protections%20provided%20by%20the%20same%2Dorigin%20policy.
[html-oac]: https://html.spec.whatwg.org/multipage/document-lifecycle.html#:~:text=Let%20requestsOAC%20be%20true%20if%20oacHeader%20is%20not%20null%20and%20oacHeader%5B0%5D%20is%20the%20boolean%20true%3B%20otherwise%20false.
[html-xfo-allowfrom]: https://html.spec.whatwg.org/multipage/speculative-loading.html#:~:text=variant%20of%20the%20header%2C%20but%20that%20is%20not%20to%20be%20implemented
[html-xfo-csp]: https://html.spec.whatwg.org/multipage/speculative-loading.html#:~:text=If%20policy's%20directive%20set%20contains%20a%20frame%2Dancestors%20directive%2C%20then%20return%20true.
[html-xfo-invalid]: https://html.spec.whatwg.org/multipage/speculative-loading.html#:~:text=These%20are%20treated%20as%20if%20the%20header%20were%20omitted%20entirely.
[html-xfo-multi]: https://html.spec.whatwg.org/multipage/speculative-loading.html#:~:text=If%20xFrameOptions's%20size%20is%20greater%20than%201%2C%20and%20xFrameOptions%20contains%20any%20of%20%22deny%22%2C%20%22allowall%22%2C%20or%20%22sameorigin%22%2C%20then%20return%20false.
[html-xfo-sameorigin]: https://html.spec.whatwg.org/multipage/speculative-loading.html#:~:text=If%20containerDocument's%20origin%20is%20not%20same%20origin%20with%20destinationOrigin%2C%20then%20return%20false.
[html-xfo-several-invalid]: https://html.spec.whatwg.org/multipage/speculative-loading.html#:~:text=This%20means%20it%20contains%20multiple%20invalid%20values%2C%20which%20we%20treat%20the%20same%20way%20as%20if%20the%20header%20was%20omitted%20entirely.
[ie-end]: https://learn.microsoft.com/en-us/lifecycle/announcements/internet-explorer-11-end-of-support-windows-10#:~:text=On%20June%2015%2C%202022%2C%20the%20Internet%20Explorer%2011%20(IE11)%20desktop%20application%20ended%20support
[ie8-xdo]: https://learn.microsoft.com/en-us/archive/blogs/ie/ie8-security-part-v-comprehensive-protection#:~:text=When%20the%20new%20X%2DDownload%2DOptions%20header,opening%20a%20file%20download%20directly
[mdn-acao-null]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin#:~:text=Note%3A%20The%20value%20null%20should%20not%20be%20used.
[mdn-bamc]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/block-all-mixed-content#:~:text=Warning%3A%20This%20directive%20is%20marked%20as%20obsolete%20in%20the%20specification.
[mdn-coep-doc]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy#:~:text=configures%20the%20current%20document's%20policy%20for%20loading%20and%20embedding%20cross%2Dorigin%20resources
[mdn-corp-nocors]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cross-Origin_Resource_Policy#:~:text=The%20policy%20is%20only%20effective%20for%20no%2Dcors%20requests
[mdn-corp-xssi]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cross-Origin_Resource_Policy#:~:text=to%20mitigate%20speculative%20side%2Dchannel%20attacks%2C%20like%20Spectre%2C%20as%20well%20as%20Cross%2DSite%20Script%20Inclusion%20attacks
[mdn-docdomain-oac]: https://developer.mozilla.org/en-US/docs/Web/API/Document/domain#:~:text=If%20used%20on%20an%20origin%2Disolated%20page%2C%20i.e.%2C%20one%20that%20uses%20the%20Origin%2DAgent%2DCluster%20HTTP%20header
[mdn-docdomain-shared]: https://developer.mozilla.org/en-US/docs/Web/API/Document/domain#:~:text=Similar%20problems%20occur%20with%20shared%20hosting%20sites%20that%20give%20each%20customer%20a%20different%20subdomain.
[mdn-expectct]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Expect-CT#:~:text=Only%20Google%20Chrome%20and%20other,now%20enforces%20CT%20by%20default.
[mdn-oac-doc]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Origin-Agent-Cluster#:~:text=is%20used%20to%20request%20that%20the%20associated%20Document%20should%20be%20placed%20in%20an%20origin%2Dkeyed%20agent%20cluster
[mdn-oac-hint]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Origin-Agent-Cluster#:~:text=Origin%2Dkeyed%20agent%20clusters%20should%20not%20be%20viewed%20as%20a%20security%20feature
[mdn-oac-ignored]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Origin-Agent-Cluster#:~:text=Values%20other%20than%20%3F1%20are%20ignored%20(e.g.%2C%20the%20%3F0%20structured%20field%20for%20false).
[mdn-object-src]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/object-src#:~:text=Therefore%20it%20is%20recommended%20to%20restrict%20this%20fetch%2Ddirective
[mdn-pragma]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Pragma#:~:text=The%20Pragma%20header%20is%20not,for%20the%20HTTP%2F1.1%20Cache%2DControl%20header
[mdn-prefetch]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/prefetch-src#:~:text=Non%2Dstandard%3A%20This%20feature%20is%20not%20standardized.
[mdn-samesite-default]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#:~:text=Some%20browsers%20use%20Lax%20as%20the%20default%20value%20if%20SameSite%20is%20not%20specified
[mdn-samesite-lax]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#:~:text=and%20for%20cross%2Dsite%20requests%20that%20meet%20both%20of%20the%20following%20criteria,The%20request%20uses%20a%20safe%20method
[mdn-xdns-doc]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-DNS-Prefetch-Control#:~:text=links%20that%20the%20user%20may%20choose%20to%20follow%20as%20well%20as%20URLs%20for%20items%20referenced%20by%20the%20document
[mdn-xdns-nonstd]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-DNS-Prefetch-Control#:~:text=Non%2Dstandard%3A%20This%20feature%20is%20not%20standardized.
[mdn-xpcdp]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Permitted-Cross-Domain-Policies#:~:text=Some%20security%20testing%20tools%20will,accident%20or%20through%20malicious%20actions.
[mdn-xpcdp-none]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Permitted-Cross-Domain-Policies#:~:text=No%20policy%20files%20are%20allowed%20anywhere%20on%20the%20target%20server%2C%20including%20in%20a%20master%20policy%20file.
[mdn-xpcdp-ntr]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Permitted-Cross-Domain-Policies#:~:text=Indicates%20that%20the%20current%20document%20should%20not%20be%20used%20as%20a%20policy%20file%20despite%20other%20headers%20or%20its%20content.
[mdn-xxp-block]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-XSS-Protection#:~:text=though%20this%20approach%20might%20be%20vulnerable%20to%20side%2Dchannel%20attacks%20if%20the%20website%20is%20embeddable%20in%20an
[mdn-xxp-pages]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-XSS-Protection#:~:text=stopped%20pages%20from%20loading%20when%20they%20detected%20reflected%20cross%2Dsite%20scripting
[mdn-xxp-warn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-XSS-Protection#:~:text=in%20some%20cases%2C%20X%2DXSS%2DProtection%20can%20create%20XSS%20vulnerabilities%20in%20otherwise%20safe%20websites
[mediacapture-default]: https://www.w3.org/TR/mediacapture-streams/#:~:text=This%20specification%20defines%20two%20policy%2Dcontrolled%20features%20identified%20by%20the%20strings%20%22camera%22%20and%20%22microphone%22.%20Both%20have%20a%20default%20allowlist%20of%20%22self%22.
[mimesniff-js]: https://mimesniff.spec.whatwg.org/#:~:text=A%20JavaScript%20MIME%20type%20is%20any%20MIME%20type%20whose%20essence%20is%20one%20of%20the%20following
[mimesniff-type]: https://mimesniff.spec.whatwg.org/#:~:text=If%20type%20is%20the%20empty%20string%20or%20does%20not%20solely%20contain%20HTTP%20token%20code%20points%2C%20then%20return%20failure.
[mixed-script]: https://www.w3.org/TR/mixed-content/#:~:text=A%20request%20for%20the%20script,rather%20than%20loading%20the%20resource.
[obs-coop-absent]: https://github.com/mdn/mdn-http-observatory/blob/093035e33568f9e5a6ef85a2afb1b9c92df296e3/src/grader/charts.js#L966-L971
[obs-cors-public]: https://github.com/mdn/mdn-http-observatory/blob/093035e33568f9e5a6ef85a2afb1b9c92df296e3/src/grader/charts.js#L367-L372
[obs-csp-absent]: https://github.com/mdn/mdn-http-observatory/blob/093035e33568f9e5a6ef85a2afb1b9c92df296e3/src/grader/charts.js#L204-L209
[obs-csp-eval]: https://github.com/mdn/mdn-http-observatory/blob/093035e33568f9e5a6ef85a2afb1b9c92df296e3/src/grader/charts.js#L158-L163
[obs-csp-inline]: https://github.com/mdn/mdn-http-observatory/blob/093035e33568f9e5a6ef85a2afb1b9c92df296e3/src/grader/charts.js#L168-L173
[obs-csp-style]: https://github.com/mdn/mdn-http-observatory/blob/093035e33568f9e5a6ef85a2afb1b9c92df296e3/src/grader/charts.js#L133-L138
[obs-hsts-absent]: https://github.com/mdn/mdn-http-observatory/blob/093035e33568f9e5a6ef85a2afb1b9c92df296e3/src/grader/charts.js#L575-L580
[obs-hsts-short]: https://github.com/mdn/mdn-http-observatory/blob/093035e33568f9e5a6ef85a2afb1b9c92df296e3/src/grader/charts.js#L563-L568
[obs-rp-absent]: https://github.com/mdn/mdn-http-observatory/blob/093035e33568f9e5a6ef85a2afb1b9c92df296e3/src/grader/charts.js#L503-L508
[obs-rp-unsafe]: https://github.com/mdn/mdn-http-observatory/blob/093035e33568f9e5a6ef85a2afb1b9c92df296e3/src/grader/charts.js#L515-L520
[obs-xcto-absent]: https://github.com/mdn/mdn-http-observatory/blob/093035e33568f9e5a6ef85a2afb1b9c92df296e3/src/grader/charts.js#L725-L730
[obs-xfo-absent]: https://github.com/mdn/mdn-http-observatory/blob/093035e33568f9e5a6ef85a2afb1b9c92df296e3/src/grader/charts.js#L783-L788
[obs-xfo-csp]: https://github.com/mdn/mdn-http-observatory/blob/093035e33568f9e5a6ef85a2afb1b9c92df296e3/src/grader/charts.js#L751-L756
[orb-blocklist]: https://github.com/annevk/orb/blob/main/README.md#:~:text=An%20opaque%2Dblocklisted%20MIME%20type%20is%20an%20HTML%20MIME%20type%2C%20JSON%20MIME%20type%2C%20or%20XML%20MIME%20type.
[owasp-rr-critical]: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology#:~:text=Overall%20Risk%20Severity,Critical
[permissions-delegation]: https://www.w3.org/TR/permissions/#:~:text=Most%20powerful%20features%20grant%20permission,is%20known%20as%20permission%20delegation.
[pp-default]: https://www.w3.org/TR/permissions-policy/#:~:text=Every%20policy%2Dcontrolled%20feature%20has%20a%20default%20allowlist.
[pp-dict]: https://www.w3.org/TR/permissions-policy/#:~:text=Member%20Values%20of%20any%20other%20form%20will%20cause%20the%20entire%20Dictionary%20Member%20to%20be%20ignored%20by%20the%20processing%20steps.
[pp-empty]: https://www.w3.org/TR/permissions-policy/#:~:text=If%20parsed%20header%20is%20null%2C%20return%20an%20empty%20ordered%20map.
[ps-cache]: https://portswigger.net/kb/issues/00700100_cacheable-https-response#:~:text=Typical%20severity,Information
[ps-cors-http]: https://portswigger.net/kb/issues/00200602_cross-origin-resource-sharing-unencrypted-origin-trusted#:~:text=If%20a%20site%20allows%20interaction,a%20user's%20unencrypted%20network%20traffic.
[ps-css-attr]: https://portswigger.net/research/blind-css-exfiltration#:~:text=Attribute%20selectors%20are%20an%20extremely%20powerful%20way%20to%20extract%20data.
[ps-css-csp]: https://portswigger.net/research/blind-css-exfiltration#:~:text=Imagine%20you've%20got%20a%20blind%20HTML%20injection%20vulnerability%20but%20you%20can't%20get%20XSS%20because%20of%20the%20site's%20CSP
[ps-hsts]: https://portswigger.net/kb/issues/01000300_strict-transport-security-not-enforced#:~:text=Typical%20severity,Low
[ps-referer]: https://portswigger.net/kb/issues/00500400_cross-domain-referer-leakage#:~:text=Typical%20severity,Information
[referrer-last]: https://www.w3.org/TR/referrer-policy/#:~:text=For%20each%20token%20in%20policy%2Dtokens%2C,then%20set%20policy%20to%20token.
[rest-cc]: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#:~:text=Instructs%20compliant%20private%20and%20shared%20HTTP%20caches%20not%20to%20store%20the%20response%20or%20reuse%20it%20for%20another%20request
[rest-cors]: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#:~:text=Be%20as%20specific%20as%20possible%20and%20as%20general%20as%20necessary%20when%20setting%20the%20origins%20of%20cross%2Ddomain%20calls.
[rest-csp-dd]: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#:~:text=The%20majority%20of%20CSP%20functionality%20only%20affects%20pages%20rendered%20as%20HTML.
[rest-ct]: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#:~:text=This%20must%20be%20specified%20as%20per%20the%20type%20of%20content%20returned%20by%20an%20API%20call.
[rest-ct-guess]: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#:~:text=If%20not%20specified%20or%20if%20specified%20incorrectly%2C%20a%20browser%20might%20attempt%20to%20guess%20the%20content%20type%20of%20the%20response.
[rest-ct-js]: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#:~:text=Ensure%20sending%20intended%20content%20type%20headers%20in%20your%20response%20matching%20your%20body%20content%20e.g.%20application%2Fjson%20and%20not%20application%2Fjavascript.
[rest-dd]: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#:~:text=The%20headers%20below%20are%20only%20intended%20to%20provide%20additional%20security%20when%20responses%20are%20rendered%20as%20HTML.
[rest-dd-uncertain]: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#:~:text=However%2C%20if%20there%20is%20any%20uncertainty%20about%20the%20function%20of%20the%20headers,as%20part%20of%20a%20defense%2Din%2Ddepth%20approach
[rest-fa]: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#:~:text=For%20an%20API%20response%2C%20there%20is%20no%20requirement%20to%20be%20framed%20in%20any%20of%20those%20elements.
[rest-fa-dnd]: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#:~:text=This%20header%20protects%20against%20drag%2Dand%2Ddrop%20style%20clickjacking%20attacks.
[rest-pp]: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#:~:text=When%20browsers%20heed%20this%20header%2C%20it%20is%20used%20to%20control%20browser%20features%20via%20directives.
[rest-rp]: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#:~:text=Non%2DHTML%20responses%20should%20not%20trigger%20additional%20requests.
[rest-scope]: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#:~:text=The%20following%20headers%20should%20be%20included%20in%20all%20API%20responses%20that%20may%20be%20consumed%20by%20browser%20clients
[rest-stateless]: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#:~:text=Stateful%20services%20are%20out%20of%20scope%20of%20this%20Cheat%20Sheet
[rest-xfo]: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#:~:text=Still%20recommended%20for%20compatibility%20with%20older%20browsers%20that%20do%20not%20support%20CSP%20Level%202.
[rfc6266-unknown]: https://www.rfc-editor.org/rfc/rfc6266.html#:~:text=Unknown%20or%20unhandled%20disposition%20types%20SHOULD%20be%20handled%20by,recipients%20the%20same%20way%20as%20%22attachment%22
[rfc6797-first]: https://www.rfc-editor.org/rfc/rfc6797.html#:~:text=If%20a%20UA%20receives%20more%20than%20one%20STS%20header%20field%20in%20an%20HTTP,only%20the%20first%20such%20header%20field.
[rfc6797-invalid]: https://www.rfc-editor.org/rfc/rfc6797.html#:~:text=The%20UA%20MUST%20ignore%20any%20STS%20header%20fields%20not%20conforming%20to%20the,Response%20Header%20Field%22).
[rfc6797-zero]: https://www.rfc-editor.org/rfc/rfc6797.html#:~:text=If%20the%20max%2Dage%20header%20field%20value%20token%20has%20a%20value%20of%20zero%2C%20the,UA%20MUST%20remove%20its%20cached%20HSTS%20Policy%20information
[rfc9110-combine]: https://www.rfc-editor.org/rfc/rfc9110.html#:~:text=A%20recipient%20MAY%20combine%20multiple,the%20semantics%20of%20the%20message
[rfc9110-etag]: https://www.rfc-editor.org/rfc/rfc9110.html#:~:text=An%20entity%20tag%20is%20an%20opaque%20validator%20for%20differentiating%20between%20multiple%20representations%20of%20the%20same%20resource
[rfc9110-etag-privacy]: https://www.rfc-editor.org/rfc/rfc9110.html#:~:text=An%20entity%20tag%20can%20be%20abused%20in%20ways%20that%20create%20privacy%20risks.
[rfc9111-auth]: https://www.rfc-editor.org/rfc/rfc9111.html#:~:text=A%20shared%20cache%20MUST%20NOT%20use%20a%20cached%20response%20to%20a%20request%20with%20an%20Authorization%20header%20field
[rfc9111-auth-directives]: https://www.rfc-editor.org/rfc/rfc9111.html#:~:text=In%20this%20specification%2C%20the%20following,5.2.2.9)%2C%20and%20s%2Dmaxage%20(Section%205.2.2.10).
[rfc9111-expires]: https://www.rfc-editor.org/rfc/rfc9111.html#:~:text=If%20a%20response%20includes%20a,ignore%20the%20Expires%20header%20field.
[rfc9111-heuristic]: https://www.rfc-editor.org/rfc/rfc9111.html#:~:text=a%20cache%20MAY%20assign%20a%20heuristic%20expiration%20time%20when%20an%20explicit%20time%20is%20not%20specified
[rfc9111-pragma]: https://www.rfc-editor.org/rfc/rfc9111.html#:~:text=As%20a%20result%2C%20this%20specification%20deprecates%20Pragma.
[rfc9111-pragma-response]: https://www.rfc-editor.org/rfc/rfc9111.html#:~:text=Because%20the%20meaning%20of%20%22Pragma%3A,for%20%22Cache%2DControl%3A%20no%2Dcache%22%20in%20them.
[rfc9111-private]: https://www.rfc-editor.org/rfc/rfc9111.html#:~:text=The%20unqualified%20private%20response%20directive%20indicates%20that%20a%20shared%20cache%20MUST%20NOT%20store%20the%20response
[rfc9112-fold]: https://www.rfc-editor.org/rfc/rfc9112.html#:~:text=This%20specification%20deprecates%20such%20line%20folding%20except%20within%20the%20%22message%2Fhttp%22%20media%20type
[rfc9112-ws]: https://www.rfc-editor.org/rfc/rfc9112.html#:~:text=No%20whitespace%20is%20allowed%20between%20the%20field%20name%20and%20colon.
[rfc9651-fail]: https://www.rfc-editor.org/rfc/rfc9651.html#:~:text=When%20parsing%20fails%2C%20the%20entire%20field%20is%20ignored
[session-csd]: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#:~:text=This%20can%20be%20achieved%20by%20returning%20the%20Clear%2DSite%2DData%20response%20header
[shp-deprecated]: https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/01_headers.md#:~:text=Feature%2DPolicy,Pragma
[sonar-detect]: https://www.sonarsource.com/blog/encoding-differentials-why-charset-matters/#:~:text=A%20single%20occurrence%20of%20one,body%20is%20encoded%20with%20ISO%2D2022%2DJP.
[strictcsp-fallback]: https://web.dev/articles/strict-csp#:~:text=Setting%20fallbacks%20doesn't%20reduce%20the%20security%20of%20your%20policy%20in%20modern%20browsers
[strictcsp-https]: https://web.dev/articles/strict-csp#:~:text=All%20browsers%20that%20support%20strict%2Ddynamic%20ignore%20the%20https%3A%20fallback%2C%20so%20this%20won't%20reduce%20the%20strength%20of%20the%20policy.
[sw-allowed]: https://w3c.github.io/ServiceWorker/#:~:text=Servers%20can%20remove%20the%20path%20restriction%20by%20setting%20a%20Service%2DWorker%2DAllowed%20header%20on%20the%20service%20worker%20script.
[webdev-corp-all]: https://web.dev/articles/security-headers#:~:text=All%20resources%20are%20recommended%20to%20send%20this%20header%20to%20indicate%20whether%20they%20allow%20being%20loaded%20by%20other%20websites.
[webdev-corp-api]: https://web.dev/articles/security-headers#:~:text=You%20should%20apply%20this%20to%20resources%20that%20include%20sensitive%20information%20about%20the%20user,intended%20to%20be%20called%20only%20from%20the%20same%20origin
[zap-10015]: https://www.zaproxy.org/docs/alerts/10015/#:~:text=Risk,Informational
[zap-10020-1]: https://www.zaproxy.org/docs/alerts/10020-1/#:~:text=Risk,Medium
[zap-10020-4]: https://www.zaproxy.org/docs/alerts/10020-4/#:~:text=Risk,Medium
[zap-10021]: https://www.zaproxy.org/docs/alerts/10021/#:~:text=Risk,Low
[zap-10035-1]: https://www.zaproxy.org/docs/alerts/10035-1/#:~:text=Risk,Low
[zap-10035-2]: https://www.zaproxy.org/docs/alerts/10035-2/#:~:text=Risk,Low
[zap-10035-3]: https://www.zaproxy.org/docs/alerts/10035-3/#:~:text=Risk,Low
[zap-10038-1]: https://www.zaproxy.org/docs/alerts/10038-1/#:~:text=Risk,Medium
[zap-10038-3]: https://www.zaproxy.org/docs/alerts/10038-3/#:~:text=Risk,Informational
[zap-10055-10]: https://www.zaproxy.org/docs/alerts/10055-10/#:~:text=Risk,Medium
[zap-10055-13]: https://www.zaproxy.org/docs/alerts/10055-13/#:~:text=Risk,Medium
[zap-10055-3]: https://www.zaproxy.org/docs/alerts/10055-3/#:~:text=Risk,Low
[zap-10055-4]: https://www.zaproxy.org/docs/alerts/10055-4/#:~:text=Risk,Medium
[zap-10055-5]: https://www.zaproxy.org/docs/alerts/10055-5/#:~:text=Risk,Medium
[zap-10055-6]: https://www.zaproxy.org/docs/alerts/10055-6/#:~:text=Risk,Medium
[zap-10055-7]: https://www.zaproxy.org/docs/alerts/10055-7/#:~:text=Risk,Medium
[zap-10063-1]: https://www.zaproxy.org/docs/alerts/10063-1/#:~:text=Risk,Low
[zap-20016-1]: https://www.zaproxy.org/docs/alerts/20016-1/#:~:text=Risk,High
[zap-40040-2]: https://www.zaproxy.org/docs/alerts/40040-2/#:~:text=Risk,Medium
[zap-40040-3]: https://www.zaproxy.org/docs/alerts/40040-3/#:~:text=Risk,High
[zap-90004-1]: https://www.zaproxy.org/docs/alerts/90004-1/#:~:text=Risk,Low
[zap-90004-2]: https://www.zaproxy.org/docs/alerts/90004-2/#:~:text=Risk,Low
[zap-90004-3]: https://www.zaproxy.org/docs/alerts/90004-3/#:~:text=Risk,Low
[zap-cors-risk]: https://github.com/zaproxy/zap-extensions/blob/b769b254cef350eca913dd563e8fea0562256635/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/CorsScanRule.java#L116-L124

<!-- sources:end -->
