/*
 * Header Analyzer: per-header rules and their orchestration.
 *
 * Each checker has the signature (value, ctx) -> Finding[] and sees one
 * header's effective value. `ctx.absentSeverity` is what the header would be
 * worth if it were absent, for values a browser cannot use: those leave the
 * response exactly where no header would, and are graded the same.
 */
(function (HL) {
  'use strict';

  const { Severity, Status, finding } = HL.models;
  const { splitOutsideQuotes, parseDirectives, parseSfItem, parseSfDictionary, trimOWS } = HL.fields;
  const { evaluateCsp } = HL.csp;

  // ---------------------------------------------------------------------------
  // Registry: [key, canonical name, severity when absent, null when absence is
  // the correct state]. Every header here is checked whether present or absent.
  // Absence grades (RULES.md has sources): MEDIUM where ZAP rates the gap Medium
  // or ASVS makes it L1 (CSP, HSTS, anti-clickjacking); LOW for every other
  // header OWASP recommends sending.
  // ---------------------------------------------------------------------------
  const SECURITY_HEADERS = Object.freeze([
    ['content-security-policy', 'Content-Security-Policy', Severity.MEDIUM],
    ['strict-transport-security', 'Strict-Transport-Security', Severity.MEDIUM],
    // LOW instead when CSP frame-ancestors already restricts framing (see below).
    ['x-frame-options', 'X-Frame-Options', Severity.MEDIUM],
    ['x-content-type-options', 'X-Content-Type-Options', Severity.LOW],
    ['cross-origin-opener-policy', 'Cross-Origin-Opener-Policy', Severity.LOW],
    ['permissions-policy', 'Permissions-Policy', Severity.LOW],
    ['referrer-policy', 'Referrer-Policy', Severity.LOW],
    ['cross-origin-embedder-policy', 'Cross-Origin-Embedder-Policy', Severity.LOW],
    ['cross-origin-resource-policy', 'Cross-Origin-Resource-Policy', Severity.LOW],
    ['x-permitted-cross-domain-policies', 'X-Permitted-Cross-Domain-Policies', Severity.LOW],
    ['cache-control', 'Cache-Control', Severity.LOW],
    ['clear-site-data', 'Clear-Site-Data', Severity.LOW],
    ['x-dns-prefetch-control', 'X-DNS-Prefetch-Control', Severity.LOW],
    ['origin-agent-cluster', 'Origin-Agent-Cluster', Severity.LOW],
    ['access-control-allow-origin', 'Access-Control-Allow-Origin', null],
    ['access-control-allow-credentials', 'Access-Control-Allow-Credentials', null],
    ['service-worker-allowed', 'Service-Worker-Allowed', null],
    ['content-disposition', 'Content-Disposition', null],
    ['pragma', 'Pragma', null],
    ['expires', 'Expires', null],
    ['etag', 'ETag', null],
    ['x-download-options', 'X-Download-Options', null],
    // Deprecated: a problem when present, correct when absent
    ['x-xss-protection', 'X-XSS-Protection', null],
    ['expect-ct', 'Expect-CT', null],
    // Only its charset is checked, and only on HTML (OWASP Cheat Sheet).
    ['content-type', 'Content-Type', null],
  ].map(Object.freeze));

  // What the report says when a header whose absence is correct is not sent.
  const ABSENT_NOTES = {
    'service-worker-allowed': 'Not sent, so a service worker stays limited to the path its script is served from: the safest state.',
    'content-disposition': 'Not sent. Content-Disposition only matters on responses meant to be downloaded; for those OWASP recommends attachment, together with nosniff.',
    'pragma': 'Not sent. Pragma is an HTTP/1.0 header superseded by Cache-Control (RFC 9111); caching is evaluated on Cache-Control.',
    'expires': 'Not sent. Expires is superseded by Cache-Control max-age (RFC 9111); caching is evaluated on Cache-Control.',
    'etag': 'Not sent. ETag is a cache validator, so its absence weakens nothing; RFC 9110 even notes that an entity tag can be abused to track users.',
    'x-download-options': 'Not sent. X-Download-Options only ever affected Internet Explorer, retired in 2022; not sending it is correct.',
  };

  // ---------------------------------------------------------------------------
  // Duplicate headers, resolved the way browsers resolve them:
  //   join:  occurrences combine into one comma-separated value (RFC 9110
  //           §5.3, and Fetch "get", which every header read through Fetch
  //           goes through); whether the result is still valid is the
  //           checker's call.
  //   first: the first occurrence is evaluated: HSTS per RFC 6797 §8.1, and
  //           headers no standard defines a resolution for.
  // ---------------------------------------------------------------------------
  const JOIN = new Set([
    'referrer-policy', 'x-frame-options', 'content-security-policy', 'cache-control',
    'clear-site-data', 'permissions-policy', 'pragma', 'cross-origin-opener-policy',
    'cross-origin-embedder-policy', 'x-content-type-options', 'access-control-allow-origin',
    'access-control-allow-credentials', 'content-type', 'cross-origin-resource-policy',
    'origin-agent-cluster', 'service-worker-allowed',
  ]);

  function dupSources(key) {
    if (key === 'strict-transport-security') return ['rfc6797-first', 'zap-10035-3'];
    return JOIN.has(key) ? ['rfc9110-combine', 'fetch-get'] : ['rfc9110-combine'];
  }

  function resolveDuplicates(key, canonical, values) {
    if (values.length === 1) return { value: values[0], note: null };

    const join = JOIN.has(key);
    const identical = new Set(values.map((v) => v.trim().toLowerCase())).size === 1;
    let effective;
    let behavior;
    // 'join' comes first: a browser concatenates whether or not the copies
    // match, and for a single-valued header (COOP) that is what breaks it.
    if (join) {
      effective = values.join(', ');
      behavior = 'browsers combine them into a single header value';
    } else if (identical) {
      effective = values[0];
      behavior = 'the duplicate values are identical';
    } else if (key === 'strict-transport-security') {
      effective = values[0];
      behavior = 'RFC 6797 has browsers process only the first';
    } else {
      effective = values[0];
      behavior = 'no standard says how copies of this header are resolved, so the first is assumed';
    }
    const seen = `Values sent: ${values.join(' | ')}. Evaluated as '${effective}' because ${behavior}.`;

    if (identical || join) {
      return {
        value: effective,
        note: finding(canonical, Severity.LOW, `${canonical}: header sent ${values.length} times`, {
          status: Status.DUPLICATED, brief: identical ? `Sent ${values.length} times with the same value` : `Sent ${values.length} times; browsers combine the values`,
          description: seen,
          recommendation: identical ? `Configure the server (and any proxy or CDN) to send ${canonical} only once.` : '',
          sources: dupSources(key),
        }),
      };
    }
    // One component's value is discarded, so whoever set it is working on a
    // false assumption.
    return {
      value: effective,
      note: finding(canonical, Severity.LOW, `${canonical}: sent ${values.length} times with conflicting values`, {
        status: Status.DUPLICATED, brief: `Sent ${values.length} times with conflicting values`,
        description: `${seen} Whichever component set a discarded value is operating on a false assumption, and the resolution is not guaranteed to be identical in every browser.`,
        sources: dupSources(key),
        recommendation: `Decide which value is intended, then send ${canonical} once.`,
      }),
    };
  }

  // ---------------------------------------------------------------------------
  // Strict-Transport-Security: RFC 6797
  // ---------------------------------------------------------------------------
  const HSTS = 'Strict-Transport-Security';

  function hstsSyntaxError(value, directives) {
    const spell = { 'max-age': 'max-age', includesubdomains: 'includeSubDomains', preload: 'preload' };
    const sp = (n) => spell[n] || n;
    const names = splitOutsideQuotes(value, ';')
      .map((t) => trimOWS(t.split('=')[0]).toLowerCase())
      .filter((n) => n);
    const repeated = [...new Set(names.filter((n, i) => names.indexOf(n) !== i))].sort();
    if (repeated.length) return `the ${repeated.map(sp).join(', ')} directive appears more than once`;

    // parseDirectives maps a bare name to null and `name=` to '': both "=" forms are invalid.
    const valued = ['includesubdomains', 'preload'].filter((n) => directives.has(n) && directives.get(n) !== null);
    if (valued.length) return `${valued.map(sp).join(' and ')} must not be given a value`;

    const maxAge = directives.get('max-age');
    if (maxAge === undefined || maxAge === null) return 'the required max-age directive is missing';
    if (!/^[0-9]+$/.test(maxAge)) return `max-age must be a number of seconds, not '${maxAge}'`;
    return null;
  }

  function checkHsts(value, ctx) {
    const cfg = ctx.hsts;
    const directives = parseDirectives(value, ';');
    const reason = hstsSyntaxError(value, directives);
    if (reason) {
      return [finding(HSTS, ctx.absentSeverity, `HSTS: the header is not valid because ${reason}`, {
        sources: ['rfc6797-invalid', 'obs-hsts-absent', 'cs-hsts-rec'],
        brief: 'Invalid syntax, so browsers ignore the header',
        description: 'A browser ignores a Strict-Transport-Security header that does not conform to RFC 6797 §6.1, so this site has no HSTS at all: the same position as never sending the header. Nothing in the response says so.',
        recommendation: 'Strict-Transport-Security: max-age=63072000; includeSubDomains',
      })];
    }
    // Compared as a string length first: a 400-digit max-age is valid and huge.
    const raw = directives.get('max-age').replace(/^0+(?=\d)/, '');
    const maxAge = raw.length > 15 ? Number.MAX_SAFE_INTEGER : Number(raw);

    if (maxAge === 0) {
      return [finding(HSTS, ctx.absentSeverity, 'HSTS: max-age=0 revokes HSTS protection', {
        sources: ['rfc6797-zero', 'zap-10035-2'],
        brief: 'max-age=0 switches HSTS off',
        description: 'max-age=0 instructs browsers to delete the HSTS entry, so this site has no HSTS, the same position as never sending the header, and worse for a visitor who had the entry already. It is the documented way to turn HSTS off, so it may well be deliberate.',
        recommendation: 'Set max-age to at least 63072000 (2 years).',
      })];
    }

    const findings = [];
    if (maxAge < cfg.minMaxAge) {
      findings.push(finding(HSTS, Severity.LOW, `HSTS: max-age too short (${maxAge}s < ${cfg.minMaxAge}s)`, {
        sources: ['cs-hsts-rec', 'hstspreload-min', 'asvs-3.4.1', 'obs-hsts-short'],
        brief: `max-age=${maxAge} is below the ${duration(cfg.minMaxAge)} minimum`,
        description: 'Protection lapses this long after the last visit, and the next first request goes out over plain HTTP where it can be stripped. OWASP recommends max-age=63072000 (2 years); hstspreload.org requires at least one year.',
        recommendation: `Set max-age to at least ${cfg.minMaxAge}.`,
      }));
    }
    // Not contingent on the site having subdomains: the attacker supplies the name.
    if (cfg.requireIncludeSubdomains && !directives.has('includesubdomains')) {
      findings.push(finding(HSTS, Severity.LOW, 'HSTS: missing includeSubDomains', {
        sources: ['asvs-3.4.1', 'cs-hsts-rec', 'bp-hsts'],
        brief: 'includeSubDomains is not set',
        description: 'HSTS covers this host and nothing else, and a host that does not exist is not covered either. An attacker on the network path can answer for anything.example.com over plain HTTP, and from there set cookies with Domain=example.com, which the browser then sends to the protected site. Browsers no longer let such an origin overwrite an existing Secure cookie, but injecting one, or shadowing it on another path, still works. A site with no subdomains at all is not exempt: the name is the attacker\'s to choose.',
        recommendation: 'Add includeSubDomains, once every host under the domain is served over HTTPS.',
      }));
    }
    // Both branches are contingent on the same lookup: the token declares
    // intent, and membership of the list is a separate step.
    if (cfg.requirePreload) {
      const listed = 'Is the domain on the preload list? Check hstspreload.org. If it is, there is nothing here. If it is not, ';
      if (!directives.has('preload')) {
        findings.push(finding(HSTS, Severity.LOW, 'HSTS: preload is not declared', {
          sources: ['cs-hsts-rec', 'hstspreload-token'],
          brief: 'preload is not set',
          description: 'Preloading is what closes the one gap HSTS cannot close on its own: the first request to this domain, made before the browser has ever seen the site, goes out over plain HTTP and can be stripped by anyone on the network path.',
          verify: listed + 'this stands. Preloading is also hard to undo and covers every subdomain, so a site may have declined it deliberately: that is a decision to record, not a defect to report.',
        }));
      } else {
        findings.push(finding(HSTS, Severity.LOW, 'HSTS: preload is declared, which is not the same as being on the list', {
          sources: ['hstspreload-token'],
          brief: 'preload is declared but list membership is unverified',
          description: 'The token is what a domain must send to be accepted, not what puts it there: submission at hstspreload.org is a separate step, and it can be refused or reversed. A domain can carry this token for years without ever being listed.',
          verify: listed + 'the first-visit protection this header looks like it provides does not exist, and the site is exactly where it would be without the token.',
        }));
      }
    }
    if (!findings.length) findings.push(finding(HSTS, Severity.OK, 'HSTS correctly configured', { sources: ['cs-hsts-rec', 'asvs-3.4.1'] }));
    return findings;
  }

  // ---------------------------------------------------------------------------
  // X-Frame-Options: HTML "check a navigation response's adherence to
  // X-Frame-Options", which works on a set of lowercased values.
  // ---------------------------------------------------------------------------
  const XFO = 'X-Frame-Options';

  function checkXFrameOptions(value, ctx) {
    const values = new Set(splitOutsideQuotes(value, ',', true).map((v) => v.toLowerCase()));
    const usable = ['deny', 'allowall', 'sameorigin'].some((v) => values.has(v));

    if (values.size > 1) {
      if (usable) {
        return [finding(XFO, Severity.LOW, `X-Frame-Options: '${value}' blocks framing by contradicting itself`, {
          sources: ['html-xfo-multi'],
          brief: 'Contradictory values; browsers block framing',
          description: 'More than one value is given, and at least one is usable, so a browser refuses the frame rather than guess which was meant. Framing is prevented, and a contradiction here can only ever be stricter than the values it is made of, but whichever component set the value being ignored is working on a false assumption, and two components writing this header may be writing others.',
          recommendation: 'Send X-Frame-Options once, with DENY.',
        })];
      }
      return [finding(XFO, ctx.absentSeverity, `X-Frame-Options: '${value}' leaves the page framable by anyone`, {
        brief: 'No valid value, so browsers ignore the header',
        description: 'Several values are given and none of them is one a browser applies, so the header is treated as if it had been omitted.',
        sources: ['html-xfo-several-invalid', 'zap-10020-4'],
        recommendation: 'Set X-Frame-Options: DENY',
      })];
    }

    const only = [...values][0];
    if (only === 'deny') return [finding(XFO, Severity.OK, 'X-Frame-Options: DENY (optimal)', { sources: ['cs-xfo-rec', 'bp-xfo'] })];
    if (only === 'sameorigin') {
      return [finding(XFO, Severity.LOW, 'X-Frame-Options: SAMEORIGIN lets another page on this origin frame it', {
        sources: ['html-xfo-sameorigin', 'cs-xfo-rec', 'bp-xfo'],
        brief: 'SAMEORIGIN instead of DENY',
        description: 'A browser walks every containing document and refuses the frame as soon as one is cross-origin, so this is as strong as frame-ancestors \'self\'. What it still permits is a page on this same origin. That matters where an attacker can put markup on one: a stored HTML injection that a CSP stops short of script execution, say: they cannot read anything through it, but they can frame this page and overlay it, which DENY would have prevented outright.',
        verify: 'Does another page on this origin need to frame this one (an admin console, a preview pane, an embedded editor)? If one does, this stands and the exposure is the price of the feature. If none does, DENY costs nothing and closes it.',
      })];
    }
    if (only.startsWith('allow-from')) {
      return [finding(XFO, ctx.absentSeverity, 'X-Frame-Options: ALLOW-FROM leaves the page framable by anyone', {
        sources: ['html-xfo-allowfrom', 'html-xfo-invalid', 'zap-10020-4'],
        status: Status.DEPRECATED, brief: 'ALLOW-FROM is unsupported, so browsers ignore the header',
        description: 'No current browser implements ALLOW-FROM, and none of them ignore just the directive: they discard the whole header. The page is in the same position as one that never sent it, while the header suggests a policy is in force.',
        recommendation: 'Set X-Frame-Options: DENY, and name the permitted origins in Content-Security-Policy: frame-ancestors.',
      })];
    }
    return [finding(XFO, ctx.absentSeverity, `X-Frame-Options: '${value}' leaves the page framable by anyone`, {
      brief: 'Invalid value, so browsers ignore the header',
      description: 'A browser applies this header for DENY and SAMEORIGIN and nothing else. Anything else it cannot use, so framing is allowed exactly as if the header were absent.',
      sources: ['html-xfo-invalid', 'zap-10020-4'],
      recommendation: 'Set X-Frame-Options: DENY',
    })];
  }

  // ---------------------------------------------------------------------------
  // X-Content-Type-Options: Fetch "determine nosniff": values[0] only,
  // ASCII case-insensitive, quotes kept.
  // ---------------------------------------------------------------------------
  function checkXContentTypeOptions(value, ctx) {
    const first = splitOutsideQuotes(value, ',', true)[0];
    if (first.toLowerCase() === 'nosniff') {
      return [finding('X-Content-Type-Options', Severity.OK, 'X-Content-Type-Options: nosniff (correct)', { sources: ['fetch-nosniff', 'asvs-3.4.4'] })];
    }
    return [finding('X-Content-Type-Options', ctx.absentSeverity, `X-Content-Type-Options: '${first}' leaves MIME sniffing on`, {
      sources: ['fetch-nosniff', 'cs-xcto', 'zap-10021'],
      brief: 'Not set to nosniff',
      description: 'Only \'nosniff\' switches the protection on, and only as the first value of the header. Anything else leaves the browser free to ignore the declared Content-Type and guess from the bytes, so a file a user uploaded, served as text/plain, can still be read as HTML and run as the site. It also stops blocking a script or stylesheet whose response carries the wrong type.',
      recommendation: 'Set X-Content-Type-Options: nosniff',
    })];
  }

  // ---------------------------------------------------------------------------
  // COOP / COEP: structured field items (HTML §7.1.3.1). The token is compared
  // case-sensitively; a value that fails to parse leaves the policy at
  // unsafe-none.
  // ---------------------------------------------------------------------------
  const COOP = 'Cross-Origin-Opener-Policy';
  const COEP = 'Cross-Origin-Embedder-Policy';

  /** {token} when the value parses to a token item; {invalid: reason} otherwise. */
  function structuredToken(value) {
    const r = parseSfItem(value);
    if (!r.ok) return { invalid: r.reason };
    const bare = r.item[0];
    if (bare.type !== 'token') return { invalid: `it is a ${bare.type === 'string' ? 'quoted string' : bare.type}, not a token` };
    return { token: bare.value };
  }

  function caseHint(token, valid) {
    const match = valid.find((v) => v === token.toLowerCase());
    return match && match !== token ? ` Values are case-sensitive: '${match}' would be applied, '${token}' is not.` : '';
  }

  function coopNotApplied(ctx, reason, recommendation, extra) {
    return finding(COOP, ctx.absentSeverity, `COOP: the header is not applied because ${reason}`, {
      sources: ['rfc9651-fail', 'cs-coop-rec', 'zap-90004-3'],
      brief: reason.startsWith('it carries more than one') ? 'More than one value, so no policy is applied' : 'Invalid value, so no policy is applied',
      description: 'A browser that cannot use this value applies unsafe-none, so this response has no COOP at all, the same position as never sending the header, with no Spectre or XS-Leak protection. Nothing in the response says so.' + (extra || ''),
      recommendation: recommendation || 'Set Cross-Origin-Opener-Policy: same-origin',
    });
  }

  const COOP_ALLOW_POPUPS_KEPT = {
    'same-origin-allow-popups': 'No cross-origin document can open this one into an existing browsing context group, so the protection COOP mainly exists for is in place.',
    'noopener-allow-popups': 'Only a same-origin document sending this same value can navigate to this one without a browsing context group switch, and through window.open() not even that: stricter than same-origin in that direction. It does not provide cross-origin isolation, though: that needs same-origin plus COEP.',
  };
  const COOP_VALUES = ['same-origin', 'same-origin-allow-popups', 'noopener-allow-popups', 'unsafe-none'];

  function checkCoop(value, ctx) {
    if (splitOutsideQuotes(value, ',').length > 1) {
      return [coopNotApplied(ctx, 'it carries more than one value', 'Send Cross-Origin-Opener-Policy: same-origin once.')];
    }
    const t = structuredToken(value);
    if (t.invalid) return [coopNotApplied(ctx, `'${value.trim()}' is not a valid header value (${t.invalid})`)];
    const n = t.token;
    if (n === 'same-origin') return [finding(COOP, Severity.OK, 'COOP: same-origin (optimal)', { sources: ['cs-coop-rec', 'bp-coop'] })];
    if (n === 'same-origin-allow-popups' || n === 'noopener-allow-popups') {
      return [finding(COOP, Severity.LOW, `COOP: ${n} lets a window this document opens keep a reference back`, {
        sources: ['asvs-3.4.8', 'cs-coop-rec'],
        brief: `${n} instead of same-origin`,
        description: `${COOP_ALLOW_POPUPS_KEPT[n]} What it gives up is in the other direction: a window this document opens with window.open() stays in its browsing context group if that window sends no COOP of its own, so the window keeps a window.opener reference back and can probe this document through it. That only matters if this document opens windows it does not control.`,
        verify: 'What does this document pass to window.open()? A provider the site chose, an OAuth or payment flow, is what this value exists for, and there is nothing here. A URL the site does not control keeps a window.opener reference back to this document, and then this stands: same-origin severs it.',
      })];
    }
    if (n === 'unsafe-none') {
      return [finding(COOP, ctx.absentSeverity, 'COOP: unsafe-none opts this document out of COOP protection', {
        sources: ['cs-coop-spectre', 'asvs-3.4.8', 'zap-90004-3'],
        brief: 'unsafe-none disables the protection',
        description: 'Any document that opens this one shares its browsing context group and keeps a reference to its window, which is what XS-Leaks are probed through. It also rules out cross-origin isolation, which needs same-origin together with COEP.',
        recommendation: 'Set Cross-Origin-Opener-Policy: same-origin',
      })];
    }
    if (n.toLowerCase() === 'same-origin-plus-coep') {
      return [coopNotApplied(ctx, 'same-origin-plus-COEP cannot be set through this header',
        'It is the result of Cross-Origin-Opener-Policy: same-origin together with Cross-Origin-Embedder-Policy: require-corp, not a value to send.')];
    }
    return [coopNotApplied(ctx, `'${n}' is not a policy browsers recognize`, '', caseHint(n, COOP_VALUES))];
  }

  function coepNoIsolation(ctx, title, why) {
    return finding(COEP, ctx.absentSeverity, title, {
      sources: ['cs-coep', 'zap-90004-2', 'rfc9651-fail'],
      brief: /more than one value/.test(title) ? 'More than one value, so no policy is applied' : /unsafe-none/.test(title) ? 'unsafe-none provides no isolation' : 'Invalid value, so no policy is applied',
      description: `${why} Cross-origin resources requested in no-cors mode load without having to opt in through CORP, and the document is not cross-origin isolated, the same position as never sending the header. This fails safe: features that depend on the isolation are withheld, not left running without it.`,
      recommendation: 'Set Cross-Origin-Embedder-Policy: require-corp (with Cross-Origin-Opener-Policy: same-origin) if cross-origin isolation is wanted.',
    });
  }

  function checkCoep(value, ctx) {
    if (splitOutsideQuotes(value, ',').length > 1) {
      return [coepNoIsolation(ctx, 'COEP: the header is not applied because it carries more than one value',
        'Cross-Origin-Embedder-Policy must hold a single token, and a browser cannot parse this one, so it applies unsafe-none. Sending the header twice produces this, even when both copies are identical.')];
    }
    const t = structuredToken(value);
    if (t.invalid) {
      return [coepNoIsolation(ctx, `COEP: the header is not applied because '${value.trim()}' is not a valid header value`,
        `A browser cannot parse this value (${t.invalid}), so it applies unsafe-none.`)];
    }
    const n = t.token;
    if (n === 'require-corp') {
      return [finding(COEP, Severity.OK, 'COEP: require-corp', {
        sources: ['cs-coep', 'html-coep-compat', 'bp-coep'],
        description: 'Cross-origin resources requested in no-cors mode must opt in through CORP or CORS. This is the COEP half of cross-origin isolation, which also needs Cross-Origin-Opener-Policy: same-origin.',
      })];
    }
    if (n === 'credentialless') {
      return [finding(COEP, Severity.OK, 'COEP: credentialless', {
        sources: ['html-coep-compat'],
        description: 'Cross-origin resources requested in no-cors mode load without having to opt in through CORP, but are fetched with no credentials, so they cannot carry anyone\'s private data. It qualifies for cross-origin isolation exactly as require-corp does: a different mechanism for the same guarantee, not a weaker one.',
      })];
    }
    if (n === 'unsafe-none') {
      return [coepNoIsolation(ctx, 'COEP: unsafe-none is the value a browser applies anyway',
        'unsafe-none is the default, so stating it changes nothing.')];
    }
    return [coepNoIsolation(ctx, `COEP: the header is not applied because '${n}' is not a policy browsers recognize`,
      'A browser that does not recognise the token applies unsafe-none.' + caseHint(n, ['require-corp', 'credentialless', 'unsafe-none']))];
  }

  // ---------------------------------------------------------------------------
  // Cross-Origin-Resource-Policy: Fetch "cross-origin resource policy check":
  // the value is compared byte for byte.
  // ---------------------------------------------------------------------------
  function checkCorp(value, ctx) {
    const H = 'Cross-Origin-Resource-Policy';
    const n = value.trim();
    if (n === 'same-origin' || n === 'same-site') return [finding(H, Severity.OK, `CORP: ${n}`, { sources: ['fetch-corp', 'cs-corp', 'bp-corp'] })];
    if (n === 'cross-origin') {
      return [finding(H, Severity.LOW, 'CORP: cross-origin allows any origin to load this resource', {
        sources: ['cs-corp', 'zap-90004-1'],
        brief: 'cross-origin lets any site load the resource',
        description: 'Any site can embed this resource in no-cors mode, which brings it into that site\'s process, readable through a Spectre-style side channel on browsers without full site isolation. For a resource meant to be public (a CDN asset, an embeddable widget) that is the intent.',
        verify: 'Is this resource meant to be embedded by other sites? If it is, there is nothing here: cross-origin is the value for public assets. If it is not, this stands, and same-site or same-origin closes it.',
      })];
    }
    return [finding(H, ctx.absentSeverity, `CORP: unrecognized value '${value}', not applied`, {
      sources: ['fetch-corp', 'zap-90004-1'],
      brief: 'Invalid value, so browsers ignore the header',
      description: 'Fetch compares the value with same-origin, same-site and cross-origin exactly (it is case-sensitive). Anything else is ignored, leaving the resource as if no header had been sent.',
      recommendation: 'Set Cross-Origin-Resource-Policy: same-origin (or same-site).',
    })];
  }

  // ---------------------------------------------------------------------------
  // Permissions-Policy: an RFC 9651 dictionary. A value that does not parse
  // leaves the empty policy; a member of an unaccepted form is dropped alone.
  // ---------------------------------------------------------------------------
  const PP = 'Permissions-Policy';

  // Features a browser allows to every origin by default. It is these, not
  // camera or payment, that an embedded cross-origin document can use unless
  // the policy takes them away.
  const PP_DEFAULT_ANY_ORIGIN = new Set([
    'attribution-reporting', 'browsing-topics', 'ch-ua-high-entropy-values',
    'deferred-fetch-minimal', 'gamepad', 'picture-in-picture',
    'private-state-token-issuance', 'private-state-token-redemption', 'storage-access',
  ]);
  const PP_DEFAULT_SELF = new Set([
    'accelerometer', 'ambient-light-sensor', 'aria-notify', 'autoplay', 'bluetooth',
    'camera', 'captured-surface-control', 'compute-pressure', 'cross-origin-isolated',
    'deferred-fetch', 'display-capture', 'encrypted-media', 'fullscreen', 'geolocation',
    'gyroscope', 'hid', 'identity-credentials-get', 'idle-detection', 'language-detector',
    'local-fonts', 'local-network', 'local-network-access', 'loopback-network',
    'magnetometer', 'microphone', 'midi', 'on-device-speech-recognition',
    'otp-credentials', 'payment', 'publickey-credentials-create',
    'publickey-credentials-get', 'screen-wake-lock', 'serial', 'speaker-selection',
    'summarizer', 'translator', 'usb', 'web-share', 'window-management',
    'xr-spatial-tracking',
  ]);
  // The any-origin features worth naming: tracking and fingerprinting surface.
  const PP_TRACKING = [
    'attribution-reporting', 'browsing-topics', 'ch-ua-high-entropy-values',
    'private-state-token-issuance', 'private-state-token-redemption', 'storage-access',
  ];
  // Features an XSS turns into access with a single click: the prompt names the
  // site, never the code that asked, and "Allow" is the whole interaction.
  const PP_ONE_CLICK = ['camera', 'microphone', 'geolocation'];

  function ppItem(bare) {
    if (bare.type === 'token') {
      if (bare.value === '*') return '*';
      return bare.value.toLowerCase() === 'self' ? 'self' : null;
    }
    return bare.type === 'string' ? bare.value : null;
  }

  function ppAllowlist(member) {
    const v = member[0];
    if (Array.isArray(v)) return v.map((it) => ppItem(it[0])).filter((o) => o !== null);
    const o = ppItem(v);
    return o === null ? null : [o];
  }

  function ppEffective(feature, declared) {
    if (declared.has(feature)) return declared.get(feature);
    return PP_DEFAULT_ANY_ORIGIN.has(feature) ? ['*'] : ['self'];
  }

  const ppReachesAnEmbed = (f, d) => ppEffective(f, d).some((o) => o !== 'self');
  const ppReachesThisOrigin = (f, d) => {
    const o = ppEffective(f, d);
    return o.includes('*') || o.includes('self');
  };

  const PP_CLOSE_ALL = 'Close what this response does not need: '
    + [...PP_TRACKING].sort().concat(PP_ONE_CLICK).map((f) => f + '=()').join(', ');

  function checkPermissionsPolicy(value, ctx) {
    const parsed = parseSfDictionary(value);
    if (!parsed.ok) {
      return [finding(PP, ctx.absentSeverity, `Permissions-Policy: the header is not valid because ${parsed.reason}`, {
        sources: ['pp-empty', 'rfc9651-fail', 'zap-10063-1'],
        brief: 'Invalid syntax, so the whole policy is ignored',
        description: 'Permissions-Policy is a structured field dictionary (RFC 9651), and a browser that cannot parse one applies the empty policy: every feature stays at its default and nothing this header lists takes effect. That is the same position as never sending it, with the response looking like it restricts something. The most common way to land here is the old Feature-Policy syntax (features separated by semicolons, allowlists written as \'none\' or \'self\') which this header does not accept.',
        recommendation: PP_CLOSE_ALL,
      })];
    }

    const findings = [];
    const declared = new Map();
    const dropped = [];
    for (const [feature, member] of parsed.dict) {
      const origins = ppAllowlist(member);
      if (origins === null) dropped.push(feature);
      else declared.set(feature, origins);
    }

    if (dropped.length) {
      findings.push(finding(PP, Severity.LOW, `Permissions-Policy: dropped by the browser: ${dropped.sort().join(', ')}`, {
        sources: ['pp-dict'],
        brief: `Invalid allowlist for ${dropped.join(', ')}`,
        description: 'An allowlist has to be *, self, a quoted origin, or a parenthesised list of those. These are none of them, so a browser ignores each of these directives on its own and leaves that feature at its default: the rest of the header still applies. Whatever they were written to restrict is not restricted.',
        recommendation: 'Write each allowlist as (), (self) or ("https://origin").',
      }));
    }

    const opened = [...declared].filter(([f, o]) => PP_DEFAULT_SELF.has(f) && o.includes('*')).map(([f]) => f).sort();
    if (opened.length) {
      findings.push(finding(PP, Severity.LOW, `Permissions-Policy: opened to any origin: ${opened.join(', ')}`, {
        sources: ['pp-default', 'chromium-default-self', 'cs-pp-rec'],
        brief: `${opened.join(', ')} allowed to any origin`,
        description: 'A browser allows these features to this origin only. The policy widens them to *, so any document embedded in this page can use them: the policy is granting access rather than restricting it.',
        recommendation: 'Restrict these to () or (self) unless an embedded third party genuinely needs them.',
      }));
    }

    const delegated = PP_ONE_CLICK
      .filter((f) => declared.has(f) && !declared.get(f).includes('*'))
      .map((f) => [f, declared.get(f).filter((o) => o !== 'self')])
      .filter(([, named]) => named.length);
    if (delegated.length) {
      findings.push(finding(PP, Severity.LOW, 'Permissions-Policy: handed to another origin: '
        + delegated.map(([f, o]) => `${f} → ${o.join(', ')}`).join(', '), {
        sources: ['permissions-delegation', 'cs-pp-rec'],
        brief: `${delegated.map(([f]) => f).join(', ')} delegated to another origin`,
        description: 'A browser keeps these to this origin; the policy hands them to the origins named here, so a document from one of them, embedded in this page, can ask for them. What the user is shown when it does is this site\'s name: browsers put the top-level origin in the permission prompt rather than the frame\'s, so someone reading "this site wants to use your camera" has no way to learn that the stream goes somewhere else. Delegating is what this header is for, so this is a question about who was chosen, not a defect in itself. It sits below an allowlist of * because that one also admits a frame nobody chose: an HTML injection that can place an iframe is enough to reach the prompt, while a named origin has to be compromised first.',
        verify: 'What does this page embed, and are these origins parties you meant to give the camera, the microphone or the location to? If they are, there is nothing here: this is the header doing its job. If they are not, or if you cannot say what one of these domains is, the user cannot tell either: the prompt they answer will carry this site\'s name.',
      }));
    }

    const embeds = PP_TRACKING.filter((f) => ppReachesAnEmbed(f, declared)).sort();
    if (embeds.length) {
      findings.push(finding(PP, Severity.LOW, `Permissions-Policy: reachable by an embedded document: ${embeds.join(', ')}`, {
        sources: ['chromium-topics', 'attribution-default', 'chromium-uach', 'chromium-pst-issuance', 'chromium-pst-redemption', 'chromium-storage-access', 'chromium-gamepad', 'chromium-pip', 'chromium-deferred'],
        brief: 'Tracking features left open to embedded content',
        description: 'A browser allows these to every origin, so any cross-origin document this page embeds can use them until the policy says otherwise: reading the user\'s inferred interest topics, asking for high-entropy user-agent hints, registering ad attributions, issuing and redeeming tracking tokens, requesting its own third-party cookies. (gamepad, picture-in-picture and deferred-fetch-minimal are open the same way, with nothing worth reporting behind them.) This is the user\'s privacy toward parties the site chose to embed, and for an advertising or analytics frame it is what the frame was embedded to do: which is why it is stated rather than counted as a defect. Closing them to an embed takes (self); () also takes them from this origin.',
        verify: 'What does this page embed? For an advertising or analytics frame, reading topics and registering attributions is what it was embedded to do, and there is nothing here. For a frame that is there for something else (a chat widget, a video player) it picks these up along the way, and closing them costs nothing: '
          + embeds.map((f) => f + '=()').join(', '),
      }));
    }

    const oneClick = PP_ONE_CLICK.filter((f) => ppReachesThisOrigin(f, declared));
    if (oneClick.length) {
      findings.push(finding(PP, Severity.LOW, `Permissions-Policy: an XSS on this origin could ask for ${oneClick.join(', ')}`, {
        sources: ['mediacapture-default', 'geolocation-default', 'permissions-delegation', 'cs-pp-example'],
        brief: `${oneClick.join(', ')} not disabled`,
        description: 'Nothing embedded cross-origin can reach these: a browser keeps them to this origin either way. What is left open is script that achieves execution here: it can raise the permission prompt, and the prompt names the site, never the code that asked, so a user who has no way to tell the two apart grants it. One click is the whole interaction. Disabling them removes the prompt itself; (self) does not, because an XSS runs on this origin.',
        verify: 'Does this response need them? If it does not, this stands: script that reaches execution here can raise the prompt, and one click grants it: '
          + oneClick.map((f) => f + '=()').join(', ') + '. If it does, the header is per-response, so they can still be closed on every other response.',
      }));
    }

    if (!findings.length) findings.push(finding(PP, Severity.OK, 'Permissions-Policy: every feature addressed', { sources: ['cs-pp-rec'] }));
    return findings;
  }

  // ---------------------------------------------------------------------------
  // Referrer-Policy: W3C Referrer Policy §8.1: the last recognised token wins.
  // ---------------------------------------------------------------------------
  const REFERRER_POLICIES = new Set([
    'no-referrer', 'no-referrer-when-downgrade', 'same-origin', 'origin', 'strict-origin',
    'origin-when-cross-origin', 'strict-origin-when-cross-origin', 'unsafe-url',
  ]);

  function checkReferrerPolicy(value, ctx) {
    const RP = 'Referrer-Policy';
    let n = '';
    for (const token of splitOutsideQuotes(value, ',')) {
      const t = token.toLowerCase();
      if (REFERRER_POLICIES.has(t)) n = t;
    }
    if (n === 'no-referrer' || n === 'same-origin') {
      return [finding(RP, Severity.OK, `Referrer-Policy: '${n}' (sends nothing cross-origin)`, { sources: ['referrer-last', 'bp-rp'] })];
    }
    if (n === 'strict-origin' || n === 'strict-origin-when-cross-origin') {
      return [finding(RP, Severity.OK, `Referrer-Policy: '${n}' (sends only the origin cross-origin)`, { sources: ['referrer-last', 'cs-rp-default'] })];
    }
    if (n === 'origin' || n === 'origin-when-cross-origin') {
      return [finding(RP, Severity.LOW, `Referrer-Policy: '${n}' (sends the origin to plain-HTTP destinations too)`, {
        sources: ['cs-rp-default', 'asvs-3.4.5'],
        brief: `${n} sends the origin over plain HTTP`,
        description: 'Only the origin is sent, never the path or query, but it reaches destinations that are not TLS-protected as well, where anyone on the network path reads which site the user is on. The strict- variants are identical except that they withhold it on such a downgrade.',
        verify: 'Does the page link to, or load anything from, a plain-HTTP destination? If it does, the origin reaches whoever is on the network path and this stands. If it does not, nothing leaks today, but the strict- variants behave identically over HTTPS, so they give up strictly less for nothing in return and the change is free either way.',
      })];
    }
    if (n === 'no-referrer-when-downgrade' || n === 'unsafe-url') {
      const alsoInClear = n === 'unsafe-url';
      return [finding(RP, Severity.LOW, `Referrer-Policy: '${n}' (sends the full URL to third parties)`, {
        sources: ['obs-rp-unsafe', 'ps-referer', 'asvs-3.4.5'],
        brief: `${n} sends full URLs to third parties`,
        description: 'Every third party the page loads a resource from, or links to, receives the complete URL including path and query string, so a password-reset token, a search query or an internal path ends up in someone else\'s logs.'
          + (alsoInClear ? ' It is sent to plain-HTTP destinations too, where anyone on the network can read it.'
            : ' It is withheld only on a downgrade to plain HTTP, which is the one case browsers increasingly prevent anyway.'),
        recommendation: 'Use no-referrer, or strict-origin-when-cross-origin to send no more than the origin.',
      })];
    }
    return [finding(RP, ctx.absentSeverity, `Referrer-Policy: unrecognized value '${value}', so no policy is in force`, {
      sources: ['referrer-last', 'cs-rp-rec'],
      brief: 'Invalid value, so the browser default applies',
      description: 'A token that is not one of the eight defined policies is skipped, so the browser falls back to its own default exactly as if the header had not been sent. The policy intended here is not applied, and nothing in the response reveals that.',
      recommendation: 'Check the spelling. The defined values are no-referrer, no-referrer-when-downgrade, same-origin, origin, strict-origin, origin-when-cross-origin, strict-origin-when-cross-origin, unsafe-url.',
    })];
  }

  // ---------------------------------------------------------------------------
  // Cache-Control: RFC 9111, graded for a response carrying a signed-in user's
  // data, which is the case where caching costs something.
  // ---------------------------------------------------------------------------
  const CACHE_DIRECTIVES = new Set([
    'max-age', 's-maxage', 'no-cache', 'no-store', 'no-transform', 'must-revalidate',
    'proxy-revalidate', 'must-understand', 'private', 'public', 'immutable',
    'stale-while-revalidate', 'stale-if-error',
  ]);

  const CACHE_VERIFY = 'Does this response carry data belonging to a signed-in user? If it does not, there is nothing here: storing a public resource is what these directives are for, and no-store would only cost bandwidth. If it does, how is the user identified? By a session cookie: this stands, and a shared cache can hand the response to the next person who asks for the same URL. By an Authorization header: RFC 9111 §3.5 already bars a shared cache from reusing it, so what is left is the copy on the user\'s own disk, unless the value also carries public, s-maxage or must-revalidate, the three directives that switch shared-cache reuse back on for exactly those requests.';

  function checkCacheControl(value, ctx) {
    const CC = 'Cache-Control';
    const d = parseDirectives(value, ',');
    const bare = (name) => d.has(name) && !d.get(name);

    if (![...d.keys()].some((k) => CACHE_DIRECTIVES.has(k))) {
      return [finding(CC, ctx.absentSeverity, `Cache-Control: '${value}' holds no directive a cache understands`, {
        sources: ['rfc9111-heuristic', 'cs-cc-default', 'zap-10015'],
        brief: 'No valid directive, so heuristic caching applies',
        description: 'None of these tokens is a standard cache directive, so caches ignore them and fall back to heuristic freshness, the same position as sending no Cache-Control at all. Nothing keeps this response out of a shared cache.',
        verify: CACHE_VERIFY,
      })];
    }
    if (d.has('no-store')) return [finding(CC, Severity.OK, 'Cache-Control: no-store (not stored by any cache)', { sources: ['cs-cc-nostore', 'asvs-14.3.2', 'bp-cc'] })];
    if (bare('private')) {
      return [finding(CC, Severity.LOW, 'Cache-Control: private keeps this out of shared caches, not off the disk', {
        sources: ['rfc9111-private', 'cs-cc-private', 'bp-cache'],
        brief: 'private still allows storage on disk',
        description: 'Shared caches will not store the response, so it cannot be served to another user. The browser still writes it to disk, where it can be recovered with the back button after logout, or by whoever uses the machine next.',
        verify: CACHE_VERIFY,
      })];
    }
    const alwaysRevalidates = bare('no-cache')
      || (d.get('max-age') === '0' && (d.has('must-revalidate') || d.has('proxy-revalidate')));
    if (alwaysRevalidates) {
      return [finding(CC, Severity.LOW, `Cache-Control: '${value}' revalidates but does not stop a shared cache storing this`, {
        sources: ['cs-cc-nocache'],
        brief: 'Revalidates but does not prevent storage',
        description: 'Revalidation before reuse is forced, but storage is not prevented. A shared cache may keep the response, and nothing here marks it as belonging to a single user.',
        verify: CACHE_VERIFY,
      })];
    }
    const qualified = ['private', 'no-cache'].find((n) => d.get(n));
    const detail = qualified ? ` The qualified form (${qualified}="${d.get(qualified)}") covers only the fields it names.` : '';
    return [finding(CC, Severity.MEDIUM, `Cache-Control: '${value}' lets a shared cache store this response`, {
      sources: ['cs-cc-nostore', 'asvs-14.3.2', 'rfc9111-auth-directives', 'ps-cache'],
      brief: 'Shared caches may store the response',
      description: 'Nothing here keeps the response out of a shared cache, so a CDN or proxy may store it under this URL and serve it to the next person who asks, one user\'s data handed to another.' + detail,
      verify: CACHE_VERIFY,
    })];
  }

  // ---------------------------------------------------------------------------
  // Smaller checks
  // ---------------------------------------------------------------------------
  function checkXPermittedCrossDomainPolicies(value, ctx) {
    const H = 'X-Permitted-Cross-Domain-Policies';
    const n = value.trim().toLowerCase();
    if (n === 'none' || n === 'master-only') {
      return [finding(H, Severity.OK, `X-Permitted-Cross-Domain-Policies: '${value}' (restrictive)`, { sources: ['mdn-xpcdp-none', 'bp-xpcdp'] })];
    }
    if (n === 'none-this-response') {
      return [finding(H, ctx.absentSeverity, 'X-Permitted-Cross-Domain-Policies: none-this-response sets no site-wide policy', {
        brief: 'none-this-response sets no site-wide policy',
        description: 'none-this-response is valid, but it only stops this one response from being used as a policy file. It declares no meta-policy for the site, so other policy files are governed as if the header were absent.',
        recommendation: 'Set X-Permitted-Cross-Domain-Policies: none',
        sources: ['mdn-xpcdp-ntr', 'mdn-xpcdp-none'],
      })];
    }
    if (n === 'all' || n === 'by-content-type' || n === 'by-ftp-filename') {
      return [finding(H, Severity.MEDIUM, `X-Permitted-Cross-Domain-Policies: '${value}' is permissive`, {
        sources: ['zap-20016-1', 'adobe-master', 'mdn-xpcdp'],
        brief: `${n} allows cross-domain policy files`,
        description: 'Allows cross-domain policy files to be loaded. A PDF opened in the Adobe Reader plugin, or legacy Flash content, can request a cross-domain policy from this origin, and a permissive policy grants it.',
        verify: 'Does this origin serve files a browser plugin might load (PDFs opened in Adobe Reader, or SWF files for Flash)? If it does not, there is nothing here: no content a plugin can load means no cross-domain policy to exploit. If it does, this stands.',
      })];
    }
    return [finding(H, ctx.absentSeverity, `X-Permitted-Cross-Domain-Policies: unrecognized value '${value}'`, {
      sources: ['adobe-invalid', 'mdn-xpcdp'],
      brief: 'Invalid value, so plugins ignore the header',
      description: 'This value is not one of those the Adobe cross-domain policy specification defines (none, master-only, by-content-type, by-ftp-filename, all, none-this-response). Adobe clients ignore it and apply their default, which is the same position as sending no header at all.',
      recommendation: 'Set X-Permitted-Cross-Domain-Policies: none',
    })];
  }

  function checkXXssProtection(value) {
    const H = 'X-XSS-Protection';
    const parts = value.split(';').map((p) => p.trim().toLowerCase());
    const flag = parts[0];
    const rest = parts.slice(1);
    if (flag === '0') {
      return [finding(H, Severity.OK, 'X-XSS-Protection: 0 (deprecated header, disabled correctly)', {
        sources: ['cs-xxp-rec'],
        description: 'The header is deprecated. Setting it to 0 is what OWASP recommends for any browser that still reads it.',
        recommendation: 'Consider removing this header entirely and relying on Content-Security-Policy.',
      })];
    }
    if (flag === '1' && !rest.includes('mode=block')) {
      return [finding(H, Severity.LOW, 'X-XSS-Protection: 1 enables the deprecated XSS filter', {
        sources: ['cs-xxp-warn', 'mdn-xxp-warn', 'shp-deprecated'],
        status: Status.DEPRECATED, brief: 'Enables the obsolete XSS filter',
        description: 'The filter matched text from the URL against the scripts in the page, so an attacker could craft a URL that made it neutralise a script the page legitimately contains (an anti-CSRF or framebusting script, for example). No current browser honours the header, which is what keeps this low.',
        recommendation: 'Set to 0 or remove the header; rely on Content-Security-Policy.',
      })];
    }
    if (flag === '1') {
      return [finding(H, Severity.LOW, 'X-XSS-Protection: 1; mode=block (deprecated, potentially risky)', {
        sources: ['mdn-xxp-block', 'cs-xxp-rec', 'shp-deprecated'],
        status: Status.DEPRECATED, brief: 'Enables the obsolete XSS filter in block mode',
        description: 'mode=block stops the page from rendering when the filter triggers, and the filter triggers on scripts the page legitimately contains whenever their markup also appears in the URL. Whether a page was blocked is observable from another origin, turning "does this page contain script X?" into a yes/no readable from outside. No current browser honours the header, which is what keeps this low.',
        recommendation: 'Set to 0 or remove; use Content-Security-Policy instead.',
      })];
    }
    return [finding(H, Severity.LOW, `X-XSS-Protection: '${value}' (deprecated header)`, {
      sources: ['cs-xxp-rec', 'shp-deprecated'],
      status: Status.DEPRECATED, brief: 'Obsolete header',
      recommendation: 'Remove this header and rely on Content-Security-Policy.',
    })];
  }

  function checkExpectCt() {
    return [finding('Expect-CT', Severity.LOW, 'Expect-CT: deprecated header', {
      sources: ['mdn-expectct', 'cs-expectct', 'shp-deprecated'],
      status: Status.DEPRECATED, brief: 'Obsolete, ignored by browsers',
      description: 'Only Chromium ever implemented this header, and it deprecated it in version 107 because it now enforces Certificate Transparency by default, so the header does nothing. OWASP recommends not using it, and Mozilla recommends removing it.',
      recommendation: 'Remove Expect-CT.',
    })];
  }

  // ---------------------------------------------------------------------------
  // Content-Type: Fetch "extract a MIME type", MIME Sniffing "parse a MIME type"
  // ---------------------------------------------------------------------------
  const MIME_TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

  /** {essence, charset} as MIME Sniffing parses one value, or null on failure. */
  function parseMimeType(text) {
    const parts = splitOutsideQuotes(text, ';', true);
    const slash = parts[0].indexOf('/');
    if (slash === -1) return null;
    // No whitespace is allowed around the slash: "text /html" is a failure.
    const type = parts[0].slice(0, slash);
    const subtype = parts[0].slice(slash + 1);
    if (!MIME_TOKEN.test(type) || !MIME_TOKEN.test(subtype)) return null;
    let charset = null;
    for (const param of parts.slice(1)) {
      const eq = param.indexOf('=');
      if (eq === -1) continue;
      const name = param.slice(0, eq).toLowerCase();
      const raw = param.slice(eq + 1);
      let val;
      if (raw[0] === '"') {
        // "Collect an HTTP quoted string": escapes are resolved, the string ends
        // at the closing quote (or the end), and anything after it is dropped.
        // An empty quoted value still counts as the parameter.
        val = '';
        for (let i = 1; i < raw.length && raw[i] !== '"'; i++) {
          val += raw[i] === '\\' && i + 1 < raw.length ? raw[++i] : raw[i];
        }
      } else {
        // An empty unquoted value is skipped as if the parameter were absent.
        val = raw.trim();
        if (val === '') continue;
      }
      // The first occurrence of a parameter wins.
      if (name === 'charset' && charset === null) charset = val;
    }
    return { essence: `${type}/${subtype}`.toLowerCase(), charset };
  }

  /**
   * Fetch "extract a MIME type" over every value of the header: the last valid
   * type wins, and keeps an earlier charset when the essence is the same.
   */
  function extractMimeType(value) {
    let mime = null;
    let essence = null;
    let charset = null;
    for (const v of splitOutsideQuotes(value, ',')) {
      const m = parseMimeType(v);
      if (!m || m.essence === '*/*') continue;
      if (m.essence !== essence) {
        essence = m.essence;
        charset = m.charset;
      } else if (m.charset !== null) {
        charset = m.charset;
      }
      mime = { essence, charset };
    }
    return mime;
  }

  // OWASP Cheat Sheet: "the charset attribute is necessary to prevent XSS in
  // HTML pages". Without it browsers detect the encoding, and an injected
  // ISO-2022-JP escape sequence is enough to change it (Sonar, 2024).
  const CHARSET_VERIFY = 'Does the HTML declare its encoding itself, with <meta charset="utf-8"> within its first 1024 bytes, or start with a UTF-8 byte order mark? If it does, there is nothing here. If it does not, this stands: set Content-Type: text/html; charset=utf-8.';

  // Every label the WHATWG Encoding Standard defines (encodings.json), all 228.
  // A charset that is not one of them is ignored, exactly as if it were absent.
  const ENCODING_LABELS = new Set((
    'unicode-1-1-utf-8 unicode11utf8 unicode20utf8 utf-8 utf8 x-unicode20utf8 866 cp866 csibm866 ' +
    'ibm866 csisolatin2 iso-8859-2 iso-ir-101 iso8859-2 iso88592 iso_8859-2 iso_8859-2:1987 l2 latin2 ' +
    'csisolatin3 iso-8859-3 iso-ir-109 iso8859-3 iso88593 iso_8859-3 iso_8859-3:1988 l3 latin3 ' +
    'csisolatin4 iso-8859-4 iso-ir-110 iso8859-4 iso88594 iso_8859-4 iso_8859-4:1988 l4 latin4 ' +
    'csisolatincyrillic cyrillic iso-8859-5 iso-ir-144 iso8859-5 iso88595 iso_8859-5 iso_8859-5:1988 ' +
    'arabic asmo-708 csiso88596e csiso88596i csisolatinarabic ecma-114 iso-8859-6 iso-8859-6-e ' +
    'iso-8859-6-i iso-ir-127 iso8859-6 iso88596 iso_8859-6 iso_8859-6:1987 csisolatingreek ecma-118 ' +
    'elot_928 greek greek8 iso-8859-7 iso-ir-126 iso8859-7 iso88597 iso_8859-7 iso_8859-7:1987 ' +
    'sun_eu_greek csiso88598e csisolatinhebrew hebrew iso-8859-8 iso-8859-8-e iso-ir-138 iso8859-8 ' +
    'iso88598 iso_8859-8 iso_8859-8:1988 visual csiso88598i iso-8859-8-i logical csisolatin6 ' +
    'iso-8859-10 iso-ir-157 iso8859-10 iso885910 l6 latin6 iso-8859-13 iso8859-13 iso885913 ' +
    'iso-8859-14 iso8859-14 iso885914 csisolatin9 iso-8859-15 iso8859-15 iso885915 iso_8859-15 l9 ' +
    'iso-8859-16 cskoi8r koi koi8 koi8-r koi8_r koi8-ru koi8-u csmacintosh mac macintosh x-mac-roman ' +
    'dos-874 iso-8859-11 iso8859-11 iso885911 tis-620 windows-874 cp1250 windows-1250 x-cp1250 cp1251 ' +
    'windows-1251 x-cp1251 ansi_x3.4-1968 ascii cp1252 cp819 csisolatin1 ibm819 iso-8859-1 iso-ir-100 ' +
    'iso8859-1 iso88591 iso_8859-1 iso_8859-1:1987 l1 latin1 us-ascii windows-1252 x-cp1252 cp1253 ' +
    'windows-1253 x-cp1253 cp1254 csisolatin5 iso-8859-9 iso-ir-148 iso8859-9 iso88599 iso_8859-9 ' +
    'iso_8859-9:1989 l5 latin5 windows-1254 x-cp1254 cp1255 windows-1255 x-cp1255 cp1256 windows-1256 ' +
    'x-cp1256 cp1257 windows-1257 x-cp1257 cp1258 windows-1258 x-cp1258 x-mac-cyrillic ' +
    'x-mac-ukrainian chinese csgb2312 csiso58gb231280 gb2312 gb_2312 gb_2312-80 gbk iso-ir-58 x-gbk ' +
    'gb18030 big5 big5-hkscs cn-big5 csbig5 x-x-big5 cseucpkdfmtjapanese euc-jp x-euc-jp csiso2022jp ' +
    'iso-2022-jp csshiftjis ms932 ms_kanji shift-jis shift_jis sjis windows-31j x-sjis cseuckr ' +
    'csksc56011987 euc-kr iso-ir-149 korean ks_c_5601-1987 ks_c_5601-1989 ksc5601 ksc_5601 ' +
    'windows-949 csiso2022kr hz-gb-2312 iso-2022-cn iso-2022-cn-ext iso-2022-kr replacement ' +
    'unicodefffe utf-16be csunicode iso-10646-ucs-2 ucs-2 unicode unicodefeff utf-16 utf-16le ' +
    'x-user-defined'
  ).split(' '));

  /** Encoding Standard "get an encoding": trim ASCII whitespace, lowercase, match. */
  function isEncodingLabel(label) {
    return ENCODING_LABELS.has(label.replace(/^[\t\n\f\r ]+|[\t\n\f\r ]+$/g, '').toLowerCase());
  }

  const CHARSET_RISK = 'With no charset in the header and none in the page, the browser guesses the encoding from the bytes. An attacker who can place a few bytes in the page, in a comment or a username, can steer that guess: a single ISO-2022-JP escape sequence is enough for Chrome and Firefox to decode the whole page as Japanese, where a backslash can turn into a yen sign and the escaping the server applied stops working. Correctly escaped output then becomes XSS.';

  function checkContentType(value) {
    const H = 'Content-Type';
    const mime = extractMimeType(value);
    if (!mime || mime.essence !== 'text/html') {
      return [finding(H, Severity.OK, `Content-Type: ${mime ? mime.essence : `'${value}'`} (charset is checked on HTML only)`, { sources: ['cs-ct-charset'] })];
    }
    if (mime.charset === '') mime.charset = null;
    if (mime.charset !== null && isEncodingLabel(mime.charset)) {
      return [finding(H, Severity.OK, `Content-Type: text/html; charset=${mime.charset}`, { sources: ['cs-ct-charset', 'encoding-label'] })];
    }
    if (mime.charset !== null) {
      return [finding(H, Severity.LOW, `Content-Type: unrecognised charset '${mime.charset}'`, {
        sources: ['encoding-label', 'html-charset-transport', 'cs-ct-charset', 'sonar-detect'],
        brief: 'Unrecognised charset, so browsers ignore it',
        description: `'${mime.charset}' is not an encoding name the WHATWG Encoding Standard defines, so browsers discard it and treat the page as if it declared no charset. ${CHARSET_RISK}`,
        verify: CHARSET_VERIFY,
      })];
    }
    return [finding(H, Severity.LOW, 'Content-Type: text/html without a charset', {
      sources: ['cs-ct-charset', 'sonar-detect', 'html-charset-1024'],
      brief: 'No charset declared',
      description: CHARSET_RISK,
      verify: CHARSET_VERIFY,
    })];
  }

  function checkXDnsPrefetchControl(value, ctx) {
    const H = 'X-DNS-Prefetch-Control';
    if (value.trim().toLowerCase() === 'off') return [finding(H, Severity.OK, 'X-DNS-Prefetch-Control: off', { sources: ['cs-xdns'] })];
    return [finding(H, ctx.absentSeverity, `X-DNS-Prefetch-Control: '${value}' (DNS prefetching enabled)`, {
      sources: ['cs-xdns', 'bp-xdns-pii', 'bp-xdns-inj', 'cs-xdns-nonstd'],
      brief: 'DNS prefetching is not disabled',
      description: DNS_PREFETCH_TEXT,
      verify: DNS_PREFETCH_VERIFY,
    })];
  }

  // OWASP Cheat Sheet: off "if you do not control links on your website".
  // OWASP Secure Headers Project: add it to responses that "Return sensitive or
  // private content", or are "Prone to HTML injection". Either condition makes
  // it stand.
  const DNS_PREFETCH_VERIFY = 'Does the page link to, or load anything from, domains you do not control (user-generated links, third-party widgets, comments)? Does this response carry sensitive or personal data, or reflect input an attacker could turn into an HTML injection? If any of these applies, this stands: set X-DNS-Prefetch-Control: off. If none does, prefetching reveals nothing worth protecting and there is nothing here.';

  const DNS_PREFETCH_TEXT = 'DNS prefetching resolves domains linked in the page before the user clicks. The DNS resolver learns every hostname the page links to (internal services, private subdomains, an admin panel the page references) whether or not the user navigates there. And an attacker with HTML injection can exfiltrate data through it: <link rel=dns-prefetch> resolves before any CSP directive can stop it, so a page whose CSP blocks scripts, images and connections still leaks data through DNS queries to a resolver the attacker controls. The header is non-standard and only some browsers honour it.';

  function checkOriginAgentCluster(value, ctx) {
    const H = 'Origin-Agent-Cluster';
    const r = parseSfItem(value);
    if (r.ok && r.item[0].type === 'boolean') {
      if (r.item[0].value) return [finding(H, Severity.OK, 'Origin-Agent-Cluster: ?1 (origin-keyed agent cluster)', { sources: ['html-oac'] })];
      return [finding(H, ctx.absentSeverity, 'Origin-Agent-Cluster: ?0 opts out of origin keying', {
        brief: 'Origin keying is explicitly disabled',
        description: 'Chrome and Edge make document.domain immutable by default since version 115, and ?0 is the opt-out that lets this page set it again: once it and a page on another subdomain of the same site both set document.domain, each can read and change the other\'s DOM. Other browsers act only on ?1 and treat ?0 as no header, where document.domain still works anyway.',
        recommendation: 'Set Origin-Agent-Cluster: ?1, and replace any document.domain use with postMessage.',
        sources: ['chrome-docdomain-opt-out', 'chrome-docdomain-115', 'mdn-docdomain-shared', 'mdn-oac-ignored'],
      })];
    }
    return [finding(H, ctx.absentSeverity, `Origin-Agent-Cluster: unrecognized value '${value}', ignored`, {
      sources: ['html-oac', 'rfc9651-fail'],
      brief: 'Invalid value, so browsers ignore the header',
      description: 'The value must be a structured-field boolean: ?1 or ?0. Anything else is ignored and the browser applies its default.',
      recommendation: 'Set Origin-Agent-Cluster: ?1',
    })];
  }

  function checkAcao(value) {
    const H = 'Access-Control-Allow-Origin';
    const n = value.trim();
    if (n === '*') {
      return [finding(H, Severity.LOW, 'Access-Control-Allow-Origin: * (wildcard)', {
        sources: ['asvs-3.4.2-star', 'cs-acao-public', 'bp-cors-public', 'obs-cors-public'],
        brief: 'Any origin can read the response',
        description: 'Any site can read this response. That costs nothing if the endpoint is genuinely public, which is what the wildcard is for. It matters when the endpoint is reachable by a victim\'s browser but not by an attacker\'s server: an internal API, a service on localhost, a device admin page, anything authorised by network or IP rather than by credentials. Without the wildcard a browser sends such a request but refuses to hand the response to the calling page; with it, an attacker\'s page reads the answer through the browser of whoever can reach the endpoint.',
        verify: 'Is this endpoint reachable from anywhere, or only from certain networks? Reachable from anywhere and it costs nothing: that is what the wildcard is for. Limited in any way (an internal network, a VPN, localhost) and this stands: name the origins allowed to read it instead of *.',
      })];
    }
    if (n !== 'null' && n.toLowerCase() === 'null') {
      return [finding(H, Severity.OK, `Access-Control-Allow-Origin: '${n}' matches no origin`, {
        sources: ['fetch-cors-origin'],
        status: Status.NONE,
        description: 'Fetch compares this value with the requesting origin byte for byte, and the opaque origin serialises as lowercase null. Written any other way it matches nothing, so no site is granted access.',
        recommendation: 'Remove the header, or send the single origin that needs access.',
      })];
    }
    if (n === 'null') {
      return [finding(H, Severity.MEDIUM, 'Access-Control-Allow-Origin: null', {
        sources: ['mdn-acao-null', 'zap-40040-2', 'zap-cors-risk'],
        brief: 'Allows the null origin',
        description: 'The null origin is not a trusted party: any page can obtain it through a sandboxed iframe, a data: URL or a cross-origin redirect. Unlike the wildcard, it is a concrete origin, so browsers do send credentials with it when Access-Control-Allow-Credentials is true, which lets an attacker read authenticated responses. It usually comes from reflecting the Origin header.',
        recommendation: 'Never allowlist null. Echo only origins from a known list.',
      })];
    }
    if (n.includes(',')) {
      return [finding(H, Severity.OK, `Access-Control-Allow-Origin lists more than one origin: '${n}'`, {
        sources: ['fetch-cors-origin'],
        status: Status.NONE,
        description: 'The header carries exactly one origin, or *, or null. A list never matches the requesting origin, so the CORS check fails and no site gets access, including the ones it was meant for. A list usually means two components are both setting the header, typically the application and a proxy in front of it.',
        recommendation: 'Send a single origin, picked per request from an allowlist.',
      })];
    }
    if (n.toLowerCase().startsWith('http://')) {
      return [finding(H, Severity.LOW, `Access-Control-Allow-Origin allows a plaintext origin: '${n}'`, {
        sources: ['ps-cors-http', 'zap-cors-risk'],
        brief: 'Allows a plain-HTTP origin',
        description: 'The allowed origin is not protected by TLS, so anyone able to tamper with traffic to it can impersonate it and read whatever this endpoint returns to it. A localhost origin here usually means a development configuration reached production.',
        recommendation: 'Allow an https:// origin instead.',
      })];
    }
    return [finding(H, Severity.LOW, `Access-Control-Allow-Origin: single origin ('${n}'), an allowlist or a mirror`, {
      sources: ['asvs-3.4.2', 'bp-cors-mirror', 'cs-acao-rec'],
      brief: 'Single origin, possibly reflected',
      description: 'One origin is authorised, which is how CORS is meant to be used. But a server that copies the request\'s Origin header into the response produces exactly this, and then the authorised origin is whichever one asked: any site reads what this endpoint returns, the same as *.',
      verify: `Replay the request with Origin: https://an-origin-you-made-up.example. If it comes back here, the origin is reflected and this stands. If the header keeps naming ${n} or disappears, the allowlist is real and there is nothing here.`,
    })];
  }

  function checkAcac(value) {
    // "Send the cookies" says nothing without knowing to whom, so the verdict
    // is reached in correlations.js, which also sees the allowed origin.
    const H = 'Access-Control-Allow-Credentials';
    if (value.trim() === 'true') {
      return [finding(H, Severity.OK, 'Access-Control-Allow-Credentials: true', {
        sources: ['fetch-cors-cred'],
        description: 'Assessed together with Access-Control-Allow-Origin.',
      })];
    }
    return [finding(H, Severity.OK, `Access-Control-Allow-Credentials: '${value.trim()}' (credentials not exposed)`, {
      sources: ['fetch-cors-cred'],
      description: 'Fetch only honours the exact, case-sensitive value true; anything else leaves credentialed responses unreadable.',
    })];
  }

  function checkServiceWorkerAllowed(value) {
    const H = 'Service-Worker-Allowed';
    const n = value.trim();
    if (n === '/') {
      return [finding(H, Severity.LOW, 'Service-Worker-Allowed: / (full site scope)', {
        sources: ['sw-allowed'],
        brief: 'Service worker scope covers the whole site',
        description: 'A service worker registered from this script can intercept every request on the origin. Whoever can control that script (through an upload, a JSONP endpoint or a compromised dependency) controls every page of the site, persistently.',
        verify: 'Is this the site\'s own service worker, meant to control the whole origin? If it is, there is nothing here. If the script lives somewhere less controlled, this stands; restrict the scope to the path it needs.',
      })];
    }
    return [finding(H, Severity.OK, `Service-Worker-Allowed: '${n}'`, {
      sources: ['sw-allowed'],
      status: Status.NONE,
      description: 'The service worker scope is extended beyond the script\'s own path. Check the scope is what the worker needs.',
    })];
  }

  function checkContentDisposition(value) {
    const H = 'Content-Disposition';
    const type = value.split(';')[0].trim().toLowerCase();
    if (type === 'attachment') return [finding(H, Severity.OK, 'Content-Disposition: attachment (prevents inline rendering)', { sources: ['cs-download', 'bp-upload'] })];
    if (type === 'inline') {
      return [finding(H, Severity.OK, 'Content-Disposition: inline', {
        sources: ['cs-download', 'bp-upload'],
        description: 'The browser renders the content inline. For user-supplied files, attachment (together with nosniff) keeps them from rendering as part of the site.',
      })];
    }
    return [finding(H, Severity.OK, `Content-Disposition: unrecognized type '${type}'`, {
      sources: ['rfc6266-unknown'],
      status: Status.NONE,
      description: 'RFC 6266 says an unknown disposition type is handled as attachment, but behaviour has not always been consistent.',
    })];
  }

  function checkPragma(value) {
    return [finding('Pragma', Severity.OK, value.trim().toLowerCase() === 'no-cache'
      ? 'Pragma: no-cache (HTTP/1.0 legacy header)' : `Pragma: '${value}' (legacy HTTP/1.0 header)`, {
      sources: ['rfc9111-pragma', 'shp-deprecated'],
      description: 'Pragma is a legacy HTTP/1.0 header that RFC 9111 has deprecated; Cache-Control is what caches act on. Its presence is harmless.',
    })];
  }

  function checkExpires(value) {
    if (['0', '-1'].includes(value.trim())) return [finding('Expires', Severity.OK, `Expires: ${value.trim()} (already expired)`)];
    return [finding('Expires', Severity.OK, `Expires: '${value}' (legacy freshness header)`, {
      sources: ['rfc9111-expires'],
      description: 'Expires is ignored whenever Cache-Control carries max-age or s-maxage; its presence is harmless.',
    })];
  }

  function checkEtag(value) {
    return [finding('ETag', Severity.OK, value.trim().startsWith('W/') ? 'ETag: weak validator present' : 'ETag: strong validator present')];
  }

  function checkXDownloadOptions(value) {
    const H = 'X-Download-Options';
    if (value.trim().toLowerCase() === 'noopen') {
      return [finding(H, Severity.LOW, 'X-Download-Options: noopen (obsolete Internet Explorer header)', {
        sources: ['ie8-xdo', 'ie-end'],
        status: Status.DEPRECATED, brief: 'Obsolete Internet Explorer header',
        description: 'noopen stopped Internet Explorer from opening a download in the site\'s context. Internet Explorer 11 reached end of support in 2022 and no current browser reads the header, so it does nothing. For downloads, Content-Disposition: attachment and nosniff are what apply.',
        recommendation: 'Remove X-Download-Options.',
      })];
    }
    return [finding(H, Severity.LOW, `X-Download-Options: '${value}'`, {
      sources: ['ie8-xdo', 'ie-end'],
      status: Status.DEPRECATED, brief: 'Obsolete Internet Explorer header with an invalid value',
      description: 'The only defined value is noopen, and only Internet Explorer, retired in 2022, ever read it. This value was not valid even there, so the protection it suggests was never in force.',
      recommendation: 'Remove X-Download-Options.',
    })];
  }

  // ---------------------------------------------------------------------------
  // Clear-Site-Data: W3C Clear Site Data §3.1 / §4.1
  // ---------------------------------------------------------------------------
  const CSD_TYPES = new Set(['"cache"', '"cookies"', '"storage"', '"executionContexts"', '"clientHints"', '"prefetchCache"', '"prerenderCache"']);
  const CSD_WILDCARD = '"*"';
  const CSD_EXPECTED = ['"cache"', '"cookies"', '"storage"'];
  const CSD_VERIFY = 'Is this a response that ends a session: a logout, a password change, an account deletion? If it is not, there is nothing here: this header only has a job where data should stop being available, and clearing a visitor\'s storage on an ordinary page would be the defect. If it is, what the response leaves behind stays readable to whoever uses the browser next.';

  function checkClearSiteData(value) {
    const H = 'Clear-Site-Data';
    const declared = new Set(splitOutsideQuotes(value, ','));
    const known = new Set([...declared].filter((t) => CSD_TYPES.has(t) || t === CSD_WILDCARD));
    if (!known.size) {
      return [finding(H, Severity.LOW, `Clear-Site-Data: '${value}' clears nothing`, {
        sources: ['csd-grammar', 'csd-unknown'],
        brief: 'Invalid values, so nothing is cleared',
        description: 'Every value has to be a quoted string (the grammar is 1#( quoted-string )) and a browser compares each one with its quotes still attached, case-sensitively. None of these matches a type it knows, so the list it builds is empty and no data is removed. Writing * or cookies without quotes is the usual way to land here.',
        verify: CSD_VERIFY,
      })];
    }
    if (known.has(CSD_WILDCARD)) return [finding(H, Severity.OK, 'Clear-Site-Data: "*" (every type cleared)', { sources: ['asvs-14.3.1'] })];
    const missing = CSD_EXPECTED.filter((t) => !known.has(t));
    if (missing.length) {
      return [finding(H, Severity.LOW, `Clear-Site-Data: missing directives: ${missing.join(', ')}`, {
        sources: ['csd-subset', 'bp-csd-time', 'asvs-14.3.1'],
        brief: `${missing.join(', ')} not cleared`,
        description: 'Some types are cleared and these are not. Leaving one out can be deliberate: the specification has an example of a site clearing a subset on purpose, because sweeping every subdomain does damage of its own, and OWASP notes the header costs the browser additional processing time.',
        verify: CSD_VERIFY + ' Was leaving these out a decision? What the session relies on decides whether it matters: a token in localStorage outlives a policy that clears only cookies.',
      })];
    }
    return [finding(H, Severity.OK, 'Clear-Site-Data: cache, cookies and storage cleared', { sources: ['asvs-14.3.1', 'bp-csd-logout'] })];
  }

  const CHECKERS = {
    'strict-transport-security': checkHsts,
    'x-frame-options': checkXFrameOptions,
    'x-content-type-options': checkXContentTypeOptions,
    'cross-origin-opener-policy': checkCoop,
    'cross-origin-embedder-policy': checkCoep,
    'cross-origin-resource-policy': checkCorp,
    'permissions-policy': checkPermissionsPolicy,
    'referrer-policy': checkReferrerPolicy,
    'cache-control': checkCacheControl,
    'x-permitted-cross-domain-policies': checkXPermittedCrossDomainPolicies,
    'x-xss-protection': checkXXssProtection,
    'expect-ct': checkExpectCt,
    'content-type': checkContentType,
    'x-dns-prefetch-control': checkXDnsPrefetchControl,
    'origin-agent-cluster': checkOriginAgentCluster,
    'access-control-allow-origin': checkAcao,
    'access-control-allow-credentials': checkAcac,
    'service-worker-allowed': checkServiceWorkerAllowed,
    'content-disposition': checkContentDisposition,
    'pragma': checkPragma,
    'expires': checkExpires,
    'etag': checkEtag,
    'x-download-options': checkXDownloadOptions,
    'clear-site-data': checkClearSiteData,
    'content-security-policy': (v) => evaluateCsp(v),
  };

  const MISSING_RECS = {
    'content-security-policy': "Add a CSP. A strict starting point: Content-Security-Policy: script-src 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    'strict-transport-security': 'Strict-Transport-Security: max-age=63072000; includeSubDomains',
    'x-frame-options': "X-Frame-Options: DENY (and Content-Security-Policy: frame-ancestors 'none')",
    'x-content-type-options': 'X-Content-Type-Options: nosniff',
    'cross-origin-opener-policy': 'Cross-Origin-Opener-Policy: same-origin',
    'permissions-policy': PP_CLOSE_ALL,
    'referrer-policy': 'Referrer-Policy: strict-origin-when-cross-origin',
    'cross-origin-embedder-policy': 'Cross-Origin-Embedder-Policy: require-corp',
    'cross-origin-resource-policy': 'Cross-Origin-Resource-Policy: same-origin',
    'x-dns-prefetch-control': 'X-DNS-Prefetch-Control: off',
    'x-permitted-cross-domain-policies': 'X-Permitted-Cross-Domain-Policies: none',
  };

  // Where an absence only matters under a condition the response does not
  // state, the finding carries that check instead of a recommendation.
  const MISSING_VERIFY = {
    'cache-control': CACHE_VERIFY,
    'clear-site-data': CSD_VERIFY,
    'x-dns-prefetch-control': DNS_PREFETCH_VERIFY,
  };

  const MISSING_DESCRIPTIONS = {
    'content-security-policy': 'Without a policy, nothing limits what an HTML injection can do: inline scripts, scripts from any origin, plugins and form submissions are all allowed. CSP is the main defence-in-depth control against XSS.',
    'strict-transport-security': 'Without HSTS, a user who types the domain, or follows an http:// link, makes the first request over plain HTTP, where anyone on the network path can strip the upgrade to HTTPS and intercept the session.',
    'x-frame-options': 'Without X-Frame-Options or a CSP frame-ancestors directive, any site can embed this page in a frame and trick the user into clicking it (clickjacking).',
    'x-content-type-options': 'Without nosniff the browser may ignore the declared Content-Type and guess from the bytes, so user-supplied content served as text can be run as HTML or script.',
    'cross-origin-opener-policy': 'Without COOP, a cross-origin page that opens this one (or that this one opens) shares its browsing context group and keeps a window reference, which is the channel XS-Leak attacks probe through.',
    'referrer-policy': 'With no policy of its own, the response inherits whatever default the browser applies, something the site does not control and that has already changed once. Current browsers use strict-origin-when-cross-origin, which sends no more than the origin; older ones send the complete URL, path and query string included, to every third party reached over HTTPS. Stating the policy makes every browser behave the same.',
    'cache-control': 'With no explicit caching instruction, browsers and intermediaries fall back to heuristic caching and may keep this response on disk. That is harmless for a static asset. It is a problem for a response carrying a signed-in user\'s data, which can then be read from the cache after logout or by the next person to use a shared machine.',
    'clear-site-data': 'This response clears no site data. On almost every response that is the right outcome: the header exists to end things, not to be present.',
    'permissions-policy': `Every feature stays at the allowlist a browser applies by default, which leaves two things open. A cross-origin document embedded in this page can use the features a browser allows to every origin (${[...PP_TRACKING].sort().join(', ')}) which is tracking and fingerprinting surface. And script that achieves execution on this origin can raise the permission prompt for ${PP_ONE_CLICK.join(', ')}: the prompt names the site, never the code that asked, so one click from a user who cannot tell the two apart is the whole interaction. A policy is the only thing that removes the prompt.`,
    'x-dns-prefetch-control': DNS_PREFETCH_TEXT,
    'origin-agent-cluster': 'Without it the browser decides whether this page shares an agent cluster with other same-site origins. ?1 asks for origin-keyed isolation, which also disables the document.domain relaxation for this origin.',
    'x-permitted-cross-domain-policies': 'Without this header, Adobe clients still look for a policy file at the site root (/crossdomain.xml) and honour what it grants; other policy files on the site need a meta-policy of by-content-type or all. Setting none makes the restriction explicit: no policy file on the origin, the root one included, can grant cross-domain access.',
    'cross-origin-embedder-policy': 'Without COEP the document cannot be cross-origin isolated, which only matters if it needs SharedArrayBuffer or high-resolution timers. Nothing is exposed by its absence.',
    'cross-origin-resource-policy': 'Without CORP any site can embed this resource in no-cors mode, pulling it into that site\'s process.',
  };

  // The passages behind each absence's grade and description.
  const MISSING_SOURCES = {
    'content-security-policy': ['zap-10038-1', 'obs-csp-absent', 'asvs-3.4.3'],
    'strict-transport-security': ['asvs-3.4.1', 'obs-hsts-absent', 'zap-10035-1', 'ps-hsts'],
    'x-frame-options': ['zap-10020-1', 'obs-xfo-absent', 'cs-xfo-rec'],
    'x-content-type-options': ['zap-10021', 'obs-xcto-absent', 'asvs-3.4.4'],
    'cross-origin-opener-policy': ['zap-90004-3', 'obs-coop-absent', 'asvs-3.4.8'],
    'permissions-policy': ['zap-10063-1', 'cs-pp-rec'],
    'referrer-policy': ['asvs-3.4.5', 'obs-rp-absent', 'cs-rp-default', 'cs-rp-rec'],
    'cross-origin-embedder-policy': ['zap-90004-2', 'cs-coep'],
    'cross-origin-resource-policy': ['zap-90004-1', 'cs-corp'],
    'x-permitted-cross-domain-policies': ['adobe-default', 'adobe-master', 'mdn-xpcdp-none'],
    'cache-control': ['zap-10015', 'asvs-14.3.2', 'bp-cache', 'rfc9111-heuristic'],
    'clear-site-data': ['asvs-14.3.1', 'bp-csd-logout', 'csd-logout'],
    'x-dns-prefetch-control': ['cs-xdns', 'bp-xdns-pii', 'bp-xdns-inj', 'cs-xdns-nonstd'],
    'origin-agent-cluster': ['html-oac', 'mdn-docdomain-oac', 'mdn-docdomain-shared', 'chrome-docdomain-115'],
  };

  const PRAGMA_INSTEAD = 'The response does carry Pragma, but Pragma does not stand in for Cache-Control: its meaning in a response was never specified, so caches and browsers are free to ignore it.';

  const ABSENT_SOURCES = {
    'service-worker-allowed': ['sw-allowed'],
    'content-disposition': ['cs-download'],
    'pragma': ['rfc9111-pragma'],
    'expires': ['rfc9111-expires'],
    'x-download-options': ['ie-end'],
    'etag': ['rfc9110-etag', 'rfc9110-etag-privacy'],
  };

  // The clause after "Missing." in the findings list: what is left unprotected.
  const MISSING_BRIEF = {
    'content-security-policy': 'No defence in depth against XSS',
    'strict-transport-security': 'HTTPS is not enforced',
    'x-frame-options': 'Framing is not restricted by this header',
    'x-content-type-options': 'MIME sniffing is not disabled',
    'cross-origin-opener-policy': 'Cross-origin windows are not isolated',
    'permissions-policy': 'Browser features are not restricted',
    'referrer-policy': 'Referrer leakage depends on browser defaults',
    'cross-origin-embedder-policy': 'No cross-origin isolation',
    'cross-origin-resource-policy': 'Any site can load the resource',
    'x-permitted-cross-domain-policies': 'Cross-domain policy files are not restricted',
    'cache-control': 'Caching is not controlled',
    'clear-site-data': 'Session data is not cleared',
    'x-dns-prefetch-control': 'DNS prefetching is not disabled',
    'origin-agent-cluster': 'Origin keying is not requested',
  };

  // OWASP HTTP Headers Cheat Sheet: X-Frame-Options "does not provide any
  // security" on a redirect or a JSON API, CSP "might be meaningless" on a REST
  // API response that is not rendered, and COOP "may not make sense" for REST
  // APIs. On a response that is evidently not a page, their absence is a check.
  const PAGE_ONLY = new Set(['content-security-policy', 'x-frame-options', 'cross-origin-opener-policy']);
  const PAGE_ONLY_SOURCES = {
    'content-security-policy': ['cs-csp-api'],
    'x-frame-options': ['cs-xfo-api'],
    'cross-origin-opener-policy': ['cs-coop-api'],
  };
  const DOCUMENT_TYPES = new Set(['text/html', 'application/xhtml+xml', 'image/svg+xml', 'text/xml', 'application/xml']);

  /** Why this response is evidently not a page a browser displays, or null. */
  function notAPage(headers, context) {
    const code = context && context.status ? context.status.code : null;
    if (code >= 300 && code <= 399 && code !== 304) {
      return `This is a ${code} redirect, which a browser follows rather than displays`;
    }
    const contentType = headers.get('content-type');
    const mime = contentType ? extractMimeType(contentType.join(', ')) : null;
    if (mime && !DOCUMENT_TYPES.has(mime.essence)) return `Its Content-Type is ${mime.essence}, which a browser does not display as a page`;
    return null;
  }

  function pageOnlyVerify(reason, canonical) {
    return `${reason}, and ${canonical} only protects a page. To check, open this URL in a browser tab, also with a wrong parameter so that an error page shows up if there is one. If you only ever get data (JSON, a file) or a redirect, there is nothing here: when this data ends up inside a page, it is that page's response that needs this header, so analyse that one. If a web page appears, this stands.`;
  }

  /** 63072000 -> "2-year"; anything not a whole number of years stays in seconds. */
  function duration(seconds) {
    const years = seconds / 31536000;
    return Number.isInteger(years) ? `${years}-year` : `${seconds}-second`;
  }

  // ---------------------------------------------------------------------------
  // Orchestration
  // ---------------------------------------------------------------------------

  /**
   * Evaluate every in-scope header. `headers` is a Map {lowercase name: [values]};
   * `context.status` (optional) is the response's status line.
   * Returns HeaderResult objects: {key, name, value, present, findings}.
   */
  function analyzeHeaders(headers, profile, context) {
    const results = [];
    const notPage = notAPage(headers, context);
    const cspValues = headers.get('content-security-policy');
    const framingByCsp = !!cspValues && HL.csp.restrictsFraming(cspValues.join(', '));

    for (const [key, canonical, registryAbsent] of SECURITY_HEADERS) {
      if (profile.skip.has(key)) continue;
      let absentSeverity = registryAbsent;
      // CSP frame-ancestors replaces X-Frame-Options in every browser that has
      // it (ASVS 3.4.6 asks for frame-ancestors). XFO is then only the fallback
      // OWASP recommends for older browsers, so its absence weighs less.
      const xfoFallbackOnly = key === 'x-frame-options' && framingByCsp;
      if (xfoFallbackOnly) absentSeverity = Severity.LOW;
      // Browsers ignore an empty header, so empty and absent are the same state;
      // a value a browser cannot use weighs the same as well (ctx.absentSeverity).
      const ctx = { absentSeverity: absentSeverity === null ? Severity.LOW : absentSeverity, hsts: profile.hsts };

      const occurrences = headers.get(key);
      const findings = [];
      let value = null;

      const verify = MISSING_VERIFY[key] || (notPage && PAGE_ONLY.has(key) ? pageOnlyVerify(notPage, canonical) : '');
      const pageOnly = notPage && PAGE_ONLY.has(key) && !MISSING_VERIFY[key];
      const missingSources = [
        ...(xfoFallbackOnly ? ['csp3-fa-xfo', 'cs-xfo-fa', 'obs-xfo-csp'] : (MISSING_SOURCES[key] || [])),
        ...(pageOnly ? PAGE_ONLY_SOURCES[key] : []),
      ];
      // Pragma beside a missing Cache-Control usually means it was meant to do
      // Cache-Control's job, which in a response it was never defined to do.
      const pragmaInstead = key === 'cache-control' && headers.has('pragma');
      const missingFinding = (title, description, status, brief) => finding(canonical, absentSeverity, title, {
        description: pragmaInstead ? `${description} ${PRAGMA_INSTEAD}` : description,
        status,
        brief,
        recommendation: verify ? '' : (MISSING_RECS[key] || `Add the ${canonical} header.`),
        verify,
        sources: pragmaInstead ? [...missingSources, 'rfc9111-pragma-response', 'mdn-pragma'] : missingSources,
      });
      const absent = (title) => (xfoFallbackOnly
        ? missingFinding(title,
          'Content-Security-Policy frame-ancestors already restricts framing in every current browser. X-Frame-Options is the fallback OWASP recommends alongside it, for browsers that do not implement frame-ancestors.',
          Status.MISSING, 'Only CSP frame-ancestors restricts framing')
        : missingFinding(title,
          MISSING_DESCRIPTIONS[key] || `The ${canonical} header is absent from the response.`,
          Status.MISSING, MISSING_BRIEF[key] || 'The header is not set'));

      if (!occurrences) {
        if (absentSeverity !== null) findings.push(absent(`Missing ${canonical}`));
        else if (ABSENT_NOTES[key]) findings.push(finding(canonical, Severity.OK, `${canonical}: not sent`, { status: Status.NONE, description: ABSENT_NOTES[key], sources: ABSENT_SOURCES[key] || [] }));
      } else {
        const resolved = resolveDuplicates(key, canonical, occurrences);
        value = resolved.value;
        if (resolved.note) findings.push(resolved.note);
        if (value.trim() === '') {
          if (absentSeverity !== null) {
            findings.push(missingFinding(`${canonical}: present but empty`,
              `${canonical} is present but carries no value. Browsers ignore it entirely, so the effect is the same as not sending it at all. An empty value usually points at a misconfigured template or proxy.`,
              Status.MISCONFIGURED, 'Empty value, so browsers ignore the header'));
          }
        } else {
          findings.push(...CHECKERS[key](value, ctx));
        }
      }
      results.push({ key, name: canonical, value, present: value !== null, findings });
    }
    HL.correlations.apply(results, headers);
    for (const r of results) {
      for (const f of r.findings) {
        if (f.verify && f.recommendation) throw new Error(`Finding carries both a check and a recommendation: ${f.title}`);
        if (!(f.severity in SEVERITY_BY_VALUE)) throw new Error(`Unknown severity on: ${f.title}`);
      }
    }
    return results;
  }

  const SEVERITY_BY_VALUE = Object.fromEntries(Object.values(Severity).map((v) => [v, true]));

  HL.rules = Object.freeze({
    SECURITY_HEADERS,
    analyzeHeaders,
    PP_TRACKING,
    PP_ONE_CLICK,
  });
})(globalThis.HeaderAnalyzer = globalThis.HeaderAnalyzer || {});
