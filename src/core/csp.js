/*
 * Header Analyzer: Content-Security-Policy evaluation.
 *
 * Parsing follows CSP Level 3 §2.2.1 ("parse a serialized CSP") exactly:
 * directives are split on ';', names are ASCII-lowercased, a token that is
 * empty or not ASCII is skipped, and a directive whose name was already seen
 * is ignored: the first occurrence wins.
 *
 * Evaluation reads each directive the way a CSP3 browser applies it:
 *   - the fallback lists of §6.8.3 (script-src-elem → script-src → default-src,
 *     worker-src → child-src → script-src → default-src, …);
 *   - "does a source list allow all inline behavior" (§6.7.3.3): a nonce or a
 *     hash in a list switches 'unsafe-inline' off, and so does 'strict-dynamic'
 *     for scripts;
 *   - 'strict-dynamic' also switches host-sources, scheme-sources and 'self'
 *     off. Google's recommended strict policy relies on both, carrying
 *     `'unsafe-inline' https:` purely as a fallback for old browsers, so those
 *     are reported as fallbacks rather than as weaknesses.
 */
(function (HL) {
  'use strict';

  const { Severity, Status, finding } = HL.models;
  const H = 'Content-Security-Policy';

  // Every directive a current browser acts on.
  const DIRECTIVES = new Set([
    'default-src', 'child-src', 'connect-src', 'font-src', 'frame-src', 'img-src',
    'manifest-src', 'media-src', 'object-src', 'script-src', 'script-src-elem',
    'script-src-attr', 'style-src', 'style-src-elem', 'style-src-attr', 'worker-src',
    'fenced-frame-src', 'webrtc', 'base-uri', 'sandbox', 'form-action', 'frame-ancestors',
    'report-uri', 'report-to', 'upgrade-insecure-requests', 'require-trusted-types-for',
    'trusted-types',
  ]);

  // Directives that were once specified or shipped and no longer do anything.
  const RETIRED = new Map([
    ['block-all-mixed-content', ['Mixed content is blocked or upgraded by every current browser anyway; the directive is obsolete.', ['mdn-bamc']]],
    ['prefetch-src', ['Removed from the specification; browsers ignore it.', ['mdn-prefetch', 'cspe-deprecated']]],
    ['navigate-to', ['Removed from the specification and never shipped; browsers ignore it.', ['csp3-registry']]],
    ['plugin-types', ['Removed from the specification; browsers ignore it. Use object-src \'none\'.', ['cscsp-plugin-types']]],
    ['reflected-xss', ['Never implemented outside an early draft; browsers ignore it.', ['cspe-deprecated']]],
    ['referrer', ['Replaced by the Referrer-Policy header; browsers ignore it.', ['cspe-deprecated']]],
    ['disown-opener', ['Never shipped; browsers ignore it. Cross-Origin-Opener-Policy does this job.', ['cspe-deprecated']]],
    ['require-sri-for', ['Never shipped in a stable browser; browsers ignore it.', ['csp3-registry']]],
  ]);

  const ALL_NAMES = new Set([...DIRECTIVES, ...RETIRED.keys()]);

  const KEYWORDS = new Set([
    "'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'",
    "'unsafe-hashes'", "'report-sample'", "'unsafe-allow-redirects'", "'wasm-unsafe-eval'",
    "'trusted-types-eval'", "'report-sha256'", "'report-sha384'", "'report-sha512'",
    "'inline-speculation-rules'", "'unsafe-webtransport-hashes'",
    // sandbox, trusted-types and require-trusted-types-for values
    "'script'", "'allow-duplicates'",
  ]);
  const UNQUOTED_KEYWORDS = new Set([
    'self', 'none', 'unsafe-inline', 'unsafe-eval', 'strict-dynamic', 'unsafe-hashes',
    'report-sample', 'wasm-unsafe-eval',
  ]);

  const NONCE = /^'nonce-([A-Za-z0-9+/\-_]+={0,2})'$/;
  const HASH = /^'(sha256|sha384|sha512)-[A-Za-z0-9+/\-_]+={0,2}'$/;
  const UNQUOTED_NONCE_HASH = /^(nonce|sha256|sha384|sha512)-/;
  const SCHEME_SOURCE = /^[a-z][a-z0-9+.\-]*:$/;

  // Hosts that serve attacker-chosen script: JSONP endpoints that echo a
  // callback, or CDNs that serve any version of any library (old AngularJS
  // evaluates template expressions: a classic CSP bypass) or any npm package.
  const BYPASS_HOSTS = new Set([
    'ajax.googleapis.com', 'www.googleapis.com', 'maps.googleapis.com', 'www.google.com',
    'clients1.google.com', 'accounts.google.com', 'ssl.google-analytics.com',
    'www.google-analytics.com', 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com',
    'code.jquery.com', 'maxcdn.bootstrapcdn.com', 'yandex.st', 'unpkg.com', 'esm.sh',
    'cdn.skypack.dev',
  ]);
  // A wildcard over these reaches a subdomain hosting a bypass endpoint.
  const BYPASS_BASES = new Set([
    'googleapis.com', 'googleusercontent.com', 'jsdelivr.net', 'cloudflare.com', 'bootstrapcdn.com',
  ]);
  // A wildcard over these reaches a subdomain anyone can register and publish to.
  const USER_CONTENT_BASES = new Set([
    'github.io', 'herokuapp.com', 'appspot.com', 'firebaseapp.com', 'web.app', 'netlify.app',
    'vercel.app', 'pages.dev', 'workers.dev', 'azurewebsites.net', 'cloudfront.net',
    'amazonaws.com', 'glitch.me', 'blob.core.windows.net',
  ]);
  // Two-label public suffixes worth recognising; one-label ones are detected structurally.
  const MULTI_LABEL_SUFFIXES = new Set([
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'co.jp', 'com.br', 'co.in',
    'com.cn', 'co.nz', 'co.za', 'com.mx', 'com.tr',
  ]);

  const FALLBACK = {
    'script-src-elem': ['script-src-elem', 'script-src', 'default-src'],
    'script-src-attr': ['script-src-attr', 'script-src', 'default-src'],
    'script-src': ['script-src', 'default-src'],
    'style-src-elem': ['style-src-elem', 'style-src', 'default-src'],
    'style-src-attr': ['style-src-attr', 'style-src', 'default-src'],
    'style-src': ['style-src', 'default-src'],
    'worker-src': ['worker-src', 'child-src', 'script-src', 'default-src'],
    'frame-src': ['frame-src', 'child-src', 'default-src'],
    'child-src': ['child-src', 'default-src'],
    'object-src': ['object-src', 'default-src'],
    'img-src': ['img-src', 'default-src'],
    'font-src': ['font-src', 'default-src'],
  };

  const ASCII_WS = /[\t\n\f\r ]+/;

  // ---------------------------------------------------------------------------
  // Parsing
  // ---------------------------------------------------------------------------

  /** CSP3 §2.2.1 for one serialized policy. */
  function parsePolicy(raw) {
    const directives = new Map();     // name -> {tokens, lower}
    const duplicates = [];
    const nonAscii = [];
    for (const part of raw.split(';')) {
      const token = part.replace(/^[\t\n\f\r ]+|[\t\n\f\r ]+$/g, '');
      if (token === '') continue;
      if (/[^\x00-\x7f]/.test(token)) {
        nonAscii.push(token.split(ASCII_WS)[0]);
        continue;
      }
      const pieces = token.split(ASCII_WS);
      const name = pieces[0].toLowerCase();
      if (directives.has(name)) {
        duplicates.push({ name, value: pieces.slice(1).join(' ') });
        continue;
      }
      const tokens = pieces.slice(1);
      directives.set(name, { tokens, lower: tokens.map((t) => t.toLowerCase()) });
    }
    return { raw, directives, duplicates, nonAscii };
  }

  /** The directive a browser applies for `name`, following the fallback list. */
  function effective(policy, name) {
    for (const candidate of FALLBACK[name] || [name]) {
      const d = policy.directives.get(candidate);
      if (d) return { name: candidate, tokens: d.tokens, lower: d.lower };
    }
    return null;
  }

  function hostOf(source) {
    let s = source.toLowerCase().replace(/^[a-z][a-z0-9+.\-]*:\/\//, '');
    s = s.split('/')[0];
    if (s.startsWith('[')) return { host: s, wildcard: false };     // IPv6 literal
    s = s.split(':')[0];
    const wildcard = s.startsWith('*.');
    return { host: wildcard ? s.slice(2) : s, wildcard };
  }

  function isHostSource(lower) {
    return !lower.startsWith("'") && !SCHEME_SOURCE.test(lower) && lower !== '*';
  }

  /** Levenshtein distance, for suggesting the directive a typo meant. */
  function distance(a, b) {
    const dp = Array.from({ length: a.length + 1 }, (_, i) => [i]);
    for (let j = 1; j <= b.length; j++) dp[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1,
          dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
    }
    return dp[a.length][b.length];
  }

  function suggestion(name) {
    let best = null;
    let bestD = 3;
    for (const known of DIRECTIVES) {
      const d = distance(name, known);
      if (d < bestD) { best = known; bestD = d; }
    }
    return best;
  }

  // ---------------------------------------------------------------------------
  // Evaluation of one policy
  // ---------------------------------------------------------------------------

  /** Collects findings keyed by title, so two routes to one problem report it once. */
  class Collector {
    constructor() { this.map = new Map(); }
    add(severity, title, opts, absence) {
      if (this.map.has(title)) return;
      const f = finding(H, severity, title, opts);
      if (absence) Object.defineProperty(f, 'absence', { value: true, enumerable: false });
      this.map.set(title, f);
    }
    list() { return [...this.map.values()]; }
  }

  /**
   * How a finding names the directive it is about: the directive that actually
   * applied, marked when it was reached through default-src. script-src-elem and
   * script-src-attr usually both resolve to script-src, and then share one title,
   * so a weakness reached by both routes is reported once.
   */
  function label(family, eff) {
    return eff.name === 'default-src' ? `${family} (from default-src)` : eff.name;
  }

  function inlineState(lower) {
    const hasNonce = lower.some((t) => t.startsWith("'nonce-"));
    const hasHash = lower.some((t) => HASH.test(t));
    return {
      hasNonce,
      hasHash,
      strictDynamic: lower.includes("'strict-dynamic'"),
      unsafeInline: lower.includes("'unsafe-inline'"),
    };
  }

  function checkStructure(policy, out) {
    for (const [name, d] of policy.directives) {
      if (!ALL_NAMES.has(name)) {
        const guess = suggestion(name);
        out.add(Severity.LOW, `Unrecognised directive '${name}' is ignored`, {
          sources: ['csp3-registry', 'zap-10055-3'],
          brief: `Unknown directive ${name}`,
          description: `'${name}' is not a CSP directive, so browsers skip it and whatever it was written to restrict is not restricted.`
            + (guess ? ` It looks like a misspelling of '${guess}'.` : ''),
          recommendation: guess ? `Rename it to '${guess}'.` : `Remove '${name}', or replace it with the directive that was meant.`,
        });
      }
      for (const t of d.lower) {
        if (ALL_NAMES.has(t)) {
          out.add(Severity.LOW, `Possible missing semicolon: '${t}' inside '${name}'`, {
            sources: ['csp3-split', 'zap-10055-3'],
            brief: `Missing semicolon before ${t}`,
            description: `'${t}' is a directive name but appears as a source of '${name}', which usually means a ';' is missing. A browser reads it as a host called '${t}', and the directive that was meant is not in the policy at all.`,
            recommendation: `Separate '${name}' and '${t}' with a semicolon.`,
          });
        } else if (UNQUOTED_KEYWORDS.has(t)) {
          out.add(Severity.LOW, `Keyword '${t}' in '${name}' is missing its single quotes`, {
            sources: ['csp3-keywords', 'zap-10055-3'],
            brief: `Unquoted keyword ${t} in ${name}`,
            description: `Without single quotes '${t}' is a host name, not a keyword, so the policy does not do what it says: the keyword's effect is not applied, and a host called '${t}' is allowed instead.`,
            recommendation: `Write it as '${"'"}${t}${"'"}'.`,
          });
        } else if (UNQUOTED_NONCE_HASH.test(t)) {
          out.add(Severity.LOW, `Nonce or hash in '${name}' is missing its single quotes`, {
            sources: ['csp3-nonce-grammar', 'zap-10055-3'],
            brief: `Unquoted nonce or hash in ${name}`,
            description: `'${t}' without single quotes is read as a host name, so the scripts or styles it was meant to allow are blocked.`,
            recommendation: `Write it as '${"'"}${d.tokens[d.lower.indexOf(t)]}${"'"}'.`,
          });
        } else if (t.startsWith("'") && !KEYWORDS.has(t) && !NONCE.test(t) && !HASH.test(t)) {
          out.add(Severity.LOW, `Unrecognised source expression ${t} in '${name}' is ignored`, {
            sources: ['csp3-keywords', 'zap-10055-3'],
            brief: `Invalid source ${t} in ${name}`,
            description: `${t} is quoted like a keyword but is not one, nor a valid nonce or hash, so browsers skip it.`,
            recommendation: 'Check the spelling against the keywords CSP defines.',
          });
        }
      }
      if (d.lower.includes("'none'") && d.lower.length > 1) {
        out.add(Severity.LOW, `'none' in '${name}' is combined with other sources`, {
          sources: ['csp3-none'],
          brief: `'none' combined with other sources in ${name}`,
          description: `'none' only means "nothing" when it is the only source. Next to other sources it is ignored, and the directive allows exactly what the other sources allow.`,
          recommendation: `Remove 'none' from '${name}', or remove the other sources.`,
        });
      }
    }
    for (const dup of policy.duplicates) {
      out.add(Severity.LOW, `Directive '${dup.name}' appears more than once; only the first is applied`, {
        sources: ['csp3-dup', 'zap-10055-3'],
        brief: `${dup.name} is declared twice; only the first applies`,
        description: `CSP3 §2.2.1 skips a directive whose name has already been seen, so '${(dup.name + ' ' + dup.value).trim()}' is ignored. If it was added to tighten the policy, it does not.`,
        recommendation: `Merge the two '${dup.name}' directives into one.`,
      });
    }
    for (const name of policy.nonAscii) {
      out.add(Severity.LOW, `Directive '${name}' contains non-ASCII characters and is ignored`, {
        sources: ['csp3-ascii'],
        brief: `Non-ASCII characters in ${name}`,
        description: 'CSP3 §2.2.1 skips any directive that is not pure ASCII: often the result of a curly quote or a non-breaking space pasted from a document.',
        recommendation: 'Retype the directive with plain ASCII quotes and spaces.',
      });
    }
    for (const [name, [why, refs]] of RETIRED) {
      if (policy.directives.has(name)) {
        out.add(Severity.LOW, `Obsolete CSP directive: ${name}`, {
          status: Status.DEPRECATED, brief: `Obsolete directive ${name}`,
          description: why,
          sources: refs,
          recommendation: `Remove '${name}'.`,
        });
      }
    }
  }

  function checkScripts(policy, out) {
    if (!policy.directives.has('script-src') && !policy.directives.has('default-src')
        && !policy.directives.has('script-src-elem')) {
      out.add(Severity.MEDIUM, 'Missing script-src and default-src', {
        sources: ['cspe-script', 'csp3-default'],
        brief: 'Scripts are not restricted',
        description: 'With neither directive, the policy places no restriction on which scripts run, so it offers no protection against XSS.',
        recommendation: "Add script-src with a per-response nonce and 'strict-dynamic', or at minimum default-src 'self'.",
      }, true);
    }

    const elem = effective(policy, 'script-src-elem');
    const attr = effective(policy, 'script-src-attr');
    const evalList = effective(policy, 'script-src');
    const upgrades = policy.directives.has('upgrade-insecure-requests');

    if (elem) checkScriptElements(label('script-src', elem), elem, upgrades, out);
    if (attr) checkInline(label('script-src', attr), attr, 'script', out);
    if (evalList && evalList.lower.includes("'unsafe-eval'")) {
      out.add(Severity.MEDIUM, `${label('script-src', evalList)}: 'unsafe-eval'`, {
        sources: ['zap-10055-10', 'obs-csp-eval'],
        brief: `'unsafe-eval' allowed for scripts in ${evalList.name}`,
        description: "Lets script turn strings into code with eval(), new Function(), setTimeout(string) and similar APIs, so an injection into any string that reaches them becomes code execution. 'strict-dynamic' does not switch it off.",
        recommendation: "Remove 'unsafe-eval' and refactor the code that needs it. If only WebAssembly needs it, 'wasm-unsafe-eval' is the narrow replacement.",
      });
    }
  }

  function checkInline(lbl, eff, kind, out, leak) {
    const st = inlineState(eff.lower);
    if (!st.unsafeInline) return;
    const disabled = st.hasNonce || st.hasHash || (kind === 'script' && st.strictDynamic);
    if (disabled) {
      out.add(Severity.OK, `${lbl}: 'unsafe-inline' is a fallback for old browsers`, {
        sources: ['csp3-inline-nonce', 'csp3-inline-sd', 'strictcsp-fallback'],
        status: Status.NONE,
        description: `A ${st.hasNonce ? 'nonce' : st.hasHash ? 'hash' : "'strict-dynamic'"} in the same list switches 'unsafe-inline' off in every browser that supports CSP Level 2 or later (CSP3 §6.7.3.2). It only takes effect in browsers too old to understand the rest of the list: the documented backwards-compatible pattern.`,
      });
      return;
    }
    if (kind === 'script') {
      out.add(Severity.MEDIUM, `${lbl}: 'unsafe-inline'`, {
        brief: `'unsafe-inline' allowed for scripts in ${eff.name}`,
        description: 'Any inline <script> block and any event-handler attribute runs, so an HTML injection anywhere on the page is code execution. This removes most of what a CSP protects against.',
        sources: ['zap-10055-5', 'obs-csp-inline'],
        recommendation: "Remove 'unsafe-inline' and allow the scripts you need with a per-response nonce or a hash, plus 'strict-dynamic'.",
      });
    } else if (leak) {
      out.add(Severity.MEDIUM, `${lbl}: 'unsafe-inline'`, {
        sources: ['ps-css-csp', 'ps-css-attr', 'csp3-exfil', 'zap-10055-6'],
        brief: `Inline styles allowed and ${leak.split(' ')[0]} reaches any origin`,
        description: `Any inline style block or style attribute is applied, so an HTML injection can run CSS even where script is blocked. Attribute selectors read values out of the page character by character (CSRF tokens, prefilled form fields, hidden inputs), and each match loads a background image or a font from the attacker's server, which ${leak} allows. The injection becomes theft of those values without a line of script.`,
        recommendation: `Allow inline styles with a nonce or a hash, or move them into stylesheets. Restricting ${leak.split(' ')[0]} (default-src 'self' does it) closes the channel even before that.`,
      });
    } else {
      out.add(Severity.LOW, `${lbl}: 'unsafe-inline'`, {
        brief: `'unsafe-inline' allowed for styles in ${eff.name}`,
        description: 'Any inline style block or style attribute is applied, so an HTML injection can restyle the page: hiding content or overlaying a fake message on the real site. Reading values out of the page with CSS would need a background image or a font from another origin, and this policy\'s img-src and font-src do not allow one.',
        sources: ['zap-10055-6', 'obs-csp-style', 'ps-css-attr', 'csp3-exfil'],
        recommendation: 'Allow inline styles with a nonce or a hash, or move them into stylesheets.',
      });
    }
  }

  function checkScriptElements(lbl, eff, upgrades, out) {
    const st = inlineState(eff.lower);
    checkInline(lbl, eff, 'script', out);

    if (st.strictDynamic && !st.hasNonce && !st.hasHash) {
      out.add(Severity.OK, `${lbl}: 'strict-dynamic' without a nonce or hash blocks every script`, {
        sources: ['csp3-sd-ignores'],
        status: Status.NONE,
        description: "'strict-dynamic' switches off the allowlist and 'unsafe-inline', and trusts only scripts already trusted through a nonce or a hash. With neither, no script can run. That is not a weakness, but it is probably not what was meant.",
        recommendation: "Add a per-response 'nonce-…' (or the hashes of the inline scripts) to the same list.",
      });
    }

    if (eff.lower.includes("'unsafe-hashes'")) {
      if (st.hasHash) {
        out.add(Severity.LOW, `${lbl}: 'unsafe-hashes'`, {
          sources: ['csp3-unsafe-hashes', 'zap-10055-7'],
          brief: `'unsafe-hashes' allowed in ${eff.name}`,
          description: "Lets event-handler attributes and javascript: URLs run when their text matches a hash. An attacker who can inject markup can reuse any allowed handler on an element of their choosing.",
          recommendation: 'Replace inline event handlers with addEventListener, then remove it.',
        });
      } else {
        out.add(Severity.OK, `${lbl}: 'unsafe-hashes' has no effect without a hash`, {
          sources: ['csp3-unsafe-hashes'],
          status: Status.NONE,
          description: "'unsafe-hashes' only widens what hashes match; with no hash in the list it allows nothing.",
          recommendation: "Remove 'unsafe-hashes'.",
        });
      }
    }

    for (const t of eff.lower) {
      const m = NONCE.exec(t);
      if (m && m[1].replace(/=+$/, '').length < 22) {
        out.add(Severity.LOW, `${lbl}: nonce is shorter than 128 bits`, {
          sources: ['csp3-nonce-128'],
          brief: 'Nonce shorter than 128 bits',
          description: `The nonce '${m[1]}' has ${m[1].replace(/=+$/, '').length} characters. CSP3 asks for at least 128 bits of cryptographically random data, which is 22 base64 characters; a short one can be guessed.`,
          recommendation: 'Generate at least 16 random bytes per response and base64-encode them.',
        });
      }
    }
    if (st.hasNonce) {
      out.add(Severity.OK, `${lbl}: the nonce must change on every response`, {
        sources: ['csp3-nonce-unique'],
        status: Status.NONE,
        description: 'A nonce works only if an attacker cannot know it in advance. One that is fixed, cached with the page, or reused across responses can be copied straight into an injected <script nonce=…>, and the policy then allows the injection: no better than \'unsafe-inline\'. One saved response cannot show which it is.',
        verify: 'Request the same URL twice (with any cache bypassed) and compare the nonce values. If they differ, there is nothing here. If they are the same, this stands: the nonce is predictable and the policy can be bypassed by anyone who has seen it.',
      });
    }

    if (st.strictDynamic && (st.hasNonce || st.hasHash)) {
      const ignored = eff.tokens.filter((t, k) => {
        const l = eff.lower[k];
        return l === "'self'" || l === '*' || SCHEME_SOURCE.test(l) || isHostSource(l);
      });
      if (ignored.length) {
        out.add(Severity.OK, `${lbl}: allowlist entries are ignored under 'strict-dynamic'`, {
          sources: ['csp3-sd-ignores', 'strictcsp-https'],
          status: Status.NONE,
          description: `With 'strict-dynamic' and a ${st.hasNonce ? 'nonce' : 'hash'}, browsers that support CSP3 ignore ${ignored.join(' ')}: only scripts trusted through the ${st.hasNonce ? 'nonce' : 'hash'}, and the scripts those load, can run. The entries only matter to older browsers, which is how Google's recommended strict policy keeps them working.`,
        });
      }
      return;
    }

    for (let k = 0; k < eff.lower.length; k++) {
      const t = eff.lower[k];
      const raw = eff.tokens[k];
      if (t === '*' || t === 'http:') {
        out.add(Severity.MEDIUM, `${lbl}: overly broad source '${raw}'`, {
          sources: ['cspe-wildcard', 'cspe-schemes', 'zap-10055-4'],
          brief: `Scripts allowed from ${raw}`,
          description: `'${raw}' allows scripts from any ${t === '*' ? 'web' : 'plain-HTTP'} origin, including one the attacker owns, so an HTML injection can load arbitrary script.`,
          recommendation: "Replace it with a nonce and 'strict-dynamic', or with the exact origins scripts come from.",
        });
      } else if (t === 'https:') {
        out.add(Severity.MEDIUM, `${lbl}: overly broad source 'https:'`, {
          sources: ['cspe-schemes'],
          brief: 'Scripts allowed from any HTTPS origin',
          description: "'https:' allows scripts from every HTTPS origin, including one the attacker registers for a few euros.",
          recommendation: "Replace it with a nonce and 'strict-dynamic', or with the exact origins scripts come from.",
        });
      } else if (t === 'data:') {
        out.add(Severity.MEDIUM, `${lbl}: 'data:' URI scheme`, {
          sources: ['cspe-schemes'],
          brief: 'Scripts allowed from data: URIs',
          description: "An injected <script src=\"data:text/javascript,…\"> carries its own code, so 'data:' is as good as 'unsafe-inline' to an attacker.",
          recommendation: "Remove 'data:'.",
        });
      } else if (t === 'blob:' || t === 'filesystem:') {
        out.add(Severity.LOW, `${lbl}: '${t}' URI scheme`, {
          sources: ['csp3-schemes'],
          brief: `Scripts allowed from ${t} URIs`,
          description: `Script that can create a ${t.slice(0, -1)} URL, or an injection that can reach code that does, can run arbitrary code through it.`,
          recommendation: `Remove '${t}' unless the application really loads scripts from it.`,
        });
      } else if (isHostSource(t)) {
        checkHost(lbl, raw, t, upgrades, out);
      }
    }
  }

  function checkHost(lbl, raw, t, upgrades, out) {
    const { host, wildcard } = hostOf(t);
    if (wildcard && (!host.includes('.') || MULTI_LABEL_SUFFIXES.has(host))) {
      out.add(Severity.MEDIUM, `${lbl}: wildcard over a whole top-level domain '${raw}'`, {
        sources: ['csp3-wildcard'],
        brief: `Scripts allowed from ${raw}`,
        description: `'${raw}' allows scripts from every domain under .${host}, including any the attacker registers.`,
        recommendation: `Replace '${raw}' with the specific hosts scripts come from.`,
      });
      return;
    }
    if (wildcard && BYPASS_BASES.has(host)) {
      out.add(Severity.MEDIUM, `${lbl}: known CSP bypass via wildcard '${raw}'`, {
        sources: ['cspe-bypass', 'csp3-wildcard'],
        brief: `Scripts allowed from bypassable hosts ${raw}`,
        description: `'${raw}' covers subdomains of ${host} that host JSONP endpoints or old AngularJS builds, either of which runs attacker-chosen code under this policy.`,
        recommendation: "Use a nonce with 'strict-dynamic' instead of allowlisting CDNs.",
      });
    } else if (wildcard && USER_CONTENT_BASES.has(host)) {
      out.add(Severity.MEDIUM, `${lbl}: wildcard over a domain anyone can publish on '${raw}'`, {
        sources: ['csp3-wildcard'],
        brief: `Scripts allowed from user-content hosts ${raw}`,
        description: `Anyone can create a site under ${host}, so '${raw}' lets an attacker host a script there and load it through an HTML injection.`,
        recommendation: `Name the exact subdomain of ${host} that serves your scripts.`,
      });
    } else if (!wildcard && BYPASS_HOSTS.has(host)) {
      out.add(Severity.MEDIUM, `${lbl}: known CSP bypass host '${host}'`, {
        sources: ['cspe-bypass'],
        brief: `Scripts allowed from bypassable host ${host}`,
        description: `${host} serves attacker-chosen code: a JSONP endpoint that runs any callback, or any version of any library (old AngularJS evaluates template expressions). Allowlisting it therefore lets an HTML injection run arbitrary script.`,
        recommendation: "Remove the host and allow its scripts with a nonce and 'strict-dynamic' instead.",
      });
    }
    if (t.startsWith('http://') && !upgrades) {
      out.add(Severity.LOW, `${lbl}: scripts allowed over plain HTTP from '${raw}'`, {
        sources: ['mixed-script', 'cspe-http'],
        brief: `Scripts allowed over plain HTTP from ${raw}`,
        description: 'On a page served over HTTPS, browsers block a plain-HTTP script as mixed content, so this source only fails to load. On a page served over plain HTTP the script can be replaced by anyone on the network path, and it runs with this page\'s privileges.',
        recommendation: `Use https:// for '${raw}', or add upgrade-insecure-requests.`,
      });
    }
  }

  function checkStyles(policy, out) {
    const elem = effective(policy, 'style-src-elem');
    const attr = effective(policy, 'style-src-attr');
    const leak = exfiltrationChannel(policy);
    if (elem) checkInline(label('style-src', elem), elem, 'style', out, leak);
    if (attr) checkInline(label('style-src', attr), attr, 'style', out, leak);
  }

  /**
   * The directive through which injected CSS can send what it reads to any
   * origin (a background image or a font), or null when both are restricted.
   * Missing, with no default-src to fall back on, counts as open.
   */
  function exfiltrationChannel(policy) {
    for (const name of ['img-src', 'font-src']) {
      const eff = effective(policy, name);
      if (!eff) return `${name} (not set, and no default-src)`;
      if (eff.lower.some(permissiveAncestor)) return eff.name === name ? name : `${name} (from ${eff.name})`;
    }
    return null;
  }

  const BROAD = new Set(['*', 'http:', 'https:']);

  function checkOthers(policy, out) {
    const object = effective(policy, 'object-src');
    if (!object) {
      out.add(Severity.LOW, 'Missing object-src directive', {
        sources: ['cspe-object', 'asvs-3.4.3', 'bp-csp'],
        brief: 'object-src is not set',
        description: 'With neither object-src nor default-src, <object> and <embed> can load content from anywhere, historically the easiest way around a CSP.',
        recommendation: "Add object-src 'none'.",
      }, true);
    } else if (object.lower.length > 0 && !(object.lower.length === 1 && object.lower[0] === "'none'")) {
      out.add(Severity.LOW, `Permissive object-src${object.name === 'object-src' ? '' : ' (from default-src)'}`, {
        sources: ['asvs-3.4.3', 'bp-csp'],
        brief: `object-src is not 'none'`,
        description: "Anything other than 'none' lets <object> and <embed> load content, and the content they load has been used to bypass CSP. No modern application needs plugins.",
        recommendation: "Set object-src 'none'.",
      });
    }

    const base = policy.directives.get('base-uri');
    if (!base) {
      out.add(baseCanRedirectTrusted(policy) ? Severity.MEDIUM : Severity.LOW, 'Missing base-uri directive', {
        sources: ['csp3-base', 'cspe-base-uri', 'asvs-3.4.3'],
        brief: 'base-uri is not set',
        description: 'base-uri does not fall back to default-src. Without it an injected <base href> redirects every relative script URL on the page to the attacker\'s server, which defeats a nonce-based policy, since the nonced <script> tag itself is legitimate.',
        recommendation: "Add base-uri 'none' (or 'self' if the page uses <base>).",
      }, true);
    } else if (base.lower.some((t) => BROAD.has(t) || t === 'data:')) {
      out.add(Severity.MEDIUM, 'Permissive base-uri', {
        sources: ['csp3-base', 'asvs-3.4.3'],
        brief: 'base-uri allows any URL',
        description: 'base-uri allows any URL as the document base, so an injected <base href> can point relative script URLs at the attacker\'s server.',
        recommendation: "Set base-uri 'none' or 'self'.",
      });
    }

    const ancestors = policy.directives.get('frame-ancestors');
    if (!ancestors) {
      out.add(Severity.LOW, 'Missing frame-ancestors directive', {
        sources: ['asvs-3.4.6', 'csp3-fa-nofallback', 'zap-10055-13'],
        brief: 'frame-ancestors is not set',
        description: 'frame-ancestors is the standard control for who may frame this page, and it takes precedence over X-Frame-Options in every browser that implements it. Without it, framing is decided by X-Frame-Options alone.',
        recommendation: "Add frame-ancestors 'none' (or 'self').",
      }, true);
    } else if (ancestors.lower.some(permissiveAncestor)) {
      out.add(Severity.MEDIUM, PERMISSIVE_FRAME_ANCESTORS, {
        sources: ['asvs-3.4.6', 'cs-xfo-fa'],
        brief: 'frame-ancestors allows any site',
        description: 'frame-ancestors allows any site to embed this page, so an attacker can frame it invisibly and trick the user into clicking it (clickjacking).',
        recommendation: "Set frame-ancestors 'none', 'self', or the exact origins that need to embed the page.",
      });
    }

    const def = policy.directives.get('default-src');
    if (!def) {
      out.add(Severity.LOW, 'Missing default-src directive', {
        sources: ['csp3-default', 'csp3-exfil', 'bp-csp'],
        brief: 'default-src is not set',
        description: 'Resource types without a directive of their own are unrestricted when default-src is absent: fonts, media, connections, frames and so on.',
        recommendation: "Add default-src 'none' (or 'self') as a baseline, then allow what each type needs.",
      }, true);
    } else if (def.lower.includes('*') || def.lower.includes('http:')) {
      out.add(Severity.LOW, 'Permissive default-src', {
        sources: ['csp3-default', 'bp-csp'],
        brief: 'default-src allows any origin',
        description: 'default-src applies to every resource type without its own directive, and this one allows any origin.',
        recommendation: "Use default-src 'none' or 'self' and add per-type directives.",
      });
    } else if (def.lower.includes('https:')) {
      out.add(Severity.LOW, "Permissive default-src 'https:'", {
        sources: ['csp3-default', 'bp-csp'],
        brief: 'default-src allows any HTTPS origin',
        description: "default-src applies to every resource type without its own directive, and 'https:' allows every HTTPS origin, including one the attacker owns.",
        recommendation: "Use default-src 'none' or 'self' and add per-type directives.",
      });
    }

    const form = policy.directives.get('form-action');
    if (!form) {
      out.add(Severity.LOW, 'Missing form-action directive', {
        sources: ['csp3-form', 'bp-csp', 'zap-10055-13'],
        brief: 'form-action is not set',
        description: 'form-action does not fall back to default-src. Without it an injected <form>, or an injected button that overrides an existing form\'s action, can send what the user types, password managers\' autofill included, to any URL.',
        recommendation: "Add form-action 'self' (or 'none' if the page has no forms).",
      }, true);
    } else if (form.lower.some((t) => BROAD.has(t))) {
      out.add(Severity.LOW, 'Permissive form-action', {
        sources: ['csp3-form', 'bp-csp'],
        brief: 'form-action allows any origin',
        description: 'form-action allows submissions to any origin, so an injected form can send what the user types anywhere.',
        recommendation: "Set form-action 'self' or the exact origins forms post to.",
      });
    }

    if (!policy.directives.has('upgrade-insecure-requests')) {
      out.add(Severity.LOW, 'Missing upgrade-insecure-requests', {
        sources: ['bp-csp'],
        brief: 'upgrade-insecure-requests is not set',
        description: 'upgrade-insecure-requests makes the browser fetch http:// subresources over HTTPS. It matters for pages that still reference http:// URLs.',
        recommendation: 'Consider adding upgrade-insecure-requests.',
      }, true);
    }
  }

  const PERMISSIVE_FRAME_ANCESTORS = 'Permissive frame-ancestors';

  /**
   * Whether an injected <base> can point trusted scripts elsewhere, as CSP
   * Evaluator judges it: a nonce trusts the element whatever its URL, and a
   * hash does so through 'strict-dynamic' (a hashed script loading a relative
   * URL). A hash alone pins the content, which a moved URL cannot change.
   */
  function baseCanRedirectTrusted(policy) {
    const scripts = effective(policy, 'script-src-elem');
    if (!scripts) return false;
    if (scripts.lower.some((t) => t.startsWith("'nonce-"))) return true;
    return scripts.lower.includes("'strict-dynamic'") && scripts.lower.some((t) => HASH.test(t));
  }

  function permissiveAncestor(t) {
    return BROAD.has(t) || (isHostSource(t) && hostOf(t).wildcard && !hostOf(t).host.includes('.'));
  }

  /** Whether an enforced policy restricts who may frame the page. */
  function restrictsFraming(value) {
    return value.split(',').some((p) => {
      const d = parsePolicy(p).directives.get('frame-ancestors');
      return !!d && !d.lower.some(permissiveAncestor);
    });
  }

  function evaluatePolicy(policy) {
    const out = new Collector();
    checkStructure(policy, out);
    checkScripts(policy, out);
    checkStyles(policy, out);
    checkOthers(policy, out);
    return out.list();
  }

  /**
   * Evaluate a CSP header value. A comma separates independent policies (the
   * wire form of the header sent twice), and a resource must pass every one, so
   * the effective policy is their intersection:
   *   - an absence ("Missing …") is reported only when no policy declares it;
   *   - any other finding is reported if any policy carries it. Cancelling a
   *     weakness would need an exact intersection of the source lists; reporting
   *     it may be conservative, but never hides a real one.
   */
  function evaluateCsp(value) {
    const parts = value.split(',').map((p) => p.trim()).filter((p) => p !== '');
    const policies = (parts.length ? parts : [value]).map(parsePolicy);
    const perPolicy = policies.map(evaluatePolicy);

    const absentEverywhere = perPolicy
      .map((fs) => new Set(fs.filter((f) => f.absence).map((f) => f.title)))
      .reduce((a, b) => new Set([...a].filter((t) => b.has(t))));

    const seen = new Set();
    const combined = [];
    for (const fs of perPolicy) {
      for (const f of fs) {
        if (f.absence && !absentEverywhere.has(f.title)) continue;
        if (seen.has(f.title)) continue;
        seen.add(f.title);
        combined.push({ ...f });    // spread drops the non-enumerable marker
      }
    }
    if (policies.length > 1) {
      combined.unshift(finding(H, Severity.OK, `${policies.length} policies are enforced together`, {
        sources: ['csp3-each', 'csp3-list'],
        status: Status.NONE,
        description: 'The value holds several comma-separated policies, which is what a browser sees when the header is sent more than once. Each is enforced on its own, so a resource must pass all of them, and a weakness in one is only cancelled where another restricts the same thing.',
      }));
    }
    return combined;
  }

  HL.csp = Object.freeze({
    evaluateCsp,
    restrictsFraming,
    PERMISSIVE_FRAME_ANCESTORS,
  });
})(globalThis.HeaderAnalyzer = globalThis.HeaderAnalyzer || {});
