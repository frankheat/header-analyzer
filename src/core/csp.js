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
globalThis.HeaderAnalyzer.i18n.module(function (HL, L) {
  'use strict';

  const { Severity, Status, finding, check } = HL.models;
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
    ['block-all-mixed-content', [L('Mixed content is blocked or upgraded by every current browser anyway; the directive is obsolete.', "Ogni browser attuale blocca o aggiorna comunque il contenuto misto; la direttiva è obsoleta."), ['mdn-bamc']]],
    ['prefetch-src', [L('Removed from the specification; browsers ignore it.', "Rimossa dalla specifica; i browser la ignorano."), ['mdn-prefetch', 'cspe-deprecated']]],
    ['navigate-to', [L('Removed from the specification and never shipped; browsers ignore it.', "Rimossa dalla specifica e mai rilasciata; i browser la ignorano."), ['csp3-registry']]],
    ['plugin-types', [L('Removed from the specification; browsers ignore it. Use object-src \'none\'.', "Rimossa dalla specifica; i browser la ignorano. Usare object-src 'none'."), ['cscsp-plugin-types']]],
    ['reflected-xss', [L('Never implemented outside an early draft; browsers ignore it.', "Mai implementata al di fuori di una prima bozza; i browser la ignorano."), ['cspe-deprecated']]],
    ['referrer', [L('Replaced by the Referrer-Policy header; browsers ignore it.', "Sostituita dall'header Referrer-Policy; i browser la ignorano."), ['cspe-deprecated']]],
    ['disown-opener', [L('Never shipped; browsers ignore it. Cross-Origin-Opener-Policy does this job.', "Mai rilasciata; i browser la ignorano. Questo compito lo svolge Cross-Origin-Opener-Policy."), ['cspe-deprecated']]],
    ['require-sri-for', [L('Never shipped in a stable browser; browsers ignore it.', "Mai rilasciata in un browser stabile; i browser la ignorano."), ['csp3-registry']]],
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
    return eff.name === 'default-src' ? L(`${family} (from default-src)`, `${family} (da default-src)`) : eff.name;
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
        out.add(Severity.LOW, L(`Unrecognised directive '${name}' is ignored`, `La direttiva non riconosciuta '${name}' viene ignorata`), {
          sources: ['csp3-registry', 'zap-10055-3'],
          brief: L(`Unknown directive ${name}`, `Direttiva sconosciuta ${name}`),
          description: L(`'${name}' is not a CSP directive, so browsers skip it and whatever it was written to restrict is not restricted.`, `'${name}' non è una direttiva CSP, quindi i browser la saltano e ciò che doveva restringere non è ristretto.`)
            + (guess ? L(` It looks like a misspelling of '${guess}'.`, ` Sembra un errore di battitura per '${guess}'.`) : ''),
          recommendation: guess ? L(`Rename it to '${guess}'.`, `Rinominarla in '${guess}'.`) : L(`Remove '${name}', or replace it with the directive that was meant.`, `Rimuovere '${name}', oppure sostituirla con la direttiva che si intendeva.`),
        });
      }
      for (const t of d.lower) {
        if (ALL_NAMES.has(t)) {
          out.add(Severity.LOW, L(`Possible missing semicolon: '${t}' inside '${name}'`, `Possibile punto e virgola mancante: '${t}' dentro '${name}'`), {
            sources: ['csp3-split', 'zap-10055-3'],
            brief: L(`Missing semicolon before ${t}`, `Punto e virgola mancante prima di ${t}`),
            description: L(`'${t}' is a directive name but appears as a source of '${name}', which usually means a ';' is missing. A browser reads it as a host called '${t}', and the directive that was meant is not in the policy at all.`, `'${t}' è il nome di una direttiva ma compare come sorgente di '${name}', il che di solito significa che manca un ';'. Il browser lo legge come un host chiamato '${t}', e la direttiva che si intendeva non è affatto nella policy.`),
            recommendation: L(`Separate '${name}' and '${t}' with a semicolon.`, `Separare '${name}' e '${t}' con un punto e virgola.`),
          });
        } else if (UNQUOTED_KEYWORDS.has(t)) {
          out.add(Severity.LOW, L(`Keyword '${t}' in '${name}' is missing its single quotes`, `Alla keyword '${t}' in '${name}' mancano gli apici singoli`), {
            sources: ['csp3-keywords', 'zap-10055-3'],
            brief: L(`Unquoted keyword ${t} in ${name}`, `Keyword ${t} senza apici in ${name}`),
            description: L(`Without single quotes '${t}' is a host name, not a keyword, so the policy does not do what it says: the keyword's effect is not applied, and a host called '${t}' is allowed instead.`, `Senza apici singoli '${t}' è un nome di host, non una keyword, quindi la policy non fa ciò che dice: l'effetto della keyword non viene applicato, e viene invece consentito un host chiamato '${t}'.`),
            recommendation: L(`Write it as '${"'"}${t}${"'"}'.`, `Scriverla come '${"'"}${t}${"'"}'.`),
          });
        } else if (UNQUOTED_NONCE_HASH.test(t)) {
          out.add(Severity.LOW, L(`Nonce or hash in '${name}' is missing its single quotes`, `Al nonce o all'hash in '${name}' mancano gli apici singoli`), {
            sources: ['csp3-nonce-grammar', 'zap-10055-3'],
            brief: L(`Unquoted nonce or hash in ${name}`, `Nonce o hash senza apici in ${name}`),
            description: L(`'${t}' without single quotes is read as a host name, so the scripts or styles it was meant to allow are blocked.`, `'${t}' senza apici singoli viene letto come nome di host, quindi gli script o gli stili che doveva consentire sono bloccati.`),
            recommendation: L(`Write it as '${"'"}${d.tokens[d.lower.indexOf(t)]}${"'"}'.`, `Scriverlo come '${"'"}${d.tokens[d.lower.indexOf(t)]}${"'"}'.`),
          });
        } else if (t.startsWith("'") && !KEYWORDS.has(t) && !NONCE.test(t) && !HASH.test(t)) {
          out.add(Severity.LOW, L(`Unrecognised source expression ${t} in '${name}' is ignored`, `L'espressione sorgente non riconosciuta ${t} in '${name}' viene ignorata`), {
            sources: ['csp3-keywords', 'zap-10055-3'],
            brief: L(`Invalid source ${t} in ${name}`, `Sorgente non valida ${t} in ${name}`),
            description: L(`${t} is quoted like a keyword but is not one, nor a valid nonce or hash, so browsers skip it.`, `${t} è tra apici come una keyword ma non lo è, né è un nonce o un hash valido, quindi i browser la saltano.`),
            recommendation: L('Check the spelling against the keywords CSP defines.', "Controllare l'ortografia rispetto alle keyword definite dalla CSP."),
          });
        }
      }
      if (d.lower.includes("'none'") && d.lower.length > 1) {
        out.add(Severity.LOW, L(`'none' in '${name}' is combined with other sources`, `'none' in '${name}' è combinato con altre sorgenti`), {
          sources: ['csp3-none'],
          brief: L(`'none' combined with other sources in ${name}`, `'none' combinato con altre sorgenti in ${name}`),
          description: L(`'none' only means "nothing" when it is the only source. Next to other sources it is ignored, and the directive allows exactly what the other sources allow.`, `'none' significa "nulla" solo quando è l'unica sorgente. Accanto ad altre sorgenti viene ignorato, e la direttiva consente esattamente ciò che consentono le altre sorgenti.`),
          recommendation: L(`Remove 'none' from '${name}', or remove the other sources.`, `Rimuovere 'none' da '${name}', oppure rimuovere le altre sorgenti.`),
        });
      }
    }
    for (const dup of policy.duplicates) {
      out.add(Severity.LOW, L(`Directive '${dup.name}' appears more than once; only the first is applied`, `La direttiva '${dup.name}' compare più di una volta; viene applicata solo la prima`), {
        sources: ['csp3-dup', 'zap-10055-3'],
        brief: L(`${dup.name} is declared twice; only the first applies`, `${dup.name} è dichiarata due volte; vale solo la prima`),
        description: L(`CSP3 §2.2.1 skips a directive whose name has already been seen, so '${(dup.name + ' ' + dup.value).trim()}' is ignored. If it was added to tighten the policy, it does not.`, `CSP3 §2.2.1 salta una direttiva il cui nome è già stato visto, quindi '${(dup.name + ' ' + dup.value).trim()}' viene ignorata. Se era stata aggiunta per restringere la policy, non lo fa.`),
        recommendation: L(`Merge the two '${dup.name}' directives into one.`, `Unire le due direttive '${dup.name}' in una sola.`),
      });
    }
    for (const name of policy.nonAscii) {
      out.add(Severity.LOW, L(`Directive '${name}' contains non-ASCII characters and is ignored`, `La direttiva '${name}' contiene caratteri non ASCII e viene ignorata`), {
        sources: ['csp3-ascii'],
        brief: L(`Non-ASCII characters in ${name}`, `Caratteri non ASCII in ${name}`),
        description: L('CSP3 §2.2.1 skips any directive that is not pure ASCII: often the result of a curly quote or a non-breaking space pasted from a document.', "CSP3 §2.2.1 salta qualsiasi direttiva che non sia puro ASCII: spesso è l'effetto di un apice tipografico o di uno spazio non separabile incollati da un documento."),
        recommendation: L('Retype the directive with plain ASCII quotes and spaces.', "Riscrivere la direttiva con apici e spazi ASCII semplici."),
      });
    }
    for (const [name, [why, refs]] of RETIRED) {
      if (policy.directives.has(name)) {
        out.add(Severity.LOW, L(`Obsolete CSP directive: ${name}`, `Direttiva CSP obsoleta: ${name}`), {
          status: Status.DEPRECATED, brief: L(`Obsolete directive ${name}`, `Direttiva obsoleta ${name}`),
          description: why,
          sources: refs,
          recommendation: L(`Remove '${name}'.`, `Rimuovere '${name}'.`),
        });
      }
    }
  }

  function checkScripts(policy, out) {
    if (!policy.directives.has('script-src') && !policy.directives.has('default-src')
        && !policy.directives.has('script-src-elem')) {
      out.add(Severity.MEDIUM, L('Missing script-src and default-src', "script-src e default-src mancanti"), {
        sources: ['cspe-script', 'csp3-default'],
        brief: L('Scripts are not restricted', "Gli script non sono ristretti"),
        description: L('With neither directive, the policy places no restriction on which scripts run, so it offers no protection against XSS.', "Senza nessuna delle due direttive, la policy non pone alcun limite agli script eseguibili, quindi non offre protezione contro l'XSS."),
        recommendation: L("Add script-src with a per-response nonce and 'strict-dynamic', or at minimum default-src 'self'.", "Aggiungere script-src con un nonce per risposta e 'strict-dynamic', o almeno default-src 'self'."),
      }, true);
    }

    const elem = effective(policy, 'script-src-elem');
    const attr = effective(policy, 'script-src-attr');
    const evalList = effective(policy, 'script-src');
    const upgrades = policy.directives.has('upgrade-insecure-requests');

    if (elem) checkScriptElements(label('script-src', elem), elem, upgrades, out);
    if (attr) checkInline(label('script-src', attr), attr, 'script', out);
    if (evalList && evalList.lower.includes("'unsafe-eval'")) {
      out.add(Severity.MEDIUM, L(`${label('script-src', evalList)}: 'unsafe-eval'`, `${label('script-src', evalList)}: 'unsafe-eval'`), {
        sources: ['zap-10055-10', 'obs-csp-eval'],
        brief: L(`'unsafe-eval' allowed for scripts in ${evalList.name}`, `'unsafe-eval' consentito per gli script in ${evalList.name}`),
        description: L("Lets script turn strings into code with eval(), new Function(), setTimeout(string) and similar APIs, so an injection into any string that reaches them becomes code execution. 'strict-dynamic' does not switch it off.", "Permette agli script di trasformare stringhe in codice con eval(), new Function(), setTimeout(stringa) e API simili, quindi un'iniezione in una qualsiasi stringa che arriva lì diventa esecuzione di codice. 'strict-dynamic' non lo disattiva."),
        recommendation: L("Remove 'unsafe-eval' and refactor the code that needs it. If only WebAssembly needs it, 'wasm-unsafe-eval' is the narrow replacement.", "Rimuovere 'unsafe-eval' e riscrivere il codice che ne ha bisogno. Se serve solo a WebAssembly, 'wasm-unsafe-eval' è il sostituto più ristretto."),
      });
    }
  }

  function checkInline(lbl, eff, kind, out, leak) {
    const st = inlineState(eff.lower);
    if (!st.unsafeInline) return;
    const disabled = st.hasNonce || st.hasHash || (kind === 'script' && st.strictDynamic);
    if (disabled) {
      out.add(Severity.OK, L(`${lbl}: 'unsafe-inline' is a fallback for old browsers`, `${lbl}: 'unsafe-inline' è un fallback per i browser vecchi`), {
        sources: ['csp3-inline-nonce', 'csp3-inline-sd', 'strictcsp-fallback'],
        status: Status.NONE,
        description: L(`A ${st.hasNonce ? 'nonce' : st.hasHash ? 'hash' : "'strict-dynamic'"} in the same list switches 'unsafe-inline' off in every browser that supports CSP Level 2 or later (CSP3 §6.7.3.2). It only takes effect in browsers too old to understand the rest of the list: the documented backwards-compatible pattern.`, `Un ${st.hasNonce ? 'nonce' : st.hasHash ? 'hash' : "'strict-dynamic'"} nello stesso elenco disattiva 'unsafe-inline' in ogni browser che supporta CSP Level 2 o successive (CSP3 §6.7.3.2). Ha effetto solo nei browser troppo vecchi per capire il resto dell'elenco: è lo schema documentato di retrocompatibilità.`),
      });
      return;
    }
    if (kind === 'script') {
      out.add(Severity.MEDIUM, L(`${lbl}: 'unsafe-inline'`, `${lbl}: 'unsafe-inline'`), {
        brief: L(`'unsafe-inline' allowed for scripts in ${eff.name}`, `'unsafe-inline' consentito per gli script in ${eff.name}`),
        description: L('Any inline <script> block and any event-handler attribute runs, so an HTML injection anywhere on the page is code execution. This removes most of what a CSP protects against.', "Qualsiasi blocco <script> inline e qualsiasi attributo event handler viene eseguito, quindi un'iniezione HTML in qualsiasi punto della pagina diventa esecuzione di codice. Questo toglie la maggior parte di ciò da cui una CSP protegge."),
        sources: ['zap-10055-5', 'obs-csp-inline'],
        recommendation: L("Remove 'unsafe-inline' and allow the scripts you need with a per-response nonce or a hash, plus 'strict-dynamic'.", "Rimuovere 'unsafe-inline' e consentire gli script necessari con un nonce per risposta o un hash, più 'strict-dynamic'."),
      });
    } else if (leak) {
      out.add(Severity.MEDIUM, L(`${lbl}: 'unsafe-inline'`, `${lbl}: 'unsafe-inline'`), {
        sources: ['ps-css-csp', 'ps-css-attr', 'csp3-exfil', 'zap-10055-6'],
        brief: L(`Inline styles allowed and ${leak.split(' ')[0]} reaches any origin`, `Stili inline consentiti e ${leak.split(' ')[0]} raggiunge qualsiasi origine`),
        description: L(`Any inline style block or style attribute is applied, so an HTML injection can run CSS even where script is blocked. Attribute selectors read values out of the page character by character (CSRF tokens, prefilled form fields, hidden inputs), and each match loads a background image or a font from the attacker's server, which ${leak} allows. The injection becomes theft of those values without a line of script.`, `Qualsiasi blocco di stile inline o attributo style viene applicato, quindi un'iniezione HTML può eseguire CSS anche dove gli script sono bloccati. I selettori di attributo leggono i valori della pagina un carattere alla volta (token CSRF, campi precompilati, input nascosti), e ogni corrispondenza carica un'immagine di sfondo o un font dal server dell'attaccante, cosa che ${leak} consente. L'iniezione diventa furto di quei valori senza una riga di script.`),
        recommendation: L(`Allow inline styles with a nonce or a hash, or move them into stylesheets. Restricting ${leak.split(' ')[0]} (default-src 'self' does it) closes the channel even before that.`, `Consentire gli stili inline con un nonce o un hash, oppure spostarli in fogli di stile. Restringere ${leak.split(' ')[0]} (lo fa default-src 'self') chiude il canale già prima.`),
      });
    } else {
      out.add(Severity.LOW, L(`${lbl}: 'unsafe-inline'`, `${lbl}: 'unsafe-inline'`), {
        brief: L(`'unsafe-inline' allowed for styles in ${eff.name}`, `'unsafe-inline' consentito per gli stili in ${eff.name}`),
        description: L('Any inline style block or style attribute is applied, so an HTML injection can restyle the page: hiding content or overlaying a fake message on the real site. Reading values out of the page with CSS would need a background image or a font from another origin, and this policy\'s img-src and font-src do not allow one.', "Qualsiasi blocco di stile inline o attributo style viene applicato, quindi un'iniezione HTML può modificare l'aspetto della pagina: nascondere contenuti o sovrapporre un messaggio falso al sito vero. Leggere valori della pagina con il CSS richiederebbe un'immagine di sfondo o un font da un'altra origine, e img-src e font-src di questa policy non lo consentono."),
        sources: ['zap-10055-6', 'obs-csp-style', 'ps-css-attr', 'csp3-exfil'],
        recommendation: L('Allow inline styles with a nonce or a hash, or move them into stylesheets.', "Consentire gli stili inline con un nonce o un hash, oppure spostarli in fogli di stile."),
      });
    }
  }

  function checkScriptElements(lbl, eff, upgrades, out) {
    const st = inlineState(eff.lower);
    checkInline(lbl, eff, 'script', out);

    if (st.strictDynamic && !st.hasNonce && !st.hasHash) {
      out.add(Severity.OK, L(`${lbl}: 'strict-dynamic' without a nonce or hash blocks every script`, `${lbl}: 'strict-dynamic' senza nonce né hash blocca ogni script`), {
        sources: ['csp3-sd-ignores'],
        status: Status.NONE,
        description: L("'strict-dynamic' switches off the allowlist and 'unsafe-inline', and trusts only scripts already trusted through a nonce or a hash. With neither, no script can run. That is not a weakness, but it is probably not what was meant.", "'strict-dynamic' disattiva l'allowlist e 'unsafe-inline', e si fida solo degli script già autorizzati tramite un nonce o un hash. Senza nessuno dei due, nessuno script può essere eseguito. Non è una debolezza, ma probabilmente non è ciò che si intendeva."),
        recommendation: L("Add a per-response 'nonce-…' (or the hashes of the inline scripts) to the same list.", "Aggiungere allo stesso elenco un 'nonce-…' per risposta (o gli hash degli script inline)."),
      });
    }

    if (eff.lower.includes("'unsafe-hashes'")) {
      if (st.hasHash) {
        out.add(Severity.LOW, L(`${lbl}: 'unsafe-hashes'`, `${lbl}: 'unsafe-hashes'`), {
          sources: ['csp3-unsafe-hashes', 'zap-10055-7'],
          brief: L(`'unsafe-hashes' allowed in ${eff.name}`, `'unsafe-hashes' consentito in ${eff.name}`),
          description: L("Lets event-handler attributes and javascript: URLs run when their text matches a hash. An attacker who can inject markup can reuse any allowed handler on an element of their choosing.", "Permette l'esecuzione degli attributi event handler e degli URL javascript: quando il loro testo corrisponde a un hash. Un attaccante che può iniettare markup può riusare qualsiasi handler consentito su un elemento a sua scelta."),
          recommendation: L('Replace inline event handlers with addEventListener, then remove it.', "Sostituire gli event handler inline con addEventListener, poi rimuoverlo."),
        });
      } else {
        out.add(Severity.OK, L(`${lbl}: 'unsafe-hashes' has no effect without a hash`, `${lbl}: 'unsafe-hashes' non ha effetto senza un hash`), {
          sources: ['csp3-unsafe-hashes'],
          status: Status.NONE,
          description: L("'unsafe-hashes' only widens what hashes match; with no hash in the list it allows nothing.", "'unsafe-hashes' allarga solo ciò che gli hash riconoscono; senza un hash nell'elenco non consente nulla."),
          recommendation: L("Remove 'unsafe-hashes'.", "Rimuovere 'unsafe-hashes'."),
        });
      }
    }

    for (const t of eff.lower) {
      const m = NONCE.exec(t);
      if (m && m[1].replace(/=+$/, '').length < 22) {
        out.add(Severity.LOW, L(`${lbl}: nonce is shorter than 128 bits`, `${lbl}: il nonce è più corto di 128 bit`), {
          sources: ['csp3-nonce-128'],
          brief: L('Nonce shorter than 128 bits', "Nonce più corto di 128 bit"),
          description: L(`The nonce '${m[1]}' has ${m[1].replace(/=+$/, '').length} characters. CSP3 asks for at least 128 bits of cryptographically random data, which is 22 base64 characters; a short one can be guessed.`, `Il nonce '${m[1]}' ha ${m[1].replace(/=+$/, '').length} caratteri. CSP3 chiede almeno 128 bit di dati casuali crittograficamente sicuri, cioè 22 caratteri base64; uno corto può essere indovinato.`),
          recommendation: L('Generate at least 16 random bytes per response and base64-encode them.', "Generare almeno 16 byte casuali per risposta e codificarli in base64."),
        });
      }
    }
    if (st.hasNonce) {
      out.add(Severity.OK, L(`${lbl}: the nonce must change on every response`, `${lbl}: il nonce deve cambiare a ogni risposta`), {
        sources: ['csp3-nonce-unique'],
        status: Status.NONE,
        description: L('A nonce works only if an attacker cannot know it in advance. One that is fixed, cached with the page, or reused across responses can be copied straight into an injected <script nonce=…>, and the policy then allows the injection: no better than \'unsafe-inline\'. One saved response cannot show which it is.', "Un nonce funziona solo se un attaccante non può conoscerlo in anticipo. Uno fisso, salvato in cache con la pagina o riusato tra le risposte può essere copiato direttamente in un <script nonce=…> iniettato, e la policy allora consente l'iniezione: non meglio di 'unsafe-inline'. Una sola risposta salvata non può mostrare quale sia il caso."),
        ...check(L('Request the same URL twice (with any cache bypassed) and compare the nonce values.', "Richiedere lo stesso URL due volte (aggirando qualsiasi cache) e confrontare i valori del nonce."), L('they are the same', "sono uguali"), L('they differ', "sono diversi")),
      });
    }

    if (st.strictDynamic && (st.hasNonce || st.hasHash)) {
      const ignored = eff.tokens.filter((t, k) => {
        const l = eff.lower[k];
        return l === "'self'" || l === '*' || SCHEME_SOURCE.test(l) || isHostSource(l);
      });
      if (ignored.length) {
        out.add(Severity.OK, L(`${lbl}: allowlist entries are ignored under 'strict-dynamic'`, `${lbl}: le voci dell'allowlist vengono ignorate con 'strict-dynamic'`), {
          sources: ['csp3-sd-ignores', 'strictcsp-https'],
          status: Status.NONE,
          description: L(`With 'strict-dynamic' and a ${st.hasNonce ? 'nonce' : 'hash'}, browsers that support CSP3 ignore ${ignored.join(' ')}: only scripts trusted through the ${st.hasNonce ? 'nonce' : 'hash'}, and the scripts those load, can run. The entries only matter to older browsers, which is how Google's recommended strict policy keeps them working.`, `Con 'strict-dynamic' e un ${st.hasNonce ? 'nonce' : 'hash'}, i browser che supportano CSP3 ignorano ${ignored.join(' ')}: possono essere eseguiti solo gli script autorizzati tramite il ${st.hasNonce ? 'nonce' : 'hash'}, e gli script che questi caricano. Le voci contano solo per i browser più vecchi, ed è così che la strict policy raccomandata da Google li mantiene funzionanti.`),
        });
      }
      return;
    }

    for (let k = 0; k < eff.lower.length; k++) {
      const t = eff.lower[k];
      const raw = eff.tokens[k];
      if (t === '*' || t === 'http:') {
        out.add(Severity.MEDIUM, L(`${lbl}: overly broad source '${raw}'`, `${lbl}: sorgente troppo ampia '${raw}'`), {
          sources: ['cspe-wildcard', 'cspe-schemes', 'zap-10055-4'],
          brief: L(`Scripts allowed from ${raw}`, `Script consentiti da ${raw}`),
          description: L(`'${raw}' allows scripts from any ${t === '*' ? 'web' : 'plain-HTTP'} origin, including one the attacker owns, so an HTML injection can load arbitrary script.`, `'${raw}' consente script da qualsiasi origine ${t === '*' ? 'web' : 'in HTTP in chiaro'}, inclusa una dell'attaccante, quindi un'iniezione HTML può caricare script arbitrari.`),
          recommendation: L("Replace it with a nonce and 'strict-dynamic', or with the exact origins scripts come from.", "Sostituirla con un nonce e 'strict-dynamic', oppure con le origini esatte da cui provengono gli script."),
        });
      } else if (t === 'https:') {
        out.add(Severity.MEDIUM, L(`${lbl}: overly broad source 'https:'`, `${lbl}: sorgente troppo ampia 'https:'`), {
          sources: ['cspe-schemes'],
          brief: L('Scripts allowed from any HTTPS origin', "Script consentiti da qualsiasi origine HTTPS"),
          description: L("'https:' allows scripts from every HTTPS origin, including one the attacker registers for a few euros.", "'https:' consente script da ogni origine HTTPS, inclusa una che l'attaccante registra con pochi euro."),
          recommendation: L("Replace it with a nonce and 'strict-dynamic', or with the exact origins scripts come from.", "Sostituirla con un nonce e 'strict-dynamic', oppure con le origini esatte da cui provengono gli script."),
        });
      } else if (t === 'data:') {
        out.add(Severity.MEDIUM, L(`${lbl}: 'data:' URI scheme`, `${lbl}: schema URI 'data:'`), {
          sources: ['cspe-schemes'],
          brief: L('Scripts allowed from data: URIs', "Script consentiti da URI data:"),
          description: L("An injected <script src=\"data:text/javascript,…\"> carries its own code, so 'data:' is as good as 'unsafe-inline' to an attacker.", "Uno <script src=\"data:text/javascript,…\"> iniettato porta con sé il proprio codice, quindi per un attaccante 'data:' equivale a 'unsafe-inline'."),
          recommendation: L("Remove 'data:'.", "Rimuovere 'data:'."),
        });
      } else if (t === 'blob:' || t === 'filesystem:') {
        out.add(Severity.LOW, L(`${lbl}: '${t}' URI scheme`, `${lbl}: schema URI '${t}'`), {
          sources: ['csp3-schemes'],
          brief: L(`Scripts allowed from ${t} URIs`, `Script consentiti da URI ${t}`),
          description: L(`Script that can create a ${t.slice(0, -1)} URL, or an injection that can reach code that does, can run arbitrary code through it.`, `Uno script che può creare un URL ${t.slice(0, -1)}, o un'iniezione che può raggiungere codice che lo fa, può eseguire codice arbitrario attraverso di esso.`),
          recommendation: L(`Remove '${t}' unless the application really loads scripts from it.`, `Rimuovere '${t}' a meno che l'applicazione non carichi davvero script da lì.`),
        });
      } else if (isHostSource(t)) {
        checkHost(lbl, raw, t, upgrades, out);
      }
    }
  }

  function checkHost(lbl, raw, t, upgrades, out) {
    const { host, wildcard } = hostOf(t);
    if (wildcard && (!host.includes('.') || MULTI_LABEL_SUFFIXES.has(host))) {
      out.add(Severity.MEDIUM, L(`${lbl}: wildcard over a whole top-level domain '${raw}'`, `${lbl}: wildcard su un intero dominio di primo livello '${raw}'`), {
        sources: ['csp3-wildcard'],
        brief: L(`Scripts allowed from ${raw}`, `Script consentiti da ${raw}`),
        description: L(`'${raw}' allows scripts from every domain under .${host}, including any the attacker registers.`, `'${raw}' consente script da ogni dominio sotto .${host}, inclusi quelli che l'attaccante registra.`),
        recommendation: L(`Replace '${raw}' with the specific hosts scripts come from.`, `Sostituire '${raw}' con gli host specifici da cui provengono gli script.`),
      });
      return;
    }
    if (wildcard && BYPASS_BASES.has(host)) {
      out.add(Severity.MEDIUM, L(`${lbl}: known CSP bypass via wildcard '${raw}'`, `${lbl}: bypass CSP noto tramite wildcard '${raw}'`), {
        sources: ['cspe-bypass', 'csp3-wildcard'],
        brief: L(`Scripts allowed from bypassable hosts ${raw}`, `Script consentiti da host aggirabili ${raw}`),
        description: L(`'${raw}' covers subdomains of ${host} that host JSONP endpoints or old AngularJS builds, either of which runs attacker-chosen code under this policy.`, `'${raw}' copre sottodomini di ${host} che ospitano endpoint JSONP o vecchie versioni di AngularJS, e ognuno dei due esegue codice scelto dall'attaccante con questa policy.`),
        recommendation: L("Use a nonce with 'strict-dynamic' instead of allowlisting CDNs.", "Usare un nonce con 'strict-dynamic' invece di autorizzare le CDN."),
      });
    } else if (wildcard && USER_CONTENT_BASES.has(host)) {
      out.add(Severity.MEDIUM, L(`${lbl}: wildcard over a domain anyone can publish on '${raw}'`, `${lbl}: wildcard su un dominio su cui chiunque può pubblicare '${raw}'`), {
        sources: ['csp3-wildcard'],
        brief: L(`Scripts allowed from user-content hosts ${raw}`, `Script consentiti da host di contenuti degli utenti ${raw}`),
        description: L(`Anyone can create a site under ${host}, so '${raw}' lets an attacker host a script there and load it through an HTML injection.`, `Chiunque può creare un sito sotto ${host}, quindi '${raw}' permette a un attaccante di ospitarvi uno script e caricarlo tramite un'iniezione HTML.`),
        recommendation: L(`Name the exact subdomain of ${host} that serves your scripts.`, `Indicare il sottodominio esatto di ${host} che serve i vostri script.`),
      });
    } else if (!wildcard && BYPASS_HOSTS.has(host)) {
      out.add(Severity.MEDIUM, L(`${lbl}: known CSP bypass host '${host}'`, `${lbl}: host noto per aggirare la CSP '${host}'`), {
        sources: ['cspe-bypass'],
        brief: L(`Scripts allowed from bypassable host ${host}`, `Script consentiti dall'host aggirabile ${host}`),
        description: L(`${host} serves attacker-chosen code: a JSONP endpoint that runs any callback, or any version of any library (old AngularJS evaluates template expressions). Allowlisting it therefore lets an HTML injection run arbitrary script.`, `${host} serve codice scelto dall'attaccante: un endpoint JSONP che esegue qualsiasi callback, oppure qualsiasi versione di qualsiasi libreria (il vecchio AngularJS valuta le espressioni nei template). Autorizzarlo permette quindi a un'iniezione HTML di eseguire script arbitrari.`),
        recommendation: L("Remove the host and allow its scripts with a nonce and 'strict-dynamic' instead.", "Rimuovere l'host e consentire i suoi script con un nonce e 'strict-dynamic'."),
      });
    }
    if (t.startsWith('http://') && !upgrades) {
      out.add(Severity.LOW, L(`${lbl}: scripts allowed over plain HTTP from '${raw}'`, `${lbl}: script consentiti in HTTP in chiaro da '${raw}'`), {
        sources: ['mixed-script', 'cspe-http'],
        brief: L(`Scripts allowed over plain HTTP from ${raw}`, `Script consentiti in HTTP in chiaro da ${raw}`),
        description: L('On a page served over HTTPS, browsers block a plain-HTTP script as mixed content, so this source only fails to load. On a page served over plain HTTP the script can be replaced by anyone on the network path, and it runs with this page\'s privileges.', "Su una pagina servita in HTTPS, i browser bloccano uno script in HTTP in chiaro come contenuto misto, quindi questa sorgente semplicemente non si carica. Su una pagina servita in HTTP in chiaro lo script può essere sostituito da chiunque sia sul percorso di rete, e viene eseguito con i privilegi di questa pagina."),
        recommendation: L(`Use https:// for '${raw}', or add upgrade-insecure-requests.`, `Usare https:// per '${raw}', oppure aggiungere upgrade-insecure-requests.`),
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
      if (!eff) return L(`${name} (not set, and no default-src)`, `${name} (non impostata, e nessun default-src)`);
      if (eff.lower.some(permissiveAncestor)) return eff.name === name ? name : L(`${name} (from ${eff.name})`, `${name} (da ${eff.name})`);
    }
    return null;
  }

  const BROAD = new Set(['*', 'http:', 'https:']);

  function checkOthers(policy, out) {
    const object = effective(policy, 'object-src');
    if (!object) {
      out.add(Severity.LOW, L('Missing object-src directive', "Direttiva object-src mancante"), {
        sources: ['cspe-object', 'asvs-3.4.3', 'bp-csp'],
        brief: L('object-src is not set', "object-src non è impostata"),
        description: L('With neither object-src nor default-src, <object> and <embed> can load content from anywhere, historically the easiest way around a CSP.', "Senza object-src né default-src, <object> e <embed> possono caricare contenuti da qualsiasi origine: storicamente il modo più facile per aggirare una CSP."),
        recommendation: L("Add object-src 'none'.", "Aggiungere object-src 'none'."),
      }, true);
    } else if (object.lower.length > 0 && !(object.lower.length === 1 && object.lower[0] === "'none'")) {
      out.add(Severity.LOW, L(`Permissive object-src${object.name === 'object-src' ? '' : ' (from default-src)'}`, `object-src permissiva${object.name === 'object-src' ? '' : ' (da default-src)'}`), {
        sources: ['asvs-3.4.3', 'bp-csp'],
        brief: L(`object-src is not 'none'`, `object-src non è 'none'`),
        description: L("Anything other than 'none' lets <object> and <embed> load content, and the content they load has been used to bypass CSP. No modern application needs plugins.", "Qualsiasi valore diverso da 'none' permette a <object> e <embed> di caricare contenuti, e quei contenuti sono stati usati per aggirare la CSP. Nessuna applicazione moderna ha bisogno di plugin."),
        recommendation: L("Set object-src 'none'.", "Impostare object-src 'none'."),
      });
    }

    const base = policy.directives.get('base-uri');
    if (!base) {
      out.add(baseCanRedirectTrusted(policy) ? Severity.MEDIUM : Severity.LOW, L('Missing base-uri directive', "Direttiva base-uri mancante"), {
        sources: ['csp3-base', 'cspe-base-uri', 'asvs-3.4.3'],
        brief: L('base-uri is not set', "base-uri non è impostata"),
        description: L('base-uri does not fall back to default-src. Without it an injected <base href> redirects every relative script URL on the page to the attacker\'s server, which defeats a nonce-based policy, since the nonced <script> tag itself is legitimate.', "base-uri non ricade su default-src. Senza di essa un <base href> iniettato reindirizza ogni URL relativo degli script della pagina verso il server dell'attaccante, e questo vanifica una policy basata su nonce, perché il tag <script> con il nonce è legittimo."),
        recommendation: L("Add base-uri 'none' (or 'self' if the page uses <base>).", "Aggiungere base-uri 'none' (o 'self' se la pagina usa <base>)."),
      }, true);
    } else if (base.lower.some((t) => BROAD.has(t) || t === 'data:')) {
      out.add(Severity.MEDIUM, L('Permissive base-uri', "base-uri permissiva"), {
        sources: ['csp3-base', 'asvs-3.4.3'],
        brief: L('base-uri allows any URL', "base-uri consente qualsiasi URL"),
        description: L('base-uri allows any URL as the document base, so an injected <base href> can point relative script URLs at the attacker\'s server.', "base-uri consente qualsiasi URL come base del documento, quindi un <base href> iniettato può puntare gli URL relativi degli script verso il server dell'attaccante."),
        recommendation: L("Set base-uri 'none' or 'self'.", "Impostare base-uri 'none' o 'self'."),
      });
    }

    const ancestors = policy.directives.get('frame-ancestors');
    if (!ancestors) {
      out.add(Severity.LOW, L('Missing frame-ancestors directive', "Direttiva frame-ancestors mancante"), {
        sources: ['asvs-3.4.6', 'csp3-fa-nofallback', 'zap-10055-13'],
        brief: L('frame-ancestors is not set', "frame-ancestors non è impostata"),
        description: L('frame-ancestors is the standard control for who may frame this page, and it takes precedence over X-Frame-Options in every browser that implements it. Without it, framing is decided by X-Frame-Options alone.', "frame-ancestors è il controllo standard su chi può incorniciare questa pagina, e prevale su X-Frame-Options in ogni browser che lo implementa. Senza di essa, il framing è deciso solo da X-Frame-Options."),
        recommendation: L("Add frame-ancestors 'none' (or 'self').", "Aggiungere frame-ancestors 'none' (o 'self')."),
      }, true);
    } else if (ancestors.lower.some(permissiveAncestor)) {
      out.add(Severity.MEDIUM, PERMISSIVE_FRAME_ANCESTORS, {
        sources: ['asvs-3.4.6', 'cs-xfo-fa'],
        brief: L('frame-ancestors allows any site', "frame-ancestors consente qualsiasi sito"),
        description: L('frame-ancestors allows any site to embed this page, so an attacker can frame it invisibly and trick the user into clicking it (clickjacking).', "frame-ancestors consente a qualsiasi sito di incorporare questa pagina, quindi un attaccante può incorniciarla in modo invisibile e indurre l'utente a cliccarci (clickjacking)."),
        recommendation: L("Set frame-ancestors 'none', 'self', or the exact origins that need to embed the page.", "Impostare frame-ancestors 'none', 'self', o le origini esatte che devono incorporare la pagina."),
      });
    }

    const def = policy.directives.get('default-src');
    if (!def) {
      out.add(Severity.LOW, L('Missing default-src directive', "Direttiva default-src mancante"), {
        sources: ['csp3-default', 'csp3-exfil', 'bp-csp'],
        brief: L('default-src is not set', "default-src non è impostata"),
        description: L('Resource types without a directive of their own are unrestricted when default-src is absent: fonts, media, connections, frames and so on.', "Senza default-src, i tipi di risorsa che non hanno una direttiva propria non sono ristretti: font, media, connessioni, frame e così via."),
        recommendation: L("Add default-src 'none' (or 'self') as a baseline, then allow what each type needs.", "Aggiungere default-src 'none' (o 'self') come base, poi consentire ciò che serve a ogni tipo."),
      }, true);
    } else if (def.lower.includes('*') || def.lower.includes('http:')) {
      out.add(Severity.LOW, L('Permissive default-src', "default-src permissiva"), {
        sources: ['csp3-default', 'bp-csp'],
        brief: L('default-src allows any origin', "default-src consente qualsiasi origine"),
        description: L('default-src applies to every resource type without its own directive, and this one allows any origin.', "default-src si applica a ogni tipo di risorsa senza una direttiva propria, e questa consente qualsiasi origine."),
        recommendation: L("Use default-src 'none' or 'self' and add per-type directives.", "Usare default-src 'none' o 'self' e aggiungere direttive per tipo."),
      });
    } else if (def.lower.includes('https:')) {
      out.add(Severity.LOW, L("Permissive default-src 'https:'", "default-src permissiva 'https:'"), {
        sources: ['csp3-default', 'bp-csp'],
        brief: L('default-src allows any HTTPS origin', "default-src consente qualsiasi origine HTTPS"),
        description: L("default-src applies to every resource type without its own directive, and 'https:' allows every HTTPS origin, including one the attacker owns.", "default-src si applica a ogni tipo di risorsa senza una direttiva propria, e 'https:' consente ogni origine HTTPS, inclusa una dell'attaccante."),
        recommendation: L("Use default-src 'none' or 'self' and add per-type directives.", "Usare default-src 'none' o 'self' e aggiungere direttive per tipo."),
      });
    }

    const form = policy.directives.get('form-action');
    if (!form) {
      out.add(Severity.LOW, L('Missing form-action directive', "Direttiva form-action mancante"), {
        sources: ['csp3-form', 'bp-csp', 'zap-10055-13'],
        brief: L('form-action is not set', "form-action non è impostata"),
        description: L('form-action does not fall back to default-src. Without it an injected <form>, or an injected button that overrides an existing form\'s action, can send what the user types, password managers\' autofill included, to any URL.', "form-action non ricade su default-src. Senza di essa un <form> iniettato, o un pulsante iniettato che sovrascrive l'action di un form esistente, può inviare ciò che l'utente digita, compreso l'autocompletamento dei password manager, a qualsiasi URL."),
        recommendation: L("Add form-action 'self' (or 'none' if the page has no forms).", "Aggiungere form-action 'self' (o 'none' se la pagina non ha form)."),
      }, true);
    } else if (form.lower.some((t) => BROAD.has(t))) {
      out.add(Severity.LOW, L('Permissive form-action', "form-action permissiva"), {
        sources: ['csp3-form', 'bp-csp'],
        brief: L('form-action allows any origin', "form-action consente qualsiasi origine"),
        description: L('form-action allows submissions to any origin, so an injected form can send what the user types anywhere.', "form-action consente invii verso qualsiasi origine, quindi un form iniettato può mandare ovunque ciò che l'utente digita."),
        recommendation: L("Set form-action 'self' or the exact origins forms post to.", "Impostare form-action 'self' o le origini esatte verso cui inviano i form."),
      });
    }

    if (!policy.directives.has('upgrade-insecure-requests')) {
      out.add(Severity.LOW, L('Missing upgrade-insecure-requests', "upgrade-insecure-requests mancante"), {
        sources: ['bp-csp'],
        brief: L('upgrade-insecure-requests is not set', "upgrade-insecure-requests non è impostata"),
        description: L('upgrade-insecure-requests makes the browser fetch http:// subresources over HTTPS. It matters for pages that still reference http:// URLs.', "upgrade-insecure-requests fa scaricare al browser in HTTPS le sottorisorse http://. Conta per le pagine che fanno ancora riferimento a URL http://."),
        recommendation: L('Consider adding upgrade-insecure-requests.', "Valutare l'aggiunta di upgrade-insecure-requests."),
      }, true);
    }
  }

  const PERMISSIVE_FRAME_ANCESTORS = L('Permissive frame-ancestors', "frame-ancestors permissiva");

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

  /**
   * REST API mode reads only two directives (OWASP REST Security Cheat Sheet):
   * frame-ancestors, and default-src as defence in depth. Across several
   * policies a resource must pass every one, so one strict policy is enough.
   */
  function apiView(value) {
    const policies = value.split(',').map((p) => p.trim()).filter((p) => p !== '').map(parsePolicy);
    const only = (d, token) => d.lower.length === 0 || (d.lower.length === 1 && d.lower[0] === token);
    const frame = policies.map((p) => p.directives.get('frame-ancestors')).filter(Boolean);
    const dflt = policies.map((p) => p.directives.get('default-src')).filter(Boolean);
    return {
      frameNone: frame.some((d) => only(d, "'none'")),
      frameRestricted: frame.some((d) => !d.lower.some(permissiveAncestor)),
      frameAncestors: frame.length ? frame[0].tokens.join(' ') : null,
      defaultNone: dflt.some((d) => only(d, "'none'")),
      defaultSrc: dflt.length ? dflt[0].tokens.join(' ') : null,
    };
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
      combined.unshift(finding(H, Severity.OK, L(`${policies.length} policies are enforced together`, `${policies.length} policy applicate insieme`), {
        sources: ['csp3-each', 'csp3-list'],
        status: Status.NONE,
        description: L('The value holds several comma-separated policies, which is what a browser sees when the header is sent more than once. Each is enforced on its own, so a resource must pass all of them, and a weakness in one is only cancelled where another restricts the same thing.', "Il valore contiene più policy separate da virgole, che è ciò che vede un browser quando l'header viene inviato più di una volta. Ognuna viene applicata per conto suo, quindi una risorsa deve superarle tutte, e una debolezza in una viene annullata solo dove un'altra restringe la stessa cosa."),
      }));
    }
    return combined;
  }

  HL.csp = Object.freeze({
    evaluateCsp,
    restrictsFraming,
    apiView,
    PERMISSIVE_FRAME_ANCESTORS,
  });
});
