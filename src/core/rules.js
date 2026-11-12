/*
 * Header Analyzer: per-header rules and their orchestration.
 *
 * Each checker has the signature (value, ctx) -> Finding[] and sees one
 * header's effective value. `ctx.absentSeverity` is what the header would be
 * worth if it were absent, for values a browser cannot use: those leave the
 * response exactly where no header would, and are graded the same.
 */
globalThis.HeaderAnalyzer.i18n.module(function (HL, L) {
  'use strict';

  const { Severity, Status, finding, check } = HL.models;
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
    'service-worker-allowed': L('Not sent, so a service worker stays limited to the path its script is served from: the safest state.', "Non inviato, quindi un service worker resta limitato al percorso da cui viene servito il suo script: lo stato più sicuro."),
    'content-disposition': L('Not sent. Content-Disposition only matters on responses meant to be downloaded; for those OWASP recommends attachment, together with nosniff.', "Non inviato. Content-Disposition conta solo sulle risposte destinate al download; per quelle OWASP raccomanda attachment, insieme a nosniff."),
    'pragma': L('Not sent. Pragma is an HTTP/1.0 header superseded by Cache-Control (RFC 9111); caching is evaluated on Cache-Control.', "Non inviato. Pragma è un header HTTP/1.0 superato da Cache-Control (RFC 9111); la cache viene valutata su Cache-Control."),
    'expires': L('Not sent. Expires is superseded by Cache-Control max-age (RFC 9111); caching is evaluated on Cache-Control.', "Non inviato. Expires è superato da max-age di Cache-Control (RFC 9111); la cache viene valutata su Cache-Control."),
    'etag': L('Not sent. ETag is a cache validator, so its absence weakens nothing; RFC 9110 even notes that an entity tag can be abused to track users.', "Non inviato. ETag è un validatore di cache, quindi la sua assenza non indebolisce nulla; RFC 9110 nota anzi che un entity tag può essere abusato per tracciare gli utenti."),
    'x-download-options': L('Not sent. X-Download-Options only ever affected Internet Explorer, retired in 2022; not sending it is correct.', "Non inviato. X-Download-Options ha sempre riguardato solo Internet Explorer, dismesso nel 2022; non inviarlo è corretto."),
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
      behavior = L('browsers combine them into a single header value', "i browser li uniscono in un unico valore");
    } else if (identical) {
      effective = values[0];
      behavior = L('the duplicate values are identical', "i valori duplicati sono identici");
    } else if (key === 'strict-transport-security') {
      effective = values[0];
      behavior = L('RFC 6797 has browsers process only the first', "RFC 6797 fa elaborare ai browser solo il primo");
    } else {
      effective = values[0];
      behavior = L('no standard says how copies of this header are resolved, so the first is assumed', "nessuno standard dice come risolvere le copie di questo header, quindi si assume il primo");
    }
    const seen = L(`Values sent: ${values.join(' | ')}. Evaluated as '${effective}' because ${behavior}.`, `Valori inviati: ${values.join(' | ')}. Valutato come '${effective}' perché ${behavior}.`);

    if (identical || join) {
      return {
        value: effective,
        note: finding(canonical, Severity.LOW, L(`${canonical}: header sent ${values.length} times`, `${canonical}: header inviato ${values.length} volte`), {
          status: Status.DUPLICATED, brief: identical ? L(`Sent ${values.length} times with the same value`, `Inviato ${values.length} volte con lo stesso valore`) : L(`Sent ${values.length} times; browsers combine the values`, `Inviato ${values.length} volte; i browser uniscono i valori`),
          description: seen,
          recommendation: identical ? L(`Configure the server (and any proxy or CDN) to send ${canonical} only once.`, `Configurare il server (e qualsiasi proxy o CDN) per inviare ${canonical} una sola volta.`) : '',
          sources: dupSources(key),
        }),
      };
    }
    // One component's value is discarded, so whoever set it is working on a
    // false assumption.
    return {
      value: effective,
      note: finding(canonical, Severity.LOW, L(`${canonical}: sent ${values.length} times with conflicting values`, `${canonical}: inviato ${values.length} volte con valori in conflitto`), {
        status: Status.DUPLICATED, brief: L(`Sent ${values.length} times with conflicting values`, `Inviato ${values.length} volte con valori in conflitto`),
        description: L(`${seen} Whichever component set a discarded value is operating on a false assumption, and the resolution is not guaranteed to be identical in every browser.`, `${seen} Il componente che ha impostato un valore scartato lavora su un presupposto falso, e la risoluzione non è garantita identica in ogni browser.`),
        sources: dupSources(key),
        recommendation: L(`Decide which value is intended, then send ${canonical} once.`, `Decidere quale valore si intende, poi inviare ${canonical} una sola volta.`),
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
    if (repeated.length) return L(`the ${repeated.map(sp).join(', ')} directive appears more than once`, `la direttiva ${repeated.map(sp).join(', ')} compare più di una volta`);

    // parseDirectives maps a bare name to null and `name=` to '': both "=" forms are invalid.
    const valued = ['includesubdomains', 'preload'].filter((n) => directives.has(n) && directives.get(n) !== null);
    if (valued.length) return L(`${valued.map(sp).join(' and ')} must not be given a value`, `${valued.map(sp).join(' e ')} non deve avere un valore`);

    const maxAge = directives.get('max-age');
    if (maxAge === undefined || maxAge === null) return L('the required max-age directive is missing', "manca la direttiva obbligatoria max-age");
    if (!/^[0-9]+$/.test(maxAge)) return L(`max-age must be a number of seconds, not '${maxAge}'`, `max-age deve essere un numero di secondi, non '${maxAge}'`);
    return null;
  }

  function checkHsts(value, ctx) {
    const cfg = ctx.hsts;
    const directives = parseDirectives(value, ';');
    const reason = hstsSyntaxError(value, directives);
    if (reason) {
      return [finding(HSTS, ctx.absentSeverity, L(`HSTS: the header is not valid because ${reason}`, `HSTS: l'header non è valido perché ${reason}`), {
        sources: ['rfc6797-invalid', 'obs-hsts-absent', 'cs-hsts-rec'],
        brief: L('Invalid syntax, so browsers ignore the header', "Sintassi non valida, quindi i browser ignorano l'header"),
        description: L('A browser ignores a Strict-Transport-Security header that does not conform to RFC 6797 §6.1, so this site has no HSTS at all: the same position as never sending the header. Nothing in the response says so.', "Un browser ignora un header Strict-Transport-Security che non è conforme a RFC 6797 §6.1, quindi questo sito non ha alcun HSTS: la stessa situazione di chi non invia l'header. Nulla nella risposta lo segnala."),
        recommendation: 'Strict-Transport-Security: max-age=63072000; includeSubDomains',
      })];
    }
    // Compared as a string length first: a 400-digit max-age is valid and huge.
    const raw = directives.get('max-age').replace(/^0+(?=\d)/, '');
    const maxAge = raw.length > 15 ? Number.MAX_SAFE_INTEGER : Number(raw);

    if (maxAge === 0) {
      return [finding(HSTS, ctx.absentSeverity, L('HSTS: max-age=0 revokes HSTS protection', "HSTS: max-age=0 revoca la protezione HSTS"), {
        sources: ['rfc6797-zero', 'zap-10035-2'],
        brief: L('max-age=0 switches HSTS off', "max-age=0 disattiva HSTS"),
        description: L('max-age=0 instructs browsers to delete the HSTS entry, so this site has no HSTS, the same position as never sending the header, and worse for a visitor who had the entry already. It is the documented way to turn HSTS off, so it may well be deliberate.', "max-age=0 chiede ai browser di cancellare la voce HSTS, quindi questo sito non ha HSTS, la stessa situazione di chi non invia l'header, e peggio per un visitatore che aveva già la voce. È il modo documentato per disattivare HSTS, quindi può benissimo essere voluto."),
        recommendation: L('Set max-age to at least 63072000 (2 years).', "Impostare max-age ad almeno 63072000 (2 anni)."),
      })];
    }

    const findings = [];
    if (maxAge < cfg.minMaxAge) {
      findings.push(finding(HSTS, Severity.LOW, L(`HSTS: max-age too short (${maxAge}s < ${cfg.minMaxAge}s)`, `HSTS: max-age troppo breve (${maxAge}s < ${cfg.minMaxAge}s)`), {
        sources: ['cs-hsts-rec', 'hstspreload-min', 'asvs-3.4.1', 'obs-hsts-short'],
        brief: L(`max-age=${maxAge} is below the ${duration(cfg.minMaxAge)} minimum`, `max-age=${maxAge} è sotto il minimo di ${duration(cfg.minMaxAge)}`),
        description: L('Protection lapses this long after the last visit, and the next first request goes out over plain HTTP where it can be stripped. OWASP recommends max-age=63072000 (2 years); hstspreload.org requires at least one year.', "La protezione scade questo tempo dopo l'ultima visita, e la prima richiesta successiva parte in HTTP in chiaro, dove può essere declassata. OWASP raccomanda max-age=63072000 (2 anni); hstspreload.org richiede almeno un anno."),
        recommendation: L(`Set max-age to at least ${cfg.minMaxAge}.`, `Impostare max-age ad almeno ${cfg.minMaxAge}.`),
      }));
    }
    // Not contingent on the site having subdomains: the attacker supplies the name.
    if (cfg.requireIncludeSubdomains && !directives.has('includesubdomains')) {
      findings.push(finding(HSTS, Severity.LOW, L('HSTS: missing includeSubDomains', "HSTS: includeSubDomains mancante"), {
        sources: ['asvs-3.4.1', 'cs-hsts-rec', 'bp-hsts'],
        brief: L('includeSubDomains is not set', "includeSubDomains non è impostato"),
        description: L('HSTS covers this host and nothing else, and a host that does not exist is not covered either. An attacker on the network path can answer for anything.example.com over plain HTTP, and from there set cookies with Domain=example.com, which the browser then sends to the protected site. Browsers no longer let such an origin overwrite an existing Secure cookie, but injecting one, or shadowing it on another path, still works. A site with no subdomains at all is not exempt: the name is the attacker\'s to choose.', "HSTS copre questo host e nient'altro, e nemmeno un host che non esiste è coperto. Un attaccante sul percorso di rete può rispondere per qualsiasi.example.com in HTTP in chiaro, e da lì impostare cookie con Domain=example.com, che il browser poi invia al sito protetto. I browser non permettono più a un'origine così di sovrascrivere un cookie Secure esistente, ma iniettarne uno, o oscurarlo su un altro percorso, funziona ancora. Un sito senza alcun sottodominio non è esente: il nome lo sceglie l'attaccante."),
        recommendation: L('Add includeSubDomains, once every host under the domain is served over HTTPS.', "Aggiungere includeSubDomains, quando ogni host sotto il dominio è servito in HTTPS."),
      }));
    }
    // Both branches are contingent on the same lookup: the token declares
    // intent, and membership of the list is a separate step.
    if (cfg.requirePreload) {
      // The list entry is for the base domain and covers its subdomains, so a
      // subdomain's own header need not carry the token.
      const token = directives.has('preload');
      findings.push(finding(HSTS, Severity.LOW, L('HSTS: preload list membership not verified', "HSTS: presenza nella lista di preload non verificata"), {
        sources: token ? ['hstspreload-token', 'hstspreload-base', 'hstspreload-subdomains']
          : ['cs-hsts-rec', 'hstspreload-token', 'hstspreload-base', 'hstspreload-subdomains'],
        brief: token ? L('preload is declared but list membership is unverified', "preload è dichiarato ma la presenza nella lista non è verificata") : L('preload is not set', "preload non è impostato"),
        description: L('Preloading is what closes the one gap HSTS cannot close on its own: the first request to this domain, made before the browser has ever seen the site, goes out over plain HTTP and can be stripped by anyone on the network path. ', "Il preload è ciò che chiude l'unica falla che HSTS da solo non può chiudere: la prima richiesta a questo dominio, fatta prima che il browser abbia mai visto il sito, parte in HTTP in chiaro e può essere declassata da chiunque sia sul percorso di rete. ")
          + (token
            ? L('The token is what a domain must send to be accepted, not what puts it there: submission at hstspreload.org is a separate step, and it can be refused or reversed. A domain can carry this token for years without ever being listed.', "Il token è ciò che un dominio deve inviare per essere accettato, non ciò che lo inserisce: l'invio su hstspreload.org è un passaggio separato, e può essere rifiutato o annullato. Un dominio può avere questo token per anni senza mai essere in lista.")
            : L('This header does not carry the preload token, which a domain must send to be accepted; a subdomain can still be covered through its base domain\'s entry.', "Questo header non contiene il token preload, che un dominio deve inviare per essere accettato; un sottodominio può comunque essere coperto tramite la voce del suo dominio principale.")),
        ...check(L('Is the domain, or its base domain (example.com for api.example.com), on hstspreload.org?', "Il dominio, o il suo dominio principale (example.com per api.example.com), è su hstspreload.org?"), L('it is not listed', "non è in lista"), L('it is listed', "è in lista")),
      }));
    }
    if (!findings.length) findings.push(finding(HSTS, Severity.OK, L('HSTS correctly configured', "HSTS configurato correttamente"), { sources: ['cs-hsts-rec', 'asvs-3.4.1'] }));
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
        return [finding(XFO, Severity.LOW, L(`X-Frame-Options: '${value}' blocks framing by contradicting itself`, `X-Frame-Options: '${value}' blocca il framing contraddicendosi`), {
          sources: ['html-xfo-multi'],
          brief: L('Contradictory values; browsers block framing', "Valori contraddittori; i browser bloccano il framing"),
          description: L('More than one value is given, and at least one is usable, so a browser refuses the frame rather than guess which was meant. Framing is prevented, and a contradiction here can only ever be stricter than the values it is made of, but whichever component set the value being ignored is working on a false assumption, and two components writing this header may be writing others.', "Sono indicati più valori, e almeno uno è utilizzabile, quindi il browser rifiuta il frame invece di indovinare quale si intendesse. Il framing è impedito, e una contraddizione qui può solo essere più restrittiva dei valori che la compongono, ma il componente che ha impostato il valore ignorato lavora su un presupposto falso, e due componenti che scrivono questo header potrebbero scriverne anche altri."),
          recommendation: L('Send X-Frame-Options once, with DENY.', "Inviare X-Frame-Options una sola volta, con DENY."),
        })];
      }
      return [finding(XFO, ctx.absentSeverity, L(`X-Frame-Options: '${value}' leaves the page framable by anyone`, `X-Frame-Options: '${value}' lascia la pagina incorniciabile da chiunque`), {
        brief: L('No valid value, so browsers ignore the header', "Nessun valore valido, quindi i browser ignorano l'header"),
        description: L('Several values are given and none of them is one a browser applies, so the header is treated as if it had been omitted.', "Sono indicati più valori e nessuno è tra quelli che un browser applica, quindi l'header viene trattato come se fosse assente."),
        sources: ['html-xfo-several-invalid', 'zap-10020-4'],
        recommendation: L('Set X-Frame-Options: DENY', "Impostare X-Frame-Options: DENY"),
      })];
    }

    const only = [...values][0];
    if (only === 'deny') return [finding(XFO, Severity.OK, L('X-Frame-Options: DENY (optimal)', "X-Frame-Options: DENY (ottimale)"), { sources: ['cs-xfo-rec', 'bp-xfo'] })];
    if (only === 'sameorigin') {
      return [finding(XFO, Severity.LOW, L('X-Frame-Options: SAMEORIGIN lets another page on this origin frame it', "X-Frame-Options: SAMEORIGIN permette a un'altra pagina di questa origine di incorniciarla"), {
        sources: ['html-xfo-sameorigin', 'cs-xfo-rec', 'bp-xfo'],
        brief: L('SAMEORIGIN instead of DENY', "SAMEORIGIN invece di DENY"),
        description: L('A browser walks every containing document and refuses the frame as soon as one is cross-origin, so this is as strong as frame-ancestors \'self\'. What it still permits is a page on this same origin. That matters where an attacker can put markup on one: a stored HTML injection that a CSP stops short of script execution, say: they cannot read anything through it, but they can frame this page and overlay it, which DENY would have prevented outright.', "Il browser controlla ogni documento contenitore e rifiuta il frame appena uno è cross-origin, quindi è forte quanto frame-ancestors 'self'. Ciò che consente ancora è una pagina della stessa origine. Conta dove un attaccante può inserire markup su una di esse, per esempio un'iniezione HTML persistente che una CSP ferma prima dell'esecuzione di script: attraverso di essa non può leggere nulla, ma può incorniciare questa pagina e sovrapporle qualcosa, cosa che DENY avrebbe impedito del tutto."),
        ...check(L('Does another page on this origin need to frame this one (an admin console, a preview pane, an embedded editor)?', "Un'altra pagina di questa origine ha bisogno di incorniciare questa (una console di amministrazione, un riquadro di anteprima, un editor incorporato)?"), L('no', 'no'), L('yes', 'sì')),
      })];
    }
    if (only.startsWith('allow-from')) {
      return [finding(XFO, ctx.absentSeverity, L('X-Frame-Options: ALLOW-FROM leaves the page framable by anyone', "X-Frame-Options: ALLOW-FROM lascia la pagina incorniciabile da chiunque"), {
        sources: ['html-xfo-allowfrom', 'html-xfo-invalid', 'zap-10020-4'],
        status: Status.DEPRECATED, brief: L('ALLOW-FROM is unsupported, so browsers ignore the header', "ALLOW-FROM non è supportato, quindi i browser ignorano l'header"),
        description: L('No current browser implements ALLOW-FROM, and none of them ignore just the directive: they discard the whole header. The page is in the same position as one that never sent it, while the header suggests a policy is in force.', "Nessun browser attuale implementa ALLOW-FROM, e nessuno ignora solo la direttiva: scartano l'intero header. La pagina è nella stessa situazione di una che non lo ha mai inviato, mentre l'header fa pensare che una policy sia attiva."),
        recommendation: L('Set X-Frame-Options: DENY, and name the permitted origins in Content-Security-Policy: frame-ancestors.', "Impostare X-Frame-Options: DENY, e indicare le origini consentite in Content-Security-Policy: frame-ancestors."),
      })];
    }
    return [finding(XFO, ctx.absentSeverity, L(`X-Frame-Options: '${value}' leaves the page framable by anyone`, `X-Frame-Options: '${value}' lascia la pagina incorniciabile da chiunque`), {
      brief: L('Invalid value, so browsers ignore the header', "Valore non valido, quindi i browser ignorano l'header"),
      description: L('A browser applies this header for DENY and SAMEORIGIN and nothing else. Anything else it cannot use, so framing is allowed exactly as if the header were absent.', "Un browser applica questo header per DENY e SAMEORIGIN e nient'altro. Qualsiasi altro valore non lo può usare, quindi il framing è consentito esattamente come se l'header fosse assente."),
      sources: ['html-xfo-invalid', 'zap-10020-4'],
      recommendation: L('Set X-Frame-Options: DENY', "Impostare X-Frame-Options: DENY"),
    })];
  }

  // ---------------------------------------------------------------------------
  // X-Content-Type-Options: Fetch "determine nosniff": values[0] only,
  // ASCII case-insensitive, quotes kept.
  // ---------------------------------------------------------------------------
  function checkXContentTypeOptions(value, ctx) {
    const first = splitOutsideQuotes(value, ',', true)[0];
    if (first.toLowerCase() === 'nosniff') {
      return [finding('X-Content-Type-Options', Severity.OK, L('X-Content-Type-Options: nosniff (correct)', "X-Content-Type-Options: nosniff (corretto)"), { sources: ['fetch-nosniff', 'asvs-3.4.4'] })];
    }
    return [finding('X-Content-Type-Options', ctx.absentSeverity, L(`X-Content-Type-Options: '${first}' leaves MIME sniffing on`, `X-Content-Type-Options: '${first}' lascia attivo il MIME sniffing`), {
      sources: ['fetch-nosniff', 'cs-xcto', 'zap-10021'],
      brief: L('Not set to nosniff', "Non impostato a nosniff"),
      description: L('Only \'nosniff\' switches the protection on, and only as the first value of the header. Anything else leaves the browser free to ignore the declared Content-Type and guess from the bytes, so a file a user uploaded, served as text/plain, can still be read as HTML and run as the site. It also stops blocking a script or stylesheet whose response carries the wrong type.', "Solo 'nosniff' attiva la protezione, e solo come primo valore dell'header. Qualsiasi altro valore lascia il browser libero di ignorare il Content-Type dichiarato e indovinare dai byte, quindi un file caricato da un utente, servito come text/plain, può comunque essere letto come HTML ed eseguito come il sito. Smette anche di bloccare uno script o un foglio di stile la cui risposta ha il tipo sbagliato."),
      recommendation: L('Set X-Content-Type-Options: nosniff', "Impostare X-Content-Type-Options: nosniff"),
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
    if (bare.type !== 'token') return { invalid: L(`it is a ${bare.type === 'string' ? 'quoted string' : bare.type}, not a token`, `è una ${bare.type === 'string' ? 'stringa tra virgolette' : bare.type}, non un token`) };
    return { token: bare.value };
  }

  function caseHint(token, valid) {
    const match = valid.find((v) => v === token.toLowerCase());
    return match && match !== token ? L(` Values are case-sensitive: '${match}' would be applied, '${token}' is not.`, ` I valori distinguono maiuscole e minuscole: '${match}' verrebbe applicato, '${token}' no.`) : '';
  }

  function coopNotApplied(ctx, reason, recommendation, extra) {
    return finding(COOP, ctx.absentSeverity, L(`COOP: the header is not applied because ${reason}`, `COOP: l'header non viene applicato perché ${reason}`), {
      sources: ['rfc9651-fail', 'cs-coop-rec', 'zap-90004-3'],
      brief: reason.startsWith('it carries more than one') ? L('More than one value, so no policy is applied', "Più di un valore, quindi non viene applicata alcuna policy") : L('Invalid value, so no policy is applied', "Valore non valido, quindi non viene applicata alcuna policy"),
      description: L('A browser that cannot use this value applies unsafe-none, so this response has no COOP at all, the same position as never sending the header, with no Spectre or XS-Leak protection. Nothing in the response says so.', "Un browser che non può usare questo valore applica unsafe-none, quindi questa risposta non ha alcun COOP, la stessa situazione di chi non invia l'header, senza protezione contro Spectre o XS-Leak. Nulla nella risposta lo segnala.") + (extra || ''),
      recommendation: recommendation || L('Set Cross-Origin-Opener-Policy: same-origin', "Impostare Cross-Origin-Opener-Policy: same-origin"),
    });
  }

  const COOP_ALLOW_POPUPS_KEPT = {
    'same-origin-allow-popups': L('No cross-origin document can open this one into an existing browsing context group, so the protection COOP mainly exists for is in place.', "Nessun documento cross-origin può aprire questo in un browsing context group esistente, quindi la protezione per cui COOP esiste è attiva."),
    'noopener-allow-popups': L('Only a same-origin document sending this same value can navigate to this one without a browsing context group switch, and through window.open() not even that: stricter than same-origin in that direction. It does not provide cross-origin isolation, though: that needs same-origin plus COEP.', "Solo un documento della stessa origine che invia questo stesso valore può navigare verso questo senza cambio di browsing context group, e tramite window.open() nemmeno quello: più restrittivo di same-origin in quella direzione. Non fornisce però l'isolamento cross-origin: per quello servono same-origin più COEP."),
  };
  const COOP_VALUES = ['same-origin', 'same-origin-allow-popups', 'noopener-allow-popups', 'unsafe-none'];

  function checkCoop(value, ctx) {
    if (splitOutsideQuotes(value, ',').length > 1) {
      return [coopNotApplied(ctx, L('it carries more than one value', "contiene più di un valore"), L('Send Cross-Origin-Opener-Policy: same-origin once.', "Inviare Cross-Origin-Opener-Policy: same-origin una sola volta."))];
    }
    const t = structuredToken(value);
    if (t.invalid) return [coopNotApplied(ctx, L(`'${value.trim()}' is not a valid header value (${t.invalid})`, `'${value.trim()}' non è un valore valido per l'header (${t.invalid})`))];
    const n = t.token;
    if (n === 'same-origin') return [finding(COOP, Severity.OK, L('COOP: same-origin (optimal)', "COOP: same-origin (ottimale)"), { sources: ['cs-coop-rec', 'bp-coop'] })];
    if (n === 'same-origin-allow-popups' || n === 'noopener-allow-popups') {
      return [finding(COOP, Severity.LOW, L(`COOP: ${n} lets a window this document opens keep a reference back`, `COOP: ${n} permette a una finestra aperta da questo documento di mantenere un riferimento all'indietro`), {
        sources: ['asvs-3.4.8', 'cs-coop-rec'],
        brief: L(`${n} instead of same-origin`, `${n} invece di same-origin`),
        description: L(`${COOP_ALLOW_POPUPS_KEPT[n]} What it gives up is in the other direction: a window this document opens with window.open() stays in its browsing context group if that window sends no COOP of its own, so the window keeps a window.opener reference back and can probe this document through it. That only matters if this document opens windows it does not control.`, `${COOP_ALLOW_POPUPS_KEPT[n]} Ciò a cui rinuncia è nell'altra direzione: una finestra che questo documento apre con window.open() resta nel suo browsing context group se quella finestra non invia un proprio COOP, quindi mantiene un riferimento window.opener all'indietro e può sondare questo documento attraverso di esso. Conta solo se questo documento apre finestre che non controlla.`),
        ...check(L('Does this document open windows (window.open) on sites it does not control?', "Questo documento apre finestre (window.open) su siti che non controlla?"), L('yes', 'sì'), L('no, or only providers the site chose (an OAuth or payment flow)', "no, oppure solo fornitori scelti dal sito (un flusso OAuth o di pagamento)")),
      })];
    }
    if (n === 'unsafe-none') {
      return [finding(COOP, ctx.absentSeverity, L('COOP: unsafe-none opts this document out of COOP protection', "COOP: unsafe-none esclude questo documento dalla protezione COOP"), {
        sources: ['cs-coop-spectre', 'asvs-3.4.8', 'zap-90004-3'],
        brief: L('unsafe-none disables the protection', "unsafe-none disattiva la protezione"),
        description: L('Any document that opens this one shares its browsing context group and keeps a reference to its window, which is what XS-Leaks are probed through. It also rules out cross-origin isolation, which needs same-origin together with COEP.', "Qualsiasi documento che apre questo ne condivide il browsing context group e mantiene un riferimento alla sua finestra, che è ciò attraverso cui si sondano gli XS-Leak. Esclude anche l'isolamento cross-origin, che richiede same-origin insieme a COEP."),
        recommendation: L('Set Cross-Origin-Opener-Policy: same-origin', "Impostare Cross-Origin-Opener-Policy: same-origin"),
      })];
    }
    if (n.toLowerCase() === 'same-origin-plus-coep') {
      return [coopNotApplied(ctx, L('same-origin-plus-COEP cannot be set through this header', "same-origin-plus-COEP non si può impostare tramite questo header"),
        L('It is the result of Cross-Origin-Opener-Policy: same-origin together with Cross-Origin-Embedder-Policy: require-corp, not a value to send.', "È il risultato di Cross-Origin-Opener-Policy: same-origin insieme a Cross-Origin-Embedder-Policy: require-corp, non un valore da inviare."))];
    }
    return [coopNotApplied(ctx, L(`'${n}' is not a policy browsers recognize`, `'${n}' non è una policy riconosciuta dai browser`), '', caseHint(n, COOP_VALUES))];
  }

  function coepNoIsolation(ctx, title, why) {
    return finding(COEP, ctx.absentSeverity, title, {
      sources: ['cs-coep', 'zap-90004-2', 'rfc9651-fail'],
      brief: /more than one value/.test(title) ? L('More than one value, so no policy is applied', "Più di un valore, quindi non viene applicata alcuna policy") : /unsafe-none/.test(title) ? L('unsafe-none provides no isolation', "unsafe-none non fornisce alcun isolamento") : L('Invalid value, so no policy is applied', "Valore non valido, quindi non viene applicata alcuna policy"),
      description: L(`${why} Cross-origin resources requested in no-cors mode load without having to opt in through CORP, and the document is not cross-origin isolated, the same position as never sending the header. This fails safe: features that depend on the isolation are withheld, not left running without it.`, `${why} Le risorse cross-origin richieste in modalità no-cors si caricano senza doverlo consentire tramite CORP, e il documento non è isolato cross-origin, la stessa situazione di chi non invia l'header. Fallisce in modo sicuro: le funzioni che dipendono dall'isolamento vengono negate, non lasciate attive senza di esso.`),
      recommendation: L('Set Cross-Origin-Embedder-Policy: require-corp (with Cross-Origin-Opener-Policy: same-origin) if cross-origin isolation is wanted.', "Impostare Cross-Origin-Embedder-Policy: require-corp (con Cross-Origin-Opener-Policy: same-origin) se si vuole l'isolamento cross-origin."),
    });
  }

  function checkCoep(value, ctx) {
    if (splitOutsideQuotes(value, ',').length > 1) {
      return [coepNoIsolation(ctx, L('COEP: the header is not applied because it carries more than one value', "COEP: l'header non viene applicato perché contiene più di un valore"),
        L('Cross-Origin-Embedder-Policy must hold a single token, and a browser cannot parse this one, so it applies unsafe-none. Sending the header twice produces this, even when both copies are identical.', "Cross-Origin-Embedder-Policy deve contenere un solo token, e il browser non riesce a interpretare questo, quindi applica unsafe-none. Inviare l'header due volte produce questo risultato, anche quando le due copie sono identiche."))];
    }
    const t = structuredToken(value);
    if (t.invalid) {
      return [coepNoIsolation(ctx, L(`COEP: the header is not applied because '${value.trim()}' is not a valid header value`, `COEP: l'header non viene applicato perché '${value.trim()}' non è un valore valido`),
        L(`A browser cannot parse this value (${t.invalid}), so it applies unsafe-none.`, `Il browser non riesce a interpretare questo valore (${t.invalid}), quindi applica unsafe-none.`))];
    }
    const n = t.token;
    if (n === 'require-corp') {
      return [finding(COEP, Severity.OK, 'COEP: require-corp', {
        sources: ['cs-coep', 'html-coep-compat', 'bp-coep'],
        description: L('Cross-origin resources requested in no-cors mode must opt in through CORP or CORS. This is the COEP half of cross-origin isolation, which also needs Cross-Origin-Opener-Policy: same-origin.', "Le risorse cross-origin richieste in modalità no-cors devono acconsentire tramite CORP o CORS. È la metà COEP dell'isolamento cross-origin, che richiede anche Cross-Origin-Opener-Policy: same-origin."),
      })];
    }
    if (n === 'credentialless') {
      return [finding(COEP, Severity.OK, 'COEP: credentialless', {
        sources: ['html-coep-compat'],
        description: L('Cross-origin resources requested in no-cors mode load without having to opt in through CORP, but are fetched with no credentials, so they cannot carry anyone\'s private data. It qualifies for cross-origin isolation exactly as require-corp does: a different mechanism for the same guarantee, not a weaker one.', "Le risorse cross-origin richieste in modalità no-cors si caricano senza dover acconsentire tramite CORP, ma vengono scaricate senza credenziali, quindi non possono contenere dati privati di nessuno. Vale per l'isolamento cross-origin esattamente come require-corp: un meccanismo diverso per la stessa garanzia, non uno più debole."),
      })];
    }
    if (n === 'unsafe-none') {
      return [coepNoIsolation(ctx, L('COEP: unsafe-none is the value a browser applies anyway', "COEP: unsafe-none è il valore che il browser applica comunque"),
        L('unsafe-none is the default, so stating it changes nothing.', "unsafe-none è il valore predefinito, quindi dichiararlo non cambia nulla."))];
    }
    return [coepNoIsolation(ctx, L(`COEP: the header is not applied because '${n}' is not a policy browsers recognize`, `COEP: l'header non viene applicato perché '${n}' non è una policy riconosciuta dai browser`),
      L('A browser that does not recognise the token applies unsafe-none.', "Un browser che non riconosce il token applica unsafe-none.") + caseHint(n, ['require-corp', 'credentialless', 'unsafe-none']))];
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
      return [finding(H, Severity.LOW, L('CORP: cross-origin allows any origin to load this resource', "CORP: cross-origin permette a qualsiasi origine di caricare questa risorsa"), {
        sources: ['cs-corp', 'zap-90004-1'],
        brief: L('cross-origin lets any site load the resource', "cross-origin permette a qualsiasi sito di caricare la risorsa"),
        description: L('Any site can embed this resource in no-cors mode, which brings it into that site\'s process, readable through a Spectre-style side channel on browsers without full site isolation. For a resource meant to be public (a CDN asset, an embeddable widget) that is the intent.', "Qualsiasi sito può incorporare questa risorsa in modalità no-cors, portandola nel processo di quel sito, dove è leggibile tramite un canale laterale di tipo Spectre nei browser senza isolamento completo dei siti. Per una risorsa pensata per essere pubblica (un asset su CDN, un widget incorporabile) è proprio l'intento."),
        ...check(L('Is this resource meant to be loaded by other sites (a public image, script or font, an embeddable widget)?', "Questa risorsa è pensata per essere caricata da altri siti (un'immagine, uno script o un font pubblici, un widget incorporabile)?"), L('no', 'no'), L('yes', 'sì')),
      })];
    }
    return [finding(H, ctx.absentSeverity, L(`CORP: unrecognized value '${value}', not applied`, `CORP: valore non riconosciuto '${value}', non applicato`), {
      sources: ['fetch-corp', 'zap-90004-1'],
      brief: L('Invalid value, so browsers ignore the header', "Valore non valido, quindi i browser ignorano l'header"),
      description: L('Fetch compares the value with same-origin, same-site and cross-origin exactly (it is case-sensitive). Anything else is ignored, leaving the resource as if no header had been sent.', "Fetch confronta il valore con same-origin, same-site e cross-origin in modo esatto (distingue maiuscole e minuscole). Qualsiasi altro valore viene ignorato, e la risorsa resta come se l'header non fosse stato inviato."),
      recommendation: L('Set Cross-Origin-Resource-Policy: same-origin (or same-site).', "Impostare Cross-Origin-Resource-Policy: same-origin (o same-site)."),
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

  const PP_CLOSE_ALL = L('Close what this response does not need: ', "Chiudere ciò che non serve a questa risposta: ")
    + [...PP_TRACKING].sort().concat(PP_ONE_CLICK).map((f) => f + '=()').join(', ');

  function checkPermissionsPolicy(value, ctx) {
    const parsed = parseSfDictionary(value);
    if (!parsed.ok) {
      return [finding(PP, ctx.absentSeverity, L(`Permissions-Policy: the header is not valid because ${parsed.reason}`, `Permissions-Policy: l'header non è valido perché ${parsed.reason}`), {
        sources: ['pp-empty', 'rfc9651-fail', 'zap-10063-1'],
        brief: L('Invalid syntax, so the whole policy is ignored', "Sintassi non valida, quindi l'intera policy viene ignorata"),
        description: L('Permissions-Policy is a structured field dictionary (RFC 9651), and a browser that cannot parse one applies the empty policy: every feature stays at its default and nothing this header lists takes effect. That is the same position as never sending it, with the response looking like it restricts something. The most common way to land here is the old Feature-Policy syntax (features separated by semicolons, allowlists written as \'none\' or \'self\') which this header does not accept.', "Permissions-Policy è un dizionario di structured field (RFC 9651), e un browser che non riesce a interpretarlo applica la policy vuota: ogni funzionalità resta al suo valore predefinito e nulla di ciò che questo header elenca ha effetto. È la stessa situazione di chi non lo invia, con una risposta che sembra restringere qualcosa. Il modo più comune per arrivarci è la vecchia sintassi di Feature-Policy (funzionalità separate da punto e virgola, allowlist scritte come 'none' o 'self'), che questo header non accetta."),
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
      findings.push(finding(PP, Severity.LOW, L(`Permissions-Policy: dropped by the browser: ${dropped.sort().join(', ')}`, `Permissions-Policy: scartate dal browser: ${dropped.sort().join(', ')}`), {
        sources: ['pp-dict'],
        brief: L(`Invalid allowlist for ${dropped.join(', ')}`, `Allowlist non valida per ${dropped.join(', ')}`),
        description: L('An allowlist has to be *, self, a quoted origin, or a parenthesised list of those. These are none of them, so a browser ignores each of these directives on its own and leaves that feature at its default: the rest of the header still applies. Whatever they were written to restrict is not restricted.', "Un'allowlist deve essere *, self, un'origine tra virgolette, o un elenco tra parentesi di questi. Queste non sono nessuna di queste cose, quindi il browser ignora ciascuna di queste direttive e lascia quella funzionalità al suo valore predefinito: il resto dell'header si applica comunque. Ciò che dovevano restringere non è ristretto."),
        recommendation: L('Write each allowlist as (), (self) or ("https://origin").', "Scrivere ogni allowlist come (), (self) o (\"https://origine\")."),
      }));
    }

    const opened = [...declared].filter(([f, o]) => PP_DEFAULT_SELF.has(f) && o.includes('*')).map(([f]) => f).sort();
    if (opened.length) {
      findings.push(finding(PP, Severity.LOW, L(`Permissions-Policy: opened to any origin: ${opened.join(', ')}`, `Permissions-Policy: aperte a qualsiasi origine: ${opened.join(', ')}`), {
        sources: ['pp-default', 'chromium-default-self', 'cs-pp-rec'],
        brief: L(`${opened.join(', ')} allowed to any origin`, `${opened.join(', ')} consentite a qualsiasi origine`),
        description: L('A browser allows these features to this origin only. The policy widens them to *, so any document embedded in this page can use them: the policy is granting access rather than restricting it.', "Un browser consente queste funzionalità solo a questa origine. La policy le allarga a *, quindi qualsiasi documento incorporato in questa pagina può usarle: la policy concede l'accesso invece di restringerlo."),
        recommendation: L('Restrict these to () or (self) unless an embedded third party genuinely needs them.', "Restringerle a () o (self), a meno che una terza parte incorporata ne abbia davvero bisogno."),
      }));
    }

    const delegated = PP_ONE_CLICK
      .filter((f) => declared.has(f) && !declared.get(f).includes('*'))
      .map((f) => [f, declared.get(f).filter((o) => o !== 'self')])
      .filter(([, named]) => named.length);
    if (delegated.length) {
      findings.push(finding(PP, Severity.LOW, L('Permissions-Policy: handed to another origin: ', "Permissions-Policy: concesse a un'altra origine: ")
        + delegated.map(([f, o]) => `${f} → ${o.join(', ')}`).join(', '), {
        sources: ['permissions-delegation', 'cs-pp-rec'],
        brief: L(`${delegated.map(([f]) => f).join(', ')} delegated to another origin`, `${delegated.map(([f]) => f).join(', ')} delegate a un'altra origine`),
        description: L('A browser keeps these to this origin; the policy hands them to the origins named here, so a document from one of them, embedded in this page, can ask for them. What the user is shown when it does is this site\'s name: browsers put the top-level origin in the permission prompt rather than the frame\'s, so someone reading "this site wants to use your camera" has no way to learn that the stream goes somewhere else. Delegating is what this header is for, so this is a question about who was chosen, not a defect in itself. It sits below an allowlist of * because that one also admits a frame nobody chose: an HTML injection that can place an iframe is enough to reach the prompt, while a named origin has to be compromised first.', "Un browser riserva queste funzionalità a questa origine; la policy le concede alle origini indicate qui, quindi un documento di una di esse, incorporato in questa pagina, può chiederle. Ciò che l'utente vede quando succede è il nome di questo sito: i browser mettono nella richiesta di autorizzazione l'origine principale e non quella del frame, quindi chi legge \"questo sito vuole usare la tua fotocamera\" non ha modo di sapere che il flusso va altrove. Delegare è lo scopo di questo header, quindi è una questione di chi è stato scelto, non un difetto in sé. Sta sotto un'allowlist con *, perché quella ammette anche un frame che nessuno ha scelto: basta un'iniezione HTML che inserisca un iframe per arrivare alla richiesta, mentre un'origine indicata va prima compromessa."),
        ...check(L('Is each origin in the header a known service that needs this feature (for example, a video-call or identity-verification provider)?', "Ogni origine nell'header è un servizio noto che ha bisogno di questa funzionalità (per esempio, un fornitore di videochiamate o di riconoscimento dell'identità)?"), L('no, or you cannot tell what one of them is', "no, oppure non si riesce a capire cosa sia una di esse"), L('yes', 'sì')),
      }));
    }

    const embeds = PP_TRACKING.filter((f) => ppReachesAnEmbed(f, declared)).sort();
    if (embeds.length) {
      findings.push(finding(PP, Severity.LOW, L(`Permissions-Policy: reachable by an embedded document: ${embeds.join(', ')}`, `Permissions-Policy: raggiungibili da un documento incorporato: ${embeds.join(', ')}`), {
        sources: ['chromium-topics', 'attribution-default', 'chromium-uach', 'chromium-pst-issuance', 'chromium-pst-redemption', 'chromium-storage-access', 'chromium-gamepad', 'chromium-pip', 'chromium-deferred'],
        brief: L('Tracking features left open to embedded content', "Funzionalità di tracciamento lasciate aperte ai contenuti incorporati"),
        description: L('A browser allows these to every origin, so any cross-origin document this page embeds can use them until the policy says otherwise: reading the user\'s inferred interest topics, asking for high-entropy user-agent hints, registering ad attributions, issuing and redeeming tracking tokens, requesting its own third-party cookies. (gamepad, picture-in-picture and deferred-fetch-minimal are open the same way, with nothing worth reporting behind them.) This is the user\'s privacy toward parties the site chose to embed, and for an advertising or analytics frame it is what the frame was embedded to do: which is why it is stated rather than counted as a defect. Closing them to an embed takes (self); () also takes them from this origin. To close them: ', "Un browser le consente a ogni origine, quindi qualsiasi documento cross-origin incorporato in questa pagina può usarle finché la policy non dice altrimenti: leggere gli argomenti di interesse dedotti per l'utente, chiedere user-agent hint ad alta entropia, registrare attribuzioni pubblicitarie, emettere e riscattare token di tracciamento, chiedere i propri cookie di terze parti. (gamepad, picture-in-picture e deferred-fetch-minimal sono aperte allo stesso modo, senza nulla che valga la pena segnalare.) Riguarda la privacy dell'utente verso le parti che il sito ha scelto di incorporare, e per un frame pubblicitario o di analytics è proprio ciò per cui è stato incorporato: per questo è descritto invece di essere contato come difetto. Per chiuderle a un contenuto incorporato serve (self); () le toglie anche a questa origine. Per chiuderle: ") + embeds.map((f) => f + '=(self)').join(', ') + '.',
        ...check(L('Does this page embed content from other sites that is not advertising or analytics (a chat widget, a video player, a map)?', "Questa pagina incorpora contenuti di altri siti che non sono pubblicità o analytics (una chat, un video player, una mappa)?"), L('yes', 'sì'), L('no, it embeds nothing from other sites, or only advertising or analytics', "no, non incorpora nulla da altri siti, oppure solo pubblicità o analytics")),
      }));
    }

    const oneClick = PP_ONE_CLICK.filter((f) => ppReachesThisOrigin(f, declared));
    if (oneClick.length) {
      findings.push(finding(PP, Severity.LOW, L(`Permissions-Policy: an XSS on this origin could ask for ${oneClick.join(', ')}`, `Permissions-Policy: un XSS su questa origine potrebbe chiedere ${oneClick.join(', ')}`), {
        sources: ['mediacapture-default', 'geolocation-default', 'permissions-delegation', 'cs-pp-example'],
        brief: L(`${oneClick.join(', ')} not disabled`, `${oneClick.join(', ')} non disattivate`),
        description: L('Nothing embedded cross-origin can reach these: a browser keeps them to this origin either way. What is left open is script that achieves execution here: it can raise the permission prompt, and the prompt names the site, never the code that asked, so a user who has no way to tell the two apart grants it. One click is the whole interaction. Disabling them removes the prompt itself; (self) does not, because an XSS runs on this origin. To close them: ', "Nulla di incorporato cross-origin può raggiungerle: un browser le riserva comunque a questa origine. Ciò che resta aperto è uno script che riesce a eseguire qui: può far comparire la richiesta di autorizzazione, e la richiesta indica il sito, mai il codice che l'ha fatta, quindi un utente che non ha modo di distinguere i due la concede. Un clic è tutta l'interazione. Disattivarle elimina la richiesta stessa; (self) no, perché un XSS viene eseguito su questa origine. Per chiuderle: ") + oneClick.map((f) => f + '=()').join(', ') + '.',
        ...check(L('Does this page use these features itself (for example, the camera for video identification)?', "Questa pagina usa direttamente queste funzionalità (per esempio, la fotocamera per il riconoscimento video)?"), L('no', 'no'), L('yes', 'sì')),
      }));
    }

    if (!findings.length) findings.push(finding(PP, Severity.OK, L('Permissions-Policy: every feature addressed', "Permissions-Policy: ogni funzionalità è gestita"), { sources: ['cs-pp-rec'] }));
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
      return [finding(RP, Severity.OK, L(`Referrer-Policy: '${n}' (sends nothing cross-origin)`, `Referrer-Policy: '${n}' (non invia nulla cross-origin)`), { sources: ['referrer-last', 'bp-rp'] })];
    }
    if (n === 'strict-origin' || n === 'strict-origin-when-cross-origin') {
      return [finding(RP, Severity.OK, L(`Referrer-Policy: '${n}' (sends only the origin cross-origin)`, `Referrer-Policy: '${n}' (invia cross-origin solo l'origine)`), { sources: ['referrer-last', 'cs-rp-default'] })];
    }
    if (n === 'origin' || n === 'origin-when-cross-origin') {
      return [finding(RP, Severity.LOW, L(`Referrer-Policy: '${n}' (sends the origin to plain-HTTP destinations too)`, `Referrer-Policy: '${n}' (invia l'origine anche a destinazioni in HTTP in chiaro)`), {
        sources: ['cs-rp-default', 'asvs-3.4.5'],
        brief: L(`${n} sends the origin over plain HTTP`, `${n} invia l'origine in HTTP in chiaro`),
        description: L('Only the origin is sent, never the path or query, but it reaches destinations that are not TLS-protected as well, where anyone on the network path reads which site the user is on. The strict- variants are identical except that they withhold it on such a downgrade, so they cost nothing; this value is also weaker than the strict-origin-when-cross-origin browsers apply when the header is absent.', "Viene inviata solo l'origine, mai il percorso o la query, ma raggiunge anche destinazioni non protette da TLS, dove chiunque sul percorso di rete legge su quale sito si trova l'utente. Le varianti strict- sono identiche, salvo che la trattengono in questo declassamento, quindi non costano nulla; questo valore è anche più debole di strict-origin-when-cross-origin, che i browser applicano quando l'header è assente."),
        recommendation: L(`Use the strict- variant, strict-${n}: it sends the same origin over HTTPS and nothing over plain HTTP.`, `Usare la variante strict-, strict-${n}: invia la stessa origine in HTTPS e nulla in HTTP in chiaro.`),
      })];
    }
    if (n === 'no-referrer-when-downgrade' || n === 'unsafe-url') {
      const alsoInClear = n === 'unsafe-url';
      return [finding(RP, Severity.LOW, L(`Referrer-Policy: '${n}' (sends the full URL to third parties)`, `Referrer-Policy: '${n}' (invia l'URL completo a terze parti)`), {
        sources: ['obs-rp-unsafe', 'ps-referer', 'asvs-3.4.5'],
        brief: L(`${n} sends full URLs to third parties`, `${n} invia URL completi a terze parti`),
        description: L('Every third party the page loads a resource from, or links to, receives the complete URL including path and query string, so a password-reset token, a search query or an internal path ends up in someone else\'s logs.', "Ogni terza parte da cui la pagina carica una risorsa, o verso cui ha un link, riceve l'URL completo con percorso e query string, quindi un token di reset della password, una ricerca o un percorso interno finiscono nei log di qualcun altro.")
          + (alsoInClear ? L(' It is sent to plain-HTTP destinations too, where anyone on the network can read it.', " Viene inviato anche a destinazioni in HTTP in chiaro, dove chiunque sulla rete può leggerlo.")
            : L(' It is withheld only on a downgrade to plain HTTP, which is the one case browsers increasingly prevent anyway.', " Viene trattenuto solo nel declassamento a HTTP in chiaro, che è proprio il caso che i browser impediscono sempre più spesso.")),
        recommendation: L('Use no-referrer, or strict-origin-when-cross-origin to send no more than the origin.', "Usare no-referrer, oppure strict-origin-when-cross-origin per non inviare più dell'origine."),
      })];
    }
    return [finding(RP, ctx.absentSeverity, L(`Referrer-Policy: unrecognized value '${value}', so no policy is in force`, `Referrer-Policy: valore non riconosciuto '${value}', quindi nessuna policy è attiva`), {
      sources: ['referrer-last', 'cs-rp-rec'],
      brief: L('Invalid value, so the browser default applies', "Valore non valido, quindi si applica il valore predefinito del browser"),
      description: L('A token that is not one of the eight defined policies is skipped, so the browser falls back to its own default exactly as if the header had not been sent. The policy intended here is not applied, and nothing in the response reveals that.', "Un token che non è una delle otto policy definite viene saltato, quindi il browser ricade sul proprio valore predefinito esattamente come se l'header non fosse stato inviato. La policy che si intendeva non viene applicata, e nulla nella risposta lo rivela."),
      recommendation: L('Check the spelling. The defined values are no-referrer, no-referrer-when-downgrade, same-origin, origin, strict-origin, origin-when-cross-origin, strict-origin-when-cross-origin, unsafe-url.', "Controllare l'ortografia. I valori definiti sono no-referrer, no-referrer-when-downgrade, same-origin, origin, strict-origin, origin-when-cross-origin, strict-origin-when-cross-origin, unsafe-url."),
    })];
  }

  // ---------------------------------------------------------------------------
  // Cache-Control: RFC 9111, graded for a response only signed-in users may
  // see (content that is not public), which is the case where caching costs
  // something.
  // ---------------------------------------------------------------------------
  const CACHE_DIRECTIVES = new Set([
    'max-age', 's-maxage', 'no-cache', 'no-store', 'no-transform', 'must-revalidate',
    'proxy-revalidate', 'must-understand', 'private', 'public', 'immutable',
    'stale-while-revalidate', 'stale-if-error',
  ]);

  const CACHE_CHECK = check(L('Is the response visible only to signed-in users (content that is not public)?', "La risposta è visibile solo agli utenti autenticati (contenuto non pubblico)?"), L('yes', 'sì'), L('no (a public page or resource, the same for everyone)', "no (una pagina o una risorsa pubblica, uguale per tutti)"));

  function checkCacheControl(value, ctx) {
    const CC = 'Cache-Control';
    const d = parseDirectives(value, ',');
    // REST API mode: the same rules, with the REST Security Cheat Sheet cited too.
    const finding = (h, sev, title, o) => HL.models.finding(h, sev, title, ctx.api && sev > Severity.OK ? { ...o, sources: [...o.sources, 'rest-cc'] } : o);
    const bare = (name) => d.has(name) && !d.get(name);

    if (![...d.keys()].some((k) => CACHE_DIRECTIVES.has(k))) {
      return [finding(CC, ctx.absentSeverity, L(`Cache-Control: '${value}' holds no directive a cache understands`, `Cache-Control: '${value}' non contiene direttive comprensibili da una cache`), {
        sources: ['rfc9111-heuristic', 'cs-cc-default', 'zap-10015'],
        brief: L('No valid directive, so heuristic caching applies', "Nessuna direttiva valida, quindi si applica la cache euristica"),
        description: L('None of these tokens is a standard cache directive, so caches ignore them and fall back to heuristic freshness, the same position as sending no Cache-Control at all. Nothing keeps this response out of a shared cache.', "Nessuno di questi token è una direttiva di cache standard, quindi le cache li ignorano e ricadono sulla freschezza euristica, la stessa situazione di chi non invia Cache-Control. Nulla tiene questa risposta fuori da una cache condivisa."),
        ...CACHE_CHECK,
      })];
    }
    if (d.has('no-store')) return [finding(CC, Severity.OK, L('Cache-Control: no-store (not stored by any cache)', "Cache-Control: no-store (non salvata da nessuna cache)"), { sources: ['cs-cc-nostore', 'asvs-14.3.2', 'bp-cc'] })];
    if (bare('private')) {
      return [finding(CC, Severity.LOW, L('Cache-Control: private keeps this out of shared caches, not off the disk', "Cache-Control: private la tiene fuori dalle cache condivise, non dal disco"), {
        sources: ['rfc9111-private', 'cs-cc-private', 'bp-cache'],
        brief: L('private still allows storage on disk', "private permette comunque il salvataggio su disco"),
        description: L('Shared caches will not store the response, so it cannot be served to another user. The browser still writes it to disk, where it can be recovered with the back button after logout, or by whoever uses the machine next.', "Le cache condivise non salveranno la risposta, quindi non può essere servita a un altro utente. Il browser la scrive comunque su disco, dove si può recuperare con il tasto indietro dopo il logout, o da chi usa il computer dopo."),
        ...CACHE_CHECK,
      })];
    }
    const alwaysRevalidates = bare('no-cache')
      || (d.get('max-age') === '0' && (d.has('must-revalidate') || d.has('proxy-revalidate')));
    if (alwaysRevalidates) {
      return [finding(CC, Severity.LOW, L(`Cache-Control: '${value}' revalidates but does not stop a shared cache storing this`, `Cache-Control: '${value}' rivalida ma non impedisce a una cache condivisa di salvarla`), {
        sources: ['cs-cc-nocache'],
        brief: L('Revalidates but does not prevent storage', "Rivalida ma non impedisce il salvataggio"),
        description: L('Revalidation before reuse is forced, but storage is not prevented. A shared cache may keep the response, and nothing here marks it as belonging to a single user.', "La rivalidazione prima del riuso è forzata, ma il salvataggio non è impedito. Una cache condivisa può conservare la risposta, e nulla qui la segna come appartenente a un singolo utente."),
        ...CACHE_CHECK,
      })];
    }
    const qualified = ['private', 'no-cache'].find((n) => d.get(n));
    const detail = qualified ? L(` The qualified form (${qualified}="${d.get(qualified)}") covers only the fields it names.`, ` La forma qualificata (${qualified}="${d.get(qualified)}") riguarda solo i campi che nomina.`) : '';
    return [finding(CC, Severity.MEDIUM, L(`Cache-Control: '${value}' lets a shared cache store this response`, `Cache-Control: '${value}' permette a una cache condivisa di salvare questa risposta`), {
      sources: ['cs-cc-nostore', 'asvs-14.3.2', 'rfc9111-auth-directives', 'ps-cache'],
      brief: L('Shared caches may store the response', "Le cache condivise possono salvare la risposta"),
      description: L('Nothing here keeps the response out of a shared cache, so a CDN or proxy may store it under this URL and serve it to the next person who asks: content meant for signed-in users handed to someone who should not see it, even someone not signed in. If requests carry an Authorization header, RFC 9111 already keeps shared caches from reusing the response, unless the value also has public, s-maxage or must-revalidate: then only the copy on the user\'s disk remains.', "Nulla qui tiene la risposta fuori da una cache condivisa, quindi una CDN o un proxy può salvarla sotto questo URL e servirla alla persona successiva che la chiede: contenuti riservati agli utenti autenticati consegnati a chi non dovrebbe vederli, anche a chi non è autenticato. Se le richieste portano un header Authorization, RFC 9111 impedisce già alle cache condivise di riusare la risposta, a meno che il valore non contenga anche public, s-maxage o must-revalidate: in quel caso resta solo la copia sul disco dell'utente.") + detail,
      ...CACHE_CHECK,
    })];
  }

  // ---------------------------------------------------------------------------
  // Smaller checks
  // ---------------------------------------------------------------------------
  function checkXPermittedCrossDomainPolicies(value, ctx) {
    const H = 'X-Permitted-Cross-Domain-Policies';
    const n = value.trim().toLowerCase();
    if (n === 'none' || n === 'master-only') {
      return [finding(H, Severity.OK, L(`X-Permitted-Cross-Domain-Policies: '${value}' (restrictive)`, `X-Permitted-Cross-Domain-Policies: '${value}' (restrittivo)`), { sources: ['mdn-xpcdp-none', 'bp-xpcdp'] })];
    }
    if (n === 'none-this-response') {
      return [finding(H, ctx.absentSeverity, L('X-Permitted-Cross-Domain-Policies: none-this-response sets no site-wide policy', "X-Permitted-Cross-Domain-Policies: none-this-response non imposta una policy per tutto il sito"), {
        brief: L('none-this-response sets no site-wide policy', "none-this-response non imposta una policy per tutto il sito"),
        description: L('none-this-response is valid, but it only stops this one response from being used as a policy file. It declares no meta-policy for the site, so other policy files are governed as if the header were absent.', "none-this-response è valido, ma impedisce solo che questa risposta venga usata come file di policy. Non dichiara una meta-policy per il sito, quindi gli altri file di policy sono regolati come se l'header fosse assente."),
        recommendation: L('Set X-Permitted-Cross-Domain-Policies: none', "Impostare X-Permitted-Cross-Domain-Policies: none"),
        sources: ['mdn-xpcdp-ntr', 'mdn-xpcdp-none'],
      })];
    }
    if (n === 'all' || n === 'by-content-type' || n === 'by-ftp-filename') {
      return [finding(H, Severity.MEDIUM, L(`X-Permitted-Cross-Domain-Policies: '${value}' is permissive`, `X-Permitted-Cross-Domain-Policies: '${value}' è permissivo`), {
        sources: ['zap-20016-1', 'adobe-master', 'mdn-xpcdp'],
        brief: L(`${n} allows cross-domain policy files`, `${n} consente i file di policy cross-domain`),
        description: L('Allows cross-domain policy files to be loaded. A PDF opened in the Adobe Reader plugin, or legacy Flash content, can request a cross-domain policy from this origin, and a permissive policy grants it.', "Consente il caricamento dei file di policy cross-domain. Un PDF aperto nel plugin di Adobe Reader, o un vecchio contenuto Flash, può chiedere una policy cross-domain a questa origine, e una policy permissiva gliela concede."),
        ...check(L('Does this origin serve files a browser plugin can load (for example, PDFs opened in Adobe Reader, or SWF files)?', "Questa origine serve file che un plugin del browser può caricare (per esempio, PDF aperti in Adobe Reader, o file SWF)?"), L('yes', 'sì'), L('no', 'no')),
      })];
    }
    return [finding(H, ctx.absentSeverity, L(`X-Permitted-Cross-Domain-Policies: unrecognized value '${value}'`, `X-Permitted-Cross-Domain-Policies: valore non riconosciuto '${value}'`), {
      sources: ['adobe-invalid', 'mdn-xpcdp'],
      brief: L('Invalid value, so plugins ignore the header', "Valore non valido, quindi i plugin ignorano l'header"),
      description: L('This value is not one of those the Adobe cross-domain policy specification defines (none, master-only, by-content-type, by-ftp-filename, all, none-this-response). Adobe clients ignore it and apply their default, which is the same position as sending no header at all.', "Questo valore non è tra quelli definiti dalla specifica Adobe sulle policy cross-domain (none, master-only, by-content-type, by-ftp-filename, all, none-this-response). I client Adobe lo ignorano e applicano il loro valore predefinito, la stessa situazione di chi non invia l'header."),
      recommendation: L('Set X-Permitted-Cross-Domain-Policies: none', "Impostare X-Permitted-Cross-Domain-Policies: none"),
    })];
  }

  function checkXXssProtection(value, ctx) {
    const H = 'X-XSS-Protection';
    const parts = value.split(';').map((p) => p.trim().toLowerCase());
    const flag = parts[0];
    const rest = parts.slice(1);
    // REST API mode: the filter acted on pages, so what is left is an obsolete header.
    if (ctx && ctx.api && flag === '1') {
      const block = rest.includes('mode=block');
      return [finding(H, Severity.LOW, block ? L('X-XSS-Protection: 1; mode=block (deprecated header)', "X-XSS-Protection: 1; mode=block (header deprecato)") : L('X-XSS-Protection: 1 enables the deprecated XSS filter', "X-XSS-Protection: 1 attiva il filtro XSS deprecato"), {
        sources: ['mdn-xxp-pages', 'cs-xxp-rec', 'shp-deprecated'],
        status: Status.DEPRECATED, brief: block ? L('Enables the obsolete XSS filter in block mode', "Attiva il filtro XSS obsoleto in modalità block") : L('Enables the obsolete XSS filter', "Attiva il filtro XSS obsoleto"),
        description: L('The filter stopped pages from loading when it detected a reflected XSS attack, and the ways it could be abused all worked on a page being rendered. An API response is not rendered, so the filter has nothing to act on here. The header is still obsolete, and OWASP recommends not setting it, or setting it to 0. No current browser honours it.', "Il filtro bloccava il caricamento delle pagine quando rilevava un attacco XSS riflesso, e i modi in cui poteva essere abusato funzionavano tutti su una pagina visualizzata. Una risposta di un'API non viene visualizzata, quindi qui il filtro non ha nulla su cui agire. L'header resta comunque obsoleto, e OWASP raccomanda di non impostarlo, o di impostarlo a 0. Nessun browser attuale lo rispetta."),
        recommendation: L('Remove the header, or set it to 0.', "Rimuovere l'header, o impostarlo a 0."),
      })];
    }
    if (flag === '0') {
      return [finding(H, Severity.OK, L('X-XSS-Protection: 0 (deprecated header, disabled correctly)', "X-XSS-Protection: 0 (header deprecato, disattivato correttamente)"), {
        sources: ['cs-xxp-rec'],
        description: L('The header is deprecated. Setting it to 0 is what OWASP recommends for any browser that still reads it.', "L'header è deprecato. Impostarlo a 0 è ciò che OWASP raccomanda per qualsiasi browser che lo legge ancora."),
        recommendation: L('Consider removing this header entirely and relying on Content-Security-Policy.', "Valutare di rimuovere del tutto questo header e affidarsi a Content-Security-Policy."),
      })];
    }
    if (flag === '1' && !rest.includes('mode=block')) {
      return [finding(H, Severity.LOW, L('X-XSS-Protection: 1 enables the deprecated XSS filter', "X-XSS-Protection: 1 attiva il filtro XSS deprecato"), {
        sources: ['cs-xxp-warn', 'mdn-xxp-warn', 'shp-deprecated'],
        status: Status.DEPRECATED, brief: L('Enables the obsolete XSS filter', "Attiva il filtro XSS obsoleto"),
        description: L('The filter matched text from the URL against the scripts in the page, so an attacker could craft a URL that made it neutralise a script the page legitimately contains (an anti-CSRF or framebusting script, for example). No current browser honours the header, which is what keeps this low.', "Il filtro confrontava il testo dell'URL con gli script della pagina, quindi un attaccante poteva costruire un URL che gli facesse neutralizzare uno script legittimo della pagina (per esempio uno script anti-CSRF o anti-framing). Nessun browser attuale rispetta l'header, ed è questo che tiene bassa la gravità."),
        recommendation: L('Set to 0 or remove the header; rely on Content-Security-Policy.', "Impostarlo a 0 o rimuovere l'header; affidarsi a Content-Security-Policy."),
      })];
    }
    if (flag === '1') {
      return [finding(H, Severity.LOW, L('X-XSS-Protection: 1; mode=block (deprecated, potentially risky)', "X-XSS-Protection: 1; mode=block (deprecato, potenzialmente rischioso)"), {
        sources: ['mdn-xxp-block', 'cs-xxp-rec', 'shp-deprecated'],
        status: Status.DEPRECATED, brief: L('Enables the obsolete XSS filter in block mode', "Attiva il filtro XSS obsoleto in modalità block"),
        description: L('mode=block stops the page from rendering when the filter triggers, and the filter triggers on scripts the page legitimately contains whenever their markup also appears in the URL. Whether a page was blocked is observable from another origin, turning "does this page contain script X?" into a yes/no readable from outside. No current browser honours the header, which is what keeps this low.', "mode=block impedisce la visualizzazione della pagina quando il filtro scatta, e il filtro scatta sugli script legittimi della pagina ogni volta che il loro markup compare anche nell'URL. Se una pagina è stata bloccata è osservabile da un'altra origine, e questo trasforma \"questa pagina contiene lo script X?\" in un sì/no leggibile dall'esterno. Nessun browser attuale rispetta l'header, ed è questo che tiene bassa la gravità."),
        recommendation: L('Set to 0 or remove; use Content-Security-Policy instead.', "Impostarlo a 0 o rimuoverlo; usare invece Content-Security-Policy."),
      })];
    }
    return [finding(H, Severity.LOW, L(`X-XSS-Protection: '${value}' (deprecated header)`, `X-XSS-Protection: '${value}' (header deprecato)`), {
      sources: ['cs-xxp-rec', 'shp-deprecated'],
      status: Status.DEPRECATED, brief: L('Obsolete header', "Header obsoleto"),
      recommendation: L('Remove this header and rely on Content-Security-Policy.', "Rimuovere questo header e affidarsi a Content-Security-Policy."),
    })];
  }

  function checkExpectCt() {
    return [finding('Expect-CT', Severity.LOW, L('Expect-CT: deprecated header', "Expect-CT: header deprecato"), {
      sources: ['mdn-expectct', 'cs-expectct', 'shp-deprecated'],
      status: Status.DEPRECATED, brief: L('Obsolete, ignored by browsers', "Obsoleto, ignorato dai browser"),
      description: L('Only Chromium ever implemented this header, and it deprecated it in version 107 because it now enforces Certificate Transparency by default, so the header does nothing. OWASP recommends not using it, and Mozilla recommends removing it.', "Solo Chromium ha implementato questo header, e lo ha deprecato nella versione 107 perché ora applica Certificate Transparency in modo predefinito, quindi l'header non fa nulla. OWASP raccomanda di non usarlo, e Mozilla di rimuoverlo."),
      recommendation: L('Remove Expect-CT.', "Rimuovere Expect-CT."),
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
  // A <meta charset> in the page does not settle it: the header is what OWASP
  // asks for, and the only declaration the browser takes as certain.
  const CHARSET_META = L(' A <meta charset> in the page can also set the encoding, but only if it sits in the first 1024 bytes, and it is read from the page itself; the header is what the browser takes as certain before reading a byte of it.', " Anche un <meta charset> nella pagina può impostare la codifica, ma solo se si trova nei primi 1024 byte, e viene letto dalla pagina stessa; l'header è ciò che il browser considera certo prima di leggerne un solo byte.");
  const CHARSET_REC = L('Set Content-Type: text/html; charset=utf-8.', "Impostare Content-Type: text/html; charset=utf-8.");

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

  const CHARSET_RISK = L('With no charset in the header and none in the page, the browser guesses the encoding from the bytes. An attacker who can place a few bytes in the page, in a comment or a username, can steer that guess: a single ISO-2022-JP escape sequence is enough for Chrome and Firefox to decode the whole page as Japanese, where a backslash can turn into a yen sign and the escaping the server applied stops working. Correctly escaped output then becomes XSS.', "Senza charset nell'header né nella pagina, il browser indovina la codifica dai byte. Un attaccante che può inserire pochi byte nella pagina, in un commento o in uno username, può pilotare quella scelta: una sola sequenza di escape ISO-2022-JP basta a Chrome e Firefox per decodificare l'intera pagina come giapponese, dove un backslash può diventare il simbolo dello yen e l'escaping applicato dal server smette di funzionare. Un output correttamente escapato diventa allora XSS.");

  function checkContentType(value) {
    const H = 'Content-Type';
    const mime = extractMimeType(value);
    if (!mime || mime.essence !== 'text/html') {
      return [finding(H, Severity.OK, L(`Content-Type: ${mime ? mime.essence : `'${value}'`} (charset is checked on HTML only)`, `Content-Type: ${mime ? mime.essence : `'${value}'`} (il charset si controlla solo sull'HTML)`), { sources: ['cs-ct-charset'] })];
    }
    if (mime.charset === '') mime.charset = null;
    if (mime.charset !== null && isEncodingLabel(mime.charset)) {
      return [finding(H, Severity.OK, `Content-Type: text/html; charset=${mime.charset}`, { sources: ['cs-ct-charset', 'encoding-label'] })];
    }
    if (mime.charset !== null) {
      return [finding(H, Severity.LOW, L(`Content-Type: unrecognised charset '${mime.charset}'`, `Content-Type: charset non riconosciuto '${mime.charset}'`), {
        sources: ['encoding-label', 'html-charset-transport', 'html-charset-1024', 'cs-ct-charset', 'sonar-detect'],
        brief: L('Unrecognised charset, so browsers ignore it', "Charset non riconosciuto, quindi i browser lo ignorano"),
        description: L(`'${mime.charset}' is not an encoding name the WHATWG Encoding Standard defines, so browsers discard it and treat the page as if it declared no charset. ${CHARSET_RISK}${CHARSET_META}`, `'${mime.charset}' non è un nome di codifica definito dal WHATWG Encoding Standard, quindi i browser lo scartano e trattano la pagina come se non dichiarasse un charset. ${CHARSET_RISK}${CHARSET_META}`),
        recommendation: CHARSET_REC,
      })];
    }
    return [finding(H, Severity.LOW, L('Content-Type: text/html without a charset', "Content-Type: text/html senza charset"), {
      sources: ['cs-ct-charset', 'sonar-detect', 'html-charset-transport', 'html-charset-1024'],
      brief: L('No charset declared', "Nessun charset dichiarato"),
      description: CHARSET_RISK + CHARSET_META,
      recommendation: CHARSET_REC,
    })];
  }

  function checkXDnsPrefetchControl(value, ctx) {
    const H = 'X-DNS-Prefetch-Control';
    if (value.trim().toLowerCase() === 'off') return [finding(H, Severity.OK, 'X-DNS-Prefetch-Control: off', { sources: ['cs-xdns'] })];
    return [finding(H, ctx.absentSeverity, L(`X-DNS-Prefetch-Control: '${value}' (DNS prefetching enabled)`, `X-DNS-Prefetch-Control: '${value}' (DNS prefetching attivo)`), {
      sources: ['cs-xdns', 'bp-xdns-pii', 'bp-xdns-inj', 'cs-xdns-nonstd'],
      brief: L('DNS prefetching is not disabled', "Il DNS prefetching non è disattivato"),
      description: DNS_PREFETCH_TEXT,
      ...DNS_PREFETCH_CHECK,
    })];
  }

  // OWASP Cheat Sheet: off "if you do not control links on your website".
  // OWASP Secure Headers Project: add it to responses that "Return sensitive or
  // private content", or are "Prone to HTML injection". The check asks only for
  // what opens a channel: a link to another site, or an injection that can add
  // one. Personal data alone, or user content the page escapes, opens none (a
  // deviation noted in RULES.md).
  const DNS_PREFETCH_CHECK = check(L('Does the page have links (<a href>) to external sites (including links made from what users write), or an HTML injection?', "La pagina ha link (<a href>) verso siti esterni (compresi i link creati da ciò che scrivono gli utenti), oppure un'HTML injection?"), L('either', 'almeno una delle due'), L('neither', 'nessuna delle due'));

  const DNS_PREFETCH_TEXT = L('DNS prefetching resolves domains linked in the page before the user clicks. The DNS resolver learns every hostname the page links to (internal services, private subdomains, an admin panel the page references) whether or not the user navigates there. And an attacker with HTML injection can exfiltrate data through it: <link rel=dns-prefetch> resolves before any CSP directive can stop it, so a page whose CSP blocks scripts, images and connections still leaks data through DNS queries to a resolver the attacker controls. The header is non-standard and only some browsers honour it.', "Il DNS prefetching risolve i domini linkati nella pagina prima che l'utente clicchi. Il resolver DNS viene a sapere ogni nome host a cui la pagina rimanda (servizi interni, sottodomini privati, un pannello di amministrazione citato dalla pagina), che l'utente ci vada o no. E un attaccante con un'HTML injection può esfiltrare dati attraverso di esso: <link rel=dns-prefetch> risolve prima che qualsiasi direttiva CSP possa fermarlo, quindi una pagina la cui CSP blocca script, immagini e connessioni perde comunque dati tramite query DNS verso un resolver controllato dall'attaccante. L'header non è standard e solo alcuni browser lo rispettano.");

  function checkOriginAgentCluster(value, ctx) {
    const H = 'Origin-Agent-Cluster';
    const r = parseSfItem(value);
    if (r.ok && r.item[0].type === 'boolean') {
      if (r.item[0].value) return [finding(H, Severity.OK, L('Origin-Agent-Cluster: ?1 (origin-keyed agent cluster)', "Origin-Agent-Cluster: ?1 (agent cluster per origine)"), { sources: ['html-oac'] })];
      return [finding(H, ctx.absentSeverity, L('Origin-Agent-Cluster: ?0 opts out of origin keying', "Origin-Agent-Cluster: ?0 rinuncia all'isolamento per origine"), {
        brief: L('Origin keying is explicitly disabled', "L'isolamento per origine è disattivato esplicitamente"),
        description: L('?0 explicitly requests a site-keyed agent cluster, the setting that lets a page set document.domain: once it and a page on another subdomain of the same site both set it, each can read and change the other\'s DOM. Browsers are switching their default to origin-keyed (?1); where they have, as Chrome and Edge have since version 115, ?0 is what turns document.domain back on. Where the default is still site-keyed, ?0 changes nothing today, but keeps the page on the old behaviour once the default changes.', "?0 chiede esplicitamente un agent cluster per sito, l'impostazione che permette a una pagina di modificare document.domain: quando lei e una pagina su un altro sottodominio dello stesso sito lo modificano entrambe, ognuna può leggere e modificare il DOM dell'altra. I browser stanno passando a un valore predefinito per origine (?1); dove lo hanno fatto, come Chrome ed Edge dalla versione 115, ?0 è ciò che riattiva document.domain. Dove il valore predefinito è ancora per sito, oggi ?0 non cambia nulla, ma mantiene la pagina sul vecchio comportamento quando il valore predefinito cambierà."),
        recommendation: L('Set Origin-Agent-Cluster: ?1, and replace any document.domain use with postMessage.', "Impostare Origin-Agent-Cluster: ?1, e sostituire ogni uso di document.domain con postMessage."),
        sources: ['mdn-oac-site', 'mdn-oac-default', 'chrome-docdomain-opt-out', 'chrome-docdomain-115', 'mdn-docdomain-shared'],
      })];
    }
    return [finding(H, ctx.absentSeverity, L(`Origin-Agent-Cluster: unrecognized value '${value}', ignored`, `Origin-Agent-Cluster: valore non riconosciuto '${value}', ignorato`), {
      sources: ['html-oac', 'rfc9651-fail'],
      brief: L('Invalid value, so browsers ignore the header', "Valore non valido, quindi i browser ignorano l'header"),
      description: L('The value must be a structured-field boolean: ?1 or ?0. Anything else is ignored and the browser applies its default.', "Il valore deve essere un booleano structured field: ?1 o ?0. Qualsiasi altra cosa viene ignorata e il browser applica il suo valore predefinito."),
      recommendation: L('Set Origin-Agent-Cluster: ?1', "Impostare Origin-Agent-Cluster: ?1"),
    })];
  }

  // Shared with correlations.js, which asks the same with credentials.
  const REFLECTION_REPLAY = L('Replay the request with the header Origin: https://attacker.example, then with origins that try to slip past the server\'s check (see the PortSwigger URL validation bypass cheat sheet in Sources).', "Ripetere la richiesta con l'header Origin: https://attacker.example, poi con origini che cercano di aggirare il controllo del server (vedi la URL validation bypass cheat sheet di PortSwigger nelle Fonti).");

  function checkAcao(value) {
    const H = 'Access-Control-Allow-Origin';
    const n = value.trim();
    if (n === '*') {
      return [finding(H, Severity.LOW, 'Access-Control-Allow-Origin: * (wildcard)', {
        sources: ['asvs-3.4.2-star', 'cs-acao-public', 'bp-cors-public', 'obs-cors-public'],
        brief: L('Any origin can read the response', "Qualsiasi origine può leggere la risposta"),
        description: L('Any site can read this response. That costs nothing if the endpoint is genuinely public, which is what the wildcard is for. It matters when the endpoint is reachable by a victim\'s browser but not by an attacker\'s server: an internal API, a service on localhost, a device admin page, anything authorised by network or IP rather than by credentials. Without the wildcard a browser sends such a request but refuses to hand the response to the calling page; with it, an attacker\'s page reads the answer through the browser of whoever can reach the endpoint.', "Qualsiasi sito può leggere questa risposta. Non costa nulla se l'endpoint è davvero pubblico, che è lo scopo del wildcard. Conta quando l'endpoint è raggiungibile dal browser di una vittima ma non dal server di un attaccante: un'API interna, un servizio su localhost, la pagina di amministrazione di un dispositivo, qualsiasi cosa autorizzata in base alla rete o all'IP invece che alle credenziali. Senza il wildcard il browser invia la richiesta ma si rifiuta di consegnare la risposta alla pagina chiamante; con il wildcard, la pagina di un attaccante legge la risposta attraverso il browser di chiunque possa raggiungere l'endpoint."),
        ...check(L('Is this endpoint reachable only from certain networks or addresses (for example, an internal network, a VPN, an IP allowlist)?', "Questo endpoint è raggiungibile solo da certe reti o indirizzi (per esempio, una rete interna, una VPN, un'allowlist di IP)?"), L('yes', 'sì'), L('no, anyone on the internet can reach it', "no, chiunque su internet può raggiungerlo")),
      })];
    }
    if (n !== 'null' && n.toLowerCase() === 'null') {
      return [finding(H, Severity.OK, L(`Access-Control-Allow-Origin: '${n}' matches no origin`, `Access-Control-Allow-Origin: '${n}' non corrisponde a nessuna origine`), {
        sources: ['fetch-cors-origin'],
        status: Status.NONE,
        description: L('Fetch compares this value with the requesting origin byte for byte, and the opaque origin serialises as lowercase null. Written any other way it matches nothing, so no site is granted access.', "Fetch confronta questo valore con l'origine della richiesta byte per byte, e l'origine opaca si serializza come null minuscolo. Scritto in qualsiasi altro modo non corrisponde a nulla, quindi nessun sito ottiene l'accesso."),
        recommendation: L('Remove the header, or send the single origin that needs access.', "Rimuovere l'header, oppure inviare la singola origine che ha bisogno di accesso."),
      })];
    }
    if (n === 'null') {
      return [finding(H, Severity.MEDIUM, 'Access-Control-Allow-Origin: null', {
        sources: ['mdn-acao-null', 'zap-40040-2', 'zap-cors-risk'],
        brief: L('Allows the null origin', "Consente l'origine null"),
        description: L('The null origin is not a trusted party: any page can obtain it through a sandboxed iframe, a data: URL or a cross-origin redirect. Unlike the wildcard, it is a concrete origin, so browsers do send credentials with it when Access-Control-Allow-Credentials is true, which lets an attacker read authenticated responses. It usually comes from reflecting the Origin header.', "L'origine null non è una parte fidata: qualsiasi pagina può ottenerla con un iframe sandbox, un URL data: o un redirect cross-origin. A differenza del wildcard è un'origine concreta, quindi i browser inviano le credenziali quando Access-Control-Allow-Credentials è true, e questo permette a un attaccante di leggere le risposte autenticate. Di solito nasce dal rimandare indietro l'header Origin."),
        recommendation: L('Never allowlist null. Echo only origins from a known list.', "Non autorizzare mai null. Rimandare solo origini prese da un elenco noto."),
      })];
    }
    if (n.includes(',')) {
      return [finding(H, Severity.OK, L(`Access-Control-Allow-Origin lists more than one origin: '${n}'`, `Access-Control-Allow-Origin elenca più di un'origine: '${n}'`), {
        sources: ['fetch-cors-origin'],
        status: Status.NONE,
        description: L('The header carries exactly one origin, or *, or null. A list never matches the requesting origin, so the CORS check fails and no site gets access, including the ones it was meant for. A list usually means two components are both setting the header, typically the application and a proxy in front of it.', "L'header contiene esattamente un'origine, oppure *, oppure null. Un elenco non corrisponde mai all'origine della richiesta, quindi il controllo CORS fallisce e nessun sito ottiene l'accesso, nemmeno quelli a cui era destinato. Un elenco di solito significa che due componenti impostano entrambi l'header, tipicamente l'applicazione e un proxy davanti a essa."),
        recommendation: L('Send a single origin, picked per request from an allowlist.', "Inviare una singola origine, scelta a ogni richiesta da un'allowlist."),
      })];
    }
    if (n.toLowerCase().startsWith('http://')) {
      return [finding(H, Severity.LOW, L(`Access-Control-Allow-Origin allows a plaintext origin: '${n}'`, `Access-Control-Allow-Origin consente un'origine in chiaro: '${n}'`), {
        sources: ['ps-cors-http', 'zap-cors-risk'],
        brief: L('Allows a plain-HTTP origin', "Consente un'origine in HTTP in chiaro"),
        description: L('The allowed origin is not protected by TLS, so anyone able to tamper with traffic to it can impersonate it and read whatever this endpoint returns to it. A localhost origin here usually means a development configuration reached production.', "L'origine consentita non è protetta da TLS, quindi chiunque possa manomettere il traffico verso di essa può impersonarla e leggere ciò che questo endpoint le restituisce. Un'origine localhost qui di solito significa che una configurazione di sviluppo è arrivata in produzione."),
        recommendation: L('Allow an https:// origin instead.', "Consentire invece un'origine https://."),
      })];
    }
    return [finding(H, Severity.LOW, L(`Access-Control-Allow-Origin: single origin ('${n}'), an allowlist or a mirror`, `Access-Control-Allow-Origin: una sola origine ('${n}'), un'allowlist o un mirror`), {
      sources: ['asvs-3.4.2', 'bp-cors-mirror', 'cs-acao-rec', 'ps-url-bypass'],
      brief: L('Single origin, possibly reflected', "Una sola origine, forse riflessa"),
      description: L('One origin is authorised, which is how CORS is meant to be used. But a server that copies the request\'s Origin header into the response produces exactly this, and then the authorised origin is whichever one asked: any site reads what this endpoint returns, the same as *.', "È autorizzata un'origine, che è il modo in cui il CORS va usato. Ma un server che copia nella risposta l'header Origin della richiesta produce esattamente questo, e allora l'origine autorizzata è quella che ha fatto la richiesta: qualsiasi sito legge ciò che questo endpoint restituisce, come con *."),
      ...check(REFLECTION_REPLAY, L('the response allows any of these origins in Access-Control-Allow-Origin', "la risposta consente una qualsiasi di queste origini in Access-Control-Allow-Origin"), L(`every attempt still gets ${n}, or no Access-Control-Allow-Origin`, `ogni tentativo riceve ancora ${n}, oppure nessun Access-Control-Allow-Origin`)),
    })];
  }

  function checkAcac(value) {
    // "Send the cookies" says nothing without knowing to whom, so the verdict
    // is reached in correlations.js, which also sees the allowed origin.
    const H = 'Access-Control-Allow-Credentials';
    if (value.trim() === 'true') {
      return [finding(H, Severity.OK, 'Access-Control-Allow-Credentials: true', {
        sources: ['fetch-cors-cred'],
        description: L('Assessed together with Access-Control-Allow-Origin.', "Valutato insieme ad Access-Control-Allow-Origin."),
      })];
    }
    return [finding(H, Severity.OK, L(`Access-Control-Allow-Credentials: '${value.trim()}' (credentials not exposed)`, `Access-Control-Allow-Credentials: '${value.trim()}' (credenziali non esposte)`), {
      sources: ['fetch-cors-cred'],
      description: L('Fetch only honours the exact, case-sensitive value true; anything else leaves credentialed responses unreadable.', "Fetch rispetta solo il valore esatto true, distinguendo maiuscole e minuscole; qualsiasi altra cosa lascia illeggibili le risposte con credenziali."),
    })];
  }

  function checkServiceWorkerAllowed(value) {
    const H = 'Service-Worker-Allowed';
    const n = value.trim();
    if (n === '/') {
      return [finding(H, Severity.LOW, L('Service-Worker-Allowed: / (full site scope)', "Service-Worker-Allowed: / (ambito su tutto il sito)"), {
        sources: ['sw-allowed'],
        brief: L('Service worker scope covers the whole site', "L'ambito del service worker copre tutto il sito"),
        description: L('A service worker registered from this script can intercept every request on the origin. Whoever can control that script (through an upload, a JSONP endpoint or a compromised dependency) controls every page of the site, persistently.', "Un service worker registrato da questo script può intercettare ogni richiesta sull'origine. Chi riesce a controllare quello script (tramite un upload, un endpoint JSONP o una dipendenza compromessa) controlla ogni pagina del sito, in modo persistente."),
        ...check(L('Is this the site\'s own service worker, meant to control the whole site?', "È il service worker del sito, pensato per controllare tutto il sito?"), L('no (for example, the script is in a path others can write to, such as user uploads, or it only needs part of the site)', "no (per esempio, lo script si trova in un percorso dove altri possono scrivere, come gli upload degli utenti, oppure gli basta una parte del sito)"), L('yes', 'sì')),
      })];
    }
    return [finding(H, Severity.OK, `Service-Worker-Allowed: '${n}'`, {
      sources: ['sw-allowed'],
      status: Status.NONE,
      description: L('The service worker scope is extended beyond the script\'s own path. Check the scope is what the worker needs.', "L'ambito del service worker è esteso oltre il percorso dello script. Verificare che l'ambito sia quello di cui il worker ha bisogno."),
    })];
  }

  function checkContentDisposition(value) {
    const H = 'Content-Disposition';
    const type = value.split(';')[0].trim().toLowerCase();
    if (type === 'attachment') return [finding(H, Severity.OK, L('Content-Disposition: attachment (prevents inline rendering)', "Content-Disposition: attachment (impedisce la visualizzazione inline)"), { sources: ['cs-download', 'bp-upload'] })];
    if (type === 'inline') {
      return [finding(H, Severity.OK, 'Content-Disposition: inline', {
        sources: ['cs-download', 'bp-upload'],
        description: L('The browser renders the content inline. For user-supplied files, attachment (together with nosniff) keeps them from rendering as part of the site.', "Il browser visualizza il contenuto inline. Per i file forniti dagli utenti, attachment (insieme a nosniff) impedisce che vengano visualizzati come parte del sito."),
      })];
    }
    return [finding(H, Severity.OK, L(`Content-Disposition: unrecognized type '${type}'`, `Content-Disposition: tipo non riconosciuto '${type}'`), {
      sources: ['rfc6266-unknown'],
      status: Status.NONE,
      description: L('RFC 6266 says an unknown disposition type is handled as attachment, but behaviour has not always been consistent.', "RFC 6266 dice che un tipo di disposition sconosciuto va trattato come attachment, ma il comportamento non è sempre stato coerente."),
    })];
  }

  function checkPragma(value) {
    return [finding('Pragma', Severity.OK, value.trim().toLowerCase() === 'no-cache'
      ? L('Pragma: no-cache (HTTP/1.0 legacy header)', "Pragma: no-cache (header legacy HTTP/1.0)") : L(`Pragma: '${value}' (legacy HTTP/1.0 header)`, `Pragma: '${value}' (header legacy HTTP/1.0)`), {
      sources: ['rfc9111-pragma', 'shp-deprecated'],
      description: L('Pragma is a legacy HTTP/1.0 header that RFC 9111 has deprecated; Cache-Control is what caches act on. Its presence is harmless.', "Pragma è un header legacy HTTP/1.0 deprecato da RFC 9111; le cache agiscono su Cache-Control. La sua presenza è innocua."),
    })];
  }

  function checkExpires(value) {
    if (['0', '-1'].includes(value.trim())) return [finding('Expires', Severity.OK, L(`Expires: ${value.trim()} (already expired)`, `Expires: ${value.trim()} (già scaduto)`))];
    return [finding('Expires', Severity.OK, L(`Expires: '${value}' (legacy freshness header)`, `Expires: '${value}' (header legacy di freschezza)`), {
      sources: ['rfc9111-expires'],
      description: L('Expires is ignored whenever Cache-Control carries max-age or s-maxage; its presence is harmless.', "Expires viene ignorato ogni volta che Cache-Control contiene max-age o s-maxage; la sua presenza è innocua."),
    })];
  }

  function checkEtag(value) {
    return [finding('ETag', Severity.OK, value.trim().startsWith('W/') ? L('ETag: weak validator present', "ETag: presente un validatore debole") : L('ETag: strong validator present', "ETag: presente un validatore forte"))];
  }

  function checkXDownloadOptions(value) {
    const H = 'X-Download-Options';
    if (value.trim().toLowerCase() === 'noopen') {
      return [finding(H, Severity.LOW, L('X-Download-Options: noopen (obsolete Internet Explorer header)', "X-Download-Options: noopen (header obsoleto di Internet Explorer)"), {
        sources: ['ie8-xdo', 'ie-end'],
        status: Status.DEPRECATED, brief: L('Obsolete Internet Explorer header', "Header obsoleto di Internet Explorer"),
        description: L('noopen stopped Internet Explorer from opening a download in the site\'s context. Internet Explorer 11 reached end of support in 2022 and no current browser reads the header, so it does nothing. For downloads, Content-Disposition: attachment and nosniff are what apply.', "noopen impediva a Internet Explorer di aprire un download nel contesto del sito. Il supporto a Internet Explorer 11 è terminato nel 2022 e nessun browser attuale legge l'header, quindi non fa nulla. Per i download valgono Content-Disposition: attachment e nosniff."),
        recommendation: L('Remove X-Download-Options.', "Rimuovere X-Download-Options."),
      })];
    }
    return [finding(H, Severity.LOW, `X-Download-Options: '${value}'`, {
      sources: ['ie8-xdo', 'ie-end'],
      status: Status.DEPRECATED, brief: L('Obsolete Internet Explorer header with an invalid value', "Header obsoleto di Internet Explorer con un valore non valido"),
      description: L('The only defined value is noopen, and only Internet Explorer, retired in 2022, ever read it. This value was not valid even there, so the protection it suggests was never in force.', "L'unico valore definito è noopen, e solo Internet Explorer, dismesso nel 2022, lo ha mai letto. Questo valore non era valido nemmeno lì, quindi la protezione che suggerisce non è mai stata attiva."),
      recommendation: L('Remove X-Download-Options.', "Rimuovere X-Download-Options."),
    })];
  }

  // ---------------------------------------------------------------------------
  // Clear-Site-Data: W3C Clear Site Data §3.1 / §4.1
  // ---------------------------------------------------------------------------
  const CSD_TYPES = new Set(['"cache"', '"cookies"', '"storage"', '"executionContexts"', '"clientHints"', '"prefetchCache"', '"prerenderCache"']);
  const CSD_WILDCARD = '"*"';
  const CSD_EXPECTED = ['"cache"', '"cookies"', '"storage"'];
  const CSD_CHECK = check(L('Does this response end a session (for example, a logout, a password change, an account deletion)?', "Questa risposta chiude una sessione (per esempio, un logout, un cambio password, la cancellazione dell'account)?"), L('yes', 'sì'), L('no', 'no'));

  function checkClearSiteData(value) {
    const H = 'Clear-Site-Data';
    const declared = new Set(splitOutsideQuotes(value, ','));
    const known = new Set([...declared].filter((t) => CSD_TYPES.has(t) || t === CSD_WILDCARD));
    if (!known.size) {
      return [finding(H, Severity.LOW, L(`Clear-Site-Data: '${value}' clears nothing`, `Clear-Site-Data: '${value}' non cancella nulla`), {
        sources: ['csd-grammar', 'csd-unknown'],
        brief: L('Invalid values, so nothing is cleared', "Valori non validi, quindi non viene cancellato nulla"),
        description: L('Every value has to be a quoted string (the grammar is 1#( quoted-string )) and a browser compares each one with its quotes still attached, case-sensitively. None of these matches a type it knows, so the list it builds is empty and no data is removed. Writing * or cookies without quotes is the usual way to land here.', "Ogni valore deve essere una stringa tra virgolette (la grammatica è 1#( quoted-string )) e il browser confronta ciascuno con le virgolette incluse, distinguendo maiuscole e minuscole. Nessuno di questi corrisponde a un tipo che conosce, quindi l'elenco che costruisce è vuoto e nessun dato viene rimosso. Scrivere * o cookies senza virgolette è il modo più comune per arrivarci."),
        ...CSD_CHECK,
      })];
    }
    if (known.has(CSD_WILDCARD)) return [finding(H, Severity.OK, L('Clear-Site-Data: "*" (every type cleared)', "Clear-Site-Data: \"*\" (cancellati tutti i tipi)"), { sources: ['asvs-14.3.1'] })];
    const missing = CSD_EXPECTED.filter((t) => !known.has(t));
    if (missing.length) {
      return [finding(H, Severity.LOW, L(`Clear-Site-Data: missing directives: ${missing.join(', ')}`, `Clear-Site-Data: direttive mancanti: ${missing.join(', ')}`), {
        sources: ['csd-subset', 'bp-csd-time', 'asvs-14.3.1'],
        brief: L(`${missing.join(', ')} not cleared`, `${missing.join(', ')} non cancellati`),
        description: L('Some types are cleared and these are not. Leaving one out can be deliberate: the specification has an example of a site clearing a subset on purpose, because sweeping every subdomain does damage of its own, and OWASP notes the header costs the browser additional processing time.', "Alcuni tipi vengono cancellati e questi no. Escluderne uno può essere voluto: la specifica ha l'esempio di un sito che cancella di proposito solo una parte, perché ripulire ogni sottodominio fa danni a sua volta, e OWASP nota che l'header costa al browser tempo di elaborazione in più."),
        ...check(L('Does this response end a session, and does the application keep anything in the types it leaves out (for example, a token in localStorage when "storage" is missing)?', "Questa risposta chiude una sessione, e l'applicazione tiene qualcosa nei tipi esclusi (per esempio, un token in localStorage quando manca \"storage\")?"), L('yes to both', "sì a entrambe"), L('it does not end a session, or nothing the application relies on is in those types', "non chiude una sessione, oppure nei tipi esclusi non c'è nulla su cui l'applicazione si basa")),
      })];
    }
    return [finding(H, Severity.OK, L('Clear-Site-Data: cache, cookies and storage cleared', "Clear-Site-Data: cache, cookie e storage cancellati"), { sources: ['asvs-14.3.1', 'bp-csd-logout'] })];
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
    'content-security-policy': L("Add a CSP. A strict starting point: Content-Security-Policy: script-src 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'", "Aggiungere una CSP. Un punto di partenza rigoroso: Content-Security-Policy: script-src 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"),
    'strict-transport-security': 'Strict-Transport-Security: max-age=63072000; includeSubDomains',
    'x-frame-options': L("X-Frame-Options: DENY (and Content-Security-Policy: frame-ancestors 'none')", "X-Frame-Options: DENY (e Content-Security-Policy: frame-ancestors 'none')"),
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
  const MISSING_CHECKS = {
    'cache-control': CACHE_CHECK,
    'clear-site-data': CSD_CHECK,
    'x-dns-prefetch-control': DNS_PREFETCH_CHECK,
  };

  const MISSING_DESCRIPTIONS = {
    'content-security-policy': L('Without a policy, nothing limits what an HTML injection can do: inline scripts, scripts from any origin, plugins and form submissions are all allowed. CSP is the main defence-in-depth control against XSS.', "Senza una policy, nulla limita ciò che un'HTML injection può fare: script inline, script da qualsiasi origine, plugin e invii di form sono tutti consentiti. La CSP è il principale controllo di difesa in profondità contro l'XSS."),
    'strict-transport-security': L('Without HSTS, a user who types the domain, or follows an http:// link, makes the first request over plain HTTP, where anyone on the network path can strip the upgrade to HTTPS and intercept the session.', "Senza HSTS, un utente che digita il dominio, o segue un link http://, fa la prima richiesta in HTTP in chiaro, dove chiunque sul percorso di rete può impedire il passaggio a HTTPS e intercettare la sessione."),
    'x-frame-options': L('Without X-Frame-Options or a CSP frame-ancestors directive, any site can embed this page in a frame and trick the user into clicking it (clickjacking).', "Senza X-Frame-Options né una direttiva CSP frame-ancestors, qualsiasi sito può incorporare questa pagina in un frame e indurre l'utente a cliccarci (clickjacking)."),
    'x-content-type-options': L('Without nosniff the browser may ignore the declared Content-Type and guess from the bytes, so user-supplied content served as text can be run as HTML or script.', "Senza nosniff il browser può ignorare il Content-Type dichiarato e indovinare dai byte, quindi contenuti forniti dagli utenti e serviti come testo possono essere eseguiti come HTML o script."),
    'cross-origin-opener-policy': L('Without COOP, a cross-origin page that opens this one (or that this one opens) shares its browsing context group and keeps a window reference, which is the channel XS-Leak attacks probe through.', "Senza COOP, una pagina cross-origin che apre questa (o che questa apre) ne condivide il browsing context group e mantiene un riferimento alla finestra, che è il canale attraverso cui sondano gli attacchi XS-Leak."),
    'referrer-policy': L('With no policy of its own, the response inherits whatever default the browser applies, something the site does not control and that has already changed once. Current browsers use strict-origin-when-cross-origin, which sends no more than the origin; older ones send the complete URL, path and query string included, to every third party reached over HTTPS. Stating the policy makes every browser behave the same.', "Senza una policy propria, la risposta eredita il valore predefinito del browser, che il sito non controlla e che è già cambiato una volta. I browser attuali usano strict-origin-when-cross-origin, che non invia più dell'origine; quelli più vecchi inviano l'URL completo, percorso e query string compresi, a ogni terza parte raggiunta in HTTPS. Dichiarare la policy fa comportare allo stesso modo tutti i browser."),
    'cache-control': L('With no explicit caching instruction, browsers and intermediaries fall back to heuristic caching and may keep this response on disk. That is harmless for a static asset. It is a problem for a response meant only for signed-in users, which can then be read from the cache after logout or by the next person to use a shared machine.', "Senza un'istruzione di cache esplicita, browser e intermediari ricadono sulla cache euristica e possono conservare questa risposta su disco. È innocuo per un asset statico. È un problema per una risposta riservata agli utenti autenticati, che può essere letta dalla cache dopo il logout o dalla persona successiva su un computer condiviso."),
    'clear-site-data': L('This response clears no site data. On almost every response that is the right outcome: the header exists to end things, not to be present.', "Questa risposta non cancella dati del sito. Su quasi ogni risposta è il risultato corretto: l'header serve a chiudere qualcosa, non a essere presente."),
    'permissions-policy': L(`Every feature stays at the allowlist a browser applies by default, which leaves two things open. A cross-origin document embedded in this page can use the features a browser allows to every origin (${[...PP_TRACKING].sort().join(', ')}) which is tracking and fingerprinting surface. And script that achieves execution on this origin can raise the permission prompt for ${PP_ONE_CLICK.join(', ')}: the prompt names the site, never the code that asked, so one click from a user who cannot tell the two apart is the whole interaction. A policy is the only thing that removes the prompt.`, `Ogni funzionalità resta all'allowlist che il browser applica per impostazione predefinita, e questo lascia aperte due cose. Un documento cross-origin incorporato in questa pagina può usare le funzionalità che il browser consente a ogni origine (${[...PP_TRACKING].sort().join(', ')}), che sono superficie di tracciamento e fingerprinting. E uno script che riesce a eseguire su questa origine può far comparire la richiesta di autorizzazione per ${PP_ONE_CLICK.join(', ')}: la richiesta indica il sito, mai il codice che l'ha fatta, quindi un clic da parte di un utente che non può distinguere i due è tutta l'interazione. Solo una policy elimina la richiesta.`),
    'x-dns-prefetch-control': DNS_PREFETCH_TEXT,
    'origin-agent-cluster': L('Without it the browser decides whether this page shares an agent cluster with other same-site origins. ?1 asks for origin-keyed isolation, which also disables the document.domain relaxation for this origin.', "Senza questo header il browser decide se questa pagina condivide un agent cluster con altre origini dello stesso sito. ?1 chiede l'isolamento per origine, che disattiva anche il rilassamento di document.domain per questa origine."),
    'x-permitted-cross-domain-policies': L('Without this header, Adobe clients still look for a policy file at the site root (/crossdomain.xml) and honour what it grants; other policy files on the site need a meta-policy of by-content-type or all. Setting none makes the restriction explicit: no policy file on the origin, the root one included, can grant cross-domain access.', "Senza questo header, i client Adobe cercano comunque un file di policy nella radice del sito (/crossdomain.xml) e rispettano ciò che concede; gli altri file di policy sul sito richiedono una meta-policy by-content-type o all. Impostare none rende esplicita la restrizione: nessun file di policy sull'origine, compreso quello nella radice, può concedere accesso cross-domain."),
    'cross-origin-embedder-policy': L('Without COEP the document cannot be cross-origin isolated, which only matters if it needs SharedArrayBuffer or high-resolution timers. Nothing is exposed by its absence.', "Senza COEP il documento non può essere isolato cross-origin, il che conta solo se ha bisogno di SharedArrayBuffer o di timer ad alta risoluzione. La sua assenza non espone nulla."),
    'cross-origin-resource-policy': L('Without CORP any site can embed this resource in no-cors mode, pulling it into that site\'s process.', "Senza CORP qualsiasi sito può incorporare questa risorsa in modalità no-cors, portandola nel processo di quel sito."),
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
    'clear-site-data': ['asvs-14.3.1', 'bp-csd-logout', 'session-csd', 'csd-logout'],
    'x-dns-prefetch-control': ['cs-xdns', 'bp-xdns-pii', 'bp-xdns-inj', 'cs-xdns-nonstd'],
    'origin-agent-cluster': ['html-oac', 'mdn-docdomain-oac', 'mdn-docdomain-shared', 'chrome-docdomain-115'],
  };

  const PRAGMA_INSTEAD = L('The response does carry Pragma, but Pragma does not stand in for Cache-Control: its meaning in a response was never specified, so caches and browsers are free to ignore it.', "La risposta contiene Pragma, ma Pragma non sostituisce Cache-Control: il suo significato in una risposta non è mai stato specificato, quindi cache e browser sono liberi di ignorarlo.");

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
    'content-security-policy': L('No defence in depth against XSS', "Nessuna difesa in profondità contro l'XSS"),
    'strict-transport-security': L('HTTPS is not enforced', "HTTPS non è imposto"),
    'x-frame-options': L('Framing is not restricted by this header', "Il framing non è ristretto da questo header"),
    'x-content-type-options': L('MIME sniffing is not disabled', "Il MIME sniffing non è disattivato"),
    'cross-origin-opener-policy': L('Cross-origin windows are not isolated', "Le finestre cross-origin non sono isolate"),
    'permissions-policy': L('Browser features are not restricted', "Le funzionalità del browser non sono soggette a restrizioni"),
    'referrer-policy': L('Referrer leakage depends on browser defaults', "L'eventuale esposizione del Referer dipende dalle impostazioni predefinite del browser"),
    'cross-origin-embedder-policy': L('No cross-origin isolation', "Nessun isolamento cross-origin"),
    'cross-origin-resource-policy': L('Any site can load the resource', "Qualsiasi sito può caricare la risorsa"),
    'x-permitted-cross-domain-policies': L('Cross-domain policy files are not restricted', "I file di policy cross-domain non sono ristretti"),
    'cache-control': L('Caching is not controlled', "La cache non è controllata"),
    'clear-site-data': L('Session data is not cleared', "I dati di sessione non vengono cancellati"),
    'x-dns-prefetch-control': L('DNS prefetching is not disabled', "Il DNS prefetching non è disattivato"),
    'origin-agent-cluster': L('Origin keying is not requested', "L'isolamento per origine non è richiesto"),
  };

  // ---------------------------------------------------------------------------
  // REST API mode. The user says the response is a call to an API read by a
  // browser; nothing here guesses it. The reference is the OWASP REST Security
  // Cheat Sheet: six headers for every API response, three more as defence in
  // depth for a response that might be rendered as HTML. Headers outside it
  // keep their page rules, except those that only act on a document.
  // ---------------------------------------------------------------------------
  // The cheat sheet's defence-in-depth headers only act on a response rendered
  // as HTML. In this mode the response is an API response, so a gap in them is
  // explained, never graded: asking whether the API might return HTML would
  // reopen what the mode already settles.
  const API_DEFENCE_SOURCES = ['rest-dd', 'rest-dd-never'];

  function apiDefenceNote(header, title, what, setting, sources) {
    return finding(header, Severity.OK, title, {
      status: Status.NONE,
      description: L(`${what} The OWASP REST Security Cheat Sheet lists this header as defence in depth for responses rendered as HTML, and an API response is not one, so there is nothing to report. ${setting} costs nothing if you want it anyway.`, `${what} L'OWASP REST Security Cheat Sheet elenca questo header come difesa in profondità per le risposte visualizzate come HTML, e una risposta di un'API non lo è, quindi non c'è nulla da riportare. ${setting} non costa nulla, se lo si vuole comunque.`),
      sources: [...sources, ...API_DEFENCE_SOURCES],
    });
  }
  const API_CT_REC = L('Declare the type the API returns, such as Content-Type: application/json', "Dichiarare il tipo che l'API restituisce, per esempio Content-Type: application/json");
  // MIME Sniffing: the JavaScript MIME types.
  const JS_TYPES = new Set(['application/ecmascript', 'application/javascript', 'application/x-ecmascript', 'application/x-javascript',
    'text/ecmascript', 'text/javascript', 'text/javascript1.0', 'text/javascript1.1', 'text/javascript1.2', 'text/javascript1.3',
    'text/javascript1.4', 'text/javascript1.5', 'text/jscript', 'text/livescript', 'text/x-ecmascript', 'text/x-javascript']);

  const apiTitle = (header, empty) => (empty ? L(`${header}: present but empty`, `${header}: presente ma vuoto`) : L(`Missing ${header}`, `${header} mancante`));
  const apiStatus = (empty) => (empty ? Status.MISCONFIGURED : Status.MISSING);

  function apiCsp(value, empty) {
    const H = 'Content-Security-Policy';
    const view = value === null ? { frameNone: false, frameRestricted: false, frameAncestors: null, defaultNone: false, defaultSrc: null } : HL.csp.apiView(value);
    const out = [];
    if (view.frameNone) {
      out.push(finding(H, Severity.OK, L("CSP: frame-ancestors 'none' (no site can frame this response)", "CSP: frame-ancestors 'none' (nessun sito può incorniciare questa risposta)"), { sources: ['rest-fa'] }));
    } else {
      const restricted = view.frameRestricted;
      const title = value === null ? apiTitle(H, empty)
        : view.frameAncestors === null ? L("CSP: frame-ancestors is not set, so any site can frame this response", "CSP: frame-ancestors non è impostata, quindi qualsiasi sito può incorniciare questa risposta")
          : L(`CSP: frame-ancestors ${view.frameAncestors} lets ${restricted ? 'the sites it names' : 'any site'} frame this response`, `CSP: frame-ancestors ${view.frameAncestors} permette a ${restricted ? 'i siti che indica' : 'qualsiasi sito'} di incorniciare questa risposta`);
      out.push(finding(H, Severity.LOW, title, {
        status: value === null ? apiStatus(empty) : view.frameAncestors === null ? Status.MISSING : Status.MISCONFIGURED,
        brief: restricted ? L("frame-ancestors is not 'none'", "frame-ancestors non è 'none'") : L('Any site can frame the response', "Qualsiasi sito può incorniciare la risposta"),
        description: L(`${restricted ? 'The sites this directive names' : 'Any site'} can load this API response in a frame. A page that frames it can lead a signed-in user to drag the data shown in it into a field the page controls (drag-and-drop clickjacking). An API response never needs to be framed, so frame-ancestors 'none' costs nothing.`, `${restricted ? 'I siti indicati da questa direttiva' : 'Qualsiasi sito'} può caricare in un frame questa risposta dell'API. Una pagina che la incornicia può indurre un utente autenticato a trascinare i dati mostrati in un campo controllato dalla pagina (clickjacking con drag-and-drop). Una risposta di un'API non ha mai bisogno di essere incorniciata, quindi frame-ancestors 'none' non costa nulla.`),
        recommendation: "Content-Security-Policy: frame-ancestors 'none'",
        sources: ['rest-fa', 'rest-fa-dnd', 'rest-scope', 'asvs-3.4.6'],
      }));
    }
    if (view.defaultNone) {
      out.push(finding(H, Severity.OK, L("CSP: default-src 'none' (the response may load nothing)", "CSP: default-src 'none' (la risposta non può caricare nulla)"), { sources: ['rest-csp-dd'] }));
    } else {
      out.push(apiDefenceNote(H,
        view.defaultSrc === null ? L("CSP: default-src 'none' is not set (not needed on an API response)", "CSP: default-src 'none' non è impostata (non necessaria su una risposta di un'API)") : L(`CSP: default-src ${view.defaultSrc} instead of 'none' (not needed on an API response)`, `CSP: default-src ${view.defaultSrc} invece di 'none' (non necessaria su una risposta di un'API)`),
        L("default-src 'none' stops a response rendered as HTML from loading or running anything.", "default-src 'none' impedisce a una risposta visualizzata come HTML di caricare o eseguire qualsiasi cosa."),
        "Content-Security-Policy: default-src 'none'", ['rest-csp-dd']));
    }
    return out;
  }

  function apiXFrameOptions(value, empty, ctx, framingByCsp) {
    const H = 'X-Frame-Options';
    if (value === null) {
      return [finding(H, Severity.LOW, apiTitle(H, empty), {
        status: apiStatus(empty), brief: framingByCsp ? L('Only CSP frame-ancestors restricts framing', "Solo frame-ancestors della CSP restringe il framing") : L('Framing is not restricted by this header', "Il framing non è ristretto da questo header"),
        description: framingByCsp
          ? L('CSP frame-ancestors already restricts framing in every current browser. X-Frame-Options: DENY is the legacy fallback the OWASP REST Security Cheat Sheet still recommends, for browsers without CSP Level 2.', "frame-ancestors della CSP restringe già il framing in ogni browser attuale. X-Frame-Options: DENY è il fallback legacy che l'OWASP REST Security Cheat Sheet raccomanda ancora, per i browser senza CSP Level 2.")
          : L('Neither this header nor CSP frame-ancestors stops another site framing this API response. The OWASP REST Security Cheat Sheet recommends X-Frame-Options: DENY next to frame-ancestors \'none\', for browsers without CSP Level 2.', "Né questo header né frame-ancestors della CSP impediscono a un altro sito di incorniciare questa risposta dell'API. L'OWASP REST Security Cheat Sheet raccomanda X-Frame-Options: DENY accanto a frame-ancestors 'none', per i browser senza CSP Level 2."),
        recommendation: 'X-Frame-Options: DENY',
        sources: ['rest-xfo', 'rest-fa'],
      })];
    }
    const page = checkXFrameOptions(value, ctx);
    if (page.length === 1 && page[0].title.startsWith('X-Frame-Options: SAMEORIGIN')) {
      return [finding(H, Severity.LOW, L('X-Frame-Options: SAMEORIGIN instead of DENY', "X-Frame-Options: SAMEORIGIN invece di DENY"), {
        status: Status.MISCONFIGURED, brief: L('SAMEORIGIN instead of DENY', "SAMEORIGIN invece di DENY"),
        description: L('SAMEORIGIN still lets a page on this origin frame the response. An API response never needs to be framed, and DENY is the value the OWASP REST Security Cheat Sheet recommends.', "SAMEORIGIN permette comunque a una pagina di questa origine di incorniciare la risposta. Una risposta di un'API non ha mai bisogno di essere incorniciata, e DENY è il valore che l'OWASP REST Security Cheat Sheet raccomanda."),
        recommendation: 'X-Frame-Options: DENY',
        sources: ['rest-xfo', 'rest-fa'],
      })];
    }
    return page;
  }

  const JS_TYPE_RISK = L('The response declares itself a script. Another site can include it with <script src>, and the browser runs it there with the user\'s cookies: data the script holds can be read by that site (Cross-Site Script Inclusion). A JSON type is not run that way.', "La risposta si dichiara uno script. Un altro sito può includerla con <script src>, e il browser la esegue lì con i cookie dell'utente: i dati contenuti nello script possono essere letti da quel sito (Cross-Site Script Inclusion). Un tipo JSON non viene eseguito in quel modo.");

  /**
   * What the pasted body plainly is: 'json' for an object or array that parses
   * as JSON, 'html' for a document that opens with a doctype or <html>, null
   * for anything else (no body, a fragment, compressed bytes). Only these two
   * answers settle a check; anything less certain leaves it to confirm.
   */
  function bodyKind(body) {
    const text = String(body || '').replace(/^\uFEFF/, '').trim();
    if (/^[[{]/.test(text)) {
      try { JSON.parse(text); return 'json'; } catch (_) { return null; }
    }
    if (/^<!doctype\s+html[\s>]/i.test(text) || /^<html[\s>]/i.test(text)) return 'html';
    return null;
  }

  function apiContentType(value, empty, ctx) {
    const H = 'Content-Type';
    const kind = bodyKind(ctx && ctx.body);
    if (value === null) {
      return [finding(H, Severity.LOW, apiTitle(H, empty), {
        status: apiStatus(empty), brief: L('Browsers may guess the content type', "I browser possono indovinare il tipo di contenuto"),
        description: L('Without a Content-Type, a browser may guess the type from the bytes and read this API response as HTML or script (MIME sniffing). The OWASP REST Security Cheat Sheet and ASVS 4.1.1 ask every response to declare it.', "Senza Content-Type, un browser può indovinare il tipo dai byte e leggere questa risposta dell'API come HTML o script (MIME sniffing). L'OWASP REST Security Cheat Sheet e ASVS 4.1.1 chiedono che ogni risposta lo dichiari."),
        recommendation: API_CT_REC,
        sources: ['rest-ct', 'rest-ct-guess', 'asvs-4.1.1'],
      })];
    }
    const mime = extractMimeType(value);
    if (!mime) {
      return [finding(H, Severity.LOW, L(`Content-Type: '${value}' is not a valid MIME type`, `Content-Type: '${value}' non è un MIME type valido`), {
        status: Status.MISCONFIGURED, brief: L('Invalid value, so browsers may guess the type', "Valore non valido, quindi i browser possono indovinare il tipo"),
        description: L('A browser cannot read a type from this value, so it is in the same position as one that received none, and may guess the type from the bytes.', "Un browser non riesce a leggere un tipo da questo valore, quindi è nella stessa situazione di uno che non ne ha ricevuto nessuno, e può indovinare il tipo dai byte."),
        recommendation: API_CT_REC,
        sources: ['rest-ct-guess', 'fetch-mime', 'asvs-4.1.1'],
      })];
    }
    if (mime.essence === 'text/html' && kind === 'html') {
      return [finding(H, Severity.OK, L('Content-Type: text/html, and the body is an HTML document', "Content-Type: text/html, e il corpo è un documento HTML"), { sources: ['rest-ct'] })];
    }
    if (mime.essence === 'text/html' && kind === 'json') {
      return [finding(H, Severity.LOW, L('Content-Type: text/html on a JSON body', "Content-Type: text/html su un corpo JSON"), {
        status: Status.MISCONFIGURED, brief: L('JSON declared as HTML', "JSON dichiarato come HTML"),
        description: L('The body is JSON, but the response declares itself HTML, so a browser that opens it renders it as a page, and anything injected into it can run as markup.', "Il corpo è JSON, ma la risposta si dichiara HTML, quindi un browser che la apre la visualizza come pagina, e qualsiasi cosa vi sia iniettata può essere eseguita come markup."),
        recommendation: API_CT_REC,
        sources: ['rest-ct', 'asvs-4.1.1'],
      })];
    }
    if (mime.essence === 'text/html') {
      return [finding(H, Severity.LOW, L('Content-Type: text/html on an API response', "Content-Type: text/html su una risposta di un'API"), {
        status: Status.MISCONFIGURED, brief: L('Declared as HTML', "Dichiarato come HTML"),
        description: L('The response declares itself HTML, so a browser that opens it renders it as a page, and anything injected into it can run as markup.', "La risposta si dichiara HTML, quindi un browser che la apre la visualizza come pagina, e qualsiasi cosa vi sia iniettata può essere eseguita come markup."),
        ...check(L('Is the body of the response an HTML document?', "Il corpo della risposta è un documento HTML?"), L('no (JSON, XML, plain text or anything else)', "no (JSON, XML, testo semplice o altro)"), L('yes', 'sì')),
        sources: ['rest-ct', 'asvs-4.1.1'],
      })];
    }
    if (JS_TYPES.has(mime.essence) && kind === 'json') {
      return [finding(H, Severity.LOW, L(`Content-Type: ${mime.essence} on a JSON body`, `Content-Type: ${mime.essence} su un corpo JSON`), {
        status: Status.MISCONFIGURED, brief: L('JSON declared as JavaScript', "JSON dichiarato come JavaScript"),
        description: JS_TYPE_RISK.replace('The response declares itself a script.', 'The body is JSON, but the response declares itself a script.'),
        recommendation: API_CT_REC,
        sources: ['rest-ct-js', 'mimesniff-js', 'mdn-corp-xssi'],
      })];
    }
    if (JS_TYPES.has(mime.essence)) {
      return [finding(H, Severity.LOW, L(`Content-Type: ${mime.essence} on an API response`, `Content-Type: ${mime.essence} su una risposta di un'API`), {
        status: Status.MISCONFIGURED, brief: L('Declared as JavaScript', "Dichiarato come JavaScript"),
        description: JS_TYPE_RISK,
        ...check(L('Is the body of the response a script (JavaScript code)?', "Il corpo della risposta è uno script (codice JavaScript)?"), L('no (JSON or anything else)', "no (JSON o altro)"), L('yes', 'sì')),
        sources: ['rest-ct-js', 'mimesniff-js', 'mdn-corp-xssi'],
      })];
    }
    return [finding(H, Severity.OK, `Content-Type: ${mime.essence}`, { sources: ['rest-ct'] })];
  }

  function apiPermissionsPolicy(value, empty) {
    const H = 'Permissions-Policy';
    const parsed = value === null ? null : parseSfDictionary(value);
    if (parsed && parsed.ok) {
      // OK when every feature it names is closed with (), as in the cheat
      // sheet's example; it need not name them all.
      const open = [...parsed.dict].filter(([, member]) => {
        const origins = ppAllowlist(member);
        return origins === null || origins.length > 0;   // an invalid allowlist is dropped: the default applies
      }).map(([feature]) => feature).sort();
      if (!open.length) return [finding(H, Severity.OK, L('Permissions-Policy: every feature it names is disabled', "Permissions-Policy: ogni funzionalità indicata è disattivata"), { sources: ['rest-pp'] })];
      return [apiDefenceNote(H, L(`Permissions-Policy: allows ${open.join(', ')} (not needed on an API response)`, `Permissions-Policy: consente ${open.join(', ')} (non necessaria su una risposta di un'API)`),
        L('The policy restricts the browser features a response rendered as HTML could use.', "La policy restringe le funzionalità del browser che una risposta visualizzata come HTML potrebbe usare."),
        L('Closing every feature with an empty allowlist (), as in the cheat sheet\'s example,', "Chiudere ogni funzionalità con un'allowlist vuota (), come nell'esempio della cheat sheet,"), ['rest-pp'])];
    }
    return [apiDefenceNote(H, value === null ? (empty ? L('Permissions-Policy: present but empty (not needed on an API response)', "Permissions-Policy: presente ma vuota (non necessaria su una risposta di un'API)") : L('Permissions-Policy: not set (not needed on an API response)', "Permissions-Policy: non impostata (non necessaria su una risposta di un'API)"))
      : L(`Permissions-Policy: '${value}' is not a valid policy (not needed on an API response)`, `Permissions-Policy: '${value}' non è una policy valida (non necessaria su una risposta di un'API)`),
    L('The policy restricts the browser features a response rendered as HTML could use.', "La policy restringe le funzionalità del browser che una risposta visualizzata come HTML potrebbe usare."),
    L('A policy that closes every feature with (), as in the cheat sheet\'s example,', "Una policy che chiude ogni funzionalità con (), come nell'esempio della cheat sheet,"), ['rest-pp'])];
  }

  function apiReferrerPolicy(value, empty) {
    const H = 'Referrer-Policy';
    let n = '';
    if (value !== null) {
      for (const token of splitOutsideQuotes(value, ',')) {
        if (REFERRER_POLICIES.has(token.toLowerCase())) n = token.toLowerCase();
      }
    }
    if (n === 'no-referrer') return [finding(H, Severity.OK, 'Referrer-Policy: no-referrer', { sources: ['rest-rp', 'referrer-last'] })];
    const title = value === null ? (empty ? L('Referrer-Policy: present but empty', "Referrer-Policy: presente ma vuota") : L('Referrer-Policy: not set', "Referrer-Policy: non impostata"))
      : n === '' ? L(`Referrer-Policy: unrecognized value '${value}'`, `Referrer-Policy: valore non riconosciuto '${value}'`) : L(`Referrer-Policy: '${n}' instead of no-referrer`, `Referrer-Policy: '${n}' invece di no-referrer`);
    return [apiDefenceNote(H, L(`${title} (not needed on an API response)`, `${title} (non necessaria su una risposta di un'API)`),
      L('A response that is not HTML triggers no further requests, so it has no referrer to send.', "Una risposta che non è HTML non genera altre richieste, quindi non ha un referrer da inviare."),
      'Referrer-Policy: no-referrer', ['rest-rp'])];
  }

  function apiCorp(value, empty, ctx) {
    const H = 'Cross-Origin-Resource-Policy';
    if (value !== null) return checkCorp(value, ctx);
    return [finding(H, Severity.LOW, apiTitle(H, empty), {
      status: apiStatus(empty), brief: L('Any site can load the response', "Qualsiasi sito può caricare la risposta"),
      description: L("Without CORP, any site can load this endpoint with a tag such as <script> or <img>. If the browser sends the user's cookies with it, the response, with the user's data, enters that site's process: a response that parses as script can be read directly (Cross-Site Script Inclusion), any response is exposed to Spectre-style reads, and whether it loads tells the site whether the user is signed in. Cross-Origin-Resource-Policy: same-origin makes the browser drop the response first. Browsers that implement opaque response blocking already withhold a JSON, HTML or XML response from such a tag, when the Content-Type is right; CORP asks for the same protection explicitly, from every browser and for every type of response, as defence in depth.", "Senza CORP, qualsiasi sito può caricare questo endpoint con un tag come <script> o <img>. Se il browser invia i cookie dell'utente, la risposta, con i dati dell'utente, entra nel processo di quel sito: una risposta interpretabile come script può essere letta direttamente (Cross-Site Script Inclusion), qualsiasi risposta è esposta a letture di tipo Spectre, e il fatto che si carichi o no dice al sito se l'utente è autenticato. Cross-Origin-Resource-Policy: same-origin fa scartare prima la risposta al browser. I browser che implementano l'opaque response blocking negano già a un tag del genere una risposta JSON, HTML o XML, quando il Content-Type è corretto; CORP chiede la stessa protezione in modo esplicito, a ogni browser e per ogni tipo di risposta, come difesa in profondità."),
      ...check(L('Does this endpoint answer GET requests with user data, authenticated by a cookie?', "Questo endpoint risponde a richieste GET con dati dell'utente, autenticate da un cookie?"), L('yes, and the cookie is SameSite=None or has no SameSite attribute', "sì, e il cookie è SameSite=None o non ha l'attributo SameSite"), L('it only accepts POST, it authenticates with an Authorization header, or the cookie is SameSite=Lax or Strict', "accetta solo POST, autentica con un header Authorization, oppure il cookie è SameSite=Lax o Strict")),
      sources: ['webdev-corp-api', 'webdev-corp-all', 'mdn-corp-xssi', 'mdn-corp-spectre', 'mdn-corp-nocors', 'orb-blocklist', 'fetch-method-get', 'mdn-samesite-lax', 'mdn-samesite-default'],
    })];
  }

  // Headers that act on a document only: an API response is not one.
  const API_NOT_APPLICABLE = {
    'cross-origin-opener-policy': [L('COOP decides which windows a document shares its browsing context group with. An API response is not a window, so the header has no effect on it, sent or not.', "COOP decide con quali finestre un documento condivide il suo browsing context group. Una risposta di un'API non è una finestra, quindi l'header non ha effetto su di essa, che sia inviato o no."), ['cs-coop-api']],
    'cross-origin-embedder-policy': [L('COEP sets the policy a document applies when it loads cross-origin resources. An API response loads nothing, so the header has no effect on it, sent or not.', "COEP imposta la policy che un documento applica quando carica risorse cross-origin. Una risposta di un'API non carica nulla, quindi l'header non ha effetto su di essa, che sia inviato o no."), ['mdn-coep-doc']],
    'origin-agent-cluster': [L('Origin-Agent-Cluster asks for a document to be placed in an origin-keyed agent cluster. An API response is not a document, so the header has no effect on it, sent or not.', "Origin-Agent-Cluster chiede che un documento sia messo in un agent cluster per origine. Una risposta di un'API non è un documento, quindi l'header non ha effetto su di essa, che sia inviato o no."), ['mdn-oac-doc']],
    'x-dns-prefetch-control': [L('DNS prefetching acts on the links and resources a document references. An API response references none, so the header has no effect on it, sent or not.', "Il DNS prefetching agisce sui link e sulle risorse a cui un documento rimanda. Una risposta di un'API non rimanda a nulla, quindi l'header non ha effetto su di essa, che sia inviato o no."), ['mdn-xdns-doc']],
  };

  function apiNotApplicable(key, canonical) {
    const [description, sources] = API_NOT_APPLICABLE[key];
    return () => [finding(canonical, Severity.OK, L(`${canonical}: not applicable to an API response`, `${canonical}: non applicabile a una risposta di un'API`), { status: Status.NONE, description, sources })];
  }

  const API_CHECKERS = {
    'content-security-policy': apiCsp,
    'x-frame-options': apiXFrameOptions,
    'content-type': apiContentType,
    'permissions-policy': apiPermissionsPolicy,
    'referrer-policy': apiReferrerPolicy,
    'cross-origin-resource-policy': apiCorp,
  };

  /** 63072000 -> "2-year"; anything not a whole number of years stays in seconds. */
  function duration(seconds) {
    const years = seconds / 31536000;
    if (Number.isInteger(years)) return L(`${years}-year`, years === 1 ? '1 anno' : `${years} anni`);
    return L(`${seconds}-second`, `${seconds} secondi`);
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
    const mode = HL.profiles.getMode(context && context.mode ? context.mode.id : 'page');
    const api = mode.id === 'api';
    const cspValues = headers.get('content-security-policy');
    const framingByCsp = !!cspValues && HL.csp.restrictsFraming(cspValues.join(', '));

    for (const [key, canonical, registryAbsent] of SECURITY_HEADERS) {
      if (!HL.profiles.inScope(key, profile, mode)) continue;
      if (api && (API_CHECKERS[key] || API_NOT_APPLICABLE[key])) {
        results.push(apiResult(key, canonical, headers.get(key), profile, framingByCsp, context && context.body));
        continue;
      }
      let absentSeverity = registryAbsent;
      // CSP frame-ancestors replaces X-Frame-Options in every browser that has
      // it (ASVS 3.4.6 asks for frame-ancestors). XFO is then only the fallback
      // OWASP recommends for older browsers, so its absence weighs less.
      const xfoFallbackOnly = key === 'x-frame-options' && framingByCsp;
      if (xfoFallbackOnly) absentSeverity = Severity.LOW;
      // Browsers ignore an empty header, so empty and absent are the same state;
      // a value a browser cannot use weighs the same as well (ctx.absentSeverity).
      const ctx = { absentSeverity: absentSeverity === null ? Severity.LOW : absentSeverity, hsts: profile.hsts, api };

      const occurrences = headers.get(key);
      const findings = [];
      let value = null;

      const missingCheck = MISSING_CHECKS[key] || null;
      const missingSources = [
        ...(xfoFallbackOnly ? ['csp3-fa-xfo', 'cs-xfo-fa', 'obs-xfo-csp'] : (MISSING_SOURCES[key] || [])),
        ...(api && key === 'cache-control' ? ['rest-cc'] : []),
      ];
      // Pragma beside a missing Cache-Control usually means it was meant to do
      // Cache-Control's job, which in a response it was never defined to do.
      const pragmaInstead = key === 'cache-control' && headers.has('pragma');
      const missingFinding = (title, description, status, brief) => finding(canonical, absentSeverity, title, {
        description: pragmaInstead ? `${description} ${PRAGMA_INSTEAD}` : description,
        status,
        brief,
        recommendation: missingCheck ? '' : (MISSING_RECS[key] || L(`Add the ${canonical} header.`, `Aggiungere l'header ${canonical}.`)),
        ...missingCheck,
        sources: pragmaInstead ? [...missingSources, 'rfc9111-pragma-response', 'mdn-pragma'] : missingSources,
      });
      const absent = (title) => (xfoFallbackOnly
        ? missingFinding(title,
          L('Content-Security-Policy frame-ancestors already restricts framing in every current browser. X-Frame-Options is the fallback OWASP recommends alongside it, for browsers that do not implement frame-ancestors.', "frame-ancestors di Content-Security-Policy restringe già il framing in ogni browser attuale. X-Frame-Options è il fallback che OWASP raccomanda accanto, per i browser che non implementano frame-ancestors."),
          Status.MISSING, L('Only CSP frame-ancestors restricts framing', "Solo frame-ancestors della CSP restringe il framing"))
        : missingFinding(title,
          MISSING_DESCRIPTIONS[key] || L(`The ${canonical} header is absent from the response.`, `L'header ${canonical} non è presente nella risposta.`),
          Status.MISSING, MISSING_BRIEF[key] || L('The header is not set', "L'header non è impostato")));

      if (!occurrences) {
        if (absentSeverity !== null) findings.push(absent(L(`Missing ${canonical}`, `${canonical} mancante`)));
        else if (ABSENT_NOTES[key]) findings.push(finding(canonical, Severity.OK, L(`${canonical}: not sent`, `${canonical}: non inviato`), { status: Status.NONE, description: ABSENT_NOTES[key], sources: ABSENT_SOURCES[key] || [] }));
      } else {
        const resolved = resolveDuplicates(key, canonical, occurrences);
        value = resolved.value;
        if (resolved.note) findings.push(resolved.note);
        if (value.trim() === '') {
          if (absentSeverity !== null) {
            findings.push(missingFinding(L(`${canonical}: present but empty`, `${canonical}: presente ma vuoto`),
              L(`${canonical} is present but carries no value. Browsers ignore it entirely, so the effect is the same as not sending it at all. An empty value usually points at a misconfigured template or proxy.`, `${canonical} è presente ma non ha un valore. I browser lo ignorano del tutto, quindi l'effetto è lo stesso di non inviarlo. Un valore vuoto di solito indica un template o un proxy configurati male.`),
              Status.MISCONFIGURED, L('Empty value, so browsers ignore the header', "Valore vuoto, quindi i browser ignorano l'header")));
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

  /** One header in REST API mode: duplicates resolved as in page mode, then judged as an API response. */
  function apiResult(key, canonical, occurrences, profile, framingByCsp, body) {
    const findings = [];
    let value = null;
    if (occurrences) {
      const resolved = resolveDuplicates(key, canonical, occurrences);
      value = resolved.value;
      if (resolved.note) findings.push(resolved.note);
    }
    const empty = value !== null && value.trim() === '';
    const ctx = { absentSeverity: Severity.LOW, hsts: profile.hsts, body: body || '' };
    const check = API_CHECKERS[key] || apiNotApplicable(key, canonical);
    findings.push(...check(empty || value === null ? null : value, empty, ctx, framingByCsp));
    return { key, name: canonical, value, present: value !== null, findings };
  }

  const SEVERITY_BY_VALUE = Object.fromEntries(Object.values(Severity).map((v) => [v, true]));

  HL.rules = Object.freeze({
    SECURITY_HEADERS,
    REFLECTION_REPLAY,
    analyzeHeaders,
    PP_TRACKING,
    PP_ONE_CLICK,
  });
});
