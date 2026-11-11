/*
 * Header Analyzer: checks that need more than one header.
 *
 * A checker in rules.js sees a single value, which is enough for almost every
 * rule. Where it is not (`Access-Control-Allow-Credentials: true` says "send
 * the cookies" without saying to whom), the single-header checker stays
 * neutral and the verdict is reached here, with every result in view.
 * Correlations only append findings; they never rewrite or suppress one.
 */
globalThis.HeaderAnalyzer.i18n.module(function (HL, L) {
  'use strict';

  const { Severity, Status, finding, check } = HL.models;
  const { PERMISSIVE_FRAME_ANCESTORS } = HL.csp;

  const ACAO = 'access-control-allow-origin';
  const ACAC = 'access-control-allow-credentials';
  const CSP = 'content-security-policy';
  const XFO = 'x-frame-options';

  /** Judge credentials against the origin they are sent to: one verdict, always. */
  function corsCredentials(byKey) {
    const acac = byKey.get(ACAC);
    // Fetch's CORS check compares the value with `true` byte for byte.
    if (!acac || !acac.present || acac.value.trim() !== 'true') return [];
    const make = (severity, title, opts) => [[ACAC, finding('Access-Control-Allow-Credentials', severity, title, opts)]];

    const acao = byKey.get(ACAO);
    if (!acao) {
      return make(Severity.OK, L('Credentials are enabled but Access-Control-Allow-Origin was not evaluated', "Le credenziali sono abilitate ma Access-Control-Allow-Origin non è stato valutato"), {
        sources: ['fetch-cors-cred'],
        status: Status.NONE,
        description: L('This profile excludes Access-Control-Allow-Origin, so there is no way to tell which origins may read authenticated responses.', "Questo profilo esclude Access-Control-Allow-Origin, quindi non si può sapere quali origini possono leggere le risposte autenticate."),
      });
    }
    if (!acao.present || acao.value.trim() === '') {
      return make(Severity.OK, L('Access-Control-Allow-Credentials has no effect without Access-Control-Allow-Origin', "Access-Control-Allow-Credentials non ha effetto senza Access-Control-Allow-Origin"), {
        sources: ['fetch-cors-null'],
        status: Status.NONE,
        brief: L('Has no effect without Access-Control-Allow-Origin', "Non ha effetto senza Access-Control-Allow-Origin"),
        description: L('No origin is authorised to read the response, so enabling credentials changes nothing. The header is most likely left over from an earlier configuration.', "Nessuna origine è autorizzata a leggere la risposta, quindi abilitare le credenziali non cambia nulla. Probabilmente l'header è rimasto da una configurazione precedente."),
        recommendation: L('Remove Access-Control-Allow-Credentials, or set the origin it is meant for.', "Rimuovere Access-Control-Allow-Credentials, oppure impostare l'origine a cui è destinato."),
      });
    }
    const origin = acao.value.trim();
    if (origin === '*') {
      // Browsers reject the credentialed request: nothing is exposed beyond what
      // the wildcard already exposes, which is graded on its own row.
      return make(Severity.OK, L('Access-Control-Allow-Origin: * with credentials enabled, so the request fails', "Access-Control-Allow-Origin: * con le credenziali abilitate, quindi la richiesta fallisce"), {
        sources: ['fetch-cors-star', 'bp-cors-star-cred'],
        status: Status.NONE,
        brief: L('Combined with a wildcard origin, so requests fail', "Combinato con un'origine wildcard, quindi le richieste falliscono"),
        description: L('Browsers refuse the wildcard together with credentials, so every credentialed cross-origin request to this endpoint is rejected. Nothing is exposed by the combination itself: whoever wanted authenticated cross-origin access does not have it. (The wildcard\'s own effect on non-credentialed requests is reported on Access-Control-Allow-Origin.)', "I browser rifiutano il wildcard insieme alle credenziali, quindi ogni richiesta cross-origin con credenziali verso questo endpoint viene respinta. La combinazione in sé non espone nulla: chi voleva un accesso cross-origin autenticato non lo ottiene. (L'effetto del wildcard sulle richieste senza credenziali è riportato su Access-Control-Allow-Origin.)"),
        recommendation: L('Allowlist the specific origins that need authenticated access, or drop Access-Control-Allow-Credentials. Do not echo back the request\'s Origin header to make it work: that would let any site read logged-in users\' data.', "Autorizzare le singole origini che hanno bisogno di un accesso autenticato, oppure togliere Access-Control-Allow-Credentials. Per farlo funzionare non bisogna rimandare indietro l'header Origin della richiesta: qualsiasi sito potrebbe leggere i dati degli utenti autenticati."),
      });
    }
    if (origin.includes(',')) {
      return make(Severity.OK, L('Access-Control-Allow-Credentials has no effect: the allowed origin is not usable', "Access-Control-Allow-Credentials non ha effetto: l'origine autorizzata non è utilizzabile"), {
        sources: ['fetch-cors-origin'],
        status: Status.NONE,
        brief: L('Has no effect; the allowed origin is invalid', "Non ha effetto; l'origine autorizzata non è valida"),
        description: L('Access-Control-Allow-Origin lists more than one origin, which never matches the requesting origin, so no site can read the response with or without credentials.', "Access-Control-Allow-Origin elenca più di un'origine, che non corrisponde mai all'origine della richiesta, quindi nessun sito può leggere la risposta, con o senza credenziali."),
        recommendation: L('Fix Access-Control-Allow-Origin first; this header cannot take effect until then.', "Correggere prima Access-Control-Allow-Origin; fino ad allora questo header non può avere effetto."),
      });
    }
    if (origin !== 'null' && origin.toLowerCase() === 'null') {
      return make(Severity.OK, L('Access-Control-Allow-Credentials has no effect: the allowed origin matches nothing', "Access-Control-Allow-Credentials non ha effetto: l'origine autorizzata non corrisponde a nulla"), {
        sources: ['fetch-cors-origin'],
        status: Status.NONE,
        brief: L('Has no effect; the allowed origin is invalid', "Non ha effetto; l'origine autorizzata non è valida"),
        description: L(`'${origin}' is compared with the requesting origin byte for byte, so it matches no origin and no site can read the response.`, `'${origin}' viene confrontata byte per byte con l'origine della richiesta, quindi non corrisponde a nessuna origine e nessun sito può leggere la risposta.`),
        recommendation: L('Fix Access-Control-Allow-Origin first; this header cannot take effect until then.', "Correggere prima Access-Control-Allow-Origin; fino ad allora questo header non può avere effetto."),
      });
    }
    if (origin === 'null') {
      return make(Severity.HIGH, L('Access-Control-Allow-Origin: null with credentials enabled', "Access-Control-Allow-Origin: null con le credenziali abilitate"), {
        sources: ['zap-40040-3', 'zap-cors-risk', 'mdn-acao-null'],
        brief: L('Credentials allowed for the null origin', "Credenziali consentite per l'origine null"),
        description: L('Any page can obtain the null origin through a sandboxed iframe, a data: URL or a cross-origin redirect, and null is a concrete origin, so browsers do send cookies with it. An attacker\'s page can therefore read this endpoint\'s responses as the logged-in user.', "Qualsiasi pagina può ottenere l'origine null con un iframe sandbox, un URL data: o un redirect cross-origin, e null è un'origine concreta, quindi i browser inviano i cookie. La pagina di un attaccante può quindi leggere le risposte di questo endpoint come l'utente autenticato."),
        recommendation: L('Never allowlist null. Echo only origins from a fixed list.', "Non autorizzare mai null. Rimandare solo origini prese da un elenco fisso."),
      });
    }
    // A plain-HTTP origin with credentials: anyone on that origin's network path
    // can inject script there and read authenticated responses (ZAP rates it
    // High; impact high × likelihood low on the OWASP Risk Rating: MEDIUM).
    if (origin.toLowerCase().startsWith('http://')) {
      return make(Severity.MEDIUM, L(`Authenticated cross-origin access is granted to a plain-HTTP origin (${origin})`, `Accesso cross-origin autenticato concesso a un'origine in HTTP in chiaro (${origin})`), {
        sources: ['ps-cors-http', 'zap-cors-risk', 'owasp-rr-critical'],
        brief: L(`Credentials allowed for plain-HTTP origin ${origin}`, `Credenziali consentite per l'origine in HTTP in chiaro ${origin}`),
        description: L(`This response lets ${origin} read data using the user's cookies, and that origin is not protected by TLS. Anyone able to tamper with traffic to it (a shared Wi-Fi, a compromised router) can inject script into it and read this endpoint as the logged-in user. It needs a position on the network path, which is what keeps this below HIGH.`, `Questa risposta consente a ${origin} di leggere i dati usando i cookie dell'utente, e quell'origine non è protetta da TLS. Chiunque possa manomettere il traffico verso di essa (una Wi-Fi condivisa, un router compromesso) può iniettarvi uno script e leggere questo endpoint come l'utente autenticato. Serve una posizione sul percorso di rete, ed è questo che lo tiene sotto HIGH.`),
        recommendation: L(`Allow the https:// version of ${origin} instead, and serve that origin over HTTPS only.`, `Autorizzare la versione https:// di ${origin}, e servire quell'origine solo in HTTPS.`),
      });
    }
    // "Restricted with authentication" is the configuration the OWASP Secure
    // Headers Project recommends; what the response cannot show is whether the
    // origin is allowlisted or mirrored, and that is the check.
    return make(Severity.LOW, L(`Authenticated cross-origin access is granted to ${origin}`, `Accesso cross-origin autenticato concesso a ${origin}`), {
      sources: ['bp-cors-auth', 'bp-cors-mirror', 'zap-cors-risk', 'ps-url-bypass'],
      brief: L(`Credentials allowed for ${origin}, possibly reflected`, `Credenziali consentite per ${origin}, forse riflessa`),
      description: L(`This response lets ${origin} read data using the user's cookies. A fixed, allowlisted origin with credentials is the configuration OWASP recommends for authenticated CORS. A server that echoes back the request's Origin header produces exactly the same bytes, though, and then any site can read this endpoint as the logged-in user. A single saved response cannot tell the two apart.`, `Questa risposta consente a ${origin} di leggere i dati usando i cookie dell'utente. Un'origine fissa e autorizzata, con credenziali, è la configurazione che OWASP raccomanda per il CORS autenticato. Un server che rimanda indietro l'header Origin della richiesta produce però esattamente gli stessi byte, e allora qualsiasi sito può leggere questo endpoint come l'utente autenticato. Una sola risposta salvata non permette di distinguere i due casi.`),
      ...check(HL.rules.REFLECTION_REPLAY, L('the response allows any of these origins in Access-Control-Allow-Origin: any site then reads this endpoint as the logged-in user, and it is HIGH', "la risposta consente una qualsiasi di queste origini in Access-Control-Allow-Origin: qualsiasi sito legge allora questo endpoint come l'utente autenticato, ed è HIGH"), L(`every attempt still gets ${origin}, or no Access-Control-Allow-Origin`, `ogni tentativo riceve ancora ${origin}, oppure nessun Access-Control-Allow-Origin`)),
    });
  }

  /**
   * HTML returns early, X-Frame-Options unread, as soon as an enforced policy
   * carries frame-ancestors, whatever it says. A correct X-Frame-Options next
   * to a permissive frame-ancestors protects only browsers without CSP.
   */
  function frameAncestorsReplacesXfo(byKey) {
    const xfo = byKey.get(XFO);
    const csp = byKey.get(CSP);
    if (!xfo || !csp || !xfo.present) return [];
    // Web page mode grades the CSP's permissive frame-ancestors with PERMISSIVE_FRAME_ANCESTORS;
    // REST API mode names the value it read.
    const permissive = (f) => f.title === PERMISSIVE_FRAME_ANCESTORS || L(/^CSP: frame-ancestors .+ lets any site frame this response$/, /^CSP: frame-ancestors .+ permette a qualsiasi sito di incorniciare questa risposta$/).test(f.title);
    if (!csp.findings.some(permissive)) return [];
    return [[XFO, finding('X-Frame-Options', Severity.OK, L('X-Frame-Options: replaced by the CSP, which allows framing', "X-Frame-Options: sostituito dalla CSP, che consente il framing"), {
      sources: ['csp3-fa-xfo', 'html-xfo-csp'],
      status: Status.NONE,
      description: L('A browser that implements CSP frame-ancestors does not read this header at all: the directive\'s presence replaces it, whatever its value. Here it is permissive, so anyone can frame this response, and this header protects only browsers old enough to ignore CSP entirely. The exposure is graded on the Content-Security-Policy row; what is said here is that this one does not offset it.', "Un browser che implementa frame-ancestors della CSP non legge affatto questo header: la presenza della direttiva lo sostituisce, qualunque sia il suo valore. Qui è permissiva, quindi chiunque può incorniciare questa risposta, e questo header protegge solo i browser così vecchi da ignorare del tutto la CSP. L'esposizione è valutata sulla riga Content-Security-Policy; qui si dice che questo header non la compensa."),
      recommendation: L('Restrict frame-ancestors, and keep this header for the browsers that do not implement it.', "Restringere frame-ancestors, e mantenere questo header per i browser che non lo implementano."),
    })]];
  }

  /** A report-only policy is easy to mistake for an enforced one. */
  function reportOnlyPolicy(byKey, headers) {
    const csp = byKey.get(CSP);
    const ro = headers.get('content-security-policy-report-only');
    if (!csp || !ro || ro.every((v) => v.trim() === '')) return [];
    if (csp.present && csp.value.trim() !== '') {
      return [[CSP, finding('Content-Security-Policy', Severity.OK, L('A report-only policy is also being tested', "È in prova anche una policy report-only"), {
        sources: ['zap-10038-3'],
        status: Status.NONE,
        description: L('Content-Security-Policy-Report-Only is present next to the enforced policy. It blocks nothing; violations of it are only reported. Only the enforced policy is evaluated here.', "Content-Security-Policy-Report-Only è presente accanto alla policy applicata. Non blocca nulla; le sue violazioni vengono solo segnalate. Qui viene valutata solo la policy applicata."),
      })]];
    }
    return [[CSP, finding('Content-Security-Policy', Severity.OK, L('Only a report-only policy is present, and it blocks nothing', "È presente solo una policy report-only, che non blocca nulla"), {
      sources: ['zap-10038-3'],
      status: Status.NONE,
      description: L('The response carries Content-Security-Policy-Report-Only, which makes the browser report what a policy would block without blocking any of it. It is the right way to trial a policy, but until it is moved to Content-Security-Policy there is no protection.', "La risposta contiene Content-Security-Policy-Report-Only, che fa segnalare al browser ciò che una policy bloccherebbe senza bloccare nulla. È il modo giusto per provare una policy, ma finché non viene spostata in Content-Security-Policy non c'è protezione."),
      recommendation: L('Once the reports are clean, send the same policy as Content-Security-Policy.', "Quando i report sono puliti, inviare la stessa policy come Content-Security-Policy."),
    })]];
  }

  const RULES = [corsCredentials, frameAncestorsReplacesXfo, reportOnlyPolicy];

  function apply(results, headers) {
    const byKey = new Map(results.map((r) => [r.key, r]));
    for (const rule of RULES) {
      for (const [key, f] of rule(byKey, headers)) {
        const target = byKey.get(key);
        if (target) target.findings.push(f);
      }
    }
  }

  HL.correlations = Object.freeze({ apply });
});
