/*
 * Header Analyzer: checks that need more than one header.
 *
 * A checker in rules.js sees a single value, which is enough for almost every
 * rule. Where it is not (`Access-Control-Allow-Credentials: true` says "send
 * the cookies" without saying to whom), the single-header checker stays
 * neutral and the verdict is reached here, with every result in view.
 * Correlations only append findings; they never rewrite or suppress one.
 */
(function (HL) {
  'use strict';

  const { Severity, Status, finding } = HL.models;
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
      return make(Severity.OK, 'Credentials are enabled but Access-Control-Allow-Origin was not evaluated', {
        sources: ['fetch-cors-cred'],
        status: Status.NONE,
        description: 'This profile excludes Access-Control-Allow-Origin, so there is no way to tell which origins may read authenticated responses.',
      });
    }
    if (!acao.present || acao.value.trim() === '') {
      return make(Severity.OK, 'Access-Control-Allow-Credentials has no effect without Access-Control-Allow-Origin', {
        sources: ['fetch-cors-null'],
        status: Status.NONE,
        brief: 'Has no effect without Access-Control-Allow-Origin',
        description: 'No origin is authorised to read the response, so enabling credentials changes nothing. The header is most likely left over from an earlier configuration.',
        recommendation: 'Remove Access-Control-Allow-Credentials, or set the origin it is meant for.',
      });
    }
    const origin = acao.value.trim();
    if (origin === '*') {
      // Browsers reject the credentialed request: nothing is exposed beyond what
      // the wildcard already exposes, which is graded on its own row.
      return make(Severity.OK, 'Access-Control-Allow-Origin: * with credentials enabled, so the request fails', {
        sources: ['fetch-cors-star', 'bp-cors-star-cred'],
        status: Status.NONE,
        brief: 'Combined with a wildcard origin, so requests fail',
        description: 'Browsers refuse the wildcard together with credentials, so every credentialed cross-origin request to this endpoint is rejected. Nothing is exposed by the combination itself: whoever wanted authenticated cross-origin access does not have it. (The wildcard\'s own effect on non-credentialed requests is reported on Access-Control-Allow-Origin.)',
        recommendation: 'Allowlist the specific origins that need authenticated access, or drop Access-Control-Allow-Credentials. Do not echo back the request\'s Origin header to make it work: that would let any site read logged-in users\' data.',
      });
    }
    if (origin.includes(',')) {
      return make(Severity.OK, 'Access-Control-Allow-Credentials has no effect: the allowed origin is not usable', {
        sources: ['fetch-cors-origin'],
        status: Status.NONE,
        brief: 'Has no effect; the allowed origin is invalid',
        description: 'Access-Control-Allow-Origin lists more than one origin, which never matches the requesting origin, so no site can read the response with or without credentials.',
        recommendation: 'Fix Access-Control-Allow-Origin first; this header cannot take effect until then.',
      });
    }
    if (origin !== 'null' && origin.toLowerCase() === 'null') {
      return make(Severity.OK, 'Access-Control-Allow-Credentials has no effect: the allowed origin matches nothing', {
        sources: ['fetch-cors-origin'],
        status: Status.NONE,
        brief: 'Has no effect; the allowed origin is invalid',
        description: `'${origin}' is compared with the requesting origin byte for byte, so it matches no origin and no site can read the response.`,
        recommendation: 'Fix Access-Control-Allow-Origin first; this header cannot take effect until then.',
      });
    }
    if (origin === 'null') {
      return make(Severity.HIGH, 'Access-Control-Allow-Origin: null with credentials enabled', {
        sources: ['zap-40040-3', 'zap-cors-risk', 'mdn-acao-null'],
        brief: 'Credentials allowed for the null origin',
        description: 'Any page can obtain the null origin through a sandboxed iframe, a data: URL or a cross-origin redirect, and null is a concrete origin, so browsers do send cookies with it. An attacker\'s page can therefore read this endpoint\'s responses as the logged-in user.',
        recommendation: 'Never allowlist null. Echo only origins from a fixed list.',
      });
    }
    // A plain-HTTP origin with credentials: anyone on that origin's network path
    // can inject script there and read authenticated responses (ZAP rates it
    // High; impact high × likelihood low on the OWASP Risk Rating: MEDIUM).
    if (origin.toLowerCase().startsWith('http://')) {
      return make(Severity.MEDIUM, `Authenticated cross-origin access is granted to a plain-HTTP origin (${origin})`, {
        sources: ['ps-cors-http', 'zap-cors-risk', 'owasp-rr-critical'],
        brief: `Credentials allowed for plain-HTTP origin ${origin}`,
        description: `This response lets ${origin} read data using the user's cookies, and that origin is not protected by TLS. Anyone able to tamper with traffic to it (a shared Wi-Fi, a compromised router) can inject script into it and read this endpoint as the logged-in user. It needs a position on the network path, which is what keeps this below HIGH.`,
        recommendation: `Allow the https:// version of ${origin} instead, and serve that origin over HTTPS only.`,
      });
    }
    // "Restricted with authentication" is the configuration the OWASP Secure
    // Headers Project recommends; what the response cannot show is whether the
    // origin is allowlisted or mirrored, and that is the check.
    return make(Severity.LOW, `Authenticated cross-origin access is granted to ${origin}`, {
      sources: ['bp-cors-auth', 'bp-cors-mirror', 'zap-cors-risk'],
      brief: `Credentials allowed for ${origin}, possibly reflected`,
      description: `This response lets ${origin} read data using the user's cookies. A fixed, allowlisted origin with credentials is the configuration OWASP recommends for authenticated CORS. A server that echoes back the request's Origin header produces exactly the same bytes, though, and then any site can read this endpoint as the logged-in user. A single saved response cannot tell the two apart.`,
      verify: 'Replay the request with Origin: https://an-origin-you-made-up.example. If it comes back in Access-Control-Allow-Origin, the server reflects whatever it is sent and any site reads this endpoint as the logged-in user: this stands, and it is HIGH. If it does not come back, the allowlist is real, this is correct authenticated CORS, and there is nothing here.',
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
    const permissive = (f) => f.title === PERMISSIVE_FRAME_ANCESTORS || /^CSP: frame-ancestors .+ lets any site frame this response$/.test(f.title);
    if (!csp.findings.some(permissive)) return [];
    return [[XFO, finding('X-Frame-Options', Severity.OK, 'X-Frame-Options: replaced by the CSP, which allows framing', {
      sources: ['csp3-fa-xfo', 'html-xfo-csp'],
      status: Status.NONE,
      description: 'A browser that implements CSP frame-ancestors does not read this header at all: the directive\'s presence replaces it, whatever its value. Here it is permissive, so anyone can frame this response, and this header protects only browsers old enough to ignore CSP entirely. The exposure is graded on the Content-Security-Policy row; what is said here is that this one does not offset it.',
      recommendation: 'Restrict frame-ancestors, and keep this header for the browsers that do not implement it.',
    })]];
  }

  /** A report-only policy is easy to mistake for an enforced one. */
  function reportOnlyPolicy(byKey, headers) {
    const csp = byKey.get(CSP);
    const ro = headers.get('content-security-policy-report-only');
    if (!csp || !ro || ro.every((v) => v.trim() === '')) return [];
    if (csp.present && csp.value.trim() !== '') {
      return [[CSP, finding('Content-Security-Policy', Severity.OK, 'A report-only policy is also being tested', {
        sources: ['zap-10038-3'],
        status: Status.NONE,
        description: 'Content-Security-Policy-Report-Only is present next to the enforced policy. It blocks nothing; violations of it are only reported. Only the enforced policy is evaluated here.',
      })]];
    }
    return [[CSP, finding('Content-Security-Policy', Severity.OK, 'Only a report-only policy is present, and it blocks nothing', {
      sources: ['zap-10038-3'],
      status: Status.NONE,
      description: 'The response carries Content-Security-Policy-Report-Only, which makes the browser report what a policy would block without blocking any of it. It is the right way to trial a policy, but until it is moved to Content-Security-Policy there is no protection.',
      recommendation: 'Once the reports are clean, send the same policy as Content-Security-Policy.',
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
})(globalThis.HeaderAnalyzer = globalThis.HeaderAnalyzer || {});
