/*
 * Header Analyzer: data types shared by the engine and the interface.
 *
 * Every file in src/ is a classic script that registers itself on the
 * `HeaderAnalyzer` global. Classic scripts load from file:// in every browser,
 * which ES modules do not, and the same files run unchanged under Node for
 * the test suite (tests/load.js).
 */
(function (HL) {
  'use strict';

  // Ordered: comparisons (`>`, Math.max) rely on it throughout the engine.
  /*
   * Three severities, and OK. A finding with a severity is a deviation from an
   * OWASP or ASVS recommendation; OK means the check passed. An OK finding may
   * still carry a description (a fact worth explaining, e.g. 'unsafe-inline'
   * kept as a fallback next to a nonce) or a check to run (the nonce must change
   * on every response): a note, never counted as a problem.
   *
   * Grading rules (RULES.md has the full rationale and sources):
   *   - anchored on OWASP ZAP's alert risks, arbitrated by OWASP ASVS 5.0 and
   *     Mozilla HTTP Observatory, on the OWASP Risk Rating scale;
   *   - a value never weighs more than the header's absence, unless it grants
   *     more than the browser default; a value a browser ignores weighs as absence;
   *   - "to confirm" never inflates: the severity is what the response shows.
   */
  const Severity = Object.freeze({
    OK: 0,
    LOW: 1,
    MEDIUM: 2,
    HIGH: 3,
  });

  const SEVERITY_NAMES = Object.freeze(['OK', 'LOW', 'MEDIUM', 'HIGH']);

  /**
   * What kind of problem a finding is, for the one-line findings list
   * (`<Header>: <status>. <brief>.`):
   *   Missing        the header is not present;
   *   Misconfigured  it is present but not configured securely;
   *   Duplicated     it is returned more than once;
   *   Deprecated     it uses an obsolete or no longer recommended feature.
   * NONE marks a finding that states a fact rather than a problem (a fallback
   * kept for old browsers, a note about another header); it is never listed.
   */
  const Status = Object.freeze({
    MISSING: 'Missing',
    MISCONFIGURED: 'Misconfigured',
    DUPLICATED: 'Duplicated',
    DEPRECATED: 'Deprecated',
    NONE: '',
  });

  /**
   * `severity` is what the finding is worth **if it applies** to this target.
   *
   * Whether it applies is a separate question, and for some checks the response
   * cannot settle it. Those findings carry `verify`: the check that settles it,
   * and what each outcome means. An empty `verify` is the claim that the
   * response is enough on its own. A finding therefore has either `verify` or
   * `recommendation`, never both: until the check is done there is nothing to
   * recommend.
   *
   * `sources` are citation ids (src/core/sources.js): the exact passages that
   * back what the finding says.
   */
  function finding(header, severity, title, opts) {
    const o = opts || {};
    const sources = Object.freeze([...(o.sources || [])]);
    if (HL.sources) for (const id of sources) HL.sources.cite(id);   // an unknown id throws
    return {
      header: header,
      severity: severity,
      title: title,
      description: o.description || '',
      recommendation: o.recommendation || '',
      verify: o.verify || '',
      // `brief` is the short clause after the status in the findings list.
      status: 'status' in o ? o.status : Status.MISCONFIGURED,
      brief: o.brief || '',
      sources,
    };
  }

  /** A problem the response cannot settle on its own (an OK note may carry a check too). */
  function isContingent(f) {
    return f.verify !== '' && f.severity > Severity.OK;
  }

  /** Whether a finding says something specific enough to stand on its own. */
  function isIssue(severity) {
    return severity > Severity.OK;
  }

  function worstSeverity(result) {
    let worst = Severity.OK;
    for (const f of result.findings) if (f.severity > worst) worst = f.severity;
    return worst;
  }

  /** Nothing settled reaches this result's worst severity on its own. */
  function resultIsContingent(result) {
    if (result.findings.length === 0) return false;
    const worst = worstSeverity(result);
    return result.findings.every((f) => f.severity !== worst || isContingent(f));
  }

  HL.models = Object.freeze({
    Severity,
    SEVERITY_NAMES,
    Status,
    finding,
    isContingent,
    isIssue,
    worstSeverity,
    resultIsContingent,
  });
})(globalThis.HeaderAnalyzer = globalThis.HeaderAnalyzer || {});
