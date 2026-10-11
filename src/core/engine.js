/*
 * Header Analyzer: the engine's public entry point.
 *
 * `analyze` never throws: whatever the input, it returns a report object,
 * with `ok: false` and a message a person can act on when there is nothing to
 * analyse, or when the engine itself failed, which is reported as such rather
 * than as a verdict about the response.
 */
(function (HL) {
  'use strict';

  const { Severity, SEVERITY_NAMES, Status, isContingent } = HL.models;
  const VERSION = '1.0.0';

  function tally(findings) {
    const counts = {};
    for (const name of SEVERITY_NAMES) counts[name] = 0;
    for (const f of findings) counts[SEVERITY_NAMES[f.severity]]++;
    return counts;
  }

  function summarize(results) {
    const all = results.flatMap((r) => r.findings);
    let worst = Severity.OK;
    for (const f of all) if (f.severity > worst) worst = f.severity;
    const atWorst = all.filter((f) => f.severity === worst);
    return {
      worst,
      worstName: SEVERITY_NAMES[worst],
      // Marked when only a contingent finding reaches the top: an unconfirmed
      // HIGH heading an otherwise clean report would read as a verdict the tool
      // has not earned.
      worstIsContingent: atWorst.length > 0 && worst > Severity.OK && atWorst.every(isContingent),
      settled: tally(all.filter((f) => !isContingent(f) && f.severity > Severity.OK)),
      toConfirm: tally(all.filter((f) => isContingent(f))),
    };
  }

  function failure(error, extra) {
    return Object.assign({ ok: false, error, notes: [], results: [], summary: null }, extra || {});
  }

  /**
   * @param {string} text       raw response text
   * @param {string} profileId  'basic' | 'extended'
   */
  function analyze(text, profileId) {
    const profile = HL.profiles.getProfile(profileId);
    const meta = { version: VERSION, profile: { id: profile.id, name: profile.name } };
    try {
      if (typeof text !== 'string' || text.trim() === '') {
        return failure('empty', meta);
      }
      const parsed = HL.parser.parseResponse(text);
      if (parsed.error) return failure(parsed.error, Object.assign(meta, { notes: parsed.notes }));
      const response = parsed.response;
      if (!response || response.fields.length === 0) {
        return failure('No HTTP header fields were found. Paste a raw response: a status line such as "HTTP/1.1 200 OK", then one "Name: value" per line.', meta);
      }

      const notes = [...parsed.notes, ...response.notes];
      const results = HL.rules.analyzeHeaders(HL.parser.headerMap(response), profile, { status: response.status });
      return Object.assign(meta, {
        ok: true,
        error: null,
        status: response.status,
        notes,
        results,
        summary: summarize(results),
      });
    } catch (e) {
      return failure('internal', Object.assign(meta, { detail: e && e.stack ? String(e.stack) : String(e) }));
    }
  }

  // When one header has problems of several kinds, the line carries the status
  // of the most severe; on a tie, the first of these.
  const STATUS_PRECEDENCE = [Status.MISSING, Status.MISCONFIGURED, Status.DEPRECATED, Status.DUPLICATED];
  const MAX_BRIEFS = 3;

  /** "Sent 2 times" → "sent 2 times" inside a sentence; "SAMEORIGIN …" and "'none' …" stay. */
  function midSentence(brief) {
    return /^[A-Z][a-z]/.test(brief) ? brief[0].toLowerCase() + brief.slice(1) : brief;
  }

  /**
   * One line per header: `<Header>: <status>. <brief>.`
   *
   * Each header's listed findings are merged. The status is the one of the most
   * severe finding (STATUS_PRECEDENCE breaks ties). The brief joins the
   * findings' briefs, most severe first, with "; ", keeping at most MAX_BRIEFS
   * and summing up the rest as "and N more"; the detailed report has them all.
   *
   * Every finding with a severity is listed (OK notes never are). `show`
   * selects which: 'all' (the default), 'confirmed' (only findings the response
   * settles) or 'toConfirm' (only those that need a check, each marked
   * "(to confirm)"). A header with both kinds appears under each, with the
   * findings of that kind.
   * Lines are sorted by their most severe finding; ties keep the report's order.
   */
  const SHOW = ['all', 'confirmed', 'toConfirm'];

  function findingList(report, options) {
    const o = Object.assign({ show: 'all' }, options || {});
    if (!SHOW.includes(o.show)) throw new Error(`Unknown findings list option: ${o.show}`);
    if (!report || !report.ok) return [];
    const lines = [];
    report.results.forEach((r, order) => {
      const items = [];
      const seen = new Set();
      for (const f of r.findings) {
        if (f.status === Status.NONE || f.severity === Severity.OK) continue;
        const contingent = isContingent(f);
        if ((o.show === 'confirmed' && contingent) || (o.show === 'toConfirm' && !contingent)) continue;
        const brief = f.brief + (contingent ? ' (to confirm)' : '');
        if (seen.has(brief)) continue;          // two routes to the same problem
        seen.add(brief);
        items.push({ status: f.status, brief, severity: f.severity, toConfirm: contingent });
      }
      if (!items.length) return;

      items.sort((a, b) => b.severity - a.severity
        || STATUS_PRECEDENCE.indexOf(a.status) - STATUS_PRECEDENCE.indexOf(b.status));
      const top = items[0];
      const shown = items.slice(0, MAX_BRIEFS).map((it, k) => (k === 0 ? it.brief : midSentence(it.brief)));
      const rest = items.length - shown.length;
      const brief = shown.join('; ') + (rest > 0 ? `; and ${rest} more` : '');
      lines.push({
        header: r.name,
        status: top.status,
        brief,
        severity: SEVERITY_NAMES[top.severity],
        // Unconfirmed when nothing settled reaches the line's severity.
        toConfirm: items.filter((it) => it.severity === top.severity).every((it) => it.toConfirm),
        text: `${r.name}: ${top.status}. ${brief}.`,
        items: items.map((it) => ({ ...it, severity: SEVERITY_NAMES[it.severity] })),
        rank: -top.severity,
        order,
      });
    });
    lines.sort((a, b) => a.rank - b.rank || a.order - b.order);
    return lines.map(({ rank, order, ...line }) => line);
  }

  HL.engine = Object.freeze({ analyze, findingList, VERSION });
})(globalThis.HeaderAnalyzer = globalThis.HeaderAnalyzer || {});
