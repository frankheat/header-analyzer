/*
 * Header Analyzer: turning pasted text into the header list a browser would see.
 *
 * One response is read: the first one in the text. Two things in front of it
 * are skipped: a request (Burp copies a request and its response together)
 * and informational 1xx responses such as the `100 Continue` that `curl -i`
 * prints before the real one. DevTools copies headers with no status line at
 * all, which is accepted too. Everything after the response's header section is
 * its body and is ignored, status lines included.
 *
 * Field lines follow RFC 9112 §5: `name ":" OWS value OWS`. Lines a browser
 * would discard are discarded here too, and each is reported as a parse note so
 * nothing disappears without a word.
 */
(function (HL) {
  'use strict';

  const { trimOWS } = HL.fields;

  const STATUS_LINE = /^HTTP\/(\d(?:\.\d)?)[ \t]+(\d{3})(?:[ \t]+(.*))?$/i;
  const STATUS_LINE_NO_REASON = /^HTTP\/(\d(?:\.\d)?)[ \t]*$/i;
  const REQUEST_LINE = /^[A-Z][A-Z-]*[ \t]+\S+[ \t]+HTTP\/\d(?:\.\d)?$/;
  // RFC 9110 §5.1: field-name = token
  const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

  const MAX_INPUT = 5 * 1024 * 1024;

  function splitLines(text) {
    // RFC 9112 §2.2: a recipient MAY treat a bare LF as a line terminator; a bare
    // CR elsewhere is replaced with SP before the line is processed.
    return text.split(/\r?\n/).map((l) => l.replace(/\r/g, ' '));
  }

  function statusOf(line) {
    const m = STATUS_LINE.exec(line);
    if (m) return { version: m[1], code: Number(m[2]), reason: (m[3] || '').trim(), line: line.trim() };
    return null;
  }

  /**
   * Parse a header section starting at `start` (the line after the status line,
   * or the first line). Returns {fields, end, notes, pseudoStatus}, where `fields` is an array
   * of {name, lower, value} in order and `end` is the index of the line after
   * the blank line that terminates the section (or lines.length).
   */
  function parseFieldSection(lines, start) {
    const fields = [];
    const notes = [];
    let pseudoStatus = null;
    let i = start;
    let last = null;
    for (; i < lines.length; i++) {
      const line = lines[i];
      if (line.trim() === '') { i++; break; }

      // obs-fold (RFC 9112 §5.2): a user agent replaces it with SP.
      if (line[0] === ' ' || line[0] === '\t') {
        if (last) {
          last.value = trimOWS(last.value + ' ' + trimOWS(line));
          notes.push(`Line ${i + 1}: a folded continuation line (obs-fold) was joined to ${last.name}. Folding is deprecated by RFC 9112 §5.2.`);
        } else {
          notes.push(`Line ${i + 1}: an indented line with no field before it was ignored.`);
        }
        continue;
      }

      const colon = line.indexOf(':');
      // HTTP/2 and HTTP/3 pseudo-header fields, as some tools print them.
      if (colon === 0) {
        const m = /^:([a-z]+):[ \t]*(.*)$/.exec(line);
        if (m) {
          if (m[1] === 'status') pseudoStatus = Number(m[2].trim()) || null;
          last = null;
          continue;
        }
      }
      if (colon <= 0) {
        notes.push(`Line ${i + 1}: "${clip(line)}" is not a field line (no "name: value") and was ignored.`);
        last = null;
        continue;
      }

      const rawName = line.slice(0, colon);
      const name = rawName.replace(/[ \t]+$/, '');
      if (!TOKEN.test(name)) {
        notes.push(`Line ${i + 1}: "${clip(rawName)}" is not a valid field name, so browsers discard the line. It was ignored.`);
        last = null;
        continue;
      }
      if (name !== rawName) {
        notes.push(`Line ${i + 1}: whitespace between the field name "${name}" and the colon is forbidden by RFC 9112 §5.1. Clients handle it inconsistently; it was read as "${name}".`);
      }
      const field = { name: name, lower: name.toLowerCase(), value: trimOWS(line.slice(colon + 1)) };
      fields.push(field);
      last = field;
    }
    return { fields, end: i, notes, pseudoStatus };
  }

  function clip(s) {
    return s.length > 60 ? s.slice(0, 57) + '…' : s;
  }

  /**
   * Read the response in `text`.
   * Returns {response: {status, fields, notes}, notes, request, error}.
   */
  function parseResponse(text) {
    const notes = [];
    if (typeof text !== 'string') text = String(text == null ? '' : text);
    if (text.length > MAX_INPUT) {
      return { response: null, notes, error: `The input is larger than ${MAX_INPUT / 1024 / 1024} MB. Only the response headers are needed.` };
    }
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
    const lines = splitLines(text);

    let i = 0;
    while (i < lines.length && lines[i].trim() === '') i++;
    if (i >= lines.length) return { response: null, notes };

    // A request in front of the response (Burp "copy request and response",
    // a saved exchange). Skip to the first status line after its headers.
    let request = null;
    if (REQUEST_LINE.test(lines[i].trim())) {
      request = lines[i].trim();
      const section = parseFieldSection(lines, i + 1);
      let j = section.end;
      while (j < lines.length && !statusOf(lines[j])) j++;
      if (j >= lines.length) {
        return {
          response: null, notes, request,
          error: 'This is an HTTP request, not a response. Paste the response the server sent back: it starts with a status line such as "HTTP/1.1 200 OK".',
        };
      }
      notes.push(`The input starts with a request (${clip(request)}); it was skipped and the response after it was read.`);
      i = j;
    }

    for (;;) {
      const status = statusOf(lines[i]);
      let start = i;
      if (status) {
        start = i + 1;
      } else if (STATUS_LINE_NO_REASON.test(lines[i].trim())) {
        notes.push(`Line ${i + 1}: the status line "${clip(lines[i].trim())}" has no status code.`);
        start = i + 1;
      }
      const section = parseFieldSection(lines, start);

      // An informational 1xx response (100 Continue, 103 Early Hints) is not the
      // response: when another status line follows, that one is read instead.
      if (status && status.code >= 100 && status.code <= 199) {
        let j = section.end;
        while (j < lines.length && lines[j].trim() === '') j++;
        if (j < lines.length && statusOf(lines[j])) {
          notes.push(`The informational "${clip(status.line)}" in front of the response was skipped.`);
          i = j;
          continue;
        }
      }

      const st = status || (section.pseudoStatus
        ? { version: '2', code: section.pseudoStatus, reason: '', line: `:status: ${section.pseudoStatus}` }
        : null);
      return { response: { status: st, fields: section.fields, notes: section.notes }, notes, request };
    }
  }

  /** Group a response's fields into {lowercase name: [values in order]}. */
  function headerMap(response) {
    const map = new Map();
    for (const f of response.fields) {
      if (!map.has(f.lower)) map.set(f.lower, []);
      map.get(f.lower).push(f.value);
    }
    return map;
  }

  HL.parser = Object.freeze({
    parseResponse,
    headerMap,
    MAX_INPUT,
  });
})(globalThis.HeaderAnalyzer = globalThis.HeaderAnalyzer || {});
