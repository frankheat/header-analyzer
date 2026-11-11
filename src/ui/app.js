/*
 * Header Analyzer: the interface.
 *
 * Rules this file keeps:
 *   - every piece of text that came from the input reaches the page through
 *     textContent or a text node, never through innerHTML;
 *   - the input is never persisted: only the profile, mode, language and appearance choices;
 *     what the user decides about findings to confirm lives in memory and is
 *     dropped with the report it belongs to;
 *   - a failure anywhere in rendering is caught and shown, never left as a
 *     blank pane.
 */
(function (HL) {
  'use strict';

  const { Severity, SEVERITY_NAMES, worstSeverity, resultIsContingent, isContingent } = HL.models;

  // ------------------------------------------------------------------ helpers

  function $(id) { return document.getElementById(id); }

  /** Build an element. `props` may hold className, text, attrs, on; children are nodes or strings. */
  function el(tag, props, ...children) {
    const node = document.createElement(tag);
    const p = props || {};
    if (p.className) node.className = p.className;
    if (p.text !== undefined) node.textContent = p.text;
    if (p.attrs) for (const [k, v] of Object.entries(p.attrs)) if (v !== null && v !== undefined && v !== false) node.setAttribute(k, v === true ? '' : String(v));
    if (p.on) for (const [k, v] of Object.entries(p.on)) node.addEventListener(k, v);
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      node.append(typeof c === 'string' ? document.createTextNode(c) : c);
    }
    return node;
  }

  const storage = {
    get(key) { try { return window.localStorage.getItem('header-analyzer.' + key); } catch (_) { return null; } },
    set(key, value) { try { window.localStorage.setItem('header-analyzer.' + key, value); } catch (_) { /* private mode */ } },
  };

  const SVG_NS = 'http://www.w3.org/2000/svg';

  function icon(id, className) {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    if (className) svg.setAttribute('class', className);
    const use = document.createElementNS(SVG_NS, 'use');
    use.setAttribute('href', '#' + id);
    svg.append(use);
    return svg;
  }

  const sevClass = (s) => 'sev-' + SEVERITY_NAMES[s].toLowerCase();
  const SEV_LABEL = ['OK', 'Low', 'Medium', 'High'];
  const SEV_ICON = ['i-ok', 'i-warning', 'i-warning', 'i-error'];

  /** A severity as an M3 assist chip: tonal for settled, outlined with "?" for to-confirm. */
  function badge(severity, contingent) {
    return el('span', {
      className: `badge ${sevClass(severity)}${contingent ? ' contingent' : ''}`,
      attrs: { title: contingent ? tr('ifApplies', SEV_LABEL[severity]) : SEV_LABEL[severity] },
    }, contingent ? icon('i-help', 'badge-icon') : null, SEV_LABEL[severity]);
  }

  /**
   * Beside a settled badge: how many findings in the row still need a check,
   * which the badge alone does not show (HSTS: a short max-age is certain, the
   * preload is to confirm).
   */
  function toConfirmMarker(r, contingent) {
    if (contingent) return null;
    const n = r.findings.filter((f) => f.severity > Severity.OK && isContingent(f)).length;
    if (!n) return null;
    const label = tr('moreToConfirm', n);
    return el('span', { className: 'badge contingent to-confirm-marker', attrs: { title: label, 'aria-label': label } },
      `+${n}`, icon('i-help', 'badge-icon'));
  }

  /** The leading element of a list item: the severity icon in a tonal circle. */
  function avatar(severity, contingent) {
    return el('span', { className: `avatar ${sevClass(severity)}` }, icon(contingent ? 'i-help' : SEV_ICON[severity]));
  }

  // --------------------------------------------------------------- language
  // The interface's own words. Findings, notes and the copied list come from
  // the engine in the same language (HL.i18n.localized).

  const UI_TEXT = {
    en: {
      langButton: 'IT', langSwitch: 'Passa all\'italiano',
      skip: 'Skip to results', profile: 'Profile', basic: 'Basic', extended: 'Extended',
      responseType: 'Response type', webPage: 'Web page', restApi: 'REST API', actions: 'Actions',
      samples: 'Samples', loadSample: 'Load a sample response', response: 'Response', pasteRaw: 'Paste a raw HTTP response',
      clear: 'Clear', clearInput: 'Clear the input', rawResponse: 'Raw HTTP response', results: 'Results',
      toLight: 'Switch to light theme', toDark: 'Switch to dark theme',
      profileHint: { basic: 'The core security headers: the standard review.', extended: 'Every header the analyzer knows, including legacy and deprecated ones.' },
      modeHint: { page: 'The response is a page a browser displays', api: 'The response is a call to an API read by a browser (OWASP REST Security Cheat Sheet)' },
      moreToConfirm: (n) => `${n} more finding${n === 1 ? '' : 's'} to confirm`,
      ifApplies: (sev) => `${sev} if it applies, to confirm`,
      analysisUpdated: (unconfirmed, sev, issues) => `Analysis updated. Overall ${unconfirmed ? 'unconfirmed ' : ''}${sev}. ${issues} header${issues === 1 ? '' : 's'} with issues.`,
      drawFailedTitle: 'The report could not be displayed', drawFailed: 'Something went wrong while drawing the results. Your input is untouched.',
      emptyTitle: 'No response yet', empty: 'Paste a raw HTTP response into the Response field. Header Analyzer reads its security headers the way a browser does and explains what each leaves open.',
      trySample: 'Try a sample', technicalDetails: 'Technical details',
      internalTitle: 'Header Analyzer hit an internal error', internal: 'This is a bug in Header Analyzer, not a verdict about the response. Please report it with the details below (they contain no part of your input).',
      nothingToAnalyse: 'Nothing to analyse',
      showAll: 'All findings', showAllDetail: 'Every header with a finding',
      showConfirmed: 'Confirmed', showConfirmedDetail: 'Settled by the response, or checked by you',
      showToConfirm: 'To confirm', showToConfirmDetail: 'Depend on a check the response cannot show',
      copyFindings: 'Copy findings',
      copiedAll: (n) => `${n} finding${n === 1 ? '' : 's'} copied`,
      copiedConfirmed: (n) => `${n} confirmed finding${n === 1 ? '' : 's'} copied`,
      copiedToConfirm: (n) => `${n} finding${n === 1 ? '' : 's'} to confirm copied`,
      readingNotes: (n) => `Reading notes (${n})`,
      show: 'Show', all: 'All', issues: 'Issues', toConfirm: 'To confirm', passing: 'Passing',
      search: 'Search headers and findings',
      noMatch: (q) => `No header or finding matches “${q}”.`, nothingInView: 'Nothing in this view.',
      notPresent: 'Not present', emptyValue: 'Empty value', notSent: 'The response does not send this header.',
      copyValue: 'Copy value', copyValueOf: (name) => `Copy the ${name} value`, valueCopied: 'Value copied',
      correctAbsent: 'Not sending it is the correct state for this header.', nothingToReport: 'Nothing to report.',
      confirmedManually: 'Confirmed manually', excluded: 'Excluded', confirmed: 'Confirmed', check: 'Check', recommendation: 'Recommendation',
      fineIf: 'Fine if', problemIf: 'Problem if', confirmedIf: 'Confirmed if', excludedIf: 'Excluded if',
      checkResult: 'Result of the check', markedConfirmed: 'Marked as confirmed', markedExcluded: 'Marked as excluded', backToConfirm: 'Back to confirm',
      sources: (n) => `Sources (${n})`,
      textToCopy: 'Text to copy', copyManually: 'Copy manually',
      clipboardRefused: 'This page may not write to the clipboard. The text is selected: press Ctrl+C (⌘C on a Mac).', close: 'Close',
      noFiles: 'Files are not opened: paste the response instead',
      crashed: 'Something went wrong in Header Analyzer. Reload the page if it misbehaves.',
    },
    it: {
      langButton: 'EN', langSwitch: 'Switch to English',
      skip: 'Vai ai risultati', profile: 'Profilo', basic: 'Base', extended: 'Esteso',
      responseType: 'Tipo di risposta', webPage: 'Pagina web', restApi: 'REST API', actions: 'Azioni',
      samples: 'Esempi', loadSample: 'Carica una risposta di esempio', response: 'Risposta', pasteRaw: 'Incolla una risposta HTTP grezza',
      clear: 'Svuota', clearInput: 'Svuota il campo', rawResponse: 'Risposta HTTP grezza', results: 'Risultati',
      toLight: 'Passa al tema chiaro', toDark: 'Passa al tema scuro',
      profileHint: { basic: 'Gli header di sicurezza principali: la revisione standard.', extended: 'Tutti gli header che lo strumento conosce, compresi quelli legacy e deprecati.' },
      modeHint: { page: 'La risposta è una pagina visualizzata da un browser', api: 'La risposta è una chiamata a un\'API letta da un browser (OWASP REST Security Cheat Sheet)' },
      moreToConfirm: (n) => (n === 1 ? 'Un altro finding da confermare' : `Altri ${n} finding da confermare`),
      ifApplies: (sev) => `${sev} se si applica, da confermare`,
      analysisUpdated: (unconfirmed, sev, issues) => `Analisi aggiornata. Complessivo ${sev}${unconfirmed ? ', da confermare' : ''}. ${issues} header con problemi.`,
      drawFailedTitle: 'Non è stato possibile mostrare il report', drawFailed: 'Qualcosa è andato storto mentre venivano mostrati i risultati. Il tuo input non è stato toccato.',
      emptyTitle: 'Ancora nessuna risposta', empty: 'Incolla una risposta HTTP grezza nel campo Risposta. Header Analyzer legge i suoi header di sicurezza come fa un browser e spiega cosa lascia aperto ciascuno.',
      trySample: 'Prova un esempio', technicalDetails: 'Dettagli tecnici',
      internalTitle: 'Header Analyzer ha avuto un errore interno', internal: 'È un bug di Header Analyzer, non un giudizio sulla risposta. Segnalalo con i dettagli qui sotto (non contengono nulla del tuo input).',
      nothingToAnalyse: 'Niente da analizzare',
      showAll: 'Tutti i finding', showAllDetail: 'Ogni header con un finding',
      showConfirmed: 'Confermati', showConfirmedDetail: 'Certi dalla risposta, o verificati da te',
      showToConfirm: 'Da confermare', showToConfirmDetail: 'Dipendono da una verifica che la risposta non può mostrare',
      copyFindings: 'Copia i finding',
      copiedAll: (n) => (n === 1 ? '1 finding copiato' : `${n} finding copiati`),
      copiedConfirmed: (n) => (n === 1 ? '1 finding confermato copiato' : `${n} finding confermati copiati`),
      copiedToConfirm: (n) => (n === 1 ? '1 finding da confermare copiato' : `${n} finding da confermare copiati`),
      readingNotes: (n) => `Note di lettura (${n})`,
      show: 'Mostra', all: 'Tutti', issues: 'Problemi', toConfirm: 'Da confermare', passing: 'Superati',
      search: 'Cerca header e finding',
      noMatch: (q) => `Nessun header o finding corrisponde a “${q}”.`, nothingInView: 'Niente in questa vista.',
      notPresent: 'Non presente', emptyValue: 'Valore vuoto', notSent: 'La risposta non invia questo header.',
      copyValue: 'Copia il valore', copyValueOf: (name) => `Copia il valore di ${name}`, valueCopied: 'Valore copiato',
      correctAbsent: 'Non inviarlo è lo stato corretto per questo header.', nothingToReport: 'Niente da riportare.',
      confirmedManually: 'Confermato manualmente', excluded: 'Escluso', confirmed: 'Confermato', check: 'Verifica', recommendation: 'Raccomandazione',
      fineIf: 'Nessun problema se', problemIf: 'Problema se', confirmedIf: 'Confermato se', excludedIf: 'Escluso se',
      checkResult: 'Esito della verifica', markedConfirmed: 'Segnato come confermato', markedExcluded: 'Segnato come escluso', backToConfirm: 'Di nuovo da confermare',
      sources: (n) => `Fonti (${n})`,
      textToCopy: 'Testo da copiare', copyManually: 'Copia manualmente',
      clipboardRefused: 'Questa pagina potrebbe non poter scrivere negli appunti. Il testo è selezionato: premi Ctrl+C (⌘C su Mac).', close: 'Chiudi',
      noFiles: 'I file non vengono aperti: incolla invece la risposta',
      crashed: 'Qualcosa è andato storto in Header Analyzer. Ricarica la pagina se si comporta in modo strano.',
    },
  };

  /** The interface text for `key` in the current language; a function entry takes arguments. */
  function tr(key, ...args) {
    const v = UI_TEXT[state.lang][key];
    return typeof v === 'function' ? v(...args) : v;
  }

  /** A saved choice wins; without one, Italian for an Italian browser and English otherwise. */
  function initialLang() {
    const saved = storage.get('lang');
    if (HL.i18n.LANGS.includes(saved)) return saved;
    const nav = (navigator.languages && navigator.languages[0]) || navigator.language || '';
    return /^it\b/i.test(nav) ? 'it' : HL.i18n.DEFAULT_LANG;
  }

  /** The engine in the current language. */
  const core = () => HL.i18n.localized(state.lang).engine;

  // -------------------------------------------------------------------- state

  const state = {
    profile: HL.profiles.getProfile(storage.get('profile')).id,
    mode: HL.profiles.getMode(storage.get('mode')).id,
    lang: HL.i18n.DEFAULT_LANG,
    filter: 'all',
    query: '',
    report: null,
    open: new Set(),
    // Findings to confirm the user has checked: decisionKey -> 'confirmed' | 'excluded'.
    decisions: new Map(),
    lastInput: null,
  };

  // ---------------------------------------------------------------- feedback

  let toastTimer = 0;
  function toast(message) {
    const t = $('toast');
    t.textContent = message;
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, 2400);
  }

  function announce(message) {
    const a = $('announcer');
    a.textContent = '';
    // A fresh node each time makes screen readers repeat identical messages.
    setTimeout(() => { a.textContent = message; }, 30);
  }

  // ------------------------------------------------------------- appearance

  // A saved choice wins; without one the page follows the system, also when
  // the system setting changes while the page is open. theme.js applies the
  // saved choice before the first paint.
  const systemDark = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

  function savedTheme() {
    const t = storage.get('theme');
    return t === 'light' || t === 'dark' ? t : null;
  }

  function currentTheme() {
    return savedTheme() || (systemDark && systemDark.matches ? 'dark' : 'light');
  }

  function applyTheme() {
    const theme = currentTheme();
    if (savedTheme()) document.documentElement.setAttribute('data-theme', theme);
    else document.documentElement.removeAttribute('data-theme');
    const label = theme === 'dark' ? tr('toLight') : tr('toDark');
    const b = $('theme-button');
    b.setAttribute('aria-label', label);
    b.title = label;
  }


  // ---------------------------------------------------------------- profile

  function applyProfile() {
    for (const b of document.querySelectorAll('#profile-control [data-profile]')) {
      const on = b.dataset.profile === state.profile;
      b.setAttribute('aria-checked', String(on));
      b.tabIndex = on ? 0 : -1;
      b.title = tr('profileHint')[b.dataset.profile];
    }
  }

  function setProfile(id) {
    if (id === state.profile) return;
    state.profile = HL.profiles.getProfile(id).id;
    storage.set('profile', state.profile);
    applyProfile();
    runAnalysis(true);
  }

  // ------------------------------------------------------------------- mode
  // What the response is: the user's choice, never guessed from the response.

  function applyMode() {
    for (const b of document.querySelectorAll('#mode-control [data-mode]')) {
      const on = b.dataset.mode === state.mode;
      b.setAttribute('aria-checked', String(on));
      b.tabIndex = on ? 0 : -1;
      b.title = tr('modeHint')[b.dataset.mode];
    }
  }

  function setMode(id, analyse = true) {
    if (id === state.mode) return;
    state.mode = HL.profiles.getMode(id).id;
    storage.set('mode', state.mode);
    applyMode();
    if (analyse) runAnalysis(true);
  }

  function initSegmented(container, onSelect) {
    container.addEventListener('click', (e) => {
      const b = e.target.closest('button[role="radio"]');
      if (b) onSelect(b);
    });
    container.addEventListener('keydown', (e) => {
      const keys = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 };
      if (!(e.key in keys)) return;
      e.preventDefault();
      const items = [...container.querySelectorAll('button[role="radio"]')];
      const i = items.indexOf(document.activeElement);
      const next = items[(i + keys[e.key] + items.length) % items.length];
      next.focus();
      onSelect(next);
    });
  }

  // ------------------------------------------------------------------ menus

  let openMenu = null;

  function closeMenu(focusButton) {
    if (!openMenu) return;
    const { menu, button } = openMenu;
    menu.hidden = true;
    button.setAttribute('aria-expanded', 'false');
    openMenu = null;
    if (focusButton) button.focus();
  }

  function initMenu(button, menu, onAction) {
    const items = () => [...menu.querySelectorAll('button:not(:disabled)')];

    button.addEventListener('click', () => {
      if (openMenu && openMenu.menu === menu) { closeMenu(false); return; }
      closeMenu(false);
      menu.hidden = false;
      button.setAttribute('aria-expanded', 'true');
      openMenu = { menu, button };
      const first = items()[0];
      if (first) first.focus();
    });
    menu.addEventListener('click', (e) => {
      const item = e.target.closest('button');
      if (!item) return;
      closeMenu(true);
      onAction(item);
    });
    menu.addEventListener('keydown', (e) => {
      const list = items();
      const i = list.indexOf(document.activeElement);
      if (e.key === 'ArrowDown') { e.preventDefault(); list[(i + 1) % list.length].focus(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); list[(i - 1 + list.length) % list.length].focus(); }
      else if (e.key === 'Home') { e.preventDefault(); list[0].focus(); }
      else if (e.key === 'End') { e.preventDefault(); list[list.length - 1].focus(); }
      else if (e.key === 'Escape') { e.preventDefault(); closeMenu(true); }
      else if (e.key === 'Tab') { closeMenu(false); }
    });
  }

  document.addEventListener('pointerdown', (e) => {
    if (openMenu && !openMenu.menu.contains(e.target) && !openMenu.button.contains(e.target)) closeMenu(false);
  });

  // --------------------------------------------------------------- analysis

  let debounce = 0;
  function scheduleAnalysis() {
    clearTimeout(debounce);
    const size = $('input').value.length;
    debounce = setTimeout(() => runAnalysis(false), size > 200000 ? 350 : 120);
  }

  /** `keepDecisions`: the same response read again in another language, so the checks recorded still apply. */
  function runAnalysis(force, keepDecisions) {
    const text = $('input').value;
    $('clear-button').disabled = text === '';
    if (!force && text === state.lastInput) return;
    state.lastInput = text;

    const report = core().analyze(text, state.profile, state.mode);
    state.report = report;
    if (!keepDecisions) state.decisions.clear();
    render();
    if (report.ok) {
      const s = report.summary;
      const issues = report.results.filter((r) => worstSeverity(r) >= Severity.LOW).length;
      announce(tr('analysisUpdated', s.worstIsContingent, SEV_LABEL[s.worst], issues));
    }
  }

  // ---------------------------------------------------------------- render

  function render() {
    const root = $('results-root');
    try {
      root.replaceChildren(...buildResults(state.report));
    } catch (e) {
      root.replaceChildren(errorState(tr('drawFailedTitle'), tr('drawFailed'), e && e.stack ? e.stack : String(e)));
    }
  }

  function emptyState() {
    return el('div', { className: 'card empty-state' },
      el('span', { className: 'empty-icon' }, icon('i-inbox')),
      el('h3', { text: tr('emptyTitle') }),
      el('p', { text: tr('empty') }),
      el('button', {
        className: 'filled-button',
        attrs: { type: 'button' },
        on: { click: () => loadText(HL.samples.find((x) => x.id === 'legacy').text) },
      }, icon('i-sparkles'), tr('trySample')));
  }

  function errorState(title, message, detail) {
    return el('div', { className: 'card empty-state error', attrs: { role: 'alert' } },
      el('span', { className: 'empty-icon' }, icon('i-error')),
      el('h3', { text: title }),
      el('p', { text: message }),
      detail ? el('details', null, el('summary', { text: tr('technicalDetails') }), el('pre', { text: detail })) : null);
  }

  function buildResults(report) {
    if (!report || report.error === 'empty') return [emptyState()];
    if (report.error === 'internal') {
      return [errorState(tr('internalTitle'), tr('internal'), firstLine(report.detail))];
    }
    if (!report.ok) return [errorState(tr('nothingToAnalyse'), report.error)];

    const nodes = [];
    if (report.notes.length) nodes.push(notesCard(report.notes));
    const view = core().resolve(report, state.decisions);
    nodes.push(filterBar(report, view));
    nodes.push(...listSections(report, view));
    return nodes;
  }

  function firstLine(detail) {
    return String(detail || '').split('\n').slice(0, 6).join('\n');
  }

  /**
   * The findings list for a report: one `- <Header>: <status>. <brief>.` line
   * per header, copied from a menu. All, only the findings the response
   * settles, or only those to confirm.
   */
  const LIST_SHOW = [
    ['all', 'showAll', 'showAllDetail'],
    ['confirmed', 'showConfirmed', 'showConfirmedDetail'],
    ['toConfirm', 'showToConfirm', 'showToConfirmDetail'],
  ];

  function copyMenu(report) {
    const button = el('button', {
      className: 'tonal-button',
      attrs: { type: 'button', 'aria-haspopup': 'menu', 'aria-expanded': 'false', 'aria-controls': 'copy-menu', id: 'copy-button' },
    }, icon('i-copy'), tr('copyFindings'), icon('i-expand', 'trailing'));
    const menu = el('div', { className: 'menu', attrs: { id: 'copy-menu', role: 'menu', 'aria-labelledby': 'copy-button' } });
    menu.hidden = true;
    for (const [id, label, detail] of LIST_SHOW) {
      const count = core().findingList(report, { show: id }).length;
      menu.append(el('button', {
        className: 'two-line',
        attrs: { type: 'button', role: 'menuitem', 'data-show': id, disabled: !count },
      }, el('span', null, `${tr(label)} · ${count}`, el('span', { className: 'menu-detail', text: tr(detail) }))));
    }
    initMenu(button, menu, (item) => {
      const lines = core().findingList(report, { show: item.dataset.show });
      const done = { all: tr('copiedAll', lines.length), confirmed: tr('copiedConfirmed', lines.length), toConfirm: tr('copiedToConfirm', lines.length) }[item.dataset.show];
      copyText(lines.map((l) => `- ${l.text}`).join('\n'), done);
    });
    return el('div', { className: 'menu-anchor copy-anchor' }, button, menu);
  }

  function notesCard(notes) {
    const details = el('details', { className: 'card notes' },
      el('summary', null, icon('i-info', 'lead'), el('span', { text: tr('readingNotes', notes.length) }), icon('i-expand', 'chev')),
      el('ul', null, notes.map((n) => el('li', { text: n }))));
    if (notes.some((n) => /request|informational/.test(n))) details.open = true;
    return details;
  }

  /**
   * `r` is the result as the user's decisions leave it, `raw` as analysed.
   * "To confirm" keeps showing a row after its checks are decided, so the
   * decisions stay in view and can be changed.
   */
  function matchesFilter(r, raw) {
    if (state.filter === 'issues' && worstSeverity(r) < Severity.LOW) return false;
    if (state.filter === 'confirm' && !raw.findings.some(isContingent)) return false;
    if (state.query) {
      const q = state.query.toLowerCase();
      const hay = [raw.name, raw.value || '', ...raw.findings.map((f) => f.title)].join('\n').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }

  function filterBar(report, view) {
    const counts = {
      all: report.results.length,
      issues: view.results.filter((r) => worstSeverity(r) >= Severity.LOW).length,
      confirm: report.results.filter((r) => r.findings.some(isContingent)).length,
    };
    // M3 filter chips behaving as a single-choice group.
    const chips = el('div', { className: 'chip-set', attrs: { role: 'radiogroup', 'aria-label': tr('show') } });
    for (const [id, label] of [['all', tr('all')], ['issues', tr('issues')], ['confirm', tr('toConfirm')]]) {
      chips.append(el('button', {
        className: 'filter-chip',
        attrs: { type: 'button', role: 'radio', 'aria-checked': String(state.filter === id), tabindex: state.filter === id ? 0 : -1, 'data-filter': id },
      }, icon('i-check', 'chip-check'), `${label} · ${counts[id]}`));
    }
    initSegmented(chips, (b) => {
      if (state.filter === b.dataset.filter) return;
      state.filter = b.dataset.filter;
      render();
      const again = document.querySelector(`[data-filter="${state.filter}"]`);
      if (again) again.focus();
    });

    const input = el('input', {
      attrs: { type: 'search', placeholder: tr('search'), 'aria-label': tr('search'), value: state.query, id: 'search-input', autocomplete: 'off', spellcheck: 'false' },
    });
    input.addEventListener('input', () => {
      state.query = input.value.trim();
      for (const n of document.querySelectorAll('.result-section')) n.remove();
      $('results-root').append(...listSections(state.report, core().resolve(state.report, state.decisions)));
    });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && input.value) { e.stopPropagation(); input.value = ''; input.dispatchEvent(new Event('input')); }
    });
    return el('div', { className: 'filter-bar' },
      el('label', { className: 'search-bar' }, icon('i-search'), input),
      el('div', { className: 'filter-row' }, chips, copyMenu(view)));
  }

  function listSections(report, view) {
    const rows = view.results
      .map((r, order) => ({ r, raw: report.results[order], order, worst: worstSeverity(r) }))
      .filter(({ r, raw }) => matchesFilter(r, raw))
      .sort((a, b) => b.worst - a.worst || a.order - b.order);

    if (!rows.length) {
      return [el('div', { className: 'card no-match result-section', text: state.query ? tr('noMatch', state.query) : tr('nothingInView') })];
    }
    const bands = [
      [tr('issues'), (w) => w >= Severity.LOW],
      [tr('passing'), (w) => w === Severity.OK],
    ];
    const out = [];
    for (const [title, test] of bands) {
      const group = rows.filter(({ worst }) => test(worst));
      if (!group.length) continue;
      out.push(el('section', { className: 'result-section', attrs: { 'aria-label': title } },
        el('h3', { className: 'section-header' }, title, el('span', { className: 'section-count', text: String(group.length) })),
        el('div', { className: 'card list', attrs: { role: 'list' } }, group.map(({ r, raw }) => resultRow(r, raw)))));
    }
    return out;
  }

  /** `r` drives the row's badges, as the user's decisions leave it; `raw` lists every finding with its decision. */
  function resultRow(r, raw) {
    const worst = worstSeverity(r);
    const contingent = resultIsContingent(r);
    const absent = r.value === null;
    const empty = r.value !== null && r.value.trim() === '';

    const summary = el('summary', null,
      avatar(worst, contingent),
      el('div', { className: 'row-text' },
        el('div', { className: 'row-name', text: r.name }),
        el('div', { className: `row-value${absent || empty ? ' absent' : ''}`, text: absent ? tr('notPresent') : empty ? tr('emptyValue') : r.value })),
      el('span', { className: 'row-badges' }, badge(worst, contingent), toConfirmMarker(r, contingent)),
      icon('i-expand', 'row-chevron'));

    const detail = el('div', { className: 'row-detail' });
    if (absent) {
      detail.append(el('div', { className: 'value-block absent', text: tr('notSent') }));
    } else {
      detail.append(el('div', { className: 'value-block' },
        el('code', { text: empty ? '(empty)' : r.value }),
        el('button', {
          className: 'icon-button small',
          attrs: { type: 'button', title: tr('copyValue'), 'aria-label': tr('copyValueOf', r.name) },
          on: { click: () => copyText(r.value, tr('valueCopied')) },
        }, icon('i-copy'))));
    }
    const indexed = raw.findings.map((f, i) => ({ f, key: core().decisionKey(raw, i) }));
    const shown = indexed.filter(({ f }) => f.severity > Severity.OK || f.description || f.recommendation);
    const findings = (shown.length ? shown : indexed).slice().sort((a, b) => b.f.severity - a.f.severity);
    if (!findings.length) {
      detail.append(el('p', { className: 'finding-desc', text: absent ? tr('correctAbsent') : tr('nothingToReport') }));
    }
    for (const { f, key } of findings) detail.append(findingNode(f, key));

    const details = el('details', { className: 'row', attrs: { role: 'listitem', 'data-key': r.key } }, summary, detail);
    if (state.open.has(r.key)) details.open = true;
    details.addEventListener('toggle', () => {
      if (details.open) state.open.add(r.key); else state.open.delete(r.key);
    });
    return details;
  }

  const DECISION_LABEL = { confirmed: 'confirmedManually', excluded: 'excluded' };

  /**
   * A finding with a severity carries its badge; an OK finding is a note:
   * explained, never graded. A finding to confirm also carries the user's
   * decision: confirmed (settled from now on) or excluded (dropped).
   */
  function findingNode(f, key) {
    const note = f.severity === Severity.OK;
    const contingent = isContingent(f);
    const decision = contingent ? state.decisions.get(key) : undefined;
    const node = el('div', { className: `finding${note ? ' note' : ''}${decision ? ' decided-' + decision : ''}` },
      el('div', { className: 'finding-head' },
        note ? icon('i-info', 'note-icon') : badge(f.severity, contingent && decision !== 'confirmed'),
        el('span', { className: 'finding-title', text: f.title })));
    if (f.description) node.append(el('p', { className: 'finding-desc', text: f.description }));
    if (f.verify) {
      const label = note ? tr('check') : tr(DECISION_LABEL[decision] || 'toConfirm');
      node.append(el('div', { className: 'callout verify' }, icon(decision === 'confirmed' ? 'i-check' : 'i-help'),
        el('div', null, el('span', { className: 'callout-label', text: label }), el('p', { className: 'check-question', text: f.verify }), outcomes(f, note))));
    }
    if (contingent) node.append(decisionChips(key, decision));
    if (f.recommendation) {
      node.append(el('div', { className: 'callout rec' }, icon('i-bulb'),
        el('div', null, el('span', { className: 'callout-label', text: tr('recommendation') }), f.recommendation)));
    }
    if (f.sources.length) node.append(sourcesNode(f.sources));
    return node;
  }

  /**
   * The two answers to a check, one per line. On a finding to confirm they
   * read as the buttons below it; on an OK note, the problem a check would
   * show and its absence.
   */
  function outcomes(f, note) {
    const rows = note
      ? [['i-check', tr('fineIf'), f.excludeIf], ['i-close', tr('problemIf'), f.confirmIf]]
      : [['i-check', tr('confirmedIf'), f.confirmIf], ['i-close', tr('excludedIf'), f.excludeIf]];
    return el('ul', { className: 'check-outcomes' }, rows.filter(([, , text]) => text).map(([ic, label, text]) =>
      el('li', null, icon(ic), el('span', null, el('strong', { text: `${label}: ` }), text))));
  }

  /** Two toggles under a finding to confirm; pressing the active one again reopens it. */
  function decisionChips(key, decision) {
    const set = el('div', { className: 'chip-set decision-set', attrs: { role: 'group', 'aria-label': tr('checkResult') } });
    for (const [value, label] of [['confirmed', tr('confirmed')], ['excluded', tr('excluded')]]) {
      set.append(el('button', {
        className: 'filter-chip',
        attrs: { type: 'button', 'aria-pressed': String(decision === value), 'data-decision': `${key}|${value}` },
        on: { click: () => decide(key, decision === value ? null : value) },
      }, icon('i-check', 'chip-check'), label));
    }
    return set;
  }

  function decide(key, value) {
    if (value) state.decisions.set(key, value); else state.decisions.delete(key);
    render();
    const again = document.querySelector(`[data-decision="${CSS.escape(key)}|${value || 'confirmed'}"]`);
    if (again) again.focus();
    announce(value === 'confirmed' ? tr('markedConfirmed') : value === 'excluded' ? tr('markedExcluded') : tr('backToConfirm'));
  }

  /**
   * The passages a finding rests on. Each link carries a text fragment, so the
   * page opens scrolled to the quoted passage with it highlighted.
   */
  function sourcesNode(ids) {
    const items = ids.map((id) => {
      const c = HL.sources.cite(id);
      return el('li', null,
        el('a', {
          className: 'source-link',
          attrs: { href: c.url, target: '_blank', rel: 'noopener noreferrer', referrerpolicy: 'no-referrer' },
        }, el('span', { text: c.title }), icon('i-open', 'source-open')),
        el('q', { className: 'source-quote', text: c.quote }));
    });
    return el('details', { className: 'sources' },
      el('summary', null, icon('i-expand', 'chev'), el('span', { text: tr('sources', ids.length) })),
      el('ol', null, items));
  }

  // ------------------------------------------------------------------ input

  function loadText(text) {
    const input = $('input');
    input.value = text;
    input.scrollTop = 0;
    state.open.clear();
    runAnalysis(true);
  }

  /** Copy through the old selection API, for pages where the clipboard API is refused. */
  function copyBySelection(text) {
    const ta = el('textarea', { attrs: { readonly: true, 'aria-hidden': 'true' } });
    ta.value = text;
    ta.className = 'visually-hidden';
    document.body.append(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (_) { ok = false; }
    ta.remove();
    return ok;
  }

  /** Last resort: the text in a dialog, already selected, to copy by hand. */
  function manualCopy(text) {
    const area = el('textarea', { className: 'manual-copy-text', attrs: { readonly: true, rows: 10, 'aria-label': tr('textToCopy') } });
    area.value = text;
    const dialog = el('dialog', { className: 'manual-copy', attrs: { 'aria-labelledby': 'manual-copy-title' } },
      el('h3', { text: tr('copyManually'), attrs: { id: 'manual-copy-title' } }),
      el('p', { className: 'subtitle', text: tr('clipboardRefused') }),
      area,
      el('div', { className: 'dialog-actions' },
        el('button', { className: 'filled-button', text: tr('close'), attrs: { type: 'button' }, on: { click: () => dialog.close() } })));
    dialog.addEventListener('close', () => dialog.remove());
    document.body.append(dialog);
    dialog.showModal();
    area.focus();
    area.select();
  }

  async function copyText(text, done) {
    let ok = false;
    if (navigator.clipboard && window.isSecureContext) {
      try { await navigator.clipboard.writeText(text); ok = true; } catch (_) { ok = false; }
    }
    if (!ok) ok = copyBySelection(text);
    if (ok) toast(done);
    else manualCopy(text);
  }

  // ------------------------------------------------------------------- init

  /** The samples menu, in the current language. */
  function fillSamples() {
    $('samples-menu').replaceChildren(...HL.samples.map((s) => {
      const label = (s.label && s.label[state.lang]) || s.label.en;
      return el('button', { className: 'two-line', attrs: { type: 'button', role: 'menuitem', 'data-sample': s.id } },
        icon('i-sparkles'), el('span', null, label.name, el('span', { className: 'menu-detail', text: label.detail })));
    }));
  }

  /**
   * The static page in the current language: elements carry data-i18n (their
   * text) or data-i18n-attr ("attribute:key; ..."), keys of UI_TEXT.
   */
  function applyLanguage() {
    document.documentElement.lang = state.lang;
    for (const n of document.querySelectorAll('[data-i18n]')) n.textContent = tr(n.dataset.i18n);
    for (const n of document.querySelectorAll('[data-i18n-attr]')) {
      for (const pair of n.dataset.i18nAttr.split(';')) {
        const [attr, key] = pair.split(':').map((x) => x.trim());
        if (attr && key) n.setAttribute(attr, tr(key));
      }
    }
    const b = $('lang-button');
    b.querySelector('.lang-code').textContent = tr('langButton');
    b.setAttribute('aria-label', tr('langSwitch'));
    b.title = tr('langSwitch');
    applyTheme();
    applyProfile();
    applyMode();
    fillSamples();
  }

  function setLang(lang) {
    state.lang = HL.i18n.LANGS.includes(lang) ? lang : HL.i18n.DEFAULT_LANG;
    storage.set('lang', state.lang);
    applyLanguage();
    runAnalysis(true, true);
  }

  function init() {
    state.lang = initialLang();
    applyLanguage();
    applyTheme();
    applyProfile();
    applyMode();

    const input = $('input');
    input.addEventListener('input', scheduleAnalysis);

    initSegmented($('profile-control'), (b) => setProfile(b.dataset.profile));
    initSegmented($('mode-control'), (b) => setMode(b.dataset.mode));

    const samplesMenu = $('samples-menu');
    fillSamples();
    initMenu($('samples-button'), samplesMenu, (item) => {
      const s = HL.samples.find((x) => x.id === item.dataset.sample);
      if (s) {
        if (s.mode) setMode(s.mode, false);
        loadText(s.text);
      }
    });
    $('lang-button').addEventListener('click', () => setLang(state.lang === 'it' ? 'en' : 'it'));
    $('theme-button').addEventListener('click', () => {
      storage.set('theme', currentTheme() === 'dark' ? 'light' : 'dark');
      applyTheme();
    });
    if (systemDark && systemDark.addEventListener) systemDark.addEventListener('change', () => { if (!savedTheme()) applyTheme(); });

    $('clear-button').addEventListener('click', () => { loadText(''); input.focus(); });

    // Files are not opened. A file dropped by mistake would make the browser
    // navigate to it and lose what was pasted, so the drop is caught and refused.
    const isFileDrag = (e) => e.dataTransfer && [...e.dataTransfer.types].includes('Files');
    window.addEventListener('dragover', (e) => { if (isFileDrag(e)) e.preventDefault(); });
    window.addEventListener('drop', (e) => {
      if (!isFileDrag(e)) return;
      e.preventDefault();
      toast(tr('noFiles'));
    });

    document.addEventListener('keydown', (e) => {
      const mod = e.metaKey || e.ctrlKey;
      if (e.key === 'Escape' && openMenu) {
        closeMenu(true);
      } else if (e.key === '/' && !mod && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) {
        const search = $('search-input');
        if (search) { e.preventDefault(); search.focus(); }
      }
    });

    // M3 top app bar: it takes the surface-container tone once content scrolls under it.
    const bar = document.querySelector('.top-app-bar');
    const onScroll = () => bar.classList.toggle('scrolled', window.scrollY > 0);
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();

    window.addEventListener('error', (e) => {
      // Something escaped every handler: say so rather than fail silently.
      toast(tr('crashed'));
      if (window.console) console.error(e.error || e.message);
    });

    runAnalysis(true);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})(globalThis.HeaderAnalyzer = globalThis.HeaderAnalyzer || {});
