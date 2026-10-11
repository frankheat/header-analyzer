/*
 * Header Analyzer: the interface.
 *
 * Rules this file keeps:
 *   - every piece of text that came from the input reaches the page through
 *     textContent or a text node, never through innerHTML;
 *   - the input is never persisted: only the profile and appearance choices;
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
      attrs: { title: contingent ? `${SEV_LABEL[severity]} if it applies, to confirm` : SEV_LABEL[severity] },
    }, contingent ? icon('i-help', 'badge-icon') : null, SEV_LABEL[severity]);
  }

  /** The leading element of a list item: the severity icon in a tonal circle. */
  function avatar(severity, contingent) {
    return el('span', { className: `avatar ${sevClass(severity)}` }, icon(contingent ? 'i-help' : SEV_ICON[severity]));
  }

  // -------------------------------------------------------------------- state

  const state = {
    profile: HL.profiles.getProfile(storage.get('profile')).id,
    filter: 'all',
    query: '',
    listShow: 'all',
    report: null,
    open: new Set(),
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
    const label = theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';
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
      b.title = HL.profiles.getProfile(b.dataset.profile).summary;
    }
  }

  function setProfile(id) {
    if (id === state.profile) return;
    state.profile = HL.profiles.getProfile(id).id;
    storage.set('profile', state.profile);
    applyProfile();
    runAnalysis(true);
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

  function initMenu(buttonId, menuId, onAction) {
    const button = $(buttonId);
    const menu = $(menuId);
    const items = () => [...menu.querySelectorAll('button')];

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

  function runAnalysis(force) {
    const text = $('input').value;
    $('clear-button').disabled = text === '';
    if (!force && text === state.lastInput) return;
    state.lastInput = text;

    const report = HL.engine.analyze(text, state.profile);
    state.report = report;
    render();
    if (report.ok) {
      const s = report.summary;
      const issues = report.results.filter((r) => worstSeverity(r) >= Severity.LOW).length;
      announce(`Analysis updated. Overall ${s.worstIsContingent ? 'unconfirmed ' : ''}${SEV_LABEL[s.worst]}. ${issues} header${issues === 1 ? '' : 's'} with issues.`);
    }
  }

  // ---------------------------------------------------------------- render

  function render() {
    const root = $('results-root');
    try {
      root.replaceChildren(...buildResults(state.report));
    } catch (e) {
      root.replaceChildren(errorState('The report could not be displayed', 'Something went wrong while drawing the results. Your input is untouched.', e && e.stack ? e.stack : String(e)));
    }
  }

  function emptyState() {
    return el('div', { className: 'card empty-state' },
      el('span', { className: 'empty-icon' }, icon('i-inbox')),
      el('h3', { text: 'No response yet' }),
      el('p', { text: 'Paste a raw HTTP response into the Response field. Header Analyzer reads its security headers the way a browser does and explains what each leaves open.' }),
      el('button', {
        className: 'filled-button',
        attrs: { type: 'button' },
        on: { click: () => loadText(HL.samples.find((x) => x.id === 'legacy').text) },
      }, icon('i-sparkles'), 'Try a sample'));
  }

  function errorState(title, message, detail) {
    return el('div', { className: 'card empty-state error', attrs: { role: 'alert' } },
      el('span', { className: 'empty-icon' }, icon('i-error')),
      el('h3', { text: title }),
      el('p', { text: message }),
      detail ? el('details', null, el('summary', { text: 'Technical details' }), el('pre', { text: detail })) : null);
  }

  function buildResults(report) {
    if (!report || report.error === 'empty') return [emptyState()];
    if (report.error === 'internal') {
      return [errorState('Header Analyzer hit an internal error', 'This is a bug in Header Analyzer, not a verdict about the response. Please report it with the details below (they contain no part of your input).', firstLine(report.detail))];
    }
    if (!report.ok) return [errorState('Nothing to analyse', report.error)];

    const nodes = [findingListCard(report)];
    if (report.notes.length) nodes.push(notesCard(report.notes));
    nodes.push(filterBar(report));
    nodes.push(...listSections(report));
    return nodes;
  }

  function firstLine(detail) {
    return String(detail || '').split('\n').slice(0, 6).join('\n');
  }

  /** The bulleted list: one `<Header>: <status>. <brief>.` line per finding. */
  const LIST_SHOW = [['all', 'All'], ['confirmed', 'Confirmed'], ['toConfirm', 'To confirm']];

  function findingListCard(report) {
    const lines = HL.engine.findingList(report, { show: state.listShow });

    // M3 filter chips behaving as a single-choice group, as in the filter bar.
    const chips = el('div', { className: 'chip-set', attrs: { role: 'radiogroup', 'aria-label': 'List' } });
    for (const [id, label] of LIST_SHOW) {
      const count = HL.engine.findingList(report, { show: id }).length;
      chips.append(el('button', {
        className: 'filter-chip',
        attrs: { type: 'button', role: 'radio', 'aria-checked': String(state.listShow === id), tabindex: state.listShow === id ? 0 : -1, 'data-list-show': id },
      }, icon('i-check', 'chip-check'), `${label} · ${count}`));
    }
    initSegmented(chips, (btn) => {
      if (state.listShow === btn.dataset.listShow) return;
      state.listShow = btn.dataset.listShow;
      refreshList(state.listShow);
    });

    const list = lines.length
      ? el('ul', { className: 'finding-list' }, lines.map((l) => el('li', {
        className: `sev-${l.severity.toLowerCase()}`,
        attrs: { title: l.items.map((it) => `${it.status}: ${it.brief}`).join('\n') },
      },
        el('span', { className: 'fl-text' },
          el('button', {
            className: 'fl-header', text: l.header,
            attrs: { type: 'button', title: `Show the ${l.header} details` },
            on: { click: () => revealRow(l.header) },
          }), ': ',
          el('span', { className: `fl-status fl-${l.status.toLowerCase()}`, text: l.status }), `. ${l.brief}.`),
        badge(HL.models.Severity[l.severity], l.toConfirm))))
      : el('p', { className: 'fl-empty', text: 'No findings to list with these options.' });

    return el('section', { className: 'card findings-list-card', attrs: { 'aria-labelledby': 'fl-title', id: 'findings-list' } },
      el('div', { className: 'fl-head' },
        el('div', null,
          el('h3', { text: 'Findings list', attrs: { id: 'fl-title' } }),
          el('p', { className: 'subtitle', text: `${lines.length} finding${lines.length === 1 ? '' : 's'} · Header: Status. Description.` })),
        el('button', {
          className: 'icon-button',
          attrs: { type: 'button', title: 'Copy the list', 'aria-label': 'Copy the findings list', disabled: !lines.length },
          on: { click: () => copyText(lines.map((l) => `- ${l.text}`).join('\n'), 'Findings list copied') },
        }, icon('i-copy'))),
      chips,
      list);
  }

  /** Open a header's row in the detailed list and bring it into view. */
  function revealRow(headerName) {
    const result = state.report && state.report.results.find((r) => r.name === headerName);
    if (!result) return;
    let row = document.querySelector(`.row[data-key="${result.key}"]`);
    if (!row && (state.filter !== 'all' || state.query)) {
      // Hidden by the current filter: show everything, then look again.
      state.filter = 'all';
      state.query = '';
      render();
      row = document.querySelector(`.row[data-key="${result.key}"]`);
    }
    if (!row) return;
    row.open = true;
    state.open.add(result.key);
    const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    row.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
    row.querySelector('summary').focus({ preventScroll: true });
  }

  function refreshList(focusKey) {
    const old = $('findings-list');
    if (old && state.report && state.report.ok) old.replaceWith(findingListCard(state.report));
    const again = focusKey && document.querySelector(`[data-list-show="${focusKey}"]`);
    if (again) again.focus();
  }

  function notesCard(notes) {
    const details = el('details', { className: 'card notes' },
      el('summary', null, icon('i-info', 'lead'), el('span', { text: `Reading notes (${notes.length})` }), icon('i-expand', 'chev')),
      el('ul', null, notes.map((n) => el('li', { text: n }))));
    if (notes.some((n) => /request|informational/.test(n))) details.open = true;
    return details;
  }

  function matchesFilter(r) {
    if (state.filter === 'issues' && worstSeverity(r) < Severity.LOW) return false;
    if (state.filter === 'confirm' && !r.findings.some(isContingent)) return false;
    if (state.query) {
      const q = state.query.toLowerCase();
      const hay = [r.name, r.value || '', ...r.findings.map((f) => f.title)].join('\n').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }

  function filterBar(report) {
    const counts = {
      all: report.results.length,
      issues: report.results.filter((r) => worstSeverity(r) >= Severity.LOW).length,
      confirm: report.results.filter((r) => r.findings.some(isContingent)).length,
    };
    // M3 filter chips behaving as a single-choice group.
    const chips = el('div', { className: 'chip-set', attrs: { role: 'radiogroup', 'aria-label': 'Show' } });
    for (const [id, label] of [['all', 'All'], ['issues', 'Issues'], ['confirm', 'To confirm']]) {
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
      attrs: { type: 'search', placeholder: 'Search headers and findings', 'aria-label': 'Search headers and findings', value: state.query, id: 'search-input', autocomplete: 'off', spellcheck: 'false' },
    });
    input.addEventListener('input', () => {
      state.query = input.value.trim();
      for (const n of document.querySelectorAll('.result-section')) n.remove();
      $('results-root').append(...listSections(state.report));
    });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && input.value) { e.stopPropagation(); input.value = ''; input.dispatchEvent(new Event('input')); }
    });
    return el('div', { className: 'filter-bar' },
      el('label', { className: 'search-bar' }, icon('i-search'), input),
      chips);
  }

  function listSections(report) {
    const rows = report.results
      .map((r, order) => ({ r, order, worst: worstSeverity(r) }))
      .filter(({ r }) => matchesFilter(r))
      .sort((a, b) => b.worst - a.worst || a.order - b.order);

    if (!rows.length) {
      return [el('div', { className: 'card no-match result-section', text: state.query ? `No header or finding matches “${state.query}”.` : 'Nothing in this view.' })];
    }
    const bands = [
      ['Issues', (w) => w >= Severity.LOW],
      ['Passing', (w) => w === Severity.OK],
    ];
    const out = [];
    for (const [title, test] of bands) {
      const group = rows.filter(({ worst }) => test(worst));
      if (!group.length) continue;
      out.push(el('section', { className: 'result-section', attrs: { 'aria-label': title } },
        el('h3', { className: 'section-header' }, title, el('span', { className: 'section-count', text: String(group.length) })),
        el('div', { className: 'card list', attrs: { role: 'list' } }, group.map(({ r }) => resultRow(r)))));
    }
    return out;
  }

  function resultRow(r) {
    const worst = worstSeverity(r);
    const contingent = resultIsContingent(r);
    const absent = r.value === null;
    const empty = r.value !== null && r.value.trim() === '';

    const summary = el('summary', null,
      avatar(worst, contingent),
      el('div', { className: 'row-text' },
        el('div', { className: 'row-name', text: r.name }),
        el('div', { className: `row-value${absent || empty ? ' absent' : ''}`, text: absent ? 'Not present' : empty ? 'Empty value' : r.value })),
      badge(worst, contingent),
      icon('i-expand', 'row-chevron'));

    const detail = el('div', { className: 'row-detail' });
    if (absent) {
      detail.append(el('div', { className: 'value-block absent', text: 'The response does not send this header.' }));
    } else {
      detail.append(el('div', { className: 'value-block' },
        el('code', { text: empty ? '(empty)' : r.value }),
        el('button', {
          className: 'icon-button small',
          attrs: { type: 'button', title: 'Copy value', 'aria-label': `Copy the ${r.name} value` },
          on: { click: () => copyText(r.value, 'Value copied') },
        }, icon('i-copy'))));
    }
    const shown = r.findings.filter((f) => f.severity > Severity.OK || f.description || f.recommendation);
    const findings = (shown.length ? shown : r.findings).slice().sort((a, b) => b.severity - a.severity);
    if (!findings.length) {
      detail.append(el('p', { className: 'finding-desc', text: absent ? 'Not sending it is the correct state for this header.' : 'Nothing to report.' }));
    }
    for (const f of findings) detail.append(findingNode(f));

    const details = el('details', { className: 'row', attrs: { role: 'listitem', 'data-key': r.key } }, summary, detail);
    if (state.open.has(r.key)) details.open = true;
    details.addEventListener('toggle', () => {
      if (details.open) state.open.add(r.key); else state.open.delete(r.key);
    });
    return details;
  }

  /** A finding with a severity carries its badge; an OK finding is a note: explained, never graded. */
  function findingNode(f) {
    const note = f.severity === Severity.OK;
    const node = el('div', { className: `finding${note ? ' note' : ''}` },
      el('div', { className: 'finding-head' },
        note ? icon('i-info', 'note-icon') : badge(f.severity, isContingent(f)),
        el('span', { className: 'finding-title', text: f.title })));
    if (f.description) node.append(el('p', { className: 'finding-desc', text: f.description }));
    if (f.verify) {
      node.append(el('div', { className: 'callout verify' }, icon('i-help'),
        el('div', null, el('span', { className: 'callout-label', text: note ? 'Check' : 'To confirm' }), f.verify)));
    }
    if (f.recommendation) {
      node.append(el('div', { className: 'callout rec' }, icon('i-bulb'),
        el('div', null, el('span', { className: 'callout-label', text: 'Recommendation' }), f.recommendation)));
    }
    if (f.sources.length) node.append(sourcesNode(f.sources));
    return node;
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
      el('summary', null, icon('i-expand', 'chev'), el('span', { text: `Sources (${ids.length})` })),
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

  async function copyText(text, done) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        const ta = el('textarea', { attrs: { readonly: true, 'aria-hidden': 'true' } });
        ta.value = text;
        ta.className = 'visually-hidden';
        document.body.append(ta);
        ta.select();
        const ok = document.execCommand('copy');
        ta.remove();
        if (!ok) throw new Error('copy failed');
      }
      toast(done);
    } catch (_) {
      toast('Copying is not allowed here: select the text and copy it manually');
    }
  }

  // ------------------------------------------------------------------- init

  function init() {
    applyTheme();
    applyProfile();

    const input = $('input');
    input.addEventListener('input', scheduleAnalysis);

    initSegmented($('profile-control'), (b) => setProfile(b.dataset.profile));

    const samplesMenu = $('samples-menu');
    for (const s of HL.samples) {
      samplesMenu.append(el('button', { className: 'two-line', attrs: { type: 'button', role: 'menuitem', 'data-sample': s.id } },
        icon('i-sparkles'), el('span', null, s.name, el('span', { className: 'menu-detail', text: s.detail }))));
    }
    initMenu('samples-button', 'samples-menu', (item) => {
      const s = HL.samples.find((x) => x.id === item.dataset.sample);
      if (s) loadText(s.text);
    });
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
      toast('Files are not opened: paste the response instead');
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
      toast('Something went wrong in Header Analyzer. Reload the page if it misbehaves.');
      if (window.console) console.error(e.error || e.message);
    });

    runAnalysis(true);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})(globalThis.HeaderAnalyzer = globalThis.HeaderAnalyzer || {});
