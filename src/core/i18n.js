/*
 * Header Analyzer: languages.
 *
 * Every module that writes text a person reads (the parser's notes, the CSP
 * and header rules, the correlations, the findings list) is a body run with
 * L(english, italian), which returns the string for its language. The body
 * runs once in English straight away, so HL.rules, HL.csp and the rest are
 * the English modules; localized(lang) runs the same bodies again on a copy
 * of the namespace for another language. Rules and grades are the same code
 * in every language: only the strings differ.
 */
(function (HL) {
  'use strict';

  const LANGS = Object.freeze(['en', 'it']);
  const DEFAULT_LANG = 'en';
  const bodies = [];
  const instances = new Map();

  const pick = (lang) => (lang === 'it' ? (en, it) => it : (en) => en);

  /** Register a module body, and run it now in English on HL itself. */
  function module(body) {
    bodies.push(body);
    body(HL, pick(DEFAULT_LANG));
  }

  /** The namespace in `lang`: HL itself for English, a localized copy otherwise. */
  function localized(lang) {
    if (!LANGS.includes(lang) || lang === DEFAULT_LANG) return HL;
    if (!instances.has(lang)) {
      const ns = Object.create(HL);
      for (const body of bodies) body(ns, pick(lang));
      instances.set(lang, ns);
    }
    return instances.get(lang);
  }

  HL.i18n = Object.freeze({ LANGS, DEFAULT_LANG, module, localized });
})(globalThis.HeaderAnalyzer = globalThis.HeaderAnalyzer || {});
