/*
 * Header Analyzer: the theme, set in <head> before the first paint so a saved
 * choice never flashes the other theme. A saved "light" or "dark" wins;
 * without one the page follows the system setting (the stylesheet handles it).
 * app.js adds the light/dark switch.
 */
(function () {
  'use strict';
  let saved = null;
  try { saved = window.localStorage.getItem('header-analyzer.theme'); } catch (_) { /* private mode */ }
  if (saved === 'light' || saved === 'dark') document.documentElement.setAttribute('data-theme', saved);
})();
