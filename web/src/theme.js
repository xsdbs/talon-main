// --- THEME ENGINE ---
// Applies the four visual axes as data-* attributes on <html>. The CSS does
// everything else; nothing here knows about individual components.

import { State, persist } from './store.js';

export const ACCENTS = [
  { id: 'indigo', label: 'Indigo', css: 'hsl(232 89% 64%)' },
  { id: 'violet', label: 'Violet', css: 'hsl(265 85% 67%)' },
  { id: 'cyan',   label: 'Cyan',   css: 'hsl(189 88% 47%)' },
  { id: 'green',  label: 'Green',  css: 'hsl(152 62% 46%)' },
  { id: 'amber',  label: 'Amber',  css: 'hsl(38 92% 53%)' },
  { id: 'rose',   label: 'Rose',   css: 'hsl(344 84% 60%)' },
  { id: 'mono',   label: 'Mono',   css: 'hsl(0 0% 62%)' }
];

/**
 * Every concrete theme, with the scheme it belongs to and the surface colour
 * the OS chrome should match.
 *
 * `scheme` is what light-vs-dark styling keys off. It is written to
 * `data-scheme` on <html> so a rule can target "any light theme" without
 * enumerating them. Adding a theme means adding a row here, a `:root[data-theme=…]`
 * block in style.css, and a swatch class. Nothing else.
 *
 * Keep this list in sync with THEMES in web/public/theme-preload.js.
 */
export const THEMES = [
  { id: 'auto',     label: 'Auto',     scheme: null,    bar: null },
  { id: 'dark',     label: 'Dark',     scheme: 'dark',  bar: '#0e0e11' },
  { id: 'light',    label: 'Light',    scheme: 'light', bar: '#f7f7f8' },
  { id: 'oled',     label: 'OLED',     scheme: 'dark',  bar: '#000000' },
  { id: 'graphite', label: 'Graphite', scheme: 'dark',  bar: '#1e1f23' },
  { id: 'ash',      label: 'Ash',      scheme: 'light', bar: '#d8d9dd' },
  { id: 'paper',    label: 'Paper',    scheme: 'light', bar: '#f6f2ea' }
];

const BY_ID = Object.fromEntries(THEMES.map((t) => [t.id, t]));
const darkQuery = window.matchMedia('(prefers-color-scheme: dark)');

/** Resolves the stored preference ("auto") into a concrete theme id. */
export function resolvedTheme() {
  const pref = State.settings.theme || 'auto';
  if (pref === 'auto' || !BY_ID[pref]) return darkQuery.matches ? 'dark' : 'light';
  return pref;
}

/** 'light' | 'dark' for the theme currently in effect. */
export function resolvedScheme() {
  return BY_ID[resolvedTheme()]?.scheme || 'dark';
}

export function applyTheme() {
  const root = document.documentElement;
  const s = State.settings;
  const theme = resolvedTheme();
  const def = BY_ID[theme];

  root.dataset.theme = theme;
  root.dataset.scheme = def.scheme;
  root.dataset.accent = s.accent || 'indigo';
  root.dataset.density = s.density || 'cozy';
  root.dataset.motion = s.motion || 'full';
  root.dataset.corners = s.bubbleCorners || 'round';
  root.dataset.font = s.uiFont || 'inter';
  root.style.setProperty('--font-scale', String(s.fontScale || 1));

  // Keep the browser/OS chrome in step with the app surface.
  const meta = document.getElementById('meta-theme-color');
  if (meta) meta.setAttribute('content', def.bar);
}

/** Mutates one setting, persists, and re-applies. */
export function setSetting(key, value) {
  State.settings[key] = value;
  persist.settings();
  applyTheme();
}

// Track the OS preference so "auto" stays live without a reload.
darkQuery.addEventListener('change', () => {
  if ((State.settings.theme || 'auto') === 'auto') applyTheme();
});
