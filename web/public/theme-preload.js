// Applies the saved appearance before first paint so there is no flash of the
// wrong colour scheme. Deliberately a separate, dependency-free file rather
// than an inline <script>: a strict Content-Security-Policy forbids inline
// script, and this has to run before the (much larger) app bundle loads.
//
// web/src/theme.js takes over once the bundle is up. Both read the same
// `talon_appearance` key. Keep the two in sync, including the theme table.
(function () {
  // id -> [scheme, browser-chrome colour]. Mirrors THEMES in web/src/theme.js.
  var THEMES = {
    dark:     ['dark',  '#0e0e11'],
    light:    ['light', '#f7f7f8'],
    oled:     ['dark',  '#000000'],
    graphite: ['dark',  '#1e1f23'],
    ash:      ['light', '#d8d9dd'],
    paper:    ['light', '#f6f2ea']
  };

  try {
    var raw = localStorage.getItem('talon_appearance');
    var s = raw ? JSON.parse(raw) : {};
    var root = document.documentElement;

    // Graphite is the default, matching DEFAULT_SETTINGS in web/src/store.js.
    // Only an explicit 'auto' follows the OS.
    var theme = s.theme || 'graphite';
    if (theme === 'auto' || !THEMES[theme]) {
      theme = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    }
    var def = THEMES[theme];

    root.dataset.theme = theme;
    root.dataset.scheme = def[0];
    root.dataset.accent = s.accent || 'indigo';
    root.dataset.density = s.density || 'cozy';
    root.dataset.motion = s.motion || 'full';
    root.dataset.corners = s.bubbleCorners || 'round';
    root.dataset.font = s.uiFont || 'inter';
    if (s.fontScale) root.style.setProperty('--font-scale', s.fontScale);

    var meta = document.getElementById('meta-theme-color');
    if (meta) meta.setAttribute('content', def[1]);
  } catch (e) {
    /* first run, or storage blocked, so the defaults on <html> stand */
  }
})();
