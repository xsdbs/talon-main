// --- SHARED HELPERS ---
// Pure functions only: formatting, escaping, and small DOM-free utilities.
// Anything that reaches for State or the document belongs elsewhere.

/** Escape for use in element text content built by string concatenation. */
export function escapeHTML(str) {
  return String(str == null ? '' : str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/** Escape for use inside a double-quoted HTML attribute. */
export function escapeAttr(str) {
  return escapeHTML(str).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Escapes first, so a message can never inject markup, then linkifies. The
// pattern only ever matches http(s), so javascript:/data: URLs can't slip in.
const URL_PATTERN = /(https?:\/\/[^\s<]+)/g;

export function linkify(str) {
  return escapeHTML(str).replace(URL_PATTERN, (url) => {
    // Trailing punctuation is usually sentence grammar, not part of the URL.
    const trailingMatch = url.match(/([.,!?;:)\]]+)$/);
    const trailing = trailingMatch ? trailingMatch[1] : '';
    const cleanUrl = trailing ? url.slice(0, -trailing.length) : url;
    if (!cleanUrl) return url;
    return `<a href="${cleanUrl}" target="_blank" rel="noopener noreferrer nofollow">${escapeHTML(cleanUrl)}</a>${trailing}`;
  });
}

/** Renders `code spans` and **bold** without a full markdown parser. */
export function richText(str) {
  return linkify(str)
    .replace(/`([^`\n]+)`/g, (_, code) => `<code>${code}</code>`)
    .replace(/\*\*([^*\n]+)\*\*/g, (_, b) => `<strong>${b}</strong>`)
    .replace(/\n/g, '<br>');
}

/**
 * Deterministic two-tone gradient from an ID, so every contact and group gets
 * a distinct, stable colour without needing an uploaded photo.
 */
export function avatarGradient(id) {
  if (!id) return 'linear-gradient(135deg, #64748b, #475569)';
  let hash = 0;
  for (let i = 0; i < id.length; i++) hash = (hash * 31 + id.charCodeAt(i)) >>> 0;
  const hueA = hash % 360;
  const hueB = (hueA + 40 + ((hash >> 8) % 40)) % 360;
  return `linear-gradient(135deg, hsl(${hueA}, 62%, 47%), hsl(${hueB}, 66%, 38%))`;
}

export function initials(name) {
  const clean = String(name || '?').trim();
  const parts = clean.split(/\s+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return clean.substring(0, 2).toUpperCase() || '??';
}

/* Clock format lives here as module state rather than being read from the
   store, because the dependency direction is util -> store: util may not
   import it. app.js pushes the setting in via setClockFormat() on boot and
   whenever it changes. */
let clockFormat = 'auto';   // auto | 12 | 24

export function setClockFormat(fmt) {
  clockFormat = fmt === '12' || fmt === '24' ? fmt : 'auto';
}

export function formatTime(ts) {
  const opts = { hour: '2-digit', minute: '2-digit' };
  if (clockFormat === '12') opts.hour12 = true;
  if (clockFormat === '24') opts.hour12 = false;
  return new Date(ts).toLocaleTimeString([], opts);
}

export function formatDuration(sec) {
  const m = Math.floor(sec / 60);
  const s = Math.floor(sec % 60);
  return `${m}:${s < 10 ? '0' : ''}${s}`;
}

export function formatBytes(n) {
  if (!n && n !== 0) return '';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

/** "now" / "12:04" / "Yesterday" / "Tue" / "14/03", chat-list style. */
export function relativeTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  const now = new Date();
  const diff = now - d;
  if (diff < 60_000) return 'now';

  const sameDay = d.toDateString() === now.toDateString();
  if (sameDay) return formatTime(ts);

  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (d.toDateString() === yesterday.toDateString()) return 'Yesterday';

  if (diff < 7 * 864e5) return d.toLocaleDateString([], { weekday: 'short' });
  return d.toLocaleDateString([], { day: '2-digit', month: '2-digit' });
}

/** "Today" / "Yesterday" / "Tuesday, 4 March", day-separator style. */
export function dayLabel(ts) {
  const d = new Date(ts);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) return 'Today';

  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (d.toDateString() === yesterday.toDateString()) return 'Yesterday';

  const sameYear = d.getFullYear() === now.getFullYear();
  return d.toLocaleDateString([], {
    weekday: 'long', day: 'numeric', month: 'long',
    year: sameYear ? undefined : 'numeric'
  });
}

export function dayKey(ts) {
  const d = new Date(ts);
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
}

export function truncate(str, n) {
  const s = String(str || '');
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

export function debounce(fn, ms) {
  let t = null;
  return function (...args) {
    clearTimeout(t);
    t = setTimeout(() => fn.apply(this, args), ms);
  };
}

/** Rough password strength 0–4, for the register meter. */
export function passwordScore(pw) {
  if (!pw) return 0;
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 14) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) score++;
  if (pw.length < 6) score = Math.min(score, 1);
  return Math.min(score, 4);
}

/** Inline SVG referencing the sprite defined in index.html. */
export function icon(name, size = 18) {
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" aria-hidden="true"><use href="#i-${name}"/></svg>`;
}

export function isImage(mime) {
  return typeof mime === 'string' && mime.startsWith('image/');
}
