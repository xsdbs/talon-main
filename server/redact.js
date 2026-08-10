// --- LOG REDACTION ---
//
// The relay's log is the richest metadata store on the machine. It has always
// been more revealing than db.json: every request URL, every client IP, every
// routing pair, and a presence line saying which conversation someone has open
// right now. Message content was never in it, but "who talks to whom, when,
// and what they are reading" was, in plain text, on disk, forever.
//
// Comprehensive logging is a deliberate feature of this project and the point
// is not to throw it away. In `strict` mode every event still prints, with its
// tag, its outcome and its timing. What changes is that the identities become
// per-boot pseudonyms and the addresses become classes.
//
//   TALON_LOG_PRIVACY=strict   (default) pseudonymous identities, no IPs
//   TALON_LOG_PRIVACY=full     the old behaviour, for debugging
//
// The pseudonym salt is 16 random bytes generated at boot and never written
// anywhere. Two consequences, both deliberate:
//
//   1. Within one run the same account always prints as the same short label,
//      so a session is still followable end to end while debugging.
//   2. Across restarts the labels change, and because the salt does not exist
//      on disk, a captured log cannot be brute-forced back to a username or an
//      identity key even though both come from small, guessable spaces.
//
// That second property is the reason this is an HMAC under a random salt
// rather than a plain hash or a truncated id.

import crypto from 'crypto';

const MODE = String(process.env.TALON_LOG_PRIVACY || 'strict').toLowerCase();
export const LOG_PRIVACY = MODE === 'full' ? 'full' : 'strict';
export const redacting = LOG_PRIVACY !== 'full';

const BOOT_SALT = crypto.randomBytes(16);

/**
 * A stable per-boot label for a username or an identity key.
 *
 * In `full` mode identity keys keep the old 8-hex-prefix form so the output
 * still matches what anyone debugging is used to reading.
 */
export function tag(value) {
  const s = String(value == null ? '' : value);
  if (!s) return 'anon';
  if (!redacting) return s.length === 64 ? `${s.substring(0, 8)}...` : s;
  const h = crypto.createHmac('sha256', BOOT_SALT).update(s).digest('hex');
  return `#${h.substring(0, 6)}`;
}

/**
 * Addresses collapse to a class rather than a value.
 *
 * The relay is reached over Tailscale, so the remote address is a stable
 * per-device identifier: logging it defeats the point of pseudonymising the
 * account it belongs to.
 */
export function ip(addr) {
  const s = String(addr == null ? '' : addr);
  if (!redacting) return s || 'unknown';
  if (!s) return 'unknown';
  if (s === '::1' || s === '127.0.0.1' || s === '::ffff:127.0.0.1') return 'local';
  // 100.64.0.0/10, the CGNAT range Tailscale allocates from.
  const m = /(?:^|:)(\d{1,3})\.(\d{1,3})\./.exec(s);
  if (m && Number(m[1]) === 100 && Number(m[2]) >= 64 && Number(m[2]) <= 127) return 'tailnet';
  return 'remote';
}

// Path segments that are identifiers rather than route names: attachment
// UUIDs, 64-hex identity keys, and anything else long and hex-shaped.
const ID_SEGMENT =
  /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,})$/i;

/**
 * Strips identifiers and query strings out of a request URL.
 *
 * `GET /api/download/3f2a...` names a specific blob, and a query string is
 * where a credential would end up if anyone ever moved one there. The route
 * itself is what makes the access log useful, so that is what survives.
 */
export function url(raw) {
  const s = String(raw == null ? '' : raw);
  if (!redacting) return s;
  const [pathOnly, query] = s.split('?');
  const cleaned = pathOnly
    .split('/')
    .map((seg) => (ID_SEGMENT.test(seg) ? '_' : seg))
    .join('/');
  return query ? `${cleaned}?_` : cleaned;
}

/** Describes the active mode in the boot log, so it is never a surprise. */
export function describe() {
  return redacting
    ? 'strict (identities pseudonymised per boot, addresses classed)'
    : 'full (identities and addresses logged verbatim)';
}
