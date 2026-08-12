// Constant-rate cover traffic.
//
// Encrypting the header (v3) took the conversation structure away from the
// relay. It did nothing about timing and volume, which is what anyone watching
// the NETWORK sees: the tailnet, an ISP, a hostile Wi-Fi. A burst of twelve
// envelopes at 23:40 followed by silence is a conversation whether or not
// anybody can read it.
//
// The fix is to send at a fixed rate regardless. When there is something to
// say the cell carries it; when there is not, it carries a payload the peer
// decrypts to `{ type: 'cover' }` and throws away. An observer sees one cell
// every interval either way.
//
// PURE. No timers, no socket, no storage, no State. Everything here is a
// function of the arguments, which is what lets the tests drive a full day of
// scheduling against an injected clock in a millisecond. The timers and the
// socket live in the cover block in app.js, the same split as outbox.js.

/**
 * Foreground cadence. Fast enough that a real message never waits long behind
 * the schedule, slow enough not to be absurd on a phone.
 *
 * A real send RESETS the clock rather than adding to it: at a constant rate,
 * traffic you generate replaces a cover cell instead of appearing on top of
 * one. That is the whole mechanism. If real sends were additive the rate would
 * visibly rise while you typed, which is the signal this is meant to erase.
 */
export const COVER_FOREGROUND_MS = 15_000;

/**
 * Backgrounded, or the screen is off.
 *
 * "On by default" is only defensible if the default does not eat a battery.
 * A backgrounded tab that keeps a 15-second cadence all night is a messenger
 * people uninstall, and an uninstalled messenger protects nobody.
 */
export const COVER_BACKGROUND_MS = 150_000;

/** Cover is pointless if the peer is not there to receive it. */
export function coverIntervalMs(foreground) {
  return foreground ? COVER_FOREGROUND_MS : COVER_BACKGROUND_MS;
}

/**
 * Round-robin, so cover spreads evenly instead of piling onto whichever
 * contact happens to sort first.
 *
 * Keyed by the target's identity rather than by index: the online set changes
 * between ticks, and an index into a list that just shrank points at someone
 * else. Returns the entry after `lastTarget`, wrapping.
 */
export function nextCoverTarget(targets, lastTarget) {
  if (!Array.isArray(targets) || targets.length === 0) return null;
  const at = targets.findIndex((t) => keyOf(t) === lastTarget);
  return targets[(at + 1) % targets.length];
}

export function keyOf(target) {
  if (!target) return null;
  return target.deviceId ? `${target.contactId}:${target.deviceId}` : String(target.contactId);
}

/**
 * The whole decision, in one pure function.
 *
 * @param {object}  s
 * @param {number}  s.now                 milliseconds
 * @param {number}  s.lastSentAt          last outbound send of ANY kind, real or cover
 * @param {Array}   s.onlineTargets       [{ contactId, deviceId }] known to hold a live socket
 * @param {string}  s.lastTarget          keyOf() of the previous cover cell
 * @param {boolean} s.foreground
 * @param {boolean} s.enabled
 *
 * @returns {{ send: object|null, nextCheckAt: number }}
 */
export function planCover(s) {
  const interval = coverIntervalMs(s.foreground);
  const idle = { send: null, nextCheckAt: s.now + interval };

  if (!s.enabled) return idle;

  // NEVER to a peer that is offline. Their envelope would be written to the
  // relay's offline queue and sit there, so leaving this out turns a privacy
  // feature into a way to fill someone else's disk with noise at a fixed rate,
  // which is a denial of service you inflict on yourself and on them.
  //
  // The client knows who is online because presence travels as an ordinary
  // encrypted control payload between contacts. It is not something the relay
  // is asked.
  const targets = (s.onlineTargets || []).filter((t) => t && t.contactId);
  if (targets.length === 0) return idle;

  const due = s.now - (s.lastSentAt || 0) >= interval;
  if (!due) {
    return { send: null, nextCheckAt: (s.lastSentAt || 0) + interval };
  }

  return {
    send: nextCoverTarget(targets, s.lastTarget),
    nextCheckAt: s.now + interval
  };
}

/**
 * The payload itself.
 *
 * Deliberately tiny. It is padded to a full cell before encryption like every
 * other payload, so what goes on the wire is the same size as a real message
 * no matter what is in here. Anything larger would only waste the bandwidth
 * this feature is already spending.
 *
 * `notify` is never set for this, which is enforced at the call site and
 * asserted in the tests: waking somebody's phone for cover traffic would be
 * the single most obvious way to make this feature worse than useless.
 */
export function coverPayload() {
  return { type: 'cover' };
}

/** Inbound cover is dropped before it reaches the app. */
export function isCover(payload) {
  return !!payload && payload.type === 'cover';
}
