// --- THE OUTBOX: DELIVERY GUARANTEES ---
//
// Until now a send that failed was simply lost. If the socket was down the
// bubble went red and stayed red forever, and the only recovery was to retype
// the message. Worse, a frame that left the device but never drew an ack (the
// relay restarted, the socket died mid-flight) sat on "sending" indefinitely,
// which looks like success and is not.
//
// So every outbound message now has one of three honest outcomes: acknowledged
// by the relay, waiting in the outbox to be retried, or given up on and marked
// failed with a retry button. Nothing is silently dropped and nothing lies.
//
// This module is the scheduling half and is deliberately pure: it takes plain
// objects and a clock and returns plain objects. That is what makes backoff
// and exhaustion testable without a socket, a timer, or a browser.

/** Attempts before a message stops retrying itself and waits for the user. */
export const MAX_ATTEMPTS = 8;

/** First retry delay. Doubles per attempt up to the ceiling. */
export const BASE_DELAY_MS = 2_000;
export const MAX_DELAY_MS = 60_000;

/**
 * How long a frame may sit on "sending" before it is treated as lost.
 *
 * The relay acks as soon as it has routed or queued, so this only needs to
 * cover a round trip. It is generous because a slow ack that gets retried
 * costs a duplicate the receiver discards, while a timeout that is too long
 * leaves a message looking sent when it is not.
 */
export const ACK_TIMEOUT_MS = 15_000;

/**
 * Exponential backoff with full jitter.
 *
 * The jitter matters more than it looks: without it, every message queued
 * during an outage retries on exactly the same schedule, so the relay gets the
 * whole backlog in one burst the instant it comes back, and the send rate
 * limiter refuses most of it. Spreading them out is what makes the retry
 * actually deliver rather than trip the limiter.
 */
export function nextDelay(attempts, random = Math.random) {
  const exp = Math.min(BASE_DELAY_MS * Math.pow(2, Math.max(0, attempts)), MAX_DELAY_MS);
  return Math.floor(exp / 2 + random() * (exp / 2));
}

/** A fresh outbox entry for a message that has not been acknowledged. */
export function makeEntry({ localId, convId, payload, now = Date.now(), random = Math.random }) {
  return {
    localId: String(localId),
    convId: String(convId),
    payload,
    attempts: 0,
    createdAt: now,
    nextAt: now + nextDelay(0, random)
  };
}

/**
 * Adds an entry, replacing any earlier one for the same message.
 *
 * Replacing rather than appending is load-bearing. A message can land here
 * twice, once when the send fails and again when its ack times out, and two
 * entries for one message means the recipient gets it twice for no reason.
 */
export function addEntry(list, entry) {
  const out = (Array.isArray(list) ? list : []).filter((e) => e && e.localId !== entry.localId);
  out.push(entry);
  return out;
}

export function removeEntry(list, localId) {
  return (Array.isArray(list) ? list : []).filter((e) => e && e.localId !== String(localId));
}

export function findEntry(list, localId) {
  return (Array.isArray(list) ? list : []).find((e) => e && e.localId === String(localId)) || null;
}

/** Entries whose backoff has elapsed and which have attempts left. */
export function dueEntries(list, now = Date.now()) {
  return (Array.isArray(list) ? list : []).filter(
    (e) => e && !isExhausted(e) && Number(e.nextAt) <= now
  );
}

/** True once a message has stopped retrying on its own. */
export function isExhausted(entry) {
  return !!entry && Number(entry.attempts) >= MAX_ATTEMPTS;
}

/**
 * Records that an attempt was made and schedules the next one.
 *
 * Returns a new object rather than mutating, so a caller cannot half-apply an
 * update and leave an entry that has been sent but not counted.
 */
export function afterAttempt(entry, { now = Date.now(), random = Math.random } = {}) {
  const attempts = Number(entry.attempts || 0) + 1;
  return { ...entry, attempts, nextAt: now + nextDelay(attempts, random) };
}

/** Clears the backoff so a user-triggered retry goes out immediately. */
export function forceDue(entry, now = Date.now()) {
  return { ...entry, attempts: 0, nextAt: now };
}

/** When the next retry is due, or null if nothing is waiting. */
export function nextWakeup(list, now = Date.now()) {
  const pending = (Array.isArray(list) ? list : [])
    .filter((e) => e && !isExhausted(e))
    .map((e) => Number(e.nextAt))
    .filter((t) => Number.isFinite(t));
  if (!pending.length) return null;
  return Math.max(0, Math.min(...pending) - now);
}

/* --------------------------------------------------------- receive side */

/**
 * The identity a retry preserves.
 *
 * `_mid` cannot do this job: it is a per-session counter, so re-encrypting the
 * same message allocates a new one and the retry would look like a new
 * message. `_lid` is minted once when the bubble is created and rides along
 * unchanged through every attempt, which is what lets the recipient recognise
 * the duplicate and drop it.
 */
export function alreadyReceived(messages, senderId, lid) {
  if (!lid) return false;
  return (Array.isArray(messages) ? messages : []).some(
    (m) => m && m.senderId === senderId && m.remoteId === lid
  );
}
