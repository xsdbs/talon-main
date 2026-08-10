// --- ENCRYPTED BACKUP AND RESTORE ---
//
// Everything Talon knows lives on the device. The relay holds ciphertext it
// cannot read and an offline queue it drains on delivery, so a lost or wiped
// phone loses the archive outright. "Back up db.json" does not help: the
// history, the contact names and the group rosters were never on the server in
// readable form.
//
// This produces one self-contained file, encrypted under a passphrase the user
// chooses, that another device can restore from. The relay is not involved at
// any point, which keeps the zero-knowledge property intact: a backup is
// exactly as private as the disk it is written to.
//
// This module is deliberately free of DOM and storage access. It takes plain
// objects and returns plain objects, so the whole format is testable without a
// browser. panes.js owns the file picker and the Storage writes.

import {
  bytesToHex, hexToBytes, utf8Encode, utf8Decode, deriveMasterKeyV2, sha256Hash
} from './crypto-bundle.js';
import { gcm } from '@noble/ciphers/aes.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

export const BACKUP_APP = 'talon';
export const BACKUP_KIND = 'backup';
export const BACKUP_VERSION = 1;

/**
 * A backup passphrase is not the account password, and the file it protects
 * can be copied and attacked offline at leisure with no rate limit in front of
 * it. Twelve characters is the floor, not a recommendation.
 */
export const MIN_PASSPHRASE_LENGTH = 12;

// A hostile file names its own iteration count, because restore has to know
// what the writer used. Two things follow. A count that is too low is
// self-defeating rather than dangerous: it derives a different key and the tag
// simply fails. A count that is absurdly high is a denial of service against
// whoever opens the file, so the accepted range is bounded at both ends.
export const MIN_ITERATIONS = 100_000;
export const MAX_ITERATIONS = 5_000_000;
export const DEFAULT_ITERATIONS = 600_000;

// Domain separation, and the reason it matters here more than usual: people
// reuse passwords. Someone who types their account password as the backup
// passphrase must still not end up with a backup key related to the account's
// authKey or encryptionKey. The HKDF step guarantees that even when the
// password and the salt both collide.
const BACKUP_INFO = 'TalonBackupv1';

/**
 * Stores carried by a backup, and what each one is for.
 *
 * Two stores are missing on purpose.
 *
 * `sessions` holds live Double Ratchet state. Restoring an old snapshot of it
 * would rewind chain keys that have already produced messages, which reuses
 * message keys and nonces: the one failure mode a ratchet exists to prevent.
 * Sessions cost nothing to lose because v2 re-handshakes on the next send.
 *
 * `prekeys` holds the private halves of keys already published to the relay.
 * Two devices restoring the same file would both believe they own the same
 * one-time prekeys, and the deletion-on-use that provides forward secrecy
 * would stop meaning anything.
 */
export const BACKUP_STORES = [
  'messages', 'contacts', 'groups', 'profile', 'chatMeta', 'drafts', 'settings'
];

/** Settings that are device-local security controls and never travel. */
const LOCAL_ONLY_SETTINGS = ['appLockEnabled', 'appLockPinHash', 'appLockSalt'];

/* ------------------------------------------------------------- collecting */

/**
 * Assembles the payload from already-loaded state.
 *
 * Missing stores become empty rather than undefined, so a payload built from a
 * half-initialised session still round-trips instead of encoding `null` and
 * failing on the way back in.
 */
export function collectBackup(state = {}) {
  const settings = { ...(state.settings || {}) };
  for (const key of LOCAL_ONLY_SETTINGS) delete settings[key];

  return {
    messages: Array.isArray(state.messages) ? state.messages : [],
    contacts: Array.isArray(state.contacts) ? state.contacts : [],
    groups: Array.isArray(state.groups) ? state.groups : [],
    profile: state.profile && typeof state.profile === 'object' ? state.profile : {},
    chatMeta: state.chatMeta && typeof state.chatMeta === 'object' ? state.chatMeta : {},
    drafts: state.drafts && typeof state.drafts === 'object' ? state.drafts : {},
    settings
  };
}

/** Counts worth showing before a restore commits to anything. */
export function summarise(payload) {
  const p = payload || {};
  return {
    messages: Array.isArray(p.messages) ? p.messages.length : 0,
    contacts: Array.isArray(p.contacts) ? p.contacts.length : 0,
    groups: Array.isArray(p.groups) ? p.groups.length : 0,
    conversations: new Set((p.messages || []).map((m) => m && m.contactId)).size
  };
}

/* ----------------------------------------------------------------- crypto */

/**
 * The bytes the AES-GCM tag is computed over in addition to the ciphertext.
 *
 * Without this the header would be free to edit: the username, the timestamp
 * and the format version all sit outside the ciphertext because restore needs
 * to read them before it has a key. Binding them as associated data means any
 * edit makes the tag fail, so what the file claims about itself is exactly
 * what its author wrote.
 */
export function backupAad(header) {
  return utf8Encode(JSON.stringify({
    app: BACKUP_APP,
    kind: BACKUP_KIND,
    v: Number(header.v),
    username: String(header.username || ''),
    createdAt: Number(header.createdAt) || 0,
    kdf: {
      v: Number(header.kdf.v),
      iterations: Number(header.kdf.iterations),
      salt: String(header.kdf.salt)
    }
  }));
}

async function backupKey(passphrase, saltHex, iterations) {
  const master = await deriveMasterKeyV2(passphrase, saltHex, iterations);
  return hkdf(sha256, master, hexToBytes(saltHex), utf8Encode(BACKUP_INFO), 32);
}

/**
 * Encrypts a payload into the on-disk backup object.
 *
 * `salt`, `nonce` and `iterations` exist so tests can pin them. Nothing in the
 * app passes them: reusing a nonce under a derived key would be fatal, and a
 * caller that has to opt in to that is far harder to get wrong by accident
 * than one that accepts whatever it is handed.
 */
export async function createBackup(passphrase, payload, opts = {}) {
  if (typeof passphrase !== 'string' || passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`);
  }

  const iterations = Number(opts.iterations) || DEFAULT_ITERATIONS;
  const salt = opts.salt || bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
  const nonce = opts.nonce || bytesToHex(crypto.getRandomValues(new Uint8Array(12)));

  const header = {
    app: BACKUP_APP,
    kind: BACKUP_KIND,
    v: BACKUP_VERSION,
    username: String(opts.username || ''),
    createdAt: Number(opts.createdAt) || Date.now(),
    kdf: { v: 2, iterations, salt }
  };

  const plain = utf8Encode(JSON.stringify(payload));
  const key = await backupKey(passphrase, salt, iterations);
  const ct = gcm(key, hexToBytes(nonce), backupAad(header)).encrypt(plain);

  return {
    ...header,
    cipher: 'AES-256-GCM',
    nonce,
    ct: bytesToHex(ct),
    // A fingerprint of the ciphertext, so a truncated or corrupted download can
    // be named as such instead of surfacing as "wrong passphrase", which is
    // what a failed tag looks like from the outside.
    digest: bytesToHex(sha256Hash(ct)).slice(0, 32)
  };
}

/** Structural validation, run before a passphrase is ever asked for. */
export function inspectBackup(file) {
  if (!file || typeof file !== 'object') return { ok: false, reason: 'not a backup file' };
  if (file.app !== BACKUP_APP || file.kind !== BACKUP_KIND) {
    return { ok: false, reason: 'not a Talon backup' };
  }
  if (file.v !== BACKUP_VERSION) {
    return { ok: false, reason: `backup version ${file.v} is not supported` };
  }
  if (file.cipher !== 'AES-256-GCM') return { ok: false, reason: 'unknown cipher' };

  const kdf = file.kdf;
  if (!kdf || kdf.v !== 2 || typeof kdf.salt !== 'string' || !/^[0-9a-f]{32}$/i.test(kdf.salt)) {
    return { ok: false, reason: 'bad key derivation parameters' };
  }
  const iterations = Number(kdf.iterations);
  if (!Number.isInteger(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    return { ok: false, reason: 'key derivation cost is out of range' };
  }
  if (typeof file.nonce !== 'string' || !/^[0-9a-f]{24}$/i.test(file.nonce)) {
    return { ok: false, reason: 'bad nonce' };
  }
  if (typeof file.ct !== 'string' || file.ct.length < 2 || !/^[0-9a-f]+$/i.test(file.ct)) {
    return { ok: false, reason: 'missing ciphertext' };
  }
  if (typeof file.digest === 'string'
      && bytesToHex(sha256Hash(hexToBytes(file.ct))).slice(0, 32) !== file.digest) {
    return { ok: false, reason: 'the file is damaged or incomplete' };
  }

  return {
    ok: true,
    username: typeof file.username === 'string' ? file.username : '',
    createdAt: Number(file.createdAt) || 0,
    iterations
  };
}

/**
 * Decrypts a backup file. Throws with a reason a person can act on.
 *
 * A failed tag is reported as a wrong passphrase because that is what it
 * almost always is, and the digest check above has already separated out the
 * damaged-file case.
 */
export async function openBackup(passphrase, file) {
  const shape = inspectBackup(file);
  if (!shape.ok) throw new Error(shape.reason);
  if (typeof passphrase !== 'string' || !passphrase) throw new Error('Passphrase required');

  const key = await backupKey(passphrase, file.kdf.salt, shape.iterations);

  let plain;
  try {
    plain = gcm(key, hexToBytes(file.nonce), backupAad(file)).decrypt(hexToBytes(file.ct));
  } catch {
    throw new Error('Wrong passphrase, or the file has been altered');
  }

  let payload;
  try {
    payload = JSON.parse(utf8Decode(plain));
  } catch {
    throw new Error('Backup contents are not readable');
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('Backup contents are not readable');
  }
  return payload;
}

/* ------------------------------------------------------------------ merge */

/**
 * Identity of a message row, matching findMsg() in messaging.js.
 *
 * `localId` is preferred where both rows have one, but history written before
 * localId existed only has the triple, so the triple has to keep working or a
 * restore of an old archive duplicates every message in it.
 */
function messageKey(m) {
  if (!m || typeof m !== 'object') return null;
  if (m.localId) return `L:${m.localId}`;
  return `T:${m.contactId}|${m.messageIndex}|${m.sender}`;
}

function mergeById(current, incoming, idOf) {
  const out = current.slice();
  const seen = new Map();
  out.forEach((item, i) => {
    const id = idOf(item);
    if (id != null) seen.set(id, i);
  });
  let added = 0;
  for (const item of incoming) {
    const id = idOf(item);
    if (id == null) continue;
    if (seen.has(id)) continue;
    seen.set(id, out.length);
    out.push(item);
    added++;
  }
  return { list: out, added };
}

/**
 * Combines a restored payload with what is already on the device.
 *
 * `merge` is the default and never deletes: a restore run against a device
 * that has kept talking should add the missing history, not roll it back to
 * whatever the file remembers. `replace` is the explicit destructive option
 * for a fresh device, and the caller is responsible for confirming it.
 *
 * Pure: it reads and returns plain objects and touches nothing.
 */
export function mergeBackup(currentIn, incomingIn, { mode = 'merge' } = {}) {
  // A default parameter only fires on `undefined`, and an explicit null is
  // exactly what a caller reaches for when a store is missing.
  const current = currentIn && typeof currentIn === 'object' ? currentIn : {};
  const incoming = incomingIn && typeof incomingIn === 'object' ? incomingIn : {};

  const inc = {
    messages: Array.isArray(incoming.messages) ? incoming.messages : [],
    contacts: Array.isArray(incoming.contacts) ? incoming.contacts : [],
    groups: Array.isArray(incoming.groups) ? incoming.groups : [],
    profile: incoming.profile || null,
    chatMeta: incoming.chatMeta || {},
    drafts: incoming.drafts || {},
    settings: incoming.settings || {}
  };

  if (mode === 'replace') {
    return {
      result: {
        messages: inc.messages,
        contacts: inc.contacts,
        groups: inc.groups,
        profile: inc.profile || current.profile || {},
        chatMeta: inc.chatMeta,
        drafts: inc.drafts,
        settings: { ...(current.settings || {}), ...stripLocal(inc.settings) }
      },
      stats: {
        messages: inc.messages.length, contacts: inc.contacts.length, groups: inc.groups.length
      }
    };
  }

  const messages = mergeById(
    Array.isArray(current.messages) ? current.messages : [], inc.messages, messageKey);
  // A contact is identified by its identity key, not by an `id` field: the
  // address IS the key, and there is no other identifier. Getting this wrong
  // does not throw, it silently drops every contact in the file, which is why
  // the fixtures below and in the tests use the real shape.
  const contacts = mergeById(
    Array.isArray(current.contacts) ? current.contacts : [], inc.contacts,
    (c) => (c && c.idPub ? String(c.idPub) : null));
  const groups = mergeById(
    Array.isArray(current.groups) ? current.groups : [], inc.groups,
    (g) => (g && g.id ? String(g.id) : null));

  // Sorting by timestamp matters because merged-in rows arrive at the end of
  // the array, and the chat view renders in array order. Rows without a
  // timestamp keep their relative position rather than being flung to the top.
  messages.list.sort((a, b) => (Number(a && a.timestamp) || 0) - (Number(b && b.timestamp) || 0));

  return {
    result: {
      messages: messages.list,
      contacts: contacts.list,
      groups: groups.list,
      // What is already on the device wins for everything that is a single
      // value rather than a collection. A restore is meant to recover things
      // that are gone, not to overwrite a profile or a draft being typed.
      profile: current.profile && Object.keys(current.profile).length
        ? current.profile : (inc.profile || {}),
      chatMeta: { ...inc.chatMeta, ...(current.chatMeta || {}) },
      drafts: { ...inc.drafts, ...(current.drafts || {}) },
      settings: { ...stripLocal(inc.settings), ...(current.settings || {}) }
    },
    stats: {
      messages: messages.added, contacts: contacts.added, groups: groups.added
    }
  };
}

function stripLocal(settings) {
  const out = { ...(settings || {}) };
  for (const key of LOCAL_ONLY_SETTINGS) delete out[key];
  return out;
}
