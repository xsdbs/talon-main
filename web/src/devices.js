// Multi-device: the signed device list.
//
// Pure. No DOM, no Storage, no socket, so the rules can be tested without a
// session. Mirrors the signed-roster code in messaging.js deliberately: the
// question is the same one (who is allowed to change this list) and the answer
// should look the same to anyone reading both.
//
// WHAT A DEVICE IS, AND WHAT IT IS NOT
//
// An account has one identity key, `idPub`, and that key IS the contact
// address. Devices do not change that. A device is a sub-key under the
// account, published so that each one can hold its own ratchet state.
//
// Every device of an account already holds the same `idPriv`, because
// `encryptedIdPriv` is recoverable from the relay with the password. Adding a
// second device therefore grants it nothing it could not already have. This is
// worth being precise about: multi-device here is about routing and session
// state, not about a new trust boundary.
//
// WHY THE RELAY CANNOT READ YOUR MAIL BY INVENTING A DEVICE
//
// The obvious attack on any multi-device scheme is the relay adding a device
// of its own to your list, so senders fan out to it. That fails here for a
// structural reason rather than because of the signature below: a session to
// a device still mixes `DH(EK_a, IK_b)` with the ACCOUNT identity key, exactly
// as a single-device session does. The device key is additive, the same way
// the ML-KEM prekey is additive. A device the relay invented has no `idPriv`,
// so it cannot complete the handshake, and the injected envelope is one nobody
// can open.
//
// So what is the signature for? Integrity and visibility, not confidentiality.
// It makes the list tamper-evident, so a device you do not recognise appearing
// in your own settings is a real signal rather than noise, and a relay cannot
// quietly drop a device to force your peers to stop delivering to it.
//
// Do not "simplify" the account DH out of the device handshake on the grounds
// that the list is signed. The signature is checked against a signing key the
// relay also serves, so it is the account DH that is load-bearing.

import {
  bytesToHex, hexToBytes, utf8Encode, signBytes, verifySignature
} from './crypto-bundle.js';

/** A device label the user never set. Kept short; it shows in Settings. */
export const DEFAULT_DEVICE_NAME = 'This device';

/** How many devices one account may publish. */
export const MAX_DEVICES = 8;

/**
 * Canonical bytes for a device list.
 *
 * Devices sorted by id, every field coerced, fixed key order. Two devices
 * holding the same list must produce byte-identical input or the signature is
 * a coin flip. Domain-separated so a device-list signature can never be lifted
 * into the roster or prekey contexts, which use the same key.
 */
export function buildDeviceListMessage({ idPub, rev, devices }) {
  const canon = JSON.stringify({
    idPub: String(idPub),
    rev: Number(rev),
    devices: (devices || [])
      .map((d) => ({
        deviceId: String(d.deviceId),
        devPub: String(d.devPub),
        name: String(d.name == null ? '' : d.name)
      }))
      .sort((a, b) => (a.deviceId < b.deviceId ? -1 : a.deviceId > b.deviceId ? 1 : 0))
  });
  return utf8Encode('TalonDeviceList:' + canon);
}

/** Signs a device list with the account signing key. */
export function signDeviceListWith(signingPriv, fields) {
  return bytesToHex(signBytes(signingPriv, buildDeviceListMessage(fields)));
}

/** Verifies a device-list signature against the account's Ed25519 key. */
export function verifyDeviceList(fields, sigHex, signPubHex) {
  if (typeof sigHex !== 'string' || typeof signPubHex !== 'string') return false;
  try {
    return verifySignature(
      hexToBytes(signPubHex), hexToBytes(sigHex), buildDeviceListMessage(fields)
    );
  } catch {
    return false;
  }
}

const isHex64 = (s) => typeof s === 'string' && /^[0-9a-f]{64}$/i.test(s);
const isDeviceId = (s) => typeof s === 'string' && /^[0-9a-f]{16}$/i.test(s);

/**
 * Decides whether an inbound device list may replace what we hold.
 *
 * The single gate, the way `rosterAcceptable` is the single gate for rosters.
 * Returns `{ ok, reason }`; the reason is for the log, because a refused list
 * otherwise looks like an unexplained "my other phone stopped getting
 * messages" bug.
 */
export function deviceListAcceptable(existing, incoming) {
  const { idPub, rev, devices, sig, signPub } = incoming || {};

  if (!isHex64(idPub) || !Array.isArray(devices)) {
    return { ok: false, reason: 'malformed' };
  }
  if (!Number.isSafeInteger(rev) || rev < 1) {
    return { ok: false, reason: 'bad revision' };
  }

  // An empty list would silently un-deliver every device on the account, so it
  // is refused as malformed rather than applied. Removing your last device is
  // not an operation that makes sense.
  if (devices.length < 1) return { ok: false, reason: 'empty' };

  // Bounded because the list is attacker-supplied and every entry costs the
  // sender one more session and one more envelope per message.
  if (devices.length > MAX_DEVICES) return { ok: false, reason: 'too many devices' };

  const ids = new Set();
  const pubs = new Set();
  for (const d of devices) {
    if (!d || !isDeviceId(d.deviceId) || !isHex64(d.devPub)) {
      return { ok: false, reason: 'malformed device' };
    }
    // Duplicates would make fan-out send the same envelope twice, and would
    // let one device shadow another by claiming its id.
    if (ids.has(d.deviceId)) return { ok: false, reason: 'duplicate device id' };
    if (pubs.has(d.devPub)) return { ok: false, reason: 'duplicate device key' };
    ids.add(d.deviceId);
    pubs.add(d.devPub);
  }

  // Unsigned lists are refused outright. Accepting them "for compatibility"
  // would leave the whole mechanism opt-out for anyone willing to omit a
  // field, which is how the roster version of this would have failed too.
  if (!sig || !signPub) return { ok: false, reason: 'unsigned' };

  if (!verifyDeviceList({ idPub, rev, devices }, sig, signPub)) {
    return { ok: false, reason: 'bad signature' };
  }

  if (existing) {
    if (String(existing.idPub) !== String(idPub)) {
      return { ok: false, reason: 'wrong account' };
    }
    // Strictly forward. Equal is refused too: a replayed current list is
    // pointless at best, and at worst it is an attempt to undo a revocation
    // that was published at the same revision.
    if (rev <= (existing.rev || 0)) return { ok: false, reason: 'stale revision' };

    // Pinned on first accept. A valid signature under a DIFFERENT key is
    // exactly what a substituted signing key looks like.
    if (existing.signPub && existing.signPub !== signPub) {
      return { ok: false, reason: 'signing key changed' };
    }
  }

  return { ok: true };
}

/**
 * The key a ratchet session is stored under.
 *
 * A session belongs to a (peer, device) pair, because each of a peer's
 * devices runs its own ratchet and consumes its own one-time prekeys. Sharing
 * one session across devices would have them clobbering each other's chain
 * keys, which is the same reason backups exclude sessions entirely.
 *
 * With no device it returns the bare peer id, so every session established
 * before this existed keeps its key and keeps working. That is the whole
 * migration: there isn't one.
 */
export function sessionKey(contactId, deviceId) {
  return deviceId ? `${contactId}:${deviceId}` : String(contactId);
}

/** The peer id out of a session key, whether or not it names a device. */
export function peerOfSessionKey(key) {
  const i = String(key).indexOf(':');
  return i === -1 ? String(key) : String(key).slice(0, i);
}

/**
 * Every session key held for one peer, across all of their devices.
 *
 * Used when a contact is deleted or a conversation is reset. Matching on the
 * bare id alone would leave every per-device session behind, which is a stale
 * ratchet that quietly resurrects itself on the next message.
 */
export function sessionKeysFor(sessions, contactId) {
  return Object.keys(sessions || {}).filter((k) => peerOfSessionKey(k) === contactId);
}

/**
 * Everything a sender needs to fan out to one account: the device entries to
 * address, or `null` when the peer has published no list at all.
 *
 * `null` is not an error. It means an un-upgraded peer with a single implicit
 * device, and the caller falls back to addressing the account key directly,
 * which is what every existing session already does. This mirrors the
 * `pq: true|false` pattern: a peer that has not caught up still works.
 */
export function fanoutTargets(deviceList) {
  if (!deviceList || !Array.isArray(deviceList.devices) || !deviceList.devices.length) {
    return null;
  }
  return deviceList.devices.map((d) => ({ deviceId: d.deviceId, devPub: d.devPub }));
}

/**
 * Adds or replaces this device in a list and bumps the revision.
 *
 * Replacing by id rather than appending is what makes re-registering an
 * existing device idempotent. Without it, reinstalling the app on the same
 * phone would grow the list by one every time until it hit MAX_DEVICES.
 */
export function withDevice(existing, device) {
  const rev = Number((existing && existing.rev) || 0) + 1;
  const others = ((existing && existing.devices) || [])
    .filter((d) => d && d.deviceId !== device.deviceId);
  return {
    idPub: (existing && existing.idPub) || device.idPub,
    rev,
    devices: [...others, {
      deviceId: device.deviceId,
      devPub: device.devPub,
      name: String(device.name || DEFAULT_DEVICE_NAME)
    }]
  };
}

/**
 * Removes a device and bumps the revision.
 *
 * Refuses to remove the last one, for the same reason an empty list is
 * refused on the way in.
 */
export function withoutDevice(existing, deviceId) {
  const devices = ((existing && existing.devices) || []).filter((d) => d && d.deviceId !== deviceId);
  if (!devices.length) return null;
  return {
    idPub: existing.idPub,
    rev: Number((existing && existing.rev) || 0) + 1,
    devices
  };
}
