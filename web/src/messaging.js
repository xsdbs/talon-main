// --- PROTOCOL, TRANSPORT, AND THE MESSAGE MODEL ---
//
// The ratchet code below is carried over verbatim from the original app.js.
// Session state is persisted in localStorage and has NO migration path:
// changing the HKDF info string, the ratchet labels ('MessageKey' /
// 'NextChainKey'), the role-separation order, or the shape of the session
// object silently breaks every existing conversation on every device.

import {
  generateIdentityKeypair, deriveSharedSecret, deriveInitialSessionKeys,
  ratchetChainKey, encryptMessage, decryptMessage,
  bytesToHex, hexToBytes, utf8Encode, utf8Decode, encryptWithKey,
  sha256Hash, signBytes, verifySignature, signingKeypairFromSeed, kemKeygen,
  sealSender, unsealSender
} from './crypto-bundle.js';
import {
  initiateSession, acceptSession, encryptWithSession, decryptWithSession,
  encryptWithSessionV3, decryptWithSessionV3,
  verifyBundle, buildSignedPreKeyMessage, buildKemPreKeyMessage,
  buildCapsMessage, PROTOCOL_CAPS
} from './ratchet.js';
import { State, persist, metaFor, Storage } from './store.js';
import { writeMutedTags } from './pushdb.js';
import {
  sessionKey, sessionKeysFor, deviceListAcceptable, signDeviceListWith,
  withDevice, withoutDevice, DEFAULT_DEVICE_NAME
} from './devices.js';

/* ------------------------------------------------------- server syncing */

async function postJSON(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return res.json();
}

function encryptForServer(value) {
  const keyBytes = hexToBytes(State.currentUser.encryptionKeyHex);
  return encryptWithKey(keyBytes, utf8Encode(JSON.stringify(value)));
}

export async function syncContactsWithServer() {
  if (!State.currentUser) return;
  try {
    const { ciphertext, nonce } = encryptForServer(State.contacts);
    const result = await postJSON('/api/sync-contacts', {
      username: State.currentUser.username,
      authHash: State.currentUser.authHash,
      encryptedContacts: ciphertext,
      encryptedContactsNonce: nonce
    });
    if (!result.success) console.error('[Sync] Server rejected contacts:', result.error);
  } catch (err) {
    console.error('[Sync] Network error syncing contacts:', err);
  }
}

export async function syncGroupsWithServer() {
  if (!State.currentUser) return;
  try {
    const { ciphertext, nonce } = encryptForServer(State.groups);
    const result = await postJSON('/api/sync-groups', {
      username: State.currentUser.username,
      authHash: State.currentUser.authHash,
      encryptedGroups: ciphertext,
      encryptedGroupsNonce: nonce
    });
    if (!result.success) console.error('[Sync] Server rejected groups:', result.error);
  } catch (err) {
    console.error('[Sync] Network error syncing groups:', err);
  }
}

/**
 * An opaque notification tag, replacing the conversation id the relay used to
 * be told on every send.
 *
 * Two things were wrong with sending `convId`. For a group it was the shared
 * `groupId`, repeated on every envelope of the fan-out, so the relay could
 * simply collect the recipients that kept appearing under the same value and
 * reconstruct the membership of a group it is supposed to know nothing about.
 * And the recipient's muted list had to be uploaded in the clear for the relay
 * to act on it, which handed over a slice of the contact graph outright.
 *
 * The tag is bound to the recipient as well as the conversation, so the same
 * group message produces a different tag for every member and there is nothing
 * left to correlate. It stays stable for one member and one conversation,
 * which is all the service worker needs to collapse repeat notifications and
 * to apply a mute.
 *
 * `convId` here is the conversation as the RECIPIENT knows it: the group id
 * for a group, and the sender's own identity key for a one-to-one chat.
 *
 * This is not a secret from the relay in the one-to-one case, since the relay
 * necessarily knows both ends while routing. What it buys there is that the
 * value is never stored: it appears in one frame and is gone. For groups it is
 * a genuine unlinking.
 */
export function pushTagFor(convId, recipientIdPub) {
  if (!convId || !recipientIdPub) return undefined;
  return bytesToHex(sha256Hash(utf8Encode(
    `TalonPushTagv1:${convId}:${recipientIdPub}`
  ))).slice(0, 32);
}

/** Every tag this account should suppress, for the muted conversations. */
export function mutedPushTags() {
  if (!State.currentUser) return [];
  const me = State.currentUser.idPub;
  return [
    ...State.contacts.filter((c) => c.muted).map((c) => c.idPub),
    ...State.groups.filter((g) => g.muted).map((g) => g.id)
  ].map((convId) => pushTagFor(convId, me)).filter(Boolean);
}

/**
 * Hands the muted tags to the service worker's store.
 *
 * This replaces syncMutedIdsWithServer(), which uploaded the muted
 * conversation IDs to the relay in the clear so it could skip a push. Nothing
 * leaves the device now.
 */
export function publishMutedTags() {
  return writeMutedTags(mutedPushTags());
}

/** Resolves a tag from a notification back to the conversation it belongs to. */
export function conversationForPushTag(tag) {
  if (!tag || !State.currentUser) return null;
  const me = State.currentUser.idPub;
  const candidates = [
    ...State.contacts.map((c) => c.idPub),
    ...State.groups.map((g) => g.id)
  ];
  return candidates.find((convId) => pushTagFor(convId, me) === tag) || null;
}

/* ================================================== PROTOCOL v2 PREKEYS */

const OTK_TARGET = 40;   // pool size to maintain on the relay
const OTK_REFILL_AT = 10;

/**
 * The Ed25519 prekey-signing key is DERIVED from the identity private key
 * rather than generated independently. That keeps it identical on every
 * device holding the account, which matters because prekeys are published
 * per-identity: a device-local signing key would mean whichever device
 * published last invalidated the others' signatures.
 *
 * Safe because idPriv is already the root secret for this identity; this is a
 * domain-separated second key, not a weakening of the first.
 */
function deriveSigningKey(idPrivHex) {
  return signingKeypairFromSeed(sha256Hash(utf8Encode('TalonSigningKey:' + idPrivHex)));
}

// Bumped whenever PROTOCOL_CAPS changes, so every client re-publishes its
// capability list once and exactly once. A boolean would not do it: the next
// capability added would find it already true and never publish again.
const CAPS_REVISION = 1;

/** Creates or rotates local prekey material and publishes the public halves. */
export async function ensurePreKeys({ force = false } = {}) {
  if (!State.currentUser) return;
  if (!State.preKeys) State.preKeys = Storage.getPreKeys(State.currentUser.username);
  const pk = State.preKeys;

  const signing = deriveSigningKey(State.currentUser.idPriv);
  pk.signPub = bytesToHex(signing.publicKey);
  pk.signPriv = bytesToHex(signing.privateKey);

  // Post-quantum prekey, rotated in lockstep with the signed prekey and
  // signed by the same identity so the relay cannot substitute its own.
  let publishKem = false;
  if (!pk.kem || force) {
    const kem = kemKeygen();
    const pub = bytesToHex(kem.publicKey);
    if (pk.kem) pk.kemArchive[pk.kem.pub] = pk.kem.priv;
    pk.kem = {
      pub,
      priv: bytesToHex(kem.secretKey),
      sig: bytesToHex(signBytes(signing.privateKey, buildKemPreKeyMessage(pub))),
      createdAt: Date.now()
    };
    publishKem = true;
  }

  let publishSpk = false;
  if (!pk.spk || force) {
    const spk = generateIdentityKeypair();
    const pub = bytesToHex(spk.publicKey);
    // Archive the outgoing signed prekey so in-flight handshakes that already
    // fetched it can still be completed.
    if (pk.spk) pk.spkArchive[pk.spk.pub] = pk.spk.priv;
    pk.spk = {
      pub,
      priv: bytesToHex(spk.privateKey),
      sig: bytesToHex(signBytes(signing.privateKey, buildSignedPreKeyMessage(pub))),
      createdAt: Date.now()
    };
    publishSpk = true;
  }

  // Top up the one-time pool.
  const fresh = [];
  const have = Object.keys(pk.otk).length;
  if (have < OTK_REFILL_AT || publishSpk) {
    for (let i = have; i < OTK_TARGET; i++) {
      const kp = generateIdentityKeypair();
      const id = pk.nextOtkId++;
      pk.otk[id] = bytesToHex(kp.privateKey);
      fresh.push({ id, pub: bytesToHex(kp.publicKey) });
    }
  }

  // AN UPGRADED ACCOUNT PUBLISHES NOTHING OTHERWISE. An existing user already
  // has a signed prekey, a KEM prekey and a full one-time pool, so all three
  // flags below are false on the first boot after the upgrade and the early
  // return fires. The capability list would then never reach the relay, no
  // peer would ever see `v3`, and every session would keep negotiating v2
  // while both ends were perfectly capable of v3. Silent, and it would have
  // looked like the negotiation code simply did not work.
  const capsPublished = pk.capsPublished === CAPS_REVISION;
  pk.capsPublished = CAPS_REVISION;

  persist.preKeys();

  if (!publishSpk && !publishKem && capsPublished && fresh.length === 0) return;

  try {
    await postJSON('/api/publish-prekeys', {
      username: State.currentUser.username,
      authHash: State.currentUser.authHash,
      // Published under THIS device's key so the account's devices do not
      // consume each other's one-time prekeys. Omitted before a device
      // identity exists, which stores under the account key exactly as
      // every single-device client already does.
      deviceKey: State.currentUser.devPub || undefined,
      signPub: pk.signPub,
      signedPreKey: { pub: pk.spk.pub, sig: pk.spk.sig },
      kemPreKey: { pub: pk.kem.pub, sig: pk.kem.sig },
      // Which protocol versions we speak, so a peer knows whether to open a
      // v3 session or fall back to v2. Signed under the same key as the
      // prekeys: an unsigned list would let the relay choose our protocol
      // version by editing it, which is the whole downgrade attack.
      //
      // New plaintext on an API body, and a deliberate one. It is a version
      // string, not identity-derived, and it tells the relay only what the
      // shape of our envelopes already would.
      caps: PROTOCOL_CAPS,
      capsSig: bytesToHex(signBytes(signing.privateKey, buildCapsMessage(PROTOCOL_CAPS))),
      oneTimePreKeys: fresh
    });
  } catch (err) {
    console.warn('[Prekeys] Publish failed, will retry next boot:', err.message);
  }
}

/* ------------------------------------------------------------- this device */

/**
 * Loads or creates this browser's device identity for the current account.
 *
 * The private half never leaves. The public half is published in the account's
 * signed device list so peers can address this device specifically, and it
 * names the prekey pool this device owns.
 *
 * Stable across reloads. Regenerating it on every boot would orphan the
 * device's prekey pool on the relay and grow the published list until it hit
 * the cap.
 */
export function ensureDeviceIdentity() {
  if (!State.currentUser) return null;
  const username = State.currentUser.username;

  let dev = Storage.getDevice(username);
  if (!dev || !dev.deviceId || !dev.devPub || !dev.devPriv) {
    const kp = generateIdentityKeypair();
    dev = {
      deviceId: bytesToHex(crypto.getRandomValues(new Uint8Array(8))),
      devPub: bytesToHex(kp.publicKey),
      devPriv: bytesToHex(kp.privateKey),
      name: defaultDeviceName()
    };
    Storage.saveDevice(username, dev);
  }

  State.currentUser.deviceId = dev.deviceId;
  State.currentUser.devPub = dev.devPub;
  return dev;
}

/**
 * A first guess at what to call this device, from the user agent.
 *
 * Deliberately coarse. It is a label in your own settings, not telemetry, and
 * it never leaves your account's signed list, but there is no reason for it to
 * be more specific than it needs to be to tell two devices apart.
 */
function defaultDeviceName() {
  const ua = (typeof navigator !== 'undefined' && navigator.userAgent) || '';
  if (/iPhone|Android.*Mobile/i.test(ua)) return 'Phone';
  if (/iPad|Tablet|Android/i.test(ua)) return 'Tablet';
  if (/Mac OS X/i.test(ua)) return 'Mac';
  if (/Windows/i.test(ua)) return 'PC';
  if (/Linux/i.test(ua)) return 'Linux';
  return DEFAULT_DEVICE_NAME;
}

/**
 * Publishes this device into the account's signed device list.
 *
 * Fetches what is already there, verifies it, adds or refreshes this device,
 * re-signs the whole list and uploads it. The signature is over a canonical
 * encoding, so any device of the account produces identical bytes.
 *
 * Verifying what we fetched before extending it is the load-bearing part. The
 * relay serves this list and does not check it; accepting whatever came back
 * and signing over it would launder a tampered list into a validly signed one
 * under our own key.
 */
export async function publishThisDevice() {
  if (!State.currentUser) return { ok: false, reason: 'no user' };
  const dev = ensureDeviceIdentity();
  if (!dev) return { ok: false, reason: 'no device' };

  const me = State.currentUser;
  const signing = deriveSigningKey(me.idPriv);
  const signPub = bytesToHex(signing.publicKey);

  let existing = null;
  try {
    const r = await postJSON('/api/devices', {
      username: me.username, authHash: me.authHash, peerId: me.idPub
    });
    if (r.success && r.list) {
      const verdict = deviceListAcceptable(null, r.list);
      if (verdict.ok && r.list.signPub === signPub) {
        existing = r.list;
      } else {
        // Either it does not verify, or it verifies under a key that is not
        // ours. Both mean the stored list is not something we wrote, so we
        // start a fresh one at a revision past it rather than signing over
        // whatever is there.
        console.warn('[Devices] Ignoring a stored device list we did not sign:', verdict.reason || 'wrong key');
        existing = { idPub: me.idPub, rev: Number(r.list.rev) || 0, devices: [] };
      }
    }
  } catch (err) {
    console.warn('[Devices] Could not read the current list:', err.message);
    return { ok: false, reason: 'fetch failed' };
  }

  const next = withDevice(existing, {
    idPub: me.idPub, deviceId: dev.deviceId, devPub: dev.devPub, name: dev.name
  });

  // Nothing changed except the revision: skip the write. Without this, every
  // reload burns a revision and rewrites the relay's copy for no reason.
  if (existing && sameDevices(existing.devices, next.devices)) {
    State.deviceList = existing;
    return { ok: true, unchanged: true };
  }

  const list = {
    ...next,
    sig: signDeviceListWith(signing.privateKey, next),
    signPub
  };

  try {
    const r = await postJSON('/api/publish-devices', {
      username: me.username, authHash: me.authHash, list
    });
    if (!r.success) return { ok: false, reason: r.error || 'refused' };
    State.deviceList = list;
    return { ok: true };
  } catch (err) {
    console.warn('[Devices] Publish failed:', err.message);
    return { ok: false, reason: 'publish failed' };
  }
}

/* ------------------------------------------------------------- self sync */

/**
 * Tells your OTHER devices about a message you just sent.
 *
 * Without this a second device is receive-only in practice: it sees incoming
 * messages and has no idea what you said from the phone in your pocket, so the
 * two histories diverge permanently and neither is complete.
 *
 * It is an ordinary encrypted envelope addressed to your own identity key, so
 * the relay handles it exactly like any other message and learns nothing new.
 * `notify` is false: waking your own phone for something you just typed on it
 * is the definition of a pointless notification.
 *
 * Fire and forget. A failed sync must never fail the send that triggered it,
 * because the message did reach the person it was for and saying otherwise
 * would be a lie about the thing the user cares about.
 */
export async function syncToMyDevices(convId, payloadObj, localId) {
  if (!State.currentUser) return { sent: 0 };
  const me = State.currentUser.idPub;
  const mine = State.currentUser.deviceId;

  // No device identity means a single-device client, and there is nobody to
  // tell.
  if (!mine) return { sent: 0 };

  let targets;
  try {
    targets = await ensureSendSessions(me);
  } catch {
    return { sent: 0 };
  }

  // Everything except this device. Sending to ourselves would echo the
  // message straight back and store it twice.
  const others = targets.filter((t) => t.session && isModern(t.session) && t.deviceId && t.deviceId !== mine);
  if (!others.length) return { sent: 0 };

  const envelope = {
    type: 'control',
    action: 'sync-sent',
    convId,
    lid: localId || null,
    payload: payloadObj
  };

  let sent = 0;
  for (const { deviceId, session } of others) {
    try {
      const r = sendV2(me, session, envelope, undefined, false, deviceId);
      if (r.success) sent++;
    } catch (err) {
      console.warn('[Sync] Could not reach one of your devices:', err.message);
    }
  }
  return { sent };
}

/** Two device arrays holding the same devices, ignoring order. */
function sameDevices(a, b) {
  const key = (d) => `${d.deviceId}|${d.devPub}|${d.name}`;
  const sa = (a || []).map(key).sort();
  const sb = (b || []).map(key).sort();
  return sa.length === sb.length && sa.every((v, i) => v === sb[i]);
}

/** The account's device list as last seen. Used by the Settings pane. */
export async function fetchMyDevices() {
  if (!State.currentUser) return null;
  const me = State.currentUser;
  try {
    const r = await postJSON('/api/devices', {
      username: me.username, authHash: me.authHash, peerId: me.idPub
    });
    return r.success ? r.list : null;
  } catch {
    return null;
  }
}

/**
 * Removes a device from the account's list and republishes.
 *
 * Honest about what this does NOT do: the removed device keeps its copy of
 * the account, its identity key and its decrypted history, because all of
 * that is already on it. What changes is that peers stop addressing it, so it
 * receives nothing further. Actually revoking read access needs a key the
 * removed device does not have, which is the group-key problem in another
 * shape and is not built.
 */
export async function revokeDevice(deviceId) {
  if (!State.currentUser) return { ok: false, reason: 'no user' };
  const me = State.currentUser;
  const current = await fetchMyDevices();
  if (!current) return { ok: false, reason: 'no list' };

  const next = withoutDevice(current, deviceId);
  if (!next) return { ok: false, reason: 'last device' };

  const signing = deriveSigningKey(me.idPriv);
  const list = {
    ...next,
    sig: signDeviceListWith(signing.privateKey, next),
    signPub: bytesToHex(signing.publicKey)
  };

  try {
    const r = await postJSON('/api/publish-devices', {
      username: me.username, authHash: me.authHash, list
    });
    if (!r.success) return { ok: false, reason: r.error || 'refused' };
    State.deviceList = list;
    return { ok: true };
  } catch (err) {
    return { ok: false, reason: err.message };
  }
}

/**
 * A session on the X3DH + Double Ratchet path, whichever version of it.
 *
 * v2 and v3 differ only in whether the ratchet header travels encrypted, so
 * every call site that used to ask "is this v2" means "is this not v1". Spelt
 * out once here rather than as `=== 2 || === 3` in eight places, because the
 * next version would have to find all eight again.
 */
function isModern(session) {
  return !!session && (session.v === 2 || session.v === 3);
}

/** Resolvers handed to acceptSession() so it can find our private halves. */
function preKeyResolver() {
  const pk = State.preKeys || {};
  return {
    signedPreKeyPriv(pub) {
      if (pk.spk && pk.spk.pub === pub) return pk.spk.priv;
      return (pk.spkArchive && pk.spkArchive[pub]) || null;
    },
    kemPreKeyPriv(pub) {
      // Long-lived by design: a KEM prekey is not single-use, so the archive
      // is what lets a handshake that fetched the previous one still land.
      if (pk.kem && pk.kem.pub === pub) return pk.kem.priv;
      return (pk.kemArchive && pk.kemArchive[pub]) || null;
    },
    oneTimePreKeyPriv(id) {
      const priv = pk.otk ? pk.otk[id] : null;
      if (priv) {
        // Single use: consuming it is what gives the session forward secrecy
        // against a later identity-key compromise.
        delete pk.otk[id];
        persist.preKeys();
        // Quietly replenish in the background once the pool runs low.
        if (Object.keys(pk.otk).length < OTK_REFILL_AT) ensurePreKeys();
      }
      return priv;
    }
  };
}

/* -------------------------------------------------- ratchet session engine */

function getOrCreateSessionForSending(contactId) {
  let session = State.sessions[contactId];
  let ephemPubHex = null;

  if (!session) {
    const myPrivBytes = hexToBytes(State.currentUser.idPriv);
    const contactPubBytes = hexToBytes(contactId);
    const ephemKeys = generateIdentityKeypair();
    ephemPubHex = bytesToHex(ephemKeys.publicKey);

    const dh1 = deriveSharedSecret(myPrivBytes, contactPubBytes);
    const dh2 = deriveSharedSecret(ephemKeys.privateKey, contactPubBytes);
    const derived = deriveInitialSessionKeys(dh1, dh2, 'sender');

    session = {
      sendingChainKey: bytesToHex(derived.sendingChainKey),
      receivingChainKey: bytesToHex(derived.receivingChainKey),
      messageIndexSending: 0,
      messageIndexReceiving: 0,
      skippedMessageKeys: {}
    };

    State.sessions[contactId] = session;
    persist.sessions();
  }

  return { session, ephemPubHex };
}

/**
 * Encrypts a payload and pushes it over the socket.
 *
 * `notify` is an explicit opt-in and must be true ONLY for real chat content.
 * Typing, read receipts, reactions, edits, deletes, profile syncs and call
 * signalling all ride this same frame and must stay false, or else a
 * typing indicator wakes someone's phone.
 */
// Session establishment is async (it fetches a prekey bundle), so concurrent
// sends to the same peer must not each start their own handshake. One promise
// per peer; everything after establishment is synchronous, which keeps the
// ratchet counters strictly ordered.
const sessionSetup = new Map();

/**
 * Prekey bundles for a peer, one per device they have published.
 *
 * Returns an array of `{ deviceId, bundle }`. A peer that has published no
 * device list yields a single entry with `deviceId: null`, which is the
 * single-device path and is what every existing conversation looks like.
 *
 * A device that appears in the list with no bundle is dropped here rather
 * than earlier: the relay reports it explicitly so that "this device has not
 * published prekeys yet" stays distinguishable from "this device does not
 * exist", and the distinction is worth keeping until the last possible
 * moment.
 */
async function fetchBundles(peerId) {
  try {
    const r = await postJSON('/api/prekey-bundle', {
      username: State.currentUser.username,
      authHash: State.currentUser.authHash,
      peerId
    });
    if (!r.success) return [];

    if (Array.isArray(r.devices)) {
      const usable = r.devices.filter((d) => d && d.bundle);
      if (usable.length < r.devices.length) {
        console.warn('[Devices] Peer has device(s) with no prekeys; they will not receive this message.');
      }
      return usable.map((d) => ({ deviceId: d.deviceId, bundle: d.bundle }));
    }

    return r.bundle ? [{ deviceId: null, bundle: r.bundle }] : [];
  } catch {
    return [];
  }
}

/**
 * Returns a v2 session for this peer, establishing one via X3DH if needed.
 * Falls back to whatever v1 session exists when the peer has published no
 * bundle (i.e. they are still running the old client).
 */
async function ensureSendSession(contactId) {
  const current = State.sessions[contactId];
  if (current && isModern(current)) return current;
  if (sessionSetup.has(contactId)) return sessionSetup.get(contactId);

  const job = (async () => {
    const bundles = await fetchBundles(contactId);
    // Only the account-level bundle is of interest here. A peer that has
    // published devices is handled by ensureSendSessions below.
    const entry = bundles.find((b) => !b.deviceId);
    if (!entry) return current || null;

    if (!verifyBundle(entry.bundle)) {
      // A bundle that fails signature verification means the relay tampered
      // with it (or the peer's signing key changed). Refuse rather than
      // silently downgrading to an unauthenticated handshake.
      console.error('[Ratchet] Prekey bundle signature invalid for', contactId.slice(0, 12));
      return current || null;
    }

    const session = initiateSession(State.currentUser.idPriv, { ...entry.bundle, idPub: contactId });
    session.seq = current && current.seq ? current.seq : 0;
    State.sessions[contactId] = session;
    persist.sessions();
    return session;
  })().finally(() => sessionSetup.delete(contactId));

  sessionSetup.set(contactId, job);
  return job;
}

/**
 * Every session needed to reach one peer: one per device they have published,
 * or a single account-level session if they have published none.
 *
 * Returns `[{ deviceId, session }]`. `deviceId` is null for the single-device
 * case, and that null is what tells the send path to omit `recipientDev` and
 * behave exactly as it did before devices existed.
 *
 * THE PEER IDENTITY IS ALWAYS THE ACCOUNT KEY, never the device key. X3DH
 * still mixes DH(EK_a, IK_b) against `contactId`, which is the Client ID the
 * user pasted out of band. That is what stops a relay inventing a device and
 * reading the fan-out addressed to it: an invented device has no idPriv and
 * cannot complete the handshake. The per-device part is only which prekey
 * pool the signed prekey and one-time prekey came from.
 */
async function ensureSendSessions(contactId) {
  const bundles = await fetchBundles(contactId);

  // No bundle at all means a peer still on v1. Fall back to whatever session
  // exists so the legacy path can carry the message.
  if (!bundles.length) {
    const current = State.sessions[contactId];
    return current ? [{ deviceId: null, session: current }] : [];
  }

  const out = [];
  for (const { deviceId, bundle } of bundles) {
    const key = sessionKey(contactId, deviceId);
    const current = State.sessions[key];
    if (current && isModern(current)) {
      out.push({ deviceId, session: current });
      continue;
    }

    if (!verifyBundle(bundle)) {
      console.error('[Ratchet] Prekey bundle signature invalid for', contactId.slice(0, 12));
      continue;
    }

    const session = initiateSession(State.currentUser.idPriv, { ...bundle, idPub: contactId });
    session.seq = current && current.seq ? current.seq : 0;
    State.sessions[key] = session;
    out.push({ deviceId, session });
  }

  if (out.length) persist.sessions();
  return out;
}

export async function sendE2EPayload(contactId, payloadObj, convId, notify = false) {
  if (!State.currentUser) return { success: false, messageIndex: -1 };

  const targets = await ensureSendSessions(contactId);
  const v2Targets = targets.filter((t) => t.session && isModern(t.session));

  if (v2Targets.length) {
    // One envelope per device. Each has its own ratchet, so each gets its own
    // `_mid` and its own correlation token; `_lid`, which the caller put in
    // the payload, is the same across all of them and is what makes them one
    // message rather than several to the receiving devices.
    const results = v2Targets.map(
      ({ deviceId, session }) => sendV2(contactId, session, payloadObj, convId, notify, deviceId)
    );

    // Success means at least one device took it. Requiring all of them would
    // mark a message failed because a peer's spare laptop is unreachable,
    // and the outbox would retry forever against a device that may never
    // come back.
    const refs = results.map((r) => r.ref).filter(Boolean);
    const first = results.find((r) => r.success) || results[0];
    return {
      success: results.some((r) => r.success),
      messageIndex: first.messageIndex,
      ref: first.ref,
      refs
    };
  }

  return sendV1(contactId, payloadObj, convId, notify);
}

/**
 * Sends a frame, sealing the sender identity into it first.
 *
 * The relay routes on `recipientId` alone; who sent the envelope is inside an
 * AEAD only the recipient can open. That keeps the sender out of everything
 * the relay writes down (the offline queue, the access log, the push payload)
 * and stops the relay forging a `senderId` it never had.
 */
function transmit(frame) {
  if (!(State.socketConnected && State.socket && State.socket.readyState === WebSocket.OPEN)) {
    return false;
  }

  // Every outbound frame passes through here, which is why the cover-traffic
  // clock is reset here rather than at the send sites. A real message must
  // REPLACE the cover cell that would otherwise have gone out, not arrive on
  // top of it, or the observable rate rises while you type and the constant
  // rate stops being constant. Setting it at each call site instead would mean
  // the next one added quietly reintroduces that.
  State.lastSentAt = Date.now();
  const out = frame.type === 'send' && State.currentUser
    ? { ...frame, payload: { sealed: 1, ...sealSender(frame.recipientId, {
        senderId: State.currentUser.idPub,
        // WHICH of our devices sent this, so the recipient can keep one
        // ratchet per sending device instead of letting two of ours collide
        // under a single key.
        //
        // It rides INSIDE the seal, not beside it. The relay already learns
        // the recipient's device from `recipientDev`, but it has no reason to
        // learn the sender's, and putting this in the frame would have handed
        // it over for free. Undefined on a single-device client, which keeps
        // the sealed object byte-identical to what it was.
        senderDev: State.currentUser.deviceId || undefined,
        payload: frame.payload
      }) } }
    : frame;
  State.socket.send(JSON.stringify(out));
  return true;
}

/**
 * Opens a sealed envelope. Returns `{ senderId, payload }`, or null if the
 * seal does not verify, which is exactly what happens if the relay tampers
 * with it or replays it at the wrong recipient.
 */
export function openSealed(payload) {
  if (!payload || !payload.sealed) return null;
  if (!State.currentUser) return null;
  const inner = unsealSender(State.currentUser.idPriv, payload);
  if (!inner || typeof inner.senderId !== 'string' || inner.senderId.length !== 64) return null;

  // senderDev selects which ratchet this envelope belongs to, so it is
  // attacker-chosen input to a storage key. Anything that is not a device id
  // is read as "no device", which lands on the peer's account session rather
  // than minting an arbitrary one. Without this, a peer could grow the
  // session store without bound, one key per message.
  const dev = typeof inner.senderDev === 'string' && /^[0-9a-f]{16}$/i.test(inner.senderDev)
    ? inner.senderDev.toLowerCase()
    : null;

  return { ...inner, senderDev: dev };
}

/**
 * A per-frame correlation token, so the relay's `ack` can be matched back to
 * the bubble that produced it.
 *
 * This is deliberately NOT the message index. Under protocol v2 the index
 * lives inside the ciphertext, so the relay cannot echo it, which is why v2
 * messages used to sit on "sending" forever.
 *
 * ZERO-KNOWLEDGE NOTE: this is a new plaintext field on the `send` frame. It
 * is 8 random bytes with no relation to the message, the sender, or the
 * recipient, and it is never stored: the relay bounces it straight back down
 * the same socket it arrived on. It tells the relay nothing it does not
 * already know from having routed the frame at all.
 */
function newRef() {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(8)));
}

function sendV2(contactId, session, payloadObj, convId, notify, deviceId = null) {
  // `_mid` is a monotonic per-session counter carried INSIDE the ciphertext.
  // It is the stable identity both sides use for replies, reactions, edits
  // and deletes. The ratchet's own `n` resets on every DH step, so it cannot
  // serve that purpose.
  const mid = session.seq || 0;
  session.seq = mid + 1;

  // v3 puts { dh, pn, n } inside an AEAD; v2 sends them in the clear. Both
  // shapes are produced here so a session opened before the upgrade keeps
  // working without a migration, and so mail already queued for a v2 peer
  // still drains.
  const payload = session.v === 3
    ? encryptWithSessionV3(session, { ...payloadObj, _mid: mid })
    : { v: 2, ...encryptWithSession(session, { ...payloadObj, _mid: mid }) };
  persist.sessions();

  const ref = newRef();
  const ok = transmit({
    type: 'send',
    recipientId: contactId,
    // Which of the recipient's devices this envelope is for. Omitted entirely
    // for a single-device peer, so the frame is byte-identical to what it was
    // before devices existed. See the note in server.js: this is deliberate
    // new plaintext, and the relay learns which device a message is for.
    recipientDev: deviceId || undefined,
    payload,
    // The conversation the RECIPIENT sees: the group id for a group, our
    // own identity key for a one-to-one chat. Hashed with the recipient, so
    // no two members of a group send the same tag.
    pushTag: notify ? pushTagFor(convId || State.currentUser.idPub, contactId) : undefined,
    notify: !!notify,
    ref
  });
  return { success: ok, messageIndex: mid, ref };
}

function sendV1(contactId, payloadObj, convId, notify) {
  const { session, ephemPubHex } = getOrCreateSessionForSending(contactId);
  const sendingChainKeyBytes = hexToBytes(session.sendingChainKey);
  const msgKeyBytes = ratchetChainKey(sendingChainKeyBytes, 'MessageKey');
  const nextChainKeyBytes = ratchetChainKey(sendingChainKeyBytes, 'NextChainKey');

  const { ciphertext, nonce } = encryptMessage(msgKeyBytes, utf8Encode(JSON.stringify(payloadObj)));

  const messageIndex = session.messageIndexSending;
  session.sendingChainKey = bytesToHex(nextChainKeyBytes);
  session.messageIndexSending++;

  State.sessions[contactId] = session;
  persist.sessions();

  const payload = { messageIndex, nonce: bytesToHex(nonce), ciphertext: bytesToHex(ciphertext) };
  if (ephemPubHex) payload.ephemPub = ephemPubHex;

  const ref = newRef();
  const frame = {
    type: 'send',
    recipientId: contactId,
    payload,
    // The conversation the RECIPIENT sees: the group id for a group, our
    // own identity key for a one-to-one chat. Hashed with the recipient, so
    // no two members of a group send the same tag.
    pushTag: notify ? pushTagFor(convId || State.currentUser.idPub, contactId) : undefined,
    notify: !!notify,
    ref
  };

  if (State.socketConnected && State.socket && State.socket.readyState === WebSocket.OPEN) {
    State.socket.send(JSON.stringify(frame));
    return { success: true, messageIndex, ref };
  }
  return { success: false, messageIndex, ref };
}

// --- SKIPPED-KEY LIMITS ---
//
// `messageIndex` arrives as PLAINTEXT in the envelope, so it is fully
// attacker-controlled, and the relay will forward a `send` frame to any
// recipientId from any registered client. Without these bounds a single
// envelope carrying `ephemPub` plus `messageIndex: 1e9` makes the recipient
// ratchet a billion times and write a billion keys to localStorage. That is an
// unauthenticated remote denial of service against any user whose ID is known.
//
// MAX_SKIP caps how far a single envelope may jump ahead. MAX_STORED and
// SKIP_TTL_MS bound the retained pool, which also limits how long a stolen
// device can be used to decrypt messages that were never delivered.
const MAX_SKIP = 1000;
const MAX_STORED_SKIPPED = 2000;
const SKIP_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Skipped keys used to be stored as `{ [index]: hexKey }` with no timestamp.
 * They are now `{ [index]: { k, t } }` so they can expire. Old entries are
 * upgraded on read rather than migrated, and are treated as freshly seen.
 */
function readSkipped(store, index) {
  const entry = store[index];
  if (!entry) return null;
  return typeof entry === 'string' ? entry : entry.k;
}

function pruneSkipped(session) {
  const store = session.skippedMessageKeys || {};
  const now = Date.now();

  for (const [index, entry] of Object.entries(store)) {
    if (typeof entry === 'string') {
      // Legacy entry: adopt it with a current timestamp so it ages out later.
      store[index] = { k: entry, t: now };
    } else if (!entry || typeof entry.t !== 'number' || now - entry.t > SKIP_TTL_MS) {
      delete store[index];
    }
  }

  // Oldest-first eviction if the pool is still over budget.
  const keys = Object.keys(store);
  if (keys.length > MAX_STORED_SKIPPED) {
    keys
      .sort((a, b) => (store[a].t || 0) - (store[b].t || 0))
      .slice(0, keys.length - MAX_STORED_SKIPPED)
      .forEach((k) => delete store[k]);
  }

  session.skippedMessageKeys = store;
}

/**
 * Decrypts an inbound envelope, dispatching on the protocol version stamped
 * on the payload. v1 is retained so messages queued by an older peer (or by
 * this account before the upgrade) still drain.
 */
export function processIncomingMessage(senderId, payload, senderDev = null) {
  if (payload && (payload.v === 2 || payload.v === 3)) return processV2(senderId, payload, senderDev);
  return processV1(senderId, payload);
}

/* ------------------------------------------------- session health ------- */

// Consecutive envelopes from a peer that would not open. In memory only: this
// is a symptom of the current session, not a fact about the account, and a
// reload legitimately clears it.
const decryptFailures = new Map();

export function decryptFailureCount(contactId) {
  return decryptFailures.get(contactId) || 0;
}

/** What the session with this peer actually is, for the details panel. */
export function sessionInfo(contactId) {
  const s = State.sessions[contactId];
  if (!s) return { established: false };
  return {
    established: true,
    version: isModern(s) ? s.v : 1,
    // Recorded at handshake time: a peer without a KEM prekey still gets a
    // working session, just a classical one.
    postQuantum: !!s.pq
  };
}

/**
 * Discards the session so the next send performs a fresh X3DH.
 *
 * The only recovery from a desynchronised ratchet. A peer who reinstalls
 * comes back with new prekeys and a new ratchet, but we keep replaying into
 * the old session and every message they send fails to open; the accept path
 * deliberately ignores their new preamble, because honouring a replayed
 * preamble would let anyone reset the session at will.
 *
 * Safe to do. Decrypted history is stored separately from session state, so
 * this costs undelivered messages, not the archive. It does NOT weaken
 * verification: a contact IS their identity key here, so the safety number
 * cannot change without it being a different contact.
 */
export function resetSession(contactId) {
  // Every device of theirs, not just the account session. Leaving a
  // per-device ratchet behind means the reset appears to work and then the
  // stale session resurrects itself on the next message from that device.
  for (const key of sessionKeysFor(State.sessions, contactId)) {
    delete State.sessions[key];
  }
  decryptFailures.delete(contactId);
  persist.sessions();
}

function processV2(senderId, payload, senderDev = null) {
  const isV3 = payload.v === 3;
  // v3 keeps { dh, pn, n } inside `eh`. The only thing readable before a key
  // exists is `hs`, the X3DH preamble, and only until the peer replies.
  const header = isV3 ? payload.hs : payload.header;
  const { nonce, ciphertext } = payload;
  if (typeof nonce !== 'string' || typeof ciphertext !== 'string') return null;
  if (isV3 ? typeof payload.eh !== 'string' : !header) return null;

  // One ratchet per SENDING device. Two devices of the same peer each run
  // their own X3DH against us, and keying both under the bare peer id meant
  // the second handshake overwrote the first, after which every message from
  // the first device failed to open.
  //
  // A peer with no devices yields the bare id, so nothing established before
  // this existed is disturbed.
  const skey = sessionKey(senderId, senderDev);
  let session = State.sessions[skey];

  const wantVersion = isV3 ? 3 : 2;

  // NO MID-SESSION DOWNGRADE. Once a session is v3 the peer is known to speak
  // v3, so a v2-shaped envelope arriving under the same key is either a relay
  // replaying something old or a relay trying to talk us back down to a
  // readable header. Neither deserves an answer, and the reverse direction is
  // refused for the same reason.
  if (session && session.v !== wantVersion && session.theirRatchetPub != null) return null;

  // An X3DH preamble means the peer is opening (or re-opening) a session.
  // The preamble is replayed until they hear back from us, so only act on it
  // when we do not already hold a matching session.
  const needsAccept = header && header.ek && header.spk &&
    (!session || session.v !== wantVersion || session.theirRatchetPub == null);

  if (needsAccept) {
    const accepted = acceptSession(State.currentUser.idPriv, senderId, header, preKeyResolver());
    if (accepted && accepted.v === wantVersion) {
      accepted.seq = session && session.seq ? session.seq : 0;
      session = accepted;
      State.sessions[skey] = session;
    }
  }

  if (!session || session.v !== wantVersion) return null;

  let payloadObj;
  let openedHeader = header;
  if (isV3) {
    const r = decryptWithSessionV3(session, payload.eh, nonce, ciphertext);
    payloadObj = r ? r.payload : null;
    // `n` only becomes readable once the header is open, and the fallback
    // envelope index below still needs it.
    if (r) openedHeader = r.header;
  } else {
    payloadObj = decryptWithSession(session, header, nonce, ciphertext);
  }
  persist.sessions();
  if (!payloadObj) {
    decryptFailures.set(senderId, (decryptFailures.get(senderId) || 0) + 1);
    return null;
  }
  decryptFailures.delete(senderId);

  // `_mid` is the sender's stable counter; strip it before the app sees it.
  const envelopeIndex = Number.isSafeInteger(payloadObj._mid)
    ? payloadObj._mid
    : (openedHeader ? openedHeader.n : 0);
  delete payloadObj._mid;

  // `_lid` is the sender's own id for this message, minted once and reused on
  // every retry. `_mid` cannot serve: re-encrypting allocates a new counter,
  // so a retry would arrive looking like a new message. Surfaced as remoteId
  // for the duplicate check in outbox.js.
  const remoteId = typeof payloadObj._lid === 'string' ? payloadObj._lid : null;
  delete payloadObj._lid;

  return { payloadObj, envelopeIndex, remoteId };
}

function processV1(senderId, payload) {
  let session = State.sessions[senderId];
  const { ephemPub, messageIndex, nonce, ciphertext } = payload;

  // A v1 envelope can never resurrect a v2 session.
  if (session && isModern(session)) return null;

  // Reject a malformed or hostile envelope before touching any key material.
  if (!Number.isSafeInteger(messageIndex) || messageIndex < 0) return null;
  if (typeof nonce !== 'string' || typeof ciphertext !== 'string') return null;

  const myPrivBytes = hexToBytes(State.currentUser.idPriv);
  const senderPubBytes = hexToBytes(senderId);

  if (ephemPub) {
    const ephemPubBytes = hexToBytes(ephemPub);
    const dh1 = deriveSharedSecret(myPrivBytes, senderPubBytes);
    const dh2 = deriveSharedSecret(myPrivBytes, ephemPubBytes);
    const derived = deriveInitialSessionKeys(dh1, dh2, 'recipient');

    session = {
      sendingChainKey: bytesToHex(derived.sendingChainKey),
      receivingChainKey: bytesToHex(derived.receivingChainKey),
      messageIndexSending: 0,
      messageIndexReceiving: 0,
      skippedMessageKeys: {}
    };
    State.sessions[senderId] = session;
    persist.sessions();
  }

  if (!session) return null;

  let receivingChainKeyBytes = hexToBytes(session.receivingChainKey);
  let messageKeyHex = null;

  if (messageIndex === session.messageIndexReceiving) {
    const messageKeyBytes = ratchetChainKey(receivingChainKeyBytes, 'MessageKey');
    receivingChainKeyBytes = ratchetChainKey(receivingChainKeyBytes, 'NextChainKey');
    session.receivingChainKey = bytesToHex(receivingChainKeyBytes);
    session.messageIndexReceiving++;
    messageKeyHex = bytesToHex(messageKeyBytes);
  } else if (messageIndex > session.messageIndexReceiving) {
    // Refuse to ratchet an implausible distance. A genuine gap is at most a
    // handful of messages lost in transit; anything larger is hostile.
    if (messageIndex - session.messageIndexReceiving > MAX_SKIP) {
      console.warn('[Ratchet] Rejected envelope skipping too far ahead:',
        messageIndex - session.messageIndexReceiving);
      return null;
    }

    // Ratchet forward past the gap, stashing the keys we skipped so the
    // delayed messages can still be decrypted when they arrive.
    const now = Date.now();
    while (session.messageIndexReceiving < messageIndex) {
      const skipped = ratchetChainKey(receivingChainKeyBytes, 'MessageKey');
      receivingChainKeyBytes = ratchetChainKey(receivingChainKeyBytes, 'NextChainKey');
      session.skippedMessageKeys[session.messageIndexReceiving] = { k: bytesToHex(skipped), t: now };
      session.messageIndexReceiving++;
    }
    const messageKeyBytes = ratchetChainKey(receivingChainKeyBytes, 'MessageKey');
    receivingChainKeyBytes = ratchetChainKey(receivingChainKeyBytes, 'NextChainKey');
    session.receivingChainKey = bytesToHex(receivingChainKeyBytes);
    session.messageIndexReceiving++;
    messageKeyHex = bytesToHex(messageKeyBytes);

    pruneSkipped(session);
  } else {
    messageKeyHex = readSkipped(session.skippedMessageKeys, messageIndex);
    if (!messageKeyHex) return null;
    // Single use: a message key is never valid twice.
    delete session.skippedMessageKeys[messageIndex];
  }

  State.sessions[senderId] = session;
  persist.sessions();

  try {
    const decrypted = decryptMessage(hexToBytes(messageKeyHex), hexToBytes(ciphertext), hexToBytes(nonce));
    const str = utf8Decode(decrypted);
    try {
      return { payloadObj: JSON.parse(str), envelopeIndex: messageIndex };
    } catch {
      return { payloadObj: { type: 'text', text: str }, envelopeIndex: messageIndex };
    }
  } catch {
    return null;
  }
}

/* --------------------------------------------------------- group fan-out */

/**
 * Groups are pure client-side fan-out. The server has no group concept.
 *
 * Resolves to the correlation tokens of every envelope it sent, so the one
 * bubble the user sees can be flipped off "sending" when the relay acks any of
 * them. There is no per-member delivery state in the UI, and inventing one
 * would be a lie: fan-out to a member who is offline is queued, not delivered.
 */
export async function sendGroupMessage(groupId, payloadObj) {
  const group = State.groups.find((g) => g.id === groupId);
  if (!group) return [];
  const wrapped = {
    type: 'group-message',
    groupId,
    senderId: State.currentUser.idPub,
    message: payloadObj
  };
  const results = await Promise.all(
    group.members
      .filter((memberId) => memberId !== State.currentUser.idPub)
      .map((memberId) => sendE2EPayload(memberId, wrapped, groupId, true))
  );
  return results.map((r) => r && r.ref).filter(Boolean);
}

/* ------------------------------------------------- group administration -- */

/**
 * Who may change a group.
 *
 * The creator owns it. There is no server-side group at all, so there is no
 * authority to appeal to: whatever rule the clients agree on is the rule. A
 * single owner is the simplest one that cannot produce two members holding
 * contradictory rosters and both believing they are right.
 *
 * Groups created before ownership existed have no owner recorded. Rather than
 * freezing them forever, any member may administer those, which is exactly
 * the level of trust they were created under.
 */
/* ------------------------------------------------------- signed rosters */
/**
 * Membership used to be an assertion. Whoever's envelope arrived last decided
 * who was in the group, and a new invitee had no way to tell a real roster
 * from one a member had invented, because the only thing vouching for it was
 * the sender saying so.
 *
 * A roster is now signed by the group's owner over a canonical encoding, and
 * every member verifies before applying. A non-owner cannot mint one, and a
 * roster that has been edited in flight fails verification instead of being
 * applied. The owner's signing key is pinned on first accept, so a later
 * roster signed by a different key is refused rather than silently trusted.
 *
 * What this does NOT do, stated plainly: a first invitation is still trust on
 * first use. An invitee with no prior knowledge of the group cannot tell a
 * current signed roster from an older one the inviter replayed, and nothing
 * stops the owner themselves lying about the membership. It closes forgery by
 * other members and tampering in transit, which is what "a member can lie to
 * an invitee" actually meant.
 */
export function buildRosterMessage({ groupId, rev, name, owner, members }) {
  // Canonical: members sorted, everything coerced, fixed key order. Two
  // clients holding the same roster must produce byte-identical input or the
  // signature is a coin flip. Domain-separated so a roster signature can never
  // be lifted into the prekey contexts, which use the same key.
  const canon = JSON.stringify({
    groupId: String(groupId),
    rev: Number(rev),
    name: String(name == null ? '' : name),
    owner: String(owner == null ? '' : owner),
    members: Array.from(new Set((members || []).map(String))).sort()
  });
  return utf8Encode('TalonGroupRoster:' + canon);
}

/** Signs roster fields with a signing private key. */
export function signRosterWith(signingPriv, fields) {
  return bytesToHex(signBytes(signingPriv, buildRosterMessage(fields)));
}

/** Verifies a roster signature against the signer's Ed25519 public key. */
export function verifyRoster(fields, sigHex, signPubHex) {
  if (typeof sigHex !== 'string' || typeof signPubHex !== 'string') return false;
  try {
    return verifySignature(
      hexToBytes(signPubHex), hexToBytes(sigHex), buildRosterMessage(fields)
    );
  } catch {
    return false;
  }
}

/**
 * Decides whether an inbound roster may replace what we hold.
 *
 * Split out from the handler and kept pure so the rules can be tested without
 * a session, a socket or a DOM. Returns `{ ok, reason }`; the reason is for
 * the log, since a refused roster is exactly the kind of thing that otherwise
 * looks like an unexplained sync bug.
 */
export function rosterAcceptable(existing, incoming) {
  const { groupId, rev, name, owner, members, sig, ownerSignPub } = incoming || {};

  if (typeof groupId !== 'string' || !Array.isArray(members)) {
    return { ok: false, reason: 'malformed' };
  }
  if (!Number.isSafeInteger(rev) || rev < 1) {
    return { ok: false, reason: 'bad revision' };
  }

  // Unsigned rosters are refused outright. Accepting them "for compatibility"
  // would leave the whole mechanism opt-out for anyone willing to omit a field.
  if (!sig || !ownerSignPub) return { ok: false, reason: 'unsigned' };
  if (typeof owner !== 'string' || !owner) return { ok: false, reason: 'no owner' };
  if (!members.includes(owner)) return { ok: false, reason: 'owner not a member' };

  if (!verifyRoster({ groupId, rev, name, owner, members }, sig, ownerSignPub)) {
    return { ok: false, reason: 'bad signature' };
  }

  if (existing) {
    if (rev <= (existing.rev || 0)) return { ok: false, reason: 'stale revision' };
    if (existing.owner && existing.owner !== owner) {
      return { ok: false, reason: 'owner changed' };
    }
    // Pinned on first accept. A valid signature under a *different* key is
    // exactly what a substituted signing key looks like.
    if (existing.ownerSignPub && existing.ownerSignPub !== ownerSignPub) {
      return { ok: false, reason: 'owner signing key changed' };
    }
  }

  return { ok: true };
}

export function canAdminGroup(group) {
  if (!group || !State.currentUser) return false;
  if (!group.members.includes(State.currentUser.idPub)) return false;
  return group.owner ? group.owner === State.currentUser.idPub : true;
}

/** True when `senderId` is allowed to have made this change. */
export function acceptsAdminFrom(group, senderId) {
  if (!group.members.includes(senderId)) return false;
  return group.owner ? group.owner === senderId : true;
}

/**
 * Monotonic per-group revision.
 *
 * Roster updates are fanned out one envelope per member and can arrive out of
 * order, or late from a member who was offline. Without a counter, a stale
 * update would happily overwrite a newer roster and members would silently
 * diverge, which is the failure this whole area is prone to.
 */
export function nextGroupRev(group) {
  return (group.rev || 0) + 1;
}

export function acceptGroupRev(group, rev) {
  const incoming = Number.isSafeInteger(rev) ? rev : 0;
  if (incoming <= (group.rev || 0)) return false;
  group.rev = incoming;
  return true;
}

/**
 * Signs the group's current state and returns the fields every roster-bearing
 * payload must carry. Called after `rev` has already been advanced, so the
 * signature covers the revision it is announcing.
 */
function signCurrentRoster(group) {
  const signing = deriveSigningKey(State.currentUser.idPriv);
  const fields = {
    groupId: group.id,
    rev: group.rev,
    name: group.name,
    owner: group.owner || State.currentUser.idPub,
    members: group.members
  };
  return {
    ...fields,
    sig: signRosterWith(signing.privateKey, fields),
    ownerSignPub: bytesToHex(signing.publicKey)
  };
}

export function renameGroup(groupId, name) {
  const group = State.groups.find((g) => g.id === groupId);
  if (!group || !canAdminGroup(group)) return false;
  group.name = name;
  group.rev = nextGroupRev(group);
  // Adopt ownership for legacy groups that never recorded one, otherwise the
  // roster we are about to sign names no owner and every member refuses it.
  if (!group.owner) group.owner = State.currentUser.idPub;
  persist.groups();
  syncGroupsWithServer();
  sendGroupControl(groupId, 'rename', signCurrentRoster(group));
  return true;
}

/**
 * Replaces the roster.
 *
 * New members get a full `create` invite, since a roster update alone would
 * name a group they have never heard of. Continuing members get the roster.
 * Anyone dropped gets told, so their client can stop presenting the group as
 * live rather than leaving them talking into a room no one is in.
 *
 * On removal there is nothing cryptographic to rotate: a group has no group
 * key, only a ratchet per member, so "removed" means the rest of us stop
 * addressing them. It is an agreement between clients, not an enforcement,
 * and the UI says so.
 */
export function setGroupMembers(groupId, members) {
  const group = State.groups.find((g) => g.id === groupId);
  if (!group || !canAdminGroup(group)) return false;

  const me = State.currentUser.idPub;
  const next = Array.from(new Set([...members, me]));
  const before = group.members.slice();
  const added = next.filter((id) => !before.includes(id));
  const removed = before.filter((id) => !next.includes(id));

  group.members = next;
  group.rev = nextGroupRev(group);
  if (!group.owner) group.owner = me;
  persist.groups();
  syncGroupsWithServer();

  // One signature, reused by both payloads. The invite and the roster describe
  // the same state, so signing them separately would only create a way for the
  // two to disagree.
  const signed = signCurrentRoster(group);

  const invite = { type: 'group-control', action: 'create', ...signed };
  added.forEach((id) => sendE2EPayload(id, invite, groupId, true));

  const roster = { type: 'group-control', action: 'roster', ...signed };
  next.forEach((id) => {
    if (id !== me && !added.includes(id)) sendE2EPayload(id, roster, groupId, false);
  });

  removed.forEach((id) => sendE2EPayload(
    id, { type: 'group-control', action: 'removed', groupId }, groupId, false
  ));

  return { added: added.length, removed: removed.length };
}

/**
 * Announces that we are leaving.
 *
 * Previously leaving was purely local, so everyone else carried on sending to
 * someone who had gone. Deletion of our own copy stays the caller's job; this
 * is only the part the other members need to hear.
 */
export function announceLeave(groupId) {
  const group = State.groups.find((g) => g.id === groupId);
  if (!group) return;
  sendGroupControl(groupId, 'leave', {});
}

export function sendGroupControl(groupId, action, extra = {}) {
  const group = State.groups.find((g) => g.id === groupId);
  if (!group) return;
  const wrapped = { type: 'group-control', action, groupId, ...extra };
  group.members.forEach((memberId) => {
    if (memberId !== State.currentUser.idPub) sendE2EPayload(memberId, wrapped, groupId, false);
  });
}

/** Routes a control payload to the right transport for this conversation. */
export function sendControl(convId, action, extra = {}) {
  const group = State.groups.find((g) => g.id === convId);
  if (group) {
    sendGroupControl(convId, action, extra);
  } else {
    sendE2EPayload(convId, { type: 'control', action, ...extra }, undefined, false);
  }
}

/* ------------------------------------------------------- message helpers */

export function isGroupId(id) {
  return State.groups.some((g) => g.id === id);
}

/* -------------------------------------------------- contact trust states */
//
// Three flags govern how much a peer is allowed to do:
//
//   blocked    envelopes are dropped on arrival, nothing is stored
//   pending    a stranger who messaged us; their conversation is quarantined
//                behind an Accept/Block bar and they cannot pull us into
//                groups until accepted
//   nameLocked the local user named this contact, so `profile-sync` may not
//                overwrite it. Without this any contact can silently rename
//                themselves to another contact's exact display name, which in
//                a group chat (where the author label is the only identifier)
//                is a working impersonation.

export function findContact(id) {
  return State.contacts.find((c) => c.idPub === id) || null;
}

export function isBlocked(id) {
  const c = findContact(id);
  return !!(c && c.blocked);
}

export function isPending(id) {
  const c = findContact(id);
  return !!(c && c.pending);
}

/** True once the peer is a contact we have actually accepted. */
export function isTrusted(id) {
  const c = findContact(id);
  return !!(c && !c.pending && !c.blocked);
}

export function setContactFlags(id, flags) {
  const c = findContact(id);
  if (!c) return null;
  Object.assign(c, flags);
  persist.contacts();
  return c;
}

export function pendingRequests() {
  return State.contacts.filter((c) => c.pending && !c.blocked);
}

export function blockedContacts() {
  return State.contacts.filter((c) => c.blocked);
}

/**
 * Messages predate stable IDs: identity is the (contactId, messageIndex,
 * sender) triple, and group messages use Date.now() as their index. New
 * messages also carry a localId, but lookups must keep working for history
 * written before that existed.
 */
export function findMsg(convId, messageIndex, sender) {
  return State.messages.find(
    (m) => m.contactId === convId && m.messageIndex === messageIndex && m.sender === sender
  );
}

export function messagesFor(convId) {
  return State.messages.filter((m) => m.contactId === convId);
}

export function lastMessageFor(convId) {
  return State.messages.findLast((m) => m.contactId === convId);
}

/** TTL is per-conversation; 0 means disappearing messages are off. */
/**
 * The disappearing-message timer for a conversation.
 *
 * A conversation that has never had one set inherits `defaultTtl` from
 * Settings. Once it is set explicitly, including explicitly to Off, the
 * per-conversation value wins, so changing the default later never silently
 * re-enables expiry on a chat where it was turned off.
 */
export function ttlFor(convId) {
  const meta = metaFor(convId);
  if (meta.ttl === undefined) return State.settings.defaultTtl || 0;
  return meta.ttl || 0;
}

export function expiryFor(convId) {
  const ttl = ttlFor(convId);
  return ttl > 0 ? Date.now() + ttl : null;
}

/**
 * Reactions used to be a bare string[] with no dedupe or attribution. They
 * are now { emoji: [senderId] }. Upgrade old rows on read rather than running
 * a migration pass, so nothing has to touch every message at boot.
 */
export function normalizeReactions(msg) {
  if (!msg.reactions) return null;
  if (Array.isArray(msg.reactions)) {
    const upgraded = {};
    // Legacy rows lost the attribution, so credit them to the peer. The only
    // thing we can say truthfully is "someone other than a known self-react".
    msg.reactions.forEach((emoji) => {
      if (!upgraded[emoji]) upgraded[emoji] = [];
      upgraded[emoji].push('legacy');
    });
    msg.reactions = upgraded;
  }
  return msg.reactions;
}

export function toggleReactionLocal(msg, emoji, whoId) {
  const reactions = normalizeReactions(msg) || (msg.reactions = {});
  const list = reactions[emoji] || (reactions[emoji] = []);
  const at = list.indexOf(whoId);
  if (at >= 0) {
    list.splice(at, 1);
    if (list.length === 0) delete reactions[emoji];
    return false;
  }
  list.push(whoId);
  return true;
}

/** Number of inbound messages in a conversation that have not been read. */
export function unreadCount(convId) {
  let n = 0;
  for (const m of State.messages) {
    if (m.contactId === convId && m.sender === 'them' && m.status !== 'read' && !m.deleted) n++;
  }
  return n;
}

export function totalUnread() {
  const seen = new Set();
  let n = 0;
  for (const m of State.messages) {
    if (m.sender === 'them' && m.status !== 'read' && !m.deleted) {
      n++;
      seen.add(m.contactId);
    }
  }
  return { messages: n, conversations: seen.size };
}

/** One-line preview for the chat list. */
export function previewFor(msg) {
  if (!msg) return '';
  if (msg.deleted) return 'Message deleted';
  switch (msg.type) {
    case 'file': return msg.file && msg.file.mime && msg.file.mime.startsWith('image/') ? 'Photo' : 'File';
    case 'voice-memo': return 'Voice message';
    case 'sticker': return msg.text || 'Sticker';
    default: return msg.text || '';
  }
}
