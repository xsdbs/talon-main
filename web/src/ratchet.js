// --- PROTOCOL v2 AND v3: X3DH + DOUBLE RATCHET ---
//
// v3 is current. v2 is retained because a session that is already open stays
// open, and because mail queued by an un-upgraded peer still has to drain.
//
// A v3 session object looks like:
//
//   {
//     v: 3,
//     rootKey,                 hex
//     ratchetPriv, ratchetPub, hex   our current ratchet keypair
//     theirRatchetPub,         hex | null
//     sendingChainKey,         hex | null
//     receivingChainKey,       hex | null
//     Ns, Nr,                  message counters in the current chains
//     PN,                      length of the previous sending chain
//     hks, hkr,                hex | null   header keys for each direction
//     nhks, nhkr,              hex | null   the ones the next DH step promotes
//     oldHkr: [hex],           BOUNDED tail of retired receiving header keys
//     skipped: { "<hkTag>:<n>": { k, t } },
//     pending                  X3DH preamble replayed on every message until
//                              the peer replies, so a lost first message
//                              cannot strand the session
//   }
//
// v2 is the same minus the four header keys and `oldHkr`, and its `skipped`
// is keyed by the peer's visible ratchet key instead of a header key tag.
//
// WHAT CHANGED AND WHY. A v2 envelope carried { v, dh, pn, n } in the clear.
// That header is the most useful thing the relay was ever handed: `dh` is
// stable for a whole DH epoch and shows up on messages in BOTH directions, so
// grouping envelopes by it reconstructs conversations and pairs the two
// participants even though the sender is sealed. v3 encrypts the header under
// a key that ratchets with the chain, so the only plaintext left on a v3
// envelope is the version and the opaque blobs.
//
// The FIRST message of a session still carries its X3DH preamble in the clear,
// in `hs`, because the recipient cannot derive a header key before completing
// X3DH and cannot complete X3DH without reading the preamble. The Double
// Ratchet specification has the same carve-out. One message per session
// reveals that a handshake happened and whether it was post-quantum.

import {
  generateIdentityKeypair, deriveSharedSecret, bytesToHex, hexToBytes,
  utf8Encode, utf8Decode, encryptMessage, decryptMessage,
  deriveX3DHSecret, kdfRootKey, kdfChainKey, kdfRootKeyHE,
  deriveInitialHeaderKeys, encryptHeader, decryptHeader, sha256Hash,
  verifySignature, padPlaintext, unpadPlaintext,
  kemEncapsulate, kemDecapsulate
} from './crypto-bundle.js';

// Same rationale as the v1 bounds in messaging.js: `n` and `pn` are
// attacker-controlled plaintext, so every loop driven by them must be capped.
export const MAX_SKIP = 1000;
const MAX_STORED_SKIPPED = 2000;
const SKIP_TTL_MS = 7 * 24 * 60 * 60 * 1000;

// How many retired receiving header keys a v3 session keeps.
//
// THIS BOUND IS THE WHOLE POINT. With encrypted headers a receiver cannot read
// which epoch a message belongs to without first decrypting the header, so it
// has to try candidate keys. The Double Ratchet specification's own pseudocode
// loops over every banked skipped key, which here would be up to
// MAX_STORED_SKIPPED AEAD attempts driven by a value an attacker chooses: an
// unauthenticated remote DoS, and this project has already shipped that exact
// bug once with `MAX_SKIP`.
//
// So the candidates are bounded instead: hkr, nhkr, and this many retired
// keys. Worst case is MAX_OLD_HEADER_KEYS + 2 attempts per inbound envelope.
// The cost is that a message delayed across more than this many changes of
// direction can no longer be opened, which is a far better failure than a
// relay being able to pin the CPU by sending garbage.
const MAX_OLD_HEADER_KEYS = 6;

/* --------------------------------------------------------------- prekeys */

export function buildSignedPreKeyMessage(preKeyPubHex) {
  // What the Ed25519 signature actually covers. Domain-separated so a
  // signature can never be lifted into another context.
  return utf8Encode('TalonSignedPreKey:' + preKeyPubHex);
}

/** The KEM prekey gets its own domain so the two signatures can't be swapped. */
export function buildKemPreKeyMessage(kemPubHex) {
  return utf8Encode('TalonKemPreKey:' + kemPubHex);
}

/**
 * What the capability list signature covers.
 *
 * Sorted and joined, so two clients holding the same capabilities produce
 * identical bytes. Same canonical-encoding discipline as the group rosters in
 * messaging.js, and for the same reason: a signature over a JSON object whose
 * key order can vary is a signature over nothing dependable.
 */
export function buildCapsMessage(caps) {
  return utf8Encode('TalonCaps:' + [...(caps || [])].map(String).sort().join(','));
}

export const PROTOCOL_CAPS = ['v3'];

/**
 * Validates a bundle fetched from the relay. The signature is the only thing
 * standing between us and a relay that substitutes its own prekeys, so a
 * bundle that fails verification is refused outright rather than downgraded.
 */
export function verifyBundle(bundle) {
  if (!bundle || !bundle.signPub || !bundle.signedPreKey) return false;
  const signPub = hexToBytes(bundle.signPub);

  if (!verifySignature(
    signPub,
    hexToBytes(bundle.signedPreKey.sig),
    buildSignedPreKeyMessage(bundle.signedPreKey.pub)
  )) return false;

  // The KEM prekey is optional on the wire (a peer on an older build has
  // none) but if one is offered it must be signed by the same identity.
  // Otherwise the relay could inject a KEM key it holds the secret for and
  // the post-quantum half would protect nothing.
  if (bundle.kemPreKey) {
    if (!bundle.kemPreKey.pub || !bundle.kemPreKey.sig) return false;
    if (!verifySignature(
      signPub,
      hexToBytes(bundle.kemPreKey.sig),
      buildKemPreKeyMessage(bundle.kemPreKey.pub)
    )) return false;
  }

  // The capability list says which protocol versions the peer speaks, and it
  // decides whether we open a v3 session or fall back to v2. An unsigned one
  // would let the relay pick our protocol version for us, so a list that
  // arrives without a valid signature is refused rather than trusted.
  //
  // HONEST LIMIT, and the reason the v2 sunset date matters: a relay can still
  // DELETE `caps` and `capsSig` together, and a bundle with no capability list
  // is indistinguishable from one published by an un-upgraded client, which we
  // must keep accepting for as long as v2 exists. Downgrade is therefore
  // possible during coexistence and impossible after it. Refusing an absent
  // list is what closes this, and that is a change to make on the sunset date,
  // not before.
  if (bundle.caps !== undefined) {
    if (!Array.isArray(bundle.caps) || !bundle.capsSig) return false;
    if (!verifySignature(
      signPub,
      hexToBytes(bundle.capsSig),
      buildCapsMessage(bundle.caps)
    )) return false;
  }
  return true;
}

/** True when the peer's verified bundle says it speaks v3. */
export function bundleSpeaksV3(bundle) {
  return !!(bundle && Array.isArray(bundle.caps) && bundle.caps.includes('v3'));
}

/* ------------------------------------------------------ session creation */

/**
 * Initiator side of X3DH. Produces the session plus the header fields the
 * recipient needs to derive the same secret.
 */
export function initiateSession(myIdPrivHex, bundle) {
  const ek = generateIdentityKeypair();
  const myIdPriv = hexToBytes(myIdPrivHex);
  const spkPub = hexToBytes(bundle.signedPreKey.pub);

  const dhs = [
    deriveSharedSecret(myIdPriv, spkPub),          // IK_a x SPK_b
    deriveSharedSecret(ek.privateKey, hexToBytes(bundle.idPub)), // EK_a x IK_b
    deriveSharedSecret(ek.privateKey, spkPub)      // EK_a x SPK_b
  ];
  if (bundle.oneTimePreKey) {
    dhs.push(deriveSharedSecret(ek.privateKey, hexToBytes(bundle.oneTimePreKey.pub)));
  }

  // Post-quantum half. Encapsulating to the peer's signed KEM prekey yields a
  // secret an adversary cannot recover from recorded traffic even with a
  // quantum computer, because it never travels as a Diffie-Hellman value.
  // The X25519 outputs above are still mixed in, so breaking ML-KEM alone
  // does not break the session either.
  let kemSecret = null;
  let kemCt = null;
  if (bundle.kemPreKey) {
    const enc = kemEncapsulate(hexToBytes(bundle.kemPreKey.pub));
    kemSecret = enc.sharedSecret;
    kemCt = bytesToHex(enc.cipherText);
  }

  const sk = deriveX3DHSecret(dhs, kemSecret);

  // The peer's signed prekey doubles as their initial ratchet public key.
  const ratchet = generateIdentityKeypair();

  // Replayed until the peer answers; without this a dropped first message
  // would leave them unable to derive the session at all. `hv` tells the
  // responder which protocol to build, and it travels in the clear alongside
  // the rest of the preamble because it has to be readable before any key
  // exists. A relay that strips it makes the session fail to open, which is a
  // denial of service and not a downgrade: the body is still v3 and a v2
  // responder cannot read it.
  const pending = {
    ek: bytesToHex(ek.publicKey),
    spk: bundle.signedPreKey.pub,
    opkId: bundle.oneTimePreKey ? bundle.oneTimePreKey.id : null,
    kemCt: kemCt || undefined,
    kemPub: bundle.kemPreKey ? bundle.kemPreKey.pub : undefined
  };

  if (!bundleSpeaksV3(bundle)) {
    const step = kdfRootKey(sk, deriveSharedSecret(ratchet.privateKey, spkPub));
    return {
      v: 2,
      pq: !!kemSecret,
      rootKey: bytesToHex(step.rootKey),
      ratchetPriv: bytesToHex(ratchet.privateKey),
      ratchetPub: bytesToHex(ratchet.publicKey),
      theirRatchetPub: bundle.signedPreKey.pub,
      sendingChainKey: bytesToHex(step.chainKey),
      receivingChainKey: null,
      Ns: 0, Nr: 0, PN: 0,
      skipped: {},
      pending
    };
  }

  // v3. Both sides derive the same opening pair of header keys from the X3DH
  // secret, because neither has ratcheted yet and the first encrypted header
  // has to be readable by the other side before any DH step has happened.
  const { hka, nhkb } = deriveInitialHeaderKeys(sk);
  const step = kdfRootKeyHE(sk, deriveSharedSecret(ratchet.privateKey, spkPub));

  return {
    v: 3,
    pq: !!kemSecret,
    rootKey: bytesToHex(step.rootKey),
    ratchetPriv: bytesToHex(ratchet.privateKey),
    ratchetPub: bytesToHex(ratchet.publicKey),
    theirRatchetPub: bundle.signedPreKey.pub,
    sendingChainKey: bytesToHex(step.chainKey),
    receivingChainKey: null,
    Ns: 0, Nr: 0, PN: 0,
    hks: bytesToHex(hka),
    hkr: null,
    nhks: bytesToHex(step.nextHeaderKey),
    nhkr: bytesToHex(nhkb),
    oldHkr: [],
    skipped: {},
    pending: { ...pending, hv: 3 }
  };
}

/**
 * Responder side of X3DH, driven by the header of an inbound first message.
 * `resolvePreKey` maps a prekey public (and optional one-time id) to the
 * matching private key held locally.
 */
export function acceptSession(myIdPrivHex, senderIdPub, header, resolvePreKey) {
  const spkPriv = resolvePreKey.signedPreKeyPriv(header.spk);
  if (!spkPriv) return null; // rotated away; cannot complete this handshake

  const myIdPriv = hexToBytes(myIdPrivHex);
  const ekPub = hexToBytes(header.ek);

  const dhs = [
    deriveSharedSecret(hexToBytes(spkPriv), hexToBytes(senderIdPub)),
    deriveSharedSecret(myIdPriv, ekPub),
    deriveSharedSecret(hexToBytes(spkPriv), ekPub)
  ];
  if (header.opkId != null) {
    const opkPriv = resolvePreKey.oneTimePreKeyPriv(header.opkId);
    if (!opkPriv) return null; // already consumed: a replay, or a duplicate
    dhs.push(deriveSharedSecret(hexToBytes(opkPriv), ekPub));
  }

  // Mirror of the initiator's KEM step. If the header carries a ciphertext we
  // must be able to decapsulate it: failing open would let anyone strip the
  // post-quantum half by simply omitting the field.
  let kemSecret = null;
  if (header.kemCt) {
    const kemPriv = resolvePreKey.kemPreKeyPriv
      ? resolvePreKey.kemPreKeyPriv(header.kemPub)
      : null;
    if (!kemPriv) return null;
    kemSecret = kemDecapsulate(hexToBytes(header.kemCt), hexToBytes(kemPriv));
    if (!kemSecret) return null;
  }

  const sk = deriveX3DHSecret(dhs, kemSecret);

  const base = {
    pq: !!kemSecret,
    rootKey: bytesToHex(sk),
    // Our signed prekey IS our initial ratchet keypair.
    ratchetPriv: spkPriv,
    ratchetPub: header.spk,
    theirRatchetPub: null,
    sendingChainKey: null,
    receivingChainKey: null,
    Ns: 0, Nr: 0, PN: 0,
    skipped: {},
    pending: null
  };

  if (header.hv !== 3) return { v: 2, ...base };

  // Mirror of the initiator's opening header keys, with the roles swapped:
  // what they will send under is what we will receive under. Both of ours
  // start null because nothing has been sent or received in this session yet;
  // the first inbound message trial-decrypts against `nhkr` and the DH step
  // that follows promotes both into place.
  const { hka, nhkb } = deriveInitialHeaderKeys(sk);
  return {
    v: 3,
    ...base,
    hks: null,
    hkr: null,
    nhks: bytesToHex(nhkb),
    nhkr: bytesToHex(hka),
    oldHkr: []
  };
}

/* ------------------------------------------------------------- encrypting */

/**
 * v3 envelope: `{ v: 3, eh, nonce, ciphertext }`, plus `hs` until the peer
 * replies. `eh` is the encrypted { dh, pn, n } that v2 sent in the clear.
 */
export function encryptWithSessionV3(session, payloadObj) {
  const { messageKey, nextChainKey } = kdfChainKey(hexToBytes(session.sendingChainKey));
  session.sendingChainKey = bytesToHex(nextChainKey);

  const header = { dh: session.ratchetPub, pn: session.PN, n: session.Ns };
  session.Ns++;

  const plaintext = padPlaintext(utf8Encode(JSON.stringify(payloadObj)));
  const { ciphertext, nonce } = encryptMessage(messageKey, plaintext);

  const out = {
    v: 3,
    eh: encryptHeader(hexToBytes(session.hks), header),
    nonce: bytesToHex(nonce),
    ciphertext: bytesToHex(ciphertext)
  };
  // The X3DH preamble, in the clear and outside the encrypted header, because
  // the recipient needs it to derive the key that opens that header.
  if (session.pending) out.hs = session.pending;
  return out;
}

export function encryptWithSession(session, payloadObj) {
  const { messageKey, nextChainKey } = kdfChainKey(hexToBytes(session.sendingChainKey));
  session.sendingChainKey = bytesToHex(nextChainKey);

  const header = { v: 2, dh: session.ratchetPub, pn: session.PN, n: session.Ns };
  if (session.pending) {
    header.ek = session.pending.ek;
    header.spk = session.pending.spk;
    header.opkId = session.pending.opkId;
    // Carried until the peer replies, same as the rest of the handshake, because
    // a dropped first message must not strand the session.
    if (session.pending.kemCt) {
      header.kemCt = session.pending.kemCt;
      header.kemPub = session.pending.kemPub;
    }
  }
  session.Ns++;

  const plaintext = padPlaintext(utf8Encode(JSON.stringify(payloadObj)));
  const { ciphertext, nonce } = encryptMessage(messageKey, plaintext);

  return {
    header,
    nonce: bytesToHex(nonce),
    ciphertext: bytesToHex(ciphertext)
  };
}

/* ------------------------------------------------------------- decrypting */

function skipKey(dhPub, n) { return `${dhPub}:${n}`; }

function pruneSkipped(session) {
  const store = session.skipped || {};
  const now = Date.now();
  for (const [k, e] of Object.entries(store)) {
    if (!e || typeof e.t !== 'number' || now - e.t > SKIP_TTL_MS) delete store[k];
  }
  const keys = Object.keys(store);
  if (keys.length > MAX_STORED_SKIPPED) {
    keys.sort((a, b) => store[a].t - store[b].t)
      .slice(0, keys.length - MAX_STORED_SKIPPED)
      .forEach((k) => delete store[k]);
  }
  session.skipped = store;
}

/** Ratchets the receiving chain forward, banking the keys we stepped over. */
function skipTo(session, until) {
  if (session.receivingChainKey == null) return true;
  if (until - session.Nr > MAX_SKIP) return false;

  const now = Date.now();
  let ck = hexToBytes(session.receivingChainKey);
  while (session.Nr < until) {
    const { messageKey, nextChainKey } = kdfChainKey(ck);
    session.skipped[skipKey(session.theirRatchetPub, session.Nr)] =
      { k: bytesToHex(messageKey), t: now };
    ck = nextChainKey;
    session.Nr++;
  }
  session.receivingChainKey = bytesToHex(ck);
  return true;
}

/** The DH step: a new ratchet public key from the peer heals the session. */
function dhRatchet(session, theirDh) {
  session.PN = session.Ns;
  session.Ns = 0;
  session.Nr = 0;
  session.theirRatchetPub = theirDh;

  const theirPub = hexToBytes(theirDh);

  let step = kdfRootKey(hexToBytes(session.rootKey),
    deriveSharedSecret(hexToBytes(session.ratchetPriv), theirPub));
  session.rootKey = bytesToHex(step.rootKey);
  session.receivingChainKey = bytesToHex(step.chainKey);

  const fresh = generateIdentityKeypair();
  session.ratchetPriv = bytesToHex(fresh.privateKey);
  session.ratchetPub = bytesToHex(fresh.publicKey);

  step = kdfRootKey(hexToBytes(session.rootKey),
    deriveSharedSecret(fresh.privateKey, theirPub));
  session.rootKey = bytesToHex(step.rootKey);
  session.sendingChainKey = bytesToHex(step.chainKey);

  // The peer has replied, so the X3DH preamble is no longer needed.
  session.pending = null;
}

export function decryptWithSession(session, header, nonceHex, ciphertextHex) {
  // A v3 session must never be driven by a cleartext header, whatever the
  // caller thinks it is doing. Without this the v2 path happily reads
  // `header.dh`, decides it has never seen that ratchet key, and turns the
  // root of a v3 session on an envelope it could not open: the session is then
  // desynchronised and every later message from the real peer fails. A relay
  // could trigger that by replaying any v2 envelope at a v3 client.
  //
  // messaging.js checks the same thing before calling, and that check is not
  // redundant with this one: it is what stops the session being replaced,
  // while this is what stops the session being damaged.
  if (!session || session.v === 3) return null;
  if (!header || header.v !== 2 || typeof header.dh !== 'string') return null;
  if (!Number.isSafeInteger(header.n) || header.n < 0) return null;
  if (!Number.isSafeInteger(header.pn) || header.pn < 0) return null;

  // A message from a chain we already ratcheted past.
  const banked = session.skipped[skipKey(header.dh, header.n)];
  if (banked) {
    const out = tryDecrypt(banked.k, ciphertextHex, nonceHex);
    if (out) delete session.skipped[skipKey(header.dh, header.n)];
    return out;
  }

  if (header.dh !== session.theirRatchetPub) {
    // New sending chain from the peer: bank the tail of the old one, then
    // perform the DH step.
    if (!skipTo(session, header.pn)) return null;
    dhRatchet(session, header.dh);
  }

  if (!skipTo(session, header.n)) return null;

  const { messageKey, nextChainKey } = kdfChainKey(hexToBytes(session.receivingChainKey));
  session.receivingChainKey = bytesToHex(nextChainKey);
  session.Nr++;

  pruneSkipped(session);
  return tryDecrypt(bytesToHex(messageKey), ciphertextHex, nonceHex);
}

/* ---------------------------------------------------------------- v3 ---- */

/**
 * Short stable label for a header key, used as the prefix of a skipped-key
 * entry. Hashed rather than stored raw so the skipped store does not become a
 * second copy of the header keys it is indexed by.
 */
function hkTag(hkHex) {
  return bytesToHex(sha256Hash(hexToBytes(hkHex))).slice(0, 32);
}

function skipKeyHE(hkHex, n) { return `${hkTag(hkHex)}:${n}`; }

/**
 * Which key opens this header, and whether reading it means a DH step.
 *
 * The candidate list is deliberately short and fixed: the current receiving
 * key, the one the next DH step will promote, then the bounded tail of retired
 * keys. See MAX_OLD_HEADER_KEYS for why this is not the specification's loop
 * over the whole skipped store.
 */
function openHeader(session, encHeaderHex) {
  if (session.hkr) {
    const h = decryptHeader(hexToBytes(session.hkr), encHeaderHex);
    if (h) return { header: h, hk: session.hkr, dhStep: false };
  }
  if (session.nhkr) {
    const h = decryptHeader(hexToBytes(session.nhkr), encHeaderHex);
    if (h) return { header: h, hk: session.nhkr, dhStep: true };
  }
  for (const old of session.oldHkr || []) {
    const h = decryptHeader(hexToBytes(old), encHeaderHex);
    if (h) return { header: h, hk: old, dhStep: false };
  }
  return null;
}

/** Retires the current receiving header key, dropping the oldest if full. */
function retireHeaderKey(session, hkHex) {
  if (!hkHex) return;
  const keep = [hkHex, ...(session.oldHkr || []).filter((k) => k !== hkHex)];
  const evicted = keep.slice(MAX_OLD_HEADER_KEYS);
  session.oldHkr = keep.slice(0, MAX_OLD_HEADER_KEYS);

  // A banked message key whose header key we no longer hold can never be
  // matched to a message again, because finding it means reading `n` out of a
  // header we cannot open. Dropping the two together keeps the store from
  // filling with entries that are unreachable by construction.
  for (const dead of evicted) {
    const prefix = `${hkTag(dead)}:`;
    for (const k of Object.keys(session.skipped)) {
      if (k.startsWith(prefix)) delete session.skipped[k];
    }
  }
}

/** Ratchets the receiving chain forward, banking keys under the current hkr. */
function skipToHE(session, until) {
  if (session.receivingChainKey == null) return true;
  if (until - session.Nr > MAX_SKIP) return false;

  const now = Date.now();
  let ck = hexToBytes(session.receivingChainKey);
  while (session.Nr < until) {
    const { messageKey, nextChainKey } = kdfChainKey(ck);
    session.skipped[skipKeyHE(session.hkr, session.Nr)] = { k: bytesToHex(messageKey), t: now };
    ck = nextChainKey;
    session.Nr++;
  }
  session.receivingChainKey = bytesToHex(ck);
  return true;
}

/** The DH step for v3: promotes both header keys as it turns the root. */
function dhRatchetHE(session, theirDh) {
  session.PN = session.Ns;
  session.Ns = 0;
  session.Nr = 0;
  session.theirRatchetPub = theirDh;

  // Promotion order matters. The key we have been receiving under becomes a
  // retired candidate, and the one the previous root step produced takes its
  // place. Skipping this is what a mutation test should catch: the session
  // still turns its root and still derives chain keys, so messages keep
  // flowing in the common case and only out-of-order delivery breaks.
  retireHeaderKey(session, session.hkr);
  session.hks = session.nhks;
  session.hkr = session.nhkr;

  const theirPub = hexToBytes(theirDh);

  let step = kdfRootKeyHE(hexToBytes(session.rootKey),
    deriveSharedSecret(hexToBytes(session.ratchetPriv), theirPub));
  session.rootKey = bytesToHex(step.rootKey);
  session.receivingChainKey = bytesToHex(step.chainKey);
  session.nhkr = bytesToHex(step.nextHeaderKey);

  const fresh = generateIdentityKeypair();
  session.ratchetPriv = bytesToHex(fresh.privateKey);
  session.ratchetPub = bytesToHex(fresh.publicKey);

  step = kdfRootKeyHE(hexToBytes(session.rootKey),
    deriveSharedSecret(fresh.privateKey, theirPub));
  session.rootKey = bytesToHex(step.rootKey);
  session.sendingChainKey = bytesToHex(step.chainKey);
  session.nhks = bytesToHex(step.nextHeaderKey);

  // The peer has replied, so the X3DH preamble is no longer needed.
  session.pending = null;
}

/**
 * Returns `{ payload, header }`, or null.
 *
 * The header comes back too because the caller uses `header.n` as the fallback
 * envelope index for messages that predate `_mid`, and in v3 there is no other
 * way for it to see that number.
 */
export function decryptWithSessionV3(session, encHeaderHex, nonceHex, ciphertextHex) {
  // The mirror of the guard in decryptWithSession. A v2 session holds no
  // header keys so this would fall out anyway today, but relying on that is
  // relying on a coincidence of the current shape rather than on a rule.
  if (!session || session.v !== 3) return null;

  const opened = openHeader(session, encHeaderHex);
  if (!opened) return null;
  const { header, hk, dhStep } = opened;

  if (!Number.isSafeInteger(header.n) || header.n < 0) return null;
  if (!Number.isSafeInteger(header.pn) || header.pn < 0) return null;
  if (typeof header.dh !== 'string') return null;

  // A message from a chain we already ratcheted past. Banked under the header
  // key that opened it, so this is a direct lookup rather than a search.
  const banked = session.skipped[skipKeyHE(hk, header.n)];
  if (banked) {
    const out = tryDecrypt(banked.k, ciphertextHex, nonceHex);
    if (out) delete session.skipped[skipKeyHE(hk, header.n)];
    return out ? { payload: out, header } : null;
  }

  if (dhStep) {
    // Bank the tail of the old receiving chain BEFORE the step, or those keys
    // are lost. Refusing an over-cap `pn` here must leave the session
    // untouched: no banked keys, no advance of Nr, no DH step.
    if (!skipToHE(session, header.pn)) return null;
    dhRatchetHE(session, header.dh);
  } else if (header.dh !== session.theirRatchetPub) {
    // The header opened under a key we already hold, so the peer is claiming a
    // new ratchet key without a new header key. Nothing legitimate produces
    // that combination.
    return null;
  }

  if (!skipToHE(session, header.n)) return null;

  const { messageKey, nextChainKey } = kdfChainKey(hexToBytes(session.receivingChainKey));
  session.receivingChainKey = bytesToHex(nextChainKey);
  session.Nr++;

  pruneSkipped(session);
  const out = tryDecrypt(bytesToHex(messageKey), ciphertextHex, nonceHex);
  return out ? { payload: out, header } : null;
}

function tryDecrypt(keyHex, ciphertextHex, nonceHex) {
  try {
    const plain = decryptMessage(hexToBytes(keyHex), hexToBytes(ciphertextHex), hexToBytes(nonceHex));
    const str = utf8Decode(unpadPlaintext(plain));
    try {
      return JSON.parse(str);
    } catch {
      return { type: 'text', text: str };
    }
  } catch {
    return null;
  }
}
