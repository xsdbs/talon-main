// --- PROTOCOL v2: X3DH + DOUBLE RATCHET ---
//
// A v2 session object looks like:
//
//   {
//     v: 2,
//     rootKey,                 hex
//     ratchetPriv, ratchetPub, hex   our current ratchet keypair
//     theirRatchetPub,         hex | null
//     sendingChainKey,         hex | null
//     receivingChainKey,       hex | null
//     Ns, Nr,                  message counters in the current chains
//     PN,                      length of the previous sending chain
//     skipped: { "<theirDhPub>:<n>": { k, t } },
//     pending                  X3DH header replayed on every message until
//                              the peer replies, so a lost first message
//                              cannot strand the session
//   }
//
// Every envelope carries a plaintext header { v, dh, pn, n } plus, until the
// handshake completes, the X3DH fields. The header is necessarily visible to
// the relay. It is ephemeral public keys and counters, no identity.

import {
  generateIdentityKeypair, deriveSharedSecret, bytesToHex, hexToBytes,
  utf8Encode, utf8Decode, encryptMessage, decryptMessage,
  deriveX3DHSecret, kdfRootKey, kdfChainKey,
  verifySignature, padPlaintext, unpadPlaintext,
  kemEncapsulate, kemDecapsulate
} from './crypto-bundle.js';

// Same rationale as the v1 bounds in messaging.js: `n` and `pn` are
// attacker-controlled plaintext, so every loop driven by them must be capped.
export const MAX_SKIP = 1000;
const MAX_STORED_SKIPPED = 2000;
const SKIP_TTL_MS = 7 * 24 * 60 * 60 * 1000;

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
  return true;
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
  const step = kdfRootKey(sk, deriveSharedSecret(ratchet.privateKey, spkPub));

  const session = {
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
    // Replayed until the peer answers; without this a dropped first message
    // would leave them unable to derive the session at all.
    pending: {
      ek: bytesToHex(ek.publicKey),
      spk: bundle.signedPreKey.pub,
      opkId: bundle.oneTimePreKey ? bundle.oneTimePreKey.id : null,
      kemCt: kemCt || undefined,
      kemPub: bundle.kemPreKey ? bundle.kemPreKey.pub : undefined
    }
  };
  return session;
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

  return {
    v: 2,
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
}

/* ------------------------------------------------------------- encrypting */

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
