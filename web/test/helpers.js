// Shared fixtures for the protocol tests.
//
// These build a real prekey bundle the same way the app does, rather than
// hand-rolling one, so a change to the bundle shape breaks the tests instead of
// quietly making them test nothing.

import {
  generateIdentityKeypair, signingKeypairFromSeed, signBytes,
  bytesToHex, hexToBytes, sha256Hash, utf8Encode, kemKeygen
} from '../src/crypto-bundle.js';
import { buildSignedPreKeyMessage, buildKemPreKeyMessage } from '../src/ratchet.js';

/**
 * The Ed25519 prekey-signing key is derived from the identity private key
 * (SHA256("TalonSigningKey:" || idPriv)) so every device holding the account
 * agrees on it. Mirrored here from messaging.js.
 */
export function signingKeyFor(idPrivHex) {
  const seed = sha256Hash(utf8Encode('TalonSigningKey:' + idPrivHex));
  return signingKeypairFromSeed(seed);
}

/**
 * Builds a party: identity keypair, signing keypair, a signed prekey, an
 * optional one-time prekey and an optional ML-KEM prekey, plus the resolver
 * acceptSession() needs to find the matching private keys.
 *
 * @param {object} opts
 * @param {boolean} opts.pq       include a signed ML-KEM prekey
 * @param {boolean} opts.oneTime  include a one-time prekey
 */
export function makeParty({ pq = true, oneTime = true } = {}) {
  const id = generateIdentityKeypair();
  const idPrivHex = bytesToHex(id.privateKey);
  const idPubHex = bytesToHex(id.publicKey);
  const sign = signingKeyFor(idPrivHex);

  const spk = generateIdentityKeypair();
  const spkPubHex = bytesToHex(spk.publicKey);
  const spkPrivHex = bytesToHex(spk.privateKey);

  const bundle = {
    idPub: idPubHex,
    signPub: bytesToHex(sign.publicKey),
    signedPreKey: {
      pub: spkPubHex,
      sig: bytesToHex(signBytes(sign.privateKey, buildSignedPreKeyMessage(spkPubHex)))
    }
  };

  let opk = null;
  if (oneTime) {
    opk = generateIdentityKeypair();
    bundle.oneTimePreKey = { id: 'opk-1', pub: bytesToHex(opk.publicKey) };
  }

  let kem = null;
  if (pq) {
    kem = kemKeygen();
    const kemPubHex = bytesToHex(kem.publicKey);
    bundle.kemPreKey = {
      pub: kemPubHex,
      sig: bytesToHex(signBytes(sign.privateKey, buildKemPreKeyMessage(kemPubHex)))
    };
  }

  // What the responder uses to look its own private keys back up.
  const resolver = {
    signedPreKeyPriv: (pub) => (pub === spkPubHex ? spkPrivHex : null),
    oneTimePreKeyPriv: (id) => (opk && id === 'opk-1' ? bytesToHex(opk.privateKey) : null),
    kemPreKeyPriv: (pub) => (kem && pub === bytesToHex(kem.publicKey)
      ? bytesToHex(kem.secretKey) : null)
  };

  return { idPrivHex, idPubHex, bundle, resolver, spkPubHex };
}

/** Flips one hex nibble so a signature or key is wrong but still well-formed. */
export function corruptHex(hex) {
  const i = Math.floor(hex.length / 2);
  const c = hex[i] === '0' ? '1' : '0';
  return hex.slice(0, i) + c + hex.slice(i + 1);
}

/** Deterministic shuffle, so a failing ordering is reproducible from the seed. */
export function shuffle(arr, seed = 12345) {
  const out = arr.slice();
  let s = seed;
  const rand = () => {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    return s / 0x7fffffff;
  };
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

export { hexToBytes, bytesToHex };
