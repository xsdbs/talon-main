import { x25519, ed25519 } from '@noble/curves/ed25519.js';
import { gcm } from '@noble/ciphers/aes.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

// --- HEX UTILITIES ---

export function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0) {
    throw new Error('Invalid hex string');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// --- UTF-8 UTILITIES ---

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function utf8Encode(str) {
  return encoder.encode(str);
}

export function utf8Decode(bytes) {
  return decoder.decode(bytes);
}

// --- KEY GENERATION & DH ---

export function generateIdentityKeypair() {
  const privateKey = x25519.utils.randomSecretKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

export function deriveSharedSecret(privateKey, publicKey) {
  return x25519.getSharedSecret(privateKey, publicKey);
}

export function generateEphemeralKeypair() {
  const privateKey = x25519.utils.randomSecretKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

// --- HANDSHAKE KDF ---

export function deriveInitialSessionKeys(dh1, dh2, role) {
  // Combine both Diffie-Hellman secrets
  const ikm = new Uint8Array(dh1.length + dh2.length);
  ikm.set(dh1, 0);
  ikm.set(dh2, dh1.length);

  const salt = new Uint8Array(0);
  const info = encoder.encode("TailscaleChatHandshake");

  // Derive 64 bytes of key material
  const keyMaterial = hkdf(sha256, ikm, salt, info, 64);
  const part1 = keyMaterial.slice(0, 32);
  const part2 = keyMaterial.slice(32, 64);

  // Role separation to prevent key reuse in both directions
  if (role === 'sender') {
    return {
      sendingChainKey: part1,
      receivingChainKey: part2
    };
  } else {
    return {
      sendingChainKey: part2,
      receivingChainKey: part1
    };
  }
}

// --- SYMMETRIC RATCHET KDF (v1) ---
// Load-bearing for protocol v1. The labels and their order are part of the
// wire format; changing either silently breaks every v1 session.

export function ratchetChainKey(chainKey, label) {
  const message = encoder.encode(label);
  return hmac(sha256, chainKey, message);
}

// ===========================================================================
// PROTOCOL v2: X3DH + Double Ratchet
// ===========================================================================
//
// v1's weaknesses, both fixed here:
//
//   * The handshake mixed DH(IK_a,IK_b) and DH(EK_a,IK_b). Both are
//     recoverable from IK_b's private key, so anyone who ever obtained an
//     identity key could decrypt every recorded session it established. v2
//     mixes in a signed prekey and a single-use one-time prekey, and the
//     one-time key is deleted after use, so the transcript stays sealed.
//
//   * The ratchet was symmetric only, so a leaked chain key compromised the
//     rest of the conversation forever. v2 performs a DH step on every change
//     of direction, so one round trip after a compromise the session heals.
//
// Identity keys are unchanged: idPub is still the X25519 key, so existing
// Client IDs and contact lists keep working. A separate Ed25519 key is added
// purely to sign prekeys (X25519 cannot sign, and this build of @noble/curves
// does not expose the Montgomery/Edwards conversion that would let one key do
// both). Both keys are folded into the safety number.

const X3DH_INFO = encoder.encode('TalonX3DHv2');
// Distinct info string for the hybrid handshake, because a classical and a
// post-quantum session must never derive the same key.
const X3DH_PQ_INFO = encoder.encode('TalonPQXDHv3');
const ROOT_INFO = encoder.encode('TalonRatchetv2');

export function generateSigningKeypair() {
  const privateKey = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/** Ed25519 keypair from a fixed 32-byte seed (the key IS the seed). */
export function signingKeypairFromSeed(seed) {
  return { privateKey: seed, publicKey: ed25519.getPublicKey(seed) };
}

export function signBytes(privateKey, messageBytes) {
  return ed25519.sign(messageBytes, privateKey);
}

export function verifySignature(publicKey, signature, messageBytes) {
  try {
    return ed25519.verify(signature, messageBytes, publicKey);
  } catch {
    return false;
  }
}

/**
 * X3DH: concatenate the DH outputs in a fixed order and derive the shared
 * secret. The leading 0xFF block is the standard domain separator that stops
 * the result colliding with a raw DH output.
 *
 * `kemSecret` is the optional ML-KEM shared secret (see the KEM section
 * below). When present it is appended as the final input and the info string
 * changes, so a classical and a hybrid handshake can never derive the same
 * key even from identical DH values. That is what stops an attacker who
 * strips the KEM material from silently landing on a working session.
 */
export function deriveX3DHSecret(dhOutputs, kemSecret = null) {
  let total = 32 + (kemSecret ? kemSecret.length : 0);
  for (const d of dhOutputs) total += d.length;
  const ikm = new Uint8Array(total);
  ikm.fill(0xff, 0, 32);
  let off = 32;
  for (const d of dhOutputs) { ikm.set(d, off); off += d.length; }
  if (kemSecret) ikm.set(kemSecret, off);
  return hkdf(sha256, ikm, new Uint8Array(0), kemSecret ? X3DH_PQ_INFO : X3DH_INFO, 32);
}

/* ----------------------------------------------------- post-quantum KEM ---
 * ML-KEM-768 (FIPS 203), used as the post-quantum half of a hybrid
 * handshake. It is mixed *alongside* X25519, never instead of it: if ML-KEM
 * turns out to be broken the session is no weaker than the classical one it
 * replaced, and vice versa. This is the same construction as Signal's PQXDH.
 *
 * Sizes: public key 1184 B, ciphertext 1088 B, shared secret 32 B.
 */
export function kemKeygen() {
  const { publicKey, secretKey } = ml_kem768.keygen();
  return { publicKey, secretKey };
}

/** Initiator side: wrap a fresh secret to the peer's KEM public key. */
export function kemEncapsulate(publicKey) {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
  return { cipherText, sharedSecret };
}

/** Responder side. Returns null rather than throwing on a malformed input. */
export function kemDecapsulate(cipherText, secretKey) {
  try {
    return ml_kem768.decapsulate(cipherText, secretKey);
  } catch {
    return null;
  }
}

/* --------------------------------------------------------- sealed sender ---
 * An anonymous outer envelope addressed to the recipient's identity key. The
 * sender's ID travels *inside* it, so nothing the relay persists (the offline
 * queue, the logs, the push payload) records who sent what.
 *
 * What this does NOT do: hide the sender from a live, malicious relay. The
 * WebSocket is authenticated per identity, so the running process always knows
 * which socket a frame arrived on. Closing that would need an unauthenticated
 * send path, which is a worse trade. See the README, "What the relay can
 * and cannot see".
 *
 * A real gain beyond metadata: the sender ID is now inside an AEAD the relay
 * cannot forge. Previously the client trusted a server-asserted `senderId`.
 */
const SEAL_INFO = encoder.encode('TalonSealedSenderv1');

export function sealSender(recipientIdPubHex, innerObj) {
  const eph = generateEphemeralKeypair();
  const recipientPub = hexToBytes(recipientIdPubHex);
  const shared = x25519.getSharedSecret(eph.privateKey, recipientPub);

  // Bind the key to this exact ephemeral/recipient pair so a sealed blob can
  // never be replayed at a different recipient.
  const salt = new Uint8Array(eph.publicKey.length + recipientPub.length);
  salt.set(eph.publicKey, 0);
  salt.set(recipientPub, eph.publicKey.length);

  const key = hkdf(sha256, shared, salt, SEAL_INFO, 32);
  const { ciphertext, nonce } = encryptMessage(key, utf8Encode(JSON.stringify(innerObj)));
  // Hex, because this travels as JSON over the WebSocket.
  return { epk: bytesToHex(eph.publicKey), nonce: bytesToHex(nonce), ct: bytesToHex(ciphertext) };
}

export function unsealSender(myIdPrivHex, sealed) {
  try {
    if (!sealed || !sealed.epk || !sealed.nonce || !sealed.ct) return null;
    const myPriv = hexToBytes(myIdPrivHex);
    const epk = hexToBytes(sealed.epk);
    const myPub = x25519.getPublicKey(myPriv);
    const shared = x25519.getSharedSecret(myPriv, epk);

    const salt = new Uint8Array(epk.length + myPub.length);
    salt.set(epk, 0);
    salt.set(myPub, epk.length);

    const key = hkdf(sha256, shared, salt, SEAL_INFO, 32);
    // Argument order is (key, ciphertext, nonce); AES-GCM throws on a bad tag,
    // which the surrounding catch turns into a null.
    const plain = decryptMessage(key, hexToBytes(sealed.ct), hexToBytes(sealed.nonce));
    if (!plain) return null;
    return JSON.parse(utf8Decode(plain));
  } catch {
    return null;
  }
}

/** Root-key ratchet: folds a fresh DH output into the root key. */
export function kdfRootKey(rootKey, dhOutput) {
  const out = hkdf(sha256, dhOutput, rootKey, ROOT_INFO, 64);
  return { rootKey: out.slice(0, 32), chainKey: out.slice(32, 64) };
}

/** Symmetric chain step. Distinct constants keep the two outputs independent. */
export function kdfChainKey(chainKey) {
  return {
    messageKey: hmac(sha256, chainKey, Uint8Array.of(0x01)),
    nextChainKey: hmac(sha256, chainKey, Uint8Array.of(0x02))
  };
}

// --- LENGTH PADDING ---
//
// Ciphertext length leaks plaintext length, which for chat traffic is a
// meaningful side channel ("ok" vs a paragraph). Plaintext is padded to a
// 256-byte bucket before encryption. A single 0x80 marks the start of the
// padding, the rest is zeroes. This is unambiguous because the payload is always
// JSON, which never ends in a NUL.
const PAD_BUCKET = 256;

export function padPlaintext(bytes) {
  const target = Math.ceil((bytes.length + 1) / PAD_BUCKET) * PAD_BUCKET;
  const out = new Uint8Array(target);
  out.set(bytes, 0);
  out[bytes.length] = 0x80;
  return out;
}

export function unpadPlaintext(bytes) {
  let i = bytes.length - 1;
  while (i >= 0 && bytes[i] === 0x00) i--;
  if (i < 0 || bytes[i] !== 0x80) return bytes; // not padded (v1 message)
  return bytes.slice(0, i);
}

// --- AUTHENTICATED ENCRYPTION (AES-GCM) ---

export function encryptMessage(key, plaintextBytes) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const cipher = gcm(key, nonce);
  const ciphertext = cipher.encrypt(plaintextBytes);
  return { ciphertext, nonce };
}

export function decryptMessage(key, ciphertextBytes, nonceBytes) {
  const decipher = gcm(key, nonceBytes);
  return decipher.decrypt(ciphertextBytes);
}

// --- ZERO-KNOWLEDGE AUTH & LOCAL PASSWORD CRYPTO ---

// --- PASSWORD KEY DERIVATION ---
//
// v1 (legacy): pure-JS PBKDF2-SHA256, 10 000 iterations, salt = the username.
//   Far below the OWASP floor of 600 000, and a username is not a real salt:
//   it is guessable and shared across every server.
//
// v2: the SAME primitive but run through WebCrypto and at 600 000 iterations,
//   with a random 16-byte per-user salt.
//
// Why not Argon2id, which is memory-hard and nominally stronger? Measured on
// this machine: @noble's pure-JS Argon2id at the OWASP profile (19 MiB, t=2)
// takes ~930 ms unthrottled, and pure JS scales directly with CPU throttling,
// so a mid-range phone lands in the multi-second range. WebCrypto PBKDF2 is
// native, so 600 000 iterations costs ~900 ms even at 6x CPU throttling, or
// 60x the work of v1 for 15x the wall clock. An attacker cracking offline
// would use a native implementation regardless, so choosing the primitive the
// browser accelerates keeps the defender on equal footing instead of paying a
// pure-JS penalty the attacker never pays.
//
// Revisit if WebCrypto ever exposes Argon2 natively.

export const KDF_V1 = { v: 1, iterations: 10000 };
export const KDF_V2 = { v: 2, iterations: 600000 };

/** Legacy derivation. Kept only so existing accounts can be migrated on login. */
export function deriveMasterKeyV1(password, username) {
  const pwdBytes = encoder.encode(password);
  // Lowercase the username to ensure case-insensitivity matches
  const saltBytes = encoder.encode(username.toLowerCase());
  return pbkdf2(sha256, pwdBytes, saltBytes, { c: 10000, dkLen: 64 });
}

/** Current derivation: native PBKDF2-SHA256, 600k iterations, random salt. */
export async function deriveMasterKeyV2(password, saltHex, iterations = KDF_V2.iterations) {
  const baseKey = await crypto.subtle.importKey(
    'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: hexToBytes(saltHex), iterations },
    baseKey,
    512
  );
  return new Uint8Array(bits);
}

/**
 * Derives the 64-byte master key for whichever KDF version this account uses.
 * @param {object} params `{ v, salt, iterations }` as returned by /api/kdf-params
 */
export async function deriveMasterKey(password, username, params) {
  if (!params || params.v === 1) return deriveMasterKeyV1(password, username);
  return deriveMasterKeyV2(password, params.salt, params.iterations || KDF_V2.iterations);
}

/**
 * Encrypt bytes using a derived key with AES-GCM (returns hex ciphertext & nonce)
 */
export function encryptWithKey(key, dataBytes) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const cipher = gcm(key, nonce);
  const ciphertext = cipher.encrypt(dataBytes);
  return {
    ciphertext: bytesToHex(ciphertext),
    nonce: bytesToHex(nonce)
  };
}

/**
 * Decrypt hex ciphertext using a derived key and hex nonce with AES-GCM
 */
export function decryptWithKey(key, ciphertextHex, nonceHex) {
  const ctBytes = hexToBytes(ciphertextHex);
  const nBytes = hexToBytes(nonceHex);
  const decipher = gcm(key, nBytes);
  return decipher.decrypt(ctBytes);
}

/**
 * Simple SHA256 helper for password hashes
 */
export function sha256Hash(dataBytes) {
  return sha256(dataBytes);
}
