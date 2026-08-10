// --- CRYPTO HELPERS BUILT ON THE PRIMITIVES ---
// Kept out of crypto-bundle.js so that file stays "primitives only".

import { sha256Hash, utf8Encode, bytesToHex, hexToBytes } from './crypto-bundle.js';
import { State } from './store.js';

/**
 * Credentials for the attachment endpoints.
 *
 * Headers, not query parameters: the relay access-logs every request URL, so a
 * credential in the query string would be written to a plaintext log file.
 * These endpoints used to take no credential at all, which made the upload
 * route a disk-fill primitive for anyone who could reach the port.
 */
function attachmentAuthHeaders() {
  const u = State.currentUser;
  if (!u) throw new Error('Not signed in');
  return { 'X-Talon-User': u.username, 'X-Talon-Auth': u.authHash };
}

/**
 * A 60-digit safety number for a pair of identity keys.
 *
 * Both sides sort the two public keys before hashing, so the two devices
 * independently derive the same value. Compare the digits out-of-band (in
 * person, over a call you already trust) to rule out a relay that swapped
 * keys mid-handshake. Display only: nothing keys off this value.
 */
export function safetyNumber(idA, idB) {
  const pair = [String(idA), String(idB)].sort().join('');
  const digest = sha256Hash(utf8Encode(pair));
  const groups = [];
  for (let g = 0; g < 12; g++) {
    let v = 0;
    for (let k = 0; k < 3; k++) v = (v * 256 + digest[(g * 3 + k) % digest.length]) >>> 0;
    groups.push(String(v % 100000).padStart(5, '0'));
  }
  return groups;
}

/** Salted verifier for the app-lock PIN. The PIN itself is never stored. */
export function hashPin(pin, saltHex) {
  return bytesToHex(sha256Hash(utf8Encode(`${saltHex}:${pin}`)));
}

export function randomHex(bytes = 16) {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(bytes)));
}

/* ---------------------------------------------------- attachment crypto */

/** Encrypts a Blob/File with a fresh AES-GCM key and uploads the ciphertext. */
export async function encryptAndUpload(blob) {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const rawKey = await crypto.subtle.exportKey('raw', key);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const plain = await blob.arrayBuffer();
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain);

  const res = await fetch('/api/upload', {
    method: 'POST',
    headers: attachmentAuthHeaders(),
    body: new Blob([new Uint8Array(ct)], { type: 'application/octet-stream' })
  });
  if (res.status === 413) throw new Error('File is too large for this relay');
  if (res.status === 401) throw new Error('Not authorised to upload');
  const result = await res.json();
  if (!result.success) throw new Error('Upload rejected');

  return {
    url: `/api/download/${result.id}`,
    key: bytesToHex(new Uint8Array(rawKey)),
    iv: bytesToHex(iv)
  };
}

/**
 * Fetches ciphertext and returns the decrypted bytes.
 *
 * `revalidate` bypasses the HTTP cache. Downloads are served with a one-year
 * max-age, so a repeat fetch normally never reaches the relay. That matters
 * because the relay expires blobs by time since last read. Anything that must
 * stay alive indefinitely, i.e. an avatar, has to actually touch the server
 * now and then rather than being answered from disk cache forever.
 */
export async function fetchAndDecrypt(url, keyHex, ivHex, { revalidate = false } = {}) {
  const res = await fetch(url, {
    headers: attachmentAuthHeaders(),
    ...(revalidate ? { cache: 'reload' } : {})
  });
  if (!res.ok) throw new Error('Attachment missing');
  const ct = await (await res.blob()).arrayBuffer();
  const key = await crypto.subtle.importKey('raw', hexToBytes(keyHex), { name: 'AES-GCM' }, false, ['decrypt']);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: hexToBytes(ivHex) }, key, ct);
}
