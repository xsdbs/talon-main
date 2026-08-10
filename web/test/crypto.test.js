// Primitives: padding, AEAD, sealed sender, and the KDF split.
//
// Padding gets the most attention here because it is the one place where an
// off-by-one is invisible in normal use and leaks message length in the wild.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  padPlaintext, unpadPlaintext, utf8Encode, utf8Decode,
  encryptMessage, decryptMessage, bytesToHex, hexToBytes,
  generateIdentityKeypair, sealSender, unsealSender,
  deriveMasterKeyV2, KDF_V2, sha256Hash, deriveX3DHSecret
} from '../src/crypto-bundle.js';
import { corruptHex } from './helpers.js';

const PAD_BUCKET = 256;

describe('length padding', () => {
  test('pads to a whole number of 256-byte buckets', () => {
    for (const len of [0, 1, 100, 254, 255, 256, 257, 511, 512, 513, 1000]) {
      const out = padPlaintext(new Uint8Array(len));
      assert.equal(out.length % PAD_BUCKET, 0,
        `length ${len} padded to ${out.length}, not a bucket multiple`);
      assert.ok(out.length > len, `length ${len} must gain at least the 0x80 marker`);
    }
  });

  test('the boundary cases land in the bucket they should', () => {
    // 255 bytes + 1 marker == 256 exactly, so it must NOT spill into a second
    // bucket; 256 must. This is the off-by-one that would leak whether a
    // message is just under or just over the line.
    assert.equal(padPlaintext(new Uint8Array(254)).length, 256);
    assert.equal(padPlaintext(new Uint8Array(255)).length, 256);
    assert.equal(padPlaintext(new Uint8Array(256)).length, 512);
    assert.equal(padPlaintext(new Uint8Array(257)).length, 512);
  });

  test('round-trips every length exactly', () => {
    for (let len = 0; len <= 600; len++) {
      const original = new Uint8Array(len);
      for (let i = 0; i < len; i++) original[i] = (i * 7 + 3) & 0xff;
      const back = unpadPlaintext(padPlaintext(original));
      assert.deepEqual(back, original, `length ${len} did not survive the round trip`);
    }
  });

  test('round-trips content that ends in the marker byte or zeroes', () => {
    // Unpadding scans back over 0x00 to find 0x80. Payloads that themselves
    // end in 0x80 or 0x00 are exactly where a naive scan goes wrong.
    for (const tail of [[0x80], [0x00], [0x80, 0x00], [0x00, 0x00, 0x00], [0x80, 0x80]]) {
      const original = new Uint8Array([1, 2, 3, ...tail]);
      assert.deepEqual(unpadPlaintext(padPlaintext(original)), original,
        `tail ${JSON.stringify(tail)} did not survive`);
    }
  });

  test('lengths within a bucket are indistinguishable after padding', () => {
    // The whole point: an observer must not be able to tell a 10-byte message
    // from a 200-byte one.
    const sizes = new Set();
    for (let len = 0; len < 255; len++) sizes.add(padPlaintext(new Uint8Array(len)).length);
    assert.equal(sizes.size, 1, 'every sub-bucket length must produce one size');
  });

  test('leaves an unpadded v1 payload alone', () => {
    const v1 = utf8Encode('legacy message with no marker');
    assert.deepEqual(unpadPlaintext(v1), v1);
  });
});

describe('authenticated encryption', () => {
  test('round-trips', () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const msg = utf8Encode('the quick brown fox');
    const { ciphertext, nonce } = encryptMessage(key, msg);
    assert.deepEqual(decryptMessage(key, ciphertext, nonce), msg);
  });

  test('uses a fresh nonce every time', () => {
    // Nonce reuse under AES-GCM is catastrophic, not cosmetic.
    const key = crypto.getRandomValues(new Uint8Array(32));
    const seen = new Set();
    for (let i = 0; i < 200; i++) {
      seen.add(bytesToHex(encryptMessage(key, utf8Encode('same plaintext')).nonce));
    }
    assert.equal(seen.size, 200, 'a nonce was repeated');
  });

  test('the same plaintext never produces the same ciphertext', () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const a = bytesToHex(encryptMessage(key, utf8Encode('x')).ciphertext);
    const b = bytesToHex(encryptMessage(key, utf8Encode('x')).ciphertext);
    assert.notEqual(a, b);
  });

  test('rejects a tampered ciphertext', () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const { ciphertext, nonce } = encryptMessage(key, utf8Encode('authentic'));
    const bad = hexToBytes(corruptHex(bytesToHex(ciphertext)));
    assert.throws(() => decryptMessage(key, bad, nonce));
  });

  test('rejects the wrong key', () => {
    const { ciphertext, nonce } = encryptMessage(
      crypto.getRandomValues(new Uint8Array(32)), utf8Encode('secret'));
    assert.throws(() =>
      decryptMessage(crypto.getRandomValues(new Uint8Array(32)), ciphertext, nonce));
  });
});

describe('sealed sender', () => {
  test('round-trips to the intended recipient', () => {
    const recipient = generateIdentityKeypair();
    const inner = { senderId: 'a'.repeat(64), payload: { type: 'text', text: 'hi' } };

    const sealed = sealSender(bytesToHex(recipient.publicKey), inner);
    assert.deepEqual(
      unsealSender(bytesToHex(recipient.privateKey), sealed),
      inner
    );
  });

  test('the sender id does not appear in the sealed output', () => {
    // The entire purpose. If the id leaks into the envelope, the relay's
    // offline queue and access log record it after all.
    const recipient = generateIdentityKeypair();
    const senderId = 'ab'.repeat(32);
    const sealed = sealSender(bytesToHex(recipient.publicKey), { senderId });
    assert.equal(JSON.stringify(sealed).includes(senderId), false);
  });

  test('a third party cannot open it', () => {
    const recipient = generateIdentityKeypair();
    const stranger = generateIdentityKeypair();
    const sealed = sealSender(bytesToHex(recipient.publicKey), { senderId: 'x' });
    assert.equal(unsealSender(bytesToHex(stranger.privateKey), sealed), null);
  });
});

describe('key derivation', () => {
  // deriveMasterKeyV2 returns 64 raw bytes; callers in app.js split them at 32
  // into authKey and encryptionKey. The split is asserted here against those
  // same offsets, so moving one without the other breaks the test.
  const AUTH = (mk) => mk.slice(0, 32);
  const ENC = (mk) => mk.slice(32, 64);

  test('produces 64 bytes that split into two distinct halves', async () => {
    const saltHex = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
    // Deliberately low iterations: this asserts the split, not the work factor.
    const mk = await deriveMasterKeyV2('correct horse battery staple', saltHex, 1000);
    assert.equal(mk.length, 64, 'the master key must be 64 bytes');
    assert.equal(AUTH(mk).length, 32);
    assert.equal(ENC(mk).length, 32);
    assert.notDeepEqual(AUTH(mk), ENC(mk),
      'the auth and encryption halves must never be the same bytes');
  });

  test('is deterministic for the same password and salt', async () => {
    const saltHex = 'ab'.repeat(16);
    const a = await deriveMasterKeyV2('pw', saltHex, 1000);
    const b = await deriveMasterKeyV2('pw', saltHex, 1000);
    assert.deepEqual(a, b);
  });

  test('a different salt gives a different key for the same password', async () => {
    const a = await deriveMasterKeyV2('pw', 'ab'.repeat(16), 1000);
    const b = await deriveMasterKeyV2('pw', 'cd'.repeat(16), 1000);
    assert.notDeepEqual(AUTH(a), AUTH(b));
  });

  test('a different password gives a different key for the same salt', async () => {
    const salt = 'ab'.repeat(16);
    const a = await deriveMasterKeyV2('password one', salt, 1000);
    const b = await deriveMasterKeyV2('password two', salt, 1000);
    assert.notDeepEqual(AUTH(a), AUTH(b));
  });

  test('the shipped iteration count has not been quietly lowered', () => {
    assert.equal(KDF_V2.iterations, 600000);
  });

  test('mixing a KEM secret changes the X3DH output', () => {
    // If it did not, the post-quantum half would be decorative.
    const dhs = [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)];
    const classical = deriveX3DHSecret(dhs, null);
    const hybrid = deriveX3DHSecret(dhs, new Uint8Array(32).fill(3));
    assert.notDeepEqual(classical, hybrid);
  });

  test('the hybrid and classical paths use different domain separation', () => {
    // A hybrid handshake and a classical one must never land on the same key,
    // even if the KEM secret were all zeroes.
    const dhs = [new Uint8Array(32).fill(1)];
    assert.notDeepEqual(
      deriveX3DHSecret(dhs, null),
      deriveX3DHSecret(dhs, new Uint8Array(32))
    );
  });
});
