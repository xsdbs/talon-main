// Double Ratchet and X3DH behaviour.
//
// These exist because the protocol's safety properties are all invisible at
// runtime: a session that silently derives the wrong key, or accepts a prekey
// the relay substituted, looks exactly like a session that works until it
// matters. Every test here asserts something that would otherwise only be
// caught by a person reading the code very carefully.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  verifyBundle, initiateSession, acceptSession,
  encryptWithSession, decryptWithSession, MAX_SKIP
} from '../src/ratchet.js';
import { makeParty, corruptHex, shuffle } from './helpers.js';

/** Drives a full handshake and returns both live sessions. */
function handshake(opts = {}) {
  const alice = makeParty(opts);
  const bob = makeParty(opts);

  const aSession = initiateSession(alice.idPrivHex, bob.bundle);
  const first = encryptWithSession(aSession, { type: 'text', text: 'hello' });

  const bSession = acceptSession(bob.idPrivHex, alice.idPubHex, first.header, bob.resolver);
  assert.ok(bSession, 'responder should accept a well-formed first message');

  const out = decryptWithSession(bSession, first.header, first.nonce, first.ciphertext);
  assert.deepEqual(out, { type: 'text', text: 'hello' });

  return { alice, bob, aSession, bSession };
}

describe('bundle verification', () => {
  test('accepts a correctly signed bundle', () => {
    assert.equal(verifyBundle(makeParty().bundle), true);
  });

  test('refuses a tampered signed-prekey signature', () => {
    // This is the single check standing between the user and a relay that
    // substitutes its own prekeys. If it ever returns true, the whole
    // handshake is meaningless.
    const { bundle } = makeParty();
    bundle.signedPreKey.sig = corruptHex(bundle.signedPreKey.sig);
    assert.equal(verifyBundle(bundle), false);
  });

  test('refuses a substituted signed-prekey public key', () => {
    const { bundle } = makeParty();
    const other = makeParty();
    bundle.signedPreKey.pub = other.bundle.signedPreKey.pub;
    assert.equal(verifyBundle(bundle), false);
  });

  test('refuses a tampered KEM prekey signature', () => {
    const { bundle } = makeParty({ pq: true });
    bundle.kemPreKey.sig = corruptHex(bundle.kemPreKey.sig);
    assert.equal(verifyBundle(bundle), false);
  });

  test('refuses a KEM prekey with no signature at all', () => {
    const { bundle } = makeParty({ pq: true });
    delete bundle.kemPreKey.sig;
    assert.equal(verifyBundle(bundle), false);
  });

  test('a signed-prekey signature cannot be lifted onto the KEM prekey', () => {
    // The two are signed under different domain separators precisely so this
    // swap fails. Without domain separation it would succeed.
    const { bundle } = makeParty({ pq: true });
    bundle.kemPreKey.sig = bundle.signedPreKey.sig;
    bundle.kemPreKey.pub = bundle.signedPreKey.pub;
    assert.equal(verifyBundle(bundle), false);
  });

  test('accepts a bundle with no KEM prekey (un-upgraded peer)', () => {
    assert.equal(verifyBundle(makeParty({ pq: false }).bundle), true);
  });

  test('refuses empty or malformed input rather than throwing', () => {
    for (const bad of [null, undefined, {}, { signPub: 'aa' }]) {
      assert.equal(verifyBundle(bad), false);
    }
  });
});

describe('session establishment', () => {
  test('round-trips a message in both directions', () => {
    const { aSession, bSession } = handshake();

    const reply = encryptWithSession(bSession, { type: 'text', text: 'hi back' });
    assert.deepEqual(
      decryptWithSession(aSession, reply.header, reply.nonce, reply.ciphertext),
      { type: 'text', text: 'hi back' }
    );
  });

  test('marks the session pq when a KEM prekey was used', () => {
    const { aSession, bSession } = handshake({ pq: true });
    assert.equal(aSession.pq, true);
    assert.equal(bSession.pq, true);
  });

  test('falls back to a classical session against a peer with no KEM prekey', () => {
    const { aSession, bSession } = handshake({ pq: false });
    assert.equal(aSession.pq, false);
    assert.equal(bSession.pq, false);
  });

  test('two independent handshakes never derive the same root key', () => {
    const a = handshake();
    const b = handshake();
    assert.notEqual(a.aSession.rootKey, b.aSession.rootKey);
  });

  test('refuses to complete when the one-time prekey is already consumed', () => {
    // Replay of a first message. The OPK is deleted on use, and that deletion
    // is what provides forward secrecy, so a second attempt must fail closed.
    const alice = makeParty();
    const bob = makeParty();
    const aSession = initiateSession(alice.idPrivHex, bob.bundle);
    const first = encryptWithSession(aSession, { type: 'text', text: 'x' });

    const consumed = { ...bob.resolver, oneTimePreKeyPriv: () => null };
    assert.equal(
      acceptSession(bob.idPrivHex, alice.idPubHex, first.header, consumed),
      null
    );
  });

  test('refuses when the signed prekey has been rotated away', () => {
    const alice = makeParty();
    const bob = makeParty();
    const aSession = initiateSession(alice.idPrivHex, bob.bundle);
    const first = encryptWithSession(aSession, { type: 'text', text: 'x' });

    const rotated = { ...bob.resolver, signedPreKeyPriv: () => null };
    assert.equal(
      acceptSession(bob.idPrivHex, alice.idPubHex, first.header, rotated),
      null
    );
  });

  test('refuses a KEM ciphertext it cannot decapsulate, rather than downgrading', () => {
    // Failing open here would let anyone strip the post-quantum half by
    // presenting a ciphertext the responder cannot open.
    const alice = makeParty();
    const bob = makeParty({ pq: true });
    const aSession = initiateSession(alice.idPrivHex, bob.bundle);
    const first = encryptWithSession(aSession, { type: 'text', text: 'x' });
    assert.ok(first.header.kemCt, 'first message should carry a KEM ciphertext');

    const noKem = { ...bob.resolver, kemPreKeyPriv: () => null };
    assert.equal(
      acceptSession(bob.idPrivHex, alice.idPubHex, first.header, noKem),
      null
    );
  });

  test('a different identity cannot derive the same session', () => {
    const alice = makeParty();
    const mallory = makeParty();
    const bob = makeParty();

    const aSession = initiateSession(alice.idPrivHex, bob.bundle);
    const msg = encryptWithSession(aSession, { type: 'text', text: 'secret' });

    // Bob accepts, but is told the sender was Mallory. The X3DH transcript
    // binds the sender's identity key, so the derived secret differs and the
    // message must not decrypt.
    const bSession = acceptSession(bob.idPrivHex, mallory.idPubHex, msg.header, bob.resolver);
    assert.equal(
      bSession && decryptWithSession(bSession, msg.header, msg.nonce, msg.ciphertext),
      null
    );
  });
});

describe('message delivery', () => {
  test('decrypts a run of messages in order', () => {
    const { aSession, bSession } = handshake();
    for (let i = 0; i < 20; i++) {
      const m = encryptWithSession(aSession, { type: 'text', text: `m${i}` });
      assert.deepEqual(
        decryptWithSession(bSession, m.header, m.nonce, m.ciphertext),
        { type: 'text', text: `m${i}` }
      );
    }
  });

  test('decrypts messages that arrive out of order', () => {
    const { aSession, bSession } = handshake();
    const sent = [];
    for (let i = 0; i < 15; i++) {
      sent.push({ i, m: encryptWithSession(aSession, { type: 'text', text: `m${i}` }) });
    }

    const seen = new Set();
    for (const { i, m } of shuffle(sent)) {
      const out = decryptWithSession(bSession, m.header, m.nonce, m.ciphertext);
      assert.deepEqual(out, { type: 'text', text: `m${i}` }, `message ${i} out of order`);
      seen.add(i);
    }
    assert.equal(seen.size, 15, 'every message should decrypt exactly once');
  });

  test('survives interleaved traffic in both directions', () => {
    const { aSession, bSession } = handshake();
    for (let round = 0; round < 8; round++) {
      const a = encryptWithSession(aSession, { type: 'text', text: `a${round}` });
      assert.deepEqual(
        decryptWithSession(bSession, a.header, a.nonce, a.ciphertext),
        { type: 'text', text: `a${round}` }
      );
      const b = encryptWithSession(bSession, { type: 'text', text: `b${round}` });
      assert.deepEqual(
        decryptWithSession(aSession, b.header, b.nonce, b.ciphertext),
        { type: 'text', text: `b${round}` }
      );
    }
  });

  test('a message delayed across a DH step still decrypts', () => {
    const { aSession, bSession } = handshake();

    // Alice sends two, only the second is delivered, so a chain gap opens.
    const held = encryptWithSession(aSession, { type: 'text', text: 'held' });
    const later = encryptWithSession(aSession, { type: 'text', text: 'later' });
    assert.deepEqual(
      decryptWithSession(bSession, later.header, later.nonce, later.ciphertext),
      { type: 'text', text: 'later' }
    );

    // Bob replies, forcing a DH step, then the held message finally lands.
    const reply = encryptWithSession(bSession, { type: 'text', text: 'reply' });
    decryptWithSession(aSession, reply.header, reply.nonce, reply.ciphertext);

    assert.deepEqual(
      decryptWithSession(bSession, held.header, held.nonce, held.ciphertext),
      { type: 'text', text: 'held' },
      'the banked key from the previous chain should still open it'
    );
  });

  test('a replayed message does not decrypt twice', () => {
    const { aSession, bSession } = handshake();
    const a = encryptWithSession(aSession, { type: 'text', text: 'once' });
    const b = encryptWithSession(aSession, { type: 'text', text: 'twice' });

    // Deliver out of order so 'once' is banked, then consumed, then replayed.
    decryptWithSession(bSession, b.header, b.nonce, b.ciphertext);
    assert.deepEqual(
      decryptWithSession(bSession, a.header, a.nonce, a.ciphertext),
      { type: 'text', text: 'once' }
    );
    assert.equal(
      decryptWithSession(bSession, a.header, a.nonce, a.ciphertext),
      null,
      'the banked key must be deleted once used'
    );
  });
});

describe('post-compromise security', () => {
  test('a change of direction rekeys the sending chain', () => {
    const { aSession, bSession } = handshake();
    const before = aSession.rootKey;

    const reply = encryptWithSession(bSession, { type: 'text', text: 'r' });
    decryptWithSession(aSession, reply.header, reply.nonce, reply.ciphertext);

    assert.notEqual(aSession.rootKey, before, 'the DH step must advance the root key');
  });

  test('the ratchet public key changes on every DH step', () => {
    const { aSession, bSession } = handshake();
    const seen = new Set([aSession.ratchetPub]);

    for (let i = 0; i < 5; i++) {
      const b = encryptWithSession(bSession, { type: 'text', text: 'b' });
      decryptWithSession(aSession, b.header, b.nonce, b.ciphertext);
      assert.equal(seen.has(aSession.ratchetPub), false, 'ratchet key was reused');
      seen.add(aSession.ratchetPub);

      const a = encryptWithSession(aSession, { type: 'text', text: 'a' });
      decryptWithSession(bSession, a.header, a.nonce, a.ciphertext);
    }
  });

  test('the X3DH preamble is dropped once the peer replies', () => {
    const { aSession, bSession } = handshake();
    assert.ok(aSession.pending, 'preamble is replayed until answered');

    const reply = encryptWithSession(bSession, { type: 'text', text: 'r' });
    decryptWithSession(aSession, reply.header, reply.nonce, reply.ciphertext);
    assert.equal(aSession.pending, null);

    const next = encryptWithSession(aSession, { type: 'text', text: 'n' });
    assert.equal(next.header.ek, undefined, 'preamble should no longer be sent');
  });
});

describe('bounds on attacker-controlled counters', () => {
  // n, pn and messageIndex are all plaintext an attacker chooses. Every loop
  // driven by them is capped. Removing the cap reintroduced a confirmed
  // unauthenticated remote DoS: a single envelope with n = 1e9 hung the tab
  // and filled localStorage.

  // These assert the *mechanism*, not just the outcome. An earlier version
  // only checked that decryption returned null, which is exactly what happens
  // anyway when the wrong key is derived, so raising the cap to 1e8 left the
  // tests green while the DoS was wide open. A mutation run caught that. The
  // observable difference between "rejected by the cap" and "ratcheted a
  // thousand times and then failed" is the state left behind in the session.

  test('a skip beyond MAX_SKIP banks no keys and does not advance the chain', () => {
    const { aSession, bSession } = handshake();
    const m = encryptWithSession(aSession, { type: 'text', text: 'x' });

    const bankedBefore = Object.keys(bSession.skipped).length;
    const nrBefore = bSession.Nr;
    const chainBefore = bSession.receivingChainKey;

    const started = Date.now();
    const out = decryptWithSession(
      bSession, { ...m.header, n: MAX_SKIP + 5 }, m.nonce, m.ciphertext
    );

    assert.equal(out, null, 'must not decrypt');
    assert.equal(Object.keys(bSession.skipped).length, bankedBefore,
      'a rejected over-cap message must bank no skipped keys at all');
    assert.equal(bSession.Nr, nrBefore, 'the receiving counter must not move');
    assert.equal(bSession.receivingChainKey, chainBefore,
      'the receiving chain must not be ratcheted forward');
    assert.ok(Date.now() - started < 2000, 'must fail fast, not grind');
  });

  test('an absurd counter is rejected without work proportional to it', () => {
    const { aSession, bSession } = handshake();
    const m = encryptWithSession(aSession, { type: 'text', text: 'x' });
    const bankedBefore = Object.keys(bSession.skipped).length;

    const started = Date.now();
    assert.equal(
      decryptWithSession(bSession, { ...m.header, n: 1e9 }, m.nonce, m.ciphertext),
      null
    );
    assert.equal(
      decryptWithSession(bSession, { ...m.header, pn: 1e9, dh: 'ff'.repeat(32) }, m.nonce, m.ciphertext),
      null
    );
    assert.ok(Date.now() - started < 2000, 'must fail fast, not grind');
    assert.equal(Object.keys(bSession.skipped).length, bankedBefore,
      'must bank nothing for a message it refuses');
  });

  test('the cap bounds the skip distance, not the absolute counter', () => {
    // The limit is `n - Nr`, so a long-lived session legitimately sees large
    // absolute values of n. Getting this wrong in either direction is bad:
    // capping absolute n would break old sessions, and capping nothing is the
    // DoS. A first attempt at this test asserted the wrong semantics and
    // failed against correct code, which is worth leaving a note about.
    const { aSession, bSession } = handshake();
    const m = encryptWithSession(aSession, { type: 'text', text: 'x' });

    const nr = bSession.Nr;
    assert.ok(nr > 0, 'fixture assumption: the handshake message advanced Nr');

    // Exactly at the cap: allowed, and it banks the keys it stepped over.
    const ok = { ...bSession, skipped: { ...bSession.skipped } };
    decryptWithSession(ok, { ...m.header, n: nr + MAX_SKIP }, m.nonce, m.ciphertext);
    assert.equal(Object.keys(ok.skipped).length, MAX_SKIP,
      'a skip of exactly MAX_SKIP should be honoured');

    // One past the cap: refused, banking nothing.
    const tooFar = { ...bSession, skipped: { ...bSession.skipped } };
    const before = Object.keys(tooFar.skipped).length;
    assert.equal(
      decryptWithSession(tooFar, { ...m.header, n: nr + MAX_SKIP + 1 }, m.nonce, m.ciphertext),
      null
    );
    assert.equal(Object.keys(tooFar.skipped).length, before,
      'a skip of MAX_SKIP + 1 must be refused outright');
  });

  test('a skip right up to the cap still works', () => {
    // The cap must be a real boundary, not an off-by-one that rejects valid
    // traffic a little below it.
    const { aSession, bSession } = handshake();
    let last = null;
    for (let i = 0; i < 40; i++) {
      last = encryptWithSession(aSession, { type: 'text', text: `m${i}` });
    }
    assert.deepEqual(
      decryptWithSession(bSession, last.header, last.nonce, last.ciphertext),
      { type: 'text', text: 'm39' }
    );
  });

  test('rejects malformed headers rather than throwing', () => {
    const { aSession, bSession } = handshake();
    const m = encryptWithSession(aSession, { type: 'text', text: 'x' });

    const bad = [
      null, undefined, {},
      { ...m.header, v: 1 },
      { ...m.header, v: 2, dh: 123 },
      { ...m.header, n: -1 },
      { ...m.header, pn: -1 },
      { ...m.header, n: 1.5 },
      { ...m.header, n: NaN },
      { ...m.header, n: Number.MAX_SAFE_INTEGER + 10 }
    ];
    for (const h of bad) {
      assert.equal(
        decryptWithSession(bSession, h, m.nonce, m.ciphertext), null,
        `header ${JSON.stringify(h)} should be refused`
      );
    }
  });

  test('rejects tampered ciphertext and nonce rather than throwing', () => {
    const { aSession, bSession } = handshake();
    const m = encryptWithSession(aSession, { type: 'text', text: 'x' });

    assert.equal(
      decryptWithSession(bSession, m.header, m.nonce, corruptHex(m.ciphertext)), null,
      'AEAD must reject a flipped ciphertext bit'
    );
    assert.equal(
      decryptWithSession(bSession, m.header, corruptHex(m.nonce), m.ciphertext), null
    );
    assert.equal(
      decryptWithSession(bSession, m.header, 'zz', 'zz'), null
    );
  });
});
