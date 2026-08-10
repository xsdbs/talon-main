// Sending to a peer who has more than one device.
//
// This drives the real sendE2EPayload against a fake socket and a fake
// relay response, so the fan-out is exercised rather than merely written.
// Everything below the fake is genuine: real X3DH, real ratchets, real
// sealing, real bundle verification.
//
// The bugs it exists to catch are all "looks fine, delivers wrong":
//   - one envelope produced for a two-device peer, so a device never hears
//   - both envelopes on one ratchet, so the second is undecryptable
//   - the same correlation token reused, so the outbox mismatches acks
//   - a device id leaking onto the wire when the peer has only one device

import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// store.js reaches for localStorage as a global, so the shim goes in before
// anything imports it. Same arrangement as vault.test.js.
function makeWebStorage() {
  const map = new Map();
  return {
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => { map.set(k, String(v)); },
    removeItem: (k) => { map.delete(k); },
    clear: () => map.clear(),
    key: (i) => Array.from(map.keys())[i] ?? null,
    get length() { return map.size; },
    _keys: () => Array.from(map.keys())
  };
}
globalThis.localStorage = makeWebStorage();
globalThis.sessionStorage = makeWebStorage();

const { makeParty } = await import('./helpers.js');
const { State } = await import('../src/store.js');
const { sendE2EPayload, openSealed, syncToMyDevices } = await import('../src/messaging.js');
const {
  bytesToHex, generateIdentityKeypair, sha256Hash, utf8Encode,
  signingKeypairFromSeed, signBytes
} = await import('../src/crypto-bundle.js');
const { buildSignedPreKeyMessage } = await import('../src/ratchet.js');
const { sessionKey } = await import('../src/devices.js');

/* ------------------------------------------------------------- the fakes */

let sent;          // every frame handed to the socket
let bundleReply;   // what /api/prekey-bundle returns

function installSocket() {
  sent = [];
  State.socketConnected = true;
  State.socket = {
    readyState: 1,
    send: (raw) => sent.push(JSON.parse(raw))
  };
  globalThis.WebSocket = { OPEN: 1 };
}

function installFetch() {
  globalThis.fetch = async (url) => {
    if (String(url).includes('/api/prekey-bundle')) {
      return { json: async () => ({ success: true, ...bundleReply }) };
    }
    return { json: async () => ({ success: true }) };
  };
}

/** A local account that can seal and sign. */
function makeMe() {
  const id = generateIdentityKeypair();
  const idPriv = bytesToHex(id.privateKey);
  return {
    username: 'me',
    authHash: 'a'.repeat(64),
    idPub: bytesToHex(id.publicKey),
    idPriv,
    encryptionKeyHex: 'b'.repeat(64)
  };
}

/**
 * A second device for an existing party: its own signed prekey, signed by the
 * SAME account signing key, which is what the real client does because the
 * signing key is derived from the shared identity private key.
 */
function extraDeviceBundle(party) {
  const sign = signingKeypairFromSeed(sha256Hash(utf8Encode('TalonSigningKey:' + party.idPrivHex)));
  const spk = generateIdentityKeypair();
  const pub = bytesToHex(spk.publicKey);
  return {
    signPub: bytesToHex(sign.publicKey),
    signedPreKey: {
      pub,
      sig: bytesToHex(signBytes(sign.privateKey, buildSignedPreKeyMessage(pub)))
    },
    kemPreKey: null,
    oneTimePreKey: null
  };
}

const DEV_A = '1'.repeat(16);
const DEV_B = '2'.repeat(16);

beforeEach(() => {
  installSocket();
  installFetch();
  State.currentUser = makeMe();
  State.sessions = {};
  State.contacts = [];
  State.groups = [];
});

/* -------------------------------------------------------------- the tests */

describe('a peer with one implicit device', () => {
  test('produces exactly one envelope, with no device on the wire', async () => {
    // The compatibility case. The frame must be what it always was, or every
    // existing conversation starts carrying a field the other end ignores and
    // the relay starts learning something new for no reason.
    const peer = makeParty();
    bundleReply = { bundle: peer.bundle, devices: null };

    const r = await sendE2EPayload(peer.idPubHex, { type: 'text', text: 'hi' }, null, true);

    assert.equal(sent.length, 1, `expected one envelope, got ${sent.length}`);
    assert.equal(r.success, true);
    assert.equal('recipientDev' in sent[0], false,
      'a single-device peer had a device id put on the wire');
    assert.equal(sent[0].recipientId, peer.idPubHex);
  });

  test('the session is stored under the bare peer id', async () => {
    const peer = makeParty();
    bundleReply = { bundle: peer.bundle, devices: null };
    await sendE2EPayload(peer.idPubHex, { type: 'text', text: 'hi' }, null, false);

    assert.ok(State.sessions[peer.idPubHex],
      'the pre-device session key changed, which orphans every existing session');
  });
});

describe('a peer with two devices', () => {
  let peer;

  beforeEach(() => {
    peer = makeParty();
    bundleReply = {
      bundle: null,
      devices: [
        { deviceId: DEV_A, devPub: 'c'.repeat(64), bundle: peer.bundle },
        { deviceId: DEV_B, devPub: 'd'.repeat(64), bundle: extraDeviceBundle(peer) }
      ]
    };
  });

  test('every device gets an envelope', async () => {
    const r = await sendE2EPayload(peer.idPubHex, { type: 'text', text: 'hi' }, null, true);

    assert.equal(sent.length, 2, `a device would never receive this: got ${sent.length} envelopes`);
    assert.equal(r.success, true);
    assert.deepEqual(sent.map((f) => f.recipientDev).sort(), [DEV_A, DEV_B]);
  });

  test('each device gets its own ratchet', async () => {
    await sendE2EPayload(peer.idPubHex, { type: 'text', text: 'hi' }, null, false);

    const a = State.sessions[sessionKey(peer.idPubHex, DEV_A)];
    const b = State.sessions[sessionKey(peer.idPubHex, DEV_B)];
    assert.ok(a && b, 'a per-device session was not created');
    assert.notEqual(a.sendingChainKey || a.ck, b.sendingChainKey || b.ck,
      'both devices share one chain key, so one of them cannot decrypt');
  });

  test('each envelope carries its own correlation token', async () => {
    // The outbox matches acks by ref. Reusing one across the fan-out means
    // the first ack settles the message and the rest match nothing.
    await sendE2EPayload(peer.idPubHex, { type: 'text', text: 'hi' }, null, false);
    const refs = sent.map((f) => f.ref);
    assert.equal(new Set(refs).size, 2, 'the fan-out reused a correlation token');
    assert.ok(refs.every(Boolean), 'an envelope went out with no correlation token');
  });

  test('the caller is told about every token, not just the first', async () => {
    const r = await sendE2EPayload(peer.idPubHex, { type: 'text', text: 'hi' }, null, false);
    assert.equal(r.refs.length, 2,
      'the outbox cannot settle a message whose tokens it was never given');
    assert.ok(r.refs.includes(r.ref));
  });

  test('the ciphertexts differ, so neither is a copy of the other', async () => {
    // If both envelopes came out of one session, the payloads would be
    // identical and only one device could open either.
    await sendE2EPayload(peer.idPubHex, { type: 'text', text: 'hi' }, null, false);
    const [one, two] = sent.map((f) => JSON.stringify(f.payload));
    assert.notEqual(one, two, 'the same ciphertext was sent to both devices');
  });

  test('the sender device rides inside the seal, not on the frame', async () => {
    // The relay learns the RECIPIENT device because it has to route. It has
    // no reason to learn the sender's, so that one lives under the AEAD.
    State.currentUser.deviceId = DEV_A;
    await sendE2EPayload(peer.idPubHex, { type: 'text', text: 'hi' }, null, false);

    for (const frame of sent) {
      assert.equal('senderDev' in frame, false, 'the sender device leaked onto the frame');
      assert.equal(frame.payload.sealed, 1, 'the envelope was not sealed');
      assert.equal(JSON.stringify(frame.payload).includes(DEV_A), false,
        'the sender device is readable outside the ciphertext');
    }
  });

  test('a push tag is still per recipient, not per device', async () => {
    // The tag binds conversation and recipient account. Two devices of one
    // account share it, which is correct: muting is an account decision.
    await sendE2EPayload(peer.idPubHex, { type: 'text', text: 'hi' }, null, true);
    const tags = sent.map((f) => f.pushTag);
    assert.equal(new Set(tags).size, 1, 'the same conversation produced two different tags');
    assert.ok(tags[0], 'a notify-worthy message went out with no push tag');
  });

  test('a second send reuses the sessions rather than re-handshaking', async () => {
    await sendE2EPayload(peer.idPubHex, { type: 'text', text: 'one' }, null, false);
    const before = JSON.stringify(Object.keys(State.sessions).sort());
    sent.length = 0;

    await sendE2EPayload(peer.idPubHex, { type: 'text', text: 'two' }, null, false);
    assert.equal(sent.length, 2, 'the second message did not reach both devices');
    assert.equal(JSON.stringify(Object.keys(State.sessions).sort()), before,
      'a second send created new sessions, so the ratchet restarts every message');
  });
});

describe('a device that has published no prekeys', () => {
  test('is skipped, and the others still receive', async () => {
    // The relay reports such a device with a null bundle rather than hiding
    // it. Sending must degrade to the reachable devices instead of failing.
    const peer = makeParty();
    bundleReply = {
      bundle: null,
      devices: [
        { deviceId: DEV_A, devPub: 'c'.repeat(64), bundle: peer.bundle },
        { deviceId: DEV_B, devPub: 'd'.repeat(64), bundle: null }
      ]
    };

    const r = await sendE2EPayload(peer.idPubHex, { type: 'text', text: 'hi' }, null, false);
    assert.equal(sent.length, 1, 'a device with no prekeys was addressed anyway');
    assert.equal(sent[0].recipientDev, DEV_A);
    assert.equal(r.success, true, 'the reachable device should still count as delivered');
  });
});

describe('a tampered device bundle', () => {
  test('is refused, and does not take the honest device down with it', async () => {
    // The relay is the one serving these. A bundle whose signature does not
    // verify is the relay substituting a prekey it holds the secret for, and
    // it must be dropped rather than downgraded.
    const peer = makeParty();
    const forged = extraDeviceBundle(peer);
    forged.signedPreKey.sig = 'f'.repeat(128);

    bundleReply = {
      bundle: null,
      devices: [
        { deviceId: DEV_A, devPub: 'c'.repeat(64), bundle: peer.bundle },
        { deviceId: DEV_B, devPub: 'd'.repeat(64), bundle: forged }
      ]
    };

    await sendE2EPayload(peer.idPubHex, { type: 'text', text: 'hi' }, null, false);

    assert.equal(sent.length, 1, 'a bundle with an invalid signature was used');
    assert.equal(sent[0].recipientDev, DEV_A, 'the honest device was dropped instead');
    assert.equal(State.sessions[sessionKey(peer.idPubHex, DEV_B)], undefined,
      'a session was opened against a forged bundle');
  });
});

describe('one device unreachable, another fine', () => {
  test('the message counts as sent', async () => {
    // Requiring every device would mark a message failed because a peer's
    // spare laptop is unreachable, and the outbox would then retry forever
    // against a device that may never come back.
    const peer = makeParty();
    bundleReply = {
      bundle: null,
      devices: [
        { deviceId: DEV_A, devPub: 'c'.repeat(64), bundle: peer.bundle },
        { deviceId: DEV_B, devPub: 'd'.repeat(64), bundle: extraDeviceBundle(peer) }
      ]
    };

    // The socket closes as soon as the first envelope is away, so the second
    // fails the readiness check rather than being silently swallowed. The
    // order matters: transmit() tests readyState BEFORE calling send, so
    // flipping it during the second call would be too late to be noticed.
    State.socket.send = (raw) => {
      sent.push(JSON.parse(raw));
      State.socket.readyState = 3;
      State.socketConnected = false;
    };

    const r = await sendE2EPayload(peer.idPubHex, { type: 'text', text: 'hi' }, null, false);
    assert.equal(sent.length, 1, 'the fixture did not drop the second envelope');
    assert.equal(r.success, true,
      'one unreachable device marked the whole message failed');
  });
});

describe('the relay stops serving a bundle', () => {
  test('an established session keeps being used', async () => {
    // A peer whose prekey pool ran dry, or a relay that answers with nothing.
    // The session we already hold is still perfectly good, and discarding it
    // would silently drop the conversation back to the v1 path and start a
    // fresh handshake on every single message.
    const peer = makeParty();
    bundleReply = { bundle: peer.bundle, devices: null };
    await sendE2EPayload(peer.idPubHex, { type: 'text', text: 'one' }, null, false);

    // The frame's payload is the seal; the protocol version is inside it.
    // A v1 envelope has messageIndex where a v2 one has v, header, nonce.
    assert.ok(State.sessions[peer.idPubHex] && State.sessions[peer.idPubHex].v === 2,
      'the fixture did not establish a v2 session');

    sent.length = 0;
    bundleReply = { bundle: null, devices: null };

    const r = await sendE2EPayload(peer.idPubHex, { type: 'text', text: 'two' }, null, false);
    assert.equal(sent.length, 1, 'the message was not sent at all');
    assert.equal(r.success, true);

    // The payload is sealed to the peer, so the version cannot be read off
    // the frame. The v2 counter is the observable: only sendV2 advances it,
    // so seq of 2 after two sends is proof both took the v2 path. Asserting
    // that the session is still v2 would not do, because falling back to v1
    // leaves the session object untouched and looks identical.
    assert.equal(State.sessions[peer.idPubHex].seq, 2,
      'the established session was discarded and the send fell back to v1');
  });

  test('a peer with no session and no bundle still takes the v1 path', async () => {
    const peer = makeParty();
    bundleReply = { bundle: null, devices: null };
    State.sessions = {};

    const r = await sendE2EPayload(peer.idPubHex, { type: 'text', text: 'hi' }, null, false);
    assert.equal(sent.length, 1, 'a peer with no published bundle received nothing at all');
    assert.equal(r.success, true);
    assert.equal('recipientDev' in sent[0], false, 'a v1 envelope carried a device id');
  });
});

describe('the socket is down', () => {
  test('no envelope reports success', async () => {
    // Whatever the device count, an unsent message must not look sent, or the
    // outbox never picks it up and it is lost silently.
    const peer = makeParty();
    bundleReply = {
      bundle: null,
      devices: [
        { deviceId: DEV_A, devPub: 'c'.repeat(64), bundle: peer.bundle },
        { deviceId: DEV_B, devPub: 'd'.repeat(64), bundle: extraDeviceBundle(peer) }
      ]
    };
    State.socketConnected = false;

    const r = await sendE2EPayload(peer.idPubHex, { type: 'text', text: 'hi' }, null, false);
    assert.equal(r.success, false, 'a message sent with no socket reported success');
    assert.equal(sent.length, 0);
  });
});

describe('receiving from a peer with two devices', () => {
  // The mirror of the fan-out, and the bug that made it necessary. Both of a
  // peer's devices run their own X3DH against us. Keyed under the bare peer
  // id, the second handshake overwrote the first, and every later message
  // from the first device silently failed to decrypt.

  /**
   * Sets `me` up as a real party so acceptSession can find our own keys.
   *
   * The pool holds TWO one-time prekeys, because that is what actually
   * happens: each of a peer's devices fetches its own bundle and the relay
   * hands each a different one. Giving both devices the same one made the
   * second handshake fail, which is correct behaviour, since consuming the
   * key is precisely what buys forward secrecy.
   */
  function beMe() {
    const me = makeParty();
    const spare = generateIdentityKeypair();
    State.currentUser = {
      username: 'me',
      authHash: 'a'.repeat(64),
      idPub: me.idPubHex,
      idPriv: me.idPrivHex,
      encryptionKeyHex: 'b'.repeat(64)
    };
    State.preKeys = {
      signPub: me.bundle.signPub,
      spk: { pub: me.spkPubHex, priv: me.resolver.signedPreKeyPriv(me.spkPubHex) },
      spkArchive: {},
      kem: {
        pub: me.bundle.kemPreKey.pub,
        priv: me.resolver.kemPreKeyPriv(me.bundle.kemPreKey.pub)
      },
      kemArchive: {},
      otk: {
        'opk-1': me.resolver.oneTimePreKeyPriv('opk-1'),
        'opk-2': bytesToHex(spare.privateKey)
      },
      nextOtkId: 3
    };
    // The bundle a second fetch would return: same signed prekey, a different
    // one-time prekey.
    me.secondBundle = {
      ...me.bundle,
      idPub: me.idPubHex,
      oneTimePreKey: { id: 'opk-2', pub: bytesToHex(spare.publicKey) }
    };
    me.firstBundle = { ...me.bundle, idPub: me.idPubHex };
    return me;
  }

  /** One of a peer's devices, opening a session to us and encrypting. */
  async function envelopeFrom(peerIdPriv, myBundle, text) {
    const { initiateSession, encryptWithSession } = await import('../src/ratchet.js');
    const session = initiateSession(peerIdPriv, myBundle);
    const { header, nonce, ciphertext } = encryptWithSession(session, { type: 'text', text, _mid: 0 });
    return { v: 2, header, nonce, ciphertext };
  }

  test('each sending device gets its own ratchet on our side', async () => {
    const me = beMe();
    const { processIncomingMessage } = await import('../src/messaging.js');

    // Two devices of one peer. They share an account identity key, exactly as
    // real devices of one account do.
    const peer = makeParty();
    const first = await envelopeFrom(peer.idPrivHex, me.firstBundle, 'from A');
    const second = await envelopeFrom(peer.idPrivHex, me.secondBundle, 'from B');

    const a = processIncomingMessage(peer.idPubHex, first, DEV_A);
    const b = processIncomingMessage(peer.idPubHex, second, DEV_B);

    assert.ok(a, 'the first device could not be decrypted');
    assert.ok(b, 'the second device could not be decrypted');
    assert.equal(a.payloadObj.text, 'from A');
    assert.equal(b.payloadObj.text, 'from B');

    assert.ok(State.sessions[sessionKey(peer.idPubHex, DEV_A)], 'no session for the first device');
    assert.ok(State.sessions[sessionKey(peer.idPubHex, DEV_B)], 'no session for the second device');
  });

  test("the second device's handshake does not break the first", async () => {
    // The actual failure mode. Device A talks, device B says hello, then A
    // talks again. Under one shared key, that last message is lost.
    const me = beMe();
    const { processIncomingMessage } = await import('../src/messaging.js');
    const { initiateSession, encryptWithSession } = await import('../src/ratchet.js');

    const peer = makeParty();
    const sessionA = initiateSession(peer.idPrivHex, me.firstBundle);
    const sessionB = initiateSession(peer.idPrivHex, me.secondBundle);

    const enc = (s, text, mid) => {
      const { header, nonce, ciphertext } = encryptWithSession(s, { type: 'text', text, _mid: mid });
      return { v: 2, header, nonce, ciphertext };
    };

    assert.ok(processIncomingMessage(peer.idPubHex, enc(sessionA, 'A one', 0), DEV_A));
    assert.ok(processIncomingMessage(peer.idPubHex, enc(sessionB, 'B one', 0), DEV_B));

    const late = processIncomingMessage(peer.idPubHex, enc(sessionA, 'A two', 1), DEV_A);
    assert.ok(late, "the second device's handshake destroyed the first device's session");
    assert.equal(late.payloadObj.text, 'A two');
  });

  test('a peer with no device still lands on the bare peer id', async () => {
    const me = beMe();
    const { processIncomingMessage } = await import('../src/messaging.js');
    const peer = makeParty();
    const env = await envelopeFrom(peer.idPrivHex, me.firstBundle, 'plain');

    const r = processIncomingMessage(peer.idPubHex, env, null);
    assert.ok(r, 'a single-device peer stopped being decryptable');
    assert.ok(State.sessions[peer.idPubHex],
      'the pre-device session key changed, orphaning every existing session');
  });
});

describe('mirroring a sent message to our own devices', () => {
  // Without this a second device is receive-only in practice: it collects
  // what people say to you and knows nothing of your own side. The failure
  // modes are all quiet ones, so each is asserted directly.
  let me;

  beforeEach(() => {
    me = makeParty();
    State.currentUser = {
      username: 'me',
      authHash: 'a'.repeat(64),
      idPub: me.idPubHex,
      idPriv: me.idPrivHex,
      encryptionKeyHex: 'b'.repeat(64),
      deviceId: DEV_A
    };
    // Our own account, with two devices: this one and one other.
    bundleReply = {
      bundle: null,
      devices: [
        { deviceId: DEV_A, devPub: 'c'.repeat(64), bundle: me.bundle },
        { deviceId: DEV_B, devPub: 'd'.repeat(64), bundle: extraDeviceBundle(me) }
      ]
    };
  });

  test('goes to the other device and not back to this one', async () => {
    // Echoing to ourselves would store the message twice on the device that
    // sent it, which is the most visible way to get this wrong.
    const r = await syncToMyDevices('conv-1', { type: 'text', text: 'hi' }, 'lid-1');
    assert.equal(r.sent, 1, `expected one mirror, got ${r.sent}`);
    assert.equal(sent.length, 1);
    assert.equal(sent[0].recipientDev, DEV_B, 'the mirror went to the wrong device');
    assert.equal(sent[0].recipientId, State.currentUser.idPub);
  });

  test('never asks for a notification', async () => {
    // Waking your own phone for something you just typed on it.
    await syncToMyDevices('conv-1', { type: 'text', text: 'hi' }, 'lid-1');
    assert.equal(sent[0].notify, false, 'a self-sync asked to notify');
    assert.equal(sent[0].pushTag, undefined, 'a self-sync carried a push tag');
  });

  test('a single-device account sends nothing', async () => {
    State.currentUser.deviceId = null;
    const r = await syncToMyDevices('conv-1', { type: 'text', text: 'hi' }, 'lid-1');
    assert.equal(r.sent, 0);
    assert.equal(sent.length, 0, 'a single-device client mirrored to itself');
  });

  test('an account whose only device is this one sends nothing', async () => {
    bundleReply = {
      bundle: null,
      devices: [{ deviceId: DEV_A, devPub: 'c'.repeat(64), bundle: me.bundle }]
    };
    const r = await syncToMyDevices('conv-1', { type: 'text', text: 'hi' }, 'lid-1');
    assert.equal(r.sent, 0);
    assert.equal(sent.length, 0);
  });

  test('the mirror carries the conversation, the payload and the id', async () => {
    // The receiving device needs all three: which chat it belongs to, what
    // was said, and the id that makes it the same message rather than a new
    // one, so a resend does not double up.
    await syncToMyDevices('conv-9', { type: 'text', text: 'the words' }, 'lid-7');

    const opened = openSealed(sent[0].payload);
    assert.ok(opened, 'the mirror was not sealed');
    assert.equal(opened.senderId, State.currentUser.idPub);
    assert.equal(opened.senderDev, DEV_A, 'the mirror does not say which device sent it');
  });

  test('the other device can decrypt it, and it says what it must', async () => {
    // The only way to check the contents is to be the receiving device, so
    // the target's bundle is one whose private half this test holds. Then the
    // mirror is opened and decrypted for real.
    //
    // Asserting on the sealed frame alone would have missed a mirror that
    // dropped the conversation id or the message id, and both are load
    // bearing: without the first it cannot be filed, without the second a
    // resend arrives as a second copy.
    const { processIncomingMessage } = await import('../src/messaging.js');
    const spare = generateIdentityKeypair();

    State.preKeys = {
      signPub: me.bundle.signPub,
      spk: { pub: me.spkPubHex, priv: me.resolver.signedPreKeyPriv(me.spkPubHex) },
      spkArchive: {},
      kem: {
        pub: me.bundle.kemPreKey.pub,
        priv: me.resolver.kemPreKeyPriv(me.bundle.kemPreKey.pub)
      },
      kemArchive: {},
      otk: { 'opk-1': me.resolver.oneTimePreKeyPriv('opk-1'), 'opk-2': bytesToHex(spare.privateKey) },
      nextOtkId: 3
    };
    bundleReply = {
      bundle: null,
      devices: [
        { deviceId: DEV_A, devPub: 'c'.repeat(64), bundle: extraDeviceBundle(me) },
        { deviceId: DEV_B, devPub: 'd'.repeat(64), bundle: { ...me.bundle, idPub: me.idPubHex } }
      ]
    };

    await syncToMyDevices('conv-9', { type: 'text', text: 'the words' }, 'lid-7');
    assert.equal(sent.length, 1, 'the fixture did not produce exactly one mirror');

    const opened = openSealed(sent[0].payload);
    assert.ok(opened, 'the mirror was not sealed to us');

    // Received as if we were the other device.
    State.sessions = {};
    const got = processIncomingMessage(opened.senderId, opened.payload, opened.senderDev);
    assert.ok(got, 'the other device could not decrypt the mirror');

    const p = got.payloadObj;
    assert.equal(p.action, 'sync-sent');
    assert.equal(p.convId, 'conv-9', 'the mirror does not say which conversation it belongs to');
    assert.equal(p.lid, 'lid-7', 'the mirror lost the id that makes a resend a duplicate');
    assert.equal(p.payload.text, 'the words', 'the mirror lost the message itself');
  });

  test('a failure to reach one device is not an exception', async () => {
    // It must never fail the send that triggered it: the recipient has the
    // message either way, and saying otherwise would be a lie about the part
    // the user cares about.
    State.socketConnected = false;
    await assert.doesNotReject(() => syncToMyDevices('conv-1', { type: 'text', text: 'hi' }, 'lid-1'));
  });

  test('with no signed-in user it is a no-op', async () => {
    State.currentUser = null;
    const r = await syncToMyDevices('conv-1', { type: 'text', text: 'hi' }, 'lid-1');
    assert.equal(r.sent, 0);
  });
});

describe('openSealed validates the sender device', () => {
  test('a well formed device id survives the round trip', () => {
    State.currentUser.deviceId = DEV_A;
    const peer = makeParty();
    bundleReply = { bundle: peer.bundle, devices: null };

    // Seal to ourselves so we can open it.
    const me = State.currentUser;
    const frame = { type: 'send', recipientId: me.idPub, payload: { v: 2 } };
    State.socket.send(JSON.stringify(frame));
    sent.length = 0;

    // Round trip through the real seal.
    return sendE2EPayload(me.idPub, { type: 'text', text: 'self' }, null, false).then(() => {
      const opened = openSealed(sent[0].payload);
      assert.ok(opened, 'the seal did not open');
      assert.equal(opened.senderDev, DEV_A);
    });
  });

  test('a malformed device id is read as no device', async () => {
    // senderDev selects a storage key, so it is attacker-chosen input to the
    // session store. Anything that is not a device id must collapse to null
    // and land on the account session, or a peer can grow that store without
    // bound, one key per message.
    const me = State.currentUser;
    const peer = makeParty();
    bundleReply = { bundle: peer.bundle, devices: null };

    for (const bogus of ['../../evil', 'x'.repeat(200), '', 'ZZZZ', 12345, {}, '1'.repeat(15)]) {
      State.sessions = {};
      sent.length = 0;
      State.currentUser.deviceId = bogus;

      await sendE2EPayload(peer.idPubHex, { type: 'text', text: 'x' }, null, false);
      assert.equal(sent.length, 1, 'the fixture did not produce an envelope');

      // Seal to ourselves so we can read it back.
      State.sessions = {};
      sent.length = 0;
      await sendE2EPayload(me.idPub, { type: 'text', text: 'x' }, null, false);
      const opened = openSealed(sent[0].payload);
      assert.ok(opened, 'the seal did not open');
      assert.equal(opened.senderDev, null,
        `a malformed device id survived validation: ${JSON.stringify(bogus)}`);
    }
  });
});
