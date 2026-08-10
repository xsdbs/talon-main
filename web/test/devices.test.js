// The signed device list.
//
// What is under test is refusal. A device list that accepts everything is
// worse than no list, because it gives the relay a supported way to add a
// reader to an account and makes the Settings screen lie about which devices
// exist. So every check below asserts that something is REJECTED, and the
// mutation harness turns each of those refusals off in turn.
//
// The roster suite learned this the hard way: a gate is only a gate if
// something proves it closes.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  buildDeviceListMessage, signDeviceListWith, verifyDeviceList,
  deviceListAcceptable, fanoutTargets, withDevice, withoutDevice,
  sessionKey, peerOfSessionKey, sessionKeysFor,
  MAX_DEVICES, DEFAULT_DEVICE_NAME
} from '../src/devices.js';
import {
  generateSigningKeypair, bytesToHex, generateIdentityKeypair
} from '../src/crypto-bundle.js';

const signer = generateSigningKeypair();
const other = generateSigningKeypair();
const SIGN_PUB = bytesToHex(signer.publicKey);
const OTHER_PUB = bytesToHex(other.publicKey);

const ID = 'a'.repeat(64);
const devId = (n) => String(n).repeat(16).slice(0, 16);
const devPub = (n) => String(n).repeat(64).slice(0, 64);

const device = (n, name = `Device ${n}`) => ({
  deviceId: devId(n), devPub: devPub(n), name
});

/** A list with a valid signature over exactly the fields it carries. */
function signed(fields, priv = signer.privateKey, pub = SIGN_PUB) {
  return { ...fields, sig: signDeviceListWith(priv, fields), signPub: pub };
}

const list = (devices, rev = 1) => signed({ idPub: ID, rev, devices });

/**
 * A well-formed signed list with a hostile field swapped in afterwards.
 *
 * Used for input that cannot be signed over at all, such as a null device.
 * The signature is therefore wrong, which is the point: these must be refused
 * by the structural checks BEFORE anything reaches the verifier, or a crafted
 * list gets to choose what the crypto code is handed.
 */
const tampered = (over) => ({ ...list([device(1)]), ...over });

describe('the canonical encoding', () => {
  test('is independent of device order', () => {
    // Two devices of the same account build the list in whatever order they
    // happen to hold it. If order mattered, one of them would always compute
    // a different signature and reject the other's list.
    const a = buildDeviceListMessage({ idPub: ID, rev: 1, devices: [device(1), device(2)] });
    const b = buildDeviceListMessage({ idPub: ID, rev: 1, devices: [device(2), device(1)] });
    assert.deepEqual(a, b);
  });

  test('changes when any signed field changes', () => {
    const base = { idPub: ID, rev: 1, devices: [device(1)] };
    const bytes = (f) => bytesToHex(buildDeviceListMessage(f));
    const original = bytes(base);

    assert.notEqual(bytes({ ...base, rev: 2 }), original, 'revision is not covered');
    assert.notEqual(bytes({ ...base, idPub: 'b'.repeat(64) }), original, 'account is not covered');
    assert.notEqual(bytes({ ...base, devices: [device(2)] }), original, 'device key is not covered');
    assert.notEqual(bytes({ ...base, devices: [device(1, 'Renamed')] }), original,
      'the device name is not covered, so it can be edited in transit');
  });

  test('is domain separated from the roster and prekey contexts', () => {
    // The same signing key signs rosters and prekeys. Without a distinct
    // prefix a signature could be lifted from one context into another.
    const msg = new TextDecoder().decode(
      buildDeviceListMessage({ idPub: ID, rev: 1, devices: [device(1)] })
    );
    assert.ok(msg.startsWith('TalonDeviceList:'), `unexpected prefix: ${msg.slice(0, 24)}`);
  });
});

describe('signing', () => {
  test('a list signed by the account verifies', () => {
    const fields = { idPub: ID, rev: 1, devices: [device(1)] };
    assert.equal(verifyDeviceList(fields, signDeviceListWith(signer.privateKey, fields), SIGN_PUB), true);
  });

  test('a signature from another key does not', () => {
    const fields = { idPub: ID, rev: 1, devices: [device(1)] };
    assert.equal(verifyDeviceList(fields, signDeviceListWith(other.privateKey, fields), SIGN_PUB), false);
  });

  test('malformed input is false rather than a throw', () => {
    const fields = { idPub: ID, rev: 1, devices: [device(1)] };
    for (const bad of [null, undefined, 42, 'zz', '']) {
      assert.equal(verifyDeviceList(fields, bad, SIGN_PUB), false);
      assert.equal(verifyDeviceList(fields, 'ab', bad), false);
    }
  });
});

describe('what is refused', () => {
  const reject = (incoming, reason, existing = null) => {
    const r = deviceListAcceptable(existing, incoming);
    assert.equal(r.ok, false, `accepted a list that should have been refused (${reason})`);
    assert.equal(r.reason, reason);
  };

  test('a valid first list is accepted', () => {
    assert.deepEqual(deviceListAcceptable(null, list([device(1)])), { ok: true });
  });

  test('an unsigned list', () => {
    // The whole mechanism would be opt-out if omitting a field were enough.
    const { sig, ...noSig } = list([device(1)]);
    reject(noSig, 'unsigned');
    const { signPub, ...noKey } = list([device(1)]);
    reject(noKey, 'unsigned');
  });

  test('a list signed by the wrong key', () => {
    reject(signed({ idPub: ID, rev: 1, devices: [device(1)] }, other.privateKey, SIGN_PUB),
      'bad signature');
  });

  test('a list edited after signing', () => {
    const ok = list([device(1)]);
    reject({ ...ok, devices: [device(1), device(2)] }, 'bad signature');
    reject({ ...ok, rev: 9 }, 'bad signature');
    reject({ ...ok, idPub: 'b'.repeat(64) }, 'bad signature');
  });

  test('an empty list', () => {
    // Would silently un-deliver every device on the account.
    reject(list([]), 'empty');
  });

  test('more devices than the cap', () => {
    const many = Array.from({ length: MAX_DEVICES + 1 }, (_, i) => device(i % 9));
    // Distinct ids, so this fails on the cap and not on the duplicate check.
    many.forEach((d, i) => {
      d.deviceId = String(i).padStart(2, '0').repeat(8).slice(0, 16);
      d.devPub = String(i).padStart(2, '0').repeat(32).slice(0, 64);
    });
    reject(list(many), 'too many devices');
  });

  test('a duplicated device id or key', () => {
    const dup = { ...device(2), deviceId: devId(1) };
    reject(list([device(1), dup]), 'duplicate device id');
    const dupKey = { ...device(2), devPub: devPub(1) };
    reject(list([device(1), dupKey]), 'duplicate device key');
  });

  test('a malformed device entry', () => {
    reject(tampered({ devices: [{ deviceId: 'short', devPub: devPub(1), name: 'x' }] }),
      'malformed device');
    reject(tampered({ devices: [{ deviceId: devId(1), devPub: 'not-a-key', name: 'x' }] }),
      'malformed device');
    reject(tampered({ devices: [null] }), 'malformed device');
    reject(tampered({ devices: [{ deviceId: devId(1) }] }), 'malformed device');
  });

  test('hostile input is refused rather than thrown', () => {
    // deviceListAcceptable is the first thing an inbound list touches, so it
    // has to survive anything. A throw here is an unhandled rejection in the
    // frame handler, which takes the socket down.
    for (const bad of [null, undefined, 0, 'nope', [], { devices: [] }]) {
      assert.doesNotThrow(() => deviceListAcceptable(null, bad));
      assert.equal(deviceListAcceptable(null, bad).ok, false);
      assert.doesNotThrow(() => deviceListAcceptable(bad, list([device(1)])));
    }
  });

  test('a bad revision', () => {
    reject(list([device(1)], 0), 'bad revision');
    reject(list([device(1)], -1), 'bad revision');
    reject(list([device(1)], 1.5), 'bad revision');
  });

  test('a malformed account key', () => {
    reject(signed({ idPub: 'nope', rev: 1, devices: [device(1)] }), 'malformed');
    reject(tampered({ devices: 'not-an-array' }), 'malformed');
  });
});

describe('replacing a list we already hold', () => {
  const held = { ...list([device(1)]), idPub: ID };

  test('a higher revision is accepted', () => {
    const next = list([device(1), device(2)], 2);
    assert.equal(deviceListAcceptable(held, next).ok, true);
  });

  test('the same revision is refused', () => {
    // Replaying the current list at the same revision is how a revocation
    // published at that revision would be undone.
    const same = list([device(1), device(2)], 1);
    assert.equal(deviceListAcceptable(held, same).reason, 'stale revision');
  });

  test('a lower revision is refused', () => {
    const forward = list([device(1), device(2)], 5);
    assert.equal(deviceListAcceptable(forward, list([device(1)], 4)).reason, 'stale revision');
  });

  test('a different signing key is refused even though it verifies', () => {
    // The list is correctly signed, just by somebody else. This is precisely
    // what a substituted signing key looks like, so a valid signature is not
    // sufficient once a key has been pinned.
    const swapped = signed({ idPub: ID, rev: 2, devices: [device(9)] }, other.privateKey, OTHER_PUB);
    assert.equal(verifyDeviceList(
      { idPub: ID, rev: 2, devices: [device(9)] }, swapped.sig, OTHER_PUB), true,
      'the fixture is wrong: this list should verify under its own key');
    assert.equal(deviceListAcceptable(held, swapped).reason, 'signing key changed');
  });

  test('a list for a different account is refused', () => {
    const elsewhere = signed({ idPub: 'b'.repeat(64), rev: 2, devices: [device(1)] });
    assert.equal(deviceListAcceptable(held, elsewhere).reason, 'wrong account');
  });
});

describe('fan-out', () => {
  test('a peer with no list is not an error', () => {
    // An un-upgraded peer has one implicit device and the caller falls back to
    // addressing the account key, exactly as every existing session does.
    assert.equal(fanoutTargets(null), null);
    assert.equal(fanoutTargets({ devices: [] }), null);
    assert.equal(fanoutTargets({}), null);
  });

  test('every device is addressed', () => {
    const targets = fanoutTargets({ devices: [device(1), device(2), device(3)] });
    assert.equal(targets.length, 3, 'a device would silently stop receiving messages');
    assert.deepEqual(targets.map((t) => t.deviceId), [devId(1), devId(2), devId(3)]);
    assert.ok(targets.every((t) => t.devPub), 'a target with no key cannot be addressed');
  });
});

describe('editing the list', () => {
  test('adding a device bumps the revision', () => {
    const one = withDevice(null, { idPub: ID, ...device(1) });
    assert.equal(one.rev, 1);
    const two = withDevice(one, { idPub: ID, ...device(2) });
    assert.equal(two.rev, 2);
    assert.equal(two.devices.length, 2);
  });

  test('re-adding the same device replaces rather than appends', () => {
    // Reinstalling on the same phone must not grow the list every time.
    let l = withDevice(null, { idPub: ID, ...device(1) });
    for (let i = 0; i < 5; i++) {
      l = withDevice(l, { idPub: ID, deviceId: devId(1), devPub: devPub(7), name: 'Phone' });
    }
    assert.equal(l.devices.length, 1, `the list grew to ${l.devices.length} entries`);
    assert.equal(l.devices[0].devPub, devPub(7), 'the refreshed device key was not applied');
    assert.equal(l.rev, 6, 'the revision must still move forward on a replacement');
  });

  test('an unnamed device gets a default rather than an empty label', () => {
    const l = withDevice(null, { idPub: ID, deviceId: devId(1), devPub: devPub(1) });
    assert.equal(l.devices[0].name, DEFAULT_DEVICE_NAME);
  });

  test('removing a device bumps the revision and keeps the rest', () => {
    const two = withDevice(withDevice(null, { idPub: ID, ...device(1) }), { idPub: ID, ...device(2) });
    const one = withoutDevice(two, devId(1));
    assert.deepEqual(one.devices.map((d) => d.deviceId), [devId(2)]);
    assert.equal(one.rev, 3);
  });

  test('the last device cannot be removed', () => {
    const one = withDevice(null, { idPub: ID, ...device(1) });
    assert.equal(withoutDevice(one, devId(1)), null,
      'removing the last device would un-deliver the whole account');
  });

  test('an edited list still verifies after being re-signed', () => {
    // The round trip that matters: build, edit, sign, and have the gate accept
    // it. Testing the pieces separately would miss a field the encoder covers
    // and the editor does not populate.
    const first = withDevice(null, { idPub: ID, ...device(1) });
    const held = signed(first);
    assert.equal(deviceListAcceptable(null, held).ok, true);

    const second = withDevice(first, { idPub: ID, ...device(2) });
    assert.equal(deviceListAcceptable(held, signed(second)).ok, true);
  });
});

describe('session keys', () => {
  test('a peer with no device keeps its bare id', () => {
    // This is the entire migration story for sessions established before
    // devices existed. If it changed, every one of them would be orphaned and
    // every conversation would silently re-handshake.
    assert.equal(sessionKey(ID, null), ID);
    assert.equal(sessionKey(ID, undefined), ID);
    assert.equal(sessionKey(ID), ID);
  });

  test('each device gets its own key', () => {
    const a = sessionKey(ID, devId(1));
    const b = sessionKey(ID, devId(2));
    assert.notEqual(a, b, 'two devices would share one ratchet and clobber it');
    assert.notEqual(a, ID, 'a device session collided with the account session');
  });

  test('the peer is recoverable from either shape', () => {
    assert.equal(peerOfSessionKey(ID), ID);
    assert.equal(peerOfSessionKey(sessionKey(ID, devId(1))), ID);
  });

  test('every session for a peer is found, across devices', () => {
    // Deleting a contact has to take all of them. Matching the bare id alone
    // leaves per-device sessions behind, and a stale ratchet resurrects
    // itself on the next message.
    const other = 'b'.repeat(64);
    const sessions = {
      [ID]: {},
      [sessionKey(ID, devId(1))]: {},
      [sessionKey(ID, devId(2))]: {},
      [other]: {},
      [sessionKey(other, devId(1))]: {}
    };
    const found = sessionKeysFor(sessions, ID);
    assert.equal(found.length, 3, `expected 3 sessions for the peer, got ${found.length}`);
    assert.ok(found.includes(ID), 'the pre-device session was missed');
    assert.ok(!found.some((k) => k.startsWith(other)), "another peer's sessions were swept up");
  });

  test('an empty or missing session store is not an error', () => {
    assert.deepEqual(sessionKeysFor(null, ID), []);
    assert.deepEqual(sessionKeysFor({}, ID), []);
  });
});

describe('a device key is a real key', () => {
  test('a generated identity keypair is an acceptable device key', () => {
    // The fixtures above use repeated digits. This proves the format check
    // accepts what the app will actually produce.
    const kp = generateIdentityKeypair();
    const entry = { deviceId: devId(1), devPub: kp.publicKeyHex || bytesToHex(kp.publicKey), name: 'Real' };
    assert.equal(deviceListAcceptable(null, list([entry])).ok, true);
  });
});
