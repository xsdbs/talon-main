// The journal: append-only persistence, replay and compaction.
//
// What is under test is what survives a crash, because when nothing crashes
// there was never a question. A snapshot rewritten on every mutation was slow
// but trivially correct; a journal is fast and has to earn the same trust.
//
// Three properties carry the whole design and each has a test that fails when
// it is broken:
//
//   1. Every mutation is on disk before the call returns.
//   2. A torn final record is discarded and everything before it survives.
//   3. Replaying a record that is already in the snapshot changes nothing,
//      because compaction deletes the journal only after the snapshot lands
//      and a crash in that window replays it a second time.
//
// Db is a module with load-at-import side effects, so each test gets a fresh
// TALON_DATA_DIR and a cache-busted import. That is also what makes "reload
// from disk" expressible at all.

import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath, pathToFileURL } from 'node:url';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';

import { declaredOps, HANDLED_OPS } from './helpers.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DB_MODULE = path.join(HERE, '..', 'db.js');

let dataDir;
let generation = 0;

/**
 * Imports a fresh copy of db.js against the current TALON_DATA_DIR, which
 * re-runs its boot path: read the snapshot, replay the journal, compact.
 *
 * The query string defeats the ESM module cache. Without it every "reload"
 * would hand back the already-loaded module and the tests would assert
 * against memory rather than against the disk.
 */
async function boot() {
  return import(`${pathToFileURL(DB_MODULE).href}?g=${++generation}`);
}

const snapshotPath = () => path.join(dataDir, 'db.json');
const journalPath = () => path.join(dataDir, 'db.log');
const readSnapshot = () => JSON.parse(fs.readFileSync(snapshotPath(), 'utf-8'));
const journal = () =>
  fs.existsSync(journalPath())
    ? fs.readFileSync(journalPath(), 'utf-8').split('\n').filter((l) => l.trim())
    : [];

const idPub = () => crypto.randomBytes(32).toString('hex');

/** The minimum a createUser call needs to look like a real v2 account. */
const account = (over = {}) => ({
  idPub: idPub(),
  kdfVersion: 2,
  kdfSalt: crypto.randomBytes(16).toString('hex'),
  kdfIterations: 600000,
  authSalt: crypto.randomBytes(16).toString('hex'),
  authVerifier: crypto.randomBytes(32).toString('hex'),
  encryptedIdPriv: 'ciphertext',
  encryptedIdPrivNonce: 'nonce',
  ...over
});

beforeEach(() => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'talon-journal-'));
  process.env.TALON_DATA_DIR = dataDir;
  // A floor of zero means "compact only when the journal outgrows the
  // snapshot", which keeps the threshold tests honest about the real rule
  // instead of hiding behind a 64 KB allowance no test would ever reach.
  delete process.env.TALON_DB_LOG_MIN_BYTES;
});

afterEach(() => {
  delete process.env.TALON_DATA_DIR;
  delete process.env.TALON_DB_LOG_MIN_BYTES;
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* windows lock */ }
});

describe('a mutation reaches disk before it returns', () => {
  test('a fresh database creates a snapshot and no journal', async () => {
    await boot();
    assert.ok(fs.existsSync(snapshotPath()), 'no snapshot was written');
    assert.deepEqual(journal(), [], 'a brand new database should have nothing to replay');
  });

  test('a queued message is in the journal immediately', async () => {
    process.env.TALON_DB_LOG_MIN_BYTES = '1000000';
    const { Db } = await boot();

    const before = fs.statSync(snapshotPath()).size;
    Db.addOfflineMessage('a'.repeat(64), 'b'.repeat(64), { ct: 'x' });

    assert.equal(journal().length, 1, 'the mutation did not reach the journal');
    assert.equal(fs.statSync(snapshotPath()).size, before,
      'the snapshot was rewritten, which is the cost this design exists to remove');
  });

  test('the queue no longer pays for its own size on every write', async () => {
    // The point of the whole change. Adding the hundredth message must cost
    // about what adding the first did, not a copy of the ninety-nine.
    process.env.TALON_DB_LOG_MIN_BYTES = '100000000';
    const { Db } = await boot();

    const journalSize = () => (fs.existsSync(journalPath()) ? fs.statSync(journalPath()).size : 0);
    const growth = [];
    for (let i = 0; i < 100; i++) {
      const was = journalSize();
      Db.addOfflineMessage('a'.repeat(64), 'b'.repeat(64), { ct: 'x'.repeat(200) });
      growth.push(journalSize() - was);
    }

    const first = growth[0];
    const last = growth[growth.length - 1];
    assert.ok(last < first * 2,
      `the hundredth write cost ${last} bytes against the first at ${first}, so it is still O(queue)`);
  });
});

describe('reload', () => {
  test('every mutator survives a restart', async () => {
    // Enumerated below rather than spot-checked, and guarded by the coverage
    // test at the bottom of this file, because a mutator that persists
    // nothing looks completely fine until the relay is restarted.
    const { Db } = await boot();
    const alice = account();
    const key = idPub();

    Db.createUser('alice', alice);
    Db.updateUserContacts('alice', 'contacts-ct', 'contacts-nonce');
    Db.updateUserGroups('alice', 'groups-ct', 'groups-nonce');
    Db.setAuthVerifier('alice', 'salt2', 'verifier2');
    Db.upgradeUserKdf('alice', {
      kdfVersion: 2, kdfSalt: 's', kdfIterations: 600000,
      authSalt: 's2', authVerifier: 'v2',
      encryptedIdPriv: 'new-ct', encryptedIdPrivNonce: 'new-nonce'
    });
    Db.publishPreKeys(key, {
      signPub: 'sp', signedPreKey: { pub: 'p', sig: 's' },
      kemPreKey: { pub: 'k', sig: 's' },
      oneTimePreKeys: [{ id: 1, pub: 'o1' }, { id: 2, pub: 'o2' }]
    });
    Db.takePreKeyBundle(key);
    Db.addPushSubscription(key, { endpoint: 'https://push/1', keys: { p256dh: 'p', auth: 'a' } });
    Db.addPushSubscription(key, { endpoint: 'https://push/2', keys: { p256dh: 'p', auth: 'a' } });
    Db.removePushSubscription(key, 'https://push/1');
    Db.setDeviceList(key, {
      idPub: key, rev: 3, sig: 'sig', signPub: 'spub',
      devices: [{ deviceId: '1'.repeat(16), devPub: 'd'.repeat(64), name: 'Phone' }]
    });
    Db.addOfflineMessage('sender', 'recipient', { ct: 'queued' });
    Db.addOfflineMessage('sender', 'other', { ct: 'stays' });
    Db.getAndClearOfflineMessages('recipient');

    const fresh = (await boot()).Db;
    const user = fresh.getUser('alice');

    assert.equal(user.encryptedContacts, 'contacts-ct', 'contacts were lost');
    assert.equal(user.encryptedGroups, 'groups-ct', 'groups were lost');
    assert.equal(user.encryptedIdPriv, 'new-ct', 'the KDF upgrade was lost');
    assert.equal(user.authVerifier, 'v2', 'the auth verifier was lost');
    assert.equal(user.authHash, null, 'the legacy token came back');

    assert.equal(fresh.countOneTimePreKeys(key), 1,
      'the consumed one-time prekey came back, which undoes forward secrecy');

    const subs = fresh.getPushSubscriptions(key);
    assert.deepEqual(subs.map((s) => s.endpoint), ['https://push/2'],
      'the removed push subscription came back');

    const devices = fresh.getDeviceList(key);
    assert.ok(devices, 'the device list was lost');
    assert.equal(devices.rev, 3);
    assert.equal(devices.devices[0].name, 'Phone');

    // The drained recipient is gone and the untouched one survived. Asserting
    // only that the drained queue is empty would also pass if the reload had
    // simply lost every queued message.
    assert.deepEqual(fresh.getAndClearOfflineMessages('recipient'), []);
    const other = fresh.getAndClearOfflineMessages('other');
    assert.equal(other.length, 1, 'an unrelated queued message was lost on reload');
    assert.equal(other[0].payload.ct, 'stays');
  });

  test('the journal is folded into the snapshot at boot', async () => {
    process.env.TALON_DB_LOG_MIN_BYTES = '1000000';
    const first = (await boot()).Db;
    first.createUser('bob', account());
    assert.ok(journal().length > 0, 'nothing was journalled to begin with');

    await boot();

    assert.deepEqual(journal(), [],
      'the journal carried across a restart, so it grows forever');
    assert.ok(readSnapshot().users.bob, 'the replayed record never reached the snapshot');
  });

  test('a database written before the journal existed still loads', async () => {
    // Backwards compatibility. An existing relay has a db.json and no db.log,
    // which must be read exactly as before.
    fs.writeFileSync(snapshotPath(), JSON.stringify({
      users: { carol: { username: 'carol', idPub: 'k', authHash: 'legacy' } },
      offlineMessages: [{ id: 'm1', recipientId: 'r', payload: {} }],
      pushSubscriptions: {},
      preKeys: {}
    }, null, 2));

    const { Db } = await boot();
    assert.equal(Db.getUser('carol').authHash, 'legacy');
    assert.equal(Db.getAndClearOfflineMessages('r').length, 1);
  });

  test('the muted list is still removed from a legacy database', async () => {
    fs.writeFileSync(snapshotPath(), JSON.stringify({
      users: {}, offlineMessages: [], pushSubscriptions: {}, preKeys: {},
      mutedIds: { someIdPub: ['contact-a', 'group-b'] }
    }, null, 2));

    await boot();

    const raw = fs.readFileSync(snapshotPath(), 'utf-8');
    assert.equal(raw.includes('mutedIds'), false, 'the contact-graph slice is still on disk');
    assert.equal(raw.includes('group-b'), false);
  });
});

describe('a crash', () => {
  /** Writes state, then simulates losing power mid-append. */
  async function tornTail() {
    process.env.TALON_DB_LOG_MIN_BYTES = '1000000';
    const { Db } = await boot();
    Db.createUser('dave', account());
    Db.addOfflineMessage('s', 'r', { ct: 'survives' });

    const raw = fs.readFileSync(journalPath(), 'utf-8');
    // A record that never finished being written: valid lines, then a
    // fragment with no newline behind it.
    fs.writeFileSync(journalPath(), `${raw}{"op":"queue","k":null,"v":{"id":"tor`);
  }

  test('a torn final record is discarded and the rest survives', async () => {
    await tornTail();
    const { Db } = await boot();

    assert.ok(Db.getUser('dave'), 'a complete record before the tear was thrown away');
    const queued = Db.getAndClearOfflineMessages('r');
    assert.equal(queued.length, 1, 'the completed queue record was thrown away with the torn one');
    assert.equal(queued[0].payload.ct, 'survives');
  });

  test('a torn record does not survive into the next snapshot', async () => {
    await tornTail();
    await boot();

    assert.deepEqual(journal(), [], 'the torn journal was left in place to be re-read forever');
    assert.equal(fs.readFileSync(snapshotPath(), 'utf-8').includes('"tor'), false);
  });

  test('a damaged record stops the replay rather than skipping it', async () => {
    // Skipping would apply later records to a state their predecessors never
    // produced. The journal is an ordered sequence, so a hole in the middle
    // means the tail cannot be trusted.
    process.env.TALON_DB_LOG_MIN_BYTES = '1000000';
    const { Db } = await boot();
    Db.addOfflineMessage('s', 'r', { ct: 'before' });
    const good = fs.readFileSync(journalPath(), 'utf-8');
    Db.addOfflineMessage('s', 'r', { ct: 'after' });
    const both = fs.readFileSync(journalPath(), 'utf-8');
    const tail = both.slice(good.length);

    fs.writeFileSync(journalPath(), `${good}{ this is not json }\n${tail}`);

    const fresh = (await boot()).Db;
    const queued = fresh.getAndClearOfflineMessages('r');
    assert.equal(queued.length, 1, 'replay continued past the damage');
    assert.equal(queued[0].payload.ct, 'before');
  });

  test('an unknown record stops the replay', async () => {
    // What a downgrade looks like: a journal written by a newer relay that
    // knows an operation this one does not. Guessing would corrupt state.
    process.env.TALON_DB_LOG_MIN_BYTES = '1000000';
    const { Db } = await boot();
    Db.addOfflineMessage('s', 'r', { ct: 'before' });
    const good = fs.readFileSync(journalPath(), 'utf-8');

    fs.writeFileSync(journalPath(),
      `${good}{"op":"invent","k":"r","v":null}\n{"op":"drain","k":"r","v":null}\n`);

    const fresh = (await boot()).Db;
    assert.equal(fresh.getAndClearOfflineMessages('r').length, 1,
      'the drain after the unknown record was applied anyway');
  });

  test('a journal with no snapshot is still replayed', async () => {
    // Compaction renames the snapshot into place before deleting the journal,
    // so a lost snapshot with a live journal is recoverable rather than fatal.
    process.env.TALON_DB_LOG_MIN_BYTES = '1000000';
    const { Db } = await boot();
    Db.createUser('erin', account());
    fs.rmSync(snapshotPath());

    const fresh = (await boot()).Db;
    assert.ok(fresh.getUser('erin'), 'the account was lost with the snapshot');
  });

  test('replaying a record already in the snapshot changes nothing', async () => {
    // The exact crash window: compaction wrote the snapshot and was killed
    // before it deleted the journal. Every op has to be idempotent or the
    // next boot double-applies. `queue` is the one that would not be, which
    // is why it checks the message id.
    process.env.TALON_DB_LOG_MIN_BYTES = '1000000';
    const { Db } = await boot();
    Db.addOfflineMessage('s', 'r', { ct: 'once' });
    Db.createUser('frank', account());
    const stale = fs.readFileSync(journalPath(), 'utf-8');

    await boot();                                  // compacts, clears journal
    fs.writeFileSync(journalPath(), stale);        // the crash: journal survives

    const fresh = (await boot()).Db;
    const queued = fresh.getAndClearOfflineMessages('r');
    assert.equal(queued.length, 1,
      `the message was delivered ${queued.length} times after a crash during compaction`);
    assert.ok(fresh.getUser('frank'));
  });
});

describe('a disk that refuses to be written', () => {
  // Both cases below make one of the two writes fail for real, by putting a
  // directory where the file needs to go. Nothing is stubbed, so what is
  // under test is the actual failure path rather than a simulation of it.

  test('a failed snapshot write leaves the journal intact', async () => {
    // This is what makes the order inside compact() matter. Clearing the
    // journal before the new snapshot is safely in place would throw away
    // every mutation since the last one whenever the write failed.
    process.env.TALON_DB_LOG_MIN_BYTES = '0';
    fs.mkdirSync(path.join(dataDir, 'db.json.tmp'));   // every snapshot write now fails

    const { Db } = await boot();
    Db.createUser('gwen', account());
    Db.addOfflineMessage('s', 'r', { ct: 'kept' });

    assert.ok(journal().length >= 2,
      'the journal was cleared even though no snapshot was written, so the data is gone');

    fs.rmSync(path.join(dataDir, 'db.json.tmp'), { recursive: true, force: true });
    const fresh = (await boot()).Db;
    assert.ok(fresh.getUser('gwen'), 'the account did not survive a failed snapshot write');
    assert.equal(fresh.getAndClearOfflineMessages('r').length, 1,
      'the queued message did not survive a failed snapshot write');
  });

  test('a failed journal append falls back to a snapshot', async () => {
    // The mutation is already live in memory, so giving up here would leave
    // the running relay and the disk disagreeing until the next restart.
    process.env.TALON_DB_LOG_MIN_BYTES = '1000000';
    const { Db } = await boot();
    fs.mkdirSync(journalPath());                       // every append now fails

    Db.createUser('hank', account());

    assert.ok(readSnapshot().users.hank,
      'the mutation reached neither the journal nor the snapshot');
  });
});

describe('compaction', () => {
  test('happens once the journal outgrows the snapshot', async () => {
    process.env.TALON_DB_LOG_MIN_BYTES = '0';
    const { Db } = await boot();

    for (let i = 0; i < 40; i++) {
      Db.addOfflineMessage('s', `r${i}`, { ct: 'x'.repeat(500) });
    }

    assert.ok(fs.statSync(snapshotPath()).size > 1000,
      'the snapshot never absorbed the journal');
    assert.ok(journal().length < 40,
      `the journal still holds ${journal().length} records, so it never compacted`);
  });

  test('does not happen while the journal is still small', async () => {
    process.env.TALON_DB_LOG_MIN_BYTES = '1000000';
    const { Db } = await boot();
    for (let i = 0; i < 20; i++) Db.addOfflineMessage('s', 'r', { ct: 'x' });

    assert.equal(journal().length, 20,
      'it compacted early, which gives back the write amplification this replaced');
  });

  test('nothing is lost across a compaction boundary', async () => {
    // The dangerous moment is the handover. A message written just before the
    // fold and one written just after must both be there.
    process.env.TALON_DB_LOG_MIN_BYTES = '0';
    const { Db } = await boot();

    const ids = [];
    for (let i = 0; i < 60; i++) {
      ids.push(Db.addOfflineMessage('s', 'r', { ct: 'x'.repeat(300) }).id);
    }

    const fresh = (await boot()).Db;
    const got = fresh.getAndClearOfflineMessages('r').map((m) => m.id);
    assert.deepEqual(got.sort(), ids.sort(),
      'messages went missing around a compaction');
  });
});

describe('the journal reveals no more than the snapshot', () => {
  test('a drain record names a recipient and the buckets it emptied', async () => {
    // The buckets are device ids, which the relay already routes on. Anything
    // beyond that would be new metadata written to disk, so the record shape
    // is asserted exactly rather than loosely.
    process.env.TALON_DB_LOG_MIN_BYTES = '1000000';
    const { Db } = await boot();
    Db.addOfflineMessage('sender-id', 'recipient-id', { ct: 'x' }, '1'.repeat(16));
    Db.getAndClearOfflineMessages('recipient-id', ['1'.repeat(16), 'account']);

    const drain = journal().map((l) => JSON.parse(l)).find((r) => r.op === 'drain');
    assert.deepEqual(drain, {
      op: 'drain', k: 'recipient-id', v: ['1'.repeat(16), 'account']
    });
  });

  test('a queued record carries no clock beyond the day', async () => {
    // The offline queue deliberately stopped recording when anything was
    // written. A journal that stamped its own records would put that back.
    process.env.TALON_DB_LOG_MIN_BYTES = '1000000';
    const { Db } = await boot();
    Db.addOfflineMessage('s', 'r', { ct: 'x' });

    const rec = JSON.parse(journal()[0]);
    const DAY = 24 * 60 * 60 * 1000;
    assert.equal(rec.v.queuedDay % DAY, 0, 'the queue is recording a finer time than a day');
    assert.deepEqual(Object.keys(rec).sort(), ['k', 'op', 'v'],
      'the journal record grew a field, check it is not a timestamp');
    assert.equal(Object.keys(rec.v).includes('timestamp'), false);
  });
});

describe('device lists on the relay', () => {
  const ID = 'a'.repeat(64);
  const dev = (n, name = 'Phone') => ({
    deviceId: String(n).repeat(16).slice(0, 16),
    devPub: String(n).repeat(64).slice(0, 64),
    name
  });
  const list = (rev, devices) => ({ idPub: ID, rev, devices, sig: 'sig', signPub: 'spub' });

  test('a first list is stored', async () => {
    const { Db } = await boot();
    assert.deepEqual(Db.setDeviceList(ID, list(1, [dev(1)])), { ok: true });
    assert.equal(Db.getDeviceList(ID).devices.length, 1);
  });

  test('a stale revision is refused', async () => {
    // The relay does not verify the signature, so revision monotonicity is
    // the one thing standing between a captured publish and a revoked device
    // being reinstated by replaying it.
    const { Db } = await boot();
    Db.setDeviceList(ID, list(5, [dev(1), dev(2)]));
    assert.equal(Db.setDeviceList(ID, list(4, [dev(1)])).reason, 'stale revision');
    assert.equal(Db.setDeviceList(ID, list(5, [dev(1)])).reason, 'stale revision');
    assert.equal(Db.getDeviceList(ID).devices.length, 2, 'the replay took effect anyway');
  });

  test('a malformed list is refused', async () => {
    const { Db } = await boot();
    assert.equal(Db.setDeviceList(ID, null).reason, 'malformed');
    assert.equal(Db.setDeviceList(ID, list(1, [])).reason, 'malformed');
    assert.equal(Db.setDeviceList(ID, list(0, [dev(1)])).reason, 'bad revision');
    assert.equal(Db.setDeviceList(ID, { ...list(1, [dev(1)]), sig: null }).reason, 'unsigned');
    const many = Array.from({ length: 9 }, (_, i) => dev(i));
    assert.equal(Db.setDeviceList(ID, list(1, many)).reason, 'too many devices');
    assert.equal(Db.getDeviceList(ID), null, 'a refused list was stored anyway');
  });

  test('only protocol fields are kept', async () => {
    // Otherwise the relay is free storage addressed to your own account, and
    // whatever a client invents is handed to every peer that asks.
    const { Db } = await boot();
    Db.setDeviceList(ID, {
      ...list(1, [{ ...dev(1), secretNote: 'smuggled' }]),
      extra: 'smuggled'
    });
    const stored = JSON.stringify(Db.getDeviceList(ID));
    assert.equal(stored.includes('smuggled'), false, `stored: ${stored}`);
  });

  test('bundles come back one per device, each consuming its own prekey', async () => {
    const { Db } = await boot();
    Db.setDeviceList(ID, list(1, [dev(1), dev(2)]));
    for (const d of [dev(1), dev(2)]) {
      Db.publishPreKeys(d.devPub, {
        signPub: 'sp', signedPreKey: { pub: 'p', sig: 's' },
        oneTimePreKeys: [{ id: 1, pub: 'o1' }, { id: 2, pub: 'o2' }]
      });
    }

    const bundles = Db.takeDeviceBundles(ID);
    assert.equal(bundles.length, 2, 'a device would silently never receive anything');
    assert.ok(bundles.every((b) => b.bundle && b.bundle.oneTimePreKey),
      'a device did not get a one-time prekey of its own');

    // One consumed from each pool, not two from one.
    for (const d of [dev(1), dev(2)]) {
      assert.equal(Db.countOneTimePreKeys(d.devPub), 1,
        'devices are sharing a one-time prekey pool');
    }
  });

  test('a device with no prekeys is reported, not dropped', async () => {
    // Dropping it would mean a device that quietly never receives anything,
    // which is the hardest kind of bug to see from the outside.
    const { Db } = await boot();
    Db.setDeviceList(ID, list(1, [dev(1), dev(2)]));
    Db.publishPreKeys(dev(1).devPub, {
      signPub: 'sp', signedPreKey: { pub: 'p', sig: 's' }, oneTimePreKeys: []
    });

    const bundles = Db.takeDeviceBundles(ID);
    assert.equal(bundles.length, 2);
    assert.equal(bundles.find((b) => b.deviceId === dev(2).deviceId).bundle, null);
  });

  test('an account with no list falls back to the account key', async () => {
    // An un-upgraded peer. Returning an empty array instead of null would
    // make the sender believe the account has no reachable devices.
    const { Db } = await boot();
    assert.equal(Db.takeDeviceBundles(ID), null);
    Db.publishPreKeys(ID, { signPub: 'sp', signedPreKey: { pub: 'p', sig: 's' }, oneTimePreKeys: [] });
    assert.ok(Db.takePreKeyBundle(ID), 'the legacy single-device path stopped working');
  });
});

describe('the offline queue is per device', () => {
  const R = 'r'.repeat(64);
  const A = '1'.repeat(16);
  const B = '2'.repeat(16);

  test('a device drains only its own queue', async () => {
    const { Db } = await boot();
    Db.addOfflineMessage('s', R, { ct: 'for-a' }, A);
    Db.addOfflineMessage('s', R, { ct: 'for-b' }, B);

    const forA = Db.getAndClearOfflineMessages(R, [A]);
    assert.equal(forA.length, 1, 'a device drained the wrong number of messages');
    assert.equal(forA[0].payload.ct, 'for-a');

    // The other device's mail is still there. Asserting only that A got one
    // message would also pass if B's had been deleted along with it.
    const forB = Db.getAndClearOfflineMessages(R, [B]);
    assert.equal(forB.length, 1, "one device's drain destroyed another's mail");
    assert.equal(forB[0].payload.ct, 'for-b');
  });

  test('a device also drains the account bucket', async () => {
    // Envelopes queued by a sender that never heard of devices would
    // otherwise sit behind a device id no client will ever claim.
    const { Db } = await boot();
    Db.addOfflineMessage('s', R, { ct: 'legacy' });
    const got = Db.getAndClearOfflineMessages(R, [A, 'account']);
    assert.equal(got.length, 1, 'an account-bucket message was stranded');
  });

  test('a single-device client sees only the account bucket', async () => {
    // The compatibility path: passing no buckets must behave exactly as the
    // single-device relay did.
    const { Db } = await boot();
    Db.addOfflineMessage('s', R, { ct: 'legacy' });
    Db.addOfflineMessage('s', R, { ct: 'for-a' }, A);

    const got = Db.getAndClearOfflineMessages(R);
    assert.deepEqual(got.map((m) => m.payload.ct), ['legacy']);
    assert.equal(Db.queuedDevicesFor(R).length, 1, "the other device's mail was taken");
  });

  test('a row written before devices existed is read as the account bucket', async () => {
    // A relay upgraded in place has rows with no recipientDev at all.
    fs.writeFileSync(snapshotPath(), JSON.stringify({
      users: {}, pushSubscriptions: {}, preKeys: {}, deviceLists: {},
      offlineMessages: [{ id: 'old', recipientId: R, payload: { ct: 'old' } }]
    }, null, 2));

    const { Db } = await boot();
    const got = Db.getAndClearOfflineMessages(R, [A, 'account']);
    assert.equal(got.length, 1, 'a message queued before the upgrade became undeliverable');
  });

  test('draining survives a restart per device', async () => {
    process.env.TALON_DB_LOG_MIN_BYTES = '1000000';
    const { Db } = await boot();
    Db.addOfflineMessage('s', R, { ct: 'for-a' }, A);
    Db.addOfflineMessage('s', R, { ct: 'for-b' }, B);
    Db.getAndClearOfflineMessages(R, [A]);

    const fresh = (await boot()).Db;
    assert.deepEqual(fresh.getAndClearOfflineMessages(R, [A]), [],
      'a drained message came back after a restart');
    assert.equal(fresh.getAndClearOfflineMessages(R, [B]).length, 1,
      "the other device's mail was lost across the restart");
  });
});

describe('journal coverage', () => {
  test('the shared helpers understand every operation db.js can write', () => {
    // Other suites read the database through test/helpers.js to assert what
    // is and is not stored. A new operation those helpers skip would narrow
    // what they inspect without failing anything, which is how a credential
    // check quietly stops checking.
    const src = fs.readFileSync(DB_MODULE, 'utf-8');
    const declared = declaredOps(src);

    assert.ok(declared.length >= 5,
      `only found ${declared.length} operations, the scanner has stopped matching`);

    const unhandled = declared.filter((op) => !HANDLED_OPS.includes(op));
    assert.deepEqual(unhandled, [],
      `test/helpers.js does not know about: ${unhandled.join(', ')}`);
  });


  test('every mutator in db.js is exercised by the restart test', () => {
    // The lesson from the vault suite, applied before it can bite: a
    // hand-written list of mutators silently exempts the next one added. This
    // reads db.js for the call sites instead of trusting the list above.
    const whole = fs.readFileSync(DB_MODULE, 'utf-8').split('\r\n').join('\n');
    const self = fs.readFileSync(fileURLToPath(import.meta.url), 'utf-8');

    // Only the Db object literal. The module-level helpers above it are
    // indented the same way, so scanning the whole file picks up the `if` and
    // `for` inside replayJournal and calls them mutators.
    const start = whole.indexOf('export const Db = {');
    assert.ok(start > 0, 'the Db object literal moved, this scanner is now blind');
    const src = whole.slice(start);

    // Method names that contain a record() call, found by walking forward from
    // each method header to the next one.
    const headers = [...src.matchAll(/^  (\w+)\s*\(/gm)];
    const mutators = headers
      .filter(([, name], i) => {
        const from = headers[i].index;
        const to = i + 1 < headers.length ? headers[i + 1].index : src.length;
        return /\brecord\(/.test(src.slice(from, to));
      })
      .map(([, name]) => name);

    assert.ok(mutators.length >= 11,
      `only found ${mutators.length} mutators, the scanner has stopped matching`);

    const missing = mutators.filter((name) => !new RegExp(`Db\\.${name}\\(`).test(self));
    assert.deepEqual(missing, [],
      `these mutators persist state but no test restarts to check it: ${missing.join(', ')}`);
  });
});
