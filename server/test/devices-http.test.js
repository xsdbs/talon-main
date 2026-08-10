// The device-list routes, driven against a real relay.
//
// persistence.test.js proves the storage layer behaves. This proves the
// routes are actually wired to it and are actually authenticated, which is a
// separate question: a correct Db method reached through a route that forgets
// verifyAuth is a worse bug than a broken Db method.
//
// The pairing with ratelimit-http.test.js is deliberate and the same idea.

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';

import { deviceListsAtRest, bytesAtRest } from './helpers.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SERVER = path.join(HERE, '..', 'server.js');

const PORT = 19400 + (process.pid % 400);
const BASE = `http://127.0.0.1:${PORT}`;

let proc;
let dataDir;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

async function post(route, body) {
  const res = await fetch(BASE + route, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  let json = null;
  try { json = await res.json(); } catch { /* non-JSON error body */ }
  return { status: res.status, json };
}

let seq = 0;
const uname = (tag) => `d${tag}${seq++}`.replace(/\W/g, '').slice(0, 20);

async function makeAccount(name) {
  const authHash = sha256(name + ':secret');
  const idPub = crypto.randomBytes(32).toString('hex');
  const r = await post('/api/register', {
    username: name,
    idPub,
    authHash,
    kdfVersion: 2,
    kdfSalt: crypto.randomBytes(16).toString('hex'),
    kdfIterations: 600000,
    encryptedIdPriv: '00'.repeat(32),
    encryptedIdPrivNonce: '00'.repeat(12)
  });
  assert.equal(r.json && r.json.success, true, `registration failed: ${JSON.stringify(r.json)}`);
  return { username: name, authHash, idPub };
}

const devKey = () => crypto.randomBytes(32).toString('hex');
const devId = () => crypto.randomBytes(8).toString('hex');

const device = (name = 'Phone') => ({ deviceId: devId(), devPub: devKey(), name });
const listOf = (rev, devices) => ({ rev, devices, sig: 'a'.repeat(128), signPub: 'b'.repeat(64) });

before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'talon-devhttp-'));
  proc = spawn(process.execPath, [SERVER], {
    env: {
      ...process.env,
      TALON_DATA_DIR: dataDir,
      TALON_RL_REGISTER_BURST: '100000',
      TALON_RL_AUTH_BURST: '100000',
      TALON_RL_UPLOAD_BURST: '100000',
      TALON_RL_SEND_BURST: '100000',
      PORT: String(PORT),
      HTTPS_PORT: String(PORT + 1)
    },
    stdio: 'pipe'
  });
  proc.stdout.on('data', () => {});
  proc.stderr.on('data', () => {});

  for (let i = 0; i < 120; i++) {
    try {
      const r = await fetch(BASE + '/api/kdf-params?username=nobody');
      if (r.status) return;
    } catch { await sleep(250); }
  }
  throw new Error('server did not come up');
});

after(async () => {
  if (proc) proc.kill();
  await sleep(300);
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* windows lock */ }
});

describe('publishing a device list', () => {
  test('an authenticated account can publish one', async () => {
    const a = await makeAccount(uname('pub'));
    const r = await post('/api/publish-devices', {
      username: a.username, authHash: a.authHash, list: listOf(1, [device()])
    });
    assert.equal(r.status, 200);
    assert.equal(r.json.success, true);
  });

  test('a wrong authHash is refused and stores nothing', async () => {
    // The route could look correct and still be the one place verifyAuth was
    // forgotten, which is exactly how anyone could rewrite anyone's devices.
    const a = await makeAccount(uname('noauth'));
    const r = await post('/api/publish-devices', {
      username: a.username, authHash: sha256('wrong'), list: listOf(1, [device()])
    });
    assert.equal(r.status, 401);

    await sleep(150);
    assert.deepEqual(deviceListsAtRest(dataDir, a.idPub), [],
      'an unauthorised publish reached the database');
  });

  test('a replayed revision is refused', async () => {
    const a = await makeAccount(uname('replay'));
    const two = [device('Phone'), device('Laptop')];
    await post('/api/publish-devices', {
      username: a.username, authHash: a.authHash, list: listOf(2, two)
    });

    const r = await post('/api/publish-devices', {
      username: a.username, authHash: a.authHash, list: listOf(2, [two[0]])
    });
    assert.equal(r.status, 400);
    assert.equal(r.json.error, 'stale revision');

    const fetched = await post('/api/devices', {
      username: a.username, authHash: a.authHash, peerId: a.idPub
    });
    assert.equal(fetched.json.list.devices.length, 2,
      'the replay revoked a device by rolling the list back');
  });

  test('a malformed list is refused with a reason', async () => {
    const a = await makeAccount(uname('bad'));
    for (const [list, reason] of [
      [listOf(1, []), 'malformed'],
      [listOf(0, [device()]), 'bad revision'],
      [{ ...listOf(1, [device()]), sig: null }, 'unsigned'],
      [listOf(1, Array.from({ length: 9 }, () => device())), 'too many devices']
    ]) {
      const r = await post('/api/publish-devices', {
        username: a.username, authHash: a.authHash, list
      });
      assert.equal(r.status, 400, `expected a refusal for ${reason}`);
      assert.equal(r.json.error, reason);
    }
  });
});

describe('fetching a peer device list', () => {
  test('a peer can read it, and gets exactly what was published', async () => {
    const a = await makeAccount(uname('owner'));
    const b = await makeAccount(uname('peer'));
    const d = device('Desktop');
    await post('/api/publish-devices', {
      username: a.username, authHash: a.authHash, list: listOf(1, [d])
    });

    const r = await post('/api/devices', {
      username: b.username, authHash: b.authHash, peerId: a.idPub
    });
    assert.equal(r.json.success, true);
    assert.equal(r.json.list.devices[0].devPub, d.devPub);
    assert.equal(r.json.list.sig, 'a'.repeat(128), 'the signature was not served back');
    assert.equal(r.json.list.signPub, 'b'.repeat(64), 'the signing key was not served back');
  });

  test('reading requires authentication', async () => {
    // The device layout of an account is not public.
    const a = await makeAccount(uname('shy'));
    const r = await post('/api/devices', {
      username: a.username, authHash: sha256('wrong'), peerId: a.idPub
    });
    assert.equal(r.status, 401);
  });

  test('an account with no list reads back null rather than an error', async () => {
    const a = await makeAccount(uname('single'));
    const r = await post('/api/devices', {
      username: a.username, authHash: a.authHash, peerId: 'f'.repeat(64)
    });
    assert.equal(r.status, 200);
    assert.equal(r.json.list, null);
  });
});

describe('prekeys become per device', () => {
  test('a bundle fetch returns one entry per device', async () => {
    const a = await makeAccount(uname('multi'));
    const b = await makeAccount(uname('sender'));
    const one = device('Phone');
    const two = device('Laptop');
    await post('/api/publish-devices', {
      username: a.username, authHash: a.authHash, list: listOf(1, [one, two])
    });

    for (const d of [one, two]) {
      const r = await post('/api/publish-prekeys', {
        username: a.username, authHash: a.authHash, deviceKey: d.devPub,
        signPub: 'c'.repeat(64),
        signedPreKey: { pub: 'd'.repeat(64), sig: 'e'.repeat(128) },
        oneTimePreKeys: [{ id: 1, pub: '11'.repeat(32) }, { id: 2, pub: '22'.repeat(32) }]
      });
      assert.equal(r.json.success, true);
      assert.equal(r.json.remaining, 2, 'the device pool was not counted separately');
    }

    const r = await post('/api/prekey-bundle', {
      username: b.username, authHash: b.authHash, peerId: a.idPub
    });
    assert.equal(r.json.devices.length, 2, 'a device would never receive anything');
    assert.ok(r.json.devices.every((e) => e.bundle && e.bundle.oneTimePreKey),
      'a device did not get a one-time prekey of its own');
    const ids = r.json.devices.map((e) => e.deviceId).sort();
    assert.deepEqual(ids, [one.deviceId, two.deviceId].sort());
  });

  test('a single-device peer still returns the legacy bundle', async () => {
    // The compatibility case. An un-upgraded client reads `bundle` and knows
    // nothing about `devices`, and must keep working untouched.
    const a = await makeAccount(uname('legacy'));
    const b = await makeAccount(uname('reader'));
    await post('/api/publish-prekeys', {
      username: a.username, authHash: a.authHash,
      signPub: 'c'.repeat(64),
      signedPreKey: { pub: 'd'.repeat(64), sig: 'e'.repeat(128) },
      oneTimePreKeys: [{ id: 1, pub: '11'.repeat(32) }]
    });

    const r = await post('/api/prekey-bundle', {
      username: b.username, authHash: b.authHash, peerId: a.idPub
    });
    assert.ok(r.json.bundle, 'the legacy single-device bundle stopped being served');
    assert.equal(r.json.bundle.oneTimePreKey.id, 1);
    assert.equal(r.json.devices, null);
  });

  test('a device key that is not a key falls back to the account pool', async () => {
    // Found by mutation testing: without the shape check, any authenticated
    // caller can create a prekey pool under an arbitrary string, which is an
    // unbounded map keyed by attacker input sitting in the database. The same
    // reasoning the rate limiter is swept for.
    const a = await makeAccount(uname('shape'));
    for (const bogus of ['x', '', 'not-hex-'.repeat(8), 'a'.repeat(63), 'a'.repeat(65), 'zz'.repeat(32)]) {
      await post('/api/publish-prekeys', {
        username: a.username, authHash: a.authHash, deviceKey: bogus,
        signPub: 'c'.repeat(64),
        signedPreKey: { pub: 'd'.repeat(64), sig: 'e'.repeat(128) },
        oneTimePreKeys: [{ id: 1, pub: '11'.repeat(32) }]
      });
    }

    await sleep(150);
    // Snapshot and journal together, through the shared helper. Reading
    // db.log directly is wrong: compaction removes it, so the file may not
    // exist at all by the time this runs.
    assert.equal(bytesAtRest(dataDir).includes('not-hex-'), false,
      'a prekey pool was created under an attacker-chosen key');

    // Each one fell back to the account pool instead, which is where a client
    // that sends no device key at all already lands.
    const account = await post('/api/prekey-count', {
      username: a.username, authHash: a.authHash
    });
    assert.equal(account.json.remaining, 6,
      'the malformed device keys did not fall back to the account pool');
  });

  test('publishing per device does not touch the account pool', async () => {
    const a = await makeAccount(uname('sep'));
    const d = device();
    await post('/api/publish-prekeys', {
      username: a.username, authHash: a.authHash, deviceKey: d.devPub,
      signPub: 'c'.repeat(64),
      signedPreKey: { pub: 'd'.repeat(64), sig: 'e'.repeat(128) },
      oneTimePreKeys: [{ id: 1, pub: '11'.repeat(32) }]
    });

    const account = await post('/api/prekey-count', {
      username: a.username, authHash: a.authHash
    });
    assert.equal(account.json.remaining, 0, 'the device pool leaked into the account pool');

    const perDevice = await post('/api/prekey-count', {
      username: a.username, authHash: a.authHash, deviceKey: d.devPub
    });
    assert.equal(perDevice.json.remaining, 1, 'the device could not read its own pool');
  });
});
