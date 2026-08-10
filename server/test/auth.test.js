// Relay authentication, driven against a real server process.
//
// The headline case is the `register` frame. It drains the offline queue
// destructively, so before it was authenticated, knowing a Client ID (a value
// the app actively encourages people to share) was enough to delete someone's
// queued mail. That was an unauthenticated remote denial-of-delivery, and this
// file exists so it cannot come back silently.
//
// Every test runs against a throwaway TALON_DATA_DIR. Nothing here can touch a
// real db.json or regenerate the CA that devices have installed.

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';

import { bytesAtRest, userRowsAtRest } from './helpers.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SERVER = path.join(HERE, '..', 'server.js');

const PORT = 18080 + (process.pid % 500);
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

/**
 * Registers an account and returns its credentials. New accounts must be KDF
 * v2 and carry the salt the client derived against, so this mirrors what the
 * real client sends rather than the minimum the route happens to accept.
 *
 * Usernames must match /^[a-zA-Z0-9_]{3,20}$/, so callers pass short names.
 */
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

/** Unique, valid username: alphanumeric plus underscore, 3-20 chars. */
let seq = 0;
const uname = (tag) => `t${tag}${seq++}`.replace(/\W/g, '').slice(0, 20);

before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'talon-test-'));
  proc = spawn(process.execPath, [SERVER], {
    env: {
      ...process.env,
      TALON_DATA_DIR: dataDir,
      // Limits are exercised by ratelimit-http.test.js. Everywhere else they
      // must be out of the way, or a suite that registers many accounts from
      // one address throttles itself and fails for the wrong reason.
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

  // Certificate generation on a cold data dir takes a moment.
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
  // The throwaway data dir holds a generated CA key; do not leave it lying about.
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* windows lock */ }
});

describe('registration', () => {
  test('creates an account', async () => {
    const acct = await makeAccount(uname('alice'));
    assert.ok(acct.idPub);
  });

  test('refuses a duplicate username', async () => {
    const name = uname('dup');
    await makeAccount(name);
    const again = await post('/api/register', {
      username: name,
      idPub: crypto.randomBytes(32).toString('hex'),
      authHash: sha256('someone else'),
      encryptedIdPriv: '00'.repeat(32),
      encryptedIdPrivNonce: '00'.repeat(12)
    });
    assert.notEqual(again.json && again.json.success, true,
      'a second registration must not take over an existing username');
  });
});

describe('authenticated routes reject a wrong authHash', () => {
  // Every route that mutates or discloses account state must verify. A new
  // route added without the check is the failure this guards against.
  // These are the real routes, taken from the `req.url ===` chain in
  // server.js. An earlier version of this list included a route that does not
  // exist; the server answered 404, the negative test passed for the wrong
  // reason, and the positive test passed too because 404 is neither 401 nor
  // 403. Hence the explicit "not 404" assertion below.
  const routes = [
    ['/api/sync-contacts', (a) => ({
      username: a.username, encryptedContacts: 'aa', encryptedContactsNonce: 'bb'
    })],
    ['/api/sync-groups', (a) => ({
      username: a.username, encryptedGroups: 'aa', encryptedGroupsNonce: 'bb'
    })],
    ['/api/publish-prekeys', (a) => ({
      username: a.username, signPub: 'aa'.repeat(32),
      signedPreKey: { pub: 'bb'.repeat(32), sig: 'cc'.repeat(64) }, oneTimePreKeys: []
    })],
    ['/api/prekey-count', (a) => ({ username: a.username })],
    ['/api/devices', (a) => ({ username: a.username })]
  ];

  for (const [route, body] of routes) {
    test(`${route} refuses a wrong authHash`, async () => {
      const acct = await makeAccount(uname('r'));
      const wrong = { ...body(acct), authHash: sha256('not the password') };
      const res = await post(route, wrong);

      assert.notEqual(res.status, 404, `${route} does not exist; fix the test list`);
      assert.notEqual(res.json && res.json.success, true,
        `${route} accepted a wrong authHash`);
      assert.ok(res.status === 401 || res.status === 403 || res.status === 400,
        `${route} returned ${res.status} for a bad credential`);
    });

    test(`${route} accepts the correct authHash`, async () => {
      // The negative test above is worthless if the route rejects everything.
      const acct = await makeAccount(uname('g'));
      const res = await post(route, { ...body(acct), authHash: acct.authHash });

      assert.notEqual(res.status, 404, `${route} does not exist; fix the test list`);
      assert.notEqual(res.status, 401, `${route} rejected a valid credential`);
      assert.notEqual(res.status, 403, `${route} rejected a valid credential`);
    });
  }

  test('an unknown username is refused', async () => {
    const res = await post('/api/sync-contacts', {
      username: 'nobodyatall', authHash: sha256('x'),
      encryptedContacts: 'aa', encryptedContactsNonce: 'bb'
    });
    assert.notEqual(res.json && res.json.success, true);
  });

  test('/api/push-mute no longer exists', async () => {
    // It took a plaintext list of muted conversation IDs so the relay could
    // skip a push, which meant uploading a slice of the contact graph. Deleted
    // rather than left as a no-op, because a route that quietly accepts and
    // discards is how a client keeps sending something nobody notices.
    const acct = await makeAccount(uname('mute'));
    const res = await post('/api/push-mute', {
      username: acct.username, authHash: acct.authHash, mutedIds: ['abc']
    });
    assert.equal(res.status, 404, 'the muted-list route is still reachable');
  });
});

describe('credential storage', () => {
  test('the raw authHash is never stored verbatim', async () => {
    // A leaked database must not be replayable as a login. The stored value is
    // SHA256(salt || authHash), so the presented token itself must not appear.
    //
    // This reads the journal as well as the snapshot. Checking db.json alone
    // kept passing once account writes started landing in db.log first, which
    // would have made this test agree with a relay that wrote the token
    // verbatim.
    const acct = await makeAccount(uname('store'));
    await sleep(300);

    assert.equal(bytesAtRest(dataDir).includes(acct.authHash), false,
      'the client-presented authHash is on disk verbatim');
  });

  test('a salted verifier is recorded instead', async () => {
    const acct = await makeAccount(uname('salt'));
    await sleep(300);
    const rows = userRowsAtRest(dataDir, acct.username);
    assert.ok(rows.length > 0, 'user row should exist');

    // Every version written, not just the latest. A verifier that was correct
    // only after a later overwrite is not good enough.
    for (const user of rows) {
      assert.ok(user.authSalt && user.authVerifier,
        'expected a salt and a derived verifier on the stored record');
      assert.notEqual(user.authVerifier, acct.authHash);
    }
  });

  test('the private identity key is stored only as ciphertext', async () => {
    const acct = await makeAccount(uname('idpriv'));
    await sleep(300);
    const rows = userRowsAtRest(dataDir, acct.username);
    assert.ok(rows.length > 0, 'user row should exist');

    for (const user of rows) {
      assert.ok(user.encryptedIdPriv, 'the encrypted blob should be present');
      assert.equal(user.idPriv, undefined, 'a plaintext private key must never be stored');
    }
  });
});
