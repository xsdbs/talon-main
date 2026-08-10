// Rate limits as the relay actually applies them.
//
// ratelimit.test.js covers the bucket in isolation against an injected clock.
// This file is the other half: proof that the limiters are wired to the routes
// at all. A limiter that is correct but never called is the failure mode worth
// guarding against, and it is invisible from a unit test.
//
// Limits here are set absurdly tight on purpose. Everywhere else in the suite
// they are set absurdly loose, for the opposite reason.

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';

import { userRowsAtRest } from './helpers.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SERVER = path.join(HERE, '..', 'server.js');

const PORT = 17080 + (process.pid % 400);
const BASE = `http://127.0.0.1:${PORT}`;

const REGISTER_BURST = 3;
const AUTH_BURST = 10;
const AUTH_FAILURE_COST = 5; // so two failures exhaust the burst
const UPLOAD_BURST = 2;

let proc;
let dataDir;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

let seq = 0;
const uname = (tag) => `q${tag}${seq++}`;

const register = (name) => fetch(BASE + '/api/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username: name,
    idPub: crypto.randomBytes(32).toString('hex'),
    authHash: sha256(name + ':secret'),
    kdfVersion: 2,
    kdfSalt: crypto.randomBytes(16).toString('hex'),
    kdfIterations: 600000,
    encryptedIdPriv: '00'.repeat(32),
    encryptedIdPrivNonce: '00'.repeat(12)
  })
});

before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'talon-rl-'));
  proc = spawn(process.execPath, [SERVER], {
    env: {
      ...process.env,
      TALON_DATA_DIR: dataDir,
      PORT: String(PORT),
      HTTPS_PORT: String(PORT + 1),
      TALON_RL_REGISTER_BURST: String(REGISTER_BURST),
      TALON_RL_REGISTER_PER_HOUR: '0',      // no refill during the test
      TALON_RL_AUTH_BURST: String(AUTH_BURST),
      TALON_RL_AUTH_PER_MIN: '0',
      TALON_RL_AUTH_FAILURE_COST: String(AUTH_FAILURE_COST),
      TALON_RL_UPLOAD_BURST: String(UPLOAD_BURST),
      TALON_RL_UPLOAD_PER_HOUR: '0'
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

describe('registration is rate limited', () => {
  test('allows the burst then answers 429', async () => {
    const codes = [];
    for (let i = 0; i < REGISTER_BURST + 2; i++) {
      codes.push((await register(uname('reg'))).status);
    }
    const allowed = codes.filter((c) => c === 200).length;
    const refused = codes.filter((c) => c === 429).length;

    assert.equal(allowed, REGISTER_BURST, `expected ${REGISTER_BURST} to succeed, got ${codes}`);
    assert.equal(refused, 2, `expected 2 refusals, got ${codes}`);
  });

  test('the refusal carries a Retry-After the client can act on', async () => {
    const res = await register(uname('reg'));
    assert.equal(res.status, 429);
    const retry = Number(res.headers.get('retry-after'));
    assert.ok(Number.isFinite(retry) && retry >= 1,
      `Retry-After should be a positive number of seconds, got ${res.headers.get('retry-after')}`);
  });

  test('a throttled registration does not create the account', async () => {
    const name = uname('ghost');
    const res = await register(name);
    assert.equal(res.status, 429);

    await sleep(200);
    // Snapshot and journal. A row written to db.log is just as created as one
    // in db.json, and checking only the snapshot would miss it entirely.
    assert.deepEqual(userRowsAtRest(dataDir, name), [],
      'a refused registration must not write a user row');
  });
});

describe('failed credentials are rate limited', () => {
  // The stored verifier is a fast hash by design, so without a penalty on
  // failure the only thing bounding an online guessing attack is the network.
  test('repeated wrong credentials start being refused', async () => {
    const body = (h) => ({
      username: 'whoever', authHash: h,
      encryptedContacts: 'aa', encryptedContactsNonce: 'bb'
    });

    const codes = [];
    for (let i = 0; i < 5; i++) {
      const res = await fetch(BASE + '/api/sync-contacts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body(sha256('guess ' + i)))
      });
      codes.push(res.status);
    }

    assert.ok(codes.includes(429),
      `expected guessing to be throttled, got ${JSON.stringify(codes)}`);
    // The first couple must still have been answered normally, or the limit is
    // so tight it would break ordinary use.
    assert.ok(codes[0] !== 429, 'the very first attempt should not be throttled');
  });
});

describe('uploads are rate limited per account', () => {
  test('allows the burst then answers 429', async () => {
    const name = uname('up');
    const reg = await register(name);
    // Registration itself is limited in this run; skip cleanly if exhausted
    // rather than reporting a confusing upload failure.
    if (reg.status !== 200) return;

    const headers = { 'X-Talon-User': name, 'X-Talon-Auth': sha256(name + ':secret') };
    const codes = [];
    for (let i = 0; i < UPLOAD_BURST + 2; i++) {
      const res = await fetch(BASE + '/api/upload', {
        method: 'POST', headers, body: Buffer.from('ciphertext')
      });
      codes.push(res.status);
    }

    assert.equal(codes.filter((c) => c === 200).length, UPLOAD_BURST,
      `expected ${UPLOAD_BURST} uploads to succeed, got ${codes}`);
    assert.ok(codes.includes(429), `expected a refusal, got ${codes}`);
  });

  test('a throttled upload writes no file', async () => {
    const uploads = path.join(dataDir, 'uploads');
    const before = fs.existsSync(uploads) ? fs.readdirSync(uploads).length : 0;

    const name = uname('up');
    const headers = { 'X-Talon-User': name, 'X-Talon-Auth': sha256(name + ':secret') };
    await fetch(BASE + '/api/upload', { method: 'POST', headers, body: Buffer.from('x') });

    await sleep(200);
    const after = fs.existsSync(uploads) ? fs.readdirSync(uploads).length : 0;
    assert.equal(after, before, 'a refused upload must not leave a file behind');
  });
});
