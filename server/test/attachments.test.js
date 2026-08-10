// Attachment upload and download.
//
// These endpoints took no credential at all until now, which made /api/upload
// a disk-fill primitive for anyone who could reach the port, and made every
// blob readable by anyone who learned its id. Contents are always
// client-encrypted, so this was never a confidentiality break, but "the bytes
// are useless to you" is not a reason to let a stranger write to the disk.

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SERVER = path.join(HERE, '..', 'server.js');

const PORT = 19080 + (process.pid % 400);
const BASE = `http://127.0.0.1:${PORT}`;
const MAX_MB = 1; // keep the over-size test cheap

let proc;
let dataDir;
let acct;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

const authHeaders = (a) => ({ 'X-Talon-User': a.username, 'X-Talon-Auth': a.authHash });

async function makeAccount(name) {
  const authHash = sha256(name + ':secret');
  const res = await fetch(BASE + '/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: name,
      idPub: crypto.randomBytes(32).toString('hex'),
      authHash,
      kdfVersion: 2,
      kdfSalt: crypto.randomBytes(16).toString('hex'),
      kdfIterations: 600000,
      encryptedIdPriv: '00'.repeat(32),
      encryptedIdPrivNonce: '00'.repeat(12)
    })
  });
  const json = await res.json();
  assert.equal(json.success, true, `registration failed: ${JSON.stringify(json)}`);
  return { username: name, authHash };
}

const upload = (body, headers) =>
  fetch(BASE + '/api/upload', { method: 'POST', headers, body });

before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'talon-att-'));
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
      HTTPS_PORT: String(PORT + 1),
      TALON_MAX_UPLOAD_MB: String(MAX_MB)
    },
    stdio: 'pipe'
  });
  proc.stdout.on('data', () => {});
  proc.stderr.on('data', () => {});

  for (let i = 0; i < 120; i++) {
    try {
      const r = await fetch(BASE + '/api/kdf-params?username=nobody');
      if (r.status) break;
    } catch { await sleep(250); }
  }
  acct = await makeAccount('attuser');
});

after(async () => {
  if (proc) proc.kill();
  await sleep(300);
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* windows lock */ }
});

describe('upload requires a credential', () => {
  test('refuses an upload with no credential', async () => {
    const before = fs.readdirSync(path.join(dataDir, 'uploads')).length;
    const res = await upload(Buffer.from('malicious'), {});
    assert.equal(res.status, 401);

    await sleep(200);
    assert.equal(fs.readdirSync(path.join(dataDir, 'uploads')).length, before,
      'a refused upload must not leave a file behind');
  });

  test('refuses an upload with a wrong authHash', async () => {
    const res = await upload(Buffer.from('x'), {
      'X-Talon-User': acct.username, 'X-Talon-Auth': sha256('wrong')
    });
    assert.equal(res.status, 401);
  });

  test('refuses an upload for an unknown user', async () => {
    const res = await upload(Buffer.from('x'), {
      'X-Talon-User': 'ghost', 'X-Talon-Auth': sha256('x')
    });
    assert.equal(res.status, 401);
  });

  test('accepts an upload with a valid credential', async () => {
    const res = await upload(Buffer.from('ciphertext bytes'), authHeaders(acct));
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.success, true);
    assert.match(json.id, /^[0-9a-f-]{36}$/);
  });
});

describe('upload size cap', () => {
  test('refuses a file over the cap and leaves nothing behind', async () => {
    const uploadsDir = path.join(dataDir, 'uploads');
    const before = fs.readdirSync(uploadsDir).length;

    const tooBig = Buffer.alloc(MAX_MB * 1024 * 1024 + 64 * 1024, 7);
    let status = 0;
    try {
      status = (await upload(tooBig, authHeaders(acct))).status;
    } catch {
      // The server destroys the request mid-stream, which surfaces as a
      // transport error in some Node versions. Either shape is acceptable;
      // what matters is the file not surviving.
      status = 413;
    }
    assert.equal(status, 413, 'an over-size upload should be refused');

    await sleep(400);
    assert.equal(fs.readdirSync(uploadsDir).length, before,
      'a partial file must be cleaned up, or the GC keeps it for 30 days');
  });

  test('accepts a file just under the cap', async () => {
    const ok = Buffer.alloc(200 * 1024, 3);
    const res = await upload(ok, authHeaders(acct));
    assert.equal(res.status, 200);
  });
});

describe('download requires a credential', () => {
  let id;

  test('setup: upload a blob', async () => {
    const res = await upload(Buffer.from('the ciphertext'), authHeaders(acct));
    id = (await res.json()).id;
    assert.ok(id);
  });

  test('refuses a download with no credential', async () => {
    const res = await fetch(`${BASE}/api/download/${id}`);
    assert.equal(res.status, 401);
  });

  test('refuses a download with a wrong authHash', async () => {
    const res = await fetch(`${BASE}/api/download/${id}`, {
      headers: { 'X-Talon-User': acct.username, 'X-Talon-Auth': sha256('nope') }
    });
    assert.equal(res.status, 401);
  });

  test('serves the exact bytes to an authenticated caller', async () => {
    const res = await fetch(`${BASE}/api/download/${id}`, { headers: authHeaders(acct) });
    assert.equal(res.status, 200);
    assert.equal(await res.text(), 'the ciphertext');
  });

  test('marks the response private and varying on the credential', async () => {
    // It is cached for a year, so a shared cache handing one account's blob to
    // another would be a real leak.
    const res = await fetch(`${BASE}/api/download/${id}`, { headers: authHeaders(acct) });
    assert.match(res.headers.get('cache-control') || '', /private/);
    assert.match(res.headers.get('vary') || '', /X-Talon-User/i);
  });
});

describe('download id validation', () => {
  const badIds = ['..', '.', 'not-a-uuid', '../db.json', '%2e%2e', 'a'.repeat(200)];

  for (const bad of badIds) {
    test(`refuses ${JSON.stringify(bad)}`, async () => {
      const res = await fetch(`${BASE}/api/download/${bad}`, { headers: authHeaders(acct) });
      assert.ok(res.status === 400 || res.status === 404,
        `expected a rejection, got ${res.status}`);
      // Whatever happens, it must not be a successful read of something else.
      if (res.status === 200) assert.fail('served a file for a malformed id');
    });
  }

  test('a well-formed but unknown id is a 404', async () => {
    const res = await fetch(`${BASE}/api/download/${crypto.randomUUID()}`, {
      headers: authHeaders(acct)
    });
    assert.equal(res.status, 404);
  });
});
