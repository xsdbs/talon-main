// What the relay writes down about its users.
//
// The log has always been more revealing than db.json. Message content was
// never in it, but the username, the client IP, the routing pair and a line
// naming the conversation someone had open right now all were, in plain text.
//
// Two halves here, and the second is the one that matters. The first drives
// the redaction helpers directly. The second captures the real stdout of a
// real relay through register, login, sync, upload and a WebSocket send, then
// asserts that no username, identity key, IP or attachment id appears in any
// of it. Testing the helper is not the same as testing that the helper is
// wired to every call site, and the call sites are the whole point.

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';

import { queuedRowsAtRest } from './helpers.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SERVER = path.join(HERE, '..', 'server.js');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

/* ------------------------------------------------------------- unit half */

describe('the redaction helpers', () => {
  let R;
  before(async () => { R = await import('../redact.js'); });

  test('strict is the default', () => {
    assert.equal(R.LOG_PRIVACY, 'strict');
    assert.equal(R.redacting, true);
  });

  test('a tag is stable within a run', () => {
    assert.equal(R.tag('alice'), R.tag('alice'));
  });

  test('different inputs get different tags', () => {
    assert.notEqual(R.tag('alice'), R.tag('bob'));
  });

  test('a tag contains none of its input', () => {
    // The reason this is an HMAC under a random per-boot salt rather than a
    // truncated hash: usernames and identity keys both come from small,
    // guessable spaces, and a captured log must not be brute-forceable.
    const idPub = 'a4c123b1612dd272d1371c17149d439536b3216fdaeeb975729fae923d5a4fd1';
    const t = R.tag(idPub);
    assert.equal(t.includes(idPub.substring(0, 8)), false);
    assert.ok(t.length <= 8, `tags should stay short, got ${t}`);
  });

  test('an empty identity is named rather than blank', () => {
    assert.equal(R.tag(''), 'anon');
    assert.equal(R.tag(null), 'anon');
    assert.equal(R.tag(undefined), 'anon');
  });

  test('addresses collapse to a class', () => {
    assert.equal(R.ip('127.0.0.1'), 'local');
    assert.equal(R.ip('::1'), 'local');
    assert.equal(R.ip('::ffff:127.0.0.1'), 'local');
    assert.equal(R.ip('100.93.64.18'), 'tailnet');
    assert.equal(R.ip('::ffff:100.64.0.1'), 'tailnet');
    assert.equal(R.ip('8.8.8.8'), 'remote');
    assert.equal(R.ip(''), 'unknown');
  });

  test('an address never survives as digits', () => {
    for (const addr of ['100.93.64.18', '192.168.1.55', '8.8.8.8']) {
      assert.equal(R.ip(addr).includes('.'), false, `${addr} leaked through`);
    }
  });

  test('identifiers are stripped from request paths', () => {
    assert.equal(
      R.url('/api/download/3f2a1b4c-5d6e-7f80-9a1b-2c3d4e5f6071'), '/api/download/_');
    assert.equal(R.url('/api/kdf-params?username=alice'), '/api/kdf-params?_');
    assert.equal(R.url('/js/app.js'), '/js/app.js');
    assert.equal(R.url('/'), '/');
  });

  test('a 64-hex identity key in a path is stripped', () => {
    const id = 'a4c123b1612dd272d1371c17149d439536b3216fdaeeb975729fae923d5a4fd1';
    assert.equal(R.url(`/add/${id}`).includes(id), false);
  });

  test('the salt is per boot, so tags do not survive a restart', async () => {
    // A fixed salt, or a plain hash, would let anyone holding a captured log
    // brute-force it back to a username: the space is small enough to
    // enumerate. A fresh module instance stands in for a fresh process.
    const fresh = await import('../redact.js?instance=2');
    assert.notEqual(fresh.tag('alice'), R.tag('alice'),
      'two runs produced the same label, so the salt is not per boot');
    assert.equal(fresh.tag('alice'), fresh.tag('alice'),
      'labels must still be stable within one run');
  });

  test('malformed input does not throw', () => {
    for (const bad of [null, undefined, 0, {}, []]) {
      assert.doesNotThrow(() => R.tag(bad));
      assert.doesNotThrow(() => R.ip(bad));
      assert.doesNotThrow(() => R.url(bad));
    }
  });
});

/* ------------------------------------------------------- the static half */
//
// The runtime half below can only catch a leak on a route it happens to call,
// and it missed two: `/api/publish-prekeys` logged the username verbatim and
// `/ca.crt` logged the raw remote address, because the fixture never hit
// either. Adding those two calls fixes those two lines and leaves the next
// one exposed.
//
// So this reads server.js and checks every `log()` call in it, covered by a
// test or not. A new log line that interpolates an identity without going
// through Redact fails here on the day it is written.

describe('every log call site in server.js', () => {
  const SENSITIVE = [
    'username', 'idPub', 'clientId', 'recipientId', 'senderId',
    'conversationKey', 'convId', 'fileId', 'remoteAddress', 'clientIp',
    'req.url', 'clientKey(', 'endpoint'
  ];

  /** Extracts the full argument text of every log()/logError() call. */
  function logCalls(source) {
    const calls = [];
    const re = /\blog(?:Error)?\s*\(/g;
    let m;
    while ((m = re.exec(source))) {
      let depth = 0;
      let i = m.index + m[0].length - 1;
      const start = i + 1;
      for (; i < source.length; i++) {
        const ch = source[i];
        if (ch === '(') depth++;
        else if (ch === ')') {
          depth--;
          if (depth === 0) break;
        }
      }
      calls.push({ text: source.slice(start, i), index: m.index });
    }
    return calls;
  }

  test('never interpolates an identity without redacting it', () => {
    const source = fs.readFileSync(SERVER, 'utf8');
    const lineOf = (idx) => source.slice(0, idx).split('\n').length;
    const offenders = [];

    for (const call of logCalls(source)) {
      for (const expr of call.text.match(/\$\{[^}]*\}/g) || []) {
        if (expr.includes('Redact.')) continue;
        const hit = SENSITIVE.find((s) => expr.includes(s));
        if (hit) offenders.push(`server.js:${lineOf(call.index)}  ${expr}  (${hit})`);
      }
    }

    assert.deepEqual(offenders, [],
      `these log lines leak an identity:\n  ${offenders.join('\n  ')}`);
  });

  test('the scanner actually finds the log calls', () => {
    // Otherwise the assertion above passes by finding nothing at all, which
    // is exactly the shape of failure this whole file exists to prevent.
    const source = fs.readFileSync(SERVER, 'utf8');
    const calls = logCalls(source);
    assert.ok(calls.length > 40, `expected many log calls, found ${calls.length}`);
    assert.ok(calls.some((c) => c.text.includes('Redact.tag')),
      'expected to see redacted interpolations in the extracted calls');
  });

  test('the scanner would catch a planted leak', () => {
    // Proves the rule has teeth without waiting for someone to write the bug.
    const planted = "log('API', `Registered user: ${username.toLowerCase()}`);";
    const offenders = [];
    for (const call of logCalls(planted)) {
      for (const expr of call.text.match(/\$\{[^}]*\}/g) || []) {
        if (expr.includes('Redact.')) continue;
        if (SENSITIVE.some((s) => expr.includes(s))) offenders.push(expr);
      }
    }
    assert.equal(offenders.length, 1, 'the scanner missed an obvious leak');
  });
});

/* --------------------------------------------------- the wired-up half */

const PORT = 17600 + (process.pid % 300);
const BASE = `http://127.0.0.1:${PORT}`;

let proc;
let dataDir;
let output = '';

const USER = 'redacttestuser';
const PASSWORD_HASH = sha256(USER + ':secret');
const ID_PUB = crypto.randomBytes(32).toString('hex');
const PEER_ID = crypto.randomBytes(32).toString('hex');

before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'talon-redact-'));
  proc = spawn(process.execPath, [SERVER], {
    env: {
      ...process.env,
      TALON_DATA_DIR: dataDir,
      PORT: String(PORT),
      HTTPS_PORT: String(PORT + 1),
      // Everything loose, so nothing throttles and changes what gets logged.
      TALON_RL_REGISTER_BURST: '500',
      TALON_RL_AUTH_BURST: '500',
      TALON_RL_UPLOAD_BURST: '500',
      TALON_RL_SEND_BURST: '500'
    },
    stdio: 'pipe'
  });
  proc.stdout.on('data', (d) => { output += d.toString(); });
  proc.stderr.on('data', (d) => { output += d.toString(); });

  for (let i = 0; i < 120; i++) {
    try {
      const r = await fetch(BASE + '/api/kdf-params?username=nobody');
      if (r.status) break;
    } catch { await sleep(250); }
  }

  // Exercise the routes that log an identity.
  await fetch(BASE + '/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: USER, idPub: ID_PUB, authHash: PASSWORD_HASH,
      kdfVersion: 2, kdfSalt: crypto.randomBytes(16).toString('hex'),
      kdfIterations: 600000,
      encryptedIdPriv: '00'.repeat(32), encryptedIdPrivNonce: '00'.repeat(12)
    })
  });
  await fetch(BASE + '/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: USER, authHash: PASSWORD_HASH })
  });
  await fetch(BASE + '/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: USER, authHash: sha256('wrong') })
  });
  await fetch(BASE + '/api/sync-contacts', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: USER, authHash: PASSWORD_HASH,
      encryptedContacts: 'aa', encryptedContactsNonce: 'bb'
    })
  });

  // Both of these were found leaking by inspection, not by this suite, and
  // the reason is that the fixture never called them.
  await fetch(BASE + '/api/publish-prekeys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: USER, authHash: PASSWORD_HASH,
      signPub: crypto.randomBytes(32).toString('hex'),
      signedPreKey: { pub: crypto.randomBytes(32).toString('hex'), sig: 'aa' },
      oneTimePreKeys: [{ id: 'opk-1', pub: crypto.randomBytes(32).toString('hex') }]
    })
  });
  await fetch(BASE + '/ca.crt');

  const up = await fetch(BASE + '/api/upload', {
    method: 'POST',
    headers: { 'X-Talon-User': USER, 'X-Talon-Auth': PASSWORD_HASH },
    body: Buffer.from('ciphertext')
  });
  const { id: fileId } = await up.json();
  await fetch(BASE + `/api/download/${fileId}`, {
    headers: { 'X-Talon-User': USER, 'X-Talon-Auth': PASSWORD_HASH }
  });
  globalThis.__fileId = fileId;

  // A second account, so a message can actually be routed live. Without a
  // connected recipient every send falls into the queued branch and the
  // "routed live" logging is never reached at all.
  const PEER_USER = 'redactpeeruser';
  const PEER_HASH = sha256(PEER_USER + ':secret');
  await fetch(BASE + '/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: PEER_USER, idPub: PEER_ID, authHash: PEER_HASH,
      kdfVersion: 2, kdfSalt: crypto.randomBytes(16).toString('hex'),
      kdfIterations: 600000,
      encryptedIdPriv: '00'.repeat(32), encryptedIdPrivNonce: '00'.repeat(12)
    })
  });

  const peerWs = new WebSocket(`ws://127.0.0.1:${PORT}`);
  await new Promise((r) => { peerWs.addEventListener('open', r); peerWs.addEventListener('error', r); });
  peerWs.send(JSON.stringify({
    type: 'register', clientId: PEER_ID, username: PEER_USER, authHash: PEER_HASH
  }));
  await sleep(300);

  // And the WebSocket path, which held the routing pair.
  const ws = new WebSocket(`ws://127.0.0.1:${PORT}`);
  await new Promise((r) => { ws.addEventListener('open', r); ws.addEventListener('error', r); });
  ws.send(JSON.stringify({
    type: 'register', clientId: ID_PUB, username: USER, authHash: PASSWORD_HASH
  }));
  await sleep(300);

  // Live routes, both sealed and addressed, to the connected peer.
  ws.send(JSON.stringify({
    type: 'send', recipientId: PEER_ID, convId: ID_PUB,
    payload: { sealed: true, c: 'aa', n: 'bb' }, notify: false
  }));
  ws.send(JSON.stringify({
    type: 'send', recipientId: PEER_ID, convId: ID_PUB,
    payload: { c: 'aa', n: 'bb', messageIndex: 1 }, notify: false
  }));
  await sleep(300);
  peerWs.close();
  await sleep(200);
  ws.send(JSON.stringify({
    type: 'send', recipientId: crypto.randomBytes(32).toString('hex'),
    convId: ID_PUB, payload: { sealed: true, c: 'aa', n: 'bb' }, notify: false
  }));
  // And an addressed (un-sealed) envelope, which is the branch that used to
  // print "sender -> recipient". A mutation run caught that a sealed-only
  // fixture never reaches it, so restoring the pair left the suite green.
  ws.send(JSON.stringify({
    type: 'send', recipientId: crypto.randomBytes(32).toString('hex'),
    convId: ID_PUB, payload: { c: 'aa', n: 'bb', messageIndex: 1 }, notify: false
  }));
  ws.send(JSON.stringify({ type: 'presence', activeConversationId: ID_PUB, focused: true }));
  ws.send(JSON.stringify({ type: 'ping' }));
  await sleep(500);
  ws.close();
  await sleep(300);
});

after(async () => {
  if (proc) proc.kill();
  await sleep(300);
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* windows lock */ }
});

describe('what a running relay writes to its log', () => {
  test('the relay actually did the work', () => {
    // Guard against the whole suite passing because nothing was logged at all.
    assert.ok(output.length > 500, `expected a busy log, got ${output.length} bytes`);
    assert.match(output, /Registered user/);
    assert.match(output, /User logged in/);
    assert.match(output, /File uploaded/);
    assert.match(output, /Client online/);
    assert.match(output, /Routed message live/);
    assert.match(output, /Queued offline message/);
    assert.match(output, /Prekeys published/);
    assert.match(output, /CA certificate downloaded/);
  });

  test('the username never appears', () => {
    assert.equal(output.includes(USER), false,
      `"${USER}" appears in the log`);
  });

  test('the identity key never appears, not even truncated', () => {
    assert.equal(output.includes(ID_PUB), false, 'full identity key in the log');
    assert.equal(output.includes(ID_PUB.substring(0, 8)), false,
      'the old 8-hex prefix is still being logged');
  });

  test('the attachment id never appears', () => {
    assert.equal(output.includes(globalThis.__fileId), false,
      'a download id in the access log names a specific blob');
  });

  test('no routing pair is recorded', () => {
    // The social graph. "a -> b" was printed for every message.
    assert.equal(/#[0-9a-f]{6} -> #[0-9a-f]{6}/.test(output), false,
      'a sender and recipient still appear together on one line');
  });

  test('no client address appears on an access-log line', () => {
    // Scoped to [HTTP] lines rather than the whole output: the boot banner
    // legitimately prints this machine's own addresses, because you need them
    // to connect. What must not appear is where a request came FROM.
    const offenders = output
      .split('\n')
      .filter((l) => l.includes('[HTTP]'))
      .filter((l) => /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(l));
    assert.deepEqual(offenders, [], 'an access-log line carries a raw IP');
  });

  test('access-log lines still say which route was hit', () => {
    // Redaction that removed the path would make the access log useless, and
    // useless logging gets turned off, which is worse than redacted logging.
    //
    // The tag and the method are separated by an ANSI reset, so the codes come
    // out before matching rather than being written into the pattern.
    const plain = output.replace(/\x1b\[[0-9;]*m/g, '');
    assert.match(plain, /\[HTTP\] POST \/api\/register/);
    assert.match(plain, /\[HTTP\] GET \/api\/download\/_/);
  });

  test('presence is not logged at all', () => {
    assert.equal(/Presence:/.test(output), false,
      'the log still records which conversation is open');
  });

  test('the boot banner states the mode', () => {
    assert.match(output, /Log privacy: strict/);
  });

  test('identities still print as stable pseudonyms', () => {
    // The log has to stay useful. Redaction that removed the identity
    // entirely would make it impossible to follow one client's session.
    const tags = output.match(/#[0-9a-f]{6}/g) || [];
    assert.ok(tags.length >= 5, `expected pseudonymous labels, found ${tags.length}`);
    assert.ok(new Set(tags).size < tags.length,
      'the same account should reuse the same label within a run');
  });
});

describe('the offline queue', () => {
  test('records no wall-clock time and no time-derived id', () => {
    // Queued rows used to carry a millisecond timestamp and an id with
    // Date.now() baked into it, recording exactly when every undelivered
    // message was written. The client reads neither.
    // Snapshot and journal together. A queued row now reaches db.log first,
    // so reading db.json alone would inspect an empty list and pass without
    // having looked at a single message.
    const queued = queuedRowsAtRest(dataDir);
    assert.ok(queued.length >= 1, 'expected the send above to have been queued');

    for (const row of queued) {
      assert.equal('timestamp' in row, false, 'millisecond timestamp still stored');
      assert.equal(row.queuedDay % (24 * 60 * 60 * 1000), 0,
        'queuedDay should be rounded to a whole day');
      assert.match(row.id, /^[0-9a-f-]{36}$/, 'id should be a random UUID');
    }

    const sealed = queued.filter((r) => r.payload && r.payload.sealed);
    assert.ok(sealed.length >= 1, 'expected a sealed envelope in the queue');
    for (const row of sealed) {
      assert.equal(row.senderId, null, 'a sealed envelope must not name its sender');
    }
  });
});
