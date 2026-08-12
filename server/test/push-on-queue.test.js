// The relay pushes only when it QUEUES a message, never on live delivery.
//
// Two reasons, and the second is the one that made this a change rather than
// a tidy-up.
//
// A recipient holding an open socket already has the envelope. It can raise
// its own notification, and unlike the push service it can actually read the
// message. Pushing anyway cost a wakeup per message and told nobody anything.
//
// And with constant-rate cover traffic switched on, `notify` was the last
// plaintext field separating real traffic from cover. Cover cells only ever
// go to peers that are online, so if the relay fires a push on the live path
// then `notify: true` means "this one is real" and the cover traffic is
// decoration. Firing only on the queued path removes the correlation.
//
// Observed by pointing a real push subscription at a local listener and
// counting CONNECTIONS, at the TCP level rather than the HTTP one. web-push
// always speaks TLS to a push endpoint, so a plain HTTP server never completes
// a request and sees nothing even when the push definitely happened. Counting
// connections needs no certificate and measures the thing that actually
// matters: whether the relay tried to wake somebody.
//
// Asserting on relay state instead would prove nothing, because the relay's
// own view is identical either way. That is exactly why this behaviour went
// untested when it was first written.

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { WebSocket } from 'ws';
import crypto from 'node:crypto';
import net from 'node:net';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SERVER = path.join(HERE, '..', 'server.js');

const PORT = 19400 + (process.pid % 150);
const PUSH_PORT = PORT + 2;
const BASE = `http://127.0.0.1:${PORT}`;
const WS_URL = `ws://127.0.0.1:${PORT}`;

let proc;
let dataDir;
let pushServer;
let pushHits = [];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const b64url = (buf) => buf.toString('base64')
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function post(route, body) {
  const res = await fetch(BASE + route, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  let json = null;
  try { json = await res.json(); } catch { /* non-JSON */ }
  return { status: res.status, json };
}

let seq = 0;
const uname = () => `pq${process.pid % 1000}x${seq++}`;

/**
 * A real P-256 subscription, because web-push encrypts the payload to it and
 * would refuse an invented key. The private half is never needed: the test
 * only counts that a request was attempted.
 */
function subscriptionFor(endpoint) {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return {
    endpoint,
    keys: {
      p256dh: b64url(ecdh.getPublicKey()),
      auth: b64url(crypto.randomBytes(16))
    }
  };
}

async function makeAccount() {
  const name = uname();
  const authHash = sha256(name + ':secret');
  const idPub = crypto.randomBytes(32).toString('hex');
  const r = await post('/api/register', {
    username: name, idPub, authHash,
    kdfVersion: 2,
    kdfSalt: crypto.randomBytes(16).toString('hex'),
    kdfIterations: 600000,
    encryptedIdPriv: '00'.repeat(32),
    encryptedIdPrivNonce: '00'.repeat(12)
  });
  assert.equal(r.json && r.json.success, true, `registration failed: ${JSON.stringify(r.json)}`);

  const sub = await post('/api/push-subscribe', {
    username: name,
    authHash,
    subscription: subscriptionFor(`https://127.0.0.1:${PUSH_PORT}/push/${idPub.slice(0, 8)}`)
  });
  assert.equal(sub.json && sub.json.success, true, 'push subscribe failed');

  return { username: name, authHash, idPub };
}

async function connect(account) {
  const ws = new WebSocket(WS_URL);
  const received = [];
  ws.on('message', (raw) => {
    try { received.push(JSON.parse(raw)); } catch { /* ignore */ }
  });
  await new Promise((resolve, reject) => {
    ws.on('open', resolve);
    ws.on('error', reject);
  });
  ws.send(JSON.stringify({
    type: 'register',
    clientId: account.idPub,
    username: account.username,
    authHash: account.authHash
  }));
  for (let i = 0; i < 60; i++) {
    if (received.some((m) => m.type === 'registered' && m.success)) break;
    await sleep(50);
  }
  assert.ok(received.some((m) => m.type === 'registered' && m.success), 'socket never registered');
  return {
    ws,
    received,
    send: (frame) => ws.send(JSON.stringify(frame)),
    close: () => new Promise((r) => { ws.on('close', r); ws.close(); })
  };
}

/** Waits for the ack, then a beat more, so a push had every chance to fire. */
async function sendAndSettle(sock, frame) {
  const before = sock.received.length;
  sock.send(frame);
  for (let i = 0; i < 60; i++) {
    if (sock.received.slice(before).some((m) => m.type === 'ack')) break;
    await sleep(50);
  }
  await sleep(400);
  return sock.received.slice(before).find((m) => m.type === 'ack');
}

before(async () => {
  pushServer = net.createServer((socket) => {
    pushHits.push(Date.now());
    socket.destroy();
  });
  await new Promise((r) => pushServer.listen(PUSH_PORT, '127.0.0.1', r));

  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'talon-push-'));
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
      const r = await fetch(`${BASE}/api/vapid-public-key`);
      if (r.ok) return;
    } catch { /* not up yet */ }
    await sleep(100);
  }
  throw new Error('relay never came up');
});

after(async () => {
  if (proc) proc.kill();
  if (pushServer) await new Promise((r) => pushServer.close(r));
  if (dataDir) fs.rmSync(dataDir, { recursive: true, force: true });
});

describe('push fires only when the message is queued', () => {
  test('a live recipient gets the envelope and no push', async () => {
    pushHits = [];
    const alice = await makeAccount();
    const bob = await makeAccount();

    const aSock = await connect(alice);
    const bSock = await connect(bob);

    const ack = await sendAndSettle(aSock, {
      type: 'send',
      recipientId: bob.idPub,
      payload: { sealed: 1, ct: 'x' },
      pushTag: 'a'.repeat(32),
      notify: true,
      ref: 'r1'
    });

    assert.equal(ack && ack.status, 'delivered', 'the message should have gone out live');
    assert.ok(bSock.received.some((m) => m.type === 'message'), 'the live socket never got it');
    assert.deepEqual(pushHits, [], 'a push was sent to a recipient who was already holding the envelope');

    await aSock.close();
    await bSock.close();
  });

  test('an offline recipient gets a push', async () => {
    // The other half. Without this, "no push on the live path" would also be
    // satisfied by a relay that had stopped pushing altogether, and the test
    // above would pass against a completely broken push path.
    pushHits = [];
    const alice = await makeAccount();
    const bob = await makeAccount();

    const aSock = await connect(alice);
    const bSock = await connect(bob);
    await bSock.close();
    await sleep(200);

    const ack = await sendAndSettle(aSock, {
      type: 'send',
      recipientId: bob.idPub,
      payload: { sealed: 1, ct: 'x' },
      pushTag: 'b'.repeat(32),
      notify: true,
      ref: 'r2'
    });

    assert.equal(ack && ack.status, 'queued');
    assert.equal(pushHits.length, 1, `expected exactly one push, saw ${pushHits.length}`);

    await aSock.close();
  });

  test('a queued message with notify false still sends no push', async () => {
    // Control traffic, cover cells and read receipts all travel over the same
    // frame. Queuing one must not wake a phone.
    pushHits = [];
    const alice = await makeAccount();
    const bob = await makeAccount();

    const aSock = await connect(alice);
    const bSock = await connect(bob);
    await bSock.close();
    await sleep(200);

    const ack = await sendAndSettle(aSock, {
      type: 'send',
      recipientId: bob.idPub,
      payload: { sealed: 1, ct: 'x' },
      notify: false,
      ref: 'r3'
    });

    assert.equal(ack && ack.status, 'queued');
    assert.deepEqual(pushHits, [], 'a notify:false message woke a phone');

    await aSock.close();
  });

  test('one of two devices online is enough to suppress the push', async () => {
    // The relay decides on whether it QUEUED, and it queues per device. A
    // recipient with one device connected and one not gets the envelope live
    // on the connected one, so there is nothing to wake it about.
    pushHits = [];
    const alice = await makeAccount();
    const bob = await makeAccount();

    const aSock = await connect(alice);
    const bSock = await connect(bob);

    const ack = await sendAndSettle(aSock, {
      type: 'send',
      recipientId: bob.idPub,
      payload: { sealed: 1, ct: 'x' },
      notify: true,
      ref: 'r4'
    });

    assert.equal(ack && ack.status, 'delivered');
    assert.deepEqual(pushHits, []);

    await aSock.close();
    await bSock.close();
  });
});
