// Multi-device routing, over real WebSockets against a real relay.
//
// The bug this exists to prevent is specific and was live until now: a second
// device registering the same account evicted the first from onlineClients.
// The evicted socket stayed OPEN, so from the client's side nothing looked
// wrong at all. It simply stopped receiving, which is indistinguishable from
// the network being quiet.
//
// Every test therefore asserts on what a socket RECEIVES, not on relay state.
// A test that inspects the map would have passed against the broken version
// too, because the map was never the thing that was wrong.

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { WebSocket } from 'ws';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SERVER = path.join(HERE, '..', 'server.js');

const PORT = 19800 + (process.pid % 150);
const BASE = `http://127.0.0.1:${PORT}`;
const WS_URL = `ws://127.0.0.1:${PORT}`;

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
  try { json = await res.json(); } catch { /* non-JSON */ }
  return { status: res.status, json };
}

let seq = 0;
const uname = (tag) => `r${tag}${seq++}`.replace(/\W/g, '').slice(0, 20);
const devId = () => crypto.randomBytes(8).toString('hex');

async function makeAccount(name) {
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
  return { username: name, authHash, idPub };
}

/**
 * A connected, registered socket that records every frame it is sent.
 *
 * `received` is the whole point: the eviction bug was invisible from the
 * relay's own state and only showed up as an absence here.
 */
async function connect(account, deviceId) {
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
    authHash: account.authHash,
    deviceId
  }));

  for (let i = 0; i < 60; i++) {
    if (received.some((m) => m.type === 'registered' && m.success)) break;
    await sleep(50);
  }
  assert.ok(received.some((m) => m.type === 'registered' && m.success),
    'the socket never registered');

  return {
    ws,
    received,
    messages: () => received.filter((m) => m.type === 'message'),
    offline: () => received.filter((m) => m.type === 'offline-messages'),
    send: (frame) => ws.send(JSON.stringify(frame)),
    close: () => ws.close()
  };
}

const sealed = (text) => ({ sealed: true, ct: text });

before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'talon-routing-'));
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

describe('two devices on one account', () => {
  test('the second does not evict the first', async () => {
    // The headline. Before this change, phone.received stopped growing the
    // moment the laptop connected, and nothing anywhere reported an error.
    const bob = await makeAccount(uname('bob'));
    const alice = await makeAccount(uname('al'));
    const phoneId = devId();
    const laptopId = devId();

    const phone = await connect(bob, phoneId);
    const laptop = await connect(bob, laptopId);
    const sender = await connect(alice, devId());

    sender.send({
      type: 'send', recipientId: bob.idPub, recipientDev: phoneId,
      payload: sealed('to-phone'), ref: 'r1'
    });
    sender.send({
      type: 'send', recipientId: bob.idPub, recipientDev: laptopId,
      payload: sealed('to-laptop'), ref: 'r2'
    });
    await sleep(400);

    assert.equal(phone.messages().length, 1,
      'the first device stopped receiving when the second connected');
    assert.equal(phone.messages()[0].payload.ct, 'to-phone');
    assert.equal(laptop.messages().length, 1, 'the second device received nothing');
    assert.equal(laptop.messages()[0].payload.ct, 'to-laptop');

    phone.close(); laptop.close(); sender.close();
  });

  test('an envelope for one device does not reach the other', async () => {
    // Fan-out correctness in the other direction. If the relay broadcast
    // everything, the test above would pass and this one would not.
    const bob = await makeAccount(uname('bob2'));
    const alice = await makeAccount(uname('al2'));
    const phoneId = devId();
    const phone = await connect(bob, phoneId);
    const laptop = await connect(bob, devId());
    const sender = await connect(alice, devId());

    sender.send({
      type: 'send', recipientId: bob.idPub, recipientDev: phoneId,
      payload: sealed('private'), ref: 'r3'
    });
    await sleep(400);

    assert.equal(phone.messages().length, 1);
    assert.equal(laptop.messages().length, 0,
      'the relay broadcast a device-addressed envelope to every device');

    phone.close(); laptop.close(); sender.close();
  });

  test('reconnecting the same device replaces only its own socket', async () => {
    const bob = await makeAccount(uname('bob3'));
    const alice = await makeAccount(uname('al3'));
    const phoneId = devId();
    const laptopId = devId();

    const laptop = await connect(bob, laptopId);
    const phoneOld = await connect(bob, phoneId);
    const phoneNew = await connect(bob, phoneId);   // same device, new socket
    await sleep(200);

    const sender = await connect(alice, devId());
    sender.send({
      type: 'send', recipientId: bob.idPub, recipientDev: laptopId,
      payload: sealed('still-here'), ref: 'r4'
    });
    sender.send({
      type: 'send', recipientId: bob.idPub, recipientDev: phoneId,
      payload: sealed('to-new-phone'), ref: 'r5'
    });
    await sleep(400);

    assert.equal(laptop.messages().length, 1,
      'a reconnect from one device knocked another device off');
    assert.equal(phoneNew.messages().length, 1, 'the reconnected socket is not routable');
    assert.equal(phoneOld.messages().length, 0, 'the replaced socket is still being written to');

    laptop.close(); phoneOld.close(); phoneNew.close(); sender.close();
  });

  test('closing one device leaves the other routable', async () => {
    // The close handler has to remove one entry, not the account. Getting
    // this wrong takes every other device offline with it.
    const bob = await makeAccount(uname('bob4'));
    const alice = await makeAccount(uname('al4'));
    const laptopId = devId();
    const phone = await connect(bob, devId());
    const laptop = await connect(bob, laptopId);

    phone.close();
    await sleep(300);

    const sender = await connect(alice, devId());
    sender.send({
      type: 'send', recipientId: bob.idPub, recipientDev: laptopId,
      payload: sealed('survivor'), ref: 'r6'
    });
    await sleep(400);

    assert.equal(laptop.messages().length, 1,
      'closing one device made the whole account unroutable');

    laptop.close(); sender.close();
  });
});

describe('offline delivery per device', () => {
  test('a message for an offline device waits for that device', async () => {
    const bob = await makeAccount(uname('bob5'));
    const alice = await makeAccount(uname('al5'));
    const phoneId = devId();
    const laptopId = devId();

    const laptop = await connect(bob, laptopId);   // online
    const sender = await connect(alice, devId());
    sender.send({
      type: 'send', recipientId: bob.idPub, recipientDev: phoneId,
      payload: sealed('waiting'), ref: 'r7'
    });
    await sleep(400);

    assert.equal(laptop.messages().length, 0,
      'a message for an absent device was handed to a different one');

    const phone = await connect(bob, phoneId);
    await sleep(300);
    const drained = phone.offline().flatMap((m) => m.messages);
    assert.equal(drained.length, 1, 'the queued message did not reach its device');
    assert.equal(drained[0].payload.ct, 'waiting');

    laptop.close(); phone.close(); sender.close();
  });

  test('one device draining does not consume another device queue', async () => {
    const bob = await makeAccount(uname('bob6'));
    const alice = await makeAccount(uname('al6'));
    const phoneId = devId();
    const laptopId = devId();

    const sender = await connect(alice, devId());
    sender.send({
      type: 'send', recipientId: bob.idPub, recipientDev: phoneId,
      payload: sealed('phone-mail'), ref: 'r8'
    });
    sender.send({
      type: 'send', recipientId: bob.idPub, recipientDev: laptopId,
      payload: sealed('laptop-mail'), ref: 'r9'
    });
    await sleep(400);

    const phone = await connect(bob, phoneId);
    await sleep(300);
    assert.deepEqual(
      phone.offline().flatMap((m) => m.messages).map((m) => m.payload.ct),
      ['phone-mail']
    );

    // The laptop's mail survived the phone's destructive drain.
    const laptop = await connect(bob, laptopId);
    await sleep(300);
    assert.deepEqual(
      laptop.offline().flatMap((m) => m.messages).map((m) => m.payload.ct),
      ['laptop-mail'],
      "one device's drain destroyed another device's queued mail"
    );

    phone.close(); laptop.close(); sender.close();
  });
});

describe('a sender that has never heard of devices', () => {
  test('reaches every device of a multi-device account', async () => {
    // A legacy sender names no device, so the relay cannot know which session
    // the envelope belongs to. It goes to all of them and the wrong ones fail
    // to decrypt, which is the only correct answer available.
    const bob = await makeAccount(uname('bob7'));
    const alice = await makeAccount(uname('al7'));
    const phone = await connect(bob, devId());
    const laptop = await connect(bob, devId());
    const sender = await connect(alice, devId());

    sender.send({
      type: 'send', recipientId: bob.idPub, payload: sealed('broadcast'), ref: 'r10'
    });
    await sleep(400);

    assert.equal(phone.messages().length, 1, 'a legacy envelope missed a device');
    assert.equal(laptop.messages().length, 1, 'a legacy envelope missed a device');

    phone.close(); laptop.close(); sender.close();
  });

  test('a single-device account is unaffected', async () => {
    // The compatibility case that must not regress: no device ids anywhere.
    const bob = await makeAccount(uname('bob8'));
    const alice = await makeAccount(uname('al8'));
    const only = await connect(bob, undefined);
    const sender = await connect(alice, undefined);

    sender.send({
      type: 'send', recipientId: bob.idPub, payload: sealed('plain'), ref: 'r11'
    });
    await sleep(400);

    assert.equal(only.messages().length, 1, 'the single-device path regressed');
    assert.equal(only.messages()[0].payload.ct, 'plain');

    only.close(); sender.close();
  });

  test('a device drains mail queued before its account had a device list', async () => {
    // Found by mutation testing. The queue row lands in the account bucket
    // because nobody named a device, but the recipient's client registers
    // with a device id. If it drained only its own bucket, that message would
    // sit on the relay forever behind an id no client will ever claim.
    //
    // This is not a corner case: it is what every relay upgraded in place
    // looks like, and what a device-aware client sees before it has published
    // anything.
    const bob = await makeAccount(uname('bob10'));
    const alice = await makeAccount(uname('al10'));
    const phoneId = devId();

    const sender = await connect(alice, devId());
    sender.send({
      type: 'send', recipientId: bob.idPub, payload: sealed('stranded'), ref: 'r13'
    });
    await sleep(400);

    const phone = await connect(bob, phoneId);
    await sleep(300);
    const drained = phone.offline().flatMap((m) => m.messages);
    assert.equal(drained.length, 1,
      'a message queued before the account had devices was never delivered');
    assert.equal(drained[0].payload.ct, 'stranded');

    phone.close(); sender.close();
  });

  test('an offline multi-device account gets one queued copy per device', async () => {
    // Queued while nobody is connected, so the relay has to use the published
    // device list rather than the set of live sockets.
    const bob = await makeAccount(uname('bob9'));
    const alice = await makeAccount(uname('al9'));
    const phoneId = devId();
    const laptopId = devId();

    await post('/api/publish-devices', {
      username: bob.username, authHash: bob.authHash,
      list: {
        rev: 1, sig: 'a'.repeat(128), signPub: 'b'.repeat(64),
        devices: [
          { deviceId: phoneId, devPub: 'c'.repeat(64), name: 'Phone' },
          { deviceId: laptopId, devPub: 'd'.repeat(64), name: 'Laptop' }
        ]
      }
    });

    const sender = await connect(alice, devId());
    sender.send({
      type: 'send', recipientId: bob.idPub, payload: sealed('to-all'), ref: 'r12'
    });
    await sleep(400);

    const phone = await connect(bob, phoneId);
    await sleep(300);
    assert.equal(phone.offline().flatMap((m) => m.messages).length, 1,
      'the phone got no copy of a legacy envelope');

    const laptop = await connect(bob, laptopId);
    await sleep(300);
    assert.equal(laptop.offline().flatMap((m) => m.messages).length, 1,
      'the laptop got no copy, so a legacy sender can only ever reach one device');

    phone.close(); laptop.close(); sender.close();
  });
});
