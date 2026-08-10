// Opaque notification tags.
//
// The relay used to be told `convId` on every send. For a group that was the
// shared groupId, repeated on every envelope of the fan-out, so collecting the
// recipients that keep appearing under one value reconstructs the membership
// of a group the relay is supposed to know nothing about. And the muted list
// had to be uploaded in the clear for the relay to act on it, which handed
// over a slice of the contact graph outright.
//
// The property that makes the replacement work is that the tag is bound to the
// recipient as well as the conversation. Everything below is really one test
// of that, from different angles: the same group message must look different
// to the relay for every member, and both ends must still agree.

import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// store.js reaches for localStorage as a global, and messaging.js imports it.
function shim() {
  const map = new Map();
  return {
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => { map.set(k, String(v)); },
    removeItem: (k) => { map.delete(k); },
    clear: () => map.clear(),
    key: (i) => Array.from(map.keys())[i] ?? null,
    get length() { return map.size; }
  };
}
globalThis.localStorage = shim();
globalThis.sessionStorage = shim();

const { pushTagFor, mutedPushTags, conversationForPushTag } =
  await import('../src/messaging.js');
const { State } = await import('../src/store.js');

const ALICE = 'a'.repeat(64);
const BOB   = 'b'.repeat(64);
const CARA  = 'c'.repeat(64);
const GROUP = 'g'.repeat(64);

beforeEach(() => {
  State.currentUser = { idPub: ALICE, username: 'alice' };
  State.contacts = [];
  State.groups = [];
});

describe('the tag itself', () => {
  test('is deterministic', () => {
    assert.equal(pushTagFor(GROUP, BOB), pushTagFor(GROUP, BOB));
  });

  test('is short, lowercase hex', () => {
    assert.match(pushTagFor(GROUP, BOB), /^[0-9a-f]{32}$/);
  });

  test('differs per recipient for the same conversation', () => {
    // The whole point. One group message fans out to every member, and if the
    // tag were the same on each envelope the relay could just group them.
    assert.notEqual(pushTagFor(GROUP, BOB), pushTagFor(GROUP, CARA));
  });

  test('differs per conversation for the same recipient', () => {
    assert.notEqual(pushTagFor(GROUP, BOB), pushTagFor(ALICE, BOB));
  });

  test('a whole group fan-out shares nothing', () => {
    const members = [BOB, CARA, 'd'.repeat(64), 'e'.repeat(64), 'f'.repeat(64)];
    const tags = members.map((m) => pushTagFor(GROUP, m));
    assert.equal(new Set(tags).size, members.length,
      'two members produced the same tag, so the fan-out is still linkable');
  });

  test('reveals neither the conversation nor the recipient', () => {
    const tag = pushTagFor(GROUP, BOB);
    assert.equal(tag.includes(GROUP.substring(0, 16)), false);
    assert.equal(tag.includes(BOB.substring(0, 16)), false);
  });

  test('is not the plain hash of either half on its own', () => {
    // If the recipient were left out, every member of a group would send the
    // same value and nothing would have been gained.
    assert.notEqual(pushTagFor(GROUP, BOB), pushTagFor(GROUP, ''));
    assert.notEqual(pushTagFor(GROUP, BOB), pushTagFor(BOB, GROUP));
  });

  test('is undefined rather than a tag when either half is missing', () => {
    assert.equal(pushTagFor(null, BOB), undefined);
    assert.equal(pushTagFor(GROUP, null), undefined);
    assert.equal(pushTagFor('', ''), undefined);
  });
});

describe('both ends agree', () => {
  test('what the sender stamps is what the recipient computes', () => {
    // Sender is Bob writing to Alice one to one, so the conversation as ALICE
    // knows it is Bob's identity key.
    const stamped = pushTagFor(BOB, ALICE);

    State.currentUser = { idPub: ALICE, username: 'alice' };
    State.contacts = [{ idPub: BOB, muted: true }];
    assert.deepEqual(mutedPushTags(), [stamped]);
  });

  test('the same holds for a group', () => {
    const stamped = pushTagFor(GROUP, ALICE);
    State.groups = [{ id: GROUP, muted: true }];
    assert.deepEqual(mutedPushTags(), [stamped]);
  });
});

describe('the muted tag list', () => {
  test('covers muted contacts and muted groups', () => {
    State.contacts = [{ idPub: BOB, muted: true }, { idPub: CARA, muted: false }];
    State.groups = [{ id: GROUP, muted: true }];
    const tags = mutedPushTags();
    assert.equal(tags.length, 2);
    assert.ok(tags.includes(pushTagFor(BOB, ALICE)));
    assert.ok(tags.includes(pushTagFor(GROUP, ALICE)));
  });

  test('an unmuted conversation is absent', () => {
    State.contacts = [{ idPub: BOB, muted: false }];
    assert.deepEqual(mutedPushTags(), []);
  });

  test('holds tags only, never a conversation id', () => {
    // This list is written to IndexedDB. If it held ids, reading that database
    // would give up exactly the contact graph this change removed.
    State.contacts = [{ idPub: BOB, muted: true }];
    State.groups = [{ id: GROUP, muted: true }];
    const serialised = JSON.stringify(mutedPushTags());
    assert.equal(serialised.includes(BOB), false);
    assert.equal(serialised.includes(GROUP), false);
    assert.equal(serialised.includes(ALICE), false);
  });

  test('is empty when signed out rather than throwing', () => {
    State.currentUser = null;
    assert.deepEqual(mutedPushTags(), []);
  });
});

describe('resolving a tag back to a conversation', () => {
  test('finds the contact a notification came from', () => {
    State.contacts = [{ idPub: BOB }, { idPub: CARA }];
    assert.equal(conversationForPushTag(pushTagFor(BOB, ALICE)), BOB);
  });

  test('finds the group', () => {
    State.groups = [{ id: GROUP }];
    assert.equal(conversationForPushTag(pushTagFor(GROUP, ALICE)), GROUP);
  });

  test('returns null for a tag that matches nothing', () => {
    State.contacts = [{ idPub: BOB }];
    assert.equal(conversationForPushTag('0'.repeat(32)), null);
  });

  test('returns null rather than throwing on junk', () => {
    for (const bad of [null, undefined, '', 0, {}]) {
      assert.equal(conversationForPushTag(bad), null);
    }
  });

  test('only this device can do it', () => {
    // The resolver works by recomputing the tag for every conversation it
    // knows. The relay has the tag but not the contact list, which is what
    // makes the tag opaque to it rather than merely unfamiliar.
    State.contacts = [{ idPub: BOB }];
    const tag = pushTagFor(BOB, ALICE);
    State.contacts = [];
    assert.equal(conversationForPushTag(tag), null);
  });
});
