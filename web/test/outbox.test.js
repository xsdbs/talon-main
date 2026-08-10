// Delivery guarantees.
//
// The behaviour under test is what happens when things go wrong, because when
// they go right there was never a problem. Three failures used to be possible
// and all three were silent: a send with the socket down was stranded forever,
// a frame that drew no ack sat on "sending" and looked delivered, and a retry
// would have arrived as a second copy of the same message.
//
// The clock and the randomness are both injected. A backoff test that sleeps
// is a test nobody runs.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  nextDelay, makeEntry, addEntry, removeEntry, findEntry, dueEntries,
  isExhausted, afterAttempt, forceDue, nextWakeup, alreadyReceived,
  MAX_ATTEMPTS, BASE_DELAY_MS, MAX_DELAY_MS, ACK_TIMEOUT_MS
} from '../src/outbox.js';

const NOW = 1_700_000_000_000;
const noJitter = () => 0;      // shortest delay the formula allows
const fullJitter = () => 0.999; // longest

const entry = (over = {}) => ({
  ...makeEntry({ localId: 'a', convId: 'c1', payload: { type: 'text' }, now: NOW, random: noJitter }),
  ...over
});

describe('backoff', () => {
  test('grows with each attempt', () => {
    const delays = [0, 1, 2, 3].map((n) => nextDelay(n, noJitter));
    for (let i = 1; i < delays.length; i++) {
      assert.ok(delays[i] > delays[i - 1], `attempt ${i} did not back off further: ${delays}`);
    }
  });

  test('is capped', () => {
    assert.ok(nextDelay(50, fullJitter) <= MAX_DELAY_MS);
    assert.ok(nextDelay(999, fullJitter) <= MAX_DELAY_MS);
  });

  test('never returns zero or negative', () => {
    for (let n = 0; n < 20; n++) {
      assert.ok(nextDelay(n, noJitter) > 0, `attempt ${n} gave a non-positive delay`);
    }
  });

  test('is jittered, not a fixed schedule', () => {
    // Without jitter every message queued during an outage retries at the same
    // instant, the relay gets the whole backlog at once, and the send limiter
    // refuses most of it. The spread is what makes a retry actually deliver.
    const low = nextDelay(3, noJitter);
    const high = nextDelay(3, fullJitter);
    assert.ok(high > low, 'the delay does not vary, so every retry fires together');
  });

  test('the first delay is derived from the base, not invented', () => {
    assert.ok(nextDelay(0, noJitter) <= BASE_DELAY_MS);
    assert.ok(nextDelay(0, fullJitter) <= BASE_DELAY_MS);
  });
});

describe('the outbox list', () => {
  test('an entry starts unattempted and scheduled', () => {
    const e = makeEntry({ localId: 'x', convId: 'c', payload: {}, now: NOW, random: noJitter });
    assert.equal(e.attempts, 0);
    assert.ok(e.nextAt > NOW);
    assert.equal(e.localId, 'x');
  });

  test('adding the same message twice replaces rather than duplicates', () => {
    // A message reaches the outbox twice in normal operation: once when the
    // send fails and again when its ack times out. Two entries would mean the
    // recipient gets it twice for no reason.
    let list = addEntry([], entry({ localId: 'a' }));
    list = addEntry(list, entry({ localId: 'a', attempts: 3 }));
    assert.equal(list.length, 1);
    assert.equal(list[0].attempts, 3);
  });

  test('different messages coexist', () => {
    let list = addEntry([], entry({ localId: 'a' }));
    list = addEntry(list, entry({ localId: 'b' }));
    assert.equal(list.length, 2);
  });

  test('removing takes out only the named message', () => {
    let list = addEntry(addEntry([], entry({ localId: 'a' })), entry({ localId: 'b' }));
    list = removeEntry(list, 'a');
    assert.deepEqual(list.map((e) => e.localId), ['b']);
  });

  test('find returns null rather than undefined for a miss', () => {
    assert.equal(findEntry([], 'nope'), null);
    assert.equal(findEntry(null, 'nope'), null);
  });

  test('survives a corrupt list rather than throwing', () => {
    for (const bad of [null, undefined, 'nope', [null, 3]]) {
      assert.doesNotThrow(() => addEntry(bad, entry()));
      assert.doesNotThrow(() => removeEntry(bad, 'a'));
      assert.doesNotThrow(() => dueEntries(bad, NOW));
      assert.doesNotThrow(() => nextWakeup(bad, NOW));
    }
  });
});

describe('what is due', () => {
  test('nothing before its time', () => {
    const list = [entry({ localId: 'a', nextAt: NOW + 5000 })];
    assert.deepEqual(dueEntries(list, NOW), []);
  });

  test('due once the delay has elapsed', () => {
    const list = [entry({ localId: 'a', nextAt: NOW + 5000 })];
    assert.equal(dueEntries(list, NOW + 5000).length, 1);
  });

  test('an exhausted entry is never due again', () => {
    // It stops retrying itself and waits for the user. Retrying forever would
    // hammer a relay that is never coming back.
    const list = [entry({ localId: 'a', nextAt: NOW - 1, attempts: MAX_ATTEMPTS })];
    assert.deepEqual(dueEntries(list, NOW), []);
    assert.equal(isExhausted(list[0]), true);
  });

  test('the attempt just below the cap still retries', () => {
    // The boundary, or the cap silently means one fewer than it says.
    const list = [entry({ localId: 'a', nextAt: NOW - 1, attempts: MAX_ATTEMPTS - 1 })];
    assert.equal(dueEntries(list, NOW).length, 1);
    assert.equal(isExhausted(list[0]), false);
  });
});

describe('recording an attempt', () => {
  test('counts it and pushes the next one out', () => {
    const before = entry({ nextAt: NOW });
    const after = afterAttempt(before, { now: NOW, random: noJitter });
    assert.equal(after.attempts, 1);
    assert.ok(after.nextAt > NOW);
  });

  test('does not mutate the entry it was given', () => {
    // A half-applied update would leave a message sent but not counted, which
    // is how a retry loop becomes infinite.
    const before = entry({ attempts: 2 });
    afterAttempt(before, { now: NOW, random: noJitter });
    assert.equal(before.attempts, 2);
  });

  test('reaches exhaustion in exactly MAX_ATTEMPTS steps', () => {
    let e = entry();
    for (let i = 0; i < MAX_ATTEMPTS; i++) {
      assert.equal(isExhausted(e), false, `gave up early at attempt ${i}`);
      e = afterAttempt(e, { now: NOW, random: noJitter });
    }
    assert.equal(isExhausted(e), true, 'never gave up');
  });

  test('a manual retry clears the backoff and the attempt count', () => {
    const dead = entry({ attempts: MAX_ATTEMPTS, nextAt: NOW + MAX_DELAY_MS });
    const revived = forceDue(dead, NOW);
    assert.equal(isExhausted(revived), false);
    assert.equal(dueEntries([revived], NOW).length, 1);
  });
});

describe('when to wake up', () => {
  test('null when there is nothing waiting', () => {
    assert.equal(nextWakeup([], NOW), null);
    assert.equal(nextWakeup([entry({ attempts: MAX_ATTEMPTS })], NOW), null);
  });

  test('the soonest pending entry wins', () => {
    const list = [
      entry({ localId: 'a', nextAt: NOW + 9000 }),
      entry({ localId: 'b', nextAt: NOW + 3000 })
    ];
    assert.equal(nextWakeup(list, NOW), 3000);
  });

  test('never negative for something already overdue', () => {
    assert.equal(nextWakeup([entry({ nextAt: NOW - 10_000 })], NOW), 0);
  });

  test('ignores exhausted entries when picking the next wake', () => {
    const list = [
      entry({ localId: 'dead', nextAt: NOW + 1000, attempts: MAX_ATTEMPTS }),
      entry({ localId: 'live', nextAt: NOW + 4000 })
    ];
    assert.equal(nextWakeup(list, NOW), 4000);
  });
});

describe('the receiver drops a duplicate retry', () => {
  const SENDER = 'a'.repeat(64);

  test('recognises a message it already has', () => {
    const messages = [{ senderId: SENDER, remoteId: 'lid-1', text: 'hi' }];
    assert.equal(alreadyReceived(messages, SENDER, 'lid-1'), true);
  });

  test('lets a genuinely new message through', () => {
    const messages = [{ senderId: SENDER, remoteId: 'lid-1' }];
    assert.equal(alreadyReceived(messages, SENDER, 'lid-2'), false);
  });

  test('does not confuse two senders reusing an id', () => {
    // localId is minted per device with no coordination, so two contacts can
    // produce the same one. Without the sender in the comparison, one peer's
    // message would silently suppress another's.
    const messages = [{ senderId: SENDER, remoteId: 'lid-1' }];
    assert.equal(alreadyReceived(messages, 'b'.repeat(64), 'lid-1'), false);
  });

  test('an untagged message is never treated as a duplicate', () => {
    // History written before _lid existed has no remoteId. Treating that as a
    // match would drop every incoming message from an un-upgraded peer.
    const messages = [{ senderId: SENDER, text: 'old', remoteId: undefined }];
    assert.equal(alreadyReceived(messages, SENDER, undefined), false);
    assert.equal(alreadyReceived(messages, SENDER, null), false);
  });

  test('survives a broken history rather than throwing', () => {
    for (const bad of [null, undefined, 'nope', [null, 3]]) {
      assert.doesNotThrow(() => alreadyReceived(bad, SENDER, 'lid-1'));
    }
  });
});

describe('constants', () => {
  test('the ack timeout is longer than the first retry delay', () => {
    // Otherwise a message is declared lost before its first retry was even
    // due, and every send would double up.
    assert.ok(ACK_TIMEOUT_MS > nextDelay(0, fullJitter));
  });

  test('giving up takes minutes, not seconds', () => {
    let total = 0;
    for (let n = 0; n < MAX_ATTEMPTS; n++) total += nextDelay(n, noJitter);
    assert.ok(total > 60_000, `gives up after only ${Math.round(total / 1000)}s`);
  });
});
