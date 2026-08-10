// Token bucket behaviour, tested against an injected clock rather than by
// sleeping. A rate limiter tested with real timers is slow and flaky, and the
// interesting cases (a bucket refilling over an hour) cannot be tested at all.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createLimiter, clientKey } from '../ratelimit.js';

describe('token bucket', () => {
  test('allows up to capacity, then refuses', () => {
    const l = createLimiter({ capacity: 3, refillPerSec: 1 });
    const t = 1000;
    assert.equal(l.take('a', 1, t), true);
    assert.equal(l.take('a', 1, t), true);
    assert.equal(l.take('a', 1, t), true);
    assert.equal(l.take('a', 1, t), false, 'the fourth in the same instant must be refused');
  });

  test('refills over time', () => {
    const l = createLimiter({ capacity: 2, refillPerSec: 1 });
    let t = 0;
    l.take('a', 1, t); l.take('a', 1, t);
    assert.equal(l.take('a', 1, t), false);

    t += 1000; // one second, one token
    assert.equal(l.take('a', 1, t), true);
    assert.equal(l.take('a', 1, t), false, 'only one token should have accrued');
  });

  test('never refills past capacity', () => {
    const l = createLimiter({ capacity: 2, refillPerSec: 10 });
    let t = 0;
    l.take('a', 2, t);
    t += 60_000; // a minute of refill at 10/s is far more than capacity
    assert.equal(l.take('a', 2, t), true);
    assert.equal(l.take('a', 1, t), false, 'the bucket must cap at capacity, not accumulate');
  });

  test('keys are independent', () => {
    const l = createLimiter({ capacity: 1, refillPerSec: 0.1 });
    assert.equal(l.take('a', 1, 0), true);
    assert.equal(l.take('a', 1, 0), false);
    assert.equal(l.take('b', 1, 0), true, 'one caller must not exhaust another');
  });

  test('a costly take can be refused while a cheap one passes', () => {
    const l = createLimiter({ capacity: 10, refillPerSec: 1 });
    assert.equal(l.take('a', 20, 0), false, 'cost above capacity is never satisfiable');
    assert.equal(l.take('a', 1, 0), true, 'a refused take must not have spent anything');
  });

  test('reports a sane retry-after', () => {
    const l = createLimiter({ capacity: 2, refillPerSec: 0.5 });
    l.take('a', 2, 0);
    assert.equal(l.retryAfter('a', 1, 0), 2, '0.5 tokens/sec means 2s for one token');
    assert.equal(l.retryAfter('a', 1, 4000), 0, 'after 4s it should be free');
  });

  test('refund returns tokens without exceeding capacity', () => {
    const l = createLimiter({ capacity: 2, refillPerSec: 0 });
    l.take('a', 2, 0);
    assert.equal(l.take('a', 1, 0), false);
    l.refund('a', 1);
    assert.equal(l.take('a', 1, 0), true);
    l.refund('a', 99);
    assert.equal(l.take('a', 2, 0), true);
    assert.equal(l.take('a', 1, 0), false, 'refund must not push past capacity');
  });

  test('fails open when there is no key', () => {
    // Better to let a request through than to lock out every caller the
    // server could not identify.
    const l = createLimiter({ capacity: 1, refillPerSec: 0 });
    assert.equal(l.take(null, 1, 0), true);
    assert.equal(l.take('', 1, 0), true);
  });
});

describe('bucket housekeeping', () => {
  test('sweeping drops fully refilled buckets', () => {
    // An unbounded map keyed by remote address is itself a memory-exhaustion
    // vector, which would make the limiter the vulnerability.
    const l = createLimiter({ capacity: 5, refillPerSec: 1 });
    for (let i = 0; i < 500; i++) l.take('ip-' + i, 1, 0);
    assert.equal(l.size(), 500);

    l.sweep(10_000); // 10s at 1/s refills the single token each spent
    assert.equal(l.size(), 0, 'idle buckets carry no state and should be dropped');
  });

  test('sweeping keeps buckets that are still depleted', () => {
    const l = createLimiter({ capacity: 5, refillPerSec: 1 });
    l.take('busy', 5, 0);
    l.sweep(1000); // only one token back, still short of capacity
    assert.equal(l.size(), 1, 'a depleted bucket must survive the sweep');
    assert.equal(l.take('busy', 5, 1000), false, 'and must still be enforcing');
  });
});

describe('client key', () => {
  test('uses the socket address', () => {
    assert.equal(clientKey({ socket: { remoteAddress: '100.64.0.1' } }), '100.64.0.1');
  });

  test('ignores X-Forwarded-For', () => {
    // Trusting a client-supplied header would let any caller reset their own
    // bucket by inventing an address. Nothing is meant to sit in front of this
    // relay, so there is no legitimate reason to honour it.
    const req = {
      socket: { remoteAddress: '100.64.0.1' },
      headers: { 'x-forwarded-for': '1.2.3.4' }
    };
    assert.equal(clientKey(req), '100.64.0.1');
  });

  test('degrades to a constant rather than throwing', () => {
    assert.equal(clientKey({}), 'unknown');
  });
});
