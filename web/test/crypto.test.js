// The constant-rate cover traffic scheduler.
//
// Pure, so a full day of scheduling runs against an injected clock. The tests
// that matter here are the ones about what cover must NEVER do: reach an
// offline peer, wake a phone, or change its rate when you start typing. Each
// of those failures makes the feature worse than not having it, and none of
// them is visible from the outside.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  planCover, nextCoverTarget, keyOf, coverIntervalMs, coverPayload, isCover,
  COVER_FOREGROUND_MS, COVER_BACKGROUND_MS
} from '../src/cover.js';

const peers = (...ids) => ids.map((contactId) => ({ contactId }));

const base = {
  now: 1_000_000,
  lastSentAt: 0,
  onlineTargets: peers('aaa', 'bbb'),
  lastTarget: null,
  foreground: true,
  enabled: true
};

describe('when a cover cell is due', () => {
  test('not before the interval has elapsed', () => {
    const r = planCover({ ...base, lastSentAt: base.now - (COVER_FOREGROUND_MS - 1) });
    assert.equal(r.send, null);
  });

  test('exactly on the interval', () => {
    const r = planCover({ ...base, lastSentAt: base.now - COVER_FOREGROUND_MS });
    assert.ok(r.send);
  });

  test('a real send resets the clock instead of adding to it', () => {
    // THE MECHANISM. At a constant rate, traffic you generate must REPLACE a
    // cover cell, not arrive on top of one. If real sends were additive the
    // observable rate would rise while you typed, which is exactly the signal
    // cover traffic exists to erase, and every test above would still pass.
    const justSent = planCover({ ...base, lastSentAt: base.now });
    assert.equal(justSent.send, null, 'a cover cell went out right after a real message');
    assert.equal(justSent.nextCheckAt, base.now + COVER_FOREGROUND_MS);
  });

  test('backgrounded, the cadence slows down', () => {
    assert.ok(COVER_BACKGROUND_MS > COVER_FOREGROUND_MS);
    assert.equal(coverIntervalMs(true), COVER_FOREGROUND_MS);
    assert.equal(coverIntervalMs(false), COVER_BACKGROUND_MS);

    const bg = { ...base, foreground: false, lastSentAt: base.now - COVER_FOREGROUND_MS };
    assert.equal(planCover(bg).send, null, 'foreground cadence used while backgrounded');
    assert.ok(planCover({ ...bg, lastSentAt: base.now - COVER_BACKGROUND_MS }).send);
  });
});

describe('who a cover cell may reach', () => {
  test('never an offline peer, because the relay would queue it', () => {
    // Cover addressed to somebody who is not connected is written to the
    // relay's offline queue and stays there. At a fixed rate that is a way to
    // fill a disk with noise forever: a denial of service you inflict on
    // yourself, dressed up as a privacy feature.
    const r = planCover({ ...base, onlineTargets: [], lastSentAt: 0 });
    assert.equal(r.send, null);
  });

  test('nothing is scheduled when every contact goes offline mid-run', () => {
    let state = { ...base, lastSentAt: 0 };
    assert.ok(planCover(state).send);
    state = { ...state, onlineTargets: [] };
    assert.equal(planCover(state).send, null);
  });

  test('targets rotate rather than piling onto the first contact', () => {
    const targets = peers('aaa', 'bbb', 'ccc');
    const seen = [];
    let last = null;
    for (let i = 0; i < 6; i++) {
      const t = nextCoverTarget(targets, last);
      seen.push(t.contactId);
      last = keyOf(t);
    }
    // Starts at the first target on a cold start, then wraps.
    assert.deepEqual(seen, ['aaa', 'bbb', 'ccc', 'aaa', 'bbb', 'ccc']);
  });

  test('rotation survives the online set changing underneath it', () => {
    // Keyed by identity, not by index. An index into a list that just shrank
    // points at a different person, so cover would silently concentrate on
    // whoever moved into that slot.
    const t = nextCoverTarget(peers('bbb', 'ccc'), keyOf({ contactId: 'aaa' }));
    assert.ok(t, 'a target that is no longer online must not stall the rotation');
    assert.equal(t.contactId, 'bbb');
  });

  test('a single online contact is targeted repeatedly rather than skipped', () => {
    const only = peers('aaa');
    assert.equal(nextCoverTarget(only, keyOf(only[0])).contactId, 'aaa');
  });

  test('devices are distinct targets', () => {
    const targets = [
      { contactId: 'aaa', deviceId: '1111111111111111' },
      { contactId: 'aaa', deviceId: '2222222222222222' }
    ];
    assert.notEqual(keyOf(targets[0]), keyOf(targets[1]));
    assert.equal(nextCoverTarget(targets, keyOf(targets[0])).deviceId, '2222222222222222');
  });
});

describe('the switch', () => {
  test('disabled means nothing is ever scheduled', () => {
    const r = planCover({ ...base, enabled: false, lastSentAt: 0 });
    assert.equal(r.send, null);
  });

  test('disabled still returns a sane next check, so the loop does not spin', () => {
    const r = planCover({ ...base, enabled: false, lastSentAt: 0 });
    assert.ok(r.nextCheckAt > base.now);
  });
});

describe('the payload', () => {
  test('is recognisable to the receiver and nothing else', () => {
    assert.equal(isCover(coverPayload()), true);
    assert.equal(isCover({ type: 'text', text: 'hello' }), false);
    assert.equal(isCover(null), false);
    assert.equal(isCover({}), false);
  });

  test('is small, since padding makes its real size a full cell anyway', () => {
    assert.ok(JSON.stringify(coverPayload()).length < 40);
  });
});

describe('a day of scheduling', () => {
  test('holds a steady rate and never runs away', () => {
    // Drives the real loop rather than one call, because the failure this
    // catches is a nextCheckAt that does not advance: the timer then fires in
    // a tight loop and the "constant rate" becomes as fast as the CPU allows.
    let now = 0;
    let lastSentAt = 0;
    let lastTarget = null;
    let sent = 0;
    let iterations = 0;

    const DAY = 24 * 60 * 60 * 1000;
    while (now < DAY) {
      iterations++;
      assert.ok(iterations < 100_000, 'the scheduler is spinning rather than waiting');

      const r = planCover({ ...base, now, lastSentAt, lastTarget });
      if (r.send) {
        sent++;
        lastSentAt = now;
        lastTarget = keyOf(r.send);
      }
      assert.ok(r.nextCheckAt > now, `nextCheckAt (${r.nextCheckAt}) did not advance past now (${now})`);
      now = r.nextCheckAt;
    }

    const expected = DAY / COVER_FOREGROUND_MS;
    assert.ok(
      Math.abs(sent - expected) <= 2,
      `sent ${sent} cover cells in a day, expected about ${expected}`
    );
  });

  test('a chatty hour produces no more traffic than a silent one', () => {
    // The property the whole feature rests on. If a busy hour and an idle hour
    // produce different cell counts, the rate is not constant and an observer
    // can still see when you were talking.
    const HOUR = 60 * 60 * 1000;

    const run = (realSendEvery) => {
      let now = 0, lastSentAt = 0, lastTarget = null, cells = 0;
      while (now < HOUR) {
        const realSend = realSendEvery && now > 0 && now % realSendEvery === 0;
        if (realSend) { cells++; lastSentAt = now; }

        const r = planCover({ ...base, now, lastSentAt, lastTarget });
        if (r.send) { cells++; lastSentAt = now; lastTarget = keyOf(r.send); }
        now = Math.min(r.nextCheckAt, realSendEvery ? now + realSendEvery : r.nextCheckAt);
        if (now === 0) break;
      }
      return cells;
    };

    const silent = run(0);
    const chatty = run(COVER_FOREGROUND_MS * 2);
    assert.ok(
      Math.abs(silent - chatty) <= 2,
      `a silent hour sent ${silent} cells and a chatty hour sent ${chatty}`
    );
  });
});
