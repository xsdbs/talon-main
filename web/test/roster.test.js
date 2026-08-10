// Signed group rosters.
//
// Groups are pure client-side fan-out, so the relay has no concept of one and
// cannot arbitrate membership. That left the roster as an assertion: whoever's
// envelope arrived last decided who was in the group, and a new invitee had no
// way to distinguish a real roster from one a member had made up.
//
// The rules under test: only the owner can produce a roster, a roster edited
// in flight fails verification, revisions only move forward, and the owner's
// signing key is pinned on first accept.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  buildRosterMessage, signRosterWith, verifyRoster, rosterAcceptable
} from '../src/messaging.js';
import { bytesToHex } from '../src/crypto-bundle.js';
import { makeParty, signingKeyFor, corruptHex } from './helpers.js';

/** An owner plus a signed roster naming `members`. */
function makeGroup(members, { rev = 1, name = 'Weekend Cabin' } = {}) {
  const owner = makeParty();
  const signing = signingKeyFor(owner.idPrivHex);
  const all = [owner.idPubHex, ...members];
  const fields = { groupId: 'g-1', rev, name, owner: owner.idPubHex, members: all };
  return {
    owner,
    signing,
    roster: {
      ...fields,
      sig: signRosterWith(signing.privateKey, fields),
      ownerSignPub: bytesToHex(signing.publicKey)
    }
  };
}

describe('canonical encoding', () => {
  test('member order does not change the signature input', () => {
    // Fan-out means different members can hold the same set in different
    // orders. If order mattered, half the group would reject a valid roster.
    const a = buildRosterMessage({ groupId: 'g', rev: 1, name: 'n', owner: 'o', members: ['a', 'b', 'c'] });
    const b = buildRosterMessage({ groupId: 'g', rev: 1, name: 'n', owner: 'o', members: ['c', 'a', 'b'] });
    assert.deepEqual(a, b);
  });

  test('duplicate members collapse', () => {
    const a = buildRosterMessage({ groupId: 'g', rev: 1, name: 'n', owner: 'o', members: ['a', 'b'] });
    const b = buildRosterMessage({ groupId: 'g', rev: 1, name: 'n', owner: 'o', members: ['a', 'b', 'b'] });
    assert.deepEqual(a, b);
  });

  test('every field is covered', () => {
    const base = { groupId: 'g', rev: 1, name: 'n', owner: 'o', members: ['a'] };
    const ref = bytesToHex(buildRosterMessage(base));
    for (const [k, v] of Object.entries({
      groupId: 'g2', rev: 2, name: 'n2', owner: 'o2', members: ['a', 'b']
    })) {
      assert.notEqual(bytesToHex(buildRosterMessage({ ...base, [k]: v })), ref,
        `changing ${k} must change the signed bytes`);
    }
  });

  test('is domain separated from the prekey signatures', () => {
    // The same Ed25519 key signs prekeys. Without a distinct prefix a roster
    // signature could be presented as a prekey signature or the reverse.
    const bytes = buildRosterMessage({ groupId: 'g', rev: 1, name: 'n', owner: 'o', members: [] });
    assert.match(new TextDecoder().decode(bytes), /^TalonGroupRoster:/);
  });
});

describe('signature verification', () => {
  test('accepts a roster the owner signed', () => {
    const { roster } = makeGroup(['m1', 'm2']);
    assert.equal(verifyRoster(roster, roster.sig, roster.ownerSignPub), true);
  });

  test('rejects a tampered member list', () => {
    // The attack this exists to stop: a member adding themselves, or hiding
    // someone, on the way past.
    const { roster } = makeGroup(['m1', 'm2']);
    const forged = { ...roster, members: [...roster.members, 'mallory'] };
    assert.equal(verifyRoster(forged, roster.sig, roster.ownerSignPub), false);
  });

  test('rejects a tampered name, revision or owner', () => {
    const { roster } = makeGroup(['m1']);
    for (const patch of [{ name: 'Renamed' }, { rev: 99 }, { owner: 'someone-else' }]) {
      assert.equal(verifyRoster({ ...roster, ...patch }, roster.sig, roster.ownerSignPub), false,
        `${JSON.stringify(patch)} should invalidate the signature`);
    }
  });

  test('rejects a corrupted signature', () => {
    const { roster } = makeGroup(['m1']);
    assert.equal(verifyRoster(roster, corruptHex(roster.sig), roster.ownerSignPub), false);
  });

  test('rejects a signature from a different key', () => {
    const { roster } = makeGroup(['m1']);
    const stranger = signingKeyFor(makeParty().idPrivHex);
    assert.equal(verifyRoster(roster, roster.sig, bytesToHex(stranger.publicKey)), false);
  });

  test('a member cannot mint a roster of their own', () => {
    const { roster } = makeGroup(['m1']);
    const mallory = makeParty();
    const malSigning = signingKeyFor(mallory.idPrivHex);
    const fields = { ...roster, rev: roster.rev + 1, members: [...roster.members, 'friend'] };
    const forged = {
      ...fields,
      sig: signRosterWith(malSigning.privateKey, fields),
      ownerSignPub: bytesToHex(malSigning.publicKey)
    };
    // The signature is internally valid, so only the pin catches this.
    assert.equal(verifyRoster(forged, forged.sig, forged.ownerSignPub), true);
    const verdict = rosterAcceptable(
      { rev: roster.rev, owner: roster.owner, ownerSignPub: roster.ownerSignPub }, forged
    );
    assert.equal(verdict.ok, false);
    assert.equal(verdict.reason, 'owner signing key changed');
  });

  test('malformed input returns false rather than throwing', () => {
    const { roster } = makeGroup(['m1']);
    for (const [sig, pub] of [[null, roster.ownerSignPub], [roster.sig, null], ['zz', 'zz'], [undefined, undefined]]) {
      assert.equal(verifyRoster(roster, sig, pub), false);
    }
  });
});

describe('acceptance rules', () => {
  test('accepts a well-formed first roster', () => {
    const { roster } = makeGroup(['m1']);
    assert.deepEqual(rosterAcceptable(null, roster), { ok: true });
  });

  test('refuses an unsigned roster outright', () => {
    // Accepting these "for compatibility" would make the whole mechanism
    // opt-out for anyone willing to leave a field off.
    const { roster } = makeGroup(['m1']);
    assert.equal(rosterAcceptable(null, { ...roster, sig: undefined }).reason, 'unsigned');
    assert.equal(rosterAcceptable(null, { ...roster, ownerSignPub: undefined }).reason, 'unsigned');
  });

  // The `signature verification` block above exercises verifyRoster directly.
  // These assert that rosterAcceptable actually consults it. Without them,
  // deleting the verifyRoster call left every test green, which a mutation run
  // caught. Testing a helper is not the same as testing that the helper is
  // wired to the decision.
  test('refuses a roster whose signature does not verify', () => {
    const { roster } = makeGroup(['m1']);
    const tampered = { ...roster, members: [...roster.members, 'mallory'] };
    assert.equal(rosterAcceptable(null, tampered).reason, 'bad signature');
  });

  test('refuses a corrupted signature', () => {
    const { roster } = makeGroup(['m1']);
    assert.equal(
      rosterAcceptable(null, { ...roster, sig: corruptHex(roster.sig) }).reason,
      'bad signature'
    );
  });

  test('refuses a renamed group signed at the old name', () => {
    const { roster } = makeGroup(['m1']);
    assert.equal(
      rosterAcceptable(null, { ...roster, name: 'Renamed in flight' }).reason,
      'bad signature'
    );
  });

  test('refuses an owner who is not in the group', () => {
    const { roster, signing } = makeGroup(['m1']);
    const fields = { ...roster, members: roster.members.filter((m) => m !== roster.owner) };
    const signed = { ...fields, sig: signRosterWith(signing.privateKey, fields) };
    assert.equal(rosterAcceptable(null, signed).reason, 'owner not a member');
  });

  test('refuses a stale or replayed revision', () => {
    const { roster } = makeGroup(['m1'], { rev: 3 });
    const existing = { rev: 5, owner: roster.owner, ownerSignPub: roster.ownerSignPub };
    assert.equal(rosterAcceptable(existing, roster).reason, 'stale revision');
  });

  test('refuses the same revision twice', () => {
    const { roster } = makeGroup(['m1'], { rev: 4 });
    const existing = { rev: 4, owner: roster.owner, ownerSignPub: roster.ownerSignPub };
    assert.equal(rosterAcceptable(existing, roster).reason, 'stale revision');
  });

  test('accepts a newer revision from the same owner', () => {
    const g = makeGroup(['m1']);
    const fields = { ...g.roster, rev: 2, members: [...g.roster.members, 'm2'] };
    const next = { ...fields, sig: signRosterWith(g.signing.privateKey, fields) };
    const existing = { rev: 1, owner: g.roster.owner, ownerSignPub: g.roster.ownerSignPub };
    assert.deepEqual(rosterAcceptable(existing, next), { ok: true });
  });

  test('refuses a change of owner', () => {
    // Re-signed at the new revision, so this reaches the owner check rather
    // than being stopped earlier as a bad signature. A roster can be perfectly
    // well signed and still be a takeover attempt.
    const g = makeGroup(['m1']);
    const fields = { ...g.roster, rev: 2 };
    const next = { ...fields, sig: signRosterWith(g.signing.privateKey, fields) };
    assert.equal(verifyRoster(next, next.sig, next.ownerSignPub), true,
      'fixture assumption: the roster itself is validly signed');

    const existing = { rev: 1, owner: 'someone-else', ownerSignPub: g.roster.ownerSignPub };
    assert.equal(rosterAcceptable(existing, next).reason, 'owner changed');
  });

  test('refuses malformed revisions', () => {
    const { roster } = makeGroup(['m1']);
    for (const rev of [0, -1, 1.5, NaN, '2', undefined, Number.MAX_SAFE_INTEGER + 10]) {
      assert.equal(rosterAcceptable(null, { ...roster, rev }).ok, false,
        `rev ${String(rev)} should be refused`);
    }
  });

  test('refuses structurally broken input rather than throwing', () => {
    for (const bad of [null, undefined, {}, { groupId: 'g' }, { groupId: 'g', members: 'nope' }]) {
      assert.equal(rosterAcceptable(null, bad).ok, false);
    }
  });
});

describe('groups that predate signing', () => {
  // Signing is new. Groups already on disk have no owner and no pinned key,
  // and silently freezing them would look exactly like a sync bug. They must
  // adopt an owner on the first signed roster they are handed, and be pinned
  // from that point on.

  test('a legacy group adopts the first signed roster it receives', () => {
    const g = makeGroup(['m1'], { rev: 4 });
    const legacy = { rev: 3, members: ['old'], name: 'Old' }; // no owner, no pin
    assert.deepEqual(rosterAcceptable(legacy, g.roster), { ok: true });
  });

  test('a legacy group with no revision at all still accepts one', () => {
    const g = makeGroup(['m1'], { rev: 1 });
    assert.deepEqual(rosterAcceptable({ members: ['old'] }, g.roster), { ok: true });
  });

  test('once pinned, a second signing key is refused', () => {
    // The upgrade path must not be a permanent hole: after the first accept
    // the key is fixed.
    const g = makeGroup(['m1'], { rev: 1 });
    const adopted = {
      rev: g.roster.rev, owner: g.roster.owner, ownerSignPub: g.roster.ownerSignPub
    };

    const impostor = makeParty();
    const impSigning = signingKeyFor(impostor.idPrivHex);
    const fields = { ...g.roster, rev: 2 };
    const forged = {
      ...fields,
      sig: signRosterWith(impSigning.privateKey, fields),
      ownerSignPub: bytesToHex(impSigning.publicKey)
    };

    assert.equal(rosterAcceptable(adopted, forged).reason, 'owner signing key changed');
  });

  test('an unsigned update to a legacy group is still refused', () => {
    // Fail closed. Accepting unsigned rosters for "old" groups would let an
    // attacker simply claim the group is old.
    const legacy = { rev: 1, members: ['a', 'b'] };
    const unsigned = { groupId: 'g-1', rev: 2, name: 'x', owner: 'a', members: ['a', 'b', 'c'] };
    assert.equal(rosterAcceptable(legacy, unsigned).reason, 'unsigned');
  });
});
