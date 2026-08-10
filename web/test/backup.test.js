// Encrypted backup and restore.
//
// The format has to survive being handled by someone hostile: it is a file,
// it can be copied, and the header is readable before any key exists. So the
// tests are mostly about what happens when the file is wrong, not when it is
// right. A backup that only works when nobody has touched it is not a backup.
//
// Every test pins `iterations` low. The real default is 600 000, which is the
// point, but paying it a few dozen times would make the suite slow enough that
// people stop running it.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  createBackup, openBackup, inspectBackup, collectBackup, mergeBackup,
  summarise, backupAad, BACKUP_STORES, MIN_PASSPHRASE_LENGTH,
  MIN_ITERATIONS, MAX_ITERATIONS, DEFAULT_ITERATIONS
} from '../src/backup.js';
import { bytesToHex, sha256Hash, hexToBytes } from '../src/crypto-bundle.js';
import { corruptHex } from './helpers.js';

const PASS = 'correct horse battery staple';
const FAST = { iterations: MIN_ITERATIONS, username: 'alice', createdAt: 1_700_000_000_000 };

function sampleState() {
  return {
    messages: [
      { contactId: 'c1', messageIndex: 1, sender: 'me', text: 'first', timestamp: 100, localId: 'a' },
      { contactId: 'c1', messageIndex: 2, sender: 'them', text: 'second', timestamp: 200, localId: 'b' }
    ],
    contacts: [{ idPub: 'c1', nickname: 'Bo' }],
    groups: [{ id: 'g1', name: 'Cabin', members: ['c1'] }],
    profile: { nickname: 'Al', bio: '' },
    chatMeta: { c1: { pinned: true } },
    drafts: { c1: 'half typed' },
    settings: { theme: 'graphite', soundEnabled: true, appLockPinHash: 'secret', appLockSalt: 'x', appLockEnabled: true }
  };
}

/** Rebuilds the digest so a deliberately edited file is not rejected as damaged. */
function reseal(file, patch) {
  const next = { ...file, ...patch };
  next.digest = bytesToHex(sha256Hash(hexToBytes(next.ct))).slice(0, 32);
  return next;
}

describe('what a backup carries', () => {
  test('collects every store the format declares', () => {
    const payload = collectBackup(sampleState());
    assert.deepEqual(Object.keys(payload).sort(), BACKUP_STORES.slice().sort());
  });

  test('never carries ratchet sessions or prekeys', () => {
    // Restoring old ratchet state rewinds chain keys that have already
    // produced messages, and restoring prekey private halves lets two devices
    // both claim the same one-time keys. Losing sessions costs an automatic
    // re-handshake; restoring them costs key reuse.
    const payload = collectBackup({ ...sampleState(), sessions: { c1: {} }, preKeys: { otk: {} } });
    assert.equal('sessions' in payload, false);
    assert.equal('preKeys' in payload, false);
  });

  test('strips the app-lock verifier', () => {
    // It is a device-local control. Carrying it would move a lock onto a
    // machine whose owner never set one.
    const { settings } = collectBackup(sampleState());
    assert.equal('appLockPinHash' in settings, false);
    assert.equal('appLockSalt' in settings, false);
    assert.equal('appLockEnabled' in settings, false);
    assert.equal(settings.theme, 'graphite');
  });

  test('an empty account still produces a valid payload', () => {
    const payload = collectBackup({});
    assert.deepEqual(payload.messages, []);
    assert.deepEqual(payload.profile, {});
  });

  test('summarise counts conversations, not just rows', () => {
    const s = summarise(collectBackup(sampleState()));
    assert.equal(s.messages, 2);
    assert.equal(s.conversations, 1);
    assert.equal(s.contacts, 1);
  });
});

describe('round trip', () => {
  test('restores exactly what was backed up', async () => {
    const payload = collectBackup(sampleState());
    const file = await createBackup(PASS, payload, FAST);
    assert.deepEqual(await openBackup(PASS, file), payload);
  });

  test('the plaintext is nowhere in the file', async () => {
    const payload = collectBackup(sampleState());
    const file = await createBackup(PASS, payload, FAST);
    const serialised = JSON.stringify(file);
    for (const secret of ['first', 'second', 'Cabin', 'half typed', 'Bo']) {
      assert.equal(serialised.includes(secret), false, `${secret} leaked into the file`);
    }
  });

  test('the same payload twice produces different ciphertext', async () => {
    // Fresh salt and nonce per backup. Identical files would tell anyone
    // holding two of them that nothing changed in between.
    const payload = collectBackup(sampleState());
    const a = await createBackup(PASS, payload, { iterations: MIN_ITERATIONS });
    const b = await createBackup(PASS, payload, { iterations: MIN_ITERATIONS });
    assert.notEqual(a.ct, b.ct);
    assert.notEqual(a.kdf.salt, b.kdf.salt);
    assert.notEqual(a.nonce, b.nonce);
  });

  test('the wrong passphrase fails rather than returning junk', async () => {
    const file = await createBackup(PASS, collectBackup(sampleState()), FAST);
    await assert.rejects(() => openBackup(PASS + 'x', file), /Wrong passphrase/);
  });

  test('an empty passphrase is refused at open', async () => {
    const file = await createBackup(PASS, collectBackup(sampleState()), FAST);
    await assert.rejects(() => openBackup('', file), /Passphrase required/);
  });

  test('a short passphrase is refused at create', async () => {
    await assert.rejects(
      () => createBackup('a'.repeat(MIN_PASSPHRASE_LENGTH - 1), {}, FAST),
      /at least/
    );
    // The boundary itself must be allowed, or the message lies about it.
    await createBackup('a'.repeat(MIN_PASSPHRASE_LENGTH), {}, FAST);
  });

  test('unicode passphrases survive the round trip', async () => {
    const pass = 'hűvös éjszaka 夜';
    const file = await createBackup(pass, { messages: [] }, FAST);
    assert.deepEqual(await openBackup(pass, file), { messages: [] });
  });
});

describe('key separation', () => {
  test('the same passphrase and salt give a different key than the account KDF', async () => {
    // People reuse passwords. If the backup key were the account encryption
    // key, a stolen backup file plus the password would be the account.
    const { deriveMasterKeyV2 } = await import('../src/crypto-bundle.js');
    const salt = 'a'.repeat(32);
    const account = await deriveMasterKeyV2(PASS, salt, MIN_ITERATIONS);

    // Encrypting under the raw account key must not open the backup, which is
    // only true because of the HKDF step.
    const file = await createBackup(PASS, { messages: [] }, { ...FAST, salt });
    const { gcm } = await import('@noble/ciphers/aes.js');
    assert.throws(() =>
      gcm(account.slice(32, 64), hexToBytes(file.nonce), backupAad(file)).decrypt(hexToBytes(file.ct)));
  });

  test('the salt is bound into the derived key', async () => {
    const a = await createBackup(PASS, { messages: [] }, { ...FAST, salt: 'a'.repeat(32), nonce: 'b'.repeat(24) });
    const b = await createBackup(PASS, { messages: [] }, { ...FAST, salt: 'c'.repeat(32), nonce: 'b'.repeat(24) });
    assert.notEqual(a.ct, b.ct);
  });
});

describe('a file that has been tampered with', () => {
  test('editing the username breaks the tag', async () => {
    // The header sits outside the ciphertext because restore reads it before
    // it has a key. Binding it as associated data is what stops it being a
    // free-text field an attacker controls.
    const file = await createBackup(PASS, collectBackup(sampleState()), FAST);
    await assert.rejects(() => openBackup(PASS, reseal(file, { username: 'mallory' })), /altered/);
  });

  test('editing the timestamp breaks the tag', async () => {
    const file = await createBackup(PASS, collectBackup(sampleState()), FAST);
    await assert.rejects(() => openBackup(PASS, reseal(file, { createdAt: 1 })), /altered/);
  });

  test('editing the iteration count breaks the tag', async () => {
    const file = await createBackup(PASS, collectBackup(sampleState()), FAST);
    const patched = reseal(file, { kdf: { ...file.kdf, iterations: MIN_ITERATIONS + 1 } });
    await assert.rejects(() => openBackup(PASS, patched), /Wrong passphrase|altered/);
  });

  test('flipping a byte of ciphertext is reported as damage, not a bad passphrase', async () => {
    // The distinction is the whole reason the digest exists. Telling someone
    // their passphrase is wrong when the file is truncated sends them looking
    // in the wrong place.
    const file = await createBackup(PASS, collectBackup(sampleState()), FAST);
    await assert.rejects(() => openBackup(PASS, { ...file, ct: corruptHex(file.ct) }), /damaged/);
  });

  test('a truncated file is reported as damage', async () => {
    const file = await createBackup(PASS, collectBackup(sampleState()), FAST);
    await assert.rejects(() => openBackup(PASS, { ...file, ct: file.ct.slice(0, -8) }), /damaged/);
  });

  test('ciphertext swapped in with a matching digest still fails the tag', async () => {
    // Recomputing the digest is trivial, so it is an integrity hint and not a
    // security control. AES-GCM is what actually refuses.
    const mine = await createBackup(PASS, { messages: [{ text: 'mine' }] }, FAST);
    const theirs = await createBackup(PASS, { messages: [{ text: 'theirs' }] },
      { ...FAST, salt: 'f'.repeat(32) });
    await assert.rejects(() => openBackup(PASS, reseal(mine, { ct: theirs.ct })), /altered/);
  });
});

describe('inspectBackup', () => {
  test('accepts a real file and reports its header', async () => {
    const file = await createBackup(PASS, { messages: [] }, FAST);
    const shape = inspectBackup(file);
    assert.equal(shape.ok, true);
    assert.equal(shape.username, 'alice');
    assert.equal(shape.iterations, MIN_ITERATIONS);
  });

  test('refuses anything that is not a Talon backup', () => {
    for (const bad of [null, undefined, 'nope', 42, {}, { app: 'other', kind: 'backup' }]) {
      assert.equal(inspectBackup(bad).ok, false);
    }
    // A settings export is the file people will pick by mistake.
    assert.match(inspectBackup({ app: 'talon', kind: 'settings', v: 1 }).reason, /not a Talon backup/);
  });

  test('refuses a future format version rather than guessing', async () => {
    const file = await createBackup(PASS, { messages: [] }, FAST);
    assert.match(inspectBackup(reseal(file, { v: 99 })).reason, /not supported/);
  });

  test('refuses an absurd iteration count before deriving anything', async () => {
    // A hostile file naming 500 million iterations is a denial of service
    // against whoever opens it. The bound has to be checked before the KDF
    // runs, not after.
    const file = await createBackup(PASS, { messages: [] }, FAST);
    for (const iterations of [1, 1000, MIN_ITERATIONS - 1, MAX_ITERATIONS + 1, 5e8]) {
      const patched = reseal(file, { kdf: { ...file.kdf, iterations } });
      assert.equal(inspectBackup(patched).ok, false, `${iterations} should be out of range`);
      await assert.rejects(() => openBackup(PASS, patched), /out of range/);
    }
    assert.equal(inspectBackup(reseal(file, { kdf: { ...file.kdf, iterations: MAX_ITERATIONS } })).ok, true);
  });

  test('refuses malformed salts and nonces', async () => {
    const file = await createBackup(PASS, { messages: [] }, FAST);
    assert.equal(inspectBackup(reseal(file, { kdf: { ...file.kdf, salt: 'short' } })).ok, false);
    assert.equal(inspectBackup(reseal(file, { kdf: { ...file.kdf, salt: 'z'.repeat(32) } })).ok, false);
    assert.equal(inspectBackup({ ...file, nonce: 'ab' }).ok, false);
    assert.equal(inspectBackup({ ...file, ct: '' }).ok, false);
    assert.equal(inspectBackup({ ...file, ct: 'not hex!' }).ok, false);
  });

  test('the default iteration count is inside the accepted range', () => {
    assert.ok(DEFAULT_ITERATIONS >= MIN_ITERATIONS && DEFAULT_ITERATIONS <= MAX_ITERATIONS);
  });
});

describe('merging a restore into a live device', () => {
  const current = () => ({
    messages: [
      { contactId: 'c1', messageIndex: 1, sender: 'me', text: 'first', timestamp: 100, localId: 'a' },
      { contactId: 'c1', messageIndex: 9, sender: 'me', text: 'newer', timestamp: 900, localId: 'z' }
    ],
    contacts: [{ idPub: 'c1', nickname: 'Bo' }],
    groups: [],
    profile: { nickname: 'Al' },
    chatMeta: { c1: { pinned: false } },
    drafts: { c1: 'typing now' },
    settings: { theme: 'paper' }
  });

  test('adds only what is missing', () => {
    const { result, stats } = mergeBackup(current(), collectBackup(sampleState()));
    assert.equal(stats.messages, 1);
    assert.equal(result.messages.length, 3);
    assert.equal(stats.contacts, 0);
    assert.equal(stats.groups, 1);
  });

  test('restoring the same file twice adds nothing the second time', () => {
    // Idempotence is what makes a restore safe to retry after a failure part
    // way through.
    const payload = collectBackup(sampleState());
    const once = mergeBackup(current(), payload).result;
    const twice = mergeBackup(once, payload);
    assert.equal(twice.stats.messages, 0);
    assert.deepEqual(twice.result.messages, once.messages);
  });

  test('deduplicates history written before localId existed', () => {
    // Old rows only have the (contactId, messageIndex, sender) triple. If the
    // triple stopped being consulted, restoring an old archive would duplicate
    // every message in it.
    //
    // Counting is not enough on its own: a merge that silently DROPS every
    // legacy row also reports zero added, and a mutation run proved that an
    // added-count assertion alone cannot tell the two apart. So this asserts
    // the surviving row is still there, and that a legacy row the device does
    // not have is genuinely recovered.
    const old = { contactId: 'c1', messageIndex: 1, sender: 'me', text: 'first', timestamp: 100 };
    const { result, stats } = mergeBackup({ messages: [old] }, { messages: [{ ...old }] });
    assert.equal(stats.messages, 0);
    assert.equal(result.messages.length, 1);
    assert.equal(result.messages[0].text, 'first');
  });

  test('recovers a legacy row the device is missing', () => {
    const old = { contactId: 'c1', messageIndex: 1, sender: 'me', text: 'first', timestamp: 100 };
    const other = { contactId: 'c1', messageIndex: 2, sender: 'them', text: 'reply', timestamp: 200 };
    const { result, stats } = mergeBackup({ messages: [old] }, { messages: [{ ...old }, other] });
    assert.equal(stats.messages, 1);
    assert.deepEqual(result.messages.map((m) => m.text), ['first', 'reply']);
  });

  test('contacts are keyed by identity key, not by an id field', () => {
    // Found in a browser, not here: the first version keyed contacts on `c.id`,
    // which no contact has. Every contact in the file was silently dropped and
    // the added count still read zero, so counting alone could not see it. The
    // address IS the key in Talon, and this is the assertion that says so.
    const known = { idPub: 'c1', nickname: 'Bo' };
    const fresh = { idPub: 'c2', nickname: 'Kit' };
    const { result, stats } = mergeBackup(
      { contacts: [known] }, { contacts: [{ ...known, nickname: 'stale' }, fresh] });

    assert.equal(stats.contacts, 1);
    assert.deepEqual(result.contacts.map((c) => c.idPub), ['c1', 'c2']);
    // The device's own name for a contact wins over the backup's copy.
    assert.equal(result.contacts[0].nickname, 'Bo');
  });

  test('a merge never deletes', () => {
    const before = current();
    const { result } = mergeBackup(before, { messages: [], contacts: [], groups: [] });
    assert.equal(result.messages.length, before.messages.length);
    assert.equal(result.contacts.length, before.contacts.length);
  });

  test('merged messages land in timestamp order', () => {
    // Rows arrive at the end of the array and the chat view renders in array
    // order, so without the sort a restore interleaves history wrongly.
    const incoming = { messages: [
      { contactId: 'c1', messageIndex: 5, sender: 'me', timestamp: 500, localId: 'm' }
    ] };
    const { result } = mergeBackup(current(), incoming);
    const stamps = result.messages.map((m) => m.timestamp);
    assert.deepEqual(stamps, [...stamps].sort((a, b) => a - b));
  });

  test('the live device wins for profile, drafts and settings', () => {
    const { result } = mergeBackup(current(), collectBackup(sampleState()));
    assert.equal(result.profile.nickname, 'Al');
    assert.equal(result.drafts.c1, 'typing now');
    assert.equal(result.settings.theme, 'paper');
    // But a setting the device has no opinion about is still recovered.
    assert.equal(result.settings.soundEnabled, true);
  });

  test('an empty device adopts the backup profile', () => {
    const { result } = mergeBackup({ profile: {} }, collectBackup(sampleState()));
    assert.equal(result.profile.nickname, 'Al');
  });

  test('replace mode overwrites the collections outright', () => {
    const { result } = mergeBackup(current(), collectBackup(sampleState()), { mode: 'replace' });
    assert.equal(result.messages.length, 2);
    assert.equal(result.messages.some((m) => m.localId === 'z'), false);
    assert.equal(result.drafts.c1, 'half typed');
  });

  test('replace never restores the app lock', () => {
    // Replace is the destructive path, which makes it the easy place to
    // accidentally reinstate a device-local control.
    const { result } = mergeBackup(current(),
      { settings: { appLockEnabled: true, appLockPinHash: 'nope' } }, { mode: 'replace' });
    assert.equal(result.settings.appLockEnabled, undefined);
    assert.equal(result.settings.appLockPinHash, undefined);
  });

  test('survives structurally broken input', () => {
    for (const bad of [null, undefined, {}, { messages: 'nope' }, { messages: [null, 3] }]) {
      assert.doesNotThrow(() => mergeBackup(current(), bad));
      assert.doesNotThrow(() => mergeBackup(bad, current()));
    }
  });
});
