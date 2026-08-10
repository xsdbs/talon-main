// Vault mode: encryption of the local blobs at rest.
//
// This had no tests, which is uncomfortable for the one feature whose failure
// mode is "the account looks wiped". Two invariants carry the whole design and
// both are easy to break by accident:
//
//   1. Settings must stay in the clear. They record whether the vault is even
//      on, so they have to be readable before there is a key.
//   2. Every read must be self-describing. A profile half-migrated by a crash
//      still has to open, and a locked vault must return the empty fallback
//      rather than throwing or handing back ciphertext.
//
// store.js reaches for localStorage as a global, so a shim is installed before
// anything imports it. Nothing in that module touches storage at import time.

import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

/** The smallest thing that behaves like Storage for these purposes. */
function makeWebStorage() {
  const map = new Map();
  return {
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => { map.set(k, String(v)); },
    removeItem: (k) => { map.delete(k); },
    clear: () => map.clear(),
    key: (i) => Array.from(map.keys())[i] ?? null,
    get length() { return map.size; },
    _keys: () => Array.from(map.keys())
  };
}

globalThis.localStorage = makeWebStorage();
globalThis.sessionStorage = makeWebStorage();

const {
  Storage, DEFAULT_SETTINGS, WIPE_PREFIXES,
  unlockVault, lockVault, vaultUnlocked, migrateVault
} = await import('../src/store.js');

const USER = 'alice';
const KEY = 'ab'.repeat(32); // 32-byte encryption key, hex

/** The raw string on disk, bypassing readJSON entirely. */
const raw = (suffix) => localStorage.getItem(`e2e_${suffix}_${USER}`);
const isSealed = (s) => {
  if (!s) return false;
  try { return JSON.parse(s).__enc === 1; } catch { return false; }
};

/**
 * Every per-account setter on Storage, found rather than listed.
 *
 * saveSession is the one exception: it takes (session, remember) and writes
 * outside the e2e_ namespace, so it is not an account store.
 *
 * Enumerating matters more than it looks. Both callers below used to name
 * their stores by hand, which meant a store added later was silently exempt
 * from the very check that exists to catch a forgotten store.
 */
const accountSetters = () => Object.keys(Storage)
  .filter((name) => name.startsWith('save') && name !== 'saveSession')
  .sort();

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  lockVault();
});

describe('with the vault off', () => {
  test('blobs are stored as readable JSON', () => {
    Storage.saveMessages(USER, [{ text: 'hello' }]);
    assert.equal(isSealed(raw('messages')), false);
    assert.ok(raw('messages').includes('hello'));
  });

  test('everything round-trips', () => {
    Storage.saveContacts(USER, [{ idPub: 'c1' }]);
    assert.deepEqual(Storage.getContacts(USER), [{ idPub: 'c1' }]);
  });
});

describe('with the vault unlocked', () => {
  beforeEach(() => unlockVault(KEY));

  test('the plaintext is not on disk', () => {
    Storage.saveMessages(USER, [{ text: 'the quick brown fox' }]);
    const onDisk = raw('messages');
    assert.equal(isSealed(onDisk), true);
    assert.equal(onDisk.includes('quick brown fox'), false);
  });

  test('reads still return the original object', () => {
    const rows = [{ text: 'hello', n: 1 }, { text: 'again', n: 2 }];
    Storage.saveMessages(USER, rows);
    assert.deepEqual(Storage.getMessages(USER), rows);
  });

  test('every vaulted store is actually encrypted', () => {
    // Named individually rather than looped over a list, so adding a store
    // and forgetting to vault it shows up as a missing test rather than as a
    // silently shorter loop.
    Storage.saveMessages(USER, [{ a: 1 }]);
    Storage.saveContacts(USER, [{ idPub: 'x' }]);
    Storage.saveGroups(USER, [{ id: 'g' }]);
    Storage.saveSessions(USER, { s: 1 });
    Storage.saveProfile(USER, { nickname: 'Al' });
    Storage.saveDrafts(USER, { c: 'typing' });
    Storage.saveChatMeta(USER, { c: { pinned: true } });
    Storage.savePreKeys(USER, { otk: {} });

    for (const store of ['messages', 'contacts', 'groups', 'sessions',
      'profile', 'drafts', 'chatmeta', 'prekeys']) {
      assert.equal(isSealed(raw(store)), true, `${store} was written in the clear`);
    }
  });

  test('settings stay in the clear', () => {
    // Load-bearing: settings say whether the vault is on, so they have to be
    // readable before unlockVault() can possibly have run.
    Storage.saveSettings(USER, { ...DEFAULT_SETTINGS, encryptAtRest: true });
    assert.equal(isSealed(raw('settings')), false);
    assert.equal(Storage.getSettings(USER).encryptAtRest, true);
  });

  test('the same value written twice does not produce the same ciphertext', () => {
    Storage.saveMessages(USER, [{ a: 1 }]);
    const first = raw('messages');
    Storage.saveMessages(USER, [{ a: 1 }]);
    assert.notEqual(raw('messages'), first);
  });

  test('two users do not collide', () => {
    Storage.saveMessages('alice', [{ who: 'a' }]);
    Storage.saveMessages('bob', [{ who: 'b' }]);
    assert.deepEqual(Storage.getMessages('alice'), [{ who: 'a' }]);
    assert.deepEqual(Storage.getMessages('bob'), [{ who: 'b' }]);
  });

  test('usernames are matched case-insensitively', () => {
    Storage.saveMessages('Alice', [{ a: 1 }]);
    assert.deepEqual(Storage.getMessages('alice'), [{ a: 1 }]);
  });
});

describe('locking', () => {
  test('a locked vault returns the empty fallback, not ciphertext', () => {
    // The dangerous failure. If a read returned the raw record instead, the
    // app would render garbage; if it threw, boot would die. It returns the
    // documented empty value, and initializeSession is what must unlock first.
    unlockVault(KEY);
    Storage.saveMessages(USER, [{ text: 'secret' }]);
    lockVault();

    const out = Storage.getMessages(USER);
    assert.deepEqual(out, []);
    assert.equal(vaultUnlocked(), false);
  });

  test('the wrong key returns the fallback rather than throwing', () => {
    unlockVault(KEY);
    Storage.saveMessages(USER, [{ text: 'secret' }]);
    unlockVault('cd'.repeat(32));
    assert.deepEqual(Storage.getMessages(USER), []);
  });

  test('relocking and unlocking with the right key recovers the data', () => {
    unlockVault(KEY);
    Storage.saveMessages(USER, [{ text: 'secret' }]);
    lockVault();
    unlockVault(KEY);
    assert.deepEqual(Storage.getMessages(USER), [{ text: 'secret' }]);
  });
});

describe('records are self-describing', () => {
  test('a half-migrated profile reads correctly', () => {
    // A crash midway through migrateVault leaves some stores sealed and some
    // not. Both have to open, or recovery means data loss.
    lockVault();
    Storage.saveContacts(USER, [{ idPub: 'plain' }]);   // written in the clear
    unlockVault(KEY);
    Storage.saveMessages(USER, [{ text: 'sealed' }]);   // written encrypted

    assert.deepEqual(Storage.getContacts(USER), [{ idPub: 'plain' }]);
    assert.deepEqual(Storage.getMessages(USER), [{ text: 'sealed' }]);
  });

  test('a corrupt record returns the fallback rather than throwing', () => {
    localStorage.setItem(`e2e_messages_${USER}`, 'not json at all');
    assert.deepEqual(Storage.getMessages(USER), []);
  });
});

describe('migrateVault', () => {
  test('encrypts what is already on disk', () => {
    Storage.saveMessages(USER, [{ text: 'before' }]);
    Storage.saveContacts(USER, [{ idPub: 'c1' }]);
    assert.equal(isSealed(raw('messages')), false);

    const moved = migrateVault(USER, KEY, 'encrypt');

    assert.equal(moved, 2);
    assert.equal(isSealed(raw('messages')), true);
    assert.equal(isSealed(raw('contacts')), true);
    // The point of the exercise: the data survived.
    assert.deepEqual(Storage.getMessages(USER), [{ text: 'before' }]);
    assert.deepEqual(Storage.getContacts(USER), [{ idPub: 'c1' }]);
  });

  test('migrates every store, not just the ones anyone thinks to check', () => {
    // A mutation run caught this: dropping a prefix from VAULT_PREFIXES leaves
    // that store in the clear when the vault is switched on, and the two
    // stores an earlier test happened to use were both still covered. Prekeys
    // are the sharpest case, because they hold private key halves.
    //
    // The stores are enumerated from Storage itself, so a store added later
    // is covered without anyone remembering to extend this list. Naming them
    // by hand is what let the outbox slip through once already.
    lockVault();
    for (const name of accountSetters()) Storage[name](USER, {});
    Storage.savePreKeys(USER, { signPriv: 'secret-private-half' });

    // Settings stay in the clear on purpose, so they are not expected to move.
    const stores = accountSetters()
      .map((name) => name.replace(/^save/, '').toLowerCase())
      .filter((store) => store !== 'settings');
    assert.equal(migrateVault(USER, KEY, 'encrypt'), stores.length,
      'every store on disk should have been migrated');

    for (const store of stores) {
      assert.equal(isSealed(raw(store)), true, `${store} was left in the clear`);
    }
    assert.equal(raw('prekeys').includes('secret-private-half'), false);
    assert.deepEqual(Storage.getPreKeys(USER).signPriv, 'secret-private-half');
  });

  test('decrypts back to plaintext without losing anything', () => {
    Storage.saveMessages(USER, [{ text: 'round trip' }]);
    migrateVault(USER, KEY, 'encrypt');
    migrateVault(USER, KEY, 'decrypt');

    assert.equal(isSealed(raw('messages')), false);
    assert.deepEqual(Storage.getMessages(USER), [{ text: 'round trip' }]);
    assert.equal(vaultUnlocked(), false);
  });

  test('leaves settings alone in both directions', () => {
    Storage.saveSettings(USER, { ...DEFAULT_SETTINGS, theme: 'paper' });
    migrateVault(USER, KEY, 'encrypt');
    assert.equal(isSealed(raw('settings')), false);
    assert.equal(Storage.getSettings(USER).theme, 'paper');
  });

  test('skips stores that do not exist rather than creating empty ones', () => {
    Storage.saveMessages(USER, [{ a: 1 }]);
    assert.equal(migrateVault(USER, KEY, 'encrypt'), 1);
    assert.equal(raw('groups'), null);
  });

  test('touches only the named user', () => {
    Storage.saveMessages('alice', [{ who: 'a' }]);
    Storage.saveMessages('bob', [{ who: 'b' }]);
    migrateVault('alice', KEY, 'encrypt');

    assert.equal(isSealed(localStorage.getItem('e2e_messages_alice')), true);
    assert.equal(isSealed(localStorage.getItem('e2e_messages_bob')), false);
  });
});

describe('a device signing in for the first time', () => {
  // Found by a two-device browser run, and invisible to every test that
  // existed. The "is the vault on" flag lives in this device's settings, so a
  // second device has no preference recorded at all. Reading the merged
  // defaults treated that as "off" and wrote the whole account, identity key
  // material included, to that disk in the clear.
  //
  // hasSettings is what distinguishes "no preference here" from "chose off",
  // and getSettings cannot, because it merges the defaults in.

  test('a fresh device is distinguishable from one that chose the defaults', () => {
    assert.equal(Storage.hasSettings(USER), false, 'a fresh device claims to have settings');
    Storage.saveSettings(USER, { ...DEFAULT_SETTINGS, encryptAtRest: false });
    assert.equal(Storage.hasSettings(USER), true, 'a stored preference was not detected');
    assert.equal(Storage.getSettings(USER).encryptAtRest, false,
      'an explicit choice of off must survive');
  });

  test('the two cases are not conflated by the merged defaults', () => {
    // Both read as encryptAtRest false through getSettings, which is exactly
    // why the check has to be hasSettings and not the merged value.
    const fresh = Storage.getSettings(USER).encryptAtRest;
    Storage.saveSettings(USER, { ...DEFAULT_SETTINGS, encryptAtRest: false });
    const chosen = Storage.getSettings(USER).encryptAtRest;
    assert.equal(fresh, chosen,
      'the fixture is wrong: these must look identical through getSettings');
    assert.notEqual(Storage.hasSettings(USER), false);
  });

  test('an account that deliberately turned the vault off keeps it off', () => {
    // The other direction. A device that HAS a preference must be obeyed, or
    // turning the vault off would silently undo itself on the next sign-in.
    Storage.saveSettings(USER, { ...DEFAULT_SETTINGS, encryptAtRest: false });
    assert.equal(Storage.hasSettings(USER) && Storage.getSettings(USER).encryptAtRest, false);
  });
});

describe('panic wipe cannot be outrun by a new store', () => {
  test('every key Storage writes is covered by WIPE_PREFIXES', () => {
    // The documented footgun: add a Storage method, forget its prefix, and
    // Panic Wipe leaves the data on the device.
    //
    // The setters are enumerated rather than listed by hand. A hand-written
    // list is itself the same footgun one level up: this test used to name
    // nine setters, saveOutbox was added as a tenth, and dropping e2e_outbox_
    // from WIPE_PREFIXES stayed green because nothing here ever wrote one.
    unlockVault(KEY);
    for (const name of accountSetters()) Storage[name](USER, {});

    const uncovered = localStorage._keys().filter(
      (k) => k.startsWith('e2e_') && !WIPE_PREFIXES.some((p) => k.startsWith(p))
    );
    assert.deepEqual(uncovered, [],
      `these keys survive a panic wipe: ${uncovered.join(', ')}`);
  });

  test('the appearance mirror is outside the account namespace', () => {
    // talon_appearance is deliberately unprefixed so the pre-paint script can
    // read it before it knows who is logged in. It holds no personal data, but
    // it must not be mistaken for an account store.
    Storage.saveSettings(USER, { ...DEFAULT_SETTINGS, theme: 'ash' });
    const appearance = localStorage.getItem('talon_appearance');
    assert.ok(appearance);
    assert.equal(appearance.includes('ash'), true);
    assert.equal(appearance.includes(USER), false);
  });
});

describe('sessions', () => {
  test('a remembered session goes to localStorage and a plain one does not', () => {
    Storage.saveSession({ username: USER, encryptionKeyHex: KEY }, true);
    assert.ok(localStorage.getItem('talon_session_persistent'));
    assert.equal(sessionStorage.getItem('talon_session'), null);

    Storage.saveSession({ username: USER, encryptionKeyHex: KEY }, false);
    assert.equal(localStorage.getItem('talon_session_persistent'), null);
    assert.ok(sessionStorage.getItem('talon_session'));
  });

  test('clearSession removes both', () => {
    Storage.saveSession({ username: USER }, true);
    Storage.saveSession({ username: USER }, false);
    Storage.clearSession();
    assert.equal(Storage.getSession(), null);
  });
});
