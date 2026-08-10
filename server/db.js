import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// TALON_DATA_DIR relocates every piece of live state: the database, the
// certificates, the VAPID keypair and uploads. It exists so the test suite can
// run against a throwaway directory instead of the real one. Nothing should
// ever be able to run a test and lose an account, or worse, regenerate the CA
// that every trusting device has installed.
export const DATA_DIR = process.env.TALON_DATA_DIR
  ? path.resolve(process.env.TALON_DATA_DIR)
  : path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'db.json');
// The journal. Everything since the last snapshot, one JSON record per line.
const LOG_PATH = path.join(DATA_DIR, 'db.log');

// Ensure data folder exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// How large the journal may grow before it is folded back into a snapshot.
//
// The rule is self-tuning: a journal is allowed to reach the size of the
// snapshot it sits beside, with a floor so a nearly empty database still gets
// a useful amount of appending. That bounds replay work at boot to roughly one
// snapshot's worth of records, and bounds disk to about twice the snapshot,
// without a constant that is wrong for both a two-user relay and a large one.
const MIN_LOG_BYTES = Number(process.env.TALON_DB_LOG_MIN_BYTES || 64 * 1024);

// Default empty schema
let db = {
  users: {},          // username (lowercase) -> { username, idPub, authHash, encryptedIdPriv, encryptedIdPrivNonce, encryptedContacts, encryptedContactsNonce, encryptedGroups, encryptedGroupsNonce }
  offlineMessages: [], // Array of { id, senderId, recipientId, recipientDev, payload, queuedDay }
  pushSubscriptions: {}, // idPub -> [ { endpoint, keys: { p256dh, auth }, addedAt } ]
  preKeys: {},         // keyId -> { signPub, signedPreKey: {pub,sig}, oneTimePreKeys: [{id,pub}] }, public material only
  deviceLists: {}      // idPub -> { idPub, rev, devices: [{deviceId, devPub, name}], sig, signPub }
};

// `mutedIds` used to live here: idPub -> [ contactId, groupId, ... ] in the
// clear, so the relay could skip a push for a muted conversation. That is a
// slice of the contact graph sitting on disk, and it is the reason the muting
// decision moved into the service worker. See web/src/pushdb.js.

/* ------------------------------------------------------------- the journal */
//
// Every mutation used to rewrite the whole of db.json. That is correct and
// atomic, but it costs O(database) per change, and the hot path is one write
// per undelivered message: a relay holding a large offline queue rewrote that
// entire queue to add one row to it.
//
// So a mutation now appends one record describing itself, and the snapshot is
// rebuilt only when the journal has grown enough to be worth folding in.
//
// SQLite was the obvious alternative and does not fit. CI runs Node 20 and 22,
// where node:sqlite is either absent or experimental, so it would mean a
// native dependency and a compiler on every machine that runs a relay. This
// costs one file and no dependencies.
//
// EVERY OP MUST BE IDEMPOTENT. Compaction deletes the journal only after the
// new snapshot is safely renamed into place, so a crash in that window leaves
// a journal whose records are already in the snapshot, and they get replayed a
// second time on the next boot. Total assignment is naturally idempotent;
// appending is not, which is why `queue` checks the id first.
const OPS = {
  // Whole-record assignment for one user, one identity's prekeys, or one
  // identity's push subscriptions. Small next to the database, and replaying
  // one twice lands on the same value.
  user: (d, r) => { d.users[r.k] = r.v; },
  prekeys: (d, r) => { if (!d.preKeys) d.preKeys = {}; d.preKeys[r.k] = r.v; },
  push: (d, r) => { d.pushSubscriptions[r.k] = r.v; },
  devicelist: (d, r) => { if (!d.deviceLists) d.deviceLists = {}; d.deviceLists[r.k] = r.v; },

  // The hot path, and the whole reason for this design: one short line per
  // queued message instead of a copy of the entire queue.
  queue: (d, r) => {
    if (!r.v || d.offlineMessages.some((m) => m && m.id === r.v.id)) return;
    d.offlineMessages.push(r.v);
  },

  // Draining is a filter, so replaying it changes nothing the second time.
  // `v` is the set of device buckets that were drained; a row belongs to
  // exactly one bucket, so only those rows go.
  drain: (d, r) => {
    const buckets = Array.isArray(r.v) ? r.v : null;
    d.offlineMessages = d.offlineMessages.filter((m) => {
      if (m.recipientId !== r.k) return true;
      if (!buckets) return false;                    // legacy record: whole account
      return !buckets.includes(m.recipientDev || ACCOUNT_BUCKET);
    });
  }
};

/**
 * The bucket a queued message lands in when nobody named a device.
 *
 * Deliberately not 16 hex, so it can never collide with a real device id.
 * Rows written before multi-device existed have no `recipientDev` at all and
 * are read as belonging here.
 */
export const ACCOUNT_BUCKET = 'account';

let snapshotBytes = 0;
let logBytes = 0;

/**
 * Replays the journal onto whatever is currently in memory.
 *
 * Stops at the first record it cannot read rather than skipping past it. A
 * torn final line is the realistic corruption, because an append that was
 * interrupted leaves exactly that, and discarding it is correct. A bad record
 * in the middle means something worse happened, and the journal is an ordered
 * sequence: continuing past a hole would apply later operations to a state
 * their predecessors never produced.
 *
 * Nothing from a record is printed. `k` is a username or an identity key.
 */
function replayJournal() {
  if (!fs.existsSync(LOG_PATH)) return 0;

  let raw;
  try {
    raw = fs.readFileSync(LOG_PATH, 'utf-8');
  } catch (err) {
    console.error('[DB] Could not read the journal:', err.message);
    return 0;
  }

  const lines = raw.split('\n');
  let applied = 0;

  for (const line of lines) {
    if (!line.trim()) continue;

    let rec;
    try {
      rec = JSON.parse(line);
    } catch {
      console.error(`[DB] Journal ends in a torn record after ${applied}; discarding the remainder.`);
      break;
    }

    const apply = OPS[rec && rec.op];
    if (!apply) {
      console.error(`[DB] Unreadable journal record at ${applied + 1}; discarding the remainder.`);
      break;
    }

    try {
      apply(db, rec);
      applied++;
    } catch (err) {
      console.error(`[DB] Journal record at ${applied + 1} could not be applied; discarding the remainder.`);
      break;
    }
  }

  return applied;
}

/**
 * Folds the journal back into a fresh snapshot.
 *
 * The order below is load-bearing. The snapshot is written and renamed into
 * place BEFORE the journal is removed. Removing it first would mean a failed
 * write loses every mutation since the last compaction, whereas this way the
 * worst case is a journal that gets replayed onto a snapshot that already
 * contains it, which the idempotence rule on OPS exists to make harmless.
 */
function compact() {
  try {
    const json = JSON.stringify(db, null, 2);
    const tempPath = `${DB_PATH}.tmp`;
    fs.writeFileSync(tempPath, json, 'utf-8');
    fs.renameSync(tempPath, DB_PATH);
    snapshotBytes = Buffer.byteLength(json);
  } catch (err) {
    console.error('[DB] Critical: Failed to save database file:', err.message);
    return;
  }

  try {
    fs.rmSync(LOG_PATH, { force: true });
    logBytes = 0;
  } catch (err) {
    console.error('[DB] Could not clear the journal:', err.message);
  }
}

/**
 * Persists one mutation. The caller has already applied it in memory; this
 * only writes the record that reproduces it.
 *
 * Every mutator calls this exactly once, the way they all used to call
 * saveDb() exactly once. A failed append falls back to a full snapshot rather
 * than returning, because the mutation is live in memory and dropping it here
 * would mean the running relay and the disk disagree.
 */
function record(op, k, v) {
  let line;
  try {
    line = `${JSON.stringify({ op, k, v })}\n`;
  } catch (err) {
    console.error('[DB] Could not encode a journal record; writing a snapshot instead.');
    compact();
    return;
  }

  try {
    fs.appendFileSync(LOG_PATH, line, 'utf-8');
    logBytes += Buffer.byteLength(line);
  } catch (err) {
    console.error('[DB] Could not append to the journal; writing a snapshot instead:', err.message);
    compact();
    return;
  }

  if (logBytes > Math.max(MIN_LOG_BYTES, snapshotBytes)) compact();
}

/* ------------------------------------------------------------------- boot */

if (fs.existsSync(DB_PATH)) {
  try {
    const raw = fs.readFileSync(DB_PATH, 'utf-8');
    db = JSON.parse(raw);
    snapshotBytes = Buffer.byteLength(raw);
  } catch (err) {
    console.error('[DB] Failed to parse database file. Starting with a fresh one.', err.message);
  }

  const replayed = replayJournal();

  // Dropping the field from the schema above only stops NEW writes. A
  // database written before that change still holds the muted list, which
  // is the contact-graph slice this was all about, so it is deleted here
  // rather than left to sit until something happens to overwrite the file.
  const hadMutedIds = Boolean(db.mutedIds);
  if (hadMutedIds) delete db.mutedIds;

  // Compacting whenever anything was replayed keeps the journal from carrying
  // across restarts, and leaves db.json current at rest after a clean boot.
  if (replayed > 0 || hadMutedIds) {
    compact();
    if (replayed > 0) console.log(`[DB] Replayed ${replayed} journal record(s) into the snapshot.`);
    if (hadMutedIds) console.log('[DB] Removed the stored muted-conversation list (now client-side only).');
  }
} else {
  // A journal with no snapshot means the snapshot was lost. Replay is still
  // the best available reconstruction, so it happens before the file is made.
  const replayed = replayJournal();
  if (replayed > 0) console.log(`[DB] No snapshot found; rebuilt ${replayed} record(s) from the journal.`);
  compact();
}

export const Db = {
  /**
   * Fetch user details by username (case-insensitive)
   */
  getUser(username) {
    if (!username) return null;
    return db.users[username.toLowerCase()] || null;
  },

  /**
   * Create a new user account
   */
  createUser(username, userData) {
    if (!username) return;
    const key = username.toLowerCase();
    db.users[key] = {
      username: key,
      idPub: userData.idPub,
      // Password-KDF parameters the client must use. v1 accounts predate this
      // and carry none; see server.js kdfParamsFor().
      kdfVersion: userData.kdfVersion || 1,
      kdfSalt: userData.kdfSalt || null,
      kdfIterations: userData.kdfIterations || null,
      // The login token is never stored verbatim. See verifyAuth() in
      // server.js; authHash remains only on un-migrated v1 accounts.
      authSalt: userData.authSalt || null,
      authVerifier: userData.authVerifier || null,
      authHash: userData.authHash || null,
      encryptedIdPriv: userData.encryptedIdPriv,
      encryptedIdPrivNonce: userData.encryptedIdPrivNonce,
      encryptedContacts: userData.encryptedContacts || null,
      encryptedContactsNonce: userData.encryptedContactsNonce || null,
      encryptedGroups: userData.encryptedGroups || null,
      encryptedGroupsNonce: userData.encryptedGroupsNonce || null
    };
    record('user', key, db.users[key]);
  },

  /**
   * Applies a KDF upgrade: new derivation parameters, a new auth verifier and
   * the re-encrypted blobs, all in one atomic write so a crash can never leave
   * an account whose verifier and ciphertext disagree.
   */
  upgradeUserKdf(username, fields) {
    const key = String(username || '').toLowerCase();
    const user = db.users[key];
    if (!user) return false;

    user.kdfVersion = fields.kdfVersion;
    user.kdfSalt = fields.kdfSalt;
    user.kdfIterations = fields.kdfIterations;
    user.authSalt = fields.authSalt;
    user.authVerifier = fields.authVerifier;
    // The legacy verbatim token is retired the moment a verifier exists.
    user.authHash = null;

    user.encryptedIdPriv = fields.encryptedIdPriv;
    user.encryptedIdPrivNonce = fields.encryptedIdPrivNonce;
    if (fields.encryptedContacts) {
      user.encryptedContacts = fields.encryptedContacts;
      user.encryptedContactsNonce = fields.encryptedContactsNonce;
    }
    if (fields.encryptedGroups) {
      user.encryptedGroups = fields.encryptedGroups;
      user.encryptedGroupsNonce = fields.encryptedGroupsNonce;
    }

    // One record carrying the whole user, so a crash can never leave an
    // account whose verifier and ciphertext disagree.
    record('user', key, user);
    return true;
  },

  /* ------------------------------------------------------- device lists */
  //
  // An account publishes the list of devices it owns, signed by its own
  // signing key. The relay stores and serves it and does not understand it.
  //
  // IT DELIBERATELY DOES NOT VERIFY THE SIGNATURE. The relay serves the
  // signing key as well as the list, so checking one against the other proves
  // nothing an attacker who controls the relay could not arrange. The client
  // is the gate (see deviceListAcceptable in web/src/devices.js), and it pins
  // the signing key on first accept, which is the part that actually holds.
  //
  // Verifying here would mean a second copy of the canonical encoding living
  // on the server, which has to agree with the client byte for byte forever.
  // That is the theme-preload.js and sw.js drift hazard, taken on for no
  // security gain.
  //
  // What IS enforced: the caller is authenticated as the account owner (in
  // server.js), the shape is sane, and the revision moves forward. The last
  // one matters on its own, because it stops a captured publish from being
  // replayed later to reinstate a device that was revoked.

  getDeviceList(idPub) {
    if (!idPub || !db.deviceLists) return null;
    return db.deviceLists[idPub] || null;
  },

  /**
   * Stores a device list. Returns `{ ok, reason }` rather than a bare boolean
   * so the route can say why, which is the difference between a client bug
   * that is diagnosable and one that is not.
   */
  setDeviceList(idPub, list) {
    if (!idPub || !list || typeof list !== 'object') return { ok: false, reason: 'malformed' };
    if (!Array.isArray(list.devices) || list.devices.length < 1) {
      return { ok: false, reason: 'malformed' };
    }
    if (!Number.isSafeInteger(list.rev) || list.rev < 1) {
      return { ok: false, reason: 'bad revision' };
    }
    if (!list.sig || !list.signPub) return { ok: false, reason: 'unsigned' };

    // Bounded because the relay stores this and hands it to every peer who
    // asks. An unbounded list is an amplification vector regardless of
    // whether the client would accept it.
    if (list.devices.length > 8) return { ok: false, reason: 'too many devices' };

    if (!db.deviceLists) db.deviceLists = {};
    const existing = db.deviceLists[idPub];
    if (existing && Number(list.rev) <= Number(existing.rev || 0)) {
      return { ok: false, reason: 'stale revision' };
    }

    // Only the fields the protocol defines are kept. Storing whatever the
    // client sent would let it use the relay as free storage addressed to
    // its own account, and would put unreviewed fields in front of peers.
    db.deviceLists[idPub] = {
      idPub,
      rev: Number(list.rev),
      devices: list.devices.map((d) => ({
        deviceId: String(d.deviceId),
        devPub: String(d.devPub),
        name: String(d.name == null ? '' : d.name)
      })),
      sig: String(list.sig),
      signPub: String(list.signPub)
    };
    record('devicelist', idPub, db.deviceLists[idPub]);
    return { ok: true };
  },

  /* ------------------------------------------------------------ prekeys */
  //
  // Keyed by a 64-hex `keyId`. For a single-device account that is the
  // account's idPub, which is what every existing record uses. For a
  // multi-device account it is the individual device's public key, because
  // each device runs its own ratchet and must not consume another device's
  // one-time prekeys.
  //
  // Both live in one keyspace on purpose: an un-upgraded peer keeps working
  // unchanged, and there is no migration.
  //
  // The server stores only PUBLIC key material plus a signature it cannot
  // forge. The matching private keys never leave the owner's device. Handing
  // out a bundle is the one place the relay could attack the protocol, which
  // is exactly why the signed prekey carries an Ed25519 signature the fetcher
  // verifies.

  publishPreKeys(keyId, { signPub, signedPreKey, kemPreKey, oneTimePreKeys }) {
    if (!keyId) return false;
    if (!db.preKeys) db.preKeys = {};
    const existing = db.preKeys[keyId] || { oneTimePreKeys: [] };

    db.preKeys[keyId] = {
      signPub: signPub || existing.signPub,
      signedPreKey: signedPreKey || existing.signedPreKey,
      // Post-quantum prekey. Public material, signed by the owner: the relay
      // stores and hands it out but cannot substitute one of its own.
      kemPreKey: kemPreKey || existing.kemPreKey,
      // Replenishment appends; ids are allocated by the client.
      oneTimePreKeys: [
        ...(existing.oneTimePreKeys || []),
        ...(Array.isArray(oneTimePreKeys) ? oneTimePreKeys : [])
      ].slice(-200)
    };
    record('prekeys', keyId, db.preKeys[keyId]);
    return true;
  },

  /**
   * Returns a bundle and CONSUMES one one-time prekey. If the pool is empty
   * the bundle is still usable (X3DH degrades to three DH values), because running
   * out must never block messaging.
   */
  takePreKeyBundle(keyId) {
    const entry = db.preKeys && db.preKeys[keyId];
    if (!entry || !entry.signPub || !entry.signedPreKey) return null;

    let oneTimePreKey = null;
    if (entry.oneTimePreKeys && entry.oneTimePreKeys.length) {
      oneTimePreKey = entry.oneTimePreKeys.shift();
      // Consuming a one-time prekey is what provides forward secrecy, so the
      // deletion has to reach disk before the bundle reaches the caller.
      record('prekeys', keyId, entry);
    }
    return {
      signPub: entry.signPub,
      signedPreKey: entry.signedPreKey,
      kemPreKey: entry.kemPreKey || null,
      oneTimePreKey
    };
  },

  /**
   * One bundle per device on an account, for a sender about to fan out.
   *
   * Returns `null` when the account has published no device list, which means
   * a single implicit device and a caller that falls back to the account key.
   * That is not an error; it is what an un-upgraded peer looks like.
   *
   * A device with no prekeys yet comes back with `bundle: null` rather than
   * being dropped from the array. Silently omitting it would mean a device
   * that quietly never receives anything, which is the hardest class of bug
   * to notice from the outside.
   *
   * Each entry consumes one of THAT DEVICE'S one-time prekeys, which is the
   * whole reason prekeys are per device.
   */
  takeDeviceBundles(idPub) {
    const list = this.getDeviceList(idPub);
    if (!list || !Array.isArray(list.devices) || !list.devices.length) return null;
    return list.devices.map((d) => ({
      deviceId: d.deviceId,
      devPub: d.devPub,
      bundle: this.takePreKeyBundle(d.devPub)
    }));
  },

  countOneTimePreKeys(keyId) {
    const entry = db.preKeys && db.preKeys[keyId];
    return entry && entry.oneTimePreKeys ? entry.oneTimePreKeys.length : 0;
  },

  /** Replaces a v1 verbatim authHash with a salted verifier, in place. */
  setAuthVerifier(username, authSalt, authVerifier) {
    const key = String(username || '').toLowerCase();
    const user = db.users[key];
    if (!user) return false;
    user.authSalt = authSalt;
    user.authVerifier = authVerifier;
    user.authHash = null;
    record('user', key, user);
    return true;
  },

  /**
   * Sync/save user's encrypted contact list
   */
  updateUserContacts(username, encryptedContacts, encryptedContactsNonce) {
    const key = username.toLowerCase();
    const user = db.users[key];
    if (user) {
      user.encryptedContacts = encryptedContacts;
      user.encryptedContactsNonce = encryptedContactsNonce;
      record('user', key, user);
      return true;
    }
    return false;
  },

  /**
   * Sync/save user's encrypted group list
   */
  updateUserGroups(username, encryptedGroups, encryptedGroupsNonce) {
    const key = username.toLowerCase();
    const user = db.users[key];
    if (user) {
      user.encryptedGroups = encryptedGroups;
      user.encryptedGroupsNonce = encryptedGroupsNonce;
      record('user', key, user);
      return true;
    }
    return false;
  },

  /**
   * Register a push subscription for a given identity key (idPub).
   * Multiple devices/browsers can each hold their own subscription.
   */
  addPushSubscription(idPub, subscription) {
    if (!idPub || !subscription || !subscription.endpoint) return false;
    if (!db.pushSubscriptions[idPub]) db.pushSubscriptions[idPub] = [];
    const existing = db.pushSubscriptions[idPub];
    const alreadyPresent = existing.some(s => s.endpoint === subscription.endpoint);
    if (!alreadyPresent) {
      existing.push({
        endpoint: subscription.endpoint,
        keys: subscription.keys,
        addedAt: Date.now()
      });
      record('push', idPub, existing);
    }
    return true;
  },

  /**
   * Remove a single push subscription by endpoint (explicit unsubscribe,
   * or pruning after the push service reports it as gone).
   */
  removePushSubscription(idPub, endpoint) {
    const existing = db.pushSubscriptions[idPub];
    if (!existing) return false;
    const before = existing.length;
    db.pushSubscriptions[idPub] = existing.filter(s => s.endpoint !== endpoint);
    if (db.pushSubscriptions[idPub].length !== before) {
      record('push', idPub, db.pushSubscriptions[idPub]);
      return true;
    }
    return false;
  },

  getPushSubscriptions(idPub) {
    return db.pushSubscriptions[idPub] || [];
  },

  /**
   * Snapshot of server-wide counters, used for the periodic stats log.
   */
  getStats() {
    const totalOfflineMessages = db.offlineMessages.length;
    const totalPushSubscriptions = Object.values(db.pushSubscriptions).reduce((sum, arr) => sum + arr.length, 0);
    return {
      totalUsers: Object.keys(db.users).length,
      totalOfflineMessages,
      totalPushSubscriptions,
      // Journal size, so a relay that has stopped compacting is visible in the
      // periodic stats line rather than only as a slow boot months later.
      journalBytes: logBytes
    };
  },

  /**
   * Add a message to the offline queue
   */
  addOfflineMessage(senderId, recipientId, payload, recipientDev) {
    // Neither field the client reads is a clock. The id used to embed
    // Date.now() and the row carried a millisecond timestamp, which together
    // recorded exactly when every undelivered message was written. The client
    // never read either one (see the 'offline-messages' handler in app.js),
    // and nothing on the server reads them, so both were pure residue.
    //
    // `queuedDay` survives, rounded to the day, only so a future sweep can
    // expire an abandoned queue. A sweep would be measured in days anyway, and
    // a day is a far weaker statement than a millisecond.
    const DAY = 24 * 60 * 60 * 1000;
    const message = {
      id: crypto.randomUUID(),
      senderId,
      recipientId,
      // Which of the recipient's devices this envelope is for. The sender
      // decides, because only the sender knows which device's session it
      // encrypted to. A row with no device belongs to the account bucket and
      // is what a sender who has never heard of devices produces.
      recipientDev: recipientDev || ACCOUNT_BUCKET,
      payload,
      queuedDay: Math.floor(Date.now() / DAY) * DAY
    };
    db.offlineMessages.push(message);
    // The hot path. This used to rewrite every queued message in order to add
    // one, so a relay with a large backlog paid for the backlog on every
    // single delivery. The journal record is the message and nothing else.
    record('queue', null, message);
    return message;
  },

  /**
   * Retrieve and delete queued offline messages for a recipient
   */
  /**
   * Retrieve and delete queued messages for a recipient.
   *
   * `buckets` names which device queues to drain. A single-device client
   * passes nothing and gets the account bucket, which is exactly what it used
   * to get. A device-aware client passes its own device id AND the account
   * bucket, so that envelopes queued by a sender who never heard of devices
   * are not stranded forever behind a device id they will never carry.
   *
   * The drain is destructive, which is why `register` is authenticated.
   */
  getAndClearOfflineMessages(recipientId, buckets) {
    const wanted = Array.isArray(buckets) && buckets.length
      ? buckets
      : [ACCOUNT_BUCKET];

    const mine = (m) => m.recipientId === recipientId
      && wanted.includes(m.recipientDev || ACCOUNT_BUCKET);

    const messages = db.offlineMessages.filter(mine);
    if (messages.length > 0) {
      db.offlineMessages = db.offlineMessages.filter((m) => !mine(m));
      record('drain', recipientId, wanted);
    }
    return messages;
  },

  /** Device ids that currently have something queued, for the fan-out below. */
  queuedDevicesFor(recipientId) {
    const seen = new Set();
    for (const m of db.offlineMessages) {
      if (m.recipientId === recipientId) seen.add(m.recipientDev || ACCOUNT_BUCKET);
    }
    return [...seen];
  }
};
