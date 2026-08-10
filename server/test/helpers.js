// Reading what the relay actually left on disk.
//
// The database is no longer one file. A mutation appends a record to db.log
// and only periodically folds it back into db.json, so a test that reads the
// snapshot alone is reading a stale and incomplete picture.
//
// That matters most for the assertions that something must NOT be stored. A
// test checking db.json for a leaked credential keeps passing after the write
// moves into the journal, and it is then protecting nothing. Everything here
// therefore covers both files.
//
// Rows are returned as "every version ever written" rather than the current
// value. For "this must never be on disk" that is the stronger question: it
// catches a secret that was written once and later overwritten, which a
// snapshot read would miss entirely.

import fs from 'node:fs';
import path from 'node:path';

const snapshotPath = (dataDir) => path.join(dataDir, 'db.json');
const journalPath = (dataDir) => path.join(dataDir, 'db.log');

function readIfPresent(file) {
  try {
    return fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
  } catch {
    return '';
  }
}

/** Every journal record that parsed, oldest first. A torn tail is skipped. */
export function journalRecords(dataDir) {
  return readIfPresent(journalPath(dataDir))
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => { try { return JSON.parse(line); } catch { return null; } })
    .filter(Boolean);
}

/** The parsed snapshot, or an empty schema if there is not one yet. */
export function snapshot(dataDir) {
  const raw = readIfPresent(snapshotPath(dataDir));
  if (!raw) return { users: {}, offlineMessages: [], pushSubscriptions: {}, preKeys: {} };
  try {
    return JSON.parse(raw);
  } catch {
    return { users: {}, offlineMessages: [], pushSubscriptions: {}, preKeys: {} };
  }
}

/**
 * Every byte the database occupies at rest, snapshot and journal together.
 * Use this for "value X must never appear on disk".
 */
export function bytesAtRest(dataDir) {
  return readIfPresent(snapshotPath(dataDir)) + '\n' + readIfPresent(journalPath(dataDir));
}

/**
 * Every version of a user row that has been written, keyed by username.
 * A row in the snapshot and each `user` journal record both count.
 */
export function userRowsAtRest(dataDir, username) {
  const key = String(username || '').toLowerCase();
  const rows = [];
  const snap = snapshot(dataDir).users || {};
  if (snap[key]) rows.push(snap[key]);
  for (const rec of journalRecords(dataDir)) {
    if (rec.op === 'user' && rec.k === key && rec.v) rows.push(rec.v);
  }
  return rows;
}

/** Every queued message row that has been written, snapshot and journal. */
export function queuedRowsAtRest(dataDir) {
  const rows = [...(snapshot(dataDir).offlineMessages || [])];
  for (const rec of journalRecords(dataDir)) {
    if (rec.op === 'queue' && rec.v) rows.push(rec.v);
  }
  return rows;
}

/**
 * The journal operations db.js can write.
 *
 * Parsed from the source rather than listed, so that adding an operation
 * without teaching these helpers about it fails loudly in
 * persistence.test.js instead of quietly narrowing what the suite inspects.
 */
export function declaredOps(dbSource) {
  const start = dbSource.indexOf('const OPS = {');
  if (start < 0) return [];
  const end = dbSource.indexOf('\n};', start);
  return [...dbSource.slice(start, end).matchAll(/^  (\w+):/gm)].map(([, name]) => name);
}

/** The operations the helpers above actually understand. */
export const HANDLED_OPS = ['user', 'prekeys', 'push', 'queue', 'drain', 'devicelist'];

/** Every version of an account's device list that has been written. */
export function deviceListsAtRest(dataDir, idPub) {
  const lists = [];
  const snap = snapshot(dataDir).deviceLists || {};
  if (snap[idPub]) lists.push(snap[idPub]);
  for (const rec of journalRecords(dataDir)) {
    if (rec.op === 'devicelist' && rec.k === idPub && rec.v) lists.push(rec.v);
  }
  return lists;
}
