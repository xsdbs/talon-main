// --- THE MUTED-TAG STORE ---
//
// The relay used to hold the muted conversation list in the clear so it could
// skip a push. That list is a slice of the contact graph, and handing it over
// was the last deliberate plaintext exception in the design. It is gone.
//
// The decision now belongs to the service worker, which is the only thing
// awake when the app is closed. A service worker cannot read localStorage, so
// the tags live in IndexedDB, which it can. The mirror in sw.js is deliberately
// a copy rather than an import: sw.js is served as-is and never goes through
// esbuild, so it cannot share a module with src/. Keep the two in step, the
// same way theme-preload.js mirrors the theme table.
//
// Nothing here is secret. A tag is a one-way function of a conversation and a
// recipient, and the store holds only tags, so reading this database tells you
// how many conversations are muted and nothing whatsoever about which.

export const PUSH_DB_NAME = 'talon-push';
export const PUSH_DB_STORE = 'meta';
export const MUTED_TAGS_KEY = 'mutedTags';

function openDb() {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') return reject(new Error('no IndexedDB'));
    const req = indexedDB.open(PUSH_DB_NAME, 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(PUSH_DB_STORE)) {
        req.result.createObjectStore(PUSH_DB_STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/**
 * Replaces the stored tag list.
 *
 * Failure is swallowed on purpose. A browser with IndexedDB blocked still has
 * to be able to send and receive messages; the cost of the failure is that a
 * muted conversation notifies anyway, which is an annoyance rather than a
 * correctness problem, and the in-app mute still applies.
 */
export async function writeMutedTags(tags) {
  try {
    const db = await openDb();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(PUSH_DB_STORE, 'readwrite');
      tx.objectStore(PUSH_DB_STORE).put(Array.from(tags || []), MUTED_TAGS_KEY);
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
    db.close();
    return true;
  } catch (err) {
    console.warn('[Push] Could not store muted tags locally:', err && err.message);
    return false;
  }
}

/** Wipes the store. Called from panic wipe, which must leave nothing behind. */
export async function clearMutedTags() {
  try {
    const db = await openDb();
    await new Promise((resolve) => {
      const tx = db.transaction(PUSH_DB_STORE, 'readwrite');
      tx.objectStore(PUSH_DB_STORE).clear();
      tx.oncomplete = resolve;
      tx.onerror = resolve;
      tx.onabort = resolve;
    });
    db.close();
  } catch { /* nothing stored, nothing to clear */ }
}
