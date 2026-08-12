// Bump this on every app-shell change, or installed clients keep serving the
// stale cached shell forever (stale-while-revalidate returns cache first).
const CACHE_NAME = 'talon-cache-v25';

// Every fetch this worker makes to refill the cache uses `cache: 'reload'`,
// which skips the browser's own HTTP cache and forces a real network trip.
//
// Without it, bumping CACHE_NAME does nothing. `cache.add()` and the
// revalidation fetch below are ordinary fetches, so they were being answered
// out of the HTTP cache, and a brand new cache was immediately repopulated
// with the same stale bytes. On a phone that looks like a page frozen at an
// old version with no way to clear it.
const BYPASS_HTTP_CACHE = { cache: 'reload' };
const PRE_CACHE_ASSETS = [
  '/',
  '/index.html',
  '/style.css',
  '/theme-preload.js',
  '/js/app.js',
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png',
  '/fonts/inter-latin-wght-normal.woff2',
  '/fonts/jetbrains-mono-latin-wght-normal.woff2'
];

// Install Service Worker and cache all vital assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('[SW] Pre-caching application shell...');
        // Use addAll, but catch errors on individual files so setup doesn't break
        return Promise.allSettled(
          PRE_CACHE_ASSETS.map(asset =>
            cache.add(new Request(asset, BYPASS_HTTP_CACHE))
              .catch(err => console.warn(`[SW] Pre-cache failed for asset: ${asset}`, err))
          )
        );
      })
      .then(() => self.skipWaiting())
  );
});

// Activate Service Worker and clean up old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((name) => {
          if (name !== CACHE_NAME) {
            console.log('[SW] Removing deprecated cache:', name);
            return caches.delete(name);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

// Paths that must always hit the network, never the cache:
//  /ws          websocket upgrade
//  /api/        live data. Caching /api/vapid-public-key or an attachment
//               download would serve a stale key or a dead blob forever
//  /ca.crt      a cached CA would survive regeneration and break trust
//  /setup       the trust-install page must reflect the live certificate
function isNetworkOnly(pathname) {
  return pathname.includes('/ws')
    || pathname.startsWith('/api/')
    || pathname === '/ca.crt'
    || pathname === '/ca.pem'
    || pathname === '/setup'
    || pathname === '/setup/';
}

// The app shell: the files that actually change when the app is updated.
// Fonts and icons are excluded because they are large, immutable in practice,
// and there is no benefit to re-checking them on every load.
const SHELL_PATHS = new Set([
  '/', '/index.html', '/style.css', '/theme-preload.js', '/js/app.js', '/manifest.json'
]);

// Fetch handler. Network-first for the shell, stale-while-revalidate for
// everything else.
self.addEventListener('fetch', (event) => {
  // Only handle local GET requests
  const requestUrl = new URL(event.request.url);
  if (event.request.method !== 'GET' || requestUrl.origin !== self.location.origin || isNetworkOnly(requestUrl.pathname)) {
    return;
  }

  // Navigations fall back to the cached shell so a deep link still boots the
  // SPA when offline instead of hitting the server's plain-text 404.
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).catch(() => caches.match('/index.html'))
    );
    return;
  }

  // Shell assets are network-first, not stale-while-revalidate.
  //
  // Under SWR the cached copy is returned immediately and the fresh one only
  // lands in time for the *next* load, so a device is always exactly one
  // update behind. For a script and a stylesheet that must match the HTML that
  // was just fetched from the network, that is not a caching nicety, it is a
  // version skew. The cache stays populated and is still what answers when the
  // network is gone, which is all it was there for.
  if (SHELL_PATHS.has(requestUrl.pathname)) {
    event.respondWith(
      fetch(new Request(event.request.url, BYPASS_HTTP_CACHE))
        .then((networkResponse) => {
          if (networkResponse && networkResponse.status === 200) {
            const copy = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
          }
          return networkResponse;
        })
        .catch(() => caches.match(event.request))
    );
    return;
  }

  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      if (cachedResponse) {
        // Return cache instantly, fetch fresh copy in background to update
        // cache. `cache: 'reload'` is what makes this a real refresh rather
        // than the HTTP cache handing back the same stale bytes.
        fetch(new Request(event.request.url, BYPASS_HTTP_CACHE))
          .then((networkResponse) => {
            if (networkResponse && networkResponse.status === 200) {
              caches.open(CACHE_NAME).then((cache) => {
                cache.put(event.request, networkResponse);
              });
            }
          })
          .catch(() => {}); // Silently ignore fetch failure (e.g. offline)
        return cachedResponse;
      }

      // If not in cache, fetch from network
      return fetch(event.request).then((networkResponse) => {
        if (!networkResponse || networkResponse.status !== 200 || networkResponse.type !== 'basic') {
          return networkResponse;
        }

        const responseToCache = networkResponse.clone();
        caches.open(CACHE_NAME).then((cache) => {
          cache.put(event.request, responseToCache);
        });

        return networkResponse;
      });
    })
  );
});

// --- PUSH NOTIFICATIONS ---
//
// The relay is zero-knowledge and the push payload is now genuinely opaque:
// a single tag the sender derived from the conversation and this recipient.
// It used to carry conversationId, senderId and groupId, which meant handing
// Google, Apple or Mozilla a routing identifier on every message.
//
// Nothing here tries to reconstruct a sender or any content. The notification
// stays generic until the user opens the conversation, which is also why it no
// longer says whether the message was in a group: knowing that would have
// meant the relay knowing it.

const NOTIFICATION_TAG_PREFIX = 'talon-conv-';

// --- THE MUTED-TAG STORE ---
//
// Mirrors web/src/pushdb.js. It is a copy rather than an import because this
// file is served as-is and never goes through esbuild, so it cannot share a
// module with src/. Keep the two in step, the same way theme-preload.js
// mirrors the theme table.
//
// The relay used to hold the muted list in the clear and skip the push itself.
// That meant handing it a slice of the contact graph, so the decision moved
// here. A service worker cannot read localStorage, which is why this is
// IndexedDB.
const PUSH_DB_NAME = 'talon-push';
const PUSH_DB_STORE = 'meta';
const MUTED_TAGS_KEY = 'mutedTags';

function readMutedTags() {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolve(v); } };
    // Fail open. A push that shows when it should have been muted is an
    // annoyance; one that is swallowed because the database was slow is a
    // missed message.
    setTimeout(() => done([]), 400);
    try {
      const req = indexedDB.open(PUSH_DB_NAME, 1);
      req.onupgradeneeded = () => {
        if (!req.result.objectStoreNames.contains(PUSH_DB_STORE)) {
          req.result.createObjectStore(PUSH_DB_STORE);
        }
      };
      req.onerror = () => done([]);
      req.onsuccess = () => {
        try {
          const db = req.result;
          const get = db.transaction(PUSH_DB_STORE, 'readonly')
            .objectStore(PUSH_DB_STORE).get(MUTED_TAGS_KEY);
          get.onsuccess = () => { done(Array.isArray(get.result) ? get.result : []); db.close(); };
          get.onerror = () => { done([]); db.close(); };
        } catch (e) { done([]); }
      };
    } catch (e) { done([]); }
  });
}

// Ask any open window whether it's focused AND already looking at this
// conversation, so we can skip showing a redundant OS notification.
//
// This used to be a double-check on top of the relay's own suppression. The
// relay no longer does it at all, because doing so required telling it which
// conversation you had open. So this is now the only check, which is fine: it
// is the more accurate of the two, and when no window is open there is by
// definition nothing to be redundant with.
//
// The question is asked in tags, because a tag is all the payload carries.
function isClientActivelyViewing(client, pushTag) {
  return new Promise((resolve) => {
    if (!client.focused || !pushTag) return resolve(false);
    const channel = new MessageChannel();
    const timeout = setTimeout(() => resolve(false), 300);
    channel.port1.onmessage = (event) => {
      clearTimeout(timeout);
      resolve(!!(event.data && event.data.activeTag === pushTag));
    };
    try {
      client.postMessage({ type: 'query-active-conversation' }, [channel.port2]);
    } catch (e) {
      clearTimeout(timeout);
      resolve(false);
    }
  });
}

async function handlePush(event) {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    data = {};
  }

  // `t` is an opaque tag the sender derived from the conversation AND this
  // recipient. The relay forwards it without knowing what it means, and only
  // this device can map it back. A push with no tag (an un-upgraded sender)
  // still notifies, generically.
  const pushTag = typeof data.t === 'string' ? data.t : null;
  const tag = NOTIFICATION_TAG_PREFIX + (pushTag || 'unknown');

  if (pushTag) {
    const muted = await readMutedTags();
    if (muted.includes(pushTag)) return;
  }

  const allClients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
  for (const client of allClients) {
    if (await isClientActivelyViewing(client, pushTag)) {
      return;
    }
  }

  // Collapse repeated notifications for the same conversation into a
  // count summary instead of stacking duplicates (tag + renotify).
  const existing = await self.registration.getNotifications({ tag });
  const priorCount = (existing[0] && existing[0].data && existing[0].data.count) || 0;
  const count = priorCount + 1;

  // The payload no longer says whether this is a group, because saying so
  // would mean the relay knowing. "New message" covers both.
  const title = 'Talon';
  const body = count > 1 ? `${count} new messages` : 'New message';

  await self.registration.showNotification(title, {
    body,
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    tag,
    renotify: true,
    data: { pushTag, count }
  });
}

self.addEventListener('push', (event) => {
  event.waitUntil(handlePush(event));
});

self.addEventListener('notificationclick', (event) => {
  const notifData = event.notification.data || {};
  event.notification.close();

  event.waitUntil((async () => {
    // Only the page can turn a tag back into a conversation, so the tag is
    // what gets handed over, either through postMessage or in the URL.
    const pushTag = notifData.pushTag || null;
    const allClients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });

    for (const client of allClients) {
      if ('focus' in client) {
        await client.focus();
        client.postMessage({ type: 'open-conversation', tag: pushTag });
        return;
      }
    }

    if (self.clients.openWindow) {
      const url = pushTag ? `/?t=${encodeURIComponent(pushTag)}` : '/';
      await self.clients.openWindow(url);
    }
  })());
});

// If the browser/push service rotates our subscription under us, the old
// one goes silently dead. Re-subscribe and hand the fresh subscription
// back to the page so it can push it to the server.
self.addEventListener('pushsubscriptionchange', (event) => {
  event.waitUntil((async () => {
    try {
      const newSub = await self.registration.pushManager.subscribe(event.oldSubscription ? event.oldSubscription.options : { userVisibleOnly: true });
      const allClients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      allClients.forEach(client => client.postMessage({ type: 'push-subscription-renewed', subscription: newSub.toJSON() }));
    } catch (err) {
      console.error('[SW] Failed to renew push subscription:', err);
    }
  })());
});
