# Talon: the complete reference

One document covering what Talon is, why each decision was made, how the code
actually works, what the tests prove, and what is planned. It spans both
shipped projects: the messenger (`talon-main`) and the desktop launcher
(`talon-launcher-cpp`).

Everything in the verification section was re-run to produce this document. The
numbers are measured, not remembered.

**Contents**

1. [What Talon is](#1-what-talon-is)
2. [The workspace](#2-the-workspace)
3. [The relay](#3-the-relay)
4. [The client](#4-the-client)
5. [Cryptography](#5-cryptography)
6. [Storage and the vault](#6-storage-and-the-vault)
7. [Metadata](#7-metadata)
8. [Delivery guarantees](#8-delivery-guarantees)
9. [TLS and the local CA](#9-tls-and-the-local-ca)
10. [Build pipeline](#10-build-pipeline)
11. [Verification, with results](#11-verification-with-results)
12. [The launcher](#12-the-launcher-talon-launcher-cpp)
13. [Upcoming features](#13-upcoming-features)
14. [Known limitations](#14-known-limitations)

---

## 1. What Talon is

A zero-knowledge, end-to-end encrypted messenger for a handful of devices you
own, run over Tailscale on your own hardware. A deliberately stupid Node relay
stores and forwards encrypted blobs. A vanilla-JS progressive web app does all
of the cryptography client-side.

Two independent npm projects. No root `package.json`, no workspace tooling, no
framework, no bundler on the server side, no linter, and no test runner beyond
the one built into Node.

### The one constraint everything else answers to

The server may see:

- `authHash`, which is `SHA256(authKey)`. Never the password, never a key.
- Opaque ciphertext and nonce pairs: the identity private key, contacts,
  groups, messages.
- Plaintext **routing identifiers only**: `recipientId`, plus `senderId` on an
  un-upgraded envelope that has not been sealed.
- `ref` on a `send` frame: eight random bytes the relay echoes in its `ack` so
  the client can match the acknowledgement to a bubble. Never stored, never
  forwarded, unrelated to content.

The server must never see message content, contact or group names, avatars,
private keys, or anything from which those could be derived.

Adding a new plaintext field to an API body or a WebSocket frame is therefore a
security decision, not a refactor. It gets called out explicitly.

### Why "zero metadata" is not claimed

A relay that routes has to know where to route, and a socket has an address and
a time. Anyone claiming zero metadata is lying. What Talon changed is what the
relay *records*, as opposed to what it needs in the moment to deliver. Section
7 is the honest accounting of that difference.

---

## 2. The workspace

| Folder | What it is |
|---|---|
| `talon-main/` | The messenger, and the only working copy. All edits go here. |
| `github-main/` | A clean export of `talon-main/` for publishing: identical minus `node_modules/` and `server/data/`. Never edited directly. |
| `github stable release/` | An older export kept for reference. Not live. |
| `site/` | The brand site. Private, not published with the source. |
| `talon-launcher/`, `talon-launcher-cpp/` | Desktop launchers for the relay. Separate projects. Section 12. |

Re-exporting after a change:

```bash
robocopy talon-main github-main /E /XD node_modules data .git
```

`server/data/` and `node_modules/` are excluded by both that command and by
`github-main/.gitignore`, so the exclusion holds even if the copy is made some
other way.

`server/data/` holds live secrets: `ca-key.pem`, `vapid.json`, `certs/key.pem`
and `db.json`. It must never reach a repository. **`ca-key.pem` is the most
sensitive file in the project**, because anyone holding it can mint
certificates that every trusting device will accept without warning.

---

## 3. The relay

| File | Owns |
|---|---|
| `server/server.js` | Static files, REST API, WebSocket relay, all logging |
| `server/tls.js` | The local CA and leaf certificate lifecycle |
| `server/db.js` | `Db`, the whole persistence layer over one `data/db.json` |
| `server/redact.js` | Log redaction: per-boot pseudonyms, address classes, URL scrubbing |
| `server/push.js` | `Push`, VAPID keypair management and Web Push sending |
| `server/ratelimit.js` | Token buckets for register, auth, upload and send |

### Two WebSocket servers, one handler

One WebSocket server is attached to the HTTP server. A second is attached to
the HTTPS server and does nothing but re-emit `connection` into the first. All
connection logic therefore lives in a single `wss.on('connection')` handler and
both share the `onlineClients` map. New WebSocket behaviour goes there and
nowhere else.

The HTTPS server likewise reuses the HTTP server's request listener, so routes
are defined exactly once in `handleRequest`.

### `register` is authenticated

The frame carries `username` plus `authHash`, verified against the stored
verifier and bound to `user.idPub`. Before that, any 64-hex Client ID was
accepted, and since `register` drains the offline queue destructively, knowing
an ID that the app actively encourages people to share was enough to delete
somebody's queued mail.

### Authentication on REST routes

New POST routes go in the chain inside `handleRequest` and must call
**`verifyAuth(user, authHash)`**. Not a hand-rolled comparison.
`verifyAuth` goes through `timingSafeEqualHex`, handles the salted verifier,
and transparently upgrades legacy verbatim `authHash` records. A bare
`user.authHash !== authHash` is both timing-unsafe and simply wrong for a
migrated account.

### Rate limiting

Token buckets keyed by remote address before authentication and by username
after, swept periodically because an unbounded map keyed by attacker input is
itself the denial of service. Four limiters (`register`, `auth`, `upload`,
`send`), all overridable through `TALON_RL_*`. Defaults are deliberately
generous: locking someone out of their own messenger is worse than letting a
burst through.

Two details worth keeping:

- **`verifyAuth` spends tokens on failure, and the POST dispatcher enforces.**
  Spending alone throttles nothing, and that gap actually shipped briefly:
  failed guesses were charged and then cheerfully answered anyway. The
  `allowed()` check sits once in the dispatcher rather than per route, so a
  route added later cannot forget it. `allowed()` never spends, so a correct
  credential stays free however many arrive.
- **`retryAfter()` is clamped and never returns `Infinity`.** A zero-refill
  bucket really never recovers, but `Retry-After: Infinity` parses as `NaN` on
  the client.

### Persistence: a snapshot and a journal

`data/db.json` is a snapshot. `data/db.log` is an append-only journal of
everything since it was written. A mutation appends one record describing
itself, and the snapshot is rebuilt only when the journal outgrows it.

It used to rewrite the whole file on every change. That is correct and atomic,
but it costs O(database) per mutation, and the hot path is one write per
undelivered message: a relay holding a large offline queue rewrote that entire
queue in order to add one row to it.

**SQLite was the obvious alternative and does not fit.** CI runs Node 20 and
22, where `node:sqlite` is either absent or experimental, so it would mean
`better-sqlite3`, a native module needing a compiler on every machine that runs
a relay. For a project whose install story is `npm install && npm start` on
somebody's home server, that is a real regression. The journal costs one file
and no dependencies.

Rules that hold it together:

- **Every mutator calls `record(op, k, v)` exactly once**, the way they all
  used to call `saveDb()` exactly once.
- **Every op in `OPS` must be idempotent.** `compact()` deletes the journal
  only after the new snapshot is renamed into place, so a crash in that window
  replays records that are already in the snapshot. Total assignment is
  naturally idempotent; appending is not, which is why `queue` checks the
  message id first.
- **That ordering is load-bearing in both directions.** Clearing the journal
  before the snapshot lands would lose every mutation since the last
  compaction whenever the write failed.
- **Replay stops at the first record it cannot read** rather than skipping it.
  A torn final line is the realistic corruption and discarding it is correct. A
  hole in the middle means later records would be applied to a state their
  predecessors never produced.
- **A failed append falls back to a full snapshot**, because the mutation is
  already live in memory and dropping it would leave the running relay and the
  disk disagreeing.
- The compaction threshold is self-tuning: the journal may reach the size of
  the snapshot beside it, with a floor of 64 KB (`TALON_DB_LOG_MIN_BYTES`).
  That bounds replay at boot to about one snapshot's worth and disk to about
  twice the snapshot, with no constant that is wrong for both a two-user relay
  and a large one.
- The journal is folded in at boot whenever anything was replayed, so it never
  grows across restarts and `db.json` is current at rest after a clean start.

**`db.log` holds the same rows as `db.json` and is exactly as sensitive.** Any
test asserting that something is *not* stored has to read both, which is
covered in section 11.

Push subscriptions are keyed by `idPub`, while users are keyed by lowercased
username. Both keyspaces are in play at once, so pick deliberately.

### Attachments

`/api/upload` and `/api/download/:id` authenticate with the `X-Talon-User` and
`X-Talon-Auth` **headers**, checked by `authFromHeaders()`. Headers rather than
query parameters because every request URL goes through the access log, and a
credential in a query string would land in a plaintext file.

Uploads are capped at `TALON_MAX_UPLOAD_MB` (25 by default), and a rejected or
broken upload deletes its partial file. Download ids must match the UUID shape,
which closes path traversal by construction rather than by filtering.

Blobs are garbage-collected: `sweepAttachments()` deletes anything untouched
for `TALON_ATTACHMENT_TTL_DAYS` (30 by default, `0` disables), and
`/api/download` touches mtime on every fetch, so age means "since last read".
That is what keeps avatars alive.

### Two sharp HTTP edges

**Rejecting a POST before its body is read requires `Connection: close`.**
Otherwise the unread bytes stay in the socket, and the next keep-alive request
is parsed starting from the middle of this one's body, so it hangs. Draining
instead would mean reading an unbounded body from a caller who just failed to
authenticate.

**Respond to an upload on `writeStream.on('finish')`, never on
`req.on('end')`.** `createWriteStream` opens the file asynchronously, so on a
small upload `end` fires first and anything touching the file throws ENOENT
from inside an event handler: uncaught exception, no response, and the client
hangs until it times out. Large uploads hide the bug because the open wins the
race.

### Logging

Use `log(TAG, msg)` and `logError(TAG, msg, err)` with the tags
`TLS | API | WS | PUSH | HTTP | STATS | BOOT`. Never bare `console.log`.
Comprehensive logging is an intentional feature: every request is
access-logged, and a full stats snapshot prints every sixty seconds.

Never log an identity, an address or a URL raw. Everything goes through
`redact.js`: `Redact.tag()` for a username, `idPub` or file id, `Redact.ip()`
for an address, `Redact.url()` for a request path. Details in section 7.

---

## 4. The client

| File | Owns |
|---|---|
| `web/src/app.js` | Boot, auth, tab routing, WebSocket wiring, inbound dispatch, shortcuts, WebRTC, outbox runtime, panic wipe |
| `web/src/views.js` | Chat list, chat area, message bubbles, composer, emoji picker |
| `web/src/panes.js` | Profile pane, Settings pane, safety numbers, app lock, modals |
| `web/src/messaging.js` | Prekey lifecycle, envelope send and receive (v1 and v2), group fan-out, message model |
| `web/src/ratchet.js` | Protocol v2 only: X3DH and the Double Ratchet |
| `web/src/store.js` | `Storage` (all localStorage access) and `State` (the single mutable store) |
| `web/src/ui.js` | Toasts, modals, confirm and prompt, popovers, lightbox, connection banner |
| `web/src/theme.js` | The theme table and every appearance axis |
| `web/src/sound.js` | Synthesised send, receive and seen cues (WebAudio, no assets) |
| `web/src/util.js` | Pure formatting and escaping helpers |
| `web/src/backup.js` | Encrypted backup format and merge rules. Pure: no DOM, no Storage |
| `web/src/pushdb.js` | The muted push-tag store in IndexedDB, mirrored by hand in sw.js |
| `web/src/outbox.js` | Retry scheduling and duplicate detection. Pure: no timers, no socket |
| `web/src/crypto-extra.js` | Safety numbers, PIN hashing, attachment encrypt and upload |
| `web/src/crypto-bundle.js` | Crypto primitives only (noble curves, ciphers, hashes), no app logic |
| `web/public/sw.js` | Service worker: offline shell cache, push display, notification routing |

The dependency direction is one-way:
`util -> store -> {ui, theme, messaging} -> {views, panes} -> app`.
`views.js` and `panes.js` never import from `app.js`. They expose a `hooks` or
`paneHooks` object that `bootApp()` fills in.

### Conventions that are not negotiable

- **There is no reactive framework.** After mutating `State` you call the
  renderer yourself: `renderChatList()`, `renderChatArea()`, `appendMessage()`,
  or `refreshMessage()` for one bubble.
- **Rendering is `innerHTML` string assembly.** Every piece of user-controlled
  text goes through `escapeHTML()` or `escapeAttr()` from `util.js`.
- **No inline `onclick`, no `window.*` handlers.** Generated markup carries
  `data-*` attributes, and a single delegated listener on `#msg-list` reads
  them (`bindMessageInteractions`).
- **`renderChatArea()` rebuilds the whole header, list and composer subtree**,
  so new composer controls must be created and bound inside it, not in
  `bootApp()`.
- **Shell height comes from `--app-h`, never `100dvh` directly.**
  `trackViewport()` writes it from `visualViewport`. iOS reports `dvh` as the
  *large* viewport, so with the keyboard open a `100dvh` shell is taller than
  the screen. The browser then scrolls the document, and because `.detail` is
  `position: fixed` on a phone, the chat header slides up out of view while
  dead space opens under the composer.

### Appearance

Six `data-*` attributes on `<html>`
(`data-theme|scheme|accent|density|motion|corners|font`) plus `--font-scale`.
`theme-preload.js` applies them from `talon_appearance` before first paint to
avoid a flash, and `theme.js` takes over afterwards. **Both hold a copy of the
theme table, so they must be kept in sync.**

**`data-scheme` (`light` or `dark`), not `data-theme`, is what light-versus-dark
rules key off.** There are seven themes and more may be added. A rule written
against `[data-theme='light']` silently misses `ash` and `paper`.

### The read indicator

Three styles via `receiptStyle`: `eye`, `ticks`, `none`. The eye is one SVG
holding both states, and CSS decides which is drawn. **`refreshMessage()` adds
`.just-seen` only on a genuine unseen-to-seen transition**, comparing
`existing.dataset.status` before replacing the node. Without that guard, every
re-render replays the animation across the entire history.

### Panic wipe

Fires on three Escape presses within 1.2 seconds, or from Settings. It wipes
all local data for the account immediately, by design. Modal and popover
Escape handlers call `stopPropagation()`, so only "free" presses count toward
the three.

---

## 5. Cryptography

Two protocol versions coexist. v2 is current. v1 is retained read-only so that
messages queued by an un-upgraded peer still drain. Sessions carry `v`, and its
absence means v1.

### Key derivation (v2)

PBKDF2-SHA256 through **WebCrypto**, 600 000 iterations, a 16-byte random
per-user salt, producing 64 bytes split into `authKey` (bytes 0 to 31) and
`encryptionKey` (bytes 32 to 63).

v1 (pure JS, 10 000 iterations, salt equal to the username) exists only so old
accounts can be migrated on login.

Argon2id was measured and rejected. Do not "upgrade" to it without re-measuring
on a real phone.

### Handshake: X3DH

Four Diffie-Hellman values, `IK_a x SPK_b`, `EK_a x IK_b`, `EK_a x SPK_b` and
`EK_a x OPK_b`, run through HKDF with info `"TalonX3DHv2"`.

The signed prekey's Ed25519 signature **must** be verified before use. That
verification is the only thing preventing the relay from substituting its own
prekeys, which is the whole attack this design exists to stop.

The one-time prekey is deleted on use. That deletion is precisely what provides
forward secrecy against a later identity-key compromise.

### Post-quantum hybrid

The initiator encapsulates to a signed ML-KEM-768 prekey, and the secret is
mixed into the same HKDF under info `"TalonPQXDHv3"` instead of
`"TalonX3DHv2"`.

It is **additive**: X25519 is still mixed in, so neither primitive alone
carries the session. The KEM prekey is signed under its own domain
(`TalonKemPreKey:`), and `verifyBundle` checks it.

Sessions record `pq: true|false`. A bundle without a KEM prekey still works,
for an un-upgraded peer, and is marked `pq: false`. Turning that into a hard
failure is a decision about old clients, not a cleanup.

### Ratchet

A Double Ratchet. The symmetric chain advances via `HMAC(ck, 0x01|0x02)`, and a
Diffie-Hellman step happens on every change of direction, which is what
provides post-compromise security. The root key is folded with
`HKDF(info="TalonRatchetv2")`.

**Bounds are load-bearing.** `n`, `pn` and `messageIndex` are all
attacker-controlled plaintext. Every loop driven by them is capped at
`MAX_SKIP`. Removing that cap reintroduces an unauthenticated remote denial of
service. This was a real, confirmed bug, not a hypothetical.

### Identity keys

`idPub` is still the X25519 key, so every existing Client ID keeps working. The
Ed25519 prekey-signing key is *derived* from `idPriv` as
`SHA256("TalonSigningKey:" || idPriv)`, so all devices holding the account
agree on it without transmitting anything.

### Message identity

v2 carries `_mid`, a monotonic per-session counter, **inside the ciphertext**.
The ratchet's own `n` resets on every DH step, so it cannot serve as an
identifier. `_mid` is stripped before the app ever sees the payload.

`_lid` rides alongside it and survives retries; see section 8.

### Sealed sender

`transmit()` in messaging.js wraps every `send` frame so the sender identity
lives inside an AEAD addressed to the recipient. The relay routes on
`recipientId` alone and stores `senderId: null` in the offline queue.

**The live relay still knows the sender**, because the socket is authenticated
per identity. This buys at-rest privacy and log privacy, not anonymity against
a running malicious relay. That distinction is stated rather than glossed.

### Padding

Plaintext is padded to 256-byte buckets, a `0x80` marker followed by zeroes,
before encryption, so ciphertext length does not leak message length.

### Attachments

A different path from messages: a fresh WebCrypto AES-GCM key per file,
ciphertext POSTed to `/api/upload`, and the key and iv shipped *inside* the
ratchet-encrypted payload as `{ type: 'file', url, key, iv, ... }`. Voice memos
and avatars use the same pattern.

### Safety numbers

Display-only. `safetyNumber(idA, idB)` sorts the two identity keys before
hashing, so both devices derive the same sixty digits. Nothing keys off the
value.

### Backups

One AES-256-GCM file under a passphrase, keyed by PBKDF2 at 600 000 iterations
then HKDF with info `TalonBackupv1`.

The HKDF step is load-bearing: without it, somebody reusing their account
password as the backup passphrase would get a backup key related to their
`encryptionKey`.

The readable header sits outside the ciphertext, because restore must read it
before it has a key. It is therefore bound in as AES-GCM associated data by
`backupAad`, so the username, timestamp and KDF parameters cannot be edited
without breaking the tag.

`inspectBackup` runs every structural check *before* the KDF, which is what
stops a hostile file that names five hundred million iterations from acting as
a denial of service.

**`sessions` and `preKeys` are excluded on purpose**, and `BACKUP_STORES` is
the authoritative list. Restoring ratchet state rewinds chain keys that have
already produced messages, reusing message keys and nonces. Restoring prekey
private halves lets two devices claim the same one-time keys, and the
deletion-on-use that provides forward secrecy stops meaning anything. Adding
either is a security decision, not a feature.

`mergeBackup` is pure and never deletes unless `mode: 'replace'`. **Contacts
deduplicate on `idPub`, not `id`**, because a contact has no other identifier.
Getting that wrong silently drops every contact in the file rather than
throwing, which is exactly what happened once; see section 11.

### Session state

Lives in `localStorage` under `e2e_sessions_<username>`. Changing the KDF info
strings, the ratchet constants or the session shape invalidates in-flight
sessions.

**This is far less dangerous than it sounds**: decrypted history is stored
separately, so a broken session costs only undelivered messages, never the
archive. v2 sessions re-handshake automatically on the next send.

### Message protocol

Every application payload is a JSON object with a `type`, encrypted and then
wrapped in a `send` frame:

| `type` | Meaning |
|---|---|
| `text` / `file` / `voice-memo` / `sticker` | Real chat content |
| `control` | `typing`, `read`, `reaction`, `edit`, `delete`, `profile-sync` |
| `group-control` | `create`, `typing`, `rename`, `roster`, `leave`, `removed`, plus the control actions scoped to a group |
| `group-message` | Wraps a content payload with `groupId` and `senderId` |
| `call-signal` | WebRTC offer, answer, ICE |

- **`sendE2EPayload` is async**, because opening a v2 session fetches a prekey
  bundle first. It resolves immediately once a session exists, so only the very
  first message to a peer actually waits. Call sites reading `.success` or
  `.messageIndex` must `await`.
- `sendControl(convId, action, extra)` picks `control` versus `group-control`
  for you. Prefer it over calling `sendE2EPayload` directly for non-content
  traffic.
- `edit` and `delete` travel **inside the encrypted payload** like everything
  else. `delete` leaves a local tombstone (`msg.deleted`); it does not remove
  the row.
- Reactions are `{ emoji: [senderId] }`. Legacy rows were a bare `string[]`,
  and `normalizeReactions()` upgrades them on read rather than migrating at
  boot.
- **`notify` is explicit opt-in.** Set it `true` only for real chat content.
  Control, typing, read receipts, reactions, edits, deletes, profile syncs and
  call signalling all travel over the same `send` frame and must stay
  `notify: false`, or you wake somebody's phone for a typing indicator.

### Presence is peer to peer

The relay knows who is connected, but it has never known who your contacts are.
"X is online" therefore travels as an ordinary encrypted `control` payload
between contacts. A relay-side presence subscription would mean handing it your
contact graph in the clear, so there is not one.

### Signed group rosters

`buildRosterMessage`, `signRosterWith`, `verifyRoster` and `rosterAcceptable`
in messaging.js. The signature covers a canonical encoding (sorted members,
fixed key order, `TalonGroupRoster:` prefix) so that two clients holding the
same roster produce byte-identical input.

**`rosterAcceptable` is the single gate** for `create`, `rename` and `roster`.
Unsigned is refused outright, revisions must move forward, and the owner
signing key is pinned on first accept.

`acceptsAdminFrom` only says who *sent* an envelope, which is not the same as
who *authored* the roster, and forwarding one is entirely normal. Groups
predating this adopt an owner on the first signed roster they receive.

**Groups are pure client-side fan-out.** The server has no group concept. The
client encrypts and sends one envelope per member.

---

## 6. Storage and the vault

`Storage` is the **only** place that touches `localStorage` or
`sessionStorage`. Keys are `e2e_<thing>_<lowercased-username>`. The session
lives in `talon_session` (sessionStorage) or `talon_session_persistent`
(localStorage, opt-in "keep me signed in").

Add new persisted data as a `Storage` method, **and add its prefix to
`WIPE_PREFIXES`**, or panic wipe silently leaves it on the device.

### Vault mode

When `settings.encryptAtRest` is on, every per-account blob except
`e2e_settings_` is AES-GCM encrypted under a key derived from the password and
held **in memory only**. `readJSON` and `writeJSON` handle it transparently,
and records are self-describing (`{__enc:1}`), so a half-migrated profile still
reads.

Two invariants:

1. **Settings must stay in the clear**, because they are what says whether the
   vault is on.
2. **`unlockVault()` must run before any blob is read or written.** Read too
   early and every read silently returns its empty fallback, so the account
   looks wiped. Write too early and the blob lands on disk in the clear and
   stays there.

The login handler in app.js hits the second case: it writes the server's
contacts and groups before `initializeSession()`, so it unlocks the vault
itself first. That was a real bug, found by reading and confirmed by reverting
the fix.

Vault mode force-disables "keep me signed in", because a persisted session
contains `encryptionKeyHex`.

### Where the default lives, and why

**Vault mode is on by default for new accounts, and that default lives in the
registration handler, not in `DEFAULT_SETTINGS`.**

`DEFAULT_SETTINGS.encryptAtRest` stays `false` on purpose. It is the value
inherited by accounts that predate the decision, whose blobs are already
plaintext on disk. Flipping the table default would switch those accounts over
without their owner choosing to. Registration writes `encryptAtRest`
explicitly instead.

### The two prefix lists

Both are load-bearing, and both are enforced by `web/test/vault.test.js`:

- Missing from `WIPE_PREFIXES` means panic wipe leaves the store on the device.
- Missing from `VAULT_PREFIXES` means `migrateVault` skips it, so turning the
  vault on leaves it in the clear forever.

The tests enumerate the setters off `Storage` rather than naming them. That
change was forced twice by mutation runs; see section 11.

---

## 7. Metadata

Delivered in three stages. Each one removed a specific thing the relay used to
know or record.

### Stage A: the silent relay

The log used to be the richest metadata store on the machine, worse than
`db.json`. It held the username on every authenticated request, the client
address on every request at all, the sender and recipient of every message on
one line, and a presence line naming the conversation someone had open right
then.

`TALON_LOG_PRIVACY=strict` is now the **default**. `full` restores verbatim
logging for debugging.

- Identities print as a short pseudonym.
- Addresses collapse to `local`, `tailnet`, `remote` or `unknown`.
- Identifiers are stripped out of request paths, along with query strings.
- Routing pairs are never printed together.

**The pseudonym is an HMAC under sixteen random bytes generated at boot and
never written down.** Within one run an account keeps the same label, so a
session stays followable; across restarts the labels change. Because the salt
does not exist anywhere on disk, a captured log cannot be brute-forced back to
a username. A plain hash would not survive that, since usernames and identity
keys both come from small, guessable spaces.

**Anything revealing a pair or a conversation must be behind
`if (!Redact.redacting)`, not merely tagged.** Two pseudonyms on one line still
draw the social graph.

**The static rule has no allowlist, deliberately.** If a log line needs a value
derived from an identity, such as a count or a length, compute it into a local
variable first. `Db.countOneTimePreKeys(user.idPub)` inline inside a template
tripped the rule even though it prints only a number. Hoisting it to
`poolRemaining` is one line and keeps the rule absolute.

The offline queue also stopped recording time. It used to carry a millisecond
timestamp and an id with `Date.now()` baked into it, which recorded exactly
when every undelivered message was written. It now carries a random UUID and a
day-rounded `queuedDay`. **The client reads neither field**, so do not
reintroduce one for convenience.

### Stage B: push tags, and what left the wire

Push suppression used to be the relay's job, which required three things it
should never have had:

1. The muted conversation list, uploaded in the clear. A slice of the contact
   graph.
2. A `presence` frame saying which chat you had open. A running record of what
   you were reading.
3. `convId` on every send. For a one-to-one chat that told the relay nothing
   new. **For a group it was the shared `groupId`, repeated across the entire
   fan-out**, so collecting the recipients that kept appearing under one value
   reconstructed the membership of a group the relay is supposed to know
   nothing about.

What goes out instead:

```js
pushTag = SHA256('TalonPushTagv1:' + convId + ':' + recipientIdPub)  // 32 hex
```

**Binding the recipient in is the load-bearing part.** The same group message
produces a different tag for every member, so there is nothing left to
correlate. Both ends derive it independently, so there is no extra round trip.

The relay forwards the tag to the push service and stores nothing.
`/api/push-mute` is deleted. `Db.mutedIds` is deleted **and actively removed
from an existing `db.json` on load**. The `presence` frame and `sendPresence()`
are both gone, and `onlineClients` now holds `{ ws }` and nothing else.

The service worker applies the mute, reading the tag list from **IndexedDB**,
because a worker cannot read localStorage. `web/src/pushdb.js` writes it and
sw.js has a hand-copied reader, since sw.js is served as-is and never bundled.
**Keep the two in step**, the same rule as theme-preload.js.

The muted tags live in IndexedDB, outside the `WIPE_PREFIXES` sweep, so
**panic wipe calls `clearMutedTags()` separately**.

The list is a set of tags, never conversation ids. Reading that database tells
you how many conversations are muted and nothing else.

### Stage C: delivery guarantees

Covered in full in section 8.

### What remains, and always will

The relay knows a connection exists, from which address, at what time, and it
knows the recipient of a message at the moment it routes it. Padding hides
message length. **Nothing here hides timing.**

With two users the anonymity set is two. Even perfect sealed sender would tell
an observer almost everything by elimination. The structural protection is that
you own the relay, not that the traffic is indistinguishable.

---

## 8. Delivery guarantees

**Nothing outbound may vanish.** Every content send ends acknowledged, waiting
in the outbox, or shown as failed with a retry button.

Two silent failures used to exist:

1. A send with the socket down was stranded forever. The only recovery was
   retyping the message.
2. A frame that left the device but drew no acknowledgement sat on `sending`
   indefinitely, which reads as success.

`web/src/outbox.js` is the pure scheduler: backoff, exhaustion and duplicate
detection, with no timers, no socket and no persistence. The timers, socket and
persistence live in the outbox block in app.js.

### Backoff

Exponential with **full jitter**. The jitter matters more than it looks:
without it, every message queued during an outage retries on the same schedule,
the relay receives the whole backlog at once, and the send limiter refuses most
of it.

```js
export function nextDelay(attempts, random = Math.random) {
  const exp = Math.min(BASE_DELAY_MS * Math.pow(2, Math.max(0, attempts)), MAX_DELAY_MS);
  return Math.floor(exp / 2 + random() * (exp / 2));
}
```

`MAX_ATTEMPTS = 8`, `BASE_DELAY_MS = 2000`, `MAX_DELAY_MS = 60000`,
`ACK_TIMEOUT_MS = 15000`.

**The attempt is counted before the send**, so a throw or a closed tab cannot
produce an entry that retries forever. Nothing is counted while the socket is
down, because being offline is not an attempt.

### The `ref` bug

The first browser run of this feature failed, and the relay's own log explained
why:

```
[WS] Client online: #46cbcf
[WS] Queued offline message (addressed, recipient unreachable)   +0.5s
[WS] Queued offline message (addressed, recipient unreachable)   +2s
[WS] Queued offline message (addressed, recipient unreachable)   +6s
[WS] Queued offline message (addressed, recipient unreachable)   +18s
```

The retry was working perfectly. **A retry carries a new `ref`, and the bubble
still held the one from the first attempt**, so the acknowledgement matched no
message and the bubble sat on "not sent" while the relay actually had it.

```js
if (success) {
  // A retry is a new frame and carries a new correlation token. The bubble
  // still holds the token from the first attempt, so without collecting
  // the new one the ack matches no message and the bubble sits on "not
  // sent" forever while the relay actually has it.
  rememberRefs(entry.localId, freshRefs);
  watchForAck(entry.localId, entry.convId, entry.payload);
}
```

Nothing in the Node suite could have found that. It took killing the relay in a
real browser.

### Deduplication

A retry has to be recognisable to the receiver. `_mid` cannot do that job,
because re-encrypting allocates a new counter, so a retry would look like a new
message.

`_lid` therefore rides inside the ciphertext next to `_mid`, minted once and
unchanged across every attempt, and is surfaced as `remoteId` on the stored
row.

`alreadyReceived` compares `m.senderId`, not `m.sender`, which only ever holds
`'me'` or `'them'`. Two contacts can mint the same `localId` with no
coordination, so without the sender in the comparison one peer's message would
silently suppress another's.

An untagged message is never treated as a duplicate, or history written before
`_lid` existed would drop every incoming message from an un-upgraded peer.

### The UI states

`offline` means still retrying. `failed` means it gave up. Only the second one
is actually stuck, and only that one offers a `[data-retry]` button.

A group fan-out that reached **nobody** used to report success. It now reports
failure and goes to the outbox.

`e2e_outbox_` is in both `WIPE_PREFIXES` and `VAULT_PREFIXES`.

### Message identity in history

The `(contactId, messageIndex, sender)` triple via `findMsg()`. Group messages
use `Date.now()` as their index. New messages also carry `localId`, but the
triple must keep working for history written before that existed.

---

## 9. TLS and the local CA

A self-signed **leaf** can never be trusted by a browser, so the server runs a
tiny private CA:

```
Talon Local CA (10 years, cA:true)  ->  leaf (397 days, auto-renewed)
```

- The user installs the CA once per device via `GET /ca.crt`, and `GET /setup`
  serves a standalone per-OS instruction page.
- **397 days is a hard ceiling.** Safari, iOS and Chrome reject any leaf valid
  longer than 398 days, trusted or not. Do not "simplify" it back to ten years.
- **Only `subjectAltName` is consulted by browsers**; commonName is ignored.
  Every address you might type has to be in the SAN list. `TALON_EXTRA_SANS`
  adds names, such as a Tailscale MagicDNS host, without a code change.
- The leaf is re-issued when the address set changes or when it nears expiry.
  **The CA is regenerated only if missing or expired**, because anything else
  would invalidate the trust already installed on every device.
- Certificate generation uses `@peculiar/x509`. `selfsigned` was removed
  because its API cannot sign a leaf from a CA at all.

The SAN set is tracked in `data/certs/cert-meta.json` and regenerated whenever
the machine's interface addresses change.

---

## 10. Build pipeline

```bash
cd talon-main/server && npm install && npm start      # HTTP :8080, HTTPS :8443
cd talon-main/web    && npm install && npm run build  # esbuild: src/app.js -> public/js/app.js
```

**`web/public/js/app.js` is a generated, minified esbuild artifact. Never edit
it.**

- Client source lives in `web/src/*.js`.
- After *any* change to `web/src/`, run `npm run build` or the change simply
  does not ship.
- `web/public/index.html`, `style.css` and `sw.js` are **not** bundled. They
  are served as-is and edited in place.
- When the app shell changes, bump `CACHE_NAME` in `web/public/sw.js`
  (currently `talon-cache-v21`), or installed clients keep serving the stale
  cached shell.

### The service worker cache

Every fetch the worker makes to refill the cache uses `cache: 'reload'`, which
skips the browser's own HTTP cache and forces a real network trip. **Without
it, bumping `CACHE_NAME` does nothing**: `cache.add()` and the revalidation
fetch are ordinary fetches, so they were answered out of the HTTP cache and a
brand new cache was immediately repopulated with the same stale bytes. On a
phone that looks like a page frozen at an old version with no way to clear it.

Shell assets are **network-first**, not stale-while-revalidate. Under SWR the
cached copy is returned immediately and the fresh one only lands in time for
the *next* load, so a device is always exactly one update behind. For a script
and a stylesheet that must match the HTML just fetched, that is not a caching
nicety, it is a version skew.

`/ws`, `/api/`, `/ca.crt`, `/ca.pem` and `/setup` are network-only. A cached
CA would survive regeneration and break trust.

### CI

`.github/workflows/ci.yml` runs both suites on Node 20 and 22, and separately
asserts that the committed `web/public/js/app.js` still matches a fresh build
of `web/src/`.

---

## 11. Verification, with results

Both suites use the built-in `node --test`. **There is no test-runner
dependency and there should not be one.** There is still no linter.

`server/test/` spawns a real relay against a throwaway `TALON_DATA_DIR`, so it
never touches live `data/`. **Any new code that reads or writes `data/` must go
through the `DATA_DIR` export from `db.js`**, or the tests will start mutating
real accounts and regenerating the CA.

Every server suite other than the rate-limit ones sets `TALON_RL_*_BURST`
absurdly high, or it throttles itself and fails for the wrong reason.

### Test results

Measured on Node v24.15.0.

**Client: 257 tests, 257 passing, 0 failing.**

| Suite | Tests | Covers |
|---|---:|---|
| `web/test/backup.test.js` | 38 | Backup format, AAD binding, merge rules, KDF bounds |
| `web/test/devices.test.js` | 36 | Signed device lists, revision ordering, fan-out, session keying |
| `web/test/fanout.test.js` | 29 | Per-device sends, receive-side ratchets, self-sync |
| `web/test/outbox.test.js` | 30 | Backoff, exhaustion, duplicate detection |
| `web/test/ratchet.test.js` | 30 | X3DH, Double Ratchet, `MAX_SKIP`, KEM refusal |
| `web/test/roster.test.js` | 27 | Signed group rosters, revision ordering, owner pinning |
| `web/test/vault.test.js` | 27 | Vault at rest, migration, wipe coverage, first sign-in |
| `web/test/crypto.test.js` | 21 | Primitives, safety numbers, padding |
| `web/test/pushtag.test.js` | 19 | Push tag derivation, muted-tag store |

**Server: 134 tests, 134 passing, 0 failing.**

| Suite | Tests | Covers |
|---|---:|---|
| `server/test/redact.test.js` | 25 | Log redaction, static source scan, queue timestamps |
| `server/test/persistence.test.js` | 34 | Journal replay, torn records, compaction, per-device queues |
| `server/test/devices-http.test.js` | 11 | Device-list routes, auth, per-device prekey pools |
| `server/test/routing.test.js` | 10 | Multi-device routing over real WebSockets |
| `server/test/attachments.test.js` | 18 | Upload and download auth, traversal, sweeping |
| `server/test/auth.test.js` | 17 | Auth on every route, credential storage |
| `server/test/ratelimit.test.js` | 13 | Token buckets against an injected clock |
| `server/test/ratelimit-http.test.js` | 6 | The limiters are actually wired to the routes |

**Total: 391 tests, 391 passing.**

### Why the static scanner exists

`server/test/redact.test.js` enforces log redaction two ways, and **the static
half is the one that matters**. It parses every `log()` and `logError()` call
out of `server.js` and fails if any interpolation mentions an identity, an
address or a URL without going through `Redact`.

The runtime half, which captures a real relay's stdout, can only see the routes
that the fixture happens to call, and it missed exactly two on the first pass:
`/api/publish-prekeys` logged the username verbatim, and `/ca.crt` logged the
raw remote address. Adding those two calls to the fixture would have fixed
those two lines and left the next one exposed. The scanner catches the class.

### Mutation testing

**A test that cannot fail is worse than no test, because it produces confidence
instead of information.** Every safety-critical module has a mutation harness
that deliberately breaks an invariant and asserts the suite turns red.

Full results from the run made for this document. **152 mutations, 152 caught.**

**`ratchet.js`, 5 of 5 caught**

```
caught  verifyBundle always accepts (relay can substitute prekeys)
caught  MAX_SKIP cap removed (unauthenticated remote DoS)
caught  acceptSession downgrades instead of refusing an unopenable KEM ct
caught  skipped key is not deleted after use (replay accepted twice)
caught  negative counters no longer rejected
```

**`backup.js`, 14 of 14 caught**

```
caught  AAD dropped from encrypt
caught  AAD dropped from decrypt
caught  digest never checked
caught  iteration range never checked
caught  HKDF separation skipped
caught  sessions included in the payload
caught  app lock not stripped on collect
caught  app lock not stripped on replace
caught  merged messages left unsorted
caught  legacy triple ignored in dedup
caught  contacts keyed by the wrong field
caught  passphrase floor removed
caught  salt and nonce reused
caught  incoming settings win on merge
```

**`store.js` and `crypto-bundle.js` (vault), 12 of 12 caught**

```
caught  writes never encrypt
caught  settings get vaulted too
caught  locked vault returns the raw record
caught  encrypted records are not detected
caught  migrateVault never writes back
caught  migrateVault reads with the new key state
caught  a store is dropped from WIPE_PREFIXES
caught  a store is dropped from VAULT_PREFIXES
caught  corrupt records throw instead of falling back
caught  usernames are not lowercased
caught  persistent session is never cleared
caught  vault nonce is fixed rather than random
```

**`messaging.js` (push tags), 8 of 8 caught**

```
caught  recipient dropped from the tag
caught  conversation dropped from the tag
caught  tag is the raw conversation id
caught  unmuted conversations are included
caught  muted list holds ids instead of tags
caught  groups are left out of the muted list
caught  tag resolution ignores the recipient half
caught  a missing half still produces a tag
```

**`outbox.js`, 15 of 15 caught**

```
caught  backoff is constant
caught  backoff is uncapped
caught  jitter removed
caught  adding duplicates instead of replacing
caught  exhausted entries stay due
caught  backoff ignored, everything always due
caught  off by one on the attempt cap
caught  never gives up
caught  attempts are not counted
caught  afterAttempt mutates its input
caught  manual retry does not clear the attempt count
caught  wake-up includes exhausted entries
caught  wake-up can go negative
caught  duplicate check ignores the sender
caught  untagged messages count as duplicates
```

**`redact.js`, `server.js` and `db.js`, 17 of 17 caught**

```
caught  strict is no longer the default
caught  tag returns its input
caught  tag uses a fixed salt
caught  ip returns its input
caught  url returns its input
caught  url strips the whole path, not just ids
caught  the routing pair is logged again
caught  presence is logged again
caught  the access log keeps the client address
caught  the upload id is logged verbatim
caught  the registered username is logged verbatim
caught  the queued-message pair is logged again
caught  publish-prekeys logs the username raw
caught  ca.crt logs the raw remote address
caught  the queue keeps a millisecond timestamp
caught  the queue id embeds the clock again
caught  queuedDay is not rounded
```

**`db.js` (the journal), 20 of 20 caught**

```
caught  queue is not idempotent (double delivery after a crash)
caught  queue dedups on the wrong field
caught  drain is a no-op
caught  drain removes everyone, not one recipient
caught  a user record lands under the wrong key
caught  prekey consumption is not persisted
caught  push removal is not persisted
caught  the journal is never appended to
caught  a failed append gives up instead of snapshotting
caught  compaction clears the journal before the snapshot is safe
caught  compaction never happens
caught  compaction happens on every write
caught  the threshold ignores the snapshot size
caught  the journal is never replayed at boot
caught  the journal is not folded in at boot
caught  replay skips a damaged record instead of stopping
caught  replay guesses at an unknown record instead of stopping
caught  a lost snapshot is not rebuilt from the journal
caught  the muted list is no longer removed on load
caught  a queued row carries a millisecond timestamp again
```

**`devices.js` (the signed device list), 25 of 25 caught**

```
caught  unsigned lists are accepted
caught  the signature is never verified
caught  the signature does not cover the device list
caught  the signature does not cover the revision
caught  the signature does not cover the account
caught  the signature does not cover device names
caught  the canonical form depends on device order
caught  the domain separator is dropped
caught  the domain separator collides with rosters
caught  a stale revision is accepted
caught  a replayed revision is accepted
caught  the signing key is not pinned
caught  a list for another account is accepted
caught  an empty list wipes every device
caught  the device cap is removed
caught  duplicate device ids are allowed
caught  duplicate device keys are allowed
caught  malformed device entries are allowed through
caught  the revision is not checked for sanity
caught  fan-out silently drops every device but the first
caught  a peer with no list is treated as having none to send to
caught  re-adding a device appends instead of replacing
caught  adding a device does not bump the revision
caught  removing the last device is allowed
caught  removing a device does not bump the revision
```

**Multi-device, 36 of 36 caught** across `devices.js`, `db.js`, `server.js`,
`messaging.js`. The full lists are in the scratch harnesses; the shapes are:
the signed device list (unsigned accepted, signature not covering a field,
stale or replayed revision, signing key not pinned, empty list, cap removed,
duplicate ids), the relay half (stale list accepted, list stored verbatim,
device key of any shape accepted as a prekey pool, routes missing auth, one
socket per identity again, closing one device unregistering the account, a
stale close evicting the live socket, the drain ignoring which device asked),
and the client half (only the first device addressed, all devices sharing one
session, the receiver ignoring which device sent, the sender device on the
frame instead of in the seal, the mirror echoing back to itself, the mirror
losing its conversation or its message id).

**The one that mattered most** is `one socket per identity again`, which is
literally the pre-change behaviour. It proves the suite would have caught the
bug that motivated the work rather than merely describing it.

### The bug two browsers found and no unit test could

Signing into a vault-enabled account **from a second device wrote every blob to
that disk in the clear**: message history, contacts, ratchet state and prekey
private halves.

The `encryptAtRest` flag lives in that device's own storage, so a fresh device
has no preference recorded, and the merged defaults read as "off". The vault
never unlocked and every write landed plaintext.

The fix needed a new distinction, `Storage.hasSettings()`, because "no
preference recorded here" and "chose off" both read as `false` through
`getSettings`. A device signing in for the first time now gets the vault,
matching registration.

That is deliberately **not** the same decision as `DEFAULT_SETTINGS.encryptAtRest`,
which stays `false`. That default exists so an account with plaintext blobs
already on *this* disk is not flipped without its owner choosing. On a fresh
device there are no such blobs, so the reasoning does not apply.

No unit test could see it, because a unit test only ever has one device. It
took two browser profiles signed into one account.

### The journal changed what "on disk" means

Three suites read `db.json` directly to assert what the relay had stored, and
moving writes into the journal broke two of them and, worse, left two others
passing for the wrong reason.

`the raw authHash is never stored verbatim` kept passing. It scanned `db.json`
for the client-presented token, and account writes now land in `db.log` first,
so it would have agreed with a relay that wrote the token verbatim to the
journal. `a throttled registration does not create the account` had the same
shape: a row written to the journal is just as created as one in the snapshot.

The fix was not to compact before reading. `server/test/helpers.js` now
reconstructs the at-rest picture from both files, and the assertions cover
**every version of a row that has ever been written**, not just the current
one. That is a stronger question than the original: it also catches a secret
written once and overwritten later, which a snapshot read would never see.

`persistence.test.js` fails if `OPS` in db.js and `HANDLED_OPS` in the helpers
disagree, so a new operation cannot silently narrow what the other suites
inspect.

### What this run found

The run above is not the first run. It is the run after two fixes that this run
itself forced.

**Two vault mutations survived.** Dropping `e2e_outbox_` from either
`WIPE_PREFIXES` or `VAULT_PREFIXES` left the suite green. Both are real: the
first leaves pending plaintext messages on the device after a panic wipe, and
the second leaves the outbox unencrypted at rest forever.

The cause was the documented footgun one level up. The wipe-coverage test drove
nine setters **by hand**, and stage C had added `saveOutbox` as a tenth. The
migration test named its eight stores in a literal array for the same reason.
The test that exists to catch a forgotten store had itself forgotten one.

Adding a tenth line would have moved the problem to the eleventh store, so both
tests now enumerate the setters off `Storage` instead:

```js
const accountSetters = () => Object.keys(Storage)
  .filter((name) => name.startsWith('save') && name !== 'saveSession')
  .sort();
```

`saveSession` is the single exception: it takes `(session, remember)` and
writes outside the `e2e_` namespace, so it is not an account store.

**One redact mutation was a permanent SKIP masquerading as a pass.** Its anchor
flipped the guard on the relay's presence log line, but that line, the
`presence` frame and the entire server-side notion of an open conversation were
deleted in stage B. The anchor stopped matching, so the harness reported
`SKIP (anchor not found)` on every run.

The gate behind it is still real: the runtime half scans a live relay's output
for a presence line. So the mutation now reintroduces one on the `send` path,
which the fixture does exercise. It is caught.

### The recurring failure shape

Mutation testing has now found holes in these suites **eight separate times**,
and the failure is always the same shape: **asserting an outcome that a broken
implementation also produces.**

- The backup suite counted "zero contacts added" when the merge was silently
  *dropping* every contact.
- It counted "zero duplicates" when legacy rows were being *discarded* rather
  than matched.
- The first `MAX_SKIP` tests asserted only that decryption returned `null`,
  which is what happens anyway when the wrong key is derived, so raising the
  cap left them green. They now assert the *mechanism*: a rejected over-cap
  message must bank no skipped keys and must not advance `Nr`.
- The vault migration test drove two stores, both of which happened to be
  covered.
- The "routing pair is logged again" mutation survived twice: first because the
  fixture only sent *sealed* messages, then because the recipient was always
  offline so the "routed live" branch never ran.
- And this run, the two prefix lists and the stale presence anchor.

**Assert the mechanism and the surviving state, not the return value and not a
zero.**

### Browser verification

Beyond the Node suites, verification is manual and by headless browser against
a live relay over CDP. That is what found the `ref` bug in section 8, and the
contacts-keyed-on-`id` bug in the backup merge, neither of which any unit test
would have caught.

Start the server, open `https://localhost:8443`, and watch the tagged log.

### Real bugs found, by method

| Bug | Found by |
|---|---|
| Backup merge keyed contacts on `id`, dropping every contact | Headless browser run |
| Login wrote contacts and groups before `unlockVault` | Reading the code, proved by reverting |
| A retry's new `ref` never reached the bubble | Killing the relay mid-conversation in a browser |
| `/api/publish-prekeys` logged the username raw | Reported by the user, then generalised into the static scanner |
| `/ca.crt` logged the raw remote address | Same |
| Rate limiter spent tokens but never enforced | Reading the dispatcher |
| `MAX_SKIP` unbounded loop, remote DoS | Mutation testing |
| Outbox missing from both prefix lists | Mutation testing, this run |

---

## 12. The launcher (`talon-launcher-cpp`)

A small frameless Windows desktop app that installs Talon's dependencies,
builds the client, and starts, stops and restarts the relay, so you never have
to open a terminal to use your own messenger.

Drawn with Dear ImGui on Direct3D 11, carrying Talon's **graphite** theme and
typefaces so it reads as part of the product rather than a tool bolted onto it.

**One file, no runtime.** A single roughly 1 MB `.exe` with the fonts, the icon
and the C runtime linked in. Nothing to install, nothing to unpack, and no Node
or Electron needed to *run* it. (Node is still needed to run the relay itself;
the launcher drives it, it cannot replace it.)

### What it does

| | |
|---|---|
| **Finds Talon** | Checks the usual places on first run. Otherwise one click opens a folder picker, and the choice is remembered in `%APPDATA%\TalonLauncher\launcher.json`. |
| **Sets it up** | Runs `npm install` in `server/` and `web/`, then `npm run build`. Skips whatever is already done, so a retry after a failure resumes instead of starting over. |
| **Starts, stops, restarts** | Runs the relay as a child process and shows live status, PID and uptime. |
| **Shows the addresses** | Parses the relay's boot banner and turns each address into a button. localhost first, then Tailscale. |
| **Explains failures** | Checks 8080 and 8443 before starting and reads the relay's own fatal lines, so a port clash says so instead of spinning on "Starting...". |
| **Walks you through it** | A Guide tab with the whole setup as numbered steps, each ticking itself off as it is actually satisfied. Diagnostics as much as instructions. |
| **Tails the log** | A Log tab beside the controls. The window slides wider rather than squeezing anything. |
| **Cleans up** | Closing the launcher stops the relay. No orphaned `node.exe`, even if the launcher is killed. |

### Layout

```
src/
  main.cpp        Win32 window, D3D11 device, message loop, selftest      555 lines
  app.cpp/.h      The panel: state, actions, the side panel and the guide 958 lines
  widgets.cpp/.h  Buttons, icons, tabs, step rows, status dot, text       696 lines
  process.cpp/.h  The relay child process and the npm setup steps         593 lines
  config.cpp/.h   Finding, validating and remembering the Talon folder    307 lines
  theme.h         Talon's graphite tokens, transcribed from the CSS
  embed/fonts.h   Generated: Inter 400/600 and JetBrains Mono, as bytes
assets/           icon.ico, app.rc, app.manifest, the source woff2 files
third_party/      imgui (vendored, pinned), stb_image_write
tools/            embed_fonts.py, regenerates src/embed/fonts.h
```

Roughly 3 700 lines of first-party C++17.

### Build

CMake 3.21+ and Visual Studio 2022 (the free Build Tools with "Desktop
development with C++" are enough).

```bat
build.bat
```

Output is `build\Release\TalonLauncher.exe`. There is no dependency to fetch:
Dear ImGui is vendored, and the fonts and icon are compiled in.

The CMake configuration is doing three deliberate things:

- **Static CRT** (`MultiThreaded`), because the whole point is a single `.exe`
  a non-developer can run without installing the Visual C++ redistributable.
- **`/OPT:REF /OPT:ICF`** in release, folding identical code and dropping
  unused sections. This is a small tool and the binary size is user-visible.
- **`/MANIFEST:NO`**, because the manifest is embedded through `app.rc` and the
  linker's generated one would collide with it as a duplicate resource
  (CVT1100).

### Design notes

- **Nothing is a stock ImGui widget.** Every control is drawn into the draw
  list by hand so it can carry Talon's radii, weights and easing, and so
  buttons can physically scale, which the stock ones cannot.
- **All positions are logical pixels**, multiplied by `ui::g_scale` through
  `S()` at draw time. That is what makes the panel match the messenger on a
  150% display. Never write a raw pixel value into a draw call.
- **The loop is event-driven and paced in three bands.** Idle, it sleeps in
  `MsgWaitForMultipleObjects` for a second at a time, which is long enough to
  keep the uptime honest. With only ambient motion left, meaning the status
  ping while the relay runs, it drops to 30fps focused and 10fps not. Full rate
  is reserved for transitions and actual pointer interaction. Worker threads
  nudge it with a `PostMessage`.
- **The relay running is not, by itself, a reason to draw fast.** It animates,
  but nothing is interactive, so it belongs in the ambient band.
- **Every clause of `App::fastFrames_` needs an epsilon or an emptiness
  check.** `toastAge_` only advances while a toast exists, and the eased fades
  approach their targets asymptotically. Write one of them naively and it is
  true forever, so the launcher silently never leaves full speed. That was a
  real bug, caught only because `--selftest-drive` reports its frame rate.

### The relay is a job object, not a process

`KILL_ON_JOB_CLOSE` means the whole process tree dies with the handle, so
nothing can be orphaned even if the launcher itself is killed. This replaced
the `taskkill /f /t` escalation the Electron version needed.

Node on Windows cannot be shut down politely anyway: its `kill()` is a
`TerminateProcess` either way, so there is no graceful path being given up.

### Reading the relay's output

**"Server Active" is the ready signal, and `[FATAL]` is the failure signal.**
Both are read out of the relay's own stdout.

The second one matters because the relay installs an `uncaughtException`
handler that only *logs*. A failure to bind leaves node alive with nothing
listening, so waiting for the ready line would wait forever.

### Fonts

**Static instances, not the variable originals.** stb_truetype ignores
variation axes, so shipping the variable font would silently render every
weight at 400. `tools/embed_fonts.py` instantiates 400 and 600 into separate
faces and subsets them. Re-run it only if you change the fonts or need a glyph
the log pane is drawing as `?`.

### CA trust, and what the launcher deliberately will not do

`config::CaIsTrusted()` reports whether Talon's local CA is in the machine's
trusted-root store, by enumerating for the subject prefix the relay issues
(`CN=Talon Local CA (<hostname>), O=Talon`).

It is **read-only**. It opens the store for enumeration and never modifies it.
Trusting a root certificate is the user's decision, made through the relay's
own `/setup` page. **The launcher must not install a root certificate itself.**

`config::OpenUrl` likewise refuses anything that is not http or https, so
nothing else can be launched through it.

### Self-test

```bat
build\Release\TalonLauncher.exe --selftest
```

Renders the panel off-screen, prints the DPI scale, client size and font
status, writes a screenshot, and exits. A visual check without a window
appearing.

```bat
set SELFTEST_DIR=C:\some\folder
build\Release\TalonLauncher.exe --selftest-drive
```

Presses the real buttons on a timer (open the guide, start, switch to the log,
restart, stop, close the panel) and screenshots each result. **Clicks go in as
input events rather than by calling the handlers**, so it exercises the same
path a mouse would, against a real relay. Takes about 50 seconds and needs
ports 8080 and 8443 free.

Each line reports the panel state, the client size and **the frame rate since
the previous shot**, which is what makes the pacing testable:

```
[drive]  19.1s shot  panel=guide  740x470  23.6fps  ...drive-3-started-guide.png
[drive]  19.5s shot  panel=guide  740x470   9.2fps  ...drive-3b-ping.png
```

Two habits worth keeping when extending it:

- **Move the pointer off the window after a click.** Left parked on a button it
  counts as hover, which pins the frame rate at full speed and hides whether
  the pacing works.
- **Never sample an animation at half its period.** The two ping rings are
  offset by exactly half, so half-period samples swap them and the diff comes
  out as zero. The animation looks broken when it is fine. `3b-ping` is
  deliberately a *quarter* period after `3`.

**The honest test of the guide is a wrong state.** Run it with Node off PATH
and check that step 1 goes red and says so:

```bat
set PATH=C:\Windows\System32
build\Release\TalonLauncher.exe --selftest-drive
```

A checklist that is always green is worthless. That principle is the same one
driving the mutation testing in section 11.

### Licence

MIT. Dear ImGui is MIT. `stb_image_write` is public domain. Inter and JetBrains
Mono are used under the SIL Open Font License.

---

## 13. Upcoming features

### Phase 2, remaining

| # | Item | Why |
|---|---|---|
| **2.6** | Accessibility pass | Screen reader labels, modal focus trapping, keyboard-only operation. The last thing outstanding for 1.0. |

Phase 2.1 (vault on by default), 2.4 (the journal), 2.5 (reproducible build)
and metadata stages A, B and C are all complete.

### 2.5, as built

`npm run build` now writes `public/build-manifest.json` and stamps a
Subresource Integrity hash into `index.html`. `npm run verify` checks four
things against a fresh clone: the committed bundle matches the manifest, the
installed esbuild is the one that produced it, **rebuilding the source
reproduces the bundle byte for byte**, and the page carries a matching
integrity hash. CI runs `verify` before rebuilding, so it checks the artifacts
exactly as a user cloning the repository would find them.

The manifest deliberately carries **no timestamp and no builder name**. Either
would make two correct builds differ and turn the check into noise.

What a pass proves: these bytes came from this source with this tool. What it
does not prove: that the source is trustworthy, or that some other relay serves
the same thing. SRI has a matching limit, written into the code where somebody
might overstate it: the bundle is same-origin, so whoever can rewrite `app.js`
can usually rewrite `index.html` too. It catches a partial compromise.

### Multi-device

**Built and verified.** Two real browser profiles signed into one account,
against a live relay, pass 22 checks end to end.

#### What a device is, and what it is not

An account has one identity key, and **that key is the contact address**.
Devices do not change that: a device is a sub-key under the account, published
so each one can hold its own ratchet state.

Every device of an account already holds the same `idPriv`, because
`encryptedIdPriv` is recoverable from the relay with the password. Adding a
second device therefore grants it nothing it could not already have.
**Multi-device here is about routing and session state, not a new trust
boundary.**

#### Why the relay cannot read your mail by inventing a device

The obvious attack is the relay adding a device of its own so senders fan out
to it. That fails for a structural reason rather than because the list is
signed: a session to a device still mixes `DH(EK_a, IK_b)` with the **account**
identity key, exactly as a single-device session does. The device key is
additive, the same way the ML-KEM prekey is additive.

A device the relay invented has no `idPriv`, so it cannot complete the
handshake, and the injected envelope is one nobody can open.

This matters because `verifyBundle` checks the signed prekey against
`bundle.signPub`, and **nothing binds `signPub` to `idPub`** since the relay
serves both. What saves the design is that `IK_b` is the Client ID the user
pasted out of band. So the account DH must stay in the device handshake; do not
remove it on the grounds that the device list is signed.

#### So what is the signature for

Integrity and visibility. It makes the list tamper-evident, so a device you do
not recognise appearing in your own settings is a real signal, and the relay
cannot quietly drop a device to stop your peers delivering to it.

`deviceListAcceptable` is the single gate, mirroring `rosterAcceptable`:
unsigned is refused outright, revisions move strictly forward (equal is refused
too, since a replay at the same revision is how a revocation gets undone), the
signing key is pinned on first accept, the list is capped at eight devices,
duplicate ids and keys are refused, and an empty list is refused because it
would silently un-deliver the whole account.

**The relay deliberately does not verify that signature.** It serves the
signing key too, so the check would prove nothing, and a second copy of the
canonical encoder on the server is the theme-preload/sw.js drift hazard for no
gain. What the relay does enforce is auth, shape, and **revision
monotonicity**, which alone stops a captured publish being replayed to
reinstate a revoked device.

#### How it fits together

| Piece | Where |
|---|---|
| Canonical encoding, signing, the gate, session keying | [web/src/devices.js](talon-main/web/src/devices.js) |
| Device list storage, per-device prekey pools, `/api/devices` | [server/db.js](talon-main/server/db.js), [server/server.js](talon-main/server/server.js) |
| One socket per device, per-device offline queue buckets | [server/server.js](talon-main/server/server.js) |
| Device identity, publishing, send fan-out, self-sync | [web/src/messaging.js](talon-main/web/src/messaging.js) |
| The Settings pane | [web/src/panes.js](talon-main/web/src/panes.js) |

Sessions are keyed `contactId` or `contactId:deviceId`. The bare form is what
every pre-device session already uses, so there is no migration.
`resetSession` clears all of them via `sessionKeysFor`, or a stale per-device
ratchet resurrects itself on the next message.

#### The receive-side collision

Two of a peer's devices each run their own X3DH against you. Keyed under the
bare peer id, the second handshake overwrote the first and every later message
from the first device silently failed to decrypt.

The sender's device id therefore rides **inside the seal**, not on the frame.
The relay learns the recipient device because it has to route; it has no reason
to learn the sender's. It is validated on the way in, because it selects a
storage key and is attacker-chosen: anything that is not a device id collapses
to null rather than minting an arbitrary session.

#### Costs, stated rather than discovered

- Fan-out multiplies envelopes per message by the recipient's device count,
  which pushes on the `send` rate limiter and the outbox.
- `recipientDev` is **new plaintext on the wire**: the relay learns which
  device a message is for. The alternative, broadcasting unlabelled, grows the
  offline queue with the square of the device count.
- A legacy sender that names no device gets one queued row per device, so the
  device holding the session is guaranteed to receive it.

#### Removing a device is not revoking it

Peers stop addressing it and it receives nothing further. The messages and keys
already on it stay there. Taking those back needs a key that device does not
have, which is the group-key problem in another shape. The confirm dialog says
so, because a button that reads as revocation would be the UI lying.

### Talon Protocol v4: three keys and a seal

Planned, not built. The specification is the stage 0 deliverable, not code.

Talon's cryptography today is good, and it is assembled from other people's
designs: X3DH, the Double Ratchet, and a PQXDH-style ML-KEM-768 hybrid bolted
onto the handshake. It works, but it has no identity of its own, and section 14
is honest about four holes it cannot close in its current shape:

1. **Post-quantum protection is frozen at handshake time.** The KEM secret is
   fixed until the KEM prekey rotates, so the post-compromise security the DH
   ratchet provides has no post-quantum equivalent.
2. **Downgrade is visible but not prevented.** A relay that strips `kemPreKey`
   from a bundle forces a classical session, and nothing refuses it.
3. **The endpoints are trusted absolutely.** Vault mode encrypts local data
   under a password-derived key, so the password is the only thing between a
   stolen disk and everything.
4. **Trust on first use.** Nothing proves a pasted identity key belongs to the
   person you think.

#### The rule this design does not break

**v4 invents no new primitives.** Every primitive stays one already vetted and
already in the tree: X25519, Ed25519, ML-KEM-768, AES-256-GCM, HKDF-SHA256,
HMAC-SHA256 and ristretto255 (confirmed present in `@noble/curves`, so the
token work adds no dependency).

What is new is the *composition*, the downgrade resistance, and the
specification. A homemade cipher or a homemade KDF construction would undo
everything else in the design, and there is no version of "Talon Protocol"
worth having that contains one.

#### Three keys

Every v4 session key folds three independent secrets. Breaking any one of them
leaves the session standing.

| | Key | Primitive | What its compromise costs an attacker |
|---|---|---|---|
| 1 | **Identity** | X25519 + Ed25519 | Nothing on its own. Present today. |
| 2 | **Post-quantum** | ML-KEM-768 | Nothing on its own. Present today, but frozen. |
| 3 | **Possession** | X25519 seeded from WebAuthn PRF | **New.** Reading the disk is no longer enough. |

And one seal, which is authentication rather than key material:

| | Seal | Source | What it closes |
|---|---|---|---|
| 4 | **Pairing** | 32 random bytes inside the QR you already scan | Trust on first use. An active relay can no longer MitM a first contact. |

#### Why possession is the headline

It changes the threat model rather than tightening it. Today the honest
statement is "if your device is compromised, Talon cannot save you", which is
true of every messenger. But "compromised" currently includes "somebody read
`localStorage`", which is a much lower bar than it sounds: any XSS slip, any
malicious extension, any unlocked laptop.

```
prf     = WebAuthn PRF output (authenticator, per credential, per salt)
seed    = HKDF(prf, info = "TalonDeviceKeyv4")
DevPriv = X25519 private key from seed   <- never stored, re-derived on touch
DevPub  = X25519 public key              <- published in the bundle, signed by IK
```

It has to be a **keypair seeded from the PRF**, not the raw PRF output. A raw
shared secret cannot work, because the initiator has no way to learn the
responder's PRF value. With a keypair the initiator computes
`DH(EK_a, DevPub_b)` from public material alone, and only the responder's
authenticator can complete it.

**Fallback is mandatory and marked.** WebAuthn PRF support is uneven, and a
browser without it must still work. The device seed then derives from the
password-derived `encryptionKey`, the session records `hw: false`, and the UI
says so. This mirrors the existing `pq: true|false` pattern exactly. It is not
to become a hard failure.

**Losing the authenticator must be survivable.** The device key is mixed into
*sessions*, which are disposable and re-handshake automatically, and it wraps
*local storage*, which is recoverable from the encrypted backup file. It is
deliberately **not** required to recover the identity key, which stays
recoverable with the password alone. A hardware key that can brick an account
is a hardware key people will refuse to enable.

#### The handshake

```
SK = HKDF(
       0xFF * 32
    || DH(IK_a, SPK_b)
    || DH(EK_a, IK_b)
    || DH(EK_a, SPK_b)
    || DH(EK_a, OPK_b)     if a one-time prekey is available
    || DH(EK_a, DevPub_b)  if the peer published a device key
    || KEM(kemPreKey_b)    ML-KEM-768 encapsulation
    || PSK_pair            if the two have paired out of band
    || H_transcript
     , info = "TalonProtocolv4")
```

#### The bundle manifest

The cheapest high-value change in the whole design, and the one that ships
first. Today each prekey is signed individually, so a relay cannot *substitute*
one, but it can freely *delete* one, and the client accepts the weaker session.

```
sig_IK( "TalonBundle:" || canonical({ idPub, signPub, spk, kemPub, devPub,
                                      hasOtk, caps, notBefore }) )
```

This reuses the canonical-encoding discipline already proven in
`buildRosterMessage`: sorted keys, fixed field order, domain-separated prefix.
Deleting `kemPub` now breaks the signature, so the downgrade fails closed
instead of silently succeeding.

`H_transcript` hashes the manifest, `ek`, `opkId`, `kemCt` and the negotiated
capability set into `SK`, which stops any mix-and-match of one handshake's
parts into another.

#### The Triple Ratchet

| Ratchet | Cadence | Gives |
|---|---|---|
| Symmetric chain (HMAC) | every message | Per-message keys. Present today. |
| DH ratchet (X25519) | every change of direction | Post-compromise security. Present today. |
| **KEM ratchet (ML-KEM-768)** | **every epoch: N messages or T elapsed** | **Post-quantum post-compromise security. New.** |

The KEM ratchet re-encapsulates to a fresh ML-KEM public key carried in the
header and folds the result into the root key alongside the DH step. A quantum
adversary who breaks one epoch is locked out of the next.

**Cost, stated plainly:** an ML-KEM-768 public key is 1184 bytes and a
ciphertext is 1088 bytes. Putting either in every header would roughly triple
envelope size. Hence epochs rather than per-message. Opening values to measure:
`KEM_EPOCH_MESSAGES = 50`, `KEM_EPOCH_MS = 24h`, both tunable, both to be
measured on a real phone before being fixed.

**Every new counter is attacker-controlled plaintext.** The epoch index joins
`n`, `pn` and `messageIndex` on that list, so it gets a `MAX_SKIP`-style bound
from the first line of code, not after somebody finds the DoS. That bug has
already happened once here.

#### Storage: a second factor

```
vaultKey = HKDF(encryptionKey || devicePRF, info = "TalonVaultv2")
```

Both the password and the authenticator are required to read local data. The
escape hatch stays the encrypted backup file: passphrase only, no hardware, so
a dead authenticator costs a re-handshake and not an archive.

#### Metadata: tokens, then shaping

Two honest notes first, because they change *why* this is worth building rather
than whether:

- **With two users the anonymity set is two.** Unlinkable delivery tokens
  protect against a relay operator who is not you. In a two-person self-hosted
  deployment that is nobody. The real reasons to build it are that it makes
  Talon correct for a larger group, and that it is the difference between
  "sealed sender, partial" and sealed sender.
- **Traffic shaping protects against a different adversary than you might
  expect.** It does very little against the relay, which is your own hardware.
  It does a lot against anyone watching the *network*: the tailnet, an ISP, a
  hostile Wi-Fi. That is the real target and it should be named as such.

**Delivery tokens** would be a Privacy Pass style VOPRF over ristretto255. The
client blinds a random nonce, the relay evaluates it under a long-term key, the
client unblinds, and later spends the token to deliver a message without
presenting an identity. The relay can verify the token is one it issued and has
not seen before, and cannot link it to the issuance.

Known cost, to be designed in from the start rather than discovered: this
breaks the current rate limiter, which is keyed by username after
authentication. Token issuance becomes the rate-limited operation, and spending
becomes free but single-use.

**Traffic shaping** would be fixed-size cells on a fixed cadence with cover
traffic when idle, extending the existing 256-byte bucket padding to a single
fixed cell size plus a heartbeat. It must be a setting with an honest cost
label attached, because it costs battery, bandwidth and latency, and most
people should leave it off.

#### Group keys

Signed rosters fixed *who may change the roster*. They did not fix *who can
read*: removing someone means the others stop addressing them rather than
losing the ability to read.

v4 adds a sender-key style group key, rotated on every membership removal, so
removal actually removes read access. It lands late because signed rosters
already closed the forgery hole, which was the sharper one.

#### Staging

Ordered by value per unit of risk, not by how interesting each part is.

| Stage | Work | Why here |
|---|---|---|
| **0** | Spec document plus test vectors. No app code. | Everything else is validated against it. |
| **1** | Bundle manifest, transcript binding, `v: 4` negotiation. | Cheapest change, closes a documented hole, no new key material. |
| **2** | KEM ratchet (the Triple Ratchet). | Largest crypto gain. Self-contained in `ratchet.js`. |
| **3** | Possession key plus hardware-wrapped vault. | The headline. Depends on stage 1 for capability negotiation. |
| **4** | Pairing seal in the QR, closing TOFU. | Small once stage 1 exists. |
| **5** | Group keys. | Independent of 1 to 4. |
| **6** | Delivery tokens (VOPRF). | Expensive, and least valuable at two users. |
| **7** | Traffic shaping. | Most expensive, opt-in, network-observer threat only. |
| **8** | Sunset v1/v2/v3 on the published date. | Only after v4 has run in anger. |

**Compatibility:** v4 coexists with v2 and v3 and is negotiated when both sides
advertise it. The old paths are then removed on a date written into
the README from day one. Nobody loses history, and the branches have an end
date instead of accumulating forever.

**Single device.** The wire format still carries a device id field so the
option is not designed out, but device lists, revocation and fan-out are
explicitly out of scope. The consequence, accepted: with a device-bound key,
moving to a new machine means restoring the backup and re-handshaking every
conversation.

#### Verification a protocol earns

The discipline in section 11 applies unchanged, plus two additions:

1. **Test vectors, frozen and committed.** A handshake and a hundred-message
   ratchet run with fixed randomness, checked into the repo, so any change that
   alters the wire format fails loudly instead of quietly breaking a peer.
2. **Mutation testing on every new gate.** Manifest verification, epoch bounds,
   downgrade refusal and token single-use each get a mutation that must turn
   the suite red.
3. **A formal model of the handshake.** Verifpal or ProVerif on the v4
   handshake is a few hundred lines, and is the only way to have real
   confidence that folding four optional inputs into one HKDF has no
   mix-and-match attack. This is the step that separates a protocol from a pile
   of primitives.
4. **Downgrade tests are the interesting ones.** For every optional input,
   assert that a bundle with the field stripped is *refused*, not merely
   downgraded.
5. **Measure on a real phone before fixing any constant.** The KEM epoch
   values, the cell size and the cadence are guesses until then. Argon2id was
   rejected on measurement rather than opinion, and the same standard applies.

### Considered and rejected

**Rotating recipient identifiers.** The obvious next step after push tags is to
address envelopes to a rotating mailbox derived from a secret the relay does
not hold, rather than to a stable identity key.

It does not work in this architecture. The recipient has to tell the relay
which mailboxes to deliver to, over a socket authenticated as their account,
which re-links every mailbox to the identity the moment they connect. Closing
that needs unauthenticated delivery backed by unlinkable tokens, which is a
protocol change rather than a relay change.

Shipping mailboxes without it would move the leak rather than remove it, and
would read as a stronger claim than it is. It is therefore deferred to v4 stage
6, where the tokens exist to make it real.

---

## 14. Known limitations

Real and deliberate. Do not assume otherwise.

**Sealed sender is partial.** Nothing the relay *persists* records who sent
what: the offline queue, the access log and the push payload all carry the
recipient only. A stolen database no longer reconstructs the social graph, and
the relay can no longer forge a `senderId`, which is now inside an AEAD.

What it does not do is hide the sender from a live, malicious relay. The
WebSocket is authenticated per identity, so the running process always knows
which socket a frame arrived on.

**New accounts are encrypted at rest. Older ones are not, unless they asked to
be.** Accounts created before vault mode existed have plaintext blobs on disk
and no recorded preference, so they are left exactly as they are. Silently
switching them over would change a security property without their owner
deciding to.

The catch is unavoidable: the key cannot be written to disk, so the vault is
incompatible with "keep me signed in" and you must enter your password on every
cold start. The registration form disables the one when you choose the other
rather than accepting both and quietly dropping one.

**The app-lock PIN is a UI gate.** Stored as a salted verifier, protecting
nothing cryptographically. Anyone with filesystem access reads the messages
regardless, because the message keys are still on disk.

**Removing a device is not revoking it.** Multi-device works: one socket per
device, per-device prekey pools and ratchets, per-device offline queues, and
sent messages mirrored to your other devices. What removal does is stop peers
addressing that device. The messages and keys already on it stay there, because
taking them back needs a key that device does not have.

Two smaller consequences worth naming. The relay learns which of your devices
an envelope is for, which it did not before. And a new device starts empty: it
does not backfill history, so restore a backup if you want the archive.

**Group membership is signed, but a first invitation is still trust on first
use.** An invitee with no prior knowledge of the group cannot tell a current
signed roster from an older one the inviter replayed, and the owner is trusted
not to lie about the membership. There is also still no group key.

**Metadata is reduced, not eliminated, and it never can be.** See section 7.

**A backup file is only as strong as its passphrase.** The file has no rate
limit in front of it. A weak passphrase is crackable offline at whatever speed
the attacker's hardware allows, and the twelve-character minimum is a floor,
not a recommendation. There is no recovery, by design.

**Trust on first use.** The first time you add someone, nothing proves the key
belongs to them. Compare safety numbers out of band to close this. There is,
however, no directory that could substitute a key afterwards, because a
contact's address *is* their key.

**No key-change detection**, because it is structurally unnecessary: the
identity key is the contact identifier, so a "changed key" is simply a
different contact.

---

## Reporting

This is a personal project running on your own hardware. There is no vendor.
