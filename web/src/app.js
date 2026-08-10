// --- TALON CLIENT ENTRY ---
// Boot, auth, tab routing, WebSocket wiring, the inbound payload handler,
// keyboard shortcuts, WebRTC, and panic wipe. Rendering lives in views.js /
// panes.js; the protocol lives in messaging.js.

import {
  generateIdentityKeypair, bytesToHex, hexToBytes, utf8Encode, utf8Decode,
  deriveMasterKey, deriveMasterKeyV2, encryptWithKey, decryptWithKey,
  sha256Hash, KDF_V2
} from './crypto-bundle.js';
import {
  Storage, State, persist, metaFor, WIPE_PREFIXES, DEFAULT_SETTINGS,
  unlockVault, lockVault
} from './store.js';
import { icon, passwordScore, debounce, escapeHTML, avatarGradient, initials, setClockFormat } from './util.js';
import { applyTheme } from './theme.js';
import { clearMutedTags } from './pushdb.js';
import {
  makeEntry, addEntry, removeEntry, findEntry, dueEntries, isExhausted,
  afterAttempt, forceDue, nextWakeup, alreadyReceived, ACK_TIMEOUT_MS
} from './outbox.js';
import { playCue } from './sound.js';
import {
  toast, confirmDialog, openModal, closeModal, isModalOpen, closePopover,
  initLightbox, showNetBanner, hideNetBanner, promptDialog
} from './ui.js';
import {
  sendE2EPayload, sendGroupMessage, sendControl, processIncomingMessage,
  decryptFailureCount, acceptsAdminFrom, acceptGroupRev, announceLeave, rosterAcceptable,
  syncContactsWithServer, syncGroupsWithServer, publishMutedTags, pushTagFor,
  conversationForPushTag,
  isGroupId, findMsg, totalUnread, normalizeReactions, toggleReactionLocal,
  previewFor, ttlFor, isBlocked, isTrusted, setContactFlags, ensurePreKeys,
  openSealed, ensureDeviceIdentity, publishThisDevice
} from './messaging.js';
import { encryptAndUpload } from './crypto-extra.js';
import * as views from './views.js';
import {
  renderProfilePane, renderSettingsPane, paneHooks, openContactProfile,
  openGroupInfo, openSearchModal, openForwardModal, openShortcutsModal,
  showLockScreen, hideLockScreen
} from './panes.js';

/* ============================================================ SESSION INIT */

function initializeSession(sessionData) {
  State.currentUser = sessionData;
  const u = sessionData.username;

  // Settings are never vaulted, so this is readable before unlock, which is
  // exactly why the flag lives there. Unlock BEFORE any blob is read, or every
  // read returns its empty fallback and the account looks wiped.
  //
  // A device that has never stored settings for this account is signing in
  // for the first time, and gets the vault ON, the same as a new account.
  //
  // This is not the same decision as DEFAULT_SETTINGS.encryptAtRest, which
  // stays false so that an existing account with plaintext blobs already on
  // THIS disk is not flipped without its owner choosing to. On a fresh device
  // there are no such blobs, so that reasoning does not apply and the default
  // that does apply is the one registration uses.
  //
  // Getting this wrong is not cosmetic: without it, signing into a
  // vault-enabled account from a second device wrote every blob, including
  // the identity key material, to that disk in the clear. Found by a
  // two-device browser run, not by any unit test.
  const firstTimeHere = !Storage.hasSettings(u);
  const stored = Storage.getSettings(u);
  const wantVault = firstTimeHere ? true : stored.encryptAtRest;

  if (wantVault && sessionData.encryptionKeyHex) {
    unlockVault(sessionData.encryptionKeyHex);
    if (firstTimeHere) Storage.saveSettings(u, { ...stored, encryptAtRest: true });
  }

  State.contacts = Storage.getContacts(u);
  State.messages = Storage.getMessages(u);
  State.sessions = Storage.getSessions(u);
  State.groups = Storage.getGroups(u);
  State.myProfile = Storage.getProfile(u);
  State.settings = Storage.getSettings(u);
  State.drafts = Storage.getDrafts(u);
  State.chatMeta = Storage.getChatMeta(u);
  State.preKeys = Storage.getPreKeys(u);
  State.outbox = Storage.getOutbox(u);

  applyTheme();
  // util.js cannot import the store, so the clock preference is pushed in.
  setClockFormat(String(State.settings.clockFormat || 'auto'));

  if (!State.ttlSweepInterval) {
    State.ttlSweepInterval = setInterval(sweepExpiredMessages, 10000);
  }
}

function sweepExpiredMessages() {
  if (!State.currentUser) return;
  const now = Date.now();
  const before = State.messages.length;
  State.messages = State.messages.filter((m) => !(m.expiresAt && now >= m.expiresAt));
  if (State.messages.length !== before) {
    persist.messages();
    if (State.activeContactId) views.renderChatArea();
    views.renderChatList();
  }
}

/** Broadcasts our profile to every contact and group member. */
function syncProfileWithServer() {
  if (!State.currentUser) return;
  const payload = { type: 'control', action: 'profile-sync', profile: State.myProfile };
  const recipients = new Set(State.contacts.map((c) => c.idPub));
  State.groups.forEach((g) => g.members.forEach((m) => {
    if (m !== State.currentUser.idPub) recipients.add(m);
  }));
  recipients.forEach((id) => sendE2EPayload(id, payload));
}

/* =============================================================== TAB ROUTER */

const PANES = { chats: 'pane-chats', profile: 'pane-profile', settings: 'pane-settings' };

function setTab(tab) {
  if (!PANES[tab]) return;
  State.activeTab = tab;

  Object.entries(PANES).forEach(([name, id]) => {
    const el = document.getElementById(id);
    if (el) el.hidden = name !== tab;
  });

  document.querySelectorAll('[data-tab]').forEach((b) => {
    b.classList.toggle('active', b.dataset.tab === tab);
  });

  // Profile and Settings are full-width documents; only Chats keeps the
  // master/detail split.
  document.getElementById('app')?.classList.toggle('wide-pane', tab !== 'chats');

  if (tab === 'profile') renderProfilePane();
  if (tab === 'settings') renderSettingsPane();

  // On phones the detail column is an overlay; leaving Chats must dismiss it.
  if (tab !== 'chats') closeDetail();
}

function openDetail() {
  document.getElementById('app')?.classList.add('detail-open');
}

function closeDetail() {
  document.getElementById('app')?.classList.remove('detail-open');
}

function updateUnreadBadges() {
  const { messages, conversations } = totalUnread();
  const label = messages > 99 ? '99+' : String(messages);
  [['rail-unread', messages], ['tab-unread', messages]].forEach(([id, n]) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = label;
    el.classList.toggle('hidden', n === 0);
  });
  document.title = messages > 0 ? `(${label}) Talon` : 'Talon';
  void conversations;
}

/* ========================================================== CONVERSATIONS */

function selectConversation(convId, jumpTo = null) {
  if (!convId) return;
  if (!State.contacts.some((c) => c.idPub === convId) && !isGroupId(convId)) return;

  // Persist any draft from the conversation we're leaving.
  const prevInput = document.getElementById('composer-input');
  if (prevInput && State.activeContactId) {
    const v = prevInput.value;
    if (v.trim()) State.drafts[State.activeContactId] = v;
    else delete State.drafts[State.activeContactId];
    persist.drafts();
  }

  State.activeContactId = convId;
  State.replyingTo = null;
  State.editingMessage = null;
  setTab('chats');

  // Snapshot the unread boundary before marking anything read, so the "New"
  // divider lands above the first message that was genuinely unread.
  const firstUnread = State.messages.find(
    (m) => m.contactId === convId && m.sender === 'them' && m.status !== 'read'
  );
  State.unreadDividerContactId = convId;
  State.unreadDividerMessageIndex = firstUnread ? firstUnread.messageIndex : null;

  views.renderChatList();
  views.renderChatAreaSkeleton();
  openDetail();

  requestAnimationFrame(() => requestAnimationFrame(() => {
    views.renderChatArea();
    views.markConversationRead(convId);
    views.renderChatList();
    updateUnreadBadges();
    if (jumpTo) {
      setTimeout(() => views.jumpToMessage(jumpTo.messageIndex, jumpTo.sender), 90);
    }
  }));
}

function backToList() {
  const input = document.getElementById('composer-input');
  if (input && State.activeContactId) {
    const v = input.value;
    if (v.trim()) State.drafts[State.activeContactId] = v;
    else delete State.drafts[State.activeContactId];
    persist.drafts();
  }
  State.activeContactId = null;
  closeDetail();
  views.renderChatList();
  views.renderChatArea();
}

/**
 * Handles `#add=<idPub>`, the link behind the profile QR code.
 *
 * The other device's camera opens this URL, and we turn it into a pre-filled
 * Add contact sheet. It is a prompt, never an automatic add: a link can be
 * sent by anyone, so the decision stays with the user.
 *
 * The fragment is stripped immediately, so a reload does not reopen the sheet
 * and the ID does not linger in the address bar over someone's shoulder.
 */
function consumeAddLink() {
  const m = /^#add=([0-9a-f]{64})$/i.exec(location.hash || '');
  if (!m) return;
  const id = m[1].toLowerCase();
  history.replaceState(null, '', location.pathname + location.search);

  if (id === State.currentUser.idPub) {
    toast('That is your own Client ID');
    return;
  }
  const existing = State.contacts.find((c) => c.idPub === id);
  if (existing && !existing.pending) {
    toast(`${existing.nickname} is already a contact`);
    selectConversation(id);
    return;
  }
  addContactFlow(id);
}

async function addContactFlow(prefill = '') {
  openModal({
    title: 'Add a contact',
    body: `
      <div class="field">
        <label class="field-label" for="ac-id">Client ID</label>
        <input class="input mono" id="ac-id" placeholder="64-character hex identity key"
               value="${escapeHTML(prefill)}" autocomplete="off" spellcheck="false" data-autofocus>
        <div class="field-hint">Ask them to copy this from their Profile tab.</div>
      </div>
      <div class="field">
        <label class="field-label" for="ac-name">Name (optional)</label>
        <input class="input" id="ac-name" placeholder="What should we call them?" autocomplete="off">
      </div>`,
    footer: `
      <button class="btn" data-close>Cancel</button>
      <button class="btn btn-primary" id="ac-add">Add contact</button>`,
    onMount(root, close) {
      const idField = root.querySelector('#ac-id');
      const nameField = root.querySelector('#ac-name');

      const submit = () => {
        const id = idField.value.trim().toLowerCase();
        if (!/^[0-9a-f]{64}$/.test(id)) {
          idField.classList.add('invalid');
          toast('A Client ID is 64 hex characters', { type: 'error' });
          return;
        }
        if (id === State.currentUser.idPub) { toast('That is your own ID', { type: 'error' }); return; }
        if (State.contacts.some((c) => c.idPub === id)) {
          toast('You already have that contact');
          close();
          selectConversation(id);
          return;
        }

        const chosenName = nameField.value.trim();
        State.contacts.push({
          idPub: id,
          nickname: chosenName || `Peer-${id.substring(0, 6)}`,
          // A name the user typed is theirs; profile-sync must not clobber it.
          nameLocked: !!chosenName
        });
        persist.contacts();
        syncContactsWithServer();
        close();
        views.renderChatList();
        selectConversation(id);
        toast('Contact added', { type: 'ok' });
      };

      root.querySelector('#ac-add').onclick = submit;
      idField.onkeydown = (e) => { if (e.key === 'Enter') { e.preventDefault(); nameField.focus(); } };
      nameField.onkeydown = (e) => { if (e.key === 'Enter') { e.preventDefault(); submit(); } };
    }
  });
}

function newGroupFlow() {
  if (State.contacts.length === 0) {
    toast('Add a contact first', { type: 'warn' });
    return;
  }

  openModal({
    title: 'New group',
    body: `
      <div class="field">
        <label class="field-label" for="ng-name">Group name</label>
        <input class="input" id="ng-name" placeholder="Weekend plans" maxlength="40" data-autofocus>
      </div>
      <div class="field-label" style="margin-bottom:var(--sp-2)">Members</div>
      <div class="card" style="max-height:40vh;overflow-y:auto">
        ${State.contacts.map((c) => `
          <label class="row" style="cursor:pointer">
            <div class="avatar-wrap">${views.avatarHTML(c.idPub, c.nickname, 'avatar-sm')}</div>
            <div class="row-main"><div class="row-title">${escapeHTML(c.nickname)}</div></div>
            <div class="row-ctl">
              <span class="checkbox">
                <input type="checkbox" value="${c.idPub}">
                <span class="checkbox-box"></span>
              </span>
            </div>
          </label>`).join('')}
      </div>`,
    footer: `
      <button class="btn" data-close>Cancel</button>
      <button class="btn btn-primary" id="ng-create">Create group</button>`,
    onMount(root, close) {
      root.querySelector('#ng-create').onclick = () => {
        const name = root.querySelector('#ng-name').value.trim();
        const members = Array.from(root.querySelectorAll('input[type=checkbox]:checked')).map((i) => i.value);

        if (!name) { toast('Give the group a name', { type: 'error' }); return; }
        if (!members.length) { toast('Pick at least one member', { type: 'error' }); return; }

        const groupId = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
        const group = {
          id: groupId, name,
          members: [...members, State.currentUser.idPub],
          // The creator administers it. There is no server-side group, so
          // this is the only thing that keeps two members from writing
          // contradictory rosters.
          owner: State.currentUser.idPub,
          rev: 1
        };

        State.groups.push(group);
        persist.groups();
        syncGroupsWithServer();

        const invite = {
          type: 'group-control', action: 'create',
          groupId, name, members: group.members, owner: group.owner, rev: 1
        };
        members.forEach((id) => sendE2EPayload(id, invite, groupId, true));

        close();
        views.renderChatList();
        selectConversation(groupId);
        toast('Group created', { type: 'ok' });
      };
    }
  });
}

async function forwardMessage(msg, targetId) {
  const isGroup = isGroupId(targetId);
  let payload;

  if (msg.type === 'file' || msg.type === 'voice-memo') {
    payload = { ...msg.file, type: msg.type };
  } else if (msg.type === 'sticker') {
    payload = { type: 'sticker', emoji: msg.text };
  } else {
    payload = { type: 'text', text: msg.text };
  }

  // Travels inside the ciphertext like everything else, so the recipient sees
  // the same "Forwarded" caveat the sender does. Without it the warning only
  // ever appears on the copy that needs it least.
  payload.forwarded = true;

  const ttl = ttlFor(targetId);
  if (ttl) payload.ttl = ttl;

  let success = true;
  let messageIndex = Date.now();
  let ref;
  let refs;
  if (isGroup) {
    refs = await sendGroupMessage(targetId, payload);
  } else {
    const r = await sendE2EPayload(targetId, payload, undefined, true);
    success = r.success;
    messageIndex = r.messageIndex;
    ref = r.ref;
  }

  State.messages.push({
    contactId: targetId,
    senderId: State.currentUser.idPub,
    sender: 'me',
    type: msg.type,
    text: msg.type === 'sticker' ? msg.text : (msg.text || ''),
    file: msg.file || null,
    timestamp: Date.now(),
    status: success ? 'sending' : 'offline',
    messageIndex,
    ref,
    refs,
    replyTo: null,
    forwarded: true,
    expiresAt: ttl ? Date.now() + ttl : null,
    localId: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  });
  persist.messages();
  views.renderChatList();

  if (State.activeContactId === targetId) views.renderChatArea();
  toast(`Forwarded to ${views.displayNameFor(targetId)}`, {
    type: 'ok',
    action: { label: 'Open', onClick: () => selectConversation(targetId) }
  });
}

/* ============================================================== TRANSPORT */

function connectWebSocket() {
  if (!State.currentUser) return;
  if (State.socket) { try { State.socket.close(); } catch {} }

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${proto}//${location.host}/ws`);
  State.socket = ws;

  ws.onopen = () => {
    State.socketConnected = true;
    State.reconnectAttempts = 0;
    updateConnectionUI();
    // The relay authenticates this frame before it will route to us or hand
    // over the offline queue. Same credential the REST routes take.
    ws.send(JSON.stringify({
      type: 'register',
      clientId: State.currentUser.idPub,
      username: State.currentUser.username,
      authHash: State.currentUser.authHash,
      // Which device this socket is. The relay keeps one socket per device
      // rather than per account, so without this a second device would
      // silently displace the first from the routing table.
      deviceId: State.currentUser.deviceId || undefined
    }));
    broadcastPresence('online');
    startPresenceHeartbeat();
    // Anything stranded by the outage goes out now rather than waiting for its
    // backoff to elapse. Coming back online is the event we were waiting for.
    flushOutbox();

    if (State.reconnectInterval) { clearInterval(State.reconnectInterval); State.reconnectInterval = null; }
    if (State.pingInterval) clearInterval(State.pingInterval);
    State.pingInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'ping' }));
    }, 30000);
  };

  ws.onmessage = (event) => {
    let data;
    try { data = JSON.parse(event.data); } catch { return; }

    switch (data.type) {
      case 'message': {
        // The sender lives inside the sealed envelope, not in the frame. Fall
        // back to the frame's own claim only for an un-upgraded peer.
        const opened = openSealed(data.payload);
        const from = opened ? opened.senderId : data.senderId;
        const inner = opened ? opened.payload : data.payload;
        if (!from) break;
        // Which of the sender's devices wrote this, from inside the seal. It
        // selects the ratchet, so two devices of one peer do not share one.
        const decoded = processIncomingMessage(from, inner, opened ? opened.senderDev : null);
        if (decoded) handleIncoming(from, decoded);
        else noteUndecryptable(from);
        break;
      }

      case 'offline-messages': {
        data.messages.forEach((m) => {
          const opened = openSealed(m.payload);
          const from = opened ? opened.senderId : m.senderId;
          const inner = opened ? opened.payload : m.payload;
          if (from) {
            handleIncoming(from, processIncomingMessage(from, inner, opened ? opened.senderDev : null), true);
          }
        });
        persist.messages();
        views.renderChatList();
        if (State.activeContactId) views.renderChatArea();
        updateUnreadBadges();
        if (data.messages.length) {
          toast(`${data.messages.length} message${data.messages.length === 1 ? '' : 's'} delivered while you were away`);
        }
        break;
      }

      case 'registered': {
        // A rejection here is not transient, so stop the 5s reconnect loop
        // rather than hammering the relay with a credential it has already
        // refused. In practice this means the stored session no longer
        // matches the account on the server.
        if (data.success === false) {
          State.registrationRejected = true;
          if (State.reconnectInterval) {
            clearInterval(State.reconnectInterval);
            State.reconnectInterval = null;
          }
          toast('The relay rejected this session. Sign in again.', { type: 'error', duration: 15000 });
        }
        break;
      }

      case 'ack': {
        // Match on the frame's own correlation token. The index is only a
        // fallback for v1 envelopes, where it is the sole thing the relay can
        // see; under v2 it lives inside the ciphertext and arrives undefined,
        // which used to mean no outbound message ever left "sending".
        const msg = data.ref
          ? State.messages.findLast(
              (m) => m.ref === data.ref || (m.refs && m.refs.includes(data.ref))
            )
          : State.messages.findLast(
              (m) => m.contactId === data.recipientId && m.sender === 'me'
                && m.messageIndex === data.messageIndex
            );
        if (!msg) break;

        // A group send produces one ack per member, and they can disagree:
        // one recipient online, another queued. Never let a later ack walk
        // the bubble backwards, or a single offline member would make a
        // delivered message look undelivered.
        // The relay has it, so the watchdog and the retry both stand down.
        settleDelivery(msg.localId);

        const RANK = { sending: 0, offline: 0, failed: 0, queued: 1, delivered: 2, read: 3 };
        if ((RANK[data.status] ?? 0) > (RANK[msg.status] ?? 0)) {
          msg.status = data.status;
          persist.messages();
          // Group acks name the individual member as `recipientId`, not the
          // group, so refresh against the bubble's own conversation.
          if (State.activeContactId === msg.contactId) views.refreshMessage(msg);
        }
        break;
      }
    }
  };

  ws.onclose = () => {
    State.socketConnected = false;
    updateConnectionUI();
    if (State.pingInterval) { clearInterval(State.pingInterval); State.pingInterval = null; }
    if (!State.reconnectInterval && State.currentUser && !State.registrationRejected) {
      State.reconnectInterval = setInterval(connectWebSocket, 5000);
    }
  };
}

function updateConnectionUI() {
  if (State.socketConnected) {
    if (State.reconnectAttempts > 0) showNetBanner('Back online', 'online', 2200);
    else hideNetBanner();
  } else {
    State.reconnectAttempts++;
    showNetBanner('Reconnecting…', 'offline');
  }
}

// sendPresence() is gone. It told the relay which conversation was open and
// whether the window was focused, purely so the relay could skip a redundant
// push. That is a running record of what someone is reading, kept for an
// optimisation the service worker was already performing on its own. See the
// push decision in server.js.

/* ------------------------------------------------------- contact presence */

// Refreshed while the window is up, so a contact who crashes or loses power
// eventually stops looking online instead of looking online forever.
const PRESENCE_HEARTBEAT_MS = 4 * 60 * 1000;

// Must match views.js. Both sides need it: views decides whether to draw the
// banner, app decides when to trigger the render that draws it.
const UNDECRYPTABLE_WARN_AT = 3;

/**
 * Tells contacts directly whether we are here.
 *
 * Only ever sent to peers there is already a session with. Presence must not
 * be the thing that opens a session: that would burn a one-time prekey for
 * every contact on every boot, including people we have never actually
 * messaged.
 */
function broadcastPresence(state) {
  if (!State.currentUser) return;
  if (State.settings.sharePresence === false) return;

  State.contacts.forEach((c) => {
    if (c.blocked || c.pending) return;
    if (!State.sessions || !State.sessions[c.idPub]) return;
    sendE2EPayload(c.idPub, { type: 'control', action: 'presence', state }, undefined, false);
  });
}

function startPresenceHeartbeat() {
  if (State.presenceTimer) clearInterval(State.presenceTimer);
  State.presenceTimer = setInterval(() => {
    if (document.visibilityState === 'visible') broadcastPresence('online');
  }, PRESENCE_HEARTBEAT_MS);
}

/* ====================================================== INBOUND DISPATCH */

/**
 * An envelope arrived from a known peer and would not open.
 *
 * Worth surfacing rather than swallowing: a run of these means their end of
 * the ratchet has moved on, usually because they reinstalled, and nothing in
 * the app recovers from that on its own. Silence here is how a conversation
 * quietly stops working with no explanation.
 */
/**
 * Group membership and name changes announced by another member.
 *
 * Every branch checks who is allowed to have said it. The relay has no group
 * concept, so these arrive as ordinary encrypted messages from whoever felt
 * like sending one: without the check, any contact could rename a group or
 * rewrite its roster.
 */
function handleGroupAdmin(senderId, p) {
  const group = State.groups.find((g) => g.id === p.groupId);
  if (!group) return;

  const notify = (text) => {
    persist.groups();
    syncGroupsWithServer();
    views.renderChatList();
    if (State.activeContactId === group.id) views.renderChatArea();
    toast(text);
  };

  // Both `rename` and `roster` carry the full signed roster, so both are
  // checked the same way: the owner's signature must cover exactly the state
  // being announced. `acceptsAdminFrom` alone was not enough, because it only
  // asks who *sent* the envelope, and a member forwarding a roster is a normal
  // thing to do. The signature is what says who *authored* it.
  const signedRoster = (p.action === 'rename' || p.action === 'roster');
  if (signedRoster) {
    const verdict = rosterAcceptable(group, p);
    if (!verdict.ok) {
      console.warn(`[Group] Refused ${p.action} for ${group.id.substring(0, 8)}: ${verdict.reason}`);
      return;
    }
    // rosterAcceptable has already checked the revision moves forward; this
    // records it and keeps `group.rev` the single source of truth.
    acceptGroupRev(group, p.rev);
    if (!group.owner) group.owner = p.owner;
    if (!group.ownerSignPub) group.ownerSignPub = p.ownerSignPub;
  }

  switch (p.action) {
    case 'rename': {
      if (typeof p.name !== 'string' || !p.name.trim()) return;
      const was = group.name;
      group.name = p.name.trim().slice(0, 40);
      notify(`"${was}" is now "${group.name}"`);
      break;
    }

    case 'roster': {
      if (!Array.isArray(p.members) || !p.members.length) return;
      const before = group.members.length;
      group.members = p.members;
      if (typeof p.name === 'string' && p.name.trim()) group.name = p.name.trim().slice(0, 40);

      // We are no longer on the roster we were just handed. Same outcome as
      // an explicit removal, and worth handling because the `removed` frame
      // can be lost while this one arrives.
      if (!group.members.includes(State.currentUser.idPub)) {
        group.removed = true;
        notify(`You are no longer in "${group.name}"`);
        return;
      }
      const delta = group.members.length - before;
      notify(delta === 0
        ? `"${group.name}" membership updated`
        : `"${group.name}" now has ${group.members.length} members`);
      break;
    }

    case 'leave': {
      // Anyone may remove themselves, and only themselves.
      if (!group.members.includes(senderId)) return;
      group.members = group.members.filter((id) => id !== senderId);
      notify(`${views.displayNameFor(senderId)} left "${group.name}"`);
      break;
    }

    case 'removed': {
      if (!acceptsAdminFrom(group, senderId)) return;
      group.removed = true;
      group.members = group.members.filter((id) => id !== State.currentUser.idPub);
      notify(`You were removed from "${group.name}"`);
      break;
    }
  }
}

function noteUndecryptable(senderId) {
  if (isGroupId(senderId)) return;
  if (decryptFailureCount(senderId) !== UNDECRYPTABLE_WARN_AT) return;
  // Render the banner exactly once, on the crossing, not on every failure.
  if (State.activeContactId === senderId) views.renderChatArea();
  else toast(`Cannot read new messages from ${views.displayNameFor(senderId)}`, { type: 'warn' });
}

/* ------------------------------------------------------------------------ */

/* ============================================================== THE OUTBOX */
/*
 * Nothing outbound is allowed to disappear quietly. A message ends in exactly
 * one of three states: acknowledged, waiting in the outbox for another go, or
 * given up on and shown as failed with a retry.
 *
 * Two failures used to be silent. A send with the socket down went red and
 * stayed red, recoverable only by retyping it. And a frame that left the
 * device but drew no ack sat on "sending" forever, which reads as success.
 * The watchdog below is what closes the second one.
 *
 * outbox.js owns the scheduling and is pure; this owns the timers, the socket
 * and the persistence.
 */

// localId -> timeout handle. In memory only: a reload legitimately forgets
// that we were waiting, and the entry is already persisted in the outbox.
const ackWatch = new Map();

function clearAckWatch(localId) {
  const t = ackWatch.get(localId);
  if (t) { clearTimeout(t); ackWatch.delete(localId); }
}

/** Treats a frame with no ack inside the window as lost, and retries it. */
function watchForAck(localId, convId, payload) {
  clearAckWatch(localId);
  ackWatch.set(localId, setTimeout(() => {
    ackWatch.delete(localId);
    const msg = State.messages.find((m) => m.localId === localId);
    // Anything past 'sending' was acknowledged while we were waiting.
    if (!msg || msg.status !== 'sending') return;
    queueForRetry(localId, convId, payload, msg);
  }, ACK_TIMEOUT_MS));
}

function queueForRetry(localId, convId, payload, msg) {
  if (!findEntry(State.outbox, localId)) {
    State.outbox = addEntry(State.outbox, makeEntry({ localId, convId, payload }));
    persist.outbox();
  }
  const row = msg || State.messages.find((m) => m.localId === localId);
  if (row && row.status !== 'offline') {
    row.status = 'offline';
    persist.messages();
    views.refreshMessage(row);
  }
  scheduleOutbox();
}

/** Called by views.js with the outcome of every content send. */
function onSendResult(localId, convId, payload, success) {
  if (success) watchForAck(localId, convId, payload);
  else queueForRetry(localId, convId, payload);
}

/** An ack arrived: stop watching and stop retrying. */
function settleDelivery(localId) {
  if (!localId) return;
  clearAckWatch(localId);
  if (findEntry(State.outbox, localId)) {
    State.outbox = removeEntry(State.outbox, localId);
    persist.outbox();
    scheduleOutbox();
  }
}

/** Adds the correlation tokens from a retry to the bubble that produced it. */
function rememberRefs(localId, refs) {
  if (!refs || !refs.length) return;
  const msg = State.messages.find((m) => m.localId === localId);
  if (!msg) return;
  const all = new Set(msg.refs || []);
  if (msg.ref) all.add(msg.ref);
  refs.forEach((r) => all.add(r));
  msg.refs = Array.from(all);
  persist.messages();
}

function scheduleOutbox() {
  if (State.outboxTimer) { clearTimeout(State.outboxTimer); State.outboxTimer = null; }
  const wait = nextWakeup(State.outbox);
  if (wait === null) return;
  State.outboxTimer = setTimeout(flushOutbox, wait);
}

function markFailed(localId) {
  const msg = State.messages.find((m) => m.localId === localId);
  if (!msg || msg.status === 'failed') return;
  msg.status = 'failed';
  persist.messages();
  views.refreshMessage(msg);
}

async function flushOutbox() {
  State.outboxTimer = null;
  if (!State.currentUser) return;
  // Offline is not a failure worth spending an attempt on, so nothing is
  // counted until there is actually a socket to send down.
  if (!State.socketConnected) { scheduleOutbox(); return; }

  for (const entry of dueEntries(State.outbox)) {
    // The attempt is recorded BEFORE it is made. If the send throws, or the
    // tab closes mid-flight, the count still moved and the message cannot
    // retry forever.
    const attempted = afterAttempt(entry);
    State.outbox = addEntry(State.outbox, attempted);
    persist.outbox();

    let success = false;
    let freshRefs = [];
    try {
      if (isGroupId(entry.convId)) {
        freshRefs = await sendGroupMessage(entry.convId, entry.payload);
        success = freshRefs.length > 0;
      } else {
        const result = await sendE2EPayload(entry.convId, entry.payload, undefined, true);
        success = !!result.success;
        if (result.ref) freshRefs = [result.ref];
      }
    } catch (err) {
      console.error('[Outbox] retry failed', err);
    }

    if (success) {
      // A retry is a new frame and carries a new correlation token. The bubble
      // still holds the token from the first attempt, so without collecting
      // the new one the ack matches no message and the bubble sits on "not
      // sent" forever while the relay actually has it. Every token is kept,
      // because an ack for any attempt settles the same message.
      rememberRefs(entry.localId, freshRefs);
      watchForAck(entry.localId, entry.convId, entry.payload);
    }
    if (isExhausted(attempted)) markFailed(entry.localId);
  }
  scheduleOutbox();
}

/** Manual retry from a failed bubble. Clears the backoff and goes now. */
export function retryMessage(localId) {
  const entry = findEntry(State.outbox, localId);
  if (!entry) return;
  State.outbox = addEntry(State.outbox, forceDue(entry));
  persist.outbox();
  const msg = State.messages.find((m) => m.localId === localId);
  if (msg) { msg.status = 'offline'; persist.messages(); views.refreshMessage(msg); }
  flushOutbox();
}

/**
 * A message one of our other devices sent, mirrored to this one.
 *
 * Stored as an ordinary outgoing message so the history matches what the
 * sending device shows. Without it a second device is receive-only in
 * practice: it collects what people say to you and knows nothing of your own
 * side of the conversation.
 *
 * Deliberately conservative about what it accepts. This envelope is
 * authenticated as coming from our own identity key, but that key is on every
 * device of the account, so a compromised one of ours could send anything
 * here. It may only add a message; it cannot delete, edit or change settings.
 */
function handleSelfSync(payloadObj, batched = false) {
  if (!payloadObj || payloadObj.action !== 'sync-sent') return;

  const convId = typeof payloadObj.convId === 'string' ? payloadObj.convId : null;
  const inner = payloadObj.payload;
  if (!convId || !inner || typeof inner !== 'object') return;

  // The same duplicate check the normal receive path uses. A retry from the
  // other device, or a message we already synced, must not double up.
  const lid = typeof payloadObj.lid === 'string' ? payloadObj.lid : null;
  if (lid && State.messages.some((m) => m && m.sender === 'me' && m.localId === lid)) return;

  const msg = {
    contactId: convId,
    senderId: State.currentUser.idPub,
    sender: 'me',
    type: inner.type === 'text' ? 'text' : inner.type,
    text: typeof inner.text === 'string' ? inner.text : '',
    file: inner.file || null,
    timestamp: Date.now(),
    // It left another device and was acknowledged there. Showing it as
    // "sending" on this one would offer a retry for something already gone.
    status: 'sent',
    messageIndex: Date.now(),
    replyTo: inner.replyTo || null,
    localId: lid || `sync-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    syncedFromOtherDevice: true
  };

  State.messages.push(msg);
  if (!batched) {
    persist.messages();
    if (State.currentConv && State.currentConv.id === convId) views.appendMessage(msg);
    views.renderChatList();
  }
}

function handleIncoming(senderId, decResult, batched = false) {
  if (!decResult) return;
  const { payloadObj, envelopeIndex, remoteId } = decResult;

  // An envelope from our OWN identity key is another of our devices telling us
  // what it sent. It must be handled before anything below, because the
  // unknown-sender path would otherwise add us to our own contact list as a
  // pending stranger called "Peer-xxxxxx".
  if (State.currentUser && senderId === State.currentUser.idPub) {
    handleSelfSync(payloadObj, batched);
    return;
  }

  // A retry of a message we already have. The sender re-sends when it never
  // saw an ack, which happens whenever the ack was the thing that got lost, so
  // this is the normal case rather than an edge one. Dropped after the ratchet
  // has advanced, exactly like a blocked peer: the session must stay in step.
  if (alreadyReceived(State.messages, senderId, remoteId)) return;

  // Blocked peers are dropped before anything is stored or rendered. The
  // ratchet has already advanced by this point, which is intentional: the
  // session must stay in step in case they are later unblocked.
  if (isBlocked(senderId)) return;

  // An unknown sender becomes a *pending* contact, not a full one. Their
  // messages are quarantined behind an Accept/Block bar and they cannot add
  // us to groups until accepted.
  let contact = State.contacts.find((c) => c.idPub === senderId);
  if (!contact) {
    contact = {
      idPub: senderId,
      nickname: `Peer-${senderId.substring(0, 6)}`,
      pending: true
    };
    State.contacts.push(contact);
    persist.contacts();
    syncContactsWithServer();
  }

  switch (payloadObj.type) {
    case 'control':
      handleControl(senderId, senderId, payloadObj);
      return;

    case 'call-signal':
      handleCallSignal(senderId, payloadObj);
      return;

    case 'group-control':
      if (payloadObj.action === 'create') {
        const { groupId, name, members } = payloadObj;

        // Only an accepted contact may pull us into a group. Otherwise a
        // stranger could inject a group with arbitrary claimed membership,
        // which then appears in our list as though it were real.
        if (!isTrusted(senderId)) {
          console.warn('[Group] Ignored invite from an unaccepted contact:', senderId.substring(0, 12));
          return;
        }
        if (!Array.isArray(members) || typeof name !== 'string' || typeof groupId !== 'string') return;
        // The inviter must actually be in the group they are inviting us to,
        // and so must we.
        if (!members.includes(senderId) || !members.includes(State.currentUser.idPub)) {
          console.warn('[Group] Ignored invite with inconsistent membership');
          return;
        }

        const existing = State.groups.find((g) => g.id === groupId);

        // The membership must be signed by the group's owner. Without this the
        // list is only an assertion by whoever sent it, and any member could
        // invent a roster naming people who were never in the group. The
        // signature does not make a first invitation trustworthy on its own,
        // that is still trust on first use, but it does stop a member forging
        // one and stops anything being edited in flight.
        const verdict = rosterAcceptable(existing, payloadObj);
        if (!verdict.ok) {
          console.warn(`[Group] Refused invite for ${groupId.substring(0, 8)}: ${verdict.reason}`);
          return;
        }

        if (!existing) {
          State.groups.push({
            id: groupId, name, members,
            owner: payloadObj.owner,
            // Pinned on first accept. A later roster signed by a different key
            // is a substituted signing key, not a legitimate change.
            ownerSignPub: payloadObj.ownerSignPub,
            rev: payloadObj.rev
          });
          persist.groups();
          syncGroupsWithServer();
          views.renderChatList();
          toast(`${contact.nickname} added you to "${name}"`, {
            action: { label: 'Open', onClick: () => selectConversation(groupId) }
          });
        } else if (existing.removed) {
          // Re-invited after having been removed: clear the tombstone rather
          // than ignoring it as a duplicate invite.
          delete existing.removed;
          existing.members = members;
          existing.name = name;
          persist.groups();
          syncGroupsWithServer();
          views.renderChatList();
          if (State.activeContactId === groupId) views.renderChatArea();
          toast(`${contact.nickname} added you back to "${name}"`);
        }
      } else if (payloadObj.action === 'typing') {
        views.showTyping(payloadObj.groupId, senderId);
      } else if (['rename', 'roster', 'leave', 'removed'].includes(payloadObj.action)) {
        handleGroupAdmin(senderId, payloadObj);
      } else {
        // Group control actions ride inside the group envelope too.
        handleControl(payloadObj.groupId, senderId, payloadObj);
      }
      return;

    case 'group-message': {
      const { groupId, senderId: from, message } = payloadObj;
      let group = State.groups.find((g) => g.id === groupId);
      if (!group) {
        group = { id: groupId, name: `Group-${groupId.substring(0, 6)}`, members: [State.currentUser.idPub, senderId] };
        State.groups.push(group);
        persist.groups();
        syncGroupsWithServer();
      }
      storeInbound(groupId, from, message, envelopeIndex, batched, remoteId);
      return;
    }

    case 'text':
    case 'file':
    case 'voice-memo':
    case 'sticker':
      storeInbound(senderId, senderId, payloadObj, envelopeIndex, batched, remoteId);
      return;
  }
}

/**
 * Control payloads carry no content worth notifying about. `convId` is the
 * conversation the action targets (the group for group control, the peer for
 * a DM); `from` is who sent it.
 */
function handleControl(convId, from, p) {
  switch (p.action) {
    case 'typing':
      views.showTyping(convId, isGroupId(convId) ? from : null);
      break;

    case 'read': {
      const msg = findMsg(convId, p.targetIndex, 'me');
      if (msg && msg.status !== 'read') {
        msg.status = 'read';
        persist.messages();
        playCue('seen');
        if (State.activeContactId === convId) views.refreshMessage(msg);
      }
      break;
    }

    case 'reaction': {
      // The sender describes the target from their perspective, so flip it.
      const mine = p.targetSender === 'me' ? 'them' : 'me';
      const msg = findMsg(convId, p.targetIndex, mine);
      if (msg) {
        toggleReactionLocal(msg, p.emoji, from);
        persist.messages();
        if (State.activeContactId === convId) views.refreshMessage(msg);
      }
      break;
    }

    case 'edit': {
      const mine = p.targetSender === 'me' ? 'them' : 'me';
      const msg = findMsg(convId, p.targetIndex, mine);
      if (msg && typeof p.text === 'string') {
        msg.text = p.text;
        msg.edited = Date.now();
        persist.messages();
        if (State.activeContactId === convId) views.refreshMessage(msg);
        views.renderChatList();
      }
      break;
    }

    case 'delete': {
      const mine = p.targetSender === 'me' ? 'them' : 'me';
      const msg = findMsg(convId, p.targetIndex, mine);
      if (msg) {
        msg.deleted = true;
        msg.text = '';
        msg.file = null;
        delete msg.reactions;
        persist.messages();
        if (State.activeContactId === convId) views.refreshMessage(msg);
        views.renderChatList();
      }
      break;
    }

    case 'presence': {
      // Peer-to-peer, not relay-reported. The relay does know who is
      // connected, but it has never known who your contacts are, and asking
      // it to broadcast "X is online" to the right people would mean handing
      // it your contact graph in clear. So presence rides the same encrypted
      // channel as everything else: contacts tell each other directly.
      const c = State.contacts.find((x) => x.idPub === from);
      if (!c) break;
      c.lastSeen = Date.now();
      c.online = p.state === 'online';
      persist.contacts();
      views.renderChatList();
      if (State.activeContactId === from) views.renderChatArea();
      break;
    }

    case 'profile-sync': {
      const c = State.contacts.find((x) => x.idPub === from);
      if (!c || !p.profile) break;

      // A peer may not overwrite a name the local user chose. Without this,
      // any contact can silently rename themselves to another contact's exact
      // display name, and in a group chat the author label is the only thing
      // distinguishing speakers, so that is a working impersonation.
      if (p.profile.nickname && !c.nameLocked) {
        const proposed = String(p.profile.nickname).slice(0, 40);
        const clashes = State.contacts.some(
          (x) => x.idPub !== from && !x.blocked && x.nickname === proposed
        );
        if (clashes) {
          // Keep them distinguishable rather than silently allowing the clash.
          c.nickname = `${proposed} (${from.substring(0, 6)})`;
          toast(`${proposed} is a name you already use for someone else`, { type: 'warn' });
        } else {
          c.nickname = proposed;
        }
      }

      c.bio = typeof p.profile.bio === 'string' ? p.profile.bio.slice(0, 300) : '';
      c.avatar = p.profile.avatar || null;
      persist.contacts();
      views.renderChatList();
      if (State.activeContactId === from) views.renderChatArea();
      break;
    }
  }
}

function storeInbound(convId, fromId, payload, envelopeIndex, batched, remoteId) {
  const isVoice = payload.type === 'voice-memo';
  const isFile = payload.type === 'file';
  const isSticker = payload.type === 'sticker';

  const msg = {
    contactId: convId,
    senderId: fromId,
    sender: fromId === State.currentUser.idPub ? 'me' : 'them',
    type: payload.type,
    text: payload.text || (isSticker ? payload.emoji : ''),
    file: (isFile || isVoice) ? payload : null,
    timestamp: Date.now(),
    status: 'received',
    messageIndex: envelopeIndex,
    replyTo: payload.replyTo || null,
    forwarded: !!payload.forwarded,
    expiresAt: payload.ttl ? Date.now() + payload.ttl : null,
    // The sender's own id for this message. Recorded so a retry of it is
    // recognised as a duplicate rather than stored a second time.
    remoteId: remoteId || null
  };

  State.messages.push(msg);
  if (!batched) persist.messages();

  if (!batched) playCue('receive');

  const open = State.activeContactId === convId;
  if (open && !batched) {
    views.appendMessage(msg);
    if (!isGroupId(convId) && !isVoice && State.settings.sendReadReceipts) {
      msg.status = 'read';
      sendE2EPayload(convId, { type: 'control', action: 'read', targetIndex: envelopeIndex });
      persist.messages();
    }
  }

  if (!batched) {
    views.renderChatList();
    updateUnreadBadges();
  }
}

/* ============================================================ PUSH / SW */

function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

async function sendSubscriptionToServer(subscription) {
  if (!State.currentUser) return;
  try {
    await fetch('/api/push-subscribe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: State.currentUser.username,
        authHash: State.currentUser.authHash,
        subscription: subscription.toJSON ? subscription.toJSON() : subscription
      })
    });
  } catch (err) {
    console.error('[Push] Could not register subscription:', err);
  }
}

/** Must be called from a user gesture. Browsers require one for permission. */
async function subscribeToPush() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    toast('Push notifications are not supported in this browser', { type: 'error' });
    return false;
  }

  const permission = await Notification.requestPermission();
  if (permission !== 'granted') {
    toast('Notification permission was not granted', { type: 'warn' });
    return false;
  }

  try {
    const reg = await navigator.serviceWorker.ready;
    const { publicKey } = await (await fetch('/api/vapid-public-key')).json();

    let sub = await reg.pushManager.getSubscription();
    if (!sub) {
      sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(publicKey)
      });
    }
    await sendSubscriptionToServer(sub);
    toast('Notifications enabled', { type: 'ok' });
    return true;
  } catch (err) {
    console.error('[Push] Subscription failed:', err);
    toast('Could not enable notifications', { type: 'error' });
    return false;
  }
}

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.addEventListener('message', (event) => {
    const msg = event.data || {};
    if (msg.type === 'query-active-conversation') {
      // The worker asks in tags, not conversation ids, because a tag is all
      // the push payload carries now. Only this page can map one back.
      const active = (document.hasFocus() && document.visibilityState === 'visible' && !State.locked)
        ? State.activeContactId : null;
      const activeTag = (active && State.currentUser)
        ? pushTagFor(active, State.currentUser.idPub) : null;
      if (event.ports && event.ports[0]) event.ports[0].postMessage({ activeTag });
    } else if (msg.type === 'open-conversation') {
      const convId = msg.conversationId || conversationForPushTag(msg.tag);
      if (convId && State.currentUser) selectConversation(convId);
    } else if (msg.type === 'push-subscription-renewed' && msg.subscription) {
      sendSubscriptionToServer(msg.subscription);
    }
  });
}

/* ========================================================== VOICE MEMOS */

async function toggleVoiceRecording() {
  if (State.activeVoiceRecorder) { State.activeVoiceRecorder.stop(); return; }

  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    toast('Voice recording needs HTTPS', { type: 'error' });
    return;
  }

  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  } catch {
    toast('Could not access the microphone', { type: 'error' });
    return;
  }

  const recorder = new MediaRecorder(stream);
  State.activeVoiceRecorder = recorder;
  State.voiceRecordingChunks = [];
  State.voiceRecordingTime = 0;

  const composer = document.getElementById('composer');
  const input = document.getElementById('composer-input');
  const micBtn = document.getElementById('btn-mic');

  // Swap the composer for a live recording pill.
  const pill = document.createElement('div');
  pill.className = 'rec-pill';
  pill.innerHTML = `<span class="rec-dot"></span><span id="rec-time">0:00</span>
    <span class="rec-wave" id="rec-wave">${Array.from({ length: 22 }, () => '<i></i>').join('')}</span>
    <button type="button" class="btn btn-sm" id="rec-cancel">Cancel</button>`;
  if (input) input.style.display = 'none';
  if (composer) composer.insertBefore(pill, micBtn);
  if (micBtn) micBtn.classList.add('recording');

  let cancelled = false;
  pill.querySelector('#rec-cancel').onclick = () => { cancelled = true; recorder.stop(); };

  // Drive the bars from the real mic level rather than a canned loop.
  let cleanupWave = () => {};
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const analyser = ctx.createAnalyser();
    analyser.fftSize = 64;
    ctx.createMediaStreamSource(stream).connect(analyser);
    const bins = new Uint8Array(analyser.frequencyBinCount);
    const bars = Array.from(pill.querySelectorAll('#rec-wave i'));
    let raf = null;
    const tick = () => {
      analyser.getByteFrequencyData(bins);
      bars.forEach((bar, i) => {
        const v = bins[Math.floor((i / bars.length) * bins.length)] || 0;
        bar.style.height = `${15 + (v / 255) * 85}%`;
      });
      raf = requestAnimationFrame(tick);
    };
    tick();
    cleanupWave = () => { if (raf) cancelAnimationFrame(raf); ctx.close().catch(() => {}); };
  } catch { /* visualiser is optional */ }

  State.voiceRecordingInterval = setInterval(() => {
    State.voiceRecordingTime++;
    const t = pill.querySelector('#rec-time');
    const m = Math.floor(State.voiceRecordingTime / 60);
    const s = State.voiceRecordingTime % 60;
    if (t) t.textContent = `${m}:${String(s).padStart(2, '0')}`;
  }, 1000);

  recorder.ondataavailable = (e) => { if (e.data.size > 0) State.voiceRecordingChunks.push(e.data); };

  recorder.onstop = async () => {
    clearInterval(State.voiceRecordingInterval);
    stream.getTracks().forEach((t) => t.stop());
    cleanupWave();

    const seconds = State.voiceRecordingTime;
    const blob = new Blob(State.voiceRecordingChunks, { type: 'audio/webm' });

    pill.remove();
    if (input) input.style.display = '';
    if (micBtn) micBtn.classList.remove('recording');
    State.activeVoiceRecorder = null;
    State.voiceRecordingTime = 0;

    if (cancelled || seconds < 1) {
      if (cancelled) toast('Recording discarded');
      return;
    }

    try {
      const { url, key, iv } = await encryptAndUpload(blob);
      views.sendVoiceMemo({
        type: 'voice-memo', mime: 'audio/webm', url, key, iv,
        duration: `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`
      });
    } catch {
      toast('Could not send that voice message', { type: 'error' });
    }
  };

  recorder.start();
}

/* ============================================================== APP LOCK */

function armAppLock() {
  if (!State.settings.appLockEnabled) return;
  clearTimeout(State.lockTimer);
  State.lockTimer = setTimeout(() => showLockScreen(), State.settings.appLockDelayMs || 0);
}

function disarmAppLock() {
  clearTimeout(State.lockTimer);
}

document.addEventListener('visibilitychange', () => {
  broadcastPresence(document.visibilityState === 'hidden' ? 'offline' : 'online');
  const app = document.getElementById('app');
  if (document.visibilityState === 'hidden') {
    armAppLock();
    if (State.settings.privacyBlur && app) app.classList.add('privacy-blur');
  } else {
    disarmAppLock();
    if (app) app.classList.remove('privacy-blur');
  }
});

window.addEventListener('blur', () => {
  const app = document.getElementById('app');
  if (State.settings.privacyBlur && app) app.classList.add('privacy-blur');
});

window.addEventListener('focus', () => {
  const app = document.getElementById('app');
  if (app) app.classList.remove('privacy-blur');
});

/* =========================================================== PANIC WIPE */

function panicWipe() {
  const username = State.currentUser ? State.currentUser.username : null;

  // Best effort, fire and forget. Never block the wipe on the network.
  if (State.currentUser && 'serviceWorker' in navigator) {
    navigator.serviceWorker.getRegistration()
      .then((reg) => (reg ? reg.pushManager.getSubscription() : null))
      .then((sub) => {
        if (!sub) return;
        fetch('/api/push-unsubscribe', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: State.currentUser.username,
            authHash: State.currentUser.authHash,
            endpoint: sub.endpoint
          })
        }).catch(() => {});
        sub.unsubscribe().catch(() => {});
      }).catch(() => {});
  }

  try { if (State.socket) State.socket.close(); } catch {}

  if (username) {
    WIPE_PREFIXES.forEach((p) => localStorage.removeItem(`${p}${username.toLowerCase()}`));
  } else {
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const k = localStorage.key(i);
      if (k && k.startsWith('e2e_')) localStorage.removeItem(k);
    }
  }
  sessionStorage.removeItem('talon_session');
  localStorage.removeItem('talon_session_persistent');

  // The muted tags live in IndexedDB, outside the localStorage sweep above,
  // because the service worker has to be able to read them. Same rule as
  // WIPE_PREFIXES: anything persisted has to be wiped here or Panic Wipe
  // quietly leaves it on the device.
  clearMutedTags();

  if ('caches' in window) {
    caches.keys().then((names) => names.forEach((n) => caches.delete(n))).catch(() => {});
  }

  location.href = location.pathname;
}

async function confirmPanicWipe() {
  const ok = await confirmDialog({
    title: 'Erase everything on this device?',
    message: 'All messages, contacts, groups, keys and settings cached in this browser are deleted immediately. Your encrypted backups on the server and your other devices are untouched, so you can sign in again elsewhere.',
    confirmLabel: 'Erase now',
    danger: true
  });
  if (ok) panicWipe();
}

// Triple-Escape within 1.2s is a deliberate emergency gesture. Modal and
// popover Escape handlers stopPropagation, so this only counts "free" presses.
let panicTimestamps = [];
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  const now = Date.now();
  panicTimestamps.push(now);
  panicTimestamps = panicTimestamps.filter((t) => now - t < 1200);
  if (panicTimestamps.length >= 3) {
    panicTimestamps = [];
    panicWipe();
  }
});

/* ========================================================== SHORTCUTS */

function bindShortcuts() {
  document.addEventListener('keydown', (e) => {
    if (State.locked) return;

    const typing = /^(INPUT|TEXTAREA)$/.test(e.target.tagName) || e.target.isContentEditable;
    const mod = e.ctrlKey || e.metaKey;

    if (mod && e.key.toLowerCase() === 'k') { e.preventDefault(); openSearchModal(); return; }
    if (mod && e.key.toLowerCase() === 'n') { e.preventDefault(); addContactFlow(); return; }
    if (mod && e.key === ',') { e.preventDefault(); setTab('settings'); return; }
    if (mod && e.key.toLowerCase() === 'f') {
      e.preventDefault();
      setTab('chats');
      document.getElementById('filter-input')?.focus();
      return;
    }

    if (typing || isModalOpen()) return;

    if (e.key === '?') { e.preventDefault(); openShortcutsModal(); return; }
    if (e.key === 'Escape' && State.activeContactId) { backToList(); return; }
  });
}

/* =============================================================== AUTH */

function showAuthError(message) {
  const box = document.getElementById('auth-error');
  const text = document.getElementById('auth-error-text');
  if (!box || !text) return;
  text.textContent = message;
  box.classList.remove('hidden');
  // Re-trigger the shake animation on repeated failures.
  box.style.animation = 'none';
  void box.offsetWidth;
  box.style.animation = '';
}

function hideAuthError() {
  document.getElementById('auth-error')?.classList.add('hidden');
}

function setAuthBusy(btn, busy, label) {
  if (!btn) return;
  btn.disabled = busy;
  btn.innerHTML = busy ? '<span class="spinner"></span>' : label;
}

/* ------------------------------------------------------- KDF negotiation */

async function fetchKdfParams(username) {
  try {
    const res = await fetch('/api/kdf-params', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    const json = await res.json();
    return json.params || { v: 1 };
  } catch {
    return { v: 1 };
  }
}

function randomSaltHex() {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
}

/**
 * Re-derives the master key under KDF v2 and re-encrypts everything the server
 * holds under the new encryption key, then swaps it all atomically.
 *
 * Runs silently inside login. Failure is non-fatal: the account keeps working
 * on v1 and the upgrade is retried on the next sign-in, so a flaky network can
 * never lock anyone out.
 */
async function upgradeKdf(username, password, oldAuthHash, session) {
  try {
    const salt = randomSaltHex();
    const masterKey = await deriveMasterKeyV2(password, salt);
    const newAuthKey = masterKey.slice(0, 32);
    const newEncKey = masterKey.slice(32, 64);
    const newAuthHash = bytesToHex(sha256Hash(newAuthKey));

    // Re-encrypt everything the server stores under the new encryption key.
    const idPriv = encryptWithKey(newEncKey, hexToBytes(session.idPriv));
    const contacts = encryptWithKey(newEncKey, utf8Encode(JSON.stringify(State.contacts)));
    const groups = encryptWithKey(newEncKey, utf8Encode(JSON.stringify(State.groups)));

    const res = await fetch('/api/upgrade-kdf', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        authHash: oldAuthHash,
        newAuthHash,
        kdfVersion: 2,
        kdfSalt: salt,
        kdfIterations: KDF_V2.iterations,
        encryptedIdPriv: idPriv.ciphertext,
        encryptedIdPrivNonce: idPriv.nonce,
        encryptedContacts: contacts.ciphertext,
        encryptedContactsNonce: contacts.nonce,
        encryptedGroups: groups.ciphertext,
        encryptedGroupsNonce: groups.nonce
      })
    });
    const json = await res.json();
    if (!json.success) throw new Error(json.error || 'rejected');

    // Only now is the in-memory session switched to the new credential.
    session.authHash = newAuthHash;
    session.encryptionKeyHex = bytesToHex(newEncKey);
    console.info('[Auth] Password key derivation upgraded to v2 (PBKDF2-600k).');
    return true;
  } catch (err) {
    console.warn('[Auth] KDF upgrade deferred to next sign-in:', err.message);
    return false;
  }
}

function bindAuth() {
  const loginForm = document.getElementById('login-form');
  const registerForm = document.getElementById('register-form');

  document.getElementById('go-register').onclick = () => {
    hideAuthError();
    loginForm.classList.add('hidden');
    registerForm.classList.remove('hidden');
    document.getElementById('auth-tagline').textContent =
      'Your password derives your keys. Choose something strong.';
    document.getElementById('register-username').focus();
  };

  document.getElementById('go-login').onclick = () => {
    hideAuthError();
    registerForm.classList.add('hidden');
    loginForm.classList.remove('hidden');
    document.getElementById('auth-tagline').textContent =
      'Private messaging. Nothing leaves your devices readable.';
    document.getElementById('login-username').focus();
  };

  const pw = document.getElementById('register-password');
  const meter = document.getElementById('pw-meter');
  pw.addEventListener('input', () => {
    meter.dataset.score = String(passwordScore(pw.value));
  });

  // Vault mode and "keep me signed in" cannot both be true: a persisted
  // session holds the vault key. Rather than accepting both and silently
  // dropping one, the checkbox that cannot apply is disabled so the reason is
  // visible before the account exists.
  const vaultBox = document.getElementById('register-vault');
  const rememberBox = document.getElementById('register-remember');
  if (vaultBox && rememberBox) {
    const syncRemember = () => {
      rememberBox.disabled = vaultBox.checked;
      if (vaultBox.checked) rememberBox.checked = false;
    };
    vaultBox.addEventListener('change', syncRemember);
    syncRemember();
  }

  loginForm.onsubmit = async (e) => {
    e.preventDefault();
    hideAuthError();
    const btn = document.getElementById('login-submit');
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;

    setAuthBusy(btn, true, 'Sign in');
    try {
      // Which KDF this account uses is decided by the server; unknown
      // usernames get decoy parameters so this reveals nothing.
      const kdfParams = await fetchKdfParams(username);
      const masterKey = await deriveMasterKey(password, username, kdfParams);
      const authKey = masterKey.slice(0, 32);
      const encryptionKey = masterKey.slice(32, 64);
      const authHash = bytesToHex(sha256Hash(authKey));

      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, authHash })
      });
      const result = await res.json();
      if (!result.success) {
        showAuthError(result.error || 'Incorrect username or password.');
        setAuthBusy(btn, false, 'Sign in');
        return;
      }

      const idPriv = decryptWithKey(encryptionKey, result.encryptedIdPriv, result.encryptedIdPrivNonce);
      const sessionData = {
        username: username.toLowerCase(),
        idPub: result.idPub,
        idPriv: bytesToHex(idPriv),
        authHash,
        encryptionKeyHex: bytesToHex(encryptionKey)
      };

      // The vault key has to be installed before ANY blob is written, not just
      // before one is read. The contacts and groups pulled from the server
      // below are written straight to disk, and with the vault still locked
      // they land in the clear and stay there until something happens to
      // rewrite them. initializeSession() unlocks too, but it runs after this.
      //
      // A device with no recorded preference is signing in here for the first
      // time and gets the vault, matching initializeSession. Reading the
      // merged defaults instead would leave the FIRST thing a new device
      // writes, its contact list, sitting in the clear.
      const priorSettings = Storage.getSettings(username);
      const wantVault = !Storage.hasSettings(username) || priorSettings.encryptAtRest;
      if (wantVault) unlockVault(bytesToHex(encryptionKey));

      if (result.encryptedContacts && result.encryptedContactsNonce) {
        try {
          const dec = decryptWithKey(encryptionKey, result.encryptedContacts, result.encryptedContactsNonce);
          Storage.saveContacts(username, JSON.parse(utf8Decode(dec)));
        } catch {}
      }
      if (result.encryptedGroups && result.encryptedGroupsNonce) {
        try {
          const dec = decryptWithKey(encryptionKey, result.encryptedGroups, result.encryptedGroupsNonce);
          const serverGroups = JSON.parse(utf8Decode(dec));
          // Merge so a group created locally before sync existed survives.
          const merged = new Map();
          Storage.getGroups(username).forEach((g) => merged.set(g.id, g));
          serverGroups.forEach((g) => merged.set(g.id, g));
          Storage.saveGroups(username, Array.from(merged.values()));
        } catch {}
      }

      // Load contacts/groups into State first, because upgradeKdf re-encrypts them.
      initializeSession(sessionData);

      if ((result.kdfVersion || 1) < 2) {
        await upgradeKdf(username, password, authHash, sessionData);
      }

      Storage.saveSession(
        sessionData,
        document.getElementById('login-remember').checked && !Storage.getSettings(username).encryptAtRest
      );
      State.currentUser = sessionData;
      syncGroupsWithServer();
      enterApp();
    } catch (err) {
      console.error('[Auth]', err);
      showAuthError('Could not sign in. Is the server reachable?');
      setAuthBusy(btn, false, 'Sign in');
    }
  };

  registerForm.onsubmit = async (e) => {
    e.preventDefault();
    hideAuthError();
    const btn = document.getElementById('register-submit');
    const username = document.getElementById('register-username').value.trim();
    const password = document.getElementById('register-password').value;
    const confirmPw = document.getElementById('register-password-confirm').value;

    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      showAuthError('Usernames must be 3–20 letters, numbers or underscores.');
      return;
    }
    if (password !== confirmPw) { showAuthError('The two passwords do not match.'); return; }
    if (password.length < 8) { showAuthError('Use a password of at least 8 characters.'); return; }

    setAuthBusy(btn, true, 'Create account');
    try {
      // New accounts are always KDF v2: PBKDF2-600k with a fresh random salt.
      const kdfSalt = randomSaltHex();
      const masterKey = await deriveMasterKeyV2(password, kdfSalt);
      const authKey = masterKey.slice(0, 32);
      const encryptionKey = masterKey.slice(32, 64);
      const authHash = bytesToHex(sha256Hash(authKey));

      const keypair = generateIdentityKeypair();
      const idPub = bytesToHex(keypair.publicKey);
      const { ciphertext, nonce } = encryptWithKey(encryptionKey, keypair.privateKey);

      const res = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username, idPub, authHash,
          kdfVersion: 2, kdfSalt, kdfIterations: KDF_V2.iterations,
          encryptedIdPriv: ciphertext, encryptedIdPrivNonce: nonce
        })
      });
      const result = await res.json();
      if (!result.success) {
        showAuthError(result.error || 'Could not create that account.');
        setAuthBusy(btn, false, 'Create account');
        return;
      }

      const sessionData = {
        username: username.toLowerCase(),
        idPub,
        idPriv: bytesToHex(keypair.privateKey),
        authHash,
        encryptionKeyHex: bytesToHex(encryptionKey)
      };

      // Vault mode is on by default for new accounts, and the decision is
      // written down explicitly rather than being inherited from
      // DEFAULT_SETTINGS. Accounts created before this existed have plaintext
      // blobs on disk and no stored value, so flipping the table default would
      // silently switch them over instead of leaving that to their owner.
      const useVault = document.getElementById('register-vault').checked;
      Storage.saveSettings(username, { ...DEFAULT_SETTINGS, encryptAtRest: useVault });
      if (useVault) unlockVault(bytesToHex(encryptionKey));

      // A persisted session carries encryptionKeyHex, which is the vault key.
      // Writing it to localStorage would undo the whole exercise, so the vault
      // wins over the checkbox rather than the two contradicting each other.
      Storage.saveSession(
        sessionData,
        !useVault && document.getElementById('register-remember').checked
      );
      initializeSession(sessionData);
      enterApp();
      toast('Welcome to Talon', { type: 'ok' });
    } catch (err) {
      console.error('[Auth]', err);
      showAuthError('Could not create that account. Is the server reachable?');
      setAuthBusy(btn, false, 'Create account');
    }
  };
}

async function logout(force = false) {
  if (!force) {
    const ok = await confirmDialog({
      title: 'Sign out?',
      message: 'Your message history stays on this device unless you also panic wipe.',
      confirmLabel: 'Sign out'
    });
    if (!ok) return;
  }
  try { if (State.socket) State.socket.close(); } catch {}
  Storage.clearSession();
  location.reload();
}

/* ================================================================ BOOT */

function enterApp() {
  document.getElementById('auth').hidden = true;
  const app = document.getElementById('app');
  app.hidden = false;
  requestAnimationFrame(() => app.classList.remove('booting'));
  bootApp();
}

function bootApp() {
  if (!State.currentUser) return;

  // Rail avatar
  bootAvatarRefresh();

  consumeAddLink();

  // Tabs
  document.querySelectorAll('[data-tab]').forEach((b) => {
    b.onclick = () => setTab(b.dataset.tab);
  });
  document.getElementById('rail-shortcuts').onclick = openShortcutsModal;

  // Chat list actions
  document.getElementById('btn-add-contact').onclick = () => addContactFlow();
  document.getElementById('btn-new-group').onclick = newGroupFlow;
  document.getElementById('btn-search').onclick = () => openSearchModal();

  const filter = document.getElementById('filter-input');
  const filterClear = document.getElementById('filter-clear');
  filter.addEventListener('input', debounce(() => {
    State.filterQuery = filter.value;
    filterClear.classList.toggle('hidden', !filter.value);
    views.renderChatList();
  }, 110));
  filterClear.onclick = () => {
    filter.value = '';
    State.filterQuery = '';
    filterClear.classList.add('hidden');
    views.renderChatList();
    filter.focus();
  };

  // View callbacks
  views.hooks.onSelectConversation = selectConversation;
  views.hooks.onBack = backToList;
  views.hooks.onOpenProfile = (id) => (isGroupId(id) ? openGroupInfo(id) : openContactProfile(id));
  views.hooks.onStartCall = startCall;
  views.hooks.onUnreadChanged = updateUnreadBadges;
  views.hooks.onToggleVoiceRecording = toggleVoiceRecording;
  views.hooks.onForward = (msg) => openForwardModal(msg, forwardMessage);
  views.hooks.onSendResult = onSendResult;
  views.hooks.onRetryMessage = retryMessage;

  // Pane callbacks
  paneHooks.onSelectConversation = (id, jump) => selectConversation(id, jump);
  paneHooks.onSyncProfile = () => { syncProfileWithServer(); bootAvatarRefresh(); };
  paneHooks.onLogout = logout;
  paneHooks.onPanicWipe = confirmPanicWipe;
  paneHooks.onEnablePush = subscribeToPush;

  initLightbox();
  bindShortcuts();
  bindCallControls();

  // Deep link from a tapped notification. `?t=<tag>` is what the worker sends
  // now; `?conv=<id>` is still honoured for a notification that was already
  // sitting in the tray when this version installed.
  const params = new URLSearchParams(location.search);
  const deepLink = params.get('conv') || conversationForPushTag(params.get('t'));
  if (deepLink) {
    setTimeout(() => selectConversation(deepLink), 0);
    history.replaceState({}, '', location.pathname);
  }

  // The worker reads these from IndexedDB when a push arrives and the app is
  // closed, so they have to be written whenever the app is open, not only when
  // a mute is toggled.
  publishMutedTags();

  // Silently re-confirm an existing push subscription. Permission is already
  // settled, so this needs no gesture.
  if ('Notification' in window && Notification.permission === 'granted' && 'serviceWorker' in navigator) {
    navigator.serviceWorker.ready
      .then((reg) => reg.pushManager.getSubscription())
      .then((sub) => { if (sub) sendSubscriptionToServer(sub); })
      .catch(() => {});
  }

  views.renderChatListSkeleton();
  requestAnimationFrame(() => requestAnimationFrame(() => {
    views.renderChatList();
    views.renderChatArea();
    updateUnreadBadges();
  }));

  // This device's identity has to exist BEFORE anything else, because the
  // register frame names it and prekeys are published under it. Creating it
  // afterwards would register the socket as the account rather than as this
  // device, and publish this device's prekeys into the account pool.
  ensureDeviceIdentity();

  connectWebSocket();

  // Publish protocol-v2 prekeys so peers can open forward-secret sessions
  // with us. Idempotent, and only tops up the one-time pool when it runs low.
  // Publishing the device list after the prekeys matters: a peer that reads
  // the list is entitled to expect a bundle for every device in it.
  ensurePreKeys()
    .then(() => publishThisDevice())
    .then((r) => {
      if (r && !r.ok) console.warn('[Devices] Not published:', r.reason);
    })
    .catch((err) => console.warn('[Prekeys]', err));

  if (State.settings.appLockEnabled) showLockScreen();
}

/** Keeps the rail avatar in step with the profile (same gradient as anywhere
 *  else that renders this identity). */
function bootAvatarRefresh() {
  const el = document.getElementById('rail-avatar');
  if (!el || !State.currentUser) return;
  const name = State.myProfile.nickname || State.currentUser.username;
  el.style.background = avatarGradient(State.currentUser.idPub);
  el.textContent = initials(name);
  // `revalidate` on purpose, and only here. The relay expires uploads by time
  // since last read, and an avatar is uploaded once but referenced forever,
  // so without a real request reaching the server it would be the first blob
  // the GC ever deleted. One cache-bypassing fetch per app start, by the only
  // client that can be relied on to care, keeps it alive. Contacts render
  // from cache as before.
  if (State.myProfile.avatar) {
    views.decryptAndShowAvatar(State.myProfile.avatar, el, { revalidate: true });
  }
}

/** Keeps the shell the size of what is actually on screen.
 *
 *  iOS does not shrink the layout viewport for the keyboard: `100dvh` still
 *  reports the full screen, so the shell stays too tall and the browser
 *  scrolls the document to bring the focused field into view. Everything
 *  `position: fixed`, which on a phone is the whole chat pane, is pinned to
 *  the layout viewport, so the header slides up under the status bar and dead
 *  space opens between the composer and the keyboard. Both screenshots of the
 *  bug are the same cause.
 *
 *  Driving the height off `visualViewport` makes the document exactly as tall
 *  as the visible area, so there is nothing left to scroll. */
function trackViewport() {
  const vv = window.visualViewport;
  if (!vv) return;

  const applyHeight = () => {
    document.documentElement.style.setProperty('--app-h', `${Math.round(vv.height)}px`);
  };

  vv.addEventListener('resize', () => {
    applyHeight();
    // Undo any scroll iOS already performed before the resize landed.
    if (window.scrollY !== 0) window.scrollTo(0, 0);
    // The keyboard covers the newest messages; put them back in view.
    const list = document.getElementById('msg-list');
    if (list) list.scrollTop = list.scrollHeight;
  });
  window.addEventListener('orientationchange', () => setTimeout(applyHeight, 300));

  applyHeight();
}

window.addEventListener('DOMContentLoaded', () => {
  trackViewport();
  bindAuth();
  const session = Storage.getSession();
  if (session) {
    initializeSession(session);
    enterApp();
  } else {
    document.getElementById('auth').hidden = false;
    document.getElementById('login-username').focus();
  }
});

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js').catch(() => {}));
}

/* ============================================================== WEBRTC */

const ICE_CONFIG = {
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' }
  ]
};

function createPeerConnection(contactId) {
  const pc = new RTCPeerConnection(ICE_CONFIG);
  State.peerConnection = pc;
  State.callContactId = contactId;

  pc.onicecandidate = (e) => {
    if (e.candidate) {
      sendE2EPayload(contactId, {
        type: 'call-signal', action: 'ice-candidate', candidate: e.candidate.toJSON()
      });
    }
  };

  pc.ontrack = (e) => {
    const v = document.getElementById('remote-video');
    if (v && e.streams[0]) v.srcObject = e.streams[0];
  };

  pc.onconnectionstatechange = () => {
    if (['disconnected', 'failed', 'closed'].includes(pc.connectionState)) endCall();
    if (pc.connectionState === 'connected') startCallTimer();
  };

  return pc;
}

async function startCall(contactId, withVideo) {
  if (State.peerConnection) { toast('Already in a call'); return; }

  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: withVideo });
    State.localStream = stream;
    const local = document.getElementById('local-video');
    if (local) local.srcObject = stream;

    const pc = createPeerConnection(contactId);
    stream.getTracks().forEach((t) => pc.addTrack(t, stream));

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    sendE2EPayload(contactId, { type: 'call-signal', action: 'offer', sdp: offer, withVideo });

    showCallUI(views.displayNameFor(contactId), withVideo);
  } catch (err) {
    console.error('[WebRTC]', err);
    toast('Could not access the camera or microphone', { type: 'error' });
    endCall();
  }
}

async function handleCallSignal(fromId, signal) {
  switch (signal.action) {
    case 'offer': {
      State.pendingOffer = { sdp: signal.sdp, fromId, withVideo: signal.withVideo };
      const ring = document.getElementById('call-ring');
      const name = views.displayNameFor(fromId);
      document.getElementById('ring-name').textContent = name;
      document.getElementById('ring-kind').textContent =
        signal.withVideo ? 'Encrypted video call' : 'Encrypted voice call';
      const av = document.getElementById('ring-avatar');
      av.textContent = name.substring(0, 2).toUpperCase();
      av.style.background = `linear-gradient(135deg, hsl(220 60% 50%), hsl(265 60% 45%))`;
      ring.hidden = false;
      break;
    }

    case 'answer':
      if (State.peerConnection) {
        try { await State.peerConnection.setRemoteDescription(new RTCSessionDescription(signal.sdp)); }
        catch (err) { console.error('[WebRTC]', err); }
      }
      break;

    case 'ice-candidate':
      if (State.peerConnection && signal.candidate) {
        try { await State.peerConnection.addIceCandidate(new RTCIceCandidate(signal.candidate)); }
        catch (err) { console.error('[WebRTC]', err); }
      }
      break;

    case 'end':
      endCall();
      break;
  }
}

async function acceptCall() {
  document.getElementById('call-ring').hidden = true;
  if (!State.pendingOffer) return;
  const { sdp, fromId, withVideo } = State.pendingOffer;
  State.pendingOffer = null;

  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: !!withVideo });
    State.localStream = stream;
    const local = document.getElementById('local-video');
    if (local) local.srcObject = stream;

    const pc = createPeerConnection(fromId);
    stream.getTracks().forEach((t) => pc.addTrack(t, stream));

    await pc.setRemoteDescription(new RTCSessionDescription(sdp));
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    sendE2EPayload(fromId, { type: 'call-signal', action: 'answer', sdp: answer });

    showCallUI(views.displayNameFor(fromId), !!withVideo);
  } catch (err) {
    console.error('[WebRTC]', err);
    toast('Could not join the call', { type: 'error' });
    endCall();
  }
}

function rejectCall() {
  document.getElementById('call-ring').hidden = true;
  const from = State.pendingOffer && State.pendingOffer.fromId;
  State.pendingOffer = null;
  if (from) sendE2EPayload(from, { type: 'call-signal', action: 'end' });
}

function endCall() {
  if (State.peerConnection) {
    if (State.callContactId) {
      try { sendE2EPayload(State.callContactId, { type: 'call-signal', action: 'end' }); } catch {}
    }
    State.peerConnection.close();
    State.peerConnection = null;
  }
  if (State.localStream) {
    State.localStream.getTracks().forEach((t) => t.stop());
    State.localStream = null;
  }
  if (State.callTimerInterval) {
    clearInterval(State.callTimerInterval);
    State.callTimerInterval = null;
  }
  State.callContactId = null;
  State.callStartTime = null;
  State.pendingOffer = null;

  document.getElementById('call-live').hidden = true;
  document.getElementById('call-ring').hidden = true;
}

function showCallUI(name, withVideo) {
  const live = document.getElementById('call-live');
  document.getElementById('call-live-name').textContent = name;
  document.getElementById('call-live-timer').textContent = '00:00';
  document.getElementById('local-video').style.display = withVideo ? '' : 'none';
  live.hidden = false;
}

function bindCallControls() {
  document.getElementById('ring-accept').onclick = acceptCall;
  document.getElementById('ring-decline').onclick = rejectCall;
  document.getElementById('call-end').onclick = endCall;

  document.getElementById('call-mic').onclick = function () {
    if (!State.localStream) return;
    const enabled = State.localStream.getAudioTracks().some((t) => t.enabled);
    State.localStream.getAudioTracks().forEach((t) => { t.enabled = !enabled; });
    this.classList.toggle('off', enabled);
    this.innerHTML = icon(enabled ? 'mic-off' : 'mic', 21);
  };

  document.getElementById('call-cam').onclick = function () {
    if (!State.localStream) return;
    const tracks = State.localStream.getVideoTracks();
    if (!tracks.length) { toast('This is a voice-only call'); return; }
    const enabled = tracks.some((t) => t.enabled);
    tracks.forEach((t) => { t.enabled = !enabled; });
    this.classList.toggle('off', enabled);
    this.innerHTML = icon(enabled ? 'cam-off' : 'video', 21);
  };
}

function startCallTimer() {
  if (State.callTimerInterval) return;
  State.callStartTime = Date.now();
  State.callTimerInterval = setInterval(() => {
    const el = document.getElementById('call-live-timer');
    if (!el) return;
    const s = Math.floor((Date.now() - State.callStartTime) / 1000);
    el.textContent = `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
  }, 1000);
}
