// --- CHAT VIEWS ---
// The chat list, the chat area (header + message list + composer), and the
// message bubbles. Everything here reads State and writes DOM; the protocol
// lives in messaging.js.
//
// NOTE: renderChatArea() rebuilds the entire composer subtree, so any new
// composer control must be created AND bound inside it. Binding in boot()
// would be lost on the first chat switch.

import { State, persist, metaFor } from './store.js';
import {
  escapeHTML, escapeAttr, richText, avatarGradient, initials, icon,
  formatTime, formatDuration, formatBytes, relativeTime, dayLabel, dayKey,
  truncate, isImage, debounce
} from './util.js';
import {
  sendE2EPayload, sendGroupMessage, sendControl, syncToMyDevices, isGroupId, findMsg,
  messagesFor, lastMessageFor, ttlFor, expiryFor, normalizeReactions,
  toggleReactionLocal, unreadCount, previewFor, syncContactsWithServer,
  syncGroupsWithServer, setContactFlags, publishMutedTags,
  decryptFailureCount, resetSession, announceLeave
} from './messaging.js';
import { fetchAndDecrypt, encryptAndUpload } from './crypto-extra.js';
import { playCue } from './sound.js';
import { toast, openPopover, closePopover, openLightbox, confirmDialog, openModal } from './ui.js';

const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;

// One failure is ordinary: a duplicate envelope, or a message from a chain we
// already advanced past. A run of them means the two ends no longer agree.
const UNDECRYPTABLE_WARN_AT = 3;

export const EMOJI_GROUPS = [
  { tab: '🙂', label: 'Smileys', list: ['😀','😃','😄','😁','😆','😅','🤣','😂','🙂','🙃','😉','😊','😇','🥰','😍','🤩','😘','😗','😚','😙','😋','😛','😜','🤪','😝','🤑','🤗','🤭','🤫','🤔','🤐','😐','😑','😶','😏','😒','🙄','😬','😌','😔','😪','😴','😷','🤒','🤕','🤢','🥴','😵','🤯','🤠','🥳','😎','🤓','🧐','😕','😟','🙁','😮','😯','😲','😳','🥺','😦','😨','😰','😥','😢','😭','😱','😖','😣','😞','😓','😩','😫','🥱','😤','😡','😠','🤬','😈','💀','💩','🤡'] },
  { tab: '👍', label: 'Gestures', list: ['👍','👎','👌','🤌','✌️','🤞','🤟','🤘','🤙','👈','👉','👆','👇','☝️','✋','🤚','🖐️','🖖','👋','🤝','🙏','✍️','💪','🦾','👏','🙌','👐','🤲','🫶','❤️','🧡','💛','💚','💙','💜','🖤','🤍','🤎','💔','❣️','💕','💞','💓','💗','💖','💘','💝','💯','💢','💥','✨','⭐','🌟','💫','🔥'] },
  { tab: '🐶', label: 'Nature', list: ['🐶','🐱','🐭','🐹','🐰','🦊','🐻','🐼','🐨','🐯','🦁','🐮','🐷','🐸','🐵','🙈','🙉','🙊','🐔','🐧','🐦','🐤','🦆','🦅','🦉','🦇','🐺','🐗','🐴','🦄','🐝','🐛','🦋','🐌','🐞','🐜','🕷️','🐢','🐍','🦎','🐙','🦑','🦐','🦀','🐡','🐠','🐟','🐬','🐳','🐋','🦈','🌵','🎄','🌲','🌳','🌴','🌱','🌿','☘️','🍀','🎋','🍃','🍂','🍁','🌾','🌷','🌹','🥀','🌺','🌸','🌼','🌻','🌞','🌝','🌚','🌙','⭐','🌠','☁️','⛅','🌧️','⛈️','🌈','❄️','⛄','🔥','💧','🌊'] },
  { tab: '🍔', label: 'Food', list: ['🍏','🍎','🍐','🍊','🍋','🍌','🍉','🍇','🍓','🫐','🍈','🍒','🍑','🥭','🍍','🥥','🥝','🍅','🥑','🍆','🥔','🥕','🌽','🌶️','🥒','🥬','🥦','🧄','🧅','🍄','🥜','🌰','🍞','🥐','🥖','🥨','🧀','🥚','🍳','🧈','🥞','🧇','🥓','🍔','🍟','🍕','🌭','🥪','🌮','🌯','🥙','🧆','🥘','🍝','🍜','🍲','🍛','🍣','🍱','🥟','🍤','🍙','🍚','🍥','🥠','🍦','🍰','🎂','🧁','🥧','🍫','🍬','🍭','🍩','🍪','☕','🍵','🧃','🥤','🍺','🍻','🥂','🍷','🥃','🍸'] },
  { tab: '⚽', label: 'Activity', list: ['⚽','🏀','🏈','⚾','🥎','🎾','🏐','🏉','🥏','🎱','🪀','🏓','🏸','🏒','🏑','🥍','🏏','🥅','⛳','🪁','🏹','🎣','🤿','🥊','🥋','🎽','🛹','🛼','🛷','⛸️','🥌','🎿','⛷️','🏂','🏋️','🤼','🤸','⛹️','🤺','🤾','🏌️','🏇','🧘','🏄','🏊','🤽','🚣','🧗','🚵','🚴','🏆','🥇','🥈','🥉','🏅','🎖️','🎗️','🎫','🎪','🎭','🎨','🎬','🎤','🎧','🎼','🎹','🥁','🎷','🎺','🎸','🪕','🎻','🎲','♟️','🎯','🎳','🎮','🎰','🧩'] },
  { tab: '🚗', label: 'Travel', list: ['🚗','🚕','🚙','🚌','🚎','🏎️','🚓','🚑','🚒','🚐','🛻','🚚','🚛','🚜','🦯','🦽','🛴','🚲','🛵','🏍️','🛺','🚨','🚔','🚍','🚘','🚖','🚡','🚠','🚟','🚃','🚋','🚞','🚝','🚄','🚅','🚈','🚂','🚆','🚇','🚊','🚉','✈️','🛫','🛬','🛩️','💺','🛰️','🚀','🛸','🚁','🛶','⛵','🚤','🛥️','🛳️','⛴️','🚢','⚓','🗺️','🗽','🗼','🏰','🏯','🏟️','🎡','🎢','🎠','⛲','⛱️','🏖️','🏝️','🏜️','🌋','⛰️','🏔️','🗻','🏕️','⛺','🏠','🏡','🏘️','🏢','🏬','🏣','🏤','🏥','🏦','🏨','🏪','🏫','🏩','💒','🏛️','⛪','🕌','🕍'] },
  { tab: '💡', label: 'Objects', list: ['⌚','📱','💻','⌨️','🖥️','🖨️','🖱️','💽','💾','💿','📀','📷','📸','📹','🎥','📞','☎️','📟','📠','📺','📻','🎙️','⏰','⏲️','⏱️','🕰️','⌛','⏳','📡','🔋','🔌','💡','🔦','🕯️','🧯','🛢️','💸','💵','💴','💶','💷','💰','💳','💎','⚖️','🧰','🔧','🔨','⚒️','🛠️','⛏️','🔩','⚙️','🧱','⛓️','🧲','🔫','💣','🧨','🪓','🔪','🗡️','⚔️','🛡️','🚬','⚰️','🏺','🔮','📿','🧿','💈','⚗️','🔭','🔬','🕳️','💊','💉','🩸','🩹','🩺','🌡️','🧹','🧺','🧻','🚽','🚿','🛁','🧼','🪒','🧽','🔑','🗝️','🚪','🛋️','🛏️','🖼️','🛍️','🎁','🎈','🎏','🎀','🎊','🎉','🏮','📩','📨','📧','💌','📦','📪','📫','📮','📜','📃','📑','📊','📈','📉','📄','📅','📆','🗒️','🗓️','📇','🗃️','🗳️','🗄️','📋','📁','📂','🗂️','📰','📓','📔','📒','📕','📗','📘','📙','📚','📖','🔖','🧷','🔗','📎','📐','📏','🧮','📌','📍','✂️','🖊️','🖋️','✒️','🖌️','🖍️','📝','✏️','🔍','🔎','🔏','🔐','🔒','🔓'] },
  { tab: '✅', label: 'Symbols', list: ['✅','❌','❎','✔️','☑️','🔘','🔴','🟠','🟡','🟢','🔵','🟣','⚫','⚪','🟤','🔺','🔻','🔸','🔹','🔶','🔷','🔳','🔲','▪️','▫️','◾','◽','◼️','◻️','⬛','⬜','🟥','🟧','🟨','🟩','🟦','🟪','⬆️','↗️','➡️','↘️','⬇️','↙️','⬅️','↖️','↕️','↔️','↩️','↪️','⤴️','⤵️','🔃','🔄','🔙','🔚','🔛','🔜','🔝','🛐','⚛️','🕉️','✡️','☸️','☯️','✝️','☦️','☪️','☮️','🕎','🔯','♈','♉','♊','♋','♌','♍','♎','♏','♐','♑','♒','♓','⛎','🆔','⚠️','🚸','⛔','🚫','💯','♻️','✳️','❇️','❓','❔','❗','❕','〽️','⚜️','🔱','📛','🔰','⭕','🈯','💹','❄️','💠','Ⓜ️','🌀','💤','🏧','🚾','♿','🅿️','🈳','🈂️','🛂','🛃','🛄','🛅','🚹','🚺','🚼','⚧️','🚻','🚮','🎦','📶','🈁','🔣','ℹ️','🔤','🔡','🔠','🆖','🆗','🆙','🆒','🆕','🆓'] }
];

const QUICK_REACTIONS = ['👍', '❤️', '😂', '😮', '😢', '🙏'];

/* ------------------------------------------------------------- callbacks */
// Wired by app.js at boot so views.js never has to import back from it.
export const hooks = {
  onSelectConversation: () => {},
  onOpenProfile: () => {},
  onStartCall: () => {},
  onBack: () => {},
  onUnreadChanged: () => {},
  onToggleVoiceRecording: () => {},
  // Called with the outcome of every content send, so app.js can put an
  // unacknowledged message in the outbox and retry it.
  onSendResult: () => {},
  onRetryMessage: () => {}
};

/* ------------------------------------------------------------- avatar bits */

export async function decryptAndShowAvatar(avatarObj, containerEl, opts) {
  if (!avatarObj || !avatarObj.url || !avatarObj.key || !avatarObj.iv || !containerEl) return;
  try {
    const plain = await fetchAndDecrypt(avatarObj.url, avatarObj.key, avatarObj.iv, opts);
    const url = URL.createObjectURL(new Blob([plain]));
    containerEl.innerHTML = `<img src="${url}" alt="">`;
  } catch {
    /* keep the initials fallback */
  }
}

export function avatarHTML(id, label, extraClass = '', domId = '') {
  return `<div class="avatar ${extraClass}"${domId ? ` id="${domId}"` : ''} style="background:${avatarGradient(id)}">${escapeHTML(initials(label))}</div>`;
}

export function displayNameFor(id) {
  if (State.currentUser && id === State.currentUser.idPub) {
    return State.myProfile.nickname || State.currentUser.username;
  }
  const c = State.contacts.find((x) => x.idPub === id);
  if (c) return c.nickname;
  const g = State.groups.find((x) => x.id === id);
  if (g) return g.name;
  return `Peer-${String(id || '').substring(0, 6)}`;
}

function conversationFor(id) {
  const group = State.groups.find((g) => g.id === id);
  if (group) return { kind: 'group', group, name: group.name, id };
  const contact = State.contacts.find((c) => c.idPub === id);
  if (contact) return { kind: 'dm', contact, name: contact.nickname, id };
  return null;
}

/* ============================================================== CHAT LIST */

export function renderChatListSkeleton(count = 7) {
  const el = document.getElementById('chat-list');
  if (!el) return;
  el.innerHTML = Array.from({ length: count }).map(() => `
    <div class="skel-row">
      <div class="skeleton skel-avatar"></div>
      <div class="skel-lines">
        <div class="skeleton skel-line" style="width:52%"></div>
        <div class="skeleton skel-line" style="width:78%"></div>
      </div>
    </div>
  `).join('');
}

/** Every conversation, newest activity first, pinned ones hoisted. */
function conversationRows() {
  const rows = [];

  State.groups.forEach((g) => {
    const last = lastMessageFor(g.id);
    rows.push({
      id: g.id, kind: 'group', name: g.name, muted: !!g.muted,
      last, ts: last ? last.timestamp : 0,
      pinned: !!metaFor(g.id).pinned, unread: unreadCount(g.id),
      avatarSource: null, sub: `${g.members.length} members`
    });
  });

  State.contacts.forEach((c) => {
    if (c.blocked) return; // blocked conversations never appear in the list
    const last = lastMessageFor(c.idPub);
    rows.push({
      id: c.idPub, kind: 'dm', name: c.nickname, muted: !!c.muted,
      last, ts: last ? last.timestamp : 0,
      pinned: !!metaFor(c.idPub).pinned, unread: unreadCount(c.idPub),
      avatarSource: c.avatar, sub: '', pending: !!c.pending, contact: c
    });
  });

  const q = State.filterQuery.trim().toLowerCase();
  const filtered = q
    ? rows.filter((r) => r.name.toLowerCase().includes(q) || previewFor(r.last).toLowerCase().includes(q))
    : rows;

  // Requests sit above everything, then pinned, then by recency.
  filtered.sort((a, b) => {
    if (!!a.pending !== !!b.pending) return a.pending ? -1 : 1;
    if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
    return b.ts - a.ts;
  });
  return filtered;
}

export function renderChatList() {
  const el = document.getElementById('chat-list');
  if (!el) return;

  const rows = conversationRows();

  if (rows.length === 0) {
    const filtering = State.filterQuery.trim().length > 0;
    el.innerHTML = `
      <div class="empty">
        <div class="empty-icon">${icon(filtering ? 'search' : 'chat', 26)}</div>
        <div class="empty-title">${filtering ? 'No matches' : 'No conversations yet'}</div>
        <div class="empty-text">${filtering
          ? 'Nothing here matches that filter.'
          : 'Add someone by their Client ID to start a conversation. Everything you send is encrypted before it leaves this device.'}</div>
      </div>`;
    hooks.onUnreadChanged();
    return;
  }

  const pendingCount = rows.filter((r) => r.pending).length;
  const pinnedCount = rows.filter((r) => r.pinned && !r.pending).length;
  let html = '';

  rows.forEach((r, i) => {
    if (pendingCount && i === 0) {
      html += `<div class="list-label">Message requests · ${pendingCount}</div>`;
    }
    if (i === pendingCount) {
      if (pinnedCount) html += `<div class="list-label">Pinned</div>`;
      else if (pendingCount) html += `<div class="list-label">Conversations</div>`;
    }
    if (pinnedCount && i === pendingCount + pinnedCount) {
      html += `<div class="list-label">Conversations</div>`;
    }

    const active = State.activeContactId === r.id;
    const preview = State.settings.showPreviews ? previewFor(r.last) : '';
    const prefix = r.last && r.last.sender === 'me' ? 'You: '
      : (r.kind === 'group' && r.last && r.last.senderId ? `${truncate(displayNameFor(r.last.senderId), 12)}: ` : '');
    const draft = State.drafts[r.id];

    html += `
      <button class="chat-row${active ? ' active' : ''}${r.unread ? ' unread' : ''}" data-conv="${escapeAttr(r.id)}">
        <div class="avatar-wrap">
          ${r.kind === 'group'
            ? `<div class="avatar" style="background:${avatarGradient(r.id)}">${icon('users', 18)}</div>`
            : avatarHTML(r.id, r.name, '', `list-avatar-${r.id}`)}
          ${r.kind === 'dm' && isOnline(r.contact) ? '<span class="presence online" title="Online"></span>' : ''}
        </div>
        <div class="chat-row-main">
          <div class="chat-row-top">
            <span class="chat-row-name">${escapeHTML(r.name)}</span>
            ${r.pending ? '<span class="tag accent">Request</span>' : ''}
            <span class="chat-row-time">${r.ts ? relativeTime(r.ts) : ''}</span>
          </div>
          <div class="chat-row-preview">
            ${draft ? `<span style="color:var(--warn);font-weight:650">Draft:</span> ${escapeHTML(truncate(draft, 34))}`
                    : escapeHTML(truncate(prefix + preview, 42)) || '<span style="opacity:.6">No messages yet</span>'}
          </div>
        </div>
        <div class="chat-row-meta">
          <div class="chat-row-icons">
            ${r.pinned ? icon('pin', 13) : ''}
            ${r.muted ? icon('bell-off', 13) : ''}
          </div>
          ${r.unread ? `<span class="badge${r.muted ? ' muted-badge' : ''}">${r.unread > 99 ? '99+' : r.unread}</span>` : ''}
        </div>
      </button>`;
  });

  el.innerHTML = html;

  el.querySelectorAll('.chat-row').forEach((row) => {
    const id = row.dataset.conv;
    row.onclick = () => hooks.onSelectConversation(id);
    row.oncontextmenu = (e) => { e.preventDefault(); openConversationMenu(row, id); };
  });

  // Decrypt contact avatars after paint so the list appears immediately.
  rows.forEach((r) => {
    if (r.avatarSource) decryptAndShowAvatar(r.avatarSource, document.getElementById(`list-avatar-${r.id}`));
  });

  hooks.onUnreadChanged();
}

function openConversationMenu(anchor, convId) {
  const conv = conversationFor(convId);
  if (!conv) return;
  const meta = metaFor(convId);
  const muted = conv.kind === 'group' ? conv.group.muted : conv.contact.muted;

  openPopover(anchor, `
    <div class="menu">
      <button class="menu-item" data-act="pin">${icon('pin', 16)}${meta.pinned ? 'Unpin' : 'Pin to top'}</button>
      <button class="menu-item" data-act="mute">${icon(muted ? 'bell' : 'bell-off', 16)}${muted ? 'Unmute' : 'Mute'}</button>
      <button class="menu-item" data-act="read">${icon('check', 16)}Mark as read</button>
      <div class="menu-sep"></div>
      <button class="menu-item danger" data-act="delete">${icon('trash', 16)}${conv.kind === 'group' ? 'Leave group' : 'Delete chat'}</button>
    </div>
  `, {
    onMount(pop, close) {
      pop.querySelector('[data-act=pin]').onclick = () => {
        meta.pinned = !meta.pinned; persist.chatMeta(); renderChatList(); close();
      };
      pop.querySelector('[data-act=mute]').onclick = () => { toggleMute(convId); close(); };
      pop.querySelector('[data-act=read]').onclick = () => { markConversationRead(convId); renderChatList(); close(); };
      pop.querySelector('[data-act=delete]').onclick = () => { close(); deleteConversation(convId); };
    }
  });
}

export function toggleMute(convId) {
  const group = State.groups.find((g) => g.id === convId);
  if (group) {
    group.muted = !group.muted;
    persist.groups();
    syncGroupsWithServer();
  } else {
    const contact = State.contacts.find((c) => c.idPub === convId);
    if (!contact) return;
    contact.muted = !contact.muted;
    persist.contacts();
    syncContactsWithServer();
  }
  publishMutedTags();
  renderChatList();
  if (State.activeContactId === convId) renderChatArea();
}

export function markConversationRead(convId) {
  const isGroup = isGroupId(convId);
  let changed = false;
  State.messages.forEach((m) => {
    if (m.contactId === convId && m.sender === 'them' && m.status !== 'read') {
      m.status = 'read';
      changed = true;
      if (!isGroup && State.settings.sendReadReceipts) {
        sendE2EPayload(convId, { type: 'control', action: 'read', targetIndex: m.messageIndex });
      }
    }
  });
  if (changed) persist.messages();
}

export async function deleteConversation(convId) {
  const conv = conversationFor(convId);
  if (!conv) return;
  const isGroup = conv.kind === 'group';

  const ok = await confirmDialog({
    title: isGroup ? `Leave "${conv.name}"?` : `Delete chat with ${conv.name}?`,
    message: isGroup
      ? 'The other members are told you have left, and stop addressing you. This group and its history are erased from this device.'
      : 'This contact and all messages exchanged with them will be erased from this device. Their copy is unaffected.',
    confirmLabel: isGroup ? 'Leave group' : 'Delete',
    danger: true
  });
  if (!ok) return;

  if (isGroup) {
    // Tell them before the group is gone locally: the announcement is fanned
    // out from our own copy of the roster.
    if (!conv.group.removed) announceLeave(convId);
    State.groups = State.groups.filter((g) => g.id !== convId);
    persist.groups();
    syncGroupsWithServer();
  } else {
    State.contacts = State.contacts.filter((c) => c.idPub !== convId);
    delete State.sessions[convId];
    persist.contacts();
    persist.sessions();
    syncContactsWithServer();
  }

  State.messages = State.messages.filter((m) => m.contactId !== convId);
  delete State.chatMeta[convId];
  delete State.drafts[convId];
  persist.messages();
  persist.chatMeta();
  persist.drafts();

  State.activeContactId = null;
  renderChatList();
  renderChatArea();
  hooks.onBack();
  toast(isGroup ? 'Left the group' : 'Chat deleted', { type: 'ok' });
}

/* ============================================================== CHAT AREA */

export function renderChatAreaSkeleton() {
  const el = document.getElementById('detail');
  if (!el) return;
  const widths = [38, 56, 30, 62, 44];
  el.innerHTML = `
    <div class="msg-list" style="justify-content:flex-end">
      ${widths.map((w, i) => `<div class="skeleton skel-bubble" style="width:${w}%;align-self:${i % 2 ? 'flex-end' : 'flex-start'}"></div>`).join('')}
    </div>`;
}

export function renderChatArea() {
  const root = document.getElementById('detail');
  if (!root) return;

  const conv = conversationFor(State.activeContactId);
  if (!conv) {
    root.innerHTML = `
      <div class="empty" style="height:100%">
        <div class="empty-icon">${icon('chat', 28)}</div>
        <div class="empty-title">Pick up where you left off</div>
        <div class="empty-text">Choose a conversation on the left, or add someone new. Messages are end-to-end encrypted, so the relay only ever sees ciphertext.</div>
      </div>`;
    return;
  }

  const isGroup = conv.kind === 'group';
  const meta = metaFor(conv.id);
  const muted = isGroup ? conv.group.muted : conv.contact.muted;
  const ttl = ttlFor(conv.id);

  // Presence, when the peer has told us anything, otherwise fall back to the
  // Client ID. The ID is only useful for identifying an unfamiliar contact;
  // once you know who they are, whether they are here is the better line.
  const presence = isGroup ? '' : presenceLabel(conv.contact);
  const sub = isGroup
    ? `${conv.group.members.length} member${conv.group.members.length === 1 ? '' : 's'}`
    : (presence || `${conv.contact.idPub.substring(0, 12)}…${conv.contact.idPub.slice(-6)}`);

  root.innerHTML = `
    <header class="chat-head">
      <button class="icon-btn back-btn" id="chat-back" aria-label="Back">${icon('back', 20)}</button>
      <div class="avatar-wrap">
        ${isGroup
          ? `<div class="avatar" style="background:${avatarGradient(conv.id)}">${icon('users', 18)}</div>`
          : avatarHTML(conv.id, conv.name, '', 'head-avatar')}
        ${!isGroup && isOnline(conv.contact) ? '<span class="presence online" title="Online"></span>' : ''}
      </div>
      <div class="chat-head-info" id="chat-head-info">
        <div class="chat-head-name">
          ${escapeHTML(conv.name)}
          ${meta.verified ? `<span class="verified-mark" title="Safety number verified">${icon('shield-check', 15)}</span>` : ''}
          ${ttl ? `<span class="tag accent">${ttlLabel(ttl)}</span>` : ''}
        </div>
        <div class="chat-head-sub${presence === 'Online' ? ' is-online' : ''}" id="chat-head-sub">${escapeHTML(sub)}</div>
      </div>
      <div class="chat-head-actions">
        <button class="icon-btn" id="btn-chat-search" title="Search in conversation">${icon('search', 18)}</button>
        ${isGroup ? '' : `
          <button class="icon-btn" id="btn-voice-call" title="Voice call">${icon('phone', 18)}</button>
          <button class="icon-btn" id="btn-video-call" title="Video call">${icon('video', 18)}</button>`}
        <button class="icon-btn" id="btn-chat-menu" title="More">${icon('more', 18)}</button>
      </div>
    </header>

    <div class="chat-search hidden" id="chat-search">
      <span class="chat-search-icon">${icon('search', 15)}</span>
      <input class="chat-search-input" id="chat-search-input" type="search"
             placeholder="Search in this conversation" autocomplete="off" spellcheck="false">
      <span class="chat-search-count" id="chat-search-count"></span>
      <button class="icon-btn chat-search-up" id="chat-search-prev" title="Previous match">${icon('down', 16)}</button>
      <button class="icon-btn" id="chat-search-next" title="Next match">${icon('down', 16)}</button>
      <button class="icon-btn" id="chat-search-close" title="Close search">${icon('close', 16)}</button>
    </div>

    ${!isGroup && decryptFailureCount(conv.id) >= UNDECRYPTABLE_WARN_AT ? `
    <div class="session-warn" id="session-warn">
      <span class="session-warn-icon">${icon('alert', 16)}</span>
      <div class="session-warn-body">
        <strong>Messages from ${escapeHTML(conv.name)} cannot be read.</strong>
        Their device most likely reinstalled Talon, so their end of the
        encryption no longer matches this one. Resetting starts a fresh
        handshake. Your saved history is not affected.
      </div>
      <button class="btn btn-sm" id="session-reset">Reset</button>
    </div>` : ''}

    <div class="msg-list scroll-y" id="msg-list"></div>

    <button class="jump-btn" id="jump-btn" aria-label="Jump to latest">${icon('down', 18)}</button>

    ${isGroup && conv.group.removed ? `
    <div class="composer-wrap">
      <div class="request-bar">
        <div class="request-text">
          You are no longer a member of <strong>${escapeHTML(conv.name)}</strong>.
          The history stays on this device until you delete the group.
        </div>
        <div class="request-actions">
          <button class="btn btn-sm" id="req-delete-group">Delete group</button>
        </div>
      </div>
    </div>` : conv.kind === 'dm' && conv.contact.pending ? `
    <div class="composer-wrap">
      <div class="request-bar">
        <div class="request-text">
          <strong>${escapeHTML(conv.name)}</strong> is not in your contacts.
          Accept to reply, or block to stop receiving from them.
        </div>
        <div class="request-actions">
          <button class="btn btn-danger btn-sm" id="req-block">Block</button>
          <button class="btn btn-primary btn-sm" id="req-accept">Accept</button>
        </div>
      </div>
    </div>` : `
    <div class="composer-wrap" id="composer-wrap">
      <div class="reply-bar hidden" id="context-bar">
        <span class="reply-bar-mark" id="context-mark">${icon('reply', 15)}</span>
        <div class="reply-bar-body">
          <div class="reply-bar-label" id="context-label">Replying to</div>
          <div class="reply-bar-text" id="context-text"></div>
        </div>
        <button class="icon-btn reply-bar-x" id="context-cancel" aria-label="Cancel">${icon('close', 15)}</button>
      </div>

      <form class="composer" id="composer">
        <button type="button" class="icon-btn" id="btn-attach" title="Attach file">${icon('attach', 20)}</button>
        <button type="button" class="icon-btn" id="btn-emoji" title="Emoji">${icon('smile', 20)}</button>
        <input type="file" id="file-input" hidden multiple>
        <textarea class="composer-input" id="composer-input" rows="1"
                  placeholder="Message${isGroup ? ` ${escapeAttr(conv.name)}` : ''}…"
                  autocomplete="off" enterkeyhint="send"
                  spellcheck="${State.settings.spellcheck !== false}"></textarea>
        <button type="button" class="icon-btn mic-btn" id="btn-mic" title="Record voice message">${icon('mic', 20)}</button>
        <button type="submit" class="send-btn" id="btn-send" aria-label="Send">${icon('send', 18)}</button>
      </form>
    </div>`}
  `;

  if (!isGroup && conv.contact.avatar) {
    decryptAndShowAvatar(conv.contact.avatar, document.getElementById('head-avatar'));
  }

  paintMessages(conv);
  bindChatHeader(conv);
  bindMessageInteractions(conv);

  if (conv.kind === 'group' && conv.group.removed) {
    const del = document.getElementById('req-delete-group');
    if (del) del.onclick = () => deleteConversation(conv.id);
  } else if (conv.kind === 'dm' && conv.contact.pending) {
    bindRequestBar(conv);
  } else {
    bindComposer(conv);
  }
}

function bindRequestBar(conv) {
  const accept = document.getElementById('req-accept');
  const block = document.getElementById('req-block');

  if (accept) {
    accept.onclick = () => {
      setContactFlags(conv.id, { pending: false });
      syncContactsWithServer();
      renderChatArea();
      renderChatList();
      toast(`You can now reply to ${conv.name}`, { type: 'ok' });
    };
  }

  if (block) {
    block.onclick = async () => {
      const ok = await confirmDialog({
        title: `Block ${conv.name}?`,
        message: 'Their messages will be dropped on arrival and this conversation will be removed from your list. They are not told they have been blocked.',
        confirmLabel: 'Block',
        danger: true
      });
      if (!ok) return;

      setContactFlags(conv.id, { blocked: true, pending: false });
      State.messages = State.messages.filter((m) => m.contactId !== conv.id);
      persist.messages();
      syncContactsWithServer();

      State.activeContactId = null;
      renderChatArea();
      renderChatList();
      hooks.onBack();
      toast('Blocked', { type: 'ok' });
    };
  }
}

function ttlLabel(ms) {
  if (ms >= 604800000) return '1w';
  if (ms >= 86400000) return `${Math.round(ms / 86400000)}d`;
  if (ms >= 3600000) return `${Math.round(ms / 3600000)}h`;
  return `${Math.round(ms / 60000)}m`;
}

/* --------------------------------------------------------- message paint */

function paintMessages(conv) {
  const list = document.getElementById('msg-list');
  if (!list) return;

  const msgs = messagesFor(conv.id);
  if (msgs.length === 0) {
    list.innerHTML = `
      <div class="empty" style="margin:auto">
        <div class="empty-icon">${icon('lock', 24)}</div>
        <div class="empty-title">No messages yet</div>
        <div class="empty-text">Say hello. Messages in this conversation are end-to-end encrypted.</div>
      </div>`;
    return;
  }

  const dividerAt = State.unreadDividerContactId === conv.id ? State.unreadDividerMessageIndex : null;
  let lastDay = null;
  let prev = null;
  const frag = document.createDocumentFragment();

  msgs.forEach((msg) => {
    const dk = dayKey(msg.timestamp);
    if (dk !== lastDay) {
      const sep = document.createElement('div');
      sep.className = 'day-sep';
      sep.textContent = dayLabel(msg.timestamp);
      frag.appendChild(sep);
      lastDay = dk;
      prev = null; // a new day always starts a fresh bubble group
    }

    if (dividerAt !== null && msg.messageIndex === dividerAt && msg.sender === 'them') {
      const sep = document.createElement('div');
      sep.className = 'unread-sep';
      sep.textContent = 'New';
      frag.appendChild(sep);
    }

    frag.appendChild(buildMessageEl(msg, conv, prev));
    prev = msg;
  });

  list.innerHTML = '';
  list.appendChild(frag);
  list.appendChild(buildTypingEl());

  requestAnimationFrame(() => scrollToBottom(false));
}

function buildTypingEl() {
  const el = document.createElement('div');
  el.className = 'typing hidden';
  el.id = 'typing';
  el.innerHTML = `
    <span class="typing-who" id="typing-who" hidden></span>
    <span class="typing-dots"><i class="typing-dot"></i><i class="typing-dot"></i><i class="typing-dot"></i></span>`;
  return el;
}

/** True when this message should visually tuck under the previous one. */
function isSameGroup(msg, prev) {
  if (!prev) return false;
  if (prev.sender !== msg.sender) return false;
  if (prev.senderId !== msg.senderId) return false;
  if (msg.timestamp - prev.timestamp > 5 * 60_000) return false;
  return true;
}

export function buildMessageEl(msg, conv, prev, isLive = false) {
  const isGroup = conv.kind === 'group';
  const out = msg.sender === 'me';
  const grouped = isSameGroup(msg, prev);

  const el = document.createElement('div');
  el.className = [
    'msg',
    out ? 'out' : 'in',
    msg.type === 'sticker' && !msg.deleted ? 'sticker' : '',
    msg.deleted ? 'tombstone' : '',
    grouped ? 'tail-mid' : 'tail-first',
    msg.status === 'sending' ? 'pending' : '',
    (msg.status === 'offline' || msg.status === 'failed') ? 'failed' : ''
  ].filter(Boolean).join(' ');
  el.dataset.msgIndex = msg.messageIndex;
  el.dataset.msgSender = msg.sender;
  // refreshMessage() reads this off the outgoing element to tell a genuine
  // transition-to-read from an ordinary re-render.
  el.dataset.status = msg.status || '';
  if (isLive) el.style.animationDelay = '0ms';

  if (msg.deleted) {
    el.innerHTML = `<div class="msg-text">${icon('trash', 13)} This message was deleted</div>`;
    return el;
  }

  let html = '<div class="swipe-hint">' + icon('reply', 16) + '</div>';

  // Author line for inbound group messages, only on the first of a run.
  if (isGroup && !out && !grouped && msg.senderId) {
    const name = displayNameFor(msg.senderId);
    html += `<div class="msg-author" style="--author-h:${authorHue(msg.senderId)}">${escapeHTML(name)}</div>`;
  }

  // Provenance. Forwarding strips the original author, so without this a
  // quote passed along reads as though the person who forwarded it wrote it.
  if (msg.forwarded) {
    html += `<div class="msg-forwarded">${icon('forward', 12)}<span>Forwarded</span></div>`;
  }

  if (msg.replyTo) {
    html += `
      <button class="quote" data-jump="${escapeAttr(String(msg.replyTo.index))}" data-jump-sender="${escapeAttr(msg.replyTo.sender || '')}">
        <span class="quote-author">${escapeHTML(msg.replyTo.sender === 'me' ? 'You' : displayNameFor(msg.replyTo.senderId) || 'Reply')}</span>
        <span class="quote-body">${escapeHTML(truncate(msg.replyTo.text || 'Attachment', 60))}</span>
      </button>`;
  }

  html += renderContent(msg);

  const ticks = out ? statusTick(msg.status) : '';
  html += `
    <div class="msg-meta">
      ${msg.edited ? '<span class="msg-edited">edited</span>' : ''}
      <span>${formatTime(msg.timestamp)}</span>
      ${ticks}
    </div>`;

  html += renderReactions(msg);
  html += renderTools(msg, out);

  el.innerHTML = html;

  if (msg.type === 'file' && msg.file && isImage(msg.file.mime) && State.settings.autoDownloadImages) {
    hydrateImage(el, msg);
  }
  return el;
}

/* ------------------------------------------------------ contact presence */

// A contact who crashes, loses power, or force-quits never gets to say
// "offline". Treat a stale claim as unknown rather than as truth, so nobody
// is shown online indefinitely on the strength of one old frame.
const ONLINE_TTL_MS = 10 * 60 * 1000;

export function isOnline(contact) {
  if (!contact || !contact.online || !contact.lastSeen) return false;
  return Date.now() - contact.lastSeen < ONLINE_TTL_MS;
}

/** "Online", "Last seen 5m ago", or '' when the peer has never reported. */
export function presenceLabel(contact) {
  if (!contact) return '';
  if (isOnline(contact)) return 'Online';
  if (!contact.lastSeen) return '';
  return `Last seen ${relativeTime(contact.lastSeen)}`;
}

// Stable per-author hue for group messages, derived the same way as avatars.
// Only the hue travels inline; style.css picks a lightness per theme.
function authorHue(id) {
  let hash = 0;
  for (let i = 0; i < String(id).length; i++) hash = (hash * 31 + id.charCodeAt(i)) >>> 0;
  return hash % 360;
}

/**
 * The read indicator on an outgoing message.
 *
 * Three styles, chosen in Settings:
 *   eye     a lid that opens once the message has actually been seen
 *   ticks   the classic one/two check marks
 *   none    nothing at all
 *
 * The eye is one inline SVG holding both states; CSS decides which is drawn,
 * so the closed→open change is a transition on a live element rather than a
 * swap between two different icons. `.just-seen` (added by refreshMessage on
 * the real transition) is what plays the opening animation. Without it a
 * re-render of old history would blink every eye on the page.
 */
function statusTick(status) {
  const style = State.settings.receiptStyle || 'eye';
  if (style === 'none') return '';
  // 'offline' is still being retried by the outbox; 'failed' has given up and
  // is waiting for the user. Both look wrong on purpose, but only one of them
  // is actually stuck, and only that one offers a retry.
  if (status === 'offline') {
    return `<span class="tick failed" title="Not sent yet, retrying">${icon('alert', 13)}</span>`;
  }
  if (status === 'failed') {
    return `<button class="tick failed" data-retry title="Could not send. Tap to try again" aria-label="Retry sending">${icon('alert', 13)}</button>`;
  }
  if (style === 'ticks') {
    if (status === 'sending') return `<span class="tick">${icon('clock', 12)}</span>`;
    return legacyTicks(status);
  }

  // Anything short of "read" is a shut eye, including still-in-flight. The
  // bubble already carries `.pending` while sending, so a separate clock adds
  // nothing, and showing one would mean the closed eye never appears at all
  // on a slow or unacknowledged send.
  const seen = status === 'read';
  const label = seen
    ? 'Seen'
    : status === 'delivered' ? 'Delivered, not seen yet'
    : status === 'queued' ? 'Queued, not seen yet'
    : 'Sending';
  return `
    <span class="seen${seen ? ' is-seen' : ''}" title="${label}" role="img" aria-label="${label}">
      <svg viewBox="0 0 24 24" width="15" height="15" fill="none" aria-hidden="true">
        <path class="seen-lid" d="M3.2 10.6 Q12 17.6 20.8 10.6"/>
        <path class="seen-open" d="M1.5 12s4-7.5 10.5-7.5S22.5 12 22.5 12s-4 7.5-10.5 7.5S1.5 12 1.5 12z"/>
        <circle class="seen-iris" cx="12" cy="12" r="3"/>
        <circle class="seen-pupil" cx="12" cy="12" r="1.1"/>
      </svg>
    </span>`;
}

function legacyTicks(status) {
  if (status === 'read') return `<span class="tick read">${icon('check', 13)}${icon('check', 13)}</span>`;
  if (status === 'delivered') return `<span class="tick">${icon('check', 13)}${icon('check', 13)}</span>`;
  return `<span class="tick">${icon('check', 13)}</span>`;
}

function renderContent(msg) {
  if (msg.type === 'sticker') {
    return `<div class="sticker-glyph">${escapeHTML(msg.text)}</div>`;
  }

  if (msg.type === 'voice-memo' && msg.file) {
    const bars = Array.from({ length: 28 }, (_, i) => {
      // Deterministic pseudo-waveform: real amplitude data isn't retained,
      // but a stable shape per memo reads better than a flat bar.
      const h = 22 + ((i * 37 + (msg.messageIndex || 0) * 13) % 60);
      return `<i class="voice-bar" style="height:${h}%"></i>`;
    }).join('');
    return `
      <div class="voice" data-voice="${escapeAttr(msg.file.url)}"
           data-key="${escapeAttr(msg.file.key)}" data-iv="${escapeAttr(msg.file.iv)}">
        <button type="button" class="voice-play" data-voice-play>${icon('play', 16)}</button>
        <div class="voice-body">
          <div class="voice-wave" data-voice-seek>${bars}</div>
          <div class="voice-time" data-voice-time>${escapeHTML(msg.file.duration || '0:00')}</div>
        </div>
      </div>`;
  }

  if (msg.type === 'file' && msg.file) {
    if (isImage(msg.file.mime)) {
      return `
        <img class="img-attach loading" alt="${escapeAttr(msg.file.name || 'Image')}"
             data-img data-url="${escapeAttr(msg.file.url)}"
             data-key="${escapeAttr(msg.file.key)}" data-iv="${escapeAttr(msg.file.iv)}"
             data-name="${escapeAttr(msg.file.name || 'image')}">
        ${msg.text ? `<div class="msg-text">${richText(msg.text)}</div>` : ''}`;
    }
    return `
      <button type="button" class="attach" data-file
              data-url="${escapeAttr(msg.file.url)}" data-key="${escapeAttr(msg.file.key)}"
              data-iv="${escapeAttr(msg.file.iv)}" data-name="${escapeAttr(msg.file.name || 'file')}"
              data-mime="${escapeAttr(msg.file.mime || 'application/octet-stream')}">
        <span class="attach-icon">${icon('file', 18)}</span>
        <span class="attach-info">
          <span class="attach-name">${escapeHTML(msg.file.name || 'File')}</span>
          <span class="attach-sub">${formatBytes(msg.file.size)} · Tap to download</span>
        </span>
      </button>
      ${msg.text ? `<div class="msg-text">${richText(msg.text)}</div>` : ''}`;
  }

  return `<div class="msg-text">${richText(msg.text || '')}</div>`;
}

function renderReactions(msg) {
  const reactions = normalizeReactions(msg);
  if (!reactions) return '';
  const entries = Object.entries(reactions).filter(([, who]) => who.length > 0);
  if (entries.length === 0) return '';

  const me = State.currentUser ? State.currentUser.idPub : '';
  return `<div class="reactions">${entries.map(([emoji, who]) => `
    <button type="button" class="reaction${who.includes(me) ? ' mine' : ''}" data-react="${escapeAttr(emoji)}">
      <span>${escapeHTML(emoji)}</span>
      ${who.length > 1 ? `<span class="reaction-count">${who.length}</span>` : ''}
    </button>`).join('')}</div>`;
}

function renderTools(msg, out) {
  const canEdit = out && msg.type === 'text';
  return `
    <div class="msg-tools">
      <button class="tool-btn" data-tool="react" title="React">${icon('smile', 15)}</button>
      <button class="tool-btn" data-tool="reply" title="Reply">${icon('reply', 15)}</button>
      <button class="tool-btn" data-tool="forward" title="Forward">${icon('forward', 15)}</button>
      ${canEdit ? `<button class="tool-btn" data-tool="edit" title="Edit">${icon('edit', 15)}</button>` : ''}
      <button class="tool-btn" data-tool="more" title="More">${icon('more', 15)}</button>
    </div>`;
}

async function hydrateImage(el, msg) {
  const img = el.querySelector('[data-img]');
  if (!img) return;
  const cacheKey = msg.file.url;
  try {
    let url = State.decryptedImages[cacheKey];
    if (!url) {
      const plain = await fetchAndDecrypt(msg.file.url, msg.file.key, msg.file.iv);
      url = URL.createObjectURL(new Blob([plain], { type: msg.file.mime }));
      State.decryptedImages[cacheKey] = url;
    }
    img.src = url;
    img.classList.remove('loading');
  } catch {
    img.classList.remove('loading');
    img.replaceWith(Object.assign(document.createElement('div'), {
      className: 'msg-text',
      textContent: 'Image unavailable'
    }));
  }
}

/* ------------------------------------------------------- live append path */

export function appendMessage(msg) {
  const list = document.getElementById('msg-list');
  const conv = conversationFor(State.activeContactId);
  if (!list || !conv) return;

  // Replace the empty state on the first message.
  const empty = list.querySelector('.empty');
  if (empty) { empty.remove(); list.appendChild(buildTypingEl()); }

  const typing = document.getElementById('typing');
  const nearBottom = isNearBottom(list);

  const msgs = messagesFor(conv.id);
  const prev = msgs[msgs.length - 2] || null;

  // Insert a day separator if this message crossed midnight.
  if (!prev || dayKey(prev.timestamp) !== dayKey(msg.timestamp)) {
    const sep = document.createElement('div');
    sep.className = 'day-sep';
    sep.textContent = dayLabel(msg.timestamp);
    list.insertBefore(sep, typing);
  }

  const el = buildMessageEl(msg, conv, prev, true);
  list.insertBefore(el, typing);

  if (msg.sender === 'me' || nearBottom) scrollToBottom(true);
  else bumpJumpCount();
  updateJumpButton();
}

/** Re-renders a single bubble in place after an edit/delete/reaction. */
export function refreshMessage(msg) {
  const list = document.getElementById('msg-list');
  const conv = conversationFor(State.activeContactId);
  if (!list || !conv || msg.contactId !== conv.id) return;

  const existing = list.querySelector(
    `.msg[data-msg-index="${CSS.escape(String(msg.messageIndex))}"][data-msg-sender="${msg.sender}"]`
  );
  if (!existing) return;

  const msgs = messagesFor(conv.id);
  const at = msgs.indexOf(msg);
  const wasRead = existing.dataset.status === 'read';
  const fresh = buildMessageEl(msg, conv, at > 0 ? msgs[at - 1] : null);
  fresh.style.animation = 'none';

  // Play the eye-opening animation only when the message has just been seen.
  // Every other re-render (edit, reaction, delete) leaves the eye static.
  if (!wasRead && msg.status === 'read') {
    fresh.querySelector('.seen')?.classList.add('just-seen');
  }
  existing.replaceWith(fresh);
}

/* ------------------------------------------------------------- scrolling */

const NEAR_BOTTOM_PX = 130;

export function isNearBottom(list) {
  if (!list) return true;
  return list.scrollHeight - list.scrollTop - list.clientHeight < NEAR_BOTTOM_PX;
}

export function scrollToBottom(smooth = false) {
  const list = document.getElementById('msg-list');
  if (!list) return;
  if (smooth) list.scrollTo({ top: list.scrollHeight, behavior: 'smooth' });
  else list.scrollTop = list.scrollHeight;
  updateJumpButton();
}

function updateJumpButton() {
  const list = document.getElementById('msg-list');
  const btn = document.getElementById('jump-btn');
  if (!list || !btn) return;
  const show = !isNearBottom(list);
  btn.classList.toggle('show', show);
  if (!show) {
    btn.dataset.count = '0';
    const c = btn.querySelector('.jump-count');
    if (c) c.remove();
  }
}

function bumpJumpCount() {
  const btn = document.getElementById('jump-btn');
  if (!btn) return;
  const n = (parseInt(btn.dataset.count, 10) || 0) + 1;
  btn.dataset.count = String(n);
  let c = btn.querySelector('.jump-count');
  if (!c) {
    c = document.createElement('span');
    c.className = 'jump-count';
    btn.appendChild(c);
  }
  c.textContent = n > 9 ? '9+' : String(n);
}

export function jumpToMessage(index, sender) {
  const list = document.getElementById('msg-list');
  if (!list) return;
  const el = list.querySelector(
    `.msg[data-msg-index="${CSS.escape(String(index))}"]${sender ? `[data-msg-sender="${sender}"]` : ''}`
  );
  if (!el) { toast('That message is no longer here'); return; }
  el.scrollIntoView({ behavior: 'smooth', block: 'center' });
  el.classList.add('highlight');
  setTimeout(() => el.classList.remove('highlight'), 2400);
}

/* ------------------------------------------------------- typing indicator */

export function showTyping(convId, typistId = null) {
  if (State.activeContactId !== convId) return;
  const el = document.getElementById('typing');
  if (!el) return;

  if (isGroupId(convId) && typistId) {
    if (!State.groupTypists[convId]) State.groupTypists[convId] = {};
    const typists = State.groupTypists[convId];
    clearTimeout(typists[typistId]);
    typists[typistId] = setTimeout(() => {
      delete typists[typistId];
      renderGroupTyping(convId);
    }, 3000);
    renderGroupTyping(convId);
    return;
  }

  el.classList.remove('hidden');
  const who = document.getElementById('typing-who');
  if (who) who.hidden = true;
  clearTimeout(State.typingContacts[convId]);
  State.typingContacts[convId] = setTimeout(() => el.classList.add('hidden'), 3000);
}

function renderGroupTyping(groupId) {
  if (State.activeContactId !== groupId) return;
  const el = document.getElementById('typing');
  const who = document.getElementById('typing-who');
  if (!el || !who) return;

  const ids = Object.keys(State.groupTypists[groupId] || {});
  if (ids.length === 0) { el.classList.add('hidden'); return; }

  const names = ids.map(displayNameFor);
  let text;
  if (names.length === 1) text = `${names[0]} is typing`;
  else if (names.length === 2) text = `${names[0]} and ${names[1]} are typing`;
  else text = `${names[0]} and ${names.length - 1} others are typing`;

  who.textContent = text;
  who.hidden = false;
  el.classList.remove('hidden');
}

/* ------------------------------------------------------------- bindings */

function bindChatHeader(conv) {
  const back = document.getElementById('chat-back');
  if (back) back.onclick = () => hooks.onBack();

  const info = document.getElementById('chat-head-info');
  if (info) info.onclick = () => hooks.onOpenProfile(conv.id);

  const jump = document.getElementById('jump-btn');
  if (jump) jump.onclick = () => scrollToBottom(true);

  const list = document.getElementById('msg-list');
  if (list) list.addEventListener('scroll', updateJumpButton, { passive: true });

  if (conv.kind === 'dm') {
    const v = document.getElementById('btn-voice-call');
    const c = document.getElementById('btn-video-call');
    if (v) v.onclick = () => hooks.onStartCall(conv.id, false);
    if (c) c.onclick = () => hooks.onStartCall(conv.id, true);
  }

  const menuBtn = document.getElementById('btn-chat-menu');
  if (menuBtn) menuBtn.onclick = () => openChatMenu(menuBtn, conv);

  bindChatSearch(conv);

  const reset = document.getElementById('session-reset');
  if (reset) {
    reset.onclick = async () => {
      const ok = await confirmDialog({
        title: 'Reset the secure session?',
        body: `The next message you send ${escapeHTML(conv.name)} will negotiate fresh keys. `
          + 'Anything of theirs that failed to decrypt stays unreadable, and your saved '
          + 'history is untouched.',
        confirmLabel: 'Reset session'
      });
      if (!ok) return;
      resetSession(conv.id);
      renderChatArea();
      toast('Session reset. Send a message to re-establish it.', { type: 'ok' });
    };
  }
}

/* ---------------------------------------------------- in-chat search */

/**
 * Find-in-conversation.
 *
 * The global search modal answers "where did we discuss X"; this answers
 * "where in this thread", which is a different job and the one you want with
 * a conversation already open.
 *
 * Matches are marked at bubble level rather than by wrapping the matched
 * substring. Bubble content is assembled as an HTML string by richText(),
 * which escapes and linkifies as it goes, so splicing <mark> into the result
 * afterwards would mean pattern-matching finished HTML and risking a match
 * inside a tag or an href. Highlighting the whole bubble is honest about what
 * it found and cannot be tricked into injecting anything.
 */
function bindChatSearch(conv) {
  const bar = document.getElementById('chat-search');
  const input = document.getElementById('chat-search-input');
  const count = document.getElementById('chat-search-count');
  const openBtn = document.getElementById('btn-chat-search');
  if (!bar || !input || !openBtn) return;

  let hits = [];
  let cursor = -1;

  const clearMarks = () => {
    document.querySelectorAll('#msg-list .search-hit, #msg-list .search-current')
      .forEach((el) => el.classList.remove('search-hit', 'search-current'));
  };

  const focusHit = (i) => {
    if (!hits.length) return;
    cursor = (i + hits.length) % hits.length;
    document.querySelectorAll('#msg-list .search-current')
      .forEach((el) => el.classList.remove('search-current'));
    const el = hits[cursor];
    el.classList.add('search-current');
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    count.textContent = `${cursor + 1}/${hits.length}`;
  };

  const run = () => {
    const q = input.value.trim().toLowerCase();
    clearMarks();
    hits = [];
    cursor = -1;

    if (!q) { count.textContent = ''; return; }

    // Search the rendered bubbles, so what is searched is exactly what is on
    // screen: captions, edits and tombstones included, without a second
    // source of truth to keep in step with the message model.
    document.querySelectorAll('#msg-list .msg').forEach((el) => {
      if (el.textContent.toLowerCase().includes(q)) {
        el.classList.add('search-hit');
        hits.push(el);
      }
    });

    if (!hits.length) { count.textContent = 'No matches'; return; }
    // Newest first: the most recent mention is nearly always the one wanted.
    focusHit(hits.length - 1);
  };

  const close = () => {
    bar.classList.add('hidden');
    input.value = '';
    clearMarks();
    hits = [];
    count.textContent = '';
  };

  openBtn.onclick = () => {
    const opening = bar.classList.contains('hidden');
    bar.classList.toggle('hidden', !opening);
    if (opening) input.focus(); else close();
  };

  input.oninput = debounce(run, 180);
  input.onkeydown = (e) => {
    if (e.key === 'Enter') { e.preventDefault(); focusHit(cursor + (e.shiftKey ? -1 : 1)); }
    // Swallowed so it closes the search rather than the conversation, and so
    // it never reaches the triple-Escape panic-wipe counter.
    if (e.key === 'Escape') { e.stopPropagation(); close(); }
  };
  document.getElementById('chat-search-next').onclick = () => focusHit(cursor + 1);
  document.getElementById('chat-search-prev').onclick = () => focusHit(cursor - 1);
  document.getElementById('chat-search-close').onclick = close;
  void conv;
}

function openChatMenu(anchor, conv) {
  const meta = metaFor(conv.id);
  const muted = conv.kind === 'group' ? conv.group.muted : conv.contact.muted;

  openPopover(anchor, `
    <div class="menu">
      ${conv.kind === 'group'
        ? `<button class="menu-item" data-act="members">${icon('users', 16)}Group members</button>`
        : `<button class="menu-item" data-act="verify">${icon('shield', 16)}Verify safety number</button>`}
      <button class="menu-item" data-act="pin">${icon('pin', 16)}${meta.pinned ? 'Unpin' : 'Pin to top'}</button>
      <button class="menu-item" data-act="mute">${icon(muted ? 'bell' : 'bell-off', 16)}${muted ? 'Unmute' : 'Mute'}</button>
      <button class="menu-item" data-act="ttl">${icon('clock', 16)}Disappearing messages<span class="shortcut">${ttlFor(conv.id) ? ttlLabel(ttlFor(conv.id)) : 'Off'}</span></button>
      <div class="menu-sep"></div>
      <button class="menu-item" data-act="clear">${icon('trash', 16)}Clear messages</button>
      <button class="menu-item danger" data-act="delete">${icon('logout', 16)}${conv.kind === 'group' ? 'Leave group' : 'Delete chat'}</button>
    </div>
  `, {
    onMount(pop, close) {
      const on = (act, fn) => {
        const b = pop.querySelector(`[data-act="${act}"]`);
        if (b) b.onclick = () => { close(); fn(); };
      };
      on('members', () => hooks.onOpenProfile(conv.id));
      on('verify', () => hooks.onOpenProfile(conv.id));
      on('pin', () => { meta.pinned = !meta.pinned; persist.chatMeta(); renderChatList(); });
      on('mute', () => toggleMute(conv.id));
      on('ttl', () => openTtlPicker(conv));
      on('clear', () => clearMessages(conv));
      on('delete', () => deleteConversation(conv.id));
    }
  });
}

function openTtlPicker(conv) {
  const options = [
    { label: 'Off', value: 0 },
    { label: '1 hour', value: 3600000 },
    { label: '8 hours', value: 28800000 },
    { label: '1 day', value: 86400000 },
    { label: '1 week', value: 604800000 }
  ];
  const current = ttlFor(conv.id);

  openModal({
    title: 'Disappearing messages',
    body: `
      <p style="color:var(--fg-muted);margin-bottom:var(--sp-4);line-height:1.6">
        New messages in this conversation will be removed from this device after the chosen time.
        This is a local sweep. It does not force deletion on the other device.
      </p>
      <div class="card">
        ${options.map((o) => `
          <button class="row" data-ttl="${o.value}">
            <div class="row-main"><div class="row-title">${o.label}</div></div>
            <div class="row-ctl">${o.value === current ? `<span style="color:var(--accent)">${icon('check', 18)}</span>` : ''}</div>
          </button>`).join('')}
      </div>`,
    onMount(root, close) {
      root.querySelectorAll('[data-ttl]').forEach((b) => {
        b.onclick = () => {
          metaFor(conv.id).ttl = Number(b.dataset.ttl);
          persist.chatMeta();
          close();
          renderChatArea();
          toast(Number(b.dataset.ttl) ? 'Disappearing messages on' : 'Disappearing messages off', { type: 'ok' });
        };
      });
    }
  });
}

async function clearMessages(conv) {
  const ok = await confirmDialog({
    title: 'Clear messages?',
    message: `All messages in this conversation will be erased from this device. ${conv.name}'s copy is unaffected.`,
    confirmLabel: 'Clear',
    danger: true
  });
  if (!ok) return;
  State.messages = State.messages.filter((m) => m.contactId !== conv.id);
  persist.messages();
  renderChatArea();
  renderChatList();
  toast('Messages cleared', { type: 'ok' });
}

/* ------------------------------------------------------------- composer */

const saveDraftSoon = debounce(() => persist.drafts(), 400);

function bindComposer(conv) {
  const form = document.getElementById('composer');
  const input = document.getElementById('composer-input');
  const sendBtn = document.getElementById('btn-send');
  const fileInput = document.getElementById('file-input');
  if (!form || !input) return;

  // Restore any draft for this conversation.
  const draft = State.drafts[conv.id] || '';
  if (draft) input.value = draft;
  autosize(input);
  sendBtn.classList.toggle('show', input.value.trim().length > 0);

  const refreshSendBtn = () => sendBtn.classList.toggle('show', input.value.trim().length > 0);

  input.addEventListener('input', () => {
    autosize(input);
    refreshSendBtn();

    const v = input.value;
    if (v.trim()) State.drafts[conv.id] = v; else delete State.drafts[conv.id];
    saveDraftSoon();

    if (State.settings.sendTypingIndicators && !State.isTypingTimer) {
      sendControl(conv.id, 'typing', { isTyping: true });
    }
    clearTimeout(State.isTypingTimer);
    State.isTypingTimer = setTimeout(() => { State.isTypingTimer = null; }, 2000);
  });

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const wantsSend = State.settings.enterToSend ? !e.shiftKey : (e.ctrlKey || e.metaKey);
      if (wantsSend) { e.preventDefault(); form.requestSubmit(); }
    }
    // Up-arrow on an empty composer edits your last message, like a shell.
    if (e.key === 'ArrowUp' && input.value === '' && !State.editingMessage) {
      const mine = messagesFor(conv.id).filter((m) => m.sender === 'me' && m.type === 'text' && !m.deleted);
      const last = mine[mine.length - 1];
      if (last) { e.preventDefault(); beginEdit(last); }
    }
    if (e.key === 'Escape' && (State.replyingTo || State.editingMessage)) {
      e.stopPropagation();
      clearContext();
    }
  });

  // Paste-to-upload for images and files on the clipboard.
  input.addEventListener('paste', (e) => {
    const items = Array.from(e.clipboardData?.items || []);
    const files = items.filter((i) => i.kind === 'file').map((i) => i.getAsFile()).filter(Boolean);
    if (files.length) { e.preventDefault(); confirmAttachments(files, conv); }
  });

  form.onsubmit = (e) => { e.preventDefault(); submitComposer(conv); };

  document.getElementById('btn-attach').onclick = () => fileInput.click();
  fileInput.onchange = () => {
    confirmAttachments(Array.from(fileInput.files || []), conv);
    fileInput.value = '';
  };

  document.getElementById('btn-mic').onclick = () => hooks.onToggleVoiceRecording();
  document.getElementById('btn-emoji').onclick = (e) => openEmojiPicker(e.currentTarget, (emoji) => {
    input.value += emoji;
    input.focus();
    autosize(input);
    refreshSendBtn();
    State.drafts[conv.id] = input.value;
    saveDraftSoon();
  }, false, (emoji) => sendSticker(emoji));

  document.getElementById('context-cancel').onclick = clearContext;
  updateContextBar();

  bindDragAndDrop(conv);
}

function autosize(el) {
  el.style.height = 'auto';
  el.style.height = `${Math.min(el.scrollHeight, 168)}px`;
}

function bindDragAndDrop(conv) {
  const root = document.getElementById('detail');
  if (!root) return;
  let depth = 0;

  const veil = () => {
    let v = root.querySelector('.drop-veil');
    if (!v) {
      v = document.createElement('div');
      v.className = 'drop-veil';
      v.innerHTML = `<div style="text-align:center">${icon('download', 30)}<div style="margin-top:8px">Drop to send</div></div>`;
      root.appendChild(v);
    }
    return v;
  };

  root.addEventListener('dragenter', (e) => {
    if (!Array.from(e.dataTransfer?.types || []).includes('Files')) return;
    e.preventDefault(); depth++; veil();
  });
  root.addEventListener('dragover', (e) => {
    if (!Array.from(e.dataTransfer?.types || []).includes('Files')) return;
    e.preventDefault();
  });
  root.addEventListener('dragleave', () => {
    depth = Math.max(0, depth - 1);
    if (depth === 0) root.querySelector('.drop-veil')?.remove();
  });
  root.addEventListener('drop', (e) => {
    if (!Array.from(e.dataTransfer?.types || []).includes('Files')) return;
    e.preventDefault();
    depth = 0;
    root.querySelector('.drop-veil')?.remove();
    confirmAttachments(Array.from(e.dataTransfer.files || []), conv);
  });
}

/* ------------------------------------------------------------ send paths */

function baseMessage(conv, overrides) {
  return {
    contactId: conv.id,
    senderId: State.currentUser.idPub,
    sender: 'me',
    type: 'text',
    text: '',
    file: null,
    timestamp: Date.now(),
    status: 'sending',
    messageIndex: Date.now(),
    replyTo: null,
    expiresAt: expiryFor(conv.id),
    localId: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    ...overrides
  };
}

/**
 * Dispatches a content payload over the right transport.
 *
 * Async because opening a protocol-v2 session fetches a prekey bundle first.
 * Callers render the bubble optimistically and patch its status when this
 * resolves, so the UI never waits on the network.
 */
/**
 * Mints the id a message keeps for its whole life, including every retry.
 *
 * It has to exist before the payload is built, because it travels inside the
 * ciphertext as `_lid`: that is what lets the recipient recognise a retry as a
 * duplicate instead of storing it twice.
 */
function newLocalId() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

async function dispatch(conv, payloadObj, localId) {
  // Every outbound content message funnels through here: text, files,
  // stickers, voice notes. This is the one place the send cue belongs.
  playCue('send');
  const withId = localId ? { ...payloadObj, _lid: localId } : payloadObj;

  if (conv.kind === 'group') {
    // One bubble, N envelopes: keep every token so an ack for any of them
    // clears the bubble's "sending" state.
    const refs = await sendGroupMessage(conv.id, withId);
    const success = refs.length > 0;
    if (localId) hooks.onSendResult(localId, conv.id, withId, success);
    mirrorToMyDevices(conv.id, withId, localId, success);
    return { success, messageIndex: Date.now(), refs };
  }

  const result = await sendE2EPayload(conv.id, withId, undefined, true);
  if (localId) hooks.onSendResult(localId, conv.id, withId, result.success);
  mirrorToMyDevices(conv.id, withId, localId, result.success);
  return result;
}

/**
 * Mirrors a sent message to this account's other devices.
 *
 * Only after the real send succeeded, and never awaited. A message that did
 * not go out has nothing to mirror, and a mirror that fails must not affect
 * the send: the recipient has it either way, and reporting a failure because
 * your own laptop is asleep would be a lie about the thing that matters.
 */
function mirrorToMyDevices(convId, payloadObj, localId, success) {
  if (!success) return;
  syncToMyDevices(convId, payloadObj, localId)
    .catch((err) => console.warn('[Sync] Mirror failed:', err && err.message));
}

async function submitComposer(conv) {
  const input = document.getElementById('composer-input');
  const text = input.value.trim();
  if (!text) return;

  if (State.editingMessage) { commitEdit(conv, text); return; }

  const payload = { type: 'text', text };
  if (State.replyingTo) payload.replyTo = State.replyingTo;
  const ttl = ttlFor(conv.id);
  if (ttl) payload.ttl = ttl;

  // Clear the composer immediately; the send itself may await a handshake.
  const replyingTo = State.replyingTo;
  input.value = '';
  autosize(input);
  document.getElementById('btn-send')?.classList.remove('show');
  delete State.drafts[conv.id];
  persist.drafts();
  State.replyingTo = null;
  updateContextBar();

  const localId = newLocalId();
  const { success, messageIndex, ref, refs } = await dispatch(conv, payload, localId);

  const msg = baseMessage(conv, {
    type: 'text',
    text,
    status: success ? 'sending' : 'offline',
    messageIndex, ref, refs, localId,
    replyTo: replyingTo
  });

  State.messages.push(msg);
  persist.messages();
  appendMessage(msg);
  renderChatList();
}

export async function sendSticker(emoji) {
  const conv = conversationFor(State.activeContactId);
  if (!conv) return;

  const payload = { type: 'sticker', emoji };
  const ttl = ttlFor(conv.id);
  if (ttl) payload.ttl = ttl;

  const localId = newLocalId();
  const { success, messageIndex, ref, refs } = await dispatch(conv, payload, localId);
  const msg = baseMessage(conv, {
    type: 'sticker', text: emoji, status: success ? 'sending' : 'offline', messageIndex, ref, refs, localId
  });

  State.messages.push(msg);
  persist.messages();
  appendMessage(msg);
  renderChatList();
}

/**
 * Confirms an attachment before it goes, and collects a caption.
 *
 * Everything that can produce an attachment funnels through here: the
 * paperclip, drag and drop, and paste. That matters most for paste and drop,
 * which used to fire the moment you let go, with no way back if you dropped
 * the wrong file into the wrong conversation.
 *
 * A batch shares one caption. Splitting them would mean a sheet per file,
 * which is worse for the common case of a handful of photos.
 */
function confirmAttachments(files, conv) {
  if (!files.length) return;

  // Thumbnails are local object URLs, revoked on the way out so a cancelled
  // sheet does not leak the blob.
  const objectUrls = [];
  const previews = files.map((f) => {
    let thumb = `<span class="attach-pre-icon">${icon('file', 20)}</span>`;
    if (isImage(f.type)) {
      const src = URL.createObjectURL(f);
      objectUrls.push(src);
      thumb = `<img class="attach-pre-img" src="${escapeAttr(src)}" alt="">`;
    }
    return `
      <div class="attach-pre">
        ${thumb}
        <span class="attach-pre-info">
          <span class="attach-pre-name">${escapeHTML(truncate(f.name, 34))}</span>
          <span class="attach-pre-size">${formatBytes(f.size)}</span>
        </span>
      </div>`;
  }).join('');

  openModal({
    title: files.length === 1 ? 'Send attachment' : `Send ${files.length} attachments`,
    body: `
      <div class="attach-pre-list scroll-y">${previews}</div>
      <label class="field">
        <span class="field-label">Caption${files.length > 1 ? ' (applies to all)' : ''}</span>
        <input class="input" id="attach-caption" maxlength="1000"
               placeholder="Optional" autocomplete="off">
      </label>`,
    footer: `
      <button class="btn" data-close>Cancel</button>
      <button class="btn btn-primary" id="attach-send">Send</button>`,
    onMount(root, close) {
      const input = root.querySelector('#attach-caption');
      const go = () => {
        const caption = input.value.trim();
        close();
        objectUrls.forEach((url) => URL.revokeObjectURL(url));
        files.forEach((f) => uploadAndSend(f, conv, caption));
      };
      root.querySelector('#attach-send').onclick = go;
      input.onkeydown = (e) => { if (e.key === 'Enter') { e.preventDefault(); go(); } };
      input.focus();
    }
  });
}

async function uploadAndSend(file, conv, caption = '') {
  if (file.size > MAX_UPLOAD_BYTES) {
    toast(`"${truncate(file.name, 24)}" is over the 50 MB limit`, { type: 'error' });
    return;
  }
  const dismiss = toast(`Encrypting ${truncate(file.name, 22)}…`, { duration: 60000 });

  try {
    const { url, key, iv } = await encryptAndUpload(file);
    const payload = {
      type: 'file', mime: file.type || 'application/octet-stream',
      name: file.name, size: file.size, url, key, iv
    };
    // The caption is just the message's text. A file bubble already renders
    // `text` under the image, so there is no second field to carry, nothing
    // new on the wire, and old clients show it without changes.
    if (caption) payload.text = caption;
    const ttl = ttlFor(conv.id);
    if (ttl) payload.ttl = ttl;

    const localId = newLocalId();
    const { success, messageIndex, ref, refs } = await dispatch(conv, payload, localId);
    const msg = baseMessage(conv, {
      type: 'file', text: caption || '', file: payload,
      status: success ? 'sending' : 'offline', messageIndex, ref, refs, localId
    });

    State.messages.push(msg);
    persist.messages();
    appendMessage(msg);
    renderChatList();
    dismiss();
  } catch (err) {
    dismiss();
    console.error('[Upload]', err);
    toast('Could not send that file', { type: 'error' });
  }
}

export async function sendVoiceMemo(payloadObj) {
  const conv = conversationFor(State.activeContactId);
  if (!conv) return;
  const ttl = ttlFor(conv.id);
  if (ttl) payloadObj.ttl = ttl;

  const localId = newLocalId();
  const { success, messageIndex, ref, refs } = await dispatch(conv, payloadObj, localId);
  const msg = baseMessage(conv, {
    type: 'voice-memo', text: '', file: payloadObj,
    status: success ? 'sending' : 'offline', messageIndex, ref, refs, localId
  });

  State.messages.push(msg);
  persist.messages();
  appendMessage(msg);
  renderChatList();
}

/* ------------------------------------------------------- reply/edit state */

function updateContextBar() {
  const bar = document.getElementById('context-bar');
  const label = document.getElementById('context-label');
  const text = document.getElementById('context-text');
  if (!bar) return;

  const mark = document.getElementById('context-mark');

  if (State.editingMessage) {
    label.textContent = 'Editing';
    text.textContent = truncate(State.editingMessage.text, 70);
    // The glyph carries the mode, so the label can stay short and quiet
    // instead of being the loud part of the bar.
    if (mark) mark.innerHTML = icon('edit', 15);
    bar.classList.add('is-edit');
    bar.classList.remove('hidden');
  } else if (State.replyingTo) {
    label.textContent = State.replyingTo.sender === 'me'
      ? 'Replying to yourself'
      : `Replying to ${displayNameFor(State.replyingTo.senderId)}`;
    text.textContent = truncate(State.replyingTo.text || 'Attachment', 70);
    if (mark) mark.innerHTML = icon('reply', 15);
    bar.classList.remove('is-edit');
    bar.classList.remove('hidden');
  } else {
    bar.classList.add('hidden');
  }
}

function clearContext() {
  const input = document.getElementById('composer-input');
  if (State.editingMessage && input) {
    input.value = '';
    autosize(input);
    document.getElementById('btn-send')?.classList.remove('show');
  }
  State.replyingTo = null;
  State.editingMessage = null;
  updateContextBar();
}

export function beginReply(msg) {
  State.editingMessage = null;
  State.replyingTo = {
    index: msg.messageIndex,
    sender: msg.sender,
    senderId: msg.senderId,
    text: previewFor(msg)
  };
  updateContextBar();
  document.getElementById('composer-input')?.focus();
}

function beginEdit(msg) {
  State.replyingTo = null;
  State.editingMessage = msg;
  const input = document.getElementById('composer-input');
  if (input) {
    input.value = msg.text;
    autosize(input);
    input.focus();
    input.setSelectionRange(input.value.length, input.value.length);
    document.getElementById('btn-send')?.classList.add('show');
  }
  updateContextBar();
}

function commitEdit(conv, text) {
  const msg = State.editingMessage;
  State.editingMessage = null;
  if (!msg) return;

  if (text !== msg.text) {
    msg.text = text;
    msg.edited = Date.now();
    persist.messages();
    refreshMessage(msg);
    // Control frame, notify:false. An edit must never wake a phone.
    sendControl(conv.id, 'edit', {
      targetIndex: msg.messageIndex, targetSender: msg.sender, text
    });
    renderChatList();
  }

  const input = document.getElementById('composer-input');
  if (input) { input.value = ''; autosize(input); }
  document.getElementById('btn-send')?.classList.remove('show');
  updateContextBar();
}

async function deleteForEveryone(conv, msg) {
  // The confirmation is skippable, but only by explicit opt-out in Settings.
  if (State.settings.confirmDelete !== false) {
    const ok = await confirmDialog({
      title: 'Delete for everyone?',
      message: 'This message will be replaced with a "deleted" placeholder on both devices. This cannot be undone.',
      confirmLabel: 'Delete for everyone',
      danger: true
    });
    if (!ok) return;
  }

  msg.deleted = true;
  msg.text = '';
  msg.file = null;
  delete msg.reactions;
  persist.messages();
  refreshMessage(msg);
  sendControl(conv.id, 'delete', { targetIndex: msg.messageIndex, targetSender: msg.sender });
  renderChatList();
  toast('Deleted for everyone', { type: 'ok' });
}

function deleteLocally(msg) {
  State.messages = State.messages.filter((m) => m !== msg);
  persist.messages();
  renderChatArea();
  renderChatList();
  toast('Removed from this device', { type: 'ok' });
}

/* ------------------------------------------------- message interactions */

function bindMessageInteractions(conv) {
  const list = document.getElementById('msg-list');
  if (!list) return;

  // Single delegated handler for every in-bubble control, keyed off the
  // data attributes rendered above. Replaces the old inline onclick markup.
  list.addEventListener('click', (e) => {
    const bubble = e.target.closest('.msg');

    const quote = e.target.closest('[data-jump]');
    if (quote) {
      jumpToMessage(Number(quote.dataset.jump), quote.dataset.jumpSender || null);
      return;
    }

    const reactionChip = e.target.closest('[data-react]');
    if (reactionChip && bubble) {
      applyReaction(conv, msgFromEl(bubble), reactionChip.dataset.react);
      return;
    }

    const tool = e.target.closest('[data-tool]');
    if (tool && bubble) {
      handleTool(conv, msgFromEl(bubble), tool.dataset.tool, tool);
      return;
    }

    const retry = e.target.closest('[data-retry]');
    if (retry && bubble) {
      const m = msgFromEl(bubble);
      if (m && m.localId) hooks.onRetryMessage(m.localId);
      return;
    }

    const fileBtn = e.target.closest('[data-file]');
    if (fileBtn) {
      downloadAttachment(fileBtn.dataset);
      return;
    }

    const img = e.target.closest('[data-img]');
    if (img && img.src) {
      openLightbox(img.src, img.dataset.name, img.dataset.name);
      return;
    }

    const play = e.target.closest('[data-voice-play]');
    if (play) {
      const holder = play.closest('[data-voice]');
      toggleVoicePlayback(holder);
    }
  });

  bindSwipeToReply(list, conv);
}

function msgFromEl(el) {
  return findMsg(State.activeContactId, Number(el.dataset.msgIndex), el.dataset.msgSender);
}

function handleTool(conv, msg, tool, anchor) {
  if (!msg) return;
  switch (tool) {
    case 'reply': beginReply(msg); break;
    case 'edit': beginEdit(msg); break;
    case 'forward': hooks.onForward(msg); break;
    case 'react':
      openEmojiPicker(anchor, (emoji) => applyReaction(conv, msg, emoji), true);
      break;
    case 'more':
      openPopover(anchor, `
        <div class="menu">
          <button class="menu-item" data-a="copy">${icon('copy', 16)}Copy text</button>
          <button class="menu-item" data-a="reply">${icon('reply', 16)}Reply</button>
          <button class="menu-item" data-a="forward">${icon('forward', 16)}Forward</button>
          <div class="menu-sep"></div>
          ${msg.sender === 'me' && !msg.deleted
            ? `<button class="menu-item danger" data-a="unsend">${icon('trash', 16)}Delete for everyone</button>` : ''}
          <button class="menu-item danger" data-a="local">${icon('trash', 16)}Delete for me</button>
        </div>`, {
        onMount(pop, close) {
          const on = (a, fn) => {
            const b = pop.querySelector(`[data-a="${a}"]`);
            if (b) b.onclick = () => { close(); fn(); };
          };
          on('copy', () => {
            navigator.clipboard.writeText(msg.text || '').then(
              () => toast('Copied', { type: 'ok' }),
              () => toast('Could not copy', { type: 'error' })
            );
          });
          on('reply', () => beginReply(msg));
          on('forward', () => hooks.onForward(msg));
          on('unsend', () => deleteForEveryone(conv, msg));
          on('local', () => deleteLocally(msg));
        }
      });
      break;
  }
}

function applyReaction(conv, msg, emoji) {
  if (!msg) return;
  closePopover();
  const me = State.currentUser.idPub;
  toggleReactionLocal(msg, emoji, me);
  persist.messages();
  refreshMessage(msg);
  sendControl(conv.id, 'reaction', {
    targetIndex: msg.messageIndex, targetSender: msg.sender, emoji
  });
}

async function downloadAttachment(data) {
  const dismiss = toast('Decrypting…', { duration: 30000 });
  try {
    const plain = await fetchAndDecrypt(data.url, data.key, data.iv);
    const url = URL.createObjectURL(new Blob([plain], { type: data.mime }));
    const a = document.createElement('a');
    a.href = url;
    a.download = data.name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    dismiss();
  } catch {
    dismiss();
    toast('That attachment is missing or could not be decrypted', { type: 'error' });
  }
}

/* --------------------------------------------------------- voice playback */

let activeAudio = null;
let activeHolder = null;

async function toggleVoicePlayback(holder) {
  if (!holder) return;
  const btn = holder.querySelector('[data-voice-play]');
  const timeEl = holder.querySelector('[data-voice-time]');
  const bars = Array.from(holder.querySelectorAll('.voice-bar'));

  if (activeHolder === holder && activeAudio) {
    if (activeAudio.paused) { activeAudio.play(); btn.innerHTML = icon('pause', 16); }
    else { activeAudio.pause(); btn.innerHTML = icon('play', 16); }
    return;
  }

  if (activeAudio) {
    activeAudio.pause();
    if (activeHolder) {
      activeHolder.querySelector('[data-voice-play]').innerHTML = icon('play', 16);
      activeHolder.querySelectorAll('.voice-bar').forEach((b) => b.classList.remove('played'));
    }
  }

  const url = holder.dataset.voice;
  btn.innerHTML = '<span class="spinner"></span>';

  try {
    let objectUrl = State.decryptedVoiceMemos[url];
    if (!objectUrl) {
      const plain = await fetchAndDecrypt(url, holder.dataset.key, holder.dataset.iv);
      objectUrl = URL.createObjectURL(new Blob([plain], { type: 'audio/webm' }));
      State.decryptedVoiceMemos[url] = objectUrl;
    }

    const audio = new Audio(objectUrl);
    activeAudio = audio;
    activeHolder = holder;

    audio.ontimeupdate = () => {
      if (!audio.duration) return;
      const pct = audio.currentTime / audio.duration;
      bars.forEach((b, i) => b.classList.toggle('played', i / bars.length <= pct));
      if (timeEl) timeEl.textContent = formatDuration(audio.currentTime);
    };
    audio.onplay = () => { btn.innerHTML = icon('pause', 16); };
    audio.onpause = () => { btn.innerHTML = icon('play', 16); };
    audio.onended = () => {
      btn.innerHTML = icon('play', 16);
      bars.forEach((b) => b.classList.remove('played'));
      if (timeEl) timeEl.textContent = formatDuration(audio.duration || 0);
      activeAudio = null;
      activeHolder = null;
    };

    const seek = holder.querySelector('[data-voice-seek]');
    if (seek) {
      seek.onclick = (e) => {
        if (!audio.duration) return;
        const r = seek.getBoundingClientRect();
        audio.currentTime = ((e.clientX - r.left) / r.width) * audio.duration;
      };
    }

    audio.play();
  } catch {
    btn.innerHTML = icon('play', 16);
    toast('Could not play that voice message', { type: 'error' });
  }
}

/* ------------------------------------------------------- swipe to reply */

function bindSwipeToReply(list, conv) {
  let swipe = null;
  const TRIGGER = 56;
  const MAX = 84;

  list.addEventListener('touchstart', (e) => {
    const bubble = e.target.closest('.msg');
    if (!bubble || bubble.classList.contains('tombstone')) return;
    swipe = { bubble, x: e.touches[0].clientX, y: e.touches[0].clientY, dx: 0, axis: null };
  }, { passive: true });

  list.addEventListener('touchmove', (e) => {
    if (!swipe) return;
    const dx = e.touches[0].clientX - swipe.x;
    const dy = e.touches[0].clientY - swipe.y;

    if (swipe.axis === null) {
      if (Math.abs(dx) < 6 && Math.abs(dy) < 6) return;
      swipe.axis = Math.abs(dx) > Math.abs(dy) ? 'x' : 'y';
    }
    if (swipe.axis === 'y') return;

    const clamped = Math.max(0, Math.min(dx, MAX));
    swipe.dx = clamped;
    swipe.bubble.classList.add('swiping');
    swipe.bubble.style.transform = `translateX(${clamped}px)`;
    swipe.bubble.classList.toggle('swipe-armed', clamped >= TRIGGER);
  }, { passive: true });

  const end = () => {
    if (!swipe) return;
    const { bubble, dx } = swipe;
    bubble.classList.remove('swiping', 'swipe-armed');
    bubble.style.transform = '';
    if (dx >= TRIGGER) {
      const msg = msgFromEl(bubble);
      if (msg) {
        beginReply(msg);
        if (navigator.vibrate) navigator.vibrate(8);
      }
    }
    swipe = null;
  };
  list.addEventListener('touchend', end);
  list.addEventListener('touchcancel', end);
  void conv;
}

/* ----------------------------------------------------------- emoji picker */

/**
 * @param onSticker  When supplied, the picker grows a "Send as sticker" toggle
 *   and routes picks there instead of into the composer. Only the composer
 *   passes it; the reaction picker has nowhere to send a sticker to.
 */
export function openEmojiPicker(anchor, onPick, quickOnly = false, onSticker = null) {
  if (quickOnly) {
    openPopover(anchor, `
      <div class="react-pop">
        ${QUICK_REACTIONS.map((e) => `<button class="emoji-cell" data-e="${escapeAttr(e)}">${e}</button>`).join('')}
        <button class="emoji-cell" data-more title="More">${icon('plus', 16)}</button>
      </div>`, {
      className: 'react-pop-wrap',
      onMount(pop, close) {
        pop.querySelectorAll('[data-e]').forEach((b) => {
          b.onclick = () => { close(); onPick(b.dataset.e); };
        });
        pop.querySelector('[data-more]').onclick = () => { close(); openEmojiPicker(anchor, onPick, false); };
      }
    });
    return;
  }

  const tabs = EMOJI_GROUPS.map((g, i) =>
    `<button class="emoji-tab${i === 0 ? ' active' : ''}" data-tab="${i}" title="${escapeAttr(g.label)}">${g.tab}</button>`
  ).join('');

  openPopover(anchor, `
    <div class="emoji-pop-inner" style="display:flex;flex-direction:column;gap:var(--sp-2);max-height:300px">
      <div class="emoji-tabs">${tabs}</div>
      <div class="emoji-grid scroll-y" id="emoji-grid"></div>
      ${onSticker ? `
        <button type="button" class="emoji-mode" id="emoji-sticker-mode"
                aria-pressed="false">
          ${icon('smile', 15)}<span>Send as sticker</span>
        </button>` : ''}
    </div>`, {
    className: 'emoji-pop',
    placement: 'up',
    onMount(pop, close) {
      const grid = pop.querySelector('#emoji-grid');
      const modeBtn = pop.querySelector('#emoji-sticker-mode');
      let stickerMode = false;

      const pick = (emoji) => {
        // A sticker is a whole message, so unlike an insert it ends the
        // interaction; the picker closes rather than staying open for more.
        if (stickerMode) { close(); onSticker(emoji); return; }
        onPick(emoji);
      };

      const paint = (i) => {
        grid.innerHTML = EMOJI_GROUPS[i].list
          .map((e) => `<button class="emoji-cell" data-e="${escapeAttr(e)}">${e}</button>`).join('');
        // Stays open so several emoji can be inserted in a row; Escape or an
        // outside click dismisses it.
        grid.querySelectorAll('[data-e]').forEach((b) => {
          b.onclick = () => pick(b.dataset.e);
        });
      };
      pop.querySelectorAll('[data-tab]').forEach((t) => {
        t.onclick = () => {
          pop.querySelectorAll('[data-tab]').forEach((x) => x.classList.remove('active'));
          t.classList.add('active');
          paint(Number(t.dataset.tab));
        };
      });
      if (modeBtn) {
        modeBtn.onclick = () => {
          stickerMode = !stickerMode;
          modeBtn.classList.toggle('active', stickerMode);
          modeBtn.setAttribute('aria-pressed', String(stickerMode));
          pop.querySelector('.emoji-grid').classList.toggle('sticker-mode', stickerMode);
        };
      }
      paint(0);
    }
  });
}
