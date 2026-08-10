// --- PROFILE & SETTINGS PANES, MODALS, APP LOCK ---

import {
  State, persist, metaFor, DEFAULT_SETTINGS, Storage, migrateVault
} from './store.js';
import {
  escapeHTML, escapeAttr, icon, avatarGradient, initials, truncate,
  relativeTime, formatBytes, debounce, setClockFormat
} from './util.js';
import { ACCENTS, THEMES, applyTheme, setSetting, resolvedTheme } from './theme.js';
import { previewCue } from './sound.js';
import { safetyNumber, hashPin, randomHex, encryptAndUpload } from './crypto-extra.js';
import {
  toast, openModal, closeModal, confirmDialog, promptDialog
} from './ui.js';
import {
  messagesFor, previewFor, isGroupId, syncContactsWithServer, unreadCount,
  blockedContacts, sessionInfo, canAdminGroup, renameGroup, setGroupMembers,
  fetchMyDevices, publishThisDevice, revokeDevice
} from './messaging.js';
import {
  decryptAndShowAvatar, avatarHTML, displayNameFor, renderChatList, renderChatArea
} from './views.js';
import { qrSVG } from './qr.js';
import {
  collectBackup, createBackup, openBackup, inspectBackup, mergeBackup, summarise,
  MIN_PASSPHRASE_LENGTH
} from './backup.js';

export const paneHooks = {
  onSelectConversation: () => {},
  onSyncProfile: () => {},
  onLogout: () => {},
  onPanicWipe: () => {},
  onEnablePush: () => {}
};

/* ============================================================ PROFILE PANE */

export function renderProfilePane() {
  const el = document.getElementById('profile-body');
  if (!el || !State.currentUser) return;

  const name = State.myProfile.nickname || State.currentUser.username;
  const id = State.currentUser.idPub;

  el.innerHTML = `
    <div class="settings-scroll" style="padding-top:0">
      <div class="settings-inner">
        <div class="profile-hero">
          <div class="avatar-wrap avatar-edit" id="avatar-edit" title="Change photo">
            ${avatarHTML(id, name, 'avatar-xl', 'my-avatar')}
            <span class="avatar-edit-icon">${icon('camera', 22)}</span>
          </div>
          <input type="file" id="avatar-file" accept="image/*" hidden>
          <div class="profile-name">${escapeHTML(name)}</div>
          ${State.myProfile.bio
            ? `<div class="profile-bio">${escapeHTML(State.myProfile.bio)}</div>`
            : `<div class="profile-bio" style="opacity:.6">No status set</div>`}
          <button class="btn btn-outline btn-sm" id="edit-profile">${icon('edit', 15)} Edit profile</button>
        </div>

        <div class="group">
          <div class="group-title">Your Client ID</div>
          <div class="card card-pad">
            <p style="font-size:var(--fs-sm);color:var(--fg-muted);margin-bottom:var(--sp-3);line-height:1.55">
              Share this with someone so they can add you. It is your public identity key, so it is safe to send over any channel.
            </p>
            <div class="keybox" id="my-id">${escapeHTML(id)}</div>
            <div style="display:flex;gap:var(--sp-2);margin-top:var(--sp-3);flex-wrap:wrap">
              <button class="btn btn-primary btn-sm" id="copy-id">${icon('copy', 15)} Copy ID</button>
              <button class="btn btn-sm" id="show-qr">${icon('image', 15)} QR code</button>
              <button class="btn btn-sm" id="share-id">${icon('forward', 15)} Share</button>
            </div>
          </div>
        </div>

        <div class="group">
          <div class="group-title">Account</div>
          <div class="card">
            <div class="row">
              <div class="row-icon">${icon('user', 17)}</div>
              <div class="row-main">
                <div class="row-title">Username</div>
                <div class="row-sub">Cannot be changed, because it salts your encryption key</div>
              </div>
              <div class="row-ctl"><span class="row-value">${escapeHTML(State.currentUser.username)}</span></div>
            </div>
            <div class="row">
              <div class="row-icon">${icon('database', 17)}</div>
              <div class="row-main">
                <div class="row-title">Conversations</div>
                <div class="row-sub">${State.contacts.length} contact${State.contacts.length === 1 ? '' : 's'} · ${State.groups.length} group${State.groups.length === 1 ? '' : 's'}</div>
              </div>
              <div class="row-ctl"><span class="row-value">${State.messages.length} msgs</span></div>
            </div>
            <button class="row danger" id="profile-logout">
              <div class="row-icon">${icon('logout', 17)}</div>
              <div class="row-main"><div class="row-title">Sign out</div>
                <div class="row-sub">Local history stays on this device</div></div>
            </button>
          </div>
        </div>
      </div>
    </div>
  `;

  if (State.myProfile.avatar) decryptAndShowAvatar(State.myProfile.avatar, document.getElementById('my-avatar'));

  document.getElementById('edit-profile').onclick = openProfileEditor;
  document.getElementById('avatar-edit').onclick = () => document.getElementById('avatar-file').click();
  document.getElementById('avatar-file').onchange = (e) => uploadAvatar(e.target.files[0]);
  document.getElementById('profile-logout').onclick = () => paneHooks.onLogout();

  document.getElementById('copy-id').onclick = () => {
    navigator.clipboard.writeText(State.currentUser.idPub).then(
      () => toast('Client ID copied', { type: 'ok' }),
      () => toast('Could not copy', { type: 'error' })
    );
  };
  document.getElementById('show-qr').onclick = openMyQr;
  document.getElementById('share-id').onclick = async () => {
    if (navigator.share) {
      try { await navigator.share({ title: 'My Talon ID', text: State.currentUser.idPub }); } catch {}
    } else {
      navigator.clipboard.writeText(State.currentUser.idPub);
      toast('Client ID copied', { type: 'ok' });
    }
  };
}

/**
 * One line describing what is actually protecting this conversation.
 *
 * Says post-quantum only when the handshake really mixed in ML-KEM. A peer on
 * an older client gets a working session with no KEM prekey, marked pq:false,
 * and claiming otherwise would be the kind of overstatement this project
 * exists to avoid.
 */
function sessionSummary(contactId) {
  const s = sessionInfo(contactId);
  if (!s.established) return 'Not established yet. Starts with your first message';
  if (s.version === 1) return 'Legacy v1 session. Upgrades on your next message';
  return s.postQuantum
    ? 'Double Ratchet with post-quantum hybrid key exchange (X25519 + ML-KEM-768)'
    : 'Double Ratchet, X25519 only. Their client has published no post-quantum prekey';
}

/**
 * The safety number as a picture.
 *
 * safetyNumber() sorts the two identity keys before hashing, so both devices
 * derive the same digits and therefore the same code. Holding two phones side
 * by side and seeing one image is a comparison people will actually perform;
 * reading out 60 digits is one they will not.
 *
 * Display only, exactly like the digits: nothing keys off this value.
 */
function safetyQr(digits) {
  try {
    return qrSVG(digits, { size: 132, margin: 2 });
  } catch {
    return '';
  }
}

/**
 * The add-me code.
 *
 * It encodes a link back to this relay with the Client ID in the fragment, so
 * the other phone can just point its camera at it: the built-in scanner opens
 * the link, Talon reads the fragment and pre-fills Add contact. That avoids
 * shipping a QR decoder and a camera permission prompt, and it beats
 * transcribing 64 hex characters by hand, which is the actual reason nobody
 * verifies anything.
 *
 * The fragment never leaves the browser, so the ID is not in the request the
 * relay serves. It is a public key either way, but there is no reason to put
 * it in an access log.
 */
function openMyQr() {
  const id = State.currentUser.idPub;
  const link = `${location.origin}/#add=${id}`;

  let svg;
  try {
    svg = qrSVG(link, { size: 232 });
  } catch {
    toast('Could not build the QR code', { type: 'error' });
    return;
  }

  openModal({
    title: 'Scan to add me',
    body: `
      <div class="qr-wrap">${svg}</div>
      <p class="qr-note">
        Point the other device's camera at this. It opens Talon on this relay
        with your Client ID already filled in.
      </p>
      <div class="keybox">${escapeHTML(id)}</div>`,
    footer: `
      <button class="btn" data-close>Close</button>
      <button class="btn btn-primary" id="qr-copy-link">${icon('copy', 15)} Copy link</button>`,
    onMount(root, close) {
      root.querySelector('#qr-copy-link').onclick = () => {
        navigator.clipboard.writeText(link).then(
          () => { close(); toast('Add link copied', { type: 'ok' }); },
          () => toast('Could not copy', { type: 'error' })
        );
      };
    }
  });
}

function openProfileEditor() {
  const name = State.myProfile.nickname || State.currentUser.username;
  openModal({
    title: 'Edit profile',
    body: `
      <div class="field">
        <label class="field-label" for="pf-name">Display name</label>
        <input class="input" id="pf-name" value="${escapeAttr(name)}" maxlength="40" data-autofocus>
      </div>
      <div class="field">
        <label class="field-label" for="pf-bio">Status</label>
        <textarea class="textarea" id="pf-bio" maxlength="140" placeholder="Say something about yourself">${escapeHTML(State.myProfile.bio || '')}</textarea>
        <div class="field-hint">Your name, status and photo are encrypted before being shared with your contacts. The server never sees them.</div>
      </div>`,
    footer: `
      <button class="btn" data-close>Cancel</button>
      <button class="btn btn-primary" id="pf-save">Save</button>`,
    onMount(root, close) {
      root.querySelector('#pf-save').onclick = () => {
        const nick = root.querySelector('#pf-name').value.trim();
        if (!nick) { toast('A display name is required', { type: 'error' }); return; }
        State.myProfile.nickname = nick;
        State.myProfile.bio = root.querySelector('#pf-bio').value.trim();
        persist.profile();
        paneHooks.onSyncProfile();
        renderProfilePane();
        close();
        toast('Profile saved', { type: 'ok' });
      };
    }
  });
}

async function uploadAvatar(file) {
  if (!file) return;
  if (!file.type.startsWith('image/')) { toast('Pick an image file', { type: 'error' }); return; }
  if (file.size > 5 * 1024 * 1024) { toast('Image must be under 5 MB', { type: 'error' }); return; }

  const dismiss = toast('Encrypting photo…', { duration: 30000 });
  try {
    State.myProfile.avatar = await encryptAndUpload(file);
    persist.profile();
    paneHooks.onSyncProfile();
    renderProfilePane();
    renderChatList();
    dismiss();
    toast('Photo updated', { type: 'ok' });
  } catch {
    dismiss();
    toast('Could not upload that photo', { type: 'error' });
  }
}

/* =========================================================== SETTINGS PANE */

/** A row whose control is a segmented picker over a fixed set of values. */
function rowSegmented(key, title, sub, iconName, options) {
  const current = State.settings[key];
  return `
    <div class="row row-wide-ctl">
      <div class="row-icon">${icon(iconName, 17)}</div>
      <div class="row-main">
        <div class="row-title">${escapeHTML(title)}</div>
        ${sub ? `<div class="row-sub">${escapeHTML(sub)}</div>` : ''}
      </div>
      <div class="row-ctl">
        <div class="segmented">
          ${options.map(([label, value]) => `
            <button class="segmented-btn${current === value ? ' active' : ''}"
                    data-choice="${escapeAttr(key)}"
                    data-value="${escapeAttr(String(value))}">${escapeHTML(label)}</button>`).join('')}
        </div>
      </div>
    </div>`;
}

/** A row whose control is a <select>, for sets too long to segment. */
function rowSelect(key, title, sub, iconName, options) {
  const current = State.settings[key];
  return `
    <div class="row">
      <div class="row-icon">${icon(iconName, 17)}</div>
      <div class="row-main">
        <div class="row-title">${escapeHTML(title)}</div>
        ${sub ? `<div class="row-sub">${escapeHTML(sub)}</div>` : ''}
      </div>
      <div class="row-ctl">
        <select class="select" data-select="${escapeAttr(key)}" style="width:150px;min-height:36px">
          ${options.map(([label, value]) => `
            <option value="${escapeAttr(String(value))}"${String(current) === String(value) ? ' selected' : ''}>${escapeHTML(label)}</option>`).join('')}
        </select>
      </div>
    </div>`;
}

function rowToggle(key, title, sub, iconName) {
  return `
    <div class="row">
      <div class="row-icon">${icon(iconName, 17)}</div>
      <div class="row-main">
        <div class="row-title">${escapeHTML(title)}</div>
        ${sub ? `<div class="row-sub">${escapeHTML(sub)}</div>` : ''}
      </div>
      <div class="row-ctl">
        <label class="switch">
          <input type="checkbox" data-toggle="${key}" ${State.settings[key] ? 'checked' : ''}>
          <span class="switch-track"></span>
        </label>
      </div>
    </div>`;
}

export function renderSettingsPane() {
  const el = document.getElementById('settings-body');
  if (!el) return;

  const s = State.settings;
  const pushSupported = 'Notification' in window && 'PushManager' in window;
  const pushGranted = pushSupported && Notification.permission === 'granted';

  el.innerHTML = `
    <div class="settings-scroll" style="padding-top:0">
      <div class="settings-inner">

        <div class="group">
          <div class="group-title">Appearance</div>
          <div class="card card-pad">
            <div class="field-label" style="margin-bottom:var(--sp-3)">Theme</div>
            <div class="theme-tiles">
              ${THEMES.map((t) => `
                <button class="theme-tile${s.theme === t.id ? ' active' : ''}" data-theme-pick="${t.id}">
                  <div class="theme-swatch t-${t.id}"><i></i><i></i></div>
                  <div class="theme-tile-label">${escapeHTML(t.label)}</div>
                </button>`).join('')}
            </div>
          </div>

          <div class="card card-pad">
            <div class="field-label" style="margin-bottom:var(--sp-3)">Accent</div>
            <div class="swatches">
              ${ACCENTS.map((a) => `
                <button class="swatch${s.accent === a.id ? ' active' : ''}" data-accent="${a.id}"
                        style="background:${a.css}" title="${escapeAttr(a.label)}" aria-label="${escapeAttr(a.label)}"></button>`).join('')}
            </div>
          </div>

          <div class="card">
            <div class="row row-wide-ctl">
              <div class="row-icon">${icon('palette', 17)}</div>
              <div class="row-main">
                <div class="row-title">Density</div>
                <div class="row-sub">How tightly rows and bubbles are packed</div>
              </div>
              <div class="row-ctl">
                <div class="segmented">
                  <button class="segmented-btn${s.density === 'cozy' ? ' active' : ''}" data-density="cozy">Cozy</button>
                  <button class="segmented-btn${s.density === 'compact' ? ' active' : ''}" data-density="compact">Compact</button>
                </div>
              </div>
            </div>
            <div class="row stacked">
              <div class="row-line">
                <div class="row-icon">${icon('text-size', 17)}</div>
                <div class="row-main">
                  <div class="row-title">Text size</div>
                  <div class="row-sub">Scales every label and message</div>
                </div>
                <span class="row-value" id="fs-value">${Math.round(s.fontScale * 100)}%</span>
              </div>
              <input class="range" type="range" id="font-scale" min="0.85" max="1.35" step="0.05" value="${s.fontScale}">
            </div>
            ${rowSegmented('bubbleCorners', 'Bubble corners', 'How rounded message bubbles are', 'chat',
              [['Round', 'round'], ['Soft', 'soft'], ['Square', 'square']])}
            ${rowSegmented('uiFont', 'Interface font', 'Applies to every label and message', 'text-size',
              [['Inter', 'inter'], ['System', 'system'], ['Mono', 'mono']])}
            <div class="row">
              <div class="row-icon">${icon('motion', 17)}</div>
              <div class="row-main">
                <div class="row-title">Reduce motion</div>
                <div class="row-sub">Disable animations and transitions</div>
              </div>
              <div class="row-ctl">
                <label class="switch">
                  <input type="checkbox" data-motion-toggle ${s.motion === 'reduced' ? 'checked' : ''}>
                  <span class="switch-track"></span>
                </label>
              </div>
            </div>
          </div>
        </div>

        <div class="group">
          <div class="group-title">Notifications</div>
          <div class="card">
            <div class="row">
              <div class="row-icon">${icon('bell', 17)}</div>
              <div class="row-main">
                <div class="row-title">Push notifications</div>
                <div class="row-sub">${!pushSupported
                  ? 'Not supported in this browser'
                  : pushGranted
                    ? 'Enabled. Notifications contain no message content'
                    : 'Get notified when the app is closed'}</div>
              </div>
              <div class="row-ctl">
                ${pushSupported && !pushGranted
                  ? `<button class="btn btn-sm btn-primary" id="enable-push">Enable</button>`
                  : pushGranted ? `<span style="color:var(--ok)">${icon('check', 18)}</span>` : ''}
              </div>
            </div>
            ${rowToggle('showPreviews', 'Show message previews', 'Display the last message in the chat list', 'chat')}
          </div>
        </div>

        <div class="group">
          <div class="group-title">Chats</div>
          <div class="card">
            ${rowToggle('enterToSend', 'Enter sends message', 'Otherwise Enter adds a newline and Ctrl+Enter sends', 'send')}
            ${rowToggle('sendReadReceipts', 'Send read receipts', 'Let others see when you have read their messages', 'check')}
            ${rowToggle('sendTypingIndicators', 'Send typing indicators', 'Let others see when you are typing', 'edit')}
            ${rowToggle('sharePresence', 'Share online status', 'Tell your contacts directly when you are online. The relay is not involved', 'user')}
            ${rowToggle('autoDownloadImages', 'Auto-load images', 'Decrypt and show images inline automatically', 'image')}
            ${rowToggle('spellcheck', 'Spell check', 'Let the browser check spelling as you type', 'edit')}
            ${rowToggle('confirmDelete', 'Confirm before deleting', 'Ask first when deleting a message', 'trash')}
            ${rowSegmented('clockFormat', 'Clock', 'Time format on message timestamps', 'clock',
              [['Auto', 'auto'], ['12h', '12'], ['24h', '24']])}
            ${rowSelect('defaultTtl', 'Default disappearing timer', 'Applied to conversations you start from now on', 'clock',
              [['Off', 0], ['1 hour', 3600000], ['8 hours', 28800000], ['1 day', 86400000],
               ['1 week', 604800000]])}
          </div>
        </div>

        <div class="group">
          <div class="group-title">Read receipts</div>
          <div class="card">
            ${rowSegmented('receiptStyle', 'Seen indicator', 'How to show that a message has been read', 'check',
              [['Eye', 'eye'], ['Ticks', 'ticks'], ['Off', 'none']])}
            <div class="row">
              <div class="row-icon">${icon('info', 17)}</div>
              <div class="row-main">
                <div class="row-title">Preview</div>
                <div class="row-sub">Unseen, then seen. Tap to replay</div>
              </div>
              <div class="row-ctl">
                <button class="btn btn-sm btn-outline" id="receipt-demo" style="gap:var(--sp-3)">
                  <span class="seen-chip"><span class="seen" id="demo-eye-a"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" aria-hidden="true">
                    <path class="seen-lid" d="M3.2 10.6 Q12 17.6 20.8 10.6"/>
                    <path class="seen-open" d="M1.5 12s4-7.5 10.5-7.5S22.5 12 22.5 12s-4 7.5-10.5 7.5S1.5 12 1.5 12z"/>
                    <circle class="seen-iris" cx="12" cy="12" r="3"/>
                    <circle class="seen-pupil" cx="12" cy="12" r="1.1"/>
                  </svg></span></span>
                  <span class="seen-chip"><span class="seen is-seen" id="demo-eye-b"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" aria-hidden="true">
                    <path class="seen-lid" d="M3.2 10.6 Q12 17.6 20.8 10.6"/>
                    <path class="seen-open" d="M1.5 12s4-7.5 10.5-7.5S22.5 12 22.5 12s-4 7.5-10.5 7.5S1.5 12 1.5 12z"/>
                    <circle class="seen-iris" cx="12" cy="12" r="3"/>
                    <circle class="seen-pupil" cx="12" cy="12" r="1.1"/>
                  </svg></span></span>
                </button>
              </div>
            </div>
          </div>
        </div>

        <div class="group">
          <div class="group-title">Sound</div>
          <div class="card">
            ${rowToggle('soundEnabled', 'Message sounds', 'Short tones on send, receive and seen', 'bell')}
            <div class="row stacked">
              <div class="row-line">
                <div class="row-icon">${icon('mic', 17)}</div>
                <div class="row-main">
                  <div class="row-title">Volume</div>
                  <div class="row-sub">Drag to preview</div>
                </div>
                <span class="row-value" id="vol-value">${Math.round((s.soundVolume ?? 0.4) * 100)}%</span>
              </div>
              <input class="range" type="range" id="sound-volume" min="0" max="1" step="0.05"
                     value="${s.soundVolume ?? 0.4}">
            </div>
          </div>
        </div>

        <div class="group">
          <div class="group-title">Privacy &amp; Security</div>
          <div class="card">
            <div class="row">
              <div class="row-icon">${icon('lock', 17)}</div>
              <div class="row-main">
                <div class="row-title">App lock</div>
                <div class="row-sub">${s.appLockEnabled ? 'A PIN is required after the app is idle' : 'Require a PIN to reopen the app'}</div>
              </div>
              <div class="row-ctl">
                <label class="switch">
                  <input type="checkbox" id="applock-toggle" ${s.appLockEnabled ? 'checked' : ''}>
                  <span class="switch-track"></span>
                </label>
              </div>
            </div>
            ${s.appLockEnabled ? `
            <div class="row">
              <div class="row-icon">${icon('clock', 17)}</div>
              <div class="row-main">
                <div class="row-title">Lock after</div>
                <div class="row-sub">Idle time before the PIN is required again</div>
              </div>
              <div class="row-ctl">
                <select class="select" id="applock-delay" style="width:140px;min-height:36px">
                  ${[['Immediately', 0], ['30 seconds', 30000], ['1 minute', 60000], ['5 minutes', 300000], ['15 minutes', 900000]]
                    .map(([l, v]) => `<option value="${v}"${s.appLockDelayMs === v ? ' selected' : ''}>${l}</option>`).join('')}
                </select>
              </div>
            </div>` : ''}
            ${rowToggle('privacyBlur', 'Blur when unfocused', 'Hide message content when you switch away', 'shield')}
            <div class="row">
              <div class="row-icon">${icon('key', 17)}</div>
              <div class="row-main">
                <div class="row-title">Encrypt local data</div>
                <div class="row-sub">${s.encryptAtRest
                  ? 'Messages, contacts and keys are encrypted on this device. The key is never written to disk, so you must sign in each time.'
                  : 'Encrypt messages, contacts and keys on disk. Disables "keep me signed in", because the key is held in memory only.'}</div>
              </div>
              <div class="row-ctl">
                <label class="switch">
                  <input type="checkbox" id="vault-toggle" ${s.encryptAtRest ? 'checked' : ''}>
                  <span class="switch-track"></span>
                </label>
              </div>
            </div>
            <button class="row" id="open-devices">
              <div class="row-icon">${icon('database', 17)}</div>
              <div class="row-main">
                <div class="row-title">Push subscriptions</div>
                <div class="row-sub">Browsers registered to receive notifications</div>
              </div>
              <div class="row-ctl">${icon('chevron', 16)}</div>
            </button>
            <button class="row" id="open-blocked">
              <div class="row-icon">${icon('shield', 17)}</div>
              <div class="row-main">
                <div class="row-title">Blocked contacts</div>
                <div class="row-sub">${blockedContacts().length} blocked · their messages are dropped on arrival</div>
              </div>
              <div class="row-ctl">${icon('chevron', 16)}</div>
            </button>
          </div>
        </div>

        <div class="group">
          <div class="group-title">Devices</div>
          <div class="card" id="devices-card">
            <div class="row">
              <div class="row-main">
                <div class="row-sub">Loading…</div>
              </div>
            </div>
          </div>
          <p class="group-note">
            Every device signed into this account holds the same identity key,
            so removing one stops others addressing it. It does not take away
            what is already on that device.
          </p>
        </div>

        <div class="group">
          <div class="group-title">Storage</div>
          <div class="card">
            <div class="row">
              <div class="row-icon">${icon('database', 17)}</div>
              <div class="row-main">
                <div class="row-title">Local data</div>
                <div class="row-sub" id="storage-size">Calculating…</div>
              </div>
            </div>
            <button class="row" id="clear-cache">
              <div class="row-icon">${icon('image', 17)}</div>
              <div class="row-main">
                <div class="row-title">Clear media cache</div>
                <div class="row-sub">Decrypted images and voice notes held in memory</div>
              </div>
              <div class="row-ctl">${icon('chevron', 16)}</div>
            </button>
            <button class="row" id="create-backup">
              <div class="row-icon">${icon('shield', 17)}</div>
              <div class="row-main">
                <div class="row-title">Create encrypted backup</div>
                <div class="row-sub">One file holding your messages, contacts and groups, locked with a passphrase you choose</div>
              </div>
              <div class="row-ctl">${icon('chevron', 16)}</div>
            </button>
            <button class="row" id="restore-backup">
              <div class="row-icon">${icon('database', 17)}</div>
              <div class="row-main">
                <div class="row-title">Restore from backup</div>
                <div class="row-sub">Add history from a backup file. Nothing is deleted unless you ask</div>
              </div>
              <div class="row-ctl">${icon('chevron', 16)}</div>
            </button>
            <button class="row" id="export-settings">
              <div class="row-icon">${icon('download', 17)}</div>
              <div class="row-main">
                <div class="row-title">Export settings</div>
                <div class="row-sub">Save your preferences as a JSON file. No keys, no messages</div>
              </div>
              <div class="row-ctl">${icon('chevron', 16)}</div>
            </button>
            <button class="row" id="import-settings">
              <div class="row-icon">${icon('file', 17)}</div>
              <div class="row-main">
                <div class="row-title">Import settings</div>
                <div class="row-sub">Apply a preferences file exported from another device</div>
              </div>
              <div class="row-ctl">${icon('chevron', 16)}</div>
            </button>
            <button class="row danger" id="panic-wipe">
              <div class="row-icon">${icon('trash', 17)}</div>
              <div class="row-main">
                <div class="row-title">Panic wipe</div>
                <div class="row-sub">Erase everything on this device now · or press Esc three times</div>
              </div>
              <div class="row-ctl">${icon('chevron', 16)}</div>
            </button>
          </div>
        </div>

        <div class="group">
          <div class="group-title">About</div>
          <div class="card">
            <a class="row" href="/setup" target="_blank" rel="noopener">
              <div class="row-icon">${icon('shield-check', 17)}</div>
              <div class="row-main">
                <div class="row-title">Certificate setup</div>
                <div class="row-sub">Install the Talon CA to remove browser warnings on this device</div>
              </div>
              <div class="row-ctl">${icon('chevron', 16)}</div>
            </a>
            <button class="row" id="show-shortcuts">
              <div class="row-icon">${icon('keyboard', 17)}</div>
              <div class="row-main">
                <div class="row-title">Keyboard shortcuts</div>
                <div class="row-sub">Press ? at any time</div>
              </div>
              <div class="row-ctl">${icon('chevron', 16)}</div>
            </button>
            <div class="row">
              <div class="row-icon">${icon('info', 17)}</div>
              <div class="row-main">
                <div class="row-title">Encryption</div>
                <div class="row-sub">X25519 handshake · AES-256-GCM · symmetric ratchet with per-message keys</div>
              </div>
            </div>
            <button class="row" id="reset-settings">
              <div class="row-icon">${icon('settings', 17)}</div>
              <div class="row-main">
                <div class="row-title">Reset settings</div>
                <div class="row-sub">Restore defaults. Messages and contacts are untouched</div>
              </div>
              <div class="row-ctl">${icon('chevron', 16)}</div>
            </button>
          </div>
        </div>

      </div>
    </div>`;

  bindSettings(el);
}

/** Settings that need more than a re-paint once they change. */
function applySideEffects(key) {
  if (key === 'clockFormat') {
    setClockFormat(String(State.settings.clockFormat));
    renderChatList();
  }
  if (key === 'clockFormat' || key === 'receiptStyle' || key === 'spellcheck') {
    if (State.activeContactId) renderChatArea();
  }
}

function bindSettings(root) {
  // Generic boolean toggles
  root.querySelectorAll('[data-toggle]').forEach((input) => {
    input.onchange = () => {
      setSetting(input.dataset.toggle, input.checked);
      if (input.dataset.toggle === 'showPreviews') renderChatList();
      if (input.dataset.toggle === 'autoDownloadImages' && State.activeContactId) renderChatArea();
    };
  });

  root.querySelectorAll('[data-theme-pick]').forEach((b) => {
    b.onclick = () => { setSetting('theme', b.dataset.themePick); renderSettingsPane(); };
  });

  root.querySelectorAll('[data-accent]').forEach((b) => {
    b.onclick = () => { setSetting('accent', b.dataset.accent); renderSettingsPane(); };
  });

  root.querySelectorAll('[data-density]').forEach((b) => {
    b.onclick = () => { setSetting('density', b.dataset.density); renderSettingsPane(); };
  });

  // Generic segmented pickers (rowSegmented). Values arrive as strings, so
  // anything numeric is coerced back before it is stored.
  root.querySelectorAll('[data-choice]').forEach((b) => {
    b.onclick = () => {
      const key = b.dataset.choice;
      const raw = b.dataset.value;
      const value = /^-?\d+(\.\d+)?$/.test(raw) ? Number(raw) : raw;
      setSetting(key, value);
      applySideEffects(key);
      renderSettingsPane();
    };
  });

  // Generic <select> settings (rowSelect).
  root.querySelectorAll('[data-select]').forEach((sel) => {
    sel.onchange = () => {
      const key = sel.dataset.select;
      const raw = sel.value;
      const value = /^-?\d+(\.\d+)?$/.test(raw) ? Number(raw) : raw;
      setSetting(key, value);
      applySideEffects(key);
    };
  });

  // Replay the eye animation on demand.
  const demo = root.querySelector('#receipt-demo');
  if (demo) {
    demo.onclick = () => {
      const b = root.querySelector('#demo-eye-b');
      if (!b) return;
      b.classList.remove('is-seen', 'just-seen');
      // Force a reflow so removing and re-adding the class restarts the
      // transition instead of being collapsed into a no-op.
      void b.offsetWidth;
      b.classList.add('is-seen', 'just-seen');
      previewCue('seen');
    };
  }

  const vol = root.querySelector('#sound-volume');
  if (vol) {
    const label = root.querySelector('#vol-value');
    const preview = debounce(() => previewCue('receive'), 220);
    vol.oninput = () => {
      const v = Number(vol.value);
      if (label) label.textContent = `${Math.round(v * 100)}%`;
      State.settings.soundVolume = v;
      persist.settings();
      preview();
    };
  }

  const motion = root.querySelector('[data-motion-toggle]');
  if (motion) {
    motion.onchange = () => setSetting('motion', motion.checked ? 'reduced' : 'full');
  }

  const fs = root.querySelector('#font-scale');
  if (fs) {
    const label = root.querySelector('#fs-value');
    const commit = debounce((v) => setSetting('fontScale', v), 120);
    fs.oninput = () => {
      const v = Number(fs.value);
      label.textContent = `${Math.round(v * 100)}%`;
      document.documentElement.style.setProperty('--font-scale', String(v));
      commit(v);
    };
  }

  const push = root.querySelector('#enable-push');
  if (push) push.onclick = async () => { await paneHooks.onEnablePush(); renderSettingsPane(); };

  const lock = root.querySelector('#applock-toggle');
  if (lock) {
    lock.onchange = async () => {
      if (lock.checked) {
        const ok = await setupAppLock();
        if (!ok) lock.checked = false;
      } else {
        setSetting('appLockEnabled', false);
        setSetting('appLockPinHash', null);
        setSetting('appLockSalt', null);
        toast('App lock disabled');
      }
      renderSettingsPane();
    };
  }

  const delay = root.querySelector('#applock-delay');
  if (delay) delay.onchange = () => setSetting('appLockDelayMs', Number(delay.value));

  const devices = root.querySelector('#open-devices');
  if (devices) devices.onclick = openDevicesModal;

  const blocked = root.querySelector('#open-blocked');
  if (blocked) blocked.onclick = openBlockedModal;

  const shortcuts = root.querySelector('#show-shortcuts');
  if (shortcuts) shortcuts.onclick = openShortcutsModal;

  const clearCache = root.querySelector('#clear-cache');
  if (clearCache) {
    clearCache.onclick = () => {
      Object.values(State.decryptedImages).forEach((u) => URL.revokeObjectURL(u));
      Object.values(State.decryptedVoiceMemos).forEach((u) => URL.revokeObjectURL(u));
      State.decryptedImages = {};
      State.decryptedVoiceMemos = {};
      if (State.activeContactId) renderChatArea();
      toast('Media cache cleared', { type: 'ok' });
    };
  }

  const makeBackup = root.querySelector('#create-backup');
  if (makeBackup) makeBackup.onclick = openCreateBackupModal;

  const restore = root.querySelector('#restore-backup');
  if (restore) restore.onclick = openRestoreBackupPicker;

  // Preferences only. The app-lock verifier is deliberately excluded: it is
  // device-local, and copying it to another machine would move a security
  // control somewhere its owner did not choose.
  const exportBtn = root.querySelector('#export-settings');
  if (exportBtn) {
    exportBtn.onclick = () => {
      const { appLockPinHash, appLockSalt, appLockEnabled, ...prefs } = State.settings;
      const blob = new Blob(
        [JSON.stringify({ app: 'talon', kind: 'settings', v: 1, settings: prefs }, null, 2)],
        { type: 'application/json' }
      );
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'talon-settings.json';
      a.click();
      URL.revokeObjectURL(url);
      toast('Settings exported', { type: 'ok' });
    };
  }

  const importBtn = root.querySelector('#import-settings');
  if (importBtn) {
    importBtn.onclick = () => {
      const input = document.createElement('input');
      input.type = 'file';
      input.accept = 'application/json,.json';
      input.onchange = async () => {
        const file = input.files && input.files[0];
        if (!file) return;
        try {
          const parsed = JSON.parse(await file.text());
          if (parsed.app !== 'talon' || parsed.kind !== 'settings' || !parsed.settings) {
            throw new Error('not a Talon settings file');
          }
          // Only keys we actually know about, so a stale or hand-edited file
          // cannot inject junk into the settings object.
          const incoming = {};
          for (const key of Object.keys(DEFAULT_SETTINGS)) {
            if (key.startsWith('appLock')) continue;
            if (key in parsed.settings) incoming[key] = parsed.settings[key];
          }
          State.settings = { ...State.settings, ...incoming };
          persist.settings();
          setClockFormat(String(State.settings.clockFormat));
          applyTheme();
          renderSettingsPane();
          renderChatList();
          if (State.activeContactId) renderChatArea();
          toast(`Imported ${Object.keys(incoming).length} settings`, { type: 'ok' });
        } catch (err) {
          toast(`Could not import: ${err.message}`, { type: 'error' });
        }
      };
      input.click();
    };
  }

  const vault = root.querySelector('#vault-toggle');
  if (vault) {
    vault.onchange = async () => {
      const turningOn = vault.checked;
      const key = State.currentUser && State.currentUser.encryptionKeyHex;
      if (!key) {
        vault.checked = !turningOn;
        toast('Sign in again before changing this', { type: 'error' });
        return;
      }

      const ok = await confirmDialog({
        title: turningOn ? 'Encrypt local data?' : 'Turn off local encryption?',
        message: turningOn
          ? 'Messages, contacts, groups and key material on this device will be encrypted with a key derived from your password and held only in memory. "Keep me signed in" will be turned off, so you will need your password every time you open Talon. Nothing is uploaded and no history is lost.'
          : 'Local data will be written back in the clear. Anyone with access to this device or its disk will be able to read your message history.',
        confirmLabel: turningOn ? 'Encrypt' : 'Turn off',
        danger: !turningOn
      });
      if (!ok) { vault.checked = !turningOn; return; }

      const moved = migrateVault(
        State.currentUser.username, key, turningOn ? 'encrypt' : 'decrypt');

      setSetting('encryptAtRest', turningOn);
      if (turningOn) {
        // The persisted session holds the encryption key; leaving it on disk
        // would defeat the whole exercise.
        Storage.saveSession(State.currentUser, false);
      }
      renderSettingsPane();
      toast(turningOn ? `Encrypted ${moved} local stores` : 'Local encryption off',
        { type: turningOn ? 'ok' : 'info' });
    };
  }

  const panic = root.querySelector('#panic-wipe');
  if (panic) panic.onclick = () => paneHooks.onPanicWipe();

  const reset = root.querySelector('#reset-settings');
  if (reset) {
    reset.onclick = async () => {
      const ok = await confirmDialog({
        title: 'Reset settings?',
        message: 'Appearance and behaviour settings return to their defaults. Your messages, contacts and app lock PIN are not affected.',
        confirmLabel: 'Reset'
      });
      if (!ok) return;
      const { appLockEnabled, appLockPinHash, appLockSalt } = State.settings;
      State.settings = { ...DEFAULT_SETTINGS, appLockEnabled, appLockPinHash, appLockSalt };
      persist.settings();
      applyTheme();
      renderSettingsPane();
      renderChatList();
      toast('Settings reset', { type: 'ok' });
    };
  }

  // The device list comes from the relay, so it fills in after first paint.
  renderDevices(root);

  // Storage estimate is async; fill it in once it resolves.
  const sizeEl = root.querySelector('#storage-size');
  if (sizeEl) {
    let bytes = 0;
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith('e2e_')) bytes += (localStorage.getItem(k) || '').length * 2;
    }
    sizeEl.textContent = `${formatBytes(bytes)} of messages, contacts and keys on this device`;
  }
}

/* ================================================================ DEVICES */
/*
 * The account's published device list.
 *
 * Worth being careful about what this screen claims. Removing a device does
 * NOT revoke it: every device signed into the account holds the same identity
 * key, and the messages already on it stay there. What changes is that peers
 * stop addressing it, so it receives nothing further. The note under the group
 * says so, and the confirm dialog says so again, because a "Remove" button
 * that reads as "revoke" would be the screen lying.
 */

async function renderDevices(root) {
  const card = root.querySelector('#devices-card');
  if (!card) return;

  const thisDevice = State.currentUser && State.currentUser.deviceId;
  const list = await fetchMyDevices();

  if (!list || !Array.isArray(list.devices) || !list.devices.length) {
    card.innerHTML = `
      <div class="row">
        <div class="row-icon">${icon('phone', 17)}</div>
        <div class="row-main">
          <div class="row-title">This device only</div>
          <div class="row-sub">Sign in on another device and it will appear here</div>
        </div>
      </div>`;
    return;
  }

  // This device first, then the rest by name, so the one you are looking at
  // is never buried and the order does not jump around between loads.
  const devices = [...list.devices].sort((a, b) => {
    if (a.deviceId === thisDevice) return -1;
    if (b.deviceId === thisDevice) return 1;
    return String(a.name).localeCompare(String(b.name));
  });

  card.innerHTML = devices.map((d) => {
    const isThis = d.deviceId === thisDevice;
    return `
      <div class="row">
        <div class="row-icon">${icon('phone', 17)}</div>
        <div class="row-main">
          <div class="row-title">${escapeHTML(d.name || 'Device')}${isThis ? ' <span class="row-value">this device</span>' : ''}</div>
          <div class="row-sub">${escapeHTML(shortDeviceId(d.deviceId))}</div>
        </div>
        <div class="row-ctl">
          ${isThis
            ? `<button class="btn btn-ghost btn-sm" data-rename-device="${escapeAttr(d.deviceId)}">Rename</button>`
            : `<button class="btn btn-ghost btn-sm danger" data-remove-device="${escapeAttr(d.deviceId)}"
                       data-device-name="${escapeAttr(d.name || 'Device')}">Remove</button>`}
        </div>
      </div>`;
  }).join('');

  card.querySelectorAll('[data-rename-device]').forEach((btn) => {
    btn.onclick = async () => {
      const current = State.currentUser && Storage.getDevice(State.currentUser.username);
      const name = await promptDialog({
        title: 'Rename this device',
        label: 'Shown only to you, in this list',
        value: (current && current.name) || '',
        placeholder: 'Phone, Laptop, Work PC',
        confirmLabel: 'Save'
      });
      if (name == null) return;

      const trimmed = String(name).trim().slice(0, 40);
      if (!trimmed) return;

      Storage.saveDevice(State.currentUser.username, { ...current, name: trimmed });
      const r = await publishThisDevice();
      if (!r.ok) { toast('Could not publish the new name', { type: 'error' }); return; }
      toast('Device renamed', { type: 'ok' });
      renderDevices(root);
    };
  });

  card.querySelectorAll('[data-remove-device]').forEach((btn) => {
    btn.onclick = async () => {
      const id = btn.dataset.removeDevice;
      const name = btn.dataset.deviceName;
      const ok = await confirmDialog({
        title: `Remove ${name}?`,
        message: 'Other devices will stop sending to it, so it receives nothing further. '
          + 'It keeps the messages and keys it already has: removing it here cannot reach into that device and erase them. '
          + 'To do that, use Panic Wipe on the device itself.',
        confirmLabel: 'Remove',
        danger: true
      });
      if (!ok) return;

      const r = await revokeDevice(id);
      if (!r.ok) {
        toast(r.reason === 'last device' ? 'That is the only device on the account' : 'Could not remove it',
          { type: 'error' });
        return;
      }
      toast(`${name} removed`, { type: 'ok' });
      renderDevices(root);
    };
  });
}

/** A device id in a form a person can compare, without printing all of it. */
function shortDeviceId(id) {
  const s = String(id || '');
  return s.length > 8 ? `${s.slice(0, 4)} ${s.slice(4, 8)}` : s;
}

/* ================================================================= BACKUP */
/*
 * Everything Talon knows is on the device, so a lost phone is a lost archive.
 * These two flows write and read one encrypted file. The relay is not
 * involved, and neither is any other machine: the file is as private as
 * wherever the user puts it, which is the honest thing to tell them.
 *
 * backup.js holds the format and the merge rules and is pure. This section is
 * only the file picker, the passphrase prompts and the Storage writes.
 */

function backupFilename(username) {
  const d = new Date();
  const stamp = [d.getFullYear(), d.getMonth() + 1, d.getDate()]
    .map((n) => String(n).padStart(2, '0')).join('-');
  return `talon-backup-${String(username || 'account').toLowerCase()}-${stamp}.talon`;
}

function downloadFile(name, text) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  // Revoking immediately can cancel the download on some browsers, so this
  // waits a beat rather than leaking the object URL forever.
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}

function openCreateBackupModal() {
  if (!State.currentUser) return;

  openModal({
    title: 'Create encrypted backup',
    body: `
      <p style="color:var(--fg-muted);line-height:1.6;margin-bottom:var(--sp-4)">
        Your messages, contacts, groups and preferences are packed into one file and encrypted
        with a passphrase you choose here. Nothing is uploaded. The passphrase is not your
        account password and is never stored anywhere.
      </p>
      <div class="field">
        <label class="field-label" for="bk-pass">Passphrase</label>
        <input class="input" type="password" id="bk-pass" autocomplete="new-password"
               placeholder="At least ${MIN_PASSPHRASE_LENGTH} characters" data-autofocus>
      </div>
      <div class="field">
        <label class="field-label" for="bk-pass2">Repeat passphrase</label>
        <input class="input" type="password" id="bk-pass2" autocomplete="new-password">
      </div>
      <div class="modal-warn">
        There is no recovery. If you forget this passphrase the file is permanently unreadable,
        by you and by anyone else.
      </div>
      <div id="bk-error" class="modal-error" hidden></div>
    `,
    footer: `
      <button class="btn" data-cancel>Cancel</button>
      <button class="btn btn-primary" data-ok>Create backup</button>
    `,
    onMount(root, close) {
      const pass = root.querySelector('#bk-pass');
      const pass2 = root.querySelector('#bk-pass2');
      const err = root.querySelector('#bk-error');
      const ok = root.querySelector('[data-ok]');

      const fail = (msg) => { err.textContent = msg; err.hidden = false; };

      root.querySelector('[data-cancel]').onclick = close;
      ok.onclick = async () => {
        err.hidden = true;
        if (pass.value.length < MIN_PASSPHRASE_LENGTH) {
          return fail(`Use at least ${MIN_PASSPHRASE_LENGTH} characters.`);
        }
        if (pass.value !== pass2.value) return fail('The two passphrases do not match.');

        ok.disabled = true;
        ok.textContent = 'Encrypting…';
        try {
          // 600k PBKDF2 iterations block the main thread for around a second,
          // so the button has to say something first or the app looks hung.
          await new Promise((r) => setTimeout(r, 30));
          const payload = collectBackup({
            messages: State.messages, contacts: State.contacts, groups: State.groups,
            profile: State.myProfile, chatMeta: State.chatMeta, drafts: State.drafts,
            settings: State.settings
          });
          const file = await createBackup(pass.value, payload, {
            username: State.currentUser.username
          });
          downloadFile(backupFilename(State.currentUser.username), JSON.stringify(file));
          close();
          const s = summarise(payload);
          toast(`Backed up ${s.messages} messages across ${s.conversations} conversations`,
            { type: 'ok' });
        } catch (e) {
          ok.disabled = false;
          ok.textContent = 'Create backup';
          fail(e.message || 'Could not create the backup.');
        }
      };

      pass2.onkeydown = (e) => { if (e.key === 'Enter') ok.click(); };
    }
  });
}

function openRestoreBackupPicker() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.talon,application/json,.json';
  input.onchange = async () => {
    const file = input.files && input.files[0];
    if (!file) return;
    let parsed;
    try {
      parsed = JSON.parse(await file.text());
    } catch {
      toast('That file is not a Talon backup', { type: 'error' });
      return;
    }
    // Everything checkable without a key is checked before anyone is asked to
    // type a passphrase, so picking the wrong file costs a click and not a
    // minute of wondering why the passphrase is being rejected.
    const shape = inspectBackup(parsed);
    if (!shape.ok) {
      toast(`Cannot restore: ${shape.reason}`, { type: 'error' });
      return;
    }
    openRestoreModal(parsed, shape);
  };
  input.click();
}

function openRestoreModal(file, shape) {
  const when = shape.createdAt
    ? new Date(shape.createdAt).toLocaleString()
    : 'an unknown date';
  const whose = shape.username
    ? escapeHTML(shape.username)
    : 'an unnamed account';

  openModal({
    title: 'Restore from backup',
    body: `
      <p style="color:var(--fg-muted);line-height:1.6;margin-bottom:var(--sp-4)">
        Backup of <strong>${whose}</strong>, made ${escapeHTML(when)}.
      </p>
      <div class="field">
        <label class="field-label" for="rs-pass">Passphrase</label>
        <input class="input" type="password" id="rs-pass" autocomplete="current-password" data-autofocus>
      </div>
      <div class="field">
        <label class="field-label">How to apply it</label>
        <div class="segmented" id="rs-mode">
          <button class="segmented-btn active" data-mode="merge">Merge</button>
          <button class="segmented-btn" data-mode="replace">Replace</button>
        </div>
        <div class="field-hint" id="rs-mode-hint">Adds anything missing and keeps what is already here.</div>
      </div>
      <div id="rs-error" class="modal-error" hidden></div>
    `,
    footer: `
      <button class="btn" data-cancel>Cancel</button>
      <button class="btn btn-primary" data-ok>Restore</button>
    `,
    onMount(root, close) {
      const pass = root.querySelector('#rs-pass');
      const err = root.querySelector('#rs-error');
      const ok = root.querySelector('[data-ok]');
      const fail = (msg) => { err.textContent = msg; err.hidden = false; };

      let mode = 'merge';
      const hint = root.querySelector('#rs-mode-hint');
      root.querySelectorAll('#rs-mode .segmented-btn').forEach((b) => {
        b.onclick = () => {
          mode = b.dataset.mode;
          root.querySelectorAll('#rs-mode .segmented-btn')
            .forEach((o) => o.classList.toggle('active', o === b));
          hint.textContent = mode === 'replace'
            ? 'Discards the history on this device and uses the backup instead.'
            : 'Adds anything missing and keeps what is already here.';
        };
      });

      root.querySelector('[data-cancel]').onclick = close;
      ok.onclick = async () => {
        err.hidden = true;
        if (!pass.value) return fail('Enter the passphrase for this file.');

        ok.disabled = true;
        ok.textContent = 'Decrypting…';
        let payload;
        try {
          await new Promise((r) => setTimeout(r, 30));
          payload = await openBackup(pass.value, file);
        } catch (e) {
          ok.disabled = false;
          ok.textContent = 'Restore';
          return fail(e.message || 'Could not open the backup.');
        }

        close();
        if (mode === 'replace') {
          const s = summarise(payload);
          const confirmed = await confirmDialog({
            title: 'Replace everything on this device?',
            message: `Your current messages, contacts and groups will be discarded and replaced with ${s.messages} messages and ${s.contacts} contacts from the backup. This cannot be undone.`,
            confirmLabel: 'Replace',
            danger: true
          });
          if (!confirmed) return;
        }
        applyRestore(payload, mode);
      };

      pass.onkeydown = (e) => { if (e.key === 'Enter') ok.click(); };
    }
  });
}

/**
 * Writes a decrypted payload into State and Storage.
 *
 * Sessions and prekeys are untouched because a backup never carries them: the
 * ratchet keeps running on whatever this device already has, and any
 * conversation that has no session re-handshakes on the next send.
 */
function applyRestore(payload, mode) {
  const { result, stats } = mergeBackup({
    messages: State.messages, contacts: State.contacts, groups: State.groups,
    profile: State.myProfile, chatMeta: State.chatMeta, drafts: State.drafts,
    settings: State.settings
  }, payload, { mode });

  State.messages = result.messages;
  State.contacts = result.contacts;
  State.groups = result.groups;
  State.myProfile = result.profile;
  State.chatMeta = result.chatMeta;
  State.drafts = result.drafts;
  // The app lock is device-local and mergeBackup already dropped it from the
  // incoming side, but re-asserting the current values here means a future
  // change to the merge cannot quietly unlock someone's app.
  State.settings = {
    ...DEFAULT_SETTINGS,
    ...result.settings,
    appLockEnabled: State.settings.appLockEnabled,
    appLockPinHash: State.settings.appLockPinHash,
    appLockSalt: State.settings.appLockSalt
  };

  persist.messages();
  persist.contacts();
  persist.groups();
  persist.profile();
  persist.chatMeta();
  persist.drafts();
  persist.settings();

  applyTheme();
  setClockFormat(String(State.settings.clockFormat));
  renderSettingsPane();
  renderChatList();
  if (State.activeContactId) renderChatArea();

  toast(mode === 'replace'
    ? `Restored ${stats.messages} messages and ${stats.contacts} contacts`
    : `Added ${stats.messages} messages, ${stats.contacts} contacts and ${stats.groups} groups`,
  { type: 'ok' });
}

/* =============================================================== APP LOCK */

/** Prompts for a new PIN twice and stores only a salted verifier. */
function setupAppLock() {
  return new Promise((resolve) => {
    openModal({
      title: 'Set a PIN',
      body: `
        <p style="color:var(--fg-muted);line-height:1.6;margin-bottom:var(--sp-4)">
          You will be asked for this PIN when reopening Talon. It protects the app on this device only, and
          it is not your password and cannot decrypt anything on its own.
        </p>
        <div class="field">
          <label class="field-label" for="pin1">4-digit PIN</label>
          <input class="input mono" id="pin1" type="password" inputmode="numeric" maxlength="4" pattern="\\d{4}" data-autofocus>
        </div>
        <div class="field">
          <label class="field-label" for="pin2">Confirm PIN</label>
          <input class="input mono" id="pin2" type="password" inputmode="numeric" maxlength="4" pattern="\\d{4}">
        </div>`,
      footer: `
        <button class="btn" data-cancel>Cancel</button>
        <button class="btn btn-primary" id="pin-save">Enable lock</button>`,
      onMount(root, close) {
        const a = root.querySelector('#pin1');
        const b = root.querySelector('#pin2');
        root.querySelector('[data-cancel]').onclick = () => { resolve(false); close(); };
        root.querySelector('#pin-save').onclick = () => {
          if (!/^\d{4}$/.test(a.value)) { a.classList.add('invalid'); toast('Enter 4 digits', { type: 'error' }); return; }
          if (a.value !== b.value) { b.classList.add('invalid'); toast('PINs do not match', { type: 'error' }); return; }
          const salt = randomHex(16);
          setSetting('appLockSalt', salt);
          setSetting('appLockPinHash', hashPin(a.value, salt));
          setSetting('appLockEnabled', true);
          resolve(true);
          close();
          toast('App lock enabled', { type: 'ok' });
        };
      }
    });

    const host = document.getElementById('modal-host');
    const obs = new MutationObserver(() => {
      if (host.hidden) { resolve(false); obs.disconnect(); }
    });
    obs.observe(host, { attributes: true, attributeFilter: ['hidden'] });
  });
}

let pinBuffer = '';

export function showLockScreen() {
  const lock = document.getElementById('lock');
  if (!lock || !State.settings.appLockEnabled) return;
  State.locked = true;
  pinBuffer = '';
  lock.hidden = false;
  renderPinPad();
  paintPinDots();
}

export function hideLockScreen() {
  const lock = document.getElementById('lock');
  if (lock) lock.hidden = true;
  State.locked = false;
  pinBuffer = '';
}

function paintPinDots(wrong = false) {
  const dots = document.getElementById('pin-dots');
  if (!dots) return;
  dots.classList.toggle('wrong', wrong);
  if (wrong) setTimeout(() => dots.classList.remove('wrong'), 450);
  Array.from(dots.children).forEach((d, i) => d.classList.toggle('filled', i < pinBuffer.length));
}

function renderPinPad() {
  const pad = document.getElementById('pin-pad');
  if (!pad || pad.dataset.ready) return;

  pad.innerHTML = [1, 2, 3, 4, 5, 6, 7, 8, 9, '', 0, '⌫']
    .map((k) => k === ''
      ? '<button class="pin-key blank" tabindex="-1"></button>'
      : `<button class="pin-key" data-key="${k}">${k}</button>`)
    .join('');
  pad.dataset.ready = '1';

  pad.onclick = (e) => {
    const btn = e.target.closest('[data-key]');
    if (btn) pushPin(btn.dataset.key);
  };

  document.addEventListener('keydown', (e) => {
    if (!State.locked) return;
    if (/^\d$/.test(e.key)) pushPin(e.key);
    else if (e.key === 'Backspace') pushPin('⌫');
  });

  const out = document.getElementById('lock-signout');
  if (out) out.onclick = () => paneHooks.onLogout(true);
}

function pushPin(key) {
  if (key === '⌫') {
    pinBuffer = pinBuffer.slice(0, -1);
    paintPinDots();
    return;
  }
  if (pinBuffer.length >= 4) return;
  pinBuffer += key;
  paintPinDots();

  if (pinBuffer.length === 4) {
    const s = State.settings;
    if (s.appLockSalt && hashPin(pinBuffer, s.appLockSalt) === s.appLockPinHash) {
      hideLockScreen();
    } else {
      paintPinDots(true);
      pinBuffer = '';
      setTimeout(paintPinDots, 460);
      if (navigator.vibrate) navigator.vibrate([40, 60, 40]);
    }
  }
}

/* ============================================================ SAFETY NUMBER */

export function openContactProfile(convId) {
  if (isGroupId(convId)) { openGroupInfo(convId); return; }

  const contact = State.contacts.find((c) => c.idPub === convId);
  if (!contact) return;

  const meta = metaFor(convId);
  const groups = safetyNumber(State.currentUser.idPub, contact.idPub);

  openModal({
    title: 'Contact',
    body: `
      <div style="display:flex;flex-direction:column;align-items:center;gap:var(--sp-3);margin-bottom:var(--sp-6)">
        ${avatarHTML(contact.idPub, contact.nickname, 'avatar-lg', 'cp-avatar')}
        <div style="font-size:var(--fs-xl);font-weight:680;letter-spacing:-.02em">${escapeHTML(contact.nickname)}</div>
        ${contact.bio ? `<div style="color:var(--fg-muted);text-align:center;max-width:36ch">${escapeHTML(contact.bio)}</div>` : ''}
        <button class="btn btn-sm btn-outline" id="cp-rename">${icon('edit', 14)} Rename</button>
      </div>

      <div class="group" style="margin-bottom:var(--sp-5)">
        <div class="group-title">Safety number</div>
        <div class="fingerprint">${groups.map((g) => `<span>${g}</span>`).join('')}</div>
        <p style="font-size:var(--fs-sm);color:var(--fg-muted);margin-top:var(--sp-3);line-height:1.55">
          Compare these digits with ${escapeHTML(contact.nickname)} in person or over a channel you already trust.
          If they match, no one has swapped keys in the middle. If they ever change unexpectedly, stop and re-verify.
        </p>
        <div class="qr-side">
          <div class="qr-wrap qr-sm">${safetyQr(groups.join(' '))}</div>
          <p class="qr-note" style="text-align:left;margin:0">
            Both devices show the same digits, so both show the same code.
            Comparing two pictures is quicker and less error-prone than reading
            60 numbers aloud, which is the reason this step usually gets
            skipped.
          </p>
        </div>
        <button class="btn btn-block ${meta.verified ? 'btn-outline' : 'btn-primary'}" id="cp-verify" style="margin-top:var(--sp-3)">
          ${icon(meta.verified ? 'shield-check' : 'shield', 16)}
          ${meta.verified ? 'Verified. Tap to clear' : 'Mark as verified'}
        </button>
      </div>

      <div class="group" style="margin-bottom:var(--sp-5)">
        <div class="group-title">Encryption</div>
        <div class="card">
          <div class="row">
            <div class="row-icon">${icon('lock', 17)}</div>
            <div class="row-main">
              <div class="row-title">Session</div>
              <div class="row-sub">${escapeHTML(sessionSummary(contact.idPub))}</div>
            </div>
          </div>
        </div>
      </div>

      <div class="group">
        <div class="group-title">Identity key</div>
        <div class="keybox">${escapeHTML(contact.idPub)}</div>
      </div>`,
    onMount(root, close) {
      if (contact.avatar) decryptAndShowAvatar(contact.avatar, root.querySelector('#cp-avatar'));

      root.querySelector('#cp-verify').onclick = () => {
        meta.verified = !meta.verified;
        persist.chatMeta();
        close();
        renderChatArea();
        toast(meta.verified ? 'Marked as verified' : 'Verification cleared', { type: 'ok' });
      };

      root.querySelector('#cp-rename').onclick = async () => {
        close();
        const name = await promptDialog({
          title: 'Rename contact', label: 'Display name', value: contact.nickname
        });
        if (!name) return;
        contact.nickname = name;
        // An explicit rename is the user's choice, so profile-sync must not
        // silently overwrite it later.
        contact.nameLocked = true;
        persist.contacts();
        syncContactsWithServer();
        renderChatList();
        renderChatArea();
        toast('Contact renamed', { type: 'ok' });
      };
    }
  });
}

export function openGroupInfo(groupId) {
  const group = State.groups.find((g) => g.id === groupId);
  if (!group) return;

  const admin = canAdminGroup(group) && !group.removed;
  const me = State.currentUser.idPub;
  // Contacts not in the group yet, and not blocked or unaccepted: those are
  // the only people it makes sense to offer.
  const addable = State.contacts.filter(
    (c) => !c.blocked && !c.pending && !group.members.includes(c.idPub)
  );

  openModal({
    title: group.name,
    body: `
      <div style="display:flex;flex-direction:column;align-items:center;gap:var(--sp-2);margin-bottom:var(--sp-5)">
        <div class="avatar avatar-lg" style="background:${avatarGradient(group.id)}">${icon('users', 28)}</div>
        <div style="color:var(--fg-muted)">${group.members.length} member${group.members.length === 1 ? '' : 's'}</div>
        ${admin ? `<button class="btn btn-sm btn-outline" id="gi-rename">${icon('edit', 14)} Rename group</button>` : ''}
      </div>
      <div class="group-title">Members</div>
      <div class="card">
        ${group.members.map((id) => {
          const isMe = id === me;
          const name = isMe ? `${State.myProfile.nickname || State.currentUser.username} (you)` : displayNameFor(id);
          const isOwner = group.owner === id;
          return `
            <div class="row">
              <div class="avatar-wrap">${avatarHTML(id, name, 'avatar-sm', `gm-${id.substring(0, 12)}`)}</div>
              <div class="row-main">
                <div class="row-title">${escapeHTML(name)}${isOwner ? '<span class="tag">Admin</span>' : ''}</div>
                <div class="row-sub" style="font-family:var(--font-mono);font-size:var(--fs-xs)">${escapeHTML(id.substring(0, 20))}…</div>
              </div>
              ${admin && !isMe ? `
                <div class="row-ctl">
                  <button class="icon-btn" data-remove="${escapeAttr(id)}"
                          title="Remove from group">${icon('close', 16)}</button>
                </div>` : ''}
            </div>`;
        }).join('')}
      </div>
      ${admin && addable.length ? `
        <div class="group-title" style="margin-top:var(--sp-4)">Add members</div>
        <div class="card" style="max-height:30vh;overflow-y:auto">
          ${addable.map((c) => `
            <label class="row" style="cursor:pointer">
              <div class="avatar-wrap">${avatarHTML(c.idPub, c.nickname, 'avatar-sm')}</div>
              <div class="row-main"><div class="row-title">${escapeHTML(c.nickname)}</div></div>
              <div class="row-ctl">
                <span class="checkbox">
                  <input type="checkbox" data-add value="${escapeAttr(c.idPub)}">
                  <span class="checkbox-box"></span>
                </span>
              </div>
            </label>`).join('')}
        </div>
        <button class="btn btn-primary btn-block" id="gi-add" style="margin-top:var(--sp-3)">
          ${icon('user-plus', 15)} Add selected
        </button>` : ''}
      <p style="font-size:var(--fs-sm);color:var(--fg-muted);margin-top:var(--sp-4);line-height:1.55">
        Groups are assembled entirely on your device. Each message is encrypted separately for every member,
        so the server never learns that this group exists.
        ${admin ? `
          Removing someone tells the other members to stop addressing them. There is no group key to revoke,
          so it is an agreement between clients rather than something the encryption enforces.` : ''}
      </p>`,
    onMount(root, close) {
      group.members.forEach((id) => {
        const src = id === me
          ? State.myProfile.avatar
          : (State.contacts.find((c) => c.idPub === id) || {}).avatar;
        if (src) decryptAndShowAvatar(src, root.querySelector(`#gm-${id.substring(0, 12)}`));
      });

      const refresh = () => {
        close();
        renderChatList();
        renderChatArea();
      };

      const renameBtn = root.querySelector('#gi-rename');
      if (renameBtn) {
        renameBtn.onclick = async () => {
          close();
          const name = await promptDialog({
            title: 'Rename group', label: 'Group name', value: group.name
          });
          if (!name || name === group.name) return;
          renameGroup(groupId, name.slice(0, 40));
          renderChatList();
          renderChatArea();
          toast('Group renamed', { type: 'ok' });
        };
      }

      root.querySelectorAll('[data-remove]').forEach((b) => {
        b.onclick = async () => {
          const id = b.dataset.remove;
          const name = displayNameFor(id);
          close();
          const ok = await confirmDialog({
            title: `Remove ${name}?`,
            message: `${name} stops receiving messages sent to "${group.name}". They keep the history they already have, and nothing stops them messaging members directly.`,
            confirmLabel: 'Remove',
            danger: true
          });
          if (!ok) return;
          setGroupMembers(groupId, group.members.filter((m) => m !== id));
          renderChatList();
          renderChatArea();
          toast(`${name} removed`, { type: 'ok' });
        };
      });

      const addBtn = root.querySelector('#gi-add');
      if (addBtn) {
        addBtn.onclick = () => {
          const picked = Array.from(root.querySelectorAll('[data-add]:checked')).map((i) => i.value);
          if (!picked.length) { toast('Pick someone to add', { type: 'warn' }); return; }
          setGroupMembers(groupId, [...group.members, ...picked]);
          refresh();
          toast(`Added ${picked.length} member${picked.length === 1 ? '' : 's'}`, { type: 'ok' });
        };
      }
    }
  });
}

/* ============================================================== DEVICES */

async function openDevicesModal() {
  openModal({
    title: 'Push subscriptions',
    body: `<div id="devices-body"><div class="empty"><span class="spinner"></span></div></div>`,
    async onMount(root) {
      const body = root.querySelector('#devices-body');
      try {
        const res = await fetch('/api/devices', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: State.currentUser.username,
            authHash: State.currentUser.authHash
          })
        });
        const data = await res.json();
        if (!data.success) throw new Error(data.error);

        if (!data.devices.length) {
          body.innerHTML = `
            <div class="empty">
              <div class="empty-icon">${icon('bell-off', 24)}</div>
              <div class="empty-title">No devices registered</div>
              <div class="empty-text">Enable push notifications to register this device.</div>
            </div>`;
          return;
        }

        body.innerHTML = `
          <p style="color:var(--fg-muted);font-size:var(--fs-sm);margin-bottom:var(--sp-4);line-height:1.55">
            Each device you enable notifications on registers a push subscription. Revoking one stops
            notifications reaching it. The server stores only the endpoint, never message content.
          </p>
          <div class="card">
            ${data.devices.map((d, i) => `
              <div class="row">
                <div class="row-icon">${icon('bell', 17)}</div>
                <div class="row-main">
                  <div class="row-title">${escapeHTML(d.service || 'Push service')}${d.current ? ' · this device' : ''}</div>
                  <div class="row-sub">Added ${relativeTime(d.addedAt)}</div>
                </div>
                <div class="row-ctl">
                  <button class="btn btn-sm btn-danger" data-revoke="${i}">Revoke</button>
                </div>
              </div>`).join('')}
          </div>`;

        body.querySelectorAll('[data-revoke]').forEach((btn) => {
          btn.onclick = async () => {
            const device = data.devices[Number(btn.dataset.revoke)];
            btn.disabled = true;
            try {
              await fetch('/api/push-unsubscribe', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  username: State.currentUser.username,
                  authHash: State.currentUser.authHash,
                  endpoint: device.endpoint
                })
              });
              toast('Device revoked', { type: 'ok' });
              closeModal();
              openDevicesModal();
            } catch {
              btn.disabled = false;
              toast('Could not revoke that device', { type: 'error' });
            }
          };
        });
      } catch (err) {
        body.innerHTML = `<div class="empty"><div class="empty-title">Could not load devices</div>
          <div class="empty-text">${escapeHTML(String(err.message || err))}</div></div>`;
      }
    }
  });
}

/* =============================================================== BLOCKED */

function openBlockedModal() {
  const list = blockedContacts();

  openModal({
    title: 'Blocked contacts',
    body: list.length === 0
      ? `<div class="empty">
           <div class="empty-icon">${icon('shield', 24)}</div>
           <div class="empty-title">Nobody is blocked</div>
           <div class="empty-text">Blocking someone drops their messages before they are stored, and hides the conversation.</div>
         </div>`
      : `<p style="color:var(--fg-muted);font-size:var(--fs-sm);margin-bottom:var(--sp-4);line-height:1.55">
           Messages from these contacts are discarded on arrival. They are not told they have been blocked.
         </p>
         <div class="card">
           ${list.map((c) => `
             <div class="row">
               <div class="avatar-wrap">${avatarHTML(c.idPub, c.nickname, 'avatar-sm')}</div>
               <div class="row-main">
                 <div class="row-title">${escapeHTML(c.nickname)}</div>
                 <div class="row-sub" style="font-family:var(--font-mono);font-size:var(--fs-xs)">${escapeHTML(c.idPub.substring(0, 20))}…</div>
               </div>
               <div class="row-ctl">
                 <button class="btn btn-sm" data-unblock="${escapeAttr(c.idPub)}">Unblock</button>
               </div>
             </div>`).join('')}
         </div>`,
    onMount(root, close) {
      root.querySelectorAll('[data-unblock]').forEach((btn) => {
        btn.onclick = () => {
          const c = State.contacts.find((x) => x.idPub === btn.dataset.unblock);
          if (!c) return;
          // Unblocking returns them to "request" state rather than straight to
          // an accepted contact. You blocked them for a reason.
          c.blocked = false;
          c.pending = true;
          persist.contacts();
          syncContactsWithServer();
          renderChatList();
          renderSettingsPane();
          close();
          toast(`${c.nickname} unblocked. They are now a message request`, { type: 'ok' });
        };
      });
    }
  });
}

/* ============================================================= SHORTCUTS */

const SHORTCUTS = [
  ['Ctrl / ⌘ K', 'Search messages'],
  ['Ctrl / ⌘ N', 'Add a contact'],
  ['Ctrl / ⌘ F', 'Filter conversations'],
  ['Ctrl / ⌘ ,', 'Open settings'],
  ['Esc', 'Close, or leave the chat'],
  ['Esc ×3', 'Panic wipe'],
  ['↑', 'Edit your last message'],
  ['Enter', 'Send message'],
  ['Shift + Enter', 'New line'],
  ['?', 'This cheatsheet']
];

export function openShortcutsModal() {
  const half = Math.ceil(SHORTCUTS.length / 2);
  const col = (items) => `<div class="keys-col">${items.map(([k, d]) => `
    <div class="keys-row"><span class="keys-desc">${escapeHTML(d)}</span><kbd>${escapeHTML(k)}</kbd></div>`).join('')}</div>`;

  openModal({
    title: 'Keyboard shortcuts',
    wide: true,
    body: `<div class="keys-grid">${col(SHORTCUTS.slice(0, half))}${col(SHORTCUTS.slice(half))}</div>`
  });
}

/* ================================================================ SEARCH */

export function openSearchModal(initial = '') {
  openModal({
    title: 'Search messages',
    wide: true,
    body: `
      <div class="field" style="margin-bottom:var(--sp-3)">
        <input class="input" id="search-field" placeholder="Search all conversations…"
               value="${escapeAttr(initial)}" autocomplete="off" data-autofocus>
      </div>
      <div id="search-results" style="min-height:220px;max-height:46vh;overflow-y:auto"></div>`,
    onMount(root, close) {
      const field = root.querySelector('#search-field');
      const results = root.querySelector('#search-results');
      let cursor = -1;
      let hits = [];

      const paint = () => {
        const q = field.value.trim().toLowerCase();
        if (q.length < 2) {
          hits = [];
          results.innerHTML = `
            <div class="empty">
              <div class="empty-icon">${icon('search', 24)}</div>
              <div class="empty-text">Type at least two characters to search across every conversation on this device.</div>
            </div>`;
          return;
        }

        hits = State.messages
          .filter((m) => !m.deleted && m.text && m.text.toLowerCase().includes(q))
          .slice(-300)
          .reverse();

        if (!hits.length) {
          results.innerHTML = `
            <div class="empty">
              <div class="empty-icon">${icon('search', 24)}</div>
              <div class="empty-title">No results</div>
              <div class="empty-text">Nothing matches “${escapeHTML(field.value.trim())}”.</div>
            </div>`;
          return;
        }

        cursor = 0;
        results.innerHTML = hits.map((m, i) => {
          const who = m.sender === 'me' ? 'You' : displayNameFor(m.senderId || m.contactId);
          const where = displayNameFor(m.contactId);
          const idx = m.text.toLowerCase().indexOf(q);
          const start = Math.max(0, idx - 30);
          const snippet = (start > 0 ? '…' : '') + m.text.slice(start, idx + q.length + 60);
          const marked = escapeHTML(snippet).replace(
            new RegExp(escapeHTML(field.value.trim()).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'ig'),
            (mm) => `<mark>${mm}</mark>`
          );
          return `
            <button class="result${i === 0 ? ' cursor' : ''}" data-hit="${i}">
              <div class="result-head">
                <span class="result-who">${escapeHTML(who)} · ${escapeHTML(where)}</span>
                <span class="result-when">${relativeTime(m.timestamp)}</span>
              </div>
              <div class="result-snippet">${marked}</div>
            </button>`;
        }).join('');

        results.querySelectorAll('[data-hit]').forEach((b) => {
          b.onclick = () => {
            const m = hits[Number(b.dataset.hit)];
            close();
            paneHooks.onSelectConversation(m.contactId, m);
          };
        });
      };

      const move = (delta) => {
        if (!hits.length) return;
        cursor = Math.max(0, Math.min(hits.length - 1, cursor + delta));
        results.querySelectorAll('.result').forEach((r, i) => r.classList.toggle('cursor', i === cursor));
        results.querySelector('.result.cursor')?.scrollIntoView({ block: 'nearest' });
      };

      field.oninput = debounce(paint, 140);
      field.onkeydown = (e) => {
        if (e.key === 'ArrowDown') { e.preventDefault(); move(1); }
        else if (e.key === 'ArrowUp') { e.preventDefault(); move(-1); }
        else if (e.key === 'Enter' && hits[cursor]) {
          e.preventDefault();
          const m = hits[cursor];
          close();
          paneHooks.onSelectConversation(m.contactId, m);
        }
      };
      paint();
    }
  });
}

/* =============================================================== FORWARD */

export function openForwardModal(msg, onForward) {
  const targets = [
    ...State.groups.map((g) => ({ id: g.id, name: g.name, kind: 'group' })),
    ...State.contacts.map((c) => ({ id: c.idPub, name: c.nickname, kind: 'dm', avatar: c.avatar }))
  ];

  if (!targets.length) { toast('No conversations to forward to'); return; }

  openModal({
    title: 'Forward message',
    body: `
      <div class="card" style="max-height:52vh;overflow-y:auto">
        ${targets.map((t) => `
          <button class="row" data-target="${escapeAttr(t.id)}">
            <div class="avatar-wrap">
              ${t.kind === 'group'
                ? `<div class="avatar avatar-sm" style="background:${avatarGradient(t.id)}">${icon('users', 15)}</div>`
                : avatarHTML(t.id, t.name, 'avatar-sm', `fw-${t.id.substring(0, 12)}`)}
            </div>
            <div class="row-main"><div class="row-title">${escapeHTML(t.name)}</div></div>
            <div class="row-ctl">${icon('forward', 16)}</div>
          </button>`).join('')}
      </div>`,
    onMount(root, close) {
      targets.forEach((t) => {
        if (t.avatar) decryptAndShowAvatar(t.avatar, root.querySelector(`#fw-${t.id.substring(0, 12)}`));
      });
      root.querySelectorAll('[data-target]').forEach((b) => {
        b.onclick = () => { close(); onForward(msg, b.dataset.target); };
      });
    }
  });
}
