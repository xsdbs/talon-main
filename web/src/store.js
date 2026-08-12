import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  hexToBytes, utf8Encode, utf8Decode, encryptWithKey, decryptWithKey
} from './crypto-bundle.js';

// --- PERSISTENCE + IN-MEMORY STATE ---
//
// Storage is the ONLY place that touches localStorage/sessionStorage. Keys
// follow `e2e_<domain>_<lowercased-username>` for per-account data; the login
// session lives under talon_session* .
//
// IMPORTANT: any new `e2e_*` key must also be added to WIPE_PREFIXES below, or
// Panic Wipe will silently leave it behind on the device.

const WIPE_PREFIXES = [
  'e2e_contacts_',
  'e2e_messages_',
  'e2e_sessions_',
  'e2e_groups_',
  'e2e_profile_',
  'e2e_settings_',
  'e2e_drafts_',
  'e2e_chatmeta_',
  'e2e_prekeys_',
  'e2e_outbox_',
  'e2e_device_'
];

export { WIPE_PREFIXES };

// Appearance is stored OUTSIDE the per-account namespace, unprefixed, because
// index.html's inline pre-paint script has to read it before it knows who is
// logged in. It holds no personal data, just theme/accent/density/motion.
export const APPEARANCE_KEY = 'talon_appearance';

export const DEFAULT_SETTINGS = {
  // appearance (mirrored into APPEARANCE_KEY so the pre-paint script sees it)
  // Graphite is the house look: warm dark grey with latte ink. Deliberately
  // not 'auto', because following the OS meant a first run could land on either
  // scheme, so the app had no identity of its own until someone chose one.
  theme: 'graphite',        // auto | dark | light | oled | graphite | ash | paper
  accent: 'indigo',
  density: 'cozy',          // cozy | compact
  motion: 'full',           // full | reduced
  fontScale: 1,
  bubbleCorners: 'round',   // round | soft | square
  uiFont: 'inter',          // inter | system | mono

  // behaviour
  enterToSend: true,
  showPreviews: true,       // message preview text in the chat list
  sendReadReceipts: true,
  sendTypingIndicators: true,
  sharePresence: true,      // tell contacts when you are online, peer to peer

  // Constant-rate cover traffic. ON by default, unlike most privacy switches
  // here, because the thing it defends against (an observer counting your
  // envelopes and reading the timing) is defeated only if the rate is
  // constant, and a feature nobody switches on defends nobody. It costs data
  // and battery, and the Settings row says so in those words.
  //
  // Safe to default on for existing accounts: it changes only how often this
  // client sends, never how anything is stored or read.
  coverTraffic: true,
  autoDownloadImages: true,
  clockFormat: 'auto',      // auto | 12 | 24
  spellcheck: true,
  confirmDelete: true,      // ask before deleting a message

  // sound
  soundEnabled: false,
  soundVolume: 0.4,         // 0–1, applied to the synthesised cues

  // receipts
  receiptStyle: 'eye',      // eye | ticks | none

  // chats
  defaultTtl: 0,            // ms; 0 = disappearing messages off for new chats

  // privacy & security
  appLockEnabled: false,
  appLockPinHash: null,     // salted SHA-256 verifier; never the PIN itself
  appLockSalt: null,
  appLockDelayMs: 60_000,
  privacyBlur: false,       // blur content when the window loses focus
  encryptAtRest: false      // vault mode; see the VAULT block below
};

/* ============================================================ VAULT =======
 * Optional encryption of the local blobs (messages, contacts, sessions,
 * prekeys, ...) at rest.
 *
 * The key is derived from the password-derived `encryptionKey` and is held in
 * memory only and is NEVER written to disk. That is the whole point, and it
 * has a hard consequence: vault mode is incompatible with "keep me signed in",
 * because that persists the session (and therefore the key) to localStorage.
 * app.js enforces that.
 *
 * `e2e_settings_` is deliberately left in the clear: it has to be readable
 * before unlock to know whether the vault is even on, and it holds no message
 * content, only preferences and a salted PIN verifier.
 *
 * Records are self-describing, so a half-migrated profile still reads
 * correctly and turning the vault off is a plain rewrite rather than a
 * one-way door.
 */
const VAULT_INFO = 'TalonVaultv1';
let vaultKey = null;

/** Derives and installs the vault key. Call after the password is known. */
export function unlockVault(encryptionKeyHex) {
  vaultKey = hkdf(sha256, hexToBytes(encryptionKeyHex), new Uint8Array(0),
    utf8Encode(VAULT_INFO), 32);
}

export function lockVault() { vaultKey = null; }
export function vaultUnlocked() { return vaultKey !== null; }

function isEncrypted(v) {
  return v && typeof v === 'object' && v.__enc === 1 && typeof v.c === 'string';
}

function readJSON(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return fallback;
    const parsed = JSON.parse(raw);

    if (!isEncrypted(parsed)) return parsed;      // plaintext record
    if (!vaultKey) return fallback;               // locked: behave as empty
    const plain = decryptWithKey(vaultKey, parsed.c, parsed.n);
    return JSON.parse(utf8Decode(plain));
  } catch {
    return fallback;
  }
}

/** Every persisted blob goes through here so the vault cannot be bypassed. */
function writeJSON(key, value) {
  try {
    if (!vaultKey) {
      localStorage.setItem(key, JSON.stringify(value));
      return;
    }
    const { ciphertext, nonce } = encryptWithKey(vaultKey, utf8Encode(JSON.stringify(value)));
    localStorage.setItem(key, JSON.stringify({ __enc: 1, c: ciphertext, n: nonce }));
  } catch (err) {
    console.error('[Vault] Failed to persist', key, err);
  }
}

/** Keys the vault covers. Settings stay in the clear; see the note above. */
const VAULT_PREFIXES = [
  'e2e_messages_', 'e2e_contacts_', 'e2e_groups_', 'e2e_sessions_',
  'e2e_profile_', 'e2e_drafts_', 'e2e_chatmeta_', 'e2e_prekeys_', 'e2e_outbox_',
  'e2e_device_'
];

/**
 * Rewrites every vault-covered blob for the current user. Used when turning
 * the vault on or off; `direction` decides which way.
 *
 * Reads happen with the *old* key state and writes with the new one, so the
 * order of the two assignments below is load-bearing.
 */
export function migrateVault(username, encryptionKeyHex, direction) {
  const suffix = String(username || '').toLowerCase();
  const snapshot = {};

  for (const prefix of VAULT_PREFIXES) {
    const key = prefix + suffix;
    if (localStorage.getItem(key) === null) continue;
    snapshot[key] = readJSON(key, null);
  }

  if (direction === 'encrypt') unlockVault(encryptionKeyHex);
  else lockVault();

  for (const [key, value] of Object.entries(snapshot)) {
    if (value === null) continue;
    writeJSON(key, value);
  }
  return Object.keys(snapshot).length;
}

const u = (username) => String(username || '').toLowerCase();

export const Storage = {
  // Sessions live in one of two places:
  //  - sessionStorage (default): cleared when the browser closes.
  //  - localStorage 'talon_session_persistent' (opt-in "keep me signed in").
  // Panic Wipe and Log Out clear both.
  getSession() {
    const persistent = localStorage.getItem('talon_session_persistent');
    if (persistent) {
      try { return JSON.parse(persistent); } catch {}
    }
    const data = sessionStorage.getItem('talon_session');
    return data ? JSON.parse(data) : null;
  },
  saveSession(session, remember = false) {
    if (remember) {
      localStorage.setItem('talon_session_persistent', JSON.stringify(session));
      sessionStorage.removeItem('talon_session');
    } else {
      sessionStorage.setItem('talon_session', JSON.stringify(session));
      localStorage.removeItem('talon_session_persistent');
    }
  },
  clearSession() {
    sessionStorage.removeItem('talon_session');
    localStorage.removeItem('talon_session_persistent');
  },

  getContacts(username) { return readJSON(`e2e_contacts_${u(username)}`, []); },
  saveContacts(username, v) { writeJSON(`e2e_contacts_${u(username)}`, v); },

  getMessages(username) { return readJSON(`e2e_messages_${u(username)}`, []); },
  saveMessages(username, v) { writeJSON(`e2e_messages_${u(username)}`, v); },

  getSessions(username) { return readJSON(`e2e_sessions_${u(username)}`, {}); },
  saveSessions(username, v) { writeJSON(`e2e_sessions_${u(username)}`, v); },

  getGroups(username) { return readJSON(`e2e_groups_${u(username)}`, []); },
  saveGroups(username, v) { writeJSON(`e2e_groups_${u(username)}`, v); },

  getProfile(username) { return readJSON(`e2e_profile_${u(username)}`, { nickname: '', bio: '', avatar: null }); },
  saveProfile(username, v) { writeJSON(`e2e_profile_${u(username)}`, v); },

  getSettings(username) {
    return { ...DEFAULT_SETTINGS, ...readJSON(`e2e_settings_${u(username)}`, {}) };
  },

  /**
   * Whether this device has ever stored settings for this account.
   *
   * The difference between "no preference recorded here" and "recorded as
   * off" is load-bearing, and getSettings cannot express it because it merges
   * the defaults in. A device signing into an existing account for the first
   * time has no preference, and must not be read as having chosen the
   * defaults. See the vault decision in initializeSession.
   */
  hasSettings(username) {
    return localStorage.getItem(`e2e_settings_${u(username)}`) !== null;
  },
  saveSettings(username, v) {
    localStorage.setItem(`e2e_settings_${u(username)}`, JSON.stringify(v));
    // Mirror the four visual axes so the pre-paint script in index.html can
    // apply them on the next cold load without waiting for the bundle.
    try {
      localStorage.setItem(APPEARANCE_KEY, JSON.stringify({
        theme: v.theme, accent: v.accent, density: v.density,
        motion: v.motion, fontScale: v.fontScale,
        bubbleCorners: v.bubbleCorners, uiFont: v.uiFont
      }));
    } catch {}
  },

  // Unsent composer text, keyed by conversation.
  getDrafts(username) { return readJSON(`e2e_drafts_${u(username)}`, {}); },
  saveDrafts(username, v) { writeJSON(`e2e_drafts_${u(username)}`, v); },

  // Per-conversation UI state: { [convId]: { pinned, ttl, verified, lastRead } }
  getChatMeta(username) { return readJSON(`e2e_chatmeta_${u(username)}`, {}); },
  saveChatMeta(username, v) { writeJSON(`e2e_chatmeta_${u(username)}`, v); },

  // Protocol v2 prekey material. Only PRIVATE halves live here; the public
  // halves are published to the relay. See messaging.js ensurePreKeys().
  getPreKeys(username) {
    // Older records predate the KEM fields, so the defaults are merged in
    // rather than returned only on a cold start. Otherwise an existing
    // account would carry `kem: undefined` forever and never go hybrid.
    return {
      signPub: null, signPriv: null,
      spk: null,        // { pub, priv, sig, createdAt }
      spkArchive: {},   // pub -> priv, so handshakes against a rotated-away SPK still resolve
      kem: null,        // ML-KEM-768 prekey: { pub, priv, sig, createdAt }
      kemArchive: {},   // pub -> priv, same reason as spkArchive
      otk: {},          // id -> priv
      nextOtkId: 1,
      ...readJSON(`e2e_prekeys_${u(username)}`, {})
    };
  },
  savePreKeys(username, v) { writeJSON(`e2e_prekeys_${u(username)}`, v); },

  // Messages that left the composer but have not been acknowledged. Persisted
  // so a reload or a crash mid-outage does not strand them.
  getOutbox(username) { return readJSON(`e2e_outbox_${u(username)}`, []); },
  saveOutbox(username, v) { writeJSON(`e2e_outbox_${u(username)}`, v); },

  // This browser's device identity for this account: a stable id, and a
  // keypair whose private half never leaves. It is what separates this
  // device's ratchets and prekey pool from the account's other devices.
  //
  // Per account, not per browser, so two accounts used in one browser do not
  // share a device id and cannot be correlated through it.
  getDevice(username) { return readJSON(`e2e_device_${u(username)}`, null); },
  saveDevice(username, v) { writeJSON(`e2e_device_${u(username)}`, v); }
};

export const State = {
  currentUser: null,
  contacts: [],
  messages: [],
  sessions: {},
  groups: [],
  myProfile: { nickname: '', bio: '', avatar: null },
  settings: { ...DEFAULT_SETTINGS },
  drafts: {},
  chatMeta: {},
  preKeys: null,
  outbox: [],
  outboxTimer: null,

  // Constant-rate cover traffic. In memory only and deliberately so: these
  // describe this run of this tab, and persisting them would mean a reload
  // inherits a schedule from a session that is no longer sending.
  coverTimer: null,
  lastSentAt: 0,        // last outbound send of ANY kind, real or cover
  lastCoverTarget: null,

  activeContactId: null,
  activeTab: 'chats',

  socket: null,
  socketConnected: false,
  reconnectInterval: null,
  reconnectAttempts: 0,
  pingInterval: null,

  replyingTo: null,
  editingMessage: null,
  filterQuery: '',

  isTypingTimer: null,
  typingContacts: {},
  groupTypists: {},
  unreadDividerContactId: null,
  unreadDividerMessageIndex: null,
  ttlSweepInterval: null,

  locked: false,
  lockTimer: null,

  peerConnection: null,
  localStream: null,
  callContactId: null,
  callTimerInterval: null,
  callStartTime: null,
  pendingOffer: null,

  activeVoiceRecorder: null,
  voiceRecordingTime: 0,
  voiceRecordingInterval: null,
  voiceRecordingChunks: [],
  decryptedVoiceMemos: {},
  decryptedImages: {}
};

/** Convenience: persist whatever changed without repeating the username. */
export const persist = {
  messages() { if (State.currentUser) Storage.saveMessages(State.currentUser.username, State.messages); },
  contacts() { if (State.currentUser) Storage.saveContacts(State.currentUser.username, State.contacts); },
  groups() { if (State.currentUser) Storage.saveGroups(State.currentUser.username, State.groups); },
  sessions() { if (State.currentUser) Storage.saveSessions(State.currentUser.username, State.sessions); },
  profile() { if (State.currentUser) Storage.saveProfile(State.currentUser.username, State.myProfile); },
  settings() { if (State.currentUser) Storage.saveSettings(State.currentUser.username, State.settings); },
  drafts() { if (State.currentUser) Storage.saveDrafts(State.currentUser.username, State.drafts); },
  chatMeta() { if (State.currentUser) Storage.saveChatMeta(State.currentUser.username, State.chatMeta); },
  preKeys() { if (State.currentUser) Storage.savePreKeys(State.currentUser.username, State.preKeys); },
  outbox() { if (State.currentUser) Storage.saveOutbox(State.currentUser.username, State.outbox); }
};

/** Per-conversation metadata, created lazily. */
export function metaFor(convId) {
  if (!State.chatMeta[convId]) State.chatMeta[convId] = {};
  return State.chatMeta[convId];
}
