import webpush from 'web-push';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { Db } from './db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.join(__dirname, 'data');
const VAPID_PATH = path.join(DATA_DIR, 'vapid.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function loadOrCreateVapidKeys() {
  if (fs.existsSync(VAPID_PATH)) {
    try {
      return JSON.parse(fs.readFileSync(VAPID_PATH, 'utf-8'));
    } catch (err) {
      console.error('[Push] Failed to read existing VAPID keys, regenerating:', err.message);
    }
  }
  const keys = webpush.generateVAPIDKeys();
  fs.writeFileSync(VAPID_PATH, JSON.stringify(keys, null, 2), 'utf-8');
  console.log('[Push] Generated new VAPID key pair.');
  return keys;
}

const vapidKeys = loadOrCreateVapidKeys();

webpush.setVapidDetails(
  'mailto:admin@talon.local',
  vapidKeys.publicKey,
  vapidKeys.privateKey
);

export const Push = {
  publicKey: vapidKeys.publicKey,

  /**
   * Send an opaque push notification to every device registered for this
   * recipient (keyed by idPub, the recipient's static identity key).
   *
   * IMPORTANT: `data` must never contain plaintext message content, sender
   * display names, or group names. Only routing metadata the server
   * already possesses by virtue of relaying the encrypted envelope
   * (conversationId / senderId / groupId). This keeps the relay's
   * zero-knowledge guarantee intact even though it now also triggers pushes.
   */
  async notify(idPub, data) {
    const subs = Db.getPushSubscriptions(idPub);
    if (!subs || subs.length === 0) return;

    const body = JSON.stringify(data);

    await Promise.all(subs.map(async (sub) => {
      try {
        await webpush.sendNotification(sub, body);
      } catch (err) {
        if (err.statusCode === 404 || err.statusCode === 410) {
          // Push service says this subscription is dead, so prune it.
          Db.removePushSubscription(idPub, sub.endpoint);
          console.log(`[Push] Pruned expired subscription for ${idPub.substring(0, 8)}...`);
        } else {
          console.error('[Push] Send failed:', err.message);
        }
      }
    }));
  }
};
