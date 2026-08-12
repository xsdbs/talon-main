import http from 'http';
import https from 'https';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { WebSocketServer } from 'ws';
import { Db, DATA_DIR, ACCOUNT_BUCKET } from './db.js';
import { Push } from './push.js';
import { ensureCertificates } from './tls.js';
import { createLimiter, startSweeping, clientKey } from './ratelimit.js';
import * as Redact from './redact.js';
import os from 'os';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PUBLIC_DIR = path.join(__dirname, '../web/public');
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');

import crypto from 'crypto';

// --- LOGGING ---
// Every meaningful thing the server does gets logged here, with a
// timestamp and a colored [TAG] so you can visually scan a busy terminal:
// TLS/API/WS/PUSH/HTTP/STATS/ERROR. HTTP access logging (below) covers
// every single request automatically, so nothing goes unlogged even for
// routes that don't have their own explicit log line.
const LOG_COLORS = {
  TLS: '\x1b[36m',    // cyan
  API: '\x1b[34m',    // blue
  WS: '\x1b[35m',     // magenta
  PUSH: '\x1b[33m',   // yellow
  HTTP: '\x1b[90m',   // grey
  STATS: '\x1b[32m',  // green
  ERROR: '\x1b[31m',  // red
  BOOT: '\x1b[97m'    // bright white
};
const RESET = '\x1b[0m';

function timestamp() {
  return new Date().toISOString().split('T')[1].replace('Z', '');
}

function log(tag, message, ...rest) {
  const color = LOG_COLORS[tag] || '';
  console.log(`${color}[${timestamp()}] [${tag}]${RESET} ${message}`, ...rest);
}

function logError(tag, message, err) {
  const color = LOG_COLORS.ERROR;
  console.error(`${color}[${timestamp()}] [${tag}]${RESET} ${message}`, err && err.message ? err.message : err);
}

process.on('uncaughtException', (err) => logError('FATAL', 'Uncaught exception:', err));
process.on('unhandledRejection', (err) => logError('FATAL', 'Unhandled rejection:', err));
process.on('SIGINT', () => {
  log('BOOT', 'Shutting down (SIGINT received)...');
  process.exit(0);
});

if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// --- TLS CERTIFICATE ---
// Talon runs its own tiny certificate authority; see server/tls.js for the
// full rationale. The short version: a self-signed *leaf* can never be
// trusted by a browser, but a leaf signed by a CA you installed once can be.
// ensureCertificates() creates the CA if needed, re-issues the leaf whenever
// this machine's addresses change or it nears expiry, and hands back PEMs.
// Not const: the periodic re-check below replaces it when this machine's
// addresses change, so /ca.crt and /setup keep describing the live cert.
const CERT_DIR = path.join(DATA_DIR, 'certs');
let tlsInfo = await ensureCertificates(CERT_DIR, log);
const tlsOptions = { key: tlsInfo.key, cert: tlsInfo.cert };

// MIME types map for static file serving
const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json',
  '.webp': 'image/webp',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.txt': 'text/plain',
  '.map': 'application/json',
  '.crt': 'application/x-x509-ca-cert',
  '.pem': 'application/x-pem-file'
};

/**
 * The /setup page: per-OS instructions for installing the Talon Local CA.
 *
 * Deliberately a standalone, dependency-free HTML string rather than a file in
 * web/public, because it has to render correctly on a device that does *not* yet
 * trust this server, which is exactly the situation where the app shell and
 * its cached assets may be unreachable.
 */
function renderSetupPage() {
  const expiry = tlsInfo.leafNotAfter.toISOString().split('T')[0];
  const dns = tlsInfo.sans.dns.map((d) => `<code>${d}</code>`).join(' ');
  const ips = tlsInfo.sans.ips.map((i) => `<code>${i}</code>`).join(' ');
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Trust Talon on this device</title>
<style>
:root{color-scheme:dark light}
*{box-sizing:border-box;margin:0;padding:0}
body{font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  background:#0c0c0e;color:#e8e8ea;padding:32px 20px;display:flex;justify-content:center}
.wrap{max-width:640px;width:100%}
h1{font-size:26px;letter-spacing:-.02em;margin-bottom:8px}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.08em;color:#8b8b93;margin:32px 0 12px}
p{color:#b4b4bc;margin-bottom:12px}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.88em;
  background:rgba(255,255,255,.07);padding:2px 6px;border-radius:5px;color:#e8e8ea}
.cta{display:inline-block;background:#fff;color:#000;font-weight:600;text-decoration:none;
  padding:14px 24px;border-radius:12px;margin:8px 0 4px}
ol{margin:0 0 4px 20px}li{margin-bottom:8px;color:#b4b4bc}
.card{background:#151518;border:1px solid rgba(255,255,255,.09);border-radius:14px;padding:20px;margin-bottom:14px}
.meta{font-size:13px;color:#6e6e78;margin-top:28px;border-top:1px solid rgba(255,255,255,.08);padding-top:16px}
.warn{background:rgba(255,159,10,.1);border:1px solid rgba(255,159,10,.3);color:#ffb340;
  border-radius:12px;padding:14px 16px;font-size:14px;margin-bottom:20px}
</style></head><body><div class="wrap">
<h1>Trust Talon on this device</h1>
<p>Talon signs its own HTTPS certificate with a private authority that lives only on your server.
Install that authority once here and the browser warning disappears permanently on this device.</p>

<div class="warn">Install this only on devices you own. It lets this server, and only this server, present certificates your browser will trust.</div>

<a class="cta" href="/ca.crt" download="talon-ca.crt">Download the Talon CA</a>

<h2>iPhone / iPad</h2>
<div class="card"><ol>
<li>Tap the download button above in <b>Safari</b> (Chrome and Firefox cannot install profiles on iOS).</li>
<li>Open <b>Settings</b> → <b>Profile Downloaded</b> → <b>Install</b>, and enter your passcode.</li>
<li>Then go to <b>Settings → General → About → Certificate Trust Settings</b> and switch <b>Talon Local CA</b> on. This second step is required. Without it the certificate is installed but still not trusted.</li>
</ol></div>

<h2>Android</h2>
<div class="card"><ol>
<li>Download the file above.</li>
<li>Open <b>Settings → Security → More security settings → Encryption &amp; credentials → Install a certificate → CA certificate</b>, confirm the warning, and pick <code>talon-ca.crt</code>.</li>
<li>Exact wording varies by manufacturer; searching Settings for <em>"CA certificate"</em> is the fastest route.</li>
</ol></div>

<h2>Windows</h2>
<div class="card"><ol>
<li>Download the file, then right-click it → <b>Install Certificate</b>.</li>
<li>Choose <b>Local Machine</b> → <b>Place all certificates in the following store</b> → <b>Trusted Root Certification Authorities</b>.</li>
<li>Or from an elevated PowerShell:<br><code>Import-Certificate -FilePath talon-ca.crt -CertStoreLocation Cert:\\LocalMachine\\Root</code></li>
<li>Restart the browser afterwards.</li>
</ol></div>

<h2>macOS</h2>
<div class="card"><ol>
<li>Download the file and double-click it to open <b>Keychain Access</b>, adding it to the <b>System</b> keychain.</li>
<li>Find <b>Talon Local CA</b>, open it, expand <b>Trust</b>, and set <b>When using this certificate</b> to <b>Always Trust</b>.</li>
<li>Or:<br><code>sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain talon-ca.crt</code></li>
</ol></div>

<h2>Linux / Firefox</h2>
<div class="card"><ol>
<li>System-wide: copy to <code>/usr/local/share/ca-certificates/talon-ca.crt</code> and run <code>sudo update-ca-certificates</code>.</li>
<li>Firefox keeps its own store: <b>Settings → Privacy &amp; Security → Certificates → View Certificates → Authorities → Import</b>, and tick <em>Trust this CA to identify websites</em>.</li>
</ol></div>

<div class="meta">
This server's certificate is valid for: ${dns} ${ips}<br>
It expires on <b>${expiry}</b> and renews itself automatically, so you will not need to repeat this.<br>
If you reach Talon at an address that is not listed above, add it with
<code>TALON_EXTRA_SANS=name.example.ts.net</code> and restart the server.
</div>
</div></body></html>`;
}

// Create the HTTP server to serve static assets and handle REST API endpoints
const server = http.createServer((req, res) => {
  // Access log: fires for every request (API, static files, downloads,
  // everything), regardless of whether the route below has its own log
  // line. This is what gives full visibility into "what the server is
  // doing" without having to remember to instrument every new route.
  const reqStart = process.hrtime.bigint();
  const clientIp = (req.socket && req.socket.remoteAddress) || 'unknown';
  res.on('finish', () => {
    const durationMs = Number(process.hrtime.bigint() - reqStart) / 1e6;
    const statusColor = res.statusCode >= 500 ? '\x1b[31m' : res.statusCode >= 400 ? '\x1b[33m' : '\x1b[32m';
    console.log(
      `\x1b[90m[${timestamp()}] [HTTP]\x1b[0m ${req.method} ${Redact.url(req.url)} ${statusColor}${res.statusCode}${RESET} ${durationMs.toFixed(1)}ms  ${Redact.ip(clientIp)}`
    );
  });

  applySecurityHeaders(req, res);
  handleRequest(req, res);
});

// --- AUTHENTICATION ---
//
// The client proves itself with `authHash` = SHA256(authKey), where authKey is
// half of the password-derived master key. That value used to be stored in
// db.json verbatim, which meant a database leak was immediately a login as
// every user. It is now stored as SHA256(salt || authHash) with a random
// per-user salt, so the stored value cannot be replayed.
//
// A deliberately *fast* hash is correct here. authHash is not a password: the
// expensive work (PBKDF2, 600 000 iterations) already happened on the client,
// and that is what bounds an offline attack on a leaked database. Adding a
// slow KDF server-side would cost ~50 ms on every single authenticated
// request while raising the attacker's per-guess cost by only a few percent.
const AUTH_SECRET_PATH = path.join(DATA_DIR, 'server-secret.json');

function loadOrCreateServerSecret() {
  try {
    return JSON.parse(fs.readFileSync(AUTH_SECRET_PATH, 'utf-8')).secret;
  } catch {
    const secret = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(AUTH_SECRET_PATH, JSON.stringify({ secret }, null, 2), { mode: 0o600 });
    log('BOOT', 'Generated server secret (data/server-secret.json)');
    return secret;
  }
}
const SERVER_SECRET = loadOrCreateServerSecret();

function authVerifierFor(authHash, saltHex) {
  return crypto.createHash('sha256').update(saltHex + ':' + authHash).digest('hex');
}

function timingSafeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
  } catch {
    return false;
  }
}

/**
 * Verifies a client-presented authHash against the stored record, upgrading a
 * legacy verbatim authHash to a salted verifier on first successful use.
 */
function verifyAuth(user, authHash, req) {
  // A failed presentation costs the caller far more than a successful one.
  // The stored verifier is a fast hash on purpose, because the expensive PBKDF2
  // work happens client-side, so without a penalty the only thing bounding an
  // online guessing attack is the network. Charging only on failure means
  // ordinary use never comes near the limit.
  const charge = () => {
    if (req) authLimiter.take(clientKey(req), AUTH_FAILURE_COST);
  };

  if (!user || typeof authHash !== 'string') { charge(); return false; }

  if (user.authVerifier && user.authSalt) {
    const ok = timingSafeEqualHex(authVerifierFor(authHash, user.authSalt), user.authVerifier);
    if (!ok) charge();
    return ok;
  }

  // Legacy account: compare the stored verbatim value, then retire it.
  if (user.authHash && timingSafeEqualHex(user.authHash, authHash)) {
    const salt = crypto.randomBytes(16).toString('hex');
    Db.setAuthVerifier(user.username, salt, authVerifierFor(authHash, salt));
    log('API', `Upgraded stored credential to a salted verifier: ${Redact.tag(user.username)}`);
    return true;
  }

  return false;
}

/**
 * The KDF parameters a client must use for a given username.
 *
 * Unknown usernames get plausible, deterministic parameters derived from the
 * server secret rather than an error, so this endpoint cannot be used to
 * enumerate accounts. The salt is stable per username so repeated probes look
 * consistent.
 */
function kdfParamsFor(username) {
  const uname = String(username || '').toLowerCase();
  const user = Db.getUser(uname);

  if (user && user.kdfVersion >= 2 && user.kdfSalt) {
    return { v: user.kdfVersion, salt: user.kdfSalt, iterations: user.kdfIterations || 600000 };
  }
  if (user) {
    return { v: 1 }; // real account that has not been migrated yet
  }

  const fakeSalt = crypto.createHmac('sha256', SERVER_SECRET)
    .update('kdf-salt:' + uname).digest('hex').slice(0, 32);
  return { v: 2, salt: fakeSalt, iterations: 600000 };
}

// --- SECURITY HEADERS ---
//
// The client renders by assembling innerHTML strings, and the identity key,
// ratchet state and full message history all live in localStorage. A single
// escaping slip would therefore be enough to exfiltrate everything, so the CSP
// is the main structural defence and is deliberately strict:
//
//   script-src 'self'   no inline script anywhere. This is why the
//                         pre-paint theme code lives in theme-preload.js
//                         rather than a <script> block in index.html.
//   connect-src 'self'  the app may only talk to this origin. Even if
//                         script execution were achieved, there is nowhere
//                         to send the stolen keys.
//   img-src blob:       decrypted attachments and avatars are object URLs.
//   media-src blob:     decrypted voice notes.
//   frame-ancestors     clickjacking.
//
// 'unsafe-inline' IS present for style-src: the app sets inline style
// attributes for avatar gradients and per-author hues. Those are values, not
// executable code, so the exposure is cosmetic rather than a script vector.
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' blob: data:",
  "media-src 'self' blob:",
  "font-src 'self'",
  "connect-src 'self' ws: wss:",
  "worker-src 'self'",
  "manifest-src 'self'",
  "base-uri 'none'",
  "object-src 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'"
].join('; ');

function applySecurityHeaders(req, res) {
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  // getUserMedia is needed for calls and voice notes; everything else is off.
  res.setHeader('Permissions-Policy', 'camera=(self), microphone=(self), geolocation=(), interest-cohort=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');

  // HSTS only on the TLS listener. Sending it over plain HTTP is meaningless,
  // and pinning port 8080 to HTTPS would lock the user out of the fallback.
  if (req.socket && req.socket.encrypted) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  }
}

/**
 * Credentials for the attachment endpoints, carried in headers.
 *
 * Headers rather than query parameters, deliberately: every request URL goes
 * through the access log, so `?authHash=...` would write a working credential
 * into a plaintext file on disk. The body is not an option either, because
 * upload streams its body straight to a file.
 *
 * Returns the user record, or null. Nothing here weakens the zero-knowledge
 * position: the relay already stores a salted verifier and already knows which
 * accounts exist.
 */
function authFromHeaders(req) {
  const username = String(req.headers['x-talon-user'] || '').toLowerCase();
  const authHash = String(req.headers['x-talon-auth'] || '');
  if (!username || !authHash) return null;
  const user = Db.getUser(username);
  return verifyAuth(user, authHash, req) ? user : null;
}

// Blobs are content-addressed by crypto.randomUUID(). Validating that shape
// before touching the filesystem closes path traversal by construction rather
// than by trying to spot "..".
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/* ------------------------------------------------------------ rate limits */
//
// Deliberately generous. This is a relay for a handful of devices you own on a
// tailnet, so the job is to bound accidents, a runaway client and a
// compromised device, not to survive the open internet. Locking someone out
// of their own messenger is the worse failure, so every limit here is set well
// above anything normal use produces, and each is overridable.
//
// Keyed by remote address before authentication and by username after: an
// unauthenticated caller has no identity to attribute a bucket to, and an
// authenticated one should not be able to escape their own limit by changing
// address.

const env = (name, fallback) => Number(process.env[name] ?? fallback);

// New accounts. On a personal relay you make a handful, ever. Db rewrites the
// whole JSON file on every mutation, so unbounded registration degrades
// everything else, not just the user table.
// A failed credential presentation costs this many tokens; a successful one
// costs nothing. With the defaults below that is roughly 6 wrong guesses in a
// burst, then about 6 a minute sustained.
const AUTH_FAILURE_COST = env('TALON_RL_AUTH_FAILURE_COST', 5);

const registerLimiter = createLimiter({
  name: 'register',
  capacity: env('TALON_RL_REGISTER_BURST', 5),
  refillPerSec: env('TALON_RL_REGISTER_PER_HOUR', 5) / 3600
});

// Failed credential presentations. The stored verifier is a fast hash by
// design (the expensive work happens client-side), so without this the only
// thing bounding an online guessing attack is the network. Successful attempts
// are refunded, so ordinary use never touches this.
const authLimiter = createLimiter({
  name: 'auth',
  capacity: env('TALON_RL_AUTH_BURST', 20),
  refillPerSec: env('TALON_RL_AUTH_PER_MIN', 30) / 60
});

// Upload count per account. A single file is capped by MAX_UPLOAD_BYTES, but
// nothing capped how many, so one authenticated device could still fill the
// disk one 25 MB file at a time.
const uploadLimiter = createLimiter({
  name: 'upload',
  capacity: env('TALON_RL_UPLOAD_BURST', 30),
  refillPerSec: env('TALON_RL_UPLOAD_PER_HOUR', 120) / 3600
});

// Relayed envelopes per socket. Generous enough that a group fan-out to every
// member, which is several sends in quick succession, never trips it.
const sendLimiter = createLimiter({
  name: 'send',
  capacity: env('TALON_RL_SEND_BURST', 120),
  refillPerSec: env('TALON_RL_SEND_PER_SEC', 20)
});

startSweeping([registerLimiter, authLimiter, uploadLimiter, sendLimiter]);

/** Refuses a request with 429 and a Retry-After the client can act on. */
function tooManyRequests(res, limiter, key, cost = 1, closeSocket = false) {
  const wait = limiter.retryAfter(key, cost);
  const headers = {
    'Content-Type': 'application/json',
    'Retry-After': String(Math.max(1, wait))
  };
  // Same reasoning as the 401 path: rejecting before the body is read leaves
  // bytes in the socket, and the next keep-alive request is then parsed from
  // the middle of this one.
  if (closeSocket) headers['Connection'] = 'close';
  res.writeHead(429, headers);
  res.end(JSON.stringify({
    success: false,
    error: 'Too many requests. Try again shortly.',
    retryAfter: wait
  }));
}

// An unauthenticated, uncapped upload endpoint is a disk-fill primitive for
// anyone who can reach the port. Both halves of that are fixed: a credential
// is required, and the stream is cut off past this size.
const MAX_UPLOAD_BYTES = Number(process.env.TALON_MAX_UPLOAD_MB ?? 25) * 1024 * 1024;

function handleRequest(req, res) {
  // 1. Handle REST API POST Requests
  if (req.method === 'POST') {
    if (req.url === '/api/upload') {
      const uploader = authFromHeaders(req);
      if (uploader && !uploadLimiter.take(uploader.username)) {
        log('API', `Upload refused: ${Redact.tag(uploader.username)} over the upload rate limit`);
        tooManyRequests(res, uploadLimiter, uploader.username, 1, true);
        return;
      }
      if (!uploader) {
        log('API', 'Upload refused: missing or invalid credential');
        // `Connection: close` is load-bearing. Rejecting before the body has
        // been read leaves unconsumed bytes in the socket, and on a keep-alive
        // connection the next request is then parsed starting from the middle
        // of this one's body, so it hangs. Draining instead would mean reading
        // an unbounded body from someone who just failed to authenticate,
        // which is the bandwidth version of the problem this check exists to
        // stop. Closing the socket refuses without reading a byte.
        res.writeHead(401, { 'Content-Type': 'application/json', 'Connection': 'close' });
        res.end(JSON.stringify({ success: false, error: 'Authentication required.' }));
        return;
      }

      const fileId = crypto.randomUUID();
      const filePath = path.join(UPLOADS_DIR, fileId);
      const writeStream = fs.createWriteStream(filePath);
      let received = 0;
      let aborted = false;

      // A partial file must never survive a rejected or broken upload: the GC
      // only sweeps on age, so anything left behind sits there for 30 days.
      const discard = () => {
        writeStream.destroy();
        fs.rm(filePath, { force: true }, () => {});
      };

      req.on('data', (chunk) => {
        if (aborted) return;
        received += chunk.length;
        if (received > MAX_UPLOAD_BYTES) {
          aborted = true;
          discard();
          log('API', `Upload refused from ${Redact.tag(uploader.username)}: over ${MAX_UPLOAD_BYTES} bytes`);
          res.writeHead(413, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: 'File too large.' }));
          req.destroy();
        }
      });

      req.pipe(writeStream);

      // Respond when the file is actually on disk, not when the request body
      // ends. createWriteStream opens the file asynchronously, so for a small
      // upload `req`'s 'end' fires first and the old fs.statSync(filePath)
      // threw ENOENT from inside an event handler: an uncaught exception, no
      // response, and a client left hanging until it timed out. Large uploads
      // hid it because the open always won that race. The byte counter below
      // also removes the need to stat the file at all.
      writeStream.on('finish', () => {
        if (aborted) return;
        log('API', `File uploaded by ${Redact.tag(uploader.username)}: ${Redact.tag(fileId)} (${(received / 1024).toFixed(1)} KB)`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, id: fileId }));
      });

      const failUpload = (err) => {
        if (aborted) return;
        aborted = true;
        discard();
        logError('API', 'Upload error:', err);
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json', 'Connection': 'close' });
          res.end(JSON.stringify({ success: false, error: 'Upload failed.' }));
        }
      };
      req.on('error', failUpload);
      writeStream.on('error', failUpload);
      return;
    }
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    req.on('end', () => {
      try {
        const payload = JSON.parse(body);

        // Enforce the failed-credential budget before dispatching. verifyAuth
        // *spends* tokens on every failure, but spending alone throttles
        // nothing: something has to refuse the request once the bucket is
        // empty, and that is this. Checked here rather than per route so a
        // route added later cannot forget it.
        //
        // `allowed` deliberately does not spend. A correct credential must
        // stay free no matter how many of them arrive, or ordinary use starts
        // failing under exactly the conditions it should not.
        if (payload && typeof payload.authHash === 'string'
            && !authLimiter.allowed(clientKey(req))) {
          log('API', `Refused ${Redact.url(req.url)}: ${Redact.tag(clientKey(req))} over the failed-credential limit`);
          tooManyRequests(res, authLimiter, clientKey(req));
          return;
        }

        if (req.url === '/api/register') {
          // Keyed by address: there is no identity to attribute this to yet.
          // Db rewrites the whole JSON file on every mutation, so unbounded
          // registration degrades every other operation, not just the user
          // table.
          if (!registerLimiter.take(clientKey(req))) {
            log('API', `Registration refused: ${Redact.tag(clientKey(req))} over the rate limit`);
            tooManyRequests(res, registerLimiter, clientKey(req));
            return;
          }

          const { username, idPub, authHash, encryptedIdPriv, encryptedIdPrivNonce } = payload;
          if (!username || !idPub || !authHash || !encryptedIdPriv || !encryptedIdPrivNonce) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Missing required registration parameters.' }));
            return;
          }

          // Username validation
          const userRegex = /^[a-zA-Z0-9_]{3,20}$/;
          if (!userRegex.test(username)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Username must be 3-20 alphanumeric characters.' }));
            return;
          }

          if (Db.getUser(username)) {
            res.writeHead(409, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Username is already taken.' }));
            return;
          }

          // New accounts are always KDF v2. The client derived its key from
          // kdfSalt, which it obtained from /api/kdf-params before registering.
          const { kdfVersion, kdfSalt, kdfIterations } = payload;
          if (kdfVersion !== 2 || typeof kdfSalt !== 'string' || kdfSalt.length < 16) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Unsupported key-derivation parameters.' }));
            return;
          }

          const authSalt = crypto.randomBytes(16).toString('hex');
          Db.createUser(username, {
            idPub,
            kdfVersion,
            kdfSalt,
            kdfIterations: kdfIterations || 600000,
            authSalt,
            authVerifier: authVerifierFor(authHash, authSalt),
            encryptedIdPriv,
            encryptedIdPrivNonce
          });

          log('API', `Registered user: ${Redact.tag(username.toLowerCase())} (KDF v${kdfVersion})`);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true }));
          return;
        }

        if (req.url === '/api/login') {
          const { username, authHash } = payload;
          if (!username || !authHash) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Missing username or auth token.' }));
            return;
          }

          const user = Db.getUser(username);
          if (!verifyAuth(user, authHash, req)) {
            log('API', `Failed login attempt for: ${Redact.tag(username)}`);
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Invalid username or password.' }));
            return;
          }

          log('API', `User logged in: ${Redact.tag(username.toLowerCase())} (KDF v${user.kdfVersion || 1})`);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            success: true,
            idPub: user.idPub,
            // Tells the client whether it should perform a KDF upgrade next.
            kdfVersion: user.kdfVersion || 1,
            encryptedIdPriv: user.encryptedIdPriv,
            encryptedIdPrivNonce: user.encryptedIdPrivNonce,
            encryptedContacts: user.encryptedContacts,
            encryptedContactsNonce: user.encryptedContactsNonce,
            encryptedGroups: user.encryptedGroups,
            encryptedGroupsNonce: user.encryptedGroupsNonce
          }));
          return;
        }

        // Returns the password-derivation parameters for a username. Answers
        // for unknown users too (with deterministic decoy parameters) so this
        // cannot be used to enumerate accounts.
        if (req.url === '/api/kdf-params') {
          const { username } = payload;
          if (!username) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Missing username.' }));
            return;
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, params: kdfParamsFor(username) }));
          return;
        }

        // Completes a transparent KDF upgrade. The client authenticates with
        // its OLD credential and supplies everything re-encrypted under the
        // new key; the swap is a single atomic write.
        if (req.url === '/api/upgrade-kdf') {
          const {
            username, authHash, newAuthHash,
            kdfVersion, kdfSalt, kdfIterations,
            encryptedIdPriv, encryptedIdPrivNonce,
            encryptedContacts, encryptedContactsNonce,
            encryptedGroups, encryptedGroupsNonce
          } = payload;

          const user = Db.getUser(username);
          if (!verifyAuth(user, authHash, req)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Unauthorized.' }));
            return;
          }
          if (kdfVersion !== 2 || typeof kdfSalt !== 'string' || kdfSalt.length < 16
              || typeof newAuthHash !== 'string' || !encryptedIdPriv || !encryptedIdPrivNonce) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Invalid upgrade payload.' }));
            return;
          }

          const authSalt = crypto.randomBytes(16).toString('hex');
          Db.upgradeUserKdf(username, {
            kdfVersion,
            kdfSalt,
            kdfIterations: kdfIterations || 600000,
            authSalt,
            authVerifier: authVerifierFor(newAuthHash, authSalt),
            encryptedIdPriv,
            encryptedIdPrivNonce,
            encryptedContacts,
            encryptedContactsNonce,
            encryptedGroups,
            encryptedGroupsNonce
          });

          log('API', `KDF upgraded to v${kdfVersion}: ${Redact.tag(username.toLowerCase())}`);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true }));
          return;
        }

        if (req.url === '/api/sync-contacts') {
          const { username, authHash, encryptedContacts, encryptedContactsNonce } = payload;
          if (!username || !authHash || !encryptedContacts || !encryptedContactsNonce) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Missing sync data.' }));
            return;
          }

          const user = Db.getUser(username);
          if (!verifyAuth(user, authHash, req)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Unauthorized.' }));
            return;
          }

          Db.updateUserContacts(username, encryptedContacts, encryptedContactsNonce);
          log('API', `Contacts synced: ${Redact.tag(username.toLowerCase())}`);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true }));
          return;
        }

        // --- PROTOCOL v2 PREKEYS ---
        // Publish this account's public prekey material. Everything stored is
        // public; the signature is what stops this relay substituting keys.
        if (req.url === '/api/publish-prekeys') {
          const { username, authHash, signPub, signedPreKey, kemPreKey, caps, capsSig, oneTimePreKeys, deviceKey } = payload;
          const user = Db.getUser(username);
          if (!verifyAuth(user, authHash, req)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Unauthorized.' }));
            return;
          }
          // A multi-device client publishes under its own device key so the
          // devices do not consume each other's one-time prekeys. Omitting it
          // stores under the account key, which is what every single-device
          // client already does and must keep doing.
          const keyId = (typeof deviceKey === 'string' && /^[0-9a-f]{64}$/i.test(deviceKey))
            ? deviceKey
            : user.idPub;
          // `caps` is bounded before storage. It is attacker-controlled input
          // that ends up in a record handed to every peer who asks, and an
          // unbounded array keyed by an authenticated user is still a way to
          // grow the database without limit. Short strings, few of them.
          const safeCaps = Array.isArray(caps)
            ? caps.filter((c) => typeof c === 'string' && c.length <= 16).slice(0, 8)
            : undefined;
          const safeCapsSig = (typeof capsSig === 'string' && /^[0-9a-f]{128}$/i.test(capsSig))
            ? capsSig : undefined;

          Db.publishPreKeys(keyId, {
            signPub, signedPreKey, kemPreKey, oneTimePreKeys,
            // Both or neither. A list without its signature is one the client
            // will refuse anyway, and storing it would only make the refusal
            // happen later and look like a different bug.
            caps: safeCapsSig ? safeCaps : undefined,
            capsSig: safeCaps ? safeCapsSig : undefined
          });
          // The pool size is read into a local before the log line rather than
          // called inside it. The identity is only an argument here and never
          // printed, but the redaction check in test/redact.test.js reads the
          // source and cannot know that. Keeping the rule absolute, with no
          // allowlist to append to, is worth one extra line.
          const poolRemaining = Db.countOneTimePreKeys(keyId);
          const perDevice = keyId === user.idPub ? '' : ', per-device';
          log('API', `Prekeys published: ${Redact.tag(username.toLowerCase())} (+${(oneTimePreKeys || []).length} one-time, ${poolRemaining} in pool${kemPreKey ? ', ML-KEM' : ''}${perDevice})`);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, remaining: poolRemaining }));
          return;
        }

        // Fetch a peer's bundle to open a session. Consumes a one-time prekey.
        if (req.url === '/api/prekey-bundle') {
          const { username, authHash, peerId } = payload;
          const user = Db.getUser(username);
          if (!verifyAuth(user, authHash, req)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Unauthorized.' }));
            return;
          }
          if (typeof peerId !== 'string' || peerId.length !== 64) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Invalid peer id.' }));
            return;
          }

          // A multi-device peer needs one bundle per device, each consuming
          // that device's own one-time prekey. `bundle` is still returned for
          // a single-device peer, unchanged, so an un-upgraded client that
          // ignores `devices` keeps working exactly as before.
          const devices = Db.takeDeviceBundles(peerId);
          if (devices) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, bundle: null, devices }));
            return;
          }

          const bundle = Db.takePreKeyBundle(peerId);
          // A missing bundle is not an error: the peer may still be on v1, and
          // the caller falls back to the legacy handshake.
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, bundle: bundle || null, devices: null }));
          return;
        }

        // How many one-time prekeys are left, so the client can top up.
        if (req.url === '/api/prekey-count') {
          const { username, authHash, deviceKey } = payload;
          const user = Db.getUser(username);
          if (!verifyAuth(user, authHash, req)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Unauthorized.' }));
            return;
          }
          // Counted against the same pool the caller publishes into, or a
          // multi-device client would top up the account pool forever while
          // its own ran dry.
          const countKey = (typeof deviceKey === 'string' && /^[0-9a-f]{64}$/i.test(deviceKey))
            ? deviceKey
            : user.idPub;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, remaining: Db.countOneTimePreKeys(countKey) }));
          return;
        }

        // --- DEVICE LISTS ---
        //
        // Publish the list of devices on this account. Signed by the account,
        // stored verbatim, never verified here: see the note on setDeviceList
        // in db.js for why the relay is deliberately not the gate.
        if (req.url === '/api/publish-devices') {
          const { username, authHash, list } = payload;
          const user = Db.getUser(username);
          if (!verifyAuth(user, authHash, req)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Unauthorized.' }));
            return;
          }

          const result = Db.setDeviceList(user.idPub, list);
          if (!result.ok) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: result.reason }));
            return;
          }

          // The count is a number, but it is derived from an identity, so it
          // goes into a local first. Same rule as poolRemaining above.
          const deviceCount = list.devices.length;
          log('API', `Device list published: ${Redact.tag(username.toLowerCase())} (rev ${list.rev}, ${deviceCount} device(s))`);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true }));
          return;
        }

        // Fetch a peer's device list so a sender knows how many envelopes to
        // produce. Authenticated like every other read, so the device layout
        // of an account is not public.
        if (req.url === '/api/devices') {
          const { username, authHash, peerId } = payload;
          const user = Db.getUser(username);
          if (!verifyAuth(user, authHash, req)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Unauthorized.' }));
            return;
          }
          if (typeof peerId !== 'string' || peerId.length !== 64) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Invalid peer id.' }));
            return;
          }

          // A null list is not an error. It means a single-device peer, and
          // the caller addresses the account key as it always has.
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, list: Db.getDeviceList(peerId) }));
          return;
        }

        // Lists the push subscriptions registered for this account so the
        // client can show a device list and revoke individual ones.
        // Deliberately returns only the push *service* host and the date
        // added, never anything derived from message traffic.
        if (req.url === '/api/devices') {
          const { username, authHash } = payload;
          const user = Db.getUser(username);
          if (!verifyAuth(user, authHash, req)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Unauthorized.' }));
            return;
          }

          const devices = Db.getPushSubscriptions(user.idPub).map((sub) => {
            let service = 'Push service';
            try { service = new URL(sub.endpoint).hostname; } catch (e) { /* keep default */ }
            return { service, addedAt: sub.addedAt || null, endpoint: sub.endpoint };
          });

          log('API', `Device list requested: ${Redact.tag(username.toLowerCase())} (${devices.length})`);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, devices }));
          return;
        }

        if (req.url === '/api/sync-groups') {
          const { username, authHash, encryptedGroups, encryptedGroupsNonce } = payload;
          if (!username || !authHash || !encryptedGroups || !encryptedGroupsNonce) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Missing sync data.' }));
            return;
          }

          const user = Db.getUser(username);
          if (!verifyAuth(user, authHash, req)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Unauthorized.' }));
            return;
          }

          Db.updateUserGroups(username, encryptedGroups, encryptedGroupsNonce);
          log('API', `Groups synced: ${Redact.tag(username.toLowerCase())}`);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true }));
          return;
        }

        if (req.url === '/api/push-subscribe') {
          const { username, authHash, subscription } = payload;
          if (!username || !authHash || !subscription || !subscription.endpoint || !subscription.keys) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Missing subscription data.' }));
            return;
          }

          const user = Db.getUser(username);
          if (!verifyAuth(user, authHash, req)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Unauthorized.' }));
            return;
          }

          // Subscriptions are keyed by idPub (the identity key), not username,
          // since that's what message routing and push targeting use.
          Db.addPushSubscription(user.idPub, subscription);
          log('PUSH', `Subscribed device for ${Redact.tag(username.toLowerCase())}`);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true }));
          return;
        }

        if (req.url === '/api/push-unsubscribe') {
          const { username, authHash, endpoint } = payload;
          if (!username || !authHash || !endpoint) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Missing endpoint.' }));
            return;
          }

          const user = Db.getUser(username);
          if (!verifyAuth(user, authHash, req)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Unauthorized.' }));
            return;
          }

          Db.removePushSubscription(user.idPub, endpoint);
          log('PUSH', `Unsubscribed device for ${Redact.tag(username.toLowerCase())}`);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true }));
          return;
        }

        // /api/push-mute is gone on purpose. The relay used to hold a
        // plaintext list of muted conversation IDs so it could skip a push,
        // which meant being handed a slice of every user's contact graph. The
        // decision now lives in the service worker, which reads an opaque tag
        // list from IndexedDB. See web/src/pushdb.js.

        // Catch-all POST
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'API route not found.' }));
      } catch (err) {
        logError('API', 'Error parsing request body:', err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Internal server processing error.' }));
      }
    });
    return;
  }

  if (req.method === 'GET' && req.url === '/api/vapid-public-key') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ publicKey: Push.publicKey }));
    return;
  }

  if (req.method === 'GET' && req.url.startsWith('/api/download/')) {
    if (!authFromHeaders(req)) {
      log('API', 'Download refused: missing or invalid credential');
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'Authentication required.' }));
      return;
    }

    // Strip any query string, then require the UUID shape. `split('/').pop()`
    // on its own would happily hand `..` to path.join.
    const fileId = req.url.split('/').pop().split('?')[0];
    if (!UUID_RE.test(fileId)) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('Bad file id');
      return;
    }
    const filePath = path.join(UPLOADS_DIR, fileId);

    if (!fs.existsSync(filePath)) {
      log('API', `Download requested for missing file: ${Redact.tag(fileId)}`);
      res.writeHead(404);
      res.end('File not found');
      return;
    }

    // Touch the blob so the GC's age check measures time since last USE, not
    // time since upload. Without this the sweeper deletes by upload date
    // alone, which quietly killed every avatar on its 30th day: an avatar is
    // uploaded once and referenced forever, so it was always the oldest file
    // in the directory and always the first to go.
    try { const now = new Date(); fs.utimesSync(filePath, now, now); } catch { /* read-only or raced */ }

    log('API', `File downloaded: ${Redact.tag(fileId)}`);
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      // Immutable and encrypted, so a year is safe. `private` now that the
      // response depends on a credential: this must not land in a shared
      // cache, and Vary keeps a browser from reusing one account's copy for
      // another's request.
      'Cache-Control': 'private, max-age=31536000',
      'Vary': 'X-Talon-User'
    });
    fs.createReadStream(filePath).pipe(res);
    return;
  }

  // --- Local CA distribution ---
  // Downloading and trusting this once per device is what removes the browser
  // warning for good. Content-Type must be application/x-x509-ca-cert: it is
  // what makes iOS offer the "install profile" flow and Android the
  // "install certificate" dialog rather than dumping the PEM as text.
  // Cache-Control: no-store so a device never installs a stale CA after a
  // regeneration (and so the service worker refuses to hold onto it).
  if (req.method === 'GET' && (req.url === '/ca.crt' || req.url === '/ca.pem')) {
    log('TLS', `CA certificate downloaded by ${Redact.ip(req.socket && req.socket.remoteAddress)}`);
    res.writeHead(200, {
      'Content-Type': req.url.endsWith('.pem') ? 'application/x-pem-file' : 'application/x-x509-ca-cert',
      'Content-Disposition': 'attachment; filename="talon-ca.crt"',
      'Cache-Control': 'no-store'
    });
    res.end(tlsInfo.caPem);
    return;
  }

  if (req.method === 'GET' && (req.url === '/setup' || req.url === '/setup/')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(renderSetupPage());
    return;
  }

  // 2. Serve static files from web/public
  let safeUrl = req.url.split('?')[0];
  if (safeUrl === '/') safeUrl = '/index.html';

  /**
   * Cache policy per file. This is load-bearing and was previously wrong.
   *
   * Everything except sw.js used to be `public, max-age=3600` with no ETag.
   * That is a promise to the browser that the file cannot change for an hour,
   * and with no validator there was nothing to revalidate against, so the
   * phone kept serving an hour-old shell from its own HTTP cache. The service
   * worker could not save it either: `cache.add()` at install time and the
   * stale-while-revalidate background fetch both go through that same HTTP
   * cache, so a new CACHE_NAME was filled straight back up with stale bytes.
   * Bumping CACHE_NAME therefore appeared to do nothing, which is exactly the
   * symptom it produced.
   *
   * The shell is now `no-cache`, meaning "you may store it, but ask me every
   * time". With the ETag above, asking costs a 304 and no body.
   */
  function cacheControlFor(urlPath) {
    // The service worker script itself: never stored, at all. If this one goes
    // stale the device can never be told about any other change.
    if (urlPath.endsWith('/sw.js')) return 'no-cache, no-store, must-revalidate';

    // Content-addressed by nothing, but revalidated every load. These are the
    // files that change when the app changes.
    if (/\.(html|css|js|json|webmanifest)$/.test(urlPath)) return 'no-cache';

    // Fonts and icons change only when their filename does. A year is safe,
    // and it keeps the expensive assets off the wire.
    return 'public, max-age=31536000, immutable';
  }

  const filePath = path.join(PUBLIC_DIR, safeUrl);

  // Security check: ensure path lies within public directory
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.statusCode = 403;
    res.setHeader('Content-Type', 'text/plain');
    res.end('Forbidden');
    return;
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.statusCode = 404;
        res.setHeader('Content-Type', 'text/plain');
        res.end('404 Not Found');
      } else {
        res.statusCode = 500;
        res.setHeader('Content-Type', 'text/plain');
        res.end(`Internal Server Error: ${err.code}`);
      }
      return;
    }

    // A strong ETag over the bytes, so a revalidation costs one 304 rather
    // than a re-download. Everything here is small enough to hash per request.
    const etag = `"${crypto.createHash('sha1').update(content).digest('base64url')}"`;

    if (req.headers['if-none-match'] === etag) {
      res.writeHead(304, { 'ETag': etag, 'Cache-Control': cacheControlFor(safeUrl) });
      res.end();
      return;
    }

    res.writeHead(200, {
      'Content-Type': contentType,
      'ETag': etag,
      'Cache-Control': cacheControlFor(safeUrl)
    });
    res.end(content, 'utf-8');
  });
}

// Create the WebSocket server running on the same port
const wss = new WebSocketServer({ server });

// Online WebSocket client mapping
// clientId (idPub hex) -> Map<deviceId, ws>
//
// One socket per DEVICE, not per identity. It used to be a single socket per
// identity, so a second device registering the same account evicted the first
// from the map: the old socket stayed open but became unroutable, which looks
// exactly like messages silently vanishing.
//
// A client that names no device registers under ACCOUNT_BUCKET, which cannot
// collide with a real device id because it is not 16 hex. That is what every
// single-device client does, and it keeps working untouched.
//
// The map carries nothing but sockets. It used to hold a self-reported
// activeConversationId and focused flag for push suppression; both are the
// service worker's job now, so the relay no longer records what anyone is
// looking at.
const onlineClients = new Map();

/** Every open socket for an account, across its devices. */
function socketsFor(clientId) {
  const devices = onlineClients.get(clientId);
  if (!devices) return [];
  return [...devices.values()].filter((ws) => ws && ws.readyState === 1);
}

/** Total connected sockets, for the stats line. */
function connectedCount() {
  let n = 0;
  for (const devices of onlineClients.values()) n += devices.size;
  return n;
}

// `req` is the HTTP upgrade request. It is threaded through so verifyAuth can
// charge failed credential attempts to the connecting address, exactly as the
// REST routes do, and so the send limiter has something to key on before the
// socket has registered an identity.
wss.on('connection', (ws, req) => {
  let registeredClientId = null;
  let registeredDeviceId = null;

  ws.on('message', (messageStr) => {
    try {
      const data = JSON.parse(messageStr);

      switch (data.type) {
        case 'register': {
          // AUTHENTICATED. `register` is what drains the offline queue, and
          // the drain is destructive: getAndClearOfflineMessages deletes as
          // it reads. Accepting a bare Client ID meant anyone who knew a
          // 64-hex ID, a value the app openly encourages users to share,
          // could connect and destroy that user's queued mail. They could
          // never read it, the ratchet still holds, but losing it is enough.
          //
          // The check mirrors the REST routes: username + authHash against
          // the stored verifier. It additionally binds the credential to the
          // identity, so a valid account cannot register as someone else's
          // idPub.
          const { clientId, username, authHash, deviceId } = data;
          if (!clientId || clientId.length !== 64) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid Client ID.' }));
            return;
          }
          // A device id is optional and must look like one. Anything else is
          // read as "no device", which is the single-device path.
          const devKey = (typeof deviceId === 'string' && /^[0-9a-f]{16}$/i.test(deviceId))
            ? deviceId.toLowerCase()
            : ACCOUNT_BUCKET;

          const user = Db.getUser(String(username || '').toLowerCase());
          if (!verifyAuth(user, authHash, req) || user.idPub !== clientId) {
            ws.send(JSON.stringify({ type: 'registered', success: false, reason: 'auth' }));
            log('WS', `Rejected register for ${Redact.tag(clientId)}: bad credentials`);
            ws.close(4001, 'Authentication failed');
            return;
          }

          registeredClientId = clientId;
          registeredDeviceId = devKey;

          if (!onlineClients.has(clientId)) onlineClients.set(clientId, new Map());
          const devices = onlineClients.get(clientId);
          // Replacing the entry for THIS device is right: a reconnect from the
          // same device should displace its own stale socket. Replacing the
          // whole account is what the old single-socket map did, and it is
          // what made a second device unroutable.
          const previous = devices.get(devKey);
          if (previous && previous !== ws) {
            try { previous.close(4002, 'Replaced by a newer connection'); } catch { /* already gone */ }
          }
          devices.set(devKey, ws);
          log('WS', `Client online: ${Redact.tag(clientId)} (${devices.size} device(s) on this account, ${connectedCount()} total connected)`);

          ws.send(JSON.stringify({ type: 'registered', success: true }));

          // Its own queue, plus anything a sender who never heard of devices
          // left in the account bucket. Without the second bucket those
          // envelopes would sit behind a device id no client will ever claim.
          const buckets = devKey === ACCOUNT_BUCKET ? [ACCOUNT_BUCKET] : [devKey, ACCOUNT_BUCKET];
          const queue = Db.getAndClearOfflineMessages(clientId, buckets);
          if (queue.length > 0) {
            ws.send(JSON.stringify({ type: 'offline-messages', messages: queue }));
            log('WS', `Delivered ${queue.length} offline message(s) to ${Redact.tag(clientId)}`);
          }
          break;
        }

        case 'send': {
          const { recipientId, payload, pushTag, notify, ref } = data;
          if (!registeredClientId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Client not registered. Register first.' }));
            return;
          }
          if (!recipientId || recipientId.length !== 64 || !payload) {
            ws.send(JSON.stringify({ type: 'error', message: 'Missing recipient or payload.' }));
            return;
          }

          // Bounded per sending identity, not per socket, so reconnecting does
          // not reset it. The burst allowance is deliberately well above a
          // group fan-out, which is one send per member in quick succession
          // and is the largest legitimate spike the client ever produces.
          // Refusing tells the client rather than dropping silently: a
          // silently discarded envelope looks exactly like a delivery bug.
          if (!sendLimiter.take(registeredClientId)) {
            log('WS', `Send refused: ${Redact.tag(registeredClientId)} over the send rate limit`);
            ws.send(JSON.stringify({
              type: 'ack',
              recipientId,
              ref: (typeof ref === 'string' && ref.length <= 64) ? ref : undefined,
              status: 'rate-limited',
              retryAfter: sendLimiter.retryAfter(registeredClientId)
            }));
            return;
          }

          // The frame no longer names a conversation. It used to carry
          // , which for a group was the shared groupId repeated on
          // every envelope of the fan-out: collect the recipients that keep
          // appearing under one value and you have reconstructed the
          // membership of a group the relay is supposed to know nothing about.
          //
          // What arrives instead is an opaque tag the sender derived from the
          // conversation AND this one recipient, so the same group message
          // produces a different tag for every member. The relay forwards it
          // to the push service and never stores it.
          const tag = (typeof pushTag === 'string' && /^[0-9a-f]{1,64}$/i.test(pushTag))
            ? pushTag : undefined;

          // A sealed payload carries the sender inside an AEAD only the
          // recipient can open, so we neither forward, store, nor log it.
          // `senderId` is still set for un-upgraded clients, which have no
          // other way to know who a message came from.
          const isSealed = !!payload.sealed;

          // Correlation token for the ack. `payload.messageIndex` only exists
          // on v1 envelopes; a v2 envelope keeps its index inside the
          // ciphertext, so echoing the index alone left every v2 message stuck
          // on "sending". We bounce the sender's own opaque `ref` back instead
          // and never store or forward it. Both are sent so an un-upgraded
          // client still matches on the index.
          const ackRef = (typeof ref === 'string' && ref.length <= 64) ? ref : undefined;
          const ackFor = (status) => JSON.stringify({
            type: 'ack', recipientId, ref: ackRef, messageIndex: payload.messageIndex, status
          });

          const routedMessage = {
            type: 'message',
            senderId: isSealed ? undefined : registeredClientId,
            payload
          };

          // Which device this envelope is for.
          //
          // NEW PLAINTEXT ON THE WIRE, and a deliberate one: the relay now
          // learns which of an account's devices a message is addressed to.
          // It already knows the devices exist and which are connected, so the
          // increment is small, but it is not nothing and it is written down
          // rather than slipped in.
          //
          // The alternative was fanning every envelope out to every socket and
          // letting the wrong ones fail to decrypt. That leaks less, but it
          // makes the offline queue grow with the square of the device count,
          // which is a denial of service against the relay's own disk.
          const targetDev = (typeof data.recipientDev === 'string' && /^[0-9a-f]{16}$/i.test(data.recipientDev))
            ? data.recipientDev.toLowerCase()
            : null;

          // A named device goes to exactly that socket. An unnamed one is from
          // a sender that has never heard of devices, so it goes to every
          // socket on the account and only the device holding the session can
          // open it.
          const openSockets = targetDev
            ? [(onlineClients.get(recipientId) || new Map()).get(targetDev)]
              .filter((s) => s && s.readyState === 1)
            : socketsFor(recipientId);

          let queued = false;
          if (openSockets.length > 0) {
            const frame = JSON.stringify(routedMessage);
            for (const sock of openSockets) sock.send(frame);
            ws.send(ackFor('delivered'));
            log('WS', Redact.redacting
              ? `Routed message live (${isSealed ? 'sealed' : 'addressed'})`
              : isSealed
                ? `Routed sealed message live: -> ${Redact.tag(recipientId)}`
                : `Routed message live: ${Redact.tag(registeredClientId)} -> ${Redact.tag(recipientId)}`);
          } else {
            // Queue message persistently in db
            // null sender: the queue on disk must not say who wrote what.
            const queuedSender = isSealed ? null : registeredClientId;
            if (targetDev) {
              Db.addOfflineMessage(queuedSender, recipientId, payload, targetDev);
            } else {
              // The sender named no device. If the recipient has published
              // some, one row per device, so the one actually holding the
              // session is guaranteed to get it. A single shared row would be
              // a race that the wrong device can win, and losing it is
              // indistinguishable from a delivery bug.
              //
              // This is the only place the queue grows with the device count,
              // and only for a sender that has never heard of devices. The
              // list is capped at eight.
              const list = Db.getDeviceList(recipientId);
              const targets = (list && list.devices.length)
                ? list.devices.map((d) => d.deviceId)
                : [null];
              for (const t of targets) {
                Db.addOfflineMessage(queuedSender, recipientId, payload, t);
              }
            }
            queued = true;
            ws.send(ackFor('queued'));
            log('WS', Redact.redacting
              ? `Queued offline message (${isSealed ? 'sealed' : 'addressed'}, recipient unreachable)`
              : isSealed
                ? `Queued sealed offline message: -> ${Redact.tag(recipientId)}`
                : `Queued offline message (recipient unreachable): ${Redact.tag(registeredClientId)} -> ${Redact.tag(recipientId)}`);
          }

          // --- Push notification decision ---
          // Only fire for payloads the sender explicitly marked as
          // notify-worthy (real chat content), never for typing indicators,
          // read receipts, reactions, profile syncs, or call signalling, all
          // of which travel over this same 'send' frame.
          //
          // That is now the ONLY thing the relay decides. Suppression used to
          // be two-layered: the relay skipped a push when the conversation was
          // muted or the recipient was already looking at it, and the service
          // worker double-checked. Both server-side checks needed the relay to
          // know which conversation this was and which one you had open, and
          // the muted list had to be uploaded in the clear to make the first
          // one work. Neither is worth a stored contact graph and a running
          // record of what you are reading.
          //
          // The service worker was already doing the same check and is the
          // only thing awake when the app is closed, so it now does it alone.
          // The cost is a push that occasionally travels and is then
          // discarded on arrival, which is a little more traffic in exchange
          // for the relay knowing nothing.
          //
          // AND ONLY WHEN THE MESSAGE WAS QUEUED. A recipient with an open
          // socket already has the envelope; the page raises its own
          // notification if it is hidden, which it can do because it can
          // actually read the message. Pushing on the live path told the
          // push service nothing useful and cost a wakeup per message.
          //
          // It also closes the last thing that separated real traffic from
          // cover traffic on the wire. Cover cells only ever go to peers that
          // are online, so with pushes fired only on the queued path there is
          // no `notify` for the relay to correlate against them. Sending a
          // push for a live delivery would have made `notify: true` mean
          // "this one is real", and constant-rate traffic would have been
          // decoration.
          if (notify && queued) {
            Push.notify(recipientId, { t: tag })
              .catch(err => logError('PUSH', 'notify error:', err));
          }
          break;
        }

        case 'ping': {
          log('WS', `Ping/keepalive from ${registeredClientId ? Redact.tag(registeredClientId) : 'unregistered client'}`);
          ws.send(JSON.stringify({ type: 'pong' }));
          break;
        }

        default: {
          ws.send(JSON.stringify({ type: 'error', message: `Unknown action: ${data.type}` }));
        }
      }
    } catch (err) {
      logError('WS', 'Error processing frame:', err);
      ws.send(JSON.stringify({ type: 'error', message: 'Malformed JSON payload.' }));
    }
  });

  ws.on('close', () => {
    if (registeredClientId) {
      // Only this device leaves. Deleting the whole account would take every
      // other device of theirs offline with it, which is the single-socket
      // bug in a new place.
      //
      // The identity check matters on a reconnect: the same device opening a
      // new socket replaces the entry, and this close handler then fires for
      // the OLD socket. Without it, the stale close would evict the live one.
      const devices = onlineClients.get(registeredClientId);
      if (devices && devices.get(registeredDeviceId) === ws) {
        devices.delete(registeredDeviceId);
        if (devices.size === 0) onlineClients.delete(registeredClientId);
      }
      log('WS', `Client offline: ${Redact.tag(registeredClientId)} (${connectedCount()} total connected)`);
    }
  });

  ws.on('error', (err) => {
    logError('WS', 'WebSocket error:', err);
  });
});

// HTTP server on port 8080 (for local/fallback use)
const PORT = process.env.PORT || 8080;
server.listen(PORT, '0.0.0.0', () => {
  log('BOOT', `HTTP listener bound on port ${PORT}`);
});

// HTTPS server on port 8443. Required for getUserMedia (camera/mic) on non-localhost
const HTTPS_PORT = process.env.HTTPS_PORT || 8443;
const httpsServer = https.createServer(tlsOptions, server.listeners('request')[0]);

// Tailscale hands out addresses from the CGNAT range 100.64.0.0/10.
const isTailnetAddress = (ip) => {
  const m = /^100\.(\d{1,3})\./.exec(ip);
  return !!m && Number(m[1]) >= 64 && Number(m[1]) <= 127;
};

/**
 * The single most confusing failure this project has: the CA installs fine,
 * the phone still refuses to load, and nothing says why.
 *
 * A certificate only covers the addresses in its SAN list. If Tailscale was
 * not connected when the leaf was issued, os.networkInterfaces() never
 * reported a 100.x address, so the leaf does not cover the one address the
 * phone actually dials. The browser then rejects it no matter how well the CA
 * is trusted, because the name does not match. Silence here reads as "the
 * certificate install did not work", which sends people round the trust
 * instructions again instead of at the real cause.
 */
function warnIfNoTailnetAddress(sans) {
  if (sans.ips.some(isTailnetAddress)) return;
  if (sans.dns.some((d) => d.endsWith('.ts.net'))) return;

  log('TLS', '');
  log('TLS', 'NOTE: this certificate covers no Tailscale address.');
  log('TLS', '  Every address it does cover is listed above. A phone reaching');
  log('TLS', `  this relay on a 100.x address will be refused by HTTPS even`);
  log('TLS', '  with the CA installed, because the name will not match.');
  log('TLS', '  Usually this means Tailscale was not connected at issue time.');
  log('TLS', '  Connect it and the certificate is re-issued within a minute,');
  log('TLS', '  or pin the name yourself:');
  log('TLS', '    TALON_EXTRA_SANS=your-host.tailnet.ts.net npm start');
  log('TLS', '');
}

/**
 * Re-check the machine's addresses while running and re-issue if they changed.
 *
 * ensureCertificates() already reissues when the SAN set differs, but it only
 * ran once at boot, so starting the relay before Tailscale connected left you
 * with a certificate missing the only address that matters until the next
 * restart. setSecureContext swaps the cert on the live listener, so nothing
 * has to be torn down and existing sockets are unaffected.
 */
const CERT_RECHECK_MS = 60_000;
setInterval(async () => {
  try {
    const fresh = await ensureCertificates(CERT_DIR, () => {});
    if (fresh.leafNotAfter.getTime() === tlsInfo.leafNotAfter.getTime()
        && fresh.sans.ips.join() === tlsInfo.sans.ips.join()
        && fresh.sans.dns.join() === tlsInfo.sans.dns.join()) {
      return;
    }
    httpsServer.setSecureContext({ key: fresh.key, cert: fresh.cert });
    tlsInfo = fresh;
    log('TLS', `Addresses changed, certificate re-issued and swapped in live.`);
    log('TLS', `  IP:  ${fresh.sans.ips.join(', ')}`);
    const tailnet = fresh.sans.ips.filter(isTailnetAddress);
    if (tailnet.length) {
      log('TLS', `  Tailscale address now covered: ${tailnet.join(', ')}`);
      log('TLS', '  Phones on the tailnet can connect over HTTPS from now on.');
    } else {
      warnIfNoTailnetAddress(fresh.sans);
    }
  } catch (err) {
    logError('TLS', 'Certificate re-check failed', err);
  }
}, CERT_RECHECK_MS).unref();

// Attach a second WSS to the HTTPS server
const wssSecure = new WebSocketServer({ server: httpsServer });
// Forward the upgrade request as well as the socket. Dropping it here would
// leave every HTTPS connection, which is to say every real one, with no
// address for the rate limiter to key on.
wssSecure.on('connection', (ws, upgradeReq) => {
  wss.emit('connection', ws, upgradeReq);
});

httpsServer.listen(HTTPS_PORT, '0.0.0.0', () => {
  log('BOOT', '====================================================');
  log('BOOT', 'Talon E2E Encrypted Messenger: Server Active');
  log('BOOT', '====================================================');
  log('BOOT', `[HTTP]   http://localhost:${PORT}          (local)`);
  log('BOOT', `[HTTPS]  https://localhost:${HTTPS_PORT}        (local, camera/mic OK)`);
  for (const ip of tlsInfo.sans.ips) {
    if (ip === '127.0.0.1' || ip === '::1') continue;
    const host = ip.includes(':') ? `[${ip}]` : ip;
    log('BOOT', `[HTTPS]  https://${host}:${HTTPS_PORT}`);
  }
  log('BOOT', `Node ${process.version}, PID ${process.pid}`);
  log('BOOT', `Log privacy: ${Redact.describe()}`);
  log('BOOT', '');
  log('BOOT', 'FIRST RUN ON A NEW DEVICE:');
  log('BOOT', `  Open https://<this-host>:${HTTPS_PORT}/setup and install the`);
  log('BOOT', '  Talon CA. One time per device, then no more warnings.');
  log('BOOT', `  Certificate valid until ${tlsInfo.leafNotAfter.toISOString().split('T')[0]} (auto-renews).`);
  log('BOOT', '====================================================');

  warnIfNoTailnetAddress(tlsInfo.sans);

  const initialStats = Db.getStats();
  log('STATS', `Loaded database: ${initialStats.totalUsers} user(s), ${initialStats.totalOfflineMessages} queued message(s), ${initialStats.totalPushSubscriptions} push subscription(s)`);
});

// --- PERIODIC STATS SNAPSHOT ---
// A full health/activity readout every 60s, so you can see the server's
// state at a glance without having to piece it together from individual
// event logs.
const STATS_INTERVAL_MS = 60_000;
setInterval(() => {
  const mem = process.memoryUsage();
  const stats = Db.getStats();
  const uptimeSec = Math.floor(process.uptime());
  const uptimeStr = `${Math.floor(uptimeSec / 3600)}h ${Math.floor((uptimeSec % 3600) / 60)}m ${uptimeSec % 60}s`;

  log('STATS', '--- periodic snapshot ---');
  log('STATS', `Uptime: ${uptimeStr}`);
  log('STATS', `Memory: RSS ${(mem.rss / 1024 / 1024).toFixed(1)} MB, Heap ${(mem.heapUsed / 1024 / 1024).toFixed(1)}/${(mem.heapTotal / 1024 / 1024).toFixed(1)} MB`);
  log('STATS', `Connected clients (WS): ${connectedCount()} across ${onlineClients.size} account(s)`);
  log('STATS', `Registered users: ${stats.totalUsers}`);
  log('STATS', `Queued offline messages: ${stats.totalOfflineMessages}`);
  log('STATS', `Push subscriptions: ${stats.totalPushSubscriptions} across all devices`);
  log('STATS', `Stored attachments: ${countUploads()}`);
  log('STATS', `Journal: ${(stats.journalBytes / 1024).toFixed(1)} KB pending compaction`);
}, STATS_INTERVAL_MS);

// --- ATTACHMENT GARBAGE COLLECTION ---
//
// Uploads are content-addressed by a random UUID and referenced only from
// inside encrypted message payloads, so the server can never tell whether a
// blob is still wanted. Age is the only signal available. Anything older than
// ATTACHMENT_TTL_DAYS is deleted; recipients who have not fetched a file by
// then would have lost it to a device wipe anyway.
//
// "Age" means time since the blob was last read, not since it was uploaded:
// /api/download touches mtime on every fetch. That is what keeps long-lived
// references such as avatars alive, and it still expires anything nobody has
// looked at in a month. Clients also refresh their own avatar before it can
// go cold (see AVATAR_REFRESH_DAYS in the client), so an avatar survives even
// a conversation that has gone quiet.
//
// Set TALON_ATTACHMENT_TTL_DAYS=0 to disable and keep blobs forever.
const ATTACHMENT_TTL_DAYS = Number(process.env.TALON_ATTACHMENT_TTL_DAYS ?? 30);
const GC_INTERVAL_MS = 6 * 60 * 60 * 1000;

function countUploads() {
  try { return fs.readdirSync(UPLOADS_DIR).length; } catch { return 0; }
}

function sweepAttachments() {
  if (!ATTACHMENT_TTL_DAYS) return;
  const cutoff = Date.now() - ATTACHMENT_TTL_DAYS * 24 * 60 * 60 * 1000;
  let removed = 0;
  let freed = 0;

  let entries;
  try { entries = fs.readdirSync(UPLOADS_DIR); } catch { return; }

  for (const name of entries) {
    const file = path.join(UPLOADS_DIR, name);
    try {
      const st = fs.statSync(file);
      if (!st.isFile() || st.mtimeMs >= cutoff) continue;
      fs.unlinkSync(file);
      removed++;
      freed += st.size;
    } catch { /* raced with another delete, or locked, so skip it */ }
  }

  if (removed) {
    log('API', `Attachment GC: removed ${removed} blob(s) older than ${ATTACHMENT_TTL_DAYS}d, freed ${(freed / 1024 / 1024).toFixed(1)} MB`);
  }
}

sweepAttachments();
setInterval(sweepAttachments, GC_INTERVAL_MS);
