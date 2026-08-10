// --- TLS: LOCAL CERTIFICATE AUTHORITY ---
//
// Talon serves HTTPS so that getUserMedia (camera/mic), the Push API and
// service workers all work on non-localhost devices. Previously it served a
// single self-signed leaf certificate, which browsers can never be made to
// *trust*. You get the interstitial on every device, forever, and iOS in
// particular refuses to remember the exception for WebSocket/fetch calls.
//
// Instead we run a tiny private CA:
//
//   Talon Local CA  (10 years, cA:true, stays on disk, never leaves the box
//                    except as a public certificate you install by hand)
//        └── leaf  (397 days, re-issued automatically, carries every SAN)
//
// You install the CA once per device (GET /ca.crt, see the /setup page) and
// from then on Talon is a genuinely trusted origin: green padlock, no
// interstitial, no per-device exceptions.
//
// Two hard browser rules drive the design and must not be "simplified" away:
//
//   1. Leaf certificates valid for more than 398 days are rejected outright
//      by Safari/iOS and Chrome, regardless of trust. That is why the leaf is
//      397 days and renews itself rather than being minted for a decade.
//   2. commonName is ignored entirely; only subjectAltName is consulted. The
//      SAN list is therefore load-bearing. Every address you might type into
//      the URL bar has to be in it.
//
// The CA keypair is only regenerated if it is missing or actually expired.
// Regenerating it invalidates the trust you installed on every device, so
// nothing else is allowed to trigger it. In particular, a change in the
// machine's IP set re-issues the *leaf* only.

import * as x509 from '@peculiar/x509';
import { webcrypto } from 'crypto';
import fs from 'fs';
import path from 'path';
import os from 'os';

x509.cryptoProvider.set(webcrypto);

const ALG = {
  name: 'RSASSA-PKCS1-v1_5',
  hash: 'SHA-256',
  publicExponent: new Uint8Array([1, 0, 1]),
  modulusLength: 2048
};

const CA_YEARS = 10;
const LEAF_DAYS = 397;          // hard browser ceiling is 398
const LEAF_RENEW_WITHIN_DAYS = 30;
const DAY_MS = 24 * 60 * 60 * 1000;

function pemWrap(label, der) {
  const b64 = Buffer.from(der).toString('base64').replace(/(.{64})/g, '$1\n').trim();
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

async function exportPrivateKeyPem(key) {
  return pemWrap('PRIVATE KEY', await webcrypto.subtle.exportKey('pkcs8', key));
}

async function importPrivateKeyPem(pem) {
  const b64 = pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
  return webcrypto.subtle.importKey('pkcs8', Buffer.from(b64, 'base64'), ALG, true, ['sign']);
}

/**
 * Every address a browser might legitimately use to reach this server.
 *
 * Link-local IPv6 (fe80::…) is deliberately excluded: those addresses are
 * scoped and arrive from os.networkInterfaces() with a zone suffix on some
 * platforms ("fe80::1%eth0"), which is not a valid iPAddress SAN value and
 * makes the whole certificate unparseable. They are also never usable as a
 * URL host in practice, so nothing is lost.
 */
function collectSans() {
  const dns = new Set(['localhost', 'talon.local']);
  const ips = new Set(['127.0.0.1', '::1']);

  const hostname = os.hostname();
  if (hostname) {
    const short = hostname.split('.')[0];
    dns.add(hostname);
    if (short && short !== hostname) dns.add(short);
    if (short) dns.add(`${short}.local`);
  }

  // TALON_EXTRA_SANS lets you pin extra names without editing code, most
  // usefully your Tailscale MagicDNS name, e.g.
  //   TALON_EXTRA_SANS=box.tail1234.ts.net npm start
  for (const raw of (process.env.TALON_EXTRA_SANS || '').split(',')) {
    const entry = raw.trim();
    if (!entry) continue;
    if (/^[0-9.]+$/.test(entry) || entry.includes(':')) ips.add(entry);
    else dns.add(entry);
  }

  for (const addrs of Object.values(os.networkInterfaces())) {
    for (const iface of addrs || []) {
      if (iface.internal) continue;
      const addr = String(iface.address);
      if (addr.includes('%')) continue;                       // zoned, unusable
      if (/^fe80:/i.test(addr)) continue;                     // IPv6 link-local
      if (/^169\.254\./.test(addr)) continue;                 // IPv4 link-local
      ips.add(addr);
    }
  }

  return {
    dns: Array.from(dns).sort(),
    ips: Array.from(ips).sort()
  };
}

function sansToGeneralNames({ dns, ips }) {
  return [
    ...dns.map((value) => ({ type: 'dns', value })),
    ...ips.map((value) => ({ type: 'ip', value }))
  ];
}

function sansFingerprint({ dns, ips }) {
  return JSON.stringify({ dns, ips });
}

async function createCa(notBefore) {
  const notAfter = new Date(notBefore);
  notAfter.setFullYear(notAfter.getFullYear() + CA_YEARS);

  const keys = await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: Buffer.from(webcrypto.getRandomValues(new Uint8Array(8))).toString('hex'),
    name: `CN=Talon Local CA (${os.hostname()}), O=Talon`,
    notBefore,
    notAfter,
    signingAlgorithm: ALG,
    keys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign | x509.KeyUsageFlags.digitalSignature,
        true
      ),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey)
    ]
  });

  return { cert, keys };
}

async function createLeaf(ca, sans, notBefore) {
  const notAfter = new Date(notBefore.getTime() + LEAF_DAYS * DAY_MS);
  const keys = await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify']);

  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: Buffer.from(webcrypto.getRandomValues(new Uint8Array(8))).toString('hex'),
    subject: 'CN=talon.local, O=Talon',
    issuer: ca.cert.subject,
    notBefore,
    notAfter,
    signingAlgorithm: ALG,
    publicKey: keys.publicKey,
    signingKey: ca.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment,
        true
      ),
      new x509.ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.1'], false), // serverAuth
      new x509.SubjectAlternativeNameExtension(sansToGeneralNames(sans), false),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
      await x509.AuthorityKeyIdentifierExtension.create(ca.cert, false)
    ]
  });

  return { cert, keys };
}

/**
 * Ensure a trusted-capable cert chain exists on disk and return it.
 *
 * @param {string} certDir  directory to persist the CA + leaf into
 * @param {(tag: string, msg: string) => void} log
 * @returns {Promise<{key: string, cert: string, caPem: string, sans: object,
 *                    caPath: string, leafNotAfter: Date, caNotAfter: Date,
 *                    caFingerprint: string}>}
 */
export async function ensureCertificates(certDir, log = () => {}) {
  fs.mkdirSync(certDir, { recursive: true });

  const CA_CERT_PATH = path.join(certDir, 'ca.pem');
  const CA_KEY_PATH = path.join(certDir, 'ca-key.pem');
  const LEAF_CERT_PATH = path.join(certDir, 'cert.pem');
  const LEAF_KEY_PATH = path.join(certDir, 'key.pem');
  const META_PATH = path.join(certDir, 'cert-meta.json');

  const now = new Date();
  // Backdate slightly so a client whose clock runs behind ours still accepts it.
  const notBefore = new Date(now.getTime() - 60 * 60 * 1000);

  // --- 1. Certificate authority -------------------------------------------
  let ca = null;
  if (fs.existsSync(CA_CERT_PATH) && fs.existsSync(CA_KEY_PATH)) {
    try {
      const cert = new x509.X509Certificate(fs.readFileSync(CA_CERT_PATH, 'utf-8'));
      if (cert.notAfter.getTime() <= now.getTime()) {
        log('TLS', 'Local CA has expired. Issuing a new one (devices must re-install it).');
      } else {
        ca = { cert, privateKey: await importPrivateKeyPem(fs.readFileSync(CA_KEY_PATH, 'utf-8')) };
      }
    } catch (err) {
      log('TLS', `Existing CA could not be read (${err.message}). Issuing a new one.`);
    }
  }

  if (!ca) {
    log('TLS', 'Generating Talon Local CA (valid 10 years)...');
    const created = await createCa(notBefore);
    fs.writeFileSync(CA_CERT_PATH, created.cert.toString('pem') + '\n');
    fs.writeFileSync(CA_KEY_PATH, await exportPrivateKeyPem(created.keys.privateKey), { mode: 0o600 });
    ca = { cert: created.cert, privateKey: created.keys.privateKey };
    log('TLS', 'Local CA created. Install it on each device via /ca.crt to remove browser warnings.');
  }

  const caPem = fs.readFileSync(CA_CERT_PATH, 'utf-8');
  const caFingerprint = Buffer.from(ca.cert.serialNumber, 'hex').toString('hex');

  // --- 2. Leaf certificate -------------------------------------------------
  const sans = collectSans();
  const wantFingerprint = sansFingerprint(sans);

  let needsLeaf = !fs.existsSync(LEAF_CERT_PATH) || !fs.existsSync(LEAF_KEY_PATH);
  let reason = 'no leaf certificate on disk';

  if (!needsLeaf) {
    try {
      const meta = JSON.parse(fs.readFileSync(META_PATH, 'utf-8'));
      const leaf = new x509.X509Certificate(fs.readFileSync(LEAF_CERT_PATH, 'utf-8'));

      if (meta.caFingerprint !== caFingerprint) {
        needsLeaf = true; reason = 'it was issued by a different CA';
      } else if (meta.sansFingerprint !== wantFingerprint) {
        needsLeaf = true; reason = 'this machine\'s addresses changed';
      } else if (leaf.notAfter.getTime() - now.getTime() < LEAF_RENEW_WITHIN_DAYS * DAY_MS) {
        needsLeaf = true; reason = 'it expires within 30 days';
      }
    } catch {
      // No meta file means the leaf predates the CA scheme (the old standalone
      // self-signed cert), or the metadata is unreadable. Either way, reissue.
      needsLeaf = true;
      reason = 'it predates the local-CA scheme';
    }
  }

  if (needsLeaf) {
    log('TLS', `Issuing server certificate (${reason}).`);
    log('TLS', `  DNS: ${sans.dns.join(', ')}`);
    log('TLS', `  IP:  ${sans.ips.join(', ')}`);
    const leaf = await createLeaf(ca, sans, notBefore);
    fs.writeFileSync(LEAF_CERT_PATH, leaf.cert.toString('pem') + '\n');
    fs.writeFileSync(LEAF_KEY_PATH, await exportPrivateKeyPem(leaf.keys.privateKey), { mode: 0o600 });
    fs.writeFileSync(
      META_PATH,
      JSON.stringify({ caFingerprint, sansFingerprint: wantFingerprint, sans, issuedAt: now.toISOString() }, null, 2)
    );
    log('TLS', `Server certificate valid for ${LEAF_DAYS} days.`);
  }

  const leafCert = new x509.X509Certificate(fs.readFileSync(LEAF_CERT_PATH, 'utf-8'));

  return {
    key: fs.readFileSync(LEAF_KEY_PATH, 'utf-8'),
    cert: fs.readFileSync(LEAF_CERT_PATH, 'utf-8'),
    caPem,
    caPath: CA_CERT_PATH,
    sans,
    caFingerprint,
    leafNotAfter: leafCert.notAfter,
    caNotAfter: ca.cert.notAfter
  };
}
