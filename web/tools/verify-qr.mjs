/**
 * Checks src/qr.js against a known-good QR encoder.
 *
 *   cd web && npm i --no-save qrcode-generator && node tools/verify-qr.mjs
 *
 * qrcode-generator is deliberately NOT a dependency in package.json. qr.js
 * runs in the same page as the identity private key, so it has no third-party
 * code in it; the reference is pulled in only for this check and then thrown
 * away. A normal install stays clean.
 *
 * WHAT IS CHECKED, AND WHY NOT PLAIN EQUALITY
 *
 * The two encoders legitimately disagree on one thing: which of the eight
 * masks to use. qrcode-generator scores with the legacy rule 3 (a bare
 * 1011101) while qr.js implements the current spec (1011101 with four light
 * modules alongside). Neither is wrong; the mask is a readability heuristic
 * and the format field records which one was applied.
 *
 * So the assertion is that ONE of our eight masked renderings is
 * module-for-module identical to the reference. That leaves nothing
 * meaningful unverified: version selection, the bit stream, padding,
 * Reed-Solomon codewords, block interleaving, function patterns and the
 * format field must all be exactly right for any mask to line up.
 *
 * This matters more than it sounds. A QR with a correct payload and a wrong
 * format field renders as a perfectly plausible square that no scanner will
 * read, and eyeballing it tells you nothing.
 */
import { qrMatrix } from '../src/qr.js';

let qrcode;
try {
  ({ default: qrcode } = await import('qrcode-generator'));
} catch {
  console.error('Reference encoder missing. Run:\n  npm i --no-save qrcode-generator');
  process.exit(2);
}

// Per version at EC level M: [total codewords, ec per block, g1 blocks, g2 blocks]
const SPEC_M = [
  null,
  [26, 10, 1, 0], [44, 16, 1, 0], [70, 26, 1, 0], [100, 18, 2, 0],
  [134, 24, 2, 0], [172, 16, 4, 0], [196, 18, 4, 0], [242, 22, 2, 2],
  [292, 22, 3, 2], [346, 26, 4, 1]
];
const capacityOf = (v) => {
  const [total, ecLen, g1, g2] = SPEC_M[v];
  return total - ecLen * (g1 + g2) - (v < 10 ? 2 : 3);
};

const ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:/.#?=-_';
let passed = 0;
let failed = 0;

function check(text, label) {
  const ref = qrcode(0, 'M');
  ref.addData(text, 'Byte');
  ref.make();
  const n = ref.getModuleCount();

  if (qrMatrix(text).length !== n) {
    console.log(`FAIL ${label}: chose a different version (${qrMatrix(text).length} vs ${n})`);
    failed++;
    return;
  }

  let closest = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    const mine = qrMatrix(text, { mask });
    let diffs = 0;
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) if (!!mine[r][c] !== ref.isDark(r, c)) diffs++;
    }
    if (diffs === 0) { passed++; return; }
    closest = Math.min(closest, diffs);
  }

  console.log(`FAIL ${label}: no mask reproduces the reference (closest ${closest} modules off)`);
  failed++;
}

// Exactly at, and one under, every version's capacity: this walks each
// version boundary and both character-count field widths.
for (let v = 1; v <= 10; v++) {
  const cap = capacityOf(v);
  for (const len of [cap, Math.max(1, cap - 1)]) {
    let s = '';
    for (let i = 0; i < len; i++) s += ALPHABET[(i * 7 + v * 13) % ALPHABET.length];
    check(s, `v${v} len=${len}`);
  }
}

// The payloads Talon actually produces. The key below is a synthetic
// 32-byte value, not one any account holds. A Client ID is a public key and
// safe to share, but a fixture is not the place to bake a real one in.
const idPub = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
check(idPub, 'raw client id');
check(`https://talon.example.ts.net:8443/#add=${idPub}`, 'add link, magicdns');
check(`https://100.64.0.1:8443/#add=${idPub}`, 'add link, tailscale ip');
check('12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890', 'safety number');

console.log(`\n${passed} matched the reference, ${failed} failed`);
process.exit(failed ? 1 : 0);
