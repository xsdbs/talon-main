/**
 * A minimal QR encoder: byte mode, versions 1 to 10, error correction level M.
 *
 * Why this is here rather than a dependency: this module runs in the same page
 * as the identity private key and the whole decrypted archive. A QR encoder is
 * a pure function over bytes with no reason to touch either, and keeping it in
 * the tree means it is reviewable alongside everything else instead of being
 * one more thing to trust on every install. It is roughly 200 lines.
 *
 * Correctness was checked against the `qrcode-generator` reference
 * implementation: identical modules for every version 1 to 10 across a range
 * of payloads. See tools/verify-qr.mjs.
 *
 * Scope is deliberate. Versions 1 to 10 at level M hold up to 122 bytes, which
 * covers every payload Talon produces (an add-contact link is about 100
 * characters). Anything longer throws rather than silently truncating.
 */

/* ------------------------------------------------------------ GF(256) ---- */
// Standard QR field: generator 2, primitive polynomial 0x11d.
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();

const mul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);

/** Generator polynomial for `degree` error-correction codewords. */
function rsGenerator(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= mul(poly[j], EXP[i]);
    }
    poly = next;
  }
  return poly;
}

function rsEncode(data, ecLen) {
  const gen = rsGenerator(ecLen);
  const res = new Uint8Array(ecLen);
  for (const byte of data) {
    const factor = byte ^ res[0];
    res.copyWithin(0, 1);
    res[ecLen - 1] = 0;
    for (let i = 0; i < ecLen; i++) res[i] ^= mul(gen[i + 1], factor);
  }
  return res;
}

/* -------------------------------------------------------------- tables --- */
// Per version (index 1..10) at EC level M:
//   [total codewords, ec codewords per block, group1 blocks, group2 blocks]
// Group 2 blocks, when present, hold one more data codeword than group 1.
const SPEC_M = [
  null,
  [26, 10, 1, 0], [44, 16, 1, 0], [70, 26, 1, 0], [100, 18, 2, 0],
  [134, 24, 2, 0], [172, 16, 4, 0], [196, 18, 4, 0], [242, 22, 2, 2],
  [292, 22, 3, 2], [346, 26, 4, 1]
];

// Row/column centres of the alignment patterns, per version.
const ALIGN = [
  [], [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
  [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]
];

/* --------------------------------------------------------------- matrix -- */

function newMatrix(size) {
  return {
    size,
    px: Array.from({ length: size }, () => new Int8Array(size).fill(-1))
  };
}

function placeFinder(m, r0, c0) {
  for (let r = -1; r <= 7; r++) {
    for (let c = -1; c <= 7; c++) {
      const r1 = r0 + r;
      const c1 = c0 + c;
      if (r1 < 0 || c1 < 0 || r1 >= m.size || c1 >= m.size) continue;
      const inRing = (r >= 0 && r <= 6 && (c === 0 || c === 6))
        || (c >= 0 && c <= 6 && (r === 0 || r === 6));
      const inCore = r >= 2 && r <= 4 && c >= 2 && c <= 4;
      m.px[r1][c1] = (inRing || inCore) ? 1 : 0;
    }
  }
}

function placeFunctionPatterns(m, version) {
  const n = m.size;
  placeFinder(m, 0, 0);
  placeFinder(m, 0, n - 7);
  placeFinder(m, n - 7, 0);

  // Timing patterns.
  for (let i = 8; i < n - 8; i++) {
    const bit = i % 2 === 0 ? 1 : 0;
    m.px[6][i] = bit;
    m.px[i][6] = bit;
  }

  // Alignment patterns, skipping the three that would collide with a finder.
  const centres = ALIGN[version];
  for (const r of centres) {
    for (const c of centres) {
      const nearFinder = (r <= 8 && c <= 8) || (r <= 8 && c >= n - 9) || (r >= n - 9 && c <= 8);
      if (nearFinder) continue;
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          const edge = Math.max(Math.abs(dr), Math.abs(dc));
          m.px[r + dr][c + dc] = (edge === 1) ? 0 : 1;
        }
      }
    }
  }

  // Dark module, and the reserved format-information strips.
  //
  // The second copy is asymmetric and it is easy to get backwards: row 8
  // takes 8 modules (columns n-8 to n-1) while column 8 takes 7 (rows n-7 to
  // n-1), with the always-dark module at (n-8, 8) accounting for the
  // difference. Reserving the wrong arm costs a data module and shifts the
  // tail of the bit stream.
  m.px[n - 8][8] = 1;
  for (let i = 0; i <= 8; i++) {
    if (m.px[8][i] === -1) m.px[8][i] = 0;
    if (m.px[i][8] === -1) m.px[i][8] = 0;
  }
  for (let i = n - 8; i < n; i++) if (m.px[8][i] === -1) m.px[8][i] = 0;
  for (let i = n - 7; i < n; i++) if (m.px[i][8] === -1) m.px[i][8] = 0;

  // Version information blocks, present from version 7 upwards.
  if (version >= 7) {
    let rem = version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (version << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const bit = (bits >>> i) & 1;
      const a = Math.floor(i / 3);
      const b = (i % 3) + n - 11;
      m.px[a][b] = bit;
      m.px[b][a] = bit;
    }
  }
}

/* ---------------------------------------------------------------- data --- */

function buildCodewords(bytes, version) {
  const [total, ecLen, g1, g2] = SPEC_M[version];
  const blocks = g1 + g2;
  const dataLen = total - ecLen * blocks;

  // Mode indicator (0100 = byte), then the character count, then the payload.
  const bits = [];
  const push = (value, len) => {
    for (let i = len - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };
  push(0b0100, 4);
  push(bytes.length, version < 10 ? 8 : 16);
  for (const b of bytes) push(b, 8);

  // Terminator, pad to a byte boundary, then the alternating pad bytes.
  for (let i = 0; i < 4 && bits.length < dataLen * 8; i++) bits.push(0);
  while (bits.length % 8) bits.push(0);
  const data = new Uint8Array(dataLen);
  for (let i = 0; i < bits.length; i += 8) {
    let v = 0;
    for (let j = 0; j < 8; j++) v = (v << 1) | bits[i + j];
    data[i / 8] = v;
  }
  for (let i = bits.length / 8, alt = 0; i < dataLen; i++, alt++) {
    data[i] = alt % 2 === 0 ? 0xec : 0x11;
  }

  // Split into blocks: group 2 blocks carry one extra data codeword each.
  const shortLen = Math.floor(dataLen / blocks);
  const dataBlocks = [];
  const ecBlocks = [];
  let at = 0;
  for (let i = 0; i < blocks; i++) {
    const len = shortLen + (i >= g1 ? 1 : 0);
    const block = data.subarray(at, at + len);
    at += len;
    dataBlocks.push(block);
    ecBlocks.push(rsEncode(block, ecLen));
  }

  // Interleave: column-major across blocks, data first then EC.
  const out = new Uint8Array(total);
  let o = 0;
  const maxData = shortLen + (g2 > 0 ? 1 : 0);
  for (let i = 0; i < maxData; i++) {
    for (const b of dataBlocks) if (i < b.length) out[o++] = b[i];
  }
  for (let i = 0; i < ecLen; i++) {
    for (const b of ecBlocks) out[o++] = b[i];
  }
  return out;
}

const MASKS = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0
];

function placeData(m, codewords, mask) {
  const n = m.size;
  let bit = 0;
  const total = codewords.length * 8;
  let upward = true;

  for (let right = n - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5; // the vertical timing column is skipped
    for (let step = 0; step < n; step++) {
      const row = upward ? n - 1 - step : step;
      for (let k = 0; k < 2; k++) {
        const col = right - k;
        if (m.px[row][col] !== -1) continue;
        let v = 0;
        if (bit < total) {
          v = (codewords[bit >>> 3] >>> (7 - (bit & 7))) & 1;
          bit++;
        }
        m.px[row][col] = MASKS[mask](row, col) ? v ^ 1 : v;
      }
    }
    upward = !upward;
  }
}

function placeFormat(m, mask) {
  const n = m.size;
  // EC level M is 0b00 in the format field.
  const data = (0b00 << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bits = ((data << 10) | rem) ^ 0x5412;

  // Bit 0 first. The two copies run in opposite directions around the
  // top-left finder, and the layout is nearly symmetric, so transposing the
  // row and column arms produces something that still looks like a QR code
  // and differs from a correct one by only a handful of modules. It will not
  // scan: the format field is what tells a reader which mask to undo.
  const at = (i) => (bits >>> i) & 1;

  // Copy 1: down column 8, then left along row 8.
  for (let i = 0; i <= 5; i++) m.px[i][8] = at(i);
  m.px[7][8] = at(6);
  m.px[8][8] = at(7);
  m.px[8][7] = at(8);
  for (let i = 9; i < 15; i++) m.px[8][14 - i] = at(i);

  // Copy 2: right along row 8, then down column 8.
  for (let i = 0; i <= 7; i++) m.px[8][n - 1 - i] = at(i);
  for (let i = 8; i < 15; i++) m.px[n - 15 + i][8] = at(i);
  m.px[n - 8][8] = 1;
}

/** The standard penalty score used to pick the least-noisy mask. */
function penalty(m) {
  const n = m.size;
  let score = 0;

  const runScore = (line) => {
    let run = 1;
    let sub = 0;
    for (let i = 1; i < n; i++) {
      if (line[i] === line[i - 1]) { run++; continue; }
      if (run >= 5) sub += 3 + (run - 5);
      run = 1;
    }
    if (run >= 5) sub += 3 + (run - 5);
    return sub;
  };

  for (let r = 0; r < n; r++) score += runScore(m.px[r]);
  for (let c = 0; c < n; c++) score += runScore(m.px.map((row) => row[c]));

  for (let r = 0; r < n - 1; r++) {
    for (let c = 0; c < n - 1; c++) {
      const v = m.px[r][c];
      if (v === m.px[r][c + 1] && v === m.px[r + 1][c] && v === m.px[r + 1][c + 1]) score += 3;
    }
  }

  // 1:1:3:1:1 finder-like patterns, in both orientations.
  const NEEDLE = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
  const REV = [...NEEDLE].reverse();
  const scan = (get) => {
    for (let i = 0; i + 11 <= n; i++) {
      let fwd = true;
      let bwd = true;
      for (let j = 0; j < 11; j++) {
        const v = get(i + j);
        if (v !== NEEDLE[j]) fwd = false;
        if (v !== REV[j]) bwd = false;
      }
      // Both orientations are scored, so a run that satisfies each counts
      // twice, as the spec intends.
      if (fwd) score += 40;
      if (bwd) score += 40;
    }
  };
  for (let r = 0; r < n; r++) scan((i) => m.px[r][i]);
  for (let c = 0; c < n; c++) scan((i) => m.px[i][c]);

  let dark = 0;
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) dark += m.px[r][c];
  const pct = (dark * 100) / (n * n);
  score += Math.floor(Math.abs(pct - 50) / 5) * 10;

  return score;
}

/**
 * Encodes `text` and returns a square array of 0/1 rows.
 * @returns {number[][]}
 */
export function qrMatrix(text, { mask: forcedMask = null } = {}) {
  const bytes = new TextEncoder().encode(text);

  let version = 0;
  for (let v = 1; v <= 10; v++) {
    const [total, ecLen, g1, g2] = SPEC_M[v];
    const capacity = total - ecLen * (g1 + g2) - (v < 10 ? 2 : 3);
    if (bytes.length <= capacity) { version = v; break; }
  }
  if (!version) throw new Error('QR payload too long');

  const codewords = buildCodewords(bytes, version);
  const size = version * 4 + 17;

  let best = null;
  let bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    if (forcedMask !== null && mask !== forcedMask) continue;
    const m = newMatrix(size);
    placeFunctionPatterns(m, version);
    placeData(m, codewords, mask);
    placeFormat(m, mask);
    const s = penalty(m);
    if (s < bestScore) { bestScore = s; best = m; }
  }

  return best.px.map((row) => Array.from(row));
}

/**
 * Renders a matrix as a self-contained SVG string.
 *
 * One path of rectangles rather than a grid of elements: a version-6 code is
 * 41x41, and 1681 <rect> nodes is a lot of DOM for something the size of a
 * postage stamp.
 */
export function qrSVG(text, { size = 200, margin = 4 } = {}) {
  const m = qrMatrix(text);
  const n = m.length;
  const dim = n + margin * 2;

  let d = '';
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      if (m[r][c]) d += `M${c + margin} ${r + margin}h1v1h-1z`;
    }
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}"
    viewBox="0 0 ${dim} ${dim}" shape-rendering="crispEdges" role="img">
    <rect width="${dim}" height="${dim}" fill="#fff"/>
    <path d="${d}" fill="#000"/>
  </svg>`;
}
