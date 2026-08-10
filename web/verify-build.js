// Checks that the shipped bundle is what the committed source produces.
//
//   npm run verify
//
// Run this against a fresh clone if you want to know that public/js/app.js,
// the minified file the relay actually serves, corresponds to the src/ you
// just read. It rebuilds into a scratch directory and compares hashes; it
// never touches the committed artifact, so a failing check leaves the tree
// exactly as it found it.
//
// What a pass means: these bytes came from this source, with this esbuild.
// What it does NOT mean: that the source is trustworthy, or that some other
// relay is serving the same thing. Those are different questions and this
// answers neither.

import esbuild from 'esbuild';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

const MANIFEST = 'public/build-manifest.json';
const BUNDLE = 'public/js/app.js';

const problems = [];
const ok = [];

if (!fs.existsSync(MANIFEST)) {
  console.error(`No ${MANIFEST}. Run "npm run build" first.`);
  process.exit(1);
}
const manifest = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));

/* 1. The committed bundle matches the hash the manifest claims. ----------- */
const shipped = fs.readFileSync(BUNDLE);
const shippedHash = sha256(shipped);
if (shippedHash === manifest.bundle.sha256) {
  ok.push(`bundle matches the manifest  ${shippedHash.slice(0, 16)}…`);
} else {
  problems.push(
    `The committed bundle does not match the manifest.\n`
    + `  manifest: ${manifest.bundle.sha256}\n`
    + `  on disk:  ${shippedHash}\n`
    + `  Someone edited public/js/app.js by hand, or forgot to rebuild.`
  );
}

/* 2. The esbuild in node_modules is the one that produced it. ------------- */
const have = require('esbuild/package.json').version;
if (have === manifest.builtWith.esbuild) {
  ok.push(`esbuild ${have} matches the manifest`);
} else {
  problems.push(
    `esbuild version differs: manifest says ${manifest.builtWith.esbuild}, installed is ${have}.\n`
    + `  A different minifier legitimately produces different bytes, so the\n`
    + `  rebuild below cannot prove anything until these agree. Run "npm ci".`
  );
}

/* 3. Rebuilding the committed source reproduces those exact bytes. -------- */
if (!problems.length) {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'talon-verify-'));
  const out = path.join(scratch, 'app.js');
  try {
    await esbuild.build({
      entryPoints: ['src/app.js'],
      outfile: out,
      ...manifest.builtWith.options,
      target: [manifest.builtWith.options.target]
    });
    const rebuiltHash = sha256(fs.readFileSync(out));
    if (rebuiltHash === manifest.bundle.sha256) {
      ok.push('a fresh build of src/ reproduces the bundle byte for byte');
    } else {
      problems.push(
        `Rebuilding src/ did NOT reproduce the shipped bundle.\n`
        + `  expected: ${manifest.bundle.sha256}\n`
        + `  rebuilt:  ${rebuiltHash}\n`
        + `  The shipped bundle contains something that is not in src/.`
      );
    }
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

/* 4. The page asks the browser for that same bundle. ---------------------- */
const html = fs.readFileSync(path.join('public', 'index.html'), 'utf8');
const sri = `sha384-${crypto.createHash('sha384').update(shipped).digest('base64')}`;
if (html.includes(`integrity="${sri}"`)) {
  ok.push('index.html carries a matching integrity hash');
} else {
  problems.push(
    'index.html does not carry an integrity hash matching the bundle.\n'
    + '  Run "npm run build" to stamp it.'
  );
}

for (const line of ok) console.log(`  ok    ${line}`);
for (const line of problems) console.error(`\n  FAIL  ${line}`);

if (problems.length) {
  console.error(`\n${problems.length} problem(s). The shipped bundle cannot be trusted to match the source.`);
  process.exit(1);
}
console.log('\nThe shipped bundle is reproducible from the committed source.');
