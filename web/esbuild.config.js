import esbuild from 'esbuild';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { createRequire } from 'module';

// Fonts are vendored from npm into public/fonts rather than loaded from a CDN.
// The service worker skips cross-origin requests, so a hosted <link> would
// break the offline shell, and it would leak a request to a third party on
// every load, which is the opposite of the point of this project.
//
// Only the latin variable ("wght") files are copied: one file per family
// covers every weight, ~48 KB and ~40 KB respectively. Do not switch these to
// the full unicode-range builds without a good reason.
const FONTS = [
  ['@fontsource-variable/inter/files/inter-latin-wght-normal.woff2', 'inter-latin-wght-normal.woff2'],
  ['@fontsource-variable/jetbrains-mono/files/jetbrains-mono-latin-wght-normal.woff2', 'jetbrains-mono-latin-wght-normal.woff2']
];

function copyFonts() {
  const outDir = path.join('public', 'fonts');
  fs.mkdirSync(outDir, { recursive: true });

  for (const [from, to] of FONTS) {
    const src = path.join('node_modules', from);
    if (!fs.existsSync(src)) {
      throw new Error(`Missing font ${src}. Run "npm install" in web/`);
    }
    fs.copyFileSync(src, path.join(outDir, to));
    const kb = (fs.statSync(src).size / 1024).toFixed(0);
    console.log(`[fonts] ${to} (${kb} KB)`);
  }
}

/* ------------------------------------------------- reproducibility */
//
// The relay serves a minified bundle that nobody reads. For a project whose
// whole pitch is "read the source", that gap matters: a user has to take it on
// faith that public/js/app.js is what src/ says it is.
//
// Closing it needs two things, and neither is exotic. The build is
// deterministic, so the same sources and the same esbuild version produce the
// same bytes on any machine. And the hash of those bytes is written down where
// anyone can check it, rather than living only in the author's head.
//
// What this does NOT prove: that the source itself is trustworthy, or that the
// relay you connected to is running the code you audited. It proves the shipped
// bundle corresponds to the committed source, which is the specific doubt that
// a minified artifact in a repository creates.

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

/**
 * One hash over every client source file, so the manifest records what the
 * bundle was built FROM as well as what came out.
 *
 * Sorted by path, with the path mixed in, so renaming a file changes the
 * result. Concatenating contents alone would not notice a rename or a file
 * being split in two.
 */
function hashSources(dir) {
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.js')).sort();
  const h = crypto.createHash('sha256');
  for (const f of files) {
    h.update(f);
    h.update('\0');
    // Line endings are normalised, or a checkout with autocrlf produces a
    // different source hash from the same source.
    h.update(fs.readFileSync(path.join(dir, f), 'utf8').split('\r\n').join('\n'));
    h.update('\0');
  }
  return { hash: h.digest('hex'), files };
}

/**
 * Writes the Subresource Integrity attribute into the script tag.
 *
 * Honest about its limits: the bundle is same-origin, so anyone who can
 * rewrite app.js can usually rewrite index.html too and simply update the
 * attribute. What it does catch is a PARTIAL compromise, where only the built
 * asset is replaced, and it makes the expected hash visible in the page
 * source rather than only in a file people have to know to look for.
 */
function writeIntegrity(bundlePath, indexPath) {
  const digest = crypto.createHash('sha384').update(fs.readFileSync(bundlePath)).digest('base64');
  const sri = `sha384-${digest}`;
  const html = fs.readFileSync(indexPath, 'utf8');

  const updated = html.replace(
    /<script type="module" src="js\/app\.js"[^>]*><\/script>/,
    `<script type="module" src="js/app.js" integrity="${sri}" crossorigin="anonymous"></script>`
  );
  if (updated === html && !html.includes(sri)) {
    throw new Error('Could not find the app.js script tag to stamp with an integrity hash.');
  }
  if (updated !== html) fs.writeFileSync(indexPath, updated);
  return sri;
}

function writeManifest(bundlePath) {
  const require = createRequire(import.meta.url);
  const bytes = fs.readFileSync(bundlePath);
  const sources = hashSources('src');

  const manifest = {
    // Everything needed to reproduce the bundle byte for byte.
    bundle: {
      path: 'public/js/app.js',
      sha256: sha256(bytes),
      bytes: bytes.length
    },
    sources: {
      dir: 'web/src',
      count: sources.files.length,
      sha256: sources.hash
    },
    builtWith: {
      esbuild: require('esbuild/package.json').version,
      // The build settings that affect output. Changing any of these changes
      // the bytes, so recording them is what makes a mismatch diagnosable
      // rather than mysterious.
      options: { bundle: true, minify: true, format: 'esm', target: 'es2020', sourcemap: false }
    }
  };

  // No timestamp and no builder name, deliberately. Either would make two
  // correct builds differ and turn the reproducibility check into noise.
  fs.writeFileSync('public/build-manifest.json', `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest;
}

async function run() {
  try {
    copyFonts();

    // Bundle the main app.js which imports our E2E crypto functions
    await esbuild.build({
      entryPoints: ['src/app.js'],
      bundle: true,
      minify: true,
      sourcemap: false,
      target: ['es2020'],
      format: 'esm',
      outfile: 'public/js/app.js'
    });
    console.log('[esbuild] Client bundled successfully: public/js/app.js');

    const manifest = writeManifest('public/js/app.js');
    const sri = writeIntegrity('public/js/app.js', path.join('public', 'index.html'));
    console.log(`[build] bundle  sha256 ${manifest.bundle.sha256}  (${manifest.bundle.bytes} bytes)`);
    console.log(`[build] sources sha256 ${manifest.sources.sha256}  (${manifest.sources.count} files)`);
    console.log(`[build] integrity ${sri}`);
  } catch (err) {
    console.error('[esbuild] Build failed:', err);
    process.exit(1);
  }
}

run();
