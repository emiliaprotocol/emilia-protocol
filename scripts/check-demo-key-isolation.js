#!/usr/bin/env node
/**
 * Demo Key Isolation Check — CI guardrail script.
 *
 * Fails the build if the hardcoded demo Ed25519 private-key material in
 * lib/demo-receipt.js leaks into any other source file. The demo key is
 * deliberately committed to source so the public /r/example demo and the
 * /api/demo/trust-receipts/.../evidence endpoint share a stable signer.
 * That tradeoff is safe ONLY as long as the key is confined to the demo
 * module — copy-pasting the signing pattern into a real route would
 * silently sign production receipts with a publicly-known key.
 *
 * Zero external dependencies — uses only Node.js built-ins.
 *
 * @license Apache-2.0
 */

import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');

// Distinct fragments of the demo private key. Any of these in a non-
// allowlisted file means the key has been copy-pasted somewhere it
// shouldn't be. Keep these strings WIDE enough to be unique to the demo
// material and NARROW enough to never collide with unrelated cryptographic
// strings.
const DEMO_KEY_MARKERS = [
  '5wY2-Hj9wBu-DtV5cV5EuRD-ei-g9Xor8GHr4hUvnOI', // demo private d
  'ElZsl_xk08JOnjfQXhZCy7H1us1TrV8lzJ7-lVFgKgo', // demo public x
];

// Files that are ALLOWED to contain the demo key. Anything outside this
// allowlist triggers a CI failure.
const ALLOWLIST = [
  'lib/demo-receipt.js',
  'scripts/check-demo-key-isolation.js', // this file
];

// Directories to scan. We skip node_modules, .next, dist, .vercel,
// supabase/.temp, and binary/asset directories.
const SCAN_GLOBS_INCLUDE = [
  'app/',
  'components/',
  'lib/',
  'scripts/',
  'tests/',
  'packages/',
  'mcp-server/',
  'sdks/',
  'public/',
  'middleware.js',
  'next.config.js',
  'next.config.mjs',
];
const SCAN_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.json', '.yaml', '.yml', '.md']);

function walk(dirOrFile, acc = []) {
  const abs = path.join(ROOT, dirOrFile);
  if (!fs.existsSync(abs)) return acc;
  const stat = fs.statSync(abs);
  if (stat.isFile()) {
    if (SCAN_EXTENSIONS.has(path.extname(abs))) acc.push(dirOrFile);
    return acc;
  }
  for (const entry of fs.readdirSync(abs)) {
    if (entry === 'node_modules' || entry === '.next' || entry === 'dist' || entry === '.vercel') continue;
    if (entry.startsWith('.')) continue;
    walk(path.join(dirOrFile, entry), acc);
  }
  return acc;
}

const files = SCAN_GLOBS_INCLUDE.flatMap((g) => walk(g));

const violations = [];
for (const relPath of files) {
  if (ALLOWLIST.includes(relPath)) continue;
  const abs = path.join(ROOT, relPath);
  let src;
  try {
    src = fs.readFileSync(abs, 'utf8');
  } catch {
    continue;
  }
  for (const marker of DEMO_KEY_MARKERS) {
    if (src.includes(marker)) {
      violations.push({ file: relPath, marker });
    }
  }
}

if (violations.length > 0) {
  console.error('❌ Demo private key material found outside lib/demo-receipt.js:\n');
  for (const v of violations) {
    console.error(`  ${v.file}  (matched marker: ${v.marker.slice(0, 16)}…)`);
  }
  console.error('\nThe demo key is for /r/example only. Production receipts must be signed');
  console.error('by operator keys held in EP_OPERATOR_KEYS (env, never in source).');
  console.error('If you intentionally need the demo key elsewhere, add the file path to the');
  console.error('ALLOWLIST in scripts/check-demo-key-isolation.js with a comment explaining why.\n');
  process.exit(1);
}

console.log(`✓ Demo key isolation OK — scanned ${files.length} files, no leakage detected.`);
