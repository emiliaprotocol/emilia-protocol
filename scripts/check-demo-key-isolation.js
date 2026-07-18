#!/usr/bin/env node
/**
 * Demo Key Isolation Check — CI guardrail script.
 *
 * Fails the build if source contains a demo private-key object. The public
 * /r/example surface is a signed public-only fixture; dynamic crash-test
 * receipts use EP_DEMO_SIGNING_KEY and fail closed in production when it is
 * absent.
 *
 * Zero external dependencies — uses only Node.js built-ins.
 *
 * @license Apache-2.0
 */

import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');

const FORBIDDEN_PATTERNS = [
  /DEMO_PRIVATE_JWK/,
  /DEMO_PRIVATE_KEY/,
  /privateKeyObject\s*=\s*crypto\.createPrivateKey/,
];

// Directories to scan. We skip node_modules, .next, dist, .vercel,
// supabase/.temp, and binary/asset directories.
const SCAN_GLOBS_INCLUDE = [
  'app/',
  'components/',
  'lib/',
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
  const abs = path.join(ROOT, relPath);
  let src;
  try {
    src = fs.readFileSync(abs, 'utf8');
  } catch {
    continue;
  }
  for (const pattern of FORBIDDEN_PATTERNS) {
    if (pattern.test(src)) violations.push({ file: relPath, pattern: pattern.toString() });
  }
}

if (violations.length > 0) {
  console.error('❌ Demo private-key material found in runtime source:\n');
  for (const v of violations) {
    console.error(`  ${v.file}  (matched: ${v.pattern})`);
  }
  console.error('\nDynamic demo signing must use EP_DEMO_SIGNING_KEY (env, never in source).\n');
  process.exit(1);
}

console.log(`✓ Demo key isolation OK — scanned ${files.length} files, no leakage detected.`);
