#!/usr/bin/env node
/**
 * EMILIA Protocol — License Header Check
 *
 * Verifies that every .js file under lib/ and mcp-server/ contains
 * an Apache-2.0 license identifier. Fails with exit code 1 if any
 * files are missing a license header.
 *
 * Pattern accepted:
 *   @license Apache-2.0   (in a JSDoc block comment)
 *   // @license Apache-2.0 (single-line comment)
 *   SPDX-License-Identifier: Apache-2.0
 */

import { readdirSync, readFileSync, statSync } from 'fs';
import { join, relative } from 'path';
import { fileURLToPath } from 'url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const ROOT = join(__dirname, '..');

const LICENSE_PATTERN = /@license\s+Apache-2\.0|SPDX-License-Identifier:\s*Apache-2\.0/;

// Directories to check (relative to root)
const INCLUDE_DIRS = ['lib', 'mcp-server'];

// Files to skip (test files, configs, generated, or vendored)
const SKIP_PATTERNS = [
  /node_modules/,
  /\.min\.js$/,
  /\.test\.js$/,        // test files — not shipped
  /\.spec\.js$/,
  /vitest\.config\.js$/, // build/test config
  /design-tokens/,       // UI-only, not a protocol file
  /\/tests\//,           // any tests/ subdirectory
];

function shouldSkip(filePath) {
  return SKIP_PATTERNS.some((p) => p.test(filePath));
}

function collectFiles(dir) {
  const files = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      files.push(...collectFiles(full));
    } else if (entry.endsWith('.js') || entry.endsWith('.mjs')) {
      files.push(full);
    }
  }
  return files;
}

const missing = [];

for (const subdir of INCLUDE_DIRS) {
  const dirPath = join(ROOT, subdir);
  let files;
  try {
    files = collectFiles(dirPath);
  } catch {
    continue; // directory may not exist in all environments
  }

  for (const file of files) {
    if (shouldSkip(file)) continue;
    const content = readFileSync(file, 'utf8').slice(0, 1024); // only check first 1KB
    if (!LICENSE_PATTERN.test(content)) {
      missing.push(relative(ROOT, file));
    }
  }
}

if (missing.length > 0) {
  console.error('License header check FAILED — missing @license Apache-2.0:');
  for (const f of missing) {
    console.error('  ' + f);
  }
  console.error('');
  console.error('Add one of the following to the top of each file:');
  console.error('  @license Apache-2.0           (in JSDoc block)');
  console.error('  // @license Apache-2.0         (single-line comment)');
  console.error('  SPDX-License-Identifier: Apache-2.0');
  process.exit(1);
} else {
  console.log(`OK — all ${INCLUDE_DIRS.join(', ')} files have @license Apache-2.0 headers.`);
}
