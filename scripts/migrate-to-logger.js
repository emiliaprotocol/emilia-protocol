#!/usr/bin/env node
/**
 * migrate-to-logger.js
 *
 * One-shot migration: replaces console.error/warn/log calls with
 * structured logger calls across lib/ and app/ source files.
 *
 * Run once: node scripts/migrate-to-logger.js
 * Safe to re-run (idempotent — skips files already migrated).
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

// ── Collect target files ─────────────────────────────────────────────────────

function walk(dir, results = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === '.next') continue;
      walk(full, results);
    } else if (entry.isFile() && /\.(js|mjs)$/.test(entry.name)) {
      results.push(full);
    }
  }
  return results;
}

const targets = [
  ...walk(path.join(ROOT, 'lib')),
  ...walk(path.join(ROOT, 'app')),
].filter(f => {
  // Skip test files, vitest config, scripts, and the logger itself
  return !f.includes('.test.') && !f.includes('vitest.') &&
         !f.includes('scripts/') && !f.endsWith('lib/logger.js');
});

// ── Migration ────────────────────────────────────────────────────────────────

let migratedCount = 0;
let skippedCount  = 0;

for (const filePath of targets) {
  const src = fs.readFileSync(filePath, 'utf-8');

  // Skip if no console calls
  if (!/console\.(error|warn|log)\b/.test(src)) {
    continue;
  }

  // Skip if already using logger (idempotency)
  if (src.includes("from './logger.js'") || src.includes("from '../logger.js'") ||
      src.includes("from '../../lib/logger.js'") || src.includes("lib/logger.js'")) {
    skippedCount++;
    continue;
  }

  // Calculate relative path from this file to lib/logger.js
  const libLogger = path.join(ROOT, 'lib', 'logger.js');
  let relPath = path.relative(path.dirname(filePath), libLogger);
  // Normalise to forward slashes and ensure ./ prefix
  relPath = relPath.replace(/\\/g, '/');
  if (!relPath.startsWith('.')) relPath = './' + relPath;

  // Replace console calls
  let updated = src
    .replace(/console\.error\(/g, 'logger.error(')
    .replace(/console\.warn\(/g,  'logger.warn(')
    .replace(/console\.log\(/g,   'logger.info(');

  // Insert logger import after the last existing import line.
  // Strategy: find the last line that starts with 'import ' and insert after it.
  const importLine = `import { logger } from '${relPath}';`;

  const lines = updated.split('\n');
  let lastImportIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    if (/^import\s+/.test(lines[i]) || /^import\s*\{/.test(lines[i])) {
      lastImportIdx = i;
    }
  }

  if (lastImportIdx >= 0) {
    lines.splice(lastImportIdx + 1, 0, importLine);
  } else {
    // No existing imports — add at the top after any leading comments/license header.
    let insertAt = 0;
    let inBlockComment = false;
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes('/*')) inBlockComment = true;
      if (inBlockComment) {
        if (lines[i].includes('*/')) { inBlockComment = false; insertAt = i + 1; }
        continue;
      }
      if (lines[i].startsWith('//')) { insertAt = i + 1; continue; }
      break;
    }
    lines.splice(insertAt, 0, importLine);
  }

  updated = lines.join('\n');

  fs.writeFileSync(filePath, updated, 'utf-8');
  migratedCount++;
  console.log(`  ✓ ${path.relative(ROOT, filePath)}`);
}

console.log(`\nMigration complete: ${migratedCount} files updated, ${skippedCount} already migrated.`);
