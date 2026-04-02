#!/usr/bin/env node
/**
 * pin-action-shas.js
 *
 * One-shot migration: replaces version-tagged GitHub Action references
 * with commit SHA pins across all .github/workflows/*.yml files.
 *
 * SHA pins as of 2026-04-02. Re-run after Dependabot updates the SHAs.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT      = path.resolve(__dirname, '..');
const WORKFLOWS = path.join(ROOT, '.github', 'workflows');

// ── SHA pins (verified via gh api repos/<owner>/<repo>/tags) ─────────────────
// Format: 'owner/action@tag-or-version' → 'owner/action@SHA  # version-comment'
const PINS = {
  // ── GitHub official actions ──────────────────────────────────────────────
  'actions/checkout@v4':
    'actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4.3.1',
  'actions/setup-node@v4':
    'actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020  # v4.4.0',
  'actions/setup-python@v5':
    'actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065  # v5.6.0',
  'actions/upload-artifact@v4':
    'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02  # v4.6.2',
  'actions/setup-java@v4':
    'actions/setup-java@c1e323688fd81a25caa38c78aa6df2d33d3e20d9  # v4.8.0',

  // ── CodeQL ───────────────────────────────────────────────────────────────
  'github/codeql-action/init@v3':
    'github/codeql-action/init@5c8a8a642e79153f5d047b10ec1cba1d1cc65699  # v3.35.1',
  'github/codeql-action/analyze@v3':
    'github/codeql-action/analyze@5c8a8a642e79153f5d047b10ec1cba1d1cc65699  # v3.35.1',
  'github/codeql-action/autobuild@v3':
    'github/codeql-action/autobuild@5c8a8a642e79153f5d047b10ec1cba1d1cc65699  # v3.35.1',

  // ── Security / compliance ─────────────────────────────────────────────────
  'gitleaks/gitleaks-action@v2':
    'gitleaks/gitleaks-action@ff98106e4c7b2bc287b24eaf42907196329070c7  # v2.3.9',
  'christophebedard/dco-check@v0.4.0':
    'christophebedard/dco-check@30353d8deedf393cf55ba33355e71da7fdd095c7  # v0.4.0',

  // ── Python packaging ─────────────────────────────────────────────────────
  'pypa/gh-action-pypi-publish@release/v1':
    'pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e  # v1.13.0',
};

// ── Process each workflow file ────────────────────────────────────────────────

const files = fs.readdirSync(WORKFLOWS)
  .filter(f => f.endsWith('.yml') || f.endsWith('.yaml'))
  .map(f => path.join(WORKFLOWS, f));

let totalReplaced = 0;

for (const filePath of files) {
  const original = fs.readFileSync(filePath, 'utf-8');
  let updated = original;

  let replaced = 0;
  for (const [pattern, sha] of Object.entries(PINS)) {
    const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(escaped, 'g');
    const count = (updated.match(re) || []).length;
    if (count > 0) {
      updated = updated.replace(re, sha);
      replaced += count;
    }
  }

  if (replaced > 0) {
    fs.writeFileSync(filePath, updated, 'utf-8');
    totalReplaced += replaced;
    console.log(`  ✓ ${path.basename(filePath)} — ${replaced} replacement(s)`);
  }
}

console.log(`\nDone: ${totalReplaced} SHA pins applied across ${files.length} workflow files.`);
