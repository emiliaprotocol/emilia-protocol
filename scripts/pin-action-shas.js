#!/usr/bin/env node
// Generated from pin-action-shas.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * pin-action-shas.ts
 *
 * One-shot migration: replaces version-tagged GitHub Action references
 * with commit SHA pins across all .github/workflows/*.yml files.
 *
 * SHA pins verified against upstream tags on 2026-08-03. Re-run after
 * Dependabot updates the SHAs.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const WORKFLOWS = path.join(ROOT, '.github', 'workflows');
// ── SHA pins (verified via gh api repos/<owner>/<repo>/tags) ─────────────────
// Format: 'owner/action@tag-or-version' → 'owner/action@SHA  # version-comment'
const PINS = {
    // ── GitHub official actions ──────────────────────────────────────────────
    'actions/checkout@v7': 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1',
    'actions/setup-node@v7': 'actions/setup-node@820762786026740c76f36085b0efc47a31fe5020  # v7.0.0',
    'actions/setup-python@v7': 'actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97  # v7.0.0',
    'actions/upload-artifact@v7': 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a  # v7.0.1',
    'actions/setup-java@v5': 'actions/setup-java@b6effb05e454b25005698d916606bdc6ffcbf961  # v5.7.0',
    'actions/attest@v4': 'actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6  # v4.2.2',
    // ── CodeQL ───────────────────────────────────────────────────────────────
    'github/codeql-action/init@v4': 'github/codeql-action/init@ff2f1c621b7f889edc0d3c761ac2e6a3f8cdb0dd  # v4.37.7',
    'github/codeql-action/analyze@v4': 'github/codeql-action/analyze@ff2f1c621b7f889edc0d3c761ac2e6a3f8cdb0dd  # v4.37.7',
    'github/codeql-action/autobuild@v4': 'github/codeql-action/autobuild@ff2f1c621b7f889edc0d3c761ac2e6a3f8cdb0dd  # v4.37.7',
    // ── Security / compliance ─────────────────────────────────────────────────
    'gitleaks/gitleaks-action@v2': 'gitleaks/gitleaks-action@ff98106e4c7b2bc287b24eaf42907196329070c7  # v2.3.9',
    'christophebedard/dco-check@v0.4.0': 'christophebedard/dco-check@30353d8deedf393cf55ba33355e71da7fdd095c7  # v0.4.0',
    // ── Python packaging ─────────────────────────────────────────────────────
    'pypa/gh-action-pypi-publish@release/v1': 'pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33  # v1.14.2',
};
// ── Process each workflow file ────────────────────────────────────────────────
const files = fs.readdirSync(WORKFLOWS)
    .filter((f) => f.endsWith('.yml') || f.endsWith('.yaml'))
    .map((f) => path.join(WORKFLOWS, f));
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
