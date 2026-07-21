// SPDX-License-Identifier: Apache-2.0
//
// Drop-in fidelity: the committed copies of the zero-dependency gate MUST be a
// byte-for-byte match of a fresh regeneration from source (index.js + gate.js).
//
// build-drop-in.mjs's header long CLAIMED "it is checked in CI that the
// committed dist/ matches a fresh regeneration" — but no such check existed, so
// the committed drop-ins silently drifted (the eve example was stuck at source
// v0.4.1 and missed the quorum-distinctness AND freshness fail-closed fixes).
// This test makes the claim TRUE: it regenerates into a temp dir (via
// EP_DROPIN_OUT_DIR, so the committed files are untouched) and asserts equality
// with every committed copy. If they differ, run `npm run build:drop-in` from
// packages/require-receipt and commit the result.

import { test, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..');
const pkgDir = join(repoRoot, 'packages', 'require-receipt');
const buildScript = join(pkgDir, 'build-drop-in.mjs');

const committedDist = join(pkgDir, 'dist', 'emilia-gate.mjs');
const committedExample = join(repoRoot, 'examples', 'eve-receipt-required', 'lib', 'emilia-gate.mjs');

// Regenerate ONCE into an isolated temp dir; the build script honors
// EP_DROPIN_OUT_DIR and writes both copies there without touching committed files.
const outDir = mkdtempSync(join(tmpdir(), 'ep-dropin-fidelity-'));
execFileSync('node', [buildScript], {
  cwd: pkgDir,
  env: { ...process.env, EP_DROPIN_OUT_DIR: outDir },
  encoding: 'utf8',
});
const freshDist = readFileSync(join(outDir, 'dist-emilia-gate.mjs'), 'utf8');
const freshExample = readFileSync(join(outDir, 'example-emilia-gate.mjs'), 'utf8');

const HINT = 'Run `npm run build:drop-in` from packages/require-receipt and commit the regenerated file.';

test('committed dist/emilia-gate.mjs is byte-identical to a fresh regeneration', () => {
  const committed = readFileSync(committedDist, 'utf8');
  expect(committed, `dist/emilia-gate.mjs is stale. ${HINT}`).toBe(freshDist);
});

test('committed eve-receipt-required/lib/emilia-gate.mjs is byte-identical to a fresh regeneration', () => {
  const committed = readFileSync(committedExample, 'utf8');
  expect(committed, `examples/eve-receipt-required/lib/emilia-gate.mjs is stale. ${HINT}`).toBe(freshExample);
});

test('both committed copies are byte-identical to each other', () => {
  // The eve example README tells adopters to curl the dist file, so the two
  // shipped copies must not diverge.
  expect(readFileSync(committedDist, 'utf8')).toBe(readFileSync(committedExample, 'utf8'));
});
