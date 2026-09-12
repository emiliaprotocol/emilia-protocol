// SPDX-License-Identifier: Apache-2.0
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = path.resolve(import.meta.dirname, '..');
const SCRIPT = path.join(ROOT, 'scripts/differential-hostility.mjs');
const MANIFEST = path.join(ROOT, 'conformance/conformance-manifest.json');

describe('current-manifest differential hostility', () => {
  it('binds every exact live suite revision and refuses malformed predicted_effects', () => {
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-current-hostility-'));
    try {
      const reportPath = path.join(temporary, 'report.json');
      execFileSync('node', [SCRIPT, '--manifest', MANIFEST, '--emit', reportPath], {
        cwd: ROOT,
        timeout: 180_000,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
      const manifest = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));

      expect(report.status).toBe('pass');
      expect(report.corpus.source_manifest).toMatchObject({
        suites: manifest.totals.suites,
        vectors: manifest.totals.vectors,
      });
      expect(report.corpus.covered_suites).toEqual(manifest.suites.map((suite: any) => ({
        path: suite.path,
        sha256: suite.sha256,
        vectors: suite.vectors,
        execution_path: suite.execution_path || suite.path,
        ...(suite.execution_sha256 ? { execution_sha256: suite.execution_sha256 } : {}),
      })));
      expect(report.corpus.categories['malformed-predicted-effects']).toBe(1);
      expect(report.corpus.required_regressions).toEqual([{
        id: 'current_outcome_binding__malformed_predicted_effects_object',
        expected: { outcome: 'incomparable' },
      }]);
    } finally {
      fs.rmSync(temporary, { recursive: true, force: true });
    }
  }, 180_000);

  it('refuses a manifest whose suite bytes do not match its pin', () => {
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-current-hostility-pin-'));
    try {
      const manifest = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
      manifest.suites[0].sha256 = '0'.repeat(64);
      const manifestPath = path.join(temporary, 'manifest.json');
      fs.writeFileSync(manifestPath, `${JSON.stringify(manifest)}\n`);
      const result = spawnSync('node', [SCRIPT, '--manifest', manifestPath], {
        cwd: ROOT,
        encoding: 'utf8',
        timeout: 30_000,
      });
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain('live manifest suite hash mismatch');
    } finally {
      fs.rmSync(temporary, { recursive: true, force: true });
    }
  });

  it('detects the previously observed malformed predicted_effects divergence', () => {
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-current-hostility-mutant-'));
    try {
      const mutant = path.join(temporary, 'mutant');
      const jsRunner = path.join(ROOT, 'conformance/runners/run-js.mjs');
      fs.writeFileSync(mutant, `#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
const rows = JSON.parse(execFileSync('node', [${JSON.stringify(jsRunner)}, process.argv[2]], { encoding: 'utf8' }));
for (const row of rows) {
  if (row.id === 'current_outcome_binding__malformed_predicted_effects_object') row.outcome = 'in_bounds';
}
process.stdout.write(JSON.stringify(rows));
`);
      fs.chmodSync(mutant, 0o755);
      const configPath = path.join(temporary, 'runners.json');
      const reportPath = path.join(temporary, 'report.json');
      fs.writeFileSync(configPath, `${JSON.stringify({
        runners: [{ name: 'malformed-predicted-effects-mutant', command: mutant, args: [] }],
      })}\n`);
      const result = spawnSync('node', [
        SCRIPT,
        '--manifest', MANIFEST,
        '--external-runners', configPath,
        '--emit', reportPath,
      ], {
        cwd: ROOT,
        encoding: 'utf8',
        timeout: 180_000,
      });
      expect(result.status).not.toBe(0);
      const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
      expect(report.divergences).toContainEqual(expect.objectContaining({
        id: 'current_outcome_binding__malformed_predicted_effects_object',
        reason: 'cross_language_divergence',
      }));
    } finally {
      fs.rmSync(temporary, { recursive: true, force: true });
    }
  }, 180_000);
});
