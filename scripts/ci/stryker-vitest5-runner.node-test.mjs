// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

test('the upstream Vitest 5 runner kills covered non-static mutants in nested suites', { timeout: 120_000 }, () => {
  const directory = mkdtempSync(join(tmpdir(), 'emilia-stryker-vitest5-'));
  try {
    symlinkSync(join(root, 'node_modules'), join(directory, 'node_modules'), 'dir');
    writeFileSync(join(directory, 'package.json'), JSON.stringify({ type: 'module' }));
    writeFileSync(join(directory, 'subject.js'), 'export function allowed(value) { return value > 0; }\n');
    writeFileSync(join(directory, 'subject.test.js'), [
      "import { describe, it, expect } from 'vitest';",
      "import { allowed } from './subject.js';",
      "describe('Outer [x]', () => describe('Inner (y)', () => {",
      "  it('accepts $positive', () => expect(allowed(1)).toBe(true));",
      "  it('rejects zero', () => expect(allowed(0)).toBe(false));",
      "  it('rejects negative', () => expect(allowed(-1)).toBe(false));",
      "}));",
    ].join('\n'));
    writeFileSync(join(directory, 'vitest.config.mjs'), "export default { test: { include: ['subject.test.js'] } };\n");
    writeFileSync(join(directory, 'stryker.config.json'), JSON.stringify({
      testRunner: 'vitest', plugins: ['@stryker-mutator/vitest-runner'],
      vitest: { configFile: 'vitest.config.mjs' },
      files: ['subject.js', 'subject.test.js', 'vitest.config.mjs', 'package.json'],
      mutate: ['subject.js'], coverageAnalysis: 'perTest', concurrency: 1,
      reporters: ['json'], jsonReporter: { fileName: 'mutation.json' },
      thresholds: { break: 100 },
    }));
    execFileSync(process.execPath, [join(root, 'node_modules/@stryker-mutator/core/bin/stryker.js'), 'run'], {
      cwd: directory, timeout: 110_000, stdio: 'pipe', maxBuffer: 4 * 1024 * 1024,
    });
    const report = JSON.parse(readFileSync(join(directory, 'mutation.json'), 'utf8'));
    const mutants = Object.values(report.files).flatMap((file) => file.mutants);
    assert.ok(mutants.length >= 3, 'the fixture must produce several mutants');
    assert.ok(mutants.some((mutant) => mutant.static === false && mutant.coveredBy?.length),
      'the regression must exercise per-test selection for a non-static mutant');
    for (const mutant of mutants) {
      assert.equal(mutant.status, 'Killed');
      assert.ok(mutant.killedBy?.length, 'a real test must kill every mutant');
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
