// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  copyFileSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from 'node:fs';
import { builtinModules } from 'node:module';
import { tmpdir } from 'node:os';
import { basename, dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ENTRY = resolve(HERE, 'run.standalone.mjs');
const SUPPORT_FILES = [
  'upstream-01-allow.receipt.json',
  'report.reference.json',
  'vectors.reference.json',
  'THIRD_PARTY_NOTICES.txt',
  'standalone.manifest.json',
];

test('standalone runner imports only Node built-ins', () => {
  const source = readFileSync(ENTRY, 'utf8');
  const imports = source.split('\n')
    .map((line) => line.match(/^import .* from ["']([^"']+)["'];?$/)?.[1])
    .filter(Boolean);
  const builtins = new Set([
    ...builtinModules,
    ...builtinModules.map((name) => `node:${name}`),
  ]);

  assert.ok(imports.length > 0, 'expected explicit Node imports');
  assert.deepEqual(
    imports.filter((specifier) => !builtins.has(specifier)),
    [],
    `unexpected non-Node imports: ${imports.join(', ')}`,
  );
});

test('standalone runner passes all eight cases outside the repository', () => {
  const isolated = mkdtempSync(resolve(tmpdir(), 'ccs-aeb-standalone-'));
  try {
    copyFileSync(ENTRY, resolve(isolated, basename(ENTRY)));
    for (const filename of SUPPORT_FILES) {
      copyFileSync(resolve(HERE, filename), resolve(isolated, filename));
    }

    const result = spawnSync(
      process.execPath,
      [resolve(isolated, basename(ENTRY)), '--check'],
      { cwd: isolated, encoding: 'utf8' },
    );
    assert.equal(result.status, 0, `${result.stderr}\n${result.stdout}`);

    const report = JSON.parse(result.stdout);
    assert.equal(report.passed, true);
    assert.equal(report.cases.length, 8);
    assert.equal(report.cases.every((entry) => entry.passed), true);
    assert.equal(
      report.cases.find((entry) => entry.id === 'CCS-ALLOW-PLUS-EMILIA-AUTHORITY')
        ?.observed.provider_calls,
      1,
    );
    assert.equal(
      report.cases.find((entry) => entry.id === 'INDETERMINATE-BLOCKS-BLIND-RETRY')
        ?.observed.provider_calls,
      1,
    );
  } finally {
    rmSync(isolated, { recursive: true, force: true });
  }
});
