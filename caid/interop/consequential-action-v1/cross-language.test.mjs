// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'vitest';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../../..');
const CORPUS = path.join(HERE, 'mapping-vectors.json');

function run(command, args, cwd = ROOT) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  return JSON.parse(result.stdout);
}

test('all 100 candidate vectors have identical JavaScript, Python, and Go verdicts', () => {
  const outputs = [
    run('node', ['caid/impl/js/run-mapping-vectors.mjs', '--corpus', CORPUS, '--json']),
    run('python3', ['caid/impl/python/run_mapping_vectors.py', '--corpus', CORPUS, '--json']),
    run('go', ['run', './cmd/mapping-vectors', '--corpus', CORPUS, '--json'], path.join(ROOT, 'caid/impl/go')),
  ];

  assert.equal(outputs[0].length, 100);
  assert.ok(outputs[0].every(({ pass }) => pass));
  assert.deepEqual(outputs[1], outputs[0]);
  assert.deepEqual(outputs[2], outputs[0]);
}, 30_000);
