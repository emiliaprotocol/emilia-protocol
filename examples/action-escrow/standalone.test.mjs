// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const demoPath = fileURLToPath(new URL('./demo.mjs', import.meta.url));

test('runs the documented Action Escrow demo with plain supported Node', () => {
  const result = spawnSync(process.execPath, [demoPath], {
    encoding: 'utf8',
    env: {
      ...process.env,
      NODE_NO_WARNINGS: '1',
    },
    timeout: 30_000,
  });

  assert.equal(result.signal, null, result.stderr);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /ACTION ESCROW - KITCHEN RENOVATION REFERENCE RUN/);
  assert.match(result.stdout, /GATE\s+ALLOWED; custodian calls: 1/);
  assert.match(result.stdout, /REPLAY\s+REFUSED/);
  assert.doesNotMatch(result.stderr, /ERR_UNKNOWN_FILE_EXTENSION/);
});
