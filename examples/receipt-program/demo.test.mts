// SPDX-License-Identifier: Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const demo = fileURLToPath(new URL('./demo.mjs', import.meta.url));

test('receipt-program demo delegates budget, executes once, and verifies its certificate', () => {
  const result = spawnSync(process.execPath, [demo], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /EMILIA RECEIPT PROGRAM/);
  assert.match(result.stdout, /delegated 100 USD \(remaining 900 USD\)/);
  assert.match(result.stdout, /Step 2: RESERVE/);
  assert.match(result.stdout, /Step 4: COMMIT/);
  assert.match(result.stdout, /Child capability remaining: 50 USD/);
  assert.match(result.stdout, /Certificate: trusted and internally consistent/);
  assert.doesNotMatch(result.stdout, /secret|private/i);
});
