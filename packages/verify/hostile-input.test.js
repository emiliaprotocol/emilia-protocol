// SPDX-License-Identifier: Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyReceiptBundle } from './index.js';

test('malformed receipt bundle refuses instead of throwing', () => {
  for (const documents of [undefined, null, 'documents', 42, {}]) {
    const result = verifyReceiptBundle({ '@version': 'EP-BUNDLE-v1', documents }, 'unused');
    assert.equal(result.valid, false, `documents=${JSON.stringify(documents)} must be invalid`);
    assert.match(String(result.failed[0]), /array/i);
  }
});

test('empty receipt bundle remains a valid empty bundle', () => {
  const result = verifyReceiptBundle({ '@version': 'EP-BUNDLE-v1', documents: [] }, 'unused');
  assert.deepEqual(result, { valid: true, total: 0, verified: 0, failed: [] });
});
