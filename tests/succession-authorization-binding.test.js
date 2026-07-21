// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { canonicalize } from '../packages/verify/index.js';

const corpus = JSON.parse(readFileSync(new URL('../conformance/vectors/succession-authorization-binding.v1.json', import.meta.url), 'utf8'));

function sha256(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function setOrDelete(root, path, mutation) {
  const parts = path.slice(1).split('/');
  const key = parts.pop();
  let current = root;
  for (const part of parts) current = current[part];
  if (mutation.delete) delete current[key];
  else current[key] = mutation.value;
}

function verifyBinding(receipt, succession) {
  const binding = succession?.credential?.subject?.authorization_binding;
  if (!binding) return { present: false, valid: true, asserts_binding: false, reasons: [] };
  const reasons = [];
  if (binding.format !== 'EP-RECEIPT-v1') reasons.push('format_mismatch');
  if (binding.caid !== receipt?.caid) reasons.push('caid_mismatch');
  const canonical = canonicalize(receipt);
  const expectedHash = sha256(canonical);
  if (binding.receipt_hash !== expectedHash) reasons.push('receipt_hash_mismatch');
  return { present: true, valid: reasons.length === 0, asserts_binding: reasons.length === 0, reasons };
}

describe('succession receipt authorization_binding vector', () => {
  it('verifies the positive binding and all negative cases', () => {
    for (const vector of corpus.vectors) {
      const receipt = structuredClone(corpus.authorization_receipt);
      const succession = structuredClone(corpus.succession_receipt);
      for (const mutation of vector.mutations || []) {
        const target = mutation.path.startsWith('/succession_receipt/') ? succession : receipt;
        const relative = mutation.path.startsWith('/succession_receipt/')
          ? mutation.path.slice('/succession_receipt'.length)
          : mutation.path.slice('/authorization_receipt'.length);
        setOrDelete(target, relative, mutation);
      }
      const result = verifyBinding(receipt, succession);
      expect(result, vector.id).toEqual(vector.expect);
    }
  });
});
