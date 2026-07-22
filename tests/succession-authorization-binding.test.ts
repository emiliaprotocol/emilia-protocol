// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { canonicalize } from '../packages/verify/index.js';
import { computeCaid } from '../caid/impl/js/caid.mjs';

const corpus = JSON.parse(readFileSync(new URL('../conformance/vectors/succession-authorization-binding.v1.json', import.meta.url), 'utf8'));
const registry = JSON.parse(readFileSync(new URL('../caid/registry/action-types.json', import.meta.url), 'utf8'));
const definition = registry.types.find((entry) => entry.action_type === 'travel.cancel-notify.1');

function sha256(value: string) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function digest(value: unknown) {
  return `sha256:${sha256(canonicalize(value))}`;
}

function setOrDelete(root, path, mutation) {
  const parts = path.slice(1).split('/');
  const key = parts.pop();
  let current = root;
  for (const part of parts) current = current[part];
  if (mutation.delete) delete current[key];
  else current[key] = mutation.value;
}

function verifyBinding(receipt, succession, { nativeVerified = true } = {}) {
  const binding = succession?.credential?.subject?.authorization_binding;
  if (!binding) return { present: false, valid: true, asserts_binding: false, reasons: [] };
  const reasons: string[] = [];
  if (!nativeVerified) reasons.push('native_receipt_verification_required');
  if (digest(definition) !== corpus.caid_derivation.type_definition_digest) {
    reasons.push('type_definition_digest_mismatch');
  }
  if (binding.format !== 'EP-RECEIPT-v1') reasons.push('format_mismatch');
  const actionObject = { action_type: receipt?.action_type, ...(receipt?.action || {}) };
  const computed = computeCaid(actionObject, {
    suite: corpus.caid_derivation.suite,
    definitions: registry.types,
  });
  if (computed.caid !== receipt?.caid) reasons.push('receipt_caid_derivation_mismatch');
  if (binding.caid !== receipt?.caid) reasons.push('caid_mismatch');
  if (binding.receipt_hash !== sha256(canonicalize(receipt))) reasons.push('receipt_hash_mismatch');
  return { present: true, valid: reasons.length === 0, asserts_binding: reasons.length === 0, reasons };
}

describe('succession receipt authorization_binding correlation vector', () => {
  it('checks CAID derivation and representation binding after native verification', () => {
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
      const result = verifyBinding(receipt, succession, {
        nativeVerified: vector.native_verified !== false,
      });
      expect(result, vector.id).toEqual(vector.expect);
    }
  });
});
