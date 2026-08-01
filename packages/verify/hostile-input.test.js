// Hostile-input regression guards (audit #5).
//
// Every case here is a negative control: it fails if the corresponding guard is
// removed. The audit that produced them found the canonicalization predicate
// recursing without cycle detection and the bundle verifier dereferencing an
// unchecked field, both of which surface as an uncaught exception rather than a
// refusal. This suite exists so that "malformed input returns a reason" stays
// true by test rather than by intention.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isCanonicalizable, verifyReceiptBundle } from './index.js';

test('a self-referential payload is out of profile, not a stack overflow', () => {
  const payload = { action_hash: 'sha256:abc' };
  payload.self = payload;
  // Must return, not throw. A crash here is a denial of service in any caller
  // that builds receipt objects in memory before signing.
  assert.equal(isCanonicalizable(payload), false);
});

test('a mutually-recursive payload is out of profile', () => {
  const a = { name: 'a' };
  const b = { name: 'b', a };
  a.b = b;
  assert.equal(isCanonicalizable(a), false);
});

test('a repeated non-cyclic sibling is still canonicalizable', () => {
  // Guards against a cycle check that walks the whole path and rejects any
  // object seen twice: a DAG has a canonical form and must stay signable.
  const shared = { unit: 'USD' };
  assert.equal(isCanonicalizable({ debit: shared, credit: shared }), true);
});

test('a symbol-keyed property is out of profile', () => {
  // canonicalize() enumerates string keys only, so a symbol-keyed value would
  // be absent from the signed bytes while remaining readable on the object.
  // Anything the signature cannot cover must not be signable.
  const payload = { action_hash: 'sha256:abc' };
  payload[Symbol.for('hidden_override')] = { amount_minor: '99999900' };
  assert.equal(isCanonicalizable(payload), false);
});

test('an ordinary payload remains canonicalizable', () => {
  assert.equal(
    isCanonicalizable({ action_hash: 'sha256:abc', approver: 'ep:approver:cfo', count: 3 }),
    true,
  );
});

test('a bundle with a non-array documents field refuses with a reason', () => {
  for (const documents of [undefined, null, 'documents', 42, {}]) {
    const result = verifyReceiptBundle({ '@version': 'EP-BUNDLE-v1', documents }, 'k');
    assert.equal(result.valid, false, `documents=${JSON.stringify(documents)} must be invalid`);
    assert.match(String(result.failed[0]), /array/i);
  }
});

test('a bundle with an empty documents array still verifies vacuously', () => {
  const result = verifyReceiptBundle({ '@version': 'EP-BUNDLE-v1', documents: [] }, 'k');
  assert.equal(result.valid, true);
  assert.equal(result.total, 0);
});
