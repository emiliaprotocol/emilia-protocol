// SPDX-License-Identifier: Apache-2.0
/**
 * EP-SURFACE-BINDING-v1 tests.
 *
 * Runs every vector in conformance/vectors/surface-binding.v1.json through
 * verifySurfaceBinding(), then unit-tests the fail-closed edges of
 * validateSurfaceBinding(), bindSurfaceInto(), and receiptSurfaceBinding().
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

import {
  SURFACE_BINDING_VERSION,
  SURFACE_BINDING_FIELD,
  normalizeSurfaceDigest,
  validateSurfaceBinding,
  bindSurfaceInto,
  receiptSurfaceBinding,
  verifySurfaceBinding,
} from './surface-binding.js';
import { canonicalize } from './index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const suite = JSON.parse(
  readFileSync(
    path.join(__dirname, '..', '..', 'conformance', 'vectors', 'surface-binding.v1.json'),
    'utf8',
  ),
);

test('suite metadata', () => {
  assert.equal(suite.suite, 'EP-SURFACE-BINDING-v1');
  assert.ok(Array.isArray(suite.vectors) && suite.vectors.length >= 10);
});

for (const v of suite.vectors) {
  test(`vector: ${v.id}`, () => {
    const { receipt, evidence, require } = v.input;
    const res = verifySurfaceBinding(receipt, evidence, { require });
    assert.equal(res.valid, v.expect.valid, `valid mismatch for ${v.id}`);
    if (v.expect.reason) {
      assert.equal(res.reason, v.expect.reason, `reason mismatch for ${v.id}`);
    }
    if (v.expect.checks) {
      assert.deepEqual(res.checks, v.expect.checks, `checks mismatch for ${v.id}`);
    }
  });
}

// ── unit edges ───────────────────────────────────────────────────────────────

const GOOD_EVIDENCE = 'lit-assertion:device=sound;user=present;session=af31';
const GOOD_DIGEST = `sha256:${crypto.createHash('sha256').update(GOOD_EVIDENCE, 'utf8').digest('hex')}`;
const GOOD_BINDING = Object.freeze({
  '@version': SURFACE_BINDING_VERSION,
  surface_kind: 'wimse-condition-bounded',
  attestation_digest: GOOD_DIGEST,
});

test('normalizeSurfaceDigest fail-closed on malformed input', () => {
  assert.equal(normalizeSurfaceDigest(undefined), '');
  assert.equal(normalizeSurfaceDigest(null), '');
  assert.equal(normalizeSurfaceDigest('sha256:zz'), '');
  assert.equal(normalizeSurfaceDigest({}), '');
  assert.equal(normalizeSurfaceDigest(GOOD_DIGEST), GOOD_DIGEST.slice('sha256:'.length));
  assert.equal(
    normalizeSurfaceDigest(GOOD_DIGEST.toUpperCase().replace('SHA256:', 'sha256:')),
    GOOD_DIGEST.slice('sha256:'.length),
  );
});

test('validateSurfaceBinding refuses non-objects, arrays, and missing fields', () => {
  for (const bad of [null, undefined, 'x', 7, [], { surface_kind: 'k' }, { attestation_digest: GOOD_DIGEST }]) {
    const r = validateSurfaceBinding(bad);
    assert.equal(r.ok, false);
    assert.equal(r.normalized, null);
    assert.ok(r.errors.length >= 1);
  }
});

test('validateSurfaceBinding refuses empty verifier_hint and non-string surface_kind', () => {
  assert.equal(validateSurfaceBinding({ ...GOOD_BINDING, verifier_hint: '' }).ok, false);
  assert.equal(validateSurfaceBinding({ ...GOOD_BINDING, verifier_hint: 7 }).ok, false);
  assert.equal(validateSurfaceBinding({ ...GOOD_BINDING, surface_kind: 3 }).ok, false);
});

test('validateSurfaceBinding normalizes digest to sha256:-prefixed lowercase', () => {
  const bare = GOOD_DIGEST.slice('sha256:'.length);
  const r = validateSurfaceBinding({ surface_kind: 'k', attestation_digest: bare.toUpperCase() });
  assert.equal(r.ok, true);
  assert.equal(r.normalized.attestation_digest, GOOD_DIGEST);
  assert.equal(r.normalized['@version'], SURFACE_BINDING_VERSION);
});

test('bindSurfaceInto covers the binding under the frozen action-hash definition', () => {
  const action = { type: 'grid.curtailment', params: { feeder: 'F-12', mw: 3 } };
  const { action: bound, binding, digest_preview } = bindSurfaceInto(action, GOOD_BINDING);
  assert.equal(bound[SURFACE_BINDING_FIELD].attestation_digest, GOOD_DIGEST);
  assert.deepEqual(binding, bound[SURFACE_BINDING_FIELD]);
  const expected = `sha256:${crypto.createHash('sha256').update(canonicalize(bound), 'utf8').digest('hex')}`;
  assert.equal(digest_preview, expected);
  // original action untouched
  assert.equal(action[SURFACE_BINDING_FIELD], undefined);
});

test('bindSurfaceInto refuses to overwrite a DIFFERENT existing binding, tolerates identical', () => {
  const action = { type: 't', params: {} };
  const { action: bound } = bindSurfaceInto(action, GOOD_BINDING);
  // identical re-bind is fine
  assert.doesNotThrow(() => bindSurfaceInto(bound, GOOD_BINDING));
  // different binding refuses
  const other = { ...GOOD_BINDING, surface_kind: 'other-kind' };
  assert.throws(() => bindSurfaceInto(bound, other), /refusing to overwrite/);
});

test('bindSurfaceInto refuses invalid bindings and non-object actions', () => {
  assert.throws(() => bindSurfaceInto(null, GOOD_BINDING), TypeError);
  assert.throws(() => bindSurfaceInto([], GOOD_BINDING), TypeError);
  assert.throws(() => bindSurfaceInto({}, { surface_kind: 'k' }), /invalid surface binding/);
});

test('receiptSurfaceBinding: strength is signed_action only inside receipt.action', () => {
  const inAction = { action: { type: 't', [SURFACE_BINDING_FIELD]: GOOD_BINDING } };
  assert.equal(receiptSurfaceBinding(inAction).strength, 'signed_action');
  const topLevel = { [SURFACE_BINDING_FIELD]: GOOD_BINDING, action: { type: 't' } };
  assert.equal(receiptSurfaceBinding(topLevel).strength, 'none');
  assert.equal(receiptSurfaceBinding(null).strength, 'none');
  assert.equal(receiptSurfaceBinding({}).strength, 'none');
});

test('receiptSurfaceBinding: malformed binding reports none WITH errors, never upgrades', () => {
  const malformed = { action: { type: 't', [SURFACE_BINDING_FIELD]: { surface_kind: 'k' } } };
  const r = receiptSurfaceBinding(malformed);
  assert.equal(r.strength, 'none');
  assert.ok(r.errors.length >= 1);
});

test('verifySurfaceBinding accepts Uint8Array evidence and refuses non-string junk', () => {
  const receipt = { action: { type: 't', [SURFACE_BINDING_FIELD]: GOOD_BINDING } };
  const bytes = new TextEncoder().encode(GOOD_EVIDENCE);
  assert.equal(verifySurfaceBinding(receipt, bytes).valid, true);
  for (const junk of [null, undefined, 7, {}, []]) {
    const r = verifySurfaceBinding(receipt, junk);
    assert.equal(r.valid, false);
    assert.equal(r.reason, 'surface_digest_mismatch');
  }
});

test('evidence is ALWAYS hashed as bytes, echoing the public bound digest fails', () => {
  // Finding 2 fix: there is no precomputed-digest path. A caller who never held
  // the evidence but read the receipt's public attestation_digest and echoes it
  // back must NOT match, because we hash whatever bytes are presented.
  const evidence = 'lit-assertion:device=sound;user=present;session=af31';
  const bound = `sha256:${crypto.createHash('sha256').update(evidence, 'utf8').digest('hex')}`;
  const receipt = {
    action: { type: 't', [SURFACE_BINDING_FIELD]: { surface_kind: 'k', attestation_digest: bound } },
  };
  // real evidence bytes -> hashes to bound -> accept
  assert.equal(verifySurfaceBinding(receipt, evidence, { require: true }).valid, true);
  // echoed public digest -> hashed as bytes -> cannot equal itself-as-preimage -> refuse
  const echo = verifySurfaceBinding(receipt, bound, { require: true });
  assert.equal(echo.valid, false);
  assert.equal(echo.reason, 'surface_digest_mismatch');
});

test('64-hex-shaped evidence is hashed as bytes like anything else (no dual interpretation)', () => {
  const hexLooking = 'a'.repeat(64);
  const bound = `sha256:${crypto.createHash('sha256').update(hexLooking, 'utf8').digest('hex')}`;
  const receipt = {
    action: { type: 't', [SURFACE_BINDING_FIELD]: { surface_kind: 'k', attestation_digest: bound } },
  };
  // Now the hex-shaped bytes ARE hashed, so a binding to hash-of-those-bytes accepts.
  assert.equal(verifySurfaceBinding(receipt, hexLooking, { require: true }).valid, true);
});

test('BREAK-1 GUARD: a prototype-inherited approval_surface never upgrades to signed', () => {
  // The binding lives on the prototype, not as an own member. canonicalize() (and
  // thus the human signature) never covers it. Object.hasOwn must reject it.
  const binding = {
    '@version': SURFACE_BINDING_VERSION,
    surface_kind: 'wimse-condition-bounded',
    attestation_digest: `sha256:${crypto.createHash('sha256').update('e', 'utf8').digest('hex')}`,
  };
  const action = Object.create({ [SURFACE_BINDING_FIELD]: binding });
  action.type = 'grid.curtailment';
  assert.equal(Object.hasOwn(action, SURFACE_BINDING_FIELD), false);
  assert.equal(receiptSurfaceBinding({ action }).strength, 'none');
  const r = verifySurfaceBinding({ action }, 'e', { require: true });
  assert.equal(r.valid, false);
  assert.equal(r.reason, 'surface_binding_absent');
});

test('FAIL-CLOSED: opts=null / undefined defaults to require:true, never throws', () => {
  const receipt = { action: { type: 't' } };
  for (const opts of [null, undefined]) {
    const r = verifySurfaceBinding(receipt, 'x', opts);
    assert.equal(r.valid, false);
    assert.equal(r.reason, 'surface_binding_absent');
  }
});

test('FAIL-CLOSED: a throwing action getter refuses, never crashes', () => {
  const receipt = { get action() { throw new Error('hostile'); } };
  const r = verifySurfaceBinding(receipt, 'x', { require: true });
  assert.equal(r.valid, false);
  assert.equal(r.reason, 'surface_binding_malformed');
});

test('require:false result is marked admitted_without_possession_row', () => {
  const r = verifySurfaceBinding({ action: { type: 't' } }, 'x', { require: false });
  assert.equal(r.valid, true);
  assert.equal(r.checks.present, false);
  assert.equal(r.admitted_without_possession_row, true);
});

test('attestation_digest must be a string (parity with surface_kind)', () => {
  // A Buffer / toString-coercible object must not pass, even if its text is hex.
  const hex = crypto.createHash('sha256').update('e', 'utf8').digest('hex');
  const coercible = { surface_kind: 'k', attestation_digest: { toString: () => hex } };
  assert.equal(validateSurfaceBinding(coercible).ok, false);
});
