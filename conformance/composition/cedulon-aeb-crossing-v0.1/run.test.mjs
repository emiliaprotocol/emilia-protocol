// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { canonicalizeCrossingLab } from '../../../packages/verify/dist/crossing-lab.js';
import adapter, {
  CONTENT_TYPE,
  canonicalizeJson,
  decodeCbor,
  digestJson,
  encodeCbor,
} from './workspace/adapter.mjs';
import { runCedulonCrossingProfile } from './run.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const workspace = JSON.parse(readFileSync(resolve(HERE, 'workspace/workspace.json'), 'utf8'));
const fixture = JSON.parse(readFileSync(resolve(HERE, 'workspace/artifact.json'), 'utf8'));
const profile = workspace.config.profiles[workspace.evaluation.profile_id];
const adapterPin = workspace.config.adapters[workspace.adapter.id];
const baseInput = {
  artifact: fixture,
  artifact_ref: workspace.evaluation.artifact_ref,
  status: workspace.evaluation.status,
  trust_roots: adapterPin.trust_roots,
  adapter_config: adapterPin.config,
  expected_action: workspace.expected_action,
  now: workspace.evaluated_at,
};

const FIXTURE_SEED = Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex');
const FIXTURE_PRIVATE = crypto.createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), FIXTURE_SEED]),
  format: 'der',
  type: 'pkcs8',
});

function clone(value) {
  return structuredClone(value);
}

function requestHash(request) {
  return crypto.createHash('sha256').update(canonicalizeJson(request), 'utf8').digest('hex');
}

function signToken(artifact, privateKey = FIXTURE_PRIVATE, publicKeyPem = fixture.token.publicKeyPem, unprotected = new Map()) {
  const original = decodeCbor(Buffer.from(fixture.token.coseHex, 'hex'));
  const claims = artifact.token.claims;
  const payload = encodeCbor(new Map([
    [-70301, claims.requestHash],
    [-70302, claims.policyHash],
    [-70303, claims.expiryMs],
    [-70304, claims.nonce],
    [-70305, claims.singleUseId],
  ]));
  let protectedBytes = original[0];
  if (publicKeyPem !== fixture.token.publicKeyPem) {
    const publicDer = crypto.createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
    const kid = crypto.createHash('sha256').update(publicDer).digest().subarray(0, 8);
    protectedBytes = encodeCbor(new Map([[1, -19], [3, CONTENT_TYPE], [4, kid]]));
  }
  const signature = crypto.sign(null, encodeCbor(['Signature1', protectedBytes, Buffer.alloc(0), payload]), privateKey);
  artifact.token.publicKeyPem = publicKeyPem;
  artifact.token.coseHex = encodeCbor([protectedBytes, unprotected, payload, signature]).toString('hex');
  return artifact;
}

function verify(artifact = fixture, overrides = {}) {
  return adapter.verifyNative({ ...baseInput, artifact, ...overrides });
}

test('pinned Cedulon Decision Token verifies and maps all six request fields', () => {
  const native = verify();
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'ACCEPTED');
  assert.equal(native.evidence_role, 'machine-policy-decision');
  assert.match(native.replay_unit, /^sha256:[0-9a-f]{64}$/);
  const mapped = adapter.mapAction({ ...baseInput, profile, native });
  assert.deepEqual(mapped, {
    mapping: 'MATCH',
    caid: workspace.evaluation.caid,
    action_digest: workspace.expected_action_digest,
    reasons: [],
  });
});

test('a signature-valid COSE_Sign1 with a non-empty actual unprotected map is refused', () => {
  const artifact = signToken(clone(fixture), FIXTURE_PRIVATE, fixture.token.publicKeyPem, new Map([[9, true]]));
  const native = verify(artifact);
  assert.equal(native.native_verification, 'FAILED');
  assert.deepEqual(native.reasons, ['cose_unprotected_header_not_empty']);
});

test('a presenter cannot mint authority with a token-carried self-signed key', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const artifact = signToken(clone(fixture), privateKey, publicKeyPem);
  const native = verify(artifact);
  assert.equal(native.native_verification, 'FAILED');
  assert.deepEqual(native.reasons, ['presented_key_differs_from_pin']);
});

test('each Cedulon requestHash field is material to the mapped action', () => {
  const native = verify();
  const substitutions = {
    amount: '125001',
    currency: 'EUR',
    payee: 'merchant:substitute',
    tool: 'x402.other',
    nonce: '00000000000000000000000000000000',
    manifest_hash: '0'.repeat(64),
  };
  for (const [field, value] of Object.entries(substitutions)) {
    const expected_action = { ...workspace.expected_action, [field]: value };
    const mapped = adapter.mapAction({ ...baseInput, expected_action, profile, native });
    assert.equal(mapped.mapping, 'MISMATCH', field);
    assert.deepEqual(mapped.reasons, ['material_action_mismatch'], field);
  }
});

test('a detached request change is refused even though the original token signature still verifies', () => {
  const artifact = clone(fixture);
  artifact.request.amount = '125001';
  const native = verify(artifact);
  assert.equal(native.native_verification, 'FAILED');
  assert.deepEqual(native.reasons, ['decision_request_binding_mismatch']);
});

test('expired, unavailable, consumed, and unchecked status states fail closed on separate axes', () => {
  const expired = verify(fixture, { now: '2027-02-01T12:05:00.001Z' });
  assert.equal(expired.native_verification, 'VERIFIED');
  assert.equal(expired.acceptance, 'REJECTED');
  assert.deepEqual(expired.reasons, ['decision_expired']);

  const unavailable = verify(fixture, { status: { ...baseInput.status, unavailable: true } });
  assert.equal(unavailable.native_verification, 'VERIFIED');
  assert.equal(unavailable.acceptance, 'INDETERMINATE');
  assert.deepEqual(unavailable.reasons, ['status_unavailable']);

  const consumed = verify(fixture, { status: { ...baseInput.status, consumed: true } });
  assert.equal(consumed.acceptance, 'REJECTED');
  assert.deepEqual(consumed.reasons, ['decision_consumed']);

  const unchecked = verify(fixture, { status: { ...baseInput.status, revocation_checked: false } });
  assert.equal(unchecked.acceptance, 'INDETERMINATE');
  assert.deepEqual(unchecked.reasons, ['status_not_checked']);

  const expiredUnavailable = verify(fixture, {
    now: '2027-02-01T12:05:00.001Z',
    status: { ...baseInput.status, unavailable: true },
  });
  assert.equal(expiredUnavailable.acceptance, 'REJECTED');
  assert.deepEqual(expiredUnavailable.reasons, ['decision_expired', 'status_unavailable']);
});

test('the stable replay commitment changes when either native replay identity changes', () => {
  const original = verify();

  const changedSingleUse = clone(fixture);
  changedSingleUse.token.claims.singleUseId = 'decision:cedulon-demo:002';
  signToken(changedSingleUse);
  const singleUseResult = verify(changedSingleUse);
  assert.equal(singleUseResult.native_verification, 'VERIFIED');

  const changedNonce = clone(fixture);
  changedNonce.request.nonce = '4c6c4e70c8f55ac5b8dc708d663e8f4d';
  changedNonce.token.claims.nonce = changedNonce.request.nonce;
  changedNonce.token.claims.requestHash = requestHash(changedNonce.request);
  signToken(changedNonce);
  const nonceResult = verify(changedNonce);
  assert.equal(nonceResult.native_verification, 'VERIFIED');

  assert.notEqual(original.replay_unit, singleUseResult.replay_unit);
  assert.notEqual(original.replay_unit, nonceResult.replay_unit);
  assert.notEqual(singleUseResult.replay_unit, nonceResult.replay_unit);
});

test('post-attempt Spend Receipt-shaped input cannot satisfy the pre-settlement Decision Token role', () => {
  const receipt = {
    '@version': 'CEDULON-SPEND-RECEIPT-v1',
    outcome: 'settled',
    amount: '125000',
    currency: 'USD',
  };
  const native = verify(receipt);
  assert.equal(native.native_verification, 'FAILED');
  assert.equal(native.acceptance, 'REJECTED');
  assert.deepEqual(native.reasons, ['artifact_shape_invalid']);
});

test('action and mapping files are byte-semantically identical to workspace pins', () => {
  const action = JSON.parse(readFileSync(resolve(HERE, 'action-definition.json'), 'utf8'));
  const mapping = JSON.parse(readFileSync(resolve(HERE, 'mapping-profile.json'), 'utf8'));
  assert.equal(canonicalizeCrossingLab(mapping.definitions[0]), canonicalizeCrossingLab(action));
  assert.equal(
    canonicalizeCrossingLab(workspace.config.profiles[workspace.evaluation.profile_id].definition),
    canonicalizeCrossingLab(mapping),
  );
});

test('Crossing Lab report is deterministic and matches the reviewed reference', () => {
  const first = runCedulonCrossingProfile();
  const second = runCedulonCrossingProfile();
  const reference = JSON.parse(readFileSync(resolve(HERE, 'report.reference.json'), 'utf8'));
  assert.deepEqual(first, second);
  assert.deepEqual(first, reference);
  assert.equal(first.profile_passed, true);
  assert.equal(first.claim_boundary.authorization, false);
  assert.equal(first.claim_boundary.settlement_or_payment_finality, false);
  assert.equal(first.source_lock_digest, digestJson(JSON.parse(readFileSync(resolve(HERE, 'source-lock.json'), 'utf8'))));
});
