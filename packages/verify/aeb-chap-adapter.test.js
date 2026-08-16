// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { canonicalizeStrictJson } from './strict-json.js';
import { digestAeb } from './aeb-adapter-contract.js';
import {
  CHAP_AEB_ADAPTER_ID,
  CHAP_AEB_ADAPTER_VERSION,
  CHAP_AEB_CONFIG_VERSION,
  CHAP_CAID_MAPPER_ID,
  CHAP_CAID_MAPPING_VERSION,
  CHAP_SOURCE_COMMIT,
  CHAP_TRUST_ROOT_VERSION,
  createChapActionDefinition,
  createChapAebAdapter,
} from './aeb-chap-adapter.js';

const NOW = '2026-08-14T18:00:00.000Z';
const REVIEWER = 'human:alice@example.org';
const ACTION_TYPE = 'payment.transfer.1';
const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const publicJwk = publicKey.export({ format: 'jwk' });

const config = Object.freeze({
  '@version': CHAP_AEB_CONFIG_VERSION,
  wire_profile: 'chap-jsonrpc-security-signed-1.0',
  evidence_role: 'human-authorization',
  subject: { id: REVIEWER, kind: 'human', native_id: REVIEWER },
  action_type: ACTION_TYPE,
  approve_binding_field: 'approved_artefact_digest',
  max_decision_age_seconds: 300,
  max_status_age_seconds: 300,
});

const trustRoot = Object.freeze({
  '@version': CHAP_TRUST_ROOT_VERSION,
  use: 'chap-participant-signing-key',
  participant_id: REVIEWER,
  kid: 'alice-2026-08',
  public_jwk: {
    kty: publicJwk.kty,
    crv: publicJwk.crv,
    x: publicJwk.x,
  },
  valid_from: '2026-08-14T00:00:00.000Z',
  valid_until: '2026-08-15T00:00:00.000Z',
  identity_binding: {
    method: 'test-enrollment',
    evidence_digest: `sha256:${'a'.repeat(64)}`,
  },
});

const expectedAction = Object.freeze({
  action_type: ACTION_TYPE,
  native_action: {
    kind: 'payment.transfer',
    account: 'acct_9',
    amount: '100.00',
    currency: 'USD',
  },
});

function signEnvelope(envelope) {
  const unsigned = structuredClone(envelope);
  delete unsigned.sig;
  const signature = crypto.sign(
    null,
    Buffer.from(canonicalizeStrictJson(unsigned), 'utf8'),
    privateKey,
  ).toString('base64');
  return { ...unsigned, sig: `ed25519:${trustRoot.kid}:${signature}` };
}

function overrideEnvelope() {
  return signEnvelope({
    jsonrpc: '2.0',
    id: '01K2AEBCHAP000000000000001',
    method: 'decide.override',
    params: {
      workspace: 'wsp_payments',
      from: REVIEWER,
      to: 'service:coordinator@example.org',
      ts: NOW,
      task_id: 'tsk_payment_9',
      based_on_artefact: {
        kind: 'payment.transfer',
        account: 'acct_9',
        amount: '90.00',
        currency: 'USD',
      },
      diff: [{ op: 'replace', path: '/amount', value: '100.00' }],
      rationale: 'Approved the corrected amount.',
      tags: ['amount-corrected'],
    },
  });
}

function approveEnvelope(bound = false) {
  const params = {
    workspace: 'wsp_payments',
    from: REVIEWER,
    to: 'service:coordinator@example.org',
    ts: NOW,
    task_id: 'tsk_payment_9',
    comment: 'Approved.',
  };
  if (bound) params.approved_artefact_digest = digestAeb(expectedAction.native_action);
  return signEnvelope({
    jsonrpc: '2.0',
    id: bound ? '01K2AEBCHAP000000000000003' : '01K2AEBCHAP000000000000002',
    method: 'decide.approve',
    params,
  });
}

function profile() {
  return {
    version: CHAP_CAID_MAPPING_VERSION,
    definition: createChapActionDefinition(ACTION_TYPE),
    registry_entry_ref: 'mapping:chap-human-decision-payment-transfer',
    mapper_id: CHAP_CAID_MAPPER_ID,
    resolver: {
      id: CHAP_CAID_MAPPER_ID,
      version: '1',
      implementation_digest: digestAeb({ implementation: CHAP_CAID_MAPPER_ID, version: '1' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [
        'decision.comment',
        'decision.rationale',
        'decision.tags',
        'decision.task_id',
        'decision.workspace',
        'decision.timestamp',
      ],
    },
    profile_digest: digestAeb(null),
  };
}

function input(artifact, overrides = {}) {
  return {
    artifact,
    artifact_ref: 'chap:decision:01K2AEBCHAP000000000000001',
    status: {
      checked_at: NOW,
      expires_at: '2026-08-14T18:01:00.000Z',
      revocation_checked: true,
      revoked: false,
      consumed: false,
    },
    trust_roots: [trustRoot],
    adapter_config: config,
    expected_action: expectedAction,
    now: NOW,
    ...overrides,
  };
}

test('signed CHAP override binds the patched artifact to the exact Gate action', () => {
  const adapter = createChapAebAdapter({ config, trust_roots: [trustRoot] });
  assert.equal(adapter.id, CHAP_AEB_ADAPTER_ID);
  assert.equal(adapter.version, CHAP_AEB_ADAPTER_VERSION);

  const native = adapter.verifyNative(input(overrideEnvelope()));
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'ACCEPTED');
  assert.deepEqual(native.reasons, []);
  assert.equal(native.subject.id, REVIEWER);
  assert.match(native.replay_unit, /^sha256:[0-9a-f]{64}$/);

  const mapped = adapter.mapAction({ ...input(overrideEnvelope()), profile: profile(), native });
  assert.equal(mapped.mapping, 'MATCH');
  assert.match(mapped.caid ?? '', /^caid:1:payment\.transfer\.1:jcs-sha256:/);
  assert.equal(mapped.action_digest, digestAeb(expectedAction));
});

test('plain decide.approve remains indeterminate because task_id does not bind an artifact', () => {
  const adapter = createChapAebAdapter({ config, trust_roots: [trustRoot] });
  const native = adapter.verifyNative(input(approveEnvelope(false)));
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'INDETERMINATE');
  assert.deepEqual(native.reasons, ['chap:approve_artifact_binding_missing']);
});

test('signature-covered approve artifact digest closes the exact-action gap', () => {
  const adapter = createChapAebAdapter({ config, trust_roots: [trustRoot] });
  const artifact = approveEnvelope(true);
  const native = adapter.verifyNative(input(artifact));
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'ACCEPTED');
  assert.deepEqual(native.reasons, []);
  const mapped = adapter.mapAction({ ...input(artifact), profile: profile(), native });
  assert.equal(mapped.mapping, 'MATCH');
});

test('tampering with an override after signing is rejected before action mapping', () => {
  const adapter = createChapAebAdapter({ config, trust_roots: [trustRoot] });
  const artifact = overrideEnvelope();
  artifact.params.diff[0].value = '1000.00';
  const native = adapter.verifyNative(input(artifact));
  assert.equal(native.native_verification, 'FAILED');
  assert.equal(native.acceptance, 'REJECTED');
  assert.deepEqual(native.reasons, ['chap:signature_invalid']);
});

test('a correctly signed decision for another action is rejected', () => {
  const adapter = createChapAebAdapter({ config, trust_roots: [trustRoot] });
  const changed = structuredClone(expectedAction);
  changed.native_action.amount = '1000.00';
  const native = adapter.verifyNative(input(overrideEnvelope(), { expected_action: changed }));
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'REJECTED');
  assert.deepEqual(native.reasons, ['chap:approved_artifact_mismatch']);
});

test('unsafe JSON Pointer segments and presenter-selected roots fail closed', () => {
  const adapter = createChapAebAdapter({ config, trust_roots: [trustRoot] });
  const unsafe = overrideEnvelope();
  unsafe.params.diff = [{ op: 'add', path: '/__proto__/polluted', value: true }];
  const resigned = signEnvelope(unsafe);
  const badPatch = adapter.verifyNative(input(resigned));
  assert.equal(badPatch.native_verification, 'VERIFIED');
  assert.equal(badPatch.acceptance, 'REJECTED');
  assert.deepEqual(badPatch.reasons, ['chap:patch_invalid']);

  const swapped = structuredClone(trustRoot);
  swapped.participant_id = 'human:mallory@example.org';
  const swappedPins = adapter.verifyNative(input(overrideEnvelope(), { trust_roots: [swapped] }));
  assert.equal(swappedPins.native_verification, 'FAILED');
  assert.equal(swappedPins.acceptance, 'REJECTED');
  assert.deepEqual(swappedPins.reasons, ['chap:constructor_pin_mismatch']);
});

test('current CHAP source commit is pinned explicitly', () => {
  assert.equal(CHAP_SOURCE_COMMIT, '9e7af2b811d3368b4afba7c6d318764959c2fd0d');
});
