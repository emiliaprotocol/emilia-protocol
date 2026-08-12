// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  digestAeb,
  type AebAdapterInput,
  type AebPinnedProfile,
} from './aeb-adapter-contract.js';
import {
  OASNT_AEB_ADAPTER_ID,
  OASNT_AEB_ADAPTER_VERSION,
  OASNT_AEB_CONFIG_VERSION,
  OASNT_CAID_MAPPER_ID,
  OASNT_CAID_MAPPING_VERSION,
  OASNT_DRAFT_REVISION,
  OASNT_DRAFT_TXT_SHA256,
  OASNT_TRUST_ROOT_VERSION,
  computeOasntActionDigest,
  computeOasntDisplayDigest,
  computeOasntRequestFingerprint,
  createOasntActionDefinition,
  createOasntAebAdapter,
  type OasntAdapterConfig,
  type OasntTrustRoot,
} from './aeb-oasnt-adapter.js';

const NOW = new Date(1_800_000_000 * 1000).toISOString();
const ACTION_TYPE = 'payment.transfer.1';
const OASNT_ACTION_TYPE = 'payment.transfer';
const TOKEN = [
  'eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hc250K2p3dCJ9',
  'eyJzdWIiOiJhZ2VudC0xIiwiYWRnIjoiWWxIcDNNNEpJV0ZQUFpJVkF3QW1ZT0JPTWZVeWIyYmpFNnZlM0FEMmlhUSIsImRzcCI6InVTRWdPRzlVQzFJV0d4ekJhbEp2NWNJYmZ4RThreG1vS0YyNXlyUmwxZnMiLCJycWYiOiIxR0w3Q0lnMUprS0dhR2ZIZ2RGNV85M3JWeDRGcWZqb1kwbFlaNnhialEwIiwiaW50IjoiY2xlYW4iLCJqdGkiOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiIsImlhdCI6MTgwMDAwMDAwMCwiZXhwIjoxODAwMDAwMDYwLCJjbmYiOnsiamt0IjoieGNEYmMyLU1zUklFTlF5bkFZR3RKMFZjMHhQVEJkZmpfMWlBZUk5TU1GbyJ9fQ',
  '1rS6k1Yz9ZsYWpk51vTv0GDJX4VJ9vp3Qb9v4ZNG1VjQQwvVvUpUjNao7ZA0hxmBqEOHPLv8NY5C_Jqjl-SJzA',
].join('.');

const request = Object.freeze({
  method: 'POST',
  path: '/v1/transfers',
  org_id: 'org_acme',
  scope: 'payments:write',
  body_sha256: '05be0ab936cd56cf971cc8b57f7132a690d4ed3bf63b37ac3cb81d6e289f847a',
});
const expectedAction = Object.freeze({
  action_type: ACTION_TYPE,
  native_action: {
    type: OASNT_ACTION_TYPE,
    parameters: { amount: '100.00', payee: 'acct_9' },
  },
  request,
});

const config: OasntAdapterConfig = Object.freeze({
  '@version': OASNT_AEB_CONFIG_VERSION,
  evidence_role: 'human-authorization',
  subject: { id: 'human:agent-1', kind: 'human', native_id: 'agent-1' },
  action_type: ACTION_TYPE,
  require_request_binding: true,
  clock_skew_seconds: 5,
  max_token_lifetime_seconds: 120,
  max_status_age_seconds: 120,
});

const trustRoot: OasntTrustRoot = Object.freeze({
  '@version': OASNT_TRUST_ROOT_VERSION,
  use: 'enrolled-oasnt-signing-key',
  native_subject: 'agent-1',
  public_jwk: {
    kty: 'EC',
    crv: 'P-256',
    x: 'P7Vp3OZi4XYii2VHo4T08zkjKrKhCt-gY-oAATkXaao',
    y: 'QNEaWqPG2EI5-2AdT8oX-S4odj8TH9wj_JW2I2ILBoc',
  },
  jwk_thumbprint: 'xcDbc2-MsRIENQynAYGtJ0Vc0xPTBdfj_1iAeI9MMFo',
  enrollment: {
    hardware_attested: true,
    evidence_digest: `sha256:${'a'.repeat(64)}`,
  },
});

function profile(): AebPinnedProfile {
  return {
    version: OASNT_CAID_MAPPING_VERSION,
    definition: createOasntActionDefinition(ACTION_TYPE, true),
    registry_entry_ref: 'mapping:oasnt-payment-transfer',
    mapper_id: OASNT_CAID_MAPPER_ID,
    resolver: {
      id: OASNT_CAID_MAPPER_ID,
      version: '1',
      implementation_digest: digestAeb({ implementation: OASNT_CAID_MAPPER_ID, version: '1' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [
        'token.int',
        'token.cnf.jkt',
        'token.jti',
        'token.iat',
        'token.exp',
      ],
    },
    profile_digest: digestAeb(null),
  };
}

function input(overrides: Partial<Omit<AebAdapterInput, 'profile'>> = {}): Omit<AebAdapterInput, 'profile'> {
  return {
    artifact: TOKEN,
    artifact_ref: 'oasnt:published-v5',
    status: {
      checked_at: NOW,
      expires_at: new Date(Date.parse(NOW) + 60_000).toISOString(),
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

test('OASNT -01 published canonicalization vectors match byte-for-byte', () => {
  assert.equal(
    computeOasntActionDigest(OASNT_ACTION_TYPE, expectedAction.native_action.parameters),
    'YlHp3M4JIWFPPZIVAwAmYOBOMfUyb2bjE6ve3AD2iaQ',
  );
  assert.equal(
    computeOasntDisplayDigest(OASNT_ACTION_TYPE, expectedAction.native_action.parameters),
    'uSEgOG9UC1IWGxzBalJv5cIbfxE8kxmoKF25yrRl1fs',
  );
  assert.equal(
    computeOasntRequestFingerprint(request),
    '1GL7CIg1JkKGaGfHgdF5_93rVx4FqfjoY0lYZ6xbjQ0',
  );
});

test('OASNT -01 published compact token verifies and maps to one EMILIA CAID', () => {
  const adapter = createOasntAebAdapter({ config, trust_roots: [trustRoot] });
  assert.equal(adapter.id, OASNT_AEB_ADAPTER_ID);
  assert.equal(adapter.version, OASNT_AEB_ADAPTER_VERSION);

  const native = adapter.verifyNative(input());
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'ACCEPTED');
  assert.deepEqual(native.reasons, []);
  assert.match(native.replay_unit, /^sha256:[0-9a-f]{64}$/);

  const mapped = adapter.mapAction({ ...input(), profile: profile(), native });
  assert.equal(mapped.mapping, 'MATCH');
  assert.match(mapped.caid ?? '', /^caid:1:payment\.transfer\.1:jcs-sha256:/);
  assert.equal(mapped.action_digest, digestAeb(expectedAction));
});

test('OASNT adapter refuses an exact-action mismatch and never maps it', () => {
  const adapter = createOasntAebAdapter({ config, trust_roots: [trustRoot] });
  const changed = structuredClone(expectedAction);
  changed.native_action.parameters.amount = '1000.00';
  const changedInput = input({ expected_action: changed });
  const native = adapter.verifyNative(changedInput);
  assert.equal(native.native_verification, 'FAILED');
  assert.equal(native.acceptance, 'REJECTED');
  assert.ok(native.reasons.includes('oasnt:action_digest_mismatch'));
  assert.equal(adapter.mapAction({ ...changedInput, profile: profile(), native }).mapping, 'INDETERMINATE');
});

test('OASNT adapter fails closed on missing request binding and consumed status', () => {
  const adapter = createOasntAebAdapter({ config, trust_roots: [trustRoot] });
  const noRequest = structuredClone(expectedAction) as Record<string, unknown>;
  delete noRequest.request;
  const missing = adapter.verifyNative(input({ expected_action: noRequest }));
  assert.equal(missing.acceptance, 'INDETERMINATE');
  assert.ok(missing.reasons.includes('oasnt:concrete_request_required'));

  const consumed = adapter.verifyNative(input({
    status: { ...input().status, consumed: true },
  }));
  assert.equal(consumed.native_verification, 'VERIFIED');
  assert.equal(consumed.acceptance, 'REJECTED');
  assert.ok(consumed.reasons.includes('evidence_consumed'));
});

test('OASNT constructor pins cannot be replaced by presenter-selected roots', () => {
  const adapter = createOasntAebAdapter({ config, trust_roots: [trustRoot] });
  const swapped = structuredClone(trustRoot);
  swapped.public_jwk.x = `A${swapped.public_jwk.x.slice(1)}`;
  const result = adapter.verifyNative(input({ trust_roots: [swapped] }));
  assert.equal(result.native_verification, 'FAILED');
  assert.equal(result.acceptance, 'REJECTED');
  assert.deepEqual(result.reasons, ['oasnt:constructor_pin_mismatch']);
});

test('OASNT source lock is the current reviewed draft', () => {
  assert.equal(OASNT_DRAFT_REVISION, 'draft-thallapelly-oasnt-01');
  assert.equal(
    OASNT_DRAFT_TXT_SHA256,
    'sha256:7a5651b32017fa8945d71ce1007b2270559ad157b74100ade962f1d3382cab19',
  );
});
