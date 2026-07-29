// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { digestAeb, type AebPinnedProfile, type AebStatusInput } from './aeb-adapter-contract.js';
import {
  InMemoryPseaReplayStore,
  PSEA_AEB_ADAPTER_ID,
  PSEA_AEB_CAID_MAPPER_ID,
  PSEA_AEB_CAID_MAPPING_VERSION,
  PSEA_AEB_CONFIG_VERSION,
  PSEA_AEB_TRUST_ROOT_VERSION,
  PSEA_EAT_PROFILE,
  PSEA_SOURCE_REVISION,
  canonicalizePsea,
  createPseaAebAdapter,
  inspectPseaProof,
  verifyAndCommitPseaProof,
  type PseaAebConfig,
  type PseaArtifact,
  type PseaClaims,
  type PseaTrustRoot,
} from './aeb-psea-adapter.js';

type Obj = Record<string, any>;
const NOW = '2026-07-29T17:00:00Z';
const NOW_SEC = Math.floor(Date.parse(NOW) / 1000);

function p256(seedByte: number) {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.alloc(32, seedByte));
  const point = ecdh.getPublicKey(null, 'uncompressed');
  const privateKey = crypto.createPrivateKey({
    key: {
      kty: 'EC', crv: 'P-256',
      d: Buffer.alloc(32, seedByte).toString('base64url'),
      x: point.subarray(1, 33).toString('base64url'),
      y: point.subarray(33, 65).toString('base64url'),
    },
    format: 'jwk',
  });
  return { privateKey, publicKey: crypto.createPublicKey(privateKey) };
}

const signer = p256(0x51);
const ueid = Buffer.concat([Buffer.from([0x01]), Buffer.alloc(32, 0x71)]).toString('base64url');
const actionPayload = {
  amount: '125.00',
  asset: 'USD',
  beneficiary: 'vendor:acme',
  operation: 'release',
};
const expectedAction = { action_type: 'payment.release.1', ...actionPayload };

const config: PseaAebConfig = {
  '@version': PSEA_AEB_CONFIG_VERSION,
  source_revision: PSEA_SOURCE_REVISION,
  evidence_role: 'human_authorization',
  subject: { id: 'human:approver-7', kind: 'human', native_id: 'enrollment:approver-7' },
  action_type: 'payment.release.1',
  issuer: 'https://psea.example.test',
  audience: 'urn:emilia:gate:test',
  operation: 'payment.release',
  tier: 2,
  expected_nonce: 'nonce-20260729-001',
  max_token_lifetime_seconds: 300,
  max_clock_skew_seconds: 60,
  max_status_age_seconds: 180,
  required_attestation_statuses: ['verified-hardware-uv'],
  replay_mode: 'gate-atomic-consumption-required',
};

const root: PseaTrustRoot = {
  '@version': PSEA_AEB_TRUST_ROOT_VERSION,
  source_revision: PSEA_SOURCE_REVISION,
  issuer: config.issuer,
  kid: 'psea-device-key-7',
  public_key_spki: signer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  ueid,
  subject_native_id: config.subject.native_id,
  enrollment_status: 'active',
  attestation_status: 'verified-hardware-uv',
  counter_scope: 'psea-device-key-7',
};

function baseClaims(overrides: Partial<PseaClaims> = {}): PseaClaims {
  return {
    jti: 'proof-20260729-001',
    aud: config.audience,
    iss: config.issuer,
    iat: NOW_SEC - 20,
    exp: NOW_SEC + 120,
    ueid,
    eat_profile: PSEA_EAT_PROFILE,
    psea_tier: config.tier,
    psea_op: config.operation,
    psea_counter: 9,
    psea_payload_hash: crypto.createHash('sha256')
      .update(canonicalizePsea(actionPayload), 'utf8').digest('base64'),
    psea_uv: { verified: true, method: 'platform-biometric' },
    psea_proof_version: '1',
    eat_nonce: config.expected_nonce ?? undefined,
    submods: { 'psea-device-state': { integrityEvidenceRef: 'fixture:hardware-uv-7' } },
    ...overrides,
  };
}

function signProof(claims: Obj, options: { noncanonical?: boolean } = {}): string {
  const header = { alg: 'ES256', kid: root.kid, typ: 'psea-proof+jwt' };
  const headerPart = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  const payloadText = options.noncanonical
    ? JSON.stringify(claims)
    : canonicalizePsea(claims);
  const payloadPart = Buffer.from(payloadText, 'utf8').toString('base64url');
  const signingInput = Buffer.from(`${headerPart}.${payloadPart}`, 'ascii');
  const signature = crypto.sign('sha256', signingInput, {
    key: signer.privateKey, dsaEncoding: 'ieee-p1363',
  }).toString('base64url');
  return `${headerPart}.${payloadPart}.${signature}`;
}

function artifact(claims: PseaClaims = baseClaims(), options: { noncanonical?: boolean; action?: Obj } = {}): PseaArtifact {
  return {
    proof: signProof(claims, options),
    actionPayload: options.action ?? structuredClone(actionPayload),
    integrityEvidence: { appraisal: 'external-fixture-only' },
  };
}

function status(overrides: Partial<AebStatusInput> = {}): AebStatusInput {
  return {
    checked_at: '2026-07-29T16:59:30Z',
    expires_at: '2026-07-29T17:02:00Z',
    revocation_checked: true,
    revoked: false,
    consumed: false,
    ...overrides,
  };
}

function profile(): AebPinnedProfile {
  return {
    version: PSEA_AEB_CAID_MAPPING_VERSION,
    definition: {
      '@version': PSEA_AEB_CAID_MAPPING_VERSION,
      native_protocol: PSEA_SOURCE_REVISION,
      projection: 'add-action-type-v1',
      action_type: config.action_type,
      suite: 'jcs-sha256',
      definitions: [{
        action_type: config.action_type,
        required_fields: [
          { name: 'amount', type: 'amount-string' },
          { name: 'asset', type: 'string' },
          { name: 'beneficiary', type: 'string' },
          { name: 'operation', type: 'string' },
        ],
        optional_fields: [],
      }],
    },
    registry_entry_ref: 'mapping:psea-payment-release-v1',
    mapper_id: PSEA_AEB_CAID_MAPPER_ID,
    resolver: {
      id: PSEA_AEB_CAID_MAPPER_ID,
      version: '1',
      implementation_digest: digestAeb({ implementation: PSEA_AEB_CAID_MAPPER_ID, version: '1' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: ['integrityEvidence'],
    },
    profile_digest: digestAeb(null),
  };
}

test('valid PSEA -02 proof verifies and maps to the exact CAID action', () => {
  const inputArtifact = artifact();
  const inspected = inspectPseaProof({ artifact: inputArtifact, config, trust_roots: [root], now: NOW });
  assert.equal(inspected.verified, true);
  assert.deepEqual(inspected.reasons, []);

  const adapter = createPseaAebAdapter();
  assert.equal(adapter.id, PSEA_AEB_ADAPTER_ID);
  const native = adapter.verifyNative({
    artifact: inputArtifact,
    artifact_ref: 'fixture:psea:valid',
    status: status(),
    trust_roots: [root],
    adapter_config: config,
    expected_action: expectedAction,
    now: NOW,
  });
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'ACCEPTED');
  const mapping = adapter.mapAction({
    artifact: inputArtifact,
    artifact_ref: 'fixture:psea:valid',
    status: status(),
    trust_roots: [root],
    adapter_config: config,
    profile: profile(),
    expected_action: expectedAction,
    now: NOW,
    native,
  });
  assert.equal(mapping.mapping, 'MATCH');
  assert.match(mapping.caid ?? '', /^caid:1:/);
});

test('atomic replay store commits counter+jti together and refuses replay and rollback', async () => {
  const store = new InMemoryPseaReplayStore();
  const first = await verifyAndCommitPseaProof({
    artifact: artifact(), config, trust_roots: [root], now: NOW, replay_store: store,
  });
  assert.equal(first.verified, true);
  assert.equal(first.replay_committed, true);

  const replay = await verifyAndCommitPseaProof({
    artifact: artifact(), config, trust_roots: [root], now: NOW, replay_store: store,
  });
  assert.equal(replay.verified, false);
  assert.ok(replay.reasons.includes('psea:jti_replay'));

  const rollback = await verifyAndCommitPseaProof({
    artifact: artifact(baseClaims({ jti: 'proof-20260729-002' })),
    config, trust_roots: [root], now: NOW, replay_store: store,
  });
  assert.equal(rollback.verified, false);
  assert.deepEqual(rollback.reasons, ['psea:counter_rollback']);
});

test('published hostile PSEA vectors fail closed for their declared reason', () => {
  const suite = JSON.parse(readFileSync(
    new URL('../../conformance/vectors/psea-aeb.v1.json', import.meta.url), 'utf8',
  ));
  assert.equal(suite.source_revision, PSEA_SOURCE_REVISION);
  const cases: Record<string, { artifact: PseaArtifact; roots?: PseaTrustRoot[] }> = {
    accept_valid_proof: { artifact: artifact() },
    reject_wrong_audience: { artifact: artifact(baseClaims({ aud: 'urn:wrong:audience' })) },
    reject_stale_proof: { artifact: artifact(baseClaims({ iat: NOW_SEC - 500, exp: NOW_SEC - 200 })) },
    reject_noncanonical_payload: { artifact: artifact(baseClaims(), { noncanonical: true }) },
    reject_wrong_operation: { artifact: artifact(baseClaims({ psea_op: 'payment.cancel' })) },
    reject_inadequate_attestation: {
      artifact: artifact(),
      roots: [{ ...root, attestation_status: 'verified-key-only' }],
    },
    reject_action_canonicalization_difference: {
      artifact: artifact(baseClaims(), { action: { ...actionPayload, beneficiary: 'vendor:other' } }),
    },
  };
  for (const vector of suite.vectors) {
    if (['reject_jti_replay', 'reject_counter_rollback'].includes(vector.id)) continue;
    const fixture = cases[vector.id];
    assert.ok(fixture, `missing executable case ${vector.id}`);
    const result = inspectPseaProof({
      artifact: fixture.artifact,
      config,
      trust_roots: fixture.roots ?? [root],
      now: NOW,
    });
    assert.equal(result.verified, vector.accepted, vector.id);
    if (vector.reason) assert.ok(result.reasons.includes(vector.reason), `${vector.id}: ${result.reasons}`);
  }
});

test('adapter refuses stale status and never turns PSEA evidence into final authorization', () => {
  const adapter = createPseaAebAdapter();
  const native = adapter.verifyNative({
    artifact: artifact(), artifact_ref: 'fixture:psea:status-stale',
    status: status({ checked_at: '2026-07-29T16:00:00Z' }),
    trust_roots: [root], adapter_config: config, expected_action: expectedAction, now: NOW,
  });
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'INDETERMINATE');
  assert.deepEqual(native.reasons, ['psea:status_stale']);
});
