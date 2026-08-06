// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

import { digestAeb, type AebAdapterInput, type AebPinnedProfile } from './aeb-adapter-contract.js';
import {
  MCGRAW_BUDGET_AEB_ADAPTER_ID,
  MCGRAW_BUDGET_AEB_ADAPTER_VERSION,
  MCGRAW_BUDGET_CONFIG_VERSION,
  MCGRAW_BUDGET_COSE_ALGORITHM,
  MCGRAW_BUDGET_DRAFT_REVISION,
  MCGRAW_BUDGET_MAPPING_VERSION,
  MCGRAW_BUDGET_MAPPER_ID,
  MCGRAW_BUDGET_TRUST_ROOT_VERSION,
  createMcGrawBudgetActionDefinition,
  createMcGrawBudgetAebAdapter,
  encodeDeterministicCbor,
  tagDeterministicCbor,
  type McGrawBudgetAdapterConfig,
  type McGrawBudgetChainVerifier,
  type McGrawBudgetMldsaVerifier,
  type McGrawBudgetTrustRoot,
} from './aeb-mcgraw-delegation-adapter.js';

type Obj = Record<string, any>;

const NOW = '2026-08-06T12:00:30.000Z';
const NOW_MS = Date.parse(NOW);
const ACTION_TYPE = 'dataset.export.1';
const ISSUER = 'https://issuer.example';
const REQUESTER = 'workload:export-agent';
const VERIFIER = 'https://api.example';
const KID = Buffer.from('issuer-key-2026-08', 'utf8');
const CHALLENGE = crypto.createHash('sha256').update('challenge').digest().subarray(0, 16);
const BODY = Buffer.from('{"format":"jsonl","limit":1000}', 'utf8');
const BODY_HASH = crypto.createHash('sha256').update(BODY).digest();

function makeFixture(): Obj {
  const keypair = ml_dsa65.keygen(crypto.randomBytes(32));
  const expectedAction = {
    action_type: ACTION_TYPE,
    delegation_action: {
      delegated_requester: REQUESTER,
      required_authority: 'dataset:export',
      method: 'POST',
      origin: 'https://api.example',
      target: '/export?format=jsonl',
      body_sha256: BODY_HASH.toString('hex'),
    },
  };
  const chainBytes = Buffer.from('profile-defined-authority-chain-v1', 'utf8');
  const claims = new Map<any, any>([
    [1, 1],
    [2, ISSUER],
    [3, REQUESTER],
    [4, '100.00'],
    [5, '75.00'],
    [6, 'USD'],
    [7, ['dataset:export']],
    [8, NOW_MS - 20_000],
    [9, NOW_MS + 100_000],
    [10, CHALLENGE],
    [11, chainBytes],
    [12, BODY_HASH],
    [13, VERIFIER],
    [14, new Map<any, any>([
      ['method', expectedAction.delegation_action.method],
      ['uri-h', crypto.createHash('sha256').update(expectedAction.delegation_action.target).digest()],
      ['origin', expectedAction.delegation_action.origin],
      ['body-h', BODY_HASH],
    ])],
  ]);
  const protectedBytes = encodeDeterministicCbor(new Map<any, any>([
    [1, MCGRAW_BUDGET_COSE_ALGORITHM],
    [3, 'application/delegation-proof+cose'],
    [4, KID],
  ]));
  const payloadBytes = encodeDeterministicCbor(claims);
  const sigStructure = encodeDeterministicCbor([
    'Signature1', protectedBytes, Buffer.alloc(0), payloadBytes,
  ]);
  const signature = Buffer.from(ml_dsa65.sign(sigStructure, keypair.secretKey));
  const cose = encodeDeterministicCbor(tagDeterministicCbor(18, [
    protectedBytes,
    new Map(),
    payloadBytes,
    signature,
  ]));
  const chainVerifierDescriptor = {
    id: 'test:mcgraw-budget-chain',
    version: '1',
    implementation_digest: digestAeb({ implementation: 'test:mcgraw-budget-chain', version: '1' }),
  };
  const mldsaDescriptor = {
    id: 'noble:ml-dsa-65',
    version: '0.6.1',
    implementation_digest: digestAeb({ implementation: 'noble:ml-dsa-65', version: '0.6.1' }),
  };
  const config: McGrawBudgetAdapterConfig = {
    '@version': MCGRAW_BUDGET_CONFIG_VERSION,
    evidence_role: 'delegated-authority',
    subject: { id: 'workload:export-agent', kind: 'workload', native_id: REQUESTER },
    action_type: ACTION_TYPE,
    issuer: ISSUER,
    verifier_binding: VERIFIER,
    required_authority: 'dataset:export',
    budget_unit: 'USD',
    minimum_remaining_budget: '2.50',
    challenge_nonce: CHALLENGE.toString('base64url'),
    content_type: 'application/delegation-proof+cose',
    representation_digest_semantics: 'http-request-content-sha256',
    require_request_binding: true,
    clock_skew_seconds: 30,
    max_lifetime_seconds: 300,
    max_status_age_seconds: 120,
    chain_verifier: chainVerifierDescriptor,
    mldsa_verifier: mldsaDescriptor,
  };
  const trustRoots: McGrawBudgetTrustRoot[] = [{
    '@version': MCGRAW_BUDGET_TRUST_ROOT_VERSION,
    issuer: ISSUER,
    key_id: KID.toString('base64url'),
    algorithm: 'ML-DSA-65',
    public_key: Buffer.from(keypair.publicKey).toString('base64url'),
  }];
  const chainVerifier: McGrawBudgetChainVerifier = {
    ...chainVerifierDescriptor,
    verify(input) {
      return Buffer.from(input.chain).equals(chainBytes)
        && input.issuer === ISSUER
        && input.delegated_requester === REQUESTER
        ? { verified: true, reason: null }
        : { verified: false, reason: 'chain_invalid' };
    },
  };
  const mldsaVerifier: McGrawBudgetMldsaVerifier = {
    ...mldsaDescriptor,
    verify(signatureBytes, message, publicKey) {
      return ml_dsa65.verify(signatureBytes, message, publicKey);
    },
  };
  return {
    keypair,
    expectedAction,
    config,
    trustRoots,
    chainVerifier,
    mldsaVerifier,
    artifact: cose.toString('base64url'),
  };
}

function profile(): AebPinnedProfile {
  return {
    version: MCGRAW_BUDGET_MAPPING_VERSION,
    definition: createMcGrawBudgetActionDefinition(ACTION_TYPE),
    registry_entry_ref: 'mapping:mcgraw-budget-dataset-export',
    mapper_id: MCGRAW_BUDGET_MAPPER_ID,
    resolver: {
      id: MCGRAW_BUDGET_MAPPER_ID,
      version: '1',
      implementation_digest: digestAeb({ implementation: MCGRAW_BUDGET_MAPPER_ID, version: '1' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [
        'budget.total', 'budget.remaining', 'budget.issued_at', 'budget.expires_at',
        'budget.challenge_nonce', 'budget.authorization_chain',
      ],
    },
    profile_digest: digestAeb(null),
  };
}

function input(fixture: Obj, overrides: Partial<Omit<AebAdapterInput, 'profile'>> = {}): Omit<AebAdapterInput, 'profile'> {
  return {
    artifact: fixture.artifact,
    artifact_ref: 'delegation:budget:test-1',
    status: {
      checked_at: '2026-08-06T12:00:29.000Z',
      expires_at: '2026-08-06T12:01:00.000Z',
      revocation_checked: true,
      revoked: false,
      consumed: false,
    },
    trust_roots: fixture.trustRoots,
    adapter_config: fixture.config,
    expected_action: fixture.expectedAction,
    now: NOW,
    ...overrides,
  };
}

test('McGraw Budget -03 real ML-DSA-65 COSE proof verifies and maps', () => {
  const fixture = makeFixture();
  const adapter = createMcGrawBudgetAebAdapter({
    config: fixture.config,
    trust_roots: fixture.trustRoots,
    chain_verifier: fixture.chainVerifier,
    mldsa_verifier: fixture.mldsaVerifier,
  });
  assert.equal(adapter.id, MCGRAW_BUDGET_AEB_ADAPTER_ID);
  assert.equal(adapter.version, MCGRAW_BUDGET_AEB_ADAPTER_VERSION);
  const native = adapter.verifyNative(input(fixture));
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'ACCEPTED');
  assert.deepEqual(native.reasons, []);
  const mapped = adapter.mapAction({ ...input(fixture), profile: profile(), native });
  assert.equal(mapped.mapping, 'MATCH');
  assert.match(mapped.caid ?? '', /^caid:1:dataset\.export\.1:jcs-sha256:/);
});

test('McGraw adapter refuses a changed target and a changed ML-DSA signature', () => {
  const fixture = makeFixture();
  const adapter = createMcGrawBudgetAebAdapter({
    config: fixture.config,
    trust_roots: fixture.trustRoots,
    chain_verifier: fixture.chainVerifier,
    mldsa_verifier: fixture.mldsaVerifier,
  });
  const changedAction = structuredClone(fixture.expectedAction);
  changedAction.delegation_action.target = '/admin';
  const mismatch = adapter.verifyNative(input(fixture, { expected_action: changedAction }));
  assert.equal(mismatch.acceptance, 'REJECTED');
  assert.ok(mismatch.reasons.includes('mcgraw-budget:request_binding_mismatch'));

  const bytes = Buffer.from(fixture.artifact, 'base64url');
  bytes[bytes.length - 1] ^= 1;
  const forged = adapter.verifyNative(input(fixture, { artifact: bytes.toString('base64url') }));
  assert.equal(forged.native_verification, 'FAILED');
  assert.equal(forged.acceptance, 'REJECTED');
});

test('McGraw adapter keeps challenge replay and chain verification fail closed', () => {
  const fixture = makeFixture();
  const refusingChain: McGrawBudgetChainVerifier = {
    ...fixture.chainVerifier,
    verify: () => ({ verified: false, reason: 'chain_invalid' }),
  };
  const adapter = createMcGrawBudgetAebAdapter({
    config: fixture.config,
    trust_roots: fixture.trustRoots,
    chain_verifier: refusingChain,
    mldsa_verifier: fixture.mldsaVerifier,
  });
  const result = adapter.verifyNative(input(fixture));
  assert.equal(result.acceptance, 'REJECTED');
  assert.ok(result.reasons.includes('mcgraw-budget:chain_invalid'));

  const validAdapter = createMcGrawBudgetAebAdapter({
    config: fixture.config,
    trust_roots: fixture.trustRoots,
    chain_verifier: fixture.chainVerifier,
    mldsa_verifier: fixture.mldsaVerifier,
  });
  const consumed = validAdapter.verifyNative(input(fixture, {
    status: { ...input(fixture).status, consumed: true },
  }));
  assert.equal(consumed.native_verification, 'VERIFIED');
  assert.equal(consumed.acceptance, 'REJECTED');
  assert.ok(consumed.reasons.includes('evidence_consumed'));
});

test('McGraw source and RFC 9964 algorithm locks are explicit', () => {
  assert.equal(MCGRAW_BUDGET_DRAFT_REVISION, 'draft-mcgraw-httpapi-agent-budget-03');
  assert.equal(MCGRAW_BUDGET_COSE_ALGORITHM, -49);
});
