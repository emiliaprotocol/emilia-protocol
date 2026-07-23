// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  adapterPinDigest,
  canonicalizeAeb,
  digestAeb,
  evaluateAebEvidence,
  mappingProfileDigest,
  registryEntryDigest,
  unifiedRegistryDigest,
  type AebAdapterInput,
  type AebPinnedProfile,
  type AebStatusInput,
} from './aeb-adapter-contract.js';
import {
  AEB_NATIVE_CAID_MAPPER_ID,
  AEB_NATIVE_CAID_MAPPING_VERSION,
  AGENTROA_AEB_ADAPTER_ID,
  AGENTROA_AEB_ADAPTER_VERSION,
  AGENTROA_AEB_CONFIG_VERSION,
  AGENTROA_AEB_TRUST_ROOT_VERSION,
  ORPRG_AEB_ADAPTER_ID,
  ORPRG_AEB_ADAPTER_VERSION,
  ORPRG_AEB_CONFIG_VERSION,
  ORPRG_AEB_TRUST_ROOT_VERSION,
  createAgentRoaAebAdapter,
  createOrprgAebAdapter,
} from './aeb-native-adapters.js';

import { AGENTROA_DRAFT } from './agentroa.js';
import {
  ORPRG_ACTION_PROFILE,
  ORPRG_JSON_JCS_PROFILE,
  computeOrprgActionDigest,
} from './orprg.js';

test('published CAID runtime is byte-identical to the governed reference implementation', () => {
  const governed = readFileSync(new URL('../../caid/impl/js/caid.mjs', import.meta.url));
  const packaged = readFileSync(new URL('./vendor/caid.mjs', import.meta.url));
  assert.deepEqual(packaged, governed);
});

type Obj = Record<string, any>;

const AGENT_NOW = '2026-04-08T14:03:00Z';
const ORPRG_NOW = '2026-07-19T12:00:00Z';
const POLICY_DIGEST = `sha256:${'a'.repeat(64)}`;

function spki(key: crypto.KeyObject): string {
  return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function signObject(body: Obj, signer: string, key: crypto.KeyObject): Obj {
  const sig = crypto.sign(
    null,
    Buffer.from(canonicalizeAeb(body), 'utf8'),
    key,
  ).toString('base64url');
  return { ...structuredClone(body), signatures: [{ signer, alg: 'EdDSA', sig }] };
}

function externalStatus(now: string, overrides: Partial<AebStatusInput> = {}): AebStatusInput {
  const base = now === AGENT_NOW
    ? { checked_at: '2026-04-08T14:02:00Z', expires_at: '2026-04-08T14:05:00Z' }
    : { checked_at: '2026-07-19T11:59:00Z', expires_at: '2026-07-19T12:03:00Z' };
  return {
    ...base,
    revocation_checked: true,
    revoked: false,
    consumed: false,
    ...overrides,
  };
}

function makeAgentFixture(): Obj {
  const rootKey = crypto.generateKeyPairSync('ed25519');
  const gatewayKey = crypto.generateKeyPairSync('ed25519');
  const action = {
    capability: 'api:payments.transfer',
    target_service_id: 'payments-service',
    operation: 'transfer',
    input_hash: `sha256:${'c'.repeat(64)}`,
  };
  const root = signObject({
    schema_version: '1.0',
    envelope_id: 'env:4a7c9f2b1e8d3a6f',
    issued_at: '2026-04-08T14:00:00Z',
    expires_at: '2026-04-08T14:10:00Z',
    session: {
      session_id: 'sess:8b3d0e7f2a1c9b4e',
      channel: 'api',
      agent_id: 'aha:acme/ops/payment-agent',
    },
    authorized_scope: {
      capabilities: ['api:payments.transfer'],
      max_delegation_depth: 0,
      cross_org_permitted: false,
    },
    policy: {
      policy_id: 'payments-v4',
      policy_version: '4.2.1',
      policy_digest: POLICY_DIGEST,
    },
    authorization: {
      auth_strength: 'session_only',
      approval_state: 'not_required',
    },
    evidence: {
      session_hash: `sha256:${'b'.repeat(64)}`,
      model_provenance: ['example:model:v1'],
    },
  }, 'policy-engine:prod', rootKey.privateKey);
  const chain = [root];
  const aer = signObject({
    schema_version: '1.0',
    aer_id: 'aer:2f5a8c1d4e7b0f3a',
    produced_at: '2026-04-08T14:02:30Z',
    enforcement_outcome: 'permit',
    enforcement_mode: 'normal',
    deployment_topology: 'topology_d_domain_boundary',
    session: {
      session_id: root.session.session_id,
      agent_id: root.session.agent_id,
    },
    action,
    policy: {
      policy_id: root.policy.policy_id,
      policy_digest: root.policy.policy_digest,
    },
    chain_summary: {
      chain_depth: 0,
      root_envelope_id: root.envelope_id,
      chain_digest: digestAeb(chain),
    },
    border_gateway: {
      gateway_id: 'gateway:prod-us-east-1',
      gateway_version: '1.1.0',
    },
  }, 'gateway:prod-us-east-1', gatewayKey.privateKey);
  const artifact = { chain, aer };
  const expectedAction = { action_type: 'payment.transfer.1', ...action };
  const config = {
    '@version': AGENTROA_AEB_CONFIG_VERSION,
    evidence_role: 'operator-of-record',
    subject: {
      id: 'workload:payment-agent',
      kind: 'workload',
      native_id: root.session.agent_id,
    },
    action_type: expectedAction.action_type,
    max_status_age_seconds: 300,
    policy: {
      expected_policy_id: root.policy.policy_id,
      expected_policy_version: root.policy.policy_version,
      expected_policy_digest: root.policy.policy_digest,
      allow_degraded: false,
      allowed_topologies: ['topology_d_domain_boundary'],
      capability_manifest: {},
    },
  };
  const trustRoots = [
    {
      '@version': AGENTROA_AEB_TRUST_ROOT_VERSION,
      role: 'roa',
      signer_id: 'policy-engine:prod',
      public_key: spki(rootKey.publicKey),
    },
    {
      '@version': AGENTROA_AEB_TRUST_ROOT_VERSION,
      role: 'aer',
      signer_id: 'gateway:prod-us-east-1',
      public_key: spki(gatewayKey.publicKey),
    },
  ];
  return { artifact, action, expectedAction, config, trustRoots, rootKey, gatewayKey };
}

function resignAgentAer(fixture: Obj, mutate: (aer: Obj) => void): void {
  const body = structuredClone(fixture.artifact.aer);
  delete body.signatures;
  mutate(body);
  fixture.artifact.aer = signObject(body, body.border_gateway.gateway_id, fixture.gatewayKey.privateKey);
}

const ORPRG_ISSUER_ID = 'https://policy.example/issuers/primary';
const ORPRG_KEY_ID = 'orprg-ed25519-2026-07';
const ORPRG_EPOCH = 'policy-epoch-42';

const ORPRG_ACTION = Object.freeze({
  effect_type: 'payment.release',
  interface_id: 'payments-api-v2',
  target_id: 'escrow_4821',
  tenant_id: 'tenant_acme',
  purpose_id: 'invoice-settlement',
  jurisdiction: ['US-CA'],
  audience: 'https://payments.example/commit',
  budget: { unit: 'USD-cent', amount: 50_000 },
  request: {
    destination_account: 'acct_vendor_9',
    invoice_id: 'inv_2026_0719',
    memo: 'Milestone 3',
  },
});

function signOrprgReceipt(receipt: Obj, key: crypto.KeyObject): Obj {
  const unsigned = {
    '@version': receipt['@version'],
    receipt_core: receipt.receipt_core,
    status: receipt.status,
    authenticity: {
      issuer_id: receipt.authenticity.issuer_id,
      key_id: receipt.authenticity.key_id,
      algorithm: receipt.authenticity.algorithm,
    },
  };
  receipt.authenticity.signature = crypto
    .sign(null, Buffer.from(canonicalizeAeb(unsigned), 'utf8'), key)
    .toString('base64url');
  return receipt;
}

function makeOrprgFixture(mutator?: (receipt: Obj) => void): Obj {
  const issuerKey = crypto.generateKeyPairSync('ed25519');
  const receipt: Obj = {
    '@version': ORPRG_JSON_JCS_PROFILE,
    receipt_core: {
      policy_digest: POLICY_DIGEST,
      epoch_id: ORPRG_EPOCH,
      valid_from: '2026-07-19T11:55:00Z',
      valid_to: '2026-07-19T12:05:00Z',
      action_digest: computeOrprgActionDigest(ORPRG_ACTION),
      canonicalization_profile: ORPRG_ACTION_PROFILE,
      scope: {
        effect_type: ORPRG_ACTION.effect_type,
        interface_id: ORPRG_ACTION.interface_id,
        target_id: ORPRG_ACTION.target_id,
        tenant_id: ORPRG_ACTION.tenant_id,
        purpose_id: ORPRG_ACTION.purpose_id,
        jurisdiction: [...ORPRG_ACTION.jurisdiction],
        audience: ORPRG_ACTION.audience,
        budget: { unit: ORPRG_ACTION.budget.unit, limit: 100_000 },
      },
      anti_replay: {
        mode: 'single-use',
        nonce: 'S1ngleUseNonce_20260719_0001',
      },
    },
    status: {
      state: 'good',
      checked_at: '2026-07-19T11:59:00Z',
      next_update: '2026-07-19T12:03:00Z',
    },
    authenticity: {
      issuer_id: ORPRG_ISSUER_ID,
      key_id: ORPRG_KEY_ID,
      algorithm: 'Ed25519',
      signature: '',
    },
  };
  mutator?.(receipt);
  signOrprgReceipt(receipt, issuerKey.privateKey);
  const expectedAction = { action_type: 'payment.release.1', ...structuredClone(ORPRG_ACTION) };
  const config = {
    '@version': ORPRG_AEB_CONFIG_VERSION,
    evidence_role: 'policy-permit',
    subject: {
      id: 'organization:policy-issuer',
      kind: 'organization',
      native_id: ORPRG_ISSUER_ID,
    },
    action_type: expectedAction.action_type,
    expected_policy_digest: POLICY_DIGEST,
    expected_epoch: ORPRG_EPOCH,
    max_receipt_age_seconds: 600,
    max_status_age_seconds: 180,
    require_budget: true,
    native_replay_phase: 'inspection-only',
  };
  const trustRoots = [{
    '@version': ORPRG_AEB_TRUST_ROOT_VERSION,
    issuer_id: ORPRG_ISSUER_ID,
    key_id: ORPRG_KEY_ID,
    public_key: spki(issuerKey.publicKey),
  }];
  return { artifact: receipt, expectedAction, config, trustRoots, issuerKey };
}

function mappingProfile(
  protocol: string,
  actionType: string,
  requiredFields: Obj[],
  registryRef = `mapping:${actionType}`,
): AebPinnedProfile {
  return {
    version: AEB_NATIVE_CAID_MAPPING_VERSION,
    definition: {
      '@version': AEB_NATIVE_CAID_MAPPING_VERSION,
      native_protocol: protocol,
      projection: 'add-action-type-v1',
      action_type: actionType,
      suite: 'jcs-sha256',
      definitions: [{ action_type: actionType, required_fields: requiredFields, optional_fields: [] }],
    },
    registry_entry_ref: registryRef,
    mapper_id: AEB_NATIVE_CAID_MAPPER_ID,
    resolver: {
      id: AEB_NATIVE_CAID_MAPPER_ID,
      version: '1',
      implementation_digest: digestAeb({ implementation: AEB_NATIVE_CAID_MAPPER_ID, version: '1' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [],
    },
    profile_digest: digestAeb(null),
  };
}

function agentProfile(): AebPinnedProfile {
  return mappingProfile(AGENTROA_DRAFT, 'payment.transfer.1', [
    { name: 'action_type', type: 'string' },
    { name: 'capability', type: 'string' },
    { name: 'target_service_id', type: 'string' },
    { name: 'operation', type: 'string' },
    { name: 'input_hash', type: 'digest' },
  ]);
}

function orprgProfile(): AebPinnedProfile {
  return mappingProfile(ORPRG_JSON_JCS_PROFILE, 'payment.release.1', [
    { name: 'action_type', type: 'string' },
    { name: 'effect_type', type: 'string' },
    { name: 'interface_id', type: 'string' },
    { name: 'target_id', type: 'string' },
    { name: 'tenant_id', type: 'string' },
    { name: 'purpose_id', type: 'string' },
    { name: 'jurisdiction', type: 'array' },
    { name: 'audience', type: 'string' },
    { name: 'budget', type: 'object' },
    { name: 'request', type: 'object' },
  ]);
}

function nativeInput(
  fixture: Obj,
  now: string,
  status = externalStatus(now),
): Omit<AebAdapterInput, 'profile'> {
  return {
    artifact: fixture.artifact,
    artifact_ref: 'artifact:native-1',
    status,
    trust_roots: fixture.trustRoots,
    adapter_config: fixture.config,
    expected_action: fixture.expectedAction,
    now,
  };
}

function registryEntry(id: string, kind: string, version: string, definition: unknown): Obj {
  const entry: Obj = { kind, version, status: 'active', definition };
  entry.definition_digest = registryEntryDigest(id, entry as any);
  return entry;
}

function evaluateAgent(fixture: Obj, operationId: string, consumptionNonce: string): Obj {
  const adapter = createAgentRoaAebAdapter();
  const profileId = 'agentroa:payment-transfer';
  const profile = agentProfile();
  profile.profile_digest = mappingProfileDigest(profileId, profile);
  const directInput = nativeInput(fixture, AGENT_NOW);
  const native = adapter.verifyNative(directInput);
  const mapped = adapter.mapAction({ ...directInput, profile, native });
  assert.equal(mapped.mapping, 'MATCH');
  assert.ok(mapped.caid);

  const mappingEntry = registryEntry(profile.registry_entry_ref, 'mapping-profile', '1', {
    profile_digest: profile.profile_digest,
  });
  const roleEntry = registryEntry('role:operator-of-record', 'evidence-role', '1', {
    role: 'operator-of-record', subject_kinds: ['workload'],
  });
  const registry: Obj = {
    '@version': 'EP-EVIDENCE-REGISTRY-v1',
    registry_id: 'registry:native-adapter-tests',
    epoch: 1,
    entries: {
      [profile.registry_entry_ref]: mappingEntry,
      'role:operator-of-record': roleEntry,
    },
  };
  registry.registry_digest = unifiedRegistryDigest(registry as any);
  const adapterPin: Obj = {
    version: adapter.version,
    trust_roots: fixture.trustRoots,
    config: fixture.config,
    max_status_age_sec: fixture.config.max_status_age_seconds,
  };
  adapterPin.config_digest = adapterPinDigest(adapter.id, adapterPin as any);
  const evaluatorKey = crypto.generateKeyPairSync('ed25519');
  const config: Obj = {
    '@version': 'AEB-ADAPTER-v1',
    relying_party_id: 'rp:native-adapter-tests',
    evaluator_keys: {
      'eval:native-adapter-tests': { public_key: spki(evaluatorKey.publicKey) },
    },
    registry,
    accepted_mappers: [AEB_NATIVE_CAID_MAPPER_ID],
    adapters: { [adapter.id]: adapterPin },
    profiles: { [profileId]: profile },
    requirements: {
      'requirement:operator': {
        '@version': 'AEB-REQUIREMENT-v1',
        all_of: ['operator-of-record'],
        terms: [{ type: 'one-time-consumption' }],
      },
    },
  };
  return evaluateAebEvidence({
    config: config as any,
    adapters: { [adapter.id]: adapter },
    operation_id: operationId,
    consumption_nonce: consumptionNonce,
    initiator_id: 'workload:initiator',
    executor_id: 'workload:executor',
    requirement_ref: 'requirement:operator',
    caid: mapped.caid,
    expected_action: fixture.expectedAction,
    legs: [{
      adapter_id: adapter.id,
      profile_id: profileId,
      artifact_ref: 'artifact:native-1',
      artifact: fixture.artifact,
      status: externalStatus(AGENT_NOW),
    }],
    evaluated_at: AGENT_NOW,
    signer: { key_id: 'eval:native-adapter-tests', private_key: evaluatorKey.privateKey },
  });
}

function evaluateOrprg(fixture: Obj, operationId: string, consumptionNonce: string): Obj {
  const adapter = createOrprgAebAdapter();
  const profileId = 'orprg:payment-release';
  const profile = orprgProfile();
  profile.profile_digest = mappingProfileDigest(profileId, profile);
  const directInput = nativeInput(fixture, ORPRG_NOW);
  const native = adapter.verifyNative(directInput);
  const mapped = adapter.mapAction({ ...directInput, profile, native });
  assert.equal(mapped.mapping, 'MATCH');
  assert.ok(mapped.caid);

  const registry: Obj = {
    '@version': 'EP-EVIDENCE-REGISTRY-v1',
    registry_id: 'registry:orprg-native-adapter-tests',
    epoch: 1,
    entries: {
      [profile.registry_entry_ref]: registryEntry(profile.registry_entry_ref, 'mapping-profile', '1', {
        profile_digest: profile.profile_digest,
      }),
      'role:policy-permit': registryEntry('role:policy-permit', 'evidence-role', '1', {
        role: 'policy-permit', subject_kinds: ['organization'],
      }),
    },
  };
  registry.registry_digest = unifiedRegistryDigest(registry as any);
  const adapterPin: Obj = {
    version: adapter.version,
    trust_roots: fixture.trustRoots,
    config: fixture.config,
    max_status_age_sec: fixture.config.max_status_age_seconds,
  };
  adapterPin.config_digest = adapterPinDigest(adapter.id, adapterPin as any);
  const evaluatorKey = crypto.generateKeyPairSync('ed25519');
  const config: Obj = {
    '@version': 'AEB-ADAPTER-v1',
    relying_party_id: 'rp:orprg-native-adapter-tests',
    evaluator_keys: {
      'eval:orprg-native-adapter-tests': { public_key: spki(evaluatorKey.publicKey) },
    },
    registry,
    accepted_mappers: [AEB_NATIVE_CAID_MAPPER_ID],
    adapters: { [adapter.id]: adapterPin },
    profiles: { [profileId]: profile },
    requirements: {
      'requirement:policy-permit': {
        '@version': 'AEB-REQUIREMENT-v1',
        all_of: ['policy-permit'],
        terms: [{ type: 'one-time-consumption' }],
      },
    },
  };
  return evaluateAebEvidence({
    config: config as any,
    adapters: { [adapter.id]: adapter },
    operation_id: operationId,
    consumption_nonce: consumptionNonce,
    initiator_id: 'workload:initiator',
    executor_id: 'workload:executor',
    requirement_ref: 'requirement:policy-permit',
    caid: mapped.caid,
    expected_action: fixture.expectedAction,
    legs: [{
      adapter_id: adapter.id,
      profile_id: profileId,
      artifact_ref: 'artifact:orprg-native-1',
      artifact: fixture.artifact,
      status: externalStatus(ORPRG_NOW),
    }],
    evaluated_at: ORPRG_NOW,
    signer: { key_id: 'eval:orprg-native-adapter-tests', private_key: evaluatorKey.privateKey },
  });
}

test('AgentROA keeps VERIFIED, ACCEPTED, mapped, and SATISFIED as separate decisions', () => {
  const fixture = makeAgentFixture();
  const adapter = createAgentRoaAebAdapter();
  assert.equal(adapter.id, AGENTROA_AEB_ADAPTER_ID);
  assert.equal(adapter.version, AGENTROA_AEB_ADAPTER_VERSION);

  const input = nativeInput(fixture, AGENT_NOW);
  const native = adapter.verifyNative(input);
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'ACCEPTED');
  assert.deepEqual(native.reasons, []);

  const mapped = adapter.mapAction({ ...input, profile: agentProfile(), native });
  assert.equal(mapped.mapping, 'MATCH');
  assert.equal(mapped.action_digest, digestAeb(fixture.expectedAction));
  assert.match(mapped.caid ?? '', /^caid:1:payment\.transfer\.1:jcs-sha256:[A-Za-z0-9_-]{43}$/);

  const evaluation = evaluateAgent(fixture, 'operation:a', 'aeb-nonce:a');
  assert.equal(evaluation.record.legs[0].native_verification, 'VERIFIED');
  assert.equal(evaluation.record.legs[0].acceptance, 'ACCEPTED');
  assert.equal(evaluation.record.legs[0].verdict, 'SATISFIED');
  assert.equal(evaluation.record.verdict, 'SATISFIED');
  assert.equal(evaluation.valid, true, evaluation.reasons.join('; '));
});

test('AgentROA refuses forged relying-party roots and exact-action mismatch', () => {
  const fixture = makeAgentFixture();
  const adapter = createAgentRoaAebAdapter();
  const attacker = crypto.generateKeyPairSync('ed25519');
  const forgedRoots = fixture.trustRoots.map((root: Obj) => ({
    ...root,
    public_key: spki(attacker.publicKey),
  }));
  const forged = adapter.verifyNative({
    ...nativeInput(fixture, AGENT_NOW),
    trust_roots: forgedRoots,
  });
  assert.equal(forged.native_verification, 'FAILED');
  assert.equal(forged.acceptance, 'REJECTED');
  assert.ok(forged.reasons.some((reason) => reason.includes('signature')));

  const mismatch = adapter.verifyNative({
    ...nativeInput(fixture, AGENT_NOW),
    expected_action: { ...fixture.expectedAction, operation: 'refund' },
  });
  assert.equal(mismatch.native_verification, 'FAILED');
  assert.equal(mismatch.acceptance, 'REJECTED');
  assert.ok(mismatch.reasons.includes('agentroa:aer_action_mismatch'));
});

test('AgentROA replay identity is native-stable across AEB operation and nonce wrappers', () => {
  const fixture = makeAgentFixture();
  const first = evaluateAgent(fixture, 'operation:first', 'aeb-nonce:first');
  const second = evaluateAgent(fixture, 'operation:second', 'aeb-nonce:second');
  assert.notEqual(first.record.operation_id, second.record.operation_id);
  assert.notEqual(first.record.consumption_nonce, second.record.consumption_nonce);
  assert.equal(first.record.legs[0].replay_unit, second.record.legs[0].replay_unit);
});

test('AgentROA verifies signed negative evidence but rejects it, and refuses uncertain status', () => {
  const deniedFixture = makeAgentFixture();
  resignAgentAer(deniedFixture, (aer) => {
    aer.enforcement_outcome = 'deny';
    aer.denial_reason = 'approval_required';
  });
  const adapter = createAgentRoaAebAdapter();
  const denied = adapter.verifyNative(nativeInput(deniedFixture, AGENT_NOW));
  assert.equal(denied.native_verification, 'VERIFIED');
  assert.equal(denied.acceptance, 'REJECTED');
  assert.ok(denied.reasons.includes('agentroa:aer_denied'));

  const fixture = makeAgentFixture();
  const unavailable = adapter.verifyNative(nativeInput(
    fixture,
    AGENT_NOW,
    externalStatus(AGENT_NOW, { unavailable: true }),
  ));
  assert.equal(unavailable.native_verification, 'VERIFIED');
  assert.equal(unavailable.acceptance, 'INDETERMINATE');
  assert.ok(unavailable.reasons.includes('status_unavailable'));

  const revoked = adapter.verifyNative(nativeInput(
    fixture,
    AGENT_NOW,
    externalStatus(AGENT_NOW, { revoked: true }),
  ));
  assert.equal(revoked.native_verification, 'VERIFIED');
  assert.equal(revoked.acceptance, 'REJECTED');
  assert.ok(revoked.reasons.includes('evidence_revoked'));
});

test('mapping refuses profile ambiguity or material-information loss', () => {
  const fixture = makeAgentFixture();
  const adapter = createAgentRoaAebAdapter();
  const input = nativeInput(fixture, AGENT_NOW);
  const native = adapter.verifyNative(input);
  const lossy = agentProfile();
  lossy.semantic_equivalence.omitted_material_fields = ['input_hash'];
  const mapped = adapter.mapAction({ ...input, profile: lossy, native });
  assert.equal(mapped.mapping, 'INDETERMINATE');
  assert.equal(mapped.caid, null);
  assert.ok(mapped.reasons.includes('mapping_profile_information_loss'));
});

test('ORPRG native inspection verifies and maps without claiming final ALLOW or consuming replay', () => {
  const fixture = makeOrprgFixture();
  const adapter = createOrprgAebAdapter();
  assert.equal(adapter.id, ORPRG_AEB_ADAPTER_ID);
  assert.equal(adapter.version, ORPRG_AEB_ADAPTER_VERSION);

  const input = nativeInput(fixture, ORPRG_NOW);
  const first = adapter.verifyNative(input);
  const second = adapter.verifyNative({ ...input, artifact_ref: 'artifact:another-aeb-wrapper' });
  assert.equal(first.native_verification, 'VERIFIED');
  assert.equal(first.acceptance, 'ACCEPTED');
  assert.deepEqual(first.reasons, []);
  assert.equal(first.replay_unit, second.replay_unit);
  assert.notEqual(first.replay_unit, first.evidence_digest);

  const mapped = adapter.mapAction({ ...input, profile: orprgProfile(), native: first });
  assert.equal(mapped.mapping, 'MATCH');
  assert.match(mapped.caid ?? '', /^caid:1:payment\.release\.1:jcs-sha256:[A-Za-z0-9_-]{43}$/);
  assert.equal(mapped.action_digest, digestAeb(fixture.expectedAction));

  const evaluation = evaluateOrprg(fixture, 'operation:orprg-a', 'aeb-nonce:orprg-a');
  assert.equal(evaluation.record.legs[0].native_verification, 'VERIFIED');
  assert.equal(evaluation.record.legs[0].acceptance, 'ACCEPTED');
  assert.equal(evaluation.record.legs[0].verdict, 'SATISFIED');
  assert.equal(evaluation.record.authority_constraints.one_time_consumption, true);
  assert.equal(evaluation.record.verdict, 'SATISFIED');
  assert.equal(evaluation.valid, true, evaluation.reasons.join('; '));
});

test('ORPRG native replay identity is stable across AEB operation and nonce wrappers', () => {
  const fixture = makeOrprgFixture();
  const first = evaluateOrprg(fixture, 'operation:orprg-first', 'aeb-nonce:orprg-first');
  const second = evaluateOrprg(fixture, 'operation:orprg-second', 'aeb-nonce:orprg-second');
  assert.equal(first.record.legs[0].replay_unit, second.record.legs[0].replay_unit);
});

test('ORPRG rejects forged roots and action mismatch before the replay boundary', () => {
  const fixture = makeOrprgFixture();
  const adapter = createOrprgAebAdapter();
  const attacker = crypto.generateKeyPairSync('ed25519');
  const forged = adapter.verifyNative({
    ...nativeInput(fixture, ORPRG_NOW),
    trust_roots: fixture.trustRoots.map((root: Obj) => ({
      ...root,
      public_key: spki(attacker.publicKey),
    })),
  });
  assert.equal(forged.native_verification, 'FAILED');
  assert.equal(forged.acceptance, 'REJECTED');
  assert.ok(forged.reasons.includes('orprg:SIGNATURE_INVALID'));

  const mismatch = adapter.verifyNative({
    ...nativeInput(fixture, ORPRG_NOW),
    expected_action: {
      ...fixture.expectedAction,
      request: { ...fixture.expectedAction.request, invoice_id: 'inv_forged' },
    },
  });
  assert.equal(mismatch.native_verification, 'FAILED');
  assert.equal(mismatch.acceptance, 'REJECTED');
  assert.ok(mismatch.reasons.includes('orprg:ACTION_DIGEST_MISMATCH'));
});

test('ORPRG refuses revoked, stale, and indeterminate signed native state', () => {
  const adapter = createOrprgAebAdapter();
  for (const [state, acceptance, reason] of [
    ['revoked', 'REJECTED', 'orprg:REVOKED_CONFIRMED'],
    ['unknown', 'INDETERMINATE', 'orprg:REVOCATION_UNKNOWN_OR_STALE'],
  ] as const) {
    const fixture = makeOrprgFixture((receipt) => { receipt.status.state = state; });
    const result = adapter.verifyNative(nativeInput(fixture, ORPRG_NOW));
    assert.equal(result.native_verification, 'FAILED');
    assert.equal(result.acceptance, acceptance);
    assert.ok(result.reasons.includes(reason));
  }

  const stale = makeOrprgFixture((receipt) => {
    receipt.status.checked_at = '2026-07-19T11:50:00Z';
    receipt.status.next_update = '2026-07-19T11:55:00Z';
  });
  const staleResult = adapter.verifyNative(nativeInput(stale, ORPRG_NOW));
  assert.equal(staleResult.native_verification, 'FAILED');
  assert.equal(staleResult.acceptance, 'INDETERMINATE');
  assert.ok(staleResult.reasons.includes('orprg:REVOCATION_UNKNOWN_OR_STALE'));
});
