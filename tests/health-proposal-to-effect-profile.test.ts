// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import fs from 'node:fs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  adapterPinDigest,
  digestAeb,
  evaluateAebEvidence,
  mappingProfileDigest,
  pinnedConfigDigest,
  registryEntryDigest,
  unifiedRegistryDigest,
} from '@emilia-protocol/verify/aeb-adapter-contract';
import {
  createProposalToEffect,
  proposalToEffectConsumptionNonce,
} from '../packages/gate/proposal-to-effect.js';
import {
  HEALTHCARE_ASSURANCE_LIMITATIONS,
  HEALTHCARE_ASSURANCE_PACKET_V2_VERSION,
  HEALTHCARE_ASSURANCE_TRUST_BUNDLE_VERSION,
  HOSPICE_CAID_DEFINITION,
  HOSPICE_AEB_REQUIREMENT_REF,
  HOSPICE_PROPOSAL_PROFILE_ID,
  canonicalizeHospicePaymentAction,
  checkHealthcareAssurancePacketInternalConsistency,
  createHealthcareConsequenceControl,
  createHospiceProposalToEffectProfile,
  createMemoryHealthcareControlStores,
  verifyHealthcareAssurancePacketOffline,
  verifyHealthcareAssurancePacketOfflineV2,
} from '../lib/health/proposal-to-effect-profile.js';
import { createHospiceClaimExecuteHandler } from '../app/api/v1/adapters/health/hospice-claim/execute/route.js';
import { createHospiceClaimExportHandler } from '../app/api/v1/adapters/health/hospice-claim/export/route.js';

const NOW = '2026-07-24T12:00:00.000Z';
const TENANT = 'org:ca-dhcs';
const OPERATION_ID = 'operation:health-hospice-001';
const SERVER_CONTEXT = Object.freeze({
  tenant_id: TENANT,
  provider_id: 'provider:medi-cal-synthetic-sandbox',
  provider_account_id: 'account:synthetic-hospice-claims',
  environment: 'sandbox',
  executor_id: 'executor:health-consequence-control',
});
const INTEGRITY_KEY = crypto
  .createHash('sha256')
  .update('health-proposal-to-effect-test-integrity-key')
  .digest();
const VECTOR_SUITE = JSON.parse(fs.readFileSync(
  new URL('../conformance/vectors/health-proposal-to-effect.v1.json', import.meta.url),
  'utf8',
));
const RELYING_PARTY_ID = 'rp:healthcare-synthetic-pilot';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

function assuranceKey(role: 'evaluator' | 'receipt' | 'aeb' | 'provider') {
  const keyPair = crypto.generateKeyPairSync('ed25519');
  const key_id = `health:${role}:test`;
  const public_key_spki_b64u = keyPair.publicKey.export({
    type: 'spki',
    format: 'der',
  }).toString('base64url');
  return {
    key_id,
    keyPair,
    public_key_spki_b64u,
    signer: {
      algorithm: 'Ed25519' as const,
      key_id,
      sign(bytes: Uint8Array) {
        return crypto.sign(null, Buffer.from(bytes), keyPair.privateKey)
          .toString('base64url');
      },
    },
    pin: { key_id, public_key_spki_b64u },
  };
}

function hybridAssuranceKey(
  role: 'evaluator' | 'receipt' | 'aeb' | 'provider',
  classical: ReturnType<typeof assuranceKey>,
) {
  const pq = ml_dsa65.keygen(crypto.randomBytes(32));
  const pqKeyId = `health:${role}:test:pq`;
  return {
    signer: {
      ed25519: classical.signer,
      mldsa65: { key_id: pqKeyId, private_key: pq.secretKey },
    },
    pin: {
      ...classical.pin,
      pq_key_id: pqKeyId,
      pq_public_key_b64u: Buffer.from(pq.publicKey).toString('base64url'),
    },
  };
}

function vector(id: string): any {
  const found = VECTOR_SUITE.vectors.find((candidate: any) => candidate.id === id);
  if (!found) throw new Error(`missing healthcare vector: ${id}`);
  return found;
}

function scannerPackage(): any {
  return structuredClone(VECTOR_SUITE.cross_repo.scanner_package);
}

function refreshPackageDigest(controlPackage: any): any {
  const unsigned = structuredClone(controlPackage);
  delete unsigned.packageDigest;
  controlPackage.packageDigest = digestAeb(unsigned);
  return controlPackage;
}

function refreshPacketDigest(packet: any): any {
  const body = structuredClone(packet);
  delete body.packet_digest;
  delete body.proof;
  packet.packet_digest = digestAeb(body);
  return packet;
}

function registryEntry(
  entryId: string,
  kind: string,
  version: string,
  definition: unknown,
) {
  const entry: any = { kind, version, status: 'active', definition };
  entry.definition_digest = registryEntryDigest(entryId, entry);
  return entry;
}

function aebContext(action: Record<string, unknown>, caid: string) {
  const adapter = {
    id: 'test:health-approval',
    version: '1',
    verifyNative({ artifact, status, trust_roots }: any) {
      const trusted = trust_roots.includes(artifact.root);
      return {
        native_verification: trusted ? 'VERIFIED' : 'FAILED',
        acceptance: trusted ? 'ACCEPTED' : 'REJECTED',
        evidence_digest: digestAeb(artifact),
        status_digest: digestAeb({
          checked_at: status.checked_at,
          expires_at: status.expires_at,
          revocation_checked: status.revocation_checked,
          revoked: status.revoked,
          consumed: status.consumed,
          unavailable: status.unavailable === true,
        }),
        replay_unit: digestAeb({
          root: artifact.root,
          caid: artifact.caid,
          subject: 'human:health-reviewer',
        }),
        evidence_role: 'human-authorization',
        subject: { id: 'human:health-reviewer', kind: 'human' },
        reasons: trusted ? [] : ['native_trust_root_not_pinned'],
      };
    },
    mapAction({ artifact, native, expected_action }: any) {
      return {
        mapping: native.native_verification === 'VERIFIED'
          ? 'MATCH'
          : 'INDETERMINATE',
        caid: artifact.caid,
        action_digest: digestAeb(expected_action),
        reasons: [],
      };
    },
  };
  const profile: any = {
    version: '1',
    definition: { action_type: 'health.medi-cal.hospice-claim-payment.1' },
    registry_entry_ref: 'mapping:health-hospice-payment',
    mapper_id: 'mapper:health-hospice-payment',
    resolver: {
      id: 'resolver:health-hospice-payment',
      version: '1',
      implementation_digest: digestAeb({
        implementation: 'resolver:health-hospice-payment:1',
      }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [],
    },
  };
  profile.profile_digest = mappingProfileDigest(
    'health-hospice-payment',
    profile,
  );
  const entries: any = {
    'mapping:health-hospice-payment': registryEntry(
      'mapping:health-hospice-payment',
      'mapping-profile',
      '1',
      { profile_digest: profile.profile_digest },
    ),
    'role:human-authorization': registryEntry(
      'role:human-authorization',
      'evidence-role',
      '1',
      { role: 'human-authorization', subject_kinds: ['human'] },
    ),
  };
  const registry: any = {
    '@version': 'EP-EVIDENCE-REGISTRY-v1',
    registry_id: 'registry:health-proposal-to-effect-test',
    epoch: 1,
    entries,
  };
  registry.registry_digest = unifiedRegistryDigest(registry);
  const pin: any = {
    version: '1',
    trust_roots: ['root:health-test'],
    config: { mode: 'offline-test' },
    max_status_age_sec: 300,
  };
  pin.config_digest = adapterPinDigest('test:health-approval', pin);
  const evaluator = crypto.generateKeyPairSync('ed25519');
  const evaluatorPublicKey = evaluator.publicKey.export({
    type: 'spki',
    format: 'der',
  }).toString('base64url');
  const config: any = {
    '@version': 'AEB-ADAPTER-v1',
    relying_party_id: 'rp:healthcare-synthetic-pilot',
    evaluator_keys: {
      'eval:health-test': { public_key: evaluatorPublicKey },
    },
    registry,
    accepted_mappers: ['mapper:health-hospice-payment'],
    adapters: { 'test:health-approval': pin },
    profiles: { 'health-hospice-payment': profile },
    requirements: {
      [HOSPICE_AEB_REQUIREMENT_REF]: {
        '@version': 'AEB-REQUIREMENT-v1',
        all_of: ['human-authorization'],
        terms: [
          { type: 'initiator-exclusion', roles: ['human-authorization'] },
          { type: 'executor-exclusion', roles: ['human-authorization'] },
          { type: 'one-time-consumption' },
        ],
      },
    },
  };
  const artifact = {
    root: 'root:health-test',
    caid,
    action: structuredClone(action),
  };
  const status = {
    checked_at: '2026-07-24T11:59:00.000Z',
    expires_at: '2026-07-24T12:05:00.000Z',
    revocation_checked: true,
    revoked: false,
    consumed: false,
  };
  return {
    adapters: { 'test:health-approval': adapter },
    artifacts: { 'artifact:health-approval': artifact },
    config,
    current_statuses: { 'artifact:health-approval': status },
    evaluate(operationId = OPERATION_ID) {
      return evaluateAebEvidence({
        config,
        adapters: { 'test:health-approval': adapter },
        operation_id: operationId,
        consumption_nonce: proposalToEffectConsumptionNonce(
          operationId,
          pinnedConfigDigest(config),
        ),
        initiator_id: 'actor:health-reviewer',
        executor_id: SERVER_CONTEXT.executor_id,
        requirement_ref: HOSPICE_AEB_REQUIREMENT_REF,
        caid,
        expected_action: action,
        legs: [{
          adapter_id: 'test:health-approval',
          profile_id: 'health-hospice-payment',
          artifact_ref: 'artifact:health-approval',
          artifact,
          status,
        }],
        evaluated_at: NOW,
        signer: {
          key_id: 'eval:health-test',
          private_key: evaluator.privateKey,
        },
      }).record;
    },
  };
}

function durableAebStore() {
  const states = new Map<string, 'RESERVED' | 'CONSUMED'>();
  const replayOwners = new Map<string, string>();
  return {
    durable: true as const,
    ownershipFenced: true as const,
    permanentConsumption: true as const,
    atomicReplayFenced: true as const,
    states,
    async reserve(key: string, replayKeys: readonly string[]) {
      if (states.has(key)) return false;
      if (replayKeys.some((replayKey) => replayOwners.has(replayKey))) {
        return 'NATIVE_REPLAY_CONFLICT';
      }
      states.set(key, 'RESERVED');
      for (const replayKey of replayKeys) replayOwners.set(replayKey, key);
      return 'RESERVED';
    },
    async commit(key: string) {
      if (states.get(key) !== 'RESERVED') return false;
      states.set(key, 'CONSUMED');
      return true;
    },
    async release(key: string) {
      if (states.get(key) !== 'RESERVED') return false;
      states.delete(key);
      for (const [replayKey, owner] of replayOwners) {
        if (owner === key) replayOwners.delete(replayKey);
      }
      return true;
    },
  };
}

type AttemptState =
  'RESERVED' | 'INVOKING' | 'INDETERMINATE' | 'COMMITTED' | 'RELEASED' | 'ESCALATED';

function consequenceAttemptStore() {
  let ownerSequence = 0;
  const entries = new Map<string, any>();
  const keyFor = (tenantId: string, attemptId: string) =>
    `${tenantId}\0${attemptId}`;
  return {
    durable: true as const,
    ownershipFenced: true as const,
    compareAndSwap: true as const,
    atomicEvidenceBinding: true as const,
    entries,
    async reserve(binding: any) {
      const key = keyFor(binding.tenant_id, binding.attempt_id);
      if (entries.has(key)) return { reserved: false, reason: 'attempt_exists' };
      const owner = `owner:${++ownerSequence}:${crypto.randomBytes(8).toString('base64url')}`;
      entries.set(key, {
        ...structuredClone(binding),
        owner,
        state: 'RESERVED' as AttemptState,
        evidence: null,
      });
      return { reserved: true, owner };
    },
    async transition(input: any) {
      const entry = entries.get(keyFor(input.tenant_id, input.attempt_id));
      if (!entry
          || entry.owner !== input.owner
          || entry.state !== input.expected_state) return false;
      const allowed =
        (input.expected_state === 'RESERVED' && input.next_state === 'INVOKING')
        || (input.expected_state === 'INVOKING'
          && input.next_state === 'INDETERMINATE')
        || (input.expected_state === 'INDETERMINATE'
          && ['COMMITTED', 'RELEASED', 'ESCALATED'].includes(input.next_state));
      if (!allowed) return false;
      entry.state = input.next_state;
      return true;
    },
    async reconcile(input: any) {
      const entry = entries.get(keyFor(input.tenant_id, input.attempt_id));
      if (!entry
          || entry.owner !== input.owner
          || input.expected_state !== 'INDETERMINATE'
          || entry.state !== 'INDETERMINATE') return false;
      if (entry.tenant_id !== input.evidence.tenant_id
          || entry.request_digest !== input.evidence.request_digest
          || entry.provider_id !== input.evidence.provider_id
          || entry.provider_account_id !== input.evidence.provider_account_id
          || entry.environment !== input.evidence.environment
          || entry.attempt_id !== input.evidence.attempt_id) return false;
      entry.evidence = structuredClone(input.evidence);
      entry.state = input.next_state;
      return true;
    },
    async read(binding: any) {
      const entry = entries.get(keyFor(binding.tenant_id, binding.attempt_id));
      if (!entry
          || entry.provider_id !== binding.provider_id
          || entry.provider_account_id !== binding.provider_account_id
          || entry.environment !== binding.environment
          || entry.request_digest !== binding.request_digest) return null;
      return {
        state: entry.state,
        evidence_digest: entry.evidence?.evidence_digest ?? null,
      };
    },
  };
}

function approvalEvidence(caid: string, actionDigest: string, fresh = true) {
  return {
    '@version': 'EP-RECEIPT-v1',
    receipt_id: 'receipt:health-approval-001',
    caid,
    action_digest: actionDigest,
    fresh,
  };
}

function testGate() {
  async function check(input: any) {
    const actionDigest = digestAeb(input.observedAction);
    const receipt = input.receipt;
    const allow = receipt?.['@version'] === 'EP-RECEIPT-v1'
      && receipt?.fresh === true
      && receipt?.caid === VECTOR_SUITE.cross_repo.expected.caid
      && receipt?.action_digest === actionDigest;
    return {
      allow,
      reason: allow ? 'receipt_verified' : 'approval_evidence_stale_or_mismatched',
      requirement: { receipt_required: true },
      action_hash: actionDigest,
    };
  }
  return {
    check,
    async run(input: any, effect: (authorization: any) => Promise<unknown>) {
      const authorization = await check(input);
      if (!authorization.allow) return { ok: false, authorization };
      try {
        const result = await effect(authorization);
        return { ok: true, authorization, result };
      } catch (error: any) {
        error.emiliaGateOutcome = { outcome: 'indeterminate' };
        throw error;
      }
    },
  };
}

function providerEvidence(proposal: any, attempt: any, overrides: any = {}) {
  return {
    authenticated: true,
    evidence_id: `evidence:${attempt.attempt_id}`,
    observed_at: NOW,
    outcome: 'COMMITTED',
    operation_id: proposal.operation_id,
    caid: proposal.caid,
    action_digest: proposal.aeb_action_digest,
    tenant_id: proposal.consequence.tenant_id,
    request_digest: proposal.consequence.request_digest,
    provider_id: proposal.consequence.provider_id,
    provider_account_id: proposal.consequence.provider_account_id,
    environment: proposal.consequence.environment,
    attempt_id: attempt.attempt_id,
    ...overrides,
  };
}

async function fixture(fixtureOptions: { hybrid?: boolean } = {}) {
  const controlPackage = scannerPackage();
  const action = controlPackage.action;
  const aeb = aebContext(action, controlPackage.caid);
  const aebStore = durableAebStore();
  const attemptStore = consequenceAttemptStore();
  const queuedAttempts = ['attempt:health-001', 'attempt:health-002'];
  const controller = createProposalToEffect({
    gate: testGate(),
    proposal_integrity: { hmac_sha256_key: INTEGRITY_KEY },
    consequence: {
      ...SERVER_CONTEXT,
      store: attemptStore,
      create_attempt_id: async () =>
        queuedAttempts.shift() ?? `attempt:${crypto.randomUUID()}`,
    },
    profiles: {
      [HOSPICE_PROPOSAL_PROFILE_ID]: createHospiceProposalToEffectProfile({
        authorization_endpoint: 'https://approval.example.test/health/hospice',
      }),
    },
    aeb: {
      config: aeb.config,
      adapters: aeb.adapters,
      store: aebStore,
      resolve_artifacts: async () => aeb.artifacts,
      currentStatusResolver: async ({ leg }: any) =>
        aeb.current_statuses[leg.artifact_ref],
      statusVerifier: async ({ status_artifact }: any) => {
        if (!status_artifact || status_artifact.unavailable === true) {
          return {
            valid: false,
            outcome: 'indeterminate',
            reason: 'status_unavailable',
          };
        }
        if (status_artifact.revoked === true) {
          return {
            valid: true,
            outcome: 'revoked',
            status: structuredClone(status_artifact),
          };
        }
        return {
          valid: true,
          outcome: 'current_not_revoked',
          status: structuredClone(status_artifact),
        };
      },
      verify_provider_evidence: async ({ evidence, expected }: any) => {
        const valid = evidence?.authenticated === true
          && evidence.operation_id === expected.operation_id
          && evidence.caid === expected.caid
          && evidence.action_digest === expected.action_digest
          && evidence.tenant_id === expected.tenant_id
          && evidence.request_digest === expected.request_digest
          && evidence.provider_id === expected.provider_id
          && evidence.provider_account_id === expected.provider_account_id
          && evidence.environment === expected.environment
          && evidence.attempt_id === expected.attempt_id
          && typeof evidence.evidence_id === 'string'
          && typeof evidence.observed_at === 'string';
        return {
          valid,
          reason: valid ? undefined : 'provider_evidence_unauthenticated',
          outcome: evidence?.outcome,
          evidence_id: evidence?.evidence_id,
          observed_at: evidence?.observed_at,
          tenant_id: evidence?.tenant_id,
          request_digest: evidence?.request_digest,
          provider_id: evidence?.provider_id,
          provider_account_id: evidence?.provider_account_id,
          environment: evidence?.environment,
          attempt_id: evidence?.attempt_id,
          operation_id: evidence?.operation_id,
          caid: evidence?.caid,
          action_digest: evidence?.action_digest,
          evidence_digest: evidence ? digestAeb(evidence) : null,
        };
      },
    },
    now: () => Date.parse(NOW),
  });
  const stores = createMemoryHealthcareControlStores();
  const assuranceKeys = {
    evaluator: assuranceKey('evaluator'),
    receipt: assuranceKey('receipt'),
    aeb: assuranceKey('aeb'),
    provider: assuranceKey('provider'),
  };
  const assuranceTrust = {
    '@version': HEALTHCARE_ASSURANCE_TRUST_BUNDLE_VERSION,
    relying_party_id: RELYING_PARTY_ID,
    evaluator: assuranceKeys.evaluator.pin,
    receipt: assuranceKeys.receipt.pin,
    aeb: assuranceKeys.aeb.pin,
    provider: assuranceKeys.provider.pin,
  };
  const hybridAssuranceKeys = fixtureOptions.hybrid ? {
    evaluator: hybridAssuranceKey('evaluator', assuranceKeys.evaluator),
    receipt: hybridAssuranceKey('receipt', assuranceKeys.receipt),
    aeb: hybridAssuranceKey('aeb', assuranceKeys.aeb),
    provider: hybridAssuranceKey('provider', assuranceKeys.provider),
  } : null;
  const assuranceTrustV2 = hybridAssuranceKeys ? {
    '@version': HEALTHCARE_ASSURANCE_PACKET_V2_VERSION,
    relying_party_id: RELYING_PARTY_ID,
    evaluator: hybridAssuranceKeys.evaluator.pin,
    receipt: hybridAssuranceKeys.receipt.pin,
    aeb: hybridAssuranceKeys.aeb.pin,
    provider: hybridAssuranceKeys.provider.pin,
  } : null;
  let mutation = async () => ({ sandbox_reference: 'sandbox:mutation:health-001' });
  let mutationCount = 0;
  const controlOptions = {
    controller: controller as any,
    ...stores,
    assurance: {
      relying_party_id: RELYING_PARTY_ID,
      signers: {
        evaluator: assuranceKeys.evaluator.signer,
        receipt: assuranceKeys.receipt.signer,
        aeb: assuranceKeys.aeb.signer,
        provider: assuranceKeys.provider.signer,
      },
      ...(hybridAssuranceKeys ? {
        hybrid: {
          evaluator: hybridAssuranceKeys.evaluator.signer,
          receipt: hybridAssuranceKeys.receipt.signer,
          aeb: hybridAssuranceKeys.aeb.signer,
          provider: hybridAssuranceKeys.provider.signer,
        },
      } : {}),
    },
    allow_ephemeral_stores_for_tests: true,
    now: () => Date.parse(NOW),
    async mutate_sandbox(input) {
      mutationCount += 1;
      return mutation(input);
    },
  };
  const control = createHealthcareConsequenceControl(controlOptions);
  const prepared = await control.prepare({
    tenant_id: TENANT,
    initiator_id: 'actor:health-reviewer',
    proposal_id: 'proposal:health-hospice-001',
    operation_id: OPERATION_ID,
    prospective_control_package: controlPackage,
  });
  return {
    aeb,
    aebStore,
    attemptStore,
    control,
    controlPackage,
    assuranceKeys,
    assuranceTrust,
    assuranceTrustV2,
    controller,
    controlOptions,
    stores,
    prepared,
    evaluation: aeb.evaluate(),
    get mutationCount() {
      return mutationCount;
    },
    setMutation(next: typeof mutation) {
      mutation = next;
    },
  };
}

function executeInput(f: Awaited<ReturnType<typeof fixture>>, receipt?: any) {
  return {
    tenant_id: TENANT,
    proposal: f.prepared.proposal,
    approval_evidence: receipt ?? approvalEvidence(
      f.prepared.proposal.caid,
      f.prepared.proposal.action_digest,
    ),
    evaluation: f.evaluation,
    observed_action: f.controlPackage.action,
  };
}

function postRequest(path: string, body: unknown): Request {
  return new Request(`https://www.emiliaprotocol.ai${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

describe('healthcare Proposal-to-Effect consequence control', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('accepts the exact commercial package and reproduces the public CAID vector', async () => {
    const f = await fixture();
    const expected = VECTOR_SUITE.cross_repo.expected;

    expect(f.prepared.ok).toBe(true);
    expect(f.prepared.decision).toBe('APPROVAL_REQUIRED');
    expect(f.prepared.proposal.caid).toBe(expected.caid);
    expect(f.prepared.proposal.action_digest).toBe(expected.action_digest);
    expect(canonicalizeHospicePaymentAction(f.controlPackage.action)).toMatchObject({
      caid: expected.caid,
      action_digest: expected.action_digest,
    });
    expect(f.prepared.control_package).toEqual(f.controlPackage);
    expect(f.prepared.finding).toMatchObject(
      vector('source_finding_is_triage_not_authorization').expect,
    );
    expect(f.prepared.finding.source_finding.authorizesScannedExecution).toBe(false);
    expect(HOSPICE_CAID_DEFINITION).toEqual(VECTOR_SUITE.caid_definition);
  });

  it('fails closed on incomplete material fields, tenant mismatch, and CAID mismatch', async () => {
    const base = await fixture();
    const missing = scannerPackage();
    delete missing.action.payment_destination_digest;
    refreshPackageDigest(missing);
    const missingResult = await base.control.prepare({
      tenant_id: TENANT,
      initiator_id: 'actor:health-reviewer',
      proposal_id: 'proposal:health-missing',
      operation_id: 'operation:health-missing',
      prospective_control_package: missing,
    });
    expect(missingResult).toMatchObject({
      ok: false,
      decision: 'REFUSED',
      reason: 'healthcare_action_shape_invalid',
      program_digest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
    });

    const wrongCaid = refreshPackageDigest({
      ...scannerPackage(),
      caid: `caid:1:health.medi-cal.hospice-claim-payment.1:jcs-sha256:${'A'.repeat(43)}`,
    });
    const caidResult = await base.control.prepare({
      tenant_id: TENANT,
      initiator_id: 'actor:health-reviewer',
      proposal_id: 'proposal:health-wrong-caid',
      operation_id: 'operation:health-wrong-caid',
      prospective_control_package: wrongCaid,
    });
    expect(caidResult.reason).toBe('prospective_control_action_mismatch');

    const tenantResult = await base.control.prepare({
      tenant_id: 'org:other',
      initiator_id: 'actor:health-reviewer',
      proposal_id: 'proposal:health-wrong-tenant',
      operation_id: 'operation:health-wrong-tenant',
      prospective_control_package: scannerPackage(),
    });
    expect(tenantResult.reason).toBe('prospective_control_package_invalid');
  });

  it('rejects stale approval evidence before reservation or sandbox mutation', async () => {
    const f = await fixture();
    const result = await f.control.execute(executeInput(
      f,
      approvalEvidence(
        f.prepared.proposal.caid,
        f.prepared.proposal.action_digest,
        false,
      ),
    ));

    expect(result).toMatchObject({
      ok: false,
      decision: 'REFUSED',
      reason: 'approval_evidence_stale_or_mismatched',
      program_digest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
    });
    expect(f.mutationCount).toBe(0);
    expect(f.aebStore.states.size).toBe(0);
  });

  it('executes one protected sandbox effect and exports a signed, scoped terminal packet', async () => {
    const f = await fixture();
    const result = await f.control.execute(executeInput(f));
    expect(result).toMatchObject({
      ok: true,
      decision: 'EXECUTED',
      reconciliation_required: false,
      retry_safe: false,
    });
    expect(f.mutationCount).toBe(1);

    const packet = await f.control.exportAssurancePacket({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
    });
    expect(checkHealthcareAssurancePacketInternalConsistency(packet)).toEqual({
      consistent: true,
      reasons: [],
    });
    expect(verifyHealthcareAssurancePacketOffline(
      packet,
      f.assuranceTrust,
    )).toEqual({
      valid: true,
      reasons: [],
    });
    expect(packet.limitations).toEqual([...HEALTHCARE_ASSURANCE_LIMITATIONS]);
    expect(packet.profile.synthetic).toBe(true);
    expect(packet.finding_projection.clinical_judgment).toBe(false);
    expect(packet.limitations.join(' ')).toContain('No live Medicare');
    expect(JSON.stringify(packet)).not.toContain('"member_ref"');
    expect(packet.protocol_evidence).not.toHaveProperty('proposal');
    expect(packet.protocol_evidence).not.toHaveProperty('approval_evidence');
    expect(packet.protocol_evidence).not.toHaveProperty('aeb_evaluation');
  });

  it('exports and independently verifies the opt-in hybrid assurance packet without weakening v1', async () => {
    const f = await fixture({ hybrid: true });
    await f.control.execute(executeInput(f));

    const packet = await f.control.exportAssurancePacketV2({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
    });
    expect(packet['@version']).toBe(HEALTHCARE_ASSURANCE_PACKET_V2_VERSION);
    expect(f.assuranceTrustV2).not.toBeNull();
    await expect(verifyHealthcareAssurancePacketOfflineV2(
      packet,
      f.assuranceTrustV2,
    )).resolves.toEqual({ valid: true, reasons: [] });

    const v1 = await f.control.exportAssurancePacket({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
    });
    expect(verifyHealthcareAssurancePacketOffline(v1, f.assuranceTrust))
      .toEqual({ valid: true, reasons: [] });
  });

  it('refuses hybrid export when no hybrid signer is configured', async () => {
    const f = await fixture();
    await f.control.execute(executeInput(f));
    await expect(f.control.exportAssurancePacketV2({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
    })).resolves.toMatchObject({
      ok: false,
      reason: 'healthcare_assurance_hybrid_signer_not_configured',
    });
  });

  it('freezes timeout-after-side-effect as INDETERMINATE and never blindly replays', async () => {
    const f = await fixture();
    f.setMutation(async () => {
      throw new Error('provider_response_lost_after_side_effect');
    });

    const first = await f.control.execute(executeInput(f));
    expect(first).toMatchObject(
      vector('timeout_after_side_effect').expect,
    );
    expect(first.attempt.attempt_id).toBe('attempt:health-001');
    expect(f.mutationCount).toBe(1);

    const replay = await f.control.execute(executeInput(f));
    expect(replay.ok).toBe(false);
    expect(replay.decision).toBe('REFUSED');
    expect(replay.reason).toMatch(/consumption|replay/);
    expect(f.mutationCount).toBe(
      vector('no_blind_replay_after_indeterminate').expect.effect_invocations,
    );
  });

  it('requires exact authenticated provider evidence for indeterminate reconciliation', async () => {
    const f = await fixture();
    f.setMutation(async () => {
      throw new Error('provider_timeout_after_entry');
    });
    const indeterminate = await f.control.execute(executeInput(f));
    const attempt = indeterminate.attempt;
    const exactEvidence = providerEvidence(f.prepared.proposal, attempt);

    const wrongOperation = await f.control.reconcile({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
      proposal: f.prepared.proposal,
      evaluation: f.evaluation,
      provider_evidence: {
        ...exactEvidence,
        operation_id: 'operation:health-other',
      },
    });
    expect(wrongOperation).toMatchObject({
      ok: false,
      decision: 'INDETERMINATE',
      reason: 'provider_evidence_operation_mismatch',
      retry_safe: false,
    });

    const wrongAttempt = await f.control.reconcile({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
      proposal: f.prepared.proposal,
      evaluation: f.evaluation,
      provider_evidence: {
        ...exactEvidence,
        attempt_id: 'attempt:health-wrong',
      },
    });
    expect(wrongAttempt.reason).toBe('provider_evidence_attempt_mismatch');

    const unauthenticated = await f.control.reconcile({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
      proposal: f.prepared.proposal,
      evaluation: f.evaluation,
      provider_evidence: {
        ...exactEvidence,
        authenticated: false,
      },
    });
    expect(unauthenticated).toMatchObject({
      ok: false,
      decision: 'INDETERMINATE',
      reason: 'provider_evidence_unauthenticated',
      retry_safe: false,
    });

    const reconciled = await f.control.reconcile({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
      proposal: f.prepared.proposal,
      evaluation: f.evaluation,
      provider_evidence: exactEvidence,
    });
    expect(reconciled).toMatchObject({
      ok: true,
      decision: 'RECONCILED_EXECUTED',
      authenticated_provider_evidence: true,
      reconciliation_required: false,
    });
    const packet = await f.control.exportAssurancePacket({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
    });
    expect(packet.outcome).toMatchObject({
      decision: 'RECONCILED_EXECUTED',
      authenticated_reconciliation: true,
    });
    expect(verifyHealthcareAssurancePacketOffline(
      packet,
      f.assuranceTrust,
    ).valid).toBe(true);
  });

  it('rejects outcome substitution even when the attacker recomputes the packet digest', async () => {
    const f = await fixture();
    await f.control.execute(executeInput(f));
    const packet = await f.control.exportAssurancePacket({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
    });
    const substituted = structuredClone(packet);
    substituted.outcome.decision = 'RECONCILED_NOT_EXECUTED';
    delete substituted.packet_digest;
    const substitutedBody = structuredClone(substituted);
    delete substitutedBody.proof;
    substituted.packet_digest = digestAeb(substitutedBody);

    expect(checkHealthcareAssurancePacketInternalConsistency(
      substituted,
    )).toMatchObject({
      consistent: false,
      reasons: expect.arrayContaining([
        'packet_terminal_state_mismatch',
        'packet_reconciliation_evidence_required',
      ]),
    });
    expect(verifyHealthcareAssurancePacketOffline(
      substituted,
      f.assuranceTrust,
    ).valid).toBe(false);
  });

  it('requires an authenticated provider-key assertion for every reconciled outcome', async () => {
    const f = await fixture();
    f.setMutation(async () => {
      throw new Error('provider_timeout_after_entry');
    });
    const indeterminate = await f.control.execute(executeInput(f));
    await f.control.reconcile({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
      proposal: f.prepared.proposal,
      evaluation: f.evaluation,
      provider_evidence: providerEvidence(f.prepared.proposal, indeterminate.attempt),
    });
    const packet = await f.control.exportAssurancePacket({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
    });
    const missingProvider = structuredClone(packet);
    delete missingProvider.protocol_evidence.provider;
    delete missingProvider.packet_digest;
    const missingProviderBody = structuredClone(missingProvider);
    delete missingProviderBody.proof;
    missingProvider.packet_digest = digestAeb(missingProviderBody);

    expect(checkHealthcareAssurancePacketInternalConsistency(
      missingProvider,
    )).toMatchObject({
      consistent: false,
      reasons: expect.arrayContaining(['packet_reconciliation_evidence_required']),
    });
  });

  it('keeps evaluator, receipt, AEB, and provider trust roles non-substitutable', async () => {
    const f = await fixture();
    await f.control.execute(executeInput(f));
    const packet = await f.control.exportAssurancePacket({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
    });
    const roleSwappedTrust = structuredClone(f.assuranceTrust);
    roleSwappedTrust.receipt.public_key_spki_b64u =
      f.assuranceKeys.aeb.public_key_spki_b64u;

    expect(verifyHealthcareAssurancePacketOffline(
      packet,
      roleSwappedTrust,
    )).toMatchObject({
      valid: false,
      reasons: expect.arrayContaining(['receipt_signature_invalid']),
    });
  });

  it('normalizes prohibited PHI aliases case-insensitively and rejects free text', async () => {
    for (const alias of ['SSN', 'patientName', 'PATIENT-NAME', 'freeText', 'FREE_TEXT']) {
      const f = await fixture();
      const input = executeInput(f);
      input.approval_evidence[alias] = 'synthetic-but-prohibited';
      const result = await f.control.execute(input);
      expect(result, alias).toMatchObject({
        ok: false,
        decision: 'REFUSED',
        reason: 'healthcare_prohibited_phi',
      });
      expect(f.mutationCount, alias).toBe(0);
    }
  });

  it('fails closed across malformed preparation, execution, and reconciliation inputs', async () => {
    expect(() => createHealthcareConsequenceControl({} as any)).toThrow(
      'healthcare_proposal_to_effect_controller_required',
    );
    const f = await fixture();

    expect(await f.control.prepare({} as any)).toMatchObject({
      ok: false,
      reason: 'tenant_required',
    });
    expect(await f.control.prepare({
      tenant_id: TENANT,
    } as any)).toMatchObject({
      ok: false,
      reason: 'authenticated_initiator_required',
    });
    expect(await f.control.prepare({
      tenant_id: TENANT,
      initiator_id: 'actor:health-reviewer',
    } as any)).toMatchObject({
      ok: false,
      reason: 'healthcare_operation_identity_invalid',
    });

    expect(await f.control.execute({} as any)).toMatchObject({
      ok: false,
      reason: 'tenant_required',
    });
    expect(await f.control.execute({
      tenant_id: TENANT,
    } as any)).toMatchObject({
      ok: false,
      reason: 'approval_evidence_required',
    });
    expect(await f.control.execute({
      tenant_id: TENANT,
      approval_evidence: {},
    } as any)).toMatchObject({
      ok: false,
      reason: 'aeb_evaluation_required',
    });
    expect(await f.control.execute({
      ...executeInput(f),
      proposal: {},
    })).toMatchObject({
      ok: false,
      reason: expect.stringMatching(/proposal|integrity|invalid/),
    });
    expect(await f.control.execute({
      ...executeInput(f),
      tenant_id: 'org:other',
    })).toMatchObject({
      ok: false,
      reason: 'tenant_or_environment_mismatch',
    });
    const changedAction = structuredClone(f.controlPackage.action);
    changedAction.amount = '999.00';
    expect(await f.control.execute({
      ...executeInput(f),
      observed_action: changedAction,
    })).toMatchObject({
      ok: false,
      reason: 'execution_action_mismatch',
    });

    expect(await f.control.reconcile({} as any)).toMatchObject({
      ok: false,
      reason: 'tenant_required',
    });
    expect(await f.control.reconcile({
      tenant_id: TENANT,
    } as any)).toMatchObject({
      ok: false,
      reason: 'operation_id_required',
    });
    expect(await f.control.reconcile({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
    } as any)).toMatchObject({
      ok: false,
      reason: 'aeb_evaluation_required',
    });
    expect(await f.control.reconcile({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
      evaluation: f.evaluation,
    } as any)).toMatchObject({
      ok: false,
      reason: 'authenticated_provider_evidence_required',
    });

    const executed = await f.control.execute(executeInput(f));
    expect(await f.control.reconcile({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
      proposal: f.prepared.proposal,
      evaluation: f.evaluation,
      provider_evidence: providerEvidence(f.prepared.proposal, executed.attempt),
    })).toMatchObject({
      ok: false,
      reason: 'reconciliation_not_indeterminate',
    });
  });

  it('fails closed when package boundaries or runtime dependencies drift', async () => {
    const f = await fixture();
    expect(() => createHealthcareConsequenceControl({
      ...f.controlOptions,
      assurance: null,
    } as any)).toThrow('healthcare_assurance_signers_required');
    expect(() => createHealthcareConsequenceControl({
      ...f.controlOptions,
      evidence_store: null,
    } as any)).toThrow('healthcare_evidence_store_required');
    expect(() => createHealthcareConsequenceControl({
      ...f.controlOptions,
      reconciliation_handle_store: null,
    } as any)).toThrow('healthcare_reconciliation_handle_store_required');
    expect(() => createHealthcareConsequenceControl({
      ...f.controlOptions,
      allow_ephemeral_stores_for_tests: false,
    } as any)).toThrow('healthcare_durable_stores_required');
    expect(() => createHealthcareConsequenceControl({
      ...f.controlOptions,
      mutate_sandbox: null,
    } as any)).toThrow('healthcare_sandbox_mutation_required');

    const packageCases: Array<[string, (value: any) => void]> = [
      ['prospective_control_package_invalid', (value) => {
        value.sourceRecordDigests = ['not-a-digest'];
      }],
      ['prospective_control_finding_boundary_invalid', (value) => {
        value.sourceFinding.provesFraud = true;
      }],
      ['prospective_control_profile_invalid', (value) => {
        value.profile.version = 2;
      }],
      ['prospective_control_policy_invalid', (value) => {
        value.policy.version = 0;
      }],
      ['prospective_control_requirement_invalid', (value) => {
        value.requiredControl.consumption.maximumUses = 2;
      }],
      ['prospective_control_phi_boundary_invalid', (value) => {
        value.phi.rawPhiIncluded = true;
      }],
      ['prospective_control_package_digest_invalid', (value) => {
        value.packageDigest = `sha256:${'0'.repeat(64)}`;
      }],
    ];
    for (const [reason, mutate] of packageCases) {
      const value = scannerPackage();
      mutate(value);
      if (reason !== 'prospective_control_package_digest_invalid') {
        refreshPackageDigest(value);
      }
      expect(await f.control.prepare({
        tenant_id: TENANT,
        initiator_id: 'actor:health-reviewer',
        proposal_id: `proposal:${reason}`,
        operation_id: `operation:${reason}`,
        prospective_control_package: value,
      }), reason).toMatchObject({ ok: false, reason });
    }

    const badClock = createHealthcareConsequenceControl({
      ...f.controlOptions,
      now: () => Number.NaN,
    });
    expect(await badClock.prepare({
      tenant_id: TENANT,
      initiator_id: 'actor:health-reviewer',
      proposal_id: 'proposal:bad-clock',
      operation_id: 'operation:bad-clock',
      prospective_control_package: scannerPackage(),
    })).toMatchObject({
      ok: false,
      reason: 'healthcare_evidence_store_unavailable',
    });

    const throwingPrepare = createHealthcareConsequenceControl({
      ...f.controlOptions,
      controller: {
        ...f.controller,
        prepare() {
          throw new Error('controller_prepare_failed');
        },
      },
    } as any);
    expect(await throwingPrepare.prepare({
      tenant_id: TENANT,
      initiator_id: 'actor:health-reviewer',
      proposal_id: 'proposal:controller-failed',
      operation_id: 'operation:controller-failed',
      prospective_control_package: scannerPackage(),
    })).toMatchObject({
      ok: false,
      reason: 'controller_prepare_failed',
    });

    const unavailableStore = {
      ...f.stores.evidence_store,
      async list() {
        throw new Error('evidence_store_unavailable');
      },
    };
    const listFailure = createHealthcareConsequenceControl({
      ...f.controlOptions,
      evidence_store: unavailableStore,
    });
    expect(await listFailure.execute(executeInput(f))).toMatchObject({
      ok: false,
      reason: 'healthcare_evidence_store_unavailable',
    });
    expect(await listFailure.exportAssurancePacket({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
    })).toMatchObject({
      ok: false,
      reason: 'healthcare_evidence_store_unavailable',
    });

    const controllerRefusal = createHealthcareConsequenceControl({
      ...f.controlOptions,
      controller: {
        ...f.controller,
        async execute() {
          return {
            ok: false,
            reason: 'policy_refused',
            consequence: { state: 'RELEASED' },
          };
        },
      },
    } as any);
    expect(await controllerRefusal.execute(executeInput(f))).toMatchObject({
      ok: false,
      reason: 'policy_refused',
      retry_safe: true,
    });

    const controllerFailure = createHealthcareConsequenceControl({
      ...f.controlOptions,
      controller: {
        ...f.controller,
        async execute() {
          throw new Error('controller_execution_failed');
        },
      },
    } as any);
    expect(await controllerFailure.execute(executeInput(f))).toMatchObject({
      ok: false,
      reason: 'controller_execution_failed',
    });

    expect(await f.control.exportAssurancePacket({} as any)).toMatchObject({
      ok: false,
      reason: 'tenant_required',
    });
    expect(await f.control.exportAssurancePacket({
      tenant_id: TENANT,
    } as any)).toMatchObject({
      ok: false,
      reason: 'operation_id_required',
    });
    expect(await f.control.exportAssurancePacket({
      tenant_id: TENANT,
      operation_id: 'operation:never-prepared',
    })).toMatchObject({
      ok: false,
      reason: 'healthcare_assurance_packet_not_available',
    });
    expect(await f.stores.reconciliation_handle_store.get({
      tenant_id: TENANT,
      operation_id: 'operation:missing',
    })).toBeNull();
  });

  it('validates the exact action, acquisition endpoint, and signer outputs', async () => {
    const action = scannerPackage().action;
    const actionCases: Array<[string, (value: any) => void]> = [
      ['healthcare_prohibited_phi', (value) => {
        value.reviewer_id = { patientName: 'prohibited' };
      }],
      ['healthcare_action_profile_mismatch', (value) => {
        value['@version'] = 'EP-HEALTH-OTHER-v1';
      }],
      ['healthcare_material_field_missing:reviewer_id', (value) => {
        value.reviewer_id = '';
      }],
      ['healthcare_material_action_invalid', (value) => {
        value.amount = '0.00';
      }],
    ];
    for (const [reason, mutate] of actionCases) {
      const candidate = structuredClone(action);
      mutate(candidate);
      expect(() => canonicalizeHospicePaymentAction(candidate), reason).toThrow(
        reason,
      );
    }

    expect(() => createHospiceProposalToEffectProfile({
      authorization_endpoint: 42 as any,
    })).toThrow('healthcare_authorization_endpoint_invalid');
    expect(() => createHospiceProposalToEffectProfile({
      authorization_endpoint: 'not a URL',
    })).toThrow('healthcare_authorization_endpoint_invalid');
    expect(() => createHospiceProposalToEffectProfile({
      authorization_endpoint: 'http://approval.example.test',
    })).toThrow('healthcare_authorization_endpoint_invalid');
    expect(() => createHospiceProposalToEffectProfile({
      authorization_endpoint: 'https://approval.example.test',
      ttl_sec: 0,
    })).toThrow('healthcare_proposal_ttl_invalid');

    const badReceiptFixture = await fixture();
    const badReceiptControl = createHealthcareConsequenceControl({
      ...badReceiptFixture.controlOptions,
      assurance: {
        ...badReceiptFixture.controlOptions.assurance,
        signers: {
          ...badReceiptFixture.controlOptions.assurance.signers,
          receipt: {
            ...badReceiptFixture.controlOptions.assurance.signers.receipt,
            async sign() {
              return 'not-a-signature';
            },
          },
        },
      },
    });
    await badReceiptControl.execute(executeInput(badReceiptFixture));
    expect(await badReceiptControl.exportAssurancePacket({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
    })).toMatchObject({
      ok: false,
      reason: 'healthcare_assurance_signing_failed',
    });

    const badEvaluatorFixture = await fixture();
    const badEvaluatorControl = createHealthcareConsequenceControl({
      ...badEvaluatorFixture.controlOptions,
      assurance: {
        ...badEvaluatorFixture.controlOptions.assurance,
        signers: {
          ...badEvaluatorFixture.controlOptions.assurance.signers,
          evaluator: {
            ...badEvaluatorFixture.controlOptions.assurance.signers.evaluator,
            async sign() {
              return new Uint8Array(1);
            },
          },
        },
      },
    });
    await badEvaluatorControl.execute(executeInput(badEvaluatorFixture));
    expect(await badEvaluatorControl.exportAssurancePacket({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
    })).toMatchObject({
      ok: false,
      reason: 'healthcare_assurance_signing_failed',
    });
  });

  it('rejects every packet and trust-bundle substitution at the offline boundary', async () => {
    const executedFixture = await fixture();
    await executedFixture.control.execute(executeInput(executedFixture));
    const executedPacket = await executedFixture.control.exportAssurancePacket({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
    });

    const reconciledFixture = await fixture();
    reconciledFixture.setMutation(async () => {
      throw new Error('provider_timeout_after_entry');
    });
    const indeterminate = await reconciledFixture.control.execute(
      executeInput(reconciledFixture),
    );
    await reconciledFixture.control.reconcile({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
      proposal: reconciledFixture.prepared.proposal,
      evaluation: reconciledFixture.evaluation,
      provider_evidence: providerEvidence(
        reconciledFixture.prepared.proposal,
        indeterminate.attempt,
      ),
    });
    const reconciledPacket =
      await reconciledFixture.control.exportAssurancePacket({
        tenant_id: TENANT,
        operation_id: OPERATION_ID,
      });

    const cases: Array<{
      name: string;
      packet: any;
      reason: string;
      redigest?: boolean;
    }> = [
      {
        name: 'profile',
        packet: structuredClone(executedPacket),
        reason: 'packet_profile_invalid',
      },
      {
        name: 'safe projection',
        packet: structuredClone(executedPacket),
        reason: 'packet_safe_projection_invalid',
      },
      {
        name: 'proposal binding',
        packet: structuredClone(executedPacket),
        reason: 'packet_proposal_binding_invalid',
      },
      {
        name: 'receipt binding',
        packet: structuredClone(executedPacket),
        reason: 'packet_receipt_binding_invalid',
      },
      {
        name: 'receipt assertion envelope',
        packet: structuredClone(executedPacket),
        reason: 'packet_receipt_binding_invalid',
      },
      {
        name: 'aeb binding',
        packet: structuredClone(executedPacket),
        reason: 'packet_aeb_binding_invalid',
      },
      {
        name: 'aeb assertion envelope',
        packet: structuredClone(executedPacket),
        reason: 'packet_aeb_binding_invalid',
      },
      {
        name: 'attempt binding',
        packet: structuredClone(executedPacket),
        reason: 'packet_attempt_binding_invalid',
      },
      {
        name: 'chronology',
        packet: structuredClone(executedPacket),
        reason: 'packet_chronology_or_limitations_invalid',
      },
      {
        name: 'unexpected reconciliation evidence',
        packet: structuredClone(executedPacket),
        reason: 'packet_reconciliation_evidence_unexpected',
      },
      {
        name: 'terminal state',
        packet: structuredClone(executedPacket),
        reason: 'packet_terminal_state_mismatch',
      },
      {
        name: 'prohibited PHI',
        packet: structuredClone(executedPacket),
        reason: 'packet_contains_prohibited_phi',
      },
      {
        name: 'proof shape',
        packet: structuredClone(executedPacket),
        reason: 'packet_proof_shape_invalid',
      },
      {
        name: 'digest',
        packet: structuredClone(executedPacket),
        reason: 'packet_digest_invalid',
        redigest: false,
      },
      {
        name: 'reconciliation evidence',
        packet: structuredClone(reconciledPacket),
        reason: 'packet_reconciliation_evidence_invalid',
      },
      {
        name: 'missing reconciliation evidence',
        packet: structuredClone(reconciledPacket),
        reason: 'packet_reconciliation_evidence_required',
      },
    ];

    cases[0].packet.profile.synthetic = false;
    cases[1].packet.finding_projection.authorization_evidence = true;
    cases[2].packet.protocol_evidence.proposal_binding.projection.operation_id =
      'operation:health-other';
    cases[3].packet.protocol_evidence.receipt.body.projection.action_digest =
      `sha256:${'0'.repeat(64)}`;
    cases[4].packet.protocol_evidence.receipt.body.tenant_id = 'org:other';
    cases[5].packet.protocol_evidence.aeb.body.projection.verdict = 'FAILED';
    cases[6].packet.protocol_evidence.aeb.body.tenant_id = 'org:other';
    cases[7].packet.outcome.attempt.provider_id = 'provider:substituted';
    cases[8].packet.chronology[0].event_type = 'EXECUTION';
    cases[9].packet.protocol_evidence.provider =
      structuredClone(reconciledPacket.protocol_evidence.provider);
    cases[10].packet.outcome.decision = 'UNKNOWN';
    cases[11].packet.profile.patientName = 'prohibited';
    cases[12].packet.proof.signature_b64u = '!';
    cases[13].packet.packet_digest = `sha256:${'0'.repeat(64)}`;
    cases[14].packet.protocol_evidence.provider.body.projection.outcome =
      'NOT_COMMITTED';
    delete cases[15].packet.protocol_evidence.provider;

    expect(checkHealthcareAssurancePacketInternalConsistency(null)).toEqual({
      consistent: false,
      reasons: ['packet_shape_invalid'],
    });

    for (const candidate of cases) {
      if (candidate.redigest !== false) refreshPacketDigest(candidate.packet);
      expect(
        checkHealthcareAssurancePacketInternalConsistency(candidate.packet),
        candidate.name,
      ).toMatchObject({
        consistent: false,
        reasons: expect.arrayContaining([candidate.reason]),
      });
    }

    const invalidTrust = structuredClone(executedFixture.assuranceTrust);
    invalidTrust.receipt = structuredClone(invalidTrust.aeb);
    expect(verifyHealthcareAssurancePacketOffline(
      executedPacket,
      invalidTrust,
    )).toMatchObject({
      valid: false,
      reasons: expect.arrayContaining(['relying_party_trust_bundle_invalid']),
    });

    const malformedPin = structuredClone(executedFixture.assuranceTrust);
    malformedPin.receipt.key_id = '';
    expect(verifyHealthcareAssurancePacketOffline(
      executedPacket,
      malformedPin,
    )).toMatchObject({
      valid: false,
      reasons: expect.arrayContaining(['relying_party_trust_bundle_invalid']),
    });

    const invalidDer = structuredClone(executedFixture.assuranceTrust);
    invalidDer.receipt.public_key_spki_b64u =
      Buffer.from('not-a-public-key').toString('base64url');
    expect(verifyHealthcareAssurancePacketOffline(
      executedPacket,
      invalidDer,
    )).toMatchObject({
      valid: false,
      reasons: expect.arrayContaining(['relying_party_trust_bundle_invalid']),
    });

    const wrongRelyingParty = structuredClone(executedFixture.assuranceTrust);
    wrongRelyingParty.relying_party_id = 'rp:other';
    expect(verifyHealthcareAssurancePacketOffline(
      executedPacket,
      wrongRelyingParty,
    )).toMatchObject({
      valid: false,
      reasons: expect.arrayContaining(['relying_party_binding_invalid']),
    });

    const forgedPacket = structuredClone(executedPacket);
    forgedPacket.proof.signature_b64u = Buffer.alloc(64, 7).toString('base64url');
    expect(verifyHealthcareAssurancePacketOffline(
      forgedPacket,
      executedFixture.assuranceTrust,
    )).toMatchObject({
      valid: false,
      reasons: expect.arrayContaining(['evaluator_signature_invalid']),
    });
  });

  it('keeps execute and export routes authenticated, tenant-bound, and injectable', async () => {
    const f = await fixture();
    await f.control.execute(executeInput(f));
    const controlSpy = vi.fn(async () => f.control);
    const rejectedControlSpy = vi.fn(async () => f.control);
    const unauthenticated = createHospiceClaimExecuteHandler({
      authenticate: async () => ({ error: 'missing', status: 401 }),
      resolve_control: rejectedControlSpy,
    });
    const unauthenticatedResponse = await unauthenticated(postRequest(
      '/api/v1/adapters/health/hospice-claim/execute',
      {
        operation: 'reconcile',
        organization_id: TENANT,
      },
    ) as any);
    expect(unauthenticatedResponse.status).toBe(401);
    expect(unauthenticatedResponse.headers.get('cache-control')).toBe('no-store');
    expect(rejectedControlSpy).not.toHaveBeenCalled();

    const mismatched = createHospiceClaimExecuteHandler({
      authenticate: async () => ({
        entity: {
          entity_id: 'actor:health-reviewer',
          organization_id: TENANT,
        },
      }),
      resolve_control: controlSpy,
    });
    const mismatchedResponse = await mismatched(postRequest(
      '/api/v1/adapters/health/hospice-claim/execute',
      {
        operation: 'prepare',
        organization_id: 'org:other',
        proposal_id: 'proposal:other',
        operation_id: 'operation:other',
        prospective_control_package: scannerPackage(),
      },
    ) as any);
    expect(mismatchedResponse.status).toBe(403);
    expect(controlSpy).not.toHaveBeenCalled();

    const exportHandler = createHospiceClaimExportHandler({
      authenticate: async () => ({
        entity: {
          entity_id: 'actor:health-reviewer',
          organization_id: TENANT,
        },
      }),
      resolve_control: controlSpy,
    });
    const exportResponse = await exportHandler(new Request(
      `https://www.emiliaprotocol.ai/api/v1/adapters/health/hospice-claim/export?organization_id=${encodeURIComponent(TENANT)}&operation_id=${encodeURIComponent(OPERATION_ID)}`,
    ) as any);
    expect(exportResponse.status).toBe(200);
    expect(exportResponse.headers.get('cache-control')).toBe('no-store');
    expect(exportResponse.headers.get('content-disposition')).toContain(
      'healthcare-assurance-',
    );
    expect(verifyHealthcareAssurancePacketOffline(
      await exportResponse.json(),
      f.assuranceTrust,
    ).valid).toBe(true);
    expect(controlSpy).toHaveBeenCalledTimes(1);

    const phiControlSpy = vi.fn(async () => f.control);
    const phiHandler = createHospiceClaimExecuteHandler({
      authenticate: async () => ({
        entity: {
          entity_id: 'actor:health-reviewer',
          organization_id: TENANT,
        },
      }),
      resolve_control: phiControlSpy,
    });
    const phiResponse = await phiHandler(postRequest(
      '/api/v1/adapters/health/hospice-claim/execute',
      {
        operation: 'execute',
        organization_id: TENANT,
        SSN: '000-00-0000',
      },
    ) as any);
    expect(phiResponse.status).toBe(400);
    expect(phiControlSpy).not.toHaveBeenCalled();
  });
});
