// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import fs from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
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
  DAVINCI_PAS_ACTION_TYPE,
  buildDavinciPasReviewBinding,
  digestPasValue,
} from '../lib/health/davinci-pas-binding.js';
import {
  DAVINCI_PAS_AEB_REQUIREMENT_REF,
  DAVINCI_PAS_CONSEQUENCE_PACKET_VERSION,
  DAVINCI_PAS_CONSEQUENCE_PACKET_V2_VERSION,
  DAVINCI_PAS_CONSEQUENCE_PROFILE_ID,
  createDavinciPasConsequenceControl,
  createDavinciPasProposalToEffectProfile,
  verifyDavinciPasConsequencePacket,
  verifyDavinciPasConsequencePacketV2,
} from '../lib/health/davinci-pas-consequence-control.js';
import { createMemoryHealthcareControlStores } from '../lib/health/proposal-to-effect-profile.js';
import { createDavinciPasReviewHandler } from '../app/api/v1/adapters/health/davinci-pas/review/route.js';
import { createDavinciPasExportHandler } from '../app/api/v1/adapters/health/davinci-pas/export/route.js';

const NOW = '2026-07-27T20:00:00.000Z';
const TENANT = 'org:health-plan-001';
const OPERATION_ID = 'operation:pas-review-001';
const SERVER_CONTEXT = Object.freeze({
  tenant_id: TENANT,
  provider_id: 'provider:pas-synthetic-sandbox',
  provider_account_id: 'account:pas-reference',
  environment: 'sandbox',
  executor_id: 'executor:pas-consequence-control',
});
const INTEGRITY_KEY = crypto
  .createHash('sha256')
  .update('davinci-pas-consequence-control-test')
  .digest();
const VECTOR_SUITE = JSON.parse(fs.readFileSync(
  new URL('../conformance/vectors/davinci-pas-consequence-control.v1.json', import.meta.url),
  'utf8',
));
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const CLAIM_PROFILE =
  'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/profile-claim|2.2.1';
const RESPONSE_PROFILE =
  'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/profile-claimresponse|2.2.1';
const REVIEWER_URL =
  'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/extension-claimResponseReviewer';
const REVIEW_ACTION_URL =
  'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/extension-reviewAction';
const REVIEW_ACTION_CODE_URL =
  'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/extension-reviewActionCode';
const X12_REVIEW_ACTION_SYSTEM = 'https://codesystem.x12.org/005010/306';
const POLICY = Object.freeze({
  policy_id: 'policy:medical-pa:2026-07',
  policy_version: '2026-07',
  policy_digest: `sha256:${'a'.repeat(64)}`,
});

function claim() {
  return {
    resourceType: 'Claim',
    id: 'medical-pa-claim-001',
    meta: { profile: [CLAIM_PROFILE] },
    identifier: [{ system: 'https://payer.example.test/prior-auth', value: 'secret-pa-001' }],
    status: 'active',
    type: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/claim-type', code: 'professional' }] },
    use: 'preauthorization',
    patient: { reference: 'Patient/direct-member-123' },
    created: '2026-07-27T19:30:00Z',
    insurer: { reference: 'Organization/payer-1' },
    provider: { reference: 'Organization/requesting-provider-1' },
    priority: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/processpriority', code: 'normal' }] },
    diagnosis: [{ sequence: 1, diagnosisCodeableConcept: { coding: [{ system: 'http://hl7.org/fhir/sid/icd-10-cm', code: 'M17.11' }] } }],
    supportingInfo: [{ sequence: 1, category: { text: 'clinical note' }, valueString: 'raw clinical rationale' }],
    item: [{
      sequence: 1,
      productOrService: { coding: [{ system: 'http://www.ama-assn.org/go/cpt', code: '27447' }] },
      servicedDate: '2026-08-15',
      quantity: { value: 1 },
    }],
  };
}

function reviewerExtension() {
  return {
    url: REVIEWER_URL,
    extension: [
      { url: 'wasHumanReviewedFlag', valueBoolean: true },
      { url: 'reviewerNPI', valueIdentifier: { system: 'http://hl7.org/fhir/sid/us-npi', value: '1234567893' } },
      { url: 'reviewerSpecialty', valueCodeableConcept: { coding: [{ system: 'http://nucc.org/provider-taxonomy', code: '207X00000X' }] } },
    ],
  };
}

function claimResponse(reviewActionCode = 'A3') {
  return {
    resourceType: 'ClaimResponse',
    id: 'medical-pa-response-001',
    meta: { profile: [RESPONSE_PROFILE] },
    status: 'active',
    type: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/claim-type', code: 'professional' }] },
    use: 'preauthorization',
    patient: { reference: 'Patient/direct-member-123' },
    created: '2026-07-27T19:31:00Z',
    insurer: { reference: 'Organization/payer-1' },
    request: { reference: 'Claim/medical-pa-claim-001' },
    outcome: 'complete',
    extension: reviewActionCode === 'A1' ? [] : [reviewerExtension()],
    item: [{
      itemSequence: 1,
      adjudication: [{
        category: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/adjudication', code: 'submitted' }] },
        extension: [{
          url: REVIEW_ACTION_URL,
          extension: [{
            url: REVIEW_ACTION_CODE_URL,
            valueCodeableConcept: { coding: [{ system: X12_REVIEW_ACTION_SYSTEM, code: reviewActionCode }] },
          }],
        }],
      }],
    }],
  };
}

function pasContext(reviewActionCode = 'A3') {
  const pasClaim = claim();
  const pasClaimResponse = claimResponse(reviewActionCode);
  const responseDigest = digestPasValue(pasClaimResponse);
  const reviewer = pasClaimResponse.extension[0];
  return {
    operation_id: OPERATION_ID,
    pairwise_patient_ref: 'pairwise:medical-pa-member-7H3k9Q2p',
    claim: pasClaim,
    claim_response: pasClaimResponse,
    policy: POLICY,
    ...(reviewActionCode === 'A1' ? {} : {
      reviewer: {
        reviewer_ref: 'reviewer:utilization-reviewer-017',
        identity_evidence: {
          status: 'accepted',
          subject_ref: 'reviewer:utilization-reviewer-017',
          evidence_digest: `sha256:${'b'.repeat(64)}`,
          fhir_reviewer_digest: digestPasValue(reviewer),
        },
        authority_evidence: {
          status: 'accepted',
          subject_ref: 'reviewer:utilization-reviewer-017',
          evidence_digest: `sha256:${'c'.repeat(64)}`,
          scope: 'medical_prior_authorization.adverse_decision',
          policy_digest: POLICY.policy_digest,
          claim_response_digest: responseDigest,
        },
      },
    }),
  };
}

function registryEntry(entryId: string, kind: string, version: string, definition: unknown) {
  const entry: any = { kind, version, status: 'active', definition };
  entry.definition_digest = registryEntryDigest(entryId, entry);
  return entry;
}

function aebContext(action: Record<string, unknown>, caid: string) {
  const adapter = {
    id: 'test:davinci-pas-approval',
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
        replay_unit: digestAeb({ root: artifact.root, caid: artifact.caid }),
        evidence_role: 'human-authorization',
        subject: { id: 'human:pas-reviewer', kind: 'human' },
        reasons: trusted ? [] : ['native_trust_root_not_pinned'],
      };
    },
    mapAction({ artifact, native, expected_action }: any) {
      return {
        mapping: native.native_verification === 'VERIFIED' ? 'MATCH' : 'INDETERMINATE',
        caid: artifact.caid,
        action_digest: digestAeb(expected_action),
        reasons: [],
      };
    },
  };
  const profile: any = {
    version: '1',
    definition: { action_type: DAVINCI_PAS_ACTION_TYPE },
    registry_entry_ref: 'mapping:davinci-pas-review',
    mapper_id: 'mapper:davinci-pas-review',
    resolver: {
      id: 'resolver:davinci-pas-review',
      version: '1',
      implementation_digest: digestAeb({ implementation: 'resolver:davinci-pas-review:1' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [],
    },
  };
  profile.profile_digest = mappingProfileDigest('davinci-pas-review', profile);
  const registry: any = {
    '@version': 'EP-EVIDENCE-REGISTRY-v1',
    registry_id: 'registry:davinci-pas-consequence-test',
    epoch: 1,
    entries: {
      'mapping:davinci-pas-review': registryEntry(
        'mapping:davinci-pas-review',
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
    },
  };
  registry.registry_digest = unifiedRegistryDigest(registry);
  const pin: any = {
    version: '1',
    trust_roots: ['root:pas-test'],
    config: { mode: 'offline-test' },
    max_status_age_sec: 300,
  };
  pin.config_digest = adapterPinDigest('test:davinci-pas-approval', pin);
  const evaluator = crypto.generateKeyPairSync('ed25519');
  const config: any = {
    '@version': 'AEB-ADAPTER-v1',
    relying_party_id: 'rp:pas-synthetic-reference',
    evaluator_keys: {
      'eval:pas-test': {
        public_key: evaluator.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      },
    },
    registry,
    accepted_mappers: ['mapper:davinci-pas-review'],
    adapters: { 'test:davinci-pas-approval': pin },
    profiles: { 'davinci-pas-review': profile },
    requirements: {
      [DAVINCI_PAS_AEB_REQUIREMENT_REF]: {
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
  const status = {
    checked_at: '2026-07-27T19:59:00.000Z',
    expires_at: '2026-07-27T20:05:00.000Z',
    revocation_checked: true,
    revoked: false,
    consumed: false,
  };
  const artifact = { root: 'root:pas-test', caid, action: structuredClone(action) };
  return {
    adapter,
    artifact,
    status,
    config,
    evaluate() {
      return evaluateAebEvidence({
        config,
        adapters: { 'test:davinci-pas-approval': adapter },
        operation_id: OPERATION_ID,
        consumption_nonce: proposalToEffectConsumptionNonce(
          OPERATION_ID,
          pinnedConfigDigest(config),
        ),
        initiator_id: 'actor:pas-operator',
        executor_id: SERVER_CONTEXT.executor_id,
        requirement_ref: DAVINCI_PAS_AEB_REQUIREMENT_REF,
        caid,
        expected_action: action,
        legs: [{
          adapter_id: 'test:davinci-pas-approval',
          profile_id: 'davinci-pas-review',
          artifact_ref: 'artifact:pas-approval',
          artifact,
          status,
        }],
        evaluated_at: NOW,
        signer: { key_id: 'eval:pas-test', private_key: evaluator.privateKey },
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
      if (replayKeys.some((replayKey) => replayOwners.has(replayKey))) return 'NATIVE_REPLAY_CONFLICT';
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
      for (const [replayKey, owner] of replayOwners) if (owner === key) replayOwners.delete(replayKey);
      return true;
    },
  };
}

function consequenceAttemptStore() {
  const entries = new Map<string, any>();
  let ownerSequence = 0;
  const key = (tenantId: string, attemptId: string) => `${tenantId}\0${attemptId}`;
  return {
    durable: true as const,
    ownershipFenced: true as const,
    compareAndSwap: true as const,
    atomicEvidenceBinding: true as const,
    entries,
    async reserve(binding: any) {
      const entryKey = key(binding.tenant_id, binding.attempt_id);
      if (entries.has(entryKey)) return { reserved: false, reason: 'attempt_exists' };
      const owner = `owner:${++ownerSequence}:${crypto.randomBytes(8).toString('base64url')}`;
      entries.set(entryKey, { ...structuredClone(binding), owner, state: 'RESERVED', evidence: null });
      return { reserved: true, owner };
    },
    async transition(input: any) {
      const entry = entries.get(key(input.tenant_id, input.attempt_id));
      if (!entry || entry.owner !== input.owner || entry.state !== input.expected_state) return false;
      entry.state = input.next_state;
      return true;
    },
    async reconcile(input: any) {
      const entry = entries.get(key(input.tenant_id, input.attempt_id));
      if (!entry || entry.owner !== input.owner || entry.state !== 'INDETERMINATE') return false;
      entry.state = input.next_state;
      entry.evidence = structuredClone(input.evidence);
      return true;
    },
    async read(binding: any) {
      const entry = entries.get(key(binding.tenant_id, binding.attempt_id));
      return entry ? { state: entry.state, evidence_digest: entry.evidence?.evidence_digest ?? null } : null;
    },
  };
}

function testGate(expectedCaid: string) {
  async function check(input: any) {
    const receipt = input.receipt;
    const actionDigest = digestAeb(input.observedAction);
    const allow = receipt?.['@version'] === 'EP-RECEIPT-v1'
      && receipt?.fresh === true
      && receipt?.caid === expectedCaid
      && receipt?.action_digest === actionDigest;
    return {
      allow,
      reason: allow ? 'receipt_verified' : 'approval_evidence_stale_or_mismatched',
      action_hash: actionDigest,
      requirement: { receipt_required: true },
    };
  }
  return {
    check,
    async run(input: any, effect: (authorization: any) => Promise<unknown>) {
      const authorization = await check(input);
      if (!authorization.allow) return { ok: false, authorization };
      try {
        return { ok: true, authorization, result: await effect(authorization) };
      } catch (error: any) {
        error.emiliaGateOutcome = { outcome: 'indeterminate' };
        throw error;
      }
    },
  };
}

function receipt(caid: string, actionDigest: string) {
  return {
    '@version': 'EP-RECEIPT-v1',
    receipt_id: 'receipt:pas-human-review-001',
    caid,
    action_digest: actionDigest,
    fresh: true,
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
  const context = pasContext();
  const built = buildDavinciPasReviewBinding(context);
  if (!built.ok) throw new Error(built.reasons.join(','));
  const binding = built.binding;
  const aeb = aebContext(binding.action, binding.caid);
  const aebStore = durableAebStore();
  const attemptStore = consequenceAttemptStore();
  const attempts = ['attempt:pas-001', 'attempt:pas-002'];
  const controller = createProposalToEffect({
    gate: testGate(binding.caid),
    proposal_integrity: { hmac_sha256_key: INTEGRITY_KEY },
    consequence: {
      ...SERVER_CONTEXT,
      store: attemptStore,
      create_attempt_id: async () => attempts.shift() ?? `attempt:${crypto.randomUUID()}`,
    },
    profiles: {
      [DAVINCI_PAS_CONSEQUENCE_PROFILE_ID]: createDavinciPasProposalToEffectProfile({
        authorization_endpoint: 'https://approval.example.test/health/prior-authorization',
      }),
    },
    aeb: {
      config: aeb.config,
      adapters: { 'test:davinci-pas-approval': aeb.adapter },
      store: aebStore,
      resolve_artifacts: async () => ({ 'artifact:pas-approval': aeb.artifact }),
      currentStatusResolver: async () => aeb.status,
      statusVerifier: async ({ status_artifact }: any) => ({
        valid: status_artifact?.revoked !== true,
        outcome: status_artifact?.revoked === true ? 'revoked' : 'current_not_revoked',
        status: structuredClone(status_artifact),
      }),
      verify_provider_evidence: async ({ evidence, expected }: any) => {
        const valid = evidence?.authenticated === true
          && ['COMMITTED', 'NOT_COMMITTED', 'ESCALATED'].includes(evidence.outcome)
          && ['operation_id', 'caid', 'action_digest', 'tenant_id', 'request_digest', 'provider_id',
            'provider_account_id', 'environment', 'attempt_id']
            .every((field) => evidence[field] === expected[field])
          && typeof evidence.evidence_id === 'string'
          && typeof evidence.observed_at === 'string';
        return {
          valid,
          reason: valid ? undefined : 'provider_evidence_unauthenticated',
          ...structuredClone(evidence),
          evidence_digest: evidence ? digestAeb(evidence) : null,
        };
      },
    },
    now: () => Date.parse(NOW),
  });
  const stores = createMemoryHealthcareControlStores();
  const packetKey = crypto.generateKeyPairSync('ed25519');
  const packetSigner = {
    algorithm: 'Ed25519' as const,
    key_id: 'pas:packet:test',
    sign(bytes: Uint8Array) {
      return crypto.sign(null, Buffer.from(bytes), packetKey.privateKey).toString('base64url');
    },
  };
  const packetPqKey = fixtureOptions.hybrid
    ? ml_dsa65.keygen(crypto.randomBytes(32))
    : null;
  let mutationCount = 0;
  let mutation = async () => ({ system_of_record_reference: 'pas-sandbox:decision:001' });
  const control = createDavinciPasConsequenceControl({
    controller: controller as any,
    ...stores,
    assurance: {
      relying_party_id: 'rp:pas-synthetic-reference',
      signer: packetSigner,
      ...(packetPqKey ? {
        hybrid: {
          ed25519: packetSigner,
          mldsa65: {
            key_id: 'pas:packet:test:pq',
            private_key: packetPqKey.secretKey,
          },
        },
      } : {}),
    },
    allow_ephemeral_stores_for_tests: true,
    now: () => Date.parse(NOW),
    async mutate_pas_sandbox(input) {
      mutationCount += 1;
      return mutation(input);
    },
  });
  const prepared = await control.prepare({
    tenant_id: TENANT,
    initiator_id: 'actor:pas-operator',
    proposal_id: 'proposal:pas-review-001',
    operation_id: OPERATION_ID,
    server_observed_pas: context,
  });
  return {
    aeb,
    aebStore,
    attemptStore,
    binding,
    context,
    control,
    prepared,
    evaluation: aeb.evaluate(),
    publicKey: packetKey.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    pqPublicKey: packetPqKey
      ? Buffer.from(packetPqKey.publicKey).toString('base64url')
      : null,
    get mutationCount() { return mutationCount; },
    setMutation(next: typeof mutation) { mutation = next; },
  };
}

function executeInput(f: Awaited<ReturnType<typeof fixture>>, observed = f.context) {
  return {
    tenant_id: TENANT,
    proposal: f.prepared.proposal,
    approval_evidence: receipt(f.prepared.proposal.caid, f.prepared.proposal.action_digest),
    evaluation: f.evaluation,
    server_observed_pas: observed,
  };
}

function postRequest(path: string, body: unknown): Request {
  return new Request(`https://www.emiliaprotocol.ai${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

describe('Da Vinci PAS consequence control', () => {
  it('turns an adverse PAS review into one exact approval challenge without portable PHI', async () => {
    const f = await fixture();
    expect(f.prepared).toMatchObject({ ok: true, decision: 'APPROVAL_REQUIRED' });
    expect(f.prepared.proposal.caid).toBe(f.binding.caid);
    expect(f.prepared.proposal.action_digest).toBe(f.binding.action_digest);
    expect(f.binding.caid).toBe(VECTOR_SUITE.fixed_denial.expected_caid);
    expect(f.binding.action_digest).toBe(VECTOR_SUITE.fixed_denial.expected_action_digest);
    const portable = JSON.stringify(f.prepared.binding);
    expect(portable).not.toContain('Patient/direct-member-123');
    expect(portable).not.toContain('raw clinical rationale');
    expect(portable).not.toContain('27447');
  });

  it('executes the exact server-observed determination once and emits a signed packet', async () => {
    const f = await fixture();
    const result = await f.control.execute(executeInput(f));
    expect(result).toMatchObject({
      ok: true,
      decision: 'EXECUTED',
      retry_safe: false,
      reconciliation_required: false,
    });
    expect(f.mutationCount).toBe(1);
    const packet = await f.control.exportReliancePacket({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
    });
    expect(packet['@version']).toBe(DAVINCI_PAS_CONSEQUENCE_PACKET_VERSION);
    expect(packet.decision).toBe('EXECUTED');
    expect(verifyDavinciPasConsequencePacket(packet, {
      relying_party_id: 'rp:pas-synthetic-reference',
      key_id: 'pas:packet:test',
      public_key_spki_b64u: f.publicKey,
    })).toEqual({ valid: true, reasons: [] });
    expect(JSON.stringify(packet)).not.toContain('Patient/direct-member-123');
  });

  it('exports and verifies the opt-in hybrid packet over the same protected PAS action', async () => {
    const f = await fixture({ hybrid: true });
    await f.control.execute(executeInput(f));
    const packet = await f.control.exportReliancePacketV2({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
    });
    expect(packet['@version']).toBe(DAVINCI_PAS_CONSEQUENCE_PACKET_V2_VERSION);
    expect(f.pqPublicKey).not.toBeNull();
    await expect(verifyDavinciPasConsequencePacketV2(packet, {
      relying_party_id: 'rp:pas-synthetic-reference',
      key_id: 'pas:packet:test',
      public_key_spki_b64u: f.publicKey,
      pq_key_id: 'pas:packet:test:pq',
      pq_public_key_b64u: f.pqPublicKey!,
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
    })).resolves.toEqual({ valid: true, reasons: [] });
  });

  it('refuses hybrid export when no hybrid signer is configured', async () => {
    const f = await fixture();
    await f.control.execute(executeInput(f));
    await expect(f.control.exportReliancePacketV2({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
    })).resolves.toMatchObject({
      ok: false,
      reason: 'pas_hybrid_signer_not_configured',
    });
  });

  it('refuses source drift before the provider callback', async () => {
    const f = await fixture();
    const drifted = structuredClone(f.context);
    drifted.claim_response.item[0].adjudication[0].extension[0]
      .extension[0].valueCodeableConcept.coding[0].code = 'A2';
    const result = await f.control.execute(executeInput(f, drifted));
    expect(result).toMatchObject({
      ok: false,
      decision: 'REFUSED',
      reason: 'pas_execution_binding_mismatch',
      program_digest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
    });
    expect(f.mutationCount).toBe(0);
  });

  it('freezes timeout-after-effect as INDETERMINATE and refuses blind replay', async () => {
    const f = await fixture();
    f.setMutation(async () => { throw new Error('provider_response_lost_after_effect'); });
    const first = await f.control.execute(executeInput(f));
    expect(first).toMatchObject({
      ok: false,
      decision: 'INDETERMINATE',
      reconciliation_required: true,
      retry_safe: false,
    });
    const replay = await f.control.execute(executeInput(f));
    expect(replay.ok).toBe(false);
    expect(replay.decision).toBe('REFUSED');
    expect(replay.program_digest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(f.mutationCount).toBe(1);
  });

  it('requires exact authenticated provider evidence to reconcile an indeterminate effect', async () => {
    const f = await fixture();
    f.setMutation(async () => { throw new Error('provider_response_lost_after_effect'); });
    const first = await f.control.execute(executeInput(f));
    const wrong = await f.control.reconcile({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
      proposal: f.prepared.proposal,
      evaluation: f.evaluation,
      provider_evidence: providerEvidence(f.prepared.proposal, first.attempt, { attempt_id: 'attempt:wrong' }),
    });
    expect(wrong).toMatchObject({ ok: false, decision: 'INDETERMINATE' });
    const resolved = await f.control.reconcile({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
      proposal: f.prepared.proposal,
      evaluation: f.evaluation,
      provider_evidence: providerEvidence(f.prepared.proposal, first.attempt),
    });
    expect(resolved).toMatchObject({
      ok: true,
      decision: 'RECONCILED_EXECUTED',
      authenticated_provider_evidence: true,
    });
  });

  it('keeps the HTTP boundary authenticated, tenant-bound, and raw-FHIR-free', async () => {
    const f = await fixture();
    const loadPasContext = vi.fn(async () => f.context);
    const controlResolver = vi.fn(async () => f.control);
    const handler = createDavinciPasReviewHandler({
      authenticate: async () => ({
        entity: { entity_id: 'actor:pas-operator', organization_id: TENANT },
      }),
      resolve_control: controlResolver,
      load_pas_context: loadPasContext,
    });
    const prepared = await handler(postRequest(
      '/api/v1/adapters/health/davinci-pas/review',
      {
        operation: 'prepare',
        organization_id: TENANT,
        proposal_id: 'proposal:pas-route-001',
        operation_id: OPERATION_ID,
        pas_context_ref: 'pas-context:server:001',
      },
    ) as any);
    expect(prepared.status).toBe(201);
    expect(prepared.headers.get('cache-control')).toBe('no-store');
    expect(loadPasContext).toHaveBeenCalledWith({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
      pas_context_ref: 'pas-context:server:001',
    });

    const raw = await handler(postRequest(
      '/api/v1/adapters/health/davinci-pas/review',
      {
        operation: 'prepare',
        organization_id: TENANT,
        proposal_id: 'proposal:pas-route-raw',
        operation_id: OPERATION_ID,
        pas_context_ref: 'pas-context:server:001',
        claim: claim(),
      },
    ) as any);
    expect(raw.status).toBe(400);
    expect((await raw.json()).type).toContain('raw_pas_resources_refused');
    expect(loadPasContext).toHaveBeenCalledTimes(1);

    const crossTenant = createDavinciPasReviewHandler({
      authenticate: async () => ({
        entity: { entity_id: 'actor:pas-operator', organization_id: TENANT },
      }),
      resolve_control: controlResolver,
      load_pas_context: loadPasContext,
    });
    const denied = await crossTenant(postRequest(
      '/api/v1/adapters/health/davinci-pas/review',
      {
        operation: 'prepare',
        organization_id: 'org:other',
        proposal_id: 'proposal:pas-route-other',
        operation_id: OPERATION_ID,
        pas_context_ref: 'pas-context:server:001',
      },
    ) as any);
    expect(denied.status).toBe(403);
  });

  it('exports the signed packet only through an authenticated tenant-bound route', async () => {
    const f = await fixture();
    await f.control.execute(executeInput(f));
    const handler = createDavinciPasExportHandler({
      authenticate: async () => ({
        entity: { entity_id: 'actor:pas-operator', organization_id: TENANT },
      }),
      resolve_control: async () => f.control,
    });
    const response = await handler(new Request(
      `https://www.emiliaprotocol.ai/api/v1/adapters/health/davinci-pas/export?organization_id=${encodeURIComponent(TENANT)}&operation_id=${encodeURIComponent(OPERATION_ID)}`,
    ) as any);
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('content-disposition')).toContain('pas-consequence-');
    expect(verifyDavinciPasConsequencePacket(await response.json(), {
      relying_party_id: 'rp:pas-synthetic-reference',
      key_id: 'pas:packet:test',
      public_key_spki_b64u: f.publicKey,
    }).valid).toBe(true);
  });
});
