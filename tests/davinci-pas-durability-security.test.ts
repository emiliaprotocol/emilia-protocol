// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';

import { canonicalize } from '../lib/canonical-json.js';
import {
  DAVINCI_PAS_ACTION_TYPE,
  DAVINCI_PAS_BINDING_TYPE,
  DAVINCI_PAS_IG_VERSION,
  DAVINCI_PAS_MEDICAL_RAIL,
  DAVINCI_PAS_PROFILE_ID,
  buildDavinciPasReviewBinding,
  canonicalizeDavinciPasMaterialAction,
  digestPasValue,
  type DavinciPasReviewBinding,
} from '../lib/health/davinci-pas-binding.js';
import {
  DAVINCI_PAS_CONSEQUENCE_PACKET_VERSION,
  DAVINCI_PAS_CONSEQUENCE_PROFILE_ID,
  createDavinciPasConsequenceControl,
  verifyDavinciPasConsequencePacket,
} from '../lib/health/davinci-pas-consequence-control.js';

const NOW = '2026-07-27T20:00:00.000Z';
const TENANT = 'org:pas-durability-test';
const OPERATION_ID = 'operation:pas-durability-test';
const CLAIM_PROFILE =
  'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/profile-claim|2.2.1';
const RESPONSE_PROFILE =
  'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/profile-claimresponse|2.2.1';
const REVIEW_ACTION_URL =
  'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/extension-reviewAction';
const REVIEW_ACTION_CODE_URL =
  'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/extension-reviewActionCode';
const X12_REVIEW_ACTION_SYSTEM = 'https://codesystem.x12.org/005010/306';
const DIGEST_A = `sha256:${'a'.repeat(64)}`;

function digest(value: unknown): string {
  return `sha256:${crypto.createHash('sha256').update(canonicalize(value)).digest('hex')}`;
}

function materialBinding(
  marker: string,
  operationId = OPERATION_ID,
): DavinciPasReviewBinding {
  const fieldDigest = `sha256:${marker.repeat(64)}`;
  const canonical = canonicalizeDavinciPasMaterialAction({
    action_type: DAVINCI_PAS_ACTION_TYPE,
    operation_id: operationId,
    rail: DAVINCI_PAS_MEDICAL_RAIL,
    ig_version: DAVINCI_PAS_IG_VERSION,
    pairwise_patient_ref: `pairwise:pas-durability-member-${marker.repeat(8)}`,
    claim_digest: fieldDigest,
    claim_identifier_digest: fieldDigest,
    claim_response_digest: fieldDigest,
    request_reference_digest: fieldDigest,
    service_request_digest: fieldDigest,
    decision_digest: fieldDigest,
    decision_outcome: 'approved',
    fhir_outcome: 'complete',
    policy_id: `policy:pas-durability-${marker}`,
    policy_version: '2026-07',
    policy_digest: fieldDigest,
  });
  return {
    '@type': DAVINCI_PAS_BINDING_TYPE,
    profile_id: DAVINCI_PAS_PROFILE_ID,
    ig: {
      package: 'hl7.fhir.us.davinci-pas',
      version: DAVINCI_PAS_IG_VERSION,
      fhir_release: 'R4',
      claim_profile: CLAIM_PROFILE,
      claim_response_profile: RESPONSE_PROFILE,
    },
    rail: DAVINCI_PAS_MEDICAL_RAIL,
    action: canonical.action,
    action_digest: canonical.action_digest,
    caid: canonical.caid,
  };
}

function proposalFor(binding: DavinciPasReviewBinding, suffix: string) {
  return {
    '@version': 'EMILIA-PROPOSAL-TO-EFFECT-v1',
    proposal_id: `proposal:pas-durability-${suffix}`,
    profile_id: DAVINCI_PAS_CONSEQUENCE_PROFILE_ID,
    operation_id: binding.action.operation_id,
    initiator_id: 'actor:pas-durability-test',
    action: structuredClone(binding.action),
    action_digest: binding.action_digest,
    aeb_action_digest: binding.action_digest,
    caid: binding.caid,
    created_at: NOW,
    expires_at: '2026-07-27T20:05:00.000Z',
    authorization: {},
    challenge: {},
    aeb: {},
    consequence: {
      tenant_id: TENANT,
      provider_id: 'provider:pas-synthetic-sandbox',
      provider_account_id: 'account:pas-durability-test',
      environment: 'sandbox',
      executor_id: 'executor:pas-durability-test',
      request_digest: digest({ request: suffix }),
    },
  };
}

function event(
  sequence: number,
  eventType: 'PREPARED' | 'EXECUTION' | 'RECONCILIATION',
  payload: Record<string, unknown>,
) {
  return {
    event_id: `sha256:${sequence.toString(16).padStart(64, '0')}`,
    sequence,
    tenant_id: TENANT,
    operation_id: OPERATION_ID,
    event_type: eventType,
    recorded_at: NOW,
    payload: structuredClone(payload),
  };
}

function preparedEvent(
  sequence: number,
  binding: DavinciPasReviewBinding,
  proposal: ReturnType<typeof proposalFor>,
) {
  return event(sequence, 'PREPARED', {
    binding,
    binding_digest: digest(binding),
    proposal,
    proposal_digest: digest(proposal),
    source_resources_retained: false,
  });
}

function terminalEvent(
  sequence: number,
  decision: string,
  binding: DavinciPasReviewBinding,
  proposal: ReturnType<typeof proposalFor>,
  attempt?: Record<string, unknown>,
) {
  return event(sequence, decision.startsWith('RECONCILED_') ? 'RECONCILIATION' : 'EXECUTION', {
    decision,
    proposal_digest: digest(proposal),
    binding_digest: digest(binding),
    action_caid: binding.caid,
    action_digest: binding.action_digest,
    ...(attempt ? {
      attempt,
      proposal_to_effect: {
        consequence: {
          state: decision === 'INDETERMINATE' ? 'INDETERMINATE' : 'COMMITTED',
          attempt,
        },
      },
    } : {}),
  });
}

function attemptFor(proposal: ReturnType<typeof proposalFor>) {
  return {
    tenant_id: TENANT,
    provider_id: proposal.consequence.provider_id,
    provider_account_id: proposal.consequence.provider_account_id,
    environment: proposal.consequence.environment,
    attempt_id: 'attempt:pas-durability-test',
    request_digest: proposal.consequence.request_digest,
  };
}

function providerEvidenceFor(
  proposal: ReturnType<typeof proposalFor>,
  attempt: ReturnType<typeof attemptFor>,
) {
  return {
    authenticated: true,
    evidence_id: `evidence:${attempt.attempt_id}`,
    observed_at: NOW,
    outcome: 'COMMITTED',
    operation_id: OPERATION_ID,
    caid: proposal.caid,
    action_digest: proposal.action_digest,
    tenant_id: TENANT,
    request_digest: proposal.consequence.request_digest,
    provider_id: proposal.consequence.provider_id,
    provider_account_id: proposal.consequence.provider_account_id,
    environment: proposal.consequence.environment,
    attempt_id: attempt.attempt_id,
  };
}

function rawPasContext() {
  const claim = {
    resourceType: 'Claim',
    id: 'pas-durability-claim',
    meta: { profile: [CLAIM_PROFILE] },
    identifier: [{
      system: 'https://payer.example.test/prior-auth',
      value: 'secret-pa-durability',
    }],
    status: 'active',
    type: {
      coding: [{
        system: 'http://terminology.hl7.org/CodeSystem/claim-type',
        code: 'professional',
      }],
    },
    use: 'preauthorization',
    patient: { reference: 'Patient/direct-durability-member' },
    created: '2026-07-27T19:30:00Z',
    insurer: { reference: 'Organization/payer-1' },
    provider: { reference: 'Organization/requesting-provider-1' },
    priority: {
      coding: [{
        system: 'http://terminology.hl7.org/CodeSystem/processpriority',
        code: 'normal',
      }],
    },
    diagnosis: [{
      sequence: 1,
      diagnosisCodeableConcept: {
        coding: [{
          system: 'http://hl7.org/fhir/sid/icd-10-cm',
          code: 'M17.11',
        }],
      },
    }],
    item: [{
      sequence: 1,
      productOrService: {
        coding: [{
          system: 'http://www.ama-assn.org/go/cpt',
          code: '27447',
        }],
      },
      servicedDate: '2026-08-15',
      quantity: { value: 1 },
    }],
  };
  const claimResponse = {
    resourceType: 'ClaimResponse',
    id: 'pas-durability-response',
    meta: { profile: [RESPONSE_PROFILE] },
    status: 'active',
    type: {
      coding: [{
        system: 'http://terminology.hl7.org/CodeSystem/claim-type',
        code: 'professional',
      }],
    },
    use: 'preauthorization',
    patient: { reference: 'Patient/direct-durability-member' },
    created: '2026-07-27T19:31:00Z',
    insurer: { reference: 'Organization/payer-1' },
    request: { reference: 'Claim/pas-durability-claim' },
    outcome: 'complete',
    extension: [],
    item: [{
      itemSequence: 1,
      adjudication: [{
        category: {
          coding: [{
            system: 'http://terminology.hl7.org/CodeSystem/adjudication',
            code: 'submitted',
          }],
        },
        extension: [{
          url: REVIEW_ACTION_URL,
          extension: [{
            url: REVIEW_ACTION_CODE_URL,
            valueCodeableConcept: {
              coding: [{ system: X12_REVIEW_ACTION_SYSTEM, code: 'A1' }],
            },
          }],
        }],
      }],
    }],
  };
  return {
    operation_id: OPERATION_ID,
    pairwise_patient_ref: 'pairwise:pas-durability-member-7H3k9Q2p',
    claim,
    claim_response: claimResponse,
    policy: {
      policy_id: 'policy:pas-durability',
      policy_version: '2026-07',
      policy_digest: DIGEST_A,
    },
  };
}

function defaultController(): any {
  return {
    prepare: vi.fn(),
    verifyProposal: vi.fn((proposal: any) => ({ proposal, profile: {} })),
    execute: vi.fn(async () => ({ ok: false, reason: 'not_configured' })),
    reconcile: vi.fn(async () => ({ ok: false, reason: 'not_configured' })),
    getReconciliationHandle: vi.fn(() => null),
  };
}

function makeControl({
  initialEvents,
  controller = defaultController(),
  appendFailure,
  initialHandle = null,
  recoveryStore,
  durable = false,
  mutate = vi.fn(async () => ({ ok: true })),
}: {
  initialEvents: ReturnType<typeof event>[];
  controller?: any;
  appendFailure?: (input: any) => boolean;
  initialHandle?: Record<string, unknown> | null;
  recoveryStore?: Record<string, unknown>;
  durable?: boolean;
  mutate?: any;
}) {
  const events = structuredClone(initialEvents);
  let handle = initialHandle ? structuredClone(initialHandle) : null;
  const append = vi.fn(async (input: any) => {
    if (appendFailure?.(input)) throw new Error('evidence_store_down');
    const appended = event(events.length + 1, input.event_type, input.payload);
    events.push(appended);
    return structuredClone(appended);
  });
  const getHandle = vi.fn(async () => (handle ? structuredClone(handle) : null));
  const putHandle = vi.fn(async (input: any) => {
    handle = structuredClone(input.handle);
  });
  const packetKey = crypto.generateKeyPairSync('ed25519');
  const control = createDavinciPasConsequenceControl({
    controller: controller as any,
    evidence_store: {
      appendOnly: true,
      tenantBound: true,
      durable,
      append,
      async list() {
        return structuredClone(events);
      },
    },
    reconciliation_handle_store: {
      serverSideOnly: true,
      durable,
      put: putHandle,
      get: getHandle,
    },
    ...(recoveryStore ? { consequence_attempt_store: recoveryStore } : {}),
    assurance: {
      relying_party_id: 'rp:pas-durability-test',
      signer: {
        algorithm: 'Ed25519',
        key_id: 'key:pas-durability-test',
        sign(bytes: Uint8Array) {
          return crypto.sign(null, Buffer.from(bytes), packetKey.privateKey).toString('base64url');
        },
      },
    },
    allow_ephemeral_stores_for_tests: !durable,
    now: () => Date.parse(NOW),
    mutate_pas_sandbox: mutate,
  } as any);
  return {
    append,
    control,
    controller,
    events,
    getHandle,
    mutate,
    packetKey,
    putHandle,
  };
}

function resignPacket(packet: any, privateKey: crypto.KeyObject) {
  const body = structuredClone(packet);
  delete body.packet_digest;
  delete body.proof;
  packet.packet_digest = digest(body);
  const bytes = Buffer.from(
    `${DAVINCI_PAS_CONSEQUENCE_PACKET_VERSION}:SIGNATURE\0${canonicalize({
      packet_digest: packet.packet_digest,
      body,
    })}`,
  );
  packet.proof = {
    alg: 'Ed25519',
    key_id: 'key:pas-durability-test',
    signature_b64u: crypto.sign(null, bytes, privateKey).toString('base64url'),
  };
}

describe('Da Vinci PAS durability and semantic security', () => {
  it('exports only the prepared binding selected by the terminal proposal and binding digests', async () => {
    const bindingA = materialBinding('a');
    const bindingB = materialBinding('b');
    const proposalA = proposalFor(bindingA, 'a');
    const proposalB = proposalFor(bindingB, 'b');
    const fixture = makeControl({
      initialEvents: [
        preparedEvent(1, bindingA, proposalA),
        preparedEvent(2, bindingB, proposalB),
        terminalEvent(3, 'EXECUTED', bindingB, proposalB, attemptFor(proposalB)),
      ],
    });

    const packet = await fixture.control.exportReliancePacket({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
    });

    expect(packet).toMatchObject({
      binding: bindingB,
      binding_digest: digest(bindingB),
      proposal_digest: digest(proposalB),
      caid: bindingB.caid,
      action_digest: bindingB.action_digest,
    });

    const uncorrelated = terminalEvent(
      3,
      'EXECUTED',
      bindingB,
      proposalB,
      attemptFor(proposalB),
    );
    uncorrelated.payload.proposal_digest = digest({ substituted: true });
    const refused = makeControl({
      initialEvents: [
        preparedEvent(1, bindingA, proposalA),
        preparedEvent(2, bindingB, proposalB),
        uncorrelated,
      ],
    });
    await expect(refused.control.exportReliancePacket({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
    })).resolves.toMatchObject({
      ok: false,
      decision: 'REFUSED',
      reason: 'pas_reliance_packet_not_available',
    });
  });

  it('rejects signed semantic substitutions, PHI, and malformed packet fields', async () => {
    const binding = materialBinding('c');
    const proposal = proposalFor(binding, 'semantic');
    const fixture = makeControl({
      initialEvents: [
        preparedEvent(1, binding, proposal),
        terminalEvent(2, 'EXECUTED', binding, proposal, attemptFor(proposal)),
      ],
    });
    const packet = await fixture.control.exportReliancePacket({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
    });
    const pin = {
      relying_party_id: 'rp:pas-durability-test',
      key_id: 'key:pas-durability-test',
      public_key_spki_b64u: fixture.packetKey.publicKey
        .export({ type: 'spki', format: 'der' })
        .toString('base64url'),
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
    };
    expect(verifyDavinciPasConsequencePacket(packet, pin)).toEqual({
      valid: true,
      reasons: [],
    });

    const cases: Array<{
      name: string;
      reason: string;
      mutate(candidate: any): void;
    }> = [
      {
        name: 'profile',
        reason: 'packet_profile_invalid',
        mutate(candidate) {
          candidate.profile_id = 'healthcare.substituted';
        },
      },
      {
        name: 'decision',
        reason: 'packet_decision_invalid',
        mutate(candidate) {
          candidate.decision = 'EXECUTING';
        },
      },
      {
        name: 'tenant',
        reason: 'packet_tenant_mismatch',
        mutate(candidate) {
          candidate.tenant_id = 'org:other-tenant';
        },
      },
      {
        name: 'operation',
        reason: 'packet_operation_mismatch',
        mutate(candidate) {
          candidate.operation_id = 'operation:other';
        },
      },
      {
        name: 'binding',
        reason: 'packet_binding_invalid',
        mutate(candidate) {
          candidate.binding.debug_context = 'not-allowlisted';
          candidate.binding_digest = digest(candidate.binding);
        },
      },
      {
        name: 'CAID',
        reason: 'packet_caid_invalid',
        mutate(candidate) {
          candidate.caid = candidate.caid.replace(/.$/, 'A');
        },
      },
      {
        name: 'action digest',
        reason: 'packet_action_digest_invalid',
        mutate(candidate) {
          candidate.action_digest = `sha256:${'0'.repeat(64)}`;
        },
      },
      {
        name: 'binding digest',
        reason: 'packet_binding_digest_invalid',
        mutate(candidate) {
          candidate.binding_digest = `sha256:${'0'.repeat(64)}`;
        },
      },
      {
        name: 'event root',
        reason: 'packet_event_root_invalid',
        mutate(candidate) {
          candidate.event_root = `sha256:${'0'.repeat(64)}`;
        },
      },
      {
        name: 'PHI',
        reason: 'packet_contains_prohibited_phi',
        mutate(candidate) {
          candidate.patient_name = 'Alice Example';
        },
      },
      {
        name: 'malformed event count',
        reason: 'packet_shape_invalid',
        mutate(candidate) {
          candidate.event_count = '2';
        },
      },
    ];

    for (const candidateCase of cases) {
      const candidate = structuredClone(packet);
      candidateCase.mutate(candidate);
      resignPacket(candidate, fixture.packetKey.privateKey);
      expect(
        verifyDavinciPasConsequencePacket(candidate, pin),
        candidateCase.name,
      ).toMatchObject({
        valid: false,
        reasons: expect.arrayContaining([candidateCase.reason]),
      });
    }
  });

  it('preserves committed execution truth when the assurance event append fails', async () => {
    const context = rawPasContext();
    const built = buildDavinciPasReviewBinding(context);
    if (!built.ok) throw new Error(built.reasons.join(','));
    const proposal = proposalFor(built.binding, 'committed');
    const attempt = attemptFor(proposal);
    const controller = defaultController();
    controller.execute.mockImplementation(async (_input: any, effect: any) => {
      await effect({
        action: structuredClone(proposal.action),
        authorization: { allow: true },
        attempt: structuredClone(attempt),
        proposal: structuredClone(proposal),
      });
      return {
        ok: true,
        consequence: { state: 'COMMITTED', attempt: structuredClone(attempt) },
      };
    });
    const mutate = vi.fn(async () => ({ system_of_record_reference: 'pas:committed' }));
    const fixture = makeControl({
      initialEvents: [preparedEvent(1, built.binding, proposal)],
      controller,
      appendFailure: (input) => input.event_type === 'EXECUTION',
      mutate,
    });

    const result = await fixture.control.execute({
      tenant_id: TENANT,
      proposal,
      approval_evidence: { receipt_id: 'receipt:pas-durability-test' },
      evaluation: { verdict: 'SATISFIED' },
      server_observed_pas: context,
    });

    expect(result).toMatchObject({
      ok: true,
      decision: 'EXECUTED',
      reason: 'pas_assurance_record_unavailable',
      assurance_recorded: false,
      reconciliation_required: false,
      retry_safe: false,
    });
    expect(mutate).toHaveBeenCalledTimes(1);
  });

  it('refuses every protected-callback substitution before the PAS mutation', async () => {
    const context = rawPasContext();
    const built = buildDavinciPasReviewBinding(context);
    if (!built.ok) throw new Error(built.reasons.join(','));
    const proposal = proposalFor(built.binding, 'callback-binding');
    const baselineAttempt = attemptFor(proposal);
    const cases: Array<{
      name: string;
      mutate(input: { action: any; proposal: any; attempt: any }): void;
    }> = [
      {
        name: 'callback proposal operation',
        mutate(input) { input.proposal.operation_id = 'operation:pas-substituted'; },
      },
      {
        name: 'callback proposal CAID',
        mutate(input) { input.proposal.caid = materialBinding('f').caid; },
      },
      {
        name: 'callback action',
        mutate(input) { input.action.policy_version = '2026-08'; },
      },
      {
        name: 'attempt tenant',
        mutate(input) { input.attempt.tenant_id = 'org:other-tenant'; },
      },
      {
        name: 'attempt provider',
        mutate(input) { input.attempt.provider_id = 'provider:other'; },
      },
      {
        name: 'attempt provider account',
        mutate(input) { input.attempt.provider_account_id = 'account:other'; },
      },
      {
        name: 'attempt environment',
        mutate(input) { input.attempt.environment = 'production'; },
      },
      {
        name: 'attempt request digest',
        mutate(input) { input.attempt.request_digest = `sha256:${'0'.repeat(64)}`; },
      },
    ];

    for (const candidate of cases) {
      const controller = defaultController();
      controller.execute.mockImplementation(async (_input: any, effect: any) => {
        const callback = {
          action: structuredClone(proposal.action),
          authorization: { allow: true },
          attempt: structuredClone(baselineAttempt),
          proposal: structuredClone(proposal),
        };
        candidate.mutate(callback);
        await effect(callback);
        return {
          ok: true,
          consequence: { state: 'COMMITTED', attempt: callback.attempt },
        };
      });
      const fixture = makeControl({
        initialEvents: [preparedEvent(1, built.binding, proposal)],
        controller,
      });

      await expect(fixture.control.execute({
        tenant_id: TENANT,
        proposal,
        approval_evidence: { receipt_id: 'receipt:pas-durability-test' },
        evaluation: { verdict: 'SATISFIED' },
        server_observed_pas: context,
      }), candidate.name).resolves.toMatchObject({
        ok: false,
        decision: 'REFUSED',
        reason: 'pas_protected_callback_binding_mismatch',
      });
      expect(fixture.mutate, candidate.name).not.toHaveBeenCalled();
    }
  });

  it('preserves reconciled terminal truth when the assurance event append fails', async () => {
    const binding = materialBinding('d');
    const proposal = proposalFor(binding, 'reconciled');
    const attempt = attemptFor(proposal);
    const handle = {
      tenant_id: TENANT,
      attempt_id: attempt.attempt_id,
      owner: 'owner:pas-durability-test',
    };
    const controller = defaultController();
    controller.reconcile.mockResolvedValue({
      ok: true,
      state: 'COMMITTED',
      evidence_digest: digest({ provider: 'confirmed' }),
      consequence: { state: 'COMMITTED', attempt },
    });
    const fixture = makeControl({
      initialEvents: [
        preparedEvent(1, binding, proposal),
        terminalEvent(2, 'INDETERMINATE', binding, proposal, attempt),
      ],
      controller,
      initialHandle: handle,
      appendFailure: (input) => input.event_type === 'RECONCILIATION',
    });

    const result = await fixture.control.reconcile({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
      proposal,
      evaluation: { verdict: 'SATISFIED' },
      provider_evidence: providerEvidenceFor(proposal, attempt),
    });

    expect(result).toMatchObject({
      ok: true,
      decision: 'RECONCILED_EXECUTED',
      reason: 'pas_assurance_record_unavailable',
      assurance_recorded: false,
      reconciliation_required: false,
      retry_safe: false,
    });
  });

  it('recovers durable INVOKING custody through lookup/recover and reconciles without replay', async () => {
    const binding = materialBinding('e');
    const proposal = proposalFor(binding, 'restart');
    const attempt = attemptFor(proposal);
    const recoveryStore = {
      durable: true,
      lookup: vi.fn(async () => structuredClone(attempt)),
      read: vi.fn(async () => ({ state: 'INVOKING' })),
      recover: vi.fn(async () => ({
        recovered: true,
        owner: 'owner:pas-recovered',
        state: 'INDETERMINATE',
      })),
    };
    const controller = defaultController();
    controller.reconcile.mockImplementation(async (input: any) => {
      expect(input.attempt).toEqual({
        tenant_id: TENANT,
        attempt_id: attempt.attempt_id,
        owner: 'owner:pas-recovered',
      });
      return {
        ok: true,
        state: 'COMMITTED',
        evidence_digest: digest(input.provider_evidence),
        consequence: { state: 'COMMITTED', attempt },
      };
    });
    const mutate = vi.fn();
    const fixture = makeControl({
      initialEvents: [preparedEvent(1, binding, proposal)],
      controller,
      recoveryStore,
      durable: true,
      mutate,
    });
    const providerEvidence = providerEvidenceFor(proposal, attempt);

    const hostile = await fixture.control.reconcile({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
      proposal,
      evaluation: { verdict: 'SATISFIED' },
      provider_evidence: {
        ...providerEvidence,
        attempt_id: 'attempt:substituted',
      },
    });
    expect(hostile).toMatchObject({
      ok: false,
      decision: 'INDETERMINATE',
      reason: 'provider_evidence_binding_mismatch',
    });
    expect(recoveryStore.read).not.toHaveBeenCalled();
    expect(recoveryStore.recover).not.toHaveBeenCalled();
    expect(controller.reconcile).not.toHaveBeenCalled();
    expect(mutate).not.toHaveBeenCalled();

    const result = await fixture.control.reconcile({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
      proposal,
      evaluation: { verdict: 'SATISFIED' },
      provider_evidence: providerEvidence,
    });

    expect(result).toMatchObject({
      ok: true,
      decision: 'RECONCILED_EXECUTED',
      authenticated_provider_evidence: true,
    });
    expect(recoveryStore.lookup).toHaveBeenCalledWith({
      tenant_id: TENANT,
      provider_id: proposal.consequence.provider_id,
      provider_account_id: proposal.consequence.provider_account_id,
      environment: 'sandbox',
      request_digest: proposal.consequence.request_digest,
    });
    expect(recoveryStore.recover).toHaveBeenCalledWith(attempt);
    expect(fixture.putHandle).toHaveBeenCalledWith({
      tenant_id: TENANT,
      operation_id: OPERATION_ID,
      handle: {
        tenant_id: TENANT,
        attempt_id: attempt.attempt_id,
        owner: 'owner:pas-recovered',
      },
    });
    expect(controller.execute).not.toHaveBeenCalled();
    expect(mutate).not.toHaveBeenCalled();
    expect(fixture.events).toEqual(expect.arrayContaining([
      expect.objectContaining({
        event_type: 'EXECUTION',
        payload: expect.objectContaining({
          decision: 'INDETERMINATE',
          recovery: {
            from_state: 'INVOKING',
            method: 'durable_attempt_store',
            effect_replayed: false,
          },
        }),
      }),
    ]));
  });
});
