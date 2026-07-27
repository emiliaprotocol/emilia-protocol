// SPDX-License-Identifier: Apache-2.0
/**
 * Synthetic Da Vinci PAS consequence-control reference.
 *
 * Raw FHIR resources are server-side inputs only. This module projects them to
 * a closed, PHI-minimized action, hands consequence custody to the existing
 * Proposal-to-Effect controller, and stores only portable bindings/digests.
 */

import crypto from 'node:crypto';
import type {
  ConsequenceAttemptBinding,
  ConsequenceAttemptReference,
  ProposalToEffectProfile,
  ProposalToEffectProposal,
} from '../../packages/gate/proposal-to-effect.js';
import { canonicalize } from '../canonical-json.js';
import {
  DAVINCI_PAS_ACTION_TYPE,
  type DavinciPasReviewBinding,
  buildDavinciPasReviewBinding,
  canonicalizeDavinciPasMaterialAction,
  verifyDavinciPasReviewBinding,
} from './davinci-pas-binding.js';
import type {
  HealthcareAssuranceSigner,
  HealthcareEvidenceEvent,
  HealthcareEvidenceStore,
  HealthcareReconciliationHandleStore,
  ProposalToEffectController,
} from './proposal-to-effect-profile.js';

type JsonObject = Record<string, any>;

export const DAVINCI_PAS_CONSEQUENCE_PROFILE_ID =
  'healthcare.davinci-pas-review.consequence-control.v1';
export const DAVINCI_PAS_AEB_REQUIREMENT_REF =
  'requirement:healthcare-davinci-pas-consequence-control';
export const DAVINCI_PAS_CONSEQUENCE_PACKET_VERSION =
  'EMILIA-DAVINCI-PAS-CONSEQUENCE-PACKET-v1';
export const DAVINCI_PAS_CONSEQUENCE_CONTROL_VERSION =
  'EMILIA-DAVINCI-PAS-CONSEQUENCE-CONTROL-v1';

export const DAVINCI_PAS_CONSEQUENCE_LIMITATIONS = Object.freeze([
  'This packet covers a PHI-free synthetic Da Vinci PAS 2.2.1 reference path, not a live payer, provider, EHR, or utilization-management deployment.',
  'The PAS binding records the exact server-observed administrative decision and accepted reviewer evidence; it does not establish medical necessity, clinical correctness, source-system truth, or regulatory compliance.',
  'EXECUTED means the configured protected callback completed and Proposal-to-Effect committed its exact operation; INDETERMINATE proves neither success nor failure and requires authenticated reconciliation.',
  'The packet is relying-party evidence, not an audit opinion, certification, insurance coverage decision, or legal conclusion.',
] as const);

const REQUIRED_ACTION_FIELDS = Object.freeze([
  'action_type',
  'operation_id',
  'rail',
  'ig_version',
  'pairwise_patient_ref',
  'claim_digest',
  'claim_identifier_digest',
  'claim_response_digest',
  'request_reference_digest',
  'service_request_digest',
  'decision_digest',
  'decision_outcome',
  'fhir_outcome',
  'policy_id',
  'policy_version',
  'policy_digest',
] as const);
const OPTIONAL_ACTION_FIELDS = Object.freeze([
  'reviewer_ref',
  'reviewer_fhir_identity_digest',
  'reviewer_identity_evidence_digest',
  'reviewer_authority_evidence_digest',
  'reviewer_authority_scope',
] as const);
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
const DIGEST_RE = /^sha256:[a-f0-9]{64}$/;
const EXPORTABLE_DECISIONS = new Set([
  'EXECUTED',
  'INDETERMINATE',
  'RECONCILED_EXECUTED',
  'RECONCILED_NOT_EXECUTED',
]);
const SIGNATURE_DOMAIN = `${DAVINCI_PAS_CONSEQUENCE_PACKET_VERSION}:SIGNATURE\0`;

function clone<T>(value: T): T {
  return structuredClone(value);
}

function isObject(value: unknown): value is JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function identifier(value: unknown): value is string {
  return typeof value === 'string' && IDENTIFIER_RE.test(value);
}

function digest(value: unknown): string {
  return `sha256:${crypto.createHash('sha256').update(canonicalize(value)).digest('hex')}`;
}

function refusal(reason: string, extras: JsonObject = {}): JsonObject {
  return { ok: false, decision: 'REFUSED', reason, ...extras };
}

function safeReason(error: unknown, fallback: string): string {
  const value = error instanceof Error ? error.message : '';
  return /^[a-z0-9][a-z0-9:_-]{2,127}$/i.test(value)
    ? value.toLowerCase()
    : fallback;
}

function signerShape(value: unknown): value is HealthcareAssuranceSigner {
  return isObject(value)
    && value.algorithm === 'Ed25519'
    && identifier(value.key_id)
    && typeof value.sign === 'function';
}

function publicAttempt(value: unknown): ConsequenceAttemptBinding | null {
  if (!isObject(value)) return null;
  const fields = [
    'tenant_id',
    'provider_id',
    'provider_account_id',
    'environment',
    'attempt_id',
    'request_digest',
  ];
  if (!fields.every((field) => typeof value[field] === 'string')) return null;
  return Object.fromEntries(
    fields.map((field) => [field, value[field]]),
  ) as unknown as ConsequenceAttemptBinding;
}

function projectControllerResult(value: unknown): JsonObject {
  if (!isObject(value)) return {};
  const result: JsonObject = {};
  for (const field of ['ok', 'reason', 'state', 'outcome', 'evidence_digest']) {
    if (typeof value[field] === 'string' || typeof value[field] === 'boolean') {
      result[field] = value[field];
    }
  }
  const attempt = publicAttempt(value.consequence?.attempt);
  if (isObject(value.consequence)) {
    result.consequence = {
      ...(identifier(value.consequence.state) ? { state: value.consequence.state } : {}),
      ...(attempt ? { attempt } : {}),
    };
  }
  return result;
}

function bindingFromContext(value: unknown): DavinciPasReviewBinding {
  const built = buildDavinciPasReviewBinding(value);
  if (!built.ok) {
    throw new Error(`pas_binding_invalid:${built.reasons[0] ?? 'unknown'}`);
  }
  const verified = verifyDavinciPasReviewBinding(built.binding, value);
  if (!verified.valid) {
    throw new Error(`pas_binding_invalid:${verified.reasons[0] ?? 'unknown'}`);
  }
  return built.binding;
}

export function createDavinciPasProposalToEffectProfile({
  authorization_endpoint,
  ttl_sec = 300,
}: {
  authorization_endpoint: string;
  ttl_sec?: number;
}): ProposalToEffectProfile {
  let endpoint: URL;
  try {
    endpoint = new URL(authorization_endpoint);
  } catch {
    throw new Error('pas_authorization_endpoint_invalid');
  }
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password
      || endpoint.hash || endpoint.origin === 'null') {
    throw new Error('pas_authorization_endpoint_invalid');
  }
  if (!Number.isSafeInteger(ttl_sec) || ttl_sec < 1 || ttl_sec > 900) {
    throw new Error('pas_proposal_ttl_invalid');
  }
  return Object.freeze({
    id: DAVINCI_PAS_CONSEQUENCE_PROFILE_ID,
    action_type: DAVINCI_PAS_ACTION_TYPE,
    selector: Object.freeze({
      action_type: DAVINCI_PAS_ACTION_TYPE,
      protocol: 'https',
      method: 'POST',
      path: '/api/v1/adapters/health/davinci-pas/review',
    }),
    required_fields: REQUIRED_ACTION_FIELDS,
    authorization: Object.freeze({
      authorization_endpoint: endpoint.toString(),
      flow: 'EP-APPROVAL-v1' as const,
    }),
    aeb_requirement_ref: DAVINCI_PAS_AEB_REQUIREMENT_REF,
    ttl_sec,
    canonicalize_action(input: unknown) {
      const canonical = canonicalizeDavinciPasMaterialAction(input);
      return { action: canonical.action, caid: canonical.caid };
    },
  });
}

export interface DavinciPasConsequenceControlOptions {
  controller: ProposalToEffectController;
  evidence_store: HealthcareEvidenceStore;
  reconciliation_handle_store: HealthcareReconciliationHandleStore;
  assurance: {
    relying_party_id: string;
    signer: HealthcareAssuranceSigner;
  };
  mutate_pas_sandbox(input: {
    tenant_id: string;
    operation_id: string;
    binding: DavinciPasReviewBinding;
    action: JsonObject;
    authorization: JsonObject;
    attempt: ConsequenceAttemptBinding;
  }): Promise<unknown> | unknown;
  now?: () => number;
  allow_ephemeral_stores_for_tests?: boolean;
}

function preparedContext(
  events: HealthcareEvidenceEvent[],
  proposal: ProposalToEffectProposal,
  tenantId: string,
): { binding: DavinciPasReviewBinding; proposal_digest: string } | null {
  const event = [...events].reverse().find((candidate) => (
    candidate.event_type === 'PREPARED'
      && candidate.payload?.proposal_digest === digest(proposal)
  ));
  if (!event || event.tenant_id !== tenantId
      || event.operation_id !== proposal.operation_id
      || !isObject(event.payload?.binding)) return null;
  try {
    const canonical = canonicalizeDavinciPasMaterialAction(event.payload.binding.action);
    if (canonical.caid !== proposal.caid
        || canonical.action_digest !== proposal.action_digest
        || canonical.action_digest !== proposal.aeb_action_digest
        || event.payload.binding.caid !== proposal.caid
        || event.payload.binding.action_digest !== proposal.action_digest) return null;
  } catch {
    return null;
  }
  return {
    binding: clone(event.payload.binding) as DavinciPasReviewBinding,
    proposal_digest: event.payload.proposal_digest,
  };
}

export function createDavinciPasConsequenceControl(
  options: DavinciPasConsequenceControlOptions,
) {
  if (!options?.controller
      || typeof options.controller.prepare !== 'function'
      || typeof options.controller.verifyProposal !== 'function'
      || typeof options.controller.execute !== 'function'
      || typeof options.controller.reconcile !== 'function'
      || typeof options.controller.getReconciliationHandle !== 'function') {
    throw new Error('pas_proposal_to_effect_controller_required');
  }
  if (!options.evidence_store
      || options.evidence_store.appendOnly !== true
      || options.evidence_store.tenantBound !== true
      || typeof options.evidence_store.append !== 'function'
      || typeof options.evidence_store.list !== 'function') {
    throw new Error('pas_evidence_store_required');
  }
  if (!options.reconciliation_handle_store
      || options.reconciliation_handle_store.serverSideOnly !== true
      || typeof options.reconciliation_handle_store.put !== 'function'
      || typeof options.reconciliation_handle_store.get !== 'function') {
    throw new Error('pas_reconciliation_handle_store_required');
  }
  if (options.allow_ephemeral_stores_for_tests !== true
      && (options.evidence_store.durable !== true
        || options.reconciliation_handle_store.durable !== true)) {
    throw new Error('pas_durable_stores_required');
  }
  if (!options.assurance
      || !identifier(options.assurance.relying_party_id)
      || !signerShape(options.assurance.signer)) {
    throw new Error('pas_assurance_signer_required');
  }
  if (typeof options.mutate_pas_sandbox !== 'function') {
    throw new Error('pas_sandbox_mutation_required');
  }
  const now = options.now ?? Date.now;

  function timestamp(): string {
    const value = now();
    if (!Number.isSafeInteger(value) || !Number.isFinite(new Date(value).getTime())) {
      throw new Error('pas_clock_invalid');
    }
    return new Date(value).toISOString();
  }

  async function eventsFor(tenantId: string, operationId: string) {
    return options.evidence_store.list({ tenant_id: tenantId, operation_id: operationId });
  }

  async function append(input: Omit<HealthcareEvidenceEvent, 'event_id' | 'sequence'>) {
    return options.evidence_store.append(clone(input));
  }

  async function prepare(input: {
    tenant_id: string;
    initiator_id: string;
    proposal_id: string;
    operation_id: string;
    server_observed_pas: unknown;
  }): Promise<JsonObject> {
    if (!identifier(input?.tenant_id)) return refusal('tenant_required');
    if (!identifier(input?.initiator_id)) return refusal('authenticated_initiator_required');
    if (!identifier(input?.proposal_id) || !identifier(input?.operation_id)) {
      return refusal('pas_operation_identity_invalid');
    }
    let binding: DavinciPasReviewBinding;
    try {
      binding = bindingFromContext(input.server_observed_pas);
    } catch (error) {
      return refusal(safeReason(error, 'pas_preparation_refused'));
    }
    if (binding.action.operation_id !== input.operation_id) {
      return refusal('pas_operation_binding_mismatch');
    }
    let proposal: ProposalToEffectProposal;
    try {
      proposal = options.controller.prepare({
        proposal_id: input.proposal_id,
        profile_id: DAVINCI_PAS_CONSEQUENCE_PROFILE_ID,
        operation_id: input.operation_id,
        initiator_id: input.initiator_id,
        action: binding.action,
      });
      const verified = options.controller.verifyProposal(proposal).proposal;
      if (verified.caid !== binding.caid
          || verified.action_digest !== binding.action_digest
          || verified.aeb_action_digest !== binding.action_digest
          || verified.consequence.tenant_id !== input.tenant_id
          || verified.consequence.environment !== 'sandbox') {
        return refusal('pas_proposal_binding_mismatch');
      }
    } catch (error) {
      return refusal(safeReason(error, 'pas_proposal_preparation_failed'));
    }
    try {
      await append({
        tenant_id: input.tenant_id,
        operation_id: input.operation_id,
        event_type: 'PREPARED',
        recorded_at: timestamp(),
        payload: {
          binding: clone(binding),
          binding_digest: digest(binding),
          proposal: clone(proposal),
          proposal_digest: digest(proposal),
          source_resources_retained: false,
        },
      });
    } catch {
      return refusal('pas_evidence_store_unavailable');
    }
    return {
      ok: true,
      decision: 'APPROVAL_REQUIRED',
      binding,
      proposal,
      authorization: clone(proposal.authorization),
      challenge: clone(proposal.challenge),
    };
  }

  async function execute(input: {
    tenant_id: string;
    proposal: unknown;
    approval_evidence: unknown;
    evaluation: unknown;
    server_observed_pas: unknown;
  }): Promise<JsonObject> {
    if (!identifier(input?.tenant_id)) return refusal('tenant_required');
    if (!isObject(input?.approval_evidence)) return refusal('approval_evidence_required');
    if (!isObject(input?.evaluation)) return refusal('aeb_evaluation_required');
    let proposal: ProposalToEffectProposal;
    try {
      proposal = options.controller.verifyProposal(input.proposal).proposal;
    } catch (error) {
      return refusal(safeReason(error, 'pas_execution_input_refused'));
    }
    let observed: DavinciPasReviewBinding;
    try {
      observed = bindingFromContext(input.server_observed_pas);
    } catch {
      return refusal('pas_execution_binding_mismatch');
    }
    if (proposal.consequence.tenant_id !== input.tenant_id
        || proposal.consequence.environment !== 'sandbox') {
      return refusal('tenant_or_environment_mismatch');
    }
    const events = await eventsFor(input.tenant_id, proposal.operation_id)
      .catch(() => null);
    const prepared = events
      ? preparedContext(events, proposal, input.tenant_id)
      : null;
    if (!prepared) return refusal('pas_prepared_context_mismatch');
    if (observed.caid !== proposal.caid
        || observed.action_digest !== proposal.action_digest
        || observed.action_digest !== proposal.aeb_action_digest
        || digest(observed) !== digest(prepared.binding)) {
      return refusal('pas_execution_binding_mismatch');
    }

    const baseEvidence = {
      approval_evidence_digest: digest(input.approval_evidence),
      aeb_evaluation_digest: digest(input.evaluation),
      proposal_digest: digest(proposal),
      binding_digest: digest(observed),
    };
    try {
      const result = await options.controller.execute({
        proposal,
        receipt: input.approval_evidence,
        evaluation: input.evaluation,
      }, async ({ action, authorization, attempt, proposal: callbackProposal }) => {
        const callback = canonicalizeDavinciPasMaterialAction(action);
        if (callbackProposal.operation_id !== proposal.operation_id
            || callbackProposal.caid !== proposal.caid
            || callback.caid !== observed.caid
            || callback.action_digest !== observed.action_digest
            || attempt.tenant_id !== input.tenant_id
            || attempt.provider_id !== proposal.consequence.provider_id
            || attempt.provider_account_id !== proposal.consequence.provider_account_id
            || attempt.environment !== 'sandbox'
            || attempt.request_digest !== proposal.consequence.request_digest) {
          throw new Error('pas_protected_callback_binding_mismatch');
        }
        return options.mutate_pas_sandbox({
          tenant_id: input.tenant_id,
          operation_id: proposal.operation_id,
          binding: clone(observed),
          action: clone(callback.action),
          authorization: clone(authorization),
          attempt: clone(attempt),
        });
      });
      const projected = projectControllerResult(result);
      const state = projected.consequence?.state;
      const attempt = publicAttempt(projected.consequence?.attempt);
      if (state === 'COMMITTED') {
        try {
          await append({
            tenant_id: input.tenant_id,
            operation_id: proposal.operation_id,
            event_type: 'EXECUTION',
            recorded_at: timestamp(),
            payload: {
              ...baseEvidence,
              decision: 'EXECUTED',
              proposal_to_effect: projected,
              attempt,
            },
          });
        } catch {
          return {
            ok: false,
            decision: 'INDETERMINATE',
            reason: 'pas_assurance_record_unavailable',
            operation_id: proposal.operation_id,
            action_caid: proposal.caid,
            reconciliation_required: true,
            retry_safe: false,
          };
        }
        return {
          ok: true,
          decision: 'EXECUTED',
          operation_id: proposal.operation_id,
          action_caid: proposal.caid,
          attempt,
          reconciliation_required: false,
          retry_safe: false,
        };
      }
      return refusal(
        identifier(projected.reason) ? projected.reason : 'proposal_to_effect_refused',
        { operation_id: proposal.operation_id, action_caid: proposal.caid },
      );
    } catch (error) {
      const metadata = isObject((error as any)?.proposalToEffect)
        ? (error as any).proposalToEffect
        : {};
      const attempt = publicAttempt(metadata.attempt);
      if (metadata.attempt_state !== 'INDETERMINATE' || !attempt) {
        return refusal(safeReason(error, 'proposal_to_effect_refused'), {
          operation_id: proposal.operation_id,
          action_caid: proposal.caid,
        });
      }
      const handle = options.controller.getReconciliationHandle(error as object);
      if (handle) {
        await options.reconciliation_handle_store.put({
          tenant_id: input.tenant_id,
          operation_id: proposal.operation_id,
          handle,
        }).catch(() => undefined);
      }
      await append({
        tenant_id: input.tenant_id,
        operation_id: proposal.operation_id,
        event_type: 'EXECUTION',
        recorded_at: timestamp(),
        payload: {
          ...baseEvidence,
          decision: 'INDETERMINATE',
          proposal_to_effect: {
            consequence: { state: 'INDETERMINATE', attempt },
          },
          attempt,
        },
      }).catch(() => undefined);
      return {
        ok: false,
        decision: 'INDETERMINATE',
        reason: 'provider_outcome_indeterminate',
        operation_id: proposal.operation_id,
        action_caid: proposal.caid,
        attempt,
        reconciliation_required: true,
        retry_safe: false,
      };
    }
  }

  async function reconcile(input: {
    tenant_id: string;
    operation_id: string;
    proposal: unknown;
    evaluation: unknown;
    provider_evidence: unknown;
  }): Promise<JsonObject> {
    if (!identifier(input?.tenant_id)) return refusal('tenant_required');
    if (!identifier(input?.operation_id)) return refusal('operation_id_required');
    if (!isObject(input?.evaluation)) return refusal('aeb_evaluation_required');
    if (!isObject(input?.provider_evidence)) {
      return refusal('authenticated_provider_evidence_required');
    }
    let proposal: ProposalToEffectProposal;
    try {
      proposal = options.controller.verifyProposal(input.proposal, { allowExpired: true }).proposal;
    } catch (error) {
      return refusal(safeReason(error, 'pas_reconciliation_input_refused'));
    }
    if (proposal.consequence.tenant_id !== input.tenant_id
        || proposal.operation_id !== input.operation_id) {
      return refusal('reconciliation_operation_mismatch');
    }
    const events = await eventsFor(input.tenant_id, input.operation_id)
      .catch(() => null);
    if (!events || !preparedContext(events, proposal, input.tenant_id)) {
      return refusal('pas_prepared_context_mismatch');
    }
    const indeterminate = [...events].reverse().find((event) => (
      event.event_type === 'EXECUTION'
        && event.payload?.decision === 'INDETERMINATE'
    ));
    const attempt = publicAttempt(indeterminate?.payload?.attempt);
    if (!indeterminate || !attempt) return refusal('reconciliation_not_indeterminate');
    if (input.provider_evidence.operation_id !== input.operation_id
        || input.provider_evidence.attempt_id !== attempt.attempt_id) {
      return {
        ok: false,
        decision: 'INDETERMINATE',
        reason: 'provider_evidence_binding_mismatch',
        reconciliation_required: true,
        retry_safe: false,
      };
    }
    const handle = await options.reconciliation_handle_store.get({
      tenant_id: input.tenant_id,
      operation_id: input.operation_id,
    }).catch(() => null);
    if (!handle || handle.tenant_id !== input.tenant_id
        || handle.attempt_id !== attempt.attempt_id) {
      return {
        ok: false,
        decision: 'INDETERMINATE',
        reason: 'reconciliation_handle_unavailable',
        reconciliation_required: true,
        retry_safe: false,
      };
    }
    let result: JsonObject;
    try {
      result = await options.controller.reconcile({
        proposal,
        evaluation: input.evaluation,
        attempt: handle,
        provider_evidence: input.provider_evidence,
      });
    } catch {
      return {
        ok: false,
        decision: 'INDETERMINATE',
        reason: 'provider_evidence_unverified',
        reconciliation_required: true,
        retry_safe: false,
      };
    }
    if (result.ok !== true) {
      return {
        ok: false,
        decision: 'INDETERMINATE',
        reason: identifier(result.reason) ? result.reason : 'provider_evidence_unverified',
        reconciliation_required: true,
        retry_safe: false,
      };
    }
    const decision = result.state === 'COMMITTED'
      ? 'RECONCILED_EXECUTED'
      : result.state === 'RELEASED'
        ? 'RECONCILED_NOT_EXECUTED'
        : 'INDETERMINATE';
    const projected = projectControllerResult(result);
    const evidenceDigest = DIGEST_RE.test(result.evidence_digest)
      ? result.evidence_digest
      : digest(input.provider_evidence);
    try {
      await append({
        tenant_id: input.tenant_id,
        operation_id: input.operation_id,
        event_type: 'RECONCILIATION',
        recorded_at: timestamp(),
        payload: {
          decision,
          provider_evidence_digest: evidenceDigest,
          authenticated_provider_evidence: true,
          proposal_to_effect: projected,
          attempt,
        },
      });
    } catch {
      return {
        ok: false,
        decision: 'INDETERMINATE',
        reason: 'pas_assurance_record_unavailable',
        reconciliation_required: true,
        retry_safe: false,
      };
    }
    return {
      ok: decision !== 'INDETERMINATE',
      decision,
      operation_id: input.operation_id,
      action_caid: proposal.caid,
      provider_evidence_digest: evidenceDigest,
      authenticated_provider_evidence: true,
      reconciliation_required: decision === 'INDETERMINATE',
      retry_safe: decision === 'RECONCILED_NOT_EXECUTED',
    };
  }

  async function exportReliancePacket(input: {
    tenant_id: string;
    operation_id: string;
  }): Promise<JsonObject> {
    if (!identifier(input?.tenant_id)) return refusal('tenant_required');
    if (!identifier(input?.operation_id)) return refusal('operation_id_required');
    const events = await eventsFor(input.tenant_id, input.operation_id)
      .catch(() => null);
    if (!events) return refusal('pas_evidence_store_unavailable');
    const prepared = events.find((event) => event.event_type === 'PREPARED');
    const terminal = [...events].reverse().find((event) => (
      (event.event_type === 'EXECUTION' || event.event_type === 'RECONCILIATION')
        && EXPORTABLE_DECISIONS.has(event.payload?.decision)
    ));
    if (!prepared || !terminal
        || !isObject(prepared.payload?.binding)
        || !isObject(prepared.payload?.proposal)) {
      return refusal('pas_reliance_packet_not_available');
    }
    const proposal = prepared.payload.proposal as ProposalToEffectProposal;
    if (!preparedContext(events, proposal, input.tenant_id)) {
      return refusal('pas_prepared_context_mismatch');
    }
    const eventDigests = events.map((event) => digest(event));
    const body = {
      '@version': DAVINCI_PAS_CONSEQUENCE_PACKET_VERSION,
      profile_id: DAVINCI_PAS_CONSEQUENCE_PROFILE_ID,
      relying_party_id: options.assurance.relying_party_id,
      tenant_id: input.tenant_id,
      operation_id: input.operation_id,
      generated_at: timestamp(),
      caid: proposal.caid,
      action_digest: proposal.action_digest,
      proposal_digest: prepared.payload.proposal_digest,
      binding: clone(prepared.payload.binding),
      binding_digest: prepared.payload.binding_digest,
      decision: terminal.payload.decision,
      reconciliation_required: terminal.payload.decision === 'INDETERMINATE',
      retry_safe: terminal.payload.decision === 'RECONCILED_NOT_EXECUTED',
      event_count: events.length,
      event_root: digest(eventDigests),
      limitations: [...DAVINCI_PAS_CONSEQUENCE_LIMITATIONS],
    };
    const packetDigest = digest(body);
    const bytes = Buffer.from(`${SIGNATURE_DOMAIN}${canonicalize({
      packet_digest: packetDigest,
      body,
    })}`);
    const signature = await options.assurance.signer.sign(bytes);
    const signatureB64u = typeof signature === 'string'
      ? signature
      : Buffer.from(signature).toString('base64url');
    return {
      ...body,
      packet_digest: packetDigest,
      proof: {
        alg: 'Ed25519',
        key_id: options.assurance.signer.key_id,
        signature_b64u: signatureB64u,
      },
    };
  }

  return Object.freeze({ prepare, execute, reconcile, exportReliancePacket });
}

export type DavinciPasConsequenceControl = ReturnType<
  typeof createDavinciPasConsequenceControl
>;

export function verifyDavinciPasConsequencePacket(
  packet: unknown,
  pin: {
    relying_party_id: string;
    key_id: string;
    public_key_spki_b64u: string;
  },
): { valid: boolean; reasons: string[] } {
  const reasons: string[] = [];
  if (!isObject(packet)
      || packet['@version'] !== DAVINCI_PAS_CONSEQUENCE_PACKET_VERSION) {
    return { valid: false, reasons: ['packet_profile_invalid'] };
  }
  if (packet.relying_party_id !== pin.relying_party_id) {
    reasons.push('relying_party_mismatch');
  }
  if (!isObject(packet.proof)
      || packet.proof.alg !== 'Ed25519'
      || packet.proof.key_id !== pin.key_id
      || typeof packet.proof.signature_b64u !== 'string') {
    reasons.push('packet_proof_invalid');
  }
  const body = clone(packet);
  delete body.packet_digest;
  delete body.proof;
  const expectedDigest = digest(body);
  if (packet.packet_digest !== expectedDigest) reasons.push('packet_digest_mismatch');
  if (reasons.length === 0) {
    try {
      const publicKey = crypto.createPublicKey({
        key: Buffer.from(pin.public_key_spki_b64u, 'base64url'),
        type: 'spki',
        format: 'der',
      });
      const bytes = Buffer.from(`${SIGNATURE_DOMAIN}${canonicalize({
        packet_digest: packet.packet_digest,
        body,
      })}`);
      if (!crypto.verify(
        null,
        bytes,
        publicKey,
        Buffer.from(packet.proof.signature_b64u, 'base64url'),
      )) {
        reasons.push('packet_signature_invalid');
      }
    } catch {
      reasons.push('packet_signature_invalid');
    }
  }
  return { valid: reasons.length === 0, reasons };
}

const davinciPasConsequenceControl = {
  DAVINCI_PAS_AEB_REQUIREMENT_REF,
  DAVINCI_PAS_CONSEQUENCE_PACKET_VERSION,
  DAVINCI_PAS_CONSEQUENCE_PROFILE_ID,
  createDavinciPasConsequenceControl,
  createDavinciPasProposalToEffectProfile,
  verifyDavinciPasConsequencePacket,
};

export default davinciPasConsequenceControl;
