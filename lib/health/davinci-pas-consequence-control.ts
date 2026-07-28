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
  DAVINCI_PAS_BINDING_TYPE,
  DAVINCI_PAS_IG_VERSION,
  DAVINCI_PAS_MEDICAL_RAIL,
  DAVINCI_PAS_PROFILE_ID,
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
const PACKET_FIELDS = Object.freeze([
  '@version',
  'profile_id',
  'relying_party_id',
  'tenant_id',
  'operation_id',
  'generated_at',
  'caid',
  'action_digest',
  'proposal_digest',
  'binding',
  'binding_digest',
  'decision',
  'reconciliation_required',
  'retry_safe',
  'event_count',
  'event_digests',
  'event_root',
  'prepared_event_digest',
  'terminal_event_digest',
  'limitations',
  'packet_digest',
  'proof',
] as const);
const BINDING_FIELDS = Object.freeze([
  '@type',
  'profile_id',
  'ig',
  'rail',
  'action',
  'action_digest',
  'caid',
] as const);
const BINDING_IG_FIELDS = Object.freeze([
  'package',
  'version',
  'fhir_release',
  'claim_profile',
  'claim_response_profile',
] as const);
const PROOF_FIELDS = Object.freeze(['alg', 'key_id', 'signature_b64u'] as const);
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const ISO_INSTANT_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const DAVINCI_PAS_CLAIM_PROFILE =
  'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/profile-claim|2.2.1';
const DAVINCI_PAS_CLAIM_RESPONSE_PROFILE =
  'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/profile-claimresponse|2.2.1';
const PROHIBITED_PHI_FIELD_ALIASES = new Set([
  'accountnumber',
  'address',
  'authorizationform',
  'beneficiary',
  'beneficiaryid',
  'beneficiaryname',
  'bic',
  'birthdate',
  'cin',
  'clinical',
  'clinicalnote',
  'contained',
  'dateofbirth',
  'diagnosis',
  'diagnosistext',
  'directpatientreference',
  'dob',
  'email',
  'freetext',
  'freetextnote',
  'freeformtext',
  'membername',
  'medicarebeneficiaryidentifier',
  'patient',
  'patientname',
  'patientreference',
  'phone',
  'procedure',
  'rawclaim',
  'rawclaimresponse',
  'rawclinicalresource',
  'resource',
  'routingnumber',
  'ssn',
  'supportinginfo',
  'telephone',
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

function exactKeys(value: unknown, expected: readonly string[]): value is JsonObject {
  if (!isObject(value)) return false;
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return actual.length === sortedExpected.length
    && sortedExpected.every((key, index) => key === actual[index]);
}

function validInstant(value: unknown): value is string {
  return typeof value === 'string'
    && ISO_INSTANT_RE.test(value)
    && Number.isFinite(Date.parse(value));
}

function prohibitedPhi(
  value: unknown,
  depth = 0,
  budget: { entries: number } = { entries: 0 },
): string | null {
  if (depth > 10 || budget.entries > 4096) return 'input_complexity_limit';
  if (Array.isArray(value)) {
    for (const entry of value) {
      budget.entries += 1;
      const found = prohibitedPhi(entry, depth + 1, budget);
      if (found) return found;
    }
    return null;
  }
  if (!isObject(value)) return null;
  for (const key of Reflect.ownKeys(value)) {
    budget.entries += 1;
    if (typeof key !== 'string') return 'malformed_field';
    const normalized = key.normalize('NFKC').toLowerCase().replace(/[^a-z0-9]/g, '');
    if (PROHIBITED_PHI_FIELD_ALIASES.has(normalized)) return key;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
      return 'malformed_field';
    }
    const found = prohibitedPhi(descriptor.value, depth + 1, budget);
    if (found) return found;
  }
  return null;
}

function digest(value: unknown): string {
  return `sha256:${crypto.createHash('sha256').update(canonicalize(value)).digest('hex')}`;
}

const DAVINCI_PAS_RELIANCE_PROGRAM_DIGEST = digest({
  '@version': DAVINCI_PAS_CONSEQUENCE_CONTROL_VERSION,
  profile_id: DAVINCI_PAS_CONSEQUENCE_PROFILE_ID,
  action_type: DAVINCI_PAS_ACTION_TYPE,
  aeb_requirement_ref: DAVINCI_PAS_AEB_REQUIREMENT_REF,
  required_action_fields: REQUIRED_ACTION_FIELDS,
  optional_action_fields: OPTIONAL_ACTION_FIELDS,
});

function refusal(reason: string, extras: JsonObject = {}): JsonObject {
  return {
    ok: false,
    decision: 'REFUSED',
    reason,
    ...extras,
    program_digest: DAVINCI_PAS_RELIANCE_PROGRAM_DIGEST,
  };
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
  const identifierFields = [
    'tenant_id',
    'provider_id',
    'provider_account_id',
    'environment',
    'attempt_id',
  ];
  if (!identifierFields.every((field) => identifier(value[field]))
      || typeof value.request_digest !== 'string'
      || !DIGEST_RE.test(value.request_digest)) return null;
  const fields = [...identifierFields, 'request_digest'];
  return Object.fromEntries(
    fields.map((field) => [field, value[field]]),
  ) as unknown as ConsequenceAttemptBinding;
}

function providerEvidenceMatches(
  value: unknown,
  proposal: ProposalToEffectProposal,
  attempt: ConsequenceAttemptBinding,
): boolean {
  return isObject(value)
    && value.authenticated === true
    && value.operation_id === proposal.operation_id
    && value.caid === proposal.caid
    && value.action_digest === proposal.action_digest
    && value.tenant_id === attempt.tenant_id
    && value.provider_id === attempt.provider_id
    && value.provider_account_id === attempt.provider_account_id
    && value.environment === attempt.environment
    && value.attempt_id === attempt.attempt_id
    && value.request_digest === attempt.request_digest
    && identifier(value.evidence_id)
    && validInstant(value.observed_at)
    && ['COMMITTED', 'NOT_COMMITTED', 'ESCALATED'].includes(value.outcome);
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
  /**
   * The same owner-fenced durable consequence-attempt store used by the
   * Proposal-to-Effect controller. Its existing lookup/recover operations are
   * the restart path: a stale INVOKING attempt is rediscovered from the exact
   * server-derived provider tuple, recovered only as INDETERMINATE, and then
   * sent to authenticated reconciliation. Recovery never invokes the effect.
   */
  consequence_attempt_store?: {
    durable: true;
    lookup(input: {
      tenant_id: string;
      provider_id: string;
      provider_account_id: string;
      environment: string;
      request_digest: ConsequenceAttemptBinding['request_digest'];
    }): Promise<ConsequenceAttemptBinding | null>;
    read(input: ConsequenceAttemptBinding): Promise<{
      state: 'RESERVED' | 'INVOKING' | 'INDETERMINATE' | 'COMMITTED' | 'RELEASED' | 'ESCALATED';
    } | null>;
    recover(input: ConsequenceAttemptBinding): Promise<
      | {
        recovered: true;
        owner: ConsequenceAttemptReference['owner'];
        state: 'RESERVED' | 'INDETERMINATE';
      }
      | {
        recovered: false;
        reason: string;
      }
    >;
  };
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

function validEvidenceStream(
  events: unknown,
  tenantId: string,
  operationId: string,
): events is HealthcareEvidenceEvent[] {
  if (!Array.isArray(events) || events.length < 2 || events.length > 10_000) return false;
  let previousSequence = 0;
  for (const event of events) {
    if (!exactKeys(event, [
      'event_id',
      'sequence',
      'tenant_id',
      'operation_id',
      'event_type',
      'recorded_at',
      'payload',
    ])
        || typeof event.event_id !== 'string'
        || !DIGEST_RE.test(event.event_id)
        || !Number.isSafeInteger(event.sequence)
        || event.sequence !== previousSequence + 1
        || event.tenant_id !== tenantId
        || event.operation_id !== operationId
        || !['PREPARED', 'EXECUTION', 'RECONCILIATION'].includes(event.event_type)
        || !validInstant(event.recorded_at)
        || !isObject(event.payload)) {
      return false;
    }
    previousSequence = event.sequence;
  }
  return true;
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
  if (options.consequence_attempt_store
      && (options.consequence_attempt_store.durable !== true
        || typeof options.consequence_attempt_store.lookup !== 'function'
        || typeof options.consequence_attempt_store.read !== 'function'
        || typeof options.consequence_attempt_store.recover !== 'function')) {
    throw new Error('pas_consequence_recovery_store_invalid');
  }
  if (options.allow_ephemeral_stores_for_tests !== true
      && !options.consequence_attempt_store) {
    throw new Error('pas_consequence_recovery_store_required');
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
      action_caid: proposal.caid,
      action_digest: proposal.action_digest,
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
            ok: true,
            decision: 'EXECUTED',
            reason: 'pas_assurance_record_unavailable',
            operation_id: proposal.operation_id,
            action_caid: proposal.caid,
            attempt,
            assurance_recorded: false,
            reconciliation_required: false,
            retry_safe: false,
          };
        }
        return {
          ok: true,
          decision: 'EXECUTED',
          operation_id: proposal.operation_id,
          action_caid: proposal.caid,
          attempt,
          assurance_recorded: true,
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

  /**
   * Recover only custody, never execution. The durable store first proves the
   * exact attempt selected by the signed proposal's provider tuple and request
   * digest. Its separately authorized recovery operation rotates stale owner
   * material and conservatively changes INVOKING to INDETERMINATE. The returned
   * handle is persisted before authenticated provider reconciliation proceeds.
   */
  async function recoverReconciliationHandle(input: {
    tenant_id: string;
    proposal: ProposalToEffectProposal;
    prepared: { binding: DavinciPasReviewBinding; proposal_digest: string };
    provider_evidence: JsonObject;
    expected_attempt?: ConsequenceAttemptBinding | null;
  }): Promise<
    | {
      ok: true;
      attempt: ConsequenceAttemptBinding;
      handle: ConsequenceAttemptReference;
    }
    | {
      ok: false;
      reason: string;
    }
  > {
    const store = options.consequence_attempt_store;
    if (!store) return { ok: false, reason: 'reconciliation_handle_unavailable' };
    let located: ConsequenceAttemptBinding | null;
    try {
      located = publicAttempt(await store.lookup({
        tenant_id: input.tenant_id,
        provider_id: input.proposal.consequence.provider_id,
        provider_account_id: input.proposal.consequence.provider_account_id,
        environment: input.proposal.consequence.environment,
        request_digest: input.proposal.consequence.request_digest,
      }));
    } catch {
      return { ok: false, reason: 'consequence_attempt_recovery_unavailable' };
    }
    if (!located
        || located.tenant_id !== input.tenant_id
        || located.provider_id !== input.proposal.consequence.provider_id
        || located.provider_account_id !== input.proposal.consequence.provider_account_id
        || located.environment !== input.proposal.consequence.environment
        || located.request_digest !== input.proposal.consequence.request_digest
        || (input.expected_attempt
          && digest(located) !== digest(input.expected_attempt))) {
      return { ok: false, reason: 'consequence_attempt_recovery_binding_mismatch' };
    }
    if (!providerEvidenceMatches(input.provider_evidence, input.proposal, located)) {
      return { ok: false, reason: 'provider_evidence_binding_mismatch' };
    }
    let sourceState: string;
    try {
      const snapshot = await store.read(located);
      sourceState = snapshot?.state ?? '';
    } catch {
      return { ok: false, reason: 'consequence_attempt_recovery_unavailable' };
    }
    if (sourceState !== 'INVOKING' && sourceState !== 'INDETERMINATE') {
      return { ok: false, reason: 'consequence_attempt_not_reconcilable' };
    }
    let recovered: Awaited<ReturnType<typeof store.recover>>;
    try {
      recovered = await store.recover(located);
    } catch {
      return { ok: false, reason: 'consequence_attempt_recovery_unavailable' };
    }
    if (!recovered.recovered || recovered.state !== 'INDETERMINATE') {
      return {
        ok: false,
        reason: recovered.recovered
          ? 'consequence_attempt_not_reconcilable'
          : 'consequence_attempt_recovery_unavailable',
      };
    }
    const handle: ConsequenceAttemptReference = {
      tenant_id: located.tenant_id,
      attempt_id: located.attempt_id,
      owner: recovered.owner,
    };
    try {
      await options.reconciliation_handle_store.put({
        tenant_id: input.tenant_id,
        operation_id: input.proposal.operation_id,
        handle,
      });
    } catch {
      return { ok: false, reason: 'reconciliation_handle_unavailable' };
    }
    await append({
      tenant_id: input.tenant_id,
      operation_id: input.proposal.operation_id,
      event_type: 'EXECUTION',
      recorded_at: timestamp(),
      payload: {
        decision: 'INDETERMINATE',
        proposal_digest: input.prepared.proposal_digest,
        binding_digest: digest(input.prepared.binding),
        action_caid: input.proposal.caid,
        action_digest: input.proposal.action_digest,
        proposal_to_effect: {
          consequence: { state: 'INDETERMINATE', attempt: located },
        },
        attempt: located,
        recovery: {
          from_state: sourceState,
          method: 'durable_attempt_store',
          effect_replayed: false,
        },
      },
    }).catch(() => undefined);
    return { ok: true, attempt: located, handle };
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
    const prepared = events
      ? preparedContext(events, proposal, input.tenant_id)
      : null;
    if (!events || !prepared) {
      return refusal('pas_prepared_context_mismatch');
    }
    const indeterminate = [...events].reverse().find((event) => (
      event.event_type === 'EXECUTION'
        && event.payload?.decision === 'INDETERMINATE'
    ));
    let attempt = publicAttempt(indeterminate?.payload?.attempt);
    if (attempt && !providerEvidenceMatches(input.provider_evidence, proposal, attempt)) {
      return {
        ok: false,
        decision: 'INDETERMINATE',
        reason: 'provider_evidence_binding_mismatch',
        reconciliation_required: true,
        retry_safe: false,
      };
    }
    let handle = attempt
      ? await options.reconciliation_handle_store.get({
        tenant_id: input.tenant_id,
        operation_id: input.operation_id,
      }).catch(() => null)
      : null;
    if (!handle || !attempt
        || handle.tenant_id !== input.tenant_id
        || handle.attempt_id !== attempt.attempt_id) {
      const recovered = await recoverReconciliationHandle({
        tenant_id: input.tenant_id,
        proposal,
        prepared,
        provider_evidence: input.provider_evidence,
        expected_attempt: attempt,
      });
      if (!recovered.ok) {
        return {
          ok: false,
          decision: 'INDETERMINATE',
          reason: recovered.reason,
          reconciliation_required: true,
          retry_safe: false,
        };
      }
      attempt = recovered.attempt;
      handle = recovered.handle;
    }
    if (!providerEvidenceMatches(input.provider_evidence, proposal, attempt)) {
      return {
        ok: false,
        decision: 'INDETERMINATE',
        reason: 'provider_evidence_binding_mismatch',
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
          proposal_digest: prepared.proposal_digest,
          binding_digest: digest(prepared.binding),
          action_caid: proposal.caid,
          action_digest: proposal.action_digest,
          provider_evidence_digest: evidenceDigest,
          authenticated_provider_evidence: true,
          proposal_to_effect: projected,
          attempt,
        },
      });
    } catch {
      return {
        ok: decision !== 'INDETERMINATE',
        decision,
        reason: 'pas_assurance_record_unavailable',
        operation_id: input.operation_id,
        action_caid: proposal.caid,
        provider_evidence_digest: evidenceDigest,
        authenticated_provider_evidence: true,
        assurance_recorded: false,
        reconciliation_required: decision === 'INDETERMINATE',
        retry_safe: decision === 'RECONCILED_NOT_EXECUTED',
      };
    }
    return {
      ok: decision !== 'INDETERMINATE',
      decision,
      operation_id: input.operation_id,
      action_caid: proposal.caid,
      provider_evidence_digest: evidenceDigest,
      authenticated_provider_evidence: true,
      assurance_recorded: true,
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
    if (!validEvidenceStream(events, input.tenant_id, input.operation_id)) {
      return refusal('pas_reliance_evidence_invalid');
    }
    let terminalIndex = -1;
    for (let index = events.length - 1; index >= 0; index -= 1) {
      const event = events[index];
      if ((event.event_type === 'EXECUTION' || event.event_type === 'RECONCILIATION')
          && EXPORTABLE_DECISIONS.has(event.payload.decision)) {
        terminalIndex = index;
        break;
      }
    }
    const terminal = terminalIndex >= 0 ? events[terminalIndex] : null;
    if (!terminal
        || terminalIndex !== events.length - 1
        || typeof terminal.payload.proposal_digest !== 'string'
        || !DIGEST_RE.test(terminal.payload.proposal_digest)
        || typeof terminal.payload.binding_digest !== 'string'
        || !DIGEST_RE.test(terminal.payload.binding_digest)
        || (terminal.payload.decision.startsWith('RECONCILED_')
          ? terminal.event_type !== 'RECONCILIATION'
          : terminal.event_type !== 'EXECUTION')) {
      return refusal('pas_reliance_packet_not_available');
    }
    let preparedIndex = -1;
    for (let index = terminalIndex - 1; index >= 0; index -= 1) {
      const candidate = events[index];
      if (candidate.event_type === 'PREPARED'
          && candidate.payload.proposal_digest === terminal.payload.proposal_digest
          && candidate.payload.binding_digest === terminal.payload.binding_digest) {
        preparedIndex = index;
        break;
      }
    }
    const prepared = preparedIndex >= 0 ? events[preparedIndex] : null;
    if (!prepared
        || !isObject(prepared.payload.binding)
        || !isObject(prepared.payload.proposal)
        || digest(prepared.payload.binding) !== prepared.payload.binding_digest
        || digest(prepared.payload.proposal) !== prepared.payload.proposal_digest) {
      return refusal('pas_reliance_packet_not_available');
    }
    const proposal = prepared.payload.proposal as ProposalToEffectProposal;
    const selected = preparedContext([prepared], proposal, input.tenant_id);
    if (!selected
        || proposal.operation_id !== input.operation_id
        || proposal.consequence?.tenant_id !== input.tenant_id
        || terminal.payload.action_caid !== proposal.caid
        || terminal.payload.action_digest !== proposal.action_digest
        || selected.binding.caid !== proposal.caid
        || selected.binding.action_digest !== proposal.action_digest
        || terminal.payload.binding_digest !== digest(selected.binding)) {
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
      event_digests: eventDigests,
      event_root: digest(eventDigests),
      prepared_event_digest: eventDigests[preparedIndex],
      terminal_event_digest: eventDigests[terminalIndex],
      limitations: [...DAVINCI_PAS_CONSEQUENCE_LIMITATIONS],
    };
    if (prohibitedPhi(body)) return refusal('pas_reliance_packet_phi_refused');
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
    tenant_id?: string;
    operation_id?: string;
  },
): { valid: boolean; reasons: string[] } {
  const reasons: string[] = [];
  const add = (reason: string) => {
    if (!reasons.includes(reason)) reasons.push(reason);
  };
  const phi = prohibitedPhi(packet);
  if (phi && phi !== 'input_complexity_limit' && phi !== 'malformed_field') {
    add('packet_contains_prohibited_phi');
  }
  if (!isObject(packet)) {
    return { valid: false, reasons: ['packet_profile_invalid'] };
  }
  if (phi === 'input_complexity_limit' || phi === 'malformed_field') {
    return { valid: false, reasons: ['packet_shape_invalid'] };
  }
  if (!exactKeys(packet, PACKET_FIELDS)) {
    add('packet_shape_invalid');
    return { valid: false, reasons };
  }
  if (packet['@version'] !== DAVINCI_PAS_CONSEQUENCE_PACKET_VERSION
      || packet.profile_id !== DAVINCI_PAS_CONSEQUENCE_PROFILE_ID
      || !identifier(packet.relying_party_id)) {
    add('packet_profile_invalid');
  }

  const pinValid = isObject(pin)
    && identifier(pin.relying_party_id)
    && identifier(pin.key_id)
    && typeof pin.public_key_spki_b64u === 'string'
    && BASE64URL_RE.test(pin.public_key_spki_b64u)
    && (pin.tenant_id === undefined || identifier(pin.tenant_id))
    && (pin.operation_id === undefined || identifier(pin.operation_id));
  if (!pinValid) add('verification_pin_invalid');
  if (pinValid && packet.relying_party_id !== pin.relying_party_id) {
    add('relying_party_mismatch');
  }
  if (!identifier(packet.tenant_id)) {
    add('packet_tenant_invalid');
  } else if (pinValid && pin.tenant_id !== undefined
      && packet.tenant_id !== pin.tenant_id) {
    add('packet_tenant_mismatch');
  }
  if (!identifier(packet.operation_id)) {
    add('packet_operation_invalid');
  } else if (pinValid && pin.operation_id !== undefined
      && packet.operation_id !== pin.operation_id) {
    add('packet_operation_mismatch');
  }
  if (!validInstant(packet.generated_at)
      || typeof packet.proposal_digest !== 'string'
      || !DIGEST_RE.test(packet.proposal_digest)
      || !Array.isArray(packet.limitations)
      || packet.limitations.length !== DAVINCI_PAS_CONSEQUENCE_LIMITATIONS.length
      || !DAVINCI_PAS_CONSEQUENCE_LIMITATIONS.every(
        (limitation, index) => packet.limitations[index] === limitation,
      )) {
    add('packet_shape_invalid');
  }

  const decisionSemantics: Record<string, {
    reconciliation_required: boolean;
    retry_safe: boolean;
  }> = {
    EXECUTED: { reconciliation_required: false, retry_safe: false },
    INDETERMINATE: { reconciliation_required: true, retry_safe: false },
    RECONCILED_EXECUTED: { reconciliation_required: false, retry_safe: false },
    RECONCILED_NOT_EXECUTED: { reconciliation_required: false, retry_safe: true },
  };
  const decision = typeof packet.decision === 'string'
    ? decisionSemantics[packet.decision]
    : undefined;
  if (!decision
      || packet.reconciliation_required !== decision.reconciliation_required
      || packet.retry_safe !== decision.retry_safe) {
    add('packet_decision_invalid');
  }

  let canonicalBinding: ReturnType<typeof canonicalizeDavinciPasMaterialAction> | null = null;
  const binding = packet.binding;
  if (!exactKeys(binding, BINDING_FIELDS)
      || binding['@type'] !== DAVINCI_PAS_BINDING_TYPE
      || binding.profile_id !== DAVINCI_PAS_PROFILE_ID
      || binding.rail !== DAVINCI_PAS_MEDICAL_RAIL
      || !exactKeys(binding.ig, BINDING_IG_FIELDS)
      || binding.ig.package !== 'hl7.fhir.us.davinci-pas'
      || binding.ig.version !== DAVINCI_PAS_IG_VERSION
      || binding.ig.fhir_release !== 'R4'
      || binding.ig.claim_profile !== DAVINCI_PAS_CLAIM_PROFILE
      || binding.ig.claim_response_profile !== DAVINCI_PAS_CLAIM_RESPONSE_PROFILE) {
    add('packet_binding_invalid');
  } else {
    try {
      canonicalBinding = canonicalizeDavinciPasMaterialAction(binding.action);
    } catch {
      add('packet_binding_invalid');
    }
  }
  if (!canonicalBinding
      || typeof packet.caid !== 'string'
      || packet.caid !== binding?.caid
      || packet.caid !== canonicalBinding.caid) {
    add('packet_caid_invalid');
  }
  if (!canonicalBinding
      || typeof packet.action_digest !== 'string'
      || !DIGEST_RE.test(packet.action_digest)
      || packet.action_digest !== binding?.action_digest
      || packet.action_digest !== canonicalBinding.action_digest) {
    add('packet_action_digest_invalid');
  }
  if (binding?.action?.operation_id !== packet.operation_id) {
    add('packet_operation_mismatch');
  }
  try {
    if (typeof packet.binding_digest !== 'string'
        || !DIGEST_RE.test(packet.binding_digest)
        || packet.binding_digest !== digest(binding)) {
      add('packet_binding_digest_invalid');
    }
  } catch {
    add('packet_binding_digest_invalid');
  }

  const eventDigests = packet.event_digests;
  let eventRootValid = Array.isArray(eventDigests)
    && eventDigests.length >= 2
    && eventDigests.length <= 10_000
    && eventDigests.every((entry: unknown) => (
      typeof entry === 'string' && DIGEST_RE.test(entry)
    ))
    && Number.isSafeInteger(packet.event_count)
    && packet.event_count === eventDigests.length
    && typeof packet.event_root === 'string'
    && DIGEST_RE.test(packet.event_root)
    && typeof packet.prepared_event_digest === 'string'
    && DIGEST_RE.test(packet.prepared_event_digest)
    && typeof packet.terminal_event_digest === 'string'
    && DIGEST_RE.test(packet.terminal_event_digest);
  if (eventRootValid) {
    const preparedIndex = eventDigests.indexOf(packet.prepared_event_digest);
    const terminalIndex = eventDigests.lastIndexOf(packet.terminal_event_digest);
    eventRootValid = packet.event_root === digest(eventDigests)
      && preparedIndex >= 0
      && terminalIndex > preparedIndex
      && terminalIndex === eventDigests.length - 1;
  }
  if (!eventRootValid) add('packet_event_root_invalid');
  if (!Number.isSafeInteger(packet.event_count)) add('packet_shape_invalid');

  const proofShape = exactKeys(packet.proof, PROOF_FIELDS)
    && packet.proof.alg === 'Ed25519'
    && pinValid
    && packet.proof.key_id === pin.key_id
    && typeof packet.proof.signature_b64u === 'string'
    && BASE64URL_RE.test(packet.proof.signature_b64u)
    && Buffer.from(packet.proof.signature_b64u, 'base64url').byteLength === 64;
  if (!proofShape) add('packet_proof_invalid');

  let body: JsonObject | null = null;
  let expectedDigest: string | null = null;
  try {
    body = clone(packet);
    delete body.packet_digest;
    delete body.proof;
    expectedDigest = digest(body);
  } catch {
    add('packet_shape_invalid');
  }
  if (!body || !expectedDigest
      || typeof packet.packet_digest !== 'string'
      || !DIGEST_RE.test(packet.packet_digest)
      || packet.packet_digest !== expectedDigest) {
    add('packet_digest_mismatch');
  }
  if (proofShape && body && expectedDigest === packet.packet_digest) {
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
        add('packet_signature_invalid');
      }
    } catch {
      add('packet_signature_invalid');
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
