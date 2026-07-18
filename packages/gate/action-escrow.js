// SPDX-License-Identifier: Apache-2.0
/**
 * Pure orchestration kernel for contractor milestone release.
 *
 * The kernel owns no keys, documents, funds, or provider credentials. It joins
 * construction-pinned verification results under a durable expected-revision
 * CAS and refuses every state or external-effect ambiguity.
 */
import { canonicalize, hashCanonical } from './execution-binding.js';
import {
  ACTION_ESCROW_CONTRACTOR_TEMPLATE_VERSION,
  validateActionEscrowReleaseTemplate,
} from './action-escrow-verifiers.js';

export const ACTION_ESCROW_STATE_VERSION = 'EP-ACTION-ESCROW-STATE-v1';
export const ACTION_ESCROW_OUTCOME_VERSION = 'EP-ACTION-ESCROW-OUTCOME-v1';
export const ACTION_ESCROW_PROFILE_VERSION = 'EP-ACTION-ESCROW-PROFILE-v1';

export const ACTION_ESCROW_STATES = Object.freeze([
  'draft',
  'awaiting_acceptance',
  'effective',
  'awaiting_funding',
  'funded',
  'milestone_submitted',
  'release_reserved',
  'released',
  'disputed',
  'amendment_pending',
  'cancelled',
  'completed',
  'release_indeterminate',
]);

export const ACTION_ESCROW_TRANSITIONS = Object.freeze({
  draft: Object.freeze(['awaiting_acceptance', 'cancelled']),
  awaiting_acceptance: Object.freeze(['effective', 'cancelled']),
  effective: Object.freeze(['awaiting_funding', 'amendment_pending', 'cancelled']),
  awaiting_funding: Object.freeze(['funded']),
  funded: Object.freeze(['milestone_submitted', 'disputed']),
  milestone_submitted: Object.freeze([
    'release_reserved',
    'disputed',
  ]),
  release_reserved: Object.freeze(['released', 'release_indeterminate', 'milestone_submitted']),
  released: Object.freeze(['completed']),
  disputed: Object.freeze([]),
  amendment_pending: Object.freeze(['effective', 'cancelled']),
  cancelled: Object.freeze([]),
  completed: Object.freeze([]),
  release_indeterminate: Object.freeze([
    'released',
    'milestone_submitted',
  ]),
});

const RESOLUTION_VERSION = 'EP-RESOLUTION-v1';
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const MAX_CAS_ATTEMPTS = 4;
const MAX_OPERATIONS = 256;
const MAX_HISTORY = 512;
const MAX_SUPERSEDED_BINDINGS = 64;
const MAX_STATE_BYTES = 4 * 1024 * 1024;
const DEFAULT_PROVIDER_TIMEOUT_MS = 30_000;

const STORE_CAPABILITIES = Object.freeze([
  'durable',
  'atomicExpectedRevisionCas',
  'linearizableReads',
  'monotonicRevisions',
  'nonExpiring',
]);

const COMMON_INPUT_KEYS = Object.freeze([
  'agreement_digest',
  'document_action_binding_digest',
  'milestone_id',
  'release_action_digest',
  'parties',
  'profile',
  'idempotency_key',
]);

const RECORD_KEYS = new Set([
  '@version',
  'escrow_key',
  'revision',
  'state',
  'agreement_digest',
  'document_action_binding_digest',
  'milestone_id',
  'release_action_digest',
  'parties',
  'parties_digest',
  'profile',
  'profile_digest',
  'document_action_binding',
  'agreement_acceptances',
  'funding',
  'milestone_evidence',
  'release_approvals',
  'release',
  'dispute',
  'cancellation',
  'completion',
  'pending_amendment',
  'superseded_bindings',
  'operations',
  'history',
  'created_at',
  'updated_at',
]);
const CONTAINER_KEYS = new Set(['artifact', 'verification']);
const FUNDING_CONTAINER_KEYS = new Set(['statement', 'verification']);
const ACCEPTANCE_KEYS = new Set(['party_id', 'artifact', 'verification']);
const RELEASE_APPROVAL_KEYS = new Set(['party_id', 'resolution', 'verification']);
const CORE_VERIFICATION_KEYS = new Set([
  'valid',
  'agreement_digest',
  'document_action_binding_digest',
  'milestone_id',
  'release_action_digest',
  'parties_digest',
  'profile_digest',
]);
const ACCEPTANCE_VERIFICATION_KEYS = new Set([
  ...CORE_VERIFICATION_KEYS,
  'party_id',
  'principal_key_id',
  'acceptance_digest',
]);
const FUNDING_VERIFICATION_KEYS = new Set([
  ...CORE_VERIFICATION_KEYS,
  'authenticated',
  'provider_id',
  'statement_type',
  'status',
  'provider_transaction_id',
  'provider_milestone_id',
  'amount',
  'currency',
  'destination_id',
  'statement_digest',
]);
const MILESTONE_VERIFICATION_KEYS = new Set([
  ...CORE_VERIFICATION_KEYS,
  'evidence_digest',
  'submitter_party_id',
  'observed_at',
]);
const RELEASE_APPROVAL_VERIFICATION_KEYS = new Set([
  ...CORE_VERIFICATION_KEYS,
  'authorizes_action',
  'outcome',
  'party_role',
  'principal_key_id',
  'nonce',
  'issued_at',
  'expires_at',
  'resolution_digest',
  'evidence_digest',
]);
const PROVIDER_VERIFICATION_KEYS = new Set([
  ...CORE_VERIFICATION_KEYS,
  'authenticated',
  'provider_id',
  'provider_idempotency_key',
  'provider_request_digest',
  'provider_transaction_id',
  'provider_milestone_id',
  'amount',
  'currency',
  'destination_id',
  'statement_type',
  'status',
  'statement_digest',
]);
const OPERATION_KEYS = new Set([
  'idempotency_key',
  'operation',
  'request_digest',
  'code',
  'ok',
  'outcome',
  'state',
  'at',
]);
const HISTORY_KEYS = new Set(['from', 'to', 'operation', 'idempotency_key', 'at']);
const KERNEL_OPERATIONS = new Set([
  'create',
  'begin_acceptance',
  'accept_agreement',
  'request_funding',
  'record_funding',
  'submit_milestone',
  'approve_release',
  'release',
  'reconcile_release',
  'open_dispute',
  'propose_amendment',
  'accept_amendment',
  'cancel',
  'complete',
]);

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, allowed, required = allowed) {
  if (!isPlainObject(value)) return false;
  const keys = Object.keys(value);
  return keys.every((key) => allowed.has(key))
    && [...required].every((key) => Object.hasOwn(value, key));
}

function validString(value, max = 512) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= max
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function validDigest(value) {
  return typeof value === 'string' && DIGEST_RE.test(value);
}

function validInstant(value) {
  if (!validString(value, 64)) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function canonicalSnapshot(value) {
  return JSON.parse(canonicalize(value));
}

function canonicalDigest(value) {
  return `sha256:${hashCanonical(value)}`;
}

function resolutionBindingInput(record) {
  return {
    agreement_digest: record.agreement_digest,
    document_action_binding_digest: record.document_action_binding_digest,
    milestone_id: record.milestone_id,
    release_action_digest: record.release_action_digest,
    profile_digest: record.profile_digest,
    evidence_digest: record.milestone_evidence?.verification?.evidence_digest,
    release_action_template:
      record.document_action_binding?.verification?.release_action_template,
  };
}

/**
 * Build the exact human-facing envelope signed by an Action Escrow approver.
 *
 * The release action digest remains the normative machine-action binding. This
 * envelope binds the document, evidence, and material release fields that the
 * approver reviews before selecting the approval option.
 */
export function createActionEscrowReleaseBindingMoment(input) {
  try {
    if (!isPlainObject(input)
      || !validDigest(input.agreement_digest)
      || !validDigest(input.document_action_binding_digest)
      || !validString(input.milestone_id, 256)
      || !validDigest(input.release_action_digest)
      || !validDigest(input.profile_digest)
      || !validDigest(input.evidence_digest)
      || !isPlainObject(input.release_action_template)) {
      return null;
    }
    const template = input.release_action_template;
    if (template.action_type !== 'escrow.milestone.release'
      || !validString(template.amount, 128)
      || !validString(template.currency, 16)
      || !validString(template.payee_id, 512)
      || !validString(template.destination_id, 512)
      || !validDigest(template.document_sha256)
      || !validDigest(template.material_terms_sha256)
      || template.completion_evidence_sha256 !== input.evidence_digest
      || !Number.isSafeInteger(template.amendment_version)
      || template.amendment_version < 1) {
      return null;
    }
    return deepFreeze(canonicalSnapshot({
      synopsis: `Authorize one ${template.amount} ${template.currency} milestone release.`,
      findings: [
        `Agreement digest: ${input.agreement_digest}`,
        `Document-action binding digest: ${input.document_action_binding_digest}`,
        `Release action digest: ${input.release_action_digest}`,
        `Milestone evidence digest: ${input.evidence_digest}`,
        `Milestone: ${input.milestone_id}`,
        `Payee: ${template.payee_id}`,
        `Destination: ${template.destination_id}`,
        `Amendment version: ${template.amendment_version}`,
      ],
      recommendations: [
        'Verify the exact document, amount, destination, and completion evidence before approving.',
      ],
      offer: 'Decline if any material field is unexpected; amendments require a new binding and fresh approvals.',
      question: {
        stem: `Authorize release of ${template.amount} ${template.currency} for milestone ${input.milestone_id} to ${template.payee_id} at ${template.destination_id}?`,
        options: [
          {
            label: 'Approve exact release',
            reasoning: 'Authorize only the action identified by the signed action digest.',
          },
          {
            label: 'Decline release',
            reasoning: 'Do not authorize this action or any custodian effect.',
          },
        ],
        recommended_idx: 1,
        hatches: {
          free_text: false,
          dialogue: false,
        },
      },
      meta: {
        decision_class: 'escrow.milestone.release',
        calibration_note: 'No approval recommendation; verify every material field.',
      },
    }));
  } catch {
    return null;
  }
}

export function computeActionEscrowReleaseBindingMomentDigest(input) {
  const bindingMoment = createActionEscrowReleaseBindingMoment(input);
  return bindingMoment === null ? null : canonicalDigest(bindingMoment);
}

/**
 * Return the relying-party-pinned nonce for one party and one exact release.
 *
 * It is stable while both parties approve, changes with any material action or
 * evidence change, and is consumed by the durable approval CAS.
 */
export function computeActionEscrowResolutionNonce(input, partyId) {
  if (!validString(partyId, 256)) return null;
  const bindingMomentDigest = computeActionEscrowReleaseBindingMomentDigest(input);
  if (bindingMomentDigest === null) return null;
  try {
    return `ep-ae-resolution:${hashCanonical({
      '@version': 'EP-ACTION-ESCROW-RESOLUTION-NONCE-v1',
      party_id: partyId,
      binding_moment_digest: bindingMomentDigest,
      release_action_digest: input.release_action_digest,
      evidence_digest: input.evidence_digest,
    })}`;
  } catch {
    return null;
  }
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
}

function sameStringSet(left, right) {
  if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
  const values = new Set(left);
  return values.size === left.length && right.every((value) => values.has(value));
}

function validateParties(parties) {
  if (!Array.isArray(parties) || parties.length < 2 || parties.length > 16) {
    return 'parties_invalid';
  }
  const ids = [];
  for (const party of parties) {
    if (!exactKeys(party, new Set(['party_id', 'role']))
      || !validString(party.party_id, 256)
      || !validString(party.role, 128)) {
      return 'party_invalid';
    }
    ids.push(party.party_id);
  }
  return new Set(ids).size === ids.length ? null : 'party_duplicate';
}

function validateProfileShape(profile) {
  if (!exactKeys(profile, new Set([
    '@version',
    'profile_id',
    'provider_id',
    'required_acceptance_party_ids',
    'required_release_approver_party_ids',
    'prohibit_self_approval',
  ]))) {
    return 'profile_shape_invalid';
  }
  if (profile['@version'] !== ACTION_ESCROW_PROFILE_VERSION
    || !validString(profile.profile_id, 256)
    || !validString(profile.provider_id, 256)) {
    return 'profile_identity_invalid';
  }
  for (const field of [
    'required_acceptance_party_ids',
    'required_release_approver_party_ids',
  ]) {
    const roster = profile[field];
    if (!Array.isArray(roster) || roster.length === 0 || roster.length > 16
      || roster.some((partyId) => !validString(partyId, 256))
      || new Set(roster).size !== roster.length) {
      return `${field}_invalid`;
    }
  }
  if (profile.prohibit_self_approval !== true
    && profile.prohibit_self_approval !== false) {
    return 'profile_self_approval_policy_invalid';
  }
  return null;
}

function validateProfileForParties(profile, parties) {
  const shapeError = validateProfileShape(profile);
  if (shapeError) return shapeError;
  const partyIds = parties.map((party) => party.party_id);
  if (!sameStringSet(profile.required_acceptance_party_ids, partyIds)) {
    return 'mutual_acceptance_roster_invalid';
  }
  if (!profile.required_release_approver_party_ids.every((partyId) => partyIds.includes(partyId))) {
    return 'release_approval_roster_invalid';
  }
  return null;
}

function escrowKey(context) {
  return `ep-action-escrow:${hashCanonical({
    '@version': 'EP-ACTION-ESCROW-KEY-v1',
    agreement_digest: context.agreement_digest,
    milestone_id: context.milestone_id,
  })}`;
}

function releaseReservationKey(context) {
  return `ep-ae-reservation:${hashCanonical({
    '@version': 'EP-ACTION-ESCROW-RELEASE-KEY-v1',
    agreement_digest: context.agreement_digest,
    document_action_binding_digest: context.document_action_binding_digest,
    milestone_id: context.milestone_id,
    release_action_digest: context.release_action_digest,
    profile_digest: context.profile_digest,
  })}`;
}

function providerIdempotencyKey(context) {
  return `ep-ae-release:${hashCanonical({
    '@version': 'EP-ACTION-ESCROW-PROVIDER-IDEMPOTENCY-v1',
    agreement_digest: context.agreement_digest,
    document_action_binding_digest: context.document_action_binding_digest,
    milestone_id: context.milestone_id,
    release_action_digest: context.release_action_digest,
    profile_digest: context.profile_digest,
  })}`;
}

function expectedBindings(context) {
  return {
    agreement_digest: context.agreement_digest,
    document_action_binding_digest: context.document_action_binding_digest,
    milestone_id: context.milestone_id,
    release_action_digest: context.release_action_digest,
    parties_digest: context.parties_digest,
    profile_digest: context.profile_digest,
  };
}

function normalizedInput(operation, input, extraAllowed = [], extraRequired = extraAllowed) {
  try {
    const snapshot = canonicalSnapshot(input);
    const allowed = new Set([...COMMON_INPUT_KEYS, ...extraAllowed]);
    const required = new Set([...COMMON_INPUT_KEYS, ...extraRequired]);
    if (!exactKeys(snapshot, allowed, required)) {
      return { error: 'invalid_operation_input' };
    }
    if (!validDigest(snapshot.agreement_digest)
      || !validDigest(snapshot.document_action_binding_digest)
      || !validDigest(snapshot.release_action_digest)
      || !validString(snapshot.milestone_id, 256)
      || !validString(snapshot.idempotency_key, 256)) {
      return { error: 'invalid_operation_binding' };
    }
    const partiesError = validateParties(snapshot.parties);
    if (partiesError) return { error: partiesError };
    const profileError = validateProfileForParties(snapshot.profile, snapshot.parties);
    if (profileError) return { error: profileError };

    const context = {
      agreement_digest: snapshot.agreement_digest,
      document_action_binding_digest: snapshot.document_action_binding_digest,
      milestone_id: snapshot.milestone_id,
      release_action_digest: snapshot.release_action_digest,
      parties: snapshot.parties,
      parties_digest: canonicalDigest(snapshot.parties),
      profile: snapshot.profile,
      profile_digest: canonicalDigest(snapshot.profile),
    };
    return {
      snapshot,
      context,
      escrowKey: escrowKey(context),
      requestDigest: canonicalDigest({ operation, input: snapshot }),
    };
  } catch {
    return { error: 'invalid_operation_input' };
  }
}

function outcome({
  ok = false,
  type = 'refused',
  code,
  operation = null,
  record = null,
  details = null,
}) {
  try {
    return deepFreeze(canonicalSnapshot({
      '@version': ACTION_ESCROW_OUTCOME_VERSION,
      ok,
      outcome: type,
      code,
      operation,
      state: record?.state ?? null,
      revision: record?.revision ?? null,
      escrow_key: record?.escrow_key ?? null,
      details,
      record,
    }));
  } catch {
    return Object.freeze({
      '@version': ACTION_ESCROW_OUTCOME_VERSION,
      ok: false,
      outcome: 'refused',
      code: 'closed_outcome_encoding_failed',
      operation,
      state: null,
      revision: null,
      escrow_key: null,
      details: null,
      record: null,
    });
  }
}

function operationBindingMatches(record, normalized, mode = 'active') {
  const binding = mode === 'pending'
    ? record.pending_amendment
    : record;
  if (!binding) return false;
  return record.agreement_digest === normalized.context.agreement_digest
    && record.milestone_id === normalized.context.milestone_id
    && binding.document_action_binding_digest
      === normalized.context.document_action_binding_digest
    && binding.release_action_digest === normalized.context.release_action_digest
    && record.parties_digest === normalized.context.parties_digest
    && record.profile_digest === normalized.context.profile_digest;
}

function boundVerificationMatches(result, expected) {
  return isPlainObject(result)
    && result.valid === true
    && result.agreement_digest === expected.agreement_digest
    && result.document_action_binding_digest === expected.document_action_binding_digest
    && result.milestone_id === expected.milestone_id
    && result.release_action_digest === expected.release_action_digest
    && result.parties_digest === expected.parties_digest
    && result.profile_digest === expected.profile_digest;
}

function boundVerificationSummary(result, expected, extras = {}) {
  return {
    valid: true,
    ...expectedBindings(expected),
    ...extras,
  };
}

function bindingVerificationDetails(result, expected) {
  try {
    if (!boundVerificationMatches(result, expectedBindings(expected))
      || !validDigest(result.verification_digest)
      || !validDigest(result.document_digest)
      || !validString(result.agreement_id, 256)
      || !validString(result.binding_id, 256)
      || !isPlainObject(result.release_action_template)) {
      return null;
    }
    const releaseActionTemplate = validateActionEscrowReleaseTemplate(
      result.release_action_template,
      {
        profileDigest: expected.profile_digest,
        agreementId: result.agreement_id,
        agreementDigest: expected.agreement_digest,
        milestoneId: expected.milestone_id,
        documentDigest: result.document_digest,
        contractorProjectSource:
          result.release_action_template.action_escrow_template_profile
            === ACTION_ESCROW_CONTRACTOR_TEMPLATE_VERSION,
      },
    );
    if (!releaseActionTemplate) return null;
    return {
      verification_digest: result.verification_digest,
      document_digest: result.document_digest,
      agreement_id: result.agreement_id,
      binding_id: result.binding_id,
      release_action_template: releaseActionTemplate,
    };
  } catch {
    return null;
  }
}

function storedBindingVerificationValid(container, expected) {
  if (!isPlainObject(container)
    || !isPlainObject(container.artifact)
    || !isPlainObject(container.verification)
    || container.verification.valid !== true) {
    return false;
  }
  return bindingVerificationDetails(container.verification, expected) !== null;
}

function coreVerificationValid(value, record, allowedKeys, overrides = {}) {
  const expected = {
    agreement_digest: record.agreement_digest,
    document_action_binding_digest: record.document_action_binding_digest,
    milestone_id: record.milestone_id,
    release_action_digest: record.release_action_digest,
    parties_digest: record.parties_digest,
    profile_digest: record.profile_digest,
    ...overrides,
  };
  return exactKeys(value, allowedKeys, CORE_VERIFICATION_KEYS)
    && value.valid === true
    && Object.entries(expected).every(([key, entry]) => value[key] === entry);
}

function storedAcceptancesValid(entries, record, {
  documentActionBindingDigest = record.document_action_binding_digest,
  releaseActionDigest = record.release_action_digest,
} = {}) {
  if (!Array.isArray(entries) || entries.length > record.profile.required_acceptance_party_ids.length) {
    return false;
  }
  const required = new Set(record.profile.required_acceptance_party_ids);
  const parties = new Set(record.parties.map((party) => party.party_id));
  const seenParties = new Set();
  const seenKeys = new Set();
  for (const entry of entries) {
    const verification = entry?.verification;
    if (!exactKeys(entry, ACCEPTANCE_KEYS)
      || !isPlainObject(entry.artifact)
      || !isPlainObject(verification)
      || !coreVerificationValid(verification, record, ACCEPTANCE_VERIFICATION_KEYS, {
        document_action_binding_digest: documentActionBindingDigest,
        release_action_digest: releaseActionDigest,
      })
      || !parties.has(entry.party_id)
      || !required.has(entry.party_id)
      || seenParties.has(entry.party_id)
      || verification.party_id !== entry.party_id
      || !validString(verification.principal_key_id, 512)
      || seenKeys.has(verification.principal_key_id)
      || !validDigest(verification.acceptance_digest)) {
      return false;
    }
    seenParties.add(entry.party_id);
    seenKeys.add(verification.principal_key_id);
  }
  return true;
}

function storedFundingValid(record) {
  if (record.funding === null) return true;
  const template = record.document_action_binding.verification.release_action_template;
  const verification = record.funding?.verification;
  return exactKeys(record.funding, FUNDING_CONTAINER_KEYS)
    && isPlainObject(record.funding.statement)
    && coreVerificationValid(verification, record, FUNDING_VERIFICATION_KEYS)
    && verification.authenticated === true
    && verification.provider_id === record.profile.provider_id
    && verification.statement_type === 'funding'
    && verification.status === 'funded'
    && verification.provider_transaction_id === template.custodian_transaction_id
    && verification.provider_milestone_id === template.custodian_milestone_id
    && verification.amount === template.amount
    && verification.currency === template.currency
    && verification.destination_id === template.destination_id
    && validDigest(verification.statement_digest);
}

function storedMilestoneEvidenceValid(record) {
  if (record.milestone_evidence === null) return true;
  const verification = record.milestone_evidence?.verification;
  return exactKeys(record.milestone_evidence, CONTAINER_KEYS)
    && isPlainObject(record.milestone_evidence.artifact)
    && coreVerificationValid(verification, record, MILESTONE_VERIFICATION_KEYS)
    && validDigest(verification.evidence_digest)
    && record.parties.some((party) => (
      party.party_id === verification.submitter_party_id
    ))
    && validInstant(verification.observed_at);
}

function storedReleaseApprovalsValid(record) {
  if (!Array.isArray(record.release_approvals)
    || record.release_approvals.length > record.profile.required_release_approver_party_ids.length
    || (record.release_approvals.length > 0 && record.milestone_evidence === null)) {
    return false;
  }
  const required = new Set(record.profile.required_release_approver_party_ids);
  const parties = new Map(record.parties.map((party) => [party.party_id, party]));
  const seenParties = new Set();
  const seenKeys = new Set();
  const evidenceDigest = record.milestone_evidence?.verification?.evidence_digest;
  const bindingInput = resolutionBindingInput(record);
  const bindingMomentDigest = computeActionEscrowReleaseBindingMomentDigest(bindingInput);
  if (record.release_approvals.length > 0
    && (!validDigest(evidenceDigest) || !validDigest(bindingMomentDigest))) {
    return false;
  }
  for (const entry of record.release_approvals) {
    const party = parties.get(entry?.party_id);
    const verification = entry?.verification;
    const context = entry?.resolution?.signoff?.context;
    if (!exactKeys(entry, RELEASE_APPROVAL_KEYS)
      || !party
      || !required.has(entry.party_id)
      || seenParties.has(entry.party_id)
      || !isPlainObject(entry.resolution)
      || entry.resolution.profile !== RESOLUTION_VERSION
      || !isPlainObject(context)
      || !isPlainObject(context.resolution)
      || !coreVerificationValid(verification, record, RELEASE_APPROVAL_VERIFICATION_KEYS)
      || verification.authorizes_action !== true
      || verification.outcome !== 'approved'
      || verification.party_role !== party.role
      || !validString(verification.principal_key_id, 512)
      || seenKeys.has(verification.principal_key_id)
      || !validString(verification.nonce, 512)
      || !validInstant(verification.issued_at)
      || !validInstant(verification.expires_at)
      || verification.resolution_digest !== canonicalDigest(entry.resolution)
      || verification.evidence_digest !== evidenceDigest
      || context.principal !== entry.party_id
      || context.principal_key_id !== verification.principal_key_id
      || context.envelope_hash !== bindingMomentDigest
      || context.action_hash !== record.release_action_digest
      || context.initiator !== record.milestone_evidence.verification.submitter_party_id
      || context.nonce !== computeActionEscrowResolutionNonce(bindingInput, entry.party_id)
      || context.nonce !== verification.nonce
      || context.issued_at !== verification.issued_at
      || context.expires_at !== verification.expires_at
      || context.resolution.outcome !== 'approved'
      || context.resolution.selected_option !== 0) {
      return false;
    }
    seenParties.add(entry.party_id);
    seenKeys.add(verification.principal_key_id);
  }
  return true;
}

function storedHistoryValid(record) {
  if (!Array.isArray(record.operations)
    || record.operations.length === 0
    || !Array.isArray(record.history)
    || record.history.length === 0
    || record.operations.length > MAX_OPERATIONS
    || record.history.length > MAX_HISTORY) {
    return false;
  }
  const operations = new Map();
  for (const entry of record.operations) {
    if (!exactKeys(entry, OPERATION_KEYS)
      || !validString(entry.idempotency_key, 512)
      || operations.has(entry.idempotency_key)
      || !validString(entry.operation, 128)
      || !KERNEL_OPERATIONS.has(entry.operation)
      || !validDigest(entry.request_digest)
      || !validString(entry.code, 256)
      || typeof entry.ok !== 'boolean'
      || !validString(entry.outcome, 128)
      || !ACTION_ESCROW_STATES.includes(entry.state)
      || !validInstant(entry.at)) {
      return false;
    }
    operations.set(entry.idempotency_key, entry);
  }
  let previousState = null;
  for (const [index, entry] of record.history.entries()) {
    const operation = operations.get(entry?.idempotency_key);
    if (!exactKeys(entry, HISTORY_KEYS)
      || !ACTION_ESCROW_STATES.includes(entry.to)
      || (entry.from !== null && !ACTION_ESCROW_STATES.includes(entry.from))
      || !validString(entry.operation, 128)
      || !validString(entry.idempotency_key, 512)
      || !validInstant(entry.at)
      || !operation
      || operation.operation !== entry.operation
      || entry.from !== previousState
      || (index > 0 && !ACTION_ESCROW_TRANSITIONS[entry.from]?.includes(entry.to))) {
      return false;
    }
    if (index === 0 && (entry.from !== null || entry.to !== 'draft' || entry.operation !== 'create')) {
      return false;
    }
    previousState = entry.to;
  }
  return previousState === record.state;
}

function recordShapeValid(record, revision) {
  if (!exactKeys(record, RECORD_KEYS)
    || record['@version'] !== ACTION_ESCROW_STATE_VERSION
    || record.revision !== revision
    || !Number.isSafeInteger(record.revision)
    || record.revision < 0
    || !ACTION_ESCROW_STATES.includes(record.state)
    || !validString(record.escrow_key, 256)
    || !validDigest(record.agreement_digest)
    || !validDigest(record.document_action_binding_digest)
    || !validDigest(record.release_action_digest)
    || !validString(record.milestone_id, 256)
    || !validDigest(record.parties_digest)
    || !validDigest(record.profile_digest)
    || validateParties(record.parties)
    || validateProfileForParties(record.profile, record.parties)
    || record.parties_digest !== canonicalDigest(record.parties)
    || record.profile_digest !== canonicalDigest(record.profile)
    || record.escrow_key !== escrowKey(record)
    || !storedBindingVerificationValid(record.document_action_binding, record)
    || !Array.isArray(record.agreement_acceptances)
    || !Array.isArray(record.release_approvals)
    || !Array.isArray(record.superseded_bindings)
    || !Array.isArray(record.operations)
    || !Array.isArray(record.history)
    || record.operations.length > MAX_OPERATIONS
    || record.history.length > MAX_HISTORY
    || record.superseded_bindings.length > MAX_SUPERSEDED_BINDINGS
    || !validInstant(record.created_at)
    || !validInstant(record.updated_at)
    || !storedHistoryValid(record)
    || !storedAcceptancesValid(record.agreement_acceptances, record)
    || !storedFundingValid(record)
    || !storedMilestoneEvidenceValid(record)
    || !storedReleaseApprovalsValid(record)) {
    return false;
  }
  if (['release_reserved', 'released', 'release_indeterminate'].includes(record.state)
    && !isPlainObject(record.release)) {
    return false;
  }
  return true;
}

function existingOperation(record, normalized, operation) {
  const found = record.operations.find(
    (entry) => entry.idempotency_key === normalized.snapshot.idempotency_key,
  );
  if (!found) return null;
  if (found.operation !== operation || found.request_digest !== normalized.requestDigest) {
    return { conflict: true };
  }
  return { conflict: false, entry: found };
}

function idempotentResult(record, normalized, operation) {
  const existing = existingOperation(record, normalized, operation);
  if (!existing) return null;
  if (existing.conflict) {
    return outcome({
      code: 'idempotency_key_conflict',
      operation,
      record,
    });
  }
  if (operation === 'release'
    && ['release_reserved', 'release_indeterminate'].includes(record.state)) {
    return outcome({
      code: 'release_reconciliation_required',
      operation,
      record,
      type: 'indeterminate',
    });
  }
  return outcome({
    ok: foundOperationOk(existing.entry),
    type: foundOperationOk(existing.entry)
      ? 'idempotent'
      : existing.entry.outcome ?? 'refused',
    code: existing.entry.code,
    operation,
    record,
  });
}

function foundOperationOk(entry) {
  return entry.ok === undefined ? true : entry.ok === true;
}

function appendOperation(next, record, normalized, operation, code, at, result = {}) {
  if (record.operations.length >= MAX_OPERATIONS) {
    return 'operation_history_limit_reached';
  }
  next.operations.push({
    idempotency_key: normalized.snapshot.idempotency_key,
    operation,
    request_digest: normalized.requestDigest,
    code,
    ok: result.ok ?? true,
    outcome: result.type ?? 'applied',
    state: next.state,
    at,
  });
  return null;
}

function finalizeMutation(record, normalized, operation, code, at, mutate, result = {}) {
  const next = canonicalSnapshot(record);
  const fromState = next.state;
  mutate(next);
  next.revision = record.revision + 1;
  next.updated_at = at;
  const operationError = appendOperation(
    next,
    record,
    normalized,
    operation,
    code,
    at,
    result,
  );
  if (operationError) return { error: operationError };
  if (fromState !== next.state) {
    if (next.history.length >= MAX_HISTORY) return { error: 'state_history_limit_reached' };
    next.history.push({
      from: fromState,
      to: next.state,
      operation,
      idempotency_key: normalized.snapshot.idempotency_key,
      at,
    });
  }
  return { next };
}

  function providerExpected(record) {
    const template = record.document_action_binding.verification.release_action_template;
    return {
      ...expectedBindings(record),
      parties: record.parties,
      profile: record.profile,
      provider_id: record.profile.provider_id,
      provider_idempotency_key: record.release?.provider_idempotency_key ?? null,
      provider_request_digest: record.release?.provider_request?.request_digest ?? null,
      provider_transaction_id: template.custodian_transaction_id,
      provider_milestone_id: template.custodian_milestone_id,
      amount: template.amount,
      currency: template.currency,
      destination_id: template.destination_id,
    };
  }

/**
 * Create a fail-closed Action Escrow kernel.
 *
 * Store contract:
 *   durable === true
 *   atomicExpectedRevisionCas === true
 *   linearizableReads === true
 *   monotonicRevisions === true
 *   nonExpiring === true
 *   read(key) -> null | { revision, value: canonicalJsonText }
 *   compareAndSwap(key, expectedRevision|null, nextValue)
 *     -> { applied, revision }
 */
export function createActionEscrowKernel(options = {}) {
  let configurationError = null;
  let readStore = null;
  let compareAndSwap = null;
  let releaseProvider = null;
  let getProviderRelease = null;
  let verifyDocumentActionBinding = null;
  let verifyAgreementAcceptance = null;
  let verifyMilestoneEvidence = null;
  let verifyResolutionReceipt = null;
  let verifyProviderStatement = null;
  let verifyStateCommand = null;
  let resolveProfile = null;
  let pinnedProfiles = null;
  let now = null;
  let providerTimeoutMs = DEFAULT_PROVIDER_TIMEOUT_MS;

  try {
    if (!isPlainObject(options)) throw new Error('invalid options');
    const store = options.store;
    if (!STORE_CAPABILITIES.every((capability) => store?.[capability] === true)
      || typeof store?.read !== 'function'
      || typeof store?.compareAndSwap !== 'function') {
      configurationError = 'durable_cas_store_required';
    } else {
      readStore = store.read.bind(store);
      compareAndSwap = store.compareAndSwap.bind(store);
    }

    const provider = options.provider;
    if (!configurationError
      && (typeof provider?.release !== 'function'
        || typeof provider?.getRelease !== 'function')) {
      configurationError = 'release_provider_required';
    } else if (!configurationError) {
      releaseProvider = provider.release.bind(provider);
      getProviderRelease = provider.getRelease.bind(provider);
    }

    const verifierEntries = [
      ['verifyDocumentActionBinding', options.verifyDocumentActionBinding],
      ['verifyAgreementAcceptance', options.verifyAgreementAcceptance],
      ['verifyMilestoneEvidence', options.verifyMilestoneEvidence],
      ['verifyResolutionReceipt', options.verifyResolutionReceipt],
      ['verifyProviderStatement', options.verifyProviderStatement],
      ['verifyStateCommand', options.verifyStateCommand],
    ];
    if (!configurationError && verifierEntries.some(([, verifier]) => typeof verifier !== 'function')) {
      configurationError = 'pinned_verifiers_required';
    } else if (!configurationError) {
      verifyDocumentActionBinding = options.verifyDocumentActionBinding;
      verifyAgreementAcceptance = options.verifyAgreementAcceptance;
      verifyMilestoneEvidence = options.verifyMilestoneEvidence;
      verifyResolutionReceipt = options.verifyResolutionReceipt;
      verifyProviderStatement = options.verifyProviderStatement;
      verifyStateCommand = options.verifyStateCommand;
    }

    if (!configurationError && options.profilesById !== undefined) {
      const snapshot = canonicalSnapshot(options.profilesById);
      if (!isPlainObject(snapshot) || Object.keys(snapshot).length === 0) {
        configurationError = 'pinned_profile_configuration_invalid';
      } else {
        for (const [profileId, profile] of Object.entries(snapshot)) {
          if (profileId !== profile.profile_id || validateProfileShape(profile)) {
            configurationError = 'pinned_profile_configuration_invalid';
            break;
          }
        }
        if (!configurationError) pinnedProfiles = deepFreeze(snapshot);
      }
    } else if (!configurationError && typeof options.resolveProfile === 'function') {
      resolveProfile = options.resolveProfile;
    } else if (!configurationError) {
      configurationError = 'pinned_profile_resolver_required';
    }

    if (!configurationError && options.now !== undefined && typeof options.now !== 'function') {
      configurationError = 'clock_required';
    }
    now = typeof options.now === 'function' ? options.now : Date.now;

    if (options.providerTimeoutMs !== undefined) {
      if (!Number.isSafeInteger(options.providerTimeoutMs)
        || options.providerTimeoutMs <= 0
        || options.providerTimeoutMs > 300_000) {
        configurationError ??= 'provider_timeout_invalid';
      } else {
        providerTimeoutMs = options.providerTimeoutMs;
      }
    }
  } catch {
    configurationError ??= 'invalid_kernel_configuration';
  }

  async function safe(operation, task) {
    try {
      return await task();
    } catch {
      return outcome({
        code: 'kernel_internal_refusal',
        operation,
      });
    }
  }

  function configurationRefusal(operation) {
    return configurationError
      ? outcome({ code: configurationError, operation })
      : null;
  }

  function instant() {
    try {
      const candidate = now();
      const date = candidate instanceof Date ? candidate : new Date(candidate);
      return Number.isFinite(date.getTime()) ? date.toISOString() : null;
    } catch {
      return null;
    }
  }

  function operationInstant(record = null) {
    const at = instant();
    if (!at) return { error: 'invalid_clock' };
    if (record !== null && Date.parse(at) < Date.parse(record.updated_at)) {
      return { error: 'clock_regression' };
    }
    return { at };
  }

  async function withProviderTimeout(task) {
    let timer;
    try {
      return await Promise.race([
        Promise.resolve().then(task),
        new Promise((_, reject) => {
          timer = setTimeout(
            () => reject(new Error('provider_timeout')),
            providerTimeoutMs,
          );
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  }

  async function readRecord(key) {
    let envelope;
    try {
      envelope = await readStore(key);
    } catch {
      return { error: 'store_unavailable' };
    }
    if (envelope === null) return { record: null };
    try {
      if (!exactKeys(envelope, new Set(['revision', 'value']))
        || !Number.isSafeInteger(envelope.revision)
        || envelope.revision < 0
        || typeof envelope.value !== 'string'
        || Buffer.byteLength(envelope.value, 'utf8') > MAX_STATE_BYTES) {
        return { error: 'store_read_invalid' };
      }
      const record = JSON.parse(envelope.value);
      if (canonicalize(record) !== envelope.value
        || !recordShapeValid(record, envelope.revision)) {
        return { error: 'store_record_invalid' };
      }
      return { record: deepFreeze(record) };
    } catch {
      return { error: 'store_record_invalid' };
    }
  }

  async function writeRecord(key, expectedRevision, next) {
    let value;
    try {
      value = canonicalize(next);
    } catch {
      return { error: 'state_encoding_failed' };
    }
    let acknowledgement;
    try {
      acknowledgement = await compareAndSwap(key, expectedRevision, value);
    } catch {
      return { error: 'store_unavailable' };
    }
    try {
      const expectedNext = expectedRevision === null ? 0 : expectedRevision + 1;
      if (!exactKeys(acknowledgement, new Set(['applied', 'revision']))
        || (acknowledgement.applied !== true && acknowledgement.applied !== false)
        || (acknowledgement.revision !== null
          && (!Number.isSafeInteger(acknowledgement.revision)
            || acknowledgement.revision < 0))) {
        return { error: 'store_acknowledgement_invalid' };
      }
      if (acknowledgement.applied === true) {
        if (acknowledgement.revision !== expectedNext || next.revision !== expectedNext) {
          return { error: 'store_revision_invalid' };
        }
        return { applied: true };
      }
      return { applied: false };
    } catch {
      return { error: 'store_acknowledgement_invalid' };
    }
  }

  async function invokeVerifier(verifier, artifact, expected) {
    try {
      const artifactCopy = deepFreeze(canonicalSnapshot(artifact));
      const expectedCopy = deepFreeze(canonicalSnapshot(expected));
      const result = canonicalSnapshot(await verifier(artifactCopy, expectedCopy));
      if (!isPlainObject(result)) return { error: 'verifier_result_invalid' };
      return { artifact: artifactCopy, result };
    } catch {
      return { error: 'verifier_failed' };
    }
  }

  async function verifyStoredReleaseInputs(record, at) {
    const expectedCore = {
      ...expectedBindings(record),
      parties: record.parties,
      profile: record.profile,
    };
    const lastSupersession = record.superseded_bindings.at(-1);
    const expectedSupersedes = lastSupersession?.superseded_by_binding_digest
      === record.document_action_binding_digest
      ? lastSupersession.document_action_binding_digest
      : undefined;
    const bindingExpected = expectedSupersedes === undefined
      ? expectedCore
      : {
        ...expectedCore,
        supersedes_document_action_binding_digest: expectedSupersedes,
      };
    const binding = await invokeVerifier(
      verifyDocumentActionBinding,
      record.document_action_binding.artifact,
      bindingExpected,
    );
    const bindingDetails = binding.error
      ? null
      : bindingVerificationDetails(binding.result, bindingExpected);
    const storedBindingDetails = bindingVerificationDetails(
      record.document_action_binding.verification,
      record,
    );
    if (!bindingDetails
      || !storedBindingDetails
      || canonicalize(bindingDetails) !== canonicalize(storedBindingDetails)
      || (binding.result.supersedes_document_action_binding_digest ?? null)
        !== (record.document_action_binding.verification
          .supersedes_document_action_binding_digest ?? null)) {
      return { code: binding.error ?? 'document_action_binding_stale' };
    }

    const template = record.document_action_binding.verification.release_action_template;
    const fundingExpected = {
      ...expectedCore,
      provider_id: record.profile.provider_id,
      statement_type: 'funding',
      expected_status: 'funded',
      provider_transaction_id: template.custodian_transaction_id,
      provider_milestone_id: template.custodian_milestone_id,
      amount: template.amount,
      currency: template.currency,
      destination_id: template.destination_id,
    };
    const funding = await invokeVerifier(
      verifyProviderStatement,
      record.funding.statement,
      fundingExpected,
    );
    if (funding.error
      || !boundVerificationMatches(funding.result, expectedBindings(fundingExpected))
      || funding.result.authenticated !== true
      || funding.result.provider_id !== fundingExpected.provider_id
      || funding.result.statement_type !== 'funding'
      || funding.result.status !== 'funded'
      || funding.result.provider_transaction_id !== fundingExpected.provider_transaction_id
      || funding.result.provider_milestone_id !== fundingExpected.provider_milestone_id
      || funding.result.amount !== fundingExpected.amount
      || funding.result.currency !== fundingExpected.currency
      || funding.result.destination_id !== fundingExpected.destination_id
      || funding.result.statement_digest !== record.funding.verification.statement_digest) {
      return { code: funding.error ?? 'funding_statement_stale' };
    }

    const milestone = await invokeVerifier(
      verifyMilestoneEvidence,
      record.milestone_evidence.artifact,
      expectedCore,
    );
    const expectedEvidenceDigest = template.completion_evidence_sha256;
    if (milestone.error
      || !boundVerificationMatches(milestone.result, expectedBindings(expectedCore))
      || !validDigest(milestone.result.evidence_digest)
      || milestone.result.evidence_digest !== expectedEvidenceDigest
      || milestone.result.evidence_digest
        !== record.milestone_evidence.verification.evidence_digest
      || !record.parties.some((party) => (
        party.party_id === milestone.result.submitter_party_id
      ))
      || !validInstant(milestone.result.observed_at)
      || Date.parse(milestone.result.observed_at) > Date.parse(at)) {
      return { code: milestone.error ?? 'milestone_evidence_stale' };
    }

    const bindingInput = resolutionBindingInput(record);
    const bindingMoment = createActionEscrowReleaseBindingMoment(bindingInput);
    const bindingMomentDigest = bindingMoment === null
      ? null
      : canonicalDigest(bindingMoment);
    const expectedInitiator = record.milestone_evidence.verification.submitter_party_id;
    if (bindingMoment === null
      || bindingMomentDigest === null
      || !validString(expectedInitiator, 256)) {
      return { code: 'release_approval_context_invalid' };
    }
    for (const entry of record.release_approvals) {
      const context = entry.resolution.signoff.context;
      const expectedNonce = computeActionEscrowResolutionNonce(
        bindingInput,
        entry.party_id,
      );
      const expected = {
        ...expectedCore,
        party_id: entry.party_id,
        evidence_digest: record.milestone_evidence.verification.evidence_digest,
        binding_moment: bindingMoment,
        binding_moment_digest: bindingMomentDigest,
        expected_selected_option: 0,
        expected_initiator: expectedInitiator,
        expected_nonce: expectedNonce,
        evaluation_time: at,
      };
      const approval = await invokeVerifier(
        verifyResolutionReceipt,
        entry.resolution,
        expected,
      );
      if (approval.error
        || approval.result.valid !== true
        || approval.result.authorizes_action !== true
        || approval.result.outcome !== 'approved'
        || !boundVerificationMatches(approval.result, expectedBindings(expected))
        || approval.result.party_id !== entry.party_id
        || approval.result.party_role
          !== record.parties.find((party) => party.party_id === entry.party_id)?.role
        || approval.result.principal_key_id !== context.principal_key_id
        || approval.result.nonce !== context.nonce
        || approval.result.issued_at !== context.issued_at
        || approval.result.expires_at !== context.expires_at
        || approval.result.evidence_digest !== expected.evidence_digest
        || approval.result.principal_key_id !== entry.verification.principal_key_id
        || approval.result.nonce !== entry.verification.nonce
        || approval.result.issued_at !== entry.verification.issued_at
        || approval.result.expires_at !== entry.verification.expires_at) {
        return {
          code: approval.error ?? 'release_approval_stale',
          details: { party_id: entry.party_id },
        };
      }
    }
    return null;
  }

  async function verifyCommandAuthorization(
    artifact,
    record,
    command,
    partyId,
    details,
  ) {
    if (!record.parties.some((party) => party.party_id === partyId)) {
      return { error: 'command_party_invalid' };
    }
    const detailsDigest = canonicalDigest(details);
    const expected = {
      ...expectedBindings(record),
      profile: record.profile,
      parties: record.parties,
      command,
      party_id: partyId,
      details_digest: detailsDigest,
    };
    expected.command_digest = canonicalDigest({
      '@version': 'EP-ACTION-ESCROW-COMMAND-v1',
      ...expectedBindings(record),
      command,
      party_id: partyId,
      details_digest: detailsDigest,
    });
    const verified = await invokeVerifier(verifyStateCommand, artifact, expected);
    if (verified.error
      || verified.result.valid !== true
      || verified.result.authorizes_command !== true
      || verified.result.command !== command
      || verified.result.party_id !== partyId
      || verified.result.details_digest !== detailsDigest
      || verified.result.command_digest !== expected.command_digest
      || !boundVerificationMatches(verified.result, expectedBindings(record))) {
      return { error: verified.error ?? 'command_authorization_refused' };
    }
    return {
      artifact: verified.artifact,
      verification: {
        valid: true,
        authorizes_command: true,
        ...expectedBindings(record),
        command,
        party_id: partyId,
        details_digest: detailsDigest,
        command_digest: expected.command_digest,
      },
    };
  }

  async function selectedProfile(normalized) {
    try {
      let selected;
      if (pinnedProfiles) {
        if (!Object.hasOwn(pinnedProfiles, normalized.snapshot.profile.profile_id)) {
          return { error: 'profile_not_pinned' };
        }
        selected = pinnedProfiles[normalized.snapshot.profile.profile_id];
      } else {
        selected = canonicalSnapshot(await resolveProfile(
          normalized.snapshot.profile.profile_id,
          deepFreeze(canonicalSnapshot({
            agreement_digest: normalized.context.agreement_digest,
            milestone_id: normalized.context.milestone_id,
            parties: normalized.context.parties,
          })),
        ));
      }
      if (validateProfileForParties(selected, normalized.context.parties)
        || canonicalDigest(selected) !== normalized.context.profile_digest) {
        return { error: 'profile_not_pinned' };
      }
      return { profile: deepFreeze(canonicalSnapshot(selected)) };
    } catch {
      return { error: 'profile_resolution_failed' };
    }
  }

  async function create(input = {}) {
    const operation = 'create';
    return safe(operation, async () => {
      const normalized = normalizedInput(
        operation,
        input,
        ['document_action_binding'],
      );
      if (normalized.error) return outcome({ code: normalized.error, operation });
      const config = configurationRefusal(operation);
      if (config) return config;

      const pinned = await selectedProfile(normalized);
      if (pinned.error) return outcome({ code: pinned.error, operation });

      for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt++) {
        const loaded = await readRecord(normalized.escrowKey);
        if (loaded.error) return outcome({ code: loaded.error, operation });
        if (loaded.record) {
          if (!operationBindingMatches(loaded.record, normalized)) {
            return outcome({
              code: 'operation_binding_mismatch',
              operation,
              record: loaded.record,
            });
          }
          return idempotentResult(loaded.record, normalized, operation)
            ?? outcome({ code: 'escrow_already_exists', operation, record: loaded.record });
        }

        const at = instant();
        if (!at) return outcome({ code: 'invalid_clock', operation });
        const expected = {
          ...normalized.context,
          profile: pinned.profile,
        };
        const verification = await invokeVerifier(
          verifyDocumentActionBinding,
          normalized.snapshot.document_action_binding,
          expected,
        );
        const bindingDetails = verification.error
          ? null
          : bindingVerificationDetails(verification.result, expected);
        if (!bindingDetails) {
          return outcome({
            code: verification.error ?? 'document_action_binding_invalid',
            operation,
          });
        }

        const record = {
          '@version': ACTION_ESCROW_STATE_VERSION,
          escrow_key: normalized.escrowKey,
          revision: 0,
          state: 'draft',
          agreement_digest: normalized.context.agreement_digest,
          document_action_binding_digest:
            normalized.context.document_action_binding_digest,
          milestone_id: normalized.context.milestone_id,
          release_action_digest: normalized.context.release_action_digest,
          parties: normalized.context.parties,
          parties_digest: normalized.context.parties_digest,
          profile: pinned.profile,
          profile_digest: normalized.context.profile_digest,
          document_action_binding: {
            artifact: verification.artifact,
            verification: boundVerificationSummary(
              verification.result,
              expected,
              bindingDetails,
            ),
          },
          agreement_acceptances: [],
          funding: null,
          milestone_evidence: null,
          release_approvals: [],
          release: null,
          dispute: null,
          cancellation: null,
          completion: null,
          pending_amendment: null,
          superseded_bindings: [],
          operations: [{
            idempotency_key: normalized.snapshot.idempotency_key,
            operation,
            request_digest: normalized.requestDigest,
            code: 'escrow_created',
            ok: true,
            outcome: 'applied',
            state: 'draft',
            at,
          }],
          history: [{
            from: null,
            to: 'draft',
            operation,
            idempotency_key: normalized.snapshot.idempotency_key,
            at,
          }],
          created_at: at,
          updated_at: at,
        };
        const written = await writeRecord(normalized.escrowKey, null, record);
        if (written.error) return outcome({ code: written.error, operation });
        if (written.applied) {
          return outcome({
            ok: true,
            type: 'applied',
            code: 'escrow_created',
            operation,
            record,
          });
        }
      }
      return outcome({ code: 'store_conflict', operation });
    });
  }

  async function mutate(
    operation,
    input,
    {
      extraAllowed = [],
      extraRequired = extraAllowed,
      bindingMode = 'active',
      transform,
    },
  ) {
    return safe(operation, async () => {
      const normalized = normalizedInput(
        operation,
        input,
        extraAllowed,
        extraRequired,
      );
      if (normalized.error) return outcome({ code: normalized.error, operation });
      const config = configurationRefusal(operation);
      if (config) return config;

      for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt++) {
        const loaded = await readRecord(normalized.escrowKey);
        if (loaded.error) return outcome({ code: loaded.error, operation });
        if (!loaded.record) return outcome({ code: 'escrow_not_found', operation });
        const record = loaded.record;
        if (!operationBindingMatches(record, normalized, bindingMode)) {
          return outcome({
            code: 'operation_binding_mismatch',
            operation,
            record,
          });
        }
        const repeated = idempotentResult(record, normalized, operation);
        if (repeated) return repeated;
        const operationTime = operationInstant(record);
        if (operationTime.error) {
          return outcome({ code: operationTime.error, operation, record });
        }
        const { at } = operationTime;

        const draft = canonicalSnapshot(record);
        const decision = await transform(draft, normalized, at);
        if (decision?.refusal) {
          return outcome({
            code: decision.refusal,
            operation,
            record,
            details: decision.details ?? null,
            type: decision.type ?? 'refused',
          });
        }
        const code = decision?.code ?? `${operation}_applied`;
        const finalized = finalizeMutation(
          record,
          normalized,
          operation,
          code,
          at,
          (next) => {
            Object.assign(next, draft);
          },
          {
            ok: decision?.ok ?? true,
            type: decision?.type ?? 'applied',
          },
        );
        if (finalized.error) {
          return outcome({ code: finalized.error, operation, record });
        }
        const written = await writeRecord(
          normalized.escrowKey,
          record.revision,
          finalized.next,
        );
        if (written.error) return outcome({ code: written.error, operation, record });
        if (written.applied) {
          return outcome({
            ok: decision?.ok ?? true,
            type: decision?.type ?? 'applied',
            code,
            operation,
            record: finalized.next,
            details: decision?.details ?? null,
          });
        }
      }
      return outcome({ code: 'store_conflict', operation });
    });
  }

  async function beginAcceptance(input = {}) {
    return mutate('begin_acceptance', input, {
      transform(draft) {
        if (draft.state !== 'draft') {
          return { refusal: 'invalid_state_transition' };
        }
        draft.state = 'awaiting_acceptance';
        return { code: 'acceptance_requested' };
      },
    });
  }

  async function acceptAgreement(input = {}) {
    return mutate('accept_agreement', input, {
      extraAllowed: ['party_id', 'agreement_acceptance'],
      async transform(draft, normalized, at) {
        if (draft.state !== 'awaiting_acceptance') {
          return { refusal: 'invalid_state_transition' };
        }
        const partyId = normalized.snapshot.party_id;
        if (!draft.profile.required_acceptance_party_ids.includes(partyId)) {
          return { refusal: 'acceptance_party_not_required' };
        }
        if (draft.agreement_acceptances.some((entry) => entry.party_id === partyId)) {
          return { refusal: 'agreement_already_accepted' };
        }
        const expected = {
          ...normalized.context,
          party_id: partyId,
        };
        const verified = await invokeVerifier(
          verifyAgreementAcceptance,
          normalized.snapshot.agreement_acceptance,
          expected,
        );
        if (verified.error
          || !boundVerificationMatches(verified.result, expectedBindings(expected))
          || verified.result.party_id !== partyId
          || !validString(verified.result.principal_key_id, 512)
          || draft.agreement_acceptances.some(
            (entry) => entry.verification?.principal_key_id
              === verified.result.principal_key_id,
          )
          || !validDigest(verified.result.acceptance_digest)) {
          return { refusal: verified.error ?? 'agreement_acceptance_invalid' };
        }
        draft.agreement_acceptances.push({
          party_id: partyId,
          artifact: verified.artifact,
          verification: boundVerificationSummary(
            verified.result,
            expected,
            {
              party_id: partyId,
              principal_key_id: verified.result.principal_key_id,
              acceptance_digest: verified.result.acceptance_digest,
            },
          ),
        });
        const accepted = new Set(draft.agreement_acceptances.map((entry) => entry.party_id));
        if (draft.profile.required_acceptance_party_ids.every((id) => accepted.has(id))) {
          draft.state = 'effective';
          return { code: 'agreement_effective' };
        }
        return { code: 'agreement_acceptance_recorded' };
      },
    });
  }

  async function requestFunding(input = {}) {
    return mutate('request_funding', input, {
      transform(draft) {
        if (draft.state !== 'effective') {
          return { refusal: 'invalid_state_transition' };
        }
        draft.state = 'awaiting_funding';
        return { code: 'funding_requested' };
      },
    });
  }

  async function recordFunding(input = {}) {
    return mutate('record_funding', input, {
      extraAllowed: ['provider_statement'],
      async transform(draft, normalized, at) {
        if (draft.state !== 'awaiting_funding') {
          return { refusal: 'invalid_state_transition' };
        }
        const template = draft.document_action_binding.verification.release_action_template;
        const expected = {
          ...normalized.context,
          provider_id: draft.profile.provider_id,
          statement_type: 'funding',
          expected_status: 'funded',
          provider_transaction_id: template.custodian_transaction_id,
          provider_milestone_id: template.custodian_milestone_id,
          amount: template.amount,
          currency: template.currency,
          destination_id: template.destination_id,
        };
        const verified = await invokeVerifier(
          verifyProviderStatement,
          normalized.snapshot.provider_statement,
          expected,
        );
        if (verified.error
          || !boundVerificationMatches(verified.result, expectedBindings(expected))
          || verified.result.authenticated !== true
          || verified.result.provider_id !== draft.profile.provider_id
          || verified.result.statement_type !== 'funding'
          || verified.result.status !== 'funded'
          || verified.result.provider_transaction_id !== expected.provider_transaction_id
          || verified.result.provider_milestone_id !== expected.provider_milestone_id
          || verified.result.amount !== expected.amount
          || verified.result.currency !== expected.currency
          || verified.result.destination_id !== expected.destination_id
          || !validDigest(verified.result.statement_digest)) {
          return { refusal: verified.error ?? 'funding_statement_invalid' };
        }
        draft.funding = {
          statement: verified.artifact,
          verification: boundVerificationSummary(
            verified.result,
            expected,
            {
              authenticated: true,
              provider_id: draft.profile.provider_id,
              statement_type: 'funding',
              status: 'funded',
              provider_transaction_id: expected.provider_transaction_id,
              provider_milestone_id: expected.provider_milestone_id,
              amount: expected.amount,
              currency: expected.currency,
              destination_id: expected.destination_id,
              statement_digest: verified.result.statement_digest,
            },
          ),
        };
        draft.state = 'funded';
        return { code: 'funding_confirmed' };
      },
    });
  }

  async function submitMilestone(input = {}) {
    return mutate('submit_milestone', input, {
      extraAllowed: ['milestone_evidence'],
      async transform(draft, normalized, at) {
        if (draft.state !== 'funded') {
          return { refusal: 'invalid_state_transition' };
        }
        const expected = normalized.context;
        const verified = await invokeVerifier(
          verifyMilestoneEvidence,
          normalized.snapshot.milestone_evidence,
          expected,
        );
        const partyIds = draft.parties.map((party) => party.party_id);
        const expectedEvidenceDigest = draft.document_action_binding
          .verification.release_action_template.completion_evidence_sha256;
        if (verified.error
          || !boundVerificationMatches(verified.result, expectedBindings(expected))
          || !validDigest(verified.result.evidence_digest)
          || verified.result.evidence_digest !== expectedEvidenceDigest
          || !partyIds.includes(verified.result.submitter_party_id)
          || !validInstant(verified.result.observed_at)
          || Date.parse(verified.result.observed_at) > Date.parse(at)) {
          return { refusal: verified.error ?? 'milestone_evidence_invalid' };
        }
        draft.milestone_evidence = {
          artifact: verified.artifact,
          verification: boundVerificationSummary(
            verified.result,
            expected,
            {
              evidence_digest: verified.result.evidence_digest,
              submitter_party_id: verified.result.submitter_party_id,
              observed_at: verified.result.observed_at,
            },
          ),
        };
        draft.release_approvals = [];
        draft.state = 'milestone_submitted';
        return { code: 'milestone_evidence_recorded' };
      },
    });
  }

  async function approveRelease(input = {}) {
    return mutate('approve_release', input, {
      extraAllowed: ['party_id', 'resolution'],
      async transform(draft, normalized, at) {
        if (draft.state !== 'milestone_submitted') {
          return { refusal: 'invalid_state_transition' };
        }
        const partyId = normalized.snapshot.party_id;
        if (!draft.profile.required_release_approver_party_ids.includes(partyId)) {
          return { refusal: 'release_approval_party_not_required' };
        }
        const party = draft.parties.find((entry) => entry.party_id === partyId);
        if (draft.profile.prohibit_self_approval
          && partyId === draft.milestone_evidence?.verification?.submitter_party_id) {
          return { refusal: 'self_approval_refused' };
        }
        if (draft.release_approvals.some((entry) => entry.party_id === partyId)) {
          return { refusal: 'release_approval_already_recorded' };
        }

        const artifact = normalized.snapshot.resolution;
        const bindingInput = resolutionBindingInput(draft);
        const bindingMoment = createActionEscrowReleaseBindingMoment(bindingInput);
        const bindingMomentDigest = bindingMoment === null
          ? null
          : canonicalDigest(bindingMoment);
        const expectedNonce = computeActionEscrowResolutionNonce(bindingInput, partyId);
        const expectedInitiator = draft.milestone_evidence?.verification?.submitter_party_id;
        if (!isPlainObject(artifact)
          || artifact.profile !== RESOLUTION_VERSION
          || !isPlainObject(artifact.signoff)
          || !isPlainObject(artifact.signoff.context)
          || bindingMoment === null
          || bindingMomentDigest === null
          || expectedNonce === null
          || !validString(expectedInitiator, 256)) {
          return { refusal: 'resolution_profile_invalid' };
        }
        const resolutionContext = artifact.signoff.context;
        if (resolutionContext.principal !== partyId) {
          return { refusal: 'resolution_party_mismatch' };
        }
        if (resolutionContext.envelope_hash !== bindingMomentDigest) {
          return { refusal: 'resolution_binding_mismatch' };
        }
        if (resolutionContext.action_hash !== draft.release_action_digest) {
          return { refusal: 'resolution_action_mismatch' };
        }
        if (resolutionContext.initiator !== expectedInitiator) {
          return { refusal: 'resolution_initiator_mismatch' };
        }
        if (resolutionContext.nonce !== expectedNonce) {
          return { refusal: 'resolution_nonce_mismatch' };
        }
        if (resolutionContext.resolution?.outcome !== 'approved') {
          return { refusal: 'resolution_not_approved' };
        }
        if (!validString(resolutionContext.principal_key_id, 512)
          || !validString(resolutionContext.nonce, 512)
          || !validInstant(resolutionContext.issued_at)
          || !validInstant(resolutionContext.expires_at)
          || Date.parse(resolutionContext.issued_at)
            < Date.parse(draft.milestone_evidence.verification.observed_at)
          || Date.parse(resolutionContext.issued_at) > Date.parse(at)
          || Date.parse(resolutionContext.expires_at) <= Date.parse(at)
          || Date.parse(resolutionContext.expires_at)
            <= Date.parse(resolutionContext.issued_at)) {
          return { refusal: 'resolution_freshness_invalid' };
        }
        if (draft.release_approvals.some(
          (entry) => entry.verification?.principal_key_id
            === resolutionContext.principal_key_id,
        )) {
          return { refusal: 'resolution_key_already_counted' };
        }
        const expected = {
          ...normalized.context,
          party_id: partyId,
          evidence_digest: draft.milestone_evidence.verification.evidence_digest,
          binding_moment: bindingMoment,
          binding_moment_digest: bindingMomentDigest,
          expected_selected_option: 0,
          expected_initiator: expectedInitiator,
          expected_nonce: expectedNonce,
          evaluation_time: at,
        };
        const verified = await invokeVerifier(
          verifyResolutionReceipt,
          artifact,
          expected,
        );
        if (verified.error
          || verified.result.valid !== true
          || verified.result.authorizes_action !== true
          || verified.result.outcome !== 'approved'
          || !boundVerificationMatches(verified.result, expectedBindings(expected))
          || verified.result.party_id !== partyId
          || verified.result.party_role !== party.role
          || verified.result.principal_key_id !== resolutionContext.principal_key_id
          || verified.result.nonce !== resolutionContext.nonce
          || verified.result.issued_at !== resolutionContext.issued_at
          || verified.result.expires_at !== resolutionContext.expires_at
          || verified.result.evidence_digest !== expected.evidence_digest) {
          return { refusal: verified.error ?? 'resolution_verification_refused' };
        }
        draft.release_approvals.push({
          party_id: partyId,
          resolution: verified.artifact,
          verification: {
            valid: true,
            authorizes_action: true,
            outcome: 'approved',
            party_role: party.role,
            principal_key_id: resolutionContext.principal_key_id,
            nonce: resolutionContext.nonce,
            issued_at: resolutionContext.issued_at,
            expires_at: resolutionContext.expires_at,
            resolution_digest: canonicalDigest(verified.artifact),
            agreement_digest: draft.agreement_digest,
            document_action_binding_digest: draft.document_action_binding_digest,
            milestone_id: draft.milestone_id,
            release_action_digest: draft.release_action_digest,
            parties_digest: draft.parties_digest,
            profile_digest: draft.profile_digest,
            evidence_digest: draft.milestone_evidence.verification.evidence_digest,
          },
        });
        return { code: 'release_approval_recorded' };
      },
    });
  }

  async function releasePreconditions(record, at) {
    if (record.funding?.verification?.status !== 'funded') {
      return { code: 'funding_not_verified' };
    }
    if (!validDigest(record.milestone_evidence?.verification?.evidence_digest)) {
      return { code: 'milestone_evidence_not_verified' };
    }
    const approved = new Set(record.release_approvals
      .filter((entry) => entry.verification?.authorizes_action === true
        && entry.verification?.document_action_binding_digest
          === record.document_action_binding_digest
        && entry.verification?.release_action_digest === record.release_action_digest
        && entry.verification?.evidence_digest
          === record.milestone_evidence.verification.evidence_digest)
      .map((entry) => entry.party_id));
    const missing = record.profile.required_release_approver_party_ids
      .filter((partyId) => !approved.has(partyId));
    if (missing.length > 0) {
      return { code: 'release_approval_missing', details: { missing_party_ids: missing } };
    }
    const evaluationTime = Date.parse(at);
    const stale = record.release_approvals
      .filter((entry) => (
        !validInstant(entry.verification?.issued_at)
        || !validInstant(entry.verification?.expires_at)
        || Date.parse(entry.verification.issued_at) > evaluationTime
        || Date.parse(entry.verification.expires_at) <= evaluationTime
      ))
      .map((entry) => entry.party_id);
    if (stale.length > 0) {
      return { code: 'release_approval_expired', details: { party_ids: stale } };
    }
    return verifyStoredReleaseInputs(record, at);
  }

  function providerRequestFor(record) {
    const bindingVerification = record.document_action_binding.verification;
    const request = {
      method: 'POST',
      provider_id: record.profile.provider_id,
      agreement_digest: record.agreement_digest,
      document_action_binding_digest: record.document_action_binding_digest,
      milestone_id: record.milestone_id,
      release_action_digest: record.release_action_digest,
      parties: record.parties,
      parties_digest: record.parties_digest,
      profile: record.profile,
      profile_digest: record.profile_digest,
      agreement_id: bindingVerification.agreement_id,
      binding_id: bindingVerification.binding_id,
      document_digest: bindingVerification.document_digest,
      release_action_template: bindingVerification.release_action_template,
      release_key: releaseReservationKey(record),
      idempotency_key: providerIdempotencyKey(record),
    };
    return {
      ...request,
      request_digest: canonicalDigest({
        '@version': 'EP-ACTION-ESCROW-PROVIDER-REQUEST-v1',
        ...request,
      }),
    };
  }

  async function authoritativeProviderRelease(record) {
    const request = {
      ...record.release.provider_request,
      method: 'GET',
    };
    let response;
    try {
      response = canonicalSnapshot(await withProviderTimeout(
        () => getProviderRelease(deepFreeze(canonicalSnapshot(request))),
      ));
    } catch {
      return { error: 'provider_reconciliation_failed' };
    }
    if (!exactKeys(response, new Set(['authenticated', 'statement']))
      || response.authenticated !== true) {
      return { error: 'provider_reconciliation_unauthenticated' };
    }
    const expected = providerExpected(record);
    const verified = await invokeVerifier(
      verifyProviderStatement,
      response.statement,
      expected,
    );
    if (verified.error
      || !boundVerificationMatches(verified.result, expectedBindings(expected))
      || verified.result.authenticated !== true
      || verified.result.provider_id !== expected.provider_id
      || verified.result.statement_type !== 'release'
      || !['released', 'not_released', 'pending'].includes(verified.result.status)
      || !validDigest(verified.result.statement_digest)
      || verified.result.provider_idempotency_key !== expected.provider_idempotency_key
      || verified.result.provider_request_digest !== expected.provider_request_digest
      || verified.result.provider_transaction_id !== expected.provider_transaction_id
      || verified.result.provider_milestone_id !== expected.provider_milestone_id
      || verified.result.amount !== expected.amount
      || verified.result.currency !== expected.currency
      || verified.result.destination_id !== expected.destination_id) {
      return { error: verified.error ?? 'provider_release_statement_invalid' };
    }
    return {
      artifact: verified.artifact,
      verification: boundVerificationSummary(
        verified.result,
        expected,
        {
          authenticated: true,
          provider_id: expected.provider_id,
          provider_idempotency_key: expected.provider_idempotency_key,
          provider_request_digest: expected.provider_request_digest,
          provider_transaction_id: expected.provider_transaction_id,
          provider_milestone_id: expected.provider_milestone_id,
          amount: expected.amount,
          currency: expected.currency,
          destination_id: expected.destination_id,
          statement_type: 'release',
          status: verified.result.status,
          statement_digest: verified.result.statement_digest,
        },
      ),
    };
  }

  function updateReleaseOperation(next, idempotencyKey, code, state) {
    const entry = next.operations.find(
      (operation) => operation.operation === 'release'
        && operation.idempotency_key === idempotencyKey,
    );
    if (entry) {
      entry.code = code;
      entry.ok = state === 'released';
      entry.outcome = state === 'released'
        ? 'applied'
        : state === 'release_indeterminate'
          ? 'indeterminate'
          : 'refused';
      entry.state = state;
    }
  }

  function internalReleaseTransition(record, targetState, code, at, providerResult = null) {
    const next = canonicalSnapshot(record);
    const from = next.state;
    next.state = targetState;
    next.revision = record.revision + 1;
    next.updated_at = at;
    next.release.status = targetState === 'released'
      ? 'released'
      : targetState === 'milestone_submitted'
        ? 'not_released'
        : 'indeterminate';
    next.release.reconciled_at = at;
    if (providerResult) {
      next.release.provider_statement = providerResult.artifact;
      next.release.provider_verification = providerResult.verification;
    }
    updateReleaseOperation(
      next,
      next.release.operation_idempotency_key,
      code,
      targetState,
    );
    if (from !== targetState) {
      if (next.history.length >= MAX_HISTORY) return { error: 'state_history_limit_reached' };
      next.history.push({
        from,
        to: targetState,
        operation: 'release',
        idempotency_key: next.release.operation_idempotency_key,
        at,
      });
    }
    return { next };
  }

  async function readLatestRelease(record) {
    const loaded = await readRecord(record.escrow_key);
    return loaded.error ? { error: loaded.error } : { record: loaded.record };
  }

  async function freezeIndeterminate(record, operation, code, providerResult = null) {
    let current = record;
    for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt++) {
      if (current?.state === 'released') {
        return outcome({
          ok: true,
          type: 'reconciled',
          code: 'release_committed',
          operation,
          record: current,
        });
      }
      if (current?.state === 'release_indeterminate') {
        return outcome({
          type: 'indeterminate',
          code,
          operation,
          record: current,
        });
      }
      if (current?.state !== 'release_reserved') {
        return outcome({
          type: 'indeterminate',
          code,
          operation,
          record: current,
        });
      }
      const operationTime = operationInstant(current);
      if (operationTime.error) {
        return outcome({
          type: 'indeterminate',
          code: operationTime.error,
          operation,
          record: current,
        });
      }
      const { at } = operationTime;
      const transition = internalReleaseTransition(
        current,
        'release_indeterminate',
        code,
        at,
        providerResult,
      );
      if (transition.error) {
        return outcome({
          type: 'indeterminate',
          code: transition.error,
          operation,
          record: current,
        });
      }
      const written = await writeRecord(
        current.escrow_key,
        current.revision,
        transition.next,
      );
      if (written.applied) {
        return outcome({
          type: 'indeterminate',
          code,
          operation,
          record: transition.next,
        });
      }
      const latest = await readLatestRelease(current);
      if (latest.error) {
        return outcome({
          type: 'indeterminate',
          code,
          operation,
          record: current,
        });
      }
      current = latest.record;
    }
    return outcome({
      type: 'indeterminate',
      code,
      operation,
      record: current,
    });
  }

  async function commitReleaseResult(record, providerResult, operation) {
    const status = providerResult.verification.status;
    const operationTime = operationInstant(record);
    if (operationTime.error) {
      return freezeIndeterminate(
        record,
        operation,
        operationTime.error,
        providerResult,
      );
    }
    const { at } = operationTime;
    const targetState = status === 'released'
      ? 'released'
      : status === 'not_released'
        ? 'milestone_submitted'
        : 'release_indeterminate';
    const code = status === 'released'
      ? 'release_committed'
      : status === 'not_released'
        ? 'provider_release_not_released'
        : 'release_effect_indeterminate';
    const transition = internalReleaseTransition(
      record,
      targetState,
      code,
      at,
      providerResult,
    );
    if (transition.error) {
      return freezeIndeterminate(
        record,
        operation,
        'release_commit_indeterminate',
        providerResult,
      );
    }
    const written = await writeRecord(record.escrow_key, record.revision, transition.next);
    if (written.applied) {
      return outcome({
        ok: status === 'released',
        type: status === 'released' ? 'applied' : status === 'pending' ? 'indeterminate' : 'refused',
        code,
        operation,
        record: transition.next,
      });
    }

    const latest = await readLatestRelease(record);
    if (!latest.error
      && latest.record?.state === 'released'
      && latest.record.release?.release_key === record.release.release_key) {
      return outcome({
        ok: true,
        type: 'idempotent',
        code: 'release_committed',
        operation,
        record: latest.record,
      });
    }
    return freezeIndeterminate(
      latest.record ?? record,
      operation,
      'release_commit_indeterminate',
      providerResult,
    );
  }

  async function release(input = {}) {
    const operation = 'release';
    return safe(operation, async () => {
      const normalized = normalizedInput(operation, input);
      if (normalized.error) return outcome({ code: normalized.error, operation });
      const config = configurationRefusal(operation);
      if (config) return config;

      let reserved = null;
      for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt++) {
        const loaded = await readRecord(normalized.escrowKey);
        if (loaded.error) return outcome({ code: loaded.error, operation });
        if (!loaded.record) return outcome({ code: 'escrow_not_found', operation });
        const record = loaded.record;
        if (!operationBindingMatches(record, normalized)) {
          return outcome({ code: 'operation_binding_mismatch', operation, record });
        }
        const repeated = idempotentResult(record, normalized, operation);
        if (repeated) return repeated;
        if (['released', 'completed'].includes(record.state)) {
          return outcome({ code: 'release_already_applied', operation, record });
        }
        if (['release_reserved', 'release_indeterminate'].includes(record.state)) {
          return outcome({
            code: 'release_reconciliation_required',
            operation,
            record,
            type: 'indeterminate',
          });
        }
        if (record.state !== 'milestone_submitted') {
          return outcome({ code: 'invalid_state_transition', operation, record });
        }
        const operationTime = operationInstant(record);
        if (operationTime.error) {
          return outcome({ code: operationTime.error, operation, record });
        }
        const { at } = operationTime;
        const precondition = await releasePreconditions(record, at);
        if (precondition) {
          return outcome({
            code: precondition.code,
            operation,
            record,
            details: precondition.details ?? null,
          });
        }
        const request = providerRequestFor(record);
        const finalized = finalizeMutation(
          record,
          normalized,
          operation,
          'release_reserved',
          at,
          (next) => {
            next.state = 'release_reserved';
            next.release = {
              release_key: request.release_key,
              provider_idempotency_key: request.idempotency_key,
              operation_idempotency_key: normalized.snapshot.idempotency_key,
              status: 'reserved',
              reserved_at: at,
              reconciled_at: null,
              provider_request: request,
              provider_statement: null,
              provider_verification: null,
            };
          },
          { ok: false, type: 'reserved' },
        );
        if (finalized.error) {
          return outcome({ code: finalized.error, operation, record });
        }
        const written = await writeRecord(
          normalized.escrowKey,
          record.revision,
          finalized.next,
        );
        if (written.error) return outcome({ code: written.error, operation, record });
        if (written.applied) {
          reserved = deepFreeze(finalized.next);
          break;
        }
      }
      if (!reserved) return outcome({ code: 'store_conflict', operation });

      try {
        await withProviderTimeout(
          () => releaseProvider(
            deepFreeze(canonicalSnapshot(reserved.release.provider_request)),
          ),
        );
      } catch {
        return freezeIndeterminate(
          reserved,
          operation,
          'release_effect_indeterminate',
        );
      }

      const reconciled = await authoritativeProviderRelease(reserved);
      if (reconciled.error) {
        return freezeIndeterminate(
          reserved,
          operation,
          'release_effect_indeterminate',
        );
      }
      return commitReleaseResult(reserved, reconciled, operation);
    });
  }

  async function reconcileRelease(input = {}) {
    const operation = 'reconcile_release';
    return safe(operation, async () => {
      const normalized = normalizedInput(operation, input);
      if (normalized.error) return outcome({ code: normalized.error, operation });
      const config = configurationRefusal(operation);
      if (config) return config;

      for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt++) {
        const loaded = await readRecord(normalized.escrowKey);
        if (loaded.error) return outcome({ code: loaded.error, operation });
        if (!loaded.record) return outcome({ code: 'escrow_not_found', operation });
        const record = loaded.record;
        if (!operationBindingMatches(record, normalized)) {
          return outcome({ code: 'operation_binding_mismatch', operation, record });
        }
        const repeated = idempotentResult(record, normalized, operation);
        if (repeated) return repeated;
        if (record.state === 'released') {
          return outcome({
            ok: true,
            type: 'idempotent',
            code: 'release_already_applied',
            operation,
            record,
          });
        }
        if (!['release_reserved', 'release_indeterminate'].includes(record.state)) {
          return outcome({ code: 'invalid_state_transition', operation, record });
        }
        if (record.release?.provider_idempotency_key !== providerIdempotencyKey(record)
          || record.release?.release_key !== releaseReservationKey(record)) {
          return outcome({ code: 'release_binding_corrupt', operation, record });
        }

        const providerResult = await authoritativeProviderRelease(record);
        if (providerResult.error) {
          return outcome({
            code: providerResult.error,
            operation,
            record,
            type: 'indeterminate',
          });
        }
        const operationTime = operationInstant(record);
        if (operationTime.error) {
          return outcome({
            code: operationTime.error,
            operation,
            record,
            type: 'indeterminate',
          });
        }
        const { at } = operationTime;
        const status = providerResult.verification.status;
        const targetState = status === 'released'
          ? 'released'
          : status === 'not_released'
            ? record.pending_amendment ? 'amendment_pending' : 'milestone_submitted'
            : 'release_indeterminate';
        const code = status === 'released'
          ? 'release_reconciled_released'
          : status === 'not_released'
            ? 'release_reconciled_not_released'
            : 'release_still_indeterminate';
        const draft = canonicalSnapshot(record);
        draft.state = targetState;
        draft.release.status = status === 'pending' ? 'indeterminate' : status;
        draft.release.reconciled_at = at;
        draft.release.provider_statement = providerResult.artifact;
        draft.release.provider_verification = providerResult.verification;
        if (status === 'not_released' && draft.pending_amendment) {
          draft.funding = null;
          draft.milestone_evidence = null;
          draft.release_approvals = [];
        }
        updateReleaseOperation(
          draft,
          draft.release.operation_idempotency_key,
          code,
          targetState,
        );
        const finalized = finalizeMutation(
          record,
          normalized,
          operation,
          code,
          at,
          (next) => Object.assign(next, draft),
          {
            ok: status !== 'pending',
            type: status === 'pending' ? 'indeterminate' : 'reconciled',
          },
        );
        if (finalized.error) {
          return outcome({
            code: finalized.error,
            operation,
            record,
            type: 'indeterminate',
          });
        }
        const written = await writeRecord(
          normalized.escrowKey,
          record.revision,
          finalized.next,
        );
        if (written.error) {
          return outcome({
            code: written.error,
            operation,
            record,
            type: 'indeterminate',
          });
        }
        if (written.applied) {
          return outcome({
            ok: status !== 'pending',
            type: status === 'pending' ? 'indeterminate' : 'reconciled',
            code,
            operation,
            record: finalized.next,
          });
        }
      }
      return outcome({
        code: 'store_conflict',
        operation,
        type: 'indeterminate',
      });
    });
  }

  async function openDispute(input = {}) {
    return mutate('open_dispute', input, {
      extraAllowed: ['party_id', 'reason', 'command_authorization'],
      async transform(draft, normalized, at) {
        if (!['funded', 'milestone_submitted'].includes(draft.state)) {
          return { refusal: 'invalid_state_transition' };
        }
        const partyId = normalized.snapshot.party_id;
        if (!draft.parties.some((party) => party.party_id === partyId)
          || !validString(normalized.snapshot.reason, 2048)) {
          return { refusal: 'dispute_input_invalid' };
        }
        const authorization = await verifyCommandAuthorization(
          normalized.snapshot.command_authorization,
          draft,
          'open_dispute',
          partyId,
          { reason: normalized.snapshot.reason },
        );
        if (authorization.error) return { refusal: authorization.error };
        draft.dispute = {
          party_id: partyId,
          reason: normalized.snapshot.reason,
          authorization,
          opened_at: at,
        };
        draft.state = 'disputed';
        return { code: 'dispute_opened' };
      },
    });
  }

  async function proposeAmendment(input = {}) {
    return mutate('propose_amendment', input, {
      extraAllowed: [
        'party_id',
        'command_authorization',
        'next_document_action_binding_digest',
        'next_release_action_digest',
        'next_document_action_binding',
      ],
      async transform(draft, normalized, at) {
        if (draft.state === 'awaiting_funding') {
          return { refusal: 'amendment_requires_funding_reconciliation' };
        }
        if (draft.funding !== null
          || draft.release !== null
          || ['funded', 'milestone_submitted', 'disputed'].includes(draft.state)) {
          return { refusal: 'amendment_requires_custodian_unwind' };
        }
        if (draft.state !== 'effective'
          || draft.pending_amendment) {
          return { refusal: 'invalid_state_transition' };
        }
        const nextBindingDigest =
          normalized.snapshot.next_document_action_binding_digest;
        const nextActionDigest = normalized.snapshot.next_release_action_digest;
        if (!validDigest(nextBindingDigest)
          || !validDigest(nextActionDigest)
          || nextBindingDigest === draft.document_action_binding_digest) {
          return { refusal: 'amendment_binding_invalid' };
        }
        const partyId = normalized.snapshot.party_id;
        const authorization = await verifyCommandAuthorization(
          normalized.snapshot.command_authorization,
          draft,
          'propose_amendment',
          partyId,
          {
            next_document_action_binding_digest: nextBindingDigest,
            next_release_action_digest: nextActionDigest,
          },
        );
        if (authorization.error) return { refusal: authorization.error };
        const nextContext = {
          ...normalized.context,
          document_action_binding_digest: nextBindingDigest,
          release_action_digest: nextActionDigest,
          supersedes_document_action_binding_digest:
            draft.document_action_binding_digest,
        };
        const verified = await invokeVerifier(
          verifyDocumentActionBinding,
          normalized.snapshot.next_document_action_binding,
          nextContext,
        );
        const bindingDetails = verified.error
          ? null
          : bindingVerificationDetails(verified.result, nextContext);
        if (!bindingDetails
          || verified.result.supersedes_document_action_binding_digest
            !== draft.document_action_binding_digest
        ) {
          return { refusal: verified.error ?? 'amendment_document_binding_invalid' };
        }

        draft.pending_amendment = {
          from_state: draft.state,
          document_action_binding_digest: nextBindingDigest,
          release_action_digest: nextActionDigest,
          document_action_binding: {
            artifact: verified.artifact,
            verification: boundVerificationSummary(
              verified.result,
              nextContext,
              {
                ...bindingDetails,
                supersedes_document_action_binding_digest:
                  draft.document_action_binding_digest,
              },
            ),
          },
          agreement_acceptances: [],
          proposer_party_id: partyId,
          proposal_authorization: authorization,
          proposed_at: at,
        };
        draft.funding = null;
        draft.milestone_evidence = null;
        draft.release_approvals = [];
        draft.release = null;
        draft.dispute = null;
        draft.cancellation = null;
        draft.state = 'amendment_pending';
        return { code: 'amendment_pending' };
      },
    });
  }

  async function acceptAmendment(input = {}) {
    return mutate('accept_amendment', input, {
      extraAllowed: ['party_id', 'agreement_acceptance'],
      bindingMode: 'pending',
      async transform(draft, normalized, at) {
        if (draft.state !== 'amendment_pending' || !draft.pending_amendment) {
          return { refusal: 'invalid_state_transition' };
        }
        const partyId = normalized.snapshot.party_id;
        if (!draft.profile.required_acceptance_party_ids.includes(partyId)) {
          return { refusal: 'acceptance_party_not_required' };
        }
        if (draft.pending_amendment.agreement_acceptances
          .some((entry) => entry.party_id === partyId)) {
          return { refusal: 'amendment_already_accepted' };
        }
        const expected = {
          ...normalized.context,
          party_id: partyId,
        };
        const verified = await invokeVerifier(
          verifyAgreementAcceptance,
          normalized.snapshot.agreement_acceptance,
          expected,
        );
        if (verified.error
          || !boundVerificationMatches(verified.result, expectedBindings(expected))
          || verified.result.party_id !== partyId
          || !validString(verified.result.principal_key_id, 512)
          || draft.pending_amendment.agreement_acceptances.some(
            (entry) => entry.verification?.principal_key_id
              === verified.result.principal_key_id,
          )
          || !validDigest(verified.result.acceptance_digest)) {
          return { refusal: verified.error ?? 'amendment_acceptance_invalid' };
        }
        draft.pending_amendment.agreement_acceptances.push({
          party_id: partyId,
          artifact: verified.artifact,
          verification: boundVerificationSummary(
            verified.result,
            expected,
            {
              party_id: partyId,
              principal_key_id: verified.result.principal_key_id,
              acceptance_digest: verified.result.acceptance_digest,
            },
          ),
        });
        const accepted = new Set(
          draft.pending_amendment.agreement_acceptances
            .map((entry) => entry.party_id),
        );
        if (!draft.profile.required_acceptance_party_ids
          .every((id) => accepted.has(id))) {
          return { code: 'amendment_acceptance_recorded' };
        }
        if (draft.superseded_bindings.length >= MAX_SUPERSEDED_BINDINGS) {
          return { refusal: 'supersession_history_limit_reached' };
        }
        const pending = draft.pending_amendment;
        draft.superseded_bindings.push({
          document_action_binding_digest: draft.document_action_binding_digest,
          release_action_digest: draft.release_action_digest,
          superseded_by_binding_digest: pending.document_action_binding_digest,
          superseded_at: at,
        });
        draft.document_action_binding_digest =
          pending.document_action_binding_digest;
        draft.release_action_digest = pending.release_action_digest;
        draft.document_action_binding = pending.document_action_binding;
        draft.agreement_acceptances = pending.agreement_acceptances;
        draft.funding = null;
        draft.milestone_evidence = null;
        draft.release_approvals = [];
        draft.release = null;
        draft.dispute = null;
        draft.cancellation = null;
        draft.pending_amendment = null;
        draft.state = 'effective';
        return { code: 'amendment_effective' };
      },
    });
  }

  async function cancel(input = {}) {
    return mutate('cancel', input, {
      extraAllowed: ['party_id', 'reason', 'command_authorization'],
      extraRequired: ['party_id', 'command_authorization'],
      async transform(draft, normalized, at) {
        if (draft.state === 'awaiting_funding') {
          return { refusal: 'cancellation_requires_funding_reconciliation' };
        }
        if (draft.funding !== null || draft.release !== null) {
          return { refusal: 'cancellation_requires_custodian_unwind' };
        }
        if (![
          'draft',
          'awaiting_acceptance',
          'effective',
          'amendment_pending',
        ].includes(draft.state)) {
          return { refusal: 'invalid_state_transition' };
        }
        if (normalized.snapshot.reason !== undefined
          && !validString(normalized.snapshot.reason, 2048)) {
          return { refusal: 'cancellation_reason_invalid' };
        }
        const authorization = await verifyCommandAuthorization(
          normalized.snapshot.command_authorization,
          draft,
          'cancel',
          normalized.snapshot.party_id,
          { reason: normalized.snapshot.reason ?? null },
        );
        if (authorization.error) return { refusal: authorization.error };
        draft.state = 'cancelled';
        draft.cancellation = {
          party_id: normalized.snapshot.party_id,
          reason: normalized.snapshot.reason ?? null,
          authorization,
          cancelled_at: at,
        };
        return { code: 'escrow_cancelled' };
      },
    });
  }

  async function complete(input = {}) {
    return mutate('complete', input, {
      extraAllowed: ['party_id', 'command_authorization'],
      extraRequired: ['party_id', 'command_authorization'],
      async transform(draft, normalized, at) {
        if (draft.state !== 'released') {
          return { refusal: 'invalid_state_transition' };
        }
        const authorization = await verifyCommandAuthorization(
          normalized.snapshot.command_authorization,
          draft,
          'complete',
          normalized.snapshot.party_id,
          { meaning: 'administrative_archive_only' },
        );
        if (authorization.error) return { refusal: authorization.error };
        draft.state = 'completed';
        draft.completion = {
          party_id: normalized.snapshot.party_id,
          meaning: 'administrative_archive_only',
          authorization,
          completed_at: at,
        };
        return { code: 'escrow_completed' };
      },
    });
  }

  const methods = {
    create,
    beginAcceptance,
    acceptAgreement,
    requestFunding,
    recordFunding,
    submitMilestone,
    approveRelease,
    release,
    reconcileRelease,
    openDispute,
    proposeAmendment,
    acceptAmendment,
    cancel,
    complete,
  };

  async function apply(operation, input = {}) {
    try {
      const selected = methods[operation];
      if (typeof selected !== 'function') {
        return outcome({
          code: 'unknown_operation',
          operation: validString(operation, 128) ? operation : null,
        });
      }
      return selected(input);
    } catch {
      return outcome({
        code: 'invalid_operation_input',
        operation: null,
      });
    }
  }

  return Object.freeze({
    ready: configurationError === null,
    configuration: Object.freeze({
      ok: configurationError === null,
      reason: configurationError,
    }),
    apply,
    ...methods,
  });
}

export default Object.freeze({
  ACTION_ESCROW_STATE_VERSION,
  ACTION_ESCROW_OUTCOME_VERSION,
  ACTION_ESCROW_PROFILE_VERSION,
  ACTION_ESCROW_STATES,
  ACTION_ESCROW_TRANSITIONS,
  createActionEscrowReleaseBindingMoment,
  computeActionEscrowReleaseBindingMomentDigest,
  computeActionEscrowResolutionNonce,
  createActionEscrowKernel,
});
