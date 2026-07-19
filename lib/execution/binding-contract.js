// SPDX-License-Identifier: Apache-2.0
// EP execution-binding contract for high-risk system-of-record mutations.
//
// Execution integrity proves "the executed canonical action hashes to the
// approved action hash." This contract closes the adjacent gateway gap: for
// high-risk actions, the executor must also attest the system-observed critical
// fields (money, destination, record, permission, policy, state hashes, etc.)
// match the fields the receipt authorized.

import { GUARD_ACTION_TYPES, hashCanonicalAction } from '../guard-policies.js';

export const EXECUTION_BINDING_CONTRACT_VERSION = 'EP-EXECUTION-BINDING-v1';

const COMMON_FIELDS = Object.freeze([
  'organization_id',
  'actor_id',
  'action_type',
  'target_resource_id',
  'policy_id',
  'policy_hash',
  'before_state_hash',
  'after_state_hash',
]);

const MONEY_FIELDS = Object.freeze([
  'amount',
  'currency',
  'counterparty_name',
  'counterparty_country',
  'beneficiary_name',
  'beneficiary_country',
  'payee_name',
  'payment_instruction_id',
  'destination_hash',
  'payment_destination_hash',
  'bank_account',
  'bank_account_hash',
  'routing_number',
  'routing_number_hash',
  'iban',
  'swift_bic',
  'payment_address',
]);

const BENEFIT_IDENTITY_FIELDS = Object.freeze([
  'address_hash',
  'mailing_address_hash',
  'phone_hash',
  'email_hash',
  'contact_method',
  'identity_document_hash',
  'identity_status',
  'claimant_id',
]);

const GOV_PROGRAM_FIELDS = Object.freeze([
  'agency_id',
  'program_id',
  'recipient_id',
  'grant_id',
  'award_id',
  'vendor_id',
  'provider_id',
  'provider_tax_id_hash',
  'provider_status',
  'npi',
  'claimant_id',
  'eligibility_case_id',
  'eligibility_rule',
  'eligibility_status',
  'benefit_amount',
]);

const RECORD_FIELDS = Object.freeze([
  'case_id',
  'decision_id',
  'subject_id',
  'record_id',
  'target_changed_fields',
  'override_reason',
  'regulated_decision',
]);

const PERMISSION_FIELDS = Object.freeze([
  'principal_id',
  'permission',
  'role',
  'scope',
]);

const CODE_FIELDS = Object.freeze([
  'repo',
  'ref',
  'commit_sha',
  'artifact_digest',
  'environment',
]);

const ACTION_FIELD_MAP = Object.freeze({
  [GUARD_ACTION_TYPES.BENEFIT_BANK_ACCOUNT_CHANGE]: [...COMMON_FIELDS, ...MONEY_FIELDS, ...RECORD_FIELDS],
  [GUARD_ACTION_TYPES.BENEFIT_ADDRESS_CHANGE]: [...COMMON_FIELDS, ...RECORD_FIELDS, ...BENEFIT_IDENTITY_FIELDS],
  [GUARD_ACTION_TYPES.CASEWORKER_OVERRIDE]: [...COMMON_FIELDS, ...RECORD_FIELDS],
  [GUARD_ACTION_TYPES.GOV_VENDOR_PAYMENT_DESTINATION_CHANGE]: [...COMMON_FIELDS, ...MONEY_FIELDS, ...GOV_PROGRAM_FIELDS, ...RECORD_FIELDS],
  [GUARD_ACTION_TYPES.GOV_DISBURSEMENT_RELEASE]: [...COMMON_FIELDS, ...MONEY_FIELDS, ...GOV_PROGRAM_FIELDS],
  [GUARD_ACTION_TYPES.GOV_GRANT_DISBURSEMENT]: [...COMMON_FIELDS, ...MONEY_FIELDS, ...GOV_PROGRAM_FIELDS],
  [GUARD_ACTION_TYPES.GOV_PROVIDER_ENROLLMENT_CHANGE]: [...COMMON_FIELDS, ...MONEY_FIELDS, ...GOV_PROGRAM_FIELDS, ...RECORD_FIELDS],
  [GUARD_ACTION_TYPES.GOV_ELIGIBILITY_OVERRIDE]: [...COMMON_FIELDS, ...GOV_PROGRAM_FIELDS, ...RECORD_FIELDS],
  [GUARD_ACTION_TYPES.VENDOR_BANK_ACCOUNT_CHANGE]: [...COMMON_FIELDS, ...MONEY_FIELDS, ...RECORD_FIELDS],
  [GUARD_ACTION_TYPES.BENEFICIARY_CREATION]: [...COMMON_FIELDS, ...MONEY_FIELDS, ...RECORD_FIELDS],
  [GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE]: [...COMMON_FIELDS, ...MONEY_FIELDS],
  [GUARD_ACTION_TYPES.AI_AGENT_PAYMENT_ACTION]: [...COMMON_FIELDS, ...MONEY_FIELDS],
});

const ALWAYS_BIND_FIELDS = Object.freeze([
  ...COMMON_FIELDS,
  'amount',
  'currency',
  'risk_flags',
  'target_changed_fields',
  'display_summary',
]);

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function isPlainObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function normalizeValue(value) {
  if (Array.isArray(value)) {
    return [...new Set(value.map((v) => String(v)))].sort();
  }
  return value;
}

function hasValue(value) {
  return value !== undefined && value !== null;
}

function valueFrom(field, ...sources) {
  for (const source of sources) {
    if (source && Object.prototype.hasOwnProperty.call(source, field) && hasValue(source[field])) {
      return source[field];
    }
  }
  return undefined;
}

function observedFieldValue(field, observedAction, executedAction) {
  if (field === 'before_state_hash') {
    const direct = valueFrom(field, observedAction, executedAction);
    if (hasValue(direct)) return direct;
    const state = valueFrom('before_state', observedAction, executedAction);
    return isPlainObject(state) ? hashCanonicalAction(state) : undefined;
  }
  if (field === 'after_state_hash') {
    const direct = valueFrom(field, observedAction, executedAction);
    if (hasValue(direct)) return direct;
    const state = valueFrom('after_state', observedAction, executedAction);
    return isPlainObject(state) ? hashCanonicalAction(state) : undefined;
  }
  return valueFrom(field, observedAction, executedAction);
}

export function actionMaterialFields(actionType) {
  const direct = ACTION_FIELD_MAP[actionType] || [];
  const s = String(actionType || '').toLowerCase();
  const inferred = [];
  if (s.includes('payment') || s.includes('bank') || s.includes('beneficiary') || s.includes('money')) {
    inferred.push(...MONEY_FIELDS);
  }
  if (s.includes('benefit') || s.includes('eligibility') || s.includes('provider') || s.includes('grant')) {
    inferred.push(...GOV_PROGRAM_FIELDS);
  }
  if (s.includes('permission') || s.includes('role') || s.includes('admin')) {
    inferred.push(...PERMISSION_FIELDS);
  }
  if (s.includes('deploy') || s.includes('code') || s.includes('production')) {
    inferred.push(...CODE_FIELDS);
  }
  if (s.includes('delete') || s.includes('record') || s.includes('decision') || s.includes('override')) {
    inferred.push(...RECORD_FIELDS);
  }
  return unique([...ALWAYS_BIND_FIELDS, ...direct, ...inferred]);
}

export function enrichCanonicalActionForExecution(canonicalAction, actionDetails = {}) {
  const enriched = { ...canonicalAction };
  for (const field of actionMaterialFields(canonicalAction?.action_type || actionDetails?.action_type)) {
    if (Object.prototype.hasOwnProperty.call(enriched, field)) continue;
    const value = valueFrom(field, actionDetails);
    if (hasValue(value)) enriched[field] = normalizeValue(value);
  }
  return enriched;
}

/**
 * @param {object} [params]
 * @param {{ action_type?: string, [key: string]: * }} [params.canonicalAction] - The canonical action being bound
 * @param {{ action_type?: string, [key: string]: * }} [params.actionDetails] - Additional detail fields sourced from the caller
 * @param {{ signoffRequired?: boolean, requiredAssurance?: string, [key: string]: * }} [params.decision] - The policy decision that produced this contract
 * @returns {object} The execution binding contract
 */
export function buildExecutionBindingContract({
  canonicalAction,
  actionDetails = {},
  decision = {},
} = {}) {
  const actionType = canonicalAction?.action_type || actionDetails?.action_type;
  const fields = actionMaterialFields(actionType);
  /** @type {Record<string, unknown>} */
  const fieldValues = {};
  for (const field of fields) {
    const value = valueFrom(field, canonicalAction, actionDetails);
    if (hasValue(value)) fieldValues[field] = normalizeValue(value);
  }

  const required = decision?.signoffRequired === true
    || decision?.requiredAssurance === 'A'
    || Object.prototype.hasOwnProperty.call(ACTION_FIELD_MAP, actionType);

  return {
    '@version': EXECUTION_BINDING_CONTRACT_VERSION,
    required,
    action_type: actionType || null,
    required_fields: Object.keys(fieldValues).sort(),
    field_values: fieldValues,
    field_hash: hashCanonicalAction(fieldValues),
    note: 'Executor MUST verify system-observed mutation fields match this contract before/while attesting execution.',
  };
}

/**
 * @param {object} [params]
 * @param {{ required?: boolean, required_fields?: string[], field_values?: Record<string, unknown>, field_hash?: string, [key: string]: * }} [params.contract] - The binding contract built by buildExecutionBindingContract
 * @param {object} [params.observedAction] - System-observed action state
 * @param {object} [params.executedAction] - Executor-reported action state
 * @returns {object} Verification result
 */
export function verifyExecutionBindingContract({
  contract,
  observedAction,
  executedAction,
} = {}) {
  if (!contract || contract.required !== true) {
    return { ok: true, required: false, missing_fields: [], mismatched_fields: [], observed_values: {}, observed_hash: null };
  }

  const missing = [];
  const mismatched = [];
  /** @type {Record<string, unknown>} */
  const observedValues = {};
  const fields = Array.isArray(contract.required_fields) ? contract.required_fields : [];
  for (const field of fields) {
    const expected = contract.field_values?.[field];
    if (!hasValue(expected)) {
      missing.push(field);
      continue;
    }
    const actual = observedFieldValue(field, observedAction, executedAction);
    if (!hasValue(actual)) {
      missing.push(field);
      continue;
    }
    const normalizedActual = normalizeValue(actual);
    observedValues[field] = normalizedActual;
    // hashCanonicalAction canonicalizes any JSON-serializable value at runtime;
    // its JSDoc in lib/guard-policies.js narrowly types the param as
    // Record<string, unknown> even though scalar field values are hashed here too.
    if (hashCanonicalAction(/** @type {Record<string, unknown>} */ (normalizedActual)) !== hashCanonicalAction(/** @type {Record<string, unknown>} */ (expected))) {
      mismatched.push(field);
    }
  }

  return {
    ok: missing.length === 0 && mismatched.length === 0,
    required: true,
    missing_fields: missing,
    mismatched_fields: mismatched,
    observed_values: observedValues,
    observed_hash: hashCanonicalAction(observedValues),
    expected_hash: contract.field_hash || hashCanonicalAction(contract.field_values || {}),
  };
}
