// SPDX-License-Identifier: Apache-2.0
// Shared extraction + validation for Guard/GovGuard action inputs.

import {
  GUARD_ACTION_TYPES,
  ENFORCEMENT_MODES,
  hashCanonicalAction,
} from './guard-policies.js';

type GuardActionType = (typeof GUARD_ACTION_TYPES)[keyof typeof GUARD_ACTION_TYPES];

/**
 * Shape of the raw Guard/GovGuard action request body. Every field is
 * caller-supplied JSON and therefore optional/untrusted; fields that are
 * only ever passed through (never inspected) are typed `unknown`, and
 * fields the validator actually inspects/compares get their real type.
 * The index signature backs the dynamic `body[field]` lookups below.
 */
interface GuardActionBody {
  [key: string]: unknown;
  target_changed_fields?: unknown;
  changed_fields?: unknown;
  enforcement_mode?: string;
  mode?: string;
  amount?: number;
  benefit_amount?: number;
  recent_amounts?: unknown[];
  counterparty_name?: string;
  beneficiary_name?: string;
  payee_name?: string;
  counterparty_country?: string;
  beneficiary_country?: string;
  currency?: string;
  display_summary?: string;
  target_resource_id?: string;
  rollout_policy_id?: string;
  rollout_policy_key?: string;
  rollout_policy_version?: number;
  rollout_policy_rules?: Record<string, any>;
  rollout_policy_mode?: string;
  rollout_policy_status?: string;
  rollout_environment?: string;
  rollout_strategy?: string;
  rollout_canary_pct?: number | null;
  rollout_metadata?: Record<string, any>;
  before_state?: Record<string, any>;
  after_state?: Record<string, any>;
  expires_in_sec?: unknown;
  executing_key_id?: string;
  risk_flags?: unknown;
  payment_instruction_id?: unknown;
  destination_hash?: unknown;
  payment_destination_hash?: unknown;
  action_caid?: unknown;
  caid_digest?: unknown;
  caid_action?: unknown;
  bank_account?: unknown;
  bank_account_hash?: unknown;
  routing_number?: unknown;
  routing_number_hash?: unknown;
  iban?: unknown;
  swift_bic?: unknown;
  payment_address?: unknown;
  agency_id?: unknown;
  program_id?: unknown;
  vendor_id?: unknown;
  recipient_id?: unknown;
  grant_id?: unknown;
  award_id?: unknown;
  provider_id?: unknown;
  provider_tax_id_hash?: unknown;
  provider_status?: unknown;
  npi?: unknown;
  claimant_id?: unknown;
  eligibility_case_id?: unknown;
  eligibility_rule?: unknown;
  eligibility_status?: unknown;
  address_hash?: unknown;
  mailing_address_hash?: unknown;
  phone_hash?: unknown;
  email_hash?: unknown;
  contact_method?: unknown;
  identity_document_hash?: unknown;
  identity_status?: unknown;
  case_id?: unknown;
  decision_id?: unknown;
  subject_id?: unknown;
  record_id?: unknown;
  override_reason?: unknown;
  regulated_decision?: unknown;
  principal_id?: unknown;
  permission?: unknown;
  role?: unknown;
  scope?: unknown;
  repo?: unknown;
  ref?: unknown;
  commit_sha?: unknown;
  artifact_digest?: unknown;
  environment?: unknown;
}

const AMOUNT_REQUIRED_ACTIONS: Set<string | undefined> = new Set([
  GUARD_ACTION_TYPES.GOV_DISBURSEMENT_RELEASE,
  GUARD_ACTION_TYPES.GOV_GRANT_DISBURSEMENT,
  GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE,
]);

function isFiniteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function isStringArray(value) {
  return Array.isArray(value) && value.every((v) => typeof v === 'string');
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function distinctNormalized(values) {
  return new Set(values
    .filter((value) => typeof value === 'string' && value.trim())
    .map((value) => value.trim().toLowerCase()));
}

// Returns whatever the caller supplied (unvalidated) or `defaults` verbatim —
// validateGuardActionInput() is what actually checks the shape at runtime.
export function resolveGuardChangedFields(body: GuardActionBody = {}, defaults: string[] = []): unknown {
  if (body.target_changed_fields !== undefined) return body.target_changed_fields;
  if (body.changed_fields !== undefined) return body.changed_fields;
  return defaults;
}

// Returns whatever the caller supplied (unvalidated) or `fallback` verbatim —
// callers are expected to check the result against ENFORCEMENT_MODES themselves.
export function resolveGuardEnforcementMode(body: GuardActionBody = {}, fallback: string = ENFORCEMENT_MODES.ENFORCE): string {
  return body.enforcement_mode ?? body.mode ?? fallback;
}

/**
 * @param {object} [body]
 * @param {object} [options]
 * @param {typeof GUARD_ACTION_TYPES[keyof typeof GUARD_ACTION_TYPES]} [options.actionType]
 * @param {string[]} [options.changedFields]
 */
export function validateGuardActionInput(
  body: GuardActionBody = {},
  { actionType, changedFields }: { actionType?: GuardActionType; changedFields?: unknown } = {},
) {
  if (!isStringArray(changedFields || [])) {
    return {
      status: 400,
      code: 'invalid_target_changed_fields',
      detail: 'target_changed_fields/changed_fields must be an array of strings',
    };
  }

  if (body.amount !== undefined && !isFiniteNumber(body.amount)) {
    return { status: 400, code: 'invalid_amount', detail: 'amount must be a finite JSON number' };
  }

  if (AMOUNT_REQUIRED_ACTIONS.has(actionType) && !isFiniteNumber(body.amount)) {
    return { status: 400, code: 'invalid_amount', detail: 'amount is required and must be a finite JSON number' };
  }

  if (body.benefit_amount !== undefined && !isFiniteNumber(body.benefit_amount)) {
    return { status: 400, code: 'invalid_benefit_amount', detail: 'benefit_amount must be a finite JSON number' };
  }

  if (body.recent_amounts !== undefined
      && (!Array.isArray(body.recent_amounts) || !body.recent_amounts.every(isFiniteNumber))) {
    return { status: 400, code: 'invalid_recent_amounts', detail: 'recent_amounts must be an array of finite JSON numbers' };
  }

  const names = distinctNormalized([
    body.counterparty_name,
    body.beneficiary_name,
    body.payee_name,
  ]);
  if (names.size > 1) {
    return {
      status: 400,
      code: 'ambiguous_counterparty',
      detail: 'counterparty_name, beneficiary_name, and payee_name must identify the same counterparty when combined',
    };
  }

  const countries = distinctNormalized([
    body.counterparty_country,
    body.beneficiary_country,
  ]);
  if (countries.size > 1) {
    return {
      status: 400,
      code: 'ambiguous_counterparty_country',
      detail: 'counterparty_country and beneficiary_country must match when both are supplied',
    };
  }

  if (body.currency !== undefined && (typeof body.currency !== 'string' || !/^[A-Z]{3}$/.test(body.currency))) {
    return { status: 400, code: 'invalid_currency', detail: 'currency must be a three-letter uppercase ISO-style code' };
  }

  if (body.display_summary !== undefined
      && (typeof body.display_summary !== 'string' || body.display_summary.length > 2_000)) {
    return { status: 400, code: 'invalid_display_summary', detail: 'display_summary must be a string of at most 2000 characters' };
  }

  if (actionType === GUARD_ACTION_TYPES.POLICY_ROLLOUT) {
    const requiredStrings = [
      'executing_key_id',
      'rollout_policy_id',
      'rollout_policy_key',
      'rollout_policy_mode',
      'rollout_policy_status',
      'rollout_environment',
      'rollout_strategy',
    ];
    for (const field of requiredStrings) {
      if (typeof body[field] !== 'string' || !body[field].trim()) {
        return { status: 400, code: `invalid_${field}`, detail: `${field} must be a non-empty string` };
      }
    }
    if (body.target_resource_id !== `policy:${body.rollout_policy_key}`) {
      return {
        status: 400,
        code: 'rollout_target_mismatch',
        detail: 'target_resource_id must equal policy:<rollout_policy_key>',
      };
    }
    // `!` is safe: Number.isSafeInteger short-circuits `||` before the `< 1`
    // comparison runs, so rollout_policy_version is a real number here even
    // though Number.isSafeInteger isn't a type-narrowing guard to TS.
    if (!Number.isSafeInteger(body.rollout_policy_version) || body.rollout_policy_version! < 1) {
      return {
        status: 400,
        code: 'invalid_rollout_policy_version',
        detail: 'rollout_policy_version must be a positive integer',
      };
    }
    // `!` is safe: the `!isPlainObject(body.before_state)` check just before
    // this short-circuits `||` before before_state.active_rollouts is read,
    // so before_state is a real object here (isPlainObject isn't a
    // type-narrowing guard to TS since it has no type predicate).
    if (!isPlainObject(body.rollout_policy_rules)
        || !isPlainObject(body.rollout_metadata)
        || !isPlainObject(body.before_state)
        || !isPlainObject(body.after_state)
        || !Array.isArray(body.before_state!.active_rollouts)) {
      return {
        status: 400,
        code: 'invalid_rollout_state',
        detail: 'policy rules, metadata, before_state.active_rollouts, and after_state must be structured JSON objects',
      };
    }
    // `!` is safe: the requiredStrings loop above already returned early
    // unless body.rollout_strategy is a non-empty string (TS can't carry
    // that narrowing from the dynamic body[field] loop to this named
    // property access).
    if (!['immediate', 'canary'].includes(body.rollout_strategy!)) {
      return {
        status: 400,
        code: 'invalid_rollout_strategy',
        detail: 'rollout_strategy must be immediate or canary',
      };
    }
    // `!` is safe: Number.isSafeInteger short-circuits `&&`/`||` before the
    // range comparisons run, so rollout_canary_pct is a real number here.
    if (body.rollout_strategy === 'canary'
        && (!Number.isSafeInteger(body.rollout_canary_pct)
          || body.rollout_canary_pct! < 1
          || body.rollout_canary_pct! > 99)) {
      return {
        status: 400,
        code: 'invalid_rollout_canary_pct',
        detail: 'rollout_canary_pct must be an integer from 1 through 99 for canary rollout',
      };
    }
    if (body.rollout_strategy === 'immediate' && body.rollout_canary_pct !== null) {
      return {
        status: 400,
        code: 'invalid_rollout_canary_pct',
        detail: 'rollout_canary_pct must be null for immediate rollout',
      };
    }
    if (body.expires_in_sec !== undefined
        && (!Number.isFinite(Number(body.expires_in_sec))
          || Number(body.expires_in_sec) < 60
          || Number(body.expires_in_sec) > 900)) {
      return {
        status: 400,
        code: 'invalid_rollout_expiry',
        detail: 'policy rollout receipts must expire from 60 through 900 seconds after issuance',
      };
    }
    const expectedAfterState = {
      policy_id: body.rollout_policy_id,
      policy_key: body.rollout_policy_key,
      policy_version: body.rollout_policy_version,
      policy_rules: body.rollout_policy_rules,
      policy_mode: body.rollout_policy_mode,
      policy_status: body.rollout_policy_status,
      environment: body.rollout_environment,
      strategy: body.rollout_strategy,
      canary_pct: body.rollout_strategy === 'canary' ? body.rollout_canary_pct : null,
      metadata: body.rollout_metadata,
    };
    // `!` is safe: the isPlainObject(body.after_state) check earlier in this
    // block already returned early unless after_state is a real object.
    if (hashCanonicalAction(body.after_state!) !== hashCanonicalAction(expectedAfterState)) {
      return {
        status: 400,
        code: 'rollout_after_state_mismatch',
        detail: 'after_state must exactly match the policy rollout material',
      };
    }
  }

  return null;
}

export function extractGuardActionDetails(body: GuardActionBody = {}, changedFields: unknown = []) {
  return {
    amount: body.amount,
    currency: body.currency,
    risk_flags: body.risk_flags,
    display_summary: body.display_summary,
    target_changed_fields: changedFields,

    // Money/destination material. Hash fields are first-class because many
    // government systems cannot put raw account values into an approval packet.
    counterparty_name: body.counterparty_name,
    counterparty_country: body.counterparty_country,
    beneficiary_name: body.beneficiary_name,
    beneficiary_country: body.beneficiary_country,
    payee_name: body.payee_name,
    payment_instruction_id: body.payment_instruction_id,
    destination_hash: body.destination_hash,
    payment_destination_hash: body.payment_destination_hash,
    // Server-computed typed action identity for cross-system correlation.
    // CAID identifies exact canonical content; it does not establish authority.
    action_caid: body.action_caid,
    caid_digest: body.caid_digest,
    caid_action: body.caid_action,
    bank_account: body.bank_account,
    bank_account_hash: body.bank_account_hash,
    routing_number: body.routing_number,
    routing_number_hash: body.routing_number_hash,
    iban: body.iban,
    swift_bic: body.swift_bic,
    payment_address: body.payment_address,

    // GovGuard program / provider / eligibility material.
    agency_id: body.agency_id,
    program_id: body.program_id,
    vendor_id: body.vendor_id,
    recipient_id: body.recipient_id,
    grant_id: body.grant_id,
    award_id: body.award_id,
    provider_id: body.provider_id,
    provider_tax_id_hash: body.provider_tax_id_hash,
    provider_status: body.provider_status,
    npi: body.npi,
    claimant_id: body.claimant_id,
    eligibility_case_id: body.eligibility_case_id,
    eligibility_rule: body.eligibility_rule,
    eligibility_status: body.eligibility_status,
    benefit_amount: body.benefit_amount,
    address_hash: body.address_hash,
    mailing_address_hash: body.mailing_address_hash,
    phone_hash: body.phone_hash,
    email_hash: body.email_hash,
    contact_method: body.contact_method,
    identity_document_hash: body.identity_document_hash,
    identity_status: body.identity_status,

    // Generic record/permission/code material.
    case_id: body.case_id,
    decision_id: body.decision_id,
    subject_id: body.subject_id,
    record_id: body.record_id,
    override_reason: body.override_reason,
    regulated_decision: body.regulated_decision,
    principal_id: body.principal_id,
    permission: body.permission,
    role: body.role,
    scope: body.scope,
    repo: body.repo,
    ref: body.ref,
    commit_sha: body.commit_sha,
    artifact_digest: body.artifact_digest,
    environment: body.environment,

    // Policy rollout control-plane material. Raw rules, metadata, and
    // before/after state are deliberately bound and displayed, not replaced by
    // caller-provided labels or opaque digests.
    executing_key_id: body.executing_key_id,
    rollout_policy_id: body.rollout_policy_id,
    rollout_policy_key: body.rollout_policy_key,
    rollout_policy_version: body.rollout_policy_version,
    rollout_policy_rules: body.rollout_policy_rules,
    rollout_policy_mode: body.rollout_policy_mode,
    rollout_policy_status: body.rollout_policy_status,
    rollout_environment: body.rollout_environment,
    rollout_strategy: body.rollout_strategy,
    rollout_canary_pct: body.rollout_canary_pct,
    rollout_metadata: body.rollout_metadata,
    rollout_before_state: body.before_state,
    rollout_after_state: body.after_state,
  };
}

const guardActionInputs = {
  resolveGuardChangedFields,
  resolveGuardEnforcementMode,
  validateGuardActionInput,
  extractGuardActionDetails,
};

export default guardActionInputs;
