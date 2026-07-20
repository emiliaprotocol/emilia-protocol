// SPDX-License-Identifier: Apache-2.0
// Deterministic, PHI-free synthetic Medi-Cal hospice claim integrity demo.
//
// This module deliberately has no network, database, clock, or production
// DHCS/CMS adapter. It demonstrates the safety boundary only: verify the
// evidence slots, bind one canonical action, reserve one bounded capability,
// and preserve uncertainty until authenticated provider evidence reconciles it.

import {
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from 'node:crypto';

import {
  computeCaid,
  parseCaid,
  verifyCaid,
} from '../../caid/impl/js/caid.mjs';
import {
  computeGuardPolicyHash,
  evaluateGuardPolicy,
  GUARD_ACTION_TYPES,
  hashCanonicalAction,
} from '../guard-policies.js';
import {
  buildExecutionBindingContract,
  verifyExecutionBindingContract,
} from '../execution/binding-contract.js';
import {
  CAPABILITY_SCOPE_PROFILE,
  capabilityActionDigest,
  verifyCapabilityScope,
} from '../../packages/gate/capability-receipt.js';
import { canonicalize } from '../../packages/gate/execution-binding.js';

const ACTION_TYPE = 'health.medi-cal.hospice-claim-payment.1';
const PROFILE_ID = 'medi-cal.hospice-integrity.v1';
const ACTION_VERSION = 'EP-HEALTH-PROGRAM-INTEGRITY-ACTION-v1';
const AUTHORIZATION_VERSION = 'EP-HEALTH-PROGRAM-INTEGRITY-AUTHORIZATION-v1';
const EVIDENCE_PACKET_VERSION = 'EP-HEALTH-PROGRAM-INTEGRITY-EVIDENCE-PACKET-v1';
const PROVIDER_EVIDENCE_VERSION = 'EP-SYNTHETIC-HOSPICE-PROVIDER-EVIDENCE-v1';
const STATEFUL_PROVIDER_EVIDENCE_VERSION = 'EP-HEALTH-PROGRAM-INTEGRITY-PROVIDER-EVIDENCE-v1';
const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const OPERATION_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const PAIRWISE_MEMBER_REF_RE = /^pairwise:[A-Za-z0-9][A-Za-z0-9._~-]{7,127}$/;
const REVIEWER_RE = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{1,127}$/;
const POLICY_RE = /^(?:policy:[A-Za-z0-9][A-Za-z0-9._:-]{2,127}|sha256:[0-9a-f]{64})$/;

const REQUIREMENTS = Object.freeze([
  'provider_npi',
  'pairwise_member_ref',
  'service_period',
  'authorization_digest',
  'positive_usd_amount',
  'destination_digest',
  'provider_standing',
  'verified_authorization',
  'named_reviewer',
  'authority_proof',
  'policy',
  'trust_evidence',
]);

const CAID_DEFINITION = Object.freeze({
  action_type: ACTION_TYPE,
  required_fields: [
    { name: 'operation_id', type: 'string' },
    { name: 'provider_npi', type: 'string' },
    { name: 'provider_standing', type: 'enum', values: ['in_good_standing'] },
    { name: 'member_ref', type: 'string' },
    { name: 'service_start', type: 'string' },
    { name: 'service_end', type: 'string' },
    { name: 'amount', type: 'integer' },
    { name: 'currency', type: 'enum', values: ['USD'] },
    { name: 'destination_digest', type: 'digest' },
    { name: 'authorization_digest', type: 'digest' },
    { name: 'reviewer_ref', type: 'string' },
    { name: 'authority_proof_digest', type: 'digest' },
    { name: 'policy_id', type: 'string' },
    { name: 'policy_hash', type: 'digest' },
    { name: 'trust_evidence_digest', type: 'digest' },
  ],
  optional_fields: [],
});

const STATEFUL_CAID_DEFINITION = Object.freeze({
  action_type: ACTION_TYPE,
  required_fields: [
    { name: '@version', type: 'string' },
    { name: 'profile_id', type: 'string' },
    { name: 'organization_id', type: 'string' },
    { name: 'provider_npi', type: 'string' },
    { name: 'member_ref', type: 'string' },
    { name: 'service_period_start', type: 'string' },
    { name: 'service_period_end', type: 'string' },
    { name: 'authorization_form_digest', type: 'digest' },
    { name: 'amount', type: 'amount-string' },
    { name: 'currency', type: 'enum', values: ['USD'] },
    { name: 'payment_destination_digest', type: 'digest' },
    { name: 'reviewer_id', type: 'string' },
    { name: 'authority_proof_digest', type: 'digest' },
    { name: 'policy_id', type: 'string' },
    { name: 'policy_version', type: 'integer' },
    { name: 'policy_hash', type: 'digest' },
  ],
  optional_fields: [],
});

const STATEFUL_REQUIREMENTS = Object.freeze([
  'profile_and_action_type_pinned',
  'exact_action_caid',
  'provider_member_service_period_binding',
  'authorization_form_digest',
  'amount_currency_destination_binding',
  'named_reviewer_authority',
  'policy_and_revocation_freshness',
  'single_use_consumption',
]);

const PROHIBITED_PHI_FIELDS = new Set([
  'member_name',
  'patient_name',
  'date_of_birth',
  'address',
  'telephone',
  'phone',
  'email',
  'ssn',
  'medicare_beneficiary_identifier',
  'diagnosis',
  'diagnosis_text',
  'clinical_note',
  'authorization_form',
  'bank_account',
  'raw_provider_evidence',
]);

const RUNTIME_DOWNGRADE_FIELDS = new Set([
  'enforcement_mode',
  'fail_open',
  'bypass_checks',
]);

// This is a deliberately fixed demo-only key. It is not a production trust
// anchor and is never returned by any public interface.
const SYNTHETIC_PROVIDER_PRIVATE_KEY = createPrivateKey({
  key: Buffer.from(
    '302e020100300506032b657004220420' + '01'.repeat(32),
    'hex',
  ),
  format: 'der',
  type: 'pkcs8',
});
const SYNTHETIC_PROVIDER_PRIVATE_JWK =
  SYNTHETIC_PROVIDER_PRIVATE_KEY.export({ format: 'jwk' });
if (typeof SYNTHETIC_PROVIDER_PRIVATE_JWK.x !== 'string') {
  throw new Error('synthetic provider public key is unavailable');
}
const SYNTHETIC_PROVIDER_PUBLIC_KEY = createPublicKey({
  key: {
    kty: 'OKP',
    crv: 'Ed25519',
    x: SYNTHETIC_PROVIDER_PRIVATE_JWK.x,
  },
  format: 'jwk',
})
  .export({ type: 'spki', format: 'der' })
  .toString('base64url');

const INTERNAL_STATE = Symbol('synthetic-hospice-program-integrity-state');
const STATE_BY_INPUT = new WeakMap();

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function clone(value) {
  return structuredClone(value);
}

function isSha256Digest(value) {
  return typeof value === 'string' && SHA256_RE.test(value);
}

function digest(value) {
  return `sha256:${hashCanonicalAction(value)}`;
}

function getFirst(...values) {
  return values.find((value) => value !== undefined && value !== null);
}

function hasPath(value, path) {
  let cursor = value;
  for (const part of path) {
    if (!isRecord(cursor) || !Object.prototype.hasOwnProperty.call(cursor, part)) return false;
    cursor = cursor[part];
  }
  return true;
}

function mergeObjects(base, override) {
  if (!isRecord(base) || !isRecord(override)) return clone(override);
  const output = clone(base);
  for (const [key, value] of Object.entries(override)) {
    output[key] = isRecord(value) && isRecord(output[key])
      ? mergeObjects(output[key], value)
      : clone(value);
  }
  return output;
}

function isValidNpi(value) {
  if (typeof value !== 'string' || !/^\d{10}$/.test(value)) return false;
  // NPI uses Luhn with the 80840 CMS prefix.
  const candidate = `80840${value}`;
  let sum = 0;
  const parity = candidate.length % 2;
  for (let index = 0; index < candidate.length; index += 1) {
    let digit = Number(candidate[index]);
    if (index % 2 === parity) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
  }
  return sum % 10 === 0;
}

function isValidDateOnly(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const [year, month, day] = value.split('-').map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year
    && date.getUTCMonth() === month - 1
    && date.getUTCDate() === day;
}

function isValidServicePeriod(value) {
  if (!isRecord(value) || !isValidDateOnly(value.start) || !isValidDateOnly(value.end)) return false;
  return value.start <= value.end;
}

function isValidReviewer(value) {
  return typeof value === 'string' && REVIEWER_RE.test(value);
}

function isValidStanding(value) {
  return value === 'in_good_standing'
    || (isRecord(value) && value.status === 'in_good_standing' && value.verified === true);
}

function readInput(input) {
  const root = isRecord(input) ? input : {};
  const provider = isRecord(root.provider) ? root.provider : {};
  const claim = isRecord(root.claim) ? root.claim : {};
  const authorization = isRecord(root.authorization) ? root.authorization : {};
  const authority = isRecord(root.authority) ? root.authority : {};
  const servicePeriod = getFirst(root.service_period, root.servicePeriod);
  const standing = getFirst(provider.standing, root.provider_standing);
  const proof = getFirst(
    authority.proof_digest,
    authority.proof,
    isRecord(authority.proof) ? authority.proof.digest : undefined,
    root.authority_proof,
  );
  const policy = getFirst(
    authority.policy,
    authority.policy_id,
    isRecord(authority.policy) ? getFirst(authority.policy.id, authority.policy.policy_id) : undefined,
    root.policy,
  );
  const trust = getFirst(
    authority.trust_evidence_digest,
    authority.trust,
    isRecord(authority.trust) ? authority.trust.digest : undefined,
    root.trust_evidence,
  );

  return {
    actionType: root.action_type,
    operationId: getFirst(root.operation_id, root.operationId),
    providerNpi: getFirst(provider.npi, root.provider_npi),
    providerStanding: standing,
    memberRef: getFirst(root.member_ref, root.memberRef, root.pairwise_member_ref),
    servicePeriod,
    amount: getFirst(claim.amount_usd, claim.amount, root.amount_usd, root.amount),
    currency: getFirst(claim.currency, root.currency),
    destinationDigest: getFirst(
      claim.destination_digest,
      claim.destinationDigest,
      root.destination_digest,
    ),
    authorizationDigest: getFirst(
      authorization.digest,
      authorization.sha256,
      authorization.authorization_digest,
      root.authorization_digest,
    ),
    authorizationVerified: Object.prototype.hasOwnProperty.call(authorization, 'verified')
      ? authorization.verified === true
      : root.authorization_verified === true,
    reviewer: getFirst(
      authorization.reviewer,
      authorization.reviewer_id,
      root.reviewer,
      root.reviewer_id,
    ),
    authorityProofDigest: proof,
    policy,
    trustEvidenceDigest: trust,
  };
}

function authorizationProjection(values) {
  return {
    operation_id: values.operationId,
    provider_npi: values.providerNpi,
    provider_standing: 'in_good_standing',
    member_ref: values.memberRef,
    service_start: values.servicePeriod?.start,
    service_end: values.servicePeriod?.end,
    amount: values.amount,
    currency: values.currency,
    destination_digest: values.destinationDigest,
    reviewer_ref: values.reviewer,
    authority_proof_digest: values.authorityProofDigest,
    policy_id: values.policy,
    trust_evidence_digest: values.trustEvidenceDigest,
  };
}

function validateInput(input) {
  const values = readInput(input);
  const failures = [];
  const status = {
    provider_npi: isValidNpi(values.providerNpi) ? 'valid' : 'invalid',
    member_ref: PAIRWISE_MEMBER_REF_RE.test(values.memberRef || '') ? 'pairwise' : 'invalid',
    service_period: isValidServicePeriod(values.servicePeriod) ? 'valid' : 'invalid',
    authorization: isSha256Digest(values.authorizationDigest) ? 'present' : 'invalid',
    amount: Number.isSafeInteger(values.amount) && values.amount > 0 && values.currency === 'USD'
      ? 'positive_usd'
      : 'invalid',
    destination: isSha256Digest(values.destinationDigest) ? 'digest_bound' : 'invalid',
    provider_standing: isValidStanding(values.providerStanding) ? 'in_good_standing' : 'invalid',
    reviewer: isValidReviewer(values.reviewer) ? 'named' : 'invalid',
    authority: isSha256Digest(values.authorityProofDigest) ? 'verified' : 'invalid',
    policy: typeof values.policy === 'string' && POLICY_RE.test(values.policy) ? 'pinned' : 'invalid',
    trust: isSha256Digest(values.trustEvidenceDigest) ? 'verified' : 'invalid',
  };

  const checks = [
    ['unsupported_action_type', values.actionType === ACTION_TYPE],
    ['provider_npi', status.provider_npi === 'valid'],
    ['pairwise_member_ref', status.member_ref === 'pairwise'],
    ['service_period', status.service_period === 'valid'],
    ['authorization_digest', status.authorization === 'present'],
    ['positive_usd_amount', status.amount === 'positive_usd'],
    ['destination_digest', status.destination === 'digest_bound'],
    ['provider_standing', status.provider_standing === 'in_good_standing'],
    ['verified_authorization', values.authorizationVerified],
    ['named_reviewer', status.reviewer === 'named'],
    ['authority_proof', status.authority === 'verified'],
    ['policy', status.policy === 'pinned'],
    ['trust_evidence', status.trust === 'verified'],
  ];
  for (const [code, ok] of checks) {
    if (!ok) failures.push(code);
  }

  if (status.authorization === 'present') {
    const expected = digest(authorizationProjection(values));
    if (expected !== values.authorizationDigest) {
      status.authorization = 'mismatch';
      failures.push('authorization_action_binding_failed');
    }
  }

  if (typeof values.operationId !== 'string' || !OPERATION_ID_RE.test(values.operationId)) {
    failures.push('operation_id_invalid');
  }

  return { values, status, failures: [...new Set(failures)] };
}

function buildAction(values) {
  return {
    action_type: ACTION_TYPE,
    operation_id: values.operationId,
    provider_npi: values.providerNpi,
    provider_standing: 'in_good_standing',
    member_ref: values.memberRef,
    service_start: values.servicePeriod.start,
    service_end: values.servicePeriod.end,
    amount: values.amount,
    currency: 'USD',
    destination_digest: values.destinationDigest,
    authorization_digest: values.authorizationDigest,
    reviewer_ref: values.reviewer,
    authority_proof_digest: values.authorityProofDigest,
    policy_id: values.policy,
    policy_hash: `sha256:${computeGuardPolicyHash(values.policy)}`,
    trust_evidence_digest: values.trustEvidenceDigest,
    risk_flags: [],
    target_changed_fields: ['destination_digest', 'provider_npi', 'service_period'],
    display_summary: 'Synthetic hospice claim integrity check',
  };
}

/**
 * @param {any} status
 * @param {string} [capability]
 * @param {any} [providerEvidence]
 * @returns {any}
 */
function buildEvidenceSummary(status, capability = 'uncommitted', providerEvidence = undefined) {
  return {
    provider_npi: status.provider_npi,
    member_ref: status.member_ref,
    service_period: status.service_period,
    authorization: status.authorization === 'present' ? 'verified' : status.authorization,
    amount: status.amount,
    destination: status.destination,
    provider_standing: status.provider_standing,
    reviewer: status.reviewer,
    authority: status.authority,
    policy: status.policy,
    trust: status.trust,
    execution_binding: 'not_checked',
    capability,
    ...(providerEvidence ? { provider_evidence: providerEvidence } : {}),
  };
}

/** @param {any} [options] @returns {any} */
function makeSummary({
  decision,
  caid = null,
  operationId = null,
  status,
  reasonCodes = [],
  capability = 'uncommitted',
  providerEvidence,
  replaySafe = true,
  executionBinding = false,
} = {}) {
  const evidenceSummary = buildEvidenceSummary(status, capability, providerEvidence);
  evidenceSummary.execution_binding = executionBinding ? 'exact' : evidenceSummary.execution_binding;
  return {
    decision,
    caid,
    requirements: [...REQUIREMENTS],
    evidence_summary: evidenceSummary,
    operation_id: operationId,
    replay_safe: replaySafe,
    ...(reasonCodes.length ? { reason_codes: [...new Set(reasonCodes)] } : {}),
  };
}

/** @param {any} input @param {any} options @returns {any} */
function stateFor(input, options) {
  const supplied = isRecord(options?.state) ? options.state : null;
  if (supplied && supplied.operations instanceof Map) {
    return {
      operations: supplied.operations,
      effects: supplied.effects instanceof Set ? supplied.effects : new Set(),
      reconciliations: supplied.reconciliations instanceof Map ? supplied.reconciliations : new Map(),
    };
  }
  if (isRecord(input) && input[INTERNAL_STATE]) return input[INTERNAL_STATE];
  if (isRecord(input) && STATE_BY_INPUT.has(input)) return STATE_BY_INPUT.get(input);
  const state = { operations: new Map(), effects: new Set(), reconciliations: new Map() };
  if (isRecord(input)) STATE_BY_INPUT.set(input, state);
  return state;
}

function providerOutcome(input, options) {
  const requested = getFirst(
    options?.providerOutcome,
    options?.provider_outcome,
    isRecord(input) ? input.providerOutcome : undefined,
    isRecord(input) ? input.provider_outcome : undefined,
    'executed',
  );
  if (requested === 'executed' || requested === 'success' || requested === 'approved') return 'executed';
  if (requested === 'indeterminate' || requested === 'response_lost' || requested === 'timeout') return 'indeterminate';
  if (requested === 'pending' || requested === 'in_flight') return 'pending';
  return null;
}

function normalizeObservedAction(observed) {
  if (!isRecord(observed)) return null;
  if (observed.action_type === ACTION_TYPE) return observed;
  const validation = validateInput(observed);
  if (validation.failures.length > 0) return null;
  return buildAction(validation.values);
}

function buildProviderEvidence(action, caid, actionDigest) {
  const body = {
    '@version': PROVIDER_EVIDENCE_VERSION,
    provider_key_id: 'synthetic-provider-key-v1',
    provider_npi: action.provider_npi,
    operation_id: action.operation_id,
    caid,
    action_digest: actionDigest,
    status: 'committed',
    effect: {
      effect_id: `synthetic-provider-effect:${action.operation_id}`,
      status: 'claim_recorded',
    },
  };
  return {
    body,
    signature: {
      algorithm: 'Ed25519',
      public_key: SYNTHETIC_PROVIDER_PUBLIC_KEY,
      value: sign(
        null,
        Buffer.from(canonicalize(body), 'utf8'),
        SYNTHETIC_PROVIDER_PRIVATE_KEY,
      ).toString('base64url'),
    },
  };
}

function verifyProviderEvidence(evidence, action, caid, actionDigest) {
  if (!isRecord(evidence) || !isRecord(evidence.body) || !isRecord(evidence.signature)) return null;
  const { body, signature } = evidence;
  if (body['@version'] !== PROVIDER_EVIDENCE_VERSION
      || signature.algorithm !== 'Ed25519'
      || signature.public_key !== SYNTHETIC_PROVIDER_PUBLIC_KEY
      || typeof signature.value !== 'string') return null;
  try {
    if (!verify(
      null,
      Buffer.from(canonicalize(body), 'utf8'),
      createPublicKey({
        key: Buffer.from(SYNTHETIC_PROVIDER_PUBLIC_KEY, 'base64url'),
        format: 'der',
        type: 'spki',
      }),
      Buffer.from(signature.value, 'base64url'),
    )) return null;
  } catch {
    return null;
  }
  const expectedEffectId = `synthetic-provider-effect:${action.operation_id}`;
  if (body.provider_npi !== action.provider_npi
      || body.operation_id !== action.operation_id
      || body.caid !== caid
      || body.action_digest !== actionDigest
      || body.status !== 'committed'
      || !isRecord(body.effect)
      || body.effect.effect_id !== expectedEffectId
      || body.effect.status !== 'claim_recorded') return null;
  return {
    evidenceDigest: digest(evidence),
  };
}

/** @param {any} input @param {any} options @returns {any} */
function prepare(input, options) {
  const validation = validateInput(input);
  const operationId = typeof validation.values.operationId === 'string'
    && OPERATION_ID_RE.test(validation.values.operationId)
    ? validation.values.operationId
    : null;
  if (validation.failures.length > 0) {
    return {
      validation,
      summary: makeSummary({
        decision: 'blocked',
        operationId,
        status: validation.status,
        reasonCodes: validation.failures,
      }),
    };
  }

  const action = buildAction(validation.values);
  const actionDigest = capabilityActionDigest(action);
  const caidResult = computeCaid(action, { suite: 'jcs-sha256', definitions: [CAID_DEFINITION] });
  if (!caidResult.caid || caidResult.digest !== actionDigest) {
    return {
      validation,
      summary: makeSummary({
        decision: 'blocked',
        operationId,
        status: validation.status,
        reasonCodes: ['caid_generation_failed'],
      }),
    };
  }

  const guardDecision = evaluateGuardPolicy({
    organizationId: 'synthetic-medi-cal',
    actorId: 'synthetic-program-integrity-engine',
    actorRole: 'program_integrity_engine',
    actionType: GUARD_ACTION_TYPES.GOV_DISBURSEMENT_RELEASE,
    targetChangedFields: ['destination_hash'],
    amount: validation.values.amount,
    currency: 'USD',
    riskFlags: [],
    authStrength: 'phishing_resistant_mfa',
    initiatorId: 'synthetic-program-integrity-engine',
    approverId: validation.values.reviewer,
  });
  if (guardDecision.decision !== 'allow_with_signoff') {
    return {
      validation,
      summary: makeSummary({
        decision: 'blocked',
        caid: caidResult.caid,
        operationId,
        status: validation.status,
        reasonCodes: ['guard_policy_refused'],
      }),
    };
  }

  // Bind the relying-party policy content into the local proof computation.
  // The hash is intentionally retained only in the in-memory operation state.
  try {
    computeGuardPolicyHash(String(validation.values.policy));
  } catch {
    return {
      validation,
      summary: makeSummary({
        decision: 'blocked',
        caid: caidResult.caid,
        operationId,
        status: validation.status,
        reasonCodes: ['policy_binding_failed'],
      }),
    };
  }

  const scope = verifyCapabilityScope({
    scope: {
      profile: CAPABILITY_SCOPE_PROFILE,
      operation_id_field: 'operation_id',
      action_digests: [actionDigest],
    },
  }, action, String(operationId));
  if (!scope.ok) {
    return {
      validation,
      summary: makeSummary({
        decision: 'blocked',
        caid: caidResult.caid,
        operationId,
        status: validation.status,
        reasonCodes: ['capability_scope_refused'],
      }),
    };
  }

  const contract = buildExecutionBindingContract({
    canonicalAction: action,
    actionDetails: action,
    decision: { requiredAssurance: 'A' },
  });
  const presentedObservedAction = getFirst(options?.observedAction, options?.observed_action);
  const observedAction = presentedObservedAction === undefined
    ? action
    : normalizeObservedAction(presentedObservedAction);
  let observedDigest = null;
  try {
    observedDigest = observedAction ? capabilityActionDigest(observedAction) : null;
  } catch {
    observedDigest = null;
  }
  if (!observedAction || observedDigest !== actionDigest) {
    return {
      validation,
      summary: makeSummary({
        decision: 'blocked',
        caid: caidResult.caid,
        operationId,
        status: validation.status,
        reasonCodes: ['execution_action_mismatch'],
      }),
    };
  }
  const binding = verifyExecutionBindingContract({
    contract,
    observedAction,
    executedAction: observedAction,
  });
  if (!binding.ok) {
    return {
      validation,
      summary: makeSummary({
        decision: 'blocked',
        caid: caidResult.caid,
        operationId,
        status: validation.status,
        reasonCodes: ['execution_binding_failed'],
      }),
    };
  }

  return {
    validation,
    action,
    actionDigest,
    caid: caidResult.caid,
    operationId,
    binding,
    summary: null,
  };
}

/**
 * @param {any} prepared
 * @param {any} operation
 * @param {any[]} [reasonCodes]
 * @returns {any}
 */
function operationSummary(prepared, operation, reasonCodes = []) {
  const indeterminate = operation.outcome === 'indeterminate';
  const reconciled = operation.reconciled === true;
  return makeSummary({
    decision: reconciled ? 'reconciled' : indeterminate ? 'indeterminate' : 'approved',
    caid: prepared.caid,
    operationId: prepared.operationId,
    status: prepared.validation.status,
    reasonCodes,
    capability: reconciled
      ? 'single_use_reconciled'
      : indeterminate
        ? 'single_use_indeterminate'
        : 'single_use_committed',
    providerEvidence: reconciled ? 'authenticated_exact_match' : undefined,
    replaySafe: reconciled || !indeterminate,
    executionBinding: true,
  });
}

/**
 * Create deterministic PHI-free synthetic input for the public demo.
 * Overrides are data-only and never cause network or provider calls.
 */
export function createSyntheticHospiceScenario(overrides = {}) {
  const base = {
    schema_version: 'synthetic-medi-cal-hospice-claim-v1',
    action_type: ACTION_TYPE,
    operation_id: 'hospice-op-001',
    provider: {
      npi: '1234567893',
      standing: 'in_good_standing',
    },
    member_ref: 'pairwise:synthetic-member-001',
    service_period: {
      start: '2026-01-01',
      end: '2026-01-07',
    },
    claim: {
      amount_usd: 1250,
      currency: 'USD',
      destination_digest: `sha256:${'a'.repeat(64)}`,
    },
    authorization: {
      verified: true,
      reviewer: 'reviewer:synthetic-001',
    },
    authority: {
      proof_digest: `sha256:${'b'.repeat(64)}`,
      policy: 'policy:synthetic-hospice-integrity:v1',
      trust_evidence_digest: `sha256:${'c'.repeat(64)}`,
    },
  };
  const scenario = mergeObjects(base, isRecord(overrides) ? overrides : {});
  const values = readInput(scenario);
  const explicitAuthorizationDigest = hasPath(overrides, ['authorization', 'digest'])
    || hasPath(overrides, ['authorization', 'sha256'])
    || hasPath(overrides, ['authorization_digest']);
  if (!explicitAuthorizationDigest && isRecord(scenario.authorization)) {
    scenario.authorization.digest = digest(authorizationProjection(values));
  }

  const prepared = prepare(scenario, {});
  const state = { operations: new Map(), effects: new Set(), reconciliations: new Map() };
  Object.defineProperty(scenario, INTERNAL_STATE, { value: state, enumerable: false });
  STATE_BY_INPUT.set(scenario, state);
  if (prepared.action && prepared.caid && prepared.actionDigest) {
    const evidence = buildProviderEvidence(prepared.action, prepared.caid, prepared.actionDigest);
    Object.defineProperty(scenario, 'provider_evidence', {
      value: evidence,
      enumerable: false,
      configurable: true,
    });
    Object.defineProperty(scenario, 'providerEvidence', {
      value: evidence,
      enumerable: false,
      configurable: true,
    });
  }
  return scenario;
}

/**
 * Evaluate one exact synthetic hospice claim. The operation ledger is
 * per-input (or may be supplied as options.state) and is synchronous so the
 * demo remains deterministic while still modeling atomic reservation.
 */
export function evaluateHospiceProgramIntegrity(input, options = {}) {
  const prepared = prepare(input, options);
  if (prepared.summary) return prepared.summary;

  const state = stateFor(input, options);
  const existing = state.operations.get(prepared.operationId);
  if (existing) {
    if (existing.action_digest !== prepared.actionDigest || existing.caid !== prepared.caid) {
      return makeSummary({
        decision: 'blocked',
        caid: prepared.caid,
        operationId: prepared.operationId,
        status: prepared.validation.status,
        reasonCodes: ['operation_action_mismatch'],
        replaySafe: true,
        executionBinding: true,
      });
    }
    if (existing.status === 'reserved') {
      return makeSummary({
        decision: 'blocked',
        caid: prepared.caid,
        operationId: prepared.operationId,
        status: prepared.validation.status,
        reasonCodes: ['operation_in_flight'],
        replaySafe: true,
        executionBinding: true,
      });
    }
    if (existing.outcome === 'indeterminate') {
      if (existing.reconciled) return operationSummary(prepared, existing);
      return makeSummary({
        decision: 'blocked',
        caid: prepared.caid,
        operationId: prepared.operationId,
        status: prepared.validation.status,
        reasonCodes: ['blind_replay_refused'],
        capability: 'single_use_indeterminate',
        replaySafe: false,
        executionBinding: true,
      });
    }
    return makeSummary({
      decision: 'blocked',
      caid: prepared.caid,
      operationId: prepared.operationId,
      status: prepared.validation.status,
      reasonCodes: ['operation_already_committed'],
      capability: 'single_use_committed',
      replaySafe: true,
      executionBinding: true,
    });
  }

  const outcome = providerOutcome(input, options);
  if (!outcome) {
    return makeSummary({
      decision: 'blocked',
      caid: prepared.caid,
      operationId: prepared.operationId,
      status: prepared.validation.status,
      reasonCodes: ['provider_outcome_invalid'],
      replaySafe: true,
      executionBinding: true,
    });
  }

  // Reserve before provider entry. Once reserved, no second evaluation can
  // enter this operation, including a synchronous re-entrant caller.
  /** @type {any} */
  const operation = {
    operation_id: prepared.operationId,
    action_digest: prepared.actionDigest,
    caid: prepared.caid,
    amount: prepared.action.amount,
    currency: prepared.action.currency,
    status: 'reserved',
    outcome: null,
    reconciled: false,
  };
  state.operations.set(prepared.operationId, operation);

  if (outcome === 'pending') {
    return makeSummary({
      decision: 'blocked',
      caid: prepared.caid,
      operationId: prepared.operationId,
      status: prepared.validation.status,
      reasonCodes: ['provider_operation_in_flight'],
      capability: 'single_use_reserved',
      replaySafe: true,
      executionBinding: true,
    });
  }

  operation.status = 'committed';
  operation.outcome = outcome;
  if (outcome === 'indeterminate') state.effects.add(prepared.operationId);
  return operationSummary(prepared, operation);
}

/**
 * Reconcile only a committed indeterminate operation with an authenticated,
 * exact-operation, exact-CAID synthetic provider statement.
 */
export function reconcileHospiceProgramIntegrity(input, options = {}) {
  const prepared = prepare(input, options);
  if (prepared.summary) return prepared.summary;
  const state = stateFor(input, options);
  const operation = state.operations.get(prepared.operationId);
  if (!operation) {
    return makeSummary({
      decision: 'blocked',
      caid: prepared.caid,
      operationId: prepared.operationId,
      status: prepared.validation.status,
      reasonCodes: ['operation_not_found'],
      executionBinding: true,
    });
  }
  if (operation.action_digest !== prepared.actionDigest || operation.caid !== prepared.caid) {
    return makeSummary({
      decision: 'indeterminate',
      caid: prepared.caid,
      operationId: prepared.operationId,
      status: prepared.validation.status,
      reasonCodes: ['operation_action_mismatch'],
      capability: 'single_use_indeterminate',
      replaySafe: false,
      executionBinding: true,
    });
  }
  if (operation.status !== 'committed' || operation.outcome !== 'indeterminate') {
    return makeSummary({
      decision: 'blocked',
      caid: prepared.caid,
      operationId: prepared.operationId,
      status: prepared.validation.status,
      reasonCodes: ['operation_not_indeterminate'],
      executionBinding: true,
    });
  }

  const evidence = getFirst(
    options.providerEvidence,
    options.provider_evidence,
    isRecord(input) ? input.providerEvidence : undefined,
    isRecord(input) ? input.provider_evidence : undefined,
  );
  const verified = verifyProviderEvidence(evidence, prepared.action, prepared.caid, prepared.actionDigest);
  if (!verified) {
    return makeSummary({
      decision: 'indeterminate',
      caid: prepared.caid,
      operationId: prepared.operationId,
      status: prepared.validation.status,
      reasonCodes: ['provider_evidence_rejected'],
      capability: 'single_use_indeterminate',
      replaySafe: false,
      executionBinding: true,
    });
  }

  if (operation.reconciled) {
    if (operation.provider_evidence_digest !== verified.evidenceDigest) {
      return makeSummary({
        decision: 'indeterminate',
        caid: prepared.caid,
        operationId: prepared.operationId,
        status: prepared.validation.status,
        reasonCodes: ['reconciliation_conflict'],
        capability: 'single_use_indeterminate',
        replaySafe: false,
        executionBinding: true,
      });
    }
    return operationSummary(prepared, operation, ['reconciliation_idempotent']);
  }

  operation.reconciled = true;
  operation.provider_evidence_digest = verified.evidenceDigest;
  state.reconciliations.set(prepared.operationId, verified.evidenceDigest);
  return operationSummary(prepared, operation);
}

function findProhibitedPhi(value) {
  if (Array.isArray(value)) {
    for (const entry of value) {
      const found = findProhibitedPhi(entry);
      if (found) return found;
    }
    return null;
  }
  if (!isRecord(value)) return null;
  for (const [key, entry] of Object.entries(value)) {
    if (PROHIBITED_PHI_FIELDS.has(key)) return key;
    const found = findProhibitedPhi(entry);
    if (found) return found;
  }
  return null;
}

/** @param {string} reason @param {any} [extras] @returns {any} */
function statefulRefusal(reason, extras = {}) {
  return {
    ok: false,
    decision: 'REFUSED',
    reason,
    ...extras,
  };
}

/** @param {any} [overrides] @returns {any} */
function statefulEvidenceSummary(overrides = {}) {
  return {
    status: 'satisfied',
    authorization_status: 'verified',
    authority_status: 'verified',
    provider_snapshot_status: 'pinned',
    policy_status: 'pinned',
    revocation_status: 'current',
    consumption_status: 'unconsumed',
    execution_binding_status: 'exact',
    reconciliation_status: 'not_required',
    authorization: true,
    authority: true,
    provider_snapshot: true,
    policy: true,
    revocation: true,
    consumption: true,
    execution_binding: true,
    provider_evidence: false,
    ...overrides,
  };
}

/** @param {any} action @param {any} [options] @returns {any} */
function validateStatefulAction(action, {
  profileId = PROFILE_ID,
  actionType = ACTION_TYPE,
  permitCallerCaid = false,
} = {}) {
  if (!isRecord(action)) return statefulRefusal('invalid_action');
  const prohibited = findProhibitedPhi(action);
  if (prohibited) return statefulRefusal('prohibited_phi', { prohibited_field: prohibited });
  if (!permitCallerCaid && Object.prototype.hasOwnProperty.call(action, 'action_caid')) {
    return statefulRefusal('caller_selected_caid_refused');
  }
  if ([...RUNTIME_DOWNGRADE_FIELDS].some((field) => (
    Object.prototype.hasOwnProperty.call(action, field)
  ))) {
    return statefulRefusal('runtime_downgrade_refused');
  }
  if (action['@version'] !== ACTION_VERSION
      || action.profile_id !== profileId) {
    return statefulRefusal('unsupported_action_profile');
  }
  if (action.action_type !== actionType) {
    const grammarValid = typeof action.action_type === 'string'
      && /^(?:[a-z][a-z0-9-]*\.)+[1-9][0-9]*$/.test(action.action_type);
    return statefulRefusal(grammarValid
      ? 'unsupported_action_profile'
      : 'unsupported_action_type');
  }
  const requiredStrings = [
    'organization_id',
    'provider_npi',
    'member_ref',
    'service_period_start',
    'service_period_end',
    'authorization_form_digest',
    'amount',
    'currency',
    'payment_destination_digest',
    'reviewer_id',
    'authority_proof_digest',
    'policy_id',
    'policy_hash',
  ];
  if (requiredStrings.some((field) => (
    typeof action[field] !== 'string' || action[field].length === 0
  ))) {
    return statefulRefusal('invalid_action');
  }
  if (!/^\d{10}$/.test(action.provider_npi)
      || !/^member:sha256:[0-9a-f]{64}$/.test(action.member_ref)
      || !isValidDateOnly(action.service_period_start)
      || !isValidDateOnly(action.service_period_end)
      || action.service_period_start > action.service_period_end
      || !isSha256Digest(action.authorization_form_digest)
      || !/^(?:0|[1-9][0-9]*)\.[0-9]{2}$/.test(action.amount)
      || Number(action.amount) <= 0
      || action.currency !== 'USD'
      || !isSha256Digest(action.payment_destination_digest)
      || !isValidReviewer(action.reviewer_id)
      || !isSha256Digest(action.authority_proof_digest)
      || !Number.isSafeInteger(action.policy_version)
      || action.policy_version < 1
      || !isSha256Digest(action.policy_hash)) {
    return statefulRefusal('invalid_action');
  }
  return null;
}

/** @param {any} action @param {any} [options] @returns {any} */
function computeStatefulActionBinding(action, options = {}) {
  const validation = validateStatefulAction(action, options);
  if (validation) return validation;
  const cleanAction = clone(action);
  const computed = computeCaid(cleanAction, {
    suite: 'jcs-sha256',
    definitions: [STATEFUL_CAID_DEFINITION],
  });
  if (!computed.caid || !computed.digest) {
    return statefulRefusal('action_caid_generation_failed');
  }
  const parsed = parseCaid(computed.caid);
  const verified = verifyCaid(cleanAction, computed.caid, {
    definitions: [STATEFUL_CAID_DEFINITION],
  });
  if (!parsed.ok
      || parsed.caid.action_type !== ACTION_TYPE
      || !verified.valid) {
    return statefulRefusal('action_caid_generation_failed');
  }
  return {
    ok: true,
    action: cleanAction,
    action_caid: computed.caid,
    action_digest: computed.digest,
  };
}

function parseInstant(value) {
  if (typeof value !== 'string') return null;
  const instant = Date.parse(value);
  return Number.isFinite(instant) ? instant : null;
}

/** @param {any} packet @returns {string} */
function packetDigest(packet) {
  const unsigned = clone(packet);
  delete unsigned.packet_digest;
  return digest(unsigned);
}

/**
 * Verify a portable, PHI-free program-integrity evidence packet offline.
 * This checks its self-digest, exact-action CAID, decision/outcome coherence,
 * and one-operation unambiguity. It deliberately makes no trust claim about
 * an external provider key; that verification happens before export.
 */
/** @param {any} packet @returns {{valid: boolean, reasons: string[]}} */
export function verifyProgramIntegrityEvidencePacket(packet) {
  const refuse = () => ({ valid: false, reasons: ['evidence_packet_ambiguous'] });
  if (!isRecord(packet)
      || packet['@version'] !== EVIDENCE_PACKET_VERSION
      || typeof packet.operation_id !== 'string'
      || packet.operation_id.length === 0
      || typeof packet.action_caid !== 'string'
      || !isRecord(packet.action)
      || isRecord(packet.authorization)
      || findProhibitedPhi(packet)) {
    return refuse();
  }
  if (!isSha256Digest(packet.packet_digest)
      || packet.packet_digest !== packetDigest(packet)
      || !isSha256Digest(packet.action_digest)) {
    return refuse();
  }
  const binding = computeStatefulActionBinding(packet.action);
  if (!binding.ok
      || binding.action_caid !== packet.action_caid
      || binding.action_digest !== packet.action_digest) {
    return refuse();
  }
  const expectedOutcome = {
    EXECUTED: 'executed',
    RECONCILED_EXECUTED: 'executed',
    RECONCILED_FAILED: 'not_executed',
    INDETERMINATE: 'indeterminate',
  }[packet.decision];
  if (!expectedOutcome || packet.outcome !== expectedOutcome) return refuse();
  if (packet.operations !== undefined) {
    if (!Array.isArray(packet.operations)
        || packet.operations.length !== 1
        || packet.operations[0]?.operation_id !== packet.operation_id
        || packet.operations[0]?.decision !== packet.decision) {
      return refuse();
    }
  }
  return { valid: true, reasons: [] };
}

/**
 * Build the fail-closed stateful interface used by authenticated adapters.
 * Ephemeral state is available only when explicitly enabled; production
 * callers should supply a durable state_store implementing get/set.
 */
/** @param {any} [config] @returns {any} */
export function createProgramIntegrityEngine(config = {}) {
  const profileId = config.profile_id || PROFILE_ID;
  const actionType = config.action_type || ACTION_TYPE;
  const now = typeof config.now === 'function'
    ? config.now
    : () => new Date().toISOString();
  const ephemeral = config.allow_ephemeral_state === true ? new Map() : null;
  const stateStore = isRecord(config.state_store) ? config.state_store : null;

  /** @param {string} operationId @returns {Promise<any>} */
  async function readOperation(operationId) {
    if (stateStore && typeof stateStore.get === 'function') {
      return stateStore.get(operationId);
    }
    return ephemeral?.get(operationId) || null;
  }

  /** @param {string} operationId @param {any} operation @returns {Promise<boolean>} */
  async function writeOperation(operationId, operation) {
    if (stateStore && typeof stateStore.set === 'function') {
      await stateStore.set(operationId, clone(operation));
      return true;
    }
    if (ephemeral) {
      ephemeral.set(operationId, clone(operation));
      return true;
    }
    return false;
  }

  /** @param {any} [input] @returns {Promise<any>} */
  async function prepareStateful({ action } = {}) {
    const binding = computeStatefulActionBinding(action, {
      profileId,
      actionType,
    });
    if (!binding.ok) return binding;
    return {
      ok: true,
      action_caid: binding.action_caid,
      action_digest: binding.action_digest,
      requirements: [...STATEFUL_REQUIREMENTS],
      evidence_summary: statefulEvidenceSummary({
        status: 'prepared',
        authorization_status: 'not_checked',
        authority_status: 'not_checked',
        consumption_status: 'not_reserved',
        authorization: false,
        authority: false,
        consumption: false,
      }),
    };
  }

  /** @param {any} [input] @returns {Promise<any>} */
  async function precheck({ action, authorization } = {}) {
    if (isRecord(action)
        && Object.prototype.hasOwnProperty.call(action, 'action_caid')) {
      return statefulRefusal('caller_selected_caid_refused');
    }
    const binding = computeStatefulActionBinding(action, {
      profileId,
      actionType,
    });
    if (!binding.ok) {
      if (binding.reason === 'unsupported_action_profile') {
        return statefulRefusal('action_caid_mismatch');
      }
      return binding;
    }
    const authorizationPhi = findProhibitedPhi(authorization);
    if (authorizationPhi) {
      return statefulRefusal('prohibited_phi', {
        prohibited_field: authorizationPhi,
        action_caid: binding.action_caid,
      });
    }
    if (!isRecord(authorization)
        || authorization['@version'] !== AUTHORIZATION_VERSION
        || authorization.reviewer_id !== action.reviewer_id
        || authorization.organization_id !== action.organization_id
        || authorization.action_caid !== binding.action_caid
        || !isSha256Digest(authorization.authorization_evidence_digest)) {
      return statefulRefusal('action_caid_mismatch', {
        action_caid: binding.action_caid,
      });
    }
    const current = parseInstant(now());
    const issuedAt = parseInstant(authorization.issued_at);
    const expiresAt = parseInstant(authorization.expires_at);
    if (current === null || issuedAt === null || expiresAt === null
        || issuedAt > current || expiresAt <= current) {
      return statefulRefusal('authorization_expired', {
        action_caid: binding.action_caid,
      });
    }

    let authority;
    try {
      if (typeof config.resolveReviewerAuthority !== 'function') {
        throw new Error('reviewer authority resolver not configured');
      }
      authority = await config.resolveReviewerAuthority({
        reviewer_id: action.reviewer_id,
        organization_id: action.organization_id,
        action_type: action.action_type,
        at: now(),
      });
    } catch {
      return statefulRefusal('reviewer_authority_unavailable', {
        action_caid: binding.action_caid,
      });
    }
    const validFrom = parseInstant(authority?.valid_from);
    const validUntil = parseInstant(authority?.valid_until);
    if (!isRecord(authority)
        || authority.valid !== true
        || authority.reviewer_id !== action.reviewer_id
        || authority.organization_id !== action.organization_id
        || authority.authority_id !== authorization.authority_id
        || !Array.isArray(authority.scope)
        || !authority.scope.includes(action.action_type)
        || validFrom === null
        || validUntil === null
        || validFrom > current
        || validUntil <= current
        || authority.revoked_at !== null
        || authority.snapshot_digest !== action.authority_proof_digest) {
      return statefulRefusal('reviewer_authority_unsatisfied', {
        action_caid: binding.action_caid,
      });
    }

    if (!ephemeral && !stateStore) {
      return statefulRefusal('state_storage_unavailable', {
        action_caid: binding.action_caid,
      });
    }
    const identifierDigest = hashCanonicalAction({
      action_caid: binding.action_caid,
      organization_id: action.organization_id,
      profile_id: action.profile_id,
    });
    const operationId = `health-op-${identifierDigest.slice(0, 24)}`;
    const idempotencyKey = `health-idem-${identifierDigest.slice(24, 48)}`;
    const existing = await readOperation(operationId);
    if (existing) {
      if (existing.action_caid !== binding.action_caid) {
        return statefulRefusal('operation_action_mismatch');
      }
      if (existing.decision === 'READY') {
        return {
          ok: true,
          decision: 'READY',
          action_caid: binding.action_caid,
          operation_id: operationId,
          idempotency_key: idempotencyKey,
          requirements: [...STATEFUL_REQUIREMENTS],
          evidence_summary: clone(existing.evidence_summary),
          idempotent: true,
        };
      }
      return statefulRefusal('replay_refused', {
        action_caid: binding.action_caid,
        operation_id: operationId,
      });
    }

    /** @type {any} */
    const operation = {
      operation_id: operationId,
      idempotency_key: idempotencyKey,
      action_caid: binding.action_caid,
      action_digest: binding.action_digest,
      action: binding.action,
      authorization_digest: digest(authorization),
      authority_snapshot_digest: authority.snapshot_digest,
      provider_snapshot_digest: config.provider_snapshot_digest || null,
      decision: 'READY',
      outcome: null,
      provider_evidence_digest: null,
      evidence_summary: statefulEvidenceSummary(),
    };
    if (!await writeOperation(operationId, operation)) {
      return statefulRefusal('state_storage_unavailable', {
        action_caid: binding.action_caid,
      });
    }
    return {
      ok: true,
      decision: 'READY',
      action_caid: binding.action_caid,
      operation_id: operationId,
      idempotency_key: idempotencyKey,
      requirements: [...STATEFUL_REQUIREMENTS],
      evidence_summary: clone(operation.evidence_summary),
    };
  }

  /** @param {any} [input] @returns {Promise<any>} */
  async function execute({ operation_id: operationId, action } = {}) {
    const operation = await readOperation(operationId);
    if (!operation) return statefulRefusal('operation_not_found');
    if (operation.decision !== 'READY') {
      return statefulRefusal('replay_refused', {
        operation_id: operationId,
        action_caid: operation.action_caid,
        previous_decision: operation.decision,
      });
    }
    const binding = computeStatefulActionBinding(action, {
      profileId,
      actionType,
    });
    if (!binding.ok
        || binding.action_caid !== operation.action_caid
        || binding.action_digest !== operation.action_digest) {
      return statefulRefusal('execution_action_mismatch', {
        operation_id: operationId,
        action_caid: operation.action_caid,
      });
    }

    operation.decision = 'SUBMITTED';
    operation.evidence_summary.consumption_status = 'submitted_once';
    await writeOperation(operationId, operation);

    /** @type {any} */
    let providerResult;
    try {
      if (typeof config.submit !== 'function') {
        throw new Error('provider submit adapter not configured');
      }
      providerResult = await config.submit({
        provider_id: config.provider_id,
        environment: config.provider_environment,
        operation_id: operationId,
        idempotency_key: operation.idempotency_key,
        action_caid: operation.action_caid,
        action: clone(operation.action),
      });
    } catch {
      providerResult = {
        status: 'indeterminate',
        dispatch_confirmed: true,
      };
    }

    if (providerResult?.status === 'executed') {
      operation.decision = 'EXECUTED';
      operation.outcome = 'executed';
      operation.provider_effect_reference_digest = providerResult.effect_reference
        ? digest({ effect_reference: providerResult.effect_reference })
        : null;
      operation.evidence_summary.consumption_status = 'consumed';
      await writeOperation(operationId, operation);
      return {
        ok: true,
        decision: 'EXECUTED',
        operation_id: operationId,
        action_caid: operation.action_caid,
        idempotency_key: operation.idempotency_key,
        evidence_summary: clone(operation.evidence_summary),
      };
    }

    if (providerResult?.status === 'indeterminate'
        || providerResult?.dispatch_confirmed === true) {
      operation.decision = 'INDETERMINATE';
      operation.outcome = 'indeterminate';
      operation.provider_request_id_digest = providerResult.provider_request_id
        ? digest({ provider_request_id: providerResult.provider_request_id })
        : null;
      operation.evidence_summary.reconciliation_status = 'required';
      await writeOperation(operationId, operation);
      return {
        ok: false,
        decision: 'INDETERMINATE',
        reason: 'provider_outcome_indeterminate',
        operation_id: operationId,
        action_caid: operation.action_caid,
        idempotency_key: operation.idempotency_key,
        evidence_summary: clone(operation.evidence_summary),
      };
    }

    operation.decision = 'REFUSED';
    operation.outcome = 'not_executed';
    await writeOperation(operationId, operation);
    return statefulRefusal('provider_refused', {
      operation_id: operationId,
      action_caid: operation.action_caid,
    });
  }

  /** @param {any} [input] @returns {Promise<any>} */
  async function reconcile({ operation_id: operationId, evidence } = {}) {
    const operation = await readOperation(operationId);
    if (!operation) return statefulRefusal('operation_not_found');
    const evidencePhi = findProhibitedPhi(evidence);
    if (evidencePhi) {
      return statefulRefusal('prohibited_phi', {
        prohibited_field: evidencePhi,
        operation_id: operationId,
        action_caid: operation.action_caid,
        previous_decision: operation.decision,
      });
    }
    if (operation.decision === 'RECONCILED_EXECUTED'
        || operation.decision === 'RECONCILED_FAILED') {
      const evidenceDigest = digest(evidence);
      if (evidenceDigest !== operation.provider_evidence_digest) {
        return statefulRefusal('reconciliation_conflict', {
          operation_id: operationId,
          action_caid: operation.action_caid,
          previous_decision: operation.decision,
        });
      }
      return {
        ok: true,
        decision: operation.decision,
        operation_id: operationId,
        action_caid: operation.action_caid,
        idempotency_key: operation.idempotency_key,
        idempotent: true,
        authenticated_provider_evidence: true,
        provider_evidence_verified: true,
        evidence_summary: clone(operation.evidence_summary),
      };
    }
    if (operation.decision !== 'INDETERMINATE') {
      return statefulRefusal('reconciliation_not_allowed', {
        operation_id: operationId,
        action_caid: operation.action_caid,
        previous_decision: operation.decision,
      });
    }

    let authenticated = false;
    try {
      authenticated = typeof config.verifyProviderEvidence === 'function'
        && await config.verifyProviderEvidence({
          provider_id: config.provider_id,
          environment: config.provider_environment,
          evidence,
        }) === true;
    } catch {
      authenticated = false;
    }
    if (!authenticated
        || !isRecord(evidence)
        || evidence['@version'] !== STATEFUL_PROVIDER_EVIDENCE_VERSION
        || evidence.provider_id !== config.provider_id
        || evidence.environment !== config.provider_environment
        || evidence.operation_id !== operationId
        || evidence.action_caid !== operation.action_caid
        || evidence.idempotency_key !== operation.idempotency_key
        || !['executed', 'not_executed'].includes(evidence.outcome)) {
      return statefulRefusal('provider_evidence_invalid', {
        operation_id: operationId,
        action_caid: operation.action_caid,
        previous_decision: 'INDETERMINATE',
      });
    }

    operation.provider_evidence_digest = digest(evidence);
    operation.outcome = evidence.outcome;
    operation.decision = evidence.outcome === 'executed'
      ? 'RECONCILED_EXECUTED'
      : 'RECONCILED_FAILED';
    operation.evidence_summary.provider_evidence = true;
    operation.evidence_summary.reconciliation_status = 'authenticated_terminal';
    await writeOperation(operationId, operation);
    return {
      ok: true,
      decision: operation.decision,
      operation_id: operationId,
      action_caid: operation.action_caid,
      idempotency_key: operation.idempotency_key,
      idempotent: false,
      authenticated_provider_evidence: true,
      provider_evidence_verified: true,
      evidence_summary: clone(operation.evidence_summary),
    };
  }

  /** @param {any} [input] @returns {Promise<any>} */
  async function exportEvidence({ operation_id: operationId } = {}) {
    const operation = await readOperation(operationId);
    if (!operation) return statefulRefusal('operation_not_found');
    if (!['EXECUTED', 'INDETERMINATE', 'RECONCILED_EXECUTED', 'RECONCILED_FAILED']
      .includes(operation.decision)) {
      return statefulRefusal('evidence_not_available');
    }
    const packet = {
      '@version': EVIDENCE_PACKET_VERSION,
      operation_id: operation.operation_id,
      idempotency_key: operation.idempotency_key,
      action_caid: operation.action_caid,
      action_digest: operation.action_digest,
      decision: operation.decision,
      outcome: operation.outcome,
      provider: {
        provider_id: config.provider_id || null,
        environment: config.provider_environment || null,
        snapshot_digest: operation.provider_snapshot_digest,
      },
      authority_snapshot_digest: operation.authority_snapshot_digest,
      authorization_evidence_digest: operation.authorization_digest,
      provider_evidence_digest: operation.provider_evidence_digest,
      action: clone(operation.action),
    };
    packet.packet_digest = packetDigest(packet);
    return packet;
  }

  return Object.freeze({
    prepare: prepareStateful,
    precheck,
    execute,
    reconcile,
    exportEvidence,
  });
}
