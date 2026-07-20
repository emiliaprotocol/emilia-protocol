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

import { computeCaid } from '../../caid/impl/js/caid.mjs';
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

const ACTION_TYPE = 'medi-cal.hospice.claim.1';
const PROVIDER_EVIDENCE_VERSION = 'EP-SYNTHETIC-HOSPICE-PROVIDER-EVIDENCE-v1';
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
const SYNTHETIC_PROVIDER_PUBLIC_KEY = createPublicKey(SYNTHETIC_PROVIDER_PRIVATE_KEY)
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
    computeGuardPolicyHash(validation.values.policy);
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
  }, action, operationId);
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
