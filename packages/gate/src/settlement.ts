// SPDX-License-Identifier: Apache-2.0
/**
 * Deterministic evidence-completeness decision for settlement workflows.
 *
 * This is not a payment rail and does not decide legal liability. It answers a
 * narrower question: does a relying-party-pinned profile have every verified,
 * digest-joined artifact it required before its own settlement system acts?
 */
import { canonicalize, hashCanonical } from './execution-binding.js';
import {
  NETWORK_WITNESS_EVENTS,
  acceptNetworkWitnessStatement,
  networkWitnessDigest,
  validateTrustedNetworkWitnessAcceptance,
} from './network-witness.js';

export const SETTLEMENT_PROFILE_VERSION = 'EP-GATE-SETTLEMENT-PROFILE-v1';
export const SETTLEMENT_RESULT_VERSION = 'EP-GATE-SETTLEMENT-RESULT-v1';
export const SETTLEMENT_VERDICTS = Object.freeze([
  'eligible',
  'refuse_profile_invalid',
  'refuse_authorization',
  'refuse_execution',
  'refuse_witness',
  'refuse_outcome',
  'refuse_coverage',
  'refuse_binding',
]);

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, allowed) {
  return isPlainObject(value) && Object.keys(value).every((key) => allowed.has(key));
}

function string(value, max = 512) {
  return typeof value === 'string' && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
}

function digest(value) {
  return typeof value === 'string' && DIGEST_RE.test(value);
}

function canonicalSnapshot(value) {
  return JSON.parse(canonicalize(value));
}

function validateProfile(profile) {
  if (!exactKeys(profile, new Set([
    '@version', 'profile_id', 'require_witness', 'require_outcome', 'require_coverage',
    'required_witness_event', 'required_witness_id', 'required_capture_point_id',
    'required_coverage_state', 'required_surface_id',
  ]))) return 'profile_shape_invalid';
  if (profile['@version'] !== SETTLEMENT_PROFILE_VERSION || !string(profile.profile_id)) return 'profile_identity_invalid';
  for (const field of ['require_witness', 'require_outcome', 'require_coverage']) {
    if (profile[field] !== true && profile[field] !== false) return `profile_${field}_invalid`;
  }
  if (profile.require_witness && (!string(profile.required_witness_event)
      || !NETWORK_WITNESS_EVENTS.includes(profile.required_witness_event)
      || !string(profile.required_witness_id) || !string(profile.required_capture_point_id))) {
    return 'profile_witness_binding_invalid';
  }
  if (!profile.require_witness && (profile.required_witness_event !== undefined
      || profile.required_witness_id !== undefined || profile.required_capture_point_id !== undefined)) {
    return 'profile_witness_fields_forbidden';
  }
  if (profile.require_coverage && (profile.required_coverage_state !== 'gated'
      || !string(profile.required_surface_id))) return 'profile_coverage_binding_invalid';
  if (!profile.require_coverage && (profile.required_coverage_state !== undefined
      || profile.required_surface_id !== undefined)) return 'profile_coverage_fields_forbidden';
  try { canonicalize(profile); } catch { return 'profile_canonicalization_invalid'; }
  return null;
}

export function settlementProfileDigest(profile) {
  const invalid = validateProfile(profile);
  if (invalid) throw new TypeError(invalid);
  return `sha256:${hashCanonical(profile)}`;
}

function refused(verdict, reason, profileHash, checks, actionDigest = null) {
  const body = {
    '@version': SETTLEMENT_RESULT_VERSION,
    verdict,
    eligible: false,
    reason,
    profile_hash: profileHash,
    action_digest: actionDigest,
    checks,
    limitations: [
      'This result is evidence-completeness input to a relying party; it is not a legal settlement instruction or warranty.',
      'A valid evidence bundle does not establish physical truth beyond the separately verified outcome source.',
    ],
  };
  return Object.freeze({ ...body, result_hash: `sha256:${hashCanonical(body)}` });
}

async function invokeVerifier(verifier, artifact, context) {
  if (typeof verifier !== 'function') return { accepted: false, reason: 'pinned_verifier_missing' };
  try {
    const result = await verifier(artifact, Object.freeze({ ...context }));
    if (!isPlainObject(result)) return { accepted: false, reason: 'verifier_result_invalid' };
    return canonicalSnapshot(result);
  } catch {
    return { accepted: false, reason: 'pinned_verifier_error' };
  }
}

/**
 * Evaluate a raw evidence bundle. Authorization, execution, outcome, and
 * coverage are interpreted only by verifier functions pinned in code by the
 * relying party; no artifact may select its own verifier.
 */
export async function evaluateSettlementEligibility(bundle = {}, options: {
  profile?: Record<string, any>;
  verifyAuthorization?: (...args: any[]) => any;
  verifyExecution?: (...args: any[]) => any;
  verifyOutcome?: (...args: any[]) => any;
  verifyCoverage?: (...args: any[]) => any;
  pinnedWitnesses?: any[];
  trustedWitnessAcceptance?: Record<string, any>;
  witnessSequenceStore?: Record<string, any>;
  allowEphemeralWitnessStore?: boolean;
  now?: number | (() => number);
  witnessMaxAgeSec?: number;
  maxFutureSkewSec?: number;
} = {}) {
  let profileInput;
  let profileInputInvalid = false;
  try { profileInput = canonicalSnapshot(options.profile); } catch { profileInputInvalid = true; }
  let verifyAuthorization;
  let verifyExecution;
  let verifyOutcome;
  let verifyCoverage;
  let pinnedWitnesses;
  let trustedWitnessAcceptance = null;
  let hasTrustedWitnessAcceptance = false;
  let witnessSequenceStore;
  let allowEphemeralWitnessStore = false;
  let witnessNow;
  let witnessMaxAgeSec;
  let maxFutureSkewSec;
  try {
    verifyAuthorization = options.verifyAuthorization;
    verifyExecution = options.verifyExecution;
    verifyOutcome = options.verifyOutcome;
    verifyCoverage = options.verifyCoverage;
    pinnedWitnesses = options.pinnedWitnesses === undefined
      ? undefined
      : canonicalSnapshot(options.pinnedWitnesses);
    hasTrustedWitnessAcceptance = Object.hasOwn(options, 'trustedWitnessAcceptance');
    if (hasTrustedWitnessAcceptance) {
      trustedWitnessAcceptance = canonicalSnapshot(options.trustedWitnessAcceptance);
    }
    witnessSequenceStore = options.witnessSequenceStore;
    allowEphemeralWitnessStore = options.allowEphemeralWitnessStore === true;
    witnessNow = options.now;
    witnessMaxAgeSec = options.witnessMaxAgeSec;
    maxFutureSkewSec = options.maxFutureSkewSec;
  } catch {
    pinnedWitnesses = [];
    hasTrustedWitnessAcceptance = true;
    trustedWitnessAcceptance = null;
  }
  let profile;
  let invalid;
  if (profileInputInvalid) {
    invalid = 'profile_hostile_input';
    profile = null;
  } else {
    invalid = validateProfile(profileInput);
    profile = profileInput;
  }
  const baseChecks = {
    profile: !invalid,
    authorization: false,
    execution: false,
    witness: profile?.require_witness === false,
    outcome: profile?.require_outcome === false,
    coverage: profile?.require_coverage === false,
    digest_join: false,
  };
  if (invalid) return refused('refuse_profile_invalid', invalid, null, baseChecks);
  const profileHash = settlementProfileDigest(profile);
  let evidence;
  try {
    evidence = JSON.parse(canonicalize(bundle));
  } catch {
    return refused('refuse_binding', 'evidence_bundle_not_canonical_json', profileHash, baseChecks);
  }
  const actionDigest = evidence.action_digest;
  if (!digest(actionDigest)) {
    return refused('refuse_binding', 'action_digest_invalid', profileHash, baseChecks);
  }
  const context = { action_digest: actionDigest, profile_hash: profileHash };

  const authorization = await invokeVerifier(verifyAuthorization, evidence.authorization, context);
  if (authorization.accepted !== true || authorization.action_digest !== actionDigest
      || !digest(authorization.decision_digest)) {
    return refused('refuse_authorization', authorization.reason ?? 'authorization_not_verified', profileHash, baseChecks, actionDigest);
  }
  baseChecks.authorization = true;

  const execution = await invokeVerifier(verifyExecution, evidence.execution, {
    ...context,
    authorization_digest: authorization.decision_digest,
  });
  if (execution.accepted !== true || execution.outcome !== 'executed'
      || execution.action_digest !== actionDigest || !digest(execution.execution_digest)) {
    return refused('refuse_execution', execution.reason ?? 'execution_not_verified', profileHash, baseChecks, actionDigest);
  }
  baseChecks.execution = true;
  if (execution.authorization_digest !== authorization.decision_digest) {
    return refused('refuse_binding', 'execution_authorization_digest_mismatch', profileHash, baseChecks, actionDigest);
  }

  let witness: Record<string, any> | null = null;
  if (profile.require_witness) {
    const witnessOptions = {
      expectedActionDigest: actionDigest,
      expectedEvent: profile.required_witness_event,
      maxAgeSec: witnessMaxAgeSec,
      maxFutureSkewSec,
      now: witnessNow,
      allowEphemeralStore: allowEphemeralWitnessStore,
    };
    if (hasTrustedWitnessAcceptance) {
      let expectedStatementDigest;
      try { expectedStatementDigest = networkWitnessDigest(evidence.witness); } catch {
        return refused('refuse_witness', 'witness_statement_digest_invalid', profileHash, baseChecks, actionDigest);
      }
      witness = validateTrustedNetworkWitnessAcceptance(trustedWitnessAcceptance, {
        ...witnessOptions,
        expectedStatementDigest,
      });
    } else {
      witness = await acceptNetworkWitnessStatement(evidence.witness, {
        ...witnessOptions,
        pinnedWitnesses,
        sequenceStore: witnessSequenceStore,
      });
    }
    if (!witness || !witness.accepted) {
      return refused('refuse_witness', witness?.reason ?? 'witness_not_verified', profileHash, baseChecks, actionDigest);
    }
    if (witness.witness_id !== profile.required_witness_id
        || witness.capture_point_id !== profile.required_capture_point_id) {
      return refused('refuse_binding', 'witness_capture_point_mismatch', profileHash, baseChecks, actionDigest);
    }
    baseChecks.witness = true;
  }

  let outcome: Record<string, any> | null = null;
  if (profile.require_outcome) {
    outcome = await invokeVerifier(verifyOutcome, evidence.outcome, {
      ...context,
      execution_digest: execution.execution_digest,
    });
    if (!outcome || outcome.accepted !== true || outcome.within_tolerance !== true
        || outcome.action_digest !== actionDigest || !digest(outcome.outcome_digest)
        || outcome.execution_digest !== execution.execution_digest) {
      return refused('refuse_outcome', outcome?.reason ?? 'outcome_not_verified', profileHash, baseChecks, actionDigest);
    }
    baseChecks.outcome = true;
  }

  let coverage: Record<string, any> | null = null;
  if (profile.require_coverage) {
    coverage = await invokeVerifier(verifyCoverage, evidence.coverage, context);
    if (!coverage || coverage.accepted !== true || coverage.state !== profile.required_coverage_state
        || coverage.surface_id !== profile.required_surface_id || !digest(coverage.report_hash)) {
      return refused('refuse_coverage', coverage?.reason ?? 'coverage_not_verified', profileHash, baseChecks, actionDigest);
    }
    baseChecks.coverage = true;
  }

  baseChecks.digest_join = true;
  const body = {
    '@version': SETTLEMENT_RESULT_VERSION,
    verdict: 'eligible',
    eligible: true,
    reason: null,
    profile_hash: profileHash,
    action_digest: actionDigest,
    evidence: {
      authorization_digest: authorization.decision_digest,
      execution_digest: execution.execution_digest,
      ...(witness ? { witness_digest: witness.statement_digest } : {}),
      ...(outcome ? { outcome_digest: outcome.outcome_digest } : {}),
      ...(coverage ? { coverage_report_hash: coverage.report_hash, surface_id: coverage.surface_id } : {}),
    },
    checks: baseChecks,
    limitations: [
      'Eligible means the relying party\'s pinned evidence profile was satisfied; the relying party still owns pricing, legal effect, and payment execution.',
      'The witness proves observation, not authorization or physical outcome; those are separate verified rows.',
    ],
  };
  return Object.freeze({ ...body, result_hash: `sha256:${hashCanonical(body)}` });
}

export default {
  SETTLEMENT_PROFILE_VERSION,
  SETTLEMENT_RESULT_VERSION,
  SETTLEMENT_VERDICTS,
  settlementProfileDigest,
  evaluateSettlementEligibility,
};
