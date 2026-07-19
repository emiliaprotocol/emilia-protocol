// SPDX-License-Identifier: Apache-2.0
/**
 * EP-OUTCOME-AUTHORITY-BOUNDED-MODEL-v1
 *
 * A finite, executable abstraction of the load-bearing safety rules shared by
 * EP-OUTCOME-BINDING-v1 and EP-AUTHORITY-DOC-PROOF-JOIN-v1.
 *
 * Scope is deliberately narrow:
 * - signatures and SHA-256 are ideal, unforgeable/injective constructors;
 * - digest equality, key presence, revocation, and relying-party pins are
 *   modeled as exact finite facts;
 * - time is an authenticated comparison result, not a clock supplied here;
 * - no physical truth, external witness, or implementation independence is
 *   represented.
 */

export const FORMAL_MODEL_VERSION = 'EP-OUTCOME-AUTHORITY-BOUNDED-MODEL-v1';

export const FORMAL_OBLIGATIONS = Object.freeze([
  'ExactActionReceiptBinding',
  'PolicyCannotWidenSignedPredictions',
  'ReplayResultDigestCommitsVerdict',
  'NewestAuthorityDocumentPreventsKeyResurrection',
  'RevokedRotationAndProofKeysFailClosed',
  'RegistryPinsMandatory',
]);

export const OUTCOMES = Object.freeze(['in_bounds', 'divergent', 'incomparable']);

const BOOLS = Object.freeze([false, true]);
const EXACT_BINDING_FIELDS = Object.freeze([
  'receipt_verified',
  'attestation_verified',
  'signed_predictions_bound',
  'receipt_id_match',
  'receipt_digest_match',
  'action_digest_match',
  'consumption_nonce_match',
]);
const AUTHORITY_ACCEPTANCE_FIELDS = Object.freeze([
  'document_chain_verified',
  'continuity_verified',
  'document_anchor_present',
  'organization_bound',
  'proof_document_bound',
  'registry_issuer_bound',
  'proof_key_present_in_newest',
  'proof_key_usage_valid',
  'proof_signature_verified',
  'proof_time_anchor_verified',
  'registry_head_pin_present',
  'registry_epoch_pin_present',
  'registry_head_matches',
  'registry_epoch_fresh',
]);

function combineOutcomes(signed, policyPresent, policy) {
  const evaluated = policyPresent ? [signed, policy] : [signed];
  if (evaluated.includes('divergent')) return 'divergent';
  if (evaluated.includes('incomparable')) return 'incomparable';
  return 'in_bounds';
}

function symbolicDigest(parts) {
  // A constructor, not a cryptographic implementation. Injectivity is the
  // model's explicit SHA-256 collision-resistance abstraction.
  return `H(${JSON.stringify(parts)})`;
}

export function normalizeOutcomeState(state = {}) {
  return {
    receipt_verified: state.receipt_verified ?? true,
    attestation_verified: state.attestation_verified ?? true,
    signed_predictions_bound: state.signed_predictions_bound ?? true,
    receipt_id_match: state.receipt_id_match ?? true,
    receipt_digest_match: state.receipt_digest_match ?? true,
    action_digest_match: state.action_digest_match ?? true,
    consumption_nonce_match: state.consumption_nonce_match ?? true,
    signed_outcome: state.signed_outcome ?? 'in_bounds',
    policy_present: state.policy_present ?? false,
    policy_outcome: state.policy_outcome ?? 'in_bounds',
    receipt_commitment: state.receipt_commitment ?? 'receipt:0',
    attestation_commitment: state.attestation_commitment ?? 'attestation:0',
    policy_commitment: state.policy_commitment ?? 'policy:0',
  };
}

export function evaluateOutcomeState(input, semantics = {}) {
  const state = normalizeOutcomeState(input);
  const exactBinding = EXACT_BINDING_FIELDS.every((field) => state[field] === true);
  const finalOutcome = semantics.policyMayReplaceSigned === true && state.policy_present
    ? state.policy_outcome
    : combineOutcomes(state.signed_outcome, state.policy_present, state.policy_outcome);
  const accepted = exactBinding && finalOutcome === 'in_bounds';
  return {
    state,
    exact_binding: exactBinding,
    final_outcome: finalOutcome,
    accepted,
  };
}

export function outcomeResultDigest(input, reportedVerdict, semantics = {}) {
  const result = evaluateOutcomeState(input, semantics);
  const checks = EXACT_BINDING_FIELDS.map((field) => [field, result.state[field]]);
  const preimage = [
    FORMAL_MODEL_VERSION,
    result.state.receipt_commitment,
    result.state.attestation_commitment,
    result.state.policy_present ? result.state.policy_commitment : null,
    checks,
    result.final_outcome,
    ...(semantics.omitReportedVerdictFromDigest === true ? [] : [reportedVerdict]),
  ];
  return symbolicDigest(preimage);
}

export function normalizeAuthorityState(state = {}) {
  return {
    document_chain_verified: state.document_chain_verified ?? true,
    continuity_verified: state.continuity_verified ?? true,
    document_anchor_present: state.document_anchor_present ?? true,
    organization_bound: state.organization_bound ?? true,
    proof_document_bound: state.proof_document_bound ?? true,
    registry_issuer_bound: state.registry_issuer_bound ?? true,
    proof_key_present_in_older: state.proof_key_present_in_older ?? true,
    proof_key_present_in_newest: state.proof_key_present_in_newest ?? true,
    proof_key_usage_valid: state.proof_key_usage_valid ?? true,
    proof_key_revoked: state.proof_key_revoked ?? false,
    proof_signature_verified: state.proof_signature_verified ?? true,
    proof_time_anchor_verified: state.proof_time_anchor_verified ?? true,
    registry_head_pin_present: state.registry_head_pin_present ?? true,
    registry_epoch_pin_present: state.registry_epoch_pin_present ?? true,
    registry_head_matches: state.registry_head_matches ?? true,
    registry_epoch_fresh: state.registry_epoch_fresh ?? true,
  };
}

export function evaluateAuthorityState(input, semantics = {}) {
  const state = normalizeAuthorityState(input);
  const proofKeyResolvable = semantics.fallBackToOlderDocument === true
    ? state.proof_key_present_in_newest || state.proof_key_present_in_older
    : state.proof_key_present_in_newest;
  const requiredFields = AUTHORITY_ACCEPTANCE_FIELDS.filter((field) => (
    semantics.registryPinsOptional === true
      ? field !== 'registry_head_pin_present' && field !== 'registry_epoch_pin_present'
      : true
  ));
  const accepted = requiredFields.every((field) => (
    field === 'proof_key_present_in_newest' ? proofKeyResolvable : state[field] === true
  )) && (semantics.ignoreProofKeyRevocation === true || state.proof_key_revoked === false);
  return {
    state,
    proof_key_resolvable: proofKeyResolvable,
    issuer_accepted: accepted,
  };
}

export function normalizeRotationState(state = {}) {
  return {
    current_chain_verified: state.current_chain_verified ?? true,
    rotation_key_present_in_current: state.rotation_key_present_in_current ?? true,
    rotation_key_usage_valid: state.rotation_key_usage_valid ?? true,
    rotation_key_valid_at_successor: state.rotation_key_valid_at_successor ?? true,
    rotation_key_revoked: state.rotation_key_revoked ?? false,
    successor_continuity_signature_verified:
      state.successor_continuity_signature_verified ?? true,
  };
}

export function evaluateRotationState(input, semantics = {}) {
  const state = normalizeRotationState(input);
  const accepted = state.current_chain_verified
    && state.rotation_key_present_in_current
    && state.rotation_key_usage_valid
    && state.rotation_key_valid_at_successor
    && state.successor_continuity_signature_verified
    && (semantics.ignoreRotationKeyRevocation === true || state.rotation_key_revoked === false);
  return { state, rotation_accepted: accepted };
}

function* booleanAssignments(fields, index = 0, current = {}) {
  if (index === fields.length) {
    yield { ...current };
    return;
  }
  const field = fields[index];
  for (const value of BOOLS) {
    current[field] = value;
    yield* booleanAssignments(fields, index + 1, current);
  }
}

export function* enumerateOutcomeStates() {
  for (const bits of booleanAssignments(EXACT_BINDING_FIELDS)) {
    for (const signed_outcome of OUTCOMES) {
      yield { ...bits, signed_outcome, policy_present: false, policy_outcome: 'in_bounds' };
      for (const policy_outcome of OUTCOMES) {
        yield { ...bits, signed_outcome, policy_present: true, policy_outcome };
      }
    }
  }
}

export function* enumerateAuthorityStates() {
  const fields = [
    ...AUTHORITY_ACCEPTANCE_FIELDS.filter((field) => field !== 'proof_key_present_in_newest'),
    'proof_key_present_in_newest',
    'proof_key_revoked',
  ];
  for (const bits of booleanAssignments(fields)) {
    yield { ...bits, proof_key_present_in_older: true };
  }
}

export function* enumerateRotationStates() {
  yield* booleanAssignments([
    'current_chain_verified',
    'rotation_key_present_in_current',
    'rotation_key_usage_valid',
    'rotation_key_valid_at_successor',
    'rotation_key_revoked',
    'successor_continuity_signature_verified',
  ]);
}

export function evaluateFormalCase(vector) {
  if (vector?.kind === 'outcome') {
    return evaluateOutcomeState(vector.state).accepted;
  }
  if (vector?.kind === 'authority_join') {
    return evaluateAuthorityState(vector.state).issuer_accepted;
  }
  if (vector?.kind === 'authority_rotation') {
    return evaluateRotationState(vector.state).rotation_accepted;
  }
  throw new Error(`unknown formal case kind: ${vector?.kind}`);
}

export const MODEL_INTERNALS = Object.freeze({
  exactBindingFields: EXACT_BINDING_FIELDS,
  authorityAcceptanceFields: AUTHORITY_ACCEPTANCE_FIELDS,
});
