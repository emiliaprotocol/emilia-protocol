#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Exhaustive bounded checker for EP-OUTCOME-AUTHORITY-BOUNDED-MODEL-v1.
 *
 * Every obligation is checked over the complete finite domain exported by the
 * model. Each obligation also carries a deliberately weakened semantics; the
 * gate requires a concrete counterexample against that mutant so a vacuous or
 * disconnected invariant cannot pass silently.
 */
import { pathToFileURL } from 'node:url';
import {
  FORMAL_MODEL_VERSION,
  FORMAL_OBLIGATIONS,
  OUTCOMES,
  MODEL_INTERNALS,
  enumerateAuthorityStates,
  enumerateOutcomeStates,
  enumerateRotationStates,
  evaluateAuthorityState,
  evaluateOutcomeState,
  evaluateRotationState,
  outcomeResultDigest,
} from './outcome-authority-join.model.mjs';

function witness(value) {
  return value ? JSON.parse(JSON.stringify(value)) : null;
}

function checkExactActionReceiptBinding(outcomeStates) {
  const violation = outcomeStates.find((state) => {
    const result = evaluateOutcomeState(state);
    return result.accepted
      && MODEL_INTERNALS.exactBindingFields.some((field) => state[field] !== true);
  });
  const mutationCounterexample = outcomeStates.find((state) => {
    const weakened = {
      ...state,
      receipt_verified: true,
      attestation_verified: true,
      signed_predictions_bound: true,
      receipt_id_match: true,
      receipt_digest_match: true,
      action_digest_match: true,
      consumption_nonce_match: true,
    };
    return evaluateOutcomeState(weakened).accepted
      && MODEL_INTERNALS.exactBindingFields.some((field) => state[field] !== true);
  });
  return {
    states_checked: outcomeStates.length,
    verified: violation === undefined,
    counterexample: witness(violation),
    mutation_counterexample: witness(mutationCounterexample),
  };
}

function checkPolicyCannotWiden(outcomeStates) {
  const violation = outcomeStates.find((state) => {
    const result = evaluateOutcomeState(state);
    return state.signed_outcome !== 'in_bounds' && result.accepted;
  });
  const mutationCounterexample = outcomeStates.find((state) => {
    const result = evaluateOutcomeState(state, { policyMayReplaceSigned: true });
    return state.policy_present
      && state.signed_outcome !== 'in_bounds'
      && state.policy_outcome === 'in_bounds'
      && result.accepted;
  });
  return {
    states_checked: outcomeStates.length,
    verified: violation === undefined,
    counterexample: witness(violation),
    mutation_counterexample: witness(mutationCounterexample),
  };
}

function digestCollision(outcomeStates, semantics = {}) {
  const seen = new Map();
  let checked = 0;
  for (const state of outcomeStates) {
    for (const reportedVerdict of OUTCOMES) {
      checked += 1;
      const digest = outcomeResultDigest(state, reportedVerdict, semantics);
      const prior = seen.get(digest);
      if (prior && prior.reported_verdict !== reportedVerdict) {
        return {
          checked,
          collision: {
            digest,
            first: prior,
            second: { state, reported_verdict: reportedVerdict },
          },
        };
      }
      seen.set(digest, { state, reported_verdict: reportedVerdict });
    }
  }
  return { checked, collision: null };
}

function checkReplayResultDigest(outcomeStates) {
  const sound = digestCollision(outcomeStates);
  const weakened = digestCollision(outcomeStates, { omitReportedVerdictFromDigest: true });
  return {
    states_checked: sound.checked,
    verified: sound.collision === null,
    counterexample: witness(sound.collision),
    mutation_counterexample: witness(weakened.collision),
  };
}

function checkNewestDocument(authorityStates) {
  const violation = authorityStates.find((state) => (
    state.proof_key_present_in_older
    && !state.proof_key_present_in_newest
    && evaluateAuthorityState(state).issuer_accepted
  ));
  const mutationCounterexample = authorityStates.find((state) => (
    state.proof_key_present_in_older
    && !state.proof_key_present_in_newest
    && evaluateAuthorityState(state, { fallBackToOlderDocument: true }).issuer_accepted
  ));
  return {
    states_checked: authorityStates.length,
    verified: violation === undefined,
    counterexample: witness(violation),
    mutation_counterexample: witness(mutationCounterexample),
  };
}

function checkRevokedKeys(authorityStates, rotationStates) {
  const proofViolation = authorityStates.find((state) => (
    state.proof_key_revoked && evaluateAuthorityState(state).issuer_accepted
  ));
  const rotationViolation = rotationStates.find((state) => (
    state.rotation_key_revoked && evaluateRotationState(state).rotation_accepted
  ));
  const proofMutation = authorityStates.find((state) => (
    state.proof_key_revoked
    && evaluateAuthorityState(state, { ignoreProofKeyRevocation: true }).issuer_accepted
  ));
  const rotationMutation = rotationStates.find((state) => (
    state.rotation_key_revoked
    && evaluateRotationState(state, { ignoreRotationKeyRevocation: true }).rotation_accepted
  ));
  return {
    states_checked: authorityStates.length + rotationStates.length,
    verified: proofViolation === undefined && rotationViolation === undefined,
    counterexample: witness(proofViolation || rotationViolation),
    mutation_counterexample: witness(proofMutation || rotationMutation),
  };
}

function checkRegistryPins(authorityStates) {
  const violation = authorityStates.find((state) => (
    (!state.registry_head_pin_present || !state.registry_epoch_pin_present)
    && evaluateAuthorityState(state).issuer_accepted
  ));
  const mutationCounterexample = authorityStates.find((state) => (
    (!state.registry_head_pin_present || !state.registry_epoch_pin_present)
    && evaluateAuthorityState(state, { registryPinsOptional: true }).issuer_accepted
  ));
  return {
    states_checked: authorityStates.length,
    verified: violation === undefined,
    counterexample: witness(violation),
    mutation_counterexample: witness(mutationCounterexample),
  };
}

export function runFormalChecks() {
  const outcomeStates = [...enumerateOutcomeStates()];
  const authorityStates = [...enumerateAuthorityStates()];
  const rotationStates = [...enumerateRotationStates()];
  const obligations = {
    ExactActionReceiptBinding: checkExactActionReceiptBinding(outcomeStates),
    PolicyCannotWidenSignedPredictions: checkPolicyCannotWiden(outcomeStates),
    ReplayResultDigestCommitsVerdict: checkReplayResultDigest(outcomeStates),
    NewestAuthorityDocumentPreventsKeyResurrection: checkNewestDocument(authorityStates),
    RevokedRotationAndProofKeysFailClosed:
      checkRevokedKeys(authorityStates, rotationStates),
    RegistryPinsMandatory: checkRegistryPins(authorityStates),
  };
  const complete = FORMAL_OBLIGATIONS.every((name) => obligations[name]);
  const verified = complete && Object.values(obligations).every((result) => (
    result.verified === true && result.mutation_counterexample !== null
  ));
  return {
    model: FORMAL_MODEL_VERSION,
    method: 'bounded_exhaustive_state_exploration',
    domains: {
      outcome_states: outcomeStates.length,
      authority_states: authorityStates.length,
      rotation_states: rotationStates.length,
    },
    obligations,
    verified,
    limitations: [
      'Finite abstraction, not an unbounded protocol proof.',
      'Signature unforgeability and SHA-256 collision resistance are ideal-constructor assumptions.',
      'Authenticated time comparisons are inputs; the model supplies no trusted time source.',
      'No physical truth, external witness, or independent implementation is modeled.',
    ],
  };
}

function printHuman(result) {
  console.log(`${result.model}: ${result.verified ? 'PASS' : 'FAIL'}`);
  for (const name of FORMAL_OBLIGATIONS) {
    const row = result.obligations[name];
    console.log(
      `${name}: ${row.verified ? 'verified' : 'FAILED'} `
      + `(${row.states_checked} states; mutation counterexample: `
      + `${row.mutation_counterexample ? 'found' : 'missing'})`,
    );
  }
}

const invokedAsScript = process.argv[1]
  && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedAsScript) {
  const result = runFormalChecks();
  if (process.argv.includes('--json')) console.log(JSON.stringify(result));
  else printHuman(result);
  if (!result.verified) process.exitCode = 1;
}
