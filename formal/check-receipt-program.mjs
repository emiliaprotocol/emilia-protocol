#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/** Deterministic bounded exhaustive checker for EP Receipt Programs. */
import { pathToFileURL } from 'node:url';
import {
  FORMAL_MODEL_VERSION,
  FORMAL_OBLIGATIONS,
  MUTATION_SEMANTICS,
  RECEIPT_PROGRAM_PROPERTIES,
  exploreReceiptProgram,
} from './receipt-program.model.mjs';

function witness(entry) {
  return entry ? JSON.parse(JSON.stringify(entry)) : null;
}

function checkObligation(obligationName, soundStates) {
  const property = RECEIPT_PROGRAM_PROPERTIES[obligationName];
  const violation = soundStates.find((entry) => !property(entry.state));
  const mutationStates = exploreReceiptProgram(MUTATION_SEMANTICS[obligationName]);
  const mutationCounterexample = mutationStates.find((entry) => !property(entry.state));
  return {
    states_checked: soundStates.length,
    mutation_states_checked: mutationStates.length,
    verified: violation === undefined,
    counterexample: witness(violation),
    mutation_counterexample: witness(mutationCounterexample),
  };
}

export function runFormalChecks() {
  const soundStates = exploreReceiptProgram();
  const obligations = {
    CaidValidatedBeforeReservation:
      checkObligation('CaidValidatedBeforeReservation', soundStates),
    ReservationPrecedesExternalEffect:
      checkObligation('ReservationPrecedesExternalEffect', soundStates),
    ConsumedReceiptReplayIsRefused:
      checkObligation('ConsumedReceiptReplayIsRefused', soundStates),
    IndeterminateRetainsReservation:
      checkObligation('IndeterminateRetainsReservation', soundStates),
    TerminalStateIsImmutable:
      checkObligation('TerminalStateIsImmutable', soundStates),
    CertificateRequiresTerminalEvidenceSignerAndAppend:
      checkObligation('CertificateRequiresTerminalEvidenceSignerAndAppend', soundStates),
  };
  const complete = FORMAL_OBLIGATIONS.every((obligationName) => obligations[obligationName]);
  const verified = complete && Object.values(obligations).every((row) => (
    row.verified === true
    && row.counterexample === null
    && row.mutation_counterexample !== null
  ));
  return {
    model: FORMAL_MODEL_VERSION,
    method: 'bounded_exhaustive_state_exploration',
    domains: {
      reachable_sound_states: soundStates.length,
      maximum_effect_attempts: 2,
      receipt_program_instances: 1,
    },
    obligations,
    verified,
    limitations: [
      'Finite same-team bounded exploration, not an unbounded protocol proof.',
      'One receipt-program instance, one reservation, and at most two attempted external effects are modeled.',
      'CAID validation, signer verification, evidence validity, and durable append are authenticated Boolean outcomes supplied to the model.',
      'Provider behavior, cryptographic compromise, database isolation failure, and physical-world truth are outside scope.',
    ],
  };
}

function printHuman(result) {
  console.log(`${result.model}: ${result.verified ? 'PASS' : 'FAIL'}`);
  for (const obligationName of FORMAL_OBLIGATIONS) {
    const row = result.obligations[obligationName];
    console.log(
      `${obligationName}: ${row.verified ? 'verified' : 'FAILED'} `
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
