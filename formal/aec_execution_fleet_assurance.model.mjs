// SPDX-License-Identifier: Apache-2.0
/**
 * EP-AEC-EXECUTION-FLEET-ASSURANCE-BOUNDED-MODEL-v1
 *
 * Finite same-team model of the stateful AEC effect boundary. Backend atomicity
 * and durability are explicit acceptance roots: this model checks the gate
 * obligations built on those roots and does not claim database linearizability.
 */

export const FORMAL_MODEL_VERSION =
  'EP-AEC-EXECUTION-FLEET-ASSURANCE-BOUNDED-MODEL-v1';

export const FORMAL_OBLIGATIONS = Object.freeze([
  'ConstructorTrustInputsImmutable',
  'VerifierMethodCaptured',
  'TransactionScopedTrustRefused',
  'CanonicalActionKeyOnly',
  'ReservationOwnerFenced',
  'ReservationNeverExpires',
  'SharedHeadAppendAtomic',
  'EvidenceReadbackAcknowledgementExact',
  'ResponseLossFreezesReplay',
  'ReplicasShareConsumptionDomain',
  'RestartCannotAdoptReservation',
  'ReservationFailureCannotExecute',
  'ProviderExecutionAtMostOnce',
]);

const TRUST_VALUES = Object.freeze(['rp-trust', 'attacker-trust']);
const OWNERS = Object.freeze(['owner-a', 'owner-b']);

function permutations(left, right) {
  return Object.freeze([
    Object.freeze([left, right]),
    Object.freeze([right, left]),
  ]);
}

function constructorTrustCases() {
  const cases = [];
  for (const constructorTrust of TRUST_VALUES) {
    for (const postConstructionTrust of TRUST_VALUES) {
      for (const presentedTrust of TRUST_VALUES) {
        cases.push(Object.freeze({
          constructorTrust,
          postConstructionTrust,
          presentedTrust,
        }));
      }
    }
  }
  return Object.freeze(cases);
}

function ownerFenceCases() {
  const cases = [];
  for (const owner of OWNERS) {
    for (const presenter of OWNERS) {
      for (const operation of ['commit', 'release']) {
        cases.push(Object.freeze({ owner, presenter, operation }));
      }
    }
  }
  return Object.freeze(cases);
}

export const BOUNDARY_DOMAINS = Object.freeze({
  ConstructorTrustInputsImmutable: constructorTrustCases(),
  VerifierMethodCaptured: Object.freeze([
    Object.freeze({ evidenceValid: false, replacementAllows: false }),
    Object.freeze({ evidenceValid: false, replacementAllows: true }),
    Object.freeze({ evidenceValid: true, replacementAllows: false }),
    Object.freeze({ evidenceValid: true, replacementAllows: true }),
  ]),
  TransactionScopedTrustRefused: Object.freeze(
    ['verifiers', 'keysByType', 'policiesByType'].map((field) => Object.freeze({ field })),
  ),
  CanonicalActionKeyOnly: Object.freeze([
    Object.freeze({ sameAction: true, firstProof: 'proof-a', secondProof: 'proof-b' }),
    Object.freeze({ sameAction: true, firstProof: 'proof-b', secondProof: 'proof-a' }),
    Object.freeze({ sameAction: false, firstProof: 'proof-a', secondProof: 'proof-b' }),
  ]),
  ReservationOwnerFenced: ownerFenceCases(),
  ReservationNeverExpires: Object.freeze([
    Object.freeze({ elapsed: 0, unsafeTtl: 1 }),
    Object.freeze({ elapsed: 1, unsafeTtl: 1 }),
    Object.freeze({ elapsed: 2, unsafeTtl: 1 }),
  ]),
  SharedHeadAppendAtomic: permutations('replica-a', 'replica-b').map(
    (order) => Object.freeze({ order }),
  ),
  EvidenceReadbackAcknowledgementExact: Object.freeze(
    ['none', 'sequence', 'predecessor', 'record_id', 'content', 'hash']
      .map((alteration) => Object.freeze({ alteration })),
  ),
  ResponseLossFreezesReplay: Object.freeze([
    Object.freeze({ lossPoint: 'before_provider' }),
    Object.freeze({ lossPoint: 'after_provider' }),
  ]),
  ReplicasShareConsumptionDomain: permutations('replica-a', 'replica-b').map(
    (order) => Object.freeze({ order }),
  ),
  RestartCannotAdoptReservation: Object.freeze(
    ['commit', 'release', 'reserve'].map((operation) => Object.freeze({ operation })),
  ),
  ReservationFailureCannotExecute: Object.freeze([
    Object.freeze({ failure: 'false' }),
    Object.freeze({ failure: 'throw' }),
  ]),
  ProviderExecutionAtMostOnce: Object.freeze(
    ['sequential_replay', 'concurrent_replay', 'response_loss', 'restart_replay']
      .map((pattern) => Object.freeze({ pattern })),
  ),
});

function outcome(safe, trace, observation = {}) {
  return { safe, trace, observation };
}

function checkConstructorTrust(input, semantics) {
  const selectedTrust = semantics.liveConstructorTrust === true
    ? input.postConstructionTrust
    : input.constructorTrust;
  const providerExecuted = selectedTrust === input.presentedTrust;
  const postConstructionMutationGrantedAuthority =
    input.presentedTrust !== input.constructorTrust && providerExecuted;
  return outcome(!postConstructionMutationGrantedAuthority, [
    `construct:${input.constructorTrust}`,
    `mutate_external:${input.postConstructionTrust}`,
    `present:${input.presentedTrust}`,
    providerExecuted ? 'provider:executed' : 'provider:refused',
  ], { selectedTrust, providerExecuted });
}

function checkVerifierCapture(input, semantics) {
  const selectedVerifierAllows = semantics.lookupVerifierAtRun === true
    ? input.replacementAllows
    : input.evidenceValid;
  const replacementGrantedAuthority = !input.evidenceValid && selectedVerifierAllows;
  return outcome(!replacementGrantedAuthority, [
    `captured_verifier:${input.evidenceValid ? 'allow' : 'refuse'}`,
    `replacement_verifier:${input.replacementAllows ? 'allow' : 'refuse'}`,
    selectedVerifierAllows ? 'provider:executed' : 'provider:refused',
  ], { selectedVerifierAllows });
}

function checkTransactionConfig(input, semantics) {
  const refused = semantics.acceptTransactionTrust !== true;
  const providerExecutions = refused ? 0 : 1;
  return outcome(providerExecutions === 0, [
    `request_config:${input.field}`,
    refused ? 'request:refused' : 'request:accepted',
    `provider_executions:${providerExecutions}`,
  ], { refused, providerExecutions });
}

function checkCanonicalActionKey(input, semantics) {
  const firstAction = 'action-digest-a';
  const secondAction = input.sameAction ? firstAction : 'action-digest-b';
  const firstKey = semantics.presenterSelectedReplayKey === true
    ? `proof:${input.firstProof}`
    : `action:${firstAction}`;
  const secondKey = semantics.presenterSelectedReplayKey === true
    ? `proof:${input.secondProof}`
    : `action:${secondAction}`;
  const providerExecutions = firstKey === secondKey ? 1 : 2;
  return outcome(!input.sameAction || providerExecutions <= 1, [
    `first_key:${firstKey}`,
    'first_provider:executed',
    `second_key:${secondKey}`,
    providerExecutions === 1 ? 'second_provider:refused' : 'second_provider:executed',
  ], { firstKey, secondKey, providerExecutions });
}

function checkReservationOwner(input, semantics) {
  const accepted = input.presenter === input.owner || semantics.ignoreReservationOwner === true;
  const foreignOwnerMutation = input.presenter !== input.owner && accepted;
  return outcome(!foreignOwnerMutation, [
    `reserve:${input.owner}`,
    `${input.operation}:${input.presenter}`,
    accepted ? `${input.operation}:accepted` : `${input.operation}:refused`,
  ], { accepted });
}

function checkReservationExpiry(input, semantics) {
  const expired = semantics.expireReservation === true
    && input.elapsed >= input.unsafeTtl;
  const replayReserved = expired;
  return outcome(!replayReserved, [
    'reserve:owner-a',
    `elapsed:${input.elapsed}`,
    expired ? 'reservation:expired' : 'reservation:frozen',
    replayReserved ? 'replay:reserved' : 'replay:refused',
  ], { expired, replayReserved });
}

function checkSharedHead(input, semantics) {
  const records = semantics.nonAtomicSharedHead === true
    ? input.order.map((replica) => ({
      replica,
      seq: 0,
      predecessor: 'genesis',
      hash: `hash-${replica}`,
    }))
    : input.order.map((replica, index) => ({
      replica,
      seq: index,
      predecessor: index === 0 ? 'genesis' : `hash-${input.order[index - 1]}`,
      hash: `hash-${replica}`,
    }));
  const linear = records.every((record, index) => (
    record.seq === index
    && record.predecessor === (index === 0 ? 'genesis' : records[index - 1].hash)
  ));
  return outcome(linear, [
    `readers:${input.order.join(',')}`,
    ...records.map((record) => (
      `append:${record.replica}:seq=${record.seq}:prev=${record.predecessor}`
    )),
    linear ? 'head:linear' : 'head:forked',
  ], { records });
}

function checkExactReadback(input, semantics) {
  const persistedMatchesSubmission = input.alteration === 'none';
  const acknowledged = semantics.trustBackendAcknowledgement === true
    ? true
    : persistedMatchesSubmission;
  const conflictingAcknowledgementAccepted = !persistedMatchesSubmission && acknowledged;
  return outcome(!conflictingAcknowledgementAccepted, [
    'append:submitted',
    `readback_alteration:${input.alteration}`,
    acknowledged ? 'ack:accepted' : 'ack:refused',
  ], { persistedMatchesSubmission, acknowledged });
}

function checkResponseLoss(input, semantics) {
  const providerEntered = input.lossPoint === 'after_provider';
  let providerExecutions = providerEntered ? 1 : 0;
  const reservationFrozen = providerEntered && semantics.releaseAfterResponseLoss !== true;
  const replayExecutes = !reservationFrozen;
  if (replayExecutes) providerExecutions += 1;
  const safe = !providerEntered || (reservationFrozen && providerExecutions === 1);
  return outcome(safe, [
    'reservation:accepted',
    providerEntered ? 'provider:entered' : 'provider:not_entered',
    `response_loss:${input.lossPoint}`,
    reservationFrozen ? 'reservation:frozen' : 'reservation:released',
    replayExecutes ? 'replay_provider:executed' : 'replay_provider:refused',
  ], { providerEntered, reservationFrozen, replayExecutes, providerExecutions });
}

function checkReplicaDomain(input, semantics) {
  const shared = semantics.perReplicaConsumptionDomain !== true;
  const providerExecutions = shared ? 1 : input.order.length;
  return outcome(providerExecutions <= 1, [
    `attempt_order:${input.order.join(',')}`,
    shared ? 'consumption_domain:shared' : 'consumption_domain:per_replica',
    `provider_executions:${providerExecutions}`,
  ], { providerExecutions, shared });
}

function checkRestart(input, semantics) {
  const accepted = semantics.reconstructReservationOwnerAfterRestart === true;
  return outcome(!accepted, [
    'reserve:pre_restart_owner',
    'process:restart',
    `${input.operation}:restarted_process`,
    accepted ? `${input.operation}:accepted` : `${input.operation}:refused`,
  ], { accepted });
}

function checkReservationFailure(input, semantics) {
  const providerExecutions = semantics.executeBeforeReservation === true ? 1 : 0;
  return outcome(providerExecutions === 0, [
    semantics.executeBeforeReservation === true ? 'provider:entered' : 'provider:not_entered',
    `reservation:${input.failure}`,
    `provider_executions:${providerExecutions}`,
  ], { providerExecutions });
}

function checkProviderAtMostOnce(input, semantics) {
  const providerExecutions = semantics.retryProviderAfterTerminal === true ? 2 : 1;
  return outcome(providerExecutions <= 1, [
    `attempt_pattern:${input.pattern}`,
    'provider:first_execution',
    semantics.retryProviderAfterTerminal === true
      ? 'provider:duplicate_execution'
      : 'provider:duplicate_refused',
  ], { providerExecutions });
}

export function evaluateBoundary(name, input, semantics = {}) {
  switch (name) {
    case 'ConstructorTrustInputsImmutable':
      return checkConstructorTrust(input, semantics);
    case 'VerifierMethodCaptured':
      return checkVerifierCapture(input, semantics);
    case 'TransactionScopedTrustRefused':
      return checkTransactionConfig(input, semantics);
    case 'CanonicalActionKeyOnly':
      return checkCanonicalActionKey(input, semantics);
    case 'ReservationOwnerFenced':
      return checkReservationOwner(input, semantics);
    case 'ReservationNeverExpires':
      return checkReservationExpiry(input, semantics);
    case 'SharedHeadAppendAtomic':
      return checkSharedHead(input, semantics);
    case 'EvidenceReadbackAcknowledgementExact':
      return checkExactReadback(input, semantics);
    case 'ResponseLossFreezesReplay':
      return checkResponseLoss(input, semantics);
    case 'ReplicasShareConsumptionDomain':
      return checkReplicaDomain(input, semantics);
    case 'RestartCannotAdoptReservation':
      return checkRestart(input, semantics);
    case 'ReservationFailureCannotExecute':
      return checkReservationFailure(input, semantics);
    case 'ProviderExecutionAtMostOnce':
      return checkProviderAtMostOnce(input, semantics);
    default:
      throw new Error(`unknown AEC fleet assurance boundary: ${name}`);
  }
}
