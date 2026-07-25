// SPDX-License-Identifier: Apache-2.0
/**
 * Deliberately unsafe comparison semantics for the bounded AEC fleet model.
 * Each mutation weakens exactly one named boundary and must yield a concrete
 * counterexample under the finite domain exercised by the checker.
 */

export const UNSAFE_COMPARISONS = Object.freeze({
  ConstructorTrustInputsImmutable: Object.freeze({
    mutation: 'unsafe_live_constructor_trust_reference',
    semantics: Object.freeze({ liveConstructorTrust: true }),
  }),
  VerifierMethodCaptured: Object.freeze({
    mutation: 'unsafe_lookup_verifier_method_at_run',
    semantics: Object.freeze({ lookupVerifierAtRun: true }),
  }),
  TransactionScopedTrustRefused: Object.freeze({
    mutation: 'unsafe_accept_transaction_scoped_trust',
    semantics: Object.freeze({ acceptTransactionTrust: true }),
  }),
  CanonicalActionKeyOnly: Object.freeze({
    mutation: 'unsafe_presenter_selected_replay_key',
    semantics: Object.freeze({ presenterSelectedReplayKey: true }),
  }),
  ReservationOwnerFenced: Object.freeze({
    mutation: 'unsafe_ignore_reservation_owner',
    semantics: Object.freeze({ ignoreReservationOwner: true }),
  }),
  ReservationNeverExpires: Object.freeze({
    mutation: 'unsafe_expire_inflight_reservation',
    semantics: Object.freeze({ expireReservation: true }),
  }),
  SharedHeadAppendAtomic: Object.freeze({
    mutation: 'unsafe_non_atomic_shared_head',
    semantics: Object.freeze({ nonAtomicSharedHead: true }),
  }),
  EvidenceReadbackAcknowledgementExact: Object.freeze({
    mutation: 'unsafe_trust_backend_ack_without_exact_readback',
    semantics: Object.freeze({ trustBackendAcknowledgement: true }),
  }),
  ResponseLossFreezesReplay: Object.freeze({
    mutation: 'unsafe_release_after_provider_response_loss',
    semantics: Object.freeze({ releaseAfterResponseLoss: true }),
  }),
  ReplicasShareConsumptionDomain: Object.freeze({
    mutation: 'unsafe_per_replica_consumption_domain',
    semantics: Object.freeze({ perReplicaConsumptionDomain: true }),
  }),
  RestartCannotAdoptReservation: Object.freeze({
    mutation: 'unsafe_reconstruct_owner_after_restart',
    semantics: Object.freeze({ reconstructReservationOwnerAfterRestart: true }),
  }),
  ReservationFailureCannotExecute: Object.freeze({
    mutation: 'unsafe_execute_before_reservation',
    semantics: Object.freeze({ executeBeforeReservation: true }),
  }),
  ProviderExecutionAtMostOnce: Object.freeze({
    mutation: 'unsafe_retry_provider_after_terminal_attempt',
    semantics: Object.freeze({ retryProviderAfterTerminal: true }),
  }),
});
