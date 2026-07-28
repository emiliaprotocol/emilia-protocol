// SPDX-License-Identifier: Apache-2.0
/**
 * EP-RELIANCE-RISK-PLANE-BOUNDED-MODEL-v1
 *
 * Finite executable abstraction of the responsibility/exposure/refusal/
 * reconciliation composition. Each Boolean is an independently verified input,
 * never a presenter assertion. The unsafe variants deliberately remove exactly
 * one guard so the checker must find a concrete counterexample for every guard.
 */

export const RELIANCE_RISK_MODEL_VERSION = 'EP-RELIANCE-RISK-PLANE-BOUNDED-MODEL-v1';
export const RELIANCE_RISK_OBLIGATIONS = Object.freeze([
  'ProgramAcceptedBeforeReserve',
  'AuthorizationRequired',
  'ExposureCapacityRequired',
  'ReservationRequiredBeforeInvoke',
  'IndeterminateRemainsOpen',
  'NoBlindRetryFromIndeterminate',
  'IndependentReconcilerRequired',
  'RefusalNeverAuthorizes',
  'LossScheduleNeverAuthorizes',
  'CoverageDoesNotProveCompleteness',
  'TerminalStateNotSuperseded',
]);

export const RELIANCE_RISK_BOOLEAN_FIELDS = Object.freeze([
  'program_accepted',
  'authorization_accepted',
  'capacity_available',
  'exposure_reserved',
  'indeterminate',
  'exposure_open',
  'blind_retry_requested',
  'reconciler_independent',
  'refusal_present',
  'loss_schedule_present',
  'coverage_attestation_present',
  'external_population_completeness_proof',
  'terminal',
  'supersession_requested',
]);

export function evaluateRelianceRiskState(state, unsafe = '') {
  const bypass = (name) => unsafe === name;
  const reserve = (state.program_accepted || bypass('ProgramAcceptedBeforeReserve'))
    && (state.authorization_accepted || bypass('AuthorizationRequired'))
    && (state.capacity_available || bypass('ExposureCapacityRequired'));
  const invoke = (state.exposure_reserved || bypass('ReservationRequiredBeforeInvoke'))
    && (!state.indeterminate || bypass('NoBlindRetryFromIndeterminate'));
  const uncertainStillOpen = !state.indeterminate
    || (bypass('IndeterminateRemainsOpen') ? state.exposure_open : true);
  const reconcile = !state.indeterminate || state.reconciler_independent
    || bypass('IndependentReconcilerRequired');
  const refusalCanAuthorize = state.refusal_present && bypass('RefusalNeverAuthorizes');
  const scheduleCanAuthorize = state.loss_schedule_present && bypass('LossScheduleNeverAuthorizes');
  const authorization = state.authorization_accepted || refusalCanAuthorize || scheduleCanAuthorize;
  const populationComplete = state.external_population_completeness_proof
    || (state.coverage_attestation_present && bypass('CoverageDoesNotProveCompleteness'));
  const supersede = state.supersession_requested
    && (!state.terminal || bypass('TerminalStateNotSuperseded'));
  return {
    reserve,
    invoke,
    uncertain_still_open: uncertainStillOpen,
    reconcile,
    authorization,
    population_complete: populationComplete,
    supersede,
  };
}

export function obligationHolds(state, result, obligation) {
  switch (obligation) {
    case 'ProgramAcceptedBeforeReserve': return !result.reserve || state.program_accepted;
    case 'AuthorizationRequired': return !result.reserve || state.authorization_accepted;
    case 'ExposureCapacityRequired': return !result.reserve || state.capacity_available;
    case 'ReservationRequiredBeforeInvoke': return !result.invoke || state.exposure_reserved;
    case 'IndeterminateRemainsOpen': return !state.indeterminate || result.uncertain_still_open;
    case 'NoBlindRetryFromIndeterminate': return !(state.indeterminate && state.blind_retry_requested && result.invoke);
    case 'IndependentReconcilerRequired': return !state.indeterminate || !result.reconcile || state.reconciler_independent;
    case 'RefusalNeverAuthorizes': return !(state.refusal_present && !state.authorization_accepted && result.authorization);
    case 'LossScheduleNeverAuthorizes': return !(state.loss_schedule_present && !state.authorization_accepted && result.authorization);
    case 'CoverageDoesNotProveCompleteness': return !(state.coverage_attestation_present
      && !state.external_population_completeness_proof && result.population_complete);
    case 'TerminalStateNotSuperseded': return !(state.terminal && result.supersede);
    default: throw new Error(`unknown risk obligation: ${obligation}`);
  }
}

export function* enumerateRelianceRiskStates() {
  const count = 1 << RELIANCE_RISK_BOOLEAN_FIELDS.length;
  for (let mask = 0; mask < count; mask += 1) {
    yield Object.fromEntries(RELIANCE_RISK_BOOLEAN_FIELDS.map((field, index) => [field, (mask & (1 << index)) !== 0]));
  }
}
