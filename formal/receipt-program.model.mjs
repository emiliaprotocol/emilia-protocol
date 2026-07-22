// SPDX-License-Identifier: Apache-2.0
/**
 * EP-RECEIPT-PROGRAM-BOUNDED-MODEL-v1
 *
 * Finite lifecycle model for a single receipt-program instance. The explorer
 * records historical facts (validation at reserve, prior held reservation,
 * first terminal state) so later state cannot erase an ordering violation.
 */

export const FORMAL_MODEL_VERSION = 'EP-RECEIPT-PROGRAM-BOUNDED-MODEL-v1';

export const FORMAL_OBLIGATIONS = Object.freeze([
  'CaidValidatedBeforeReservation',
  'ReservationPrecedesExternalEffect',
  'ConsumedReceiptReplayIsRefused',
  'IndeterminateRetainsReservation',
  'TerminalStateIsImmutable',
  'CertificateRequiresTerminalEvidenceSignerAndAppend',
]);

export const INITIAL_STATE = Object.freeze({
  caid_status: 'unchecked',
  reservation: 'none',
  reservation_created: false,
  caid_valid_at_reservation: false,
  reservation_was_held_before_effect: false,
  receipt_consumed: false,
  effect_attempts: 0,
  effect: 'none',
  status: 'ready',
  terminal_origin: null,
  terminal_evidence: false,
  signer_verified: false,
  append_succeeded: false,
  certificate_issued: false,
});

const TERMINAL_STATES = Object.freeze([
  'terminal_executed',
  'terminal_failed',
  'terminal_escalated',
]);

export function isTerminal(status) {
  return TERMINAL_STATES.includes(status);
}

function withState(state, changes) {
  return { ...state, ...changes };
}

function transition(name, state) {
  return { name, state };
}

export function nextReceiptProgramStates(state, semantics = {}) {
  const next = [];
  if (state.caid_status === 'unchecked') {
    next.push(transition('validate_caid_valid', withState(state, { caid_status: 'valid' })));
    next.push(transition('validate_caid_invalid', withState(state, { caid_status: 'invalid' })));
  }

  if (state.status === 'ready'
      && state.reservation === 'none'
      && (state.caid_status === 'valid' || semantics.allowReserveBeforeCaid === true)) {
    next.push(transition('reserve', withState(state, {
      reservation: 'held',
      reservation_created: true,
      caid_valid_at_reservation: state.caid_status === 'valid',
    })));
  }

  const reservationPermitsEffect = state.reservation === 'held'
    || semantics.allowEffectWithoutReservation === true;
  const consumptionPermitsEffect = !state.receipt_consumed
    || semantics.allowReceiptReplay === true;
  if (state.status === 'ready'
      && !isTerminal(state.status)
      && reservationPermitsEffect
      && consumptionPermitsEffect
      && state.effect_attempts < 2) {
    next.push(transition('begin_external_effect', withState(state, {
      reservation_was_held_before_effect:
        state.reservation_was_held_before_effect || state.reservation === 'held',
      receipt_consumed: true,
      effect_attempts: state.effect_attempts + 1,
      effect: 'pending',
    })));
  }

  if (state.effect === 'pending' && state.status === 'ready') {
    next.push(transition('observe_effect_succeeded', withState(state, { effect: 'succeeded' })));
    next.push(transition('observe_effect_failed', withState(state, { effect: 'failed' })));
    next.push(transition('observe_effect_indeterminate', withState(state, {
      effect: 'indeterminate',
      status: 'indeterminate',
      reservation: semantics.releaseOnIndeterminate === true ? 'released' : state.reservation,
    })));
  }

  if (state.status === 'indeterminate' && state.effect === 'indeterminate') {
    next.push(transition('reconcile_succeeded', withState(state, { effect: 'succeeded' })));
    next.push(transition('reconcile_failed', withState(state, { effect: 'failed' })));
  }

  if (['succeeded', 'failed', 'indeterminate'].includes(state.effect)
      && !state.terminal_evidence) {
    next.push(transition('record_terminal_evidence', withState(state, { terminal_evidence: true })));
  }
  if (state.terminal_evidence && !state.signer_verified) {
    next.push(transition('verify_terminal_signer', withState(state, { signer_verified: true })));
  }
  if (state.terminal_evidence && state.signer_verified && !state.append_succeeded) {
    next.push(transition('append_terminal_evidence', withState(state, { append_succeeded: true })));
  }

  const terminalPrerequisites = state.terminal_evidence
    && state.signer_verified
    && state.append_succeeded;
  if (!isTerminal(state.status) && terminalPrerequisites) {
    if (state.effect === 'succeeded') {
      next.push(transition('finalize_executed', withState(state, {
        status: 'terminal_executed',
        terminal_origin: 'terminal_executed',
        reservation: 'committed',
      })));
    }
    if (state.effect === 'failed') {
      next.push(transition('finalize_failed', withState(state, {
        status: 'terminal_failed',
        terminal_origin: 'terminal_failed',
        reservation: 'released',
      })));
    }
    if (state.effect === 'indeterminate') {
      next.push(transition('finalize_escalated', withState(state, {
        status: 'terminal_escalated',
        terminal_origin: 'terminal_escalated',
        reservation: 'released',
      })));
    }
  }

  const certificatePrerequisites = isTerminal(state.status) && terminalPrerequisites;
  if (!state.certificate_issued
      && (certificatePrerequisites || semantics.issueCertificateWithoutPrerequisites === true)) {
    next.push(transition('issue_certificate', withState(state, { certificate_issued: true })));
  }

  if (semantics.allowTerminalMutation === true && isTerminal(state.status)) {
    for (const nextTerminal of TERMINAL_STATES) {
      if (nextTerminal !== state.status) {
        next.push(transition('mutate_terminal_state', withState(state, { status: nextTerminal })));
      }
    }
  }

  return next;
}

function stateKey(state) {
  return JSON.stringify(state);
}

export function exploreReceiptProgram(semantics = {}) {
  const initial = { ...INITIAL_STATE };
  /** @type {Array<{ state: any, trace: string[] }>} */
  const queue = [{ state: initial, trace: [] }];
  /** @type {Map<string, { state: any, trace: string[] }>} */
  const visited = new Map([[stateKey(initial), queue[0]]]);
  for (let index = 0; index < queue.length; index += 1) {
    const current = queue[index];
    for (const successor of nextReceiptProgramStates(current.state, semantics)) {
      const key = stateKey(successor.state);
      if (visited.has(key)) continue;
      const entry = {
        state: successor.state,
        trace: [...current.trace, successor.name],
      };
      visited.set(key, entry);
      queue.push(entry);
    }
  }
  return queue;
}

export const RECEIPT_PROGRAM_PROPERTIES = Object.freeze({
  CaidValidatedBeforeReservation: (state) => (
    !state.reservation_created || state.caid_valid_at_reservation
  ),
  ReservationPrecedesExternalEffect: (state) => (
    state.effect_attempts === 0 || state.reservation_was_held_before_effect
  ),
  ConsumedReceiptReplayIsRefused: (state) => state.effect_attempts <= 1,
  IndeterminateRetainsReservation: (state) => (
    state.status !== 'indeterminate' || state.reservation === 'held'
  ),
  TerminalStateIsImmutable: (state) => (
    state.terminal_origin === null || state.status === state.terminal_origin
  ),
  CertificateRequiresTerminalEvidenceSignerAndAppend: (state) => (
    !state.certificate_issued
      || (isTerminal(state.status)
        && state.terminal_evidence
        && state.signer_verified
        && state.append_succeeded)
  ),
});

export const MUTATION_SEMANTICS = Object.freeze({
  CaidValidatedBeforeReservation: Object.freeze({ allowReserveBeforeCaid: true }),
  ReservationPrecedesExternalEffect: Object.freeze({ allowEffectWithoutReservation: true }),
  ConsumedReceiptReplayIsRefused: Object.freeze({ allowReceiptReplay: true }),
  IndeterminateRetainsReservation: Object.freeze({ releaseOnIndeterminate: true }),
  TerminalStateIsImmutable: Object.freeze({ allowTerminalMutation: true }),
  CertificateRequiresTerminalEvidenceSignerAndAppend:
    Object.freeze({ issueCertificateWithoutPrerequisites: true }),
});

export const MODEL_INTERNALS = Object.freeze({ terminalStates: TERMINAL_STATES });
