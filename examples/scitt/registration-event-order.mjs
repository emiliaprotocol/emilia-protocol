// SPDX-License-Identifier: Apache-2.0
// Generated from registration-event-order.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
export const ORDER_RESULTS = Object.freeze({
    ATTESTED_EFFECT_ORDER_ESTABLISHED: 'ATTESTED_EFFECT_ORDER_ESTABLISHED',
    REGISTRATION_ORDER_ONLY: 'REGISTRATION_ORDER_ONLY',
    CORRESPONDENCE_ONLY: 'CORRESPONDENCE_ONLY',
});
function registration(record, field) {
    const value = record?.[field];
    if (!value
        || typeof value.log_id !== 'string'
        || !Number.isSafeInteger(value.index)
        || value.index < 0
        || typeof value.operation_id !== 'string'
        || typeof value.record_digest !== 'string') {
        throw new TypeError(`${field} must identify an operation-bound record at a non-negative log index`);
    }
    return value;
}
function isVerifiedPreEffectEntry(record) {
    return record.phase === 'PENDING_BEFORE_EFFECT'
        && record.native_verification === 'VERIFIED';
}
function isVerifiedEffectTerminal(entry, terminal) {
    return terminal !== null
        && terminal.phase === 'TERMINAL'
        && terminal.native_verification === 'VERIFIED'
        && terminal.effect_evidence_verification === 'VERIFIED'
        && terminal.outcome === 'EFFECT_CONFIRMED'
        && terminal.operation_id === entry.operation_id;
}
function registrationOnly() {
    return {
        result: ORDER_RESULTS.REGISTRATION_ORDER_ONLY,
        attested_effect_order_established: false,
        reason: 'no_verified_effect_terminal_before_second_pre_effect_entry',
    };
}
/**
 * Classify what two transparent operation records establish about effect order.
 *
 * Registration order is not event order. Even a PENDING_BEFORE_EFFECT entry
 * only proves that the entry preceded its own attempted effect. To establish
 * an order between authenticated effect claims, an exact-operation terminal
 * attesting EFFECT_CONFIRMED for A must precede B's verified pre-effect entry
 * in one sequencer, or an independently verified cross-log relationship must
 * bind and order those exact records.
 *
 * This function classifies already verified inputs. It does not verify log
 * receipts, signatures, emitter truthfulness, or cross-log cryptography.
 */
export function assessRegistrationEventOrder({ first, second, cross_log_relationship: relationship = null }) {
    const firstEntry = registration(first, 'entry');
    const secondEntry = registration(second, 'entry');
    const firstTerminal = first?.terminal ? registration(first, 'terminal') : null;
    const validRecords = isVerifiedPreEffectEntry(firstEntry)
        && isVerifiedPreEffectEntry(secondEntry)
        && isVerifiedEffectTerminal(firstEntry, firstTerminal)
        && firstTerminal.log_id === firstEntry.log_id
        && firstEntry.index < firstTerminal.index;
    if (firstEntry.log_id === secondEntry.log_id) {
        if (validRecords
            && firstTerminal.log_id === firstEntry.log_id
            && firstEntry.index < firstTerminal.index
            && firstTerminal.index < secondEntry.index) {
            return {
                result: ORDER_RESULTS.ATTESTED_EFFECT_ORDER_ESTABLISHED,
                attested_effect_order_established: true,
                reason: 'verified_effect_terminal_precedes_second_pre_effect_entry_in_one_sequencer',
            };
        }
        return registrationOnly();
    }
    if (validRecords
        && relationship?.native_verification === 'VERIFIED'
        && typeof relationship?.profile_id === 'string'
        && relationship.profile_id.length > 0
        && relationship?.first_terminal_before_second_entry === true
        && relationship?.first_terminal_digest === firstTerminal.record_digest
        && relationship?.second_entry_digest === secondEntry.record_digest) {
        return {
            result: ORDER_RESULTS.ATTESTED_EFFECT_ORDER_ESTABLISHED,
            attested_effect_order_established: true,
            reason: 'verified_cross_log_relationship_orders_effect_terminal_before_pre_effect_entry',
        };
    }
    return {
        result: ORDER_RESULTS.CORRESPONDENCE_ONLY,
        attested_effect_order_established: false,
        reason: 'independent_or_unrelated_logs',
    };
}
