// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Public experimental Trust Program profile for EP-REVOCATION-v1.
 *
 * The portable statement is untrusted input. The relying party derives the
 * complete commit target from its own exact execution authorization binding,
 * pinned receipt context, and pinned program version before invoking the
 * published @emilia-protocol/verify verifier.
 */
import { verifyRevocation as verifyPortableRevocation } from '@emilia-protocol/verify';
import { hashCanonical } from './execution-binding.js';
export const TRUST_PROGRAM_REVOCATION_TARGET_VERSION = 'EP-GATE-TRUST-PROGRAM-REVOCATION-TARGET-v1';
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CAID = /^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const FORBIDDEN_FIELD_NAMES = new Set(['__proto__', 'prototype', 'constructor']);
const MAX_TERMINAL_RECEIPTS = 64;
const MAX_CONTEXT_BYTES = 512;
const MAX_INVALIDATION_ATTEMPTS = 3;
const UNCLAIMED_EXECUTION_STATUSES = new Set(['locked', 'ready']);
const CLAIMED_OR_TERMINAL_EXECUTION_STATUSES = new Set([
    'claimed', 'indeterminate', 'executed', 'refused', 'proved_no_effect',
]);
const DERIVATION_INPUT_KEYS = new Set([
    'authorizationBinding', 'programVersion', 'receiptContext',
]);
const VERIFICATION_INPUT_KEYS = new Set([
    'authorizationBinding', 'programVersion', 'receiptContext',
    'statement', 'revokerKeys', 'now',
]);
const APPLY_INPUT_KEYS = new Set([
    'authorizationBinding', 'programVersion', 'receiptContext',
    'statement', 'revokerKeys', 'now', 'expectedRevision', 'kernel',
]);
const AUTHORIZATION_BINDING_KEYS = new Set([
    'instance_id', 'operation_id', 'program_digest', 'root_caid', 'action_digest',
    'receipt_context_digest', 'terminal_stage_receipt_digests', 'consequence_mode',
    'capability_template_digest', 'escrow_profile_digest',
]);
const RECEIPT_CONTEXT_KEYS = new Set([
    'issuer', 'tenant', 'environment', 'audience', 'key_id',
]);
const STATEMENT_KEYS = new Set([
    '@version', 'target_type', 'target_id', 'action_hash', 'revoker_id',
    'revoked_at', 'reason', 'proof',
]);
const PROOF_KEYS = new Set([
    'algorithm', 'revoker_key_id', 'signature_b64u', 'public_key',
]);
const PIN_KEYS = new Set(['public_key', 'key_id']);
const PIN_KEYS_WITHOUT_ID = new Set(['public_key']);
function isDataRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null)
        return false;
    return Reflect.ownKeys(value).every((key) => {
        if (typeof key !== 'string')
            return false;
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
    });
}
function exactKeys(value, keys) {
    return isDataRecord(value)
        && Reflect.ownKeys(value).length === keys.size
        && Reflect.ownKeys(value).every((key) => typeof key === 'string' && keys.has(key));
}
function dataValue(value, key) {
    return Object.getOwnPropertyDescriptor(value, key).value;
}
function assertNoPrototypeNamedFields(value) {
    if (value === null || typeof value !== 'object')
        return;
    const stack = [value];
    const seen = new WeakSet();
    while (stack.length > 0) {
        const current = stack.pop();
        if (seen.has(current))
            throw new TypeError('aliased or cyclic input is forbidden');
        seen.add(current);
        for (const key of Reflect.ownKeys(current)) {
            if (typeof key !== 'string')
                throw new TypeError('symbol fields are forbidden');
            if (FORBIDDEN_FIELD_NAMES.has(key)) {
                throw new TypeError(`prototype-named field ${key} is forbidden`);
            }
            const descriptor = Object.getOwnPropertyDescriptor(current, key);
            if (!descriptor || descriptor.enumerable !== (key !== 'length')
                || !Object.hasOwn(descriptor, 'value')) {
                if (Array.isArray(current) && key === 'length'
                    && descriptor && Object.hasOwn(descriptor, 'value'))
                    continue;
                throw new TypeError('accessor or non-enumerable fields are forbidden');
            }
            const child = descriptor.value;
            if (child !== null && typeof child === 'object')
                stack.push(child);
        }
    }
}
function deepFreeze(value) {
    if (value === null || typeof value !== 'object')
        return value;
    const stack = [value];
    const seen = new WeakSet();
    while (stack.length > 0) {
        const current = stack.pop();
        if (seen.has(current))
            continue;
        seen.add(current);
        for (const child of Object.values(current)) {
            if (child !== null && typeof child === 'object')
                stack.push(child);
        }
        Object.freeze(current);
    }
    return value;
}
function validContextString(value) {
    return typeof value === 'string'
        && value.length > 0
        && Buffer.byteLength(value, 'utf8') <= MAX_CONTEXT_BYTES
        && !/[\u0000-\u001f\u007f]/.test(value)
        && !FORBIDDEN_FIELD_NAMES.has(value);
}
function snapshotReceiptContext(value) {
    if (!exactKeys(value, RECEIPT_CONTEXT_KEYS)) {
        throw new TypeError('receipt context must use the exact closed issuer schema');
    }
    assertNoPrototypeNamedFields(value);
    const context = {
        issuer: dataValue(value, 'issuer'),
        tenant: dataValue(value, 'tenant'),
        environment: dataValue(value, 'environment'),
        audience: dataValue(value, 'audience'),
        key_id: dataValue(value, 'key_id'),
    };
    if (!Object.values(context).every(validContextString)) {
        throw new TypeError('receipt context is malformed');
    }
    return context;
}
function snapshotAuthorizationBinding(value) {
    if (!exactKeys(value, AUTHORIZATION_BINDING_KEYS)) {
        throw new TypeError('closed execution authorization binding required');
    }
    assertNoPrototypeNamedFields(value);
    const binding = {
        instance_id: dataValue(value, 'instance_id'),
        operation_id: dataValue(value, 'operation_id'),
        program_digest: dataValue(value, 'program_digest'),
        root_caid: dataValue(value, 'root_caid'),
        action_digest: dataValue(value, 'action_digest'),
        receipt_context_digest: dataValue(value, 'receipt_context_digest'),
        terminal_stage_receipt_digests: dataValue(value, 'terminal_stage_receipt_digests'),
        consequence_mode: dataValue(value, 'consequence_mode'),
        capability_template_digest: dataValue(value, 'capability_template_digest'),
        escrow_profile_digest: dataValue(value, 'escrow_profile_digest'),
    };
    if (typeof binding.instance_id !== 'string' || !ID.test(binding.instance_id)
        || typeof binding.operation_id !== 'string' || !ID.test(binding.operation_id)
        || typeof binding.program_digest !== 'string' || !DIGEST.test(binding.program_digest)
        || typeof binding.root_caid !== 'string' || !CAID.test(binding.root_caid)
        || typeof binding.action_digest !== 'string' || !DIGEST.test(binding.action_digest)
        || typeof binding.receipt_context_digest !== 'string'
        || !DIGEST.test(binding.receipt_context_digest)) {
        throw new TypeError('execution authorization binding is malformed');
    }
    const receipts = binding.terminal_stage_receipt_digests;
    if (!Array.isArray(receipts) || receipts.length === 0
        || receipts.length > MAX_TERMINAL_RECEIPTS
        || receipts.some((entry) => typeof entry !== 'string' || !DIGEST.test(entry))) {
        throw new TypeError('terminal receipt digests are malformed');
    }
    for (let index = 1; index < receipts.length; index += 1) {
        if (receipts[index - 1] >= receipts[index]) {
            throw new TypeError('sorted terminal receipt digests required');
        }
    }
    const receiptProgramOwner = binding.capability_template_digest;
    const actionEscrowOwner = binding.escrow_profile_digest;
    const ownerXor = (typeof receiptProgramOwner === 'string' && DIGEST.test(receiptProgramOwner)
        && actionEscrowOwner === null)
        || (receiptProgramOwner === null
            && typeof actionEscrowOwner === 'string' && DIGEST.test(actionEscrowOwner));
    if (!ownerXor
        || (binding.consequence_mode === 'receipt-program' && receiptProgramOwner === null)
        || (binding.consequence_mode === 'action-escrow' && actionEscrowOwner === null)
        || !['receipt-program', 'action-escrow'].includes(binding.consequence_mode)) {
        throw new TypeError('exactly one consequence owner must match consequence mode');
    }
    return {
        ...binding,
        terminal_stage_receipt_digests: [...receipts],
    };
}
function deriveTargetObjectInternal(input) {
    if (!exactKeys(input, DERIVATION_INPUT_KEYS)) {
        throw new TypeError('closed derivation input required');
    }
    const binding = snapshotAuthorizationBinding(dataValue(input, 'authorizationBinding'));
    const receiptContext = snapshotReceiptContext(dataValue(input, 'receiptContext'));
    const programVersion = dataValue(input, 'programVersion');
    if (!Number.isSafeInteger(programVersion) || programVersion < 1) {
        throw new TypeError('program version must be a positive safe integer');
    }
    const derivedReceiptContextDigest = `sha256:${hashCanonical(receiptContext)}`;
    if (binding.receipt_context_digest !== derivedReceiptContextDigest) {
        throw new TypeError('receipt context digest mismatch');
    }
    return deepFreeze({
        '@version': TRUST_PROGRAM_REVOCATION_TARGET_VERSION,
        instance_id: binding.instance_id,
        program_digest: binding.program_digest,
        program_version: programVersion,
        root_caid: binding.root_caid,
        action_digest: binding.action_digest,
        operation_id: binding.operation_id,
        receipt_context_digest: derivedReceiptContextDigest,
        terminal_stage_receipt_digests: [...binding.terminal_stage_receipt_digests],
        consequence_mode: binding.consequence_mode,
        capability_template_digest: binding.capability_template_digest,
        escrow_profile_digest: binding.escrow_profile_digest,
    });
}
/** Derive the complete closed projection whose JCS SHA-256 is action_hash. */
export function deriveTrustProgramRevocationTargetObject(input) {
    try {
        return deriveTargetObjectInternal(input);
    }
    catch (error) {
        if (error instanceof TypeError)
            throw error;
        throw new TypeError('Trust Program revocation target derivation failed closed');
    }
}
/** Derive the EP-REVOCATION-v1 commit target; no statement field is consulted. */
export function deriveTrustProgramRevocationTarget(input) {
    const targetObject = deriveTrustProgramRevocationTargetObject(input);
    return Object.freeze({
        target_type: 'commit',
        target_id: targetObject.operation_id,
        action_hash: `sha256:${hashCanonical(targetObject)}`,
    });
}
function validStatementStructure(statement) {
    try {
        if (!exactKeys(statement, STATEMENT_KEYS))
            return false;
        assertNoPrototypeNamedFields(statement);
        return exactKeys(dataValue(statement, 'proof'), PROOF_KEYS);
    }
    catch {
        return false;
    }
}
function snapshotRevokerKeys(value) {
    if (!isDataRecord(value))
        throw new TypeError('pinned revoker key registry required');
    const names = Reflect.ownKeys(value);
    if (names.length === 0 || names.length > 1024) {
        throw new TypeError('pinned revoker key registry required');
    }
    const snapshot = Object.create(null);
    for (const name of names) {
        if (typeof name !== 'string' || !validContextString(name)) {
            throw new TypeError('pinned revoker identifier is malformed');
        }
        const pin = dataValue(value, name);
        if (!(exactKeys(pin, PIN_KEYS) || exactKeys(pin, PIN_KEYS_WITHOUT_ID))) {
            throw new TypeError('pinned revoker key entry is malformed');
        }
        const publicKey = dataValue(pin, 'public_key');
        const keyId = Object.hasOwn(pin, 'key_id') ? dataValue(pin, 'key_id') : undefined;
        if (typeof publicKey !== 'string' || publicKey.length === 0
            || (keyId !== undefined && (typeof keyId !== 'string' || keyId.length === 0))) {
            throw new TypeError('pinned revoker key entry is malformed');
        }
        snapshot[name] = keyId === undefined
            ? { public_key: publicKey }
            : { public_key: publicKey, key_id: keyId };
    }
    return deepFreeze(snapshot);
}
function snapshotDecisionTime(value) {
    if (typeof value === 'number' && Number.isFinite(value))
        return value;
    if (typeof value === 'string' && value.length > 0 && value.length <= 128)
        return value;
    if (value instanceof Date && Object.getPrototypeOf(value) === Date.prototype
        && Number.isFinite(value.getTime()))
        return value.getTime();
    throw new TypeError('pinned verifier decision time required');
}
function verificationRefusal(check, message, target, targetObject) {
    return {
        valid: false,
        checks: {
            target_derived: check !== 'target_derived',
            statement_structure: !['target_derived', 'statement_structure'].includes(check),
            pinned_verifier_inputs: ![
                'target_derived', 'statement_structure', 'pinned_verifier_inputs',
            ].includes(check),
            portable_verifier_completed: false,
        },
        errors: [message],
        target: target ?? null,
        target_object: targetObject ?? null,
    };
}
/**
 * Verify a presented statement against a target independently derived from
 * relying-party state. Pinned keys and decision time are mandatory.
 */
function verifyTrustProgramRevocationInternal(input) {
    if (!exactKeys(input, VERIFICATION_INPUT_KEYS)) {
        return verificationRefusal('target_derived', 'closed Trust Program revocation verification input required');
    }
    const derivationInput = {
        authorizationBinding: dataValue(input, 'authorizationBinding'),
        programVersion: dataValue(input, 'programVersion'),
        receiptContext: dataValue(input, 'receiptContext'),
    };
    let targetObject;
    let target;
    try {
        targetObject = deriveTrustProgramRevocationTargetObject(derivationInput);
        target = deriveTrustProgramRevocationTarget(derivationInput);
    }
    catch (error) {
        return verificationRefusal('target_derived', error instanceof Error ? error.message : 'Trust Program revocation target derivation failed');
    }
    const statement = dataValue(input, 'statement');
    if (!validStatementStructure(statement)) {
        return verificationRefusal('statement_structure', 'revocation statement and proof must be closed plain data objects', target, targetObject);
    }
    let revokerKeys;
    let now;
    try {
        revokerKeys = snapshotRevokerKeys(dataValue(input, 'revokerKeys'));
        now = snapshotDecisionTime(dataValue(input, 'now'));
    }
    catch (error) {
        return verificationRefusal('pinned_verifier_inputs', error instanceof Error ? error.message : 'pinned verifier inputs are malformed', target, targetObject);
    }
    try {
        const result = verifyPortableRevocation(target, statement, { revokerKeys, now });
        if (!isDataRecord(result) || typeof result.valid !== 'boolean'
            || !isDataRecord(result.checks) || !Array.isArray(result.errors)
            || result.errors.some((entry) => typeof entry !== 'string')) {
            return verificationRefusal('portable_verifier_completed', 'portable revocation verifier returned a malformed result', target, targetObject);
        }
        return {
            valid: result.valid === true,
            checks: {
                target_derived: true,
                statement_structure: true,
                pinned_verifier_inputs: true,
                portable_verifier_completed: true,
                ...result.checks,
            },
            errors: [...result.errors],
            target,
            target_object: targetObject,
        };
    }
    catch {
        return verificationRefusal('portable_verifier_completed', 'portable revocation verifier threw; refused fail-closed', target, targetObject);
    }
}
export function verifyTrustProgramRevocation(input) {
    try {
        return verifyTrustProgramRevocationInternal(input);
    }
    catch {
        return verificationRefusal('target_derived', 'malformed Trust Program revocation verification input; refused fail-closed');
    }
}
function applyRefusal(reason, verification) {
    return {
        verified: verification?.valid === true,
        applied: false,
        blocks_claim: false,
        claim_permitted: false,
        future_authority_only: false,
        retry_required: false,
        // An unauthenticated or non-binding statement is discarded; otherwise an
        // attacker could stop claims merely by submitting malformed revocations.
        // Fail-closed is reserved for a VERIFIED revocation whose atomic state
        // transition cannot be decided.
        must_fail_closed: false,
        disposition: 'refused',
        reason,
        verification: verification ?? null,
        state: null,
    };
}
function lateDisposition(reason, verification, state, applied = false) {
    return {
        verified: true,
        applied,
        blocks_claim: false,
        claim_permitted: false,
        future_authority_only: true,
        retry_required: false,
        must_fail_closed: false,
        disposition: 'late_future_authority_only',
        reason,
        verification,
        state,
    };
}
function indeterminateDisposition(reason, verification, state) {
    return {
        verified: true,
        applied: false,
        blocks_claim: false,
        claim_permitted: false,
        future_authority_only: false,
        retry_required: true,
        must_fail_closed: true,
        disposition: 'indeterminate_retry_required',
        reason,
        verification,
        state,
    };
}
/**
 * Apply a verified revocation through bounded compare-and-swap attempts. A
 * stale but still-unclaimed instance is retried at its current revision so it
 * cannot remain claimable merely because an unrelated transition advanced the
 * revision. A claim that already linearized is never relabeled or undone. If
 * repeated conflicts prevent either conclusion, callers MUST fail closed and
 * retry from a fresh authoritative snapshot.
 */
async function applyTrustProgramRevocationInternal(input) {
    if (!exactKeys(input, APPLY_INPUT_KEYS))
        return applyRefusal('closed_apply_input_required');
    const expectedRevision = dataValue(input, 'expectedRevision');
    const kernel = dataValue(input, 'kernel');
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) {
        return applyRefusal('expected_revision_invalid');
    }
    if (!isDataRecord(kernel) || typeof kernel.status !== 'function'
        || typeof kernel.invalidate !== 'function') {
        return applyRefusal('trust_program_kernel_invalid');
    }
    const verification = verifyTrustProgramRevocation({
        authorizationBinding: dataValue(input, 'authorizationBinding'),
        programVersion: dataValue(input, 'programVersion'),
        receiptContext: dataValue(input, 'receiptContext'),
        statement: dataValue(input, 'statement'),
        revokerKeys: dataValue(input, 'revokerKeys'),
        now: dataValue(input, 'now'),
    });
    if (!verification.valid)
        return applyRefusal('revocation_verification_failed', verification);
    const binding = snapshotAuthorizationBinding(dataValue(input, 'authorizationBinding'));
    const statement = dataValue(input, 'statement');
    const signedReason = dataValue(statement, 'reason');
    const reason = typeof signedReason === 'string' && signedReason.length > 0
        && signedReason.length <= 256 && !/[\u0000-\u001f\u007f]/.test(signedReason)
        ? signedReason
        : 'verified EP-REVOCATION-v1 statement';
    const loadCurrentState = async () => {
        try {
            const observed = await kernel.status(binding.instance_id);
            if (!isDataRecord(observed) || observed.ok !== true || !isDataRecord(observed.state)
                || !Number.isSafeInteger(observed.state.revision)
                || !isDataRecord(observed.state.execution)
                || typeof observed.state.execution.status !== 'string') {
                return { ok: false, reason: 'kernel_status_invalid', state: null };
            }
            return { ok: true, state: observed.state };
        }
        catch {
            return { ok: false, reason: 'kernel_status_unavailable', state: null };
        }
    };
    let loaded = await loadCurrentState();
    if (!loaded.ok)
        return indeterminateDisposition(loaded.reason, verification, loaded.state);
    let currentState = loaded.state;
    const initiallyStale = currentState.revision !== expectedRevision;
    for (let attempt = 0; attempt < MAX_INVALIDATION_ATTEMPTS; attempt += 1) {
        const executionStatus = currentState.execution.status;
        if (currentState.status === 'invalidated') {
            if (executionStatus !== 'invalidated') {
                return lateDisposition('claim_already_linearized', verification, currentState);
            }
            return {
                verified: true,
                applied: false,
                blocks_claim: true,
                claim_permitted: false,
                future_authority_only: false,
                retry_required: false,
                must_fail_closed: false,
                disposition: 'already_invalidated',
                reason: 'program_instance_invalidated',
                verification,
                state: currentState,
            };
        }
        if (CLAIMED_OR_TERMINAL_EXECUTION_STATUSES.has(executionStatus)) {
            return lateDisposition(initiallyStale ? 'stale_expected_revision_claim_already_linearized'
                : 'claim_already_linearized', verification, currentState);
        }
        if (currentState.status !== 'active'
            || !UNCLAIMED_EXECUTION_STATUSES.has(executionStatus)) {
            return indeterminateDisposition('kernel_execution_state_indeterminate', verification, currentState);
        }
        let invalidated;
        try {
            // The only mutating call in this adapter. It occurs only after the actual
            // portable verifier accepted the independently derived target.
            invalidated = await kernel.invalidate({
                instanceId: binding.instance_id,
                expectedRevision: currentState.revision,
                reason,
            });
        }
        catch {
            return indeterminateDisposition('kernel_invalidation_unavailable', verification, currentState);
        }
        if (!isDataRecord(invalidated) || typeof invalidated.ok !== 'boolean') {
            return indeterminateDisposition('kernel_invalidation_result_invalid', verification, currentState);
        }
        if (invalidated.ok === true) {
            if (!isDataRecord(invalidated.state) || invalidated.state.status !== 'invalidated'
                || !isDataRecord(invalidated.state.execution)
                || typeof invalidated.state.execution.status !== 'string') {
                return indeterminateDisposition('kernel_invalidation_state_invalid', verification, currentState);
            }
            if (invalidated.state.execution.status !== 'invalidated') {
                return lateDisposition('claim_already_linearized', verification, invalidated.state, true);
            }
            return {
                verified: true,
                applied: true,
                blocks_claim: true,
                claim_permitted: false,
                future_authority_only: false,
                retry_required: false,
                must_fail_closed: false,
                disposition: 'invalidated_before_claim',
                reason: 'revocation_linearized_before_claim',
                verification,
                state: invalidated.state,
            };
        }
        if (invalidated.reason !== 'revision_conflict') {
            return indeterminateDisposition(typeof invalidated.reason === 'string'
                ? invalidated.reason : 'kernel_invalidation_failed', verification, currentState);
        }
        loaded = await loadCurrentState();
        if (!loaded.ok)
            return indeterminateDisposition(loaded.reason, verification, loaded.state);
        currentState = loaded.state;
    }
    const finalExecutionStatus = currentState.execution.status;
    if (currentState.status === 'invalidated' && finalExecutionStatus === 'invalidated') {
        return {
            verified: true,
            applied: false,
            blocks_claim: true,
            claim_permitted: false,
            future_authority_only: false,
            retry_required: false,
            must_fail_closed: false,
            disposition: 'already_invalidated',
            reason: 'program_instance_invalidated',
            verification,
            state: currentState,
        };
    }
    if (CLAIMED_OR_TERMINAL_EXECUTION_STATUSES.has(finalExecutionStatus)) {
        return lateDisposition('revision_conflict_claim_already_linearized', verification, currentState);
    }
    return indeterminateDisposition('invalidation_conflict_retry_exhausted', verification, currentState);
}
export async function applyTrustProgramRevocation(input) {
    try {
        return await applyTrustProgramRevocationInternal(input);
    }
    catch {
        return applyRefusal('malformed_apply_input_refused_fail_closed');
    }
}
export default {
    TRUST_PROGRAM_REVOCATION_TARGET_VERSION,
    deriveTrustProgramRevocationTargetObject,
    deriveTrustProgramRevocationTarget,
    verifyTrustProgramRevocation,
    applyTrustProgramRevocation,
};
//# sourceMappingURL=trust-program-revocation.js.map