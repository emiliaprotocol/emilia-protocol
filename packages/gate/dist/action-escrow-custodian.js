// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Typed bridge between the Action Escrow kernel and an authenticated external
 * custodian adapter. Provider observations are signed by the deployment
 * operator because TLS API responses are not portable offline evidence.
 */
import crypto from 'node:crypto';
import { canonicalize, hashCanonical } from '../execution-binding.js';
import { ACTION_ESCROW_CONTRACTOR_TEMPLATE_VERSION, validateActionEscrowReleaseTemplate, } from '../action-escrow-verifiers.js';
export const ACTION_ESCROW_CUSTODIAN_OBSERVATION_VERSION = 'EP-ACTION-ESCROW-CUSTODIAN-OBSERVATION-v1';
const DOMAIN = `${ACTION_ESCROW_CUSTODIAN_OBSERVATION_VERSION}\0`;
const HASH = /^sha256:[0-9a-f]{64}$/;
function isRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function canonicalCopy(value) {
    return JSON.parse(canonicalize(value));
}
function canonicalDigest(value) {
    return `sha256:${hashCanonical(value)}`;
}
function validString(value, max = 512) {
    return typeof value === 'string'
        && value.length > 0
        && value.length <= max
        && !/[\u0000-\u001f\u007f]/.test(value);
}
function strictInstant(value) {
    if (typeof value !== 'string')
        return false;
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}
function deepFreeze(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value))
        return value;
    Object.freeze(value);
    for (const child of Object.values(value))
        deepFreeze(child);
    return value;
}
function signingBytes(payload) {
    return Buffer.concat([
        Buffer.from(DOMAIN, 'utf8'),
        Buffer.from(canonicalize(payload), 'utf8'),
    ]);
}
function requestScope(request) {
    const { request_digest: _digest, ...scope } = request;
    // The digest identifies the reserved mutation. GET is only a reconciliation
    // transport for that same POST and must not create a second request identity.
    return { ...scope, method: 'POST' };
}
function normalizeKernelRequest(value, adapter) {
    try {
        if (!isRecord(value)
            || (value.method !== 'POST' && value.method !== 'GET')
            || value.provider_id !== adapter.provider
            || value.profile?.provider_id !== adapter.provider
            || !HASH.test(value.agreement_digest)
            || !HASH.test(value.document_action_binding_digest)
            || !HASH.test(value.release_action_digest)
            || !HASH.test(value.parties_digest)
            || !HASH.test(value.profile_digest)
            || !HASH.test(value.document_digest)
            || !HASH.test(value.request_digest)
            || !validString(value.milestone_id, 256)
            || !validString(value.idempotency_key, 256)
            || !isRecord(value.release_action_template)) {
            return null;
        }
        const template = validateActionEscrowReleaseTemplate(value.release_action_template, {
            profileDigest: value.profile_digest,
            agreementId: value.agreement_id,
            agreementDigest: value.agreement_digest,
            milestoneId: value.milestone_id,
            documentDigest: value.document_digest,
            contractorProjectSource: value.release_action_template.action_escrow_template_profile
                === ACTION_ESCROW_CONTRACTOR_TEMPLATE_VERSION,
        });
        if (!template
            || template.custodian_provider !== adapter.provider
            || template.custodian_environment !== adapter.environment
            || canonicalDigest({
                '@version': 'EP-ACTION-ESCROW-PROVIDER-REQUEST-v1',
                ...requestScope(value),
            }) !== value.request_digest) {
            return null;
        }
        return canonicalCopy(value);
    }
    catch {
        return null;
    }
}
function transactionMatches(transaction, request) {
    if (!isRecord(transaction)
        || transaction.transaction_id
            !== request.release_action_template.custodian_transaction_id
        || transaction.currency !== request.release_action_template.currency
        || !Array.isArray(transaction.milestones)) {
        return false;
    }
    const milestone = transaction.milestones.find((entry) => entry.provider_item_id
        === request.release_action_template.custodian_milestone_id);
    if (!milestone || !Array.isArray(milestone.schedules) || milestone.schedules.length !== 1) {
        return false;
    }
    const schedule = milestone.schedules[0];
    return schedule.amount === request.release_action_template.amount
        && schedule.beneficiary_customer === request.release_action_template.destination_id;
}
function providerResultMatches(result, request, adapter, operation) {
    return isRecord(result)
        && result.provider === adapter.provider
        && result.environment === adapter.environment
        && result.operation === operation
        && result.transaction_id
            === request.release_action_template.custodian_transaction_id
        && (operation === 'reconcile_transaction'
            || (result.milestone_id
                === request.release_action_template.custodian_milestone_id
                && result.effect_reference === request.idempotency_key));
}
function transactionFromResult(result) {
    return isRecord(result?.transaction) ? result.transaction : null;
}
function observationStatus(result) {
    if (result.kind === 'released')
        return 'released';
    if (result.kind !== 'provider_action_required')
        return null;
    if (result.provider_phase === 'not_accepted')
        return 'not_released';
    if (result.provider_phase === 'accepted_pending_disbursement')
        return 'pending';
    return null;
}
function normalizePrivateKey(value) {
    const key = value instanceof crypto.KeyObject ? value : crypto.createPrivateKey(value);
    if (key.asymmetricKeyType !== 'ed25519') {
        throw new TypeError('custodian observation signer must use Ed25519');
    }
    return key;
}
/**
 * The bridge implements the kernel's release/getRelease contract. It never
 * claims that EMILIA holds funds or that the external provider is licensed.
 */
export function createActionEscrowCustodianBridge({ adapter, observationSigner, now = () => new Date().toISOString(), } = {}) {
    if (!isRecord(adapter)
        || adapter.kind !== 'external_custodian'
        || !validString(adapter.provider, 128)
        || !['sandbox', 'production'].includes(adapter.environment)
        || typeof adapter.reconcileTransaction !== 'function'
        || typeof adapter.releaseMilestone !== 'function'
        || typeof adapter.requestMilestoneDisbursement !== 'function'
        || !isRecord(observationSigner)
        || !validString(observationSigner.key_id, 256)
        || typeof now !== 'function') {
        throw new TypeError('external custodian adapter and observation signer are required');
    }
    const privateKey = normalizePrivateKey(observationSigner.privateKey);
    async function preflight(request) {
        // adapter is validated above; the guard's narrowing does not carry into
        // this hoisted function declaration's closure.
        const reconciled = await adapter.reconcileTransaction({
            transactionId: request.release_action_template.custodian_transaction_id,
        });
        if (!providerResultMatches(reconciled, request, adapter, 'reconcile_transaction')
            || reconciled.kind !== 'reconciled'
            || !transactionMatches(reconciled.transaction, request)) {
            throw new Error('custodian transaction does not match the signed release action');
        }
        return reconciled.transaction;
    }
    // observationSigner is validated above; the guard's narrowing does not
    // carry into this hoisted function declaration's closure.
    function signObservation(request, status, result) {
        const observedAt = now();
        if (!strictInstant(observedAt))
            throw new Error('invalid custodian observation clock');
        const transaction = transactionFromResult(result);
        const payload = {
            '@version': ACTION_ESCROW_CUSTODIAN_OBSERVATION_VERSION,
            provider_id: result.provider,
            environment: result.environment,
            statement_type: 'release',
            status,
            agreement_digest: request.agreement_digest,
            document_action_binding_digest: request.document_action_binding_digest,
            milestone_id: request.milestone_id,
            release_action_digest: request.release_action_digest,
            parties_digest: request.parties_digest,
            profile_digest: request.profile_digest,
            provider_idempotency_key: request.idempotency_key,
            provider_request_digest: request.request_digest,
            provider_effect_reference: result.effect_reference,
            provider_transaction_id: result.transaction_id,
            provider_milestone_id: result.milestone_id,
            amount: request.release_action_template.amount,
            currency: request.release_action_template.currency,
            destination_id: request.release_action_template.destination_id,
            provider_snapshot_digest: canonicalDigest(transaction),
            observed_at: observedAt,
        };
        const signature = crypto.sign(null, signingBytes(payload), privateKey);
        return deepFreeze({
            payload,
            signature: {
                algorithm: 'Ed25519',
                key_id: observationSigner.key_id,
                value: signature.toString('base64url'),
            },
        });
    }
    return Object.freeze({
        provider: adapter.provider,
        environment: adapter.environment,
        async release(untrustedRequest) {
            const request = normalizeKernelRequest(untrustedRequest, adapter);
            if (!request || request.method !== 'POST') {
                throw new Error('invalid kernel release request');
            }
            await preflight(request);
            const result = await adapter.releaseMilestone({
                effectReference: request.idempotency_key,
                transactionId: request.release_action_template.custodian_transaction_id,
                milestoneId: request.release_action_template.custodian_milestone_id,
            });
            if (!providerResultMatches(result, request, adapter, 'release_milestone')
                || !['released', 'release_submitted', 'provider_action_required'].includes(result.kind)
                || (['released', 'release_submitted'].includes(result.kind)
                    && !transactionMatches(transactionFromResult(result), request))) {
                throw new Error('custodian release outcome is not authoritative');
            }
            return { accepted: true };
        },
        async getRelease(untrustedRequest) {
            const request = normalizeKernelRequest(untrustedRequest, adapter);
            if (!request || request.method !== 'GET') {
                throw new Error('invalid kernel reconciliation request');
            }
            await preflight(request);
            const result = await adapter.requestMilestoneDisbursement({
                effectReference: request.idempotency_key,
                transactionId: request.release_action_template.custodian_transaction_id,
                milestoneId: request.release_action_template.custodian_milestone_id,
            });
            const status = observationStatus(result);
            const transaction = transactionFromResult(result);
            if (!providerResultMatches(result, request, adapter, 'request_milestone_disbursement')
                || !status
                || !transaction
                || !transactionMatches(transaction, request)) {
                throw new Error('custodian release state is indeterminate');
            }
            return {
                authenticated: true,
                statement: signObservation(request, status, result),
            };
        },
    });
}
export function createActionEscrowCustodianStatementVerifier({ operatorKeys, providerId, environment, } = {}) {
    if (!isRecord(operatorKeys)
        || !validString(providerId, 128)
        || !(environment === 'sandbox' || environment === 'production')) {
        throw new TypeError('pinned operator keys and provider identity are required');
    }
    const pins = canonicalCopy(operatorKeys);
    return async function verifyStatement(statement, expected) {
        try {
            if (!isRecord(statement)
                || !isRecord(statement.payload)
                || !isRecord(statement.signature)
                || statement.signature.algorithm !== 'Ed25519'
                || !validString(statement.signature.key_id, 256)
                || !validString(statement.signature.value, 1024)) {
                return { valid: false, reason: 'malformed_custodian_observation' };
            }
            const pin = pins[statement.signature.key_id];
            if (!isRecord(pin) || typeof pin.public_key !== 'string') {
                return { valid: false, reason: 'custodian_operator_key_not_pinned' };
            }
            const publicKey = crypto.createPublicKey({
                key: Buffer.from(pin.public_key, 'base64url'),
                type: 'spki',
                format: 'der',
            });
            if (publicKey.asymmetricKeyType !== 'ed25519'
                || !crypto.verify(null, signingBytes(statement.payload), publicKey, Buffer.from(statement.signature.value, 'base64url'))) {
                return { valid: false, reason: 'custodian_observation_signature_invalid' };
            }
            const payload = statement.payload;
            const exact = payload['@version'] === ACTION_ESCROW_CUSTODIAN_OBSERVATION_VERSION
                && payload.provider_id === providerId
                && payload.environment === environment
                && payload.statement_type === expected.statement_type
                && payload.agreement_digest === expected.agreement_digest
                && payload.document_action_binding_digest
                    === expected.document_action_binding_digest
                && payload.milestone_id === expected.milestone_id
                && payload.release_action_digest === expected.release_action_digest
                && payload.parties_digest === expected.parties_digest
                && payload.profile_digest === expected.profile_digest
                && payload.provider_idempotency_key === expected.provider_idempotency_key
                && payload.provider_request_digest === expected.provider_request_digest
                && payload.provider_effect_reference === expected.provider_idempotency_key
                && payload.provider_transaction_id === expected.provider_transaction_id
                && payload.provider_milestone_id === expected.provider_milestone_id
                && payload.amount === expected.amount
                && payload.currency === expected.currency
                && payload.destination_id === expected.destination_id
                && ['released', 'not_released', 'pending'].includes(payload.status)
                && HASH.test(payload.provider_snapshot_digest)
                && strictInstant(payload.observed_at);
            if (!exact)
                return { valid: false, reason: 'custodian_observation_binding_mismatch' };
            return {
                valid: true,
                authenticated: true,
                statement_type: payload.statement_type,
                status: payload.status,
                statement_digest: canonicalDigest(statement),
                provider_id: payload.provider_id,
                agreement_digest: payload.agreement_digest,
                document_action_binding_digest: payload.document_action_binding_digest,
                milestone_id: payload.milestone_id,
                release_action_digest: payload.release_action_digest,
                parties_digest: payload.parties_digest,
                profile_digest: payload.profile_digest,
                provider_idempotency_key: payload.provider_idempotency_key,
                provider_request_digest: payload.provider_request_digest,
                provider_transaction_id: payload.provider_transaction_id,
                provider_milestone_id: payload.provider_milestone_id,
                amount: payload.amount,
                currency: payload.currency,
                destination_id: payload.destination_id,
            };
        }
        catch {
            return { valid: false, reason: 'malformed_custodian_observation' };
        }
    };
}
export default Object.freeze({
    ACTION_ESCROW_CUSTODIAN_OBSERVATION_VERSION,
    createActionEscrowCustodianBridge,
    createActionEscrowCustodianStatementVerifier,
});
//# sourceMappingURL=action-escrow-custodian.js.map