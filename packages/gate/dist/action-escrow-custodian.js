// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Typed bridge between the Action Escrow kernel and an authenticated external
 * custodian adapter. Provider observations are signed by the deployment
 * operator because TLS API responses are not portable offline evidence.
 */
import crypto from 'node:crypto';
import { canonicalize, hashCanonical } from './execution-binding.js';
import { ACTION_ESCROW_CONTRACTOR_TEMPLATE_VERSION, validateActionEscrowReleaseTemplate, } from './action-escrow-verifiers.js';
import { signAgileSet, verifyAgileSignatureSet, } from '@emilia-protocol/verify/pq-signature-agility';
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
        // `validateActionEscrowReleaseTemplate` (action-escrow-verifiers.ts,
        // outside this file's scope) still infers its options parameter type
        // from only the one destructured property that carries a default value,
        // so a fresh object literal here trips the excess-property check.
        // Routing through a locally typed variable avoids that without changing
        // what gets passed at runtime.
        const releaseTemplateOptions = {
            profileDigest: value.profile_digest,
            agreementId: value.agreement_id,
            agreementDigest: value.agreement_digest,
            milestoneId: value.milestone_id,
            documentDigest: value.document_digest,
            contractorProjectSource: value.release_action_template.action_escrow_template_profile
                === ACTION_ESCROW_CONTRACTOR_TEMPLATE_VERSION,
        };
        const template = validateActionEscrowReleaseTemplate(value.release_action_template, releaseTemplateOptions);
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
// ===========================================================================
// EP-ACTION-ESCROW-CUSTODIAN-OBSERVATION-v2 -- hybrid (Ed25519 + ML-DSA-65)
// ===========================================================================
/**
 * REFERENCE-DERIVED HYBRID MIGRATION. Copies, move for move, the reference
 * hybrid migration documented in docs/protocol/pq-hybrid-program.md, section
 * "PATTERN: the reference hybrid migration" (EP-REVOCATION-v2 in
 * packages/verify/src/revocation.ts). The five moves, applied to the
 * custodian observation:
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of
 *    the proof, a wire-format change, so the observation payload takes a new
 *    `@version` (EP-ACTION-ESCROW-CUSTODIAN-OBSERVATION-v1 -> -v2).
 *    createActionEscrowCustodianStatementVerifier() above is untouched: its
 *    returned verifyStatement() requires
 *    `payload['@version'] === ACTION_ESCROW_CUSTODIAN_OBSERVATION_VERSION`
 *    (v1) as part of the `exact` boolean, so a v2 payload refuses on
 *    `custodian_observation_binding_mismatch` before any signature math, and
 *    never throws.
 * 2. SET SHAPE. The single `signature` object is replaced by `proof`,
 *    carrying `required_algorithms` plus a `signatures` array shaped exactly
 *    like EP-SIG-AGILITY-v1's AgileSignature ({ alg, sig, key_id? }).
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is committed INSIDE the
 *    signed bytes (custodianObservationV2Bytes below). Drop the ML-DSA leg
 *    and narrow `required_algorithms` and the surviving Ed25519 signature no
 *    longer verifies, because the bytes changed.
 * 4. V1 COMPATIBILITY. v1 statements (minted by the bridge factory above)
 *    keep verifying, unchanged, through createActionEscrowCustodianStatementVerifier.
 *    v2 verification is ASYNC (ML-DSA verification is async), so it is a
 *    SEPARATE, standalone function rather than a change to the bridge's
 *    internal signing closure. The v1 path is never made async.
 * 5. NAMED REFUSALS. Every failure path returns a named reason; nothing
 *    throws on caller input. An absent ML-DSA backend is
 *    'pq_backend_unavailable', never a skipped check and never a pass on the
 *    classical leg alone.
 *
 * SCOPE BOUNDARY (honest, not a hedge): this migration is a standalone pure
 * builder/signer/verifier pair over the SAME observation payload shape the
 * bridge's internal signObservation() closure builds; it deliberately does
 * not thread a hybrid signer into createActionEscrowCustodianBridge's
 * closures, so the deployed bridge factory keeps minting v1 (Ed25519-only)
 * observations exactly as before. A relying party that wants hybrid
 * custodian observations builds the same fields the bridge already computes
 * (see signObservation above for the source shape) and calls
 * signActionEscrowCustodianObservationV2 directly.
 *
 * HONEST BOUNDARIES carry over from v1: this authenticates an OPERATOR
 * statement about one external-custodian snapshot; it does not prove the
 * custodian holds funds or that EMILIA is a licensed money transmitter. The
 * ML-DSA backend is @noble/post-quantum's pure-JS FIPS 204 implementation,
 * not independently audited and not a FIPS validated module. v2 does NOT
 * retroactively protect statements already issued under v1.
 */
export const ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_VERSION = 'EP-ACTION-ESCROW-CUSTODIAN-OBSERVATION-v2';
const DOMAIN_V2 = `${ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_VERSION}\0`;
/** The registered required algorithm set, in canonical order. */
export const ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65']);
const OBSERVATION_V2_PAYLOAD_KEYS = new Set([
    '@version', 'provider_id', 'environment', 'statement_type', 'status',
    'agreement_digest', 'document_action_binding_digest', 'milestone_id',
    'release_action_digest', 'parties_digest', 'profile_digest',
    'provider_idempotency_key', 'provider_request_digest', 'provider_effect_reference',
    'provider_transaction_id', 'provider_milestone_id', 'amount', 'currency',
    'destination_id', 'provider_snapshot_digest', 'observed_at',
]);
function observationV2AlgorithmSetRegistered(algorithms) {
    return Array.isArray(algorithms)
        && algorithms.length === ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_REQUIRED_ALGORITHMS.length
        && algorithms.every((a, i) => a === ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_REQUIRED_ALGORITHMS[i]);
}
function validateObservationV2Payload(payload) {
    return isRecord(payload)
        && Object.keys(payload).length === OBSERVATION_V2_PAYLOAD_KEYS.size
        && Object.keys(payload).every((key) => OBSERVATION_V2_PAYLOAD_KEYS.has(key))
        && payload['@version'] === ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_VERSION
        && validString(payload.provider_id, 128)
        && (payload.environment === 'sandbox' || payload.environment === 'production')
        && payload.statement_type === 'release'
        && ['released', 'not_released', 'pending'].includes(payload.status)
        && HASH.test(payload.agreement_digest)
        && HASH.test(payload.document_action_binding_digest)
        && validString(payload.milestone_id, 256)
        && HASH.test(payload.release_action_digest)
        && HASH.test(payload.parties_digest)
        && HASH.test(payload.profile_digest)
        && validString(payload.provider_idempotency_key, 256)
        && HASH.test(payload.provider_request_digest)
        && validString(payload.provider_effect_reference, 512)
        && validString(payload.provider_transaction_id, 512)
        && validString(payload.provider_milestone_id, 512)
        && HASH.test(payload.provider_snapshot_digest)
        && strictInstant(payload.observed_at);
}
/**
 * The bytes BOTH legs sign: the SAME canonicalized payload the v1 statement
 * signs, plus the committed `required_algorithms` set, under the v2 domain
 * tag. Recomputed independently by the verifier from the PRESENTED payload
 * and the REGISTERED set.
 */
export function custodianObservationV2Bytes(payload, requiredAlgorithms = ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_REQUIRED_ALGORITHMS) {
    if (!observationV2AlgorithmSetRegistered(requiredAlgorithms)) {
        throw new TypeError('custodianObservationV2Bytes: algorithm set is not the registered EP-ACTION-ESCROW-CUSTODIAN-OBSERVATION-v2 set');
    }
    return Buffer.from(`${DOMAIN_V2}${canonicalize({ ...payload, required_algorithms: [...requiredAlgorithms] })}`, 'utf8');
}
/**
 * Mint a real hybrid custodian observation over caller-supplied fields (the
 * SAME field set signObservation() above computes from the kernel request and
 * provider result). Throws on issuer misuse; there is no caller input to
 * fail-close over on the signing side.
 */
export async function signActionEscrowCustodianObservationV2(fields, signers, options = {}) {
    const payload = { '@version': ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_VERSION, ...fields };
    if (!validateObservationV2Payload(payload)) {
        throw new TypeError('invalid EP-ACTION-ESCROW-CUSTODIAN-OBSERVATION-v2 payload');
    }
    const bytes = custodianObservationV2Bytes(payload, ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_REQUIRED_ALGORITHMS);
    const signatures = await signAgileSet(new Uint8Array(bytes), signers, options);
    return deepFreeze({
        payload,
        proof: {
            profile: ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_VERSION,
            required_algorithms: [...ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_REQUIRED_ALGORITHMS],
            key_id: signers.find((s) => typeof s.key_id === 'string')?.key_id ?? null,
            signatures,
        },
    });
}
/**
 * FAIL-CLOSED hybrid verifier for one EP-ACTION-ESCROW-CUSTODIAN-OBSERVATION-v2
 * statement. Never throws on caller input; a v2 statement NEVER verifies on
 * one leg alone. `operatorKeys` is keyed by `proof.key_id`, and BOTH halves
 * (`public_key`, `pq_public_key`) must be pinned there for that key id.
 */
export async function verifyActionEscrowCustodianStatementV2(statement, { operatorKeys, providerId, environment, expected, mldsaBackend, mldsaBackendLoader, } = {}) {
    try {
        if (!isRecord(operatorKeys) || !validString(providerId, 128)
            || !(environment === 'sandbox' || environment === 'production') || !isRecord(expected)) {
            return { valid: false, reason: 'verifier_configuration_invalid' };
        }
        if (!isRecord(statement) || !isRecord(statement.payload) || !isRecord(statement.proof)) {
            return { valid: false, reason: 'malformed_custodian_observation' };
        }
        const { payload, proof } = statement;
        if (!validateObservationV2Payload(payload))
            return { valid: false, reason: 'malformed_custodian_observation' };
        if (!exactObservationV2ProofKeys(proof) || proof.profile !== ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_VERSION
            || !validString(proof.key_id, 256)) {
            return { valid: false, reason: 'malformed_custodian_observation' };
        }
        if (!observationV2AlgorithmSetRegistered(proof.required_algorithms)) {
            return { valid: false, reason: 'custodian_algorithm_set_invalid' };
        }
        const signatures = Array.isArray(proof.signatures) ? proof.signatures : null;
        if (!signatures || signatures.length === 0)
            return { valid: false, reason: 'custodian_signature_legs_missing' };
        const presented = new Set();
        for (const s of signatures) {
            if (!isRecord(s) || typeof s.alg !== 'string' || typeof s.sig !== 'string') {
                return { valid: false, reason: 'custodian_signature_leg_malformed' };
            }
            if (presented.has(s.alg))
                return { valid: false, reason: 'custodian_signature_leg_duplicate' };
            presented.add(s.alg);
        }
        for (const alg of presented) {
            if (!ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_REQUIRED_ALGORITHMS.includes(alg)) {
                return { valid: false, reason: 'custodian_signature_leg_unexpected' };
            }
        }
        for (const alg of ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_REQUIRED_ALGORITHMS) {
            if (!presented.has(alg))
                return { valid: false, reason: 'custodian_signature_leg_stripped' };
        }
        const pin = operatorKeys[proof.key_id];
        if (!isRecord(pin) || typeof pin.public_key !== 'string' || typeof pin.pq_public_key !== 'string'
            || pin.public_key.length === 0 || pin.pq_public_key.length === 0) {
            return { valid: false, reason: 'custodian_operator_key_not_pinned' };
        }
        const bytes = custodianObservationV2Bytes(payload, ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_REQUIRED_ALGORITHMS);
        let setResult = null;
        try {
            setResult = await verifyAgileSignatureSet(new Uint8Array(bytes), signatures, [
                { alg: 'Ed25519', public_key: pin.public_key },
                { alg: 'ML-DSA-65', public_key: pin.pq_public_key },
            ], {
                mldsaBackend,
                mldsaBackendLoader,
                policy: 'hybrid_all',
                requiredAlgorithms: [...ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_REQUIRED_ALGORITHMS],
            });
        }
        catch {
            setResult = null;
        }
        if (setResult?.verified !== true) {
            const reason = String(setResult?.reason ?? 'signature_set_unverified');
            return { valid: false, reason: `custodian_observation_signature_invalid (${reason})` };
        }
        const exact = payload.provider_id === providerId
            && payload.environment === environment
            && payload.statement_type === expected.statement_type
            && payload.agreement_digest === expected.agreement_digest
            && payload.document_action_binding_digest === expected.document_action_binding_digest
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
            && payload.destination_id === expected.destination_id;
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
}
function exactObservationV2ProofKeys(proof) {
    const allowed = new Set(['profile', 'required_algorithms', 'key_id', 'signatures']);
    return isRecord(proof) && Object.keys(proof).length === allowed.size
        && Object.keys(proof).every((key) => allowed.has(key));
}
/**
 * Route a custodian statement of EITHER version. A v1 statement (flat
 * `signature`) is checked against the v1 verifier factory's returned
 * function; a v2 statement (`proof` with a `signatures` set) gets the hybrid
 * check.
 */
export async function verifyActionEscrowCustodianStatementAny(statement, options = {}) {
    if (isRecord(statement) && isRecord(statement.payload)
        && statement.payload['@version'] === ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_VERSION) {
        return verifyActionEscrowCustodianStatementV2(statement, options);
    }
    const { operatorKeys, providerId, environment } = options;
    const verifyV1 = createActionEscrowCustodianStatementVerifier({ operatorKeys, providerId, environment });
    return verifyV1(statement, options.expected);
}
export default Object.freeze({
    ACTION_ESCROW_CUSTODIAN_OBSERVATION_VERSION,
    ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_VERSION,
    ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_REQUIRED_ALGORITHMS,
    createActionEscrowCustodianBridge,
    createActionEscrowCustodianStatementVerifier,
    custodianObservationV2Bytes,
    signActionEscrowCustodianObservationV2,
    verifyActionEscrowCustodianStatementV2,
    verifyActionEscrowCustodianStatementAny,
});
//# sourceMappingURL=action-escrow-custodian.js.map