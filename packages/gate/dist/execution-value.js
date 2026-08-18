// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { canonicalize, hashCanonical } from './execution-binding.js';
import { signAgileSet, verifyAgileSignatureSet, } from '@emilia-protocol/verify/pq-signature-agility';
export const EXECUTION_VALUE_ATTESTATION_VERSION = 'EP-EXECUTION-VALUE-ATTESTATION-v1';
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const CURRENCY = /^[A-Z][A-Z0-9]{2,11}$/;
const KEY_ID = /^[A-Za-z0-9._:-]{1,128}$/;
function actionDigest(action) {
    return `sha256:${hashCanonical(action)}`;
}
function exactKeys(value, expected) {
    const keys = Object.keys(value).sort();
    return keys.length === expected.length
        && keys.every((key, index) => key === [...expected].sort()[index]);
}
function validIso(value) {
    if (typeof value !== 'string')
        return null;
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : null;
}
/** Mint a role-specific value observation; the issuer key never rides in it. */
export function signExecutionValueAttestation(input, privateKey) {
    const payload = {
        version: EXECUTION_VALUE_ATTESTATION_VERSION,
        ...input,
    };
    // Verification below is the single validation source. Signing malformed
    // evidence would create an artifact that no conforming verifier accepts.
    const preflight = validatePayload(payload);
    if (!preflight.ok)
        throw new TypeError(preflight.reason);
    const value = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey).toString('base64url');
    return Object.freeze({
        payload: Object.freeze(structuredClone(payload)),
        signature: Object.freeze({ algorithm: 'Ed25519', value }),
    });
}
function validatePayload(payload, version = EXECUTION_VALUE_ATTESTATION_VERSION) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)
        || !exactKeys(payload, [
            'version', 'action_digest', 'asset_currency', 'quote_currency',
            'value_minor', 'source', 'key_id', 'observed_at', 'expires_at',
        ]))
        return { ok: false, reason: 'execution_value_payload_malformed' };
    if (payload.version !== version)
        return { ok: false, reason: 'execution_value_version_unsupported' };
    if (!DIGEST.test(payload.action_digest))
        return { ok: false, reason: 'execution_value_action_digest_invalid' };
    if (!CURRENCY.test(payload.asset_currency) || payload.quote_currency !== 'USD')
        return { ok: false, reason: 'execution_value_currency_invalid' };
    if (!Number.isSafeInteger(payload.value_minor) || payload.value_minor < 0)
        return { ok: false, reason: 'execution_value_amount_invalid' };
    if (typeof payload.source !== 'string' || payload.source.length === 0 || payload.source.length > 256)
        return { ok: false, reason: 'execution_value_source_invalid' };
    if (!KEY_ID.test(payload.key_id))
        return { ok: false, reason: 'execution_value_key_id_invalid' };
    const observed = validIso(payload.observed_at);
    const expires = validIso(payload.expires_at);
    if (observed === null || expires === null || expires <= observed)
        return { ok: false, reason: 'execution_value_window_invalid' };
    return { ok: true };
}
export function verifyExecutionValueAttestation(attestation, { action, trustedKeys, allowedSources, maxValueMinor, maxAgeMs = 15_000, now = Date.now, }) {
    if (!attestation || typeof attestation !== 'object' || Array.isArray(attestation)) {
        return { ok: false, reason: 'execution_value_attestation_required' };
    }
    let normalized;
    try {
        normalized = JSON.parse(canonicalize(attestation));
    }
    catch {
        return { ok: false, reason: 'execution_value_attestation_malformed' };
    }
    if (!exactKeys(normalized, ['payload', 'signature']))
        return { ok: false, reason: 'execution_value_attestation_malformed' };
    const payload = normalized.payload;
    const payloadCheck = validatePayload(payload);
    if (!payloadCheck.ok)
        return payloadCheck;
    if (!normalized.signature || !exactKeys(normalized.signature, ['algorithm', 'value'])
        || normalized.signature.algorithm !== 'Ed25519'
        || typeof normalized.signature.value !== 'string') {
        return { ok: false, reason: 'execution_value_signature_malformed' };
    }
    if (!trustedKeys || typeof trustedKeys !== 'object')
        return { ok: false, reason: 'execution_value_key_unpinned' };
    const key = trustedKeys[payload.key_id];
    if (typeof key !== 'string' || key.length === 0)
        return { ok: false, reason: 'execution_value_key_unpinned' };
    if (!Array.isArray(allowedSources) || !allowedSources.includes(payload.source)) {
        return { ok: false, reason: 'execution_value_source_untrusted' };
    }
    let signatureOk = false;
    try {
        const publicKey = crypto.createPublicKey({
            key: Buffer.from(key, 'base64url'),
            type: 'spki',
            format: 'der',
        });
        signatureOk = crypto.verify(null, Buffer.from(canonicalize(payload), 'utf8'), publicKey, Buffer.from(normalized.signature.value, 'base64url'));
    }
    catch {
        signatureOk = false;
    }
    if (!signatureOk)
        return { ok: false, reason: 'execution_value_signature_invalid' };
    if (payload.action_digest !== actionDigest(action))
        return { ok: false, reason: 'execution_value_action_mismatch' };
    if (typeof action.currency === 'string' && payload.asset_currency !== action.currency.toUpperCase()) {
        return { ok: false, reason: 'execution_value_asset_mismatch' };
    }
    const at = typeof now === 'function' ? now() : now;
    const observed = Date.parse(payload.observed_at);
    const expires = Date.parse(payload.expires_at);
    if (!Number.isFinite(at) || Number(at) < observed - 1_000 || Number(at) > expires
        || Number(at) - observed > maxAgeMs)
        return { ok: false, reason: 'execution_value_stale' };
    if (!Number.isSafeInteger(maxValueMinor) || maxValueMinor < 0)
        return { ok: false, reason: 'execution_value_policy_invalid' };
    if (payload.value_minor > maxValueMinor)
        return { ok: false, reason: 'execution_value_limit_exceeded' };
    return { ok: true, reason: 'execution_value_verified', payload: Object.freeze(payload) };
}
// ===========================================================================
// EP-EXECUTION-VALUE-ATTESTATION-v2 -- the hybrid (Ed25519 + ML-DSA-65) value attestation
// ===========================================================================
// REFERENCE-PATTERN MIGRATION, following the five moves in "PATTERN: the
// reference hybrid migration" (EP-REVOCATION-v2 is the template) in
// docs/protocol/pq-hybrid-program.md:
//   1. VERSION BUMP, NOT A FIELD BUMP. signExecutionValueAttestation /
//      verifyExecutionValueAttestation above are UNCHANGED; v2 is a new
//      `version` marker, never an optional second signature bolted onto v1.
//   2. SET SHAPE. `proof.signatures` is an EP-SIG-AGILITY-v1 AgileSignature
//      array ({ alg, sig, key_id? }), reused verbatim from
//      packages/verify/src/pq-signature-agility.ts.
//   3. ANTI-STRIPPING BYTES. `required_algorithms` and the v2 version marker
//      are INSIDE the signed bytes (executionValueV2SigningBytes); the
//      verifier rebuilds them from the REGISTERED set and the PRESENTED
//      payload, never from what the proof claims.
//   4. V1 COMPATIBILITY. v1 stays synchronous and untouched; v2 is a
//      SEPARATE async entry point (ML-DSA verification is async).
//   5. NAMED REFUSALS. Nothing throws on caller input; an absent ML-DSA
//      backend is a refusal, never a skipped check and never a pass on the
//      surviving classical leg.
export const EXECUTION_VALUE_ATTESTATION_V2_VERSION = 'EP-EXECUTION-VALUE-ATTESTATION-v2';
export const EXECUTION_VALUE_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65']);
function algorithmSetMatchesRegisteredV2(algorithms) {
    return Array.isArray(algorithms)
        && algorithms.length === EXECUTION_VALUE_V2_REQUIRED_ALGORITHMS.length
        && algorithms.every((a, i) => a === EXECUTION_VALUE_V2_REQUIRED_ALGORITHMS[i]);
}
/**
 * Bytes BOTH legs sign: the v2 payload plus the committed required-algorithm
 * set. canonicalize() sorts keys, so field order is irrelevant. The verifier
 * rebuilds this from the PRESENTED payload and the REGISTERED set; the
 * presented proof never gets to choose what it is checked against.
 */
function executionValueV2SigningBytes(payload, requiredAlgorithms = EXECUTION_VALUE_V2_REQUIRED_ALGORITHMS) {
    if (!algorithmSetMatchesRegisteredV2(requiredAlgorithms)) {
        throw new Error('executionValueV2SigningBytes: algorithm set is not the registered EP-EXECUTION-VALUE-ATTESTATION-v2 set');
    }
    return Buffer.from(canonicalize({
        required_algorithms: [...requiredAlgorithms],
        payload,
    }), 'utf8');
}
/** Mint a hybrid (Ed25519 + ML-DSA-65) role-specific value observation. */
export async function signExecutionValueAttestationV2(input, keys, options = {}) {
    const payload = {
        version: EXECUTION_VALUE_ATTESTATION_V2_VERSION,
        ...input,
    };
    const preflight = validatePayload(payload, EXECUTION_VALUE_ATTESTATION_V2_VERSION);
    if (!preflight.ok)
        throw new TypeError(preflight.reason);
    const privateKeyObject = keys.privateKey instanceof crypto.KeyObject
        ? keys.privateKey : crypto.createPrivateKey(keys.privateKey);
    const bytes = executionValueV2SigningBytes(payload);
    const signatures = await signAgileSet(new Uint8Array(bytes), [
        { alg: 'Ed25519', private_key: privateKeyObject, key_id: payload.key_id },
        { alg: 'ML-DSA-65', private_key: keys.pqPrivateKey, key_id: payload.key_id },
    ], options);
    return Object.freeze({
        payload: Object.freeze(structuredClone(payload)),
        proof: Object.freeze({
            required_algorithms: [...EXECUTION_VALUE_V2_REQUIRED_ALGORITHMS],
            signatures,
        }),
    });
}
/**
 * FAIL-CLOSED hybrid verify. A v2 attestation NEVER verifies on one leg
 * alone; an absent ML-DSA backend is a refusal, never a skipped check and
 * never a pass on the surviving classical leg.
 */
export async function verifyExecutionValueAttestationV2(attestation, { action, trustedKeys, allowedSources, maxValueMinor, maxAgeMs = 15_000, now = Date.now, ...agilityOptions }) {
    if (!attestation || typeof attestation !== 'object' || Array.isArray(attestation)) {
        return { ok: false, reason: 'execution_value_attestation_required' };
    }
    let normalized;
    try {
        normalized = JSON.parse(canonicalize(attestation));
    }
    catch {
        return { ok: false, reason: 'execution_value_attestation_malformed' };
    }
    if (!exactKeys(normalized, ['payload', 'proof']))
        return { ok: false, reason: 'execution_value_attestation_malformed' };
    const payload = normalized.payload;
    const payloadCheck = validatePayload(payload, EXECUTION_VALUE_ATTESTATION_V2_VERSION);
    if (!payloadCheck.ok)
        return payloadCheck;
    const proof = normalized.proof;
    if (!proof || typeof proof !== 'object' || Array.isArray(proof)
        || !exactKeys(proof, ['required_algorithms', 'signatures'])
        || !algorithmSetMatchesRegisteredV2(proof.required_algorithms)
        || !Array.isArray(proof.signatures)) {
        return { ok: false, reason: 'execution_value_proof_malformed' };
    }
    const presented = new Set();
    for (const sig of proof.signatures) {
        if (!sig || typeof sig !== 'object' || typeof sig.alg !== 'string') {
            return { ok: false, reason: 'execution_value_proof_malformed' };
        }
        if (presented.has(sig.alg))
            return { ok: false, reason: 'execution_value_proof_duplicate_algorithm' };
        presented.add(sig.alg);
    }
    for (const alg of EXECUTION_VALUE_V2_REQUIRED_ALGORITHMS) {
        if (!presented.has(alg))
            return { ok: false, reason: `execution_value_proof_missing_${alg}` };
    }
    for (const alg of presented) {
        if (!EXECUTION_VALUE_V2_REQUIRED_ALGORITHMS.includes(alg)) {
            return { ok: false, reason: 'execution_value_proof_unexpected_algorithm' };
        }
    }
    if (!trustedKeys || typeof trustedKeys !== 'object')
        return { ok: false, reason: 'execution_value_key_unpinned' };
    const pin = trustedKeys[payload.key_id];
    if (!pin || typeof pin.public_key !== 'string' || pin.public_key.length === 0
        || typeof pin.pq_public_key !== 'string' || pin.pq_public_key.length === 0) {
        return { ok: false, reason: 'execution_value_key_unpinned' };
    }
    if (!Array.isArray(allowedSources) || !allowedSources.includes(payload.source)) {
        return { ok: false, reason: 'execution_value_source_untrusted' };
    }
    let bytes;
    try {
        bytes = executionValueV2SigningBytes(payload);
    }
    catch {
        return { ok: false, reason: 'execution_value_payload_not_canonical' };
    }
    let setResult;
    try {
        setResult = await verifyAgileSignatureSet(new Uint8Array(bytes), proof.signatures, [
            { alg: 'Ed25519', public_key: pin.public_key },
            { alg: 'ML-DSA-65', public_key: pin.pq_public_key },
        ], { ...agilityOptions, policy: 'hybrid_all', requiredAlgorithms: [...EXECUTION_VALUE_V2_REQUIRED_ALGORITHMS] });
    }
    catch {
        setResult = null;
    }
    if (setResult?.verified !== true) {
        const reason = String(setResult?.reason ?? 'signature_set_unverified');
        return {
            ok: false,
            reason: reason.includes('pq_backend_unavailable')
                ? 'execution_value_pq_backend_unavailable'
                : 'execution_value_signature_invalid',
        };
    }
    if (payload.action_digest !== actionDigest(action))
        return { ok: false, reason: 'execution_value_action_mismatch' };
    if (typeof action.currency === 'string' && payload.asset_currency !== action.currency.toUpperCase()) {
        return { ok: false, reason: 'execution_value_asset_mismatch' };
    }
    const at = typeof now === 'function' ? now() : now;
    const observed = Date.parse(payload.observed_at);
    const expires = Date.parse(payload.expires_at);
    if (!Number.isFinite(at) || Number(at) < observed - 1_000 || Number(at) > expires
        || Number(at) - observed > maxAgeMs)
        return { ok: false, reason: 'execution_value_stale' };
    if (!Number.isSafeInteger(maxValueMinor) || maxValueMinor < 0)
        return { ok: false, reason: 'execution_value_policy_invalid' };
    if (payload.value_minor > maxValueMinor)
        return { ok: false, reason: 'execution_value_limit_exceeded' };
    return { ok: true, reason: 'execution_value_verified', payload: Object.freeze(payload) };
}
function directUsdMinor(action) {
    if (Number.isSafeInteger(action.amount_minor) && action.amount_minor >= 0)
        return action.amount_minor;
    if (Number.isSafeInteger(action.amount) && action.amount >= 0
        && action.amount <= Math.floor(Number.MAX_SAFE_INTEGER / 100))
        return action.amount * 100;
    return null;
}
/**
 * Create the runtime value guard. USD actions are checked directly from the
 * exact observed action; every non-USD action requires a fresh signed oracle
 * observation bound to that action digest. Oracle outage fails closed.
 */
export function createExecutionValueProviderEntryGuard({ maxValueMinor, trustedKeys, allowedSources, resolveAttestation, maxAgeMs = 15_000, now = Date.now, }) {
    if (!Number.isSafeInteger(maxValueMinor) || maxValueMinor < 0)
        throw new TypeError('maxValueMinor must be a non-negative safe integer');
    if (typeof resolveAttestation !== 'function')
        throw new TypeError('resolveAttestation must be a function');
    return async (context) => {
        const action = context.observed_action;
        if (!action)
            return { ok: false, reason: 'execution_value_action_required', status: 409 };
        const currency = typeof action.currency === 'string' ? action.currency.toUpperCase() : null;
        if (!currency || !CURRENCY.test(currency))
            return { ok: false, reason: 'execution_value_currency_required', status: 409 };
        if (currency === 'USD') {
            const valueMinor = directUsdMinor(action);
            if (valueMinor === null)
                return { ok: false, reason: 'execution_value_amount_required', status: 409 };
            if (valueMinor > maxValueMinor)
                return { ok: false, reason: 'execution_value_limit_exceeded', status: 409 };
            return {
                ok: true,
                evidence: {
                    version: EXECUTION_VALUE_ATTESTATION_VERSION,
                    kind: 'direct_base_currency_value',
                    action_digest: actionDigest(action),
                    value_minor: valueMinor,
                    quote_currency: 'USD',
                },
            };
        }
        let attestation;
        try {
            attestation = await resolveAttestation(context);
        }
        catch {
            return { ok: false, reason: 'execution_value_oracle_unavailable', status: 503 };
        }
        const verified = verifyExecutionValueAttestation(attestation, {
            action: action, trustedKeys, allowedSources, maxValueMinor, maxAgeMs, now,
        });
        return verified.ok
            ? { ok: true, evidence: { kind: 'signed_execution_value', ...verified.payload } }
            : { ok: false, reason: verified.reason, status: verified.reason.includes('unavailable') ? 503 : 409 };
    };
}
export default {
    EXECUTION_VALUE_ATTESTATION_VERSION,
    signExecutionValueAttestation,
    verifyExecutionValueAttestation,
    createExecutionValueProviderEntryGuard,
    EXECUTION_VALUE_ATTESTATION_V2_VERSION,
    signExecutionValueAttestationV2,
    verifyExecutionValueAttestationV2,
};
//# sourceMappingURL=execution-value.js.map