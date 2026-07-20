// SPDX-License-Identifier: Apache-2.0
/**
 * EP-OUTCOME-ATTESTATION-v1 + EP-OUTCOME-BINDING-v1.
 *
 * The executor signs observations only. Human-approved predictions are read
 * from the cryptographically verified Trust Receipt action. Relying-party
 * policy may add constraints; it can never replace or loosen signed intent.
 */
import crypto from 'node:crypto';
import { DIVERGENCE_OUTCOMES, MAX_EFFECT_STRING_LENGTH, MAX_OBSERVED_EFFECTS, evaluatePredictedEffects, predictedEffectsDigest, validatePredictedEffects, } from './effect-predicates.js';
export const OUTCOME_ATTESTATION_VERSION = 'EP-OUTCOME-ATTESTATION-v1';
export const OUTCOME_ATTESTATION_DOMAIN = 'EP-OUTCOME-ATTESTATION-v1\0';
export const OUTCOME_BINDING_VERSION = 'EP-OUTCOME-BINDING-v1';
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const KEY_ID_RE = /^ep:executor-key:sha256:[0-9a-f]{64}$/;
const RFC3339_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const TOP_KEYS = new Set([
    '@version', 'receipt_id', 'receipt_digest', 'action_hash', 'consumption_nonce', 'execution_id',
    'executor_id', 'executed_at', 'observed_effects', 'observed_effects_digest', 'proof',
]);
const PROOF_KEYS = new Set(['algorithm', 'key_id', 'public_key', 'signature_b64u']);
const OBSERVED_KEYS = new Set(['effect_type', 'target', 'value', 'values']);
function canonicalize(value) {
    if (value === null || typeof value !== 'object')
        return JSON.stringify(value);
    if (Array.isArray(value))
        return `[${value.map(canonicalize).join(',')}]`;
    const objectValue = value;
    return `{${Object.keys(objectValue).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(objectValue[key])}`).join(',')}}`;
}
const sha256hex = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const digest = (value) => `sha256:${sha256hex(Buffer.from(canonicalize(value), 'utf8'))}`;
const safeDigest = (value) => {
    try {
        return digest(value);
    }
    catch {
        return null;
    }
};
const normalizeDigest = (value) => (typeof value === 'string' && /^sha256:[0-9a-f]{64}$/i.test(value)
    ? value.toLowerCase() : null);
function exactKeys(value, allowed) {
    return Boolean(value && typeof value === 'object' && !Array.isArray(value)
        && Object.keys(value).every((key) => allowed.has(key)));
}
function strictInstantMs(value) {
    if (typeof value !== 'string')
        return NaN;
    const match = value.match(RFC3339_INSTANT);
    if (!match)
        return NaN;
    const [, y, mo, d, h, mi, s, , oh, om] = match;
    const calendar = new Date(0);
    calendar.setUTCFullYear(Number(y), Number(mo) - 1, Number(d));
    calendar.setUTCHours(Number(h), Number(mi), Number(s), 0);
    if (calendar.toISOString().slice(0, 19) !== `${y}-${mo}-${d}T${h}:${mi}:${s}`)
        return NaN;
    if (oh !== undefined && (Number(oh) > 23 || Number(om) > 59))
        return NaN;
    return Date.parse(value);
}
function publicKeyB64u(key) {
    return crypto.createPublicKey(key).export({ type: 'spki', format: 'der' }).toString('base64url');
}
function executorKeyId(publicKey) {
    return `ep:executor-key:sha256:${sha256hex(Buffer.from(publicKey, 'base64url'))}`;
}
function unsigned(attestation) {
    const { proof: _proof, ...body } = attestation;
    return body;
}
function signingBytes(attestation) {
    return Buffer.from(`${OUTCOME_ATTESTATION_DOMAIN}${canonicalize(unsigned(attestation))}`, 'utf8');
}
/** Digest over the exact observed_effects array carried by the attestation. */
export function observedEffectsDigest(observedEffects) {
    return digest(observedEffects);
}
/** Digest of the exact Trust Receipt object the attestation references. */
export function trustReceiptDigest(receipt) {
    return digest(receipt);
}
function validateObservedEffects(observed) {
    const errors = [];
    if (!Array.isArray(observed))
        return { ok: false, errors: ['observed_effects must be an array'] };
    if (observed.length > MAX_OBSERVED_EFFECTS) {
        return { ok: false, errors: [`observed_effects exceeds the ${MAX_OBSERVED_EFFECTS}-entry limit`] };
    }
    observed.forEach((entry, index) => {
        const at = `observed_effects[${index}]`;
        if (!exactKeys(entry, OBSERVED_KEYS)) {
            errors.push(`${at} is not an exact observed-effect object`);
            return;
        }
        if (typeof entry.effect_type !== 'string' || !entry.effect_type
            || [...entry.effect_type].length > MAX_EFFECT_STRING_LENGTH) {
            errors.push(`${at}.effect_type is invalid`);
        }
        if (typeof entry.target !== 'string' || !entry.target
            || [...entry.target].length > MAX_EFFECT_STRING_LENGTH || entry.target.includes('*')) {
            errors.push(`${at}.target must be a bounded literal identifier`);
        }
        const hasValue = Object.hasOwn(entry, 'value');
        const hasValues = Object.hasOwn(entry, 'values');
        if (hasValue === hasValues)
            errors.push(`${at} must carry exactly one of value or values`);
        if (hasValue && (typeof entry.value !== 'string'
            || [...entry.value].length > MAX_EFFECT_STRING_LENGTH)) {
            errors.push(`${at}.value must be a bounded string`);
        }
        if (hasValues && (!Array.isArray(entry.values)
            || entry.values.length > MAX_OBSERVED_EFFECTS
            || !entry.values.every((v) => typeof v === 'string'
                && [...v].length <= MAX_EFFECT_STRING_LENGTH))) {
            errors.push(`${at}.values must be a bounded array of bounded strings`);
        }
    });
    return { ok: errors.length === 0, errors };
}
/**
 * Build an executor-signed observed-effects attestation.
 *
 * @param {{
 *   receipt_id?: string,
 *   receipt_digest?: string,
 *   action_hash?: string,
 *   consumption_nonce?: string,
 *   execution_id?: string,
 *   executor_id?: string,
 *   executed_at?: string,
 *   observed_effects?: Array<object>,
 *   signer?: {
 *     privateKey?: import('node:crypto').KeyObject,
 *     publicKey?: string,
 *     key_id?: string
 *   }
 * }} [args]
 */
export function buildOutcomeAttestation({ receipt_id, receipt_digest, action_hash, consumption_nonce, execution_id, executor_id, executed_at, observed_effects, signer, } = {}) {
    const observedValidation = validateObservedEffects(observed_effects);
    if (!observedValidation.ok)
        throw new Error(observedValidation.errors.join('; '));
    if (typeof receipt_id !== 'string' || !receipt_id)
        throw new Error('receipt_id is required');
    if (!normalizeDigest(receipt_digest))
        throw new Error('receipt_digest must be sha256:<64-hex>');
    if (!normalizeDigest(action_hash))
        throw new Error('action_hash must be sha256:<64-hex>');
    if (typeof consumption_nonce !== 'string' || !consumption_nonce)
        throw new Error('consumption_nonce is required');
    if (typeof execution_id !== 'string' || !execution_id)
        throw new Error('execution_id is required');
    if (typeof executor_id !== 'string' || !executor_id)
        throw new Error('executor_id is required');
    if (!Number.isFinite(strictInstantMs(executed_at)))
        throw new Error('executed_at must be a strict RFC 3339 instant');
    if (!signer?.privateKey)
        throw new Error('signer.privateKey is required');
    const publicKey = signer.publicKey || publicKeyB64u(signer.privateKey);
    const keyId = executorKeyId(publicKey);
    if (signer.key_id !== undefined && signer.key_id !== keyId) {
        throw new Error('signer.key_id does not match signer public key');
    }
    const body = {
        '@version': OUTCOME_ATTESTATION_VERSION,
        receipt_id,
        receipt_digest: normalizeDigest(receipt_digest),
        action_hash: normalizeDigest(action_hash),
        consumption_nonce,
        execution_id,
        executor_id,
        executed_at,
        observed_effects,
        observed_effects_digest: observedEffectsDigest(observed_effects),
    };
    return {
        ...body,
        proof: {
            algorithm: 'Ed25519',
            key_id: keyId,
            public_key: publicKey,
            signature_b64u: crypto.sign(null, signingBytes(body), signer.privateKey).toString('base64url'),
        },
    };
}
/**
 * Verify the executor attestation under a relying-party-pinned executor key.
 *
 * @param {object} attestation
 * @param {{
 *   executorKeys?: Record<string, {public_key?: string, key_id?: string}>,
 *   now?: string
 * }} [opts]
 */
export function verifyOutcomeAttestation(attestation, opts = {}) {
    opts = opts && typeof opts === 'object' ? opts : {};
    const executorKeys = opts.executorKeys && typeof opts.executorKeys === 'object'
        ? opts.executorKeys
        : {};
    const { now } = opts;
    const checks = {
        structure: false,
        observation_digest: false,
        executor_key_pinned: false,
        signature: false,
        execution_time: false,
    };
    const errors = [];
    const out = () => ({ valid: Object.values(checks).every(Boolean), checks, errors });
    if (!exactKeys(attestation, TOP_KEYS)
        || attestation?.['@version'] !== OUTCOME_ATTESTATION_VERSION
        || typeof attestation.receipt_id !== 'string' || !attestation.receipt_id
        || !normalizeDigest(attestation.receipt_digest)
        || !normalizeDigest(attestation.action_hash)
        || typeof attestation.consumption_nonce !== 'string' || !attestation.consumption_nonce
        || typeof attestation.execution_id !== 'string' || !attestation.execution_id
        || typeof attestation.executor_id !== 'string' || !attestation.executor_id
        || !DIGEST_RE.test(attestation.observed_effects_digest || '')
        || !exactKeys(attestation.proof, PROOF_KEYS)
        || attestation.proof.algorithm !== 'Ed25519'
        || !KEY_ID_RE.test(attestation.proof.key_id || '')
        || typeof attestation.proof.public_key !== 'string'
        || typeof attestation.proof.signature_b64u !== 'string') {
        errors.push('malformed_outcome_attestation');
        return out();
    }
    const observedValidation = validateObservedEffects(attestation.observed_effects);
    if (!observedValidation.ok) {
        errors.push(...observedValidation.errors);
        return out();
    }
    checks.structure = true;
    checks.observation_digest = observedEffectsDigest(attestation.observed_effects)
        === attestation.observed_effects_digest;
    if (!checks.observation_digest)
        errors.push('observed_effects_digest_mismatch');
    const derivedKeyId = executorKeyId(attestation.proof.public_key);
    const pin = executorKeys[attestation.executor_id];
    checks.executor_key_pinned = derivedKeyId === attestation.proof.key_id
        && pin?.public_key === attestation.proof.public_key
        && (pin.key_id === undefined || pin.key_id === derivedKeyId);
    if (!checks.executor_key_pinned)
        errors.push('executor_key_not_pinned');
    if (checks.executor_key_pinned) {
        try {
            const key = crypto.createPublicKey({
                key: Buffer.from(/** @type {string} */ (pin.public_key), 'base64url'), format: 'der', type: 'spki',
            });
            checks.signature = key.asymmetricKeyType === 'ed25519'
                && crypto.verify(null, signingBytes(attestation), key, Buffer.from(attestation.proof.signature_b64u, 'base64url'));
        }
        catch {
            checks.signature = false;
        }
    }
    if (!checks.signature)
        errors.push('executor_signature_invalid');
    const executedAt = strictInstantMs(attestation.executed_at);
    const nowMs = now === undefined ? Date.now() : strictInstantMs(now);
    checks.execution_time = Number.isFinite(executedAt)
        && Number.isFinite(nowMs)
        && executedAt <= nowMs;
    if (!checks.execution_time)
        errors.push('execution_time_invalid_or_future');
    return out();
}
function combineEvaluations(signed, policy) {
    const evaluations = [
        { source: 'signed_receipt', ...signed },
        ...(policy ? [{ source: 'relying_party_policy', ...policy }] : []),
    ];
    const outcome = evaluations.some((item) => item.outcome === 'divergent') ? 'divergent'
        : evaluations.some((item) => item.outcome === 'incomparable') ? 'incomparable'
            : 'in_bounds';
    return {
        '@version': OUTCOME_BINDING_VERSION,
        outcome,
        evaluations,
        reasons: evaluations.flatMap((item) => item.reasons.map((reason) => `${item.source}: ${reason}`)),
    };
}
/**
 * Core composition. `verifyReceipt` must perform the full Trust Receipt
 * cryptographic verification; the main package export injects
 * verifyTrustReceipt. This shape keeps the module independently testable.
 */
export function verifyOutcomeBindingCore(receipt, attestation, opts = {}, verifyReceipt) {
    opts = opts && typeof opts === 'object' ? opts : {};
    const checks = {
        receipt_verified: false,
        signed_predictions: false,
        receipt_bound: false,
        receipt_digest_bound: false,
        action_bound: false,
        consumption_bound: false,
        attestation_verified: false,
    };
    const errors = [];
    let receiptResult = null;
    let attestationResult = null;
    const exactCommitments = () => ({
        receipt_id: typeof receipt?.receipt_id === 'string' ? receipt.receipt_id : null,
        attested_receipt_id: typeof attestation?.receipt_id === 'string'
            ? attestation.receipt_id : null,
        receipt_digest: safeDigest(receipt),
        attested_receipt_digest: normalizeDigest(attestation?.receipt_digest),
        action_hash: normalizeDigest(receipt?.action_hash),
        attested_action_hash: normalizeDigest(attestation?.action_hash),
        consumption_nonce: typeof receipt?.consumption?.nonce === 'string'
            ? receipt.consumption.nonce : null,
        attested_consumption_nonce: typeof attestation?.consumption_nonce === 'string'
            ? attestation.consumption_nonce : null,
        execution_id: typeof attestation?.execution_id === 'string' ? attestation.execution_id : null,
        executor_id: typeof attestation?.executor_id === 'string' ? attestation.executor_id : null,
        executor_key_id: typeof attestation?.proof?.key_id === 'string'
            ? attestation.proof.key_id : null,
        observed_effects_digest: normalizeDigest(attestation?.observed_effects_digest),
    });
    const inputCommitments = () => ({
        receipt_digest: safeDigest(receipt),
        attestation_digest: safeDigest(attestation),
        policy_predictions_present: Object.hasOwn(opts, 'policyPredictedEffects'),
        policy_predictions_digest: Object.hasOwn(opts, 'policyPredictedEffects')
            ? safeDigest(opts.policyPredictedEffects)
            : null,
    });
    const refuse = (reason) => {
        errors.push(reason);
        const outcome_binding = {
            '@version': OUTCOME_BINDING_VERSION,
            outcome: 'incomparable',
            evaluations: [],
            reasons: [...errors],
        };
        const result = {
            valid: false,
            checks,
            errors,
            receipt,
            attestation,
            commitments: exactCommitments(),
            receipt_result: receiptResult,
            attestation_result: attestationResult,
            outcome_binding,
        };
        return {
            ...result,
            result_digest: digest({
                input_commitments: inputCommitments(),
                exact_commitments: result.commitments,
                valid: result.valid,
                verdict: outcome_binding.outcome,
                checks,
                errors,
                outcome_binding,
            }),
        };
    };
    if (typeof verifyReceipt !== 'function')
        return refuse('receipt_verifier_required');
    try {
        receiptResult = verifyReceipt(receipt, opts.receiptOptions || {});
    }
    catch {
        return refuse('receipt_verifier_failed');
    }
    checks.receipt_verified = receiptResult?.valid === true;
    if (!checks.receipt_verified)
        return refuse('receipt_verification_failed');
    const signedPredictions = receipt?.action?.predicted_effects;
    const boundPredictionDigest = receipt?.action?.predicted_effects_digest;
    const predictionValidation = validatePredictedEffects(signedPredictions);
    checks.signed_predictions = predictionValidation.ok
        && normalizeDigest(boundPredictionDigest) === normalizeDigest(predictedEffectsDigest(signedPredictions));
    if (!checks.signed_predictions)
        return refuse('signed_predictions_missing_or_mismatched');
    if (Object.hasOwn(opts, 'policyPredictedEffects')
        && !Array.isArray(opts.policyPredictedEffects)) {
        return refuse('policy_predictions_present_but_not_array');
    }
    if (Array.isArray(opts.policyPredictedEffects)) {
        const policyValidation = validatePredictedEffects(opts.policyPredictedEffects);
        if (!policyValidation.ok) {
            errors.push(...policyValidation.reasons.map((reason) => `relying_party_policy: ${reason}`));
            return refuse('policy_predictions_malformed');
        }
    }
    attestationResult = verifyOutcomeAttestation(attestation, {
        executorKeys: opts.executorKeys || {},
        now: opts.now,
    });
    checks.attestation_verified = attestationResult.valid;
    if (!checks.attestation_verified) {
        errors.push(...attestationResult.errors);
        return refuse('outcome_attestation_verification_failed');
    }
    checks.receipt_bound = attestation.receipt_id === receipt.receipt_id;
    checks.receipt_digest_bound = normalizeDigest(attestation.receipt_digest)
        === normalizeDigest(trustReceiptDigest(receipt));
    checks.action_bound = normalizeDigest(attestation.action_hash) === normalizeDigest(receipt.action_hash);
    checks.consumption_bound = typeof receipt?.consumption?.nonce === 'string'
        && attestation.consumption_nonce === receipt.consumption.nonce;
    if (!checks.receipt_bound)
        errors.push('receipt_id_mismatch');
    if (!checks.receipt_digest_bound)
        errors.push('receipt_digest_mismatch');
    if (!checks.action_bound)
        errors.push('action_hash_mismatch');
    if (!checks.consumption_bound)
        errors.push('consumption_nonce_mismatch');
    if (!checks.receipt_bound || !checks.receipt_digest_bound
        || !checks.action_bound || !checks.consumption_bound) {
        return refuse('attestation_not_bound_to_verified_receipt');
    }
    const signedEvaluation = evaluatePredictedEffects(signedPredictions, attestation.observed_effects);
    const policyEvaluation = Array.isArray(opts.policyPredictedEffects)
        ? evaluatePredictedEffects(opts.policyPredictedEffects, attestation.observed_effects)
        : null;
    const outcome_binding = combineEvaluations(signedEvaluation, policyEvaluation);
    const valid = Object.values(checks).every(Boolean)
        && outcome_binding.outcome === 'in_bounds';
    const result = {
        valid,
        checks,
        errors: [...errors, ...outcome_binding.reasons],
        receipt,
        attestation,
        commitments: exactCommitments(),
        receipt_result: receiptResult,
        attestation_result: attestationResult,
        outcome_binding,
    };
    return {
        ...result,
        result_digest: digest({
            input_commitments: {
                ...inputCommitments(),
                signed_predictions_digest: predictedEffectsDigest(signedPredictions),
            },
            exact_commitments: result.commitments,
            valid: result.valid,
            verdict: outcome_binding.outcome,
            checks,
            errors: result.errors,
            outcome_binding,
        }),
    };
}
export const OUTCOME_BINDING_OUTCOMES = DIVERGENCE_OUTCOMES;
//# sourceMappingURL=outcome-binding.js.map