// SPDX-License-Identifier: Apache-2.0
/**
 * EP-AUTHORIZATION-BUNDLE-v1 pre-execution verifier.
 *
 * This verifies portable human-approval evidence. It deliberately does not
 * issue an authorization decision, reserve capacity, consume a grant, or
 * assert execution. Native OAuth/WIMSE/RAR verification stays outside this
 * module and is supplied as an independently derived expected binding.
 */
import crypto from 'node:crypto';
import { canonicalizeAeb, digestAeb } from './aeb-adapter-contract.js';
export const AUTHORIZATION_BUNDLE_VERSION = 'EP-AUTHORIZATION-BUNDLE-v1';
export const OAUTH_RAR_AUTHORIZATION_BINDING_VERSION = 'EP-OAUTH-RAR-AUTHORIZATION-BINDING-v1';
const BUNDLE_KEYS = new Set([
    'bundle_version', 'bundle_id', 'action', 'action_hash', 'contexts', 'signoffs',
    'approver_key_proofs', 'presentation_evidence',
]);
const OAUTH_BINDING_REQUIRED_KEYS = new Set([
    'profile', 'authorization_server', 'transaction_id', 'actor',
    'authorization_details_digest', 'action_mapping_profile',
]);
const OAUTH_BINDING_KEYS = new Set([...OAUTH_BINDING_REQUIRED_KEYS, 'delegated_subject']);
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
function isRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function exactKeys(value, expected) {
    const keys = Object.keys(value);
    return keys.length === expected.size && keys.every((key) => expected.has(key));
}
function nonEmptyString(value) {
    return typeof value === 'string' && value.length > 0 && !/[\u0000-\u001f\u007f]/.test(value);
}
function absoluteUri(value) {
    if (!nonEmptyString(value))
        return false;
    try {
        return new URL(value).protocol.length > 1;
    }
    catch {
        return false;
    }
}
function parseInstant(value) {
    if (value instanceof Date)
        return value.getTime();
    if (typeof value === 'number')
        return Number.isFinite(value) ? value : NaN;
    if (typeof value !== 'string'
        || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value))
        return NaN;
    const result = Date.parse(value);
    return Number.isFinite(result) ? result : NaN;
}
function canonicalDigest(value) {
    try {
        return digestAeb(value);
    }
    catch {
        return null;
    }
}
function equalCanonical(left, right) {
    try {
        return canonicalizeAeb(left) === canonicalizeAeb(right);
    }
    catch {
        return false;
    }
}
function canonicalB64url(value) {
    if (typeof value !== 'string')
        return false;
    const normalized = value.replace(/^b64u:/, '');
    if (!B64URL_RE.test(normalized) || normalized.length % 4 === 1)
        return false;
    try {
        const bytes = Buffer.from(normalized, 'base64url');
        return bytes.length > 0 && bytes.toString('base64url') === normalized;
    }
    catch {
        return false;
    }
}
function verifyEd25519(signature, digest, publicKey) {
    if (!canonicalB64url(signature) || !canonicalB64url(publicKey))
        return false;
    try {
        const keyBytes = Buffer.from(String(publicKey).replace(/^b64u:/, ''), 'base64url');
        const key = crypto.createPublicKey({ key: keyBytes, type: 'spki', format: 'der' });
        if (key.asymmetricKeyType !== 'ed25519')
            return false;
        const digestBytes = Buffer.from(digest.slice('sha256:'.length), 'hex');
        return crypto.verify(null, digestBytes, key, Buffer.from(String(signature).replace(/^b64u:/, ''), 'base64url'));
    }
    catch {
        return false;
    }
}
function validOAuthBinding(value) {
    if (!isRecord(value)
        || !Object.keys(value).every((key) => OAUTH_BINDING_KEYS.has(key))
        || ![...OAUTH_BINDING_REQUIRED_KEYS].every((key) => Object.hasOwn(value, key))
        || value.profile !== OAUTH_RAR_AUTHORIZATION_BINDING_VERSION
        || !absoluteUri(value.authorization_server)
        || !nonEmptyString(value.transaction_id)
        || !nonEmptyString(value.actor)
        || !absoluteUri(value.action_mapping_profile)
        || typeof value.authorization_details_digest !== 'string'
        || !DIGEST_RE.test(value.authorization_details_digest))
        return false;
    return value.delegated_subject === undefined || nonEmptyString(value.delegated_subject);
}
function baseResult() {
    return {
        verdict: 'REFUSE',
        evidence_satisfied: false,
        authorization_decision: false,
        bundle_digest: null,
        checks: {
            closed_shape: false,
            action: false,
            contexts: false,
            signatures: false,
            approver_selection: false,
            separation_of_duties: false,
            windows: false,
            audience: false,
            authorization_binding: false,
            key_proofs: false,
            presentation: false,
            current_status: false,
            current_policy: false,
        },
        reasons: [],
    };
}
/**
 * Verify an EP-AUTHORIZATION-BUNDLE-v1 as pre-execution evidence.
 * SATISFIED never means AUTHORIZED; the caller still needs a native grant or
 * PDP decision and executor-side atomic consumption.
 */
export function verifyAuthorizationBundle(bundle, options) {
    options = isRecord(options) ? options
        : {};
    const result = baseResult();
    const definite = [];
    const uncertain = [];
    const now = parseInstant(options?.now);
    if (!Number.isFinite(now))
        definite.push('verifier_time_invalid');
    if (!absoluteUri(options?.audience))
        definite.push('audience_pin_missing_or_invalid');
    const approverKeys = isRecord(options.approverKeys)
        ? options.approverKeys
        : {};
    if (Object.keys(approverKeys).length === 0)
        definite.push('approver_keys_missing');
    if (!isRecord(bundle) || !exactKeys(bundle, BUNDLE_KEYS)
        || bundle.bundle_version !== AUTHORIZATION_BUNDLE_VERSION
        || !nonEmptyString(bundle.bundle_id)
        || !isRecord(bundle.action)
        || typeof bundle.action_hash !== 'string' || !DIGEST_RE.test(bundle.action_hash)
        || !Array.isArray(bundle.contexts) || bundle.contexts.length === 0
        || !Array.isArray(bundle.signoffs) || bundle.signoffs.length === 0
        || !Array.isArray(bundle.approver_key_proofs)
        || !Array.isArray(bundle.presentation_evidence)) {
        definite.push('bundle_malformed');
        result.reasons = [...new Set(definite)].sort();
        return result;
    }
    result.checks.closed_shape = true;
    result.bundle_digest = canonicalDigest(bundle);
    if (result.bundle_digest === null) {
        definite.push('bundle_not_canonicalizable');
        result.reasons = [...new Set(definite)].sort();
        return result;
    }
    const actionDigest = canonicalDigest(bundle.action);
    const expectedActionDigest = canonicalDigest(options.expectedAction);
    if (actionDigest !== bundle.action_hash) {
        definite.push('action_hash_mismatch');
    }
    else if (expectedActionDigest === null) {
        uncertain.push('expected_action_unavailable');
    }
    else if (expectedActionDigest === actionDigest) {
        result.checks.action = true;
    }
    else {
        definite.push('action_mismatch');
    }
    const contexts = bundle.contexts.filter(isRecord);
    const signoffs = bundle.signoffs.filter(isRecord);
    if (contexts.length !== bundle.contexts.length || signoffs.length !== bundle.signoffs.length) {
        definite.push('context_or_signoff_malformed');
    }
    const contextByDigest = new Map();
    const policyHashes = new Set();
    const policyIds = new Set();
    const audiences = new Set();
    const bindingDigests = new Set();
    const approverIds = [];
    const approverIndexes = new Set();
    const nonces = new Set();
    const requiredApprovalCounts = new Set();
    let contextsOk = contexts.length === bundle.contexts.length;
    let windowsOk = Number.isFinite(now);
    let audiencesOk = true;
    let bindingsOk = true;
    for (const context of contexts) {
        const digest = canonicalDigest(context);
        if (digest === null) {
            contextsOk = false;
            definite.push('context_not_canonicalizable');
            continue;
        }
        contextByDigest.set(digest, context);
        if (context.action_hash !== bundle.action_hash
            || typeof context.policy_hash !== 'string' || !DIGEST_RE.test(context.policy_hash)
            || !nonEmptyString(context.policy_id)
            || !nonEmptyString(context.approver)
            || context.initiator !== bundle.action.initiator
            || !Number.isInteger(context.approver_index) || Number(context.approver_index) < 1
            || !Number.isInteger(context.required_approvals) || Number(context.required_approvals) < 1
            || !canonicalB64url(context.nonce)
            || Buffer.from(String(context.nonce).replace(/^b64u:/, ''), 'base64url').length < 16) {
            contextsOk = false;
            definite.push('context_commitment_mismatch');
        }
        if (nonEmptyString(context.policy_hash))
            policyHashes.add(context.policy_hash);
        if (nonEmptyString(context.policy_id))
            policyIds.add(context.policy_id);
        if (nonEmptyString(context.approver))
            approverIds.push(context.approver);
        if (Number.isInteger(context.approver_index))
            approverIndexes.add(Number(context.approver_index));
        if (nonEmptyString(context.nonce))
            nonces.add(context.nonce);
        if (Number.isInteger(context.required_approvals)) {
            requiredApprovalCounts.add(Number(context.required_approvals));
        }
        if (!absoluteUri(context.audience)) {
            audiencesOk = false;
            definite.push('context_audience_missing_or_invalid');
        }
        else {
            audiences.add(context.audience);
            if (context.audience !== options.audience) {
                audiencesOk = false;
                definite.push('context_audience_mismatch');
            }
        }
        const issued = parseInstant(context.issued_at);
        const expires = parseInstant(context.expires_at);
        if (!Number.isFinite(issued) || !Number.isFinite(expires)
            || issued > now || now > expires || issued >= expires) {
            windowsOk = false;
            definite.push('context_outside_validity_window');
        }
        if (context.authorization_binding !== undefined) {
            if (!validOAuthBinding(context.authorization_binding)) {
                bindingsOk = false;
                definite.push('authorization_binding_malformed');
            }
            else {
                const bindingDigest = canonicalDigest(context.authorization_binding);
                if (bindingDigest !== null)
                    bindingDigests.add(bindingDigest);
                if (options.expectedAuthorizationBinding === undefined
                    || !validOAuthBinding(options.expectedAuthorizationBinding)) {
                    bindingsOk = false;
                    uncertain.push('native_authorization_binding_unavailable');
                }
                else if (!equalCanonical(context.authorization_binding, options.expectedAuthorizationBinding)) {
                    bindingsOk = false;
                    definite.push('authorization_binding_mismatch');
                }
            }
        }
    }
    if (policyHashes.size !== 1 || policyIds.size !== 1 || audiences.size !== 1
        || bindingDigests.size > 1 || approverIndexes.size !== contexts.length
        || nonces.size !== contexts.length || requiredApprovalCounts.size !== 1) {
        contextsOk = false;
        definite.push('contexts_do_not_share_one_policy_audience_and_binding');
    }
    if (options.requireAuthorizationBinding === true && bindingDigests.size === 0) {
        bindingsOk = false;
        definite.push('authorization_binding_required');
    }
    result.checks.contexts = contextsOk;
    result.checks.windows = windowsOk;
    result.checks.audience = audiencesOk;
    result.checks.authorization_binding = bindingsOk;
    const rawExpectedApprovers = options.expectedApprovers;
    const expectedApprovers = Array.isArray(rawExpectedApprovers)
        ? rawExpectedApprovers.filter(nonEmptyString)
        : [];
    if (expectedApprovers.length === 0
        || expectedApprovers.length !== rawExpectedApprovers?.length) {
        uncertain.push('approver_selection_unavailable');
    }
    else {
        const expected = [...new Set(expectedApprovers)].sort();
        const presented = [...new Set(approverIds)].sort();
        if (expected.length !== expectedApprovers.length || !equalCanonical(expected, presented)) {
            definite.push('approver_selection_mismatch');
        }
        else {
            result.checks.approver_selection = true;
        }
    }
    const validApprovers = [];
    let signaturesOk = signoffs.length === bundle.signoffs.length;
    for (const signoff of signoffs) {
        const contextDigest = signoff.context_hash;
        if (typeof contextDigest !== 'string' || !DIGEST_RE.test(contextDigest)) {
            signaturesOk = false;
            definite.push('signoff_context_hash_invalid');
            continue;
        }
        const context = contextByDigest.get(contextDigest);
        const keyId = signoff.approver_key_id;
        const key = nonEmptyString(keyId) ? approverKeys[keyId] : undefined;
        if (!context || !key || key.approver_id !== context.approver
            || key.key_class !== signoff.key_class) {
            signaturesOk = false;
            definite.push('signoff_context_or_key_mismatch');
            continue;
        }
        const issued = parseInstant(context.issued_at);
        const keyFrom = parseInstant(key.valid_from);
        const keyTo = parseInstant(key.valid_to);
        const signedAt = parseInstant(signoff.signed_at);
        const acceptedKeyClasses = Array.isArray(options.acceptedKeyClasses)
            ? options.acceptedKeyClasses
            : [];
        if (!acceptedKeyClasses.includes(key.key_class)) {
            signaturesOk = false;
            definite.push('key_class_not_accepted');
            continue;
        }
        if (![issued, keyFrom, keyTo, signedAt].every(Number.isFinite)
            || issued < keyFrom || issued > keyTo || now < keyFrom || now > keyTo
            || signedAt < issued || signedAt > parseInstant(context.expires_at) || signedAt > now
            || (key.compromised_at !== undefined && key.compromised_at !== null)) {
            signaturesOk = false;
            definite.push('approver_key_not_current');
            continue;
        }
        let verified = false;
        if (key.key_class === 'A') {
            if (!options.verifyClassASignoff) {
                uncertain.push('class_a_verifier_unavailable');
            }
            else {
                try {
                    verified = options.verifyClassASignoff({
                        signoff,
                        context,
                        contextDigest: contextDigest,
                        key,
                    }) === true;
                }
                catch {
                    verified = false;
                }
            }
        }
        else {
            verified = verifyEd25519(signoff.signature, contextDigest, key.public_key);
        }
        if (!verified) {
            signaturesOk = false;
            if (key.key_class === 'A' && !options.verifyClassASignoff)
                continue;
            definite.push('signoff_signature_invalid');
            continue;
        }
        if (context.decision === 'denied') {
            definite.push('signed_denial_does_not_approve');
            continue;
        }
        if (context.decision !== undefined && context.decision !== 'approved') {
            definite.push('signed_decision_unknown');
            continue;
        }
        validApprovers.push(String(context.approver));
    }
    result.checks.signatures = signaturesOk;
    const initiator = bundle.action.initiator;
    const requiredValues = contexts.map((context) => context.required_approvals);
    const validRequired = requiredValues.every((value) => Number.isInteger(value) && Number(value) >= 1)
        && new Set(requiredValues).size === 1;
    const required = validRequired ? Number(requiredValues[0]) : Number.POSITIVE_INFINITY;
    const sod = validRequired
        && nonEmptyString(initiator)
        && !validApprovers.includes(initiator)
        && new Set(validApprovers).size === validApprovers.length
        && validApprovers.length >= required;
    result.checks.separation_of_duties = sod;
    if (!sod)
        definite.push('separation_of_duties_or_quorum_failed');
    if (bundle.approver_key_proofs.length === 0) {
        result.checks.key_proofs = Object.keys(approverKeys).length > 0;
        if (!result.checks.key_proofs)
            uncertain.push('approver_key_trust_unavailable');
    }
    else if (!options.verifyKeyProofs) {
        uncertain.push('directory_proof_verifier_unavailable');
    }
    else {
        try {
            result.checks.key_proofs = options.verifyKeyProofs(bundle.approver_key_proofs, approverKeys) === true;
        }
        catch {
            result.checks.key_proofs = false;
        }
        if (!result.checks.key_proofs)
            definite.push('directory_proof_invalid');
    }
    if (bundle.presentation_evidence.length === 0) {
        result.checks.presentation = options.requirePresentationEvidence !== true;
        if (!result.checks.presentation)
            definite.push('presentation_evidence_required');
    }
    else if (!options.verifyPresentationEvidence) {
        uncertain.push('presentation_verifier_unavailable');
    }
    else {
        try {
            result.checks.presentation = options.verifyPresentationEvidence(bundle.presentation_evidence, contexts) === true;
        }
        catch {
            result.checks.presentation = false;
        }
        if (!result.checks.presentation)
            definite.push('presentation_evidence_invalid');
    }
    if (options.requireCurrentStatus === true) {
        const status = options.currentStatus;
        const checked = parseInstant(status?.checked_at);
        const expires = parseInstant(status?.expires_at);
        if (!status || status.unavailable === true || !Number.isFinite(checked) || !Number.isFinite(expires)
            || checked > now || now >= expires) {
            uncertain.push('current_status_unavailable_or_stale');
        }
        else if (!Array.isArray(status.revoked_key_ids)) {
            uncertain.push('current_status_malformed');
        }
        else if (signoffs.some((signoff) => status.revoked_key_ids.includes(String(signoff.approver_key_id)))) {
            definite.push('approver_key_revoked');
        }
        else {
            result.checks.current_status = true;
        }
    }
    else {
        result.checks.current_status = true;
    }
    const policy = options.currentPolicy;
    const policyChecked = parseInstant(policy?.checked_at);
    const policyExpires = parseInstant(policy?.expires_at);
    if (!policy || policy.unavailable === true
        || typeof policy.policy_hash !== 'string' || !DIGEST_RE.test(policy.policy_hash)
        || !Number.isFinite(policyChecked) || !Number.isFinite(policyExpires)
        || policyChecked > now || now >= policyExpires) {
        uncertain.push('current_policy_unavailable_or_stale');
    }
    else if (policy.decision === 'REFUSE') {
        definite.push('current_policy_refused');
    }
    else if (policy.decision !== 'PERMIT' || policyHashes.size !== 1
        || !policyHashes.has(policy.policy_hash)) {
        definite.push('current_policy_mismatch');
    }
    else {
        result.checks.current_policy = true;
    }
    result.reasons = [...new Set([...definite, ...uncertain])].sort();
    if (definite.length > 0)
        return result;
    if (uncertain.length > 0 || Object.values(result.checks).some((value) => value !== true)) {
        result.verdict = 'INDETERMINATE';
        return result;
    }
    result.verdict = 'SATISFIED';
    result.evidence_satisfied = true;
    return result;
}
/**
 * Deterministic compare-and-set transition for AS-side bundle-to-grant state.
 * The caller MUST execute this transition atomically in its authoritative
 * store; this pure helper does not claim distributed or cross-domain locking.
 */
export function bindAuthorizationBundleToGrant(current, requested) {
    if (!requested || typeof requested !== 'object'
        || typeof requested.bundle_digest !== 'string' || !DIGEST_RE.test(requested.bundle_digest)
        || !nonEmptyString(requested.grant_id)) {
        throw new TypeError('invalid authorization bundle grant binding request');
    }
    if (current === null) {
        return { outcome: 'BOUND', state: { ...requested }, reason: null };
    }
    if (current.bundle_digest !== requested.bundle_digest) {
        return { outcome: 'REFUSE', state: { ...current }, reason: 'bundle_digest_mismatch' };
    }
    if (current.grant_id === requested.grant_id) {
        return { outcome: 'IDEMPOTENT', state: { ...current }, reason: null };
    }
    return { outcome: 'REFUSE', state: { ...current }, reason: 'bundle_already_bound_to_another_grant' };
}
//# sourceMappingURL=authorization-bundle.js.map