// SPDX-License-Identifier: Apache-2.0
/**
 * Concrete ORPRG JSON/JCS verifier profile.
 *
 * HONESTY BOUNDARY
 * ----------------
 * draft-lee-orprg-permit-receipts-00 defines an abstract PermitReceipt model
 * and verifier behavior. It deliberately does not select a mandatory wire
 * format. This module therefore does NOT claim to verify every ORPRG receipt.
 * It defines and verifies one explicitly named, closed JSON profile:
 *
 *   ORPRG-JSON-JCS-ED25519-v1
 *
 * The profile uses an ORPRG-JCS-ACTION-v1 canonical request envelope,
 * RFC 8785 JSON Canonicalization Scheme semantics over an I-JSON/safe-integer
 * subset, SHA-256 action digests, Ed25519 issuer signatures, exact policy and
 * epoch pins, signed status recency, exact scope/audience checks, integer-unit
 * budget ceilings, and atomic durable single-use consumption.
 *
 * The verifier returns the component contract consumed by EP-AEC:
 *
 *   { valid: boolean, action_digest: string|null, detail: object }
 *
 * `valid` establishes a machine-policy permit under this concrete profile. It
 * does not establish human authorization, successful execution, legal effect,
 * or non-bypassable deployment.
 */
import crypto from 'node:crypto';
import { strictJsonGate } from './strict-json.js';
export const ORPRG_JSON_JCS_PROFILE = 'ORPRG-JSON-JCS-ED25519-v1';
export const ORPRG_ACTION_PROFILE = 'ORPRG-JCS-ACTION-v1';
const MAX_JSON_DEPTH = 64;
const MAX_JSON_NODES = 50_000;
const MAX_JSON_STRING_BYTES = 1024 * 1024;
const MAX_WIRE_BYTES = 2 * 1024 * 1024;
const HASH = /^sha256:[0-9a-f]{64}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const EFFECT_TYPE = /^[a-z][a-z0-9._:-]{0,127}$/;
const UNIT = /^[A-Za-z][A-Za-z0-9._:/-]{0,63}$/;
const NONCE = /^[A-Za-z0-9._~-]{16,128}$/;
const RFC3339_UTC = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/;
const RECEIPT_KEYS = new Set(['@version', 'receipt_core', 'status', 'authenticity']);
const CORE_KEYS = new Set([
    'policy_digest',
    'epoch_id',
    'valid_from',
    'valid_to',
    'action_digest',
    'canonicalization_profile',
    'scope',
    'anti_replay',
]);
const SCOPE_KEYS = new Set([
    'effect_type',
    'interface_id',
    'target_id',
    'tenant_id',
    'purpose_id',
    'jurisdiction',
    'audience',
    'budget',
]);
const REQUIRED_SCOPE_KEYS = new Set(['effect_type', 'interface_id', 'target_id', 'audience']);
const BUDGET_KEYS = new Set(['unit', 'limit']);
const ANTI_REPLAY_KEYS = new Set(['mode', 'nonce']);
const STATUS_KEYS = new Set(['state', 'checked_at', 'next_update']);
const AUTHENTICITY_KEYS = new Set(['issuer_id', 'key_id', 'algorithm', 'signature']);
const AUTHENTICITY_SIGNED_KEYS = new Set(['issuer_id', 'key_id', 'algorithm']);
const ACTION_KEYS = new Set([
    'effect_type',
    'interface_id',
    'target_id',
    'tenant_id',
    'purpose_id',
    'jurisdiction',
    'audience',
    'budget',
    'request',
]);
const REQUIRED_ACTION_KEYS = new Set([
    'effect_type',
    'interface_id',
    'target_id',
    'audience',
    'request',
]);
const ACTION_BUDGET_KEYS = new Set(['unit', 'amount']);
const STATUS_STATES = new Set(['good', 'revoked', 'unknown']);
function isRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function hasExactKeys(value, allowed, required = allowed) {
    if (!isRecord(value))
        return false;
    const keys = Object.keys(value);
    return keys.every((key) => allowed.has(key))
        && [...required].every((key) => Object.hasOwn(value, key));
}
function validUnicodeString(value) {
    if (typeof value !== 'string')
        return false;
    for (let index = 0; index < value.length; index++) {
        const unit = value.charCodeAt(index);
        if (unit >= 0xd800 && unit <= 0xdbff) {
            const next = value.charCodeAt(++index);
            if (!(next >= 0xdc00 && next <= 0xdfff))
                return false;
        }
        else if (unit >= 0xdc00 && unit <= 0xdfff) {
            return false;
        }
    }
    return true;
}
function validText(value, maximum = 512) {
    return validUnicodeString(value)
        && value.length > 0
        && value.length <= maximum
        && !/[\u0000-\u001f\u007f]/.test(value);
}
function validEpoch(value) {
    return (typeof value === 'string' && validText(value, 128))
        || (Number.isSafeInteger(value) && value >= 0);
}
function validBudgetUnit(value) {
    return typeof value === 'string' && UNIT.test(value);
}
function validJurisdictions(value) {
    if (!Array.isArray(value) || value.length === 0 || value.length > 32)
        return false;
    if (!value.every((entry) => validText(entry, 64)))
        return false;
    const sorted = [...value].sort();
    return sorted.every((entry, index) => entry === value[index] && (index === 0 || entry !== value[index - 1]));
}
function canonicalJsonSafety(value) {
    const stack = [{ value, depth: 0 }];
    const seen = new WeakSet();
    let nodes = 0;
    let stringBytes = 0;
    while (stack.length > 0) {
        // stack.length > 0 guarantees pop() is non-empty here; TS can't see the
        // loop invariant, so this asserts the type the loop already ensures.
        const current = stack.pop();
        nodes += 1;
        if (nodes > MAX_JSON_NODES || current.depth > MAX_JSON_DEPTH)
            return false;
        const item = current.value;
        if (item === null || typeof item === 'boolean')
            continue;
        if (typeof item === 'string') {
            if (!validUnicodeString(item))
                return false;
            stringBytes += Buffer.byteLength(item, 'utf8');
            if (stringBytes > MAX_JSON_STRING_BYTES)
                return false;
            continue;
        }
        if (typeof item === 'number') {
            // This concrete profile is the safe-integer I-JSON subset of JCS. It
            // avoids cross-language ambiguity in budgets, epochs, and request data.
            if (!Number.isSafeInteger(item))
                return false;
            continue;
        }
        if (!Array.isArray(item) && !isRecord(item))
            return false;
        if (seen.has(item))
            return false;
        seen.add(item);
        if (Array.isArray(item)) {
            for (const child of item)
                stack.push({ value: child, depth: current.depth + 1 });
            continue;
        }
        for (const [key, child] of Object.entries(item)) {
            if (!validUnicodeString(key))
                return false;
            stringBytes += Buffer.byteLength(key, 'utf8');
            if (stringBytes > MAX_JSON_STRING_BYTES)
                return false;
            stack.push({ value: child, depth: current.depth + 1 });
        }
    }
    return true;
}
function serializeJcs(value) {
    if (value === null)
        return 'null';
    if (typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') {
        return JSON.stringify(value);
    }
    if (Array.isArray(value))
        return `[${value.map(serializeJcs).join(',')}]`;
    return `{${Object.keys(value)
        // RFC 8785 sorts property names by UTF-16 code units.
        .sort()
        .map((key) => `${JSON.stringify(key)}:${serializeJcs(value[key])}`)
        .join(',')}}`;
}
function canonicalizeJcs(value) {
    if (!canonicalJsonSafety(value))
        return null;
    return serializeJcs(value);
}
function sha256Canonical(value) {
    const canonical = canonicalizeJcs(value);
    if (canonical === null)
        return null;
    return `sha256:${crypto.createHash('sha256').update(canonical, 'utf8').digest('hex')}`;
}
function parseInstant(value) {
    if (typeof value !== 'string')
        return NaN;
    const match = value.match(RFC3339_UTC);
    if (!match)
        return NaN;
    const [, year, month, day, hour, minute, second] = match;
    const calendar = new Date(0);
    calendar.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
    calendar.setUTCHours(Number(hour), Number(minute), Number(second), 0);
    if (calendar.toISOString().slice(0, 19) !== `${year}-${month}-${day}T${hour}:${minute}:${second}`) {
        return NaN;
    }
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? parsed : NaN;
}
function decodeCanonicalBase64url(value, expectedLength) {
    if (typeof value !== 'string' || !B64URL.test(value))
        return null;
    try {
        const bytes = Buffer.from(value, 'base64url');
        if (bytes.toString('base64url') !== value)
            return null;
        if (expectedLength !== undefined && bytes.length !== expectedLength)
            return null;
        return bytes;
    }
    catch {
        return null;
    }
}
function actionShapeValid(action) {
    if (!hasExactKeys(action, ACTION_KEYS, REQUIRED_ACTION_KEYS))
        return false;
    if (typeof action.effect_type !== 'string' || !EFFECT_TYPE.test(action.effect_type))
        return false;
    for (const field of ['interface_id', 'target_id', 'audience']) {
        if (!validText(action[field]))
            return false;
    }
    for (const field of ['tenant_id', 'purpose_id']) {
        if (Object.hasOwn(action, field) && !validText(action[field]))
            return false;
    }
    if (Object.hasOwn(action, 'jurisdiction') && !validJurisdictions(action.jurisdiction))
        return false;
    if (!isRecord(action.request))
        return false;
    if (Object.hasOwn(action, 'budget')) {
        if (!hasExactKeys(action.budget, ACTION_BUDGET_KEYS))
            return false;
        if (!validBudgetUnit(action.budget.unit))
            return false;
        if (!Number.isSafeInteger(action.budget.amount) || action.budget.amount < 0)
            return false;
    }
    return canonicalJsonSafety(action);
}
/**
 * Compute the RFC 8785/SHA-256 digest for an ORPRG-JCS-ACTION-v1 request.
 * Returns null for a malformed, open-schema, cyclic, non-I-JSON, or otherwise
 * ambiguous request.
 */
export function computeOrprgActionDigest(action) {
    try {
        return actionShapeValid(action) ? sha256Canonical(action) : null;
    }
    catch {
        return null;
    }
}
function scopeShapeValid(scope) {
    if (!hasExactKeys(scope, SCOPE_KEYS, REQUIRED_SCOPE_KEYS))
        return false;
    if (typeof scope.effect_type !== 'string' || !EFFECT_TYPE.test(scope.effect_type))
        return false;
    for (const field of ['interface_id', 'target_id', 'audience']) {
        if (!validText(scope[field]))
            return false;
    }
    for (const field of ['tenant_id', 'purpose_id']) {
        if (Object.hasOwn(scope, field) && !validText(scope[field]))
            return false;
    }
    if (Object.hasOwn(scope, 'jurisdiction') && !validJurisdictions(scope.jurisdiction))
        return false;
    if (Object.hasOwn(scope, 'budget')) {
        if (!hasExactKeys(scope.budget, BUDGET_KEYS))
            return false;
        if (!validBudgetUnit(scope.budget.unit))
            return false;
        if (!Number.isSafeInteger(scope.budget.limit) || scope.budget.limit < 0)
            return false;
    }
    return true;
}
function receiptShapeValid(receipt) {
    if (!hasExactKeys(receipt, RECEIPT_KEYS))
        return false;
    if (receipt['@version'] !== ORPRG_JSON_JCS_PROFILE)
        return false;
    if (!hasExactKeys(receipt.receipt_core, CORE_KEYS))
        return false;
    if (!hasExactKeys(receipt.status, STATUS_KEYS))
        return false;
    if (!hasExactKeys(receipt.authenticity, AUTHENTICITY_KEYS))
        return false;
    const core = receipt.receipt_core;
    if (!HASH.test(core.policy_digest) || !validEpoch(core.epoch_id))
        return false;
    if (!HASH.test(core.action_digest))
        return false;
    if (!validText(core.canonicalization_profile, 128))
        return false;
    if (!scopeShapeValid(core.scope))
        return false;
    if (!hasExactKeys(core.anti_replay, ANTI_REPLAY_KEYS))
        return false;
    if (core.anti_replay.mode !== 'single-use'
        || typeof core.anti_replay.nonce !== 'string'
        || !NONCE.test(core.anti_replay.nonce))
        return false;
    if (!STATUS_STATES.has(receipt.status.state))
        return false;
    if (!Number.isFinite(parseInstant(core.valid_from))
        || !Number.isFinite(parseInstant(core.valid_to))
        || !Number.isFinite(parseInstant(receipt.status.checked_at))
        || !Number.isFinite(parseInstant(receipt.status.next_update)))
        return false;
    const authenticity = receipt.authenticity;
    if (!validText(authenticity.issuer_id, 1024)
        || !validText(authenticity.key_id, 256)
        || authenticity.algorithm !== 'Ed25519'
        || decodeCanonicalBase64url(authenticity.signature, 64) === null)
        return false;
    return canonicalJsonSafety(receipt);
}
function parseReceipt(input) {
    if (typeof input !== 'string')
        return input;
    if (Buffer.byteLength(input, 'utf8') > MAX_WIRE_BYTES)
        return null;
    const gate = strictJsonGate(input);
    if (!gate.ok)
        return null;
    try {
        return JSON.parse(input);
    }
    catch {
        return null;
    }
}
function sameOptionalField(scope, action, field) {
    const scopeHas = Object.hasOwn(scope, field);
    const actionHas = Object.hasOwn(action, field);
    if (scopeHas !== actionHas)
        return false;
    if (!scopeHas)
        return true;
    const left = canonicalizeJcs(scope[field]);
    const right = canonicalizeJcs(action[field]);
    return left !== null && left === right;
}
function scopeMatchesAction(scope, action, requireBudget) {
    if (scope.effect_type !== action.effect_type
        || scope.interface_id !== action.interface_id
        || scope.target_id !== action.target_id
        || scope.audience !== action.audience)
        return false;
    for (const field of ['tenant_id', 'purpose_id', 'jurisdiction']) {
        if (!sameOptionalField(scope, action, field))
            return false;
    }
    const receiptHasBudget = Object.hasOwn(scope, 'budget');
    const actionHasBudget = Object.hasOwn(action, 'budget');
    if (receiptHasBudget !== actionHasBudget)
        return false;
    if (requireBudget === true && !receiptHasBudget)
        return false;
    if (!receiptHasBudget)
        return true;
    return scope.budget.unit === action.budget.unit
        && action.budget.amount <= scope.budget.limit;
}
function signedPayload(receipt) {
    return {
        '@version': receipt['@version'],
        receipt_core: receipt.receipt_core,
        status: receipt.status,
        authenticity: {
            issuer_id: receipt.authenticity.issuer_id,
            key_id: receipt.authenticity.key_id,
            algorithm: receipt.authenticity.algorithm,
        },
    };
}
function pinnedIssuerKey(issuerKeys, issuerId, keyId) {
    if (!isRecord(issuerKeys) || !Object.hasOwn(issuerKeys, issuerId))
        return null;
    const issuer = issuerKeys[issuerId];
    if (!isRecord(issuer) || !Object.hasOwn(issuer, keyId))
        return null;
    const encoded = issuer[keyId];
    const der = decodeCanonicalBase64url(encoded);
    if (der === null)
        return null;
    try {
        const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
        if (key.asymmetricKeyType !== 'ed25519')
            return null;
        const canonical = key.export({ format: 'der', type: 'spki' });
        return canonical.equals(der) ? key : null;
    }
    catch {
        return null;
    }
}
function verifySignature(receipt, key) {
    if (!key)
        return false;
    const canonical = canonicalizeJcs(signedPayload(receipt));
    const signature = decodeCanonicalBase64url(receipt.authenticity.signature, 64);
    if (canonical === null || signature === null)
        return false;
    try {
        return crypto.verify(null, Buffer.from(canonical, 'utf8'), key, signature);
    }
    catch {
        return false;
    }
}
function newChecks() {
    return {
        structure: false,
        canonical_action: false,
        canonicalization_profile: false,
        action_binding: false,
        policy_binding: false,
        epoch_binding: false,
        scope_binding: false,
        budget_binding: false,
        validity: false,
        receipt_recency: false,
        status: false,
        status_recency: false,
        issuer_pinned: false,
        signature: false,
        anti_replay: false,
    };
}
/**
 * The nullable fields below are placeholders filled in as verification
 * progresses; this annotation documents the real (post-fill) types so the
 * checker doesn't lock them to the literal `null` of the initializer.
 * @returns {{
 *   profile: string,
 *   decision: string,
 *   denial_reason_code: string|null,
 *   reason: string|null,
 *   checks: ReturnType<typeof newChecks>,
 *   evidence_digests: {
 *     action_digest: string|null,
 *     receipt_digest: string|null,
 *     policy_digest: any,
 *     epoch_id: any,
 *     status_evidence_digest: string|null,
 *   },
 *   recency_observations: {
 *     receipt_age_seconds: number|null,
 *     status_age_seconds: number|null,
 *   },
 * }}
 */
function baseDetail(checks) {
    return {
        profile: ORPRG_JSON_JCS_PROFILE,
        decision: 'DENY',
        denial_reason_code: null,
        reason: null,
        checks,
        evidence_digests: {
            action_digest: null,
            receipt_digest: null,
            policy_digest: null,
            epoch_id: null,
            status_evidence_digest: null,
        },
        recency_observations: {
            receipt_age_seconds: null,
            status_age_seconds: null,
        },
    };
}
function deny(code, reason, detail) {
    detail.decision = 'DENY';
    detail.denial_reason_code = code;
    detail.reason = reason;
    return {
        valid: false,
        action_digest: null,
        detail,
    };
}
function allow(detail, actionDigest) {
    detail.decision = 'ALLOW';
    detail.denial_reason_code = null;
    detail.reason = null;
    return {
        valid: true,
        action_digest: actionDigest,
        detail,
    };
}
function prepareVerification(input, options) {
    const checks = newChecks();
    const detail = baseDetail(checks);
    const opts = isRecord(options) ? options : {};
    const receipt = parseReceipt(input);
    checks.structure = receiptShapeValid(receipt);
    if (!checks.structure) {
        return { result: deny('MALFORMED_RECEIPT', 'receipt is not valid under the closed ORPRG JSON/JCS profile', detail) };
    }
    detail.evidence_digests.receipt_digest = sha256Canonical(receipt);
    detail.evidence_digests.status_evidence_digest = sha256Canonical(receipt.status);
    detail.evidence_digests.policy_digest = receipt.receipt_core.policy_digest;
    detail.evidence_digests.epoch_id = receipt.receipt_core.epoch_id;
    checks.canonical_action = actionShapeValid(opts.expectedAction);
    if (!checks.canonical_action) {
        return { result: deny('AMBIGUOUS_CONTEXT', 'relying party did not supply one closed canonical expected action', detail) };
    }
    const expectedActionDigest = computeOrprgActionDigest(opts.expectedAction);
    detail.evidence_digests.action_digest = expectedActionDigest;
    checks.canonicalization_profile = receipt.receipt_core.canonicalization_profile === ORPRG_ACTION_PROFILE;
    if (!checks.canonicalization_profile) {
        return { result: deny('CANONICALIZATION_MISMATCH', 'receipt uses an unsupported canonicalization profile', detail) };
    }
    checks.action_binding = expectedActionDigest !== null
        && receipt.receipt_core.action_digest === expectedActionDigest;
    if (!checks.action_binding) {
        return { result: deny('ACTION_DIGEST_MISMATCH', 'receipt does not bind the relying-party expected action', detail) };
    }
    checks.policy_binding = typeof opts.expectedPolicyDigest === 'string'
        && HASH.test(opts.expectedPolicyDigest)
        && receipt.receipt_core.policy_digest === opts.expectedPolicyDigest;
    if (!checks.policy_binding) {
        return { result: deny('POLICY_MISMATCH', 'receipt policy digest is absent, malformed, or not relying-party pinned', detail) };
    }
    checks.epoch_binding = validEpoch(opts.expectedEpoch)
        && typeof opts.expectedEpoch === typeof receipt.receipt_core.epoch_id
        && Object.is(receipt.receipt_core.epoch_id, opts.expectedEpoch);
    if (!checks.epoch_binding) {
        return { result: deny('EPOCH_MISMATCH', 'receipt epoch is absent, ambiguous, or not the relying-party expected epoch', detail) };
    }
    checks.scope_binding = scopeMatchesAction(receipt.receipt_core.scope, opts.expectedAction, opts.requireBudget === true);
    checks.budget_binding = checks.scope_binding
        && (Object.hasOwn(opts.expectedAction, 'budget')
            ? Object.hasOwn(receipt.receipt_core.scope, 'budget')
                && receipt.receipt_core.scope.budget.unit === opts.expectedAction.budget.unit
                && opts.expectedAction.budget.amount <= receipt.receipt_core.scope.budget.limit
            : opts.requireBudget !== true);
    if (!checks.scope_binding || !checks.budget_binding) {
        return { result: deny('SCOPE_VIOLATION', 'effect scope, audience, jurisdiction, or budget does not cover the expected action', detail) };
    }
    const verificationTime = parseInstant(opts.verificationTime);
    if (!Number.isFinite(verificationTime)) {
        return { result: deny('AMBIGUOUS_CONTEXT', 'an explicit RFC 3339 UTC verification time is required', detail) };
    }
    const validFrom = parseInstant(receipt.receipt_core.valid_from);
    const validTo = parseInstant(receipt.receipt_core.valid_to);
    checks.validity = Number.isFinite(validFrom)
        && Number.isFinite(validTo)
        && validFrom < validTo
        && validFrom <= verificationTime
        && verificationTime <= validTo;
    if (!checks.validity) {
        return { result: deny('VALIDITY_WINDOW_EXPIRED', 'receipt is outside its validity window', detail) };
    }
    const maxReceiptAge = opts.maxReceiptAgeSeconds;
    detail.recency_observations.receipt_age_seconds = Math.floor((verificationTime - validFrom) / 1000);
    checks.receipt_recency = Number.isSafeInteger(maxReceiptAge)
        && maxReceiptAge >= 0
        && detail.recency_observations.receipt_age_seconds >= 0
        && detail.recency_observations.receipt_age_seconds <= maxReceiptAge;
    if (!checks.receipt_recency) {
        return { result: deny('VALIDITY_WINDOW_EXPIRED', 'receipt recency is missing or exceeds the relying-party maximum', detail) };
    }
    checks.status = receipt.status.state === 'good';
    if (receipt.status.state === 'revoked') {
        return { result: deny('REVOKED_CONFIRMED', 'issuer status confirms revocation', detail) };
    }
    if (!checks.status) {
        return { result: deny('REVOCATION_UNKNOWN_OR_STALE', 'issuer status is not affirmatively good', detail) };
    }
    const checkedAt = parseInstant(receipt.status.checked_at);
    const nextUpdate = parseInstant(receipt.status.next_update);
    const maxStatusAge = opts.maxStatusAgeSeconds;
    detail.recency_observations.status_age_seconds = Math.floor((verificationTime - checkedAt) / 1000);
    checks.status_recency = Number.isSafeInteger(maxStatusAge)
        && maxStatusAge >= 0
        && checkedAt <= verificationTime
        && verificationTime <= nextUpdate
        && checkedAt < nextUpdate
        && detail.recency_observations.status_age_seconds >= 0
        && detail.recency_observations.status_age_seconds <= maxStatusAge;
    if (!checks.status_recency) {
        return { result: deny('REVOCATION_UNKNOWN_OR_STALE', 'status evidence is missing, future-dated, expired, or stale', detail) };
    }
    const issuerKey = pinnedIssuerKey(opts.issuerKeys, receipt.authenticity.issuer_id, receipt.authenticity.key_id);
    checks.issuer_pinned = issuerKey !== null;
    if (!checks.issuer_pinned) {
        return { result: deny('ISSUER_UNTRUSTED', 'no valid role-pinned Ed25519 key exists for this issuer and key id', detail) };
    }
    checks.signature = verifySignature(receipt, issuerKey);
    if (!checks.signature) {
        return { result: deny('SIGNATURE_INVALID', 'issuer signature does not bind the exact closed receipt payload', detail) };
    }
    // A nonce is single-use across receipt re-signing and issuer-key rotation
    // inside the same issuer/tenant/audience domain. Receipt and action digests
    // are audit metadata, not replay-key dimensions; including them here would
    // let changed receipt bytes mint a fresh consumption key for the same nonce.
    const replayDomain = {
        profile: ORPRG_JSON_JCS_PROFILE,
        issuer_id: receipt.authenticity.issuer_id,
        tenant_id: receipt.receipt_core.scope.tenant_id ?? null,
        audience: receipt.receipt_core.scope.audience,
        nonce: receipt.receipt_core.anti_replay.nonce,
    };
    const replayDigest = sha256Canonical(replayDomain);
    if (replayDigest === null) {
        return { result: deny('ANTI_REPLAY_FAILURE', 'anti-replay key material is not canonicalizable', detail) };
    }
    return {
        checks,
        detail,
        expectedActionDigest,
        replayKey: `orprg-replay:${replayDigest}`,
        replayContext: Object.freeze({
            ...replayDomain,
            key_id: receipt.authenticity.key_id,
            action_digest: expectedActionDigest,
            receipt_digest: detail.evidence_digests.receipt_digest,
            valid_to: receipt.receipt_core.valid_to,
        }),
        antiReplay: captureReplayHook(opts.antiReplay),
    };
}
function replayHookShapeValid(hook) {
    return isRecord(hook)
        && hook.durable === true
        && hook.atomic === true
        && typeof hook.consume === 'function';
}
function isThenable(value) {
    return value !== null
        && (typeof value === 'object' || typeof value === 'function')
        && typeof value.then === 'function';
}
/**
 * Synchronous verifier suitable for the current synchronous EP-AEC component
 * contract. The anti-replay hook MUST synchronously and atomically consume the
 * supplied key. If it returns a Promise, throws, returns an ambiguous value, or
 * reports replay, verification denies. Use verifyOrprgJsonJcsPermitAsync when
 * the durable backend is asynchronous.
 */
export function verifyOrprgJsonJcsPermit(input, options = {}) {
    try {
        const prepared = prepareVerification(input, options);
        if (prepared.result)
            return prepared.result;
        if (!replayHookShapeValid(prepared.antiReplay)) {
            return deny('ANTI_REPLAY_FAILURE', 'single-use profile requires an atomic durable anti-replay hook', prepared.detail);
        }
        let consumed;
        try {
            consumed = prepared.antiReplay.consume(prepared.replayKey, prepared.replayContext);
        }
        catch {
            consumed = false;
        }
        if (isThenable(consumed) || consumed !== true) {
            return deny('ANTI_REPLAY_FAILURE', 'receipt replayed or durable anti-replay state is unavailable or ambiguous', prepared.detail);
        }
        prepared.checks.anti_replay = true;
        return allow(prepared.detail, prepared.expectedActionDigest);
    }
    catch {
        const checks = newChecks();
        return deny('MALFORMED_RECEIPT', 'unexpected input or verifier state was denied', baseDetail(checks));
    }
}
/**
 * Asynchronous variant for production stores whose atomic consume operation
 * returns a Promise. The result is byte-for-byte the same AEC component shape.
 */
export async function verifyOrprgJsonJcsPermitAsync(input, options = {}) {
    try {
        const prepared = prepareVerification(input, options);
        if (prepared.result)
            return prepared.result;
        if (!replayHookShapeValid(prepared.antiReplay)) {
            return deny('ANTI_REPLAY_FAILURE', 'single-use profile requires an atomic durable anti-replay hook', prepared.detail);
        }
        let consumed;
        try {
            consumed = await prepared.antiReplay.consume(prepared.replayKey, prepared.replayContext);
        }
        catch {
            consumed = false;
        }
        if (consumed !== true) {
            return deny('ANTI_REPLAY_FAILURE', 'receipt replayed or durable anti-replay state is unavailable or ambiguous', prepared.detail);
        }
        prepared.checks.anti_replay = true;
        return allow(prepared.detail, prepared.expectedActionDigest);
    }
    catch {
        const checks = newChecks();
        return deny('MALFORMED_RECEIPT', 'unexpected input or verifier state was denied', baseDetail(checks));
    }
}
function captureIssuerKeys(value) {
    const captured = Object.create(null);
    if (!isRecord(value))
        return Object.freeze(captured);
    for (const [issuerId, issuer] of Object.entries(value)) {
        if (!isRecord(issuer))
            continue;
        const keys = Object.create(null);
        for (const [keyId, publicKey] of Object.entries(issuer)) {
            if (typeof publicKey === 'string')
                keys[keyId] = publicKey;
        }
        captured[issuerId] = Object.freeze(keys);
    }
    return Object.freeze(captured);
}
function captureReplayHook(value) {
    try {
        if (!isRecord(value))
            return value;
        const method = value.consume;
        if (typeof method !== 'function')
            return value;
        const consume = method.bind(value);
        return Object.freeze({
            durable: value.durable === true,
            atomic: value.atomic === true,
            consume,
        });
    }
    catch {
        return null;
    }
}
/**
 * Capture relying-party policy and trust anchors for direct registration in
 * EP-AEC's `opts.verifiers` map:
 *
 *   const verifier = createOrprgAecVerifier(profile);
 *   verifyAuthorizationChain(chain, {
 *     expectedAction,
 *     verificationTime,
 *     requirement: 'orprg-json-jcs',
 *     verifiers: { 'orprg-json-jcs': verifier }
 *   });
 *
 * AEC supplies the already executor-bound chain action and verification time.
 * This adapter captures the policy digest, epoch, issuer pins, recency limits,
 * budget requirement, and anti-replay method at construction.
 */
export function createOrprgAecVerifier(profile = {}) {
    const source = isRecord(profile) ? profile : {};
    const captured = Object.freeze({
        expectedPolicyDigest: source.expectedPolicyDigest,
        expectedEpoch: source.expectedEpoch,
        maxReceiptAgeSeconds: source.maxReceiptAgeSeconds,
        maxStatusAgeSeconds: source.maxStatusAgeSeconds,
        requireBudget: source.requireBudget === true,
        issuerKeys: captureIssuerKeys(source.issuerKeys),
        antiReplay: captureReplayHook(source.antiReplay),
        fallbackVerificationTime: source.verificationTime,
    });
    return function verifyOrprgAecComponent(evidence, context = {}) {
        const ctx = isRecord(context) ? context : {};
        return verifyOrprgJsonJcsPermit(evidence, {
            expectedAction: ctx.action,
            verificationTime: ctx.verificationTime ?? captured.fallbackVerificationTime,
            expectedPolicyDigest: captured.expectedPolicyDigest,
            expectedEpoch: captured.expectedEpoch,
            maxReceiptAgeSeconds: captured.maxReceiptAgeSeconds,
            maxStatusAgeSeconds: captured.maxStatusAgeSeconds,
            requireBudget: captured.requireBudget,
            issuerKeys: captured.issuerKeys,
            antiReplay: captured.antiReplay,
        });
    };
}
// Mutation and differential-test surface. These helpers are not a universal
// ORPRG API; they make the exact concrete profile reviewable.
export const __orprgSecurityInternals = Object.freeze({
    validUnicodeString,
    canonicalJsonSafety,
    canonicalizeJcs,
    parseInstant,
    actionShapeValid,
    scopeShapeValid,
    receiptShapeValid,
    scopeMatchesAction,
    signedPayload,
});
//# sourceMappingURL=orprg.js.map