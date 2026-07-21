// SPDX-License-Identifier: Apache-2.0
/**
 * EP-ACTION-ESCROW-STATE-STATEMENT-v1
 *
 * A portable, operator-signed statement over one exact durable Action Escrow
 * snapshot. The signature authenticates an operator statement; it does not
 * prove the operator's database was complete or that a custodian moved money.
 */
import crypto from 'node:crypto';
import { canonicalize, hashCanonical } from './execution-binding.js';
import { ACTION_ESCROW_EVIDENCE_STAGES } from './action-escrow-evidence.js';
export const ACTION_ESCROW_STATE_STATEMENT_VERSION = 'EP-ACTION-ESCROW-STATE-STATEMENT-v1';
export const ACTION_ESCROW_STATE_STATEMENT_DOMAIN = `${ACTION_ESCROW_STATE_STATEMENT_VERSION}\0`;
const HASH = /^sha256:[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/#@+-]{0,255}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const TOP_KEYS = new Set(['version', 'issuer', 'payload', 'statement_digest', 'signature']);
const ISSUER_KEYS = new Set(['operator_id', 'key_id']);
const PAYLOAD_KEYS = new Set([
    'statement_id',
    'agreement_id',
    'binding_digest',
    'action_digest',
    'profile_digest',
    'state',
    'revision',
    'amendment_digests',
    'state_record_digest',
    'previous_statement_digest',
    'occurred_at',
]);
const SIGNATURE_KEYS = new Set(['algorithm', 'signature_b64u']);
function isRecord(value) {
    return value !== null
        && typeof value === 'object'
        && !Array.isArray(value)
        && (Object.getPrototypeOf(value) === Object.prototype
            || Object.getPrototypeOf(value) === null);
}
/**
 * @param {*} value
 * @param {Set<string>} keys
 */
function exactKeys(value, keys) {
    return isRecord(value)
        && Object.keys(value).length === keys.size
        && Object.keys(value).every((key) => keys.has(key));
}
/** @param {*} value */
function strictInstant(value) {
    if (typeof value !== 'string')
        return NaN;
    const match = value.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/);
    if (!match)
        return NaN;
    const [, year, month, day, hour, minute, second] = match;
    const calendar = new Date(0);
    calendar.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
    calendar.setUTCHours(Number(hour), Number(minute), Number(second), 0);
    if (calendar.toISOString().slice(0, 19)
        !== `${year}-${month}-${day}T${hour}:${minute}:${second}`)
        return NaN;
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? parsed : NaN;
}
/** @param {*} value */
function boundedCanonicalCopy(value) {
    let nodes = 0;
    let bytes = 0;
    const seen = new WeakSet();
    /**
     * @param {*} current
     * @param {number} depth
     * @returns {*}
     */
    function copy(current, depth) {
        nodes += 1;
        if (nodes > 50_000 || depth > 64)
            throw new TypeError('state statement exceeds resource limits');
        if (current === null || typeof current === 'boolean')
            return current;
        if (typeof current === 'string') {
            bytes += Buffer.byteLength(current, 'utf8');
            if (bytes > 4 * 1024 * 1024)
                throw new TypeError('state statement exceeds string limit');
            return current;
        }
        if (typeof current === 'number') {
            if (!Number.isSafeInteger(current) || Object.is(current, -0)) {
                throw new TypeError('state statement contains a non-canonical number');
            }
            return current;
        }
        if (!isRecord(current) && !Array.isArray(current)) {
            throw new TypeError('state statement is not canonical JSON');
        }
        if (seen.has(current))
            throw new TypeError('state statement contains an alias or cycle');
        seen.add(current);
        if (Array.isArray(current))
            return current.map((entry) => copy(entry, depth + 1));
        return Object.fromEntries(Object.entries(current).map(([key, entry]) => [key, copy(entry, depth + 1)]));
    }
    return copy(value, 0);
}
/** @param {*} value */
function canonicalHash(value) {
    return `sha256:${hashCanonical(value)}`;
}
/**
 * @typedef {Object} StateStatementLike
 * @property {string} [version]
 * @property {*} [issuer]
 * @property {*} [payload]
 * @property {string} [statement_digest]
 * @property {*} [signature]
 */
/** @param {StateStatementLike} statement */
function signingBody(statement) {
    return {
        version: statement.version,
        issuer: statement.issuer,
        payload: statement.payload,
    };
}
/** @param {StateStatementLike} statement */
function stateSigningBytes(statement) {
    const body = boundedCanonicalCopy(signingBody(statement));
    return Buffer.from(ACTION_ESCROW_STATE_STATEMENT_DOMAIN + canonicalize(body), 'utf8');
}
/** @param {*} value */
function deepFreeze(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value))
        return value;
    Object.freeze(value);
    for (const child of Object.values(value))
        deepFreeze(child);
    return value;
}
/**
 * @param {*} value
 * @param {number} [length]
 */
function strictBase64url(value, length) {
    if (typeof value !== 'string' || !BASE64URL.test(value) || value.length % 4 === 1)
        return null;
    const bytes = Buffer.from(value, 'base64url');
    if (bytes.toString('base64url') !== value || (length !== undefined && bytes.length !== length))
        return null;
    return bytes;
}
/** @param {*} value */
function validDigestList(value) {
    return Array.isArray(value)
        && value.length <= 1024
        && value.every((entry) => typeof entry === 'string' && HASH.test(entry))
        && new Set(value).size === value.length;
}
/** @param {*} payload */
function payloadValid(payload) {
    return exactKeys(payload, PAYLOAD_KEYS)
        && typeof payload.statement_id === 'string' && ID.test(payload.statement_id)
        && typeof payload.agreement_id === 'string' && ID.test(payload.agreement_id)
        && HASH.test(payload.binding_digest)
        && HASH.test(payload.action_digest)
        && HASH.test(payload.profile_digest)
        && ACTION_ESCROW_EVIDENCE_STAGES.includes(payload.state)
        && Number.isSafeInteger(payload.revision) && payload.revision >= 0
        && validDigestList(payload.amendment_digests)
        && HASH.test(payload.state_record_digest)
        && (payload.previous_statement_digest === null || HASH.test(payload.previous_statement_digest))
        && Number.isFinite(strictInstant(payload.occurred_at));
}
/**
 * @typedef {Object} StateStatementChecks
 * @property {boolean} structure
 * @property {boolean} payload
 * @property {boolean} issuer_pin
 * @property {boolean} signature
 * @property {boolean} statement_digest
 * @property {boolean} state_record
 * @property {boolean} expected_bindings
 * @property {boolean} time
 */
/**
 * @param {string} reason
 * @param {StateStatementChecks} checks
 */
function refuse(reason, checks) {
    return {
        valid: false,
        reason,
        checks,
        statement_digest: null,
        agreement_id: null,
        binding_digest: null,
        action_digest: null,
        profile_digest: null,
        state: null,
        revision: null,
        amendment_digests: [],
    };
}
/**
 * Sign one exact state snapshot. Issuance may throw on invalid local input;
 * verification below never throws.
 */
export function signActionEscrowStateStatement({ statementId, agreementId, bindingDigest, actionDigest, profileDigest, state, revision, amendmentDigests = [], stateRecord, previousStatementDigest = null, occurredAt, } = {}, { operatorId, keyId, privateKey, } = {}) {
    const stateRecordCopy = boundedCanonicalCopy(stateRecord);
    const statement = {
        version: ACTION_ESCROW_STATE_STATEMENT_VERSION,
        issuer: {
            operator_id: operatorId,
            key_id: keyId,
        },
        payload: {
            statement_id: statementId,
            agreement_id: agreementId,
            binding_digest: bindingDigest,
            action_digest: actionDigest,
            profile_digest: profileDigest,
            state,
            revision,
            amendment_digests: boundedCanonicalCopy(amendmentDigests),
            state_record_digest: canonicalHash(stateRecordCopy),
            previous_statement_digest: previousStatementDigest,
            occurred_at: occurredAt,
        },
    };
    if (!exactKeys(statement.issuer, ISSUER_KEYS)
        || typeof operatorId !== 'string' || !ID.test(operatorId)
        || typeof keyId !== 'string' || !ID.test(keyId)
        || !payloadValid(statement.payload)) {
        throw new TypeError('action-escrow state statement input is invalid');
    }
    // privateKey may be omitted by a caller (optional field); createPrivateKey
    // throws on undefined input, matching this function's documented
    // throw-on-invalid-local-input contract.
    const key = privateKey instanceof crypto.KeyObject ? privateKey : crypto.createPrivateKey(privateKey);
    if (key.asymmetricKeyType !== 'ed25519') {
        throw new TypeError('action-escrow state statement key must be Ed25519');
    }
    const bytes = stateSigningBytes(statement);
    const statementDigest = `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
    return deepFreeze({
        ...statement,
        statement_digest: statementDigest,
        signature: {
            algorithm: 'Ed25519',
            signature_b64u: crypto.sign(null, bytes, key).toString('base64url'),
        },
    });
}
/**
 * Verify one state statement against an exact snapshot and relying-party pins.
 *
 * @param {*} statement
 */
export function verifyActionEscrowStateStatement(statement, { trustedKeys, stateRecord, expectedAgreementId, expectedBindingDigest, expectedActionDigest, expectedProfileDigest, expectedState, expectedRevision, expectedAmendmentDigests, expectedPreviousStatementDigest, now, } = {}) {
    const checks = {
        structure: false,
        payload: false,
        issuer_pin: false,
        signature: false,
        statement_digest: false,
        state_record: false,
        expected_bindings: false,
        time: false,
    };
    try {
        checks.structure = exactKeys(statement, TOP_KEYS)
            && statement.version === ACTION_ESCROW_STATE_STATEMENT_VERSION
            && exactKeys(statement.issuer, ISSUER_KEYS)
            && exactKeys(statement.signature, SIGNATURE_KEYS);
        if (!checks.structure)
            return refuse('malformed_state_statement', checks);
        checks.payload = payloadValid(statement.payload);
        if (!checks.payload)
            return refuse('invalid_state_payload', checks);
        const pin = isRecord(trustedKeys) && Object.hasOwn(trustedKeys, statement.issuer.key_id)
            ? trustedKeys[statement.issuer.key_id]
            : null;
        checks.issuer_pin = exactKeys(pin, new Set(['operator_id', 'public_key']))
            && pin.operator_id === statement.issuer.operator_id
            && typeof pin.public_key === 'string';
        if (!checks.issuer_pin)
            return refuse('operator_key_not_pinned', checks);
        const publicBytes = strictBase64url(pin.public_key);
        const signatureBytes = strictBase64url(statement.signature.signature_b64u, 64);
        let publicKey = null;
        try {
            // publicBytes may be null here (checked below via publicBytes !== null);
            // createPublicKey rejects a null key and the catch maps that to null.
            publicKey = crypto.createPublicKey({ key: publicBytes, format: 'der', type: 'spki' });
        }
        catch {
            publicKey = null;
        }
        const bytes = stateSigningBytes(statement);
        checks.signature = statement.signature.algorithm === 'Ed25519'
            && publicBytes !== null
            && signatureBytes !== null
            && publicKey?.asymmetricKeyType === 'ed25519'
            && crypto.verify(null, bytes, publicKey, signatureBytes);
        if (!checks.signature)
            return refuse('state_signature_invalid', checks);
        const digest = `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
        checks.statement_digest = statement.statement_digest === digest;
        if (!checks.statement_digest)
            return refuse('state_statement_digest_mismatch', checks);
        checks.state_record = canonicalHash(boundedCanonicalCopy(stateRecord))
            === statement.payload.state_record_digest;
        if (!checks.state_record)
            return refuse('state_record_digest_mismatch', checks);
        const amendments = expectedAmendmentDigests;
        checks.expected_bindings = typeof expectedAgreementId === 'string'
            && statement.payload.agreement_id === expectedAgreementId
            && statement.payload.binding_digest === expectedBindingDigest
            && statement.payload.action_digest === expectedActionDigest
            && statement.payload.profile_digest === expectedProfileDigest
            && statement.payload.state === expectedState
            && statement.payload.revision === expectedRevision
            && Array.isArray(amendments)
            && statement.payload.amendment_digests.length === amendments.length
            && statement.payload.amendment_digests.every(
            /**
             * @param {string} entry
             * @param {number} index
             */
            (entry, index) => entry === amendments[index])
            && statement.payload.previous_statement_digest === expectedPreviousStatementDigest;
        if (!checks.expected_bindings)
            return refuse('state_expected_binding_mismatch', checks);
        const evaluation = now instanceof Date
            ? now.getTime()
            : typeof now === 'number' ? now : strictInstant(now);
        checks.time = Number.isFinite(evaluation)
            && strictInstant(statement.payload.occurred_at) <= evaluation;
        if (!checks.time)
            return refuse('state_statement_from_future', checks);
        return {
            valid: true,
            reason: 'verified',
            checks,
            statement_digest: digest,
            agreement_id: statement.payload.agreement_id,
            binding_digest: statement.payload.binding_digest,
            action_digest: statement.payload.action_digest,
            profile_digest: statement.payload.profile_digest,
            state: statement.payload.state,
            revision: statement.payload.revision,
            amendment_digests: [...statement.payload.amendment_digests],
        };
    }
    catch {
        return refuse('malformed_state_statement', checks);
    }
}
/**
 * Build the callback expected by verifyActionEscrowEvidencePackage. The
 * package carries both the exact durable snapshot and the signed statement
 * over it; trust keys and time remain verifier configuration.
 */
export function createActionEscrowStatePackageVerifier({ trustedKeys, now, minimumRevision = 0, } = {}) {
    if (!Number.isSafeInteger(minimumRevision) || minimumRevision < 0) {
        throw new TypeError('minimumRevision must be a non-negative safe integer');
    }
    const pinnedKeys = boundedCanonicalCopy(trustedKeys);
    /**
     * @param {*} packaged
     */
    return async function verifyPackagedState(packaged, expected = {}) {
        if (!exactKeys(packaged, new Set(['snapshot', 'statement']))
            || !isRecord(packaged.statement?.payload)
            || !isRecord(packaged.snapshot)
            || packaged.statement.payload.state !== packaged.snapshot.state
            || packaged.statement.payload.revision !== packaged.snapshot.revision
            || packaged.statement.payload.revision < minimumRevision) {
            return refuse('malformed_packaged_state', {
                structure: false,
                payload: false,
                issuer_pin: false,
                signature: false,
                statement_digest: false,
                state_record: false,
                expected_bindings: false,
                time: false,
            });
        }
        return verifyActionEscrowStateStatement(packaged.statement, {
            trustedKeys: pinnedKeys,
            stateRecord: packaged.snapshot,
            expectedAgreementId: expected.agreementId,
            expectedBindingDigest: expected.bindingDigest,
            expectedActionDigest: expected.actionDigest,
            expectedProfileDigest: expected.profileDigest,
            expectedState: expected.stage,
            expectedRevision: packaged.statement.payload.revision,
            expectedAmendmentDigests: expected.amendmentDigests,
            expectedPreviousStatementDigest: packaged.statement.payload.previous_statement_digest,
            now,
        });
    };
}
export default {
    ACTION_ESCROW_STATE_STATEMENT_VERSION,
    ACTION_ESCROW_STATE_STATEMENT_DOMAIN,
    signActionEscrowStateStatement,
    verifyActionEscrowStateStatement,
    createActionEscrowStatePackageVerifier,
};
//# sourceMappingURL=action-escrow-state.js.map