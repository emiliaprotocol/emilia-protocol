// @ts-nocheck
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
import { verifyAgileSignatureSet, ML_DSA_65_PUBLIC_KEY_BYTES, } from '@emilia-protocol/verify/pq-signature-agility';
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
// ===========================================================================
// EP-ACTION-ESCROW-STATE-STATEMENT-v2 -- the hybrid (Ed25519 + ML-DSA-65) state
// statement.
// ===========================================================================
/**
 * REFERENCE-DERIVED HYBRID MIGRATION. This copies, move for move, the reference
 * hybrid migration documented in docs/protocol/pq-hybrid-program.md, section
 * "PATTERN: the reference hybrid migration" (EP-REVOCATION-v2 in
 * packages/verify/src/revocation.ts). The five moves, applied to the escrow
 * state statement:
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of
 *    `signature`, a wire-format change, so the artifact takes a new `version`
 *    marker (EP-ACTION-ESCROW-STATE-STATEMENT-v2). The v1 verifier above is
 *    untouched and refuses a v2 statement on its `structure` check (the version
 *    marker) before inspecting any signature, and never throws.
 * 2. SET SHAPE. `signature` carries `required_algorithms` plus a `signatures`
 *    array shaped exactly like EP-SIG-AGILITY-v1's AgileSignature
 *    ({ alg, sig, key_id? }), one entry per algorithm in the registered order.
 *    Ed25519 keeps its base64url SPKI DER public key; ML-DSA-65 carries raw
 *    base64url public key bytes.
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is committed INSIDE the
 *    signed bytes (stateV2SigningBytes below). Drop the ML-DSA leg and narrow
 *    `required_algorithms` and the surviving Ed25519 signature no longer
 *    verifies, because the bytes changed. This is a byte-level commitment,
 *    strictly stronger than EP-SIG-AGILITY-v1's relying-party `hybrid_all`
 *    policy alone. The verifier rebuilds the bytes from the REGISTERED set.
 * 4. V1 COMPATIBILITY. v1 statements keep verifying through the unchanged
 *    synchronous verifier; v2 verification is ASYNC (ML-DSA verification is
 *    async), so it is a SEPARATE entry point, with verifyActionEscrowStateStatementAny()
 *    routing on the version marker. The v1 verifier is never made async.
 * 5. NAMED REFUSALS. Every failure sets a named check false and pushes a
 *    readable reason; nothing throws on caller input. An absent ML-DSA backend
 *    is 'pq_backend_unavailable' surfaced through the agility result, never a
 *    skipped check and never a pass on the classical leg.
 *
 * HONEST BOUNDARIES carry over from v1: verification authenticates an operator
 * statement over one snapshot; it does not prove the operator's database was
 * complete or that a custodian moved money. The ML-DSA backend is
 * @noble/post-quantum's pure-JS FIPS 204 implementation, not independently
 * audited and not a FIPS validated module. v2 does NOT retroactively protect
 * statements already issued under v1.
 */
export const ACTION_ESCROW_STATE_STATEMENT_V2_VERSION = 'EP-ACTION-ESCROW-STATE-STATEMENT-v2';
export const ACTION_ESCROW_STATE_STATEMENT_V2_DOMAIN = `${ACTION_ESCROW_STATE_STATEMENT_V2_VERSION}\0`;
/** The registered required algorithm set, in canonical order. */
export const ACTION_ESCROW_STATE_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65']);
const TOP_V2_KEYS = new Set(['version', 'issuer', 'payload', 'statement_digest', 'signature']);
const SIGNATURE_V2_KEYS = new Set([
    'profile', 'required_algorithms', 'public_key', 'key_id',
    'pq_public_key', 'pq_key_id', 'signatures',
]);
function stateV2AlgorithmSetRegistered(algorithms) {
    return Array.isArray(algorithms)
        && algorithms.length === ACTION_ESCROW_STATE_V2_REQUIRED_ALGORITHMS.length
        && algorithms.every((a, i) => a === ACTION_ESCROW_STATE_V2_REQUIRED_ALGORITHMS[i]);
}
/**
 * The bytes BOTH legs sign: the same domain-separated canonical body as v1
 * (version, issuer, payload) plus the committed `required_algorithms` set,
 * under the v2 domain tag. Recomputed independently by the verifier from the
 * PRESENTED fields and the REGISTERED set. See PATTERN move 3.
 */
export function stateV2SigningBytes(statement, requiredAlgorithms = ACTION_ESCROW_STATE_V2_REQUIRED_ALGORITHMS) {
    if (!stateV2AlgorithmSetRegistered(requiredAlgorithms)) {
        throw new TypeError('stateV2SigningBytes: algorithm set is not the registered EP-ACTION-ESCROW-STATE-STATEMENT-v2 set');
    }
    const body = boundedCanonicalCopy({
        version: statement.version,
        issuer: statement.issuer,
        payload: statement.payload,
        required_algorithms: [...requiredAlgorithms],
    });
    return Buffer.from(ACTION_ESCROW_STATE_STATEMENT_V2_DOMAIN + canonicalize(body), 'utf8');
}
/** ML-DSA-65 public-key identifier: the SHA-256 of the raw public key bytes. */
function stateEscrowPqKeyId(publicKeyRawB64u) {
    try {
        if (typeof publicKeyRawB64u !== 'string' || publicKeyRawB64u.length === 0)
            return '';
        const raw = Buffer.from(publicKeyRawB64u, 'base64url');
        if (raw.length !== ML_DSA_65_PUBLIC_KEY_BYTES || raw.toString('base64url') !== publicKeyRawB64u)
            return '';
        return `ep:escrow-operator-key:ml-dsa-65:sha256:${crypto.createHash('sha256').update(raw).digest('hex')}`;
    }
    catch {
        return '';
    }
}
/** Ed25519 curve-pinned public-key identifier: SHA-256 of the SPKI DER. */
function stateEscrowEdKeyId(publicKeyB64u) {
    try {
        if (typeof publicKeyB64u !== 'string' || publicKeyB64u.length === 0)
            return '';
        const der = Buffer.from(publicKeyB64u, 'base64url');
        if (der.length === 0 || der.toString('base64url') !== publicKeyB64u)
            return '';
        const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
        if (key.asymmetricKeyType !== 'ed25519')
            return '';
        return `ep:escrow-operator-key:sha256:${crypto.createHash('sha256').update(der).digest('hex')}`;
    }
    catch {
        return '';
    }
}
function stateEscrowAgilityPassthrough(opts) {
    const out = {};
    if (opts?.mldsaBackend !== undefined)
        out.mldsaBackend = opts.mldsaBackend;
    if (opts?.mldsaBackendLoader !== undefined)
        out.mldsaBackendLoader = opts.mldsaBackendLoader;
    return out;
}
function refuseV2(reason, checks) {
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
 * FAIL-CLOSED hybrid verifier for one EP-ACTION-ESCROW-STATE-STATEMENT-v2. Never
 * throws on caller input; a v2 statement NEVER verifies on one leg alone. See
 * the PATTERN reference above.
 */
export async function verifyActionEscrowStateStatementV2(statement, { trustedKeys, stateRecord, expectedAgreementId, expectedBindingDigest, expectedActionDigest, expectedProfileDigest, expectedState, expectedRevision, expectedAmendmentDigests, expectedPreviousStatementDigest, now, mldsaBackend, mldsaBackendLoader, } = {}) {
    const checks = {
        structure: false,
        payload: false,
        issuer_pin: false,
        algorithm_set: false,
        legs_present: false,
        signature: false,
        statement_digest: false,
        state_record: false,
        expected_bindings: false,
        time: false,
    };
    try {
        // 1. Version marker + closed top-level shape. A v1 statement refuses here,
        //    the mirror image of the v1 verifier refusing a v2 statement.
        checks.structure = exactKeys(statement, TOP_V2_KEYS)
            && statement.version === ACTION_ESCROW_STATE_STATEMENT_V2_VERSION
            && exactKeys(statement.issuer, ISSUER_KEYS)
            && exactKeys(statement.signature, SIGNATURE_V2_KEYS)
            && statement.signature.profile === ACTION_ESCROW_STATE_STATEMENT_V2_VERSION;
        if (!checks.structure)
            return refuseV2('malformed_state_statement', checks);
        checks.payload = payloadValid(statement.payload);
        if (!checks.payload)
            return refuseV2('invalid_state_payload', checks);
        // 2. Operator keys: BOTH halves pinned, and the presented halves must equal
        //    the pinned ones. Identified-but-not-trusted, per leg.
        const pin = isRecord(trustedKeys) && Object.hasOwn(trustedKeys, statement.issuer.key_id)
            ? trustedKeys[statement.issuer.key_id]
            : null;
        const presentedEdKey = statement.signature.public_key;
        const presentedPqKey = statement.signature.pq_public_key;
        checks.issuer_pin = exactKeys(pin, new Set(['operator_id', 'public_key', 'pq_public_key']))
            && pin.operator_id === statement.issuer.operator_id
            && typeof pin.public_key === 'string' && pin.public_key.length > 0
            && typeof pin.pq_public_key === 'string' && pin.pq_public_key.length > 0
            && pin.public_key === presentedEdKey
            && pin.pq_public_key === presentedPqKey;
        if (!checks.issuer_pin)
            return refuseV2('operator_key_not_pinned', checks);
        // Key identifiers, curve-pinned: an Ed448 (or any non-Ed25519) SPKI
        // masquerading as the Ed25519 half fails here as well as in the signature
        // check, because stateEscrowEdKeyId() derives nothing from a non-Ed25519 SPKI.
        const derivedEdKeyId = stateEscrowEdKeyId(presentedEdKey);
        const derivedPqKeyId = stateEscrowPqKeyId(presentedPqKey);
        if (!derivedEdKeyId || statement.signature.key_id !== derivedEdKeyId
            || !derivedPqKeyId || statement.signature.pq_key_id !== derivedPqKeyId) {
            return refuseV2('operator_key_not_pinned', checks);
        }
        // 3. Committed algorithm set: exact and order-sensitive. A narrowed or
        //    widened set is refused structurally here and, independently, by the
        //    signature check, which rebuilds the bytes from the REGISTERED set.
        checks.algorithm_set = stateV2AlgorithmSetRegistered(statement.signature.required_algorithms);
        if (!checks.algorithm_set)
            return refuseV2('state_algorithm_set_invalid', checks);
        // 4. Exactly one signature per required algorithm; no duplicates, no
        //    unexpected algorithms, no missing (stripped) legs.
        const signatures = Array.isArray(statement.signature.signatures) ? statement.signature.signatures : null;
        if (!signatures || signatures.length === 0)
            return refuseV2('state_signature_legs_missing', checks);
        const presented = new Set();
        for (const s of signatures) {
            if (!isRecord(s) || typeof s.alg !== 'string' || typeof s.sig !== 'string') {
                return refuseV2('state_signature_leg_malformed', checks);
            }
            if (presented.has(s.alg))
                return refuseV2('state_signature_leg_duplicate', checks);
            presented.add(s.alg);
        }
        for (const alg of presented) {
            if (!ACTION_ESCROW_STATE_V2_REQUIRED_ALGORITHMS.includes(alg)) {
                return refuseV2('state_signature_leg_unexpected', checks);
            }
        }
        for (const alg of ACTION_ESCROW_STATE_V2_REQUIRED_ALGORITHMS) {
            if (!presented.has(alg))
                return refuseV2('state_signature_leg_stripped', checks);
        }
        checks.legs_present = true;
        // 5. Signature set: both legs, over bytes rebuilt from the PRESENTED fields
        //    and the REGISTERED algorithm set, under the PINNED keys. Policy
        //    'hybrid_all' with requiredAlgorithms pinned to the full set.
        const bytes = stateV2SigningBytes(statement, ACTION_ESCROW_STATE_V2_REQUIRED_ALGORITHMS);
        const verificationKeys = [
            { alg: 'Ed25519', public_key: pin.public_key, key_id: derivedEdKeyId },
            { alg: 'ML-DSA-65', public_key: pin.pq_public_key, key_id: derivedPqKeyId },
        ];
        let setResult = null;
        try {
            setResult = await verifyAgileSignatureSet(new Uint8Array(bytes), signatures, verificationKeys, {
                ...stateEscrowAgilityPassthrough({ mldsaBackend, mldsaBackendLoader }),
                policy: 'hybrid_all',
                requiredAlgorithms: [...ACTION_ESCROW_STATE_V2_REQUIRED_ALGORITHMS],
            });
        }
        catch {
            setResult = null;
        }
        checks.signature = setResult?.verified === true;
        if (!checks.signature) {
            const reason = String(setResult?.reason ?? 'signature_set_unverified');
            return refuseV2(`state_signature_invalid (${reason})`, checks);
        }
        const digest = `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
        checks.statement_digest = statement.statement_digest === digest;
        if (!checks.statement_digest)
            return refuseV2('state_statement_digest_mismatch', checks);
        checks.state_record = canonicalHash(boundedCanonicalCopy(stateRecord))
            === statement.payload.state_record_digest;
        if (!checks.state_record)
            return refuseV2('state_record_digest_mismatch', checks);
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
            && statement.payload.amendment_digests.every((entry, index) => entry === amendments[index])
            && statement.payload.previous_statement_digest === expectedPreviousStatementDigest;
        if (!checks.expected_bindings)
            return refuseV2('state_expected_binding_mismatch', checks);
        const evaluation = now instanceof Date
            ? now.getTime()
            : typeof now === 'number' ? now : strictInstant(now);
        checks.time = Number.isFinite(evaluation)
            && strictInstant(statement.payload.occurred_at) <= evaluation;
        if (!checks.time)
            return refuseV2('state_statement_from_future', checks);
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
        return refuseV2('malformed_state_statement', checks);
    }
}
/**
 * Route a statement of EITHER version to its verifier. v1 statements keep the
 * exact v1 verdict (synchronous path, wrapped); v2 statements get the hybrid
 * check. A statement whose `version` is neither refuses through the v1 verifier,
 * which is the fail-closed answer.
 */
export async function verifyActionEscrowStateStatementAny(statement, options = {}) {
    if (isRecord(statement) && statement.version === ACTION_ESCROW_STATE_STATEMENT_V2_VERSION) {
        return verifyActionEscrowStateStatementV2(statement, options);
    }
    return verifyActionEscrowStateStatement(statement, options);
}
export default {
    ACTION_ESCROW_STATE_STATEMENT_VERSION,
    ACTION_ESCROW_STATE_STATEMENT_DOMAIN,
    ACTION_ESCROW_STATE_STATEMENT_V2_VERSION,
    ACTION_ESCROW_STATE_STATEMENT_V2_DOMAIN,
    ACTION_ESCROW_STATE_V2_REQUIRED_ALGORITHMS,
    signActionEscrowStateStatement,
    verifyActionEscrowStateStatement,
    verifyActionEscrowStateStatementV2,
    verifyActionEscrowStateStatementAny,
    stateV2SigningBytes,
    createActionEscrowStatePackageVerifier,
};
//# sourceMappingURL=action-escrow-state.js.map