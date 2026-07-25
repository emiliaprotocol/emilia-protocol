// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Complete-mediation boundary for provider effects.
 *
 * Gate presents a short-lived signed execution envelope. The actuator verifies
 * every binding under immutable local pins, atomically reserves the envelope,
 * and only then enters a provider callback that owns its credential. Provider
 * credentials are deliberately absent from every public type in this module.
 */
import { createHash, createPrivateKey, createPublicKey, sign, verify, } from 'node:crypto';
import { canonicalize } from './execution-binding.js';
export const CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION = 'EP-CONSEQUENCE-ACTUATOR-ENVELOPE-v1';
export const CONSEQUENCE_ACTUATOR_SIGNATURE_ALGORITHM = 'Ed25519';
export const CONSEQUENCE_ACTUATOR_SIGNATURE_DOMAIN = 'EP-CONSEQUENCE-ACTUATOR-ENVELOPE-v1';
export const DEFAULT_CONSEQUENCE_ACTUATOR_MAX_TTL_MS = 60_000;
export const DEFAULT_CONSEQUENCE_ACTUATOR_CLOCK_SKEW_MS = 2_000;
export const CONSEQUENCE_ACTUATOR_STORE_TABLE = 'public.consequence_actuator_envelopes';
export const CONSEQUENCE_ACTUATOR_EXECUTOR_ROLE = 'consequence_actuator_executor';
export const CONSEQUENCE_ACTUATOR_STORE_OWNER_ROLE = 'consequence_actuator_store_owner';
export const CONSEQUENCE_ACTUATOR_SQL = deepFreeze({
    reserve: `SELECT envelope_digest
FROM consequence_actuator_private.reserve_envelope(
  $1::text, $2::text, $3::text, $4::text, $5::text, $6::text,
  $7::text, $8::text, $9::text, $10::timestamptz, $11::timestamptz,
  $12::text
)`,
    consume: `SELECT envelope_digest
FROM consequence_actuator_private.consume_envelope(
  $1::text, $2::text, $3::text, $4::text, $5::text, $6::text,
  $7::text, $8::text, $9::text, $10::text, $11::text
)`,
});
const MAX_CONFIGURED_TTL_MS = 5 * 60_000;
const MAX_CLOCK_SKEW_MS = 30_000;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const CAID_PATTERN = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const ENVELOPE_KEYS = ['payload', 'signature'];
const PAYLOAD_KEYS = [
    '@version',
    'issuer_id',
    'tenant_id',
    'attempt_id',
    'action_digest',
    'caid',
    'provider_account_id',
    'target_digest',
    'operation',
    'idempotency_key',
    'nonce',
    'issued_at',
    'expires_at',
];
const SIGNATURE_KEYS = ['algorithm', 'key_id', 'value'];
function isRecord(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function exactKeys(value, expected) {
    const keys = Reflect.ownKeys(value);
    return keys.length === expected.length
        && keys.every((key) => typeof key === 'string' && expected.includes(key));
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
function canonicalClone(value) {
    const canonical = canonicalize(value);
    return {
        canonical,
        value: deepFreeze(JSON.parse(canonical)),
    };
}
function validIdentifier(value) {
    return typeof value === 'string'
        && IDENTIFIER_PATTERN.test(value)
        && Buffer.byteLength(value, 'utf8') <= 256;
}
function validDigest(value) {
    return typeof value === 'string' && DIGEST_PATTERN.test(value);
}
function canonicalInstant(value) {
    if (typeof value !== 'string')
        return null;
    const milliseconds = Date.parse(value);
    if (!Number.isSafeInteger(milliseconds) || milliseconds < 0)
        return null;
    return new Date(milliseconds).toISOString() === value ? milliseconds : null;
}
function decodeCanonicalBase64Url(value, minimumBytes, maximumBytes) {
    if (typeof value !== 'string' || !BASE64URL_PATTERN.test(value))
        return null;
    const bytes = Buffer.from(value, 'base64url');
    if (bytes.length < minimumBytes
        || bytes.length > maximumBytes
        || bytes.toString('base64url') !== value) {
        return null;
    }
    return bytes;
}
function nowMilliseconds(now) {
    const value = typeof now === 'function' ? now() : (now ?? Date.now());
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError('consequence actuator clock must return a non-negative safe integer');
    }
    return value;
}
function normalizePrivateKey(value) {
    const key = typeof value === 'object' && value !== null && 'type' in value
        ? value
        : createPrivateKey(value);
    if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') {
        throw new TypeError('execution envelopes require an Ed25519 private key');
    }
    return key;
}
function isKeyObject(value) {
    return typeof value === 'object'
        && value !== null
        && 'type' in value
        && ['private', 'public', 'secret'].includes(value.type);
}
function normalizePublicKey(value) {
    let imported;
    if (isKeyObject(value)) {
        if (value.type !== 'public') {
            throw new TypeError('the actuator must receive a public verification key');
        }
        imported = value;
    }
    else {
        imported = createPublicKey(value);
    }
    if (imported.type !== 'public'
        || imported.asymmetricKeyType !== 'ed25519') {
        throw new TypeError('the actuator verification pin must be Ed25519');
    }
    const der = imported.export({ type: 'spki', format: 'der' });
    return createPublicKey({ key: Buffer.from(der), type: 'spki', format: 'der' });
}
function publicKeyFingerprint(key) {
    const der = key.export({ type: 'spki', format: 'der' });
    return `sha256:${createHash('sha256').update(der).digest('hex')}`;
}
function signatureInput(canonicalPayload) {
    return Buffer.concat([
        Buffer.from(CONSEQUENCE_ACTUATOR_SIGNATURE_DOMAIN, 'utf8'),
        Buffer.from([0]),
        Buffer.from(canonicalPayload, 'utf8'),
    ]);
}
function validatePayloadShape(value) {
    if (!isRecord(value) || !exactKeys(value, PAYLOAD_KEYS))
        return false;
    const issuedAt = canonicalInstant(value.issued_at);
    const expiresAt = canonicalInstant(value.expires_at);
    return value['@version'] === CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION
        && validIdentifier(value.issuer_id)
        && validIdentifier(value.tenant_id)
        && validIdentifier(value.attempt_id)
        && validDigest(value.action_digest)
        && typeof value.caid === 'string'
        && CAID_PATTERN.test(value.caid)
        && validIdentifier(value.provider_account_id)
        && validDigest(value.target_digest)
        && validIdentifier(value.operation)
        && validIdentifier(value.idempotency_key)
        && decodeCanonicalBase64Url(value.nonce, 16, 64) !== null
        && issuedAt !== null
        && expiresAt !== null
        && expiresAt > issuedAt;
}
function normalizePins(pins) {
    if (!isRecord(pins)) {
        throw new TypeError('consequence actuator pins are required');
    }
    if (!validIdentifier(pins.tenantId)
        || typeof pins.caid !== 'string'
        || !CAID_PATTERN.test(pins.caid)
        || !validIdentifier(pins.providerAccountId)
        || !validDigest(pins.targetDigest)
        || !validIdentifier(pins.operation)
        || !validIdentifier(pins.envelopeIssuerId)
        || !validIdentifier(pins.envelopeKeyId)) {
        throw new TypeError('consequence actuator pins are malformed');
    }
    const maxEnvelopeTtlMs = pins.maxEnvelopeTtlMs ?? DEFAULT_CONSEQUENCE_ACTUATOR_MAX_TTL_MS;
    const clockSkewMs = pins.clockSkewMs ?? DEFAULT_CONSEQUENCE_ACTUATOR_CLOCK_SKEW_MS;
    if (!Number.isSafeInteger(maxEnvelopeTtlMs)
        || maxEnvelopeTtlMs < 1
        || maxEnvelopeTtlMs > MAX_CONFIGURED_TTL_MS) {
        throw new TypeError('maxEnvelopeTtlMs must be between 1 millisecond and 5 minutes');
    }
    if (!Number.isSafeInteger(clockSkewMs)
        || clockSkewMs < 0
        || clockSkewMs > MAX_CLOCK_SKEW_MS) {
        throw new TypeError('clockSkewMs must be between 0 and 30 seconds');
    }
    const verificationKey = normalizePublicKey(pins.envelopePublicKey);
    const visible = deepFreeze({
        tenantId: pins.tenantId,
        caid: pins.caid,
        providerAccountId: pins.providerAccountId,
        targetDigest: pins.targetDigest,
        operation: pins.operation,
        envelopeIssuerId: pins.envelopeIssuerId,
        envelopeKeyId: pins.envelopeKeyId,
        envelopePublicKeyFingerprint: publicKeyFingerprint(verificationKey),
        maxEnvelopeTtlMs,
        clockSkewMs,
    });
    return { visible, verificationKey };
}
function verifyWithNormalizedPins(envelope, pins, expected, now) {
    let cloned;
    let canonicalEnvelope;
    try {
        const result = canonicalClone(envelope);
        cloned = result.value;
        canonicalEnvelope = result.canonical;
    }
    catch {
        return { ok: false, reason: 'malformed_envelope' };
    }
    if (!isRecord(cloned) || !exactKeys(cloned, ENVELOPE_KEYS)) {
        return { ok: false, reason: 'malformed_envelope' };
    }
    if (!isRecord(cloned.payload)) {
        return { ok: false, reason: 'malformed_envelope' };
    }
    if (cloned.payload['@version'] !== CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION) {
        return { ok: false, reason: 'unsupported_version' };
    }
    if (!validatePayloadShape(cloned.payload)) {
        return { ok: false, reason: 'malformed_envelope' };
    }
    if (!isRecord(cloned.signature)
        || !exactKeys(cloned.signature, SIGNATURE_KEYS)
        || cloned.signature.algorithm !== CONSEQUENCE_ACTUATOR_SIGNATURE_ALGORITHM
        || !validIdentifier(cloned.signature.key_id)) {
        return { ok: false, reason: 'malformed_envelope' };
    }
    const signatureBytes = decodeCanonicalBase64Url(cloned.signature.value, 64, 64);
    if (signatureBytes === null) {
        return { ok: false, reason: 'malformed_envelope' };
    }
    const payload = cloned.payload;
    const signature = cloned.signature;
    if (signature.key_id !== pins.visible.envelopeKeyId) {
        return { ok: false, reason: 'signer_key_mismatch' };
    }
    const canonicalPayload = canonicalize(payload);
    let validSignature = false;
    try {
        validSignature = verify(null, signatureInput(canonicalPayload), pins.verificationKey, signatureBytes);
    }
    catch {
        validSignature = false;
    }
    if (!validSignature) {
        return { ok: false, reason: 'signature_invalid' };
    }
    if (payload.issuer_id !== pins.visible.envelopeIssuerId) {
        return { ok: false, reason: 'issuer_mismatch' };
    }
    if (payload.tenant_id !== pins.visible.tenantId) {
        return { ok: false, reason: 'tenant_mismatch' };
    }
    if (payload.caid !== pins.visible.caid) {
        return { ok: false, reason: 'caid_mismatch' };
    }
    if (payload.provider_account_id !== pins.visible.providerAccountId) {
        return { ok: false, reason: 'provider_account_mismatch' };
    }
    if (payload.target_digest !== pins.visible.targetDigest) {
        return { ok: false, reason: 'target_mismatch' };
    }
    if (payload.operation !== pins.visible.operation) {
        return { ok: false, reason: 'operation_mismatch' };
    }
    if (payload.attempt_id !== expected.attemptId) {
        return { ok: false, reason: 'attempt_mismatch' };
    }
    if (payload.action_digest !== expected.actionDigest) {
        return { ok: false, reason: 'action_digest_mismatch' };
    }
    if (payload.idempotency_key !== expected.idempotencyKey) {
        return { ok: false, reason: 'idempotency_key_mismatch' };
    }
    let currentTime;
    try {
        currentTime = nowMilliseconds(now);
    }
    catch {
        return { ok: false, reason: 'malformed_envelope' };
    }
    const issuedAt = Date.parse(payload.issued_at);
    const expiresAt = Date.parse(payload.expires_at);
    if (issuedAt > currentTime + pins.visible.clockSkewMs) {
        return { ok: false, reason: 'envelope_not_yet_valid' };
    }
    if (expiresAt <= currentTime) {
        return { ok: false, reason: 'envelope_expired' };
    }
    if (expiresAt - issuedAt > pins.visible.maxEnvelopeTtlMs) {
        return { ok: false, reason: 'envelope_ttl_exceeded' };
    }
    return {
        ok: true,
        payload,
        envelopeDigest: `sha256:${createHash('sha256')
            .update(canonicalEnvelope)
            .digest('hex')}`,
    };
}
function reservationFrom(payload, envelopeDigest) {
    return deepFreeze({
        tenantId: payload.tenant_id,
        attemptId: payload.attempt_id,
        actionDigest: payload.action_digest,
        caid: payload.caid,
        providerAccountId: payload.provider_account_id,
        targetDigest: payload.target_digest,
        operation: payload.operation,
        idempotencyKey: payload.idempotency_key,
        nonce: payload.nonce,
        issuedAt: payload.issued_at,
        expiresAt: payload.expires_at,
        envelopeDigest,
    });
}
function refusal(reason, invoked, envelopeDigest) {
    return deepFreeze({
        ok: false,
        invoked,
        reason,
        ...(envelopeDigest === undefined ? {} : { envelopeDigest }),
    });
}
/** Create a closed Ed25519 execution envelope for an already-authorized effect. */
export function signConsequenceExecutionEnvelope(payload, options) {
    const cloned = canonicalClone(payload);
    if (!validatePayloadShape(cloned.value)) {
        throw new TypeError('execution envelope payload is malformed');
    }
    if (!validIdentifier(options?.keyId)) {
        throw new TypeError('execution envelope keyId is malformed');
    }
    const signature = sign(null, signatureInput(cloned.canonical), normalizePrivateKey(options.privateKey)).toString('base64url');
    return deepFreeze({
        payload: cloned.value,
        signature: {
            algorithm: CONSEQUENCE_ACTUATOR_SIGNATURE_ALGORITHM,
            key_id: options.keyId,
            value: signature,
        },
    });
}
/** Verify an envelope without invoking a provider or mutating replay state. */
export function verifyConsequenceExecutionEnvelope(envelope, options) {
    try {
        return verifyWithNormalizedPins(envelope, normalizePins(options.pins), options.expected, options.now);
    }
    catch {
        return { ok: false, reason: 'malformed_envelope' };
    }
}
/**
 * Credential-owning actuator. `perform` captures the provider credential in
 * the actuator process; callers cannot submit or replace that credential.
 */
export class ConsequenceActuator {
    pins;
    #normalizedPins;
    #reserve;
    #consume;
    #perform;
    #now;
    constructor(options) {
        if (!isRecord(options)
            || !isRecord(options.store)
            || typeof options.store.reserve !== 'function'
            || typeof options.store.consume !== 'function'
            || typeof options.perform !== 'function') {
            throw new TypeError('consequence actuator requires reserve/consume storage and a provider callback');
        }
        const productionCapable = options.store.durable === true
            && options.store.atomic === true
            && options.store.ownershipFenced === true
            && options.store.permanentConsumption === true;
        const explicitTestStore = options.store.testOnly === true
            && options.testOnly === true;
        if (!productionCapable && !explicitTestStore) {
            throw new TypeError('consequence actuator requires durable, atomic, ownership-fenced storage with permanent consumption; a non-production store requires testOnly: true');
        }
        this.#normalizedPins = normalizePins(options.pins);
        this.pins = this.#normalizedPins.visible;
        this.#reserve = options.store.reserve.bind(options.store);
        this.#consume = options.store.consume.bind(options.store);
        this.#perform = options.perform;
        this.#now = options.now;
        Object.freeze(this);
    }
    async execute(input) {
        const verified = verifyWithNormalizedPins(input?.envelope, this.#normalizedPins, {
            attemptId: input?.attemptId,
            actionDigest: input?.actionDigest,
            idempotencyKey: input?.idempotencyKey,
        }, this.#now);
        if (!verified.ok) {
            return refusal(verified.reason, false);
        }
        const reservation = reservationFrom(verified.payload, verified.envelopeDigest);
        let reserved = false;
        try {
            reserved = await this.#reserve(reservation);
        }
        catch {
            return refusal('store_reserve_failed', false, verified.envelopeDigest);
        }
        if (reserved !== true) {
            return refusal('envelope_replayed', false, verified.envelopeDigest);
        }
        let providerResult;
        try {
            providerResult = await this.#perform(verified.payload);
        }
        catch {
            try {
                const consumed = await this.#consume(deepFreeze({ ...reservation, outcome: 'INDETERMINATE' }));
                if (consumed !== true) {
                    return refusal('store_consume_unconfirmed', true, verified.envelopeDigest);
                }
            }
            catch {
                return refusal('store_consume_unconfirmed', true, verified.envelopeDigest);
            }
            return refusal('provider_outcome_indeterminate', true, verified.envelopeDigest);
        }
        try {
            const consumed = await this.#consume(deepFreeze({ ...reservation, outcome: 'COMMITTED' }));
            if (consumed !== true) {
                return refusal('store_consume_unconfirmed', true, verified.envelopeDigest);
            }
        }
        catch {
            return refusal('store_consume_unconfirmed', true, verified.envelopeDigest);
        }
        return deepFreeze({
            ok: true,
            invoked: true,
            result: providerResult,
            envelopeDigest: verified.envelopeDigest,
        });
    }
}
function reservationKey(tenantId, nonce) {
    return canonicalize([tenantId, nonce]);
}
function idempotencyKey(reservation) {
    return canonicalize([
        reservation.tenantId,
        reservation.providerAccountId,
        reservation.operation,
        reservation.idempotencyKey,
    ]);
}
function sameReservation(left, right) {
    const identity = (value) => ({
        tenantId: value.tenantId,
        attemptId: value.attemptId,
        actionDigest: value.actionDigest,
        caid: value.caid,
        providerAccountId: value.providerAccountId,
        targetDigest: value.targetDigest,
        operation: value.operation,
        idempotencyKey: value.idempotencyKey,
        nonce: value.nonce,
        issuedAt: value.issuedAt,
        expiresAt: value.expiresAt,
        envelopeDigest: value.envelopeDigest,
    });
    return canonicalize(identity(left)) === canonicalize(identity(right));
}
/**
 * Race-safe, process-local reference store for tests. Map mutations occur
 * before each async method yields, so concurrent calls have one reservation
 * winner. Production must use the RPC-only durable store from the migration.
 */
export class MemoryConsequenceActuatorStore {
    testOnly = true;
    durable = false;
    atomic = true;
    ownershipFenced = false;
    permanentConsumption = false;
    #records = new Map();
    #idempotency = new Map();
    #now;
    constructor(options = {}) {
        this.#now = options.now;
    }
    async reserve(reservation) {
        const key = reservationKey(reservation.tenantId, reservation.nonce);
        const operationKey = idempotencyKey(reservation);
        if (this.#records.has(key) || this.#idempotency.has(operationKey)) {
            return false;
        }
        const reservedAt = new Date(nowMilliseconds(this.#now)).toISOString();
        const snapshot = deepFreeze({
            ...reservation,
            state: 'RESERVED',
            outcome: null,
            reservedAt,
            consumedAt: null,
        });
        this.#records.set(key, snapshot);
        this.#idempotency.set(operationKey, key);
        return true;
    }
    async consume(consumption) {
        const key = reservationKey(consumption.tenantId, consumption.nonce);
        const current = this.#records.get(key);
        if (current === undefined
            || current.state !== 'RESERVED'
            || !sameReservation(current, consumption)
            || !['COMMITTED', 'INDETERMINATE'].includes(consumption.outcome)) {
            return false;
        }
        this.#records.set(key, deepFreeze({
            ...current,
            state: 'CONSUMED',
            outcome: consumption.outcome,
            consumedAt: new Date(nowMilliseconds(this.#now)).toISOString(),
        }));
        return true;
    }
    snapshot(tenantId, nonce) {
        const snapshot = this.#records.get(reservationKey(tenantId, nonce));
        if (snapshot === undefined)
            return null;
        return canonicalClone(snapshot).value;
    }
    get size() {
        return this.#records.size;
    }
}
export function createMemoryConsequenceActuatorStore(options = {}) {
    return new MemoryConsequenceActuatorStore(options);
}
const FORBIDDEN_EXECUTOR_PRINCIPALS = new Set([
    'anon',
    'authenticated',
    'postgres',
    'service_role',
    CONSEQUENCE_ACTUATOR_EXECUTOR_ROLE,
    CONSEQUENCE_ACTUATOR_STORE_OWNER_ROLE,
]);
function validStoreBinding(reservation) {
    const issuedAt = canonicalInstant(reservation?.issuedAt);
    const expiresAt = canonicalInstant(reservation?.expiresAt);
    return validIdentifier(reservation?.tenantId)
        && validIdentifier(reservation?.attemptId)
        && validDigest(reservation?.actionDigest)
        && typeof reservation?.caid === 'string'
        && CAID_PATTERN.test(reservation.caid)
        && validIdentifier(reservation?.providerAccountId)
        && validDigest(reservation?.targetDigest)
        && validIdentifier(reservation?.operation)
        && validIdentifier(reservation?.idempotencyKey)
        && decodeCanonicalBase64Url(reservation?.nonce, 16, 64) !== null
        && issuedAt !== null
        && expiresAt !== null
        && expiresAt > issuedAt
        && validDigest(reservation?.envelopeDigest);
}
function exactPostgresAcknowledgement(result, expectedEnvelopeDigest) {
    if (result !== null
        && typeof result === 'object'
        && result.rowCount === 0
        && Array.isArray(result.rows)
        && result.rows.length === 0) {
        return false;
    }
    if (result === null
        || typeof result !== 'object'
        || result.rowCount !== 1
        || !Array.isArray(result.rows)
        || result.rows.length !== 1
        || !isRecord(result.rows[0])
        || result.rows[0].envelope_digest !== expectedEnvelopeDigest) {
        throw new Error('consequence actuator store returned an ambiguous acknowledgement');
    }
    return true;
}
/**
 * Production adapter for the RPC-only PostgreSQL store. The supplied pool must
 * be dedicated to one tenant-mapped executor login; the adapter never emits
 * direct table SQL.
 */
export class PostgresConsequenceActuatorStore {
    durable = true;
    atomic = true;
    ownershipFenced = true;
    permanentConsumption = true;
    tenantId;
    executorPrincipal;
    #query;
    constructor(options) {
        if (!isRecord(options)
            || !validIdentifier(options.tenantId)
            || !validIdentifier(options.executorPrincipal)
            || FORBIDDEN_EXECUTOR_PRINCIPALS.has(options.executorPrincipal)
            || !isRecord(options.executorPool)
            || options.executorPool.principal !== options.executorPrincipal
            || typeof options.executorPool.query !== 'function') {
            throw new TypeError('a dedicated tenant executor principal and matching pool are required');
        }
        this.tenantId = options.tenantId;
        this.executorPrincipal = options.executorPrincipal;
        this.#query = options.executorPool.query.bind(options.executorPool);
        Object.freeze(this);
    }
    async reserve(reservation) {
        if (!validStoreBinding(reservation)
            || reservation.tenantId !== this.tenantId) {
            throw new TypeError('consequence actuator reservation does not match the store tenant');
        }
        const result = await this.#query(CONSEQUENCE_ACTUATOR_SQL.reserve, [
            reservation.tenantId,
            reservation.attemptId,
            reservation.actionDigest,
            reservation.caid,
            reservation.providerAccountId,
            reservation.targetDigest,
            reservation.operation,
            reservation.idempotencyKey,
            reservation.nonce,
            reservation.issuedAt,
            reservation.expiresAt,
            reservation.envelopeDigest,
        ]);
        return exactPostgresAcknowledgement(result, reservation.envelopeDigest);
    }
    async consume(consumption) {
        if (!validStoreBinding(consumption)
            || consumption.tenantId !== this.tenantId
            || !['COMMITTED', 'INDETERMINATE'].includes(consumption.outcome)) {
            throw new TypeError('consequence actuator consumption does not match the store tenant');
        }
        const result = await this.#query(CONSEQUENCE_ACTUATOR_SQL.consume, [
            consumption.tenantId,
            consumption.attemptId,
            consumption.actionDigest,
            consumption.caid,
            consumption.providerAccountId,
            consumption.targetDigest,
            consumption.operation,
            consumption.idempotencyKey,
            consumption.nonce,
            consumption.envelopeDigest,
            consumption.outcome,
        ]);
        return exactPostgresAcknowledgement(result, consumption.envelopeDigest);
    }
}
export function createPostgresConsequenceActuatorStore(options) {
    return new PostgresConsequenceActuatorStore(options);
}
//# sourceMappingURL=consequence-actuator.js.map