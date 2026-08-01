// SPDX-License-Identifier: Apache-2.0
/**
 * Relying-party-pinned WebAuthn evidence for one closed AP2 payment action.
 *
 * This adapter verifies a human-authorization ceremony over exact AP2 source
 * commitments and an exact provider-effect request identity. It does not
 * verify native AP2 credentials, grant local authorization, reserve one-time
 * execution authority, prove provider commitment, or prove an observed
 * effect. Those remain separate AEB/Gate decisions.
 */
import crypto from 'node:crypto';
// The CAID reference implementation intentionally has no TypeScript surface.
// @ts-expect-error -- runtime output is checked before use.
import { computeCaid } from '../vendor/caid.mjs';
import { canonicalizeAeb, digestAeb, mappingProfileDigest, } from './aeb-adapter-contract.js';
import { strictJsonGate } from './strict-json.js';
export const FIDO_AP2_SOURCE_REVISION = 'google-agentic-commerce/AP2@e1ea56db72a6385bce3e5c1112b3a56ce60acb43';
export const FIDO_AP2_EVIDENCE_VERSION = 'EP-FIDO-AP2-EVIDENCE-v1';
export const FIDO_AP2_AEB_ADAPTER_ID = 'fido-ap2:webauthn-human-authorization';
export const FIDO_AP2_AEB_ADAPTER_VERSION = '1';
export const FIDO_AP2_AEB_CONFIG_VERSION = 'EP-FIDO-AP2-AEB-CONFIG-v1';
export const FIDO_AP2_AEB_TRUST_ROOT_VERSION = 'EP-FIDO-AP2-P256-ROOT-v1';
export const FIDO_AP2_CAID_MAPPING_VERSION = 'EP-FIDO-AP2-CAID-MAPPING-v1';
export const FIDO_AP2_CAID_MAPPER_ID = 'mapper:fido-ap2-closed-payment-v1';
export const FIDO_AP2_CAID_PROFILE_ID = 'profile:fido-ap2-closed-payment-v1';
export const FIDO_AP2_ACTION_TYPE = 'payment.purchase.1';
export const FIDO_AP2_NATIVE_PROTOCOL_ID = 'ap2:v0.2-closed-checkout-payment';
export const FIDO_AP2_SOURCE_BYTES_DOMAIN = 'EP-FIDO-AP2-CANONICAL-TOKEN-v1';
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const RFC3339_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/;
const CURRENCY_RE = /^[A-Z]{3}$/;
const RP_ID_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$/;
const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_BE = 0x08;
const FLAG_BS = 0x10;
const ALLOWED_ASSERTION_FLAGS = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS;
const MAX_JSON_DEPTH = 64;
const MAX_NATIVE_SOURCE_BYTES = 8 * 1024 * 1024;
const MAX_AUTHENTICATOR_DATA_BYTES = 64;
const MAX_CLIENT_DATA_BYTES = 8 * 1024;
const MAX_SIGNATURE_BYTES = 128;
const MAX_PUBLIC_KEY_BYTES = 512;
function canonicalCompactJwt(value) {
    const segments = value.split('.');
    return segments.length === 3
        && segments.every((segment) => segment.length > 0
            && /^[A-Za-z0-9_-]+$/.test(segment)
            && segment.length % 4 !== 1
            && Buffer.from(segment, 'base64url').toString('base64url') === segment);
}
function canonicalSingleSdJwtToken(value, name) {
    if (typeof value !== 'string' || value.length === 0 || value.includes('~~')
        || /[^\x21-\x7e]/.test(value)) {
        throw new TypeError(`${name} must be one canonical AP2 SD-JWT token`);
    }
    const parts = value.split('~');
    if (parts.length < 2 || !canonicalCompactJwt(parts[0])) {
        throw new TypeError(`${name} must be one canonical AP2 SD-JWT token`);
    }
    const tail = parts.at(-1);
    const disclosures = value.endsWith('~') ? parts.slice(1, -1) : parts.slice(1, -1);
    if (disclosures.some((part) => part.length === 0
        || !/^[A-Za-z0-9_-]+$/.test(part)
        || part.length % 4 === 1
        || Buffer.from(part, 'base64url').toString('base64url') !== part)) {
        throw new TypeError(`${name} has a non-canonical disclosure list`);
    }
    if (!value.endsWith('~') && !canonicalCompactJwt(tail)) {
        throw new TypeError(`${name} has a malformed key-binding JWT`);
    }
    const compactParts = [parts[0], ...disclosures, ...(value.endsWith('~') ? [''] : [tail])];
    if (compactParts.join('~') !== value) {
        throw new TypeError(`${name} is not canonical`);
    }
    const bytes = Buffer.from(value, 'ascii');
    if (bytes.length === 0 || bytes.length > MAX_NATIVE_SOURCE_BYTES) {
        throw new TypeError(`${name} length is outside the closed v1 limit`);
    }
    return bytes;
}
function sourceBytesDigest(label, value) {
    const bytes = canonicalSingleSdJwtToken(value, label);
    return domainBytesDigest(label, bytes);
}
function authenticatedCheckoutHashAlgorithm(token) {
    const bytes = canonicalSingleSdJwtToken(token, 'checkout-mandate-token');
    const payloadSegment = bytes.toString('ascii').split('~', 1)[0].split('.')[1];
    let payload;
    try {
        const text = new TextDecoder('utf-8', { fatal: true })
            .decode(Buffer.from(payloadSegment, 'base64url'));
        if (!strictJsonGate(text).ok)
            throw new TypeError('invalid issuer payload');
        payload = JSON.parse(text);
    }
    catch {
        throw new TypeError('checkout mandate issuer payload is invalid');
    }
    if (!isRecord(payload)) {
        throw new TypeError('checkout mandate issuer payload is invalid');
    }
    const algorithm = payload._sd_alg ?? 'sha-256';
    if (!['sha-256', 'sha-384', 'sha-512'].includes(String(algorithm))) {
        throw new TypeError('checkout mandate _sd_alg is unsupported');
    }
    return algorithm;
}
function domainBytesDigest(label, bytes) {
    const hash = crypto.createHash('sha256');
    hash.update(FIDO_AP2_SOURCE_BYTES_DOMAIN, 'utf8');
    hash.update('\0', 'utf8');
    hash.update(label, 'utf8');
    hash.update('\0', 'utf8');
    hash.update(String(bytes.length), 'utf8');
    hash.update(':', 'utf8');
    hash.update(bytes);
    return `sha256:${hash.digest('hex')}`;
}
/**
 * Commit the exact token bytes, resolved payloads, and checkout hash algorithm
 * accepted by one successful native AP2 verification.
 *
 * Token identity remains byte-exact. Payloads use the strict AEB JSON domain;
 * together the two commitments prevent token/object splicing.
 */
export function createFidoAp2NativeSourceBinding(input) {
    const expectedKeys = [
        'checkout_mandate_token',
        'payment_mandate_token',
        'checkout_mandate_payload',
        'payment_mandate_payload',
    ];
    if (input === null || typeof input !== 'object' || Array.isArray(input)
        || Object.getPrototypeOf(input) !== Object.prototype
        || Reflect.ownKeys(input).length !== expectedKeys.length) {
        throw new TypeError('closed FIDO/AP2 native source binding input required');
    }
    const values = new Map();
    for (const key of expectedKeys) {
        const descriptor = Object.getOwnPropertyDescriptor(input, key);
        if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
            throw new TypeError('closed FIDO/AP2 native source binding input required');
        }
        values.set(key, descriptor.value);
    }
    const checkoutPayload = values.get('checkout_mandate_payload');
    const paymentPayload = values.get('payment_mandate_payload');
    if (!isRecord(checkoutPayload) || !isStrictJsonValue(checkoutPayload)
        || !isRecord(paymentPayload) || !isStrictJsonValue(paymentPayload)) {
        throw new TypeError('strict JSON AP2 payloads required');
    }
    const base = {
        source_revision: FIDO_AP2_SOURCE_REVISION,
        checkout_mandate_token_digest: sourceBytesDigest('checkout-mandate-token', values.get('checkout_mandate_token')),
        payment_mandate_token_digest: sourceBytesDigest('payment-mandate-token', values.get('payment_mandate_token')),
        checkout_mandate_payload_digest: digestAeb(checkoutPayload),
        payment_mandate_payload_digest: digestAeb(paymentPayload),
        checkout_hash_algorithm: authenticatedCheckoutHashAlgorithm(values.get('checkout_mandate_token')),
    };
    return Object.freeze({
        ...base,
        native_artifact_digest: digestAeb(base),
    });
}
const ARTIFACT_KEYS = new Set([
    '@version', 'source_revision', 'tenant_id', 'relying_party_id', 'audience',
    'operation_id', 'effect_request_digest', 'provider',
    'source_commitments', 'normalized_action', 'disclosure', 'signoff',
]);
const PROVIDER_KEYS = new Set(['provider_id', 'account_id', 'environment']);
const SOURCE_COMMITMENT_KEYS = new Set([
    'checkout_mandate_token_digest', 'payment_mandate_token_digest',
    'native_verification_attestation_digest',
]);
const CHECKOUT_MANDATE_KEYS = new Set(['vct', 'checkout_jwt', 'checkout_hash', 'iat', 'exp']);
const PAYMENT_MANDATE_KEYS = new Set([
    'vct', 'transaction_id', 'payee', 'pisp', 'payment_amount',
    'payment_instrument', 'execution_date', 'risk_data', 'iat', 'exp',
]);
const PAYMENT_MANDATE_OPTIONAL_KEYS = new Set(['pisp', 'execution_date', 'risk_data']);
const MERCHANT_KEYS = new Set(['id', 'name', 'website']);
const AMOUNT_KEYS = new Set(['amount', 'currency']);
const PAYMENT_INSTRUMENT_KEYS = new Set(['id', 'type', 'description']);
const PISP_KEYS = new Set(['legal_name', 'brand_name', 'domain_name']);
const DISCLOSURE_KEYS = new Set([
    'checkout_commitment', 'payment_commitment',
    'checkout_payload_jwt_commitment', 'transaction_id',
    'amount_minor', 'currency', 'payee_id', 'payee_name',
    'payment_instrument_id', 'payment_instrument_type', 'execution',
    'source_expires_at',
]);
const SIGNOFF_KEYS = new Set(['context', 'webauthn']);
const CONTEXT_KEYS = new Set([
    'source_revision', 'tenant_id', 'relying_party_id', 'audience',
    'operation_id', 'effect_request_digest', 'provider',
    'source_commitments', 'normalized_action_digest', 'caid', 'disclosure_digest',
    'approver_id', 'nonce', 'expires_at',
]);
const WEBAUTHN_KEYS = new Set([
    'credential_id', 'authenticator_data', 'client_data_json', 'signature',
]);
const CLIENT_DATA_KEYS = new Set(['type', 'challenge', 'origin', 'crossOrigin']);
const CONFIG_KEYS = new Set([
    '@version', 'source_revision', 'evidence_role', 'subject', 'tenant_id',
    'relying_party_id', 'audience', 'action_type', 'rp_id', 'allowed_origins', 'expected_nonce',
    'max_status_age_seconds', 'sign_count_policy', 'allow_backup_eligible',
    'allow_backup_state',
]);
const SUBJECT_KEYS = new Set(['id', 'kind', 'native_id']);
const ROOT_KEYS = new Set([
    '@version', 'source_revision', 'approver_id', 'credential_id',
    'public_key_spki', 'rp_id', 'key_class', 'status', 'sign_count',
]);
const STATUS_KEYS = new Set([
    'checked_at', 'expires_at', 'revocation_checked', 'revoked', 'consumed',
    'unavailable',
]);
const ACTION_KEYS = new Set([
    'action_type', 'checkout_mandate_digest', 'payment_mandate_digest',
    'checkout_payload_jwt_digest', 'transaction_id', 'amount_minor', 'currency',
    'payee_id', 'payee_name', 'payee_website_digest', 'pisp_digest',
    'payment_instrument_id', 'payment_instrument_type',
    'payment_instrument_description_digest', 'risk_data_digest', 'execution',
    'source_expires_at',
]);
const PROFILE_KEYS = new Set([
    'version', 'definition', 'registry_entry_ref', 'mapper_id', 'resolver',
    'semantic_equivalence', 'profile_digest',
]);
const PROFILE_DEFINITION_KEYS = new Set([
    '@version', 'source_revision', 'projection', 'action_type', 'suite',
    'definitions',
]);
export const FIDO_AP2_CAID_ACTION_DEFINITIONS = Object.freeze([Object.freeze({
        action_type: FIDO_AP2_ACTION_TYPE,
        required_fields: Object.freeze([
            Object.freeze({ name: 'checkout_mandate_digest', type: 'digest' }),
            Object.freeze({ name: 'payment_mandate_digest', type: 'digest' }),
            Object.freeze({ name: 'checkout_payload_jwt_digest', type: 'digest' }),
            Object.freeze({ name: 'transaction_id', type: 'string' }),
            Object.freeze({ name: 'amount_minor', type: 'integer' }),
            Object.freeze({ name: 'currency', type: 'string' }),
            Object.freeze({ name: 'payee_id', type: 'string' }),
            Object.freeze({ name: 'payee_name', type: 'string' }),
            Object.freeze({ name: 'payee_website_digest', type: 'digest' }),
            Object.freeze({ name: 'pisp_digest', type: 'digest' }),
            Object.freeze({ name: 'payment_instrument_id', type: 'string' }),
            Object.freeze({ name: 'payment_instrument_type', type: 'string' }),
            Object.freeze({ name: 'payment_instrument_description_digest', type: 'digest' }),
            Object.freeze({ name: 'risk_data_digest', type: 'digest' }),
            Object.freeze({ name: 'execution', type: 'enum', values: Object.freeze(['immediate']) }),
            Object.freeze({ name: 'source_expires_at', type: 'timestamp' }),
        ]),
        optional_fields: Object.freeze([]),
    })]);
export const FIDO_AP2_CAID_RESOLVER_DIGEST = digestAeb({
    mapper_id: FIDO_AP2_CAID_MAPPER_ID,
    version: '1',
    source_revision: FIDO_AP2_SOURCE_REVISION,
    projection: 'ap2-v0.2-closed-checkout-payment-immediate-v1',
    action_type: FIDO_AP2_ACTION_TYPE,
    suite: 'jcs-sha256',
    definitions: FIDO_AP2_CAID_ACTION_DEFINITIONS,
});
function isRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function exactKeys(value, keys, optional = new Set()) {
    const own = Object.keys(value);
    return own.every((key) => keys.has(key))
        && [...keys].every((key) => optional.has(key) || Object.hasOwn(value, key));
}
function nonEmptyString(value, maxLength = 1024) {
    return typeof value === 'string' && value.length > 0 && value.length <= maxLength
        && !/[\u0000-\u001f\u007f]/.test(value) && wellFormedUnicode(value);
}
function wellFormedUnicode(value) {
    for (let index = 0; index < value.length; index += 1) {
        const code = value.charCodeAt(index);
        if (code >= 0xd800 && code <= 0xdbff) {
            const next = value.charCodeAt(index + 1);
            if (!(next >= 0xdc00 && next <= 0xdfff))
                return false;
            index += 1;
        }
        else if (code >= 0xdc00 && code <= 0xdfff)
            return false;
    }
    return true;
}
function validDigest(value) {
    return typeof value === 'string' && DIGEST_RE.test(value);
}
function nonNegativeInteger(value) {
    return Number.isSafeInteger(value) && Number(value) >= 0;
}
function parseInstant(value) {
    if (typeof value !== 'string')
        return NaN;
    const match = RFC3339_RE.exec(value);
    if (!match)
        return NaN;
    const [, year, month, day, hour, minute, second, fraction = ''] = match;
    // This profile accepts only clock precision the JavaScript runtime can
    // compare without truncation. Higher precision must fail closed.
    const milliseconds = Number(fraction.padEnd(3, '0').slice(0, 3));
    const date = new Date(0);
    date.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
    date.setUTCHours(Number(hour), Number(minute), Number(second), milliseconds);
    if (date.toISOString().slice(0, 19) !== `${year}-${month}-${day}T${hour}:${minute}:${second}`)
        return NaN;
    return date.getTime();
}
function isStrictJsonValue(value, seen = new WeakSet(), depth = 0) {
    if (depth > MAX_JSON_DEPTH)
        return false;
    if (value === null || typeof value === 'boolean')
        return true;
    if (typeof value === 'string')
        return wellFormedUnicode(value);
    if (typeof value === 'number')
        return Number.isFinite(value);
    if (typeof value !== 'object')
        return false;
    if (seen.has(value))
        return false;
    seen.add(value);
    try {
        if (Array.isArray(value)) {
            if (Object.getPrototypeOf(value) !== Array.prototype)
                return false;
            const ownKeys = Reflect.ownKeys(value);
            if (ownKeys.some((key) => typeof key === 'symbol'))
                return false;
            if (ownKeys.length !== value.length + 1)
                return false;
            if (ownKeys.some((key) => key !== 'length'
                && (!/^(0|[1-9][0-9]*)$/.test(String(key))
                    || Number(key) >= value.length)))
                return false;
            for (let index = 0; index < value.length; index += 1) {
                const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
                if (!descriptor || !Object.hasOwn(descriptor, 'value')
                    || !isStrictJsonValue(descriptor.value, seen, depth + 1))
                    return false;
            }
            return true;
        }
        if (!isRecord(value))
            return false;
        for (const key of Reflect.ownKeys(value)) {
            if (typeof key !== 'string' || !wellFormedUnicode(key))
                return false;
            const descriptor = Object.getOwnPropertyDescriptor(value, key);
            if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')
                || !isStrictJsonValue(descriptor.value, seen, depth + 1))
                return false;
        }
        return true;
    }
    finally {
        seen.delete(value);
    }
}
function decodeBase64url(value, maxDecodedBytes = 64 * 1024) {
    if (typeof value !== 'string' || value.length === 0
        || value.length > Math.ceil(maxDecodedBytes * 4 / 3) + 2
        || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1)
        return null;
    try {
        const bytes = Buffer.from(value, 'base64url');
        return bytes.length > 0 && bytes.length <= maxDecodedBytes
            && bytes.toString('base64url') === value ? bytes : null;
    }
    catch {
        return null;
    }
}
function validOrigin(value) {
    if (!nonEmptyString(value, 2048))
        return false;
    try {
        const parsed = new URL(value);
        return parsed.protocol === 'https:' && parsed.username === '' && parsed.password === ''
            && parsed.pathname === '/' && parsed.search === '' && parsed.hash === ''
            && parsed.origin === value;
    }
    catch {
        return false;
    }
}
function validRpId(value) {
    return typeof value === 'string' && value === value.toLowerCase() && RP_ID_RE.test(value);
}
function safeDigest(value) {
    try {
        return digestAeb(value);
    }
    catch {
        return digestAeb({ invalid_fido_ap2_value: true });
    }
}
function tryDigest(value) {
    try {
        return digestAeb(value);
    }
    catch {
        return null;
    }
}
function statusDigest(status) {
    return safeDigest({
        checked_at: status?.checked_at,
        expires_at: status?.expires_at,
        revocation_checked: status?.revocation_checked,
        revoked: status?.revoked,
        consumed: status?.consumed,
        unavailable: status?.unavailable === true,
    });
}
function uniqueStrings(value) {
    return Array.isArray(value) && value.length > 0 && value.every((item) => nonEmptyString(item))
        && new Set(value).size === value.length;
}
function ap2HashB64url(algorithm, value) {
    return crypto.createHash(algorithm.replace('-', ''))
        .update(value, 'ascii').digest('base64url');
}
function digestOptional(value) {
    return safeDigest(value === undefined ? null : value);
}
function parseEpoch(value) {
    return Number.isSafeInteger(value) && Number(value) > 0 ? Number(value) : null;
}
function parseCheckoutMandate(value, algorithm) {
    if (!isRecord(value) || !exactKeys(value, CHECKOUT_MANDATE_KEYS)
        || value.vct !== 'mandate.checkout.1'
        || !nonEmptyString(value.checkout_jwt, MAX_NATIVE_SOURCE_BYTES)
        || !canonicalCompactJwt(value.checkout_jwt)
        || !nonEmptyString(value.checkout_hash)
        || value.checkout_hash !== ap2HashB64url(algorithm, value.checkout_jwt)
        || parseEpoch(value.iat) === null || parseEpoch(value.exp) === null
        || Number(value.iat) >= Number(value.exp))
        return null;
    return value;
}
function parsePaymentMandate(value) {
    if (!isRecord(value) || !exactKeys(value, PAYMENT_MANDATE_KEYS, PAYMENT_MANDATE_OPTIONAL_KEYS)
        || value.vct !== 'mandate.payment.1'
        || !nonEmptyString(value.transaction_id)
        || !isRecord(value.payee) || !exactKeys(value.payee, MERCHANT_KEYS, new Set(['website']))
        || !nonEmptyString(value.payee.id) || !nonEmptyString(value.payee.name)
        || (value.payee.website !== undefined && !nonEmptyString(value.payee.website, 2048))
        || !isRecord(value.payment_amount) || !exactKeys(value.payment_amount, AMOUNT_KEYS)
        || !Number.isSafeInteger(value.payment_amount.amount) || Number(value.payment_amount.amount) <= 0
        || typeof value.payment_amount.currency !== 'string' || !CURRENCY_RE.test(value.payment_amount.currency)
        || !isRecord(value.payment_instrument)
        || !exactKeys(value.payment_instrument, PAYMENT_INSTRUMENT_KEYS, new Set(['description']))
        || !nonEmptyString(value.payment_instrument.id) || !nonEmptyString(value.payment_instrument.type)
        || (value.payment_instrument.description !== undefined
            && !nonEmptyString(value.payment_instrument.description, 4096))
        || (value.pisp !== undefined
            && (!isRecord(value.pisp) || !exactKeys(value.pisp, PISP_KEYS)
                || !nonEmptyString(value.pisp.legal_name) || !nonEmptyString(value.pisp.brand_name)
                || !nonEmptyString(value.pisp.domain_name)))
        || value.execution_date !== undefined
        || (value.risk_data !== undefined && !isRecord(value.risk_data))
        || parseEpoch(value.iat) === null || parseEpoch(value.exp) === null
        || Number(value.iat) >= Number(value.exp))
        return null;
    return value;
}
function parseSourceBinding(value) {
    if (!isRecord(value) || !exactKeys(value, new Set([
        'source_revision', 'checkout_mandate_token_digest',
        'payment_mandate_token_digest', 'checkout_mandate_payload_digest',
        'payment_mandate_payload_digest', 'checkout_hash_algorithm',
        'native_artifact_digest',
    ])) || value.source_revision !== FIDO_AP2_SOURCE_REVISION
        || !validDigest(value.checkout_mandate_token_digest)
        || !validDigest(value.payment_mandate_token_digest)
        || !validDigest(value.checkout_mandate_payload_digest)
        || !validDigest(value.payment_mandate_payload_digest)
        || !['sha-256', 'sha-384', 'sha-512'].includes(String(value.checkout_hash_algorithm))
        || !validDigest(value.native_artifact_digest))
        return null;
    const base = {
        source_revision: FIDO_AP2_SOURCE_REVISION,
        checkout_mandate_token_digest: value.checkout_mandate_token_digest,
        payment_mandate_token_digest: value.payment_mandate_token_digest,
        checkout_mandate_payload_digest: value.checkout_mandate_payload_digest,
        payment_mandate_payload_digest: value.payment_mandate_payload_digest,
        checkout_hash_algorithm: value.checkout_hash_algorithm,
    };
    return digestAeb(base) === value.native_artifact_digest
        ? value : null;
}
function parseAp2(value) {
    if (!isStrictJsonValue(value) || !isRecord(value)
        || !exactKeys(value, new Set(['checkout_mandate', 'payment_mandate', 'source_binding'])))
        return null;
    const source = parseSourceBinding(value.source_binding);
    if (!source)
        return null;
    const checkout = parseCheckoutMandate(value.checkout_mandate, source.checkout_hash_algorithm);
    const payment = parsePaymentMandate(value.payment_mandate);
    if (!checkout || !payment || payment.transaction_id !== checkout.checkout_hash)
        return null;
    if (digestAeb(checkout) !== source.checkout_mandate_payload_digest) {
        throw new TypeError('verified AP2 checkout payload binding mismatch');
    }
    if (digestAeb(payment) !== source.payment_mandate_payload_digest) {
        throw new TypeError('verified AP2 payment payload binding mismatch');
    }
    const expiresEpoch = Math.min(Number(checkout.exp), Number(payment.exp));
    const sourceExpiresAt = new Date(expiresEpoch * 1_000).toISOString();
    return {
        action: {
            action_type: FIDO_AP2_ACTION_TYPE,
            checkout_mandate_digest: source.checkout_mandate_token_digest,
            payment_mandate_digest: source.payment_mandate_token_digest,
            checkout_payload_jwt_digest: domainBytesDigest('checkout-payload-jwt', Buffer.from(checkout.checkout_jwt, 'ascii')),
            transaction_id: payment.transaction_id,
            amount_minor: payment.payment_amount.amount,
            currency: payment.payment_amount.currency,
            payee_id: payment.payee.id,
            payee_name: payment.payee.name,
            payee_website_digest: digestOptional(payment.payee.website),
            pisp_digest: digestOptional(payment.pisp),
            payment_instrument_id: payment.payment_instrument.id,
            payment_instrument_type: payment.payment_instrument.type,
            payment_instrument_description_digest: digestOptional(payment.payment_instrument.description),
            risk_data_digest: digestOptional(payment.risk_data),
            execution: 'immediate',
            source_expires_at: sourceExpiresAt,
        },
        source_expires_at: sourceExpiresAt,
    };
}
function validAction(value) {
    return isStrictJsonValue(value) && isRecord(value) && exactKeys(value, ACTION_KEYS)
        && value.action_type === FIDO_AP2_ACTION_TYPE
        && validDigest(value.checkout_mandate_digest) && validDigest(value.payment_mandate_digest)
        && validDigest(value.checkout_payload_jwt_digest) && nonEmptyString(value.transaction_id)
        && Number.isSafeInteger(value.amount_minor) && Number(value.amount_minor) > 0
        && typeof value.currency === 'string' && CURRENCY_RE.test(value.currency)
        && nonEmptyString(value.payee_id) && nonEmptyString(value.payee_name)
        && validDigest(value.payee_website_digest) && validDigest(value.pisp_digest)
        && nonEmptyString(value.payment_instrument_id) && nonEmptyString(value.payment_instrument_type)
        && validDigest(value.payment_instrument_description_digest)
        && validDigest(value.risk_data_digest) && value.execution === 'immediate'
        && Number.isFinite(parseInstant(value.source_expires_at));
}
/** Project only the pinned AP2 v0.2 closed CheckoutMandate/PaymentMandate subset. */
export function projectFidoAp2PaymentAction(input) {
    const parsed = parseAp2(input);
    if (!parsed)
        throw new TypeError('unsupported or inconsistent closed AP2 payment mandate');
    return { ...parsed.action };
}
function parseConfig(value) {
    if (!isStrictJsonValue(value) || !isRecord(value) || !exactKeys(value, CONFIG_KEYS)
        || value['@version'] !== FIDO_AP2_AEB_CONFIG_VERSION
        || value.source_revision !== FIDO_AP2_SOURCE_REVISION
        || value.evidence_role !== 'human_authorization'
        || !isRecord(value.subject) || !exactKeys(value.subject, SUBJECT_KEYS)
        || !nonEmptyString(value.subject.id) || value.subject.kind !== 'human'
        || !nonEmptyString(value.subject.native_id) || !nonEmptyString(value.tenant_id)
        || !nonEmptyString(value.relying_party_id) || !nonEmptyString(value.audience)
        || value.action_type !== FIDO_AP2_ACTION_TYPE || !validRpId(value.rp_id)
        || !Array.isArray(value.allowed_origins) || value.allowed_origins.length === 0
        || !value.allowed_origins.every(validOrigin)
        || !value.allowed_origins.every((origin) => {
            const host = new URL(origin).hostname.toLowerCase();
            return host === value.rp_id || host.endsWith(`.${value.rp_id}`);
        })
        || new Set(value.allowed_origins).size !== value.allowed_origins.length
        || !nonEmptyString(value.expected_nonce) || !nonNegativeInteger(value.max_status_age_seconds)
        || !['above-enrollment-and-one-time', 'not-relied-upon']
            .includes(String(value.sign_count_policy))
        || typeof value.allow_backup_eligible !== 'boolean'
        || typeof value.allow_backup_state !== 'boolean')
        return null;
    return {
        evidence_role: 'human_authorization',
        subject: { id: value.subject.id, kind: 'human', native_id: value.subject.native_id },
        tenant_id: value.tenant_id,
        relying_party_id: value.relying_party_id,
        audience: value.audience,
        action_type: FIDO_AP2_ACTION_TYPE,
        rp_id: value.rp_id,
        allowed_origins: [...value.allowed_origins],
        expected_nonce: value.expected_nonce,
        max_status_age_seconds: value.max_status_age_seconds,
        sign_count_policy: value.sign_count_policy,
        allow_backup_eligible: value.allow_backup_eligible,
        allow_backup_state: value.allow_backup_state,
    };
}
function p256PublicKey(value) {
    const der = decodeBase64url(value, MAX_PUBLIC_KEY_BYTES);
    if (!der)
        return null;
    try {
        const key = crypto.createPublicKey({ key: der, type: 'spki', format: 'der' });
        const canonical = key.export({ type: 'spki', format: 'der' });
        const jwk = key.export({ format: 'jwk' });
        if (!Buffer.isBuffer(canonical) || !canonical.equals(der) || key.type !== 'public'
            || key.asymmetricKeyType !== 'ec' || jwk.kty !== 'EC' || jwk.crv !== 'P-256'
            || !nonEmptyString(jwk.x) || !nonEmptyString(jwk.y))
            return null;
        return { encoded: value, key };
    }
    catch {
        return null;
    }
}
function parseRoot(value, config) {
    if (!isStrictJsonValue(value) || !isRecord(value) || !exactKeys(value, ROOT_KEYS)
        || value['@version'] !== FIDO_AP2_AEB_TRUST_ROOT_VERSION
        || value.source_revision !== FIDO_AP2_SOURCE_REVISION
        || value.approver_id !== config.subject.id
        || value.credential_id !== config.subject.native_id
        || value.rp_id !== config.rp_id || value.key_class !== 'A'
        || value.status !== 'active' || !nonNegativeInteger(value.sign_count)
        || value.sign_count > 0xffffffff)
        return null;
    const publicKey = p256PublicKey(value.public_key_spki);
    if (!publicKey)
        return null;
    return {
        approver_id: value.approver_id,
        credential_id: value.credential_id,
        public_key_spki: publicKey.encoded,
        public_key: publicKey.key,
        rp_id: value.rp_id,
        sign_count: value.sign_count,
    };
}
function parseSourceCommitments(value) {
    if (!isRecord(value) || !exactKeys(value, SOURCE_COMMITMENT_KEYS)
        || !validDigest(value.checkout_mandate_token_digest)
        || !validDigest(value.payment_mandate_token_digest)
        || !validDigest(value.native_verification_attestation_digest))
        return null;
    return value;
}
function parseProvider(value) {
    if (!isRecord(value) || !exactKeys(value, PROVIDER_KEYS)
        || !nonEmptyString(value.provider_id) || !nonEmptyString(value.account_id)
        || !nonEmptyString(value.environment))
        return null;
    return value;
}
function parseContext(value) {
    if (!isRecord(value) || !exactKeys(value, CONTEXT_KEYS)
        || !nonEmptyString(value.source_revision) || !nonEmptyString(value.tenant_id)
        || !nonEmptyString(value.relying_party_id) || !nonEmptyString(value.audience)
        || !nonEmptyString(value.operation_id) || !validDigest(value.effect_request_digest)
        || !parseProvider(value.provider)
        || !parseSourceCommitments(value.source_commitments)
        || !validDigest(value.normalized_action_digest) || !nonEmptyString(value.caid)
        || !validDigest(value.disclosure_digest) || !nonEmptyString(value.approver_id)
        || !nonEmptyString(value.nonce) || !Number.isFinite(parseInstant(value.expires_at)))
        return null;
    return value;
}
function parseDisclosure(value) {
    if (!isRecord(value) || !exactKeys(value, DISCLOSURE_KEYS)
        || !validDigest(value.checkout_commitment) || !validDigest(value.payment_commitment)
        || !nonEmptyString(value.transaction_id)
        || !Number.isSafeInteger(value.amount_minor) || Number(value.amount_minor) <= 0
        || typeof value.currency !== 'string' || !CURRENCY_RE.test(value.currency)
        || !nonEmptyString(value.payee_id) || !nonEmptyString(value.payee_name)
        || !nonEmptyString(value.payment_instrument_id)
        || !nonEmptyString(value.payment_instrument_type)
        || value.execution !== 'immediate'
        || !Number.isFinite(parseInstant(value.source_expires_at)))
        return null;
    return value;
}
function parseArtifact(value) {
    if (!isStrictJsonValue(value) || !isRecord(value) || !exactKeys(value, ARTIFACT_KEYS)
        || value['@version'] !== FIDO_AP2_EVIDENCE_VERSION
        || !nonEmptyString(value.source_revision) || !nonEmptyString(value.tenant_id)
        || !nonEmptyString(value.relying_party_id) || !nonEmptyString(value.audience)
        || !nonEmptyString(value.operation_id) || !validDigest(value.effect_request_digest)
        || !parseProvider(value.provider)
        || !parseSourceCommitments(value.source_commitments)
        || !validAction(value.normalized_action) || !parseDisclosure(value.disclosure)
        || !isRecord(value.signoff)
        || !exactKeys(value.signoff, SIGNOFF_KEYS) || !parseContext(value.signoff.context)
        || !isRecord(value.signoff.webauthn) || !exactKeys(value.signoff.webauthn, WEBAUTHN_KEYS)
        || !nonEmptyString(value.signoff.webauthn.credential_id)
        || decodeBase64url(value.signoff.webauthn.authenticator_data, MAX_AUTHENTICATOR_DATA_BYTES) === null
        || decodeBase64url(value.signoff.webauthn.client_data_json, MAX_CLIENT_DATA_BYTES) === null
        || decodeBase64url(value.signoff.webauthn.signature, MAX_SIGNATURE_BYTES) === null)
        return null;
    return value;
}
function statusDisposition(status, now, maxAgeSeconds) {
    if (!isStrictJsonValue(status) || !isRecord(status)
        || !exactKeys(status, STATUS_KEYS, new Set(['unavailable']))) {
        return { acceptance: 'INDETERMINATE', reasons: ['status_malformed'] };
    }
    const reasons = [];
    if (status.unavailable === true)
        reasons.push('status_unavailable');
    if (status.revoked === true)
        reasons.push('evidence_revoked');
    if (status.consumed === true)
        reasons.push('evidence_consumed');
    if (status.revocation_checked !== true)
        reasons.push('revocation_not_checked');
    if (typeof status.revocation_checked !== 'boolean' || typeof status.revoked !== 'boolean'
        || typeof status.consumed !== 'boolean'
        || (status.unavailable !== undefined && typeof status.unavailable !== 'boolean'))
        reasons.push('status_malformed');
    const nowMs = parseInstant(now);
    const checkedMs = parseInstant(status.checked_at);
    const expiresMs = parseInstant(status.expires_at);
    if (!Number.isFinite(nowMs) || !Number.isFinite(checkedMs) || !Number.isFinite(expiresMs)) {
        reasons.push('status_time_invalid');
    }
    else {
        const ageSeconds = Math.floor((nowMs - checkedMs) / 1000);
        if (checkedMs > nowMs)
            reasons.push('status_checked_in_future');
        if (checkedMs >= expiresMs || nowMs >= expiresMs)
            reasons.push('status_expired');
        if (ageSeconds < 0 || ageSeconds > maxAgeSeconds)
            reasons.push('status_stale');
    }
    const unique = [...new Set(reasons)].sort();
    if (status.revoked === true || status.consumed === true)
        return { acceptance: 'REJECTED', reasons: unique };
    return unique.length === 0
        ? { acceptance: 'ACCEPTED', reasons: [] }
        : { acceptance: 'INDETERMINATE', reasons: unique };
}
function verifyWebAuthnAssertion(artifact, config, root) {
    const reasons = [];
    const webauthn = artifact.signoff.webauthn;
    if (webauthn.credential_id !== root.credential_id)
        reasons.push('credential_id_mismatch');
    const clientDataBytes = decodeBase64url(webauthn.client_data_json, MAX_CLIENT_DATA_BYTES);
    const authData = decodeBase64url(webauthn.authenticator_data, MAX_AUTHENTICATOR_DATA_BYTES);
    const signature = decodeBase64url(webauthn.signature, MAX_SIGNATURE_BYTES);
    if (!clientDataBytes || !authData || !signature) {
        return { verified: false, reasons: ['webauthn_encoding_invalid'], sign_count: null };
    }
    let clientData = null;
    try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(clientDataBytes);
        if (strictJsonGate(text).ok) {
            const parsed = JSON.parse(text);
            if (isStrictJsonValue(parsed) && isRecord(parsed)
                && exactKeys(parsed, CLIENT_DATA_KEYS, new Set(['crossOrigin'])))
                clientData = parsed;
        }
    }
    catch {
        clientData = null;
    }
    if (!clientData) {
        return { verified: false, reasons: ['client_data_invalid'], sign_count: null };
    }
    const expectedChallenge = crypto.createHash('sha256')
        .update(canonicalizeAeb(artifact.signoff.context), 'utf8').digest('base64url');
    if (clientData.type !== 'webauthn.get')
        reasons.push('client_data_type_invalid');
    if (clientData.challenge !== expectedChallenge)
        reasons.push('challenge_binding_mismatch');
    if (!config.allowed_origins.includes(clientData.origin) || clientData.crossOrigin === true) {
        reasons.push('origin_refused');
    }
    if (clientData.crossOrigin !== undefined && typeof clientData.crossOrigin !== 'boolean') {
        reasons.push('cross_origin_malformed');
    }
    if (authData.length !== 37)
        reasons.push('authenticator_data_not_closed_v1');
    if (authData.length < 37)
        return { verified: false, reasons: [...new Set(reasons)].sort(), sign_count: null };
    const expectedRpIdHash = crypto.createHash('sha256').update(config.rp_id, 'utf8').digest();
    if (!authData.subarray(0, 32).equals(expectedRpIdHash))
        reasons.push('rp_id_hash_mismatch');
    const flags = authData[32];
    if ((flags & ~ALLOWED_ASSERTION_FLAGS) !== 0)
        reasons.push('authenticator_flags_unsupported');
    if ((flags & FLAG_UP) !== FLAG_UP)
        reasons.push('user_presence_required');
    if ((flags & FLAG_UV) !== FLAG_UV)
        reasons.push('user_verification_required');
    if ((flags & FLAG_BS) === FLAG_BS && (flags & FLAG_BE) !== FLAG_BE)
        reasons.push('backup_state_without_eligibility');
    if (!config.allow_backup_eligible && (flags & FLAG_BE) === FLAG_BE)
        reasons.push('backup_eligible_refused');
    if (!config.allow_backup_state && (flags & FLAG_BS) === FLAG_BS)
        reasons.push('backup_state_refused');
    const signCount = authData.readUInt32BE(33);
    if (config.sign_count_policy === 'above-enrollment-and-one-time'
        && signCount <= root.sign_count) {
        reasons.push('sign_count_not_above_enrollment');
    }
    const signedData = Buffer.concat([
        authData,
        crypto.createHash('sha256').update(clientDataBytes).digest(),
    ]);
    let signatureValid = false;
    try {
        signatureValid = crypto.verify('sha256', signedData, root.public_key, signature);
    }
    catch {
        signatureValid = false;
    }
    if (!signatureValid)
        reasons.push('webauthn_signature_invalid');
    return { verified: reasons.length === 0, reasons: [...new Set(reasons)].sort(), sign_count: signCount };
}
function fallbackNative(input, config) {
    const evidenceDigest = safeDigest(input?.artifact);
    return {
        native_verification: 'FAILED',
        acceptance: 'INDETERMINATE',
        evidence_digest: evidenceDigest,
        status_digest: statusDigest(input?.status),
        evidence_role: config?.evidence_role ?? 'invalid-evidence',
        subject: config ? { id: config.subject.id, kind: 'human' } : { id: 'invalid-evidence', kind: 'system' },
        replay_unit: evidenceDigest,
        reasons: [],
    };
}
function caidForAction(action) {
    let result;
    try {
        result = computeCaid(action, {
            suite: 'jcs-sha256',
            definitions: FIDO_AP2_CAID_ACTION_DEFINITIONS,
        });
    }
    catch {
        return null;
    }
    if (!isRecord(result) || !nonEmptyString(result.caid) || !validDigest(result.digest))
        return null;
    return { caid: result.caid, digest: result.digest };
}
function exactDisclosure(disclosure, action) {
    return disclosure.checkout_commitment === action.checkout_mandate_digest
        && disclosure.payment_commitment === action.payment_mandate_digest
        && disclosure.checkout_payload_jwt_commitment === action.checkout_payload_jwt_digest
        && disclosure.transaction_id === action.transaction_id
        && disclosure.amount_minor === action.amount_minor
        && disclosure.currency === action.currency
        && disclosure.payee_id === action.payee_id
        && disclosure.payee_name === action.payee_name
        && disclosure.payment_instrument_id === action.payment_instrument_id
        && disclosure.payment_instrument_type === action.payment_instrument_type
        && disclosure.execution === action.execution
        && disclosure.source_expires_at === action.source_expires_at;
}
function exactSourceCommitments(left, right) {
    return [...SOURCE_COMMITMENT_KEYS].every((key) => left[key] === right[key]);
}
function exactProvider(left, right) {
    return [...PROVIDER_KEYS].every((key) => left[key] === right[key]);
}
function verifyNative(input) {
    const config = parseConfig(input?.adapter_config);
    const base = fallbackNative(input, config);
    if (!config) {
        base.reasons = ['pinned_config_invalid'];
        return base;
    }
    if (!Array.isArray(input.trust_roots) || input.trust_roots.length !== 1) {
        base.acceptance = 'REJECTED';
        base.reasons = ['exactly_one_pinned_trust_root_required'];
        return base;
    }
    const root = parseRoot(input.trust_roots[0], config);
    if (!root) {
        base.acceptance = 'REJECTED';
        base.reasons = ['pinned_p256_trust_root_invalid_or_inactive'];
        return base;
    }
    const artifact = parseArtifact(input.artifact);
    if (!artifact) {
        base.acceptance = 'REJECTED';
        base.reasons = ['fido_ap2_artifact_outside_closed_v1'];
        return base;
    }
    base.replay_unit = safeDigest({
        adapter_id: FIDO_AP2_AEB_ADAPTER_ID,
        source_revision: artifact.source_revision,
        tenant_id: artifact.tenant_id,
        relying_party_id: artifact.relying_party_id,
        audience: artifact.audience,
        operation_id: artifact.operation_id,
        effect_request_digest: artifact.effect_request_digest,
        provider: artifact.provider,
        approver_id: config.subject.id,
        credential_id: root.credential_id,
        nonce: artifact.signoff.context.nonce,
        context_digest: safeDigest(artifact.signoff.context),
    });
    const webauthn = verifyWebAuthnAssertion(artifact, config, root);
    if (!webauthn.verified) {
        base.acceptance = 'REJECTED';
        base.reasons = webauthn.reasons;
        return base;
    }
    // VERIFIED here means the pinned WebAuthn human-authorization artifact was
    // verified. It deliberately does not mean that AP2 itself was natively
    // verified.
    base.native_verification = 'VERIFIED';
    const nowMs = parseInstant(input.now);
    const context = artifact.signoff.context;
    const actionDigest = tryDigest(artifact.normalized_action);
    const disclosureDigest = tryDigest(artifact.disclosure);
    const caid = caidForAction(artifact.normalized_action);
    const reasons = [];
    if (!Number.isFinite(nowMs))
        reasons.push('verification_time_invalid');
    if (artifact.source_revision !== FIDO_AP2_SOURCE_REVISION
        || context.source_revision !== FIDO_AP2_SOURCE_REVISION)
        reasons.push('source_revision_mismatch');
    if (artifact.tenant_id !== config.tenant_id || context.tenant_id !== config.tenant_id) {
        reasons.push('tenant_id_mismatch');
    }
    if (artifact.relying_party_id !== config.relying_party_id
        || context.relying_party_id !== config.relying_party_id)
        reasons.push('relying_party_id_mismatch');
    if (artifact.audience !== config.audience || context.audience !== config.audience)
        reasons.push('audience_mismatch');
    if (artifact.operation_id !== context.operation_id)
        reasons.push('operation_id_mismatch');
    if (artifact.effect_request_digest !== context.effect_request_digest) {
        reasons.push('effect_request_digest_mismatch');
    }
    if (!exactProvider(artifact.provider, context.provider))
        reasons.push('provider_mismatch');
    if (context.approver_id !== config.subject.id)
        reasons.push('approver_mismatch');
    if (context.nonce !== config.expected_nonce)
        reasons.push('nonce_mismatch');
    if (!exactSourceCommitments(context.source_commitments, artifact.source_commitments)) {
        reasons.push('source_commitments_mismatch');
    }
    if (artifact.normalized_action.checkout_mandate_digest
        !== artifact.source_commitments.checkout_mandate_token_digest
        || artifact.normalized_action.payment_mandate_digest
            !== artifact.source_commitments.payment_mandate_token_digest) {
        reasons.push('action_source_commitment_mismatch');
    }
    if (actionDigest === null || context.normalized_action_digest !== actionDigest)
        reasons.push('normalized_action_digest_mismatch');
    if (!caid || caid.digest !== actionDigest || context.caid !== caid.caid)
        reasons.push('caid_mismatch');
    if (disclosureDigest === null || context.disclosure_digest !== disclosureDigest
        || !exactDisclosure(artifact.disclosure, artifact.normalized_action))
        reasons.push('disclosure_mismatch');
    const contextExpiry = parseInstant(context.expires_at);
    const sourceExpiry = parseInstant(artifact.normalized_action.source_expires_at);
    if (!Number.isFinite(nowMs) || nowMs >= contextExpiry)
        reasons.push('authorization_context_expired');
    if (!Number.isFinite(sourceExpiry) || nowMs >= sourceExpiry
        || contextExpiry > sourceExpiry)
        reasons.push('ap2_source_expiry_mismatch');
    if (reasons.length > 0) {
        base.acceptance = 'REJECTED';
        base.reasons = [...new Set(reasons)].sort();
        return base;
    }
    const currentStatus = statusDisposition(input.status, input.now, config.max_status_age_seconds);
    base.acceptance = currentStatus.acceptance;
    base.reasons = currentStatus.reasons;
    return base;
}
function cloneDefinitions() {
    return FIDO_AP2_CAID_ACTION_DEFINITIONS.map((definition) => ({
        action_type: definition.action_type,
        required_fields: definition.required_fields.map((field) => ({ ...field })),
        optional_fields: [],
    }));
}
function deepFreeze(value) {
    if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
        for (const child of Object.values(value))
            deepFreeze(child);
        Object.freeze(value);
    }
    return value;
}
/** Return the one immutable mapping profile implemented by this bridge. */
export function createFidoAp2PinnedProfile() {
    const profile = {
        version: FIDO_AP2_CAID_MAPPING_VERSION,
        definition: {
            '@version': FIDO_AP2_CAID_MAPPING_VERSION,
            source_revision: FIDO_AP2_SOURCE_REVISION,
            projection: 'ap2-v0.2-closed-checkout-payment-immediate-v1',
            action_type: FIDO_AP2_ACTION_TYPE,
            suite: 'jcs-sha256',
            definitions: cloneDefinitions(),
        },
        registry_entry_ref: FIDO_AP2_CAID_PROFILE_ID,
        mapper_id: FIDO_AP2_CAID_MAPPER_ID,
        resolver: {
            id: FIDO_AP2_CAID_MAPPER_ID,
            version: '1',
            implementation_digest: FIDO_AP2_CAID_RESOLVER_DIGEST,
        },
        semantic_equivalence: {
            assertion: 'EQUIVALENT_UNDER_PROFILE',
            loss_policy: 'NO_MATERIAL_FIELD_LOSS',
            omitted_material_fields: [],
            omitted_nonmaterial_fields: [],
        },
        profile_digest: ('sha256:' + '0'.repeat(64)),
    };
    profile.profile_digest = mappingProfileDigest(FIDO_AP2_CAID_PROFILE_ID, profile);
    return deepFreeze(profile);
}
function exactProfile(value) {
    if (!isStrictJsonValue(value) || !isRecord(value) || !exactKeys(value, PROFILE_KEYS)
        || !isRecord(value.definition) || !exactKeys(value.definition, PROFILE_DEFINITION_KEYS))
        return false;
    try {
        return canonicalizeAeb(value) === canonicalizeAeb(createFidoAp2PinnedProfile());
    }
    catch {
        return false;
    }
}
function mapAction(input) {
    if (input.native?.native_verification !== 'VERIFIED' || input.native.acceptance !== 'ACCEPTED') {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_acceptance_required'] };
    }
    const config = parseConfig(input.adapter_config);
    if (!config || !exactProfile(input.profile)) {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['pinned_mapping_profile_invalid'] };
    }
    const artifact = parseArtifact(input.artifact);
    if (!artifact) {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['human_artifact_invalid'] };
    }
    const actionDigest = tryDigest(artifact.normalized_action);
    if (!actionDigest || !validAction(input.expected_action)) {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['expected_action_invalid'] };
    }
    const expectedDigest = tryDigest(input.expected_action);
    if (!expectedDigest) {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['expected_action_not_canonicalizable'] };
    }
    if (actionDigest !== expectedDigest) {
        return {
            mapping: 'MISMATCH', caid: null, action_digest: actionDigest,
            reasons: ['normalized_action_mismatch'],
        };
    }
    const computed = caidForAction(artifact.normalized_action);
    if (!computed || computed.digest !== actionDigest
        || computed.caid !== artifact.signoff.context.caid
        || artifact.signoff.context.normalized_action_digest !== actionDigest) {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['caid_digest_disagreement'] };
    }
    return { mapping: 'MATCH', caid: computed.caid, action_digest: actionDigest, reasons: [] };
}
/** Build the fixed bridge. No presenter-controlled constructor options exist. */
export function createFidoAp2AebAdapter() {
    return Object.freeze({
        id: FIDO_AP2_AEB_ADAPTER_ID,
        version: FIDO_AP2_AEB_ADAPTER_VERSION,
        verifyNative(input) {
            try {
                return verifyNative(input);
            }
            catch {
                const config = parseConfig(input?.adapter_config);
                const result = fallbackNative(input, config);
                result.reasons = ['unexpected_fido_ap2_verification_error'];
                return result;
            }
        },
        mapAction(input) {
            try {
                return mapAction(input);
            }
            catch {
                return {
                    mapping: 'INDETERMINATE', caid: null, action_digest: null,
                    reasons: ['unexpected_fido_ap2_mapping_error'],
                };
            }
        },
    });
}
//# sourceMappingURL=fido-ap2-bridge.js.map