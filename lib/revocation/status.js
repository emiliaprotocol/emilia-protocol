// SPDX-License-Identifier: Apache-2.0
// Generated from status.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * Issuer-side builders for the closed EP-REVOKER-AUTHORITY-v1 and
 * EP-STATUS-v1 artifacts verified by packages/verify/src/status.ts.
 *
 * Private key material is intentionally outside this API. Callers inject an
 * async Ed25519 signer backed by their KMS/HSM (or by a test-only closure), and
 * the builders pass it only the exact domain-separated JCS signing bytes.
 */
import crypto from 'node:crypto';
import { REVOCER_AUTHORITY_DOMAIN, REVOCER_AUTHORITY_VERSION, STATUS_DOMAIN, STATUS_TARGET_TYPES, STATUS_TARGET_USAGES, STATUS_VERSION, revokerAuthorityCertificateDigest, statusArtifactDigest, verifyRevokerAuthorityCertificate, verifyStatusArtifact, REVOCER_AUTHORITY_V2_VERSION, REVOCER_AUTHORITY_V2_DOMAIN, REVOCER_AUTHORITY_V2_REQUIRED_ALGORITHMS, STATUS_V2_VERSION, STATUS_V2_DOMAIN, STATUS_V2_REQUIRED_ALGORITHMS, verifyRevokerAuthorityCertificateV2, verifyStatusArtifactV2, verifyRevokerAuthorityCertificateStatement, verifyStatusArtifactStatement, } from '../../packages/verify/status.js';
import { ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES } from '../../packages/verify/pq-signature-agility.js';
import { checkOperationPolicy } from '../../packages/verify/fips-mode.js';
// Kept byte-identical to the resolver in packages/verify/src/status.ts. The
// end-to-end conformance vectors (mint a registered foreign type here, accept
// it there under the same pinned registry) fail if these two ever drift.
const REGISTERED_NAME = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/;
function issuanceVocabulary(registry, key) {
    const core = key === 'types' ? STATUS_TARGET_TYPES : STATUS_TARGET_USAGES;
    const extra = registry ? registry[key] : undefined;
    if (!Array.isArray(extra) || extra.length === 0)
        return core;
    const out = [...core];
    for (const name of extra) {
        if (typeof name === 'string' && name.length <= 64 && REGISTERED_NAME.test(name)
            && !out.includes(name))
            out.push(name);
    }
    return out;
}
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const REVOKER_KEY_ID = /^ep:revoker-key:sha256:[0-9a-f]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/#@+-]{0,511}$/;
const AUTHORITY_DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const RFC3339_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const RAW_KEY_FIELD = /(?:private[_-]?key|privatekey|pkcs8|secret|seed)/i;
const AUTHORITY_INPUT_KEYS = [
    'certificateId',
    'authorityPin',
    'revokerId',
    'revokerPublicKey',
    'scope',
    'issuedAt',
    'expiresAt',
    'signer',
    'targetRegistry',
    'fipsPosture',
    'allowUnvalidatedMldsa',
];
const STATUS_INPUT_KEYS = [
    'authorityPin',
    'certificate',
    'target',
    'status',
    'issuedAt',
    'nextUpdate',
    'previousStatus',
    'signer',
    'targetRegistry',
    'fipsPosture',
    'allowUnvalidatedMldsa',
];
/** Optional fields on both build inputs: never required, so v1 issuance with
 * no FIPS posture supplied is untouched (see enforceFipsSigningPolicy above). */
const OPTIONAL_INPUT_KEYS = ['targetRegistry', 'fipsPosture', 'allowUnvalidatedMldsa'];
const AUTHORITY_PIN_KEYS = ['authority_domain', 'authority_id', 'key_id', 'public_key'];
const SCOPE_KEYS = ['allowed_target_types', 'allowed_usages'];
const TARGET_KEYS = ['type', 'id', 'digest', 'usage'];
const CERTIFICATE_KEYS = [
    '@version',
    'certificate_id',
    'authority_domain',
    'authority_id',
    'revoker_id',
    'revoker_key',
    'scope',
    'issued_at',
    'expires_at',
    'proof',
];
const REVOKER_KEY_KEYS = ['algorithm', 'key_id', 'public_key'];
const CERTIFICATE_PROOF_KEYS = ['algorithm', 'key_id', 'signature_b64u'];
const STATUS_KEYS = [
    '@version',
    'authority_domain',
    'revoker_authority_digest',
    'target',
    'status',
    'sequence',
    'previous_status_digest',
    'issued_at',
    'next_update',
    'proof',
];
const STATUS_PROOF_KEYS = ['algorithm', 'key_id', 'signature_b64u'];
export class StatusIssuanceError extends Error {
    code;
    constructor(code, message, cause) {
        super(message, cause === undefined ? undefined : { cause });
        this.name = 'StatusIssuanceError';
        this.code = code;
    }
}
function fail(code, message, cause) {
    throw new StatusIssuanceError(code, message, cause);
}
function record(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function dataProperties(value) {
    return Reflect.ownKeys(value).every((key) => {
        if (typeof key !== 'string')
            return false;
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        return Boolean(descriptor?.enumerable && Object.hasOwn(descriptor, 'value'));
    });
}
function closedObject(value, label, allowed, required = allowed) {
    if (!record(value) || !dataProperties(value)) {
        fail('unsafe_input', `${label} must be a plain data object`);
    }
    const keys = Reflect.ownKeys(value);
    const unknown = keys.filter((key) => !allowed.includes(key));
    if (unknown.length > 0) {
        fail('unknown_input', `${label} contains unknown field(s): ${unknown.join(', ')}`);
    }
    const missing = required.filter((key) => !Object.hasOwn(value, key));
    if (missing.length > 0) {
        fail('missing_input', `${label} is missing required field(s): ${missing.join(', ')}`);
    }
}
function densePlainArray(value) {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype)
        return false;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1 || !keys.includes('length'))
        return false;
    for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, String(index)))
            return false;
    }
    return true;
}
function validUnicodeString(value) {
    if (typeof value !== 'string')
        return false;
    for (let index = 0; index < value.length; index += 1) {
        const code = value.charCodeAt(index);
        if (code >= 0xd800 && code <= 0xdbff) {
            const next = value.charCodeAt(index + 1);
            if (!(next >= 0xdc00 && next <= 0xdfff))
                return false;
            index += 1;
        }
        else if (code >= 0xdc00 && code <= 0xdfff) {
            return false;
        }
    }
    return true;
}
/** RFC 8785 serialization, byte-identical to the status verifier. */
function canonicalize(value, seen = new WeakSet()) {
    if (value === null || typeof value === 'boolean')
        return JSON.stringify(value);
    if (typeof value === 'string') {
        if (!validUnicodeString(value))
            fail('unsafe_input', 'JCS input contains invalid Unicode');
        return JSON.stringify(value);
    }
    if (typeof value === 'number') {
        if (!Number.isFinite(value))
            fail('unsafe_input', 'JCS input contains a non-finite number');
        return JSON.stringify(value);
    }
    if (typeof value !== 'object' || value === null || seen.has(value)) {
        fail('unsafe_input', 'value is outside the JCS I-JSON profile');
    }
    seen.add(value);
    if (Array.isArray(value)) {
        if (!densePlainArray(value))
            fail('unsafe_input', 'JCS input contains an unsafe array');
        return `[${value.map((member) => canonicalize(member, seen)).join(',')}]`;
    }
    if (!record(value) || !dataProperties(value)) {
        fail('unsafe_input', 'JCS input contains an unsafe object');
    }
    return `{${Object.keys(value).sort()
        .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key], seen)}`).join(',')}}`;
}
function canonicalBase64url(value, expectedBytes) {
    if (typeof value !== 'string' || value.length === 0
        || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1)
        return null;
    const decoded = Buffer.from(value, 'base64url');
    if (decoded.length !== expectedBytes || decoded.toString('base64url') !== value)
        return null;
    return decoded;
}
function loadEd25519Key(value) {
    try {
        const der = canonicalBase64url(value, 44);
        if (!der)
            return null;
        const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
        return key.asymmetricKeyType === 'ed25519' ? key : null;
    }
    catch {
        return null;
    }
}
/** Derive the complete, non-truncated EP status-key identifier from SPKI DER. */
export function deriveRevokerKeyId(publicKeyB64u) {
    const der = canonicalBase64url(publicKeyB64u, 44);
    if (!der || !loadEd25519Key(publicKeyB64u)) {
        fail('invalid_revoker_public_key', 'revoker public key must be canonical base64url Ed25519 SPKI DER');
    }
    return `ep:revoker-key:sha256:${crypto.createHash('sha256').update(der).digest('hex')}`;
}
function strictInstantMs(value) {
    if (typeof value !== 'string')
        return NaN;
    const match = value.match(RFC3339_INSTANT);
    if (!match)
        return NaN;
    const [, year, month, day, hour, minute, second, , offsetHour, offsetMinute] = match;
    const calendar = new Date(0);
    calendar.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
    calendar.setUTCHours(Number(hour), Number(minute), Number(second), 0);
    if (calendar.toISOString().slice(0, 19)
        !== `${year}-${month}-${day}T${hour}:${minute}:${second}`)
        return NaN;
    if (offsetHour !== undefined && (Number(offsetHour) > 23 || Number(offsetMinute) > 59))
        return NaN;
    return Date.parse(value);
}
function instant(value, label) {
    const parsed = strictInstantMs(value);
    if (!Number.isFinite(parsed)) {
        fail('invalid_time', `${label} must be a strict RFC 3339 instant`);
    }
    return parsed;
}
function identifier(value, label) {
    if (typeof value !== 'string' || !IDENTIFIER.test(value)) {
        fail('invalid_identifier', `${label} must be a safe identifier`);
    }
}
function validateAuthorityPin(value) {
    closedObject(value, 'authorityPin', AUTHORITY_PIN_KEYS);
    if (typeof value.authority_domain !== 'string' || !AUTHORITY_DOMAIN.test(value.authority_domain)) {
        fail('invalid_authority_pin', 'authorityPin.authority_domain is invalid');
    }
    identifier(value.authority_id, 'authorityPin.authority_id');
    identifier(value.key_id, 'authorityPin.key_id');
    if (typeof value.public_key !== 'string' || !loadEd25519Key(value.public_key)) {
        fail('invalid_authority_pin', 'authorityPin.public_key must be canonical base64url Ed25519 SPKI DER');
    }
}
function validateScope(value, registry) {
    closedObject(value, 'scope', SCOPE_KEYS);
    const validateMembers = (members, allowed, label) => {
        if (!densePlainArray(members) || members.length === 0 || members.length > allowed.length
            || !members.every((member) => typeof member === 'string' && allowed.includes(member))
            || new Set(members).size !== members.length) {
            fail('invalid_scope', `${label} must be a non-empty unique subset of the supported values`);
        }
        return true;
    };
    validateMembers(value.allowed_target_types, issuanceVocabulary(registry, 'types'), 'scope.allowed_target_types');
    validateMembers(value.allowed_usages, issuanceVocabulary(registry, 'usages'), 'scope.allowed_usages');
}
function validateTarget(value, registry) {
    closedObject(value, 'target', TARGET_KEYS);
    if (typeof value.type !== 'string' || !issuanceVocabulary(registry, 'types').includes(value.type)) {
        fail('invalid_target', 'target.type is unsupported');
    }
    identifier(value.id, 'target.id');
    if (typeof value.digest !== 'string' || !DIGEST.test(value.digest)) {
        fail('invalid_target', 'target.digest must be a lowercase sha256 digest');
    }
    if (typeof value.usage !== 'string' || !issuanceVocabulary(registry, 'usages').includes(value.usage)) {
        fail('invalid_target', 'target.usage is unsupported');
    }
}
function validateSigner(value, expectedKeyId) {
    if (value === null || (typeof value !== 'object' && typeof value !== 'function')) {
        fail('invalid_signer', 'an external Ed25519 signer is required');
    }
    for (const key of Reflect.ownKeys(value)) {
        if (typeof key === 'string' && RAW_KEY_FIELD.test(key)) {
            fail('raw_private_key_refused', 'external signer input must not contain private key material');
        }
    }
    const signer = value;
    if (signer.algorithm !== 'Ed25519') {
        fail('invalid_signer', 'external signer algorithm must be Ed25519');
    }
    if (typeof signer.keyId !== 'string' || signer.keyId !== expectedKeyId) {
        fail('signer_key_id_mismatch', 'external signer key ID does not match the exact expected key ID');
    }
    if (typeof signer.sign !== 'function') {
        fail('invalid_signer', 'external signer requires async sign(bytes, context)');
    }
}
function signingBytes(value, domain) {
    return Buffer.from(`${domain}${canonicalize(value)}`, 'utf8');
}
/**
 * Opt-in FIPS posture consult at the signing call site. When
 * `fipsOptions.posture` is NOT supplied, this function does not run
 * checkOperationPolicy at all -- issuance behavior is byte-identical to
 * before this consult existed (no live crypto.getFips() probe runs, no new
 * refusal path is reachable). When a posture IS supplied (the caller
 * explicitly opted in, e.g. a gov-strict deployment that pins its own
 * getFipsPosture() snapshot), a denied Ed25519 operation policy refuses
 * issuance here with a named 'fips_policy_denied' reason before any bytes
 * reach the signer. This never asserts FIPS validation of the issued
 * artifact -- see packages/verify/src/fips-mode.ts's own module header for
 * the ceiling of what "permitted" means.
 */
function enforceFipsSigningPolicy(alg, fipsOptions) {
    if (!fipsOptions || fipsOptions.posture === undefined)
        return;
    const decision = checkOperationPolicy(alg, fipsOptions.posture, {
        allow_unvalidated_mldsa: fipsOptions.allowUnvalidatedMldsa === true,
    });
    if (!decision.permitted) {
        fail('fips_policy_denied', `${alg} signing refused under the configured FIPS posture: ${decision.reason ?? 'unknown'}`);
    }
}
async function signatureFrom(signer, body, context, fipsOptions) {
    enforceFipsSigningPolicy('Ed25519', fipsOptions);
    const bytes = signingBytes(body, context.domain);
    let output;
    try {
        output = await signer.sign(new Uint8Array(bytes), Object.freeze({ ...context }));
    }
    catch (cause) {
        const detail = cause instanceof Error && cause.message ? `: ${cause.message}` : '';
        fail('signer_failure', `external signer failed${detail}`, cause);
    }
    if (typeof output === 'string') {
        if (!canonicalBase64url(output, 64)) {
            fail('invalid_signature', 'external signer returned a non-canonical Ed25519 signature');
        }
        return output;
    }
    if (!(output instanceof Uint8Array) || output.byteLength !== 64) {
        fail('invalid_signature', 'external signer must return 64 signature bytes or canonical base64url');
    }
    return Buffer.from(output).toString('base64url');
}
function deepFreeze(value) {
    if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
        for (const member of Object.values(value))
            deepFreeze(member);
        Object.freeze(value);
    }
    return value;
}
function targetEqual(left, right) {
    return left.type === right.type
        && left.id === right.id
        && left.digest === right.digest
        && left.usage === right.usage;
}
function certificateForStatus(certificate, authorityPin, issuedAt, registry) {
    const result = verifyRevokerAuthorityCertificate(certificate, {
        authorityPin,
        now: issuedAt,
        targetRegistry: registry,
    });
    if (!result.valid) {
        fail('invalid_revoker_authority_certificate', `revoker authority certificate is invalid at status issuance time: ${result.reasons.join(', ')}`);
    }
    return certificate;
}
function validatePreviousStatus(value, target, certificate, certificateDigest, issuedAtMs, registry) {
    closedObject(value, 'previousStatus', STATUS_KEYS);
    if (value['@version'] !== STATUS_VERSION
        || value.authority_domain !== certificate.authority_domain
        || value.revoker_authority_digest !== certificateDigest) {
        fail('invalid_previous_status', 'previousStatus is not bound to the same authority certificate');
    }
    validateTarget(value.target, registry);
    if (!targetEqual(value.target, target)) {
        fail('invalid_previous_status', 'previousStatus is not bound to the exact target');
    }
    if (value.status !== 'not_revoked' && value.status !== 'revoked') {
        fail('invalid_previous_status', 'previousStatus.status is invalid');
    }
    if (!Number.isSafeInteger(value.sequence) || value.sequence < 0) {
        fail('invalid_previous_status', 'previousStatus.sequence is invalid');
    }
    if (value.previous_status_digest !== null
        && (typeof value.previous_status_digest !== 'string' || !DIGEST.test(value.previous_status_digest))) {
        fail('invalid_previous_status', 'previousStatus.previous_status_digest is invalid');
    }
    const previousIssuedAtMs = instant(value.issued_at, 'previousStatus.issued_at');
    if (issuedAtMs <= previousIssuedAtMs) {
        fail('non_monotonic_status_time', 'issuedAt must be later than previousStatus.issued_at');
    }
    if (value.status === 'revoked') {
        if (value.next_update !== null) {
            fail('invalid_previous_status', 'a revoked previousStatus must have next_update null');
        }
        fail('terminal_revocation', 'cannot issue a successor after a terminal revocation');
    }
    const previousNextUpdateMs = instant(value.next_update, 'previousStatus.next_update');
    if (previousNextUpdateMs <= previousIssuedAtMs) {
        fail('invalid_previous_status', 'previousStatus has an invalid status window');
    }
    closedObject(value.proof, 'previousStatus.proof', STATUS_PROOF_KEYS);
    if (value.proof.algorithm !== 'Ed25519'
        || value.proof.key_id !== certificate.revoker_key.key_id
        || typeof value.proof.signature_b64u !== 'string'
        || !canonicalBase64url(value.proof.signature_b64u, 64)) {
        fail('invalid_previous_status', 'previousStatus proof is invalid');
    }
    const unsignedPrevious = {};
    for (const [key, member] of Object.entries(value)) {
        if (key !== 'proof')
            unsignedPrevious[key] = member;
    }
    const previousKey = loadEd25519Key(certificate.revoker_key.public_key);
    const signature = canonicalBase64url(value.proof.signature_b64u, 64);
    if (!previousKey || !signature || !crypto.verify(null, signingBytes(unsignedPrevious, STATUS_DOMAIN), previousKey, signature)) {
        fail('invalid_previous_status', 'previousStatus signature is invalid');
    }
}
/** Build and externally sign one closed EP-REVOKER-AUTHORITY-v1 certificate. */
export async function buildRevokerAuthorityCertificate(input) {
    closedObject(input, 'certificate input', AUTHORITY_INPUT_KEYS, AUTHORITY_INPUT_KEYS.filter((key) => !OPTIONAL_INPUT_KEYS.includes(key)));
    validateAuthorityPin(input.authorityPin);
    identifier(input.certificateId, 'certificateId');
    identifier(input.revokerId, 'revokerId');
    validateScope(input.scope, input.targetRegistry);
    const issuedAtMs = instant(input.issuedAt, 'issuedAt');
    const expiresAtMs = instant(input.expiresAt, 'expiresAt');
    if (issuedAtMs >= expiresAtMs) {
        fail('invalid_certificate_window', 'expiresAt must be later than issuedAt');
    }
    const revokerKeyId = deriveRevokerKeyId(input.revokerPublicKey);
    validateSigner(input.signer, input.authorityPin.key_id);
    const body = {
        '@version': REVOCER_AUTHORITY_VERSION,
        certificate_id: input.certificateId,
        authority_domain: input.authorityPin.authority_domain,
        authority_id: input.authorityPin.authority_id,
        revoker_id: input.revokerId,
        revoker_key: {
            algorithm: 'Ed25519',
            key_id: revokerKeyId,
            public_key: input.revokerPublicKey,
        },
        scope: {
            allowed_target_types: [...input.scope.allowed_target_types],
            allowed_usages: [...input.scope.allowed_usages],
        },
        issued_at: input.issuedAt,
        expires_at: input.expiresAt,
    };
    const signature = await signatureFrom(input.signer, body, {
        artifact: 'revoker_authority_certificate',
        domain: REVOCER_AUTHORITY_DOMAIN,
        keyId: input.authorityPin.key_id,
    }, { posture: input.fipsPosture, allowUnvalidatedMldsa: input.allowUnvalidatedMldsa });
    const artifact = deepFreeze({
        ...body,
        proof: {
            algorithm: 'Ed25519',
            key_id: input.authorityPin.key_id,
            signature_b64u: signature,
        },
    });
    const verification = verifyRevokerAuthorityCertificate(artifact, {
        authorityPin: input.authorityPin,
        now: input.issuedAt,
        targetRegistry: input.targetRegistry,
    });
    if (!verification.valid) {
        fail('certificate_round_trip_failed', `issued revoker authority certificate failed verification: ${verification.reasons.join(', ')}`);
    }
    return artifact;
}
/** Build and externally sign one closed, predecessor-bound EP-STATUS-v1 head. */
export async function buildStatusArtifact(input) {
    closedObject(input, 'status input', STATUS_INPUT_KEYS, STATUS_INPUT_KEYS.filter((key) => key !== 'previousStatus'
        && !OPTIONAL_INPUT_KEYS.includes(key)));
    validateAuthorityPin(input.authorityPin);
    validateTarget(input.target, input.targetRegistry);
    if (input.status !== 'not_revoked' && input.status !== 'revoked') {
        fail('invalid_status', 'status must be not_revoked or revoked');
    }
    const issuedAtMs = instant(input.issuedAt, 'issuedAt');
    const certificate = certificateForStatus(input.certificate, input.authorityPin, input.issuedAt, input.targetRegistry);
    const certificateDigest = revokerAuthorityCertificateDigest(certificate);
    if (!certificate.scope.allowed_target_types.includes(input.target.type)
        || !certificate.scope.allowed_usages.includes(input.target.usage)) {
        fail('target_outside_scope', 'target is outside the revoker authority certificate scope');
    }
    if (input.status === 'revoked') {
        if (input.nextUpdate !== null) {
            fail('invalid_status_window', 'terminal revoked status requires nextUpdate null');
        }
    }
    else {
        const nextUpdateMs = instant(input.nextUpdate, 'nextUpdate');
        if (nextUpdateMs <= issuedAtMs) {
            fail('invalid_status_window', 'nextUpdate must be later than issuedAt');
        }
        const certificateExpiresAtMs = instant(certificate.expires_at, 'certificate.expires_at');
        if (nextUpdateMs > certificateExpiresAtMs) {
            fail('invalid_status_window', 'status window exceeds the revoker authority certificate');
        }
    }
    let sequence = 0;
    let previousStatusDigest = null;
    if (Object.hasOwn(input, 'previousStatus')) {
        validatePreviousStatus(input.previousStatus, input.target, certificate, certificateDigest, issuedAtMs, input.targetRegistry);
        if (input.previousStatus.sequence >= Number.MAX_SAFE_INTEGER) {
            fail('sequence_exhausted', 'previousStatus.sequence cannot be incremented safely');
        }
        sequence = input.previousStatus.sequence + 1;
        previousStatusDigest = statusArtifactDigest(input.previousStatus);
    }
    validateSigner(input.signer, certificate.revoker_key.key_id);
    if (!REVOKER_KEY_ID.test(input.signer.keyId)) {
        fail('invalid_signer', 'status signer key ID must be a complete revoker-key digest ID');
    }
    const body = {
        '@version': STATUS_VERSION,
        authority_domain: certificate.authority_domain,
        revoker_authority_digest: certificateDigest,
        target: {
            type: input.target.type,
            id: input.target.id,
            digest: input.target.digest,
            usage: input.target.usage,
        },
        status: input.status,
        sequence,
        previous_status_digest: previousStatusDigest,
        issued_at: input.issuedAt,
        next_update: input.nextUpdate,
    };
    const signature = await signatureFrom(input.signer, body, {
        artifact: 'status',
        domain: STATUS_DOMAIN,
        keyId: certificate.revoker_key.key_id,
    }, { posture: input.fipsPosture, allowUnvalidatedMldsa: input.allowUnvalidatedMldsa });
    const artifact = deepFreeze({
        ...body,
        proof: {
            algorithm: 'Ed25519',
            key_id: certificate.revoker_key.key_id,
            signature_b64u: signature,
        },
    });
    const verification = verifyStatusArtifact(input.target, artifact, {
        authorityPin: input.authorityPin,
        certificate,
        previousStatus: input.previousStatus,
        now: input.issuedAt,
        targetRegistry: input.targetRegistry,
    });
    const expectedOutcome = input.status === 'revoked' ? 'revoked' : 'current_not_revoked';
    if (!verification.valid || verification.outcome !== expectedOutcome) {
        fail('status_round_trip_failed', `issued status artifact failed verification: ${verification.reasons.join(', ')}`);
    }
    return artifact;
}
// ===========================================================================
// EP-REVOKER-AUTHORITY-v2 / EP-STATUS-v2 -- hybrid issuer-side builders
// ===========================================================================
/**
 * The v2 VERIFIERS are not re-implemented here, for the same reason the v1
 * comment above states: packages/verify/src/status.ts is the published,
 * portable verifier, and this module composes it rather than re-deriving the
 * hybrid checks. What lives here is the issuer half: buildRevokerAuthorityCertificateV2
 * / buildStatusArtifactV2, the v2 siblings of the v1 builders above, same
 * closed-input discipline, same "no private key material in this API"
 * boundary -- callers inject an EXTERNAL hybrid signer (one Ed25519 leg, one
 * ML-DSA-65 leg), never a raw secret key.
 */
const AUTHORITY_PIN_KEYS_V2 = ['authority_domain', 'authority_id', 'key_id', 'public_key', 'pq_key_id', 'pq_public_key'];
const STATUS_KEYS_V2 = [
    '@version',
    'authority_domain',
    'revoker_authority_digest',
    'target',
    'status',
    'sequence',
    'previous_status_digest',
    'issued_at',
    'next_update',
    'required_algorithms',
    'proof',
];
const AUTHORITY_INPUT_KEYS_V2 = [
    'certificateId',
    'authorityPin',
    'revokerId',
    'revokerPublicKey',
    'revokerPqPublicKey',
    'scope',
    'issuedAt',
    'expiresAt',
    'signer',
    'targetRegistry',
    'fipsPosture',
    'allowUnvalidatedMldsa',
];
const STATUS_INPUT_KEYS_V2 = [
    'authorityPin',
    'certificate',
    'target',
    'status',
    'issuedAt',
    'nextUpdate',
    'previousStatus',
    'signer',
    'targetRegistry',
    'fipsPosture',
    'allowUnvalidatedMldsa',
];
function loadMlDsaPublicKey(value) {
    return canonicalBase64url(value, ML_DSA_65_PUBLIC_KEY_BYTES);
}
function pqRevokerKeyIdIssuer(publicKeyB64u) {
    const raw = loadMlDsaPublicKey(publicKeyB64u);
    if (!raw)
        return null;
    return `ep:revoker-key:ml-dsa-65:sha256:${crypto.createHash('sha256').update(raw).digest('hex')}`;
}
/** Derive the complete ML-DSA-65 revoker-key identifier from raw base64url bytes. */
export function deriveRevokerPqKeyId(publicKeyRawB64u) {
    const id = pqRevokerKeyIdIssuer(publicKeyRawB64u);
    if (!id) {
        fail('invalid_revoker_public_key', 'revoker ML-DSA-65 public key must be canonical base64url raw bytes');
    }
    return id;
}
function validateAuthorityPinV2(value) {
    closedObject(value, 'authorityPin', AUTHORITY_PIN_KEYS_V2);
    if (typeof value.authority_domain !== 'string' || !AUTHORITY_DOMAIN.test(value.authority_domain)) {
        fail('invalid_authority_pin', 'authorityPin.authority_domain is invalid');
    }
    identifier(value.authority_id, 'authorityPin.authority_id');
    identifier(value.key_id, 'authorityPin.key_id');
    if (typeof value.public_key !== 'string' || !loadEd25519Key(value.public_key)) {
        fail('invalid_authority_pin', 'authorityPin.public_key must be canonical base64url Ed25519 SPKI DER');
    }
    identifier(value.pq_key_id, 'authorityPin.pq_key_id');
    if (typeof value.pq_public_key !== 'string' || !pqRevokerKeyIdIssuer(value.pq_public_key)) {
        fail('invalid_authority_pin', 'authorityPin.pq_public_key must be canonical base64url ML-DSA-65 raw public key');
    }
}
function validateMlDsaSigner(value, expectedKeyId) {
    if (value === null || (typeof value !== 'object' && typeof value !== 'function')) {
        fail('invalid_signer', 'an external ML-DSA-65 signer is required');
    }
    for (const key of Reflect.ownKeys(value)) {
        if (typeof key === 'string' && RAW_KEY_FIELD.test(key)) {
            fail('raw_private_key_refused', 'external signer input must not contain private key material');
        }
    }
    const signer = value;
    if (signer.algorithm !== 'ML-DSA-65') {
        fail('invalid_signer', 'external signer algorithm must be ML-DSA-65');
    }
    if (typeof signer.keyId !== 'string' || signer.keyId !== expectedKeyId) {
        fail('signer_key_id_mismatch', 'external signer key ID does not match the exact expected key ID');
    }
    if (typeof signer.sign !== 'function') {
        fail('invalid_signer', 'external signer requires async sign(bytes, context)');
    }
}
function validateHybridSigner(value, expectedEdKeyId, expectedPqKeyId) {
    if (!value || typeof value !== 'object') {
        fail('invalid_signer', 'an external hybrid signer {ed25519, mldsa} is required');
    }
    const signer = value;
    validateSigner(signer.ed25519, expectedEdKeyId);
    validateMlDsaSigner(signer.mldsa, expectedPqKeyId);
}
/**
 * Sign `body` under BOTH registered algorithms via an external hybrid signer.
 * Same FIPS-consult discipline as signatureFrom (see enforceFipsSigningPolicy):
 * with no fipsOptions.posture supplied, no policy consult runs at all.
 */
async function signatureSetFrom(signer, body, context, fipsOptions) {
    enforceFipsSigningPolicy('Ed25519', fipsOptions);
    enforceFipsSigningPolicy('ML-DSA-65', fipsOptions);
    const bytes = signingBytes(body, context.domain);
    let edOutput;
    try {
        edOutput = await signer.ed25519.sign(new Uint8Array(bytes), Object.freeze({ ...context }));
    }
    catch (cause) {
        const detail = cause instanceof Error && cause.message ? `: ${cause.message}` : '';
        fail('signer_failure', `external Ed25519 signer failed${detail}`, cause);
    }
    let edSig;
    if (typeof edOutput === 'string') {
        if (!canonicalBase64url(edOutput, 64)) {
            fail('invalid_signature', 'external Ed25519 signer returned a non-canonical signature');
        }
        edSig = edOutput;
    }
    else if (edOutput instanceof Uint8Array && edOutput.byteLength === 64) {
        edSig = Buffer.from(edOutput).toString('base64url');
    }
    else {
        fail('invalid_signature', 'external Ed25519 signer must return 64 signature bytes or canonical base64url');
    }
    let pqOutput;
    try {
        pqOutput = await signer.mldsa.sign(new Uint8Array(bytes), Object.freeze({ ...context }));
    }
    catch (cause) {
        const detail = cause instanceof Error && cause.message ? `: ${cause.message}` : '';
        fail('signer_failure', `external ML-DSA-65 signer failed${detail}`, cause);
    }
    let pqSig;
    if (typeof pqOutput === 'string') {
        if (!canonicalBase64url(pqOutput, ML_DSA_65_SIGNATURE_BYTES)) {
            fail('invalid_signature', 'external ML-DSA-65 signer returned a non-canonical signature');
        }
        pqSig = pqOutput;
    }
    else if (pqOutput instanceof Uint8Array && pqOutput.byteLength === ML_DSA_65_SIGNATURE_BYTES) {
        pqSig = Buffer.from(pqOutput).toString('base64url');
    }
    else {
        fail('invalid_signature', 'external ML-DSA-65 signer must return raw signature bytes or canonical base64url');
    }
    return {
        signatures: [
            { alg: 'Ed25519', sig: edSig, key_id: signer.ed25519.keyId },
            { alg: 'ML-DSA-65', sig: pqSig, key_id: signer.mldsa.keyId },
        ],
    };
}
async function certificateForStatusV2(certificate, authorityPin, issuedAt, registry) {
    const result = await verifyRevokerAuthorityCertificateV2(certificate, {
        authorityPin,
        now: issuedAt,
        targetRegistry: registry,
    });
    if (!result.valid) {
        fail('invalid_revoker_authority_certificate', `revoker authority certificate is invalid at status issuance time: ${result.reasons.join(', ')}`);
    }
    return certificate;
}
/** Build and externally sign one closed, HYBRID EP-REVOKER-AUTHORITY-v2 certificate. */
export async function buildRevokerAuthorityCertificateV2(input) {
    closedObject(input, 'certificate input', AUTHORITY_INPUT_KEYS_V2, AUTHORITY_INPUT_KEYS_V2.filter((key) => !OPTIONAL_INPUT_KEYS.includes(key)));
    validateAuthorityPinV2(input.authorityPin);
    identifier(input.certificateId, 'certificateId');
    identifier(input.revokerId, 'revokerId');
    validateScope(input.scope, input.targetRegistry);
    const issuedAtMs = instant(input.issuedAt, 'issuedAt');
    const expiresAtMs = instant(input.expiresAt, 'expiresAt');
    if (issuedAtMs >= expiresAtMs) {
        fail('invalid_certificate_window', 'expiresAt must be later than issuedAt');
    }
    const revokerKeyId = deriveRevokerKeyId(input.revokerPublicKey);
    const revokerPqKeyId = deriveRevokerPqKeyId(input.revokerPqPublicKey);
    validateHybridSigner(input.signer, input.authorityPin.key_id, input.authorityPin.pq_key_id);
    const body = {
        '@version': REVOCER_AUTHORITY_V2_VERSION,
        certificate_id: input.certificateId,
        authority_domain: input.authorityPin.authority_domain,
        authority_id: input.authorityPin.authority_id,
        revoker_id: input.revokerId,
        revoker_key: {
            key_id: revokerKeyId,
            public_key: input.revokerPublicKey,
            pq_key_id: revokerPqKeyId,
            pq_public_key: input.revokerPqPublicKey,
        },
        scope: {
            allowed_target_types: [...input.scope.allowed_target_types],
            allowed_usages: [...input.scope.allowed_usages],
        },
        issued_at: input.issuedAt,
        expires_at: input.expiresAt,
        required_algorithms: [...REVOCER_AUTHORITY_V2_REQUIRED_ALGORITHMS],
    };
    const { signatures } = await signatureSetFrom(input.signer, body, {
        artifact: 'revoker_authority_certificate',
        domain: REVOCER_AUTHORITY_V2_DOMAIN,
        keyId: input.authorityPin.key_id,
    }, { posture: input.fipsPosture, allowUnvalidatedMldsa: input.allowUnvalidatedMldsa });
    const artifact = deepFreeze({
        ...body,
        proof: {
            key_id: input.authorityPin.key_id,
            pq_key_id: input.authorityPin.pq_key_id,
            signatures,
        },
    });
    const verification = await verifyRevokerAuthorityCertificateV2(artifact, {
        authorityPin: input.authorityPin,
        now: input.issuedAt,
        targetRegistry: input.targetRegistry,
    });
    if (!verification.valid) {
        fail('certificate_round_trip_failed', `issued revoker authority certificate failed verification: ${verification.reasons.join(', ')}`);
    }
    return artifact;
}
async function validatePreviousStatusV2(value, target, certificate, certificateDigest, issuedAtMs, registry) {
    closedObject(value, 'previousStatus', STATUS_KEYS_V2);
    const previous = value;
    if (previous['@version'] !== STATUS_V2_VERSION
        || previous.authority_domain !== certificate.authority_domain
        || previous.revoker_authority_digest !== certificateDigest) {
        fail('invalid_previous_status', 'previousStatus is not bound to the same authority certificate (v2 chain requires a v2 predecessor)');
    }
    validateTarget(previous.target, registry);
    if (!targetEqual(previous.target, target)) {
        fail('invalid_previous_status', 'previousStatus is not bound to the exact target');
    }
    if (previous.status !== 'not_revoked' && previous.status !== 'revoked') {
        fail('invalid_previous_status', 'previousStatus.status is invalid');
    }
    if (!Number.isSafeInteger(previous.sequence) || previous.sequence < 0) {
        fail('invalid_previous_status', 'previousStatus.sequence is invalid');
    }
    if (previous.previous_status_digest !== null
        && (typeof previous.previous_status_digest !== 'string' || !DIGEST.test(previous.previous_status_digest))) {
        fail('invalid_previous_status', 'previousStatus.previous_status_digest is invalid');
    }
    const previousIssuedAtMs = instant(previous.issued_at, 'previousStatus.issued_at');
    if (issuedAtMs <= previousIssuedAtMs) {
        fail('non_monotonic_status_time', 'issuedAt must be later than previousStatus.issued_at');
    }
    if (previous.status === 'revoked') {
        if (previous.next_update !== null) {
            fail('invalid_previous_status', 'a revoked previousStatus must have next_update null');
        }
        fail('terminal_revocation', 'cannot issue a successor after a terminal revocation');
    }
    const previousNextUpdateMs = instant(previous.next_update, 'previousStatus.next_update');
    if (previousNextUpdateMs <= previousIssuedAtMs) {
        fail('invalid_previous_status', 'previousStatus has an invalid status window');
    }
    if (!Array.isArray(previous.required_algorithms)
        || previous.required_algorithms.length !== STATUS_V2_REQUIRED_ALGORITHMS.length
        || previous.required_algorithms.some((a, i) => a !== STATUS_V2_REQUIRED_ALGORITHMS[i])) {
        fail('invalid_previous_status', 'previousStatus.required_algorithms is not the registered v2 set');
    }
    const proof = previous.proof;
    closedObject(proof, 'previousStatus.proof', ['key_id', 'pq_key_id', 'signatures']);
    if (proof.key_id !== certificate.revoker_key.key_id || proof.pq_key_id !== certificate.revoker_key.pq_key_id) {
        fail('invalid_previous_status', 'previousStatus proof key ids do not match the certificate revoker_key');
    }
    const unsignedPrevious = {};
    for (const [key, member] of Object.entries(previous)) {
        if (key !== 'proof')
            unsignedPrevious[key] = member;
    }
    const bytes = signingBytes(unsignedPrevious, STATUS_V2_DOMAIN);
    const setResult = await verifyAgileSignatureSetIssuer(bytes, proof.signatures, certificate.revoker_key);
    if (!setResult) {
        fail('invalid_previous_status', 'previousStatus signature set is invalid');
    }
    return previous;
}
/**
 * Thin issuer-side signature-set check used only to validate a PRESENTED
 * previousStatus head before extending its chain (mirrors the read-only use
 * of crypto.verify in validatePreviousStatus above, widened to the set). Not
 * exported: the authoritative hybrid signature verification is
 * verifyStatusArtifactV2 in packages/verify/src/status.ts; this exists only
 * because validatePreviousStatusV2 needs a yes/no answer to keep extending a
 * chain it is already holding one head of, the same narrow role
 * crypto.verify(...) plays in the v1 issuer today.
 */
async function verifyAgileSignatureSetIssuer(bytes, signatures, revokerKey) {
    const { verifyAgileSignatureSet } = await import('../../packages/verify/pq-signature-agility.js');
    if (!Array.isArray(signatures))
        return false;
    const result = await verifyAgileSignatureSet(new Uint8Array(bytes), signatures, [
        { alg: 'Ed25519', public_key: revokerKey.public_key, key_id: revokerKey.key_id },
        { alg: 'ML-DSA-65', public_key: revokerKey.pq_public_key, key_id: revokerKey.pq_key_id },
    ], { policy: 'hybrid_all', requiredAlgorithms: [...STATUS_V2_REQUIRED_ALGORITHMS] });
    return result.verified === true;
}
/** Build and externally sign one closed, predecessor-bound, HYBRID EP-STATUS-v2 head. */
export async function buildStatusArtifactV2(input) {
    closedObject(input, 'status input', STATUS_INPUT_KEYS_V2, STATUS_INPUT_KEYS_V2.filter((key) => key !== 'previousStatus'
        && !OPTIONAL_INPUT_KEYS.includes(key)));
    validateAuthorityPinV2(input.authorityPin);
    validateTarget(input.target, input.targetRegistry);
    if (input.status !== 'not_revoked' && input.status !== 'revoked') {
        fail('invalid_status', 'status must be not_revoked or revoked');
    }
    const issuedAtMs = instant(input.issuedAt, 'issuedAt');
    const certificate = await certificateForStatusV2(input.certificate, input.authorityPin, input.issuedAt, input.targetRegistry);
    const certificateDigest = revokerAuthorityCertificateDigest(certificate);
    if (!certificate.scope.allowed_target_types.includes(input.target.type)
        || !certificate.scope.allowed_usages.includes(input.target.usage)) {
        fail('target_outside_scope', 'target is outside the revoker authority certificate scope');
    }
    if (input.status === 'revoked') {
        if (input.nextUpdate !== null) {
            fail('invalid_status_window', 'terminal revoked status requires nextUpdate null');
        }
    }
    else {
        const nextUpdateMs = instant(input.nextUpdate, 'nextUpdate');
        if (nextUpdateMs <= issuedAtMs) {
            fail('invalid_status_window', 'nextUpdate must be later than issuedAt');
        }
        const certificateExpiresAtMs = instant(certificate.expires_at, 'certificate.expires_at');
        if (nextUpdateMs > certificateExpiresAtMs) {
            fail('invalid_status_window', 'status window exceeds the revoker authority certificate');
        }
    }
    let sequence = 0;
    let previousStatusDigest = null;
    if (Object.hasOwn(input, 'previousStatus')) {
        const previous = await validatePreviousStatusV2(input.previousStatus, input.target, certificate, certificateDigest, issuedAtMs, input.targetRegistry);
        if (previous.sequence >= Number.MAX_SAFE_INTEGER) {
            fail('sequence_exhausted', 'previousStatus.sequence cannot be incremented safely');
        }
        sequence = previous.sequence + 1;
        previousStatusDigest = statusArtifactDigest(previous);
    }
    validateHybridSigner(input.signer, certificate.revoker_key.key_id, certificate.revoker_key.pq_key_id);
    if (!REVOKER_KEY_ID.test(input.signer.ed25519.keyId)) {
        fail('invalid_signer', 'status signer Ed25519 key ID must be a complete revoker-key digest ID');
    }
    const body = {
        '@version': STATUS_V2_VERSION,
        authority_domain: certificate.authority_domain,
        revoker_authority_digest: certificateDigest,
        target: {
            type: input.target.type,
            id: input.target.id,
            digest: input.target.digest,
            usage: input.target.usage,
        },
        status: input.status,
        sequence,
        previous_status_digest: previousStatusDigest,
        issued_at: input.issuedAt,
        next_update: input.nextUpdate,
        required_algorithms: [...STATUS_V2_REQUIRED_ALGORITHMS],
    };
    const { signatures } = await signatureSetFrom(input.signer, body, {
        artifact: 'status',
        domain: STATUS_V2_DOMAIN,
        keyId: certificate.revoker_key.key_id,
    }, { posture: input.fipsPosture, allowUnvalidatedMldsa: input.allowUnvalidatedMldsa });
    const artifact = deepFreeze({
        ...body,
        proof: {
            key_id: certificate.revoker_key.key_id,
            pq_key_id: certificate.revoker_key.pq_key_id,
            signatures,
        },
    });
    const verification = await verifyStatusArtifactV2(input.target, artifact, {
        authorityPin: input.authorityPin,
        certificate,
        previousStatus: input.previousStatus,
        now: input.issuedAt,
        targetRegistry: input.targetRegistry,
    });
    const expectedOutcome = input.status === 'revoked' ? 'revoked' : 'current_not_revoked';
    if (!verification.valid || verification.outcome !== expectedOutcome) {
        fail('status_round_trip_failed', `issued status artifact failed verification: ${verification.reasons.join(', ')}`);
    }
    return artifact;
}
export { REVOCER_AUTHORITY_V2_VERSION, REVOCER_AUTHORITY_V2_DOMAIN, REVOCER_AUTHORITY_V2_REQUIRED_ALGORITHMS, STATUS_V2_VERSION, STATUS_V2_DOMAIN, STATUS_V2_REQUIRED_ALGORITHMS, verifyRevokerAuthorityCertificateV2, verifyStatusArtifactV2, verifyRevokerAuthorityCertificateStatement, verifyStatusArtifactStatement, };
