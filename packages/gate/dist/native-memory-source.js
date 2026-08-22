// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/** Internal helpers for bounded native-memory source envelopes. */
import crypto from 'node:crypto';
import { createMemoryProjectionRecordV1, } from '@emilia-protocol/verify/memory-projection';
// @ts-ignore declarations live behind the compatibility entry point.
import { canonicalize } from '../execution-binding.js';
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
export function sha256(bytes) {
    return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}
export function isDataRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null)
        return false;
    return Reflect.ownKeys(value).every((key) => {
        if (typeof key !== 'string')
            return false;
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
    });
}
export function boundedString(value, maximum = 1024) {
    return typeof value === 'string' && value.length > 0 && value.length <= maximum
        && !/[\u0000-\u001f\u007f]/.test(value);
}
export function absoluteUri(value) {
    if (!boundedString(value, 2048))
        return false;
    try {
        return Boolean(new URL(value).protocol);
    }
    catch {
        return false;
    }
}
export function canonicalBytes(value) {
    return Buffer.from(canonicalize(value), 'utf8');
}
export function decodeCanonicalSourceEnvelope(bytes) {
    let value;
    try {
        value = JSON.parse(Buffer.from(bytes).toString('utf8'));
    }
    catch {
        throw new TypeError('native source envelope invalid');
    }
    if (!isDataRecord(value)
        || typeof value.content_b64u !== 'string'
        || !BASE64URL.test(value.content_b64u)
        || !DIGEST.test(value.content_digest)) {
        throw new TypeError('native source envelope invalid');
    }
    const sourceBytes = Buffer.from(value.content_b64u, 'base64url');
    if (sourceBytes.toString('base64url') !== value.content_b64u
        || sha256(sourceBytes) !== value.content_digest) {
        throw new TypeError('native source envelope content invalid');
    }
    if (!canonicalBytes(value).equals(Buffer.from(bytes))) {
        throw new TypeError('native source envelope is not canonical');
    }
    return value;
}
function defaultVerifier(input) {
    return Object.freeze({
        valid: true,
        formatVersion: 1,
        sealedObjectDigest: input.sealedObjectDigest,
        derivedTrust: 'unverified',
        authorship: 'unknown',
        authorKeyIdB64u: null,
        custodyPresent: false,
    });
}
function validateNativeResult(value, sealedObjectDigest) {
    if (!isDataRecord(value)
        || value.valid !== true
        || value.formatVersion !== 1
        || value.sealedObjectDigest !== sealedObjectDigest
        || !['self', 'trusted', 'unverified'].includes(value.derivedTrust)
        || !['signed', 'attested', 'unknown'].includes(value.authorship)
        || (value.authorKeyIdB64u !== null && !boundedString(value.authorKeyIdB64u, 512))
        || typeof value.custodyPresent !== 'boolean') {
        throw new TypeError('native source verification result invalid');
    }
    if (value.authorship === 'attested' && value.custodyPresent !== true) {
        throw new TypeError('native source verification result invalid');
    }
    if (value.derivedTrust === 'unverified') {
        if (value.authorship !== 'unknown' || value.authorKeyIdB64u !== null) {
            throw new TypeError('native source verification result invalid');
        }
    }
    else if (value.authorship === 'unknown' || value.authorKeyIdB64u === null) {
        throw new TypeError('native source verification result invalid');
    }
    return Object.freeze({
        valid: true,
        formatVersion: 1,
        sealedObjectDigest,
        derivedTrust: value.derivedTrust,
        authorship: value.authorship,
        authorKeyIdB64u: value.authorKeyIdB64u,
        custodyPresent: value.custodyPresent,
    });
}
function classify(verifier, providerId, sourceProfile, sourceEnvelopeBytes, validateSourceEnvelope) {
    const sourceEnvelope = decodeCanonicalSourceEnvelope(sourceEnvelopeBytes);
    validateSourceEnvelope(sourceEnvelope);
    const sourceBytes = Buffer.from(sourceEnvelope.content_b64u, 'base64url');
    const sealedObjectDigest = sha256(sourceEnvelopeBytes);
    const result = verifier({
        providerId,
        sourceProfile,
        sourceEnvelope: Object.freeze({ ...sourceEnvelope }),
        sourceBytes,
        sealedObjectDigest,
    });
    return validateNativeResult(result, sealedObjectDigest);
}
export function createNativeMemoryProjection(input) {
    if (!boundedString(input?.providerId, 128)
        || !boundedString(input?.sourceProfile, 512)
        || !boundedString(input?.contextFrameProfile, 512)
        || !Array.isArray(input?.sources)
        || input.sources.length === 0
        || input.sources.length > 256
        || typeof input.validateSourceEnvelope !== 'function') {
        throw new TypeError('native memory projection input invalid');
    }
    const verifier = input.verifyNativeSource ?? defaultVerifier;
    if (typeof verifier !== 'function')
        throw new TypeError('native source verifier invalid');
    const sourceObjectBytes = input.sources.map((source) => canonicalBytes(source.sourceEnvelope));
    const nativeResults = sourceObjectBytes.map((bytes) => classify(verifier, input.providerId, input.sourceProfile, bytes, input.validateSourceEnvelope));
    const result = createMemoryProjectionRecordV1({
        sourceProfile: input.sourceProfile,
        projectionId: input.projectionId,
        createdAt: input.createdAt,
        adapter: {
            id: input.adapter.id,
            keyId: input.adapter.keyId,
        },
        selectionContext: {
            ...input.selectionContext,
            contextFrameProfile: input.contextFrameProfile,
        },
        delivered: input.sources.map((source, position) => ({
            formatVersion: 1,
            sealedObjectBytes: sourceObjectBytes[position],
            contextFragmentBytes: source.contextFragmentBytes,
            derivedTrust: nativeResults[position].derivedTrust,
            authorship: nativeResults[position].authorship,
            authorKeyIdB64u: nativeResults[position].authorKeyIdB64u,
            custodyPresent: nativeResults[position].custodyPresent,
        })),
        exclusions: {
            authenticationFailed: input.exclusions?.authenticationFailed ?? 0,
            schemaInvalid: input.exclusions?.schemaInvalid ?? 0,
            policyFiltered: input.exclusions?.policyFiltered ?? 0,
            contextLimit: input.exclusions?.contextLimit ?? 0,
        },
        privateKey: input.adapter.privateKey,
    });
    return {
        record: result.record,
        verificationMaterial: {
            ...result.verificationMaterial,
            verifySourceEntry({ sourceProfile, sourceObjectBytes: exactBytes }) {
                if (sourceProfile !== input.sourceProfile) {
                    throw new TypeError('native source profile mismatch');
                }
                return classify(verifier, input.providerId, sourceProfile, exactBytes, input.validateSourceEnvelope);
            },
        },
    };
}
//# sourceMappingURL=native-memory-source.js.map