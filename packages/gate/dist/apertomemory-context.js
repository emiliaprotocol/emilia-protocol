// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * First Trusted Context Pack provider: ApertoMemory.
 *
 * This verifies the signed provider-neutral MEMORY-PROJECTION-RECORD-v1
 * envelope, while retaining explicit compatibility with the older
 * AMEM-PROJECTION-RECORD-v0 discussion profile. It does not decrypt `.amem`
 * objects and does not claim independent conformance with ApertoMemory's raw
 * CBOR/COSE format. Native object verification remains the ApertoMemory
 * consumer's responsibility.
 *
 * POST-QUANTUM STATUS: COORDINATION-GATED, DELIBERATELY UNCHANGED.
 *
 * This provider re-checks `record.proof.alg !== 'Ed25519'` and the 64-byte
 * signature length independently of the published verifier, over
 * MEMORY-PROJECTION-RECORD-v1 -- the wire format of the co-authored
 * draft-ferro-schrock-memory-projection-record-00. No hybrid leg is added here
 * and no version is bumped, because a unilateral change to a co-authored wire
 * is a fork, not a migration. The exact constraint and the precise list of what
 * a -01 of the joint draft would need is recorded once, in the
 * EP-MEMORY-PROJECTION-PQ-COSIGNATURE-v1 section of
 * packages/verify/src/memory-projection.ts; this file moves in lockstep with
 * that draft revision and not before it.
 *
 * A relying party that wants a post-quantum leg TODAY uses the additive,
 * detached EP-MEMORY-PROJECTION-PQ-COSIGNATURE-v1 alongside the record. That
 * co-signature is deliberately not consumed here: this provider verifies the
 * joint-wire record and only the joint-wire record, so its verdict stays
 * exactly what the draft says it is.
 */
import crypto from 'node:crypto';
import { MEMORY_PROJECTION_RECORD_VERSION, MemoryProjectionVerificationError, verifyMemoryProjectionRecordV1Envelope, } from '@emilia-protocol/verify/memory-projection';
// @ts-ignore declarations live behind the compatibility entry point.
import { canonicalize } from '../execution-binding.js';
import { canonicalContextRecordDigest, } from './trusted-context.js';
const PROJECTION_DOMAIN = Buffer.from('AMEM-EMILIA-PROJECTION-RECORD-v0\0', 'utf8');
const MEMORY_PROJECTION_FRAME_PROFILE = 'urn:apertomemory:context-frame:v0';
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const RECORD_KEYS = new Set([
    '@version',
    'profile_status',
    'source_profile',
    'projection_id',
    'created_at',
    'adapter',
    'selection_context',
    'delivered',
    'exclusions',
    'projection',
    'nonclaims',
    'proof',
]);
const ADAPTER_KEYS = new Set(['id', 'key_id']);
const SELECTION_KEYS = new Set([
    'recall_request_digest',
    'selection_policy_digest',
    'keyring_snapshot_digest',
    'trust_evaluated_at',
    'context_frame_profile',
]);
const DELIVERED_KEYS = new Set([
    'position',
    'object',
    'context_fragment_digest',
    'derived_trust',
    'authorship',
    'author_key_id_b64u',
    'custody_present',
]);
const OBJECT_KEYS = new Set(['format_version', 'sealed_object_digest']);
const EXCLUSION_KEYS = new Set(['total', 'by_reason']);
const EXCLUSION_REASON_KEYS = new Set([
    'authentication_failed',
    'schema_invalid',
    'policy_filtered',
    'context_limit',
]);
const PROJECTION_KEYS = new Set(['encoding', 'byte_length', 'digest']);
const NONCLAIM_KEYS = new Set([
    'model_use',
    'action_linkage',
    'action_authorization',
    'execution_outcome',
]);
const PROOF_KEYS = new Set(['alg', 'key_id', 'signature_b64u']);
function projectionV1Failure(error) {
    if (!(error instanceof MemoryProjectionVerificationError)) {
        return result('INDETERMINATE', 'projection_verification_unavailable');
    }
    if (error.code === 'adapter_key_revoked')
        return result('NOT_VERIFIED', 'adapter_key_revoked');
    if (error.code === 'adapter_key_inactive')
        return result('NOT_VERIFIED', 'adapter_key_inactive');
    if (error.code === 'adapter_key_not_pinned')
        return result('NOT_VERIFIED', 'adapter_key_not_pinned');
    if (error.code === 'signature_invalid')
        return result('NOT_VERIFIED', 'projection_signature_invalid');
    if (error.code === 'projection_stale' || error.code === 'projection_from_future') {
        return result('INDETERMINATE', 'projection_stale');
    }
    if (error.code === 'trust_snapshot_stale' || error.code === 'trust_snapshot_from_future') {
        return result('INDETERMINATE', 'keyring_status_stale');
    }
    return result('NOT_VERIFIED', 'projection_record_invalid');
}
function isRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function isDataRecord(value) {
    if (!isRecord(value))
        return false;
    return Reflect.ownKeys(value).every((key) => {
        if (typeof key !== 'string')
            return false;
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
    });
}
function exactKeys(value, keys) {
    return isDataRecord(value)
        && Object.keys(value).length === keys.size
        && Object.keys(value).every((key) => keys.has(key));
}
function instant(value) {
    if (typeof value !== 'string' || !RFC3339.test(value))
        return null;
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
}
function resolveInstant(value) {
    try {
        return instant(typeof value === 'function' ? value() : value);
    }
    catch {
        return null;
    }
}
function boundedString(value, maximum = 512) {
    return typeof value === 'string' && value.length > 0 && value.length <= maximum
        && !/[\u0000-\u001f\u007f]/.test(value);
}
function safeInteger(value) {
    return Number.isSafeInteger(value) && value >= 0;
}
function b64u(value, bytes) {
    if (typeof value !== 'string' || !BASE64URL.test(value))
        return false;
    const decoded = Buffer.from(value, 'base64url');
    return decoded.length === bytes && decoded.toString('base64url') === value;
}
function publicKey(value) {
    try {
        if (typeof value !== 'string' || !BASE64URL.test(value))
            return null;
        const bytes = Buffer.from(value, 'base64url');
        if (bytes.toString('base64url') !== value)
            return null;
        return crypto.createPublicKey({ key: bytes, type: 'spki', format: 'der' });
    }
    catch {
        return null;
    }
}
function result(state, reason) {
    return Object.freeze({ state, reason });
}
function validObjectRef(value) {
    return exactKeys(value, OBJECT_KEYS)
        && value.format_version === 2
        && DIGEST.test(value.sealed_object_digest);
}
function validDelivered(value, position) {
    if (!exactKeys(value, DELIVERED_KEYS)
        || value.position !== position
        || !validObjectRef(value.object)
        || !DIGEST.test(value.context_fragment_digest)
        || !['self', 'trusted', 'unverified'].includes(value.derived_trust)
        || !['signed', 'attested', 'unknown'].includes(value.authorship)
        || (value.author_key_id_b64u !== null && !b64u(value.author_key_id_b64u, 8))
        || typeof value.custody_present !== 'boolean')
        return false;
    if (value.authorship === 'attested' && value.custody_present !== true)
        return false;
    if (value.derived_trust === 'unverified') {
        return value.authorship === 'unknown' && value.author_key_id_b64u === null;
    }
    return value.authorship !== 'unknown' && value.author_key_id_b64u !== null;
}
function validNonclaims(value) {
    if (!exactKeys(value, NONCLAIM_KEYS))
        return false;
    return Object.values(value).every((entry) => entry === 'NOT_ESTABLISHED');
}
function signingInput(record) {
    const { proof: _proof, ...unsigned } = record;
    return Buffer.concat([PROJECTION_DOMAIN, Buffer.from(canonicalize(unsigned), 'utf8')]);
}
/** Construct the first provider plug-in for the Trusted Context Pack. */
export function createApertoMemoryContextProvider(options) {
    if (!isDataRecord(options?.adapterKeys)) {
        throw new TypeError('ApertoMemory adapter keys required');
    }
    const providerId = options.providerId ?? 'apertomemory';
    const profileId = options.profileId ?? 'draft-ferro-apertomemory-02';
    if (!boundedString(providerId, 128) || !boundedString(profileId, 256)) {
        throw new TypeError('ApertoMemory provider identity invalid');
    }
    let adapterKeys;
    try {
        adapterKeys = Object.freeze(JSON.parse(canonicalize(options.adapterKeys)));
    }
    catch {
        throw new TypeError('ApertoMemory adapter keys invalid');
    }
    const statusCheckedAtSource = options.statusCheckedAt;
    return Object.freeze({
        providerId,
        profileId,
        verifyProjection(record, context) {
            const verificationTime = instant(context?.verificationTime);
            const statusCheckedAt = resolveInstant(statusCheckedAtSource);
            if (!verificationTime || !statusCheckedAt || !safeInteger(context?.maxSignerStatusAgeSec)) {
                return result('INDETERMINATE', 'adapter_status_unavailable');
            }
            const statusAge = (Date.parse(verificationTime) - Date.parse(statusCheckedAt)) / 1000;
            if (statusAge < 0 || statusAge > context.maxSignerStatusAgeSec) {
                return result('INDETERMINATE', 'adapter_status_stale');
            }
            if (isDataRecord(record) && record['@version'] === MEMORY_PROJECTION_RECORD_VERSION) {
                if (!Array.isArray(record.delivered)
                    || record.delivered.length === 0
                    || record.delivered.length > 256) {
                    return result('NOT_VERIFIED', 'projection_record_invalid');
                }
                try {
                    const verified = verifyMemoryProjectionRecordV1Envelope(record, {
                        adapterKeys,
                        verificationTime,
                        maxProjectionAgeSec: context.maxProjectionAgeSec,
                        maxTrustAgeSec: context.maxTrustAgeSec,
                        expectedSourceProfile: profileId,
                        expectedContextFrameProfile: MEMORY_PROJECTION_FRAME_PROFILE,
                    });
                    return Object.freeze({
                        state: 'VERIFIED',
                        reason: null,
                        claims: Object.freeze({
                            projection_id: verified.projection_id,
                            projection_record_digest: canonicalContextRecordDigest(record),
                            projection_digest: verified.projection_digest,
                            created_at: verified.created_at,
                            trust_evaluated_at: verified.trust_evaluated_at,
                            adapter_status_checked_at: statusCheckedAt,
                            adapter_id: record.adapter.id,
                            adapter_key_id: record.adapter.key_id,
                            delivered_trust: Object.freeze(record.delivered.map((entry) => entry.derived_trust)),
                            excluded_by_reason: Object.freeze({ ...record.exclusions.by_reason }),
                        }),
                    });
                }
                catch (error) {
                    return projectionV1Failure(error);
                }
            }
            if (!exactKeys(record, RECORD_KEYS)
                || record['@version'] !== 'AMEM-PROJECTION-RECORD-v0'
                || record.profile_status !== 'EMILIA_DISCUSSION_INPUT_NOT_APERTOMEMORY_CONFORMANCE'
                || record.source_profile !== profileId
                || !boundedString(record.projection_id, 512)
                || !instant(record.created_at)
                || !exactKeys(record.adapter, ADAPTER_KEYS)
                || !boundedString(record.adapter.id, 512)
                || !boundedString(record.adapter.key_id, 256)
                || !exactKeys(record.selection_context, SELECTION_KEYS)
                || !DIGEST.test(record.selection_context.recall_request_digest)
                || !DIGEST.test(record.selection_context.selection_policy_digest)
                || !DIGEST.test(record.selection_context.keyring_snapshot_digest)
                || !instant(record.selection_context.trust_evaluated_at)
                || record.selection_context.context_frame_profile !== 'AMEM-CONTEXT-FRAME-v0'
                || !Array.isArray(record.delivered)
                || record.delivered.length === 0
                || record.delivered.length > 256
                || !record.delivered.every(validDelivered)
                || !exactKeys(record.exclusions, EXCLUSION_KEYS)
                || !safeInteger(record.exclusions.total)
                || !exactKeys(record.exclusions.by_reason, EXCLUSION_REASON_KEYS)
                || !exactKeys(record.projection, PROJECTION_KEYS)
                || record.projection.encoding !== 'utf-8'
                || !safeInteger(record.projection.byte_length)
                || !DIGEST.test(record.projection.digest)
                || !validNonclaims(record.nonclaims)
                || !exactKeys(record.proof, PROOF_KEYS)
                || record.proof.alg !== 'Ed25519'
                || record.proof.key_id !== record.adapter.key_id
                || !b64u(record.proof.signature_b64u, 64)) {
                return result('NOT_VERIFIED', 'projection_record_invalid');
            }
            let excluded = 0;
            for (const count of Object.values(record.exclusions.by_reason)) {
                if (!safeInteger(count))
                    return result('NOT_VERIFIED', 'projection_exclusions_invalid');
                excluded += count;
            }
            if (excluded !== record.exclusions.total) {
                return result('NOT_VERIFIED', 'projection_exclusions_invalid');
            }
            const directoryEntry = adapterKeys[record.adapter.key_id];
            if (!isDataRecord(directoryEntry)
                || !['active', 'revoked', 'superseded'].includes(directoryEntry.status)
                || !instant(directoryEntry.valid_from)
                || !instant(directoryEntry.valid_to)
                || (directoryEntry.revoked_at !== null && !instant(directoryEntry.revoked_at))) {
                return result('NOT_VERIFIED', 'adapter_key_not_pinned');
            }
            if (directoryEntry.status === 'revoked'
                && directoryEntry.revoked_at !== null
                && Date.parse(verificationTime) >= Date.parse(directoryEntry.revoked_at)) {
                return result('NOT_VERIFIED', 'adapter_key_revoked');
            }
            if (directoryEntry.status !== 'active'
                || Date.parse(verificationTime) < Date.parse(directoryEntry.valid_from)
                || Date.parse(verificationTime) > Date.parse(directoryEntry.valid_to)) {
                return result('NOT_VERIFIED', 'adapter_key_inactive');
            }
            const key = publicKey(directoryEntry.public_key_spki_b64u);
            if (!key)
                return result('NOT_VERIFIED', 'adapter_key_invalid');
            const validSignature = crypto.verify(null, signingInput(record), key, Buffer.from(record.proof.signature_b64u, 'base64url'));
            if (!validSignature)
                return result('NOT_VERIFIED', 'projection_signature_invalid');
            return Object.freeze({
                state: 'VERIFIED',
                reason: null,
                claims: Object.freeze({
                    projection_id: record.projection_id,
                    projection_record_digest: canonicalContextRecordDigest(record),
                    projection_digest: record.projection.digest,
                    created_at: instant(record.created_at),
                    trust_evaluated_at: instant(record.selection_context.trust_evaluated_at),
                    adapter_status_checked_at: statusCheckedAt,
                    adapter_id: record.adapter.id,
                    adapter_key_id: record.adapter.key_id,
                    delivered_trust: Object.freeze(record.delivered.map((entry) => entry.derived_trust)),
                    excluded_by_reason: Object.freeze({ ...record.exclusions.by_reason }),
                }),
            });
        },
    });
}
export default Object.freeze({ createApertoMemoryContextProvider });
//# sourceMappingURL=apertomemory-context.js.map