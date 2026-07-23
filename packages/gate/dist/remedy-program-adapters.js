// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Constructor-pinned production adapters for the Remedy Program kernel.
 *
 * The kernel deliberately stores evidence references for every post-create
 * transition. These adapters resolve those references from a relying-party
 * evidence source and perform the concrete cryptographic verification here.
 * Presenters cannot supply verifier functions, tenants, or trust keys.
 */
import crypto from 'node:crypto';
import { verifyRevocation } from '@emilia-protocol/verify';
import { canonicalize } from '../execution-binding.js';
import { verifyActionEscrowStateStatement } from './action-escrow-state.js';
export const REMEDY_PROGRAM_EVIDENCE_VERSION = 'EP-GATE-REMEDY-EVIDENCE-v1';
export const REMEDY_PROGRAM_EVIDENCE_DOMAIN = `${REMEDY_PROGRAM_EVIDENCE_VERSION}\0`;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/#@+-]{0,255}$/;
const CAID = /^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const ORIGINAL_KEYS = new Set([
    'caid', 'action_digest', 'operation_id', 'consequence_mode',
    'consequence_digest', 'terminal_evidence_digest', 'outcome', 'occurred_at',
]);
const STORED_ORIGINAL_KEYS = new Set([...ORIGINAL_KEYS, 'evidence_digest']);
const SIGNED_EVIDENCE_KEYS = new Set([
    'version', 'kind', 'issuer', 'payload', 'content_digest', 'signature',
]);
const SIGNING_BODY_KEYS = new Set([
    'version', 'kind', 'issuer', 'payload', 'content_digest',
]);
const ISSUER_KEYS = new Set(['authority_id', 'key_id']);
const SIGNATURE_KEYS = new Set(['algorithm', 'value']);
const AUTHORITY_KEYS = new Set(['authorityId', 'trustedKeys']);
const ORIGINAL_BINDING_KEYS = new Set([
    'agreementId', 'caid', 'bindingDigest', 'profileDigest', 'amendmentDigests',
]);
const DISPUTE_PAYLOAD_KEYS = new Set([
    'evidence_id', 'tenant_id', 'instance_id', 'dispute_id', 'challenger_id',
    'requested_units', 'opened_at', 'original_operation_id', 'original_action_digest',
]);
const AUTHORIZATION_PAYLOAD_KEYS = new Set([
    'evidence_id', 'tenant_id', 'instance_id', 'dispute_id',
    'original_operation_id', 'original_action_digest', 'remedy_operation_id',
    'remedy_caid', 'remedy_action_digest', 'destination_binding_digest',
    'consequence_mode', 'capability_template_digest', 'escrow_profile_digest',
    'units', 'unit', 'authorized_at',
]);
const OUTCOME_PAYLOAD_KEYS = new Set([
    'evidence_id', 'tenant_id', 'instance_id', 'remedy_operation_id',
    'remedy_action_digest', 'destination_binding_digest', 'units', 'unit',
    'outcome', 'observed_at', 'reconciliation',
]);
const ORIGINAL_OUTCOME_PAYLOAD_KEYS = new Set([
    'evidence_id', 'tenant_id', 'instance_id', 'original_operation_id',
    'original_action_digest', 'terminal_evidence_digest', 'outcome',
    'observed_at',
]);
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
function validContext(value) {
    return typeof value === 'string' && value.length > 0
        && Buffer.byteLength(value, 'utf8') <= 512
        && !/[\u0000-\u001f\u007f]/.test(value);
}
function validId(value) {
    return typeof value === 'string' && ID.test(value);
}
function instant(value) {
    if (typeof value !== 'string')
        return NaN;
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? parsed : NaN;
}
function canonicalCopy(value) {
    return JSON.parse(canonicalize(value));
}
function deepFreeze(value) {
    if (value === null || typeof value !== 'object' || Object.isFrozen(value))
        return value;
    Object.freeze(value);
    for (const child of Object.values(value))
        deepFreeze(child);
    return value;
}
function canonicalDigest(value) {
    return `sha256:${crypto.createHash('sha256').update(canonicalize(value)).digest('hex')}`;
}
/** Digest an exact evidence artifact for use as the kernel's evidence reference. */
export function remedyProgramEvidenceDigest(value) {
    return canonicalDigest(value);
}
function signingBody(value) {
    return {
        version: value.version,
        kind: value.kind,
        issuer: value.issuer,
        payload: value.payload,
        content_digest: value.content_digest,
    };
}
/** Domain-separated canonical bytes for the closed signed evidence envelope. */
export function remedyProgramEvidenceSigningBytes(value) {
    if (!isDataRecord(value))
        throw new TypeError('remedy evidence signing body invalid');
    const body = signingBody(value);
    if (!exactKeys(body, SIGNING_BODY_KEYS)) {
        throw new TypeError('remedy evidence signing body invalid');
    }
    return Buffer.from(REMEDY_PROGRAM_EVIDENCE_DOMAIN + canonicalize(body), 'utf8');
}
function strictBase64url(value, length) {
    if (typeof value !== 'string' || !BASE64URL.test(value) || value.length % 4 === 1)
        return null;
    const bytes = Buffer.from(value, 'base64url');
    return bytes.toString('base64url') === value
        && (length === undefined || bytes.length === length) ? bytes : null;
}
function ed25519PublicKey(value) {
    try {
        const bytes = strictBase64url(value);
        if (!bytes)
            return null;
        const key = crypto.createPublicKey({ key: bytes, format: 'der', type: 'spki' });
        return key.asymmetricKeyType === 'ed25519' ? key : null;
    }
    catch {
        return null;
    }
}
function validTrustedKeys(value) {
    return isDataRecord(value) && Object.keys(value).length > 0
        && Object.entries(value).every(([keyId, key]) => validId(keyId) && ed25519PublicKey(key) !== null);
}
function validAuthority(value) {
    return exactKeys(value, AUTHORITY_KEYS)
        && validContext(value.authorityId)
        && validTrustedKeys(value.trustedKeys);
}
function validOriginal(value, stored = false) {
    return exactKeys(value, stored ? STORED_ORIGINAL_KEYS : ORIGINAL_KEYS)
        && typeof value.caid === 'string' && CAID.test(value.caid)
        && typeof value.action_digest === 'string' && DIGEST.test(value.action_digest)
        && validId(value.operation_id)
        && value.consequence_mode === 'action-escrow'
        && typeof value.consequence_digest === 'string' && DIGEST.test(value.consequence_digest)
        && typeof value.terminal_evidence_digest === 'string' && DIGEST.test(value.terminal_evidence_digest)
        && ['executed', 'indeterminate'].includes(value.outcome)
        && Number.isFinite(instant(value.occurred_at))
        && (!stored || (typeof value.evidence_digest === 'string' && DIGEST.test(value.evidence_digest)));
}
function snapshotData(value) {
    return deepFreeze(canonicalCopy(value));
}
function failure() {
    return Object.freeze({ ok: false });
}
function contextMatches(expected, options) {
    return isDataRecord(expected)
        && expected.tenant_id === options.tenantId
        && expected.environment === options.environment
        && expected.audience === options.audience
        && validId(expected.instance_id);
}
function payloadMatches(value, expected, fields) {
    return fields.every((field) => value[field] === expected[field]);
}
function verifiedSignedEvidence(value, kind, authority) {
    try {
        const evidence = canonicalCopy(value);
        if (!exactKeys(evidence, SIGNED_EVIDENCE_KEYS)
            || evidence.version !== REMEDY_PROGRAM_EVIDENCE_VERSION
            || evidence.kind !== kind
            || !exactKeys(evidence.issuer, ISSUER_KEYS)
            || evidence.issuer.authority_id !== authority.authorityId
            || !validId(evidence.issuer.key_id)
            || !isDataRecord(evidence.payload)
            || typeof evidence.content_digest !== 'string'
            || !DIGEST.test(evidence.content_digest)
            || !exactKeys(evidence.signature, SIGNATURE_KEYS)
            || evidence.signature.algorithm !== 'Ed25519')
            return null;
        const unsigned = {
            version: evidence.version,
            kind: evidence.kind,
            issuer: evidence.issuer,
            payload: evidence.payload,
        };
        if (canonicalDigest(unsigned) !== evidence.content_digest)
            return null;
        const keyValue = authority.trustedKeys[evidence.issuer.key_id];
        const key = ed25519PublicKey(keyValue);
        const signature = strictBase64url(evidence.signature.value, 64);
        if (!key || !signature
            || !crypto.verify(null, remedyProgramEvidenceSigningBytes(evidence), key, signature))
            return null;
        return evidence;
    }
    catch {
        return null;
    }
}
/**
 * Build all required Remedy Program callbacks using only pinned configuration
 * and concrete repository verifiers. There are intentionally no verifier
 * override hooks.
 */
export function createRemedyProgramAdapters(options) {
    if (!isDataRecord(options)
        || !validContext(options.tenantId)
        || !validContext(options.environment)
        || !validContext(options.audience)
        || !options.evidenceSource
        || typeof options.evidenceSource.get !== 'function'
        || !isDataRecord(options.actionEscrow)
        || !isDataRecord(options.actionEscrow.trustedKeys)
        || Object.keys(options.actionEscrow.trustedKeys).length === 0
        || !isDataRecord(options.actionEscrow.originalEffects)
        || Object.keys(options.actionEscrow.originalEffects).length === 0
        || !isDataRecord(options.revokerKeys)
        || !validAuthority(options.disputeAuthority)
        || !validAuthority(options.remedyAuthority)
        || !validAuthority(options.providerAuthority)
        || (options.now !== undefined && typeof options.now !== 'function')) {
        throw new TypeError('remedy program adapter configuration invalid');
    }
    for (const [keyId, pin] of Object.entries(options.actionEscrow.trustedKeys)) {
        if (!validId(keyId) || !exactKeys(pin, new Set(['operator_id', 'public_key']))
            || !validContext(pin.operator_id) || ed25519PublicKey(pin.public_key) === null) {
            throw new TypeError('Action Escrow state key configuration invalid');
        }
    }
    for (const [operationId, binding] of Object.entries(options.actionEscrow.originalEffects)) {
        if (!validId(operationId) || !exactKeys(binding, ORIGINAL_BINDING_KEYS)
            || !validContext(binding.agreementId)
            || typeof binding.caid !== 'string' || !CAID.test(binding.caid)
            || typeof binding.bindingDigest !== 'string' || !DIGEST.test(binding.bindingDigest)
            || typeof binding.profileDigest !== 'string' || !DIGEST.test(binding.profileDigest)
            || !Array.isArray(binding.amendmentDigests)
            || binding.amendmentDigests.some((entry) => typeof entry !== 'string' || !DIGEST.test(entry))
            || new Set(binding.amendmentDigests).size !== binding.amendmentDigests.length) {
            throw new TypeError('Action Escrow original-effect binding invalid');
        }
    }
    const pinned = snapshotData({
        tenantId: options.tenantId,
        environment: options.environment,
        audience: options.audience,
        actionEscrow: options.actionEscrow,
        revokerKeys: options.revokerKeys,
        disputeAuthority: options.disputeAuthority,
        remedyAuthority: options.remedyAuthority,
        providerAuthority: options.providerAuthority,
    });
    const getEvidence = options.evidenceSource.get.bind(options.evidenceSource);
    const now = options.now ?? Date.now;
    const resolvedNow = () => {
        try {
            const value = now();
            if (value instanceof Date)
                return Number.isFinite(value.getTime()) ? new Date(value) : null;
            if (typeof value === 'number')
                return Number.isFinite(value) ? value : null;
            return Number.isFinite(instant(value)) ? value : null;
        }
        catch {
            return null;
        }
    };
    const resolveEvidence = async (evidenceId, evidenceDigest) => {
        try {
            const value = await getEvidence(Object.freeze({
                tenantId: pinned.tenantId,
                evidenceId,
                evidenceDigest,
            }));
            const copy = canonicalCopy(value);
            return canonicalDigest(copy) === evidenceDigest ? deepFreeze(copy) : null;
        }
        catch {
            return null;
        }
    };
    const resolveSigned = async (evidenceId, evidenceDigest, kind, authority) => {
        const value = await resolveEvidence(evidenceId, evidenceDigest);
        return verifiedSignedEvidence(value, kind, authority);
    };
    async function verifyOriginalEffect(input) {
        try {
            if (!exactKeys(input, new Set(['original', 'evidence', 'expected']))
                || !validOriginal(input.original)
                || !contextMatches(input.expected, pinned)
                || !exactKeys(input.evidence, new Set(['snapshot', 'statement'])))
                return failure();
            const original = input.original;
            const expected = input.expected;
            const binding = pinned.actionEscrow.originalEffects[original.operation_id];
            if (!binding || original.caid !== binding.caid
                || original.consequence_digest !== binding.bindingDigest)
                return failure();
            const snapshot = input.evidence.snapshot;
            const statement = input.evidence.statement;
            const stage = original.outcome === 'executed' ? 'released' : 'release_indeterminate';
            if (!isDataRecord(snapshot) || !isDataRecord(statement)
                || snapshot['@version'] !== 'EP-ACTION-ESCROW-STATE-v1'
                || snapshot.state !== stage
                || !Number.isSafeInteger(snapshot.revision) || snapshot.revision < 0
                || snapshot.release_action_digest !== original.action_digest
                || snapshot.document_action_binding_digest !== binding.bindingDigest
                || snapshot.profile_digest !== binding.profileDigest
                || !isDataRecord(snapshot.release)
                || snapshot.release.operation_idempotency_key !== original.operation_id
                || statement.statement_digest !== original.terminal_evidence_digest
                || statement.payload?.occurred_at !== original.occurred_at)
                return failure();
            const evaluation = resolvedNow();
            if (evaluation === null)
                return failure();
            const verified = verifyActionEscrowStateStatement(statement, {
                trustedKeys: pinned.actionEscrow.trustedKeys,
                stateRecord: snapshot,
                expectedAgreementId: binding.agreementId,
                expectedBindingDigest: binding.bindingDigest,
                expectedActionDigest: original.action_digest,
                expectedProfileDigest: binding.profileDigest,
                expectedState: stage,
                expectedRevision: snapshot.revision,
                expectedAmendmentDigests: binding.amendmentDigests,
                expectedPreviousStatementDigest: statement.payload.previous_statement_digest,
                now: evaluation,
            });
            if (verified.valid !== true || verified.statement_digest !== original.terminal_evidence_digest) {
                return failure();
            }
            return Object.freeze({
                ok: true,
                ...canonicalCopy(original),
                evidence_digest: original.terminal_evidence_digest,
            });
        }
        catch {
            return failure();
        }
    }
    async function verifyRevocationEvidence(input) {
        try {
            if (!exactKeys(input, new Set(['evidence', 'expected']))
                || !contextMatches(input.expected, pinned)
                || !validOriginal(input.expected.original, true)
                || !exactKeys(input.evidence, new Set(['id', 'digest']))
                || !validId(input.evidence.id)
                || typeof input.evidence.digest !== 'string' || !DIGEST.test(input.evidence.digest)) {
                return failure();
            }
            const statement = await resolveEvidence(input.evidence.id, input.evidence.digest);
            const evaluation = resolvedNow();
            if (!isDataRecord(statement) || evaluation === null)
                return failure();
            const target = {
                target_type: 'commit',
                target_id: input.expected.original.operation_id,
                action_hash: input.expected.original.action_digest,
            };
            const verified = verifyRevocation(target, statement, {
                revokerKeys: pinned.revokerKeys,
                now: evaluation,
            });
            if (verified.valid !== true)
                return failure();
            return Object.freeze({
                ok: true,
                evidence_id: input.evidence.id,
                evidence_digest: input.evidence.digest,
                target_operation_id: target.target_id,
                action_digest: target.action_hash,
                authority_id: statement.revoker_id,
                revoked_at: statement.revoked_at,
            });
        }
        catch {
            return failure();
        }
    }
    async function verifyDispute(input) {
        try {
            if (!exactKeys(input, new Set(['dispute', 'expected']))
                || !contextMatches(input.expected, pinned)
                || !validOriginal(input.expected.original, true)
                || !isDataRecord(input.dispute)
                || !validId(input.dispute.evidence_id)
                || typeof input.dispute.evidence_digest !== 'string'
                || !DIGEST.test(input.dispute.evidence_digest))
                return failure();
            const artifact = await resolveSigned(input.dispute.evidence_id, input.dispute.evidence_digest, 'dispute', pinned.disputeAuthority);
            if (!artifact || !exactKeys(artifact.payload, DISPUTE_PAYLOAD_KEYS))
                return failure();
            const payload = artifact.payload;
            if (payload.tenant_id !== pinned.tenantId
                || payload.instance_id !== input.expected.instance_id
                || payload.original_operation_id !== input.expected.original.operation_id
                || payload.original_action_digest !== input.expected.original.action_digest
                || !payloadMatches(payload, input.dispute, [
                    'evidence_id', 'dispute_id', 'challenger_id', 'requested_units', 'opened_at',
                ]))
                return failure();
            return Object.freeze({
                ok: true,
                dispute_id: payload.dispute_id,
                evidence_id: payload.evidence_id,
                evidence_digest: input.dispute.evidence_digest,
                challenger_id: payload.challenger_id,
                requested_units: payload.requested_units,
                opened_at: payload.opened_at,
                original_operation_id: payload.original_operation_id,
                original_action_digest: payload.original_action_digest,
            });
        }
        catch {
            return failure();
        }
    }
    async function verifyRemedyAuthorization(input) {
        try {
            if (!exactKeys(input, new Set(['authorization', 'expected']))
                || !contextMatches(input.expected, pinned)
                || !validOriginal(input.expected.original, true)
                || !isDataRecord(input.expected.dispute)
                || !isDataRecord(input.authorization)
                || !validId(input.authorization.evidence_id)
                || typeof input.authorization.evidence_digest !== 'string'
                || !DIGEST.test(input.authorization.evidence_digest))
                return failure();
            const artifact = await resolveSigned(input.authorization.evidence_id, input.authorization.evidence_digest, 'remedy_authorization', pinned.remedyAuthority);
            if (!artifact || !exactKeys(artifact.payload, AUTHORIZATION_PAYLOAD_KEYS))
                return failure();
            const payload = artifact.payload;
            const authorizationFields = [
                'evidence_id', 'remedy_operation_id', 'remedy_caid', 'remedy_action_digest',
                'consequence_mode', 'capability_template_digest', 'escrow_profile_digest',
                'units', 'authorized_at',
            ];
            if (payload.tenant_id !== pinned.tenantId
                || payload.instance_id !== input.expected.instance_id
                || payload.dispute_id !== input.expected.dispute.dispute_id
                || payload.original_operation_id !== input.expected.original.operation_id
                || payload.original_action_digest !== input.expected.original.action_digest
                || payload.destination_binding_digest !== input.expected.destination_binding_digest
                || payload.unit !== input.expected.unit
                || !payloadMatches(payload, input.authorization, authorizationFields))
                return failure();
            return Object.freeze({
                ok: true,
                evidence_id: payload.evidence_id,
                evidence_digest: input.authorization.evidence_digest,
                remedy_operation_id: payload.remedy_operation_id,
                remedy_caid: payload.remedy_caid,
                remedy_action_digest: payload.remedy_action_digest,
                consequence_mode: payload.consequence_mode,
                capability_template_digest: payload.capability_template_digest,
                escrow_profile_digest: payload.escrow_profile_digest,
                units: payload.units,
                authorized_at: payload.authorized_at,
                dispute_id: payload.dispute_id,
                original_operation_id: payload.original_operation_id,
                destination_binding_digest: payload.destination_binding_digest,
                unit: payload.unit,
            });
        }
        catch {
            return failure();
        }
    }
    async function verifyRemedyOutcome(input) {
        try {
            if (!exactKeys(input, new Set(['evidence', 'outcome', 'expected', 'reconciliation']))
                || !contextMatches(input.expected, pinned)
                || !validOriginal(input.expected.original, true)
                || typeof input.reconciliation !== 'boolean'
                || !isDataRecord(input.evidence)
                || !validId(input.evidence.evidence_id)
                || typeof input.evidence.evidence_digest !== 'string'
                || !DIGEST.test(input.evidence.evidence_digest))
                return failure();
            const artifact = await resolveSigned(input.evidence.evidence_id, input.evidence.evidence_digest, 'provider_outcome', pinned.providerAuthority);
            if (!artifact || !exactKeys(artifact.payload, OUTCOME_PAYLOAD_KEYS))
                return failure();
            const payload = artifact.payload;
            if (payload.tenant_id !== pinned.tenantId
                || payload.instance_id !== input.expected.instance_id
                || payload.reconciliation !== input.reconciliation
                || payload.outcome !== input.outcome
                || payload.evidence_id !== input.evidence.evidence_id
                || payload.observed_at !== input.evidence.observed_at
                || !payloadMatches(payload, input.expected, [
                    'remedy_operation_id', 'remedy_action_digest', 'destination_binding_digest',
                    'units', 'unit',
                ]))
                return failure();
            return Object.freeze({
                ok: true,
                evidence_id: payload.evidence_id,
                evidence_digest: input.evidence.evidence_digest,
                remedy_operation_id: payload.remedy_operation_id,
                remedy_action_digest: payload.remedy_action_digest,
                destination_binding_digest: payload.destination_binding_digest,
                units: payload.units,
                unit: payload.unit,
                outcome: payload.outcome,
                observed_at: payload.observed_at,
            });
        }
        catch {
            return failure();
        }
    }
    async function verifyOriginalReconciliation(input) {
        try {
            if (!exactKeys(input, new Set(['evidence', 'outcome', 'expected']))
                || !contextMatches(input.expected, pinned)
                || !validOriginal(input.expected.original, true)
                || !isDataRecord(input.evidence)
                || !validId(input.evidence.evidence_id)
                || typeof input.evidence.evidence_digest !== 'string'
                || !DIGEST.test(input.evidence.evidence_digest))
                return failure();
            const artifact = await resolveSigned(input.evidence.evidence_id, input.evidence.evidence_digest, 'original_outcome', pinned.providerAuthority);
            if (!artifact || !exactKeys(artifact.payload, ORIGINAL_OUTCOME_PAYLOAD_KEYS))
                return failure();
            const payload = artifact.payload;
            if (payload.tenant_id !== pinned.tenantId
                || payload.instance_id !== input.expected.instance_id
                || payload.evidence_id !== input.evidence.evidence_id
                || payload.observed_at !== input.evidence.observed_at
                || payload.outcome !== input.outcome
                || payload.original_operation_id !== input.expected.original.operation_id
                || payload.original_action_digest !== input.expected.original.action_digest
                || payload.terminal_evidence_digest !== input.expected.original.terminal_evidence_digest) {
                return failure();
            }
            return Object.freeze({
                ok: true,
                evidence_id: payload.evidence_id,
                evidence_digest: input.evidence.evidence_digest,
                original_operation_id: payload.original_operation_id,
                original_action_digest: payload.original_action_digest,
                terminal_evidence_digest: payload.terminal_evidence_digest,
                outcome: payload.outcome,
                observed_at: payload.observed_at,
            });
        }
        catch {
            return failure();
        }
    }
    return Object.freeze({
        verifyOriginalEffect,
        verifyRevocation: verifyRevocationEvidence,
        verifyDispute,
        verifyRemedyAuthorization,
        verifyRemedyOutcome,
        verifyOriginalReconciliation,
    });
}
export default Object.freeze({
    REMEDY_PROGRAM_EVIDENCE_VERSION,
    REMEDY_PROGRAM_EVIDENCE_DOMAIN,
    remedyProgramEvidenceDigest,
    remedyProgramEvidenceSigningBytes,
    createRemedyProgramAdapters,
});
//# sourceMappingURL=remedy-program-adapters.js.map