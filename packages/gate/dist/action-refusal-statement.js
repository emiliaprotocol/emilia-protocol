// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Exact-action technical refusal evidence. It is not a legal determination,
 * an adverse-benefit denial, an authorization grant, or proof of delivery.
 */
import { RISK_CAID, RISK_DIGEST, riskClone, riskDigest, riskExact, riskIdentifier, riskInstant, riskRecord, signRiskBody, verifyRiskBody, } from './reliance-risk-crypto.js';
export const ACTION_REFUSAL_STATEMENT_VERSION = 'EP-ACTION-REFUSAL-STATEMENT-v1';
export const ACTION_REFUSAL_CLAIM_BOUNDARY = 'technical_refusal_not_legal_or_benefit_determination';
export const ACTION_REFUSAL_CLASSES = Object.freeze([
    'verification_failed',
    'action_mismatch',
    'evidence_unsatisfied',
    'authorization_refused',
    'replay_detected',
    'expired',
    'indeterminate',
]);
const PROGRAM_KEYS = ['program_id', 'version', 'source_digest', 'program_digest'];
const DELIVERY_KEYS = ['channel', 'recipient_id', 'delivered_at', 'custody_digest'];
const CUSTODY_KEYS = ['custodian_id', 'acknowledged_at', 'evidence_digest'];
const ANCHOR_KEYS = ['method', 'evidence_digest'];
const SEMANTIC_KEYS = ['verification', 'match', 'satisfaction', 'authorization'];
const BODY_KEYS = [
    '@version', 'refusal_id', 'relying_party_id', 'caid', 'action_digest',
    'program', 'failed_requirement_ids', 'evidence_digests',
    'challenge_digests', 'nonce', 'refused_at', 'expires_at', 'refusal_class',
    'semantics', 'delivery', 'custody', 'transparency_anchor', 'claim_boundary',
];
const INPUT_KEYS = new Set([
    ...BODY_KEYS.filter((key) => key !== '@version' && key !== 'semantics'
        && key !== 'delivery' && key !== 'custody' && key !== 'transparency_anchor'
        && key !== 'challenge_digests'),
    'semantics', 'delivery', 'custody', 'transparency_anchor',
    'challenge_digest', 'challenge_digests',
]);
const EXPECTED_KEYS = [
    'caid', 'action_digest', 'relying_party_id', 'program_id', 'program_version',
    'source_digest', 'program_digest', 'nonce',
];
const VERIFICATION = new Set(['VERIFIED', 'NOT_VERIFIED', 'INDETERMINATE']);
const MATCH = new Set(['MATCH', 'MISMATCH', 'INDETERMINATE']);
const SATISFACTION = new Set(['SATISFIED', 'NOT_SATISFIED', 'INDETERMINATE']);
const AUTHORIZATION = new Set(['AUTHORIZED', 'NOT_AUTHORIZED', 'NOT_EVALUATED', 'INDETERMINATE']);
function canonicalSet(value, validator, maximum, requireNonEmpty) {
    if (!Array.isArray(value) || value.length > maximum
        || (requireNonEmpty && value.length === 0) || !value.every(validator)
        || new Set(value).size !== value.length)
        return false;
    return value.every((entry, index) => index === 0
        || Buffer.from(value[index - 1]).compare(Buffer.from(entry)) < 0);
}
function sortedUnique(value, validator, maximum, label, requireNonEmpty) {
    if (!Array.isArray(value) || value.length > maximum
        || (requireNonEmpty && value.length === 0) || !value.every(validator)) {
        throw new TypeError(`action refusal ${label} are invalid`);
    }
    if (new Set(value).size !== value.length) {
        throw new TypeError(`action refusal ${label} are duplicate`);
    }
    return [...value].sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
}
function defaultSemantics(refusalClass) {
    const base = {
        verification: 'VERIFIED',
        match: 'MATCH',
        satisfaction: 'NOT_SATISFIED',
        authorization: 'NOT_EVALUATED',
    };
    if (refusalClass === 'verification_failed')
        return { ...base, verification: 'NOT_VERIFIED' };
    if (refusalClass === 'action_mismatch')
        return { ...base, match: 'MISMATCH' };
    if (refusalClass === 'authorization_refused')
        return { ...base, authorization: 'NOT_AUTHORIZED' };
    if (refusalClass === 'indeterminate')
        return { ...base, satisfaction: 'INDETERMINATE' };
    return base;
}
function validSemantics(value, refusalClass) {
    if (!riskExact(value, SEMANTIC_KEYS)
        || !VERIFICATION.has(value.verification) || !MATCH.has(value.match)
        || !SATISFACTION.has(value.satisfaction) || !AUTHORIZATION.has(value.authorization)
        || value.satisfaction === 'SATISFIED')
        return false;
    if (refusalClass === 'verification_failed')
        return value.verification === 'NOT_VERIFIED';
    if (refusalClass === 'action_mismatch')
        return value.match === 'MISMATCH';
    if (refusalClass === 'evidence_unsatisfied')
        return value.satisfaction === 'NOT_SATISFIED';
    if (refusalClass === 'authorization_refused')
        return value.authorization === 'NOT_AUTHORIZED';
    if (refusalClass === 'indeterminate')
        return Object.values(value).includes('INDETERMINATE');
    return true;
}
function validate(value) {
    if (!riskRecord(value))
        throw new TypeError('action refusal statement shape is invalid');
    const { issuer, ...body } = value;
    if (issuer !== undefined && (!riskExact(issuer, ['id', 'key_id'])
        || !riskIdentifier(issuer.id) || !riskIdentifier(issuer.key_id))) {
        throw new TypeError('action refusal issuer is invalid');
    }
    if (!riskExact(body, BODY_KEYS) || body['@version'] !== ACTION_REFUSAL_STATEMENT_VERSION
        || !riskIdentifier(body.refusal_id) || !riskIdentifier(body.relying_party_id)
        || typeof body.caid !== 'string' || !RISK_CAID.test(body.caid)
        || typeof body.action_digest !== 'string' || !RISK_DIGEST.test(body.action_digest)
        || !riskExact(body.program, PROGRAM_KEYS) || !riskIdentifier(body.program.program_id)
        || !Number.isSafeInteger(body.program.version) || body.program.version < 1
        || typeof body.program.source_digest !== 'string' || !RISK_DIGEST.test(body.program.source_digest)
        || typeof body.program.program_digest !== 'string' || !RISK_DIGEST.test(body.program.program_digest)
        || !riskIdentifier(body.nonce) || !ACTION_REFUSAL_CLASSES.includes(body.refusal_class)
        || !validSemantics(body.semantics, body.refusal_class)
        || body.claim_boundary !== ACTION_REFUSAL_CLAIM_BOUNDARY) {
        throw new TypeError('action refusal statement shape is invalid');
    }
    if (!canonicalSet(body.failed_requirement_ids, riskIdentifier, 128, true)) {
        throw new TypeError('action refusal requirements are invalid, duplicate, or unsorted');
    }
    if (!canonicalSet(body.evidence_digests, (entry) => typeof entry === 'string' && RISK_DIGEST.test(entry), 256, false) || !canonicalSet(body.challenge_digests, (entry) => typeof entry === 'string' && RISK_DIGEST.test(entry), 256, true))
        throw new TypeError('action refusal evidence or challenge binding is invalid');
    const refused = riskInstant(body.refused_at);
    const expires = riskInstant(body.expires_at);
    if (!Number.isFinite(refused) || !Number.isFinite(expires) || expires <= refused) {
        throw new TypeError('action refusal time window is invalid');
    }
    if (body.delivery !== null && (!riskExact(body.delivery, DELIVERY_KEYS)
        || !riskIdentifier(body.delivery.channel) || !riskIdentifier(body.delivery.recipient_id)
        || !Number.isFinite(riskInstant(body.delivery.delivered_at))
        || riskInstant(body.delivery.delivered_at) < refused
        || riskInstant(body.delivery.delivered_at) > expires
        || typeof body.delivery.custody_digest !== 'string'
        || !RISK_DIGEST.test(body.delivery.custody_digest))) {
        throw new TypeError('action refusal delivery evidence is invalid');
    }
    if (body.custody !== null && (body.delivery === null
        || !riskExact(body.custody, CUSTODY_KEYS)
        || !riskIdentifier(body.custody.custodian_id)
        || !Number.isFinite(riskInstant(body.custody.acknowledged_at))
        || riskInstant(body.custody.acknowledged_at) < riskInstant(body.delivery.delivered_at)
        || riskInstant(body.custody.acknowledged_at) > expires
        || typeof body.custody.evidence_digest !== 'string'
        || !RISK_DIGEST.test(body.custody.evidence_digest))) {
        throw new TypeError('action refusal custody evidence is invalid');
    }
    if (body.transparency_anchor !== null && (!riskExact(body.transparency_anchor, ANCHOR_KEYS)
        || !riskIdentifier(body.transparency_anchor.method)
        || typeof body.transparency_anchor.evidence_digest !== 'string'
        || !RISK_DIGEST.test(body.transparency_anchor.evidence_digest))) {
        throw new TypeError('action refusal transparency anchor is invalid');
    }
}
function normalizedInput(input) {
    const required = [
        'refusal_id', 'relying_party_id', 'caid', 'action_digest', 'program',
        'failed_requirement_ids', 'evidence_digests', 'nonce', 'refused_at',
        'expires_at', 'refusal_class', 'claim_boundary',
    ];
    if (!riskRecord(input) || !required.every((key) => Object.hasOwn(input, key))
        || !Object.keys(input).every((key) => INPUT_KEYS.has(key))
        || (Object.hasOwn(input, 'challenge_digest') === Object.hasOwn(input, 'challenge_digests'))) {
        throw new TypeError('action refusal input shape is invalid');
    }
    const rawChallenges = input.challenge_digests ?? [input.challenge_digest];
    return {
        '@version': ACTION_REFUSAL_STATEMENT_VERSION,
        refusal_id: input.refusal_id,
        relying_party_id: input.relying_party_id,
        caid: input.caid,
        action_digest: input.action_digest,
        program: input.program,
        failed_requirement_ids: sortedUnique(input.failed_requirement_ids, riskIdentifier, 128, 'requirements', true),
        evidence_digests: sortedUnique(input.evidence_digests, (entry) => typeof entry === 'string' && RISK_DIGEST.test(entry), 256, 'evidence digests', false),
        challenge_digests: sortedUnique(rawChallenges, (entry) => typeof entry === 'string' && RISK_DIGEST.test(entry), 256, 'challenge digests', true),
        nonce: input.nonce,
        refused_at: input.refused_at,
        expires_at: input.expires_at,
        refusal_class: input.refusal_class,
        semantics: input.semantics ?? defaultSemantics(input.refusal_class),
        delivery: input.delivery ?? null,
        custody: input.custody ?? null,
        transparency_anchor: input.transparency_anchor ?? null,
        claim_boundary: input.claim_boundary,
    };
}
export function signActionRefusalStatement(input, signer) {
    const body = normalizedInput(input);
    validate(body);
    return signRiskBody(ACTION_REFUSAL_STATEMENT_VERSION, body, signer);
}
export function actionRefusalStatementDigest(statement) {
    return riskDigest(statement);
}
function expectedMismatch(body, expected) {
    if (expected === undefined)
        return null;
    if (!riskRecord(expected) || !Object.keys(expected).every((key) => EXPECTED_KEYS.includes(key))) {
        return 'expected_binding_invalid';
    }
    const bindings = {
        caid: body.caid,
        action_digest: body.action_digest,
        relying_party_id: body.relying_party_id,
        program_id: body.program.program_id,
        program_version: body.program.version,
        source_digest: body.program.source_digest,
        program_digest: body.program.program_digest,
        nonce: body.nonce,
    };
    for (const key of Object.keys(expected)) {
        if (bindings[key] !== expected[key])
            return `${key}_mismatch`;
    }
    return null;
}
export function verifyActionRefusalStatement(statement, options = {}) {
    const refuse = (reason, refusalDigest = null) => ({
        accepted: false,
        verified: false,
        reason,
        refusal_digest: refusalDigest,
        semantics: null,
        delivery_evidence: 'NOT_EVIDENCED',
        custody_evidence: 'NOT_EVIDENCED',
        transparency_anchor: 'NOT_REFERENCED',
        claim_boundary: ACTION_REFUSAL_CLAIM_BOUNDARY,
    });
    const signed = verifyRiskBody(statement, ACTION_REFUSAL_STATEMENT_VERSION, options.trusted_keys);
    if (!signed.valid || !signed.body)
        return refuse(signed.reason ?? 'refusal_invalid');
    try {
        validate(signed.body);
    }
    catch {
        return refuse('refusal_schema_invalid', signed.artifact_digest);
    }
    const now = options.now === undefined
        ? Date.now() : (typeof options.now === 'string' ? Date.parse(options.now) : Number(options.now));
    const skew = options.max_future_skew_sec ?? 30;
    if (!Number.isFinite(now) || !Number.isSafeInteger(skew) || skew < 0 || skew > 3600) {
        return refuse('verification_time_invalid', signed.artifact_digest);
    }
    if (riskInstant(signed.body.refused_at) > now + skew * 1000) {
        return refuse('refusal_from_future', signed.artifact_digest);
    }
    if (now >= riskInstant(signed.body.expires_at)) {
        return refuse('refusal_expired', signed.artifact_digest);
    }
    const mismatch = expectedMismatch(signed.body, options.expected);
    if (mismatch)
        return refuse(mismatch, signed.artifact_digest);
    return {
        accepted: true,
        verified: true,
        reason: null,
        refusal_digest: signed.artifact_digest,
        relying_party_id: signed.body.relying_party_id,
        nonce: signed.body.nonce,
        semantics: riskClone(signed.body.semantics),
        delivery_evidence: signed.body.delivery === null ? 'NOT_EVIDENCED' : 'REFERENCED',
        custody_evidence: signed.body.custody === null ? 'NOT_EVIDENCED' : 'REFERENCED',
        transparency_anchor: signed.body.transparency_anchor === null
            ? 'NOT_REFERENCED' : 'REFERENCED_NOT_EXTERNALLY_VERIFIED',
        claim_boundary: ACTION_REFUSAL_CLAIM_BOUNDARY,
    };
}
export function createMemoryActionRefusalReplayStore() {
    const consumed = new Map();
    return Object.freeze({
        durable: false,
        async consume(relyingPartyId, nonce, refusalDigest) {
            const key = JSON.stringify([relyingPartyId, nonce]);
            const existing = consumed.get(key);
            if (existing === undefined) {
                consumed.set(key, refusalDigest);
                return { accepted: true, reason: null };
            }
            if (existing === refusalDigest)
                return { accepted: false, reason: 'statement_replay' };
            return { accepted: false, reason: 'nonce_equivocation' };
        },
    });
}
const EXTERNAL_LEGS = ['delivery', 'custody', 'transparency_anchor'];
/**
 * Verify referenced delivery, custody, and transparency evidence with
 * relying-party-pinned adapters. A digest reference alone remains explicitly
 * unverified. This function never upgrades REFERENCED into VERIFIED by itself.
 */
export async function verifyActionRefusalExternalEvidence(statement, options = {}) {
    const required = new Set(options.required ?? []);
    if ([...required].some((leg) => !EXTERNAL_LEGS.includes(leg))) {
        return { accepted: false, reason: 'external_evidence_requirement_invalid', legs: null };
    }
    const signed = verifyRiskBody(statement, ACTION_REFUSAL_STATEMENT_VERSION, options.trusted_keys);
    if (!signed.valid || !signed.body) {
        return { accepted: false, reason: signed.reason ?? 'refusal_invalid', legs: null };
    }
    try {
        validate(signed.body);
    }
    catch {
        return { accepted: false, reason: 'refusal_schema_invalid', legs: null };
    }
    const body = signed.body;
    const expectedDigests = {
        delivery: body.delivery?.custody_digest,
        custody: body.custody?.evidence_digest,
        transparency_anchor: body.transparency_anchor?.evidence_digest,
    };
    const legs = {};
    for (const leg of EXTERNAL_LEGS) {
        const reference = body[leg];
        if (reference === null) {
            legs[leg] = { status: 'ABSENT', evidence_digest: null, reason: null };
            if (required.has(leg)) {
                return { accepted: false, reason: `${leg}_reference_required`, legs };
            }
            continue;
        }
        const verifier = options.verifiers?.[leg];
        if (typeof verifier !== 'function') {
            legs[leg] = {
                status: 'REFERENCED_NOT_EXTERNALLY_VERIFIED',
                evidence_digest: expectedDigests[leg],
                reason: 'verifier_not_configured',
            };
            if (required.has(leg)) {
                return { accepted: false, reason: `${leg}_verifier_required`, legs };
            }
            continue;
        }
        let result;
        try {
            result = await verifier({
                statement: riskClone(statement),
                reference: riskClone(reference),
                expected_evidence_digest: expectedDigests[leg],
            });
        }
        catch {
            legs[leg] = {
                status: 'INDETERMINATE',
                evidence_digest: expectedDigests[leg],
                reason: 'verifier_unavailable',
            };
            return { accepted: false, reason: `${leg}_verification_indeterminate`, legs };
        }
        if (!riskExact(result, ['status', 'evidence_digest', 'reason'])
            || !['VERIFIED', 'NOT_VERIFIED', 'INDETERMINATE'].includes(result.status)
            || typeof result.evidence_digest !== 'string' || !RISK_DIGEST.test(result.evidence_digest)
            || (result.reason !== null && typeof result.reason !== 'string')) {
            legs[leg] = {
                status: 'INDETERMINATE',
                evidence_digest: expectedDigests[leg],
                reason: 'verifier_result_invalid',
            };
            return { accepted: false, reason: `${leg}_verifier_result_invalid`, legs };
        }
        if (result.evidence_digest !== expectedDigests[leg]) {
            legs[leg] = {
                status: 'NOT_VERIFIED',
                evidence_digest: result.evidence_digest,
                reason: 'evidence_digest_mismatch',
            };
            return { accepted: false, reason: `${leg}_evidence_digest_mismatch`, legs };
        }
        legs[leg] = riskClone(result);
        if (result.status !== 'VERIFIED') {
            const suffix = result.status === 'INDETERMINATE' ? 'verification_indeterminate' : 'not_verified';
            return { accepted: false, reason: `${leg}_${suffix}`, legs };
        }
    }
    return { accepted: true, reason: null, legs };
}
export async function acceptActionRefusalStatement(statement, options = {}) {
    const verification = verifyActionRefusalStatement(statement, options);
    const refused = (reason, checked = false, durable = false) => ({
        ...verification,
        accepted: false,
        reason,
        replay_checked: checked,
        replay_store_durable: durable,
    });
    if (!verification.verified)
        return refused(verification.reason);
    if (typeof verification.refusal_digest !== 'string')
        return refused('refusal_digest_missing');
    if (!riskExact(options.expected, EXPECTED_KEYS))
        return refused('complete_expected_binding_required');
    let externalEvidence = null;
    if (options.external_evidence !== undefined) {
        externalEvidence = await verifyActionRefusalExternalEvidence(statement, {
            ...options.external_evidence,
            trusted_keys: options.external_evidence.trusted_keys ?? options.trusted_keys,
        });
        if (!externalEvidence.accepted) {
            return { ...refused(externalEvidence.reason), external_evidence: externalEvidence };
        }
    }
    const store = options.replayStore;
    if (!store || typeof store.consume !== 'function' || typeof store.durable !== 'boolean') {
        return refused('replay_store_required');
    }
    if (!store.durable && options.allowEphemeralReplayStore !== true) {
        return refused('durable_replay_store_required');
    }
    let result;
    try {
        result = await store.consume(verification.relying_party_id, verification.nonce, verification.refusal_digest);
    }
    catch {
        return refused('replay_store_unavailable', false, store.durable);
    }
    if (!riskExact(result, ['accepted', 'reason']) || typeof result.accepted !== 'boolean'
        || (result.reason !== null && typeof result.reason !== 'string')) {
        return refused('replay_store_result_invalid', false, store.durable);
    }
    if (!result.accepted) {
        const reason = result.reason === 'statement_replay' || result.reason === 'nonce_equivocation'
            ? result.reason : 'replay_store_refused';
        return refused(reason, true, store.durable);
    }
    if (result.reason !== null)
        return refused('replay_store_result_invalid', true, store.durable);
    return {
        ...verification,
        accepted: true,
        replay_checked: true,
        replay_store_durable: store.durable,
        external_evidence: externalEvidence,
    };
}
//# sourceMappingURL=action-refusal-statement.js.map