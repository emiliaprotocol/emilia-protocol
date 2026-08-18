// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * EP-LOSS-ALLOCATION-SCHEDULE-v1.
 *
 * A separately signed, status-gated record of responsibility terms for one
 * relying party and one exact Reliance Program. It does not adjudicate legal
 * liability, prove solvency or coverage, authorize an action, or move money.
 */
import { canonicalize } from './execution-binding.js';
import { RISK_DIGEST, riskDigest, riskExact, riskFreeze, riskIdentifier, riskInstant, riskRecord, signRiskBody, signRiskBodyV2, verifyRiskBody, verifyRiskBodyV2, } from './reliance-risk-crypto.js';
export const LOSS_ALLOCATION_SCHEDULE_VERSION = 'EP-LOSS-ALLOCATION-SCHEDULE-v1';
export const LOSS_ALLOCATION_SCHEDULE_CLAIM_BOUNDARY = 'signed_terms_not_legal_liability_adjudication_enforceability_insurance_coverage_solvency_authorization_or_payment';
const SOURCE_KEYS = [
    'schedule_id', 'relying_party_id', 'program', 'issued_at', 'valid_from',
    'expires_at', 'status_target', 'rules', 'claim_boundary',
];
const BODY_KEYS = ['@version', ...SOURCE_KEYS, 'issuer'];
const PROGRAM_KEYS = ['program_id', 'version', 'source_digest', 'program_digest'];
const STATUS_TARGET_KEYS = ['type', 'usage'];
const RULE_KEYS = [
    'failure_class', 'responsible_party_id', 'allocation', 'terms_digest',
    'dispute_endpoint',
];
const ALLOCATION_KEYS = ['currency', 'max_amount_minor'];
const ISSUER_KEYS = ['id', 'key_id'];
const STATUS_KEYS = ['outcome', 'target_digest'];
const FAILURE_CLASS = /^[a-z][a-z0-9._-]{0,127}$/;
const CURRENCY = /^[A-Z]{3}$/;
const MINOR_AMOUNT = /^(0|[1-9][0-9]*)$/;
const MAX_RULES = 256;
const ADMISSIBILITY_VERDICTS = Object.freeze([
    'unverifiable', 'conflicted', 'stale', 'missing_evidence', 'admissible',
]);
export class LossAllocationScheduleValidationError extends TypeError {
    code;
    constructor(code, message) {
        super(message);
        this.name = 'LossAllocationScheduleValidationError';
        this.code = code;
    }
}
function refuse(code, message) {
    throw new LossAllocationScheduleValidationError(code, message);
}
function validateProgram(value) {
    return riskExact(value, PROGRAM_KEYS)
        && riskIdentifier(value.program_id)
        && Number.isSafeInteger(value.version) && value.version >= 1
        && typeof value.source_digest === 'string' && RISK_DIGEST.test(value.source_digest)
        && typeof value.program_digest === 'string' && RISK_DIGEST.test(value.program_digest);
}
function httpsEndpoint(value) {
    if (value === null)
        return true;
    if (typeof value !== 'string' || value.length > 2048)
        return false;
    try {
        const parsed = new URL(value);
        return parsed.protocol === 'https:' && parsed.username === '' && parsed.password === '';
    }
    catch {
        return false;
    }
}
function validateRules(value) {
    if (!Array.isArray(value) || value.length < 1 || value.length > MAX_RULES) {
        refuse('schedule_rules_invalid', 'loss-allocation rules must be a bounded non-empty array');
    }
    const classes = new Map();
    let previousFailureClass = null;
    for (const rule of value) {
        if (!riskExact(rule, RULE_KEYS)
            || typeof rule.failure_class !== 'string' || !FAILURE_CLASS.test(rule.failure_class)
            || !riskIdentifier(rule.responsible_party_id)
            || !riskExact(rule.allocation, ALLOCATION_KEYS)
            || typeof rule.allocation.currency !== 'string' || !CURRENCY.test(rule.allocation.currency)
            || typeof rule.allocation.max_amount_minor !== 'string'
            || !MINOR_AMOUNT.test(rule.allocation.max_amount_minor)
            || typeof rule.terms_digest !== 'string' || !RISK_DIGEST.test(rule.terms_digest)
            || !httpsEndpoint(rule.dispute_endpoint)) {
            refuse('failure_rule_invalid', 'failure rule or decimal monetary allocation is invalid');
        }
        const canonicalRule = canonicalize(rule);
        const previous = classes.get(rule.failure_class);
        if (previous !== undefined) {
            refuse(previous === canonicalRule ? 'duplicate_failure_rule' : 'conflicting_failure_rule', 'duplicate or conflicting failure class is not allowed');
        }
        if (previousFailureClass !== null && previousFailureClass > rule.failure_class) {
            refuse('rules_not_canonical_order', 'failure rules must be strictly ordered by ASCII failure class');
        }
        previousFailureClass = rule.failure_class;
        classes.set(rule.failure_class, canonicalRule);
    }
}
function validateTimes(value) {
    const issuedAt = riskInstant(value.issued_at);
    const validFrom = riskInstant(value.valid_from);
    const expiresAt = riskInstant(value.expires_at);
    if (!Number.isFinite(issuedAt) || !Number.isFinite(validFrom) || !Number.isFinite(expiresAt)
        || expiresAt <= validFrom || issuedAt > expiresAt) {
        refuse('schedule_validity_invalid', 'schedule issuance and validity window are invalid');
    }
}
function validateSource(value) {
    try {
        canonicalize(value);
    }
    catch {
        refuse('schedule_not_canonical', 'loss-allocation source is not canonicalizable JSON');
    }
    if (!riskExact(value, SOURCE_KEYS)
        || !riskIdentifier(value.schedule_id)
        || !riskIdentifier(value.relying_party_id)
        || !validateProgram(value.program)
        || !riskExact(value.status_target, STATUS_TARGET_KEYS)
        || value.status_target.type !== 'loss-allocation-schedule'
        || value.status_target.usage !== 'reliance') {
        refuse('schedule_schema_invalid', 'loss-allocation source is not a closed v1 object');
    }
    validateTimes(value);
    validateRules(value.rules);
    if (value.claim_boundary !== LOSS_ALLOCATION_SCHEDULE_CLAIM_BOUNDARY) {
        refuse('claim_boundary_invalid', 'loss-allocation claim boundary is missing or changed');
    }
}
function validateBody(value, version = LOSS_ALLOCATION_SCHEDULE_VERSION) {
    try {
        canonicalize(value);
    }
    catch {
        refuse('schedule_not_canonical', 'signed loss-allocation body is not canonicalizable JSON');
    }
    if (!riskExact(value, BODY_KEYS)
        || value['@version'] !== version
        || !riskExact(value.issuer, ISSUER_KEYS)
        || !riskIdentifier(value.issuer.id)
        || !riskIdentifier(value.issuer.key_id)) {
        refuse('schedule_schema_invalid', 'signed loss-allocation body is not a closed v1 object');
    }
    const { '@version': _version, issuer: _issuer, ...source } = value;
    validateSource(source);
}
function signedParts(artifact) {
    if (!riskRecord(artifact) || !riskRecord(artifact.proof)) {
        refuse('artifact_shape_invalid', 'signed loss-allocation artifact is malformed');
    }
    const { proof: _proof, ...body } = artifact;
    validateBody(body);
    return { artifact, body };
}
function verificationTime(value) {
    if (value === undefined)
        return Date.now();
    if (value instanceof Date)
        return value.getTime();
    if (typeof value === 'number')
        return Number.isFinite(value) ? value : NaN;
    return riskInstant(value);
}
function sameProgram(actual, expected) {
    return actual.program_id === expected.program_id
        && actual.version === expected.version
        && actual.source_digest === expected.source_digest
        && actual.program_digest === expected.program_digest;
}
/** Digest of the complete signed artifact, including its proof. */
export function lossAllocationScheduleDigest(artifact) {
    const signed = signedParts(artifact);
    return riskDigest(signed.artifact);
}
/** Digest of the exact versioned failure-class rules, excluding program pins. */
export function lossAllocationRulesDigest(artifact) {
    const signed = signedParts(artifact);
    return riskDigest({
        '@version': LOSS_ALLOCATION_SCHEDULE_VERSION,
        rules: signed.body.rules,
    });
}
/**
 * Compact digest pin for an RP-owned Admissibility Profile. Status remains a
 * separate required input; this reference does not claim global freshness.
 */
export function lossAllocationScheduleProfileReference(artifact) {
    return riskFreeze({
        artifact_type: LOSS_ALLOCATION_SCHEDULE_VERSION,
        artifact_digest: lossAllocationScheduleDigest(artifact),
        required_status: true,
    });
}
/** Sign a closed schedule under the shared JCS/Ed25519 risk-artifact proof. */
export function signLossAllocationSchedule(input, signer) {
    validateSource(input);
    if (!riskRecord(signer)
        || !riskIdentifier(signer.issuer_id)
        || !riskIdentifier(signer.key_id)
        || !Object.hasOwn(signer, 'private_key')) {
        refuse('signing_key_invalid', 'loss-allocation signer is invalid');
    }
    const body = {
        '@version': LOSS_ALLOCATION_SCHEDULE_VERSION,
        ...input,
        issuer: { id: signer.issuer_id, key_id: signer.key_id },
    };
    validateBody(body);
    try {
        return signRiskBody(LOSS_ALLOCATION_SCHEDULE_VERSION, body, signer);
    }
    catch {
        refuse('signing_key_invalid', 'loss-allocation signing key must be Ed25519');
    }
}
/** Verify signature, RP/program pins, external current status, and validity. */
export function verifyLossAllocationSchedule(artifact, options = {}) {
    const fail = (reason, verified = false, scheduleDigest = null) => ({
        accepted: false,
        verified,
        reason,
        schedule_digest: scheduleDigest,
        rules_digest: null,
        claim_boundary: LOSS_ALLOCATION_SCHEDULE_CLAIM_BOUNDARY,
    });
    const signed = verifyRiskBody(artifact, LOSS_ALLOCATION_SCHEDULE_VERSION, options.trusted_keys);
    if (!signed.valid || !signed.body || !signed.artifact_digest) {
        return fail(signed.reason ?? 'schedule_invalid');
    }
    try {
        validateBody(signed.body);
    }
    catch (error) {
        return fail(error instanceof LossAllocationScheduleValidationError
            ? error.code : 'schedule_schema_invalid');
    }
    const body = signed.body;
    const artifactDigest = signed.artifact_digest;
    if (!riskExact(options.status, STATUS_KEYS)
        || typeof options.status.target_digest !== 'string'
        || !RISK_DIGEST.test(options.status.target_digest)) {
        return fail('schedule_status_required', true, artifactDigest);
    }
    if (options.status.target_digest !== artifactDigest) {
        return fail('status_target_mismatch', true, artifactDigest);
    }
    if (options.status.outcome === 'revoked') {
        return fail('schedule_revoked', true, artifactDigest);
    }
    if (options.status.outcome !== 'current_not_revoked') {
        return fail('schedule_status_not_current', true, artifactDigest);
    }
    const now = verificationTime(options.now);
    if (!Number.isFinite(now))
        return fail('verification_time_invalid', true, artifactDigest);
    if (now < riskInstant(body.issued_at)) {
        return fail('schedule_not_yet_issued', true, artifactDigest);
    }
    if (now < riskInstant(body.valid_from)) {
        return fail('schedule_not_yet_valid', true, artifactDigest);
    }
    if (now >= riskInstant(body.expires_at)) {
        return fail('schedule_stale', true, artifactDigest);
    }
    if (options.expected_relying_party_id === undefined) {
        return fail('relying_party_binding_required', true, artifactDigest);
    }
    if (!riskIdentifier(options.expected_relying_party_id)
        || options.expected_relying_party_id !== body.relying_party_id) {
        return fail('relying_party_binding_mismatch', true, artifactDigest);
    }
    if (options.expected_program === undefined) {
        return fail('program_binding_required', true, artifactDigest);
    }
    if (!validateProgram(options.expected_program)) {
        return fail('expected_program_invalid', true, artifactDigest);
    }
    if (!sameProgram(body.program, options.expected_program)) {
        return fail('reliance_program_binding_mismatch', true, artifactDigest);
    }
    return riskFreeze({
        accepted: true,
        verified: true,
        reason: null,
        schedule_digest: artifactDigest,
        rules_digest: lossAllocationRulesDigest(artifact),
        schedule_id: body.schedule_id,
        relying_party_id: body.relying_party_id,
        program_id: body.program.program_id,
        program_version: body.program.version,
        source_digest: body.program.source_digest,
        program_digest: body.program.program_digest,
        issuer_id: body.issuer.id,
        key_id: body.issuer.key_id,
        status: 'current_not_revoked',
        claim_boundary: LOSS_ALLOCATION_SCHEDULE_CLAIM_BOUNDARY,
    });
}
/**
 * Build a standard self-hashed Admissibility Profile and its unchanged
 * Reliance Program v1 profile reference. Only schedule identity, RP, issuer,
 * and exact rules are pinned here; final program digests are deliberately
 * excluded to avoid a profile/program/schedule digest cycle.
 */
export function createLossAllocationAdmissibilityProfilePin(artifact, { profileId, evaluationMaxAgeSec, }, verification) {
    const signed = signedParts(artifact);
    const verified = verifyLossAllocationSchedule(artifact, verification);
    if (verified.accepted !== true) {
        refuse('schedule_verification_required', `cannot pin an unaccepted schedule: ${verified.reason}`);
    }
    if (!riskIdentifier(profileId)
        || !Number.isSafeInteger(evaluationMaxAgeSec)
        || evaluationMaxAgeSec < 1 || evaluationMaxAgeSec > 31_536_000) {
        refuse('admissibility_profile_pin_invalid', 'profile id and evaluation age must be bounded');
    }
    const profileBody = {
        id: profileId,
        version: 1,
        authored_by: signed.body.relying_party_id,
        requires: [{
                evidence: 'loss_allocation_schedule',
                max_staleness_sec: evaluationMaxAgeSec,
                checks: [
                    'signature_valid',
                    'reliance_program_binding_valid',
                    'rules_digest_matches',
                    'status_current',
                ],
            }],
        verdicts: [...ADMISSIBILITY_VERDICTS],
        loss_allocation_schedule: {
            artifact_version: LOSS_ALLOCATION_SCHEDULE_VERSION,
            schedule_id: signed.body.schedule_id,
            relying_party_id: signed.body.relying_party_id,
            issuer_id: signed.body.issuer.id,
            issuer_key_id: signed.body.issuer.key_id,
            rules_digest: lossAllocationRulesDigest(artifact),
        },
    };
    const profile = {
        ...profileBody,
        profile_hash: riskDigest(profileBody),
    };
    return riskFreeze({
        profile,
        reference: {
            profile_id: profile.id,
            profile_hash: profile.profile_hash,
            evaluation_max_age_sec: evaluationMaxAgeSec,
            revocation_required: true,
        },
    });
}
// ===========================================================================
// EP-LOSS-ALLOCATION-SCHEDULE-v2 -- opt-in hybrid adoption of EP-RISK-HYBRID-v2
// ===========================================================================
// ADDITIVE: signLossAllocationSchedule / verifyLossAllocationSchedule above are
// UNCHANGED. This is the ADOPTION application of "PATTERN: the reference
// hybrid migration" (EP-REVOCATION-v2 is the template) in
// docs/protocol/pq-hybrid-program.md: this module already delegates signing to
// reliance-risk-crypto.js's shared signRiskBody/verifyRiskBody, so it adopts
// signRiskBodyV2/verifyRiskBodyV2 (EP-RISK-HYBRID-v2) rather than
// reimplementing the set-shaped proof, the anti-stripping bytes, or the pin
// discipline here. A deployed v1 verifier handed a v2 schedule refuses on its
// version/schema check BEFORE inspecting any signature; v2 verification is a
// SEPARATE async entry point.
export const LOSS_ALLOCATION_SCHEDULE_V2_VERSION = 'EP-LOSS-ALLOCATION-SCHEDULE-v2';
/** Mint the hybrid (Ed25519 + ML-DSA-65), set-committed twin of signLossAllocationSchedule. */
export async function signLossAllocationScheduleV2(input, signer, options = {}) {
    validateSource(input);
    if (!riskRecord(signer)
        || !riskIdentifier(signer.issuer_id)
        || !riskIdentifier(signer.key_id)
        || !Object.hasOwn(signer, 'private_key')
        || !Object.hasOwn(signer, 'pq_private_key')) {
        refuse('signing_key_invalid', 'loss-allocation hybrid signer is invalid');
    }
    const body = {
        '@version': LOSS_ALLOCATION_SCHEDULE_V2_VERSION,
        ...input,
        issuer: { id: signer.issuer_id, key_id: signer.key_id },
    };
    validateBody(body, LOSS_ALLOCATION_SCHEDULE_V2_VERSION);
    try {
        return await signRiskBodyV2(LOSS_ALLOCATION_SCHEDULE_V2_VERSION, body, signer, options);
    }
    catch {
        refuse('signing_key_invalid', 'loss-allocation hybrid signing keys must be Ed25519 + ML-DSA-65');
    }
}
/**
 * FAIL-CLOSED hybrid verify, the set-committed twin of verifyLossAllocationSchedule.
 * A v2 schedule NEVER verifies on one leg alone; an absent ML-DSA backend is a
 * refusal, never a skipped check and never a pass on the surviving classical leg.
 */
export async function verifyLossAllocationScheduleV2(artifact, options = {}) {
    const fail = (reason, verified = false, scheduleDigest = null) => ({
        accepted: false,
        verified,
        reason,
        schedule_digest: scheduleDigest,
        rules_digest: null,
        claim_boundary: LOSS_ALLOCATION_SCHEDULE_CLAIM_BOUNDARY,
    });
    const signed = await verifyRiskBodyV2(artifact, LOSS_ALLOCATION_SCHEDULE_V2_VERSION, options.trusted_keys, options);
    if (!signed.valid || !signed.body || !signed.artifact_digest) {
        return fail(signed.reason ?? 'schedule_invalid');
    }
    try {
        validateBody(signed.body, LOSS_ALLOCATION_SCHEDULE_V2_VERSION);
    }
    catch (error) {
        return fail(error instanceof LossAllocationScheduleValidationError
            ? error.code : 'schedule_schema_invalid');
    }
    const body = signed.body;
    const artifactDigest = signed.artifact_digest;
    if (!riskExact(options.status, STATUS_KEYS)
        || typeof options.status.target_digest !== 'string'
        || !RISK_DIGEST.test(options.status.target_digest)) {
        return fail('schedule_status_required', true, artifactDigest);
    }
    if (options.status.target_digest !== artifactDigest) {
        return fail('status_target_mismatch', true, artifactDigest);
    }
    if (options.status.outcome === 'revoked') {
        return fail('schedule_revoked', true, artifactDigest);
    }
    if (options.status.outcome !== 'current_not_revoked') {
        return fail('schedule_status_not_current', true, artifactDigest);
    }
    const now = verificationTime(options.now);
    if (!Number.isFinite(now))
        return fail('verification_time_invalid', true, artifactDigest);
    if (now < riskInstant(body.issued_at)) {
        return fail('schedule_not_yet_issued', true, artifactDigest);
    }
    if (now < riskInstant(body.valid_from)) {
        return fail('schedule_not_yet_valid', true, artifactDigest);
    }
    if (now >= riskInstant(body.expires_at)) {
        return fail('schedule_stale', true, artifactDigest);
    }
    if (options.expected_relying_party_id === undefined) {
        return fail('relying_party_binding_required', true, artifactDigest);
    }
    if (!riskIdentifier(options.expected_relying_party_id)
        || options.expected_relying_party_id !== body.relying_party_id) {
        return fail('relying_party_binding_mismatch', true, artifactDigest);
    }
    if (options.expected_program === undefined) {
        return fail('program_binding_required', true, artifactDigest);
    }
    if (!validateProgram(options.expected_program)) {
        return fail('expected_program_invalid', true, artifactDigest);
    }
    if (!sameProgram(body.program, options.expected_program)) {
        return fail('reliance_program_binding_mismatch', true, artifactDigest);
    }
    return riskFreeze({
        accepted: true,
        verified: true,
        reason: null,
        schedule_digest: artifactDigest,
        rules_digest: riskDigest({
            '@version': LOSS_ALLOCATION_SCHEDULE_V2_VERSION,
            rules: body.rules,
        }),
        schedule_id: body.schedule_id,
        relying_party_id: body.relying_party_id,
        program_id: body.program.program_id,
        program_version: body.program.version,
        source_digest: body.program.source_digest,
        program_digest: body.program.program_digest,
        issuer_id: body.issuer.id,
        key_id: body.issuer.key_id,
        status: 'current_not_revoked',
        claim_boundary: LOSS_ALLOCATION_SCHEDULE_CLAIM_BOUNDARY,
    });
}
//# sourceMappingURL=loss-allocation-schedule.js.map