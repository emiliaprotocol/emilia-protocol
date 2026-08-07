// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Relying-party acceptance over one signed bounded-execution report.
 *
 * A bounded execution program says what MAY execute. This profile says which
 * Gate-recorded terminal outcomes a relying party requires before it accepts
 * the recorded process as complete. It never concludes legal compliance,
 * external effect truth, process safety, or complete mediation.
 */
import { BOUNDED_EXECUTION_REPORT_VERSION, verifyBoundedExecutionReport, } from './bounded-execution-report.js';
import { RISK_DIGEST, riskClone, riskDigest, riskExact, riskFreeze, riskIdentifier, riskRecord, signRiskBody, verifyRiskBody, } from './reliance-risk-crypto.js';
import { canonicalizeStrictJson } from './strict-json.js';
export const BOUNDED_EXECUTION_ACCEPTANCE_PROFILE_VERSION = 'EP-BOUNDED-EXECUTION-ACCEPTANCE-PROFILE-v1';
export const BOUNDED_EXECUTION_EVIDENCE_PACK_VERSION = 'EP-BOUNDED-EXECUTION-EVIDENCE-PACK-v1';
export const BOUNDED_EXECUTION_ACCEPTANCE_CLAIM_BOUNDARY = 'rp_acceptance_of_gate_recorded_program_outcomes_only_not_legal_compliance_not_external_effect_truth_not_program_safety_not_complete_mediation';
const PROFILE_INPUT_KEYS = [
    'profile_id', 'relying_party_id', 'program_id', 'program_version',
    'program_digest', 'valid_from', 'expires_at', 'accepted_program_statuses',
    'max_total_unresolved', 'max_total_reserved', 'required_nodes',
];
const PROFILE_BODY_KEYS = [
    '@version', ...PROFILE_INPUT_KEYS, 'claim_boundary', 'issuer',
];
const PROFILE_CONTEXT_KEYS = [
    'trusted_keys', 'expected_profile_id', 'expected_relying_party_id',
    'expected_program_id', 'expected_program_version', 'expected_program_digest',
    'now',
];
const REQUIRED_NODE_KEYS = [
    'node_id', 'min_terminal_occurrences', 'accepted_outcomes',
    'allow_additional_terminal_outcomes',
];
const PACK_KEYS = [
    '@version', 'profile_artifact', 'report_artifact', 'evaluation',
    'claim_boundary', 'package_digest',
];
const PACK_INPUT_KEYS = [
    'profile_artifact', 'profile_context', 'report_artifact', 'report_context',
];
const PACK_CONTEXT_KEYS = ['profile_context', 'report_context'];
const ISSUER_KEYS = ['id', 'key_id'];
const SIGNER_KEYS = ['issuer_id', 'key_id', 'private_key'];
const TRUSTED_KEY_KEYS = ['issuer_id', 'public_key'];
const PROGRAM_STATUSES = new Set(['ACTIVE', 'SUSPENDED', 'REVOKED', 'SUPERSEDED']);
const TERMINAL_OUTCOMES = new Set(['COMMITTED', 'PROVEN_NOT_COMMITTED']);
const MAX_REQUIRED_NODES = 256;
const MAX_OCCURRENCES = 1_000_000;
export class BoundedExecutionAcceptanceValidationError extends TypeError {
    code;
    constructor(code, message) {
        super(message);
        this.name = 'BoundedExecutionAcceptanceValidationError';
        this.code = code;
    }
}
function refuse(code, message) {
    throw new BoundedExecutionAcceptanceValidationError(code, message);
}
function strictJsonClone(value) {
    return JSON.parse(canonicalizeStrictJson(value));
}
function byteOrder(left, right) {
    return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}
function safeInteger(value, minimum, maximum = MAX_OCCURRENCES) {
    return Number.isSafeInteger(value) && Number(value) >= minimum && Number(value) <= maximum;
}
function canonicalInstant(value, field) {
    if (typeof value !== 'string')
        refuse('instant_invalid', `${field} must be canonical RFC 3339`);
    const parsed = Date.parse(value);
    if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
        refuse('instant_invalid', `${field} must be canonical RFC 3339`);
    }
    return value;
}
function normalizeStringSet(value, allowed, field) {
    if (!Array.isArray(value) || value.length < 1 || value.length > allowed.size
        || value.some((entry) => typeof entry !== 'string' || !allowed.has(entry))
        || new Set(value).size !== value.length) {
        refuse(`${field}_invalid`, `${field} is invalid`);
    }
    return [...value].sort(byteOrder);
}
function normalizeRequiredNodes(value) {
    if (!Array.isArray(value) || value.length < 1 || value.length > MAX_REQUIRED_NODES) {
        refuse('required_nodes_invalid', 'required_nodes must be a bounded nonempty array');
    }
    const seen = new Set();
    const nodes = value.map((entry) => {
        if (!riskExact(entry, REQUIRED_NODE_KEYS)
            || !riskIdentifier(entry.node_id)
            || !safeInteger(entry.min_terminal_occurrences, 1)
            || typeof entry.allow_additional_terminal_outcomes !== 'boolean') {
            refuse('required_node_invalid', 'required node is invalid');
        }
        if (seen.has(entry.node_id))
            refuse('required_node_duplicated', 'required node is duplicated');
        seen.add(entry.node_id);
        return {
            node_id: entry.node_id,
            min_terminal_occurrences: entry.min_terminal_occurrences,
            accepted_outcomes: normalizeStringSet(entry.accepted_outcomes, TERMINAL_OUTCOMES, 'accepted_outcomes'),
            allow_additional_terminal_outcomes: entry.allow_additional_terminal_outcomes,
        };
    });
    return nodes.sort((left, right) => byteOrder(left.node_id, right.node_id));
}
function normalizeProfileInput(value) {
    if (!riskExact(value, PROFILE_INPUT_KEYS)
        || !riskIdentifier(value.profile_id)
        || !riskIdentifier(value.relying_party_id)
        || !riskIdentifier(value.program_id)
        || !safeInteger(value.program_version, 1, Number.MAX_SAFE_INTEGER)
        || typeof value.program_digest !== 'string' || !RISK_DIGEST.test(value.program_digest)
        || !safeInteger(value.max_total_unresolved, 0)
        || !safeInteger(value.max_total_reserved, 0)) {
        refuse('profile_schema_invalid', 'acceptance profile is not a closed v1 input');
    }
    const validFrom = canonicalInstant(value.valid_from, 'valid_from');
    const expiresAt = canonicalInstant(value.expires_at, 'expires_at');
    if (Date.parse(expiresAt) <= Date.parse(validFrom)) {
        refuse('profile_time_invalid', 'profile expiry must follow validity start');
    }
    return {
        profile_id: value.profile_id,
        relying_party_id: value.relying_party_id,
        program_id: value.program_id,
        program_version: value.program_version,
        program_digest: value.program_digest,
        valid_from: validFrom,
        expires_at: expiresAt,
        accepted_program_statuses: normalizeStringSet(value.accepted_program_statuses, PROGRAM_STATUSES, 'accepted_program_statuses'),
        max_total_unresolved: value.max_total_unresolved,
        max_total_reserved: value.max_total_reserved,
        required_nodes: normalizeRequiredNodes(value.required_nodes),
    };
}
function normalizeProfileBody(value) {
    if (!riskExact(value, PROFILE_BODY_KEYS)
        || value['@version'] !== BOUNDED_EXECUTION_ACCEPTANCE_PROFILE_VERSION
        || value.claim_boundary !== BOUNDED_EXECUTION_ACCEPTANCE_CLAIM_BOUNDARY
        || !riskExact(value.issuer, ISSUER_KEYS)
        || !riskIdentifier(value.issuer.id)
        || !riskIdentifier(value.issuer.key_id)) {
        refuse('profile_schema_invalid', 'acceptance profile body is invalid');
    }
    const input = {};
    for (const key of PROFILE_INPUT_KEYS)
        input[key] = value[key];
    const normalized = normalizeProfileInput(input);
    if (value.issuer.id !== normalized.relying_party_id) {
        refuse('profile_issuer_mismatch', 'profile issuer must be the relying party');
    }
    return {
        '@version': BOUNDED_EXECUTION_ACCEPTANCE_PROFILE_VERSION,
        ...normalized,
        claim_boundary: BOUNDED_EXECUTION_ACCEPTANCE_CLAIM_BOUNDARY,
        issuer: riskClone(value.issuer),
    };
}
function normalizeProfileContext(value) {
    let context;
    try {
        context = strictJsonClone(value);
    }
    catch {
        return null;
    }
    if (!riskExact(context, PROFILE_CONTEXT_KEYS)
        || !riskRecord(context.trusted_keys)
        || Object.keys(context.trusted_keys).length < 1
        || !Object.entries(context.trusted_keys).every(([keyId, pin]) => (riskIdentifier(keyId)
            && riskExact(pin, TRUSTED_KEY_KEYS)
            && riskIdentifier(pin.issuer_id)
            && typeof pin.public_key === 'string'
            && /^[A-Za-z0-9_-]+$/.test(pin.public_key)))
        || !riskIdentifier(context.expected_profile_id)
        || !riskIdentifier(context.expected_relying_party_id)
        || !riskIdentifier(context.expected_program_id)
        || !safeInteger(context.expected_program_version, 1, Number.MAX_SAFE_INTEGER)
        || typeof context.expected_program_digest !== 'string'
        || !RISK_DIGEST.test(context.expected_program_digest))
        return null;
    try {
        canonicalInstant(context.now, 'now');
    }
    catch {
        return null;
    }
    return context;
}
export function signBoundedExecutionAcceptanceProfile(input, signer) {
    let snapshot;
    try {
        snapshot = strictJsonClone(input);
    }
    catch {
        refuse('profile_non_json', 'acceptance profile must be strict canonical JSON data');
    }
    const normalized = normalizeProfileInput(snapshot);
    if (!riskExact(signer, SIGNER_KEYS)
        || !riskIdentifier(signer.issuer_id)
        || !riskIdentifier(signer.key_id)) {
        refuse('profile_signer_invalid', 'profile signer must be a closed Ed25519 signer');
    }
    if (signer.issuer_id !== normalized.relying_party_id) {
        refuse('profile_issuer_mismatch', 'profile signer must be the relying party');
    }
    return signRiskBody(BOUNDED_EXECUTION_ACCEPTANCE_PROFILE_VERSION, {
        '@version': BOUNDED_EXECUTION_ACCEPTANCE_PROFILE_VERSION,
        ...normalized,
        claim_boundary: BOUNDED_EXECUTION_ACCEPTANCE_CLAIM_BOUNDARY,
    }, signer);
}
export function verifyBoundedExecutionAcceptanceProfile(artifact, rawContext) {
    const fail = (reason, verified = false, profileDigest = null) => riskFreeze({
        accepted: false,
        verified,
        reason,
        profile_digest: profileDigest,
        claim_boundary: BOUNDED_EXECUTION_ACCEPTANCE_CLAIM_BOUNDARY,
    });
    const context = normalizeProfileContext(rawContext);
    if (!context)
        return fail('verification_context_required');
    let snapshot;
    try {
        snapshot = strictJsonClone(artifact);
    }
    catch {
        return fail('profile_artifact_invalid');
    }
    const signed = verifyRiskBody(snapshot, BOUNDED_EXECUTION_ACCEPTANCE_PROFILE_VERSION, context.trusted_keys);
    if (!signed.valid || !signed.body || !signed.artifact_digest) {
        return fail(signed.reason ?? 'profile_signature_invalid');
    }
    let profile;
    try {
        profile = normalizeProfileBody(signed.body);
    }
    catch (error) {
        return fail(error instanceof BoundedExecutionAcceptanceValidationError
            ? error.code : 'profile_schema_invalid', true, signed.artifact_digest);
    }
    const checks = [
        [profile.profile_id !== context.expected_profile_id, 'profile_id_mismatch'],
        [profile.relying_party_id !== context.expected_relying_party_id, 'relying_party_mismatch'],
        [profile.program_id !== context.expected_program_id, 'program_id_mismatch'],
        [profile.program_version !== context.expected_program_version, 'program_version_mismatch'],
        [profile.program_digest !== context.expected_program_digest, 'program_digest_mismatch'],
    ];
    for (const [condition, reason] of checks) {
        if (condition)
            return fail(reason, true, signed.artifact_digest);
    }
    const now = Date.parse(context.now);
    if (now < Date.parse(profile.valid_from))
        return fail('profile_not_active', true, signed.artifact_digest);
    if (now >= Date.parse(profile.expires_at))
        return fail('profile_expired', true, signed.artifact_digest);
    return riskFreeze({
        accepted: true,
        verified: true,
        reason: null,
        profile_digest: signed.artifact_digest,
        profile,
        claim_boundary: BOUNDED_EXECUTION_ACCEPTANCE_CLAIM_BOUNDARY,
    });
}
function evaluationFailure(reason) {
    return riskFreeze({
        valid: false,
        verdict: null,
        reason,
        reasons: [],
        profile_digest: null,
        report_digest: null,
        claim_boundary: BOUNDED_EXECUTION_ACCEPTANCE_CLAIM_BOUNDARY,
    });
}
/**
 * Pure deterministic evaluation over an already authenticated report body.
 * Callers handling untrusted reports must use evaluateBoundedExecutionAcceptance
 * or verifyBoundedExecutionEvidencePack, which verify the report signature first.
 */
function evaluateBoundedExecutionReportBody(verifiedProfile, reportArtifact) {
    if (!riskRecord(verifiedProfile)
        || verifiedProfile.accepted !== true
        || verifiedProfile.verified !== true
        || !riskRecord(verifiedProfile.profile)
        || typeof verifiedProfile.profile_digest !== 'string') {
        return evaluationFailure('verified_profile_required');
    }
    let clonedReport;
    try {
        clonedReport = strictJsonClone(reportArtifact);
    }
    catch {
        return evaluationFailure('report_artifact_invalid');
    }
    if (!riskRecord(clonedReport))
        return evaluationFailure('report_artifact_invalid');
    const report = clonedReport;
    if (report['@version'] !== BOUNDED_EXECUTION_REPORT_VERSION
        || !riskIdentifier(report.program_id)
        || !safeInteger(report.program_version, 1, Number.MAX_SAFE_INTEGER)
        || typeof report.program_digest !== 'string' || !RISK_DIGEST.test(report.program_digest)
        || typeof report.status !== 'string' || !PROGRAM_STATUSES.has(report.status)
        || !Array.isArray(report.node_buckets)) {
        return evaluationFailure('report_schema_invalid');
    }
    const profile = verifiedProfile.profile;
    const bindingChecks = [
        [report.relying_party_id !== profile.relying_party_id, 'relying_party_mismatch'],
        [report.program_id !== profile.program_id, 'program_id_mismatch'],
        [report.program_version !== profile.program_version, 'program_version_mismatch'],
        [report.program_digest !== profile.program_digest, 'program_digest_mismatch'],
    ];
    for (const [condition, reason] of bindingChecks) {
        if (condition)
            return evaluationFailure(reason);
    }
    const buckets = new Map();
    let unresolved = 0;
    let reserved = 0;
    for (const bucket of report.node_buckets) {
        if (!riskRecord(bucket)
            || !riskIdentifier(bucket.node_id)
            || buckets.has(bucket.node_id)
            || !Array.isArray(bucket.terminal_recorded_outcomes)
            || !Array.isArray(bucket.unresolved_post_entry)
            || !riskRecord(bucket.never_attempted)
            || !Array.isArray(bucket.never_attempted.reserved_occurrence_ids)) {
            return evaluationFailure('report_node_bucket_invalid');
        }
        buckets.set(bucket.node_id, bucket);
        unresolved += bucket.unresolved_post_entry.length;
        reserved += bucket.never_attempted.reserved_occurrence_ids.length;
    }
    const indeterminateReasons = [];
    if (unresolved > profile.max_total_unresolved) {
        indeterminateReasons.push('unresolved_occurrence_limit_exceeded');
    }
    if (reserved > profile.max_total_reserved) {
        indeterminateReasons.push('reserved_occurrence_limit_exceeded');
    }
    const reportDigest = riskDigest(report);
    if (indeterminateReasons.length > 0) {
        return riskFreeze({
            valid: true,
            verdict: 'INDETERMINATE',
            reason: null,
            reasons: indeterminateReasons,
            profile_digest: verifiedProfile.profile_digest,
            report_digest: reportDigest,
            claim_boundary: BOUNDED_EXECUTION_ACCEPTANCE_CLAIM_BOUNDARY,
        });
    }
    const reasons = [];
    if (!profile.accepted_program_statuses.includes(report.status)) {
        reasons.push(`program_status_not_accepted:${report.status}`);
    }
    for (const requirement of profile.required_nodes) {
        const bucket = buckets.get(requirement.node_id);
        if (!bucket) {
            reasons.push(`required_node_missing:${requirement.node_id}`);
            continue;
        }
        let acceptedCount = 0;
        let disallowed = false;
        for (const terminal of bucket.terminal_recorded_outcomes) {
            if (!riskRecord(terminal)
                || !riskIdentifier(terminal.occurrence_id)
                || typeof terminal.outcome !== 'string'
                || !TERMINAL_OUTCOMES.has(terminal.outcome)) {
                return evaluationFailure('report_terminal_outcome_invalid');
            }
            if (requirement.accepted_outcomes.includes(terminal.outcome))
                acceptedCount += 1;
            else
                disallowed = true;
        }
        if (acceptedCount < requirement.min_terminal_occurrences) {
            reasons.push(`required_terminal_count_unsatisfied:${requirement.node_id}`);
        }
        if (disallowed && !requirement.allow_additional_terminal_outcomes) {
            reasons.push(`disallowed_terminal_outcome:${requirement.node_id}`);
        }
    }
    return riskFreeze({
        valid: true,
        verdict: (reasons.length === 0
            ? 'RECORDED_PROCESS_ACCEPTED'
            : 'RECORDED_PROCESS_NOT_ACCEPTED'),
        reason: null,
        reasons,
        profile_digest: verifiedProfile.profile_digest,
        report_digest: reportDigest,
        claim_boundary: BOUNDED_EXECUTION_ACCEPTANCE_CLAIM_BOUNDARY,
    });
}
export function evaluateBoundedExecutionAcceptance(profileArtifact, profileContext, reportArtifact, reportContext) {
    const verifiedProfile = verifyBoundedExecutionAcceptanceProfile(profileArtifact, profileContext);
    if (verifiedProfile.accepted !== true || verifiedProfile.verified !== true) {
        return evaluationFailure(verifiedProfile.reason ?? 'profile_verification_failed');
    }
    const verifiedReport = verifyBoundedExecutionReport(reportArtifact, reportContext);
    if (verifiedReport.accepted !== true || verifiedReport.verified !== true) {
        return evaluationFailure(verifiedReport.reason ?? 'report_verification_failed');
    }
    const result = evaluateBoundedExecutionReportBody(verifiedProfile, reportArtifact);
    if (result.valid && result.report_digest !== verifiedReport.report_digest) {
        return evaluationFailure('report_digest_mismatch');
    }
    return result;
}
export function buildBoundedExecutionEvidencePack(input) {
    if (!riskExact(input, PACK_INPUT_KEYS)) {
        refuse('pack_input_invalid', 'evidence pack input must be closed');
    }
    let profileArtifact;
    let reportArtifact;
    try {
        profileArtifact = strictJsonClone(input.profile_artifact);
        reportArtifact = strictJsonClone(input.report_artifact);
    }
    catch {
        refuse('pack_input_invalid', 'evidence pack artifacts must be strict canonical JSON data');
    }
    const verifiedProfile = verifyBoundedExecutionAcceptanceProfile(profileArtifact, input.profile_context);
    if (verifiedProfile.accepted !== true) {
        refuse('profile_verification_failed', `profile refused: ${verifiedProfile.reason}`);
    }
    const evaluation = evaluateBoundedExecutionAcceptance(profileArtifact, input.profile_context, reportArtifact, input.report_context);
    if (evaluation.valid !== true) {
        refuse('report_verification_failed', `report refused: ${evaluation.reason}`);
    }
    const body = {
        '@version': BOUNDED_EXECUTION_EVIDENCE_PACK_VERSION,
        profile_artifact: profileArtifact,
        report_artifact: reportArtifact,
        evaluation: riskClone(evaluation),
        claim_boundary: BOUNDED_EXECUTION_ACCEPTANCE_CLAIM_BOUNDARY,
    };
    return riskFreeze({ ...body, package_digest: riskDigest(body) });
}
export function verifyBoundedExecutionEvidencePack(artifact, context) {
    const fail = (reason) => riskFreeze({
        valid: false,
        verdict: null,
        reason,
        reasons: [],
        package_digest: null,
        claim_boundary: BOUNDED_EXECUTION_ACCEPTANCE_CLAIM_BOUNDARY,
    });
    if (!riskExact(context, PACK_CONTEXT_KEYS))
        return fail('verification_context_required');
    let clonedPack;
    try {
        clonedPack = strictJsonClone(artifact);
    }
    catch {
        return fail('package_invalid');
    }
    if (!riskRecord(clonedPack))
        return fail('package_invalid');
    const pack = clonedPack;
    if (!riskExact(pack, PACK_KEYS)
        || pack['@version'] !== BOUNDED_EXECUTION_EVIDENCE_PACK_VERSION
        || pack.claim_boundary !== BOUNDED_EXECUTION_ACCEPTANCE_CLAIM_BOUNDARY
        || typeof pack.package_digest !== 'string' || !RISK_DIGEST.test(pack.package_digest)) {
        return fail('package_invalid');
    }
    const { package_digest: statedDigest, ...body } = pack;
    if (riskDigest(body) !== statedDigest)
        return fail('package_digest_mismatch');
    const verifiedProfile = verifyBoundedExecutionAcceptanceProfile(pack.profile_artifact, context.profile_context);
    if (verifiedProfile.accepted !== true) {
        return fail(verifiedProfile.reason ?? 'profile_verification_failed');
    }
    const evaluation = evaluateBoundedExecutionAcceptance(pack.profile_artifact, context.profile_context, pack.report_artifact, context.report_context);
    if (evaluation.valid !== true)
        return fail(evaluation.reason ?? 'report_verification_failed');
    if (riskDigest(evaluation) !== riskDigest(pack.evaluation)) {
        return fail('package_evaluation_mismatch');
    }
    return riskFreeze({
        valid: true,
        verdict: evaluation.verdict,
        reason: null,
        reasons: evaluation.reasons,
        package_digest: statedDigest,
        profile_digest: evaluation.profile_digest,
        report_digest: evaluation.report_digest,
        claim_boundary: BOUNDED_EXECUTION_ACCEPTANCE_CLAIM_BOUNDARY,
    });
}
//# sourceMappingURL=bounded-execution-acceptance.js.map