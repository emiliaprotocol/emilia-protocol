// SPDX-License-Identifier: Apache-2.0
/**
 * Offline, zero-dependency claim assurance kernel.
 *
 * A Claim Case presents artifacts. It does not present trust. The relying party
 * pins the profile bytes, their digest, and executable verifier registrations
 * out of band. The resulting Assurance Record reports verification only. It is
 * never authority to perform an action, even when it is bound to one.
 */
import crypto from 'node:crypto';
import { canonicalizeStrictJson, } from './strict-json.js';
export const CLAIM_ASSURANCE_PROFILE_VERSION = 'EP-CLAIM-ASSURANCE-PROFILE-v1';
export const CLAIM_CASE_VERSION = 'EP-CLAIM-CASE-v1';
export const ASSURANCE_RECORD_VERSION = 'EP-ASSURANCE-RECORD-v1';
export const CLAIM_ASSURANCE_VERDICTS = [
    'VERIFIED',
    'UNVERIFIED',
    'DIVERGED',
    'INDETERMINATE',
];
export const EVIDENCE_VERDICTS = ['VERIFIED', 'UNVERIFIED', 'INDETERMINATE'];
export const EVIDENCE_RELATIONSHIPS = ['SUPPORTS', 'CONTRADICTS', 'NEUTRAL'];
export const CLAIM_ASSURANCE_LIMITS = Object.freeze({
    max_profile_requirements: 16,
    max_evidence_items: 32,
    max_verifier_registrations: 32,
    max_artifact_depth: 32,
    max_artifact_nodes: 10_000,
    max_artifact_string_bytes: 262_144,
    max_case_depth: 40,
    max_case_nodes: 330_000,
    max_case_string_bytes: 8_454_144,
    max_identifier_bytes: 128,
    max_claim_label_bytes: 256,
    max_verifier_reasons: 16,
    max_verifier_reason_bytes: 256,
});
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const CANONICAL_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._:/-]*$/;
const PROFILE_LIMITS = {
    maxDepth: 12,
    maxNodes: 512,
    maxStringBytes: 32_768,
};
const CASE_LIMITS = {
    maxDepth: CLAIM_ASSURANCE_LIMITS.max_case_depth,
    maxNodes: CLAIM_ASSURANCE_LIMITS.max_case_nodes,
    maxStringBytes: CLAIM_ASSURANCE_LIMITS.max_case_string_bytes,
};
const ARTIFACT_LIMITS = {
    maxDepth: CLAIM_ASSURANCE_LIMITS.max_artifact_depth,
    maxNodes: CLAIM_ASSURANCE_LIMITS.max_artifact_nodes,
    maxStringBytes: CLAIM_ASSURANCE_LIMITS.max_artifact_string_bytes,
};
const VERIFIER_RESULT_LIMITS = {
    maxDepth: 8,
    maxNodes: 128,
    maxStringBytes: 8_192,
};
function protocolError(message) {
    throw new TypeError(`claim assurance: ${message}`);
}
function utf8Length(value) {
    return new TextEncoder().encode(value).byteLength;
}
function asObject(value, path) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        protocolError(`${path} must be an object`);
    }
    return value;
}
function assertExactKeys(value, path, required, optional = []) {
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value).sort()) {
        if (!allowed.has(key))
            protocolError(`unknown member ${path}.${key}`);
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key))
            protocolError(`${path}.${key} is required`);
    }
}
function assertBoundedString(value, path, maxBytes) {
    if (typeof value !== 'string' || value.length === 0 || utf8Length(value) > maxBytes || /[\u0000-\u001f\u007f]/.test(value)) {
        protocolError(`${path} must be a non-empty bounded string without control characters`);
    }
}
function assertIdentifier(value, path) {
    assertBoundedString(value, path, CLAIM_ASSURANCE_LIMITS.max_identifier_bytes);
    if (!IDENTIFIER_RE.test(value))
        protocolError(`${path} is not a valid identifier`);
}
function assertLabel(value, path) {
    assertBoundedString(value, path, CLAIM_ASSURANCE_LIMITS.max_claim_label_bytes);
}
function assertDigest(value, path) {
    if (typeof value !== 'string' || !DIGEST_RE.test(value)) {
        protocolError(`${path} must be sha256:<64 lowercase hex>`);
    }
}
function assertCanonicalTimestamp(value, path) {
    if (typeof value !== 'string' || !CANONICAL_UTC_RE.test(value)) {
        protocolError(`${path} must be a canonical UTC timestamp (YYYY-MM-DDTHH:mm:ssZ)`);
    }
    const time = Date.parse(value);
    if (!Number.isFinite(time) || new Date(time).toISOString().replace('.000Z', 'Z') !== value) {
        protocolError(`${path} must be a canonical UTC timestamp (YYYY-MM-DDTHH:mm:ssZ)`);
    }
}
function assertSafeInteger(value, path, min, max) {
    if (!Number.isSafeInteger(value) || value < min || value > max) {
        protocolError(`${path} must be a safe integer between ${min} and ${max}`);
    }
}
function sha256(bytes) {
    return `sha256:${crypto.createHash('sha256').update(bytes, 'utf8').digest('hex')}`;
}
function domainDigest(domain, value, limits) {
    return sha256(`${domain}\0${canonicalizeStrictJson(value, limits)}`);
}
function verifierKey(value) {
    return `${value.verifier_id}\0${value.verifier_version}\0${value.implementation_digest}`;
}
/**
 * Compare protocol identifiers by UTF-16 code unit value.
 *
 * Locale collation is host configuration, not protocol input. Keeping the
 * comparator here explicit makes record ordering and digests independent of
 * ICU data, process locale, and user collation preferences.
 */
function compareCodeUnits(left, right) {
    if (left < right)
        return -1;
    if (left > right)
        return 1;
    return 0;
}
function validateVerifierDescriptor(value, path) {
    const object = asObject(value, path);
    assertExactKeys(object, path, ['verifier_id', 'verifier_version', 'implementation_digest']);
    assertIdentifier(object.verifier_id, `${path}.verifier_id`);
    assertIdentifier(object.verifier_version, `${path}.verifier_version`);
    assertDigest(object.implementation_digest, `${path}.implementation_digest`);
    return object;
}
function validateProfile(value) {
    canonicalizeStrictJson(value, PROFILE_LIMITS);
    const profile = asObject(value, 'pinned_profile');
    assertExactKeys(profile, 'pinned_profile', [
        '@type',
        'profile_id',
        'claim_type',
        'predicate',
        'requirements',
    ]);
    if (profile['@type'] !== CLAIM_ASSURANCE_PROFILE_VERSION) {
        protocolError(`unsupported claim assurance profile version ${String(profile['@type'])}`);
    }
    assertIdentifier(profile.profile_id, 'pinned_profile.profile_id');
    assertLabel(profile.claim_type, 'pinned_profile.claim_type');
    assertLabel(profile.predicate, 'pinned_profile.predicate');
    if (!Array.isArray(profile.requirements)
        || profile.requirements.length < 1
        || profile.requirements.length > CLAIM_ASSURANCE_LIMITS.max_profile_requirements) {
        protocolError(`pinned_profile.requirements must contain 1-${CLAIM_ASSURANCE_LIMITS.max_profile_requirements} entries`);
    }
    const requirementIds = new Set();
    const requirementSlots = new Set();
    profile.requirements.forEach((raw, index) => {
        const path = `pinned_profile.requirements[${index}]`;
        const requirement = asObject(raw, path);
        assertExactKeys(requirement, path, [
            'requirement_id',
            'evidence_role',
            'verifier',
            'minimum_distinct_sources',
            'max_age_seconds',
        ]);
        assertIdentifier(requirement.requirement_id, `${path}.requirement_id`);
        assertIdentifier(requirement.evidence_role, `${path}.evidence_role`);
        const descriptor = validateVerifierDescriptor(requirement.verifier, `${path}.verifier`);
        assertSafeInteger(requirement.minimum_distinct_sources, `${path}.minimum_distinct_sources`, 1, 32);
        assertSafeInteger(requirement.max_age_seconds, `${path}.max_age_seconds`, 1, 31_536_000);
        if (requirementIds.has(requirement.requirement_id)) {
            protocolError(`duplicate requirement_id ${requirement.requirement_id}`);
        }
        requirementIds.add(requirement.requirement_id);
        const slot = `${requirement.evidence_role}\0${verifierKey(descriptor)}`;
        if (requirementSlots.has(slot)) {
            protocolError(`duplicate evidence role and verifier requirement ${requirement.evidence_role}`);
        }
        requirementSlots.add(slot);
    });
    return profile;
}
function validateClaimStatement(value, path = 'claim_case.claim') {
    const claim = asObject(value, path);
    assertExactKeys(claim, path, ['claim_id', 'claim_type', 'predicate', 'value']);
    assertIdentifier(claim.claim_id, `${path}.claim_id`);
    assertLabel(claim.claim_type, `${path}.claim_type`);
    assertLabel(claim.predicate, `${path}.predicate`);
    canonicalizeStrictJson(claim.value, ARTIFACT_LIMITS);
    return claim;
}
function validateEvidenceBinding(value, path) {
    const binding = asObject(value, path);
    assertExactKeys(binding, path, ['subject_digest', 'scope_digest', 'claim_id'], ['action_digest']);
    assertDigest(binding.subject_digest, `${path}.subject_digest`);
    assertDigest(binding.scope_digest, `${path}.scope_digest`);
    assertIdentifier(binding.claim_id, `${path}.claim_id`);
    if (Object.hasOwn(binding, 'action_digest'))
        assertDigest(binding.action_digest, `${path}.action_digest`);
    return binding;
}
function validateClaimCase(value) {
    canonicalizeStrictJson(value, CASE_LIMITS);
    const claimCase = asObject(value, 'claim_case');
    assertExactKeys(claimCase, 'claim_case', [
        '@type',
        'subject_digest',
        'scope_digest',
        'claim',
        'profile_id',
        'profile_hash',
        'as_of',
        'evidence',
    ], ['action_digest']);
    if (claimCase['@type'] !== CLAIM_CASE_VERSION) {
        protocolError(`unsupported claim case version ${String(claimCase['@type'])}`);
    }
    assertDigest(claimCase.subject_digest, 'claim_case.subject_digest');
    assertDigest(claimCase.scope_digest, 'claim_case.scope_digest');
    validateClaimStatement(claimCase.claim);
    assertIdentifier(claimCase.profile_id, 'claim_case.profile_id');
    assertDigest(claimCase.profile_hash, 'claim_case.profile_hash');
    if (Object.hasOwn(claimCase, 'action_digest'))
        assertDigest(claimCase.action_digest, 'claim_case.action_digest');
    assertCanonicalTimestamp(claimCase.as_of, 'as_of');
    if (!Array.isArray(claimCase.evidence)
        || claimCase.evidence.length > CLAIM_ASSURANCE_LIMITS.max_evidence_items) {
        protocolError(`claim_case.evidence must contain no more than ${CLAIM_ASSURANCE_LIMITS.max_evidence_items} entries`);
    }
    const evidenceIds = new Set();
    const artifactDigests = new Set();
    claimCase.evidence.forEach((raw, index) => {
        const path = `claim_case.evidence[${index}]`;
        const item = asObject(raw, path);
        assertExactKeys(item, path, [
            'evidence_id',
            'role',
            'verifier',
            'binding',
            'artifact',
            'artifact_digest',
        ]);
        assertIdentifier(item.evidence_id, `${path}.evidence_id`);
        assertIdentifier(item.role, `${path}.role`);
        validateVerifierDescriptor(item.verifier, `${path}.verifier`);
        validateEvidenceBinding(item.binding, `${path}.binding`);
        canonicalizeStrictJson(item.artifact, ARTIFACT_LIMITS);
        assertDigest(item.artifact_digest, `${path}.artifact_digest`);
        if (evidenceIds.has(item.evidence_id))
            protocolError(`duplicate evidence_id ${item.evidence_id}`);
        if (artifactDigests.has(item.artifact_digest))
            protocolError(`duplicate artifact_digest ${item.artifact_digest}`);
        evidenceIds.add(item.evidence_id);
        artifactDigests.add(item.artifact_digest);
    });
    return claimCase;
}
function validateRegistry(value) {
    if (!Array.isArray(value) || value.length > CLAIM_ASSURANCE_LIMITS.max_verifier_registrations) {
        protocolError(`verifier_registry must contain no more than ${CLAIM_ASSURANCE_LIMITS.max_verifier_registrations} registrations`);
    }
    const output = new Map();
    value.forEach((raw, index) => {
        const path = `verifier_registry[${index}]`;
        const registration = asObject(raw, path);
        assertExactKeys(registration, path, [
            'verifier_id',
            'verifier_version',
            'implementation_digest',
            'verify',
        ]);
        const descriptor = validateVerifierDescriptor({
            verifier_id: registration.verifier_id,
            verifier_version: registration.verifier_version,
            implementation_digest: registration.implementation_digest,
        }, path);
        if (typeof registration.verify !== 'function')
            protocolError(`${path}.verify must be a function`);
        const key = verifierKey(descriptor);
        if (output.has(key))
            protocolError(`duplicate verifier registration ${descriptor.verifier_id}`);
        // Snapshot both the pinned descriptor and callback reference. A caller that
        // mutates its registration object during another verifier callback cannot
        // redirect a later evidence item to different code under the old digest.
        output.set(key, Object.freeze({
            ...strictClone(descriptor, PROFILE_LIMITS),
            verify: registration.verify,
        }));
    });
    return output;
}
function deepFreeze(value) {
    if (value === null || typeof value !== 'object' || Object.isFrozen(value))
        return value;
    if (Array.isArray(value)) {
        for (const item of value)
            deepFreeze(item);
    }
    else {
        for (const key of Object.keys(value))
            deepFreeze(value[key]);
    }
    return Object.freeze(value);
}
function strictClone(value, limits) {
    return JSON.parse(canonicalizeStrictJson(value, limits));
}
/** SHA-256 over strict canonical artifact bytes. */
export function claimAssuranceArtifactDigest(artifact, limits = {}) {
    return sha256(canonicalizeStrictJson(artifact, { ...ARTIFACT_LIMITS, ...limits }));
}
/** Digest of the exact pinned EP-CLAIM-ASSURANCE-PROFILE-v1 bytes. */
export function claimAssuranceProfileHash(profile) {
    validateProfile(profile);
    return sha256(canonicalizeStrictJson(profile, PROFILE_LIMITS));
}
/** Digest of the exact EP-CLAIM-CASE-v1 bytes supplied for replay. */
export function claimCaseDigest(claimCase) {
    validateClaimCase(claimCase);
    return sha256(canonicalizeStrictJson(claimCase, CASE_LIMITS));
}
function malformedVerifierResult() {
    return null;
}
function validateVerifierResult(value) {
    try {
        canonicalizeStrictJson(value, VERIFIER_RESULT_LIMITS);
        const result = asObject(value, 'verifier_result');
        assertExactKeys(result, 'verifier_result', [
            'verdict',
            'relationship',
            'source_id',
            'subject_digest',
            'scope_digest',
            'claim_id',
            'observed_at',
            'expires_at',
            'artifact_digest',
            'reasons',
        ]);
        if (!EVIDENCE_VERDICTS.includes(result.verdict))
            return malformedVerifierResult();
        if (!EVIDENCE_RELATIONSHIPS.includes(result.relationship))
            return malformedVerifierResult();
        assertIdentifier(result.source_id, 'verifier_result.source_id');
        assertDigest(result.subject_digest, 'verifier_result.subject_digest');
        assertDigest(result.scope_digest, 'verifier_result.scope_digest');
        assertIdentifier(result.claim_id, 'verifier_result.claim_id');
        assertCanonicalTimestamp(result.observed_at, 'verifier_result.observed_at');
        assertCanonicalTimestamp(result.expires_at, 'verifier_result.expires_at');
        // Validity is the half-open interval [observed_at, expires_at). A
        // zero-width interval is never usable evidence.
        if (Date.parse(result.expires_at) <= Date.parse(result.observed_at))
            return malformedVerifierResult();
        assertDigest(result.artifact_digest, 'verifier_result.artifact_digest');
        if (!Array.isArray(result.reasons)
            || result.reasons.length > CLAIM_ASSURANCE_LIMITS.max_verifier_reasons)
            return malformedVerifierResult();
        for (const reason of result.reasons) {
            assertBoundedString(reason, 'verifier_result.reasons[]', CLAIM_ASSURANCE_LIMITS.max_verifier_reason_bytes);
        }
        return result;
    }
    catch {
        return malformedVerifierResult();
    }
}
function blankEvidenceResult(item) {
    return {
        evidence_id: item.evidence_id,
        role: item.role,
        verifier: strictClone(item.verifier, PROFILE_LIMITS),
        artifact_digest: item.artifact_digest,
        disposition: 'INDETERMINATE',
        verifier_verdict: null,
        relationship: null,
        source_id: null,
        observed_at: null,
        expires_at: null,
        reasons: [],
    };
}
function resultWithVerifier(base, result) {
    return {
        ...base,
        verifier_verdict: result.verdict,
        relationship: result.relationship,
        source_id: result.source_id,
        observed_at: result.observed_at,
        expires_at: result.expires_at,
    };
}
function evaluateEvidence(item, claimCase, profile, registry, evaluatedAt) {
    const base = blankEvidenceResult(item);
    const actualArtifactDigest = claimAssuranceArtifactDigest(item.artifact);
    if (actualArtifactDigest !== item.artifact_digest) {
        return { ...base, disposition: 'REJECTED', reasons: ['ARTIFACT_DIGEST_MISMATCH'] };
    }
    const bindingReasons = [];
    if (item.binding.subject_digest !== claimCase.subject_digest)
        bindingReasons.push('SUBJECT_BINDING_MISMATCH');
    if (item.binding.scope_digest !== claimCase.scope_digest)
        bindingReasons.push('SCOPE_BINDING_MISMATCH');
    if (item.binding.claim_id !== claimCase.claim.claim_id)
        bindingReasons.push('CLAIM_BINDING_MISMATCH');
    const caseAction = claimCase.action_digest ?? null;
    const itemAction = item.binding.action_digest ?? null;
    if (itemAction !== caseAction)
        bindingReasons.push('ACTION_BINDING_MISMATCH');
    if (bindingReasons.length > 0) {
        return { ...base, disposition: 'REJECTED', reasons: bindingReasons };
    }
    const matchingRequirements = profile.requirements.filter((requirement) => (requirement.evidence_role === item.role
        && verifierKey(requirement.verifier) === verifierKey(item.verifier)));
    if (matchingRequirements.length === 0) {
        // An exact registry tuple is not enough. The pinned profile must first
        // name the role/tuple pair, otherwise unrelated registered code could be
        // invoked by presenter-controlled evidence.
        return { ...base, disposition: 'REJECTED', reasons: ['EVIDENCE_NOT_IN_PROFILE'] };
    }
    const registration = registry.get(verifierKey(item.verifier));
    if (!registration)
        return { ...base, disposition: 'INDETERMINATE', reasons: ['VERIFIER_NOT_REGISTERED'] };
    const frozenArtifact = deepFreeze(strictClone(item.artifact, ARTIFACT_LIMITS));
    const frozenClaim = deepFreeze(strictClone(claimCase.claim, ARTIFACT_LIMITS));
    const input = deepFreeze({
        evidence_id: item.evidence_id,
        role: item.role,
        verifier: strictClone(item.verifier, PROFILE_LIMITS),
        artifact: frozenArtifact,
        artifact_digest: item.artifact_digest,
        subject_digest: claimCase.subject_digest,
        scope_digest: claimCase.scope_digest,
        action_digest: caseAction,
        claim: frozenClaim,
        as_of: claimCase.as_of,
    });
    let rawResult;
    try {
        rawResult = registration.verify(input);
    }
    catch {
        return { ...base, disposition: 'INDETERMINATE', reasons: ['VERIFIER_UNAVAILABLE'] };
    }
    const result = validateVerifierResult(rawResult);
    if (!result)
        return { ...base, disposition: 'INDETERMINATE', reasons: ['VERIFIER_RESULT_MALFORMED'] };
    const withVerifier = resultWithVerifier(base, result);
    const restatementReasons = [];
    if (result.subject_digest !== claimCase.subject_digest)
        restatementReasons.push('VERIFIER_SUBJECT_MISMATCH');
    if (result.scope_digest !== claimCase.scope_digest)
        restatementReasons.push('VERIFIER_SCOPE_MISMATCH');
    if (result.claim_id !== claimCase.claim.claim_id)
        restatementReasons.push('VERIFIER_CLAIM_MISMATCH');
    if (result.artifact_digest !== item.artifact_digest)
        restatementReasons.push('VERIFIER_ARTIFACT_MISMATCH');
    if (restatementReasons.length > 0) {
        return { ...withVerifier, disposition: 'REJECTED', reasons: restatementReasons };
    }
    const asOf = Date.parse(claimCase.as_of);
    const evaluationTime = Date.parse(evaluatedAt);
    const observedAt = Date.parse(result.observed_at);
    const expiresAt = Date.parse(result.expires_at);
    if (observedAt > asOf) {
        return { ...withVerifier, disposition: 'INDETERMINATE', reasons: ['EVIDENCE_NOT_YET_OBSERVED'] };
    }
    if (evaluationTime >= expiresAt) {
        return { ...withVerifier, disposition: 'INDETERMINATE', reasons: ['EVIDENCE_STALE'] };
    }
    if (matchingRequirements.some((requirement) => evaluationTime - observedAt > requirement.max_age_seconds * 1_000)) {
        return { ...withVerifier, disposition: 'INDETERMINATE', reasons: ['EVIDENCE_STALE'] };
    }
    if (result.verdict === 'INDETERMINATE') {
        return {
            ...withVerifier,
            disposition: 'INDETERMINATE',
            reasons: normalizeReasons(['VERIFIER_INDETERMINATE'], result.reasons),
        };
    }
    if (result.verdict === 'UNVERIFIED') {
        return {
            ...withVerifier,
            disposition: 'REJECTED',
            reasons: normalizeReasons(['VERIFIER_UNVERIFIED'], result.reasons),
        };
    }
    return { ...withVerifier, disposition: 'ACCEPTED', reasons: normalizeReasons([], result.reasons) };
}
function requirementResult(requirement, evidenceItems, evidenceResults) {
    const relevantIds = new Set(evidenceItems
        .filter((item) => item.role === requirement.evidence_role
        && verifierKey(item.verifier) === verifierKey(requirement.verifier))
        .map((item) => item.evidence_id));
    const relevant = evidenceResults.filter((result) => relevantIds.has(result.evidence_id));
    const supports = new Set(relevant
        .filter((result) => result.disposition === 'ACCEPTED' && result.relationship === 'SUPPORTS')
        .map((result) => result.source_id));
    const contradicts = new Set(relevant
        .filter((result) => result.disposition === 'ACCEPTED' && result.relationship === 'CONTRADICTS')
        .map((result) => result.source_id));
    const neutral = new Set(relevant
        .filter((result) => result.disposition === 'ACCEPTED' && result.relationship === 'NEUTRAL')
        .map((result) => result.source_id));
    const indeterminate = relevant.some((result) => result.disposition === 'INDETERMINATE');
    const rejected = relevant.some((result) => result.disposition === 'REJECTED');
    const base = {
        requirement_id: requirement.requirement_id,
        evidence_role: requirement.evidence_role,
        minimum_distinct_sources: requirement.minimum_distinct_sources,
        accepted_supporting_sources: supports.size,
        accepted_contradicting_sources: contradicts.size,
        accepted_neutral_sources: neutral.size,
    };
    if (supports.size > 0 && contradicts.size > 0) {
        return { ...base, disposition: 'DIVERGED', satisfied: false, reasons: ['ACCEPTED_SOURCES_DIVERGED'] };
    }
    if (contradicts.size > 0) {
        return { ...base, disposition: 'UNVERIFIED', satisfied: false, reasons: ['EVIDENCE_CONTRADICTS_CLAIM'] };
    }
    if (supports.size >= requirement.minimum_distinct_sources) {
        return { ...base, disposition: 'SATISFIED', satisfied: true, reasons: [] };
    }
    if (relevant.length === 0) {
        return { ...base, disposition: 'INDETERMINATE', satisfied: false, reasons: ['REQUIRED_EVIDENCE_MISSING'] };
    }
    if (indeterminate) {
        return { ...base, disposition: 'INDETERMINATE', satisfied: false, reasons: ['REQUIRED_EVIDENCE_INDETERMINATE'] };
    }
    if (supports.size > 0) {
        return { ...base, disposition: 'INDETERMINATE', satisfied: false, reasons: ['INSUFFICIENT_DISTINCT_SOURCES'] };
    }
    return {
        ...base,
        disposition: 'UNVERIFIED',
        satisfied: false,
        reasons: [rejected ? 'REQUIRED_EVIDENCE_REJECTED' : 'REQUIRED_EVIDENCE_UNSUPPORTED'],
    };
}
function uniqueSorted(values) {
    return [...new Set(values)].sort(compareCodeUnits);
}
function normalizeReasons(frameworkReasons, verifierReasons = []) {
    const framework = [...new Set(frameworkReasons)];
    const external = uniqueSorted(verifierReasons)
        .filter((reason) => !framework.includes(reason));
    return [
        ...framework,
        ...external.slice(0, CLAIM_ASSURANCE_LIMITS.max_verifier_reasons - framework.length),
    ];
}
function replayDigest(record) {
    return domainDigest('EP-CLAIM-ASSURANCE-REPLAY-v1', {
        profile_id: record.profile_id,
        profile_hash: record.profile_hash,
        claim_case_digest: record.claim_case_digest,
        evaluated_at: record.evaluated_at,
        evidence_results: record.evidence_results,
        requirement_results: record.requirement_results,
    }, CASE_LIMITS);
}
function assuranceRecordDigest(record) {
    return domainDigest(ASSURANCE_RECORD_VERSION, record, CASE_LIMITS);
}
/**
 * Evaluate a Claim Case using only caller-pinned profile bytes and exact
 * caller-registered verifier implementations.
 *
 * Malformed protocol inputs throw. Evidence rejection and operational
 * uncertainty are represented in the record. No path returns action authority.
 */
export function evaluateClaimAssurance(input, options) {
    const presentedProfile = validateProfile(options?.pinned_profile);
    assertDigest(options?.pinned_profile_hash, 'pinned_profile_hash');
    const computedProfileHash = claimAssuranceProfileHash(presentedProfile);
    if (options.pinned_profile_hash !== computedProfileHash) {
        protocolError('pinned_profile_hash does not match pinned_profile');
    }
    // Work from immutable byte-for-byte snapshots. Even trusted verifier code
    // may share caller state through a closure; it must not be able to create a
    // profile/hash or claim-case/digest time-of-check/time-of-use split.
    const profile = deepFreeze(strictClone(presentedProfile, PROFILE_LIMITS));
    // Snapshot the validated timestamp exactly once. A verifier callback may
    // close over and mutate the caller-owned options object, but every evidence
    // item and the final record must use the same evaluation instant.
    const evaluatedAt = options?.evaluated_at;
    assertCanonicalTimestamp(evaluatedAt, 'evaluated_at');
    if (options.expected_action_digest !== undefined && options.expected_action_digest !== null) {
        assertDigest(options.expected_action_digest, 'expected_action_digest');
    }
    const registry = validateRegistry(options?.verifier_registry);
    const presentedClaimCase = validateClaimCase(input);
    const claimCase = deepFreeze(strictClone(presentedClaimCase, CASE_LIMITS));
    if (claimCase.profile_id !== profile.profile_id)
        protocolError('claim case profile_id does not match pinned profile');
    if (claimCase.profile_hash !== computedProfileHash)
        protocolError('claim case profile_hash does not match pinned profile');
    if (claimCase.claim.claim_type !== profile.claim_type)
        protocolError('claim type does not match pinned profile');
    if (claimCase.claim.predicate !== profile.predicate)
        protocolError('claim predicate does not match pinned profile');
    if (options.expected_action_digest !== undefined) {
        const expected = options.expected_action_digest ?? null;
        if ((claimCase.action_digest ?? null) !== expected) {
            protocolError('claim case action_digest does not match expected_action_digest');
        }
    }
    if (Date.parse(evaluatedAt) < Date.parse(claimCase.as_of)) {
        protocolError('evaluated_at cannot precede claim_case.as_of');
    }
    const sortedEvidence = [...claimCase.evidence]
        .sort((left, right) => compareCodeUnits(left.evidence_id, right.evidence_id));
    const evidenceResults = sortedEvidence.map((item) => (evaluateEvidence(item, claimCase, profile, registry, evaluatedAt)));
    const sortedRequirements = [...profile.requirements]
        .sort((left, right) => compareCodeUnits(left.requirement_id, right.requirement_id));
    const requirementResults = sortedRequirements.map((requirement) => (requirementResult(requirement, sortedEvidence, evidenceResults)));
    let verdict;
    let reasons;
    const acceptedRelationships = new Set(evidenceResults
        .filter((result) => result.disposition === 'ACCEPTED')
        .map((result) => result.relationship));
    const acceptedEvidenceDiverged = acceptedRelationships.has('SUPPORTS')
        && acceptedRelationships.has('CONTRADICTS');
    if (acceptedEvidenceDiverged
        || requirementResults.some((result) => result.disposition === 'DIVERGED')) {
        verdict = 'DIVERGED';
        reasons = ['ACCEPTED_SOURCES_DIVERGED'];
    }
    else if (requirementResults.every((result) => result.satisfied)) {
        verdict = 'VERIFIED';
        reasons = [];
    }
    else if (requirementResults.some((result) => result.disposition === 'INDETERMINATE')) {
        verdict = 'INDETERMINATE';
        reasons = uniqueSorted(requirementResults.flatMap((result) => result.reasons));
    }
    else {
        verdict = 'UNVERIFIED';
        reasons = uniqueSorted(requirementResults.flatMap((result) => result.reasons));
    }
    const body = {
        '@type': ASSURANCE_RECORD_VERSION,
        profile_id: profile.profile_id,
        profile_hash: computedProfileHash,
        claim_case_digest: claimCaseDigest(claimCase),
        subject_digest: claimCase.subject_digest,
        scope_digest: claimCase.scope_digest,
        claim: strictClone(claimCase.claim, ARTIFACT_LIMITS),
        action_digest: claimCase.action_digest ?? null,
        as_of: claimCase.as_of,
        evaluated_at: evaluatedAt,
        verdict,
        profile_satisfied: verdict === 'VERIFIED',
        authorizes_action: false,
        requirement_results: requirementResults,
        evidence_results: evidenceResults,
        reasons,
    };
    const withReplay = {
        ...body,
        replay_digest: replayDigest(body),
    };
    const record = {
        ...withReplay,
        record_digest: assuranceRecordDigest(withReplay),
    };
    return deepFreeze(record);
}
const RECORD_KEYS = [
    '@type',
    'profile_id',
    'profile_hash',
    'claim_case_digest',
    'subject_digest',
    'scope_digest',
    'claim',
    'action_digest',
    'as_of',
    'evaluated_at',
    'verdict',
    'profile_satisfied',
    'authorizes_action',
    'requirement_results',
    'evidence_results',
    'reasons',
    'replay_digest',
    'record_digest',
];
function validateRecordReasons(value, path) {
    if (!Array.isArray(value)
        || value.length > CLAIM_ASSURANCE_LIMITS.max_verifier_reasons) {
        protocolError(`${path} must contain no more than ${CLAIM_ASSURANCE_LIMITS.max_verifier_reasons} entries`);
    }
    const seen = new Set();
    for (const reason of value) {
        assertBoundedString(reason, `${path}[]`, CLAIM_ASSURANCE_LIMITS.max_verifier_reason_bytes);
        if (seen.has(reason))
            protocolError(`${path} must not contain duplicate reasons`);
        seen.add(reason);
    }
}
function sameStringArray(left, right) {
    return left.length === right.length && left.every((value, index) => value === right[index]);
}
function assertSortedUniqueId(current, previous, path) {
    if (previous !== null && compareCodeUnits(previous, current) >= 0) {
        protocolError(`${path} must be in unique code-unit order`);
    }
}
function validateAssuranceRecordSemantics(value) {
    canonicalizeStrictJson(value, CASE_LIMITS);
    const record = asObject(value, 'assurance_record');
    assertExactKeys(record, 'assurance_record', RECORD_KEYS);
    if (record['@type'] !== ASSURANCE_RECORD_VERSION) {
        protocolError(`unsupported assurance record version ${String(record['@type'])}`);
    }
    assertIdentifier(record.profile_id, 'assurance_record.profile_id');
    assertDigest(record.profile_hash, 'assurance_record.profile_hash');
    assertDigest(record.claim_case_digest, 'assurance_record.claim_case_digest');
    assertDigest(record.subject_digest, 'assurance_record.subject_digest');
    assertDigest(record.scope_digest, 'assurance_record.scope_digest');
    validateClaimStatement(record.claim, 'assurance_record.claim');
    if (record.action_digest !== null)
        assertDigest(record.action_digest, 'assurance_record.action_digest');
    assertCanonicalTimestamp(record.as_of, 'assurance_record.as_of');
    assertCanonicalTimestamp(record.evaluated_at, 'assurance_record.evaluated_at');
    if (Date.parse(record.evaluated_at) < Date.parse(record.as_of)) {
        protocolError('assurance_record.evaluated_at cannot precede assurance_record.as_of');
    }
    if (!CLAIM_ASSURANCE_VERDICTS.includes(record.verdict)) {
        protocolError('assurance_record.verdict is unsupported');
    }
    if (typeof record.profile_satisfied !== 'boolean') {
        protocolError('assurance_record.profile_satisfied must be boolean');
    }
    if (record.authorizes_action !== false) {
        protocolError('assurance_record must not authorize action');
    }
    if (!Array.isArray(record.requirement_results)
        || record.requirement_results.length < 1
        || record.requirement_results.length > CLAIM_ASSURANCE_LIMITS.max_profile_requirements) {
        protocolError(`assurance_record.requirement_results must contain 1-${CLAIM_ASSURANCE_LIMITS.max_profile_requirements} entries`);
    }
    let previousRequirementId = null;
    for (const [index, raw] of record.requirement_results.entries()) {
        const path = `assurance_record.requirement_results[${index}]`;
        const result = asObject(raw, path);
        assertExactKeys(result, path, [
            'requirement_id',
            'evidence_role',
            'minimum_distinct_sources',
            'accepted_supporting_sources',
            'accepted_contradicting_sources',
            'accepted_neutral_sources',
            'disposition',
            'satisfied',
            'reasons',
        ]);
        assertIdentifier(result.requirement_id, `${path}.requirement_id`);
        assertSortedUniqueId(result.requirement_id, previousRequirementId, `${path}.requirement_id`);
        previousRequirementId = result.requirement_id;
        assertIdentifier(result.evidence_role, `${path}.evidence_role`);
        assertSafeInteger(result.minimum_distinct_sources, `${path}.minimum_distinct_sources`, 1, 32);
        assertSafeInteger(result.accepted_supporting_sources, `${path}.accepted_supporting_sources`, 0, 32);
        assertSafeInteger(result.accepted_contradicting_sources, `${path}.accepted_contradicting_sources`, 0, 32);
        assertSafeInteger(result.accepted_neutral_sources, `${path}.accepted_neutral_sources`, 0, 32);
        if (!['SATISFIED', 'UNVERIFIED', 'DIVERGED', 'INDETERMINATE'].includes(String(result.disposition))) {
            protocolError(`${path}.disposition is unsupported`);
        }
        if (typeof result.satisfied !== 'boolean')
            protocolError(`${path}.satisfied must be boolean`);
        validateRecordReasons(result.reasons, `${path}.reasons`);
        const isSatisfied = result.disposition === 'SATISFIED';
        if (result.satisfied !== isSatisfied)
            protocolError(`${path}.satisfied contradicts disposition`);
        if (isSatisfied) {
            if (result.accepted_supporting_sources < result.minimum_distinct_sources
                || result.accepted_contradicting_sources !== 0
                || result.reasons.length !== 0) {
                protocolError(`${path} has inconsistent satisfied counts or reasons`);
            }
        }
        else if (result.reasons.length === 0) {
            protocolError(`${path}.reasons must explain an unsatisfied requirement`);
        }
        if (result.disposition === 'DIVERGED'
            && (result.accepted_supporting_sources === 0
                || result.accepted_contradicting_sources === 0
                || !sameStringArray(result.reasons, ['ACCEPTED_SOURCES_DIVERGED']))) {
            protocolError(`${path} has inconsistent divergence semantics`);
        }
    }
    if (!Array.isArray(record.evidence_results)
        || record.evidence_results.length > CLAIM_ASSURANCE_LIMITS.max_evidence_items) {
        protocolError(`assurance_record.evidence_results must contain no more than ${CLAIM_ASSURANCE_LIMITS.max_evidence_items} entries`);
    }
    let previousEvidenceId = null;
    for (const [index, raw] of record.evidence_results.entries()) {
        const path = `assurance_record.evidence_results[${index}]`;
        const result = asObject(raw, path);
        assertExactKeys(result, path, [
            'evidence_id',
            'role',
            'verifier',
            'artifact_digest',
            'disposition',
            'verifier_verdict',
            'relationship',
            'source_id',
            'observed_at',
            'expires_at',
            'reasons',
        ]);
        assertIdentifier(result.evidence_id, `${path}.evidence_id`);
        assertSortedUniqueId(result.evidence_id, previousEvidenceId, `${path}.evidence_id`);
        previousEvidenceId = result.evidence_id;
        assertIdentifier(result.role, `${path}.role`);
        validateVerifierDescriptor(result.verifier, `${path}.verifier`);
        assertDigest(result.artifact_digest, `${path}.artifact_digest`);
        if (!['ACCEPTED', 'REJECTED', 'INDETERMINATE'].includes(String(result.disposition))) {
            protocolError(`${path}.disposition is unsupported`);
        }
        if (result.verifier_verdict !== null
            && !EVIDENCE_VERDICTS.includes(result.verifier_verdict)) {
            protocolError(`${path}.verifier_verdict is unsupported`);
        }
        if (result.relationship !== null
            && !EVIDENCE_RELATIONSHIPS.includes(result.relationship)) {
            protocolError(`${path}.relationship is unsupported`);
        }
        if (result.source_id !== null)
            assertIdentifier(result.source_id, `${path}.source_id`);
        if (result.observed_at !== null)
            assertCanonicalTimestamp(result.observed_at, `${path}.observed_at`);
        if (result.expires_at !== null)
            assertCanonicalTimestamp(result.expires_at, `${path}.expires_at`);
        validateRecordReasons(result.reasons, `${path}.reasons`);
        const verifierFields = [
            result.verifier_verdict,
            result.relationship,
            result.source_id,
            result.observed_at,
            result.expires_at,
        ];
        const allNull = verifierFields.every((field) => field === null);
        const allPresent = verifierFields.every((field) => field !== null);
        if (!allNull && !allPresent)
            protocolError(`${path} has a partial verifier result`);
        if (allPresent) {
            if (Date.parse(result.expires_at) <= Date.parse(result.observed_at)) {
                protocolError(`${path} has an empty or negative validity interval`);
            }
        }
        if (result.disposition === 'ACCEPTED') {
            if (!allPresent || result.verifier_verdict !== 'VERIFIED') {
                protocolError(`${path} accepts evidence without a complete VERIFIED verifier result`);
            }
            if (Date.parse(result.observed_at) > Date.parse(record.as_of)
                || Date.parse(record.evaluated_at) >= Date.parse(result.expires_at)) {
                protocolError(`${path} accepts evidence outside its validity interval`);
            }
        }
        if (result.disposition === 'INDETERMINATE' && result.verifier_verdict === 'UNVERIFIED') {
            protocolError(`${path} maps UNVERIFIED evidence to operational uncertainty`);
        }
    }
    validateRecordReasons(record.reasons, 'assurance_record.reasons');
    assertDigest(record.replay_digest, 'assurance_record.replay_digest');
    assertDigest(record.record_digest, 'assurance_record.record_digest');
    const requirements = record.requirement_results;
    const evidence = record.evidence_results;
    const acceptedRelationships = new Set(evidence
        .filter((result) => result.disposition === 'ACCEPTED')
        .map((result) => result.relationship));
    const diverged = (acceptedRelationships.has('SUPPORTS') && acceptedRelationships.has('CONTRADICTS'))
        || requirements.some((result) => result.disposition === 'DIVERGED');
    let expectedVerdict;
    let expectedReasons;
    if (diverged) {
        expectedVerdict = 'DIVERGED';
        expectedReasons = ['ACCEPTED_SOURCES_DIVERGED'];
    }
    else if (requirements.every((result) => result.satisfied)) {
        expectedVerdict = 'VERIFIED';
        expectedReasons = [];
    }
    else if (requirements.some((result) => result.disposition === 'INDETERMINATE')) {
        expectedVerdict = 'INDETERMINATE';
        expectedReasons = uniqueSorted(requirements.flatMap((result) => result.reasons));
    }
    else {
        expectedVerdict = 'UNVERIFIED';
        expectedReasons = uniqueSorted(requirements.flatMap((result) => result.reasons));
    }
    if (record.verdict !== expectedVerdict
        || record.profile_satisfied !== (expectedVerdict === 'VERIFIED')
        || !sameStringArray(record.reasons, expectedReasons)) {
        protocolError('assurance_record verdict, profile_satisfied, or reasons are inconsistent');
    }
    return record;
}
function blankIntegrityResult(recordDigest, expectedProvided, reason) {
    return {
        integrity_valid: false,
        semantics_valid: false,
        replay_digest_matches: false,
        digest_matches: false,
        expected_digest_matches: expectedProvided ? false : null,
        reperformed: false,
        record_digest: recordDigest,
        computed_record_digest: null,
        reason,
    };
}
/**
 * Inspect the strict shape, internal semantics, replay digest, record digest,
 * and optional independently pinned content address of an Assurance Record.
 *
 * This is not Claim Case re-performance. A presenter can recompute both
 * digests after fabricating a self-consistent record. Relying parties must call
 * `evaluateClaimAssurance` with the raw case and their own live verifier pins
 * before relying on the claim verdict.
 */
export function inspectAssuranceRecordIntegrity(value, options = {}) {
    const expected = options?.expected_record_digest;
    const expectedProvided = expected !== undefined;
    if (expectedProvided && (typeof expected !== 'string' || !DIGEST_RE.test(expected))) {
        return Object.freeze(blankIntegrityResult(null, true, 'expected_record_digest_invalid'));
    }
    let claimed = null;
    let record;
    try {
        canonicalizeStrictJson(value, CASE_LIMITS);
        const object = asObject(value, 'assurance_record');
        claimed = typeof object.record_digest === 'string' ? object.record_digest : null;
        assertExactKeys(object, 'assurance_record', RECORD_KEYS);
        if (object['@type'] !== ASSURANCE_RECORD_VERSION) {
            return Object.freeze(blankIntegrityResult(claimed, expectedProvided, 'unsupported_record_version'));
        }
        if (object.authorizes_action !== false) {
            return Object.freeze(blankIntegrityResult(claimed, expectedProvided, 'record_must_not_authorize_action'));
        }
        record = validateAssuranceRecordSemantics(object);
    }
    catch {
        return Object.freeze(blankIntegrityResult(claimed, expectedProvided, 'record_semantics_invalid'));
    }
    const { replay_digest: claimedReplayDigest, record_digest: _claimedRecordDigest, ...body } = record;
    const computedReplayDigest = replayDigest(body);
    const replayMatches = claimedReplayDigest === computedReplayDigest;
    const computedRecordDigest = assuranceRecordDigest({
        ...body,
        replay_digest: claimedReplayDigest,
    });
    const digestMatches = record.record_digest === computedRecordDigest;
    const expectedMatches = expectedProvided ? computedRecordDigest === expected : null;
    const integrityValid = replayMatches && digestMatches && expectedMatches !== false;
    const reason = !replayMatches
        ? 'replay_digest_mismatch'
        : !digestMatches
            ? 'record_digest_mismatch'
            : expectedMatches === false
                ? 'expected_record_digest_mismatch'
                : null;
    return Object.freeze({
        integrity_valid: integrityValid,
        semantics_valid: true,
        replay_digest_matches: replayMatches,
        digest_matches: digestMatches,
        expected_digest_matches: expectedMatches,
        reperformed: false,
        record_digest: record.record_digest,
        computed_record_digest: computedRecordDigest,
        reason,
    });
}
/**
 * Backward-compatible projection of `inspectAssuranceRecordIntegrity`.
 * `ok` means strict self-integrity only; it never means the Claim Case was
 * independently re-performed or the real-world claim is true.
 *
 * @deprecated Prefer `inspectAssuranceRecordIntegrity`, whose field names make
 * the digest and re-performance boundaries explicit.
 */
export function verifyAssuranceRecordDigest(value) {
    const result = inspectAssuranceRecordIntegrity(value);
    return {
        ok: result.integrity_valid,
        record_digest: result.record_digest,
        reason: result.reason,
    };
}
//# sourceMappingURL=claim-assurance.js.map