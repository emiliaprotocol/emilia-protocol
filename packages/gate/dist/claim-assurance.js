// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Bridge a re-performed Claim Case into Gate as non-authorizing evidence.
 *
 * The bridge deliberately accepts the raw Claim Case, not a presenter's
 * precomputed Assurance Record. It recomputes the record with a profile and
 * verifier implementations pinned by the Gate operator, then binds that result
 * to the executor-observed action. Even a VERIFIED result remains an additional
 * admissibility condition. Receipt authority, local policy, one-time
 * consumption, and provider-entry custody stay independent Gate checks.
 */
import { canonicalize, hashCanonical } from './execution-binding.js';
export const CLAIM_ASSURANCE_GATE_PRESENTATION_VERSION = 'EP-CLAIM-ASSURANCE-GATE-PRESENTATION-v1';
export const CLAIM_ASSURANCE_ADMISSIBILITY_VERSION = 'EP-CLAIM-ASSURANCE-ADMISSIBILITY-v1';
const MAX_CASE_AGE_SECONDS = 31_536_000;
function fail(message) {
    throw new TypeError(`claim assurance Gate bridge: ${message}`);
}
function strictJsonClone(value) {
    return JSON.parse(canonicalize(value));
}
function parsePresentation(value) {
    const presentation = strictJsonClone(value);
    if (presentation === null || typeof presentation !== 'object' || Array.isArray(presentation)) {
        fail('presentation must be an object');
    }
    const keys = Object.keys(presentation).sort();
    if (keys.length !== 2 || keys[0] !== '@type' || keys[1] !== 'claim_case') {
        fail('presentation must contain exactly @type and claim_case');
    }
    if (presentation['@type'] !== CLAIM_ASSURANCE_GATE_PRESENTATION_VERSION) {
        fail('unsupported presentation version');
    }
    return presentation;
}
function evaluatedAt(clock) {
    const supplied = clock();
    if (!Number.isFinite(supplied))
        fail('clock must return finite epoch milliseconds');
    const milliseconds = Math.floor(supplied / 1_000) * 1_000;
    const instant = new Date(milliseconds);
    if (!Number.isFinite(instant.getTime()))
        fail('clock returned an invalid instant');
    return {
        text: instant.toISOString().replace('.000Z', 'Z'),
        milliseconds,
    };
}
function allReasons(record) {
    return [...new Set([
            ...record.reasons,
            ...record.requirement_results.flatMap((result) => result.reasons),
            ...record.evidence_results.flatMap((result) => result.reasons),
        ])].sort();
}
function claimVerdictToAdmissibility(record) {
    if (record.verdict === 'VERIFIED') {
        return record.profile_satisfied === true && record.authorizes_action === false
            ? 'admissible'
            : 'unverifiable';
    }
    if (record.verdict === 'DIVERGED')
        return 'conflicted';
    if (record.verdict === 'UNVERIFIED')
        return 'unverifiable';
    const reasons = allReasons(record);
    const unavailable = reasons.some((reason) => [
        'VERIFIER_NOT_REGISTERED',
        'VERIFIER_UNAVAILABLE',
        'VERIFIER_RESULT_MALFORMED',
        'EVIDENCE_NOT_YET_OBSERVED',
    ].includes(reason));
    if (unavailable)
        return 'unverifiable';
    if (reasons.includes('EVIDENCE_STALE'))
        return 'stale';
    if (reasons.some((reason) => [
        'REQUIRED_EVIDENCE_MISSING',
        'INSUFFICIENT_DISTINCT_SOURCES',
    ].includes(reason)))
        return 'missing_evidence';
    return 'unverifiable';
}
function freezeRegistry(registry) {
    if (!Array.isArray(registry))
        fail('verifierRegistry must be an array');
    return Object.freeze(registry.map((entry) => Object.freeze({
        verifier_id: entry.verifier_id,
        verifier_version: entry.verifier_version,
        implementation_digest: entry.implementation_digest,
        verify: entry.verify.bind(entry),
    })));
}
/**
 * Construct the trusted callback accepted by createGate's
 * `verifyAdmissibilityPacket` option.
 */
export function createClaimAssuranceAdmissibilityVerifier({ pinnedProfile, pinnedProfileHash, evaluateClaimAssurance, verifierRegistry, maxCaseAgeSec, now = Date.now, }) {
    const profile = Object.freeze(strictJsonClone(pinnedProfile));
    const computedProfileHash = `sha256:${hashCanonical(profile)}`;
    if (pinnedProfileHash !== computedProfileHash)
        fail('pinnedProfileHash does not match pinnedProfile');
    if (!Number.isSafeInteger(maxCaseAgeSec)
        || maxCaseAgeSec < 0
        || maxCaseAgeSec > MAX_CASE_AGE_SECONDS) {
        fail(`maxCaseAgeSec must be a safe integer between 0 and ${MAX_CASE_AGE_SECONDS}`);
    }
    if (typeof now !== 'function')
        fail('now must be a function');
    if (typeof evaluateClaimAssurance !== 'function') {
        fail('evaluateClaimAssurance must be a reviewed function');
    }
    const evaluate = evaluateClaimAssurance;
    const registry = freezeRegistry(verifierRegistry);
    return async function verifyClaimAssuranceForGate(input) {
        if (input?.pinned_profile?.id !== profile.profile_id
            || input?.pinned_profile?.profile_hash !== computedProfileHash) {
            fail('Gate-selected profile does not match the constructor-pinned profile');
        }
        if (input.observed_action === null || input.observed_action === undefined) {
            fail('executor-observed action is required');
        }
        const actionDigest = `sha256:${hashCanonical(input.observed_action)}`;
        const presentation = parsePresentation(input.presented);
        const evaluation = evaluatedAt(now);
        const record = evaluate(presentation.claim_case, {
            pinned_profile: profile,
            pinned_profile_hash: computedProfileHash,
            verifier_registry: registry,
            evaluated_at: evaluation.text,
            expected_action_digest: actionDigest,
        });
        const caseInstant = Date.parse(record.as_of);
        if (!Number.isFinite(caseInstant) || caseInstant > evaluation.milliseconds) {
            fail('Claim Case as_of must not be in the future');
        }
        const caseAgeSeconds = Math.floor((evaluation.milliseconds - caseInstant) / 1_000);
        const mappedVerdict = claimVerdictToAdmissibility(record);
        const stale = caseAgeSeconds > maxCaseAgeSec;
        // Preserve the closed failure precedence. Conflict and unverifiability are
        // stronger than age, so an old DIVERGED/UNVERIFIED case must not be remapped
        // into a typed combination the Gate validator rejects. Staleness may replace
        // only an otherwise-admissible or merely-missing-evidence result.
        const admissibilityVerdict = stale
            && (mappedVerdict === 'admissible' || mappedVerdict === 'missing_evidence')
            ? 'stale'
            : mappedVerdict;
        const reasons = [...allReasons(record), ...(stale ? ['CLAIM_CASE_STALE'] : [])]
            .filter((reason, index, values) => values.indexOf(reason) === index)
            .sort();
        return Object.freeze({
            '@type': CLAIM_ASSURANCE_ADMISSIBILITY_VERSION,
            admissibility_profile: { id: profile.profile_id, version: '1' },
            profile_hash: computedProfileHash,
            verdict: admissibilityVerdict,
            replay_digest: record.replay_digest,
            assurance_record_digest: record.record_digest,
            claim_case_digest: record.claim_case_digest,
            action_digest: actionDigest,
            claim_assurance_verdict: record.verdict,
            profile_satisfied: record.profile_satisfied,
            authorizes_action: false,
            as_of: record.as_of,
            evaluated_at: record.evaluated_at,
            reasons,
        });
    };
}
export { CLAIM_ASSURANCE_ADMISSIBILITY_RESULT_VERSION, claimAssuranceResultCandidate, validateClaimAssuranceAdmissibilityResult, } from './claim-assurance-result.js';
//# sourceMappingURL=claim-assurance.js.map