// SPDX-License-Identifier: Apache-2.0
// Generated from aeb-execution-conditions.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import test from 'node:test';
import { digestAeb } from './aeb-adapter-contract.js';
import { AEB_EXECUTION_CONDITION_RESOLUTION_VERSION, AEB_EXECUTION_CONDITIONS_VERSION, AEB_EXECUTION_RESOLVER_PROFILE_VERSION, defineAebExecutionConditionsProfile, defineAebExecutionResolverProfile, evaluateAebExecutionConditions, } from './aeb-execution-conditions.js';
const NOW = '2027-12-02T12:00:00Z';
const SOON = '2027-12-02T12:00:30Z';
const LATER = '2027-12-02T12:01:00Z';
const STALE = '2027-12-02T11:58:00Z';
const RP = 'rp:emilia-gate';
const ACTION_DIGEST = digestAeb({
    action_type: 'production.deploy.1',
    environment: 'production',
    image: 'sha256:release-42',
});
const OTHER_ACTION_DIGEST = digestAeb({
    action_type: 'production.deploy.1',
    environment: 'production',
    image: 'sha256:release-43',
});
const AUTHORIZATION_EVIDENCE_DIGEST = digestAeb({ receipt: 'human-approval-7' });
const BASIS_DIGEST = digestAeb({ basis: 'approved-release-window' });
const PREDICATE_SET_DIGEST = digestAeb({ predicates: ['change-window-open', 'release-not-revoked'] });
const PRESENTATION_DIGEST = digestAeb({ rendered: 'Deploy release 42 to production?' });
const approvedBasis = Object.freeze({
    authorization_evidence_digest: AUTHORIZATION_EVIDENCE_DIGEST,
    basis_digest: BASIS_DIGEST,
    predicate_set_digest: PREDICATE_SET_DIGEST,
    presentation_method: 'emilia.wysiwys.v1',
    presentation_digest: PRESENTATION_DIGEST,
});
function sourceId(strength) {
    return `resolver:${strength}`;
}
function trustDigest(strength) {
    return digestAeb({ trust: sourceId(strength), key: '2027-q4' });
}
function buildProfiles(strengths = ['observed']) {
    const resolver = defineAebExecutionResolverProfile({
        '@version': AEB_EXECUTION_RESOLVER_PROFILE_VERSION,
        profile_id: 'resolver-profile:production-deploy',
        version: 1,
        relying_party_id: RP,
        max_resolution_age_seconds: 60,
        max_future_skew_seconds: 5,
        sources: strengths.map((strength) => ({
            source_id: sourceId(strength),
            trust_digest: trustDigest(strength),
            required_strength: strength,
        })),
    });
    const profile = defineAebExecutionConditionsProfile({
        '@version': AEB_EXECUTION_CONDITIONS_VERSION,
        profile_id: 'execution-conditions:production-deploy',
        version: 1,
        relying_party_id: RP,
        action_digest: ACTION_DIGEST,
        approved_basis: approvedBasis,
        resolver_profile_id: resolver.profile_id,
        resolver_profile_digest: resolver.profile_digest,
    });
    return { resolver, profile };
}
function resolution(resolver, strength = 'observed', overrides = {}) {
    const prevention = strength === 'compare-and-set' || strength === 'provider-enforced';
    return {
        '@version': AEB_EXECUTION_CONDITION_RESOLUTION_VERSION,
        source_id: sourceId(strength),
        source_trust_digest: trustDigest(strength),
        source_record_digest: digestAeb({ source: sourceId(strength), record: '42' }),
        resolver_profile_digest: resolver.profile_digest,
        action_digest: ACTION_DIGEST,
        authorization_evidence_digest: AUTHORIZATION_EVIDENCE_DIGEST,
        basis_digest: BASIS_DIGEST,
        predicate_set_digest: PREDICATE_SET_DIGEST,
        presentation_method: approvedBasis.presentation_method,
        presentation_digest: PRESENTATION_DIGEST,
        verdict: 'MATCH',
        strength,
        resolved_at: NOW,
        valid_until: LATER,
        lease_expires_at: strength === 'leased' ? LATER : null,
        enforcement_evidence_digest: prevention
            ? digestAeb({ mechanism: strength, operation: 'deploy-42' })
            : null,
        prevention_claimed: prevention,
        ...overrides,
    };
}
function evaluate(resolver, profile, resolutions, overrides = {}) {
    return evaluateAebExecutionConditions(profile, {
        expected_profile_digest: profile.profile_digest,
        resolver_profile: resolver,
        action_digest: ACTION_DIGEST,
        approved_basis: approvedBasis,
        basis_status: {
            verdict: 'CURRENT',
            checked_at: NOW,
            status_valid_until: LATER,
        },
        resolutions,
        evaluated_at: SOON,
        ...overrides,
    });
}
test('profiles are RP-owned, content-addressed, canonical, and immutable', () => {
    const { resolver, profile } = buildProfiles(['provider-enforced', 'compare-and-set']);
    assert.equal(profile.resolver_profile_digest, resolver.profile_digest);
    assert.deepEqual(resolver.sources.map((source) => source.source_id), ['resolver:compare-and-set', 'resolver:provider-enforced']);
    assert.ok(Object.isFrozen(profile));
    assert.ok(Object.isFrozen(profile.approved_basis));
    assert.ok(Object.isFrozen(resolver));
    assert.ok(Object.isFrozen(resolver.sources));
});
test('post-hoc human-approved basis or presentation substitution is INVALID', () => {
    const { resolver, profile } = buildProfiles();
    const changedBasis = evaluate(resolver, profile, [resolution(resolver)], {
        approved_basis: { ...approvedBasis, basis_digest: digestAeb({ basis: 'substituted' }) },
    });
    const changedPresentation = evaluate(resolver, profile, [resolution(resolver)], {
        approved_basis: {
            ...approvedBasis,
            presentation_digest: digestAeb({ rendered: 'Approve any production deployment?' }),
        },
    });
    assert.equal(changedBasis.outcome, 'INVALID');
    assert.deepEqual(changedBasis.reasons, ['basis_digest_mismatch']);
    assert.equal(changedPresentation.outcome, 'INVALID');
    assert.deepEqual(changedPresentation.reasons, ['presentation_digest_mismatch']);
});
test('a presenter-selected resolver or trust root is INVALID', () => {
    const { resolver, profile } = buildProfiles();
    const attackerResolver = structuredClone(resolver);
    attackerResolver.sources[0] = {
        ...attackerResolver.sources[0],
        trust_digest: digestAeb({ trust: 'presenter-selected' }),
    };
    const result = evaluate(resolver, profile, [resolution(resolver)], {
        resolver_profile: attackerResolver,
    });
    assert.equal(result.outcome, 'INVALID');
    assert.ok(result.reasons.includes('resolver_profile_digest_mismatch'));
});
test('stale, unavailable, and conflicting resolutions remain INDETERMINATE', () => {
    const { resolver, profile } = buildProfiles();
    const stale = evaluate(resolver, profile, [resolution(resolver, 'observed', {
            resolved_at: STALE,
            valid_until: SOON,
        })]);
    const unavailable = evaluate(resolver, profile, [resolution(resolver, 'observed', {
            verdict: 'UNAVAILABLE',
        })]);
    const conflicting = evaluate(resolver, profile, [resolution(resolver, 'observed', {
            verdict: 'CONFLICTING',
        })]);
    assert.equal(stale.outcome, 'INDETERMINATE');
    assert.deepEqual(stale.reasons, ['resolution_stale']);
    assert.equal(unavailable.outcome, 'INDETERMINATE');
    assert.deepEqual(unavailable.reasons, ['resolution_unavailable']);
    assert.equal(conflicting.outcome, 'INDETERMINATE');
    assert.deepEqual(conflicting.reasons, ['resolution_conflicting']);
});
test('an exact-action mismatch is INVALID rather than a predicate failure', () => {
    const { resolver, profile } = buildProfiles();
    const result = evaluate(resolver, profile, [resolution(resolver)], {
        action_digest: OTHER_ACTION_DIGEST,
    });
    assert.equal(result.outcome, 'INVALID');
    assert.equal(result.binding, 'MISMATCH');
    assert.deepEqual(result.reasons, ['exact_action_mismatch']);
});
test('a resolved predicate mismatch is PREDICATE_FAILED and stays distinct from status failures', () => {
    const { resolver, profile } = buildProfiles();
    const failed = evaluate(resolver, profile, [resolution(resolver, 'observed', {
            verdict: 'MISMATCH',
        })]);
    const expired = evaluate(resolver, profile, [resolution(resolver)], {
        basis_status: { verdict: 'EXPIRED', checked_at: NOW, status_valid_until: LATER },
    });
    const revoked = evaluate(resolver, profile, [resolution(resolver)], {
        basis_status: { verdict: 'REVOKED', checked_at: NOW, status_valid_until: LATER },
    });
    assert.equal(failed.outcome, 'PREDICATE_FAILED');
    assert.deepEqual(failed.reasons, ['predicate_failed']);
    assert.equal(expired.outcome, 'INVALID');
    assert.deepEqual(expired.reasons, ['basis_expired']);
    assert.equal(revoked.outcome, 'INVALID');
    assert.deepEqual(revoked.reasons, ['basis_revoked']);
});
test('observed and leased evidence may admit but may never claim prevention', () => {
    for (const strength of ['observed', 'leased']) {
        const { resolver, profile } = buildProfiles([strength]);
        const honest = evaluate(resolver, profile, [resolution(resolver, strength)]);
        const overclaim = evaluate(resolver, profile, [resolution(resolver, strength, {
                prevention_claimed: true,
            })]);
        assert.equal(honest.outcome, 'ADMIT');
        assert.equal(honest.conditions_satisfied, true);
        assert.equal(honest.prevention_established, false);
        assert.equal(overclaim.outcome, 'INVALID');
        assert.deepEqual(overclaim.reasons, ['prevention_claim_not_supported']);
    }
});
test('valid compare-and-set and provider-enforced paths can support a prevention claim', () => {
    for (const strength of ['compare-and-set', 'provider-enforced']) {
        const { resolver, profile } = buildProfiles([strength]);
        const result = evaluate(resolver, profile, [resolution(resolver, strength)]);
        assert.equal(result.outcome, 'ADMIT');
        assert.equal(result.conditions_satisfied, true);
        assert.equal(result.prevention_established, true);
        assert.equal(result.authorization_established, false);
        assert.equal(result.physical_truth_established, false);
        assert.equal(result.decision_scope, 'execution_conditions_only');
    }
});
test('missing enforcement evidence invalidates a prevention-capable path', () => {
    const { resolver, profile } = buildProfiles(['compare-and-set']);
    const result = evaluate(resolver, profile, [resolution(resolver, 'compare-and-set', {
            enforcement_evidence_digest: null,
        })]);
    assert.equal(result.outcome, 'INVALID');
    assert.deepEqual(result.reasons, ['enforcement_evidence_missing']);
});
