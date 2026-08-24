// SPDX-License-Identifier: Apache-2.0
// Generated from claim-assurance.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ASSURANCE_RECORD_VERSION, CLAIM_ASSURANCE_PROFILE_VERSION, CLAIM_CASE_VERSION, claimAssuranceArtifactDigest, claimAssuranceProfileHash, evaluateClaimAssurance, inspectAssuranceRecordIntegrity, verifyAssuranceRecordDigest, } from './dist/claim-assurance.js';
const AS_OF = '2026-08-23T12:00:00Z';
const EVALUATED_AT = '2026-08-23T12:00:01Z';
const SUBJECT = `sha256:${'11'.repeat(32)}`;
const SCOPE = `sha256:${'22'.repeat(32)}`;
const ACTION = `sha256:${'33'.repeat(32)}`;
const IMPLEMENTATION = `sha256:${'44'.repeat(32)}`;
function profile(minimumDistinctSources = 1) {
    return {
        '@type': CLAIM_ASSURANCE_PROFILE_VERSION,
        profile_id: 'emilia.finance.vendor-account.v1',
        claim_type: 'finance.vendor-account',
        predicate: 'beneficiary-account-is-approved',
        requirements: [{
                requirement_id: 'bank-confirmation',
                evidence_role: 'BANK_CONFIRMATION',
                verifier: {
                    verifier_id: 'example.bank-confirmation',
                    verifier_version: '1.0.0',
                    implementation_digest: IMPLEMENTATION,
                },
                minimum_distinct_sources: minimumDistinctSources,
                max_age_seconds: 86_400,
            }],
    };
}
function artifact(source_id = 'bank:one', relationship = 'SUPPORTS') {
    return { source_id, relationship, observed_value: 'acct-ending-1234' };
}
function claimCase(pinnedProfile, artifacts = [artifact()]) {
    return {
        '@type': CLAIM_CASE_VERSION,
        subject_digest: SUBJECT,
        scope_digest: SCOPE,
        claim: {
            claim_id: 'claim:vendor:1234',
            claim_type: pinnedProfile.claim_type,
            predicate: pinnedProfile.predicate,
            value: { beneficiary_account_digest: `sha256:${'55'.repeat(32)}` },
        },
        profile_id: pinnedProfile.profile_id,
        profile_hash: claimAssuranceProfileHash(pinnedProfile),
        action_digest: ACTION,
        as_of: AS_OF,
        evidence: artifacts.map((value, index) => ({
            evidence_id: `evidence:${index + 1}`,
            role: 'BANK_CONFIRMATION',
            verifier: {
                verifier_id: 'example.bank-confirmation',
                verifier_version: '1.0.0',
                implementation_digest: IMPLEMENTATION,
            },
            binding: {
                subject_digest: SUBJECT,
                scope_digest: SCOPE,
                claim_id: 'claim:vendor:1234',
                action_digest: ACTION,
            },
            artifact: value,
            artifact_digest: claimAssuranceArtifactDigest(value),
        })),
    };
}
function registration(transform = () => ({})) {
    return {
        verifier_id: 'example.bank-confirmation',
        verifier_version: '1.0.0',
        implementation_digest: IMPLEMENTATION,
        verify(input) {
            const body = input.artifact;
            return {
                verdict: 'VERIFIED',
                relationship: body.relationship,
                source_id: body.source_id,
                subject_digest: input.subject_digest,
                scope_digest: input.scope_digest,
                claim_id: input.claim.claim_id,
                observed_at: '2026-08-23T11:59:00Z',
                expires_at: '2026-08-24T11:59:00Z',
                artifact_digest: input.artifact_digest,
                reasons: [],
                ...transform(input),
            };
        },
    };
}
function evaluate(value, pinnedProfile, verifiers = [registration()]) {
    return evaluateClaimAssurance(value, {
        pinned_profile: pinnedProfile,
        pinned_profile_hash: claimAssuranceProfileHash(pinnedProfile),
        verifier_registry: verifiers,
        evaluated_at: EVALUATED_AT,
        expected_action_digest: ACTION,
    });
}
test('emits a deterministic offline VERIFIED record without granting authority', () => {
    const p = profile();
    const c = claimCase(p);
    const first = evaluate(c, p);
    const second = evaluate(structuredClone(c), structuredClone(p));
    assert.equal(first['@type'], ASSURANCE_RECORD_VERSION);
    assert.equal(first.verdict, 'VERIFIED');
    assert.equal(first.profile_satisfied, true);
    assert.equal(first.authorizes_action, false);
    assert.equal(first.action_digest, ACTION);
    assert.match(first.replay_digest, /^sha256:[0-9a-f]{64}$/);
    assert.match(first.record_digest, /^sha256:[0-9a-f]{64}$/);
    assert.deepEqual(first, second);
    assert.deepEqual(verifyAssuranceRecordDigest(first), {
        ok: true,
        record_digest: first.record_digest,
        reason: null,
    });
    const semanticallyTampered = structuredClone(first);
    semanticallyTampered.verdict = 'MADE_UP';
    assert.deepEqual(verifyAssuranceRecordDigest(semanticallyTampered), {
        ok: false,
        record_digest: semanticallyTampered.record_digest,
        reason: 'record_semantics_invalid',
    });
    const digestTampered = structuredClone(first);
    digestTampered.scope_digest = `sha256:${'ab'.repeat(32)}`;
    assert.deepEqual(verifyAssuranceRecordDigest(digestTampered), {
        ok: false,
        record_digest: digestTampered.record_digest,
        reason: 'record_digest_mismatch',
    });
});
test('presented self-assertions cannot register their own verifier or trust material', () => {
    const p = profile();
    const selfAssertion = artifact();
    selfAssertion.verdict = 'VERIFIED';
    selfAssertion.verifier_code = 'return true';
    selfAssertion.trust_key = 'attacker-controlled';
    const record = evaluate(claimCase(p, [selfAssertion]), p, []);
    assert.equal(record.verdict, 'INDETERMINATE');
    assert.equal(record.profile_satisfied, false);
    assert.deepEqual(record.evidence_results[0]?.reasons, ['VERIFIER_NOT_REGISTERED']);
    assert.equal(record.authorizes_action, false);
});
test('record integrity inspection is strict and explicitly does not re-perform the case', () => {
    const p = profile();
    const record = evaluate(claimCase(p), p);
    const valid = inspectAssuranceRecordIntegrity(record, {
        expected_record_digest: record.record_digest,
    });
    assert.deepEqual(valid, {
        integrity_valid: true,
        semantics_valid: true,
        replay_digest_matches: true,
        digest_matches: true,
        expected_digest_matches: true,
        reperformed: false,
        record_digest: record.record_digest,
        computed_record_digest: record.record_digest,
        reason: null,
    });
    const wrongExpected = inspectAssuranceRecordIntegrity(record, {
        expected_record_digest: `sha256:${'fe'.repeat(32)}`,
    });
    assert.equal(wrongExpected.integrity_valid, false);
    assert.equal(wrongExpected.semantics_valid, true);
    assert.equal(wrongExpected.digest_matches, true);
    assert.equal(wrongExpected.expected_digest_matches, false);
    assert.equal(wrongExpected.reperformed, false);
    assert.equal(wrongExpected.reason, 'expected_record_digest_mismatch');
    const madeUpVerdict = structuredClone(record);
    madeUpVerdict.verdict = 'MADE_UP';
    const madeUp = inspectAssuranceRecordIntegrity(madeUpVerdict);
    assert.equal(madeUp.semantics_valid, false);
    assert.equal(madeUp.reason, 'record_semantics_invalid');
    const invalidTime = structuredClone(record);
    invalidTime.evaluated_at = '2026-08-23T12:00:01.000Z';
    const badTime = inspectAssuranceRecordIntegrity(invalidTime);
    assert.equal(badTime.semantics_valid, false);
    assert.equal(badTime.reason, 'record_semantics_invalid');
    const invalidReplay = structuredClone(record);
    invalidReplay.replay_digest = `sha256:${'fd'.repeat(32)}`;
    const badReplay = inspectAssuranceRecordIntegrity(invalidReplay);
    assert.equal(badReplay.semantics_valid, true);
    assert.equal(badReplay.replay_digest_matches, false);
    assert.equal(badReplay.digest_matches, false);
    assert.equal(badReplay.reason, 'replay_digest_mismatch');
    assert.equal(badReplay.reperformed, false);
});
test('accepted verified sources that support and contradict produce DIVERGED', () => {
    const p = profile();
    const c = claimCase(p, [artifact('bank:one', 'SUPPORTS'), artifact('bank:two', 'CONTRADICTS')]);
    const record = evaluate(c, p);
    assert.equal(record.verdict, 'DIVERGED');
    assert.equal(record.profile_satisfied, false);
    assert.deepEqual(record.reasons, ['ACCEPTED_SOURCES_DIVERGED']);
});
test('missing, stale, and unavailable required evidence remain distinguishable and INDETERMINATE', () => {
    const p = profile();
    const missing = evaluate(claimCase(p, []), p);
    assert.equal(missing.verdict, 'INDETERMINATE');
    assert.ok(missing.reasons.includes('REQUIRED_EVIDENCE_MISSING'));
    const stale = evaluate(claimCase(p), p, [registration(() => ({ expires_at: '2026-08-23T11:59:59Z' }))]);
    assert.equal(stale.verdict, 'INDETERMINATE');
    assert.deepEqual(stale.evidence_results[0]?.reasons, ['EVIDENCE_STALE']);
    const expiredAfterSnapshot = evaluate(claimCase(p), p, [registration(() => ({ expires_at: '2026-08-23T12:00:00Z' }))]);
    assert.equal(expiredAfterSnapshot.verdict, 'INDETERMINATE');
    assert.deepEqual(expiredAfterSnapshot.evidence_results[0]?.reasons, ['EVIDENCE_STALE']);
    const expiresExactlyAtEvaluation = evaluate(claimCase(p), p, [registration(() => ({ expires_at: EVALUATED_AT }))]);
    assert.equal(expiresExactlyAtEvaluation.verdict, 'INDETERMINATE');
    assert.deepEqual(expiresExactlyAtEvaluation.evidence_results[0]?.reasons, ['EVIDENCE_STALE']);
    const zeroWidthValidity = evaluate(claimCase(p), p, [registration(() => ({
            observed_at: '2026-08-23T11:59:00Z',
            expires_at: '2026-08-23T11:59:00Z',
        }))]);
    assert.equal(zeroWidthValidity.verdict, 'INDETERMINATE');
    assert.deepEqual(zeroWidthValidity.evidence_results[0]?.reasons, ['VERIFIER_RESULT_MALFORMED']);
    const unavailable = registration();
    unavailable.verify = () => { throw new Error('source offline'); };
    const offline = evaluate(claimCase(p), p, [unavailable]);
    assert.equal(offline.verdict, 'INDETERMINATE');
    assert.deepEqual(offline.evidence_results[0]?.reasons, ['VERIFIER_UNAVAILABLE']);
});
test('pinned profile identity and hash are recomputed and tamper-evident', () => {
    const p = profile();
    const c = claimCase(p);
    const tampered = structuredClone(p);
    tampered.requirements[0].minimum_distinct_sources = 2;
    assert.throws(() => evaluateClaimAssurance(c, {
        pinned_profile: tampered,
        pinned_profile_hash: claimAssuranceProfileHash(p),
        verifier_registry: [registration()],
        evaluated_at: EVALUATED_AT,
        expected_action_digest: ACTION,
    }), /pinned_profile_hash does not match pinned_profile/);
    const wrongCaseHash = structuredClone(c);
    wrongCaseHash.profile_hash = `sha256:${'aa'.repeat(32)}`;
    assert.throws(() => evaluate(wrongCaseHash, p), /claim case profile_hash does not match pinned profile/);
});
test('artifact digest tampering is rejected before trusted verifier execution', () => {
    const p = profile();
    const c = claimCase(p);
    c.evidence[0].artifact = { ...c.evidence[0].artifact, observed_value: 'attacker-value' };
    let called = false;
    const verifier = registration();
    const original = verifier.verify;
    verifier.verify = (input) => { called = true; return original(input); };
    const record = evaluate(c, p, [verifier]);
    assert.equal(called, false);
    assert.equal(record.verdict, 'UNVERIFIED');
    assert.deepEqual(record.evidence_results[0]?.reasons, ['ARTIFACT_DIGEST_MISMATCH']);
});
test('subject, scope, claim, and exact-action bindings fail closed', () => {
    const p = profile();
    for (const [member, replacement, reason] of [
        ['subject_digest', `sha256:${'66'.repeat(32)}`, 'SUBJECT_BINDING_MISMATCH'],
        ['scope_digest', `sha256:${'77'.repeat(32)}`, 'SCOPE_BINDING_MISMATCH'],
        ['claim_id', 'claim:other', 'CLAIM_BINDING_MISMATCH'],
        ['action_digest', `sha256:${'88'.repeat(32)}`, 'ACTION_BINDING_MISMATCH'],
    ]) {
        const c = claimCase(p);
        c.evidence[0].binding[member] = replacement;
        const record = evaluate(c, p);
        assert.equal(record.verdict, 'UNVERIFIED');
        assert.deepEqual(record.evidence_results[0]?.reasons, [reason]);
    }
    const wrongExpectedAction = claimCase(p);
    assert.throws(() => evaluateClaimAssurance(wrongExpectedAction, {
        pinned_profile: p,
        pinned_profile_hash: claimAssuranceProfileHash(p),
        verifier_registry: [registration()],
        evaluated_at: EVALUATED_AT,
        expected_action_digest: `sha256:${'99'.repeat(32)}`,
    }), /claim case action_digest does not match expected_action_digest/);
});
test('verifier output must independently restate the bound claim context', () => {
    const p = profile();
    const record = evaluate(claimCase(p), p, [registration(() => ({ subject_digest: `sha256:${'ff'.repeat(32)}` }))]);
    assert.equal(record.verdict, 'UNVERIFIED');
    assert.deepEqual(record.evidence_results[0]?.reasons, ['VERIFIER_SUBJECT_MISMATCH']);
});
test('strict versions, keys, timestamps, duplicates, and resource limits are enforced', () => {
    const p = profile();
    const c = claimCase(p);
    c.unexpected = true;
    assert.throws(() => evaluate(c, p), /unknown member.*unexpected/);
    const wrongVersion = claimCase(p);
    wrongVersion['@type'] = 'EP-CLAIM-CASE-v0';
    assert.throws(() => evaluate(wrongVersion, p), /unsupported claim case version/);
    const badTime = claimCase(p);
    badTime.as_of = '2026-08-23T12:00:00.000Z';
    assert.throws(() => evaluate(badTime, p), /as_of must be a canonical UTC timestamp/);
    const duplicate = claimCase(p, [artifact(), artifact('bank:two')]);
    duplicate.evidence[1].evidence_id = duplicate.evidence[0].evidence_id;
    assert.throws(() => evaluate(duplicate, p), /duplicate evidence_id/);
    const duplicateArtifact = claimCase(p, [artifact(), artifact()]);
    assert.throws(() => evaluate(duplicateArtifact, p), /duplicate artifact_digest/);
    const oversized = claimCase(p);
    oversized.evidence[0].artifact.blob = 'x'.repeat(270_000);
    oversized.evidence[0].artifact_digest = claimAssuranceArtifactDigest(oversized.evidence[0].artifact, { maxStringBytes: 300_000 });
    assert.throws(() => evaluate(oversized, p), /string bytes exceed/);
});
test('profile quorum counts distinct accepted source identities', () => {
    const p = profile(2);
    const repeatedObservation = artifact('bank:one', 'SUPPORTS');
    repeatedObservation.observation_id = 'second-check';
    const repeatedSource = evaluate(claimCase(p, [artifact('bank:one'), repeatedObservation]), p);
    assert.equal(repeatedSource.verdict, 'INDETERMINATE');
    assert.equal(repeatedSource.requirement_results[0]?.accepted_supporting_sources, 1);
    assert.equal(repeatedSource.requirement_results[0]?.satisfied, false);
    const distinct = evaluate(claimCase(p, [artifact('bank:one'), artifact('bank:two')]), p);
    assert.equal(distinct.verdict, 'VERIFIED');
    assert.equal(distinct.requirement_results[0]?.accepted_supporting_sources, 2);
});
test('unsupported verifier version is operational uncertainty, not acceptance', () => {
    const p = profile();
    p.requirements[0].verifier.verifier_version = '2.0.0';
    const c = claimCase(p);
    c.evidence[0].verifier.verifier_version = '2.0.0';
    const record = evaluate(c, p);
    assert.equal(record.verdict, 'INDETERMINATE');
    assert.deepEqual(record.evidence_results[0]?.reasons, ['VERIFIER_NOT_REGISTERED']);
    assert.equal(record.authorizes_action, false);
});
test('rejects evidence outside the pinned profile before registry lookup or callback', () => {
    const p = profile();
    const c = claimCase(p);
    c.evidence[0].role = 'PRESENTER_CHOSEN_ROLE';
    let called = false;
    const verifier = registration();
    const originalVerify = verifier.verify;
    verifier.verify = (input) => {
        called = true;
        return originalVerify(input);
    };
    const record = evaluate(c, p, [verifier]);
    assert.equal(called, false);
    assert.equal(record.evidence_results[0]?.disposition, 'REJECTED');
    assert.deepEqual(record.evidence_results[0]?.reasons, ['EVIDENCE_NOT_IN_PROFILE']);
    assert.equal(record.verdict, 'INDETERMINATE');
});
test('accepted support and contradiction across separate requirements is globally DIVERGED', () => {
    const p = profile();
    const template = p.requirements[0];
    p.requirements = [
        {
            ...structuredClone(template),
            requirement_id: 'requirement:support',
            evidence_role: 'SUPPORT_ROLE',
        },
        {
            ...structuredClone(template),
            requirement_id: 'requirement:contradict',
            evidence_role: 'CONTRADICT_ROLE',
        },
    ];
    const c = claimCase(p, [artifact('bank:support', 'SUPPORTS'), artifact('bank:contradict', 'CONTRADICTS')]);
    c.evidence[0].role = 'SUPPORT_ROLE';
    c.evidence[1].role = 'CONTRADICT_ROLE';
    const record = evaluate(c, p);
    assert.equal(record.verdict, 'DIVERGED');
    assert.equal(record.profile_satisfied, false);
    assert.deepEqual(record.reasons, ['ACCEPTED_SOURCES_DIVERGED']);
    assert.deepEqual(new Set(record.requirement_results.map((result) => result.disposition)), new Set(['SATISFIED', 'UNVERIFIED']));
});
test('deduplicates and caps verifier reasons after preserving the framework reason', () => {
    const p = profile();
    const verifierReasons = [
        'duplicate',
        'duplicate',
        ...Array.from({ length: 14 }, (_, index) => `verifier:${String(index).padStart(2, '0')}`),
    ];
    const record = evaluate(claimCase(p), p, [registration(() => ({ verdict: 'UNVERIFIED', reasons: verifierReasons }))]);
    const reasons = record.evidence_results[0].reasons;
    assert.equal(reasons[0], 'VERIFIER_UNVERIFIED');
    assert.equal(reasons.length, 16);
    assert.equal(new Set(reasons).size, reasons.length);
    assert.equal(reasons.filter((reason) => reason === 'duplicate').length, 1);
});
test('snapshots evaluated_at before a verifier can mutate caller-owned options', () => {
    const p = profile(2);
    const c = claimCase(p, [artifact('bank:one'), artifact('bank:two')]);
    const expected = evaluate(structuredClone(c), structuredClone(p));
    const hostile = registration();
    const originalVerify = hostile.verify;
    let calls = 0;
    let hostileOptions;
    hostile.verify = (input) => {
        const result = originalVerify(input);
        calls += 1;
        if (calls === 1) {
            // If evaluateClaimAssurance rereads the caller's options, the second
            // item becomes stale and the record reports this attacker-chosen time.
            hostileOptions.evaluated_at = '2026-08-25T12:00:01Z';
        }
        return result;
    };
    hostileOptions = {
        pinned_profile: p,
        pinned_profile_hash: claimAssuranceProfileHash(p),
        verifier_registry: [hostile],
        evaluated_at: EVALUATED_AT,
        expected_action_digest: ACTION,
    };
    const actual = evaluateClaimAssurance(c, hostileOptions);
    assert.equal(calls, 2);
    assert.equal(hostileOptions.evaluated_at, '2026-08-25T12:00:01Z');
    assert.equal(actual.evaluated_at, EVALUATED_AT);
    assert.deepEqual(actual.evidence_results.map((result) => result.disposition), [
        'ACCEPTED',
        'ACCEPTED',
    ]);
    assert.deepEqual(actual, expected);
});
test('uses protocol code-unit order without consulting locale collation', () => {
    const p = profile();
    const firstRequirement = p.requirements[0];
    p.requirements = [
        {
            ...structuredClone(firstRequirement),
            requirement_id: 'requirement:a',
            evidence_role: 'ROLE_A',
        },
        {
            ...structuredClone(firstRequirement),
            requirement_id: 'requirement:Z',
            evidence_role: 'ROLE_Z',
        },
    ];
    const c = claimCase(p, [artifact('bank:a'), artifact('bank:Z')]);
    c.evidence[0].evidence_id = 'evidence:a';
    c.evidence[0].role = 'ROLE_A';
    c.evidence[1].evidence_id = 'evidence:Z';
    c.evidence[1].role = 'ROLE_Z';
    const expected = evaluate(structuredClone(c), structuredClone(p));
    const originalLocaleCompare = String.prototype.localeCompare;
    String.prototype.localeCompare = function forbiddenLocaleCompare() {
        throw new Error('protocol ordering consulted host locale collation');
    };
    let actual;
    try {
        actual = evaluateClaimAssurance(c, {
            pinned_profile: p,
            pinned_profile_hash: claimAssuranceProfileHash(p),
            verifier_registry: [registration()],
            evaluated_at: EVALUATED_AT,
            expected_action_digest: ACTION,
        });
    }
    finally {
        String.prototype.localeCompare = originalLocaleCompare;
    }
    assert.deepEqual(actual.evidence_results.map((result) => result.evidence_id), [
        'evidence:Z',
        'evidence:a',
    ]);
    assert.deepEqual(actual.requirement_results.map((result) => result.requirement_id), [
        'requirement:Z',
        'requirement:a',
    ]);
    assert.equal(actual.record_digest, expected.record_digest);
    assert.deepEqual(actual, expected);
});
