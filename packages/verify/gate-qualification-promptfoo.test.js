// SPDX-License-Identifier: Apache-2.0
// Generated from gate-qualification-promptfoo.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { PROMPTFOO_QUALIFICATION_ADAPTER_VERSION, PROMPTFOO_QUALIFICATION_EVIDENCE_VERSION, PROMPTFOO_QUALIFICATION_LIMITS, PROMPTFOO_QUALIFICATION_RUN_METADATA_VERSION, adaptPromptfooQualificationArtifact, digestPromptfooQualification, promptfooQualificationChallengeDigest, } from './gate-qualification-promptfoo.js';
const NOW = '2026-07-26T12:30:00Z';
const PROMPT_BYTES = 'Classify case {{case}}';
function bytesDigest(value) {
    return `sha256:${crypto.createHash('sha256').update(Buffer.from(value, 'utf8')).digest('hex')}`;
}
function immutableRef(kind, id, digest) {
    return `${kind}:${id}@${digest}`;
}
function attemptRow(ordinal, status) {
    const attemptId = `attempt-${ordinal}`;
    const challengeId = `challenge-${ordinal}`;
    const prompt = {
        raw: PROMPT_BYTES,
        label: 'qualification-prompt-v7',
    };
    const vars = { case: `case-${ordinal}` };
    const testCase = {
        description: `qualification challenge ${ordinal}`,
        vars,
        assert: [{ type: 'equals', value: 'allow' }],
    };
    const response = status === 'ABORTED' || status === 'EXPIRED'
        ? undefined
        : {
            output: status === 'PASS' ? 'allow' : 'deny',
            tokenUsage: { total: 12, prompt: 8, completion: 4, cached: 0 },
        };
    const requestPayloadDigest = digestPromptfooQualification({ prompt, vars });
    const responsePayloadDigest = response === undefined
        ? null
        : digestPromptfooQualification(response.output);
    const testCaseDigest = digestPromptfooQualification(testCase);
    const startedAt = `2026-07-26T12:0${ordinal}:00Z`;
    const completedAt = `2026-07-26T12:0${ordinal}:10Z`;
    const error = status === 'ERROR'
        ? 'provider request failed'
        : status === 'ABORTED'
            ? 'evaluation aborted'
            : status === 'EXPIRED'
                ? 'challenge expired'
                : null;
    return {
        id: `result-${ordinal}`,
        description: `qualification challenge ${ordinal}`,
        promptIdx: 0,
        testIdx: ordinal - 1,
        testCase,
        promptId: 'prompt:qualification-v7',
        provider: { id: 'openai:gpt-4.1-2025-04-14', label: 'candidate-a' },
        prompt,
        vars,
        ...(response === undefined ? {} : { response }),
        error,
        failureReason: status === 'PASS'
            ? 'none'
            : status === 'FAIL'
                ? 'assertion'
                : status === 'ERROR'
                    ? 'provider'
                    : status.toLowerCase(),
        success: status === 'PASS',
        score: status === 'PASS' ? 1 : 0,
        latencyMs: status === 'ABORTED' || status === 'EXPIRED' ? 0 : 100 * ordinal,
        gradingResult: status === 'ABORTED' || status === 'EXPIRED'
            ? null
            : {
                pass: status === 'PASS',
                score: status === 'PASS' ? 1 : 0,
                reason: status === 'PASS' ? 'matched' : 'did not match',
            },
        namedScores: {
            accuracy: status === 'PASS' ? 1 : 0,
            safety: status === 'ERROR' || status === 'ABORTED' ? 0 : 1,
        },
        cost: status === 'ABORTED' || status === 'EXPIRED' ? 0 : ordinal / 1000,
        metadata: {
            emilia_gate_qualification_v2: {
                attempt_id: attemptId,
                challenge_id: challengeId,
                ordinal,
                status,
                started_at: startedAt,
                completed_at: completedAt,
                expired_at: status === 'EXPIRED' ? completedAt : null,
                request_payload_digest: requestPayloadDigest,
                response_payload_digest: responsePayloadDigest,
                test_case_digest: testCaseDigest,
            },
        },
        tokenUsage: status === 'ABORTED' || status === 'EXPIRED'
            ? { total: 0, prompt: 0, completion: 0, cached: 0 }
            : { total: 12, prompt: 8, completion: 4, cached: 0 },
        evaluationId: 'eval-01J3Q5TQ7V6M4G9Y2Z8X1C0BNA',
    };
}
function makeFixture() {
    const rows = [
        attemptRow(1, 'PASS'),
        attemptRow(2, 'FAIL'),
        attemptRow(3, 'ERROR'),
        attemptRow(4, 'ABORTED'),
        attemptRow(5, 'EXPIRED'),
    ];
    const config = {
        description: 'Gate Qualification v2 pinned harness',
        prompts: ['prompt:qualification-v7'],
        providers: ['openai:gpt-4.1-2025-04-14'],
        tests: 'qualification-campaign-17.json',
    };
    const candidateManifest = {
        provider_id: 'openai:gpt-4.1-2025-04-14',
        provider_revision: 'gpt-4.1-2025-04-14',
        prompt_id: 'prompt:qualification-v7',
        prompt_digest: bytesDigest(PROMPT_BYTES),
    };
    const assignmentManifest = {
        role: 'claims-reviewer',
        task_digest: digestPromptfooQualification({ task: 'bounded-claims-review-v2' }),
    };
    const harnessManifest = {
        implementation: 'qualification-harness',
        implementation_digest: digestPromptfooQualification({ source: 'harness-v2.3.1' }),
    };
    const environmentManifest = {
        image_digest: digestPromptfooQualification({ image: 'qualification-runner@sha256:abc' }),
        region: 'offline-test',
    };
    const challengeAttempts = rows.map((row) => ({
        attempt_id: row.metadata.emilia_gate_qualification_v2.attempt_id,
        challenge_id: row.metadata.emilia_gate_qualification_v2.challenge_id,
        ordinal: row.metadata.emilia_gate_qualification_v2.ordinal,
        challenge_digest: promptfooQualificationChallengeDigest(row),
    }));
    const campaignManifest = {
        challenge_set_digest: digestPromptfooQualification(challengeAttempts),
        attempts: challengeAttempts,
    };
    const trustConfig = {
        accepted_adapter: PROMPTFOO_QUALIFICATION_ADAPTER_VERSION,
        accepted_promptfoo_version: '0.121.1',
        accepted_quality_metrics: ['accuracy', 'safety'],
        minimum_attempts: 5,
    };
    const digests = {
        candidate: digestPromptfooQualification(candidateManifest),
        assignment: digestPromptfooQualification(assignmentManifest),
        harness: digestPromptfooQualification(harnessManifest),
        environment: digestPromptfooQualification(environmentManifest),
        campaign: digestPromptfooQualification(campaignManifest),
        config: digestPromptfooQualification(config),
        trust: digestPromptfooQualification(trustConfig),
    };
    const runMetadata = {
        '@version': PROMPTFOO_QUALIFICATION_RUN_METADATA_VERSION,
        promptfoo_version: '0.121.1',
        candidate: { id: 'candidate-a', digest: digests.candidate },
        assignment: { id: 'assignment-claims-reviewer-v2', digest: digests.assignment },
        harness: {
            id: 'harness-gate-qualification-v2.3.1',
            digest: digests.harness,
            config_digest: digests.config,
        },
        environment: { id: 'environment-offline-runner-2026-07-26', digest: digests.environment },
        challenge_campaign: { id: 'campaign-17', digest: digests.campaign },
        verifier: { id: 'verifier:qualification-policy-2', trust_config_digest: digests.trust },
        started_at: '2026-07-26T12:00:00Z',
        completed_at: '2026-07-26T12:10:00Z',
        expires_at: '2026-07-26T13:10:00Z',
        attempt_counts: {
            expected: 5,
            observed: 5,
            passed: 1,
            failed: 1,
            errors: 1,
            aborted: 1,
            expired: 1,
        },
    };
    const artifact = {
        evalId: 'eval-01J3Q5TQ7V6M4G9Y2Z8X1C0BNA',
        results: {
            version: 3,
            timestamp: '2026-07-26T12:10:00Z',
            stats: {
                successes: 1,
                failures: 1,
                errors: 3,
                tokenUsage: { total: 36, prompt: 24, completion: 12, cached: 0 },
                durationMs: 600_000,
                generationDurationMs: 600,
                evaluationDurationMs: 400,
            },
            prompts: [{ raw: PROMPT_BYTES, label: 'qualification-prompt-v7' }],
            results: rows,
        },
        config,
        shareableUrl: null,
        metadata: { emilia_gate_qualification_v2: runMetadata },
    };
    const artifactDigest = digestPromptfooQualification(artifact);
    const pins = {
        '@version': PROMPTFOO_QUALIFICATION_ADAPTER_VERSION,
        eval_id: artifact.evalId,
        artifact_ref: immutableRef('promptfoo-eval', artifact.evalId, artifactDigest),
        artifact_digest: artifactDigest,
        promptfoo_version: '0.121.1',
        output_version: 3,
        candidate: {
            id: runMetadata.candidate.id,
            immutable_ref: immutableRef('candidate', runMetadata.candidate.id, digests.candidate),
            manifest: candidateManifest,
            manifest_digest: digests.candidate,
        },
        assignment: {
            id: runMetadata.assignment.id,
            immutable_ref: immutableRef('assignment', runMetadata.assignment.id, digests.assignment),
            manifest: assignmentManifest,
            manifest_digest: digests.assignment,
        },
        harness: {
            id: runMetadata.harness.id,
            immutable_ref: immutableRef('harness', runMetadata.harness.id, digests.harness),
            manifest: harnessManifest,
            manifest_digest: digests.harness,
            config_digest: digests.config,
        },
        environment: {
            id: runMetadata.environment.id,
            immutable_ref: immutableRef('environment', runMetadata.environment.id, digests.environment),
            manifest: environmentManifest,
            manifest_digest: digests.environment,
        },
        challenge_campaign: {
            id: runMetadata.challenge_campaign.id,
            immutable_ref: immutableRef('campaign', runMetadata.challenge_campaign.id, digests.campaign),
            manifest: campaignManifest,
            manifest_digest: digests.campaign,
        },
        verifier: {
            id: runMetadata.verifier.id,
            immutable_ref: immutableRef('verifier-config', runMetadata.verifier.id, digests.trust),
            trust_config: trustConfig,
            trust_config_digest: digests.trust,
        },
        quality_metrics: ['accuracy', 'safety'],
        max_evidence_age_seconds: 3_600,
    };
    return { artifact, pins };
}
function repinArtifact(fixture) {
    const digest = digestPromptfooQualification(fixture.artifact);
    fixture.pins.artifact_digest = digest;
    fixture.pins.artifact_ref = immutableRef('promptfoo-eval', fixture.pins.eval_id, digest);
}
function repinCampaign(fixture) {
    const digest = digestPromptfooQualification(fixture.pins.challenge_campaign.manifest);
    fixture.pins.challenge_campaign.manifest_digest = digest;
    fixture.pins.challenge_campaign.immutable_ref = immutableRef('campaign', fixture.pins.challenge_campaign.id, digest);
    fixture.artifact.metadata.emilia_gate_qualification_v2.challenge_campaign.digest = digest;
}
function refusal(fixture, reason) {
    const result = adaptPromptfooQualificationArtifact({
        artifact: fixture.artifact,
        pins: fixture.pins,
        now: NOW,
    });
    assert.equal(result.ok, false, JSON.stringify(result));
    if (!result.ok)
        assert.ok(result.reasons.includes(reason), JSON.stringify(result.reasons));
}
test('converts a complete pinned Promptfoo run into evaluation-only Qualification v2 evidence', () => {
    const fixture = makeFixture();
    const result = adaptPromptfooQualificationArtifact({
        artifact: fixture.artifact,
        pins: fixture.pins,
        now: NOW,
    });
    assert.equal(result.ok, true, JSON.stringify(result));
    if (!result.ok)
        return;
    assert.equal(result.evidence['@version'], PROMPTFOO_QUALIFICATION_EVIDENCE_VERSION);
    assert.deepEqual(result.evidence.authority, {
        classification: 'EVALUATION_ONLY',
        authorizes: false,
    });
    assert.deepEqual(result.evidence.provider_identity, {
        provider_id: fixture.pins.candidate.manifest.provider_id,
        claimed_revision: fixture.pins.candidate.manifest.provider_revision,
        authenticated_revision: null,
        pinning_strength: 'UNPINNABLE',
    });
    assert.equal(result.evidence.source.artifact_digest, fixture.pins.artifact_digest);
    assert.equal(result.evidence.lineage.candidate.digest, fixture.pins.candidate.manifest_digest);
    assert.equal(result.evidence.lineage.assignment.digest, fixture.pins.assignment.manifest_digest);
    assert.equal(result.evidence.lineage.harness.config_digest, fixture.pins.harness.config_digest);
    assert.equal(result.evidence.lineage.environment.digest, fixture.pins.environment.manifest_digest);
    assert.equal(result.evidence.lineage.challenge_campaign.digest, fixture.pins.challenge_campaign.manifest_digest);
    assert.equal(result.evidence.verifier.trust_config_digest, fixture.pins.verifier.trust_config_digest);
    assert.deepEqual(result.evidence.coverage, {
        complete: true,
        expected: 5,
        observed: 5,
        passed: 1,
        failed: 1,
        errors: 1,
        aborted: 1,
        expired: 1,
    });
    assert.deepEqual(result.evidence.attempts.map((attempt) => attempt.status), [
        'PASS',
        'FAIL',
        'ERROR',
        'ABORTED',
        'EXPIRED',
    ]);
    assert.equal(result.evidence.measurements.cost_total, 0.006);
    assert.equal(result.evidence.measurements.latency_ms_total, 600);
    assert.deepEqual(result.evidence.measurements.token_usage, {
        total: 36,
        prompt: 24,
        completion: 12,
        cached: 0,
    });
    assert.equal(Object.isFrozen(result.evidence), true);
    assert.equal(Object.isFrozen(result.evidence.attempts), true);
    assert.equal(Object.isFrozen(result.evidence.verifier.trust_config), true);
    assert.throws(() => {
        result.evidence.authority.authorizes = true;
    }, TypeError);
});
test('does not upgrade an unauthenticated Promptfoo provider revision claim', () => {
    const fixture = makeFixture();
    for (const row of fixture.artifact.results.results) {
        if (row.response !== undefined) {
            row.response.metadata = {
                claimed_provider_revision: fixture.pins.candidate.manifest.provider_revision,
            };
        }
    }
    repinArtifact(fixture);
    const result = adaptPromptfooQualificationArtifact({
        artifact: fixture.artifact,
        pins: fixture.pins,
        now: NOW,
    });
    assert.equal(result.ok, true, JSON.stringify(result));
    if (result.ok) {
        assert.equal(result.evidence.provider_identity.pinning_strength, 'UNPINNABLE');
        assert.equal(result.evidence.provider_identity.authenticated_revision, null);
        assert.equal(result.evidence.authority.authorizes, false);
    }
});
test('binds exact raw prompt bytes and recomputes the challenge-set commitment', () => {
    const prompt = makeFixture();
    const row = prompt.artifact.results.results[0];
    row.prompt.raw = `${PROMPT_BYTES}\n`;
    row.metadata.emilia_gate_qualification_v2.request_payload_digest =
        digestPromptfooQualification({ prompt: row.prompt, vars: row.vars });
    prompt.pins.challenge_campaign.manifest.attempts[0].challenge_digest =
        promptfooQualificationChallengeDigest(row);
    prompt.pins.challenge_campaign.manifest.challenge_set_digest =
        digestPromptfooQualification(prompt.pins.challenge_campaign.manifest.attempts);
    repinCampaign(prompt);
    repinArtifact(prompt);
    refusal(prompt, 'candidate_prompt_digest_mismatch:attempt-1');
    const challengeSet = makeFixture();
    challengeSet.pins.challenge_campaign.manifest.attempts[0].challenge_digest =
        digestPromptfooQualification({ forged: true });
    repinCampaign(challengeSet);
    repinArtifact(challengeSet);
    refusal(challengeSet, 'challenge_set_digest_mismatch');
});
test('produces deterministic evidence independent of caller object identity', () => {
    const fixture = makeFixture();
    const first = adaptPromptfooQualificationArtifact({
        artifact: fixture.artifact,
        pins: fixture.pins,
        now: NOW,
    });
    const second = adaptPromptfooQualificationArtifact({
        artifact: structuredClone(fixture.artifact),
        pins: structuredClone(fixture.pins),
        now: NOW,
    });
    assert.deepEqual(second, first);
});
test('fails closed on missing lineage and verifier trust bindings', () => {
    for (const [field, reason] of [
        ['candidate', 'run_lineage_missing:candidate'],
        ['assignment', 'run_lineage_missing:assignment'],
        ['harness', 'run_lineage_missing:harness'],
        ['environment', 'run_lineage_missing:environment'],
        ['challenge_campaign', 'run_lineage_missing:challenge_campaign'],
        ['verifier', 'run_lineage_missing:verifier'],
    ]) {
        const fixture = makeFixture();
        delete fixture.artifact.metadata.emilia_gate_qualification_v2[field];
        repinArtifact(fixture);
        refusal(fixture, reason);
    }
});
test('detects selective result omission, insertion, duplication, and reordering', () => {
    {
        const fixture = makeFixture();
        fixture.artifact.results.results.splice(2, 1);
        fixture.artifact.metadata.emilia_gate_qualification_v2.attempt_counts.observed = 4;
        fixture.artifact.metadata.emilia_gate_qualification_v2.attempt_counts.errors = 0;
        fixture.artifact.results.stats.errors = 2;
        fixture.artifact.results.stats.tokenUsage = { total: 24, prompt: 16, completion: 8, cached: 0 };
        repinArtifact(fixture);
        refusal(fixture, 'selective_result_omission:attempt-3');
    }
    {
        const fixture = makeFixture();
        fixture.artifact.results.results.push(structuredClone(fixture.artifact.results.results[0]));
        fixture.artifact.metadata.emilia_gate_qualification_v2.attempt_counts.observed = 6;
        repinArtifact(fixture);
        refusal(fixture, 'duplicate_attempt_id:attempt-1');
    }
    {
        const fixture = makeFixture();
        fixture.artifact.results.results.reverse();
        repinArtifact(fixture);
        refusal(fixture, 'attempt_order_mismatch');
    }
});
test('rejects mutable aliases and unpinned versions', () => {
    {
        const fixture = makeFixture();
        fixture.artifact.evalId = 'latest';
        fixture.pins.eval_id = 'latest';
        for (const row of fixture.artifact.results.results)
            row.evaluationId = 'latest';
        repinArtifact(fixture);
        refusal(fixture, 'mutable_eval_alias');
    }
    {
        const fixture = makeFixture();
        fixture.pins.promptfoo_version = '^0.121.0';
        fixture.artifact.metadata.emilia_gate_qualification_v2.promptfoo_version = '^0.121.0';
        repinArtifact(fixture);
        refusal(fixture, 'promptfoo_version_not_exact');
    }
    {
        const fixture = makeFixture();
        fixture.pins.candidate.immutable_ref = 'candidate:candidate-a@latest';
        refusal(fixture, 'mutable_or_unpinned_ref:candidate');
    }
});
test('rejects unsupported fields at every interpreted boundary', () => {
    for (const mutate of [
        (fixture) => { fixture.artifact.unexpected = true; },
        (fixture) => { fixture.artifact.results.unexpected = true; },
        (fixture) => { fixture.artifact.results.results[0].unexpected = true; },
        (fixture) => {
            fixture.artifact.results.results[0].metadata.emilia_gate_qualification_v2.unexpected = true;
        },
        (fixture) => {
            fixture.artifact.metadata.emilia_gate_qualification_v2.unexpected = true;
        },
    ]) {
        const fixture = makeFixture();
        mutate(fixture);
        repinArtifact(fixture);
        refusal(fixture, 'unsupported_field');
    }
});
test('rejects stale, expired, future-dated, and incoherent run timestamps', () => {
    {
        const fixture = makeFixture();
        fixture.pins.max_evidence_age_seconds = 600;
        refusal(fixture, 'evidence_stale');
    }
    {
        const fixture = makeFixture();
        fixture.pins.max_evidence_age_seconds = 600;
        fixture.artifact.metadata.emilia_gate_qualification_v2.expires_at = '2026-07-26T12:20:00Z';
        repinArtifact(fixture);
        refusal(fixture, 'evidence_expired');
    }
    {
        const fixture = makeFixture();
        fixture.artifact.metadata.emilia_gate_qualification_v2.completed_at = '2026-07-26T12:40:00Z';
        fixture.artifact.results.timestamp = '2026-07-26T12:40:00Z';
        repinArtifact(fixture);
        refusal(fixture, 'evidence_from_future');
    }
    {
        const fixture = makeFixture();
        fixture.artifact.metadata.emilia_gate_qualification_v2.started_at = '2026-07-26T12:11:00Z';
        repinArtifact(fixture);
        refusal(fixture, 'run_timestamp_order_invalid');
    }
});
test('rejects artifact, manifest, config, payload, and verifier digest mismatches', () => {
    {
        const fixture = makeFixture();
        fixture.artifact.results.results[0].response.output = 'tampered';
        refusal(fixture, 'artifact_digest_mismatch');
    }
    {
        const fixture = makeFixture();
        fixture.pins.candidate.manifest.provider_revision = 'different-revision';
        refusal(fixture, 'candidate_manifest_digest_mismatch');
    }
    {
        const fixture = makeFixture();
        fixture.artifact.config.description = 'mutated config';
        repinArtifact(fixture);
        refusal(fixture, 'harness_config_digest_mismatch');
    }
    {
        const fixture = makeFixture();
        fixture.artifact.results.results[0].metadata.emilia_gate_qualification_v2.request_payload_digest =
            digestPromptfooQualification({ wrong: true });
        repinArtifact(fixture);
        refusal(fixture, 'request_payload_digest_mismatch:attempt-1');
    }
    {
        const fixture = makeFixture();
        fixture.pins.verifier.trust_config.minimum_attempts = 4;
        refusal(fixture, 'verifier_trust_config_digest_mismatch');
    }
});
test('re-derives attempt and Promptfoo aggregate counts', () => {
    {
        const fixture = makeFixture();
        fixture.artifact.metadata.emilia_gate_qualification_v2.attempt_counts.failed = 0;
        repinArtifact(fixture);
        refusal(fixture, 'attempt_counts_mismatch');
    }
    {
        const fixture = makeFixture();
        fixture.artifact.results.stats.failures = 0;
        repinArtifact(fixture);
        refusal(fixture, 'promptfoo_stats_mismatch');
    }
    {
        const fixture = makeFixture();
        fixture.artifact.results.stats.tokenUsage.total = 35;
        repinArtifact(fixture);
        refusal(fixture, 'promptfoo_token_usage_mismatch');
    }
    {
        const fixture = makeFixture();
        fixture.artifact.results.stats.durationMs = 599_999;
        repinArtifact(fixture);
        refusal(fixture, 'promptfoo_duration_mismatch');
    }
});
test('rejects status laundering for failures, aborts, and expired cases', () => {
    for (const index of [1, 2, 3, 4]) {
        const fixture = makeFixture();
        fixture.artifact.results.results[index].success = true;
        repinArtifact(fixture);
        refusal(fixture, `attempt_status_inconsistent:attempt-${index + 1}`);
    }
    {
        const fixture = makeFixture();
        delete fixture.artifact.results.results[3].error;
        repinArtifact(fixture);
        refusal(fixture, 'attempt_status_inconsistent:attempt-4');
    }
    {
        const fixture = makeFixture();
        fixture.artifact.results.results[4].metadata.emilia_gate_qualification_v2.expired_at = null;
        repinArtifact(fixture);
        refusal(fixture, 'attempt_status_inconsistent:attempt-5');
    }
});
test('requires bounded costs, latency, quality metrics, and complete payload digests', () => {
    for (const [mutate, reason] of [
        [
            (fixture) => { delete fixture.artifact.results.results[0].cost; },
            'attempt_cost_invalid:attempt-1',
        ],
        [
            (fixture) => { fixture.artifact.results.results[0].latencyMs = -1; },
            'attempt_latency_invalid:attempt-1',
        ],
        [
            (fixture) => { fixture.artifact.results.results[0].score = 2; },
            'attempt_quality_invalid:attempt-1',
        ],
        [
            (fixture) => {
                delete fixture.artifact.results.results[0].namedScores.safety;
            },
            'attempt_quality_metrics_mismatch:attempt-1',
        ],
        [
            (fixture) => {
                fixture.artifact.results.results[0].metadata.emilia_gate_qualification_v2.response_payload_digest = null;
            },
            'response_payload_digest_mismatch:attempt-1',
        ],
        [
            (fixture) => {
                fixture.artifact.results.results[0].gradingResult.score = 0.5;
            },
            'grading_quality_mismatch:attempt-1',
        ],
        [
            (fixture) => {
                fixture.artifact.results.results[0].response.tokenUsage.total = 11;
            },
            'response_token_usage_mismatch:attempt-1',
        ],
    ]) {
        const fixture = makeFixture();
        mutate(fixture);
        repinArtifact(fixture);
        refusal(fixture, reason);
    }
});
test('binds every result to the pinned candidate, campaign, and eval identity', () => {
    {
        const fixture = makeFixture();
        fixture.artifact.results.results[0].provider.id = 'openai:gpt-4.1';
        const metadata = fixture.artifact.results.results[0].metadata.emilia_gate_qualification_v2;
        metadata.request_payload_digest = digestPromptfooQualification({
            prompt: fixture.artifact.results.results[0].prompt,
            vars: fixture.artifact.results.results[0].vars,
        });
        repinArtifact(fixture);
        refusal(fixture, 'candidate_provider_mismatch:attempt-1');
    }
    {
        const fixture = makeFixture();
        fixture.artifact.results.results[0].promptId = 'prompt:other';
        repinArtifact(fixture);
        refusal(fixture, 'candidate_prompt_mismatch:attempt-1');
    }
    {
        const fixture = makeFixture();
        fixture.artifact.results.results[0].evaluationId = 'eval-other';
        repinArtifact(fixture);
        refusal(fixture, 'result_eval_id_mismatch:attempt-1');
    }
    {
        const fixture = makeFixture();
        fixture.artifact.results.results[0].metadata.emilia_gate_qualification_v2.challenge_id = 'challenge-other';
        repinArtifact(fixture);
        refusal(fixture, 'attempt_manifest_mismatch:attempt-1');
    }
});
test('returns closed refusals instead of throwing on malformed untrusted input', () => {
    for (const value of [null, false, 7, 'artifact', [], {}]) {
        assert.doesNotThrow(() => {
            const result = adaptPromptfooQualificationArtifact({
                artifact: value,
                pins: value,
                now: NOW,
            });
            assert.equal(result.ok, false);
        });
    }
    const fixture = makeFixture();
    fixture.pins.candidate.manifest = null;
    fixture.pins.candidate.manifest_digest = digestPromptfooQualification(null);
    fixture.pins.candidate.immutable_ref = immutableRef('candidate', fixture.pins.candidate.id, fixture.pins.candidate.manifest_digest);
    assert.doesNotThrow(() => {
        refusal(fixture, 'candidate_manifest_invalid');
    });
});
test('fails closed on aggregate Promptfoo input byte, node, depth, and result-count limits', () => {
    {
        const fixture = makeFixture();
        fixture.artifact.config.description = 'x'.repeat(PROMPTFOO_QUALIFICATION_LIMITS.max_input_bytes);
        assert.deepEqual(adaptPromptfooQualificationArtifact({
            artifact: fixture.artifact,
            pins: fixture.pins,
            now: NOW,
        }), { ok: false, reasons: ['input_bytes_limit_exceeded'] });
    }
    {
        const fixture = makeFixture();
        fixture.pins.verifier.trust_config.aggregate = Array.from({ length: PROMPTFOO_QUALIFICATION_LIMITS.max_input_nodes }, () => null);
        assert.deepEqual(adaptPromptfooQualificationArtifact({
            artifact: fixture.artifact,
            pins: fixture.pins,
            now: NOW,
        }), { ok: false, reasons: ['input_nodes_limit_exceeded'] });
    }
    {
        const fixture = makeFixture();
        let deeplyNested = {};
        for (let depth = 0; depth <= PROMPTFOO_QUALIFICATION_LIMITS.max_input_depth; depth += 1) {
            deeplyNested = { child: deeplyNested };
        }
        fixture.artifact.config.deeplyNested = deeplyNested;
        assert.deepEqual(adaptPromptfooQualificationArtifact({
            artifact: fixture.artifact,
            pins: fixture.pins,
            now: NOW,
        }), { ok: false, reasons: ['input_depth_limit_exceeded'] });
        assert.throws(() => digestPromptfooQualification(deeplyNested), { name: 'TypeError', message: 'input_depth_limit_exceeded' });
    }
    {
        const fixture = makeFixture();
        fixture.artifact.results.results = new Array(PROMPTFOO_QUALIFICATION_LIMITS.max_summary_results + 1);
        assert.deepEqual(adaptPromptfooQualificationArtifact({
            artifact: fixture.artifact,
            pins: fixture.pins,
            now: NOW,
        }), { ok: false, reasons: ['summary_results_limit_exceeded'] });
    }
});
