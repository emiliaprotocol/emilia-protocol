// SPDX-License-Identifier: Apache-2.0
// Generated from gate-qualification.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto, {} from 'node:crypto';
import { AGENT_EVALUATION_EVIDENCE_PREDICATE, CANDIDATE_MANIFEST_VERSION, EVALUATION_CAMPAIGN_PREDICATE, GATE_QUALIFICATION_LIMITS, IN_TOTO_PAYLOAD_TYPE, IN_TOTO_STATEMENT_V1, QUALIFICATION_PROPERTY, QUALIFICATION_STATEMENT_PREDICATE, QUALIFICATION_STATUS_PAYLOAD_TYPE, QUALIFICATION_STATUS_VERSION, RUNTIME_CANDIDATE_MEASUREMENT_VERSION, RUNTIME_MEASUREMENT_PAYLOAD_TYPE, TEST_RESULT_PREDICATE, QUALIFICATION_DECISIONS, canonicalizeQualification, dsseSigningBytes, evaluateQualification, qualificationGraphDigest, qualificationMerkleParent, qualificationPayloadDigest, terminalOutcomesRoot, validateAgentEvaluationEvidence, validateCandidateManifest, validateEvaluationCampaign, validateQualificationStatement, validateQualificationStatus, validateRuntimeCandidateMeasurement, validateTestResultReference, } from './gate-qualification.js';
const NOW = '2026-07-26T12:00:00Z';
function d(label) {
    return `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
}
function descriptor(name, digest) {
    return { name, digest: { sha256: digest.slice('sha256:'.length) } };
}
function signer(keyid) {
    return { keyid, ...crypto.generateKeyPairSync('ed25519') };
}
const SIGNERS = {
    campaign: signer('key:campaign'),
    test_result: signer('key:test-result'),
    agent_evidence: signer('key:agent-evidence'),
    qualification_statement: signer('key:qualifier'),
    qualification_status: signer('key:status'),
    runtime_measurement: signer('key:runtime-measurement'),
};
function publicKey(value) {
    return value.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
}
function envelope(payload, value, payloadType = IN_TOTO_PAYLOAD_TYPE) {
    const bytes = Buffer.from(canonicalizeQualification(payload), 'utf8');
    return {
        payloadType,
        payload: bytes.toString('base64'),
        signatures: [{
                keyid: value.keyid,
                sig: crypto.sign(null, dsseSigningBytes(payloadType, bytes), value.privateKey).toString('base64'),
            }],
    };
}
function payload(value) {
    return JSON.parse(Buffer.from(value.payload, 'base64').toString('utf8'));
}
function resign(value, role, mutate, signing = SIGNERS[role]) {
    const body = structuredClone(payload(value));
    mutate(body);
    return envelope(body, signing, value.payloadType);
}
function trust(value) {
    return { keys: { [value.keyid]: publicKey(value) }, accepted_keyids: [value.keyid], threshold: 1 };
}
function nativeTestResult(manifestDigest, campaign, result, name) {
    return {
        _type: IN_TOTO_STATEMENT_V1,
        subject: [descriptor('candidate-manifest', manifestDigest)],
        predicateType: TEST_RESULT_PREDICATE,
        predicate: {
            result,
            configuration: [
                descriptor('environment', campaign.environment_digest),
                descriptor('evaluator-configuration', campaign.evaluator_configuration_digest),
                descriptor('harness', campaign.harness_digest),
            ],
            ...(result === 'PASSED' ? { passedTests: [name] } : { failedTests: [name] }),
        },
    };
}
function merkleData(commitments) {
    const left = qualificationMerkleParent(commitments[0], commitments[1]);
    const right = qualificationMerkleParent(commitments[2], commitments[3]);
    return {
        root: qualificationMerkleParent(left, right),
        proofs: [
            [{ side: 'RIGHT', digest: commitments[1] }, { side: 'RIGHT', digest: right }],
            [{ side: 'LEFT', digest: commitments[0] }, { side: 'RIGHT', digest: right }],
            [{ side: 'RIGHT', digest: commitments[3] }, { side: 'LEFT', digest: left }],
            [{ side: 'LEFT', digest: commitments[2] }, { side: 'LEFT', digest: left }],
        ],
    };
}
function makeFixture(challengeScheme = 'SALTED_SHA256_SET') {
    const staticCandidate = {
        code_digests: [d('code')],
        dependency_digests: [d('dependency')],
        prompt_template_digests: [d('prompt')],
        tool_definition_digests: [d('tool')],
        effective_permissions_digest: d('permissions'),
        model: {
            provider: 'example.ai',
            identity: 'model-1',
            version: '2026-07-01',
            artifact_digest: d('model-weights'),
            pinning_strength: 'IMMUTABLE_DIGEST',
        },
        retrieval_configuration_digest: d('retrieval-config'),
        builder_orchestrator_digest: d('builder'),
    };
    const manifest = { profile: CANDIDATE_MANIFEST_VERSION, candidate_id: 'candidate:checkout-agent:v2', static: staticCandidate };
    const manifestDigest = qualificationPayloadDigest(manifest);
    const assignmentDigest = d('assignment');
    const policyDigest = d('qualification-policy');
    const commitments = [d('hidden-0'), d('hidden-1'), d('hidden-2'), d('hidden-3')].sort();
    const merkle = merkleData(commitments);
    const campaignPredicate = {
        campaign_id: 'campaign:2026-07-26:001',
        candidate_manifest_digest: manifestDigest,
        assignment_digest: assignmentDigest,
        qualification_policy_digest: policyDigest,
        harness_digest: d('harness'),
        evaluator_configuration_digest: d('evaluator-config'),
        environment_digest: d('environment'),
        hidden_challenges: challengeScheme === 'SALTED_SHA256_SET'
            ? { scheme: challengeScheme, commitments }
            : { scheme: challengeScheme, root_digest: merkle.root, challenge_count: commitments.length },
        scenario_selection_commitment_digest: d('scenario-selection'),
        planned_batches: 1,
        maximum_batches: 2,
        attempt_ceiling: 2,
        not_before: '2026-07-26T10:00:00Z',
        not_after: '2026-07-26T11:00:00Z',
        predecessor_campaign_payload_digest: null,
    };
    const campaignStatement = {
        _type: IN_TOTO_STATEMENT_V1,
        subject: [descriptor('candidate-manifest', manifestDigest)],
        predicateType: EVALUATION_CAMPAIGN_PREDICATE,
        predicate: campaignPredicate,
    };
    const campaignEnvelope = envelope(campaignStatement, SIGNERS.campaign);
    const campaignDigest = qualificationPayloadDigest(campaignStatement);
    const passStatement = nativeTestResult(manifestDigest, campaignPredicate, 'PASSED', 'challenge-0');
    const failStatement = nativeTestResult(manifestDigest, campaignPredicate, 'FAILED', 'challenge-1');
    const passEnvelope = envelope(passStatement, SIGNERS.test_result);
    const failEnvelope = envelope(failStatement, SIGNERS.test_result);
    const resultDigests = [qualificationPayloadDigest(passStatement), qualificationPayloadDigest(failStatement)];
    const outcomes = ['PASS', 'FAIL', 'ABORTED', 'EXPIRED'];
    const terminal = outcomes.map((outcome, index) => ({
        batch: 1,
        challenge_index: index,
        attempt: 1,
        challenge_commitment: commitments[index],
        challenge_proof: challengeScheme === 'MERKLE_SHA256' ? merkle.proofs[index] : [],
        scenario_selection_commitment_digest: campaignPredicate.scenario_selection_commitment_digest,
        outcome,
        test_result_payload_digest: index < 2 ? resultDigests[index] : null,
        terminal_evidence_payload_digest: index < 2 ? resultDigests[index] : d(`terminal-${outcome}`),
        started_at: `2026-07-26T10:0${index}:00Z`,
        finished_at: `2026-07-26T10:0${index}:30Z`,
    }));
    const evidencePredicate = {
        campaign_payload_digest: campaignDigest,
        candidate_manifest_digest: manifestDigest,
        assignment_digest: assignmentDigest,
        qualification_policy_digest: policyDigest,
        completed_batches: 1,
        issued_challenges: terminal.length,
        terminal_outcomes: terminal,
        outcome_counts: { PASS: 1, FAIL: 1, ABORTED: 1, EXPIRED: 1 },
        terminal_outcomes_root: terminalOutcomesRoot(terminal),
        measurements: [
            { name: 'latency-p95', value: '740', unit: 'ms' },
            { name: 'policy-score', value: '0.98', unit: null },
        ],
        started_at: '2026-07-26T10:00:00Z',
        completed_at: '2026-07-26T10:10:00Z',
    };
    const evidenceStatement = {
        _type: IN_TOTO_STATEMENT_V1,
        subject: [descriptor('candidate-manifest', manifestDigest)],
        predicateType: AGENT_EVALUATION_EVIDENCE_PREDICATE,
        predicate: evidencePredicate,
    };
    const evidenceEnvelope = envelope(evidenceStatement, SIGNERS.agent_evidence);
    const evidenceDigest = qualificationPayloadDigest(evidenceStatement);
    const graphDigest = qualificationGraphDigest({
        campaign_payload_digests: [campaignDigest],
        test_result_payload_digests: [...resultDigests].sort(),
        agent_evaluation_evidence_payload_digests: [evidenceDigest],
    });
    const qualificationStatement = {
        _type: IN_TOTO_STATEMENT_V1,
        subject: [
            descriptor('candidate-manifest', manifestDigest),
            descriptor('evaluation-campaign', campaignDigest),
            descriptor('qualification-graph', graphDigest),
        ],
        predicateType: QUALIFICATION_STATEMENT_PREDICATE,
        predicate: {
            verifier: {
                id: 'https://qualifier.example/v2',
                policies: [descriptor('assignment', assignmentDigest), descriptor('qualification-policy', policyDigest)],
            },
            timeCreated: '2026-07-26T10:15:00Z',
            properties: [QUALIFICATION_PROPERTY],
        },
    };
    const qualificationEnvelope = envelope(qualificationStatement, SIGNERS.qualification_statement);
    const qualificationDigest = qualificationPayloadDigest(qualificationStatement);
    const status = {
        profile: QUALIFICATION_STATUS_VERSION,
        authority_id: 'authority:qualification:primary',
        qualification_statement_payload_digest: qualificationDigest,
        candidate_manifest_digest: manifestDigest,
        assignment_digest: assignmentDigest,
        qualification_policy_digest: policyDigest,
        status: 'QUALIFIED',
        sequence: 0,
        previous_status_payload_digest: null,
        issued_at: '2026-07-26T10:16:00Z',
        next_update: '2026-07-26T12:05:00Z',
        valid_until: '2026-07-27T00:00:00Z',
    };
    const statusEnvelope = envelope(status, SIGNERS.qualification_status, QUALIFICATION_STATUS_PAYLOAD_TYPE);
    const statusDigest = qualificationPayloadDigest(status);
    const runtime = {
        profile: RUNTIME_CANDIDATE_MEASUREMENT_VERSION,
        measurement_id: 'measurement:runtime:001',
        authority_id: 'authority:runtime-measurement:primary',
        measurement_mechanism_digest: d('runtime-measurement-mechanism'),
        candidate_manifest_digest: manifestDigest,
        assignment_digest: assignmentDigest,
        measured_at: '2026-07-26T11:59:30Z',
        candidate_influence_cutoff: '2026-07-26T11:59:45Z',
        remains_in_execution_path: true,
        static: structuredClone(staticCandidate),
        dynamic_retrieval_root: d('dynamic-retrieval'),
        memory_state_snapshot_digest: d('memory'),
        user_input_digest: d('user-input'),
        protected_request_digest: d('protected-request'),
    };
    const bundle = {
        candidate_manifest: manifest,
        campaigns: [campaignEnvelope],
        test_results: [passEnvelope, failEnvelope],
        agent_evaluation_evidence: [evidenceEnvelope],
        qualification_statement: qualificationEnvelope,
        qualification_status_chain: [statusEnvelope],
        qualification_status_observation: {
            authority_id: status.authority_id,
            head_payload_digest: statusDigest,
            sequence: 0,
            observed_at: '2026-07-26T11:59:50Z',
        },
        runtime_measurement: envelope(runtime, SIGNERS.runtime_measurement, RUNTIME_MEASUREMENT_PAYLOAD_TYPE),
    };
    const context = {
        now: NOW,
        expected_candidate_manifest_digest: manifestDigest,
        expected_assignment_digest: assignmentDigest,
        expected_qualification_policy_digest: policyDigest,
        expected_protected_request_digest: runtime.protected_request_digest,
        expected_runtime_measurement_authority_id: runtime.authority_id,
        expected_runtime_measurement_mechanism_digest: runtime.measurement_mechanism_digest,
        expected_status_authority_id: status.authority_id,
        minimum_status_sequence: 0,
        max_status_observation_age_seconds: 60,
        max_runtime_measurement_age_seconds: 60,
        minimum_model_pinning_strength: 'VERSION_PINNED',
        trust: {
            campaign: trust(SIGNERS.campaign),
            test_result: trust(SIGNERS.test_result),
            agent_evidence: trust(SIGNERS.agent_evidence),
            qualification_statement: trust(SIGNERS.qualification_statement),
            qualification_status: trust(SIGNERS.qualification_status),
            runtime_measurement: trust(SIGNERS.runtime_measurement),
        },
    };
    return {
        bundle,
        context,
        parts: {
            manifest,
            campaignPredicate,
            campaignEnvelope,
            evidenceEnvelope,
            qualificationEnvelope,
            statusEnvelope,
            runtime,
            commitments,
        },
    };
}
test('defines the frozen Gate Qualification v2 profiles and deterministic payload digest', () => {
    assert.equal(CANDIDATE_MANIFEST_VERSION, 'EP-CANDIDATE-MANIFEST-v1');
    assert.deepEqual(QUALIFICATION_DECISIONS, ['QUALIFIED', 'NOT_QUALIFIED', 'INDETERMINATE']);
    assert.equal(qualificationPayloadDigest({ b: 2, a: 1 }), qualificationPayloadDigest({ a: 1, b: 2 }));
    const symbolBearingPayload = { a: 1 };
    Object.defineProperty(symbolBearingPayload, Symbol.for('hidden_qualification'), {
        value: 'attacker-controlled',
        enumerable: true,
    });
    assert.throws(() => canonicalizeQualification(symbolBearingPayload), /strict canonical JSON domain/, 'qualification signatures must refuse members outside the canonical JSON domain');
    const rejected = [];
    const hidden = { visible: true };
    Object.defineProperty(hidden, 'hidden', { value: 'unsigned', enumerable: false });
    rejected.push(hidden);
    let getterCalls = 0;
    const accessor = {};
    Object.defineProperty(accessor, 'value', {
        enumerable: true,
        get() { getterCalls += 1; return 'unsigned'; },
    });
    rejected.push(accessor);
    const sparse = new Array(2);
    sparse[1] = 'value';
    rejected.push(sparse);
    const extraArrayMember = ['value'];
    Object.defineProperty(extraArrayMember, 'unsigned', { value: true, enumerable: true });
    rejected.push(extraArrayMember);
    const symbolArrayMember = ['value'];
    Object.defineProperty(symbolArrayMember, Symbol.for('unsigned'), { value: true, enumerable: true });
    rejected.push(symbolArrayMember);
    const cyclic = {};
    cyclic.self = cyclic;
    rejected.push(cyclic, new Map([['key', 'value']]), { omitted: undefined });
    for (const value of rejected) {
        assert.throws(() => canonicalizeQualification(value));
    }
    assert.equal(getterCalls, 0, 'qualification canonicalization must never execute an accessor');
});
test('qualifies a complete graph containing every terminal outcome without mutating inputs', () => {
    const fixture = makeFixture();
    const before = canonicalizeQualification({ bundle: fixture.bundle, context: fixture.context });
    const first = evaluateQualification(fixture.bundle, fixture.context);
    const second = evaluateQualification(fixture.bundle, fixture.context);
    assert.deepEqual(first, second);
    assert.equal(first.decision, 'QUALIFIED', first.reason);
    assert.equal(first.verification, 'VERIFIED');
    assert.equal(first.acceptance, 'ACCEPTED');
    assert.equal(first.candidate_match, 'EXACT_MATCH');
    assert.equal(first.assignment_scope, 'IN_SCOPE');
    assert.equal(first.currentness, 'CURRENT_AS_OBSERVED');
    assert.equal(first.campaign_graph, 'COMPLETE');
    assert.equal(first.remeasure_at_begin_invocation, true);
    assert.equal(first.payload_digests.protected_request_digest, fixture.context.expected_protected_request_digest);
    assert.ok(Object.values(first.checks).every(Boolean), JSON.stringify(first.checks));
    assert.equal(canonicalizeQualification({ bundle: fixture.bundle, context: fixture.context }), before);
});
test('accepts both salted-set and index-bound Merkle hidden challenge commitments and rejects a forged proof', () => {
    const salted = makeFixture('SALTED_SHA256_SET');
    assert.equal(evaluateQualification(salted.bundle, salted.context).decision, 'QUALIFIED');
    const merkle = makeFixture('MERKLE_SHA256');
    assert.equal(evaluateQualification(merkle.bundle, merkle.context).decision, 'QUALIFIED');
    merkle.bundle.agent_evaluation_evidence[0] = resign(merkle.bundle.agent_evaluation_evidence[0], 'agent_evidence', (body) => {
        body.predicate.terminal_outcomes[0].challenge_proof[0].digest = d('forged-sibling');
        body.predicate.terminal_outcomes_root = terminalOutcomesRoot(body.predicate.terminal_outcomes);
    });
    assert.equal(evaluateQualification(merkle.bundle, merkle.context).reason, 'hidden_challenge_commitment_mismatch');
});
test('derives Merkle proof direction and depth from challenge_index and rejects cross-index proof reuse', () => {
    const swapped = makeFixture('MERKLE_SHA256');
    swapped.bundle.agent_evaluation_evidence[0] = resign(swapped.bundle.agent_evaluation_evidence[0], 'agent_evidence', (body) => {
        const first = body.predicate.terminal_outcomes[0];
        const second = body.predicate.terminal_outcomes[1];
        [first.challenge_index, second.challenge_index] = [second.challenge_index, first.challenge_index];
        body.predicate.terminal_outcomes.sort((left, right) => left.challenge_index - right.challenge_index);
        body.predicate.terminal_outcomes_root = terminalOutcomesRoot(body.predicate.terminal_outcomes);
    });
    assert.equal(evaluateQualification(swapped.bundle, swapped.context).reason, 'hidden_challenge_commitment_mismatch');
    const reused = makeFixture('MERKLE_SHA256');
    reused.bundle.agent_evaluation_evidence[0] = resign(reused.bundle.agent_evaluation_evidence[0], 'agent_evidence', (body) => {
        body.predicate.terminal_outcomes[1].challenge_commitment =
            body.predicate.terminal_outcomes[0].challenge_commitment;
        body.predicate.terminal_outcomes[1].challenge_proof = structuredClone(body.predicate.terminal_outcomes[0].challenge_proof);
        body.predicate.terminal_outcomes_root = terminalOutcomesRoot(body.predicate.terminal_outcomes);
    });
    assert.equal(evaluateQualification(reused.bundle, reused.context).reason, 'duplicate_challenge_leaf_or_proof');
});
test('all accepted schemas are closed at every signed profile layer', () => {
    const fixture = makeFixture();
    const cases = [
        ['manifest', validateCandidateManifest, fixture.bundle.candidate_manifest],
        ['campaign', validateEvaluationCampaign, payload(fixture.bundle.campaigns[0])],
        ['test result', validateTestResultReference, payload(fixture.bundle.test_results[0])],
        ['agent evidence', validateAgentEvaluationEvidence, payload(fixture.bundle.agent_evaluation_evidence[0])],
        ['qualification', validateQualificationStatement, payload(fixture.bundle.qualification_statement)],
        ['status', validateQualificationStatus, payload(fixture.bundle.qualification_status_chain[0])],
        ['runtime', validateRuntimeCandidateMeasurement, payload(fixture.bundle.runtime_measurement)],
    ];
    for (const [name, validator, original] of cases) {
        assert.equal(validator(original).valid, true, name);
        const extra = structuredClone(original);
        extra.unrecognized = true;
        assert.equal(validator(extra).valid, false, `${name} accepted an unknown field`);
    }
    const nested = structuredClone(fixture.bundle.candidate_manifest);
    nested.static.model.unrecognized = true;
    assert.equal(validateCandidateManifest(nested).valid, false);
    const unsorted = structuredClone(fixture.bundle.candidate_manifest);
    unsorted.static.dependency_digests = [d('z'), d('a')].sort().reverse();
    assert.equal(validateCandidateManifest(unsorted).valid, false);
});
test('enforces canonical payload bytes and binds references to payload rather than envelope', () => {
    const fixture = makeFixture();
    const campaignBody = payload(fixture.parts.campaignEnvelope);
    const secondSigner = signer('key:campaign:rotated');
    const rewrapped = envelope(campaignBody, secondSigner);
    assert.equal(qualificationPayloadDigest(campaignBody), qualificationPayloadDigest(payload(rewrapped)));
    assert.notDeepEqual(rewrapped.signatures, fixture.parts.campaignEnvelope.signatures);
    fixture.context.trust.campaign.keys[secondSigner.keyid] = publicKey(secondSigner);
    fixture.context.trust.campaign.accepted_keyids = [secondSigner.keyid];
    fixture.bundle.campaigns[0] = rewrapped;
    assert.equal(evaluateQualification(fixture.bundle, fixture.context).decision, 'QUALIFIED');
    const nonCanonical = structuredClone(rewrapped);
    nonCanonical.payload = Buffer.from(JSON.stringify(campaignBody, null, 2), 'utf8').toString('base64');
    assert.equal(evaluateQualification({ ...fixture.bundle, campaigns: [nonCanonical] }, fixture.context).reason, 'non_canonical_payload');
});
test('separates native signature verification from relying-party trust acceptance', () => {
    const fixture = makeFixture();
    const alternate = signer('key:campaign:verified-only');
    fixture.bundle.campaigns[0] = envelope(payload(fixture.bundle.campaigns[0]), alternate);
    fixture.context.trust.campaign.keys[alternate.keyid] = publicKey(alternate);
    const unaccepted = evaluateQualification(fixture.bundle, fixture.context);
    assert.equal(unaccepted.verification, 'VERIFIED');
    assert.equal(unaccepted.acceptance, 'NOT_ACCEPTED');
    assert.equal(unaccepted.decision, 'NOT_QUALIFIED');
    assert.equal(unaccepted.reason, 'artifact_not_accepted');
    const invalid = makeFixture();
    const sig = invalid.bundle.campaigns[0].signatures[0].sig;
    invalid.bundle.campaigns[0].signatures[0].sig = `${sig[0] === 'A' ? 'B' : 'A'}${sig.slice(1)}`;
    const rejected = evaluateQualification(invalid.bundle, invalid.context);
    assert.equal(rejected.verification, 'NOT_VERIFIED');
    assert.equal(rejected.reason, 'invalid_artifact_signature');
});
test('signature thresholds count distinct public keys and reject aliases for duplicate key material', () => {
    const distinct = makeFixture();
    const secondSigner = signer('key:campaign:threshold-2');
    const distinctCampaign = distinct.bundle.campaigns[0];
    const distinctPayload = Buffer.from(distinctCampaign.payload, 'base64');
    distinctCampaign.signatures.push({
        keyid: secondSigner.keyid,
        sig: crypto.sign(null, dsseSigningBytes(distinctCampaign.payloadType, distinctPayload), secondSigner.privateKey).toString('base64'),
    });
    distinct.context.trust.campaign.keys[secondSigner.keyid] = publicKey(secondSigner);
    distinct.context.trust.campaign.accepted_keyids = [
        SIGNERS.campaign.keyid,
        secondSigner.keyid,
    ];
    distinct.context.trust.campaign.threshold = 2;
    assert.equal(evaluateQualification(distinct.bundle, distinct.context).decision, 'QUALIFIED');
    const pemEncoded = makeFixture();
    pemEncoded.context.trust.campaign.keys[SIGNERS.campaign.keyid] =
        SIGNERS.campaign.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    assert.equal(evaluateQualification(pemEncoded.bundle, pemEncoded.context).decision, 'QUALIFIED');
    const aliased = makeFixture();
    const aliasKeyid = 'key:campaign:alias';
    const aliasedCampaign = aliased.bundle.campaigns[0];
    const aliasedPayload = Buffer.from(aliasedCampaign.payload, 'base64');
    aliasedCampaign.signatures.push({
        keyid: aliasKeyid,
        sig: crypto.sign(null, dsseSigningBytes(aliasedCampaign.payloadType, aliasedPayload), SIGNERS.campaign.privateKey).toString('base64'),
    });
    aliased.context.trust.campaign.keys[aliasKeyid] = SIGNERS.campaign.publicKey
        .export({ type: 'spki', format: 'pem' })
        .toString();
    aliased.context.trust.campaign.accepted_keyids = [SIGNERS.campaign.keyid, aliasKeyid];
    aliased.context.trust.campaign.threshold = 2;
    const rejected = evaluateQualification(aliased.bundle, aliased.context);
    assert.equal(rejected.decision, 'INDETERMINATE');
    assert.equal(rejected.reason, 'invalid_evaluation_context');
});
test('requires an accepted DSSE runtime measurement bound to its authority and mechanism', () => {
    const raw = makeFixture();
    raw.bundle.runtime_measurement = structuredClone(raw.parts.runtime);
    assert.equal(evaluateQualification(raw.bundle, raw.context).reason, 'invalid_envelope');
    const tampered = makeFixture();
    const signature = tampered.bundle.runtime_measurement.signatures[0].sig;
    tampered.bundle.runtime_measurement.signatures[0].sig =
        `${signature[0] === 'A' ? 'B' : 'A'}${signature.slice(1)}`;
    assert.equal(evaluateQualification(tampered.bundle, tampered.context).reason, 'invalid_artifact_signature');
    const unaccepted = makeFixture();
    const alternate = signer('key:runtime-measurement:verified-only');
    unaccepted.bundle.runtime_measurement = envelope(payload(unaccepted.bundle.runtime_measurement), alternate, RUNTIME_MEASUREMENT_PAYLOAD_TYPE);
    unaccepted.context.trust.runtime_measurement.keys[alternate.keyid] = publicKey(alternate);
    const rejected = evaluateQualification(unaccepted.bundle, unaccepted.context);
    assert.equal(rejected.verification, 'VERIFIED');
    assert.equal(rejected.acceptance, 'NOT_ACCEPTED');
    assert.equal(rejected.reason, 'artifact_not_accepted');
    const authority = makeFixture();
    authority.bundle.runtime_measurement = resign(authority.bundle.runtime_measurement, 'runtime_measurement', (body) => { body.authority_id = 'authority:runtime-measurement:other'; });
    assert.equal(evaluateQualification(authority.bundle, authority.context).reason, 'runtime_measurement_authority_mismatch');
    const mechanism = makeFixture();
    mechanism.bundle.runtime_measurement = resign(mechanism.bundle.runtime_measurement, 'runtime_measurement', (body) => { body.measurement_mechanism_digest = d('substituted-mechanism'); });
    assert.equal(evaluateQualification(mechanism.bundle, mechanism.context).reason, 'runtime_measurement_mechanism_mismatch');
});
test('fails closed for every static candidate substitution and weak model identity', () => {
    const substitutions = [
        ['code', (runtime) => { runtime.static.code_digests = [d('substituted-code')]; }],
        ['dependency', (runtime) => { runtime.static.dependency_digests = [d('substituted-dependency')]; }],
        ['prompt', (runtime) => { runtime.static.prompt_template_digests = [d('substituted-prompt')]; }],
        ['tool', (runtime) => { runtime.static.tool_definition_digests = [d('substituted-tool')]; }],
        ['permissions', (runtime) => { runtime.static.effective_permissions_digest = d('substituted-permissions'); }],
        ['model', (runtime) => { runtime.static.model.identity = 'mutable-latest'; }],
        ['retrieval', (runtime) => { runtime.static.retrieval_configuration_digest = d('substituted-retrieval'); }],
        ['builder', (runtime) => { runtime.static.builder_orchestrator_digest = d('substituted-builder'); }],
    ];
    for (const [name, mutate] of substitutions) {
        const fixture = makeFixture();
        fixture.bundle.runtime_measurement = resign(fixture.bundle.runtime_measurement, 'runtime_measurement', mutate);
        const result = evaluateQualification(fixture.bundle, fixture.context);
        assert.equal(result.candidate_match, 'MISMATCH', name);
        assert.equal(result.decision, 'NOT_QUALIFIED', name);
    }
    const weak = makeFixture();
    weak.bundle.candidate_manifest.static.model.pinning_strength = 'MUTABLE_ALIAS';
    weak.bundle.candidate_manifest.static.model.artifact_digest = null;
    weak.context.expected_candidate_manifest_digest = qualificationPayloadDigest(weak.bundle.candidate_manifest);
    weak.bundle.runtime_measurement = resign(weak.bundle.runtime_measurement, 'runtime_measurement', (body) => {
        body.static.model.pinning_strength = 'MUTABLE_ALIAS';
        body.static.model.artifact_digest = null;
        body.candidate_manifest_digest = weak.context.expected_candidate_manifest_digest;
    });
    assert.equal(evaluateQualification(weak.bundle, weak.context).candidate_match, 'UNPINNABLE');
});
test('refuses cross-assignment and protected-request reuse before qualification can travel', () => {
    const assignment = makeFixture();
    assignment.bundle.runtime_measurement = resign(assignment.bundle.runtime_measurement, 'runtime_measurement', (body) => { body.assignment_digest = d('other-assignment'); });
    const out = evaluateQualification(assignment.bundle, assignment.context);
    assert.equal(out.assignment_scope, 'OUT_OF_SCOPE');
    assert.equal(out.reason, 'runtime_assignment_out_of_scope');
    const request = makeFixture();
    request.bundle.runtime_measurement = resign(request.bundle.runtime_measurement, 'runtime_measurement', (body) => { body.protected_request_digest = d('other-request'); });
    assert.equal(evaluateQualification(request.bundle, request.context).reason, 'protected_request_digest_mismatch');
    const campaign = makeFixture();
    campaign.bundle.campaigns[0] = resign(campaign.bundle.campaigns[0], 'campaign', (body) => {
        body.predicate.assignment_digest = d('other-assignment');
    });
    assert.equal(evaluateQualification(campaign.bundle, campaign.context).reason, 'campaign_binding_mismatch');
});
test('binds each decision to the exact protected request and rejects replay across valid requests', () => {
    const firstRequest = makeFixture();
    const firstDecision = evaluateQualification(firstRequest.bundle, firstRequest.context);
    assert.equal(firstDecision.decision, 'QUALIFIED', firstDecision.reason);
    assert.equal(firstDecision.payload_digests.protected_request_digest, firstRequest.context.expected_protected_request_digest);
    const secondRequestDigest = d('protected-request-2');
    const secondRequest = makeFixture();
    secondRequest.context.expected_protected_request_digest = secondRequestDigest;
    secondRequest.bundle.runtime_measurement = resign(secondRequest.bundle.runtime_measurement, 'runtime_measurement', (body) => { body.protected_request_digest = secondRequestDigest; });
    const secondDecision = evaluateQualification(secondRequest.bundle, secondRequest.context);
    assert.equal(secondDecision.decision, 'QUALIFIED', secondDecision.reason);
    assert.equal(secondDecision.payload_digests.protected_request_digest, secondRequestDigest);
    assert.notEqual(firstDecision.payload_digests.protected_request_digest, secondDecision.payload_digests.protected_request_digest);
    const replayed = evaluateQualification(firstRequest.bundle, secondRequest.context);
    assert.equal(replayed.decision, 'NOT_QUALIFIED');
    assert.equal(replayed.reason, 'protected_request_digest_mismatch');
    assert.equal(replayed.payload_digests.protected_request_digest, firstRequest.context.expected_protected_request_digest);
});
test('requires every issued challenge and every retry to terminate without gaps or selective discards', () => {
    const omitted = makeFixture();
    omitted.bundle.agent_evaluation_evidence[0] = resign(omitted.bundle.agent_evaluation_evidence[0], 'agent_evidence', (body) => {
        body.predicate.terminal_outcomes.pop();
        body.predicate.issued_challenges = 3;
        body.predicate.outcome_counts.EXPIRED = 0;
        body.predicate.terminal_outcomes_root = terminalOutcomesRoot(body.predicate.terminal_outcomes);
    });
    assert.equal(evaluateQualification(omitted.bundle, omitted.context).reason, 'omitted_terminal_outcome');
    const discarded = makeFixture();
    discarded.bundle.agent_evaluation_evidence[0] = resign(discarded.bundle.agent_evaluation_evidence[0], 'agent_evidence', (body) => {
        body.predicate.terminal_outcomes[0].attempt = 2;
        body.predicate.terminal_outcomes_root = terminalOutcomesRoot(body.predicate.terminal_outcomes);
    });
    assert.equal(evaluateQualification(discarded.bundle, discarded.context).reason, 'non_contiguous_challenge_attempts');
    const counts = makeFixture();
    counts.bundle.agent_evaluation_evidence[0] = resign(counts.bundle.agent_evaluation_evidence[0], 'agent_evidence', (body) => {
        body.predicate.outcome_counts.PASS = 2;
    });
    assert.equal(evaluateQualification(counts.bundle, counts.context).reason, 'invalid_campaign_closure');
});
test('rejects challenge grinding, excessive attempts, duplicate references, and unreferenced native results', () => {
    const grinding = makeFixture();
    grinding.bundle.agent_evaluation_evidence[0] = resign(grinding.bundle.agent_evaluation_evidence[0], 'agent_evidence', (body) => {
        body.predicate.terminal_outcomes[0].challenge_commitment = d('uncommitted-hidden-test');
        body.predicate.terminal_outcomes_root = terminalOutcomesRoot(body.predicate.terminal_outcomes);
    });
    assert.equal(evaluateQualification(grinding.bundle, grinding.context).reason, 'hidden_challenge_commitment_mismatch');
    const ceiling = makeFixture();
    ceiling.bundle.agent_evaluation_evidence[0] = resign(ceiling.bundle.agent_evaluation_evidence[0], 'agent_evidence', (body) => {
        body.predicate.terminal_outcomes[0].attempt = 3;
        body.predicate.terminal_outcomes_root = terminalOutcomesRoot(body.predicate.terminal_outcomes);
    });
    assert.equal(evaluateQualification(ceiling.bundle, ceiling.context).reason, 'hidden_challenge_commitment_mismatch');
    const extra = makeFixture();
    extra.bundle.test_results.push(resign(extra.bundle.test_results[0], 'test_result', (body) => {
        body.predicate.passedTests = ['unreferenced'];
    }));
    assert.equal(evaluateQualification(extra.bundle, extra.context).reason, 'unreferenced_test_result');
});
function replaceStatus(fixture, mutate) {
    fixture.bundle.qualification_status_chain[0] = resign(fixture.bundle.qualification_status_chain[0], 'qualification_status', mutate);
    const body = payload(fixture.bundle.qualification_status_chain[0]);
    fixture.bundle.qualification_status_observation.head_payload_digest = qualificationPayloadDigest(body);
}
test('fails closed on stale, revoked, suspended, expired, rolled-back, and equivocated status', () => {
    const stale = makeFixture();
    stale.bundle.qualification_status_observation.observed_at = '2026-07-26T11:00:00Z';
    assert.equal(evaluateQualification(stale.bundle, stale.context).currentness, 'STALE');
    for (const state of ['REVOKED', 'SUSPENDED', 'EXPIRED']) {
        const fixture = makeFixture();
        replaceStatus(fixture, (body) => { body.status = state; });
        const result = evaluateQualification(fixture.bundle, fixture.context);
        assert.equal(result.currentness, state === 'REVOKED' ? 'REVOKED' : state === 'SUSPENDED' ? 'SUSPENDED' : 'EXPIRED');
        assert.equal(result.decision, 'NOT_QUALIFIED');
    }
    const rollback = makeFixture();
    rollback.context.minimum_status_sequence = 1;
    assert.equal(evaluateQualification(rollback.bundle, rollback.context).reason, 'qualification_status_observation_mismatch');
    const equivocation = makeFixture();
    const fork = resign(equivocation.bundle.qualification_status_chain[0], 'qualification_status', (body) => { body.status = 'REVOKED'; });
    equivocation.bundle.qualification_status_chain.push(fork);
    equivocation.bundle.qualification_status_observation.head_payload_digest = qualificationPayloadDigest(payload(fork));
    const result = evaluateQualification(equivocation.bundle, equivocation.context);
    assert.equal(result.currentness, 'EQUIVOCATED');
    assert.equal(result.reason, 'qualification_status_equivocation');
});
test('enforces cardinality and payload-size controls', () => {
    const fixture = makeFixture();
    const oversizedManifest = structuredClone(fixture.bundle.candidate_manifest);
    oversizedManifest.static.dependency_digests = Array.from({ length: 1025 }, (_, index) => d(`dependency-${String(index).padStart(4, '0')}`)).sort();
    assert.equal(validateCandidateManifest(oversizedManifest).valid, false);
    const tooMany = makeFixture();
    tooMany.bundle.campaigns = Array.from({ length: GATE_QUALIFICATION_LIMITS.max_campaigns + 1 }, () => tooMany.parts.campaignEnvelope);
    assert.equal(evaluateQualification(tooMany.bundle, tooMany.context).reason, 'invalid_qualification_bundle');
    const oversized = makeFixture();
    oversized.bundle.campaigns[0] = {
        payloadType: IN_TOTO_PAYLOAD_TYPE,
        payload: Buffer.alloc(GATE_QUALIFICATION_LIMITS.max_payload_bytes + 1).toString('base64'),
        signatures: oversized.bundle.campaigns[0].signatures,
    };
    assert.equal(evaluateQualification(oversized.bundle, oversized.context).reason, 'invalid_envelope_payload');
});
test('malformed and hostile inputs return a deterministic closed refusal without throwing', () => {
    const fixture = makeFixture();
    for (const value of [null, [], {}, { ...fixture.bundle, campaigns: [] }]) {
        assert.doesNotThrow(() => evaluateQualification(value, fixture.context));
        assert.equal(evaluateQualification(value, fixture.context).decision, 'INDETERMINATE');
    }
    const hostile = new Proxy({}, { ownKeys() { throw new Error('trap'); } });
    assert.deepEqual(evaluateQualification(hostile, hostile), {
        ...evaluateQualification(null, fixture.context),
        reason: 'unexpected_verification_error',
    });
});
