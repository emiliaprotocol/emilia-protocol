// SPDX-License-Identifier: Apache-2.0
// Generated from gate-qualification-v2.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { describe, it } from 'node:test';
import { ADMISSION_CURRENTNESS_VERSION, createAdmissionSnapshot, createMemoryAdmissionStore, } from './admission-store.js';
import { GATE_QUALIFICATION_V2_VERSION, GateQualificationV2, composeQualificationDecisionV2, createMemoryInvocationAuthorityCustodyV2, } from './gate-qualification-v2.js';
const NOW = '2026-07-26T12:00:00.000Z';
const EXPIRES = '2026-07-26T12:10:00.000Z';
const INPUT_EXPIRES = '2026-07-26T12:15:00.000Z';
function d(label) {
    return `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
}
function caid(label = 'primary') {
    return `caid:1:payment.capture.1:jcs-sha256:${crypto.createHash('sha256').update(label).digest('base64url')}`;
}
function owner(index) {
    return `admission-owner:v2:${Buffer.alloc(32, index).toString('base64url')}`;
}
function invocationToken(index = 9) {
    return `admission-invocation:v2:${Buffer.alloc(32, index).toString('base64url')}`;
}
function admissionInput(role, payloadDigest) {
    return {
        role,
        artifact_type: `artifact.${role}`,
        subject: `subject:${role}`,
        payload_digest: payloadDigest,
        profile_digest: d(`profile:${role}`),
        verifier_id: `verifier:${role}`,
        trust_configuration_digest: d(`trust:${role}`),
        valid_until: INPUT_EXPIRES,
    };
}
function snapshotInput(overrides = {}) {
    const admissionId = overrides.admission_id ?? 'admission:001';
    const operationId = overrides.operation_id ?? 'operation:001';
    const candidateManifest = d('candidate-manifest');
    const runtimeMeasurement = d('runtime-measurement');
    const testResult = d('test-result');
    const agentEvidence = d('agent-evidence');
    const qualificationStatement = d('qualification-statement');
    const statusHead = d('qualification-status-head');
    const aebEvidence = d('aeb-evidence');
    const aecEvidence = d('aec-evidence');
    const localPolicyEvidence = d('local-policy-evidence');
    return {
        tenant_id: 'tenant:alpha',
        admission_id: admissionId,
        operation_id: operationId,
        candidate_manifest_digest: candidateManifest,
        runtime_measurement_digest: runtimeMeasurement,
        candidate_custody: {
            request_construction: 'EXECUTOR_ADAPTER',
            mutation_credential_custody: 'EXECUTOR_ADAPTER',
            enforcement_placement: 'ACTUATOR',
            evidence_digest: d('candidate-custody'),
        },
        assignment_digest: d('assignment'),
        qualification_policy_digest: d('qualification-policy'),
        test_result_payload_digests: [testResult],
        agent_evaluation_evidence_payload_digests: [agentEvidence],
        qualification_statement_payload_digest: qualificationStatement,
        qualification_status: {
            authority_id: 'qualification-authority:primary',
            sequence: 7,
            head_payload_digest: statusHead,
            observed_at: NOW,
            expires_at: INPUT_EXPIRES,
        },
        caid: caid(),
        action_digest: d('action'),
        effect_request_digest: d('effect-request'),
        provider: {
            provider_id: 'provider:stripe',
            account_id: 'account:merchant',
            environment: 'production',
        },
        executor_adapter_digest: d('executor-adapter'),
        idempotency_key: `idempotency:${operationId}`,
        authorization_policy_digest: d('authorization-policy'),
        trust_epoch: 4,
        trust_configuration_digest: d('trust-configuration'),
        configuration_epoch: 9,
        configuration_digest: d('configuration'),
        inputs: [
            admissionInput('candidate_manifest', candidateManifest),
            admissionInput('runtime_measurement', runtimeMeasurement),
            admissionInput('test_result', testResult),
            admissionInput('agent_evaluation_evidence', agentEvidence),
            admissionInput('qualification_statement', qualificationStatement),
            admissionInput('qualification_status', statusHead),
            admissionInput('aeb', aebEvidence),
            admissionInput('aec', aecEvidence),
            admissionInput('local_policy', localPolicyEvidence),
            admissionInput('authorization', d('authorization-evidence')),
        ],
        resource_reservations: [
            {
                kind: 'replay',
                resource_id: `receipt:${admissionId}`,
                reservation_id: `replay:${admissionId}`,
                digest: d(`replay:${admissionId}`),
                expires_at: INPUT_EXPIRES,
            },
            {
                kind: 'provider_operation',
                resource_id: operationId,
                reservation_id: `provider:${admissionId}`,
                digest: d(`provider:${operationId}`),
                expires_at: INPUT_EXPIRES,
            },
            {
                kind: 'external_lease',
                resource_id: `lease:${admissionId}`,
                reservation_id: `lease-reservation:${admissionId}`,
                digest: d(`lease:${admissionId}`),
                expires_at: INPUT_EXPIRES,
            },
        ],
        admitted_at: NOW,
        expires_at: EXPIRES,
        supersedes_admission_id: null,
        remedy_for: null,
        ...overrides,
    };
}
function snapshot(overrides = {}) {
    return createAdmissionSnapshot(snapshotInput(overrides));
}
const REQUIRED_CHECKS = [
    'schemas',
    'payload_signatures',
    'trust_accepted',
    'campaign_lineage',
    'terminal_outcomes_complete',
    'hidden_challenge_commitments',
    'qualification_statement_binding',
    'status_chain',
    'status_current_as_observed',
    'runtime_candidate_exact_match',
    'assignment_in_scope',
    'protected_request_bound',
];
function qualified(value, overrides = {}) {
    return {
        decision: 'QUALIFIED',
        reason: 'qualified',
        verification: 'VERIFIED',
        acceptance: 'ACCEPTED',
        candidate_match: 'EXACT_MATCH',
        assignment_scope: 'IN_SCOPE',
        currentness: 'CURRENT_AS_OBSERVED',
        campaign_graph: 'COMPLETE',
        remeasure_at_begin_invocation: true,
        checks: Object.fromEntries(REQUIRED_CHECKS.map((check) => [check, true])),
        payload_digests: {
            candidate_manifest: value.body.candidate_manifest_digest,
            campaign_head: d('campaign-head'),
            qualification_graph: d('qualification-graph'),
            qualification_statement: value.body.qualification_statement_payload_digest,
            qualification_status_head: value.body.qualification_status.head_payload_digest,
            runtime_measurement: value.body.runtime_measurement_digest,
            protected_request_digest: value.body.effect_request_digest,
        },
        ...overrides,
    };
}
function roleDigest(value, role) {
    const digest = value.body.inputs.find((entry) => entry.role === role)
        ?.payload_digest;
    assert.ok(digest);
    return digest;
}
function bundle(value, overrides = {}) {
    return {
        qualification: qualified(value, overrides.qualification),
        aeb: {
            decision: 'allow',
            requirementId: 'aeb:human-authorization-v1',
            evidenceDigest: roleDigest(value, 'aeb'),
            caid: value.body.caid,
            actionDigest: value.body.action_digest,
            ...overrides.aeb,
        },
        aec: {
            decision: 'allow',
            requirementId: 'aec:execution-continuity-v1',
            evidenceDigest: roleDigest(value, 'aec'),
            caid: value.body.caid,
            actionDigest: value.body.action_digest,
            ...overrides.aec,
        },
        localPolicy: {
            decision: 'allow',
            policyId: 'policy:payments-production-v1',
            evidenceDigest: roleDigest(value, 'local_policy'),
            caid: value.body.caid,
            actionDigest: value.body.action_digest,
            ...overrides.localPolicy,
        },
    };
}
function providerEvidence(value, outcome = 'COMMITTED', overrides = {}) {
    return {
        evidenceId: 'provider-evidence:001',
        evidenceDigest: d('provider-evidence'),
        tenantId: value.body.tenant_id,
        admissionId: value.body.admission_id,
        operationId: value.body.operation_id,
        snapshotDigest: value.snapshot_digest,
        caid: value.body.caid,
        actionDigest: value.body.action_digest,
        effectRequestDigest: value.body.effect_request_digest,
        provider: value.body.provider,
        executorAdapterDigest: value.body.executor_adapter_digest,
        idempotencyKey: value.body.idempotency_key,
        outcome,
        observedAt: NOW,
        ...overrides,
    };
}
function relation(value, evidence, observedRelation = 'OBSERVED_AS_REQUESTED') {
    return {
        relation: observedRelation,
        evidenceDigest: observedRelation === 'INDETERMINATE'
            ? null
            : d('effect-relation-evidence'),
        tenantId: value.body.tenant_id,
        admissionId: value.body.admission_id,
        operationId: value.body.operation_id,
        snapshotDigest: value.snapshot_digest,
        caid: value.body.caid,
        actionDigest: value.body.action_digest,
        providerEvidenceDigest: evidence.evidenceDigest,
        observedEffectDigest: observedRelation === 'INDETERMINATE'
            ? null
            : d('observed-effect'),
        observedAt: NOW,
    };
}
function matchingObservation(value) {
    return {
        '@version': ADMISSION_CURRENTNESS_VERSION,
        observed_at: NOW,
        qualification_status_authority_id: value.body.qualification_status.authority_id,
        qualification_status_sequence: value.body.qualification_status.sequence,
        qualification_status_head_digest: value.body.qualification_status.head_payload_digest,
        qualification_status_expires_at: value.body.qualification_status.expires_at,
        trust_epoch: value.body.trust_epoch,
        trust_configuration_digest: value.body.trust_configuration_digest,
        configuration_epoch: value.body.configuration_epoch,
        configuration_digest: value.body.configuration_digest,
        runtime_measurement_digest: value.body.runtime_measurement_digest,
        candidate_match: 'EXACT_MATCH',
        external_leases: value.body.resource_reservations
            .filter((resource) => resource.kind === 'external_lease')
            .map((resource) => ({
            resource_id: resource.resource_id,
            digest: resource.digest,
            expires_at: resource.expires_at,
        })),
    };
}
function memoryStore(value) {
    let ownerIndex = 0;
    let invocationIndex = 0;
    return createMemoryAdmissionStore({
        now: NOW,
        ownerTokenFactory: () => owner(++ownerIndex),
        invocationTokenFactory: () => invocationToken(++invocationIndex),
        currentnessOracle: {
            read: async (current) => matchingObservation(value ?? current),
        },
    });
}
function executionInput(value) {
    return { snapshot: value, qualification: bundle(value) };
}
function harness(options = {}) {
    const store = options.store ?? memoryStore();
    const counts = { invoke: 0, reconcile: 0 };
    const adapter = {
        custody: 'protected',
        credentialsExposed: false,
        async invoke(input) {
            counts.invoke += 1;
            if (options.invoke)
                return options.invoke(input);
            return providerEvidence(input.snapshot);
        },
        async reconcile(input) {
            counts.reconcile += 1;
            if (options.reconcile)
                return options.reconcile(input);
            return providerEvidence(input.snapshot, 'PROVEN_NOT_COMMITTED');
        },
    };
    const gate = new GateQualificationV2({
        mode: 'enforce',
        admissionStore: store,
        protectedAdapter: adapter,
        invocationRemeasurer: {
            source: 'authoritative',
            remeasure: options.remeasure ?? (async (value) => bundle(value)),
        },
        authorityCustody: options.authorityCustody
            ?? createMemoryInvocationAuthorityCustodyV2(),
        providerEvidenceVerifier: {
            async verify(raw, expected) {
                if (options.verify)
                    return options.verify(raw, expected);
                return { ok: true, evidence: raw };
            },
        },
        observedEffectRelator: {
            async relate(evidence, expected) {
                if (options.relate)
                    return options.relate(evidence, expected);
                return relation(expected, evidence, evidence.outcome === 'INDETERMINATE'
                    ? 'INDETERMINATE'
                    : evidence.outcome === 'PROVEN_NOT_COMMITTED'
                        ? 'DIVERGED'
                        : 'OBSERVED_AS_REQUESTED');
            },
        },
        adapterTimeoutMs: options.adapterTimeoutMs,
        testOnly: true,
    });
    return { gate, store, adapter, counts };
}
describe('Gate Qualification v2 pure composition', () => {
    it('consumes the real qualification verifier result and all structural legs', () => {
        const value = snapshot();
        const decision = composeQualificationDecisionV2(executionInput(value));
        assert.equal(decision.version, GATE_QUALIFICATION_V2_VERSION);
        assert.equal(decision.allow, true);
        assert.deepEqual(decision.reasons, []);
        assert.equal(decision.snapshotDigest, value.snapshot_digest);
        assert.equal(decision.effectKey, JSON.stringify([value.body.tenant_id, value.body.operation_id]));
        assert.equal(Object.isFrozen(decision), true);
        const denied = composeQualificationDecisionV2({
            snapshot: value,
            qualification: bundle(value, {
                qualification: {
                    decision: 'NOT_QUALIFIED',
                    reason: 'qualification_revoked',
                },
            }),
        });
        assert.equal(denied.allow, false);
        assert.ok(denied.reasons.includes('qualification_not_qualified:qualification_revoked'));
    });
    it('validates the immutable snapshot digest and every typed evidence binding', () => {
        const value = snapshot();
        const tampered = structuredClone(value);
        tampered.body.action_digest = d('attacker');
        const invalid = composeQualificationDecisionV2({
            snapshot: tampered,
            qualification: bundle(value),
        });
        assert.equal(invalid.allow, false);
        assert.ok(invalid.reasons.includes('admission_snapshot_invalid'));
        const qualificationMismatch = composeQualificationDecisionV2({
            snapshot: value,
            qualification: bundle(value, {
                qualification: {
                    payload_digests: {
                        ...qualified(value).payload_digests,
                        runtime_measurement: d('attacker-runtime'),
                    },
                },
            }),
        });
        assert.ok(qualificationMismatch.reasons.includes('qualification_runtime_measurement_binding_mismatch'));
        const requestB = snapshot({
            effect_request_digest: d('different-protected-request'),
        });
        const replayedRequestDecision = composeQualificationDecisionV2({
            snapshot: requestB,
            qualification: bundle(value),
        });
        assert.equal(replayedRequestDecision.allow, false);
        assert.ok(replayedRequestDecision.reasons.includes('qualification_protected_request_binding_mismatch'));
        const aebMismatch = composeQualificationDecisionV2({
            snapshot: value,
            qualification: bundle(value, {
                aeb: { evidenceDigest: d('attacker-aeb') },
            }),
        });
        assert.ok(aebMismatch.reasons.includes('aeb_snapshot_binding_mismatch'));
    });
    it('requires a new admission and operation for a remedy before store access', () => {
        const value = snapshot({
            remedy_for: {
                tenant_id: 'tenant:alpha',
                admission_id: 'admission:001',
                operation_id: 'operation:001',
                snapshot_digest: d('original-snapshot'),
            },
        });
        const decision = composeQualificationDecisionV2(executionInput(value));
        assert.equal(decision.allow, false);
        assert.ok(decision.reasons.includes('remedy_requires_new_admission'));
        assert.ok(decision.reasons.includes('remedy_requires_new_operation'));
    });
});
describe('Gate Qualification v2 custody orchestration', () => {
    it('runs shadow mode with no store, adapter, credentials, reserve, or invocation', async () => {
        let legacyCalls = 0;
        const gate = new GateQualificationV2({
            mode: 'shadow',
            legacyQualification: {
                async qualify() {
                    legacyCalls += 1;
                    return { allow: false, reasons: ['legacy_refusal'] };
                },
            },
        });
        const value = snapshot();
        const result = await gate.execute(executionInput(value));
        assert.equal(result.status, 'shadow');
        if (result.status !== 'shadow')
            assert.fail('expected shadow result');
        assert.equal(result.comparison.v2Allowed, true);
        assert.equal(result.comparison.legacyAllowed, false);
        assert.equal(legacyCalls, 1);
        assert.throws(() => new GateQualificationV2({
            mode: 'shadow',
            admissionStore: memoryStore(),
            protectedAdapter: {},
        }), /shadow mode accepts no AdmissionStore or protected adapter/);
    });
    it('requires the authoritative atomic/currentness/exclusive store contract and durability outside testOnly', () => {
        const store = memoryStore();
        const protectedAdapter = {
            custody: 'protected',
            credentialsExposed: false,
            async invoke() { return {}; },
            async reconcile() { return {}; },
        };
        const dependencies = {
            protectedAdapter,
            invocationRemeasurer: {
                source: 'authoritative',
                async remeasure(value) {
                    return bundle(value);
                },
            },
            authorityCustody: createMemoryInvocationAuthorityCustodyV2(),
            providerEvidenceVerifier: {
                async verify() {
                    return { ok: false, reason: 'unused' };
                },
            },
            observedEffectRelator: {
                async relate() {
                    throw new Error('unused');
                },
            },
        };
        assert.throws(() => new GateQualificationV2({
            mode: 'enforce', admissionStore: store, ...dependencies,
        }), /durable AdmissionStore/);
        const noCurrentness = {
            ...store,
            transactionalCurrentness: false,
        };
        assert.throws(() => new GateQualificationV2({
            mode: 'enforce',
            admissionStore: noCurrentness,
            ...dependencies,
            testOnly: true,
        }), /transactional-currentness/);
    });
    it('reserves then begins and invokes only from the immutable snapshot returned by begin', async () => {
        const value = snapshot();
        const callerSnapshot = structuredClone(value);
        const base = memoryStore(value);
        let begunSnapshot = null;
        const store = {
            ...base,
            async reserve(input) {
                const result = await base.reserve(input);
                callerSnapshot.body.provider.account_id =
                    'account:attacker';
                return result;
            },
            async beginInvocation(input) {
                const result = await base.beginInvocation(input);
                if (result.ok)
                    begunSnapshot = result.snapshot;
                return result;
            },
        };
        let adapterInput = null;
        const h = harness({
            store,
            async invoke(input) {
                adapterInput = input;
                assert.strictEqual(input.snapshot, begunSnapshot);
                assert.equal(input.snapshot.body.provider.account_id, 'account:merchant');
                assert.equal(Object.isFrozen(input.snapshot), true);
                assert.deepEqual(Object.keys(input).sort(), [
                    'invocationToken',
                    'snapshot',
                ]);
                return providerEvidence(input.snapshot);
            },
        });
        const result = await h.gate.execute({
            snapshot: callerSnapshot,
            qualification: bundle(value),
        });
        assert.equal(result.status, 'committed');
        assert.ok(adapterInput);
        assert.equal(h.counts.invoke, 1);
        const record = await base.read({
            tenant_id: value.body.tenant_id,
            admission_id: value.body.admission_id,
        });
        assert.equal(record?.state, 'COMMITTED');
    });
    it('refuses transactional currentness failure before provider entry', async () => {
        const value = snapshot();
        const stale = matchingObservation(value);
        stale.qualification_status_sequence += 1;
        const store = createMemoryAdmissionStore({
            now: NOW,
            ownerTokenFactory: () => owner(1),
            invocationTokenFactory: () => invocationToken(),
            currentnessOracle: { read: async () => stale },
        });
        const h = harness({ store });
        const result = await h.gate.execute(executionInput(value));
        assert.equal(result.status, 'refused');
        if (result.status !== 'refused')
            assert.fail('expected refusal');
        assert.equal(result.reason, 'currentness_refused');
        assert.equal(h.counts.invoke, 0);
    });
    it('rereads every authority leg immediately before begin and refuses changed evidence', async () => {
        const value = snapshot();
        let remeasureCalls = 0;
        const h = harness({
            store: memoryStore(value),
            async remeasure(current) {
                remeasureCalls += 1;
                return bundle(current, { aeb: { decision: 'deny' } });
            },
        });
        const result = await h.gate.execute(executionInput(value));
        assert.equal(result.status, 'refused');
        if (result.status !== 'refused')
            assert.fail('expected refusal');
        assert.equal(result.reason, 'aeb_denied');
        assert.equal(remeasureCalls, 1);
        assert.equal(h.counts.invoke, 0);
        const record = await h.store.read({
            tenant_id: value.body.tenant_id,
            admission_id: value.body.admission_id,
        });
        assert.equal(record?.state, 'RELEASED');
        assert.equal(record?.execution_right, 'RELEASED');
    });
    it('persists reconciliation authority across Gate process replacement', async () => {
        const value = snapshot();
        const store = memoryStore(value);
        const authorityCustody = createMemoryInvocationAuthorityCustodyV2();
        const first = harness({
            store,
            authorityCustody,
            async invoke() {
                throw new Error('process exited after provider entry');
            },
        });
        const initial = await first.gate.execute(executionInput(value));
        assert.equal(initial.status, 'reconciliation_required');
        const replacement = harness({
            store,
            authorityCustody,
            async reconcile(input) {
                return providerEvidence(input.snapshot, 'COMMITTED');
            },
        });
        const reconciled = await replacement.gate.reconcile({
            tenant_id: value.body.tenant_id,
            admission_id: value.body.admission_id,
        });
        assert.equal(reconciled.status, 'committed');
        assert.equal(replacement.counts.invoke, 0);
        assert.equal(replacement.counts.reconcile, 1);
    });
    it('authoritatively reads begin ambiguity, marks consumed state indeterminate, and never retries', async () => {
        const value = snapshot();
        const base = memoryStore(value);
        let beginCalls = 0;
        const store = {
            ...base,
            async beginInvocation(input) {
                beginCalls += 1;
                const result = await base.beginInvocation(input);
                if (result.ok)
                    throw new Error('ack lost after atomic begin');
                return result;
            },
        };
        const h = harness({ store });
        const first = await h.gate.execute(executionInput(value));
        const retry = await h.gate.execute(executionInput(value));
        assert.equal(first.status, 'reconciliation_required');
        assert.equal(retry.status, 'reconciliation_required');
        assert.equal(beginCalls, 1);
        assert.equal(h.counts.invoke, 0);
        const record = await base.read({
            tenant_id: value.body.tenant_id,
            admission_id: value.body.admission_id,
        });
        assert.equal(record?.state, 'INDETERMINATE');
        assert.equal(record?.execution_right, 'CONSUMED');
    });
    it('returns reconciliation_required when begin or its authoritative read is ambiguous', async () => {
        const value = snapshot();
        const base = memoryStore(value);
        const store = {
            ...base,
            async beginInvocation() {
                throw new Error('begin transport failure before acknowledgement');
            },
            async read() {
                throw new Error('authoritative read unavailable');
            },
        };
        const h = harness({ store });
        const result = await h.gate.execute(executionInput(value));
        assert.equal(result.status, 'reconciliation_required');
        if (result.status !== 'reconciliation_required') {
            assert.fail('expected reconciliation requirement');
        }
        assert.equal(result.reason, 'begin_invocation_read_ambiguous');
        assert.equal(h.counts.invoke, 0);
    });
    it('records COMMITTED and DIVERGED independently', async () => {
        const value = snapshot();
        const h = harness({
            async relate(evidence, expected) {
                return relation(expected, evidence, 'DIVERGED');
            },
        });
        const result = await h.gate.execute(executionInput(value));
        assert.equal(result.status, 'committed');
        if (result.status !== 'committed')
            assert.fail('expected committed result');
        assert.equal(result.relation.relation, 'DIVERGED');
        const record = await h.store.read({
            tenant_id: value.body.tenant_id,
            admission_id: value.body.admission_id,
        });
        assert.equal(record?.provider_outcome?.value, 'COMMITTED');
        assert.equal(record?.effect_relation?.value, 'DIVERGED');
    });
    it('preserves a verified provider outcome when effect relation verification crashes', async () => {
        const value = snapshot();
        const h = harness({
            async relate() {
                throw new Error('effect observer crashed');
            },
        });
        const result = await h.gate.execute(executionInput(value));
        assert.equal(result.status, 'reconciliation_required');
        const record = await h.store.read({
            tenant_id: value.body.tenant_id,
            admission_id: value.body.admission_id,
        });
        assert.equal(record?.provider_outcome?.value, 'COMMITTED');
        assert.equal(record?.effect_relation?.value, 'INDETERMINATE');
    });
    for (const failure of ['crash', 'timeout']) {
        it(`turns adapter ${failure} into INDETERMINATE and reconciles without retransmit`, async () => {
            const value = snapshot();
            let providerEffects = 0;
            const h = harness({
                adapterTimeoutMs: failure === 'timeout' ? 5 : 1_000,
                async invoke() {
                    providerEffects += 1;
                    if (failure === 'crash')
                        throw new Error('adapter crashed');
                    return new Promise(() => undefined);
                },
                async reconcile(input) {
                    return providerEvidence(input.snapshot, 'COMMITTED');
                },
            });
            const first = await h.gate.execute(executionInput(value));
            const retry = await h.gate.execute(executionInput(value));
            assert.equal(first.status, 'reconciliation_required');
            assert.equal(retry.status, 'reconciliation_required');
            assert.equal(providerEffects, 1);
            assert.equal(h.counts.invoke, 1);
            const indeterminate = await h.store.read({
                tenant_id: value.body.tenant_id,
                admission_id: value.body.admission_id,
            });
            assert.equal(indeterminate?.state, 'INDETERMINATE');
            assert.ok(indeterminate?.resources.every((resource) => resource.state === 'CONSUMED'));
            assert.deepEqual(await h.store.recordEffectRelation({
                tenant_id: value.body.tenant_id,
                admission_id: value.body.admission_id,
                expected_revision: indeterminate?.revision ?? -1,
                owner_token: owner(1),
                invocation_token: invocationToken(1),
                value: 'INDETERMINATE',
                evidence_digest: null,
                observed_at: NOW,
            }), { ok: false, reason: 'invocation_token_conflict' });
            const reconciled = await h.gate.reconcile({
                tenant_id: value.body.tenant_id,
                admission_id: value.body.admission_id,
            });
            assert.equal(reconciled.status, 'committed');
            assert.equal(h.counts.reconcile, 1);
            assert.equal(h.counts.invoke, 1);
        });
    }
    it('reconciles an unconfirmed provider-outcome write without invoking again', async () => {
        const value = snapshot();
        const base = memoryStore(value);
        let firstWrite = true;
        const store = {
            ...base,
            async recordProviderOutcome(input) {
                const result = await base.recordProviderOutcome(input);
                if (firstWrite && result.ok) {
                    firstWrite = false;
                    throw new Error('provider-outcome acknowledgement lost');
                }
                return result;
            },
        };
        const h = harness({
            store,
            async reconcile(input) {
                return providerEvidence(input.snapshot, 'COMMITTED');
            },
        });
        const first = await h.gate.execute(executionInput(value));
        assert.equal(first.status, 'reconciliation_required');
        assert.equal((await base.read({
            tenant_id: value.body.tenant_id,
            admission_id: value.body.admission_id,
        }))?.provider_outcome?.value, 'COMMITTED');
        const reconciled = await h.gate.reconcile({
            tenant_id: value.body.tenant_id,
            admission_id: value.body.admission_id,
        });
        assert.equal(reconciled.status, 'committed');
        assert.equal(h.counts.invoke, 1);
        assert.equal(h.counts.reconcile, 1);
    });
    it('keeps provider credentials inside the adapter boundary', async () => {
        const credential = 'sk_live_internal_only';
        const value = snapshot();
        const h = harness({
            async invoke(input) {
                assert.equal(credential, 'sk_live_internal_only');
                assert.equal(JSON.stringify(input).includes(credential), false);
                assert.equal(Object.hasOwn(input, 'credential'), false);
                assert.equal(Object.hasOwn(input.snapshot.body, 'prompt'), false);
                return providerEvidence(input.snapshot);
            },
        });
        assert.equal((await h.gate.execute(executionInput(value))).status, 'committed');
    });
    it('admits a remedy only as a fresh admission, operation, and CAID', async () => {
        const original = snapshot();
        const h = harness();
        assert.equal((await h.gate.execute(executionInput(original))).status, 'committed');
        const relationToOriginal = {
            tenant_id: original.body.tenant_id,
            admission_id: original.body.admission_id,
            operation_id: original.body.operation_id,
            snapshot_digest: original.snapshot_digest,
        };
        const sameCaid = snapshot({
            admission_id: 'admission:remedy-same-caid',
            operation_id: 'operation:remedy-same-caid',
            remedy_for: relationToOriginal,
        });
        const refused = await h.gate.execute(executionInput(sameCaid));
        assert.equal(refused.status, 'refused');
        if (refused.status !== 'refused')
            assert.fail('expected refusal');
        assert.equal(refused.reason, 'relation_conflict');
        const remedyInput = snapshotInput({
            admission_id: 'admission:remedy',
            operation_id: 'operation:remedy',
            caid: caid('remedy'),
            action_digest: d('remedy-action'),
            effect_request_digest: d('remedy-effect'),
            idempotency_key: 'idempotency:operation:remedy',
            remedy_for: relationToOriginal,
        });
        const remedy = createAdmissionSnapshot(remedyInput);
        const remedyResult = await h.gate.execute(executionInput(remedy));
        assert.equal(remedyResult.status, 'committed', JSON.stringify(remedyResult));
    });
});
