// SPDX-License-Identifier: Apache-2.0
// Generated from execution-program-runtime-trace-replay.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';
import { ADMISSION_CURRENTNESS_VERSION, EXECUTION_PROGRAM_STATUS_VERSION, createAdmissionSnapshot, createExecutionProgramAdmissionBinding, createMemoryAdmissionStore, } from './admission-store.js';
import { executionProgramDigest, } from './bounded-execution-program.js';
const VECTOR_URL = new URL('../../conformance/vectors/bounded-execution-program.v1.json', import.meta.url);
const vectors = JSON.parse(fs.readFileSync(VECTOR_URL, 'utf8'));
const NOW = String(vectors.syntax.common.verification_context.now);
const DEFAULT_ADMISSION_EXPIRES_AT = '2026-07-29T20:45:00.000Z';
const EVIDENCE_EXPIRES_AT = '2026-07-29T21:30:00.000Z';
function digest(label) {
    return `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
}
function byteOrder(left, right) {
    return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}
function required(value, label) {
    assert.notEqual(value, undefined, `${label} is required by the runtime trace`);
    return value;
}
function ownerToken(index) {
    return `admission-owner:v2:${Buffer.alloc(32, index).toString('base64url')}`;
}
function invocationToken(index) {
    return `admission-invocation:v2:${Buffer.alloc(32, index).toString('base64url')}`;
}
function currentness(body, now) {
    return {
        '@version': ADMISSION_CURRENTNESS_VERSION,
        observed_at: new Date(now).toISOString(),
        qualification_status_authority_id: body.qualification_status.authority_id,
        qualification_status_sequence: body.qualification_status.sequence,
        qualification_status_head_digest: body.qualification_status.head_payload_digest,
        qualification_status_expires_at: body.qualification_status.expires_at,
        trust_epoch: body.trust_epoch,
        trust_configuration_digest: body.trust_configuration_digest,
        configuration_epoch: body.configuration_epoch,
        configuration_digest: body.configuration_digest,
        runtime_measurement_digest: body.runtime_measurement_digest,
        candidate_match: 'EXACT_MATCH',
        external_leases: [],
    };
}
function materializeAdmission(traceId, stepIndex, definition, abstract) {
    const sequence = stepIndex + 1;
    const unique = `${traceId}:${sequence}`;
    const admissionId = `admission:trace:${unique}`;
    const operationId = `operation:trace:${unique}`;
    const requestedExpiresAt = abstract.expires_at ?? DEFAULT_ADMISSION_EXPIRES_AT;
    const executionProgramResources = abstract.execution_program_resources ?? [];
    let expiresAt = requestedExpiresAt;
    if (abstract.admission_form === 'snapshot' && executionProgramResources.length > 0) {
        const earliestBindingDeadline = Math.min(...executionProgramResources.map((resource) => (Date.parse(resource.expires_at))));
        if (earliestBindingDeadline < Date.parse(requestedExpiresAt)) {
            // The language-neutral hostile vector can describe a binding deadline
            // that precedes its abstract admission deadline. A concrete
            // AdmissionSnapshot rejects that shape before the program runtime sees
            // it, so lower only the concrete snapshot deadline. The supplied
            // binding remains valid evidence and still mismatches the snapshot
            // deadline, preserving the transition the abstract trace is testing.
            const loweredDeadline = earliestBindingDeadline - 1;
            assert.ok(loweredDeadline > Date.parse(NOW), 'hostile binding deadline must remain live');
            expiresAt = new Date(loweredDeadline).toISOString();
        }
    }
    const validUntil = EVIDENCE_EXPIRES_AT;
    const candidateDigest = digest(`candidate:${unique}`);
    const runtimeDigest = digest(`runtime:${unique}`);
    const testResultDigest = digest(`test-result:${unique}`);
    const profileEvidence = abstract.sealed_evidence?.find((entry) => entry.role === 'aeb') ?? null;
    const agentEvidenceDigest = digest(`agent-evidence:${unique}`);
    const qualificationStatementDigest = digest(`qualification-statement:${unique}`);
    const qualificationStatusDigest = digest(`qualification-status:${unique}`);
    const authorizationDigest = (abstract.authorization_digest
        ?? definition.program.authorization_digest);
    const inputs = [
        {
            role: 'candidate_manifest', artifact_type: 'artifact.candidate_manifest',
            subject: abstract.subject_id ?? definition.program.subject_id,
            payload_digest: candidateDigest, profile_digest: digest('profile:candidate-manifest'),
            verifier_id: 'verifier:candidate-manifest',
            trust_configuration_digest: digest('trust-config:candidate-manifest'), valid_until: validUntil,
        },
        {
            role: 'runtime_measurement', artifact_type: 'artifact.runtime_measurement',
            subject: 'runtime:trace', payload_digest: runtimeDigest,
            profile_digest: digest('profile:runtime-measurement'), verifier_id: 'verifier:runtime-measurement',
            trust_configuration_digest: digest('trust-config:runtime-measurement'), valid_until: validUntil,
        },
        {
            role: 'test_result', artifact_type: 'artifact.test_result', subject: 'test:trace',
            payload_digest: testResultDigest, profile_digest: digest('profile:test-result'),
            verifier_id: 'verifier:test-result', trust_configuration_digest: digest('trust-config:test-result'),
            valid_until: validUntil,
        },
        {
            role: 'agent_evaluation_evidence', artifact_type: 'artifact.agent_evaluation_evidence',
            subject: 'agent:trace', payload_digest: agentEvidenceDigest,
            profile_digest: digest('profile:agent-evidence'),
            verifier_id: 'verifier:agent-evidence',
            trust_configuration_digest: digest('trust-config:agent-evidence'), valid_until: validUntil,
        },
        {
            role: 'qualification_statement', artifact_type: 'artifact.qualification_statement',
            subject: 'qualification:trace', payload_digest: qualificationStatementDigest,
            profile_digest: digest('profile:qualification-statement'),
            verifier_id: 'verifier:qualification-statement',
            trust_configuration_digest: digest('trust-config:qualification-statement'), valid_until: validUntil,
        },
        {
            role: 'qualification_status', artifact_type: 'artifact.qualification_status',
            subject: 'qualification-status:trace', payload_digest: qualificationStatusDigest,
            profile_digest: digest('profile:qualification-status'), verifier_id: 'verifier:qualification-status',
            trust_configuration_digest: digest('trust-config:qualification-status'), valid_until: validUntil,
        },
        {
            role: 'aeb', artifact_type: 'artifact.aeb',
            subject: profileEvidence?.subject_id ?? definition.program.subject_id,
            payload_digest: profileEvidence?.payload_digest ?? digest(`aeb:${unique}`),
            profile_digest: profileEvidence?.profile_digest ?? digest('profile:aeb'),
            verifier_id: profileEvidence?.verifier_id ?? 'verifier:aeb',
            trust_configuration_digest: profileEvidence?.trust_configuration_digest
                ?? digest('trust-config:aeb'),
            valid_until: validUntil,
        },
        {
            role: 'aec', artifact_type: 'artifact.aec', subject: 'aec:trace',
            payload_digest: digest(`aec:${unique}`), profile_digest: digest('profile:aec'),
            verifier_id: 'verifier:aec', trust_configuration_digest: digest('trust-config:aec'),
            valid_until: validUntil,
        },
        {
            role: 'local_policy', artifact_type: 'artifact.local_policy', subject: 'policy:trace',
            payload_digest: digest(`local-policy:${unique}`), profile_digest: digest('profile:local-policy'),
            verifier_id: 'verifier:local-policy', trust_configuration_digest: digest('trust-config:local-policy'),
            valid_until: validUntil,
        },
        {
            role: 'authorization', artifact_type: 'artifact.authorization', subject: 'authorization:trace',
            payload_digest: authorizationDigest, profile_digest: digest('profile:authorization'),
            verifier_id: 'verifier:authorization', trust_configuration_digest: digest('trust-config:authorization'),
            valid_until: validUntil,
        },
    ];
    const input = {
        tenant_id: abstract.tenant_id ?? definition.program.tenant_id,
        admission_id: admissionId,
        operation_id: operationId,
        candidate_manifest_digest: candidateDigest,
        runtime_measurement_digest: runtimeDigest,
        candidate_custody: {
            request_construction: 'GATE',
            mutation_credential_custody: 'GATE',
            enforcement_placement: 'ACTUATOR',
            evidence_digest: digest(`custody:${unique}`),
        },
        assignment_digest: digest(`assignment:${unique}`),
        qualification_policy_digest: digest(`qualification-policy:${unique}`),
        test_result_payload_digests: [testResultDigest],
        agent_evaluation_evidence_payload_digests: [agentEvidenceDigest],
        qualification_statement_payload_digest: qualificationStatementDigest,
        qualification_status: {
            authority_id: 'qualification-authority:trace', sequence,
            head_payload_digest: qualificationStatusDigest, observed_at: NOW, expires_at: validUntil,
        },
        caid: required(abstract.caid, 'admission.caid'),
        action_digest: required(abstract.action_digest, 'admission.action_digest'),
        effect_request_digest: digest(`effect-request:${unique}`),
        provider: {
            provider_id: 'provider:trace', account_id: 'account:trace', environment: 'production',
        },
        executor_adapter_digest: digest('executor-adapter:trace'),
        idempotency_key: `idempotency:${operationId}`,
        authorization_policy_digest: required(abstract.authorization_policy_digest, 'admission.authorization_policy_digest'),
        trust_epoch: abstract.trust_epoch ?? 1,
        trust_configuration_digest: abstract.trust_configuration_digest
            ?? digest('trust-configuration:trace'),
        configuration_epoch: 1,
        configuration_digest: digest('configuration:trace'),
        inputs,
        resource_reservations: [
            {
                kind: 'replay', resource_id: `receipt:${unique}`, reservation_id: `replay:${unique}`,
                digest: digest(`replay:${unique}`), expires_at: validUntil,
            },
            {
                kind: 'provider_operation', resource_id: operationId,
                reservation_id: `provider-operation:${unique}`,
                digest: digest(`provider-operation:${unique}`), expires_at: validUntil,
            },
            ...executionProgramResources,
        ],
        admitted_at: NOW,
        expires_at: expiresAt,
        supersedes_admission_id: null,
        remedy_for: null,
    };
    return {
        input,
        admission: abstract.admission_form === 'snapshot' ? createAdmissionSnapshot(input) : input,
    };
}
function materializeOrdinaryAdmission(traceId, stepIndex, operation) {
    const base = required(vectors.runtime.programs.base, 'runtime.programs.base');
    const exactNode = base.program.nodes.find((node) => node.action.mode === 'exact');
    assert.ok(exactNode?.action.mode === 'exact', 'base program requires an exact node');
    const materialized = materializeAdmission(traceId, stepIndex, base, {
        tenant_id: required(operation.tenant_id, 'ordinary_reserve.tenant_id'),
        authorization_digest: required(operation.authorization_digest, 'ordinary_reserve.authorization_digest'),
        subject_id: base.program.subject_id,
        caid: exactNode.action.caid,
        action_digest: exactNode.action.action_digest,
        authorization_policy_digest: exactNode.trust_program_digest,
    });
    return {
        ...materialized.input,
        admission_id: required(operation.admission_id, 'ordinary_reserve.admission_id'),
        operation_id: `operation:${required(operation.admission_id, 'ordinary_reserve.admission_id')}`,
        idempotency_key: `idempotency:${required(operation.admission_id, 'ordinary_reserve.admission_id')}`,
    };
}
function snapshotInput(snapshot) {
    const { '@version': _version, ...input } = snapshot.body;
    return input;
}
function expectedProfileActionMatch(definition, nodeId, admission) {
    const node = definition.program.nodes.find((candidate) => candidate.node_id === nodeId);
    const evidence = admission.sealed_evidence?.find((entry) => entry.role === 'aeb');
    if (node?.action.mode !== 'profile' || !evidence)
        return null;
    return {
        tenant_id: definition.program.tenant_id,
        profile_id: node.action.profile_id,
        profile_digest: node.action.profile_digest,
        subject_id: definition.program.subject_id,
        operation_id: required(admission.operation_id, 'admission.operation_id'),
        caid: required(admission.caid, 'admission.caid'),
        action_digest: required(admission.action_digest, 'admission.action_digest'),
        verifier_id: evidence.verifier_id,
        evidence_payload_digest: evidence.payload_digest,
        evidence_trust_configuration_digest: evidence.trust_configuration_digest,
        trust_epoch: required(admission.trust_epoch, 'admission.trust_epoch'),
        trust_configuration_digest: required(admission.trust_configuration_digest, 'admission.trust_configuration_digest'),
    };
}
function actionMatchPlan(definition, nodeId, admission) {
    if (admission.action_match_evidence === undefined || !admission.action_match_verification) {
        return null;
    }
    const expected = expectedProfileActionMatch(definition, nodeId, admission);
    if (!expected)
        return null;
    const overrides = {};
    for (const key of Object.keys(expected)) {
        if (admission.action_match_verification[key] !== expected[key]) {
            overrides[key] = admission.action_match_verification[key];
        }
    }
    return { evidence: structuredClone(admission.action_match_evidence), overrides };
}
function createTraceStore(trace) {
    let ownerIndex = 1;
    let invocationIndex = 1;
    let now = Date.parse(vectors.runtime.store_configurations[trace.store_configuration_ref].clock);
    let status = null;
    const generatedStatus = new Map();
    let matchPlan = null;
    const configuration = vectors.runtime.store_configurations[trace.store_configuration_ref];
    const options = {
        now: () => now,
        ownerTokenFactory: () => ownerToken(ownerIndex++),
        invocationTokenFactory: () => invocationToken(invocationIndex++),
        currentnessOracle: { read: async (snapshot) => currentness(snapshot.body, now) },
        executionProgramVerificationPolicy: configuration.execution_program_verification_policy,
        maxExecutionProgramStatusAgeMs: configuration.max_execution_program_status_age_ms,
        executionProgramActionMatchVerifier: {
            verify: async ({ evidence, expected }) => {
                if (!matchPlan)
                    return null;
                try {
                    assert.deepEqual(evidence, matchPlan.evidence);
                }
                catch {
                    return null;
                }
                return { valid: true, result: 'MATCH', ...expected, ...matchPlan.overrides };
            },
        },
    };
    if (configuration.status_oracle !== 'none') {
        options.executionProgramStatusOracle = {
            read: async (reference) => {
                if (status !== null)
                    return structuredClone(status);
                const previous = generatedStatus.get(reference.program_digest);
                const observedAt = new Date(now).toISOString();
                if (previous?.observed_at === observedAt)
                    return structuredClone(previous);
                const definition = Object.values(vectors.runtime.programs).find((entry) => entry.program_digest === reference.program_digest);
                if (!definition)
                    return null;
                const initial = now === Date.parse(configuration.clock);
                const next = {
                    '@version': EXECUTION_PROGRAM_STATUS_VERSION,
                    ...reference,
                    status: 'ACTIVE',
                    sequence: previous ? previous.sequence + 1 : 0,
                    observed_at: observedAt,
                    expires_at: initial
                        ? definition.program.expires_at
                        : new Date(now + 3_600_000).toISOString(),
                };
                generatedStatus.set(reference.program_digest, next);
                return structuredClone(next);
            },
        };
    }
    return {
        store: createMemoryAdmissionStore(options),
        now: () => now,
        setNow: (value) => { now = Date.parse(value); },
        setStatus: (value) => { status = structuredClone(value); },
        setActionMatchPlan: (value) => { matchPlan = value; },
    };
}
function projectResult(raw, expected, binding) {
    if (!raw.ok)
        return { ok: false, reason: required(raw.reason, 'runtime refusal reason') };
    if (Object.hasOwn(expected, 'execution_program_binding')) {
        return { ok: true, execution_program_binding: required(binding, 'execution program binding') };
    }
    return { ok: true };
}
function closedRegistrationContext(definition) {
    return {
        expected_program_id: definition.program.program_id,
        expected_tenant_id: definition.program.tenant_id,
        expected_authorization_digest: definition.program.authorization_digest,
        expected_audience: definition.program.audience,
    };
}
for (const trace of vectors.runtime.traces) {
    test(`runtime trace replay: ${trace.id} [${trace.classification}]`, async () => {
        const harness = createTraceStore(trace);
        const { store } = harness;
        const handles = new Map();
        const attemptedOccurrences = new Map();
        const attemptedOrdinaryAdmissions = new Map();
        const readOccurrence = async (operation) => {
            const programRef = required(operation.program_ref, `${operation.op}.program_ref`);
            const occurrenceId = required(operation.occurrence_id, `${operation.op}.occurrence_id`);
            const definition = required(vectors.runtime.programs[programRef], `runtime.programs.${programRef}`);
            const occurrence = await store.readExecutionProgramOccurrence({
                tenant_id: definition.program.tenant_id,
                program_digest: definition.program_digest,
                occurrence_id: occurrenceId,
            });
            if (!occurrence)
                return null;
            const record = await store.read({
                tenant_id: occurrence.tenant_id,
                admission_id: occurrence.admission_id,
            });
            assert.ok(record, `${programRef}/${occurrenceId}: admission record is missing`);
            const handle = handles.get(occurrence.admission_id);
            assert.ok(handle, `${programRef}/${occurrenceId}: admission handle is missing`);
            return { occurrence, record, handle };
        };
        const projectState = async (expected) => {
            const programs = [];
            const authorizationClaims = new Map();
            const indexedNodeCounts = new Map();
            for (const attempt of attemptedOccurrences.values()) {
                const definition = vectors.runtime.programs[attempt.programRef];
                const occurrence = await store.readExecutionProgramOccurrence({
                    tenant_id: definition.program.tenant_id,
                    program_digest: definition.program_digest,
                    occurrence_id: attempt.occurrenceId,
                });
                if (occurrence && occurrence.state !== 'RELEASED') {
                    const key = `${attempt.programRef}\0${occurrence.node_id}`;
                    indexedNodeCounts.set(key, (indexedNodeCounts.get(key) ?? 0) + 1);
                }
            }
            for (const programRef of Object.keys(vectors.runtime.programs).sort(byteOrder)) {
                const definition = vectors.runtime.programs[programRef];
                const state = await store.readExecutionProgram({
                    tenant_id: definition.program.tenant_id,
                    program_digest: definition.program_digest,
                });
                if (!state)
                    continue;
                programs.push({
                    program_ref: programRef,
                    status: state.status,
                    status_sequence: state.status_sequence,
                    total_occurrences: state.total_occurrences,
                    node_occurrence_counts: state.program.nodes
                        .map((node) => ({
                        node_id: node.node_id,
                        count: indexedNodeCounts.get(`${programRef}\0${node.node_id}`) ?? 0,
                    }))
                        .sort((left, right) => byteOrder(left.node_id, right.node_id)),
                    budgets: state.budgets
                        .map((budget) => ({
                        budget_id: budget.budget_id,
                        unit: budget.unit,
                        limit: budget.limit,
                        reserved: budget.reserved,
                        consumed: budget.consumed,
                    }))
                        .sort((left, right) => byteOrder(left.budget_id, right.budget_id)),
                });
                authorizationClaims.set(`${state.tenant_id}\0${state.program.authorization_digest}`, {
                    tenant_id: state.tenant_id,
                    authorization_digest: state.program.authorization_digest,
                    program_ref: programRef,
                });
            }
            const includeBinding = expected.occurrences.some((occurrence) => (Object.hasOwn(occurrence, 'admission_binding')));
            const occurrences = [];
            const occurrenceAttempts = [...attemptedOccurrences.values()].sort((left, right) => (byteOrder(`${left.programRef}\0${left.occurrenceId}`, `${right.programRef}\0${right.occurrenceId}`)));
            for (const attempt of occurrenceAttempts) {
                const definition = required(vectors.runtime.programs[attempt.programRef], `runtime.programs.${attempt.programRef}`);
                const occurrence = await store.readExecutionProgramOccurrence({
                    tenant_id: definition.program.tenant_id,
                    program_digest: definition.program_digest,
                    occurrence_id: attempt.occurrenceId,
                });
                if (!occurrence)
                    continue;
                const record = await store.read({
                    tenant_id: occurrence.tenant_id,
                    admission_id: occurrence.admission_id,
                });
                assert.ok(record, `${attempt.programRef}/${attempt.occurrenceId}: record is missing`);
                const projection = {
                    program_ref: attempt.programRef,
                    node_id: occurrence.node_id,
                    occurrence_id: occurrence.occurrence_id,
                    state: occurrence.state,
                    effect_relation: record.effect_relation?.value ?? null,
                };
                if (includeBinding) {
                    const snapshot = await store.readSnapshot(occurrence.snapshot_digest);
                    assert.ok(snapshot, `${attempt.programRef}/${attempt.occurrenceId}: snapshot is missing`);
                    const bindings = snapshot.body.resource_reservations.filter((resource) => resource.kind === 'execution_program');
                    assert.equal(bindings.length, 1, `${attempt.programRef}/${attempt.occurrenceId}: binding count`);
                    projection.admission_binding = bindings[0];
                }
                occurrences.push(projection);
            }
            const projected = { programs, occurrences };
            if (Object.hasOwn(expected, 'authorization_claims')) {
                projected.authorization_claims = [...authorizationClaims.entries()]
                    .sort(([left], [right]) => byteOrder(left, right))
                    .map(([, claim]) => claim);
            }
            if (Object.hasOwn(expected, 'ordinary_admissions')) {
                const ordinaryAdmissions = [];
                for (const [admissionId, attempted] of [...attemptedOrdinaryAdmissions.entries()]
                    .sort(([left], [right]) => byteOrder(left, right))) {
                    const record = await store.read({ tenant_id: attempted.tenantId, admission_id: admissionId });
                    if (!record)
                        continue;
                    ordinaryAdmissions.push({
                        admission_id: admissionId,
                        tenant_id: attempted.tenantId,
                        authorization_digest: attempted.authorizationDigest,
                        execution_right: record.execution_right,
                    });
                }
                projected.ordinary_admissions = ordinaryAdmissions;
            }
            return projected;
        };
        const execute = async (operation, stepIndex) => {
            if (operation.op === 'set_store_clock') {
                harness.setNow(required(operation.now, 'set_store_clock.now'));
                return { raw: { ok: true } };
            }
            if (operation.op === 'set_status_observation') {
                harness.setStatus(required(operation.observation, 'set_status_observation.observation'));
                return { raw: { ok: true } };
            }
            if (operation.op === 'register') {
                const programRef = required(operation.program_ref, 'register.program_ref');
                const definition = required(vectors.runtime.programs[programRef], `runtime.programs.${programRef}`);
                const artifact = required(vectors.syntax.fixtures[programRef], `syntax.fixtures.${programRef}`);
                assert.equal(executionProgramDigest(artifact), definition.program_digest, `${programRef}: signed fixture does not match runtime program_digest`);
                assert.deepEqual(operation.context, closedRegistrationContext(definition));
                return {
                    raw: await store.registerExecutionProgram(artifact, closedRegistrationContext(definition)),
                };
            }
            if (operation.op === 'reserve') {
                const programRef = required(operation.program_ref, 'reserve.program_ref');
                const occurrenceId = required(operation.occurrence_id, 'reserve.occurrence_id');
                const nodeId = required(operation.node_id, 'reserve.node_id');
                const definition = required(vectors.runtime.programs[programRef], `runtime.programs.${programRef}`);
                const abstractAdmission = required(operation.admission, 'reserve.admission');
                attemptedOccurrences.set(`${programRef}\0${occurrenceId}`, { programRef, occurrenceId });
                const materialized = materializeAdmission(trace.id, stepIndex, definition, abstractAdmission);
                harness.setActionMatchPlan(actionMatchPlan(definition, nodeId, abstractAdmission));
                const raw = await store.reserveExecutionProgramAdmission({
                    program_digest: definition.program_digest,
                    node_id: nodeId,
                    occurrence_id: occurrenceId,
                    admission: materialized.admission,
                    action_match: abstractAdmission.action_match,
                    action_match_evidence: abstractAdmission.action_match_evidence,
                }).finally(() => harness.setActionMatchPlan(null));
                if (!raw.ok)
                    return { raw };
                handles.set(raw.snapshot.body.admission_id, { ownerToken: raw.owner_token });
                const binding = createExecutionProgramAdmissionBinding({
                    tenant_id: materialized.input.tenant_id,
                    program_digest: definition.program_digest,
                    node_id: nodeId,
                    occurrence_id: occurrenceId,
                    expires_at: materialized.input.expires_at,
                });
                const actualBindings = raw.snapshot.body.resource_reservations.filter((resource) => resource.kind === 'execution_program');
                assert.deepEqual(actualBindings, [binding], `${trace.id} step ${stepIndex + 1}: binding drift`);
                const existingBindings = materialized.input.resource_reservations.filter((resource) => resource.kind === 'execution_program');
                const expectedSnapshot = createAdmissionSnapshot({
                    ...materialized.input,
                    resource_reservations: existingBindings.length === 0
                        ? [...materialized.input.resource_reservations, binding]
                        : materialized.input.resource_reservations,
                });
                assert.deepEqual(raw.snapshot, expectedSnapshot, `${trace.id} step ${stepIndex + 1}: deterministic snapshot/program binding drift`);
                assert.deepEqual(createAdmissionSnapshot(snapshotInput(raw.snapshot)), raw.snapshot, `${trace.id} step ${stepIndex + 1}: snapshot digest is not reproducible`);
                return { raw, binding };
            }
            if (operation.op === 'ordinary_reserve') {
                const input = materializeOrdinaryAdmission(trace.id, stepIndex, operation);
                attemptedOrdinaryAdmissions.set(input.admission_id, {
                    tenantId: input.tenant_id,
                    authorizationDigest: required(operation.authorization_digest, 'ordinary_reserve.authorization_digest'),
                });
                const raw = await store.reserve(input);
                if (raw.ok)
                    handles.set(input.admission_id, { ownerToken: raw.owner_token });
                return { raw };
            }
            if (operation.op === 'ordinary_release') {
                const admissionId = required(operation.admission_id, 'ordinary_release.admission_id');
                const attempted = attemptedOrdinaryAdmissions.get(admissionId);
                if (!attempted)
                    return { raw: { ok: false, reason: 'admission_not_found' } };
                const handle = handles.get(admissionId);
                const record = await store.read({ tenant_id: attempted.tenantId, admission_id: admissionId });
                if (!handle || !record)
                    return { raw: { ok: false, reason: 'admission_not_found' } };
                return {
                    raw: await store.release({
                        tenant_id: attempted.tenantId,
                        admission_id: admissionId,
                        expected_revision: record.revision,
                        owner_token: handle.ownerToken,
                    }),
                };
            }
            if (operation.op === 'begin' || operation.op === 'ordinary_begin') {
                const selected = await readOccurrence(operation);
                if (!selected)
                    return { raw: { ok: false, reason: 'program_not_found' } };
                const cas = {
                    tenant_id: selected.occurrence.tenant_id,
                    admission_id: selected.occurrence.admission_id,
                    expected_revision: selected.record.revision,
                    owner_token: selected.handle.ownerToken,
                };
                const raw = operation.op === 'begin'
                    ? await store.beginExecutionProgramInvocation(cas)
                    : await store.beginInvocation(cas);
                if (raw.ok)
                    selected.handle.invocationToken = raw.invocation_token;
                return { raw };
            }
            if (operation.op === 'release') {
                const selected = await readOccurrence(operation);
                if (!selected)
                    return { raw: { ok: false, reason: 'program_not_found' } };
                return {
                    raw: await store.releaseExecutionProgramAdmission({
                        tenant_id: selected.occurrence.tenant_id,
                        admission_id: selected.occurrence.admission_id,
                        expected_revision: selected.record.revision,
                        owner_token: selected.handle.ownerToken,
                    }),
                };
            }
            if (operation.op === 'provider_outcome') {
                const selected = await readOccurrence(operation);
                if (!selected)
                    return { raw: { ok: false, reason: 'program_not_found' } };
                const outcome = required(operation.outcome, 'provider_outcome.outcome');
                return {
                    raw: await store.recordProviderOutcome({
                        tenant_id: selected.occurrence.tenant_id,
                        admission_id: selected.occurrence.admission_id,
                        expected_revision: selected.record.revision,
                        owner_token: selected.handle.ownerToken,
                        invocation_token: required(selected.handle.invocationToken, 'provider invocation token'),
                        value: outcome,
                        evidence_digest: outcome === 'INDETERMINATE'
                            ? null
                            : digest(`${trace.id}:${stepIndex + 1}:provider:${outcome}`),
                        observed_at: NOW,
                    }),
                };
            }
            if (operation.op === 'effect_relation') {
                const selected = await readOccurrence(operation);
                if (!selected)
                    return { raw: { ok: false, reason: 'program_not_found' } };
                const value = required(operation.value, 'effect_relation.value');
                return {
                    raw: await store.recordEffectRelation({
                        tenant_id: selected.occurrence.tenant_id,
                        admission_id: selected.occurrence.admission_id,
                        expected_revision: selected.record.revision,
                        owner_token: selected.handle.ownerToken,
                        invocation_token: required(selected.handle.invocationToken, 'effect invocation token'),
                        value,
                        evidence_digest: value === 'INDETERMINATE'
                            ? null
                            : digest(`${trace.id}:${stepIndex + 1}:effect:${value}`),
                        observed_at: NOW,
                    }),
                };
            }
            if (operation.op === 'supersede') {
                const successorRef = required(operation.successor_program_ref, 'supersede.successor_program_ref');
                const definition = required(vectors.runtime.programs[successorRef], `runtime.programs.${successorRef}`);
                const artifact = required(vectors.syntax.fixtures[successorRef], `syntax.fixtures.${successorRef}`);
                assert.equal(executionProgramDigest(artifact), definition.program_digest, `${successorRef}: signed fixture does not match runtime program_digest`);
                assert.deepEqual(operation.context, closedRegistrationContext(definition));
                return {
                    raw: await store.supersedeExecutionProgram(artifact, closedRegistrationContext(definition)),
                };
            }
            throw new Error(`unsupported runtime trace operation: ${operation.op}`);
        };
        for (let stepIndex = 0; stepIndex < trace.steps.length; stepIndex += 1) {
            const step = trace.steps[stepIndex];
            const executed = await execute(step.operation, stepIndex);
            const actual = {
                result: projectResult(executed.raw, step.expect.result, executed.binding),
                state: await projectState(step.expect.state),
            };
            assert.deepEqual(actual, { result: step.expect.result, state: step.expect.state }, `${trace.id} step ${stepIndex + 1} (${step.operation.op}): runtime refinement drift`);
            assert.deepEqual(await store.checkInvariants(), step.expect.store_invariants ?? { ok: true, violations: [] }, `${trace.id} step ${stepIndex + 1} (${step.operation.op}): store invariant drift`);
        }
    });
}
