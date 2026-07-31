// SPDX-License-Identifier: Apache-2.0
// Generated from bounded-execution-report.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { EXECUTION_PROGRAM_REPORT_SNAPSHOT_VERSION, EXECUTION_PROGRAM_RUNTIME_VERSION, executionProgramReportSnapshotMarker, } from './admission-store.js';
import { executionProgramDigest, signBoundedExecutionProgram, verifyBoundedExecutionProgram, } from './bounded-execution-program.js';
import { BOUNDED_EXECUTION_REPORT_CLAIM_BOUNDARY, BOUNDED_EXECUTION_REPORT_OUTSIDE_PLAN_CLAIM, BOUNDED_EXECUTION_REPORT_VERSION, boundedExecutionOccurrenceInventoryDigest, boundedExecutionReportDigest, boundedExecutionRuntimeStateDigest, signBoundedExecutionReport, verifyBoundedExecutionReport, } from './bounded-execution-report.js';
import { signRiskBody } from './dist/reliance-risk-crypto.js';
import { canonicalize } from './execution-binding.js';
const D = (character) => `sha256:${character.repeat(64)}`;
const C = (character) => (`caid:1:devops.infrastructure-change.1:jcs-sha256:${character.repeat(43)}`);
const PROGRAM_NOW = '2026-07-29T20:00:00.000Z';
const REPORT_END = '2026-07-29T20:30:00.000Z';
const GENERATED_AT = '2026-07-29T20:35:00.000Z';
const REPORT_VECTOR_PATH = fileURLToPath(new URL('../../conformance/vectors/bounded-execution-report.v1.json', import.meta.url));
function keyMaterial(issuerId, keyId) {
    const pair = generateKeyPairSync('ed25519');
    return {
        pair,
        signer: { issuer_id: issuerId, key_id: keyId, private_key: pair.privateKey },
        trusted_keys: {
            [keyId]: {
                issuer_id: issuerId,
                public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
            },
        },
    };
}
function programInput() {
    return {
        program_id: 'program:production-remediation:01',
        tenant_id: 'tenant:example',
        version: 1,
        subject_id: 'agent:operations:01',
        audience: 'gate:production:01',
        objective_digest: D('1'),
        authorization_digest: D('2'),
        presentation_digest: D('3'),
        supersedes_program_digest: null,
        issued_at: '2026-07-29T19:55:00.000Z',
        valid_from: PROGRAM_NOW,
        expires_at: '2026-07-29T21:00:00.000Z',
        max_total_occurrences: 7,
        max_concurrent_effects: 2,
        budgets: [{ budget_id: 'attempts', unit: 'attempt', limit: 10 }],
        nodes: [
            {
                node_id: 'inspect',
                action: { mode: 'exact', caid: C('A'), action_digest: D('a') },
                trust_program_digest: D('4'),
                depends_on: [],
                max_occurrences: 3,
                charges: [{ budget_id: 'attempts', amount: 1 }],
            },
            {
                node_id: 'notify',
                action: { mode: 'exact', caid: C('D'), action_digest: D('d') },
                trust_program_digest: D('7'),
                depends_on: [{ node_id: 'verify', outcomes: ['COMMITTED'] }],
                max_occurrences: 1,
                charges: [{ budget_id: 'attempts', amount: 1 }],
            },
            {
                node_id: 'remediate',
                action: { mode: 'exact', caid: C('B'), action_digest: D('b') },
                trust_program_digest: D('5'),
                depends_on: [{ node_id: 'inspect', outcomes: ['COMMITTED'] }],
                max_occurrences: 2,
                charges: [{ budget_id: 'attempts', amount: 1 }],
            },
            {
                node_id: 'verify',
                action: { mode: 'exact', caid: C('C'), action_digest: D('c') },
                trust_program_digest: D('6'),
                depends_on: [{ node_id: 'remediate', outcomes: ['COMMITTED'] }],
                max_occurrences: 2,
                charges: [{ budget_id: 'attempts', amount: 1 }],
            },
        ],
    };
}
function occurrence(nodeId, occurrenceId, state, minute) {
    const timestamp = `2026-07-29T20:${String(minute).padStart(2, '0')}:00.000Z`;
    return {
        tenant_id: 'tenant:example',
        program_digest: D('0'),
        node_id: nodeId,
        occurrence_id: occurrenceId,
        admission_id: `admission:${occurrenceId}`,
        snapshot_digest: D(String((minute % 9) + 1)),
        state,
        charges: [{ budget_id: 'attempts', amount: 1 }],
        created_at: timestamp,
        updated_at: timestamp,
    };
}
function reportSnapshot(runtimeState, occurrences) {
    const ordered = [...occurrences].sort((left, right) => (Buffer.compare(Buffer.from(left.node_id), Buffer.from(right.node_id))
        || Buffer.compare(Buffer.from(left.occurrence_id), Buffer.from(right.occurrence_id))));
    const body = {
        '@version': EXECUTION_PROGRAM_REPORT_SNAPSHOT_VERSION,
        tenant_id: runtimeState.tenant_id,
        program_digest: runtimeState.program_digest,
        runtime_state: runtimeState,
        occurrences: ordered,
    };
    return {
        ...body,
        snapshot_marker: executionProgramReportSnapshotMarker(body),
    };
}
function harness() {
    const authorizer = keyMaterial('customer:example-security', 'key:customer-program-authorizer');
    const programArtifact = signBoundedExecutionProgram(programInput(), authorizer.signer);
    const programDigest = executionProgramDigest(programArtifact);
    const verifiedProgram = verifyBoundedExecutionProgram(programArtifact, {
        trusted_keys: authorizer.trusted_keys,
        now: PROGRAM_NOW,
        expected_program_id: programInput().program_id,
        expected_tenant_id: programInput().tenant_id,
        expected_authorizer_id: authorizer.signer.issuer_id,
        expected_authorization_digest: programInput().authorization_digest,
        expected_audience: programInput().audience,
    });
    assert.equal(verifiedProgram.accepted, true);
    assert.ok(verifiedProgram.program);
    assert.ok(verifiedProgram.authorizer_id);
    const runtimeState = {
        '@version': EXECUTION_PROGRAM_RUNTIME_VERSION,
        tenant_id: verifiedProgram.program.tenant_id,
        program_id: verifiedProgram.program.program_id,
        program_digest: programDigest,
        version: verifiedProgram.program.version,
        status: 'ACTIVE',
        status_sequence: 0,
        status_observed_at: PROGRAM_NOW,
        status_expires_at: '2026-07-29T20:45:00.000Z',
        authorizer_id: verifiedProgram.authorizer_id,
        registered_at: PROGRAM_NOW,
        superseded_by_program_digest: null,
        total_occurrences: 6,
        budgets: [{
                budget_id: 'attempts', unit: 'attempt', limit: 10, reserved: 1, consumed: 4,
            }],
        program: verifiedProgram.program,
    };
    const occurrences = [
        occurrence('remediate', 'occurrence:remediate:indeterminate', 'INDETERMINATE', 14),
        occurrence('inspect', 'occurrence:inspect:released', 'RELEASED', 8),
        occurrence('verify', 'occurrence:verify:reserved', 'RESERVED', 18),
        occurrence('inspect', 'occurrence:inspect:proven-not-committed', 'PROVEN_NOT_COMMITTED', 6),
        occurrence('remediate', 'occurrence:remediate:invoking', 'INVOKING', 12),
        occurrence('inspect', 'occurrence:inspect:committed', 'COMMITTED', 4),
    ].map((entry) => ({ ...entry, program_digest: programDigest }));
    const reporter = keyMaterial('rp:example-operations', 'key:rp:bounded-report:v1');
    const input = {
        report_id: 'report:bounded-execution:2026-07-29:01',
        relying_party_id: reporter.signer.issuer_id,
        report_interval: { start: PROGRAM_NOW, end: REPORT_END },
        generated_at: GENERATED_AT,
        verified_program: verifiedProgram,
        report_snapshot: reportSnapshot(runtimeState, occurrences),
    };
    const artifact = signBoundedExecutionReport(input, {
        relying_party_id: reporter.signer.issuer_id,
        key_id: reporter.signer.key_id,
        private_key: reporter.signer.private_key,
    });
    const context = {
        trusted_keys: reporter.trusted_keys,
        expected_report_id: input.report_id,
        expected_relying_party_id: input.relying_party_id,
        expected_tenant_id: runtimeState.tenant_id,
        expected_program_id: runtimeState.program_id,
        expected_program_version: runtimeState.version,
        expected_program_digest: runtimeState.program_digest,
        expected_subject_id: verifiedProgram.program.subject_id,
        expected_audience: verifiedProgram.program.audience,
        expected_report_interval: input.report_interval,
        expected_runtime_state_digest: boundedExecutionRuntimeStateDigest(runtimeState),
        expected_occurrence_inventory_digest: boundedExecutionOccurrenceInventoryDigest(occurrences),
        expected_report_snapshot_marker: input.report_snapshot.snapshot_marker,
        now: '2026-07-29T20:36:00.000Z',
        max_report_age_ms: 10 * 60 * 1000,
    };
    return {
        artifact, authorizer, context, input, occurrences, programArtifact,
        reporter, runtimeState, verifiedProgram,
    };
}
test('signs a canonical report with deterministic per-node occurrence buckets and budget use', () => {
    const { artifact, context, occurrences, runtimeState } = harness();
    assert.equal(artifact['@version'], BOUNDED_EXECUTION_REPORT_VERSION);
    assert.equal(artifact.proof.algorithm, 'Ed25519');
    assert.equal(artifact.runtime_state_digest, boundedExecutionRuntimeStateDigest(runtimeState));
    assert.equal(artifact.report_snapshot_marker, context.expected_report_snapshot_marker);
    assert.equal(artifact.occurrence_inventory_digest, boundedExecutionOccurrenceInventoryDigest([...occurrences].reverse()));
    assert.deepEqual(artifact.budget_usage, [{
            budget_id: 'attempts', unit: 'attempt', limit: 10,
            reserved: 1, consumed: 4, remaining: 5,
        }]);
    assert.deepEqual(artifact.node_buckets.map((entry) => entry.node_id), [
        'inspect', 'notify', 'remediate', 'verify',
    ]);
    assert.deepEqual(artifact.node_buckets[0], {
        node_id: 'inspect',
        max_occurrences: 3,
        terminal_recorded_outcomes: [
            { occurrence_id: 'occurrence:inspect:committed', outcome: 'COMMITTED' },
            {
                occurrence_id: 'occurrence:inspect:proven-not-committed',
                outcome: 'PROVEN_NOT_COMMITTED',
            },
        ],
        unresolved_post_entry: [],
        released_pre_entry: ['occurrence:inspect:released'],
        never_attempted: { reserved_occurrence_ids: [], unallocated_occurrence_count: 1 },
    });
    assert.deepEqual(artifact.node_buckets[2].unresolved_post_entry, [
        { occurrence_id: 'occurrence:remediate:indeterminate', recorded_state: 'INDETERMINATE' },
        { occurrence_id: 'occurrence:remediate:invoking', recorded_state: 'INVOKING' },
    ]);
    assert.deepEqual(artifact.node_buckets[1].never_attempted, {
        reserved_occurrence_ids: [], unallocated_occurrence_count: 1,
    });
    assert.deepEqual(artifact.node_buckets[3].never_attempted, {
        reserved_occurrence_ids: ['occurrence:verify:reserved'],
        unallocated_occurrence_count: 1,
    });
    assert.equal(Object.isFrozen(artifact.node_buckets[0]), true);
    const verified = verifyBoundedExecutionReport(artifact, context);
    assert.equal(verified.accepted, true);
    assert.equal(verified.verified, true);
    assert.equal(verified.report_digest, boundedExecutionReportDigest(artifact));
});
test('requires the deterministic occurrence order returned by the report snapshot API', () => {
    const first = harness();
    const reversed = [...first.input.report_snapshot.occurrences].reverse();
    const body = {
        ...first.input.report_snapshot,
        occurrences: reversed,
    };
    const { snapshot_marker: _marker, ...markerBody } = body;
    assert.throws(() => signBoundedExecutionReport({
        ...first.input,
        report_snapshot: {
            ...markerBody,
            snapshot_marker: executionProgramReportSnapshotMarker(markerBody),
        },
    }, {
        relying_party_id: first.reporter.signer.issuer_id,
        key_id: first.reporter.signer.key_id,
        private_key: first.reporter.signer.private_key,
    }), /deterministic.*order/i);
});
test('signs release then re-reserve history without charging RELEASED against the node ceiling', () => {
    const run = harness();
    const replacement = {
        ...occurrence('inspect', 'occurrence:inspect:re-reserved', 'RESERVED', 20),
        program_digest: run.runtimeState.program_digest,
    };
    const runtimeState = {
        ...run.runtimeState,
        total_occurrences: 7,
        budgets: [{
                ...run.runtimeState.budgets[0],
                reserved: 2,
            }],
    };
    const artifact = signBoundedExecutionReport({
        ...run.input,
        report_snapshot: reportSnapshot(runtimeState, [...run.occurrences, replacement]),
    }, {
        relying_party_id: run.reporter.signer.issuer_id,
        key_id: run.reporter.signer.key_id,
        private_key: run.reporter.signer.private_key,
    });
    assert.deepEqual(artifact.node_buckets[0], {
        node_id: 'inspect',
        max_occurrences: 3,
        terminal_recorded_outcomes: [
            { occurrence_id: 'occurrence:inspect:committed', outcome: 'COMMITTED' },
            {
                occurrence_id: 'occurrence:inspect:proven-not-committed',
                outcome: 'PROVEN_NOT_COMMITTED',
            },
        ],
        unresolved_post_entry: [],
        released_pre_entry: ['occurrence:inspect:released'],
        never_attempted: {
            reserved_occurrence_ids: ['occurrence:inspect:re-reserved'],
            unallocated_occurrence_count: 0,
        },
    });
});
test('requires a fully pinned RP verification context and rejects substitutions', () => {
    const { artifact, context } = harness();
    assert.equal(verifyBoundedExecutionReport(artifact, undefined).reason, 'verification_context_required');
    const substitutions = [
        ['expected_report_id', 'report:attacker', 'report_id_mismatch'],
        ['expected_relying_party_id', 'rp:attacker', 'relying_party_mismatch'],
        ['expected_tenant_id', 'tenant:attacker', 'tenant_mismatch'],
        ['expected_program_id', 'program:attacker', 'program_id_mismatch'],
        ['expected_program_version', 2, 'program_version_mismatch'],
        ['expected_program_digest', D('9'), 'program_digest_mismatch'],
        ['expected_subject_id', 'agent:attacker', 'subject_mismatch'],
        ['expected_audience', 'gate:attacker', 'audience_mismatch'],
        ['expected_runtime_state_digest', D('8'), 'runtime_state_digest_mismatch'],
        ['expected_occurrence_inventory_digest', D('7'), 'occurrence_inventory_digest_mismatch'],
        ['expected_report_snapshot_marker', D('6'), 'report_snapshot_marker_mismatch'],
    ];
    for (const [field, value, reason] of substitutions) {
        assert.equal(verifyBoundedExecutionReport(artifact, {
            ...context, [field]: value,
        }).reason, reason, field);
    }
    assert.equal(verifyBoundedExecutionReport(artifact, {
        ...context,
        expected_report_interval: { ...context.expected_report_interval, end: GENERATED_AT },
    }).reason, 'report_interval_mismatch');
});
test('rejects mutation, signature transplant, non-Ed25519 pins, and validly signed unknown fields', () => {
    const first = harness();
    const mutated = structuredClone(first.artifact);
    mutated.node_buckets[0].terminal_recorded_outcomes[0].outcome = 'PROVEN_NOT_COMMITTED';
    assert.equal(verifyBoundedExecutionReport(mutated, first.context).reason, 'digest_mismatch');
    const algorithm = structuredClone(first.artifact);
    algorithm.proof.algorithm = 'ES256';
    assert.equal(verifyBoundedExecutionReport(algorithm, first.context).reason, 'artifact_signature_envelope_invalid');
    const second = harness();
    const transplanted = structuredClone(first.artifact);
    transplanted.proof = second.artifact.proof;
    assert.equal(verifyBoundedExecutionReport(transplanted, first.context).accepted, false);
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    assert.equal(verifyBoundedExecutionReport(first.artifact, {
        ...first.context,
        trusted_keys: {
            [first.reporter.signer.key_id]: {
                issuer_id: first.reporter.signer.issuer_id,
                public_key: rsa.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
            },
        },
    }).reason, 'pinned_key_invalid');
    const { proof: _proof, ...body } = first.artifact;
    const unknown = signRiskBody(BOUNDED_EXECUTION_REPORT_VERSION, {
        ...body,
        executed_outside_the_plan: false,
    }, first.reporter.signer);
    assert.equal(verifyBoundedExecutionReport(unknown, first.context).reason, 'report_schema_invalid');
});
test('fails closed on runtime, occurrence, budget, and closed-schema inconsistencies', () => {
    const run = harness();
    assert.throws(() => signBoundedExecutionReport({
        ...run.input,
        surprise: true,
    }, {
        relying_party_id: run.reporter.signer.issuer_id,
        key_id: run.reporter.signer.key_id,
        private_key: run.reporter.signer.private_key,
    }), /report input.*closed/i);
    assert.throws(() => signBoundedExecutionReport({
        ...run.input,
        report_snapshot: reportSnapshot({
            ...run.runtimeState,
            budgets: [{ ...run.runtimeState.budgets[0], consumed: 3 }],
        }, run.occurrences),
    }, {
        relying_party_id: run.reporter.signer.issuer_id,
        key_id: run.reporter.signer.key_id,
        private_key: run.reporter.signer.private_key,
    }), /budget.*reconcile/i);
    assert.throws(() => signBoundedExecutionReport({
        ...run.input,
        report_snapshot: reportSnapshot(run.runtimeState, run.occurrences.map((entry, index) => (index === 0 ? { ...entry, node_id: 'unknown-node' } : entry))),
    }, {
        relying_party_id: run.reporter.signer.issuer_id,
        key_id: run.reporter.signer.key_id,
        private_key: run.reporter.signer.private_key,
    }), /unknown program node/i);
    assert.throws(() => signBoundedExecutionReport({
        ...run.input,
        report_snapshot: reportSnapshot({ ...run.runtimeState, total_occurrences: run.runtimeState.total_occurrences + 1 }, [...run.occurrences, structuredClone(run.occurrences[0])]),
    }, {
        relying_party_id: run.reporter.signer.issuer_id,
        key_id: run.reporter.signer.key_id,
        private_key: run.reporter.signer.private_key,
    }), /occurrence.*duplicated/i);
});
test('rejects accessor-bearing hostile data without evaluating the accessor', () => {
    const run = harness();
    let evaluated = false;
    const hostile = structuredClone(run.occurrences[0]);
    Object.defineProperty(hostile, 'node_id', {
        enumerable: true,
        get() {
            evaluated = true;
            throw new Error('must not execute');
        },
    });
    assert.throws(() => signBoundedExecutionReport({
        ...run.input,
        report_snapshot: {
            ...run.input.report_snapshot,
            occurrences: [hostile, ...run.input.report_snapshot.occurrences.slice(1)],
        },
    }, {
        relying_party_id: run.reporter.signer.issuer_id,
        key_id: run.reporter.signer.key_id,
        private_key: run.reporter.signer.private_key,
    }), /report snapshot.*invalid/i);
    assert.equal(evaluated, false);
});
test('binds the narrow Gate-only claim boundary and makes no outside-plan claim', () => {
    const { artifact } = harness();
    assert.equal(artifact.claim_boundary, BOUNDED_EXECUTION_REPORT_CLAIM_BOUNDARY);
    assert.equal(artifact.outside_plan_claim, BOUNDED_EXECUTION_REPORT_OUTSIDE_PLAN_CLAIM);
    assert.match(artifact.claim_boundary, /gate_recorded_program_occurrences_only/);
    assert.match(artifact.claim_boundary, /not_external_effect_truth/);
    assert.match(artifact.claim_boundary, /not_program_safety/);
    assert.match(artifact.claim_boundary, /not_complete_mediation/);
    assert.match(artifact.outside_plan_claim, /SEPARATELY_SIGNED_EXTERNAL_INVENTORY_ROOT/);
    assert.match(artifact.outside_plan_claim, /NOT_CLAIMED/);
});
test('rejects stale or future-generated reports', () => {
    const { artifact, context } = harness();
    assert.equal(verifyBoundedExecutionReport(artifact, {
        ...context,
        now: '2026-07-29T20:34:59.999Z',
    }).reason, 'report_generated_in_future');
    assert.equal(verifyBoundedExecutionReport(artifact, {
        ...context,
        now: '2026-07-29T21:00:00.000Z',
    }).reason, 'report_stale');
});
test('binds runtime status and both directions of program supersession', () => {
    const run = harness();
    const successorDigest = D('9');
    const supersededState = {
        ...run.runtimeState,
        status: 'SUPERSEDED',
        status_sequence: 1,
        status_observed_at: '2026-07-29T20:20:00.000Z',
        superseded_by_program_digest: successorDigest,
    };
    const artifact = signBoundedExecutionReport({
        ...run.input,
        report_snapshot: reportSnapshot(supersededState, run.occurrences),
    }, {
        relying_party_id: run.reporter.signer.issuer_id,
        key_id: run.reporter.signer.key_id,
        private_key: run.reporter.signer.private_key,
    });
    assert.equal(artifact.status, 'SUPERSEDED');
    assert.deepEqual(artifact.supersession, {
        supersedes_program_digest: null,
        superseded_by_program_digest: successorDigest,
    });
    assert.equal(verifyBoundedExecutionReport(artifact, {
        ...run.context,
        expected_runtime_state_digest: boundedExecutionRuntimeStateDigest(supersededState),
        expected_report_snapshot_marker: artifact.report_snapshot_marker,
    }).accepted, true);
    assert.throws(() => signBoundedExecutionReport({
        ...run.input,
        report_snapshot: reportSnapshot({
            ...supersededState,
            status: 'ACTIVE',
        }, run.occurrences),
    }, {
        relying_party_id: run.reporter.signer.issuer_id,
        key_id: run.reporter.signer.key_id,
        private_key: run.reporter.signer.private_key,
    }), /status and successor digest conflict/i);
});
test('replays the same-team deterministic report known answer and hostile vectors', () => {
    const suite = JSON.parse(readFileSync(REPORT_VECTOR_PATH, 'utf8'));
    assert.equal(suite.status, 'same-team-experimental-reference-vectors');
    assert.ok(suite.claim_boundary.does_not_establish.some((entry) => (entry.includes('independent or cross-language conformance'))));
    const known = suite.known_answer;
    const verifiedProgram = verifyBoundedExecutionProgram(known.program_artifact, known.program_verification_context);
    assert.equal(verifiedProgram.accepted, true);
    assert.deepEqual(known.report_input.verified_program, verifiedProgram);
    const verifiedReport = verifyBoundedExecutionReport(known.report_artifact, known.report_verification_context);
    assert.equal(verifiedReport.accepted, true);
    assert.equal(verifiedReport.report_digest, known.report_digest);
    assert.equal(boundedExecutionReportDigest(known.report_artifact), known.report_digest);
    const { proof, ...body } = known.report_artifact;
    assert.equal(canonicalize(body), known.canonical_signed_body_utf8);
    assert.equal(Buffer.from(known.canonical_signed_body_utf8).toString('base64url'), known.canonical_signed_body_b64u);
    assert.equal(Buffer.from(`${BOUNDED_EXECUTION_REPORT_VERSION}\0${known.canonical_signed_body_utf8}`)
        .toString('base64url'), known.signature_input_b64u);
    assert.equal(proof.signature_b64u, known.signature_b64u);
    for (const entry of suite.hostile_mutations.artifact_cases) {
        assert.equal(verifyBoundedExecutionReport(entry.artifact, known.report_verification_context).reason, entry.expected_reason, entry.id);
    }
    for (const entry of suite.hostile_mutations.context_cases) {
        assert.equal(verifyBoundedExecutionReport(known.report_artifact, {
            ...known.report_verification_context,
            ...entry.context_override,
        }).reason, entry.expected_reason, entry.id);
    }
    for (const entry of suite.hostile_mutations.construction_cases) {
        assert.throws(() => signBoundedExecutionReport({
            ...known.report_input,
            report_snapshot: entry.report_snapshot,
        }, {
            relying_party_id: known.report_input.relying_party_id,
            key_id: known.report_artifact.issuer.key_id,
            private_key: null,
        }), (error) => error?.code === entry.expected_error_code, entry.id);
    }
});
