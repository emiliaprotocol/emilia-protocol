// SPDX-License-Identifier: Apache-2.0
// Generated from gate-qualification-v2.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * Runtime refinement adapter for the portable Gate Qualification v2 corpus.
 *
 * The JSON vectors name semantic faults and externally observable outcomes.
 * This adapter maps them to the canonical immutable AdmissionSnapshot,
 * transactional AdmissionStore, and protected GateQualificationV2 surfaces.
 */
import { GATE_QUALIFICATION_V2_VERSION, GateQualificationV2, composeQualificationDecisionV2, createMemoryInvocationAuthorityCustodyV2, } from "../../../packages/gate/gate-qualification-v2.js";
import { ADMISSION_CURRENTNESS_VERSION, AdmissionStoreValidationError, createAdmissionSnapshot, createMemoryAdmissionStore, } from "../../../packages/gate/admission-store.js";
export const GATE_QUALIFICATION_V2_VECTOR_VERSION = "EP-GATE-QUALIFICATION-CONFORMANCE-v2";
const NOW = "2026-07-26T18:00:00.000Z";
const VECTOR_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const OPERATIONS = new Set([
    "qualification",
    "begin_recheck",
    "snapshot",
    "admission",
    "crash",
    "provider",
]);
const REQUIRED_QUALIFICATION_CHECKS = [
    "schemas",
    "payload_signatures",
    "trust_accepted",
    "campaign_lineage",
    "terminal_outcomes_complete",
    "hidden_challenge_commitments",
    "qualification_statement_binding",
    "status_chain",
    "status_current_as_observed",
    "runtime_candidate_exact_match",
    "assignment_in_scope",
    "protected_request_bound",
];
function isRecord(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}
function nonEmpty(value) {
    return typeof value === "string" && value.trim().length > 0;
}
function closedKeys(value, allowed, label) {
    const accepted = new Set(allowed);
    const extras = Object.keys(value).filter((key) => !accepted.has(key));
    if (extras.length > 0) {
        throw new TypeError(`${label} has unknown fields: ${extras.join(", ")}`);
    }
}
function clone(value) {
    return structuredClone(value);
}
function freeze(value) {
    if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
        for (const key of Object.keys(value)) {
            freeze(value[key]);
        }
        Object.freeze(value);
    }
    return value;
}
function getPath(value, path) {
    let current = value;
    for (const segment of path.split(".")) {
        if (Array.isArray(current) && /^\d+$/u.test(segment)) {
            current = current[Number(segment)];
        }
        else if (isRecord(current)) {
            current = current[segment];
        }
        else {
            return undefined;
        }
    }
    return current;
}
function setPath(value, path, replacement) {
    const segments = path.split(".");
    let current = value;
    for (const [index, segment] of segments.entries()) {
        if (index === segments.length - 1) {
            if (Array.isArray(current) && /^\d+$/u.test(segment)) {
                current[Number(segment)] = replacement;
                return;
            }
            if (isRecord(current)) {
                current[segment] = replacement;
                return;
            }
            throw new TypeError(`mutation target is not assignable: ${path}`);
        }
        current = Array.isArray(current) && /^\d+$/u.test(segment)
            ? current[Number(segment)]
            : isRecord(current)
                ? current[segment]
                : undefined;
    }
    throw new TypeError(`mutation target is not assignable: ${path}`);
}
function digest(character) {
    return `sha256:${character.repeat(64)}`;
}
function validateMutation(mutation, label) {
    if (!isRecord(mutation))
        throw new TypeError(`${label} must be an object`);
    closedKeys(mutation, ["fault", "target", "value", "action", "resource_type"], label);
    for (const field of ["fault", "target", "action", "resource_type"]) {
        if (mutation[field] !== undefined && !nonEmpty(mutation[field])) {
            throw new TypeError(`${label}.${field} must be a non-empty string`);
        }
    }
}
/** Strict corpus validation keeps malformed vectors from becoming test skips. */
export function validateGateQualificationV2Corpus(input) {
    if (!isRecord(input))
        throw new TypeError("vector corpus must be an object");
    closedKeys(input, ["@version", "description", "limitations", "base", "vectors"], "vector corpus");
    if (input["@version"] !== GATE_QUALIFICATION_V2_VECTOR_VERSION) {
        throw new TypeError("unsupported Gate Qualification vector version");
    }
    if (!nonEmpty(input.description)) {
        throw new TypeError("vector corpus description must be non-empty");
    }
    if (!Array.isArray(input.limitations) || input.limitations.length === 0
        || !input.limitations.every(nonEmpty)) {
        throw new TypeError("vector corpus limitations must be non-empty strings");
    }
    if (!isRecord(input.base))
        throw new TypeError("vector corpus base is required");
    closedKeys(input.base, ["qualification_context", "admission_snapshot"], "vector corpus base");
    if (!isRecord(input.base.qualification_context)
        || !isRecord(input.base.admission_snapshot)) {
        throw new TypeError("vector corpus base fixtures must be objects");
    }
    const snapshot = createAdmissionSnapshot(input.base.admission_snapshot);
    const composed = composeQualificationDecisionV2({
        snapshot,
        qualification: qualificationBundle(snapshot),
    });
    if (!composed.allow) {
        throw new TypeError(`base admission snapshot is invalid: ${composed.reasons.join(",")}`);
    }
    if (!Array.isArray(input.vectors) || input.vectors.length === 0) {
        throw new TypeError("vector corpus vectors must be non-empty");
    }
    const ids = new Set();
    for (const [index, raw] of input.vectors.entries()) {
        const label = `vectors[${index}]`;
        if (!isRecord(raw))
            throw new TypeError(`${label} must be an object`);
        closedKeys(raw, ["id", "family", "description", "operation", "scenario", "mutation", "expected"], label);
        if (!nonEmpty(raw.id) || !VECTOR_ID.test(raw.id)) {
            throw new TypeError(`${label}.id must be a kebab-case identifier`);
        }
        if (ids.has(raw.id))
            throw new TypeError(`duplicate vector id: ${raw.id}`);
        ids.add(raw.id);
        if (!nonEmpty(raw.family) || !nonEmpty(raw.description)
            || !nonEmpty(raw.scenario)) {
            throw new TypeError(`${label} text fields must be non-empty`);
        }
        if (!OPERATIONS.has(raw.operation)) {
            throw new TypeError(`${label}.operation is unsupported`);
        }
        if (raw.mutation !== undefined)
            validateMutation(raw.mutation, `${label}.mutation`);
        if (!isRecord(raw.expected) || Object.keys(raw.expected).length === 0) {
            throw new TypeError(`${label}.expected must be a non-empty object`);
        }
    }
    return freeze(clone(input));
}
function roleDigest(snapshot, role) {
    const value = snapshot.body.inputs.find((entry) => entry.role === role)
        ?.payload_digest;
    if (!value)
        throw new TypeError(`base snapshot is missing ${role}`);
    return value;
}
function qualificationBundle(snapshot, decision = "QUALIFIED", reason = "qualified") {
    const binding = {
        caid: snapshot.body.caid,
        actionDigest: snapshot.body.action_digest,
    };
    return {
        qualification: {
            decision,
            reason,
            verification: "VERIFIED",
            acceptance: "ACCEPTED",
            candidate_match: "EXACT_MATCH",
            assignment_scope: "IN_SCOPE",
            currentness: "CURRENT_AS_OBSERVED",
            campaign_graph: "COMPLETE",
            remeasure_at_begin_invocation: true,
            checks: Object.fromEntries(REQUIRED_QUALIFICATION_CHECKS.map((check) => [check, true])),
            payload_digests: {
                candidate_manifest: snapshot.body.candidate_manifest_digest,
                campaign_head: digest("6"),
                qualification_graph: digest("7"),
                qualification_statement: snapshot.body.qualification_statement_payload_digest,
                qualification_status_head: snapshot.body.qualification_status.head_payload_digest,
                runtime_measurement: snapshot.body.runtime_measurement_digest,
                protected_request_digest: snapshot.body.effect_request_digest,
            },
        },
        aeb: {
            decision: "allow",
            requirementId: "aeb:human-authorization-v1",
            evidenceDigest: roleDigest(snapshot, "aeb"),
            ...binding,
        },
        aec: {
            decision: "allow",
            requirementId: "aec:execution-continuity-v1",
            evidenceDigest: roleDigest(snapshot, "aec"),
            ...binding,
        },
        localPolicy: {
            decision: "allow",
            policyId: "policy:payments-production-v1",
            evidenceDigest: roleDigest(snapshot, "local_policy"),
            ...binding,
        },
    };
}
function providerEvidence(snapshot, outcome = "COMMITTED", overrides = {}) {
    return {
        evidenceId: "provider-evidence:001",
        evidenceDigest: digest("8"),
        tenantId: snapshot.body.tenant_id,
        admissionId: snapshot.body.admission_id,
        operationId: snapshot.body.operation_id,
        snapshotDigest: snapshot.snapshot_digest,
        caid: snapshot.body.caid,
        actionDigest: snapshot.body.action_digest,
        effectRequestDigest: snapshot.body.effect_request_digest,
        provider: snapshot.body.provider,
        executorAdapterDigest: snapshot.body.executor_adapter_digest,
        idempotencyKey: snapshot.body.idempotency_key,
        outcome,
        observedAt: NOW,
        ...overrides,
    };
}
function observedRelation(snapshot, evidence, relation = evidence.outcome === "INDETERMINATE"
    ? "INDETERMINATE"
    : evidence.outcome === "PROVEN_NOT_COMMITTED"
        ? "DIVERGED"
        : "OBSERVED_AS_REQUESTED") {
    return {
        relation,
        evidenceDigest: relation === "INDETERMINATE" ? null : digest("9"),
        tenantId: snapshot.body.tenant_id,
        admissionId: snapshot.body.admission_id,
        operationId: snapshot.body.operation_id,
        snapshotDigest: snapshot.snapshot_digest,
        caid: snapshot.body.caid,
        actionDigest: snapshot.body.action_digest,
        providerEvidenceDigest: evidence.evidenceDigest,
        observedEffectDigest: relation === "INDETERMINATE" ? null : digest("0"),
        observedAt: NOW,
    };
}
function matchingObservation(snapshot) {
    return {
        "@version": ADMISSION_CURRENTNESS_VERSION,
        observed_at: NOW,
        qualification_status_authority_id: snapshot.body.qualification_status.authority_id,
        qualification_status_sequence: snapshot.body.qualification_status.sequence,
        qualification_status_head_digest: snapshot.body.qualification_status.head_payload_digest,
        qualification_status_expires_at: snapshot.body.qualification_status.expires_at,
        trust_epoch: snapshot.body.trust_epoch,
        trust_configuration_digest: snapshot.body.trust_configuration_digest,
        configuration_epoch: snapshot.body.configuration_epoch,
        configuration_digest: snapshot.body.configuration_digest,
        runtime_measurement_digest: snapshot.body.runtime_measurement_digest,
        candidate_match: "EXACT_MATCH",
        external_leases: snapshot.body.resource_reservations
            .filter((resource) => resource.kind === "external_lease")
            .map((resource) => ({
            resource_id: resource.resource_id,
            digest: resource.digest,
            expires_at: resource.expires_at,
        })),
    };
}
function ownerToken(index) {
    return `admission-owner:v2:${index.toString(36).padStart(32, "0")}`;
}
function invocationToken(index) {
    return `admission-invocation:v2:${index.toString(36).padStart(32, "0")}`;
}
function memoryStore(snapshot, observation) {
    let ownerIndex = 0;
    let invocationIndex = 0;
    return createMemoryAdmissionStore({
        now: NOW,
        ownerTokenFactory: () => ownerToken(++ownerIndex),
        invocationTokenFactory: () => invocationToken(++invocationIndex),
        currentnessOracle: {
            read: async (current) => clone(observation ?? matchingObservation(snapshot ?? current)),
        },
    });
}
function gateHarness(snapshot, options = {}) {
    const store = options.store ?? memoryStore(snapshot);
    const counts = { invoke: 0, providerEffect: 0, reconcile: 0 };
    const adapter = {
        custody: "protected",
        credentialsExposed: false,
        async invoke(input) {
            counts.invoke += 1;
            if (options.invoke)
                return options.invoke(input);
            counts.providerEffect += 1;
            return providerEvidence(input.snapshot);
        },
        async reconcile(input) {
            counts.reconcile += 1;
            if (options.reconcile)
                return options.reconcile(input);
            return providerEvidence(input.snapshot, "PROVEN_NOT_COMMITTED");
        },
    };
    const gate = new GateQualificationV2({
        mode: "enforce",
        admissionStore: store,
        protectedAdapter: adapter,
        invocationRemeasurer: {
            source: "authoritative",
            async remeasure(value) {
                return qualificationBundle(value);
            },
        },
        authorityCustody: createMemoryInvocationAuthorityCustodyV2(),
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
                return observedRelation(expected, evidence);
            },
        },
        testOnly: true,
    });
    return { gate, store, counts };
}
function executionInput(snapshot) {
    return { snapshot, qualification: qualificationBundle(snapshot) };
}
function reference(snapshot) {
    return {
        tenant_id: snapshot.body.tenant_id,
        admission_id: snapshot.body.admission_id,
    };
}
function failureReason(result) {
    return "reason" in result && typeof result.reason === "string"
        ? result.reason
        : null;
}
function firstFailureReason(results) {
    const failed = results.find((result) => "ok" in result && result.ok === false);
    return failed ? failureReason(failed) : null;
}
async function normalizeGateResult(result, harness, snapshot) {
    const record = await harness.store.read(reference(snapshot));
    return freeze({
        disposition: result.status === "committed" || result.status === "not_committed"
            ? "ACCEPT"
            : result.status === "reconciliation_required"
                ? "RECONCILE"
                : result.status === "shadow"
                    ? "SHADOW"
                    : "REFUSE",
        gate_status: result.status,
        reason: "reason" in result ? result.reason : null,
        admission_state: record?.state ?? "ABSENT",
        provider_invocations: harness.counts.invoke,
        provider_effects: harness.counts.providerEffect,
        reconciliations: harness.counts.reconcile,
    });
}
const QUALIFICATION_FAULTS = new Map([
    ["identity_substitution", { decision: "NOT_QUALIFIED", reason: "candidate_identity_mismatch" }],
    ["candidate_replacement", { decision: "NOT_QUALIFIED", reason: "runtime_candidate_replaced" }],
    ["mutable_model_alias", { decision: "INDETERMINATE", reason: "model_identity_unpinnable" }],
    ["cross_assignment_reuse", { decision: "NOT_QUALIFIED", reason: "assignment_out_of_scope" }],
    ["omitted_terminal_outcome", { decision: "NOT_QUALIFIED", reason: "campaign_graph_incomplete" }],
    ["discarded_attempt", { decision: "NOT_QUALIFIED", reason: "campaign_graph_incomplete" }],
    ["challenge_grinding", { decision: "NOT_QUALIFIED", reason: "campaign_attempt_ceiling_exceeded" }],
    ["selective_rerun", { decision: "NOT_QUALIFIED", reason: "campaign_precommit_mismatch" }],
    ["status_stale", { decision: "INDETERMINATE", reason: "qualification_status_stale" }],
    ["status_revoked", { decision: "NOT_QUALIFIED", reason: "qualification_status_revoked" }],
    ["status_equivocated", { decision: "INDETERMINATE", reason: "qualification_status_equivocated" }],
]);
async function runQualificationVector(vector, corpus) {
    const snapshot = createAdmissionSnapshot(clone(corpus.base.admission_snapshot));
    if (vector.scenario === "shadow_non_actuation") {
        let legacyCalls = 0;
        const gate = new GateQualificationV2({
            mode: "shadow",
            legacyQualification: {
                async qualify() {
                    legacyCalls += 1;
                    return { allow: true, reasons: [] };
                },
            },
        });
        const result = await gate.execute(executionInput(snapshot));
        return freeze({
            disposition: "SHADOW",
            gate_status: result.status,
            v2_allowed: result.status === "shadow" ? result.decision.allow : false,
            legacy_calls: legacyCalls,
            admission_state: "ABSENT",
            provider_invocations: 0,
            provider_effects: 0,
        });
    }
    if (vector.scenario === "eligible") {
        const harness = gateHarness(snapshot);
        const result = await harness.gate.execute(executionInput(snapshot));
        return freeze({
            ...await normalizeGateResult(result, harness, snapshot),
            portable_reason: null,
        });
    }
    const mutation = vector.mutation;
    if (!mutation?.fault || !mutation.target || mutation.value === undefined) {
        throw new TypeError(`${vector.id} requires fault, target, and value`);
    }
    const baseline = clone(corpus.base.qualification_context);
    const before = getPath(baseline, mutation.target);
    if (before === undefined) {
        throw new TypeError(`${vector.id} references missing target ${mutation.target}`);
    }
    setPath(baseline, mutation.target, mutation.value);
    if (Object.is(before, getPath(baseline, mutation.target))) {
        throw new TypeError(`${vector.id} mutation did not change ${mutation.target}`);
    }
    const classified = QUALIFICATION_FAULTS.get(mutation.fault);
    if (!classified)
        throw new TypeError(`${vector.id} has unknown qualification fault`);
    const harness = gateHarness(snapshot);
    const result = await harness.gate.execute({
        snapshot,
        qualification: qualificationBundle(snapshot, classified.decision, classified.reason),
    });
    return freeze({
        ...await normalizeGateResult(result, harness, snapshot),
        portable_reason: classified.reason,
    });
}
async function runBeginRecheckVector(vector, corpus) {
    const snapshot = createAdmissionSnapshot(clone(corpus.base.admission_snapshot));
    const mutation = vector.mutation;
    if (!mutation?.target || mutation.value === undefined) {
        throw new TypeError(`${vector.id} requires a target and value`);
    }
    const mutationTarget = mutation.target;
    if (mutationTarget.startsWith("currentness.")) {
        const observation = matchingObservation(snapshot);
        const target = mutation.target.slice("currentness.".length);
        if (getPath(observation, target) === undefined) {
            throw new TypeError(`${vector.id} references missing target ${mutation.target}`);
        }
        setPath(observation, target, mutation.value);
        const store = memoryStore(snapshot, observation);
        const harness = gateHarness(snapshot, { store });
        const result = await harness.gate.execute(executionInput(snapshot));
        return freeze({
            ...await normalizeGateResult(result, harness, snapshot),
            transactional_currentness: store.transactionalCurrentness,
        });
    }
    if (mutationTarget === "body.effect_request_digest") {
        if (typeof mutation.value !== "string"
            || !/^sha256:[0-9a-f]{64}$/.test(mutation.value)) {
            throw new TypeError(`${vector.id} requires a digest substitution`);
        }
        const substitutedInput = clone(corpus.base.admission_snapshot);
        substitutedInput.effect_request_digest = mutation.value;
        const substituted = createAdmissionSnapshot(substitutedInput);
        const harness = gateHarness(substituted);
        const result = await harness.gate.execute({
            snapshot: substituted,
            // Replay the otherwise-valid decision for request A against request B.
            qualification: qualificationBundle(snapshot),
        });
        return normalizeGateResult(result, harness, substituted);
    }
    if (!mutationTarget.startsWith("body.")) {
        throw new TypeError(`${vector.id} requires currentness.* or body.* target`);
    }
    const base = memoryStore(snapshot);
    const store = {
        ...base,
        async beginInvocation(input) {
            const begun = await base.beginInvocation(input);
            if (!begun.ok)
                return begun;
            const tampered = clone(begun.snapshot);
            const target = mutationTarget.slice("body.".length);
            if (getPath(tampered.body, target) === undefined) {
                throw new TypeError(`${vector.id} references missing target ${mutationTarget}`);
            }
            setPath(tampered.body, target, mutation.value);
            return { ...begun, snapshot: tampered };
        },
    };
    const harness = gateHarness(snapshot, { store });
    const result = await harness.gate.execute(executionInput(snapshot));
    return normalizeGateResult(result, harness, snapshot);
}
function snapshotValidationCode(error) {
    return error instanceof AdmissionStoreValidationError
        ? error.code
        : error instanceof Error
            ? error.name
            : "unknown_error";
}
async function runSnapshotVector(vector, corpus) {
    const originalInput = clone(corpus.base.admission_snapshot);
    const original = createAdmissionSnapshot(originalInput);
    const mutation = vector.mutation;
    if (vector.scenario === "canonical_order") {
        const reordered = clone(originalInput);
        reordered.inputs.reverse();
        reordered.resource_reservations.reverse();
        const candidate = createAdmissionSnapshot(reordered);
        return freeze({
            disposition: "ACCEPT",
            same_snapshot_digest: candidate.snapshot_digest === original.snapshot_digest,
            canonical_input_order: candidate.body.inputs.map((entry) => entry.role),
        });
    }
    if (vector.scenario === "duplicate_input") {
        const duplicated = clone(originalInput);
        duplicated.inputs[1] = clone(duplicated.inputs[0]);
        try {
            createAdmissionSnapshot(duplicated);
            return freeze({ disposition: "ACCEPT", reason: null });
        }
        catch (error) {
            return freeze({ disposition: "REFUSE", reason: snapshotValidationCode(error) });
        }
    }
    if (vector.scenario === "duplicate_resource") {
        const duplicated = clone(originalInput);
        duplicated.resource_reservations[1] = clone(duplicated.resource_reservations[0]);
        try {
            createAdmissionSnapshot(duplicated);
            return freeze({ disposition: "ACCEPT", reason: null });
        }
        catch (error) {
            return freeze({ disposition: "REFUSE", reason: snapshotValidationCode(error) });
        }
    }
    if (!mutation?.target || mutation.value === undefined) {
        throw new TypeError(`${vector.id} requires a target and value`);
    }
    const changedInput = clone(originalInput);
    if (getPath(changedInput, mutation.target) === undefined) {
        throw new TypeError(`${vector.id} references missing target ${mutation.target}`);
    }
    setPath(changedInput, mutation.target, mutation.value);
    const changed = createAdmissionSnapshot(changedInput);
    return freeze({
        disposition: changed.snapshot_digest === original.snapshot_digest
            ? "COLLISION"
            : "BINDING_CHANGED",
        same_snapshot_digest: changed.snapshot_digest === original.snapshot_digest,
    });
}
function transition(record, owner) {
    return {
        tenant_id: record.tenant_id,
        admission_id: record.admission_id,
        expected_revision: record.revision,
        owner_token: owner,
    };
}
function successorInput(base, admissionId = "admission:successor") {
    return {
        ...clone(base),
        admission_id: admissionId,
        inputs: base.inputs.map((entry) => ({ ...clone(entry) })),
        resource_reservations: base.resource_reservations.map((resource) => ({
            ...clone(resource),
            reservation_id: `${resource.kind}:${admissionId}`,
        })),
        supersedes_admission_id: null,
        remedy_for: null,
    };
}
async function runAdmissionVector(vector, corpus) {
    const base = clone(corpus.base.admission_snapshot);
    const canonical = createAdmissionSnapshot(base);
    const store = memoryStore(canonical);
    if (vector.scenario === "concurrent_reserve") {
        const results = await Promise.all(Array.from({ length: 24 }, (_, index) => store.reserve({ ...clone(base), admission_id: `admission:${100 + index}` })));
        const winners = results.filter((result) => result.ok);
        const record = await store.readByOperation({
            tenant_id: base.tenant_id,
            operation_id: base.operation_id,
        });
        return freeze({
            winners: winners.length,
            losers: results.length - winners.length,
            loser_reason: firstFailureReason(results),
            state: record?.state ?? "ABSENT",
            execution_right: record?.execution_right ?? "ABSENT",
        });
    }
    const reserved = await store.reserve(base);
    if (!reserved.ok)
        throw new Error(`${vector.id}: base reservation failed`);
    if (vector.scenario === "operation_replay") {
        const released = await store.release(transition(reserved.record, reserved.owner_token));
        if (!released.ok)
            throw new Error(`${vector.id}: release failed`);
        const replay = await store.reserve(successorInput(base, "admission:replay"));
        return freeze({
            disposition: replay.ok ? "ACCEPT" : "REFUSE",
            reason: failureReason(replay),
            original_state: released.record.state,
        });
    }
    if (vector.scenario === "resource_exhaustion") {
        const selected = vector.mutation?.resource_type;
        if (!selected)
            throw new TypeError(`${vector.id} requires resource_type`);
        const operationId = `operation:${selected}:conflict`;
        const second = clone(base);
        second.admission_id = `admission:${selected}:conflict`;
        second.operation_id = operationId;
        second.idempotency_key = `idempotency:${operationId}`;
        second.resource_reservations = second.resource_reservations.map((resource) => ({
            ...resource,
            resource_id: resource.kind === selected
                ? resource.resource_id
                : resource.kind === "provider_operation"
                    ? operationId
                    : `${resource.resource_id}:independent`,
            reservation_id: `${resource.kind}:conflict`,
        }));
        const conflict = await store.reserve(second);
        return freeze({
            disposition: conflict.ok ? "ACCEPT" : "REFUSE",
            reason: failureReason(conflict),
            fenced_resource: selected,
        });
    }
    if (vector.scenario === "concurrent_begin") {
        const results = await Promise.all(Array.from({ length: 24 }, () => store.beginInvocation(transition(reserved.record, reserved.owner_token))));
        const winners = results.filter((result) => result.ok);
        const record = await store.read(reference(reserved.snapshot));
        return freeze({
            winners: winners.length,
            losers: results.length - winners.length,
            loser_reason: firstFailureReason(results),
            state: record?.state ?? "ABSENT",
            execution_right: record?.execution_right ?? "ABSENT",
        });
    }
    if (vector.scenario === "stale_lease") {
        const observation = matchingObservation(reserved.snapshot);
        observation.external_leases[0].expires_at = "2026-07-26T17:59:59.000Z";
        const staleStore = memoryStore(reserved.snapshot, observation);
        const staleReserved = await staleStore.reserve(base);
        if (!staleReserved.ok)
            throw new Error(`${vector.id}: stale reservation failed`);
        const begun = await staleStore.beginInvocation(transition(staleReserved.record, staleReserved.owner_token));
        const record = await staleStore.read(reference(staleReserved.snapshot));
        return freeze({
            disposition: begun.ok ? "ACCEPT" : "REFUSE",
            reason: failureReason(begun),
            state: record?.state ?? "ABSENT",
            execution_right: record?.execution_right ?? "ABSENT",
        });
    }
    if (vector.scenario === "supersede_reserved"
        || vector.scenario === "same_operation_reserved_only") {
        const superseded = await store.supersede({
            ...transition(reserved.record, reserved.owner_token),
            successor: successorInput(base),
        });
        return freeze({
            disposition: superseded.ok ? "ACCEPT" : "REFUSE",
            reason: failureReason(superseded),
            original_state: superseded.ok
                ? superseded.predecessor_record.state
                : reserved.record.state,
            successor_state: superseded.ok
                ? superseded.successor_record.state
                : "ABSENT",
            same_operation: superseded.ok
                ? superseded.successor_record.operation_id === reserved.record.operation_id
                : false,
            successor_owner_rotated: superseded.ok
                ? superseded.successor_record.owner_digest !== reserved.record.owner_digest
                : false,
        });
    }
    if (vector.scenario === "supersede_operation_change") {
        const successor = successorInput(base);
        successor.operation_id = "operation:attacker";
        successor.idempotency_key = "idempotency:operation:attacker";
        const providerResource = successor.resource_reservations.find((resource) => resource.kind === "provider_operation");
        if (providerResource)
            providerResource.resource_id = successor.operation_id;
        const superseded = await store.supersede({
            ...transition(reserved.record, reserved.owner_token),
            successor,
        });
        return freeze({
            disposition: superseded.ok ? "ACCEPT" : "REFUSE",
            reason: failureReason(superseded),
        });
    }
    if (vector.scenario === "supersede_consumed") {
        const begun = await store.beginInvocation(transition(reserved.record, reserved.owner_token));
        if (!begun.ok)
            throw new Error(`${vector.id}: invocation failed`);
        const superseded = await store.supersede({
            ...transition(begun.record, reserved.owner_token),
            successor: successorInput(base),
        });
        return freeze({
            disposition: superseded.ok ? "ACCEPT" : "REFUSE",
            reason: failureReason(superseded),
            state: begun.record.state,
            execution_right: begun.record.execution_right,
        });
    }
    if (vector.scenario === "supersession_race") {
        const results = await Promise.all(Array.from({ length: 16 }, (_, index) => store.supersede({
            ...transition(reserved.record, reserved.owner_token),
            successor: successorInput(base, `admission:successor:${index}`),
        })));
        return freeze({
            winners: results.filter((result) => result.ok).length,
            losers: results.filter((result) => !result.ok).length,
            loser_reason: firstFailureReason(results),
        });
    }
    if (vector.scenario === "begin_supersede_race") {
        const [begin, supersede] = await Promise.all([
            store.beginInvocation(transition(reserved.record, reserved.owner_token)),
            store.supersede({
                ...transition(reserved.record, reserved.owner_token),
                successor: successorInput(base),
            }),
        ]);
        const accepted = Number(begin.ok) + Number(supersede.ok);
        const current = await store.readByOperation({
            tenant_id: base.tenant_id,
            operation_id: base.operation_id,
        });
        return freeze({
            winners: accepted,
            exclusive_winner: accepted === 1,
            original_state: current?.state ?? "ABSENT",
            execution_right: current?.execution_right ?? "ABSENT",
        });
    }
    if (vector.scenario === "contradictory_provider_outcomes") {
        const begun = await store.beginInvocation(transition(reserved.record, reserved.owner_token));
        if (!begun.ok)
            throw new Error(`${vector.id}: invocation failed`);
        const first = await store.recordProviderOutcome({
            ...transition(begun.record, reserved.owner_token),
            invocation_token: begun.invocation_token,
            value: "COMMITTED",
            evidence_digest: digest("7"),
            observed_at: NOW,
        });
        if (!first.ok)
            throw new Error(`${vector.id}: first outcome failed`);
        const second = await store.recordProviderOutcome({
            ...transition(first.record, reserved.owner_token),
            invocation_token: begun.invocation_token,
            value: "PROVEN_NOT_COMMITTED",
            evidence_digest: digest("8"),
            observed_at: NOW,
        });
        return freeze({
            disposition: second.ok ? "ACCEPT" : "REFUSE",
            reason: failureReason(second),
            execution_right: first.record.execution_right,
        });
    }
    if (vector.scenario === "token_rotation") {
        const begun = await store.beginInvocation(transition(reserved.record, reserved.owner_token));
        if (!begun.ok)
            throw new Error(`${vector.id}: invocation failed`);
        const recovered = await store.recoverIndeterminate({
            ...reference(reserved.snapshot),
            owner_token: reserved.owner_token,
        });
        if (!recovered.ok)
            throw new Error(`${vector.id}: recovery failed`);
        const stale = await store.recordProviderOutcome({
            ...transition(recovered.record, reserved.owner_token),
            invocation_token: begun.invocation_token,
            value: "COMMITTED",
            evidence_digest: digest("7"),
            observed_at: NOW,
        });
        const current = await store.recordProviderOutcome({
            ...transition(recovered.record, reserved.owner_token),
            invocation_token: recovered.reconciliation_token,
            value: "COMMITTED",
            evidence_digest: digest("7"),
            observed_at: NOW,
        });
        return freeze({
            token_rotated: recovered.reconciliation_token !== begun.invocation_token,
            stale_token_disposition: stale.ok ? "ACCEPT" : "REFUSE",
            stale_token_reason: failureReason(stale),
            current_token_disposition: current.ok ? "ACCEPT" : "REFUSE",
            state: current.ok ? current.record.state : recovered.record.state,
        });
    }
    throw new TypeError(`${vector.id} has unsupported admission scenario`);
}
async function runCrashVector(vector, corpus) {
    const base = clone(corpus.base.admission_snapshot);
    const snapshot = createAdmissionSnapshot(base);
    const store = memoryStore(snapshot);
    const reserved = await store.reserve(base);
    if (!reserved.ok)
        throw new Error(`${vector.id}: base reservation failed`);
    const admissionReference = reference(reserved.snapshot);
    if (vector.scenario === "after_reserve_write") {
        const journal = await store.journal(admissionReference);
        return freeze({
            state: reserved.record.state,
            execution_right: reserved.record.execution_right,
            journal_events: journal.map((entry) => entry.event),
            provider_attempt: reserved.record.provider_attempt,
        });
    }
    if (vector.scenario === "after_release_write") {
        const released = await store.release(transition(reserved.record, reserved.owner_token));
        if (!released.ok)
            throw new Error(`${vector.id}: release failed`);
        return freeze({
            state: released.record.state,
            execution_right: released.record.execution_right,
            journal_events: (await store.journal(admissionReference))
                .map((entry) => entry.event),
            provider_attempt: released.record.provider_attempt,
        });
    }
    if (vector.scenario === "after_supersession_write") {
        const superseded = await store.supersede({
            ...transition(reserved.record, reserved.owner_token),
            successor: successorInput(base),
        });
        if (!superseded.ok)
            throw new Error(`${vector.id}: supersession failed`);
        return freeze({
            original_state: superseded.predecessor_record.state,
            original_execution_right: superseded.predecessor_record.execution_right,
            successor_state: superseded.successor_record.state,
            successor_execution_right: superseded.successor_record.execution_right,
            provider_attempt: superseded.successor_record.provider_attempt,
        });
    }
    const begun = await store.beginInvocation(transition(reserved.record, reserved.owner_token));
    if (!begun.ok)
        throw new Error(`${vector.id}: invocation failed`);
    if (vector.scenario === "after_begin_write") {
        const retry = await store.beginInvocation(transition(begun.record, reserved.owner_token));
        return freeze({
            state: begun.record.state,
            execution_right: begun.record.execution_right,
            retry_reason: failureReason(retry),
            provider_attempt: begun.record.provider_attempt,
        });
    }
    const recovered = await store.recoverIndeterminate({
        ...admissionReference,
        owner_token: reserved.owner_token,
    });
    if (!recovered.ok)
        throw new Error(`${vector.id}: recovery failed`);
    if (vector.scenario === "after_recovery_write") {
        const retry = await store.beginInvocation(transition(recovered.record, reserved.owner_token));
        return freeze({
            state: recovered.record.state,
            execution_right: recovered.record.execution_right,
            retry_reason: failureReason(retry),
        });
    }
    const provider = await store.recordProviderOutcome({
        ...transition(recovered.record, reserved.owner_token),
        invocation_token: recovered.reconciliation_token,
        value: "COMMITTED",
        evidence_digest: digest("7"),
        observed_at: NOW,
    });
    if (!provider.ok)
        throw new Error(`${vector.id}: provider outcome failed`);
    if (vector.scenario === "after_provider_outcome_write") {
        return freeze({
            state: provider.record.state,
            execution_right: provider.record.execution_right,
            provider_outcome: provider.record.provider_outcome?.value ?? null,
            effect_relation: provider.record.effect_relation?.value ?? null,
        });
    }
    if (vector.scenario === "after_effect_outcome_write") {
        const effect = await store.recordEffectRelation({
            ...transition(provider.record, reserved.owner_token),
            invocation_token: recovered.reconciliation_token,
            value: "OBSERVED_AS_REQUESTED",
            evidence_digest: digest("8"),
            observed_at: NOW,
        });
        if (!effect.ok)
            throw new Error(`${vector.id}: effect relation failed`);
        const retry = await store.beginInvocation(transition(effect.record, reserved.owner_token));
        return freeze({
            state: effect.record.state,
            execution_right: effect.record.execution_right,
            provider_outcome: effect.record.provider_outcome?.value ?? null,
            effect_relation: effect.record.effect_relation?.value ?? null,
            retry_reason: failureReason(retry),
        });
    }
    throw new TypeError(`${vector.id} has unsupported crash scenario`);
}
async function runProviderVector(vector, corpus) {
    const snapshot = createAdmissionSnapshot(clone(corpus.base.admission_snapshot));
    if (vector.scenario === "post_begin_no_blind_retry") {
        const base = memoryStore(snapshot);
        let beginCalls = 0;
        const store = {
            ...base,
            async beginInvocation(input) {
                beginCalls += 1;
                const result = await base.beginInvocation(input);
                if (result.ok)
                    throw new Error("ack lost after atomic begin");
                return result;
            },
        };
        const harness = gateHarness(snapshot, {
            store,
            async reconcile(input) {
                return providerEvidence(input.snapshot, "PROVEN_NOT_COMMITTED");
            },
        });
        const first = await harness.gate.execute(executionInput(snapshot));
        const retry = await harness.gate.execute(executionInput(snapshot));
        const reconciled = await harness.gate.reconcile(reference(snapshot));
        const record = await base.read(reference(snapshot));
        return freeze({
            disposition: "RECONCILE",
            first_status: first.status,
            retry_status: retry.status,
            reconciliation_status: reconciled.status,
            admission_state: record?.state ?? "ABSENT",
            begin_calls: beginCalls,
            provider_invocations: harness.counts.invoke,
            reconciliations: harness.counts.reconcile,
        });
    }
    let options = {};
    if (vector.scenario === "crash_before_provider") {
        options = { async invoke() { throw new Error("crash before provider entry"); } };
    }
    else if (vector.scenario === "crash_after_provider") {
        options = { async invoke() { throw new Error("crash after possible provider entry"); } };
    }
    else if (vector.scenario === "timeout") {
        options = { async invoke() { throw new Error("provider timeout after possible commitment"); } };
    }
    else if (vector.scenario === "forged_evidence") {
        options = {
            async verify() { return { ok: false, reason: "signature_invalid" }; },
        };
    }
    else if (vector.scenario === "replayed_evidence") {
        options = {
            async verify(raw) {
                return {
                    ok: true,
                    evidence: {
                        ...raw,
                        admissionId: "admission:replayed",
                    },
                };
            },
        };
    }
    else if (vector.scenario === "contradictory_committed_no_effect") {
        options = {
            async relate(evidence, expected) {
                return {
                    ...observedRelation(expected, evidence, "DIVERGED"),
                    evidenceDigest: null,
                };
            },
        };
    }
    else if (vector.scenario === "contradictory_not_committed_effect") {
        options = {
            async invoke(input) {
                return providerEvidence(input.snapshot, "PROVEN_NOT_COMMITTED");
            },
            async relate(evidence, expected) {
                return {
                    ...observedRelation(expected, evidence, "OBSERVED_AS_REQUESTED"),
                    observedEffectDigest: null,
                };
            },
        };
    }
    else if (vector.scenario === "committed_diverged") {
        options = {
            async relate(evidence, expected) {
                return observedRelation(expected, evidence, "DIVERGED");
            },
        };
    }
    else if (vector.scenario === "no_blind_retry") {
        options = {
            async invoke() { throw new Error("provider outcome unknown"); },
            async reconcile(input) {
                return providerEvidence(input.snapshot, "PROVEN_NOT_COMMITTED");
            },
        };
    }
    else {
        throw new TypeError(`${vector.id} has unsupported provider scenario`);
    }
    const harness = gateHarness(snapshot, options);
    const first = await harness.gate.execute(executionInput(snapshot));
    if (!["no_blind_retry", "crash_before_provider", "crash_after_provider", "timeout"]
        .includes(vector.scenario)) {
        const normalized = await normalizeGateResult(first, harness, snapshot);
        if (first.status === "committed" || first.status === "not_committed") {
            return freeze({
                ...normalized,
                provider_outcome: first.evidence.outcome,
                effect_relation: first.relation.relation,
            });
        }
        return normalized;
    }
    const second = await harness.gate.execute(executionInput(snapshot));
    let reconciled = null;
    if (vector.scenario === "no_blind_retry") {
        reconciled = await harness.gate.reconcile(reference(snapshot));
    }
    const record = await harness.store.read(reference(snapshot));
    return freeze({
        disposition: first.status === "reconciliation_required" ? "RECONCILE" : "REFUSE",
        first_status: first.status,
        retry_status: second.status,
        reconciliation_status: reconciled?.status ?? null,
        admission_state: record?.state ?? "ABSENT",
        provider_invocations: harness.counts.invoke,
        reconciliations: harness.counts.reconcile,
    });
}
/** Execute one portable vector against the TypeScript reference surfaces. */
export async function runGateQualificationV2Vector(vector, corpus) {
    switch (vector.operation) {
        case "qualification":
            return runQualificationVector(vector, corpus);
        case "begin_recheck":
            return runBeginRecheckVector(vector, corpus);
        case "snapshot":
            return runSnapshotVector(vector, corpus);
        case "admission":
            return runAdmissionVector(vector, corpus);
        case "crash":
            return runCrashVector(vector, corpus);
        case "provider":
            return runProviderVector(vector, corpus);
    }
}
/** Structural subset matching lets vectors avoid implementation-only fields. */
export function vectorResultMatches(actual, expected) {
    const mismatches = [];
    function visit(actualValue, expectedValue, path) {
        if (isRecord(expectedValue)) {
            if (!isRecord(actualValue)) {
                mismatches.push(`${path}: expected object`);
                return;
            }
            for (const [key, child] of Object.entries(expectedValue)) {
                visit(actualValue[key], child, path ? `${path}.${key}` : key);
            }
            return;
        }
        if (Array.isArray(expectedValue)) {
            if (!Array.isArray(actualValue)
                || JSON.stringify(actualValue) !== JSON.stringify(expectedValue)) {
                mismatches.push(`${path}: expected ${JSON.stringify(expectedValue)}, got ${JSON.stringify(actualValue)}`);
            }
            return;
        }
        if (!Object.is(actualValue, expectedValue)) {
            mismatches.push(`${path}: expected ${JSON.stringify(expectedValue)}, got ${JSON.stringify(actualValue)}`);
        }
    }
    visit(actual, expected, "");
    return freeze({ ok: mismatches.length === 0, mismatches });
}
export default Object.freeze({
    GATE_QUALIFICATION_V2_VECTOR_VERSION,
    validateGateQualificationV2Corpus,
    runGateQualificationV2Vector,
    vectorResultMatches,
});
