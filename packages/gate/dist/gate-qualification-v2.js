// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Gate Qualification v2 orchestration over the canonical admission-custody
 * contract. Qualification is evidence, not authorization: only a complete
 * immutable AdmissionSnapshot may cross the one-time invocation boundary.
 */
import { createAdmissionSnapshot } from './admission-store.js';
export const GATE_QUALIFICATION_V2_VERSION = 'EP-GATE-QUALIFICATION-v2';
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const REQUIRED_QUALIFICATION_CHECKS = Object.freeze([
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
]);
const DEFAULT_ADAPTER_TIMEOUT_MS = 30_000;
const MAX_ADAPTER_TIMEOUT_MS = 300_000;
/** Explicitly test-only custody. Production callers must supply durable KMS-backed custody. */
export function createMemoryInvocationAuthorityCustodyV2() {
    const values = new Map();
    return {
        custody: 'protected',
        durable: false,
        testOnly: true,
        async put(input) {
            values.set(authorityKey(input.tenantId, input.admissionId), frozenCopy(input.authority));
        },
        async get(input) {
            return values.get(authorityKey(input.tenantId, input.admissionId)) ?? null;
        },
        async delete(input) {
            values.delete(authorityKey(input.tenantId, input.admissionId));
        },
    };
}
function isRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        return false;
    }
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function validString(value) {
    return typeof value === 'string' && value.length > 0 && value.length <= 512;
}
function validDigest(value) {
    return typeof value === 'string' && DIGEST.test(value);
}
function validInstant(value) {
    return typeof value === 'string' && Number.isFinite(Date.parse(value));
}
function clone(value) {
    return structuredClone(value);
}
function deepFreeze(value) {
    if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
        for (const child of Object.values(value))
            deepFreeze(child);
        Object.freeze(value);
    }
    return value;
}
function frozenCopy(value) {
    return deepFreeze(clone(value));
}
function deeplyFrozen(value, seen = new WeakSet()) {
    if (value === null || typeof value !== 'object')
        return true;
    if (seen.has(value))
        return true;
    seen.add(value);
    if (!Object.isFrozen(value))
        return false;
    return Object.values(value).every((child) => deeplyFrozen(child, seen));
}
function addReason(reasons, reason) {
    if (!reasons.includes(reason))
        reasons.push(reason);
}
function canonicalSnapshot(value) {
    if (!isRecord(value) || !isRecord(value.body)
        || !validDigest(value.snapshot_digest))
        return { ok: false };
    try {
        const normalized = createAdmissionSnapshot(value.body);
        if (normalized.snapshot_digest !== value.snapshot_digest) {
            return { ok: false };
        }
        return { ok: true, snapshot: normalized };
    }
    catch {
        return { ok: false };
    }
}
function actuationKey(snapshot) {
    return JSON.stringify([
        snapshot.body.tenant_id,
        snapshot.body.operation_id,
    ]);
}
function rolePayloads(snapshot, role) {
    return snapshot.body.inputs
        .filter((entry) => entry.role === role)
        .map((entry) => entry.payload_digest);
}
function sameDigests(left, right) {
    if (left.length !== right.length)
        return false;
    const a = [...left].sort();
    const b = [...right].sort();
    return a.every((value, index) => value === b[index]);
}
function boundedReason(value) {
    return validString(value) ? value : 'unspecified';
}
function validateQualification(qualification, snapshot, reasons) {
    if (!isRecord(qualification)) {
        addReason(reasons, 'qualification_result_invalid');
        return;
    }
    if (qualification.decision !== 'QUALIFIED') {
        addReason(reasons, `qualification_not_qualified:${boundedReason(qualification.reason)}`);
    }
    if (qualification.verification !== 'VERIFIED') {
        addReason(reasons, 'qualification_not_verified');
    }
    if (qualification.acceptance !== 'ACCEPTED') {
        addReason(reasons, 'qualification_not_accepted');
    }
    if (qualification.candidate_match !== 'EXACT_MATCH') {
        addReason(reasons, 'qualification_candidate_mismatch');
    }
    if (qualification.assignment_scope !== 'IN_SCOPE') {
        addReason(reasons, 'qualification_assignment_out_of_scope');
    }
    if (qualification.currentness !== 'CURRENT_AS_OBSERVED') {
        addReason(reasons, 'qualification_not_current');
    }
    if (qualification.campaign_graph !== 'COMPLETE') {
        addReason(reasons, 'qualification_campaign_incomplete');
    }
    if (typeof qualification.remeasure_at_begin_invocation !== 'boolean') {
        addReason(reasons, 'qualification_remeasurement_invalid');
    }
    const qualificationChecks = qualification.checks;
    if (!isRecord(qualificationChecks)
        || REQUIRED_QUALIFICATION_CHECKS.some((check) => qualificationChecks[check] !== true)) {
        addReason(reasons, 'qualification_checks_incomplete');
    }
    const payloads = qualification.payload_digests;
    if (!isRecord(payloads)) {
        addReason(reasons, 'qualification_payload_digests_invalid');
        return;
    }
    if (payloads.candidate_manifest !== snapshot.body.candidate_manifest_digest) {
        addReason(reasons, 'qualification_candidate_manifest_binding_mismatch');
    }
    if (payloads.runtime_measurement !== snapshot.body.runtime_measurement_digest) {
        addReason(reasons, 'qualification_runtime_measurement_binding_mismatch');
    }
    if (payloads.protected_request_digest
        !== snapshot.body.effect_request_digest) {
        addReason(reasons, 'qualification_protected_request_binding_mismatch');
    }
    if (payloads.qualification_statement
        !== snapshot.body.qualification_statement_payload_digest) {
        addReason(reasons, 'qualification_statement_binding_mismatch');
    }
    if (payloads.qualification_status_head
        !== snapshot.body.qualification_status.head_payload_digest) {
        addReason(reasons, 'qualification_status_binding_mismatch');
    }
    if (!validDigest(payloads.campaign_head)
        || !validDigest(payloads.qualification_graph)) {
        addReason(reasons, 'qualification_graph_binding_invalid');
    }
}
function validateRequirement(name, leg, snapshot, reasons) {
    if (!isRecord(leg)) {
        addReason(reasons, `${name}_missing`);
        return;
    }
    if (leg.decision !== 'allow')
        addReason(reasons, `${name}_denied`);
    if (!validString(leg.requirementId)) {
        addReason(reasons, `${name}_requirement_missing`);
    }
    if (leg.caid !== snapshot.body.caid
        || leg.actionDigest !== snapshot.body.action_digest) {
        addReason(reasons, `${name}_binding_mismatch`);
    }
    if (!validDigest(leg.evidenceDigest)) {
        addReason(reasons, `${name}_evidence_invalid`);
    }
    else if (!sameDigests(rolePayloads(snapshot, name), [leg.evidenceDigest])) {
        addReason(reasons, `${name}_snapshot_binding_mismatch`);
    }
}
function validateLocalPolicy(leg, snapshot, reasons) {
    if (!isRecord(leg)) {
        addReason(reasons, 'localPolicy_missing');
        return;
    }
    if (leg.decision !== 'allow')
        addReason(reasons, 'localPolicy_denied');
    if (!validString(leg.policyId)) {
        addReason(reasons, 'localPolicy_policy_missing');
    }
    if (leg.caid !== snapshot.body.caid
        || leg.actionDigest !== snapshot.body.action_digest) {
        addReason(reasons, 'localPolicy_binding_mismatch');
    }
    if (!validDigest(leg.evidenceDigest)) {
        addReason(reasons, 'localPolicy_evidence_invalid');
    }
    else if (!sameDigests(rolePayloads(snapshot, 'local_policy'), [leg.evidenceDigest])) {
        addReason(reasons, 'localPolicy_snapshot_binding_mismatch');
    }
}
function validateSnapshotBindings(snapshot, reasons) {
    const body = snapshot.body;
    const singletonBindings = [
        ['candidate_manifest', body.candidate_manifest_digest],
        ['runtime_measurement', body.runtime_measurement_digest],
        ['qualification_statement', body.qualification_statement_payload_digest],
        ['qualification_status', body.qualification_status.head_payload_digest],
    ];
    for (const [role, expected] of singletonBindings) {
        if (!sameDigests(rolePayloads(snapshot, role), [expected])) {
            addReason(reasons, `snapshot_${role}_binding_mismatch`);
        }
    }
    if (!sameDigests(rolePayloads(snapshot, 'test_result'), body.test_result_payload_digests))
        addReason(reasons, 'snapshot_test_result_binding_mismatch');
    if (!sameDigests(rolePayloads(snapshot, 'agent_evaluation_evidence'), body.agent_evaluation_evidence_payload_digests))
        addReason(reasons, 'snapshot_agent_evidence_binding_mismatch');
    if (body.candidate_custody.request_construction !== 'EXECUTOR_ADAPTER'
        || body.candidate_custody.mutation_credential_custody
            !== 'EXECUTOR_ADAPTER') {
        addReason(reasons, 'snapshot_adapter_custody_mismatch');
    }
    const providerOperations = body.resource_reservations.filter((resource) => resource.kind === 'provider_operation'
        && resource.resource_id === body.operation_id);
    if (providerOperations.length !== 1) {
        addReason(reasons, 'snapshot_provider_operation_binding_mismatch');
    }
    if (body.supersedes_admission_id !== null) {
        addReason(reasons, 'supersession_requires_atomic_store_transition');
    }
    if (body.remedy_for !== null) {
        if (body.remedy_for.admission_id === body.admission_id) {
            addReason(reasons, 'remedy_requires_new_admission');
        }
        if (body.remedy_for.operation_id === body.operation_id) {
            addReason(reasons, 'remedy_requires_new_operation');
        }
    }
}
function emptyDecision(reasons) {
    return deepFreeze({
        version: GATE_QUALIFICATION_V2_VERSION,
        allow: false,
        reasons: deepFreeze([...reasons]),
        tenantId: '',
        admissionId: '',
        operationId: '',
        caid: '',
        actionDigest: '',
        snapshotDigest: '',
        effectKey: '',
        requirements: deepFreeze({
            qualificationEvidenceDigest: '',
            aebRequirementId: '',
            aebEvidenceDigest: '',
            aecRequirementId: '',
            aecEvidenceDigest: '',
            localPolicyId: '',
            localPolicyEvidenceDigest: '',
        }),
    });
}
function composeCanonical(snapshot, qualification) {
    const reasons = [];
    validateSnapshotBindings(snapshot, reasons);
    validateQualification(qualification?.qualification, snapshot, reasons);
    validateRequirement('aeb', qualification?.aeb, snapshot, reasons);
    validateRequirement('aec', qualification?.aec, snapshot, reasons);
    validateLocalPolicy(qualification?.localPolicy, snapshot, reasons);
    return deepFreeze({
        version: GATE_QUALIFICATION_V2_VERSION,
        allow: reasons.length === 0,
        reasons: deepFreeze([...reasons]),
        tenantId: snapshot.body.tenant_id,
        admissionId: snapshot.body.admission_id,
        operationId: snapshot.body.operation_id,
        caid: snapshot.body.caid,
        actionDigest: snapshot.body.action_digest,
        snapshotDigest: snapshot.snapshot_digest,
        effectKey: actuationKey(snapshot),
        requirements: deepFreeze({
            qualificationEvidenceDigest: snapshot.body.qualification_statement_payload_digest,
            aebRequirementId: qualification?.aeb?.requirementId ?? '',
            aebEvidenceDigest: qualification?.aeb?.evidenceDigest ?? '',
            aecRequirementId: qualification?.aec?.requirementId ?? '',
            aecEvidenceDigest: qualification?.aec?.evidenceDigest ?? '',
            localPolicyId: qualification?.localPolicy?.policyId ?? '',
            localPolicyEvidenceDigest: qualification?.localPolicy?.evidenceDigest ?? '',
        }),
    });
}
/** Pure deterministic composition; it performs no store or adapter access. */
export function composeQualificationDecisionV2(input) {
    const checked = canonicalSnapshot(input?.snapshot);
    if (!checked.ok)
        return emptyDecision(['admission_snapshot_invalid']);
    return composeCanonical(checked.snapshot, input?.qualification);
}
function verifyStoreCapabilities(store, testOnly) {
    if (!store || store.atomic !== true || store.compareAndSwap !== true
        || store.appendOnlyJournal !== true
        || store.exclusiveActuation !== true) {
        throw new TypeError('Gate Qualification v2 requires an atomic, compare-and-swap, '
            + 'append-only, exclusive AdmissionStore');
    }
    if (store.transactionalCurrentness !== true) {
        throw new TypeError('Gate Qualification v2 requires a transactional-currentness AdmissionStore');
    }
    const candidate = store;
    for (const method of [
        'reserve',
        'release',
        'beginInvocation',
        'recoverIndeterminate',
        'recordProviderOutcome',
        'recordEffectRelation',
        'read',
        'readByOperation',
        'readSnapshot',
    ]) {
        if (typeof candidate[method] !== 'function') {
            throw new TypeError(`Gate Qualification v2 AdmissionStore requires ${method}()`);
        }
    }
    if (testOnly) {
        if (store.testOnly !== true) {
            throw new TypeError('Gate Qualification v2 testOnly requires an explicit test store');
        }
    }
    else if (store.durable !== true || store.testOnly === true) {
        throw new TypeError('Gate Qualification v2 production mode requires a durable AdmissionStore');
    }
}
function protectedInvocation(snapshot, invocationToken) {
    return deepFreeze({ snapshot, invocationToken });
}
function providerEvidenceBindingValid(evidence, snapshot) {
    const body = snapshot.body;
    return isRecord(evidence)
        && validString(evidence.evidenceId)
        && validDigest(evidence.evidenceDigest)
        && evidence.tenantId === body.tenant_id
        && evidence.admissionId === body.admission_id
        && evidence.operationId === body.operation_id
        && evidence.snapshotDigest === snapshot.snapshot_digest
        && evidence.caid === body.caid
        && evidence.actionDigest === body.action_digest
        && evidence.effectRequestDigest === body.effect_request_digest
        && isRecord(evidence.provider)
        && evidence.provider.provider_id === body.provider.provider_id
        && evidence.provider.account_id === body.provider.account_id
        && evidence.provider.environment === body.provider.environment
        && evidence.executorAdapterDigest === body.executor_adapter_digest
        && evidence.idempotencyKey === body.idempotency_key
        && ['COMMITTED', 'PROVEN_NOT_COMMITTED', 'INDETERMINATE'].includes(evidence.outcome)
        && validInstant(evidence.observedAt);
}
function observedRelationBindingValid(relation, evidence, snapshot) {
    const body = snapshot.body;
    if (!isRecord(relation)
        || !['OBSERVED_AS_REQUESTED', 'DIVERGED', 'INDETERMINATE'].includes(relation.relation)
        || relation.tenantId !== body.tenant_id
        || relation.admissionId !== body.admission_id
        || relation.operationId !== body.operation_id
        || relation.snapshotDigest !== snapshot.snapshot_digest
        || relation.caid !== body.caid
        || relation.actionDigest !== body.action_digest
        || relation.providerEvidenceDigest !== evidence.evidenceDigest
        || !validInstant(relation.observedAt)
        || (relation.evidenceDigest !== null
            && !validDigest(relation.evidenceDigest))
        || (relation.observedEffectDigest !== null
            && !validDigest(relation.observedEffectDigest)))
        return false;
    if (relation.relation === 'INDETERMINATE')
        return true;
    return validDigest(relation.evidenceDigest)
        && validDigest(relation.observedEffectDigest);
}
class AdapterTimeoutError extends Error {
    constructor() {
        super('protected adapter timed out');
        this.name = 'AdapterTimeoutError';
    }
}
async function withinTimeout(operation, timeoutMs) {
    let timer;
    try {
        return await Promise.race([
            Promise.resolve().then(operation),
            new Promise((_resolve, reject) => {
                timer = setTimeout(() => reject(new AdapterTimeoutError()), timeoutMs);
            }),
        ]);
    }
    finally {
        if (timer !== undefined)
            clearTimeout(timer);
    }
}
function reference(snapshot) {
    return {
        tenant_id: snapshot.body.tenant_id,
        admission_id: snapshot.body.admission_id,
    };
}
function authorityKey(tenantId, admissionId) {
    return JSON.stringify([tenantId, admissionId]);
}
function reconciliationRequired(admissionId, reason) {
    return deepFreeze({ status: 'reconciliation_required', reason, admissionId });
}
export class GateQualificationV2 {
    mode;
    #store;
    #adapter;
    #evidenceVerifier;
    #effectRelator;
    #remeasurer;
    #authorityCustody;
    #legacy;
    #adapterTimeoutMs;
    constructor(options) {
        if (!options || !['enforce', 'shadow'].includes(options.mode)) {
            throw new TypeError('Gate Qualification v2 mode must be enforce or shadow');
        }
        if (options.mode === 'shadow') {
            if ('admissionStore' in options || 'protectedAdapter' in options
                || 'providerEvidenceVerifier' in options
                || 'observedEffectRelator' in options
                || 'invocationRemeasurer' in options
                || 'authorityCustody' in options) {
                throw new TypeError('Gate Qualification v2 shadow mode accepts no AdmissionStore or protected adapter');
            }
            if (options.legacyQualification
                && typeof options.legacyQualification.qualify !== 'function') {
                throw new TypeError('Gate Qualification v2 legacy qualification must expose qualify()');
            }
            this.mode = 'shadow';
            this.#legacy = options.legacyQualification;
            this.#adapterTimeoutMs = DEFAULT_ADAPTER_TIMEOUT_MS;
            return;
        }
        verifyStoreCapabilities(options.admissionStore, options.testOnly === true);
        if (!options.protectedAdapter
            || options.protectedAdapter.custody !== 'protected'
            || options.protectedAdapter.credentialsExposed !== false
            || typeof options.protectedAdapter.invoke !== 'function'
            || typeof options.protectedAdapter.reconcile !== 'function') {
            throw new TypeError('Gate Qualification v2 requires protected adapter custody');
        }
        if (!options.providerEvidenceVerifier
            || typeof options.providerEvidenceVerifier.verify !== 'function') {
            throw new TypeError('Gate Qualification v2 requires a provider evidence verifier');
        }
        if (!options.observedEffectRelator
            || typeof options.observedEffectRelator.relate !== 'function') {
            throw new TypeError('Gate Qualification v2 requires an observed-effect relator');
        }
        if (!options.invocationRemeasurer
            || options.invocationRemeasurer.source !== 'authoritative'
            || typeof options.invocationRemeasurer.remeasure !== 'function') {
            throw new TypeError('Gate Qualification v2 requires authoritative invocation remeasurement');
        }
        if (!options.authorityCustody
            || options.authorityCustody.custody !== 'protected'
            || typeof options.authorityCustody.put !== 'function'
            || typeof options.authorityCustody.get !== 'function'
            || typeof options.authorityCustody.delete !== 'function') {
            throw new TypeError('Gate Qualification v2 requires protected invocation-authority custody');
        }
        if (options.testOnly === true) {
            if (options.authorityCustody.testOnly !== true) {
                throw new TypeError('Gate Qualification v2 testOnly requires explicit test authority custody');
            }
        }
        else if (options.authorityCustody.durable !== true
            || options.authorityCustody.testOnly === true) {
            throw new TypeError('Gate Qualification v2 production mode requires durable authority custody');
        }
        const timeout = options.adapterTimeoutMs ?? DEFAULT_ADAPTER_TIMEOUT_MS;
        if (!Number.isSafeInteger(timeout) || timeout < 1
            || timeout > MAX_ADAPTER_TIMEOUT_MS) {
            throw new TypeError('Gate Qualification v2 adapterTimeoutMs is invalid');
        }
        this.mode = 'enforce';
        this.#store = options.admissionStore;
        this.#adapter = options.protectedAdapter;
        this.#evidenceVerifier = options.providerEvidenceVerifier;
        this.#effectRelator = options.observedEffectRelator;
        this.#remeasurer = options.invocationRemeasurer;
        this.#authorityCustody = options.authorityCustody;
        this.#adapterTimeoutMs = timeout;
    }
    async #shadow(input, decision) {
        let legacyAllowed = null;
        let legacyReasons = [];
        if (this.#legacy) {
            try {
                const legacy = await this.#legacy.qualify(frozenCopy(input));
                legacyAllowed = legacy.allow === true;
                legacyReasons = deepFreeze([...legacy.reasons]);
            }
            catch {
                legacyAllowed = false;
                legacyReasons = deepFreeze(['legacy_qualification_failed']);
            }
        }
        return deepFreeze({
            status: 'shadow',
            decision,
            comparison: {
                legacyAllowed,
                v2Allowed: decision.allow,
                match: legacyAllowed === null
                    ? null
                    : legacyAllowed === decision.allow,
                legacyReasons,
                v2Reasons: decision.reasons,
            },
        });
    }
    async #saveAuthority(snapshot, authority) {
        await this.#authorityCustody.put({
            tenantId: snapshot.body.tenant_id,
            admissionId: snapshot.body.admission_id,
            authority: frozenCopy(authority),
        });
    }
    async #getAuthority(tenantId, admissionId) {
        return this.#authorityCustody.get({ tenantId, admissionId });
    }
    async #recordIndeterminateEffect(snapshot, authority, expectedRevision) {
        try {
            const recorded = await this.#store.recordEffectRelation({
                ...reference(snapshot),
                expected_revision: expectedRevision,
                owner_token: authority.ownerToken,
                invocation_token: authority.invocationToken,
                value: 'INDETERMINATE',
                evidence_digest: null,
                observed_at: new Date().toISOString(),
            });
            return recorded.ok ? recorded.record : null;
        }
        catch {
            return null;
        }
    }
    async #recoverInvoking(snapshot, ownerToken) {
        try {
            const recovered = await this.#store.recoverIndeterminate({
                ...reference(snapshot),
                owner_token: ownerToken,
            });
            if (!recovered.ok)
                return null;
            const authority = {
                ownerToken,
                invocationToken: recovered.reconciliation_token,
                snapshotDigest: snapshot.snapshot_digest,
            };
            await this.#saveAuthority(snapshot, authority);
            await this.#recordIndeterminateEffect(snapshot, authority, recovered.record.revision);
            return authority;
        }
        catch {
            return null;
        }
    }
    async #beginAmbiguity(snapshot, ownerToken) {
        let record;
        try {
            record = await this.#store.read(reference(snapshot));
        }
        catch {
            return reconciliationRequired(snapshot.body.admission_id, 'begin_invocation_read_ambiguous');
        }
        if (!record) {
            return reconciliationRequired(snapshot.body.admission_id, 'begin_invocation_read_ambiguous');
        }
        if (record.state === 'INVOKING') {
            await this.#recoverInvoking(snapshot, ownerToken);
        }
        return reconciliationRequired(snapshot.body.admission_id, 'begin_invocation_unconfirmed');
    }
    async #existingAdmissionResult(snapshot, storeReason, decision) {
        if (storeReason !== 'admission_exists') {
            return deepFreeze({ status: 'refused', reason: storeReason, decision });
        }
        try {
            const record = await this.#store.read(reference(snapshot));
            if (record && (record.state === 'RESERVED'
                || record.state === 'INVOKING'
                || record.state === 'INDETERMINATE')) {
                return reconciliationRequired(record.admission_id, storeReason);
            }
        }
        catch {
            return reconciliationRequired(snapshot.body.admission_id, 'admission_read_ambiguous');
        }
        return deepFreeze({ status: 'refused', reason: storeReason, decision });
    }
    async #verifyProviderEvidence(rawEvidence, snapshot) {
        let verification;
        try {
            verification = await withinTimeout(() => this.#evidenceVerifier.verify(rawEvidence, snapshot), this.#adapterTimeoutMs);
        }
        catch {
            return { ok: false, reason: 'provider_evidence_verification_failed' };
        }
        if (!verification.ok) {
            return {
                ok: false,
                reason: `provider_evidence_verification_failed:${verification.reason}`,
            };
        }
        const evidence = frozenCopy(verification.evidence);
        if (!providerEvidenceBindingValid(evidence, snapshot)) {
            return { ok: false, reason: 'provider_evidence_binding_mismatch' };
        }
        return { ok: true, evidence };
    }
    async #relateEffect(evidence, snapshot) {
        let relation;
        try {
            relation = frozenCopy(await withinTimeout(() => this.#effectRelator.relate(evidence, snapshot), this.#adapterTimeoutMs));
        }
        catch {
            return { ok: false, reason: 'observed_effect_relation_failed' };
        }
        if (!observedRelationBindingValid(relation, evidence, snapshot)) {
            return { ok: false, reason: 'observed_effect_relation_mismatch' };
        }
        return { ok: true, relation };
    }
    async #processEvidence(rawEvidence, snapshot, authority, record) {
        const verified = await this.#verifyProviderEvidence(rawEvidence, snapshot);
        if (!verified.ok) {
            if (record.state === 'INVOKING') {
                await this.#recoverInvoking(snapshot, authority.ownerToken);
            }
            return reconciliationRequired(snapshot.body.admission_id, verified.reason);
        }
        let providerRecord;
        const currentProvider = record.provider_outcome;
        if (currentProvider && currentProvider.value !== 'INDETERMINATE') {
            if (currentProvider.value !== verified.evidence.outcome
                || currentProvider.evidence_digest
                    !== verified.evidence.evidenceDigest) {
                return reconciliationRequired(snapshot.body.admission_id, 'provider_outcome_conflict');
            }
            providerRecord = record;
        }
        else if (currentProvider?.value === 'INDETERMINATE'
            && verified.evidence.outcome === 'INDETERMINATE') {
            providerRecord = record;
        }
        else {
            try {
                const recorded = await this.#store.recordProviderOutcome({
                    ...reference(snapshot),
                    expected_revision: record.revision,
                    owner_token: authority.ownerToken,
                    invocation_token: authority.invocationToken,
                    value: verified.evidence.outcome,
                    evidence_digest: verified.evidence.evidenceDigest,
                    observed_at: verified.evidence.observedAt,
                });
                if (!recorded.ok) {
                    return reconciliationRequired(snapshot.body.admission_id, `provider_outcome_unconfirmed:${recorded.reason}`);
                }
                providerRecord = recorded.record;
            }
            catch {
                return reconciliationRequired(snapshot.body.admission_id, 'provider_outcome_unconfirmed');
            }
        }
        const related = await this.#relateEffect(verified.evidence, snapshot);
        if (!related.ok) {
            await this.#recordIndeterminateEffect(snapshot, authority, providerRecord.revision);
            return reconciliationRequired(snapshot.body.admission_id, related.reason);
        }
        let effectRecord;
        const currentEffect = providerRecord.effect_relation;
        if (currentEffect && currentEffect.value !== 'INDETERMINATE') {
            if (currentEffect.value !== related.relation.relation
                || currentEffect.evidence_digest !== related.relation.evidenceDigest) {
                return reconciliationRequired(snapshot.body.admission_id, 'effect_relation_conflict');
            }
            effectRecord = providerRecord;
        }
        else if (currentEffect?.value === 'INDETERMINATE'
            && related.relation.relation === 'INDETERMINATE') {
            effectRecord = providerRecord;
        }
        else {
            try {
                const recorded = await this.#store.recordEffectRelation({
                    ...reference(snapshot),
                    expected_revision: providerRecord.revision,
                    owner_token: authority.ownerToken,
                    invocation_token: authority.invocationToken,
                    value: related.relation.relation,
                    evidence_digest: related.relation.evidenceDigest,
                    observed_at: related.relation.observedAt,
                });
                if (!recorded.ok) {
                    return reconciliationRequired(snapshot.body.admission_id, `effect_relation_unconfirmed:${recorded.reason}`);
                }
                effectRecord = recorded.record;
            }
            catch {
                return reconciliationRequired(snapshot.body.admission_id, 'effect_relation_unconfirmed');
            }
        }
        if (verified.evidence.outcome === 'INDETERMINATE'
            || related.relation.relation === 'INDETERMINATE'
            || effectRecord.provider_outcome?.value === 'INDETERMINATE'
            || effectRecord.effect_relation?.value === 'INDETERMINATE') {
            return reconciliationRequired(snapshot.body.admission_id, 'provider_or_effect_indeterminate');
        }
        await this.#authorityCustody.delete({
            tenantId: snapshot.body.tenant_id,
            admissionId: snapshot.body.admission_id,
        });
        return deepFreeze({
            status: verified.evidence.outcome === 'COMMITTED'
                ? 'committed'
                : 'not_committed',
            admissionId: snapshot.body.admission_id,
            evidence: verified.evidence,
            relation: related.relation,
        });
    }
    async execute(input) {
        const checked = canonicalSnapshot(input?.snapshot);
        const decision = checked.ok
            ? composeCanonical(checked.snapshot, input?.qualification)
            : emptyDecision(['admission_snapshot_invalid']);
        if (this.mode === 'shadow')
            return this.#shadow(input, decision);
        if (!checked.ok || !decision.allow) {
            return deepFreeze({
                status: 'refused',
                reason: decision.reasons[0] ?? 'qualification_refused',
                decision,
            });
        }
        const snapshot = checked.snapshot;
        let reserved;
        try {
            reserved = await this.#store.reserve(snapshot);
        }
        catch {
            return deepFreeze({
                status: 'refused',
                reason: 'admission_reserve_failed',
                decision,
            });
        }
        if (!reserved.ok) {
            return this.#existingAdmissionResult(snapshot, reserved.reason, decision);
        }
        const reservedSnapshot = canonicalSnapshot(reserved.snapshot);
        if (!reservedSnapshot.ok || !deeplyFrozen(reserved.snapshot)
            || reserved.snapshot.snapshot_digest !== snapshot.snapshot_digest
            || reserved.record.snapshot_digest !== snapshot.snapshot_digest) {
            try {
                await this.#store.release({
                    ...reference(snapshot),
                    expected_revision: reserved.record.revision,
                    owner_token: reserved.owner_token,
                }, 'reserve_snapshot_mismatch');
            }
            catch {
                // No provider entry occurred; the reservation remains closed.
            }
            return deepFreeze({
                status: 'refused',
                reason: 'reserve_snapshot_mismatch',
                decision,
            });
        }
        // Reread the candidate, qualification status, AEB, AEC, local policy and
        // protected-request binding from authoritative sources immediately before
        // the store's transactional currentness check consumes execution rights.
        // The caller-supplied decision is never reused across this boundary.
        let refreshedBundle;
        try {
            refreshedBundle = await withinTimeout(() => this.#remeasurer.remeasure(reserved.snapshot), this.#adapterTimeoutMs);
        }
        catch {
            try {
                await this.#store.release({
                    ...reference(reserved.snapshot),
                    expected_revision: reserved.record.revision,
                    owner_token: reserved.owner_token,
                }, 'invocation_remeasurement_failed');
            }
            catch {
                // No execution right was consumed and no provider entry occurred.
            }
            return deepFreeze({
                status: 'refused',
                reason: 'invocation_remeasurement_failed',
                decision,
            });
        }
        const refreshedDecision = composeCanonical(reserved.snapshot, frozenCopy(refreshedBundle));
        if (!refreshedDecision.allow) {
            try {
                await this.#store.release({
                    ...reference(reserved.snapshot),
                    expected_revision: reserved.record.revision,
                    owner_token: reserved.owner_token,
                }, 'invocation_remeasurement_refused');
            }
            catch {
                // No execution right was consumed and no provider entry occurred.
            }
            return deepFreeze({
                status: 'refused',
                reason: refreshedDecision.reasons[0]
                    ?? 'invocation_remeasurement_refused',
                decision: refreshedDecision,
            });
        }
        let begun;
        try {
            begun = await this.#store.beginInvocation({
                ...reference(reserved.snapshot),
                expected_revision: reserved.record.revision,
                owner_token: reserved.owner_token,
            });
        }
        catch {
            return this.#beginAmbiguity(reserved.snapshot, reserved.owner_token);
        }
        if (!begun.ok) {
            if (begun.reason === 'state_conflict'
                || begun.reason === 'revision_conflict') {
                return this.#beginAmbiguity(reserved.snapshot, reserved.owner_token);
            }
            return deepFreeze({
                status: 'refused',
                reason: begun.reason,
                decision,
            });
        }
        const begunSnapshot = canonicalSnapshot(begun.snapshot);
        if (!begunSnapshot.ok || !deeplyFrozen(begun.snapshot)
            || begun.snapshot.snapshot_digest !== reserved.snapshot.snapshot_digest
            || begun.record.snapshot_digest !== begun.snapshot.snapshot_digest
            || begun.record.state !== 'INVOKING'
            || begun.record.execution_right !== 'CONSUMED'
            || begun.record.resources.some((resource) => resource.state !== 'CONSUMED')) {
            await this.#recoverInvoking(begun.snapshot, reserved.owner_token);
            return reconciliationRequired(reserved.snapshot.body.admission_id, 'begin_invocation_snapshot_mismatch');
        }
        const authority = {
            ownerToken: reserved.owner_token,
            invocationToken: begun.invocation_token,
            snapshotDigest: begun.snapshot.snapshot_digest,
        };
        try {
            await this.#saveAuthority(begun.snapshot, authority);
        }
        catch {
            await this.#recoverInvoking(begun.snapshot, reserved.owner_token);
            return reconciliationRequired(begun.snapshot.body.admission_id, 'invocation_authority_custody_failed');
        }
        const adapterInput = protectedInvocation(begun.snapshot, begun.invocation_token);
        let rawEvidence;
        try {
            rawEvidence = await withinTimeout(() => this.#adapter.invoke(adapterInput), this.#adapterTimeoutMs);
        }
        catch (error) {
            await this.#recoverInvoking(begun.snapshot, authority.ownerToken);
            return reconciliationRequired(begun.snapshot.body.admission_id, error instanceof AdapterTimeoutError
                ? 'provider_invocation_timed_out'
                : 'provider_invocation_outcome_unknown');
        }
        return this.#processEvidence(rawEvidence, begun.snapshot, authority, begun.record);
    }
    /** Evidence-only reconciliation. This method has no mutation-adapter path. */
    async reconcile(input) {
        if (this.mode !== 'enforce') {
            return deepFreeze({
                status: 'refused',
                reason: 'reconciliation_unavailable_in_shadow',
            });
        }
        if (!input || !validString(input.tenant_id)
            || !validString(input.admission_id)) {
            return deepFreeze({ status: 'refused', reason: 'admission_reference_invalid' });
        }
        let record;
        try {
            record = await this.#store.read(input);
        }
        catch {
            return reconciliationRequired(input.admission_id, 'admission_read_ambiguous');
        }
        if (!record) {
            return deepFreeze({ status: 'refused', reason: 'admission_not_found' });
        }
        if (record.execution_right !== 'CONSUMED') {
            return deepFreeze({
                status: 'refused',
                reason: 'reconciliation_not_required',
            });
        }
        let snapshot;
        try {
            snapshot = await this.#store.readSnapshot(record.snapshot_digest);
        }
        catch {
            return reconciliationRequired(input.admission_id, 'admission_snapshot_read_ambiguous');
        }
        const checked = canonicalSnapshot(snapshot);
        if (!snapshot || !checked.ok || !deeplyFrozen(snapshot)
            || snapshot.snapshot_digest !== record.snapshot_digest) {
            return reconciliationRequired(input.admission_id, 'admission_snapshot_read_ambiguous');
        }
        let authority;
        try {
            authority = await this.#getAuthority(input.tenant_id, input.admission_id);
        }
        catch {
            return reconciliationRequired(input.admission_id, 'reconciliation_authority_unavailable');
        }
        if (!authority || authority.snapshotDigest !== snapshot.snapshot_digest) {
            return reconciliationRequired(input.admission_id, 'reconciliation_authority_unavailable');
        }
        if (record.state === 'INVOKING') {
            const recovered = await this.#recoverInvoking(snapshot, authority.ownerToken);
            if (!recovered) {
                return reconciliationRequired(input.admission_id, 'recovery_unconfirmed');
            }
            authority = recovered;
            try {
                record = await this.#store.read(input);
            }
            catch {
                return reconciliationRequired(input.admission_id, 'admission_read_ambiguous');
            }
            if (!record) {
                return reconciliationRequired(input.admission_id, 'admission_read_ambiguous');
            }
        }
        const providerUnresolved = !record.provider_outcome
            || record.provider_outcome.value === 'INDETERMINATE';
        const effectUnresolved = !record.effect_relation
            || record.effect_relation.value === 'INDETERMINATE';
        if (!providerUnresolved && !effectUnresolved) {
            return deepFreeze({
                status: 'refused',
                reason: 'reconciliation_not_required',
            });
        }
        const base = protectedInvocation(snapshot, authority.invocationToken);
        let rawEvidence;
        try {
            rawEvidence = await withinTimeout(() => this.#adapter.reconcile(deepFreeze({
                ...base,
                reconciliationOnly: true,
            })), this.#adapterTimeoutMs);
        }
        catch (error) {
            return reconciliationRequired(input.admission_id, error instanceof AdapterTimeoutError
                ? 'provider_reconciliation_timed_out'
                : 'provider_reconciliation_failed');
        }
        return this.#processEvidence(rawEvidence, snapshot, authority, record);
    }
}
export default {
    GATE_QUALIFICATION_V2_VERSION,
    composeQualificationDecisionV2,
    GateQualificationV2,
};
//# sourceMappingURL=gate-qualification-v2.js.map