// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Gate Qualification v2 admission custody.
 *
 * The immutable snapshot is the complete input to one consequential operation.
 * Mutable lifecycle state lives in a separately CAS-owned record and every
 * accepted transition is chained into an append-only journal.  The in-memory
 * implementation is a linearizable reference for conformance and crash-model
 * tests; it is deliberately not a durability claim.
 */
import crypto from 'node:crypto';
export const ADMISSION_SNAPSHOT_VERSION = 'EP-GATE-ADMISSION-SNAPSHOT-v2';
export const ADMISSION_RECORD_VERSION = 'EP-GATE-ADMISSION-RECORD-v2';
export const ADMISSION_JOURNAL_VERSION = 'EP-GATE-ADMISSION-JOURNAL-v2';
export const ADMISSION_CURRENTNESS_VERSION = 'EP-GATE-ADMISSION-CURRENTNESS-v2';
export const ADMISSION_LIMITS = Object.freeze({
    inputs: 128,
    resources: 64,
    testResults: 64,
    agentEvidence: 32,
    identifierBytes: 512,
    currentnessMaxAgeMs: 5_000,
});
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const CAID = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{0,511}$/;
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const OWNER_TOKEN = /^admission-owner:v2:[A-Za-z0-9_-]{32,128}$/;
const REQUIRED_SINGLETON_ROLES = Object.freeze([
    'candidate_manifest',
    'runtime_measurement',
    'qualification_statement',
    'qualification_status',
    'aeb',
    'aec',
    'local_policy',
    'authorization',
]);
const REPEATABLE_ROLES = new Set([
    'test_result',
    'agent_evaluation_evidence',
]);
const ROLE_ORDER = new Map([
    'candidate_manifest', 'runtime_measurement', 'test_result',
    'agent_evaluation_evidence', 'qualification_statement',
    'qualification_status', 'aeb', 'aec', 'local_policy', 'authorization',
].map((role, index) => [role, index]));
export class AdmissionStoreValidationError extends TypeError {
    code;
    constructor(code, message) {
        super(message);
        this.name = 'AdmissionStoreValidationError';
        this.code = code;
    }
}
function fail(code, message) {
    throw new AdmissionStoreValidationError(code, message);
}
function plain(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
}
function canonical(value) {
    if (value === null || typeof value === 'boolean' || typeof value === 'string')
        return JSON.stringify(value);
    if (typeof value === 'number') {
        if (!Number.isFinite(value))
            fail('invalid_json', 'non-finite JSON number');
        return JSON.stringify(value);
    }
    if (Array.isArray(value))
        return `[${value.map((item) => canonical(item)).join(',')}]`;
    if (!plain(value))
        fail('invalid_json', 'non-plain JSON object');
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}
function hash(domain, value) {
    return `sha256:${crypto.createHash('sha256').update(domain).update('\0').update(canonical(value)).digest('hex')}`;
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
    return deepFreeze(structuredClone(value));
}
function identifier(value, field) {
    if (typeof value !== 'string' || !IDENTIFIER.test(value))
        fail('invalid_identifier', `${field} is invalid`);
    return value;
}
function digest(value, field) {
    if (typeof value !== 'string' || !SHA256.test(value))
        fail('invalid_digest', `${field} is invalid`);
    return value;
}
function instant(value, field) {
    if (typeof value !== 'string' || !RFC3339.test(value))
        fail('invalid_instant', `${field} must be RFC 3339`);
    const ms = Date.parse(value);
    if (!Number.isFinite(ms))
        fail('invalid_instant', `${field} must identify an instant`);
    return { iso: new Date(ms).toISOString(), ms };
}
function nonNegativeInteger(value, field) {
    if (!Number.isSafeInteger(value) || value < 0)
        fail('invalid_integer', `${field} is invalid`);
    return value;
}
function stringBytes(value) { return Buffer.byteLength(value, 'utf8'); }
function currentMs(source) {
    const raw = typeof source === 'function' ? source() : source;
    if (raw === undefined)
        return Date.now();
    if (raw instanceof Date)
        return raw.getTime();
    if (typeof raw === 'string')
        return instant(raw, 'now').ms;
    if (!Number.isFinite(raw))
        fail('invalid_time', 'now is invalid');
    return raw;
}
function normalizeInputs(raw, admittedAt) {
    if (!Array.isArray(raw) || raw.length > ADMISSION_LIMITS.inputs)
        fail('invalid_inputs', 'inputs are invalid');
    const counts = new Map();
    const seen = new Set();
    const inputs = raw.map((entry, index) => {
        if (!plain(entry))
            fail('invalid_input', `inputs[${index}] is invalid`);
        const role = entry.role;
        if (!ROLE_ORDER.has(role))
            fail('invalid_input_role', `inputs[${index}].role is invalid`);
        const normalized = {
            role,
            artifact_type: identifier(entry.artifact_type, `inputs[${index}].artifact_type`),
            subject: identifier(entry.subject, `inputs[${index}].subject`),
            payload_digest: digest(entry.payload_digest, `inputs[${index}].payload_digest`),
            profile_digest: digest(entry.profile_digest, `inputs[${index}].profile_digest`),
            verifier_id: identifier(entry.verifier_id, `inputs[${index}].verifier_id`),
            trust_configuration_digest: digest(entry.trust_configuration_digest, `inputs[${index}].trust_configuration_digest`),
            valid_until: instant(entry.valid_until, `inputs[${index}].valid_until`).iso,
        };
        if (Date.parse(normalized.valid_until) <= admittedAt)
            fail('expired_input', `inputs[${index}] is expired`);
        const key = canonical(normalized);
        if (seen.has(key))
            fail('duplicate_input', `inputs[${index}] is duplicated`);
        seen.add(key);
        counts.set(role, (counts.get(role) ?? 0) + 1);
        if (!REPEATABLE_ROLES.has(role) && (counts.get(role) ?? 0) > 1)
            fail('duplicate_input_role', `${role} is singleton`);
        return normalized;
    });
    for (const role of REQUIRED_SINGLETON_ROLES)
        if (counts.get(role) !== 1)
            fail('missing_input_role', `${role} is required exactly once`);
    for (const role of REPEATABLE_ROLES)
        if ((counts.get(role) ?? 0) < 1)
            fail('missing_input_role', `${role} is required`);
    inputs.sort((left, right) => {
        const role = (ROLE_ORDER.get(left.role) ?? 99) - (ROLE_ORDER.get(right.role) ?? 99);
        if (role !== 0)
            return role;
        return Buffer.from(canonical(left)).compare(Buffer.from(canonical(right)));
    });
    return inputs;
}
function normalizeDigests(raw, field, limit) {
    if (!Array.isArray(raw) || raw.length < 1 || raw.length > limit)
        fail('invalid_digest_list', `${field} is invalid`);
    const values = raw.map((value, index) => digest(value, `${field}[${index}]`)).sort();
    if (new Set(values).size !== values.length)
        fail('duplicate_digest', `${field} contains duplicates`);
    return values;
}
function normalizeResources(raw, admittedAt) {
    if (!Array.isArray(raw) || raw.length < 1 || raw.length > ADMISSION_LIMITS.resources)
        fail('invalid_resources', 'resource reservations are invalid');
    const allowed = new Set(['replay', 'capability', 'budget', 'qualification_use', 'provider_operation', 'external_lease', 'monotonic_counter']);
    const seen = new Set();
    const values = raw.map((entry, index) => {
        if (!plain(entry) || !allowed.has(entry.kind))
            fail('invalid_resource', `resource[${index}] is invalid`);
        const counter = entry.kind === 'monotonic_counter';
        const allowedKeys = new Set([
            'kind', 'resource_id', 'reservation_id', 'digest', 'expires_at',
            ...(counter ? ['expected_value', 'next_value'] : []),
        ]);
        if (Reflect.ownKeys(entry).some((key) => typeof key !== 'string' || !allowedKeys.has(key))) {
            fail('invalid_resource', `resource[${index}] has unknown fields`);
        }
        const value = {
            kind: entry.kind,
            resource_id: identifier(entry.resource_id, `resource[${index}].resource_id`),
            reservation_id: identifier(entry.reservation_id, `resource[${index}].reservation_id`),
            digest: digest(entry.digest, `resource[${index}].digest`),
            expires_at: instant(entry.expires_at, `resource[${index}].expires_at`).iso,
        };
        if (counter) {
            value.expected_value = nonNegativeInteger(entry.expected_value, `resource[${index}].expected_value`);
            value.next_value = nonNegativeInteger(entry.next_value, `resource[${index}].next_value`);
            if (value.next_value <= value.expected_value || value.next_value > 0xffffffff) {
                fail('invalid_resource', `resource[${index}] counter transition is invalid`);
            }
        }
        else if (entry.expected_value !== undefined || entry.next_value !== undefined) {
            fail('invalid_resource', `resource[${index}] counter fields are invalid`);
        }
        if (Date.parse(value.expires_at) <= admittedAt)
            fail('expired_resource', `resource[${index}] is expired`);
        const key = `${value.kind}\0${value.resource_id}`;
        if (seen.has(key))
            fail('duplicate_resource', `resource[${index}] is duplicated`);
        seen.add(key);
        return value;
    });
    values.sort((left, right) => Buffer.from(`${left.kind}\0${left.resource_id}`).compare(Buffer.from(`${right.kind}\0${right.resource_id}`)));
    return values;
}
function normalizeRelation(raw) {
    if (raw === undefined || raw === null)
        return null;
    if (!plain(raw))
        fail('invalid_relation', 'relation is invalid');
    return {
        tenant_id: identifier(raw.tenant_id, 'relation.tenant_id'),
        admission_id: identifier(raw.admission_id, 'relation.admission_id'),
        operation_id: identifier(raw.operation_id, 'relation.operation_id'),
        snapshot_digest: digest(raw.snapshot_digest, 'relation.snapshot_digest'),
    };
}
export function createAdmissionSnapshot(raw) {
    if (!plain(raw))
        fail('invalid_snapshot', 'snapshot input is invalid');
    const admitted = instant(raw.admitted_at, 'admitted_at');
    const expires = instant(raw.expires_at, 'expires_at');
    if (expires.ms <= admitted.ms)
        fail('invalid_expiration', 'expires_at must follow admitted_at');
    const inputs = normalizeInputs(raw.inputs, admitted.ms);
    const resources = normalizeResources(raw.resource_reservations, admitted.ms);
    const status = raw.qualification_status;
    if (!plain(status))
        fail('invalid_status_binding', 'qualification_status is invalid');
    const statusBinding = {
        authority_id: identifier(status.authority_id, 'qualification_status.authority_id'),
        sequence: nonNegativeInteger(status.sequence, 'qualification_status.sequence'),
        head_payload_digest: digest(status.head_payload_digest, 'qualification_status.head_payload_digest'),
        observed_at: instant(status.observed_at, 'qualification_status.observed_at').iso,
        expires_at: instant(status.expires_at, 'qualification_status.expires_at').iso,
    };
    const custody = raw.candidate_custody;
    if (!plain(custody)
        || !['GATE', 'EXECUTOR_ADAPTER', 'EXTERNAL'].includes(custody.request_construction)
        || !['GATE', 'EXECUTOR_ADAPTER', 'EXTERNAL'].includes(custody.mutation_credential_custody)
        || !['SYSTEM_OF_RECORD', 'ACTUATOR', 'MIDDLEWARE'].includes(custody.enforcement_placement)) {
        fail('invalid_custody', 'candidate_custody is invalid');
    }
    const provider = raw.provider;
    if (!plain(provider))
        fail('invalid_provider', 'provider is invalid');
    const body = {
        '@version': ADMISSION_SNAPSHOT_VERSION,
        tenant_id: identifier(raw.tenant_id, 'tenant_id'),
        admission_id: identifier(raw.admission_id, 'admission_id'),
        operation_id: identifier(raw.operation_id, 'operation_id'),
        candidate_manifest_digest: digest(raw.candidate_manifest_digest, 'candidate_manifest_digest'),
        runtime_measurement_digest: digest(raw.runtime_measurement_digest, 'runtime_measurement_digest'),
        candidate_custody: {
            request_construction: custody.request_construction,
            mutation_credential_custody: custody.mutation_credential_custody,
            enforcement_placement: custody.enforcement_placement,
            evidence_digest: digest(custody.evidence_digest, 'candidate_custody.evidence_digest'),
        },
        assignment_digest: digest(raw.assignment_digest, 'assignment_digest'),
        qualification_policy_digest: digest(raw.qualification_policy_digest, 'qualification_policy_digest'),
        test_result_payload_digests: normalizeDigests(raw.test_result_payload_digests, 'test_result_payload_digests', ADMISSION_LIMITS.testResults),
        agent_evaluation_evidence_payload_digests: normalizeDigests(raw.agent_evaluation_evidence_payload_digests, 'agent_evaluation_evidence_payload_digests', ADMISSION_LIMITS.agentEvidence),
        qualification_statement_payload_digest: digest(raw.qualification_statement_payload_digest, 'qualification_statement_payload_digest'),
        qualification_status: statusBinding,
        caid: typeof raw.caid === 'string' && CAID.test(raw.caid) ? raw.caid : fail('invalid_caid', 'caid is invalid'),
        action_digest: digest(raw.action_digest, 'action_digest'),
        effect_request_digest: digest(raw.effect_request_digest, 'effect_request_digest'),
        provider: {
            provider_id: identifier(provider.provider_id, 'provider.provider_id'),
            account_id: identifier(provider.account_id, 'provider.account_id'),
            environment: identifier(provider.environment, 'provider.environment'),
        },
        executor_adapter_digest: digest(raw.executor_adapter_digest, 'executor_adapter_digest'),
        idempotency_key: identifier(raw.idempotency_key, 'idempotency_key'),
        authorization_policy_digest: digest(raw.authorization_policy_digest, 'authorization_policy_digest'),
        trust_epoch: nonNegativeInteger(raw.trust_epoch, 'trust_epoch'),
        trust_configuration_digest: digest(raw.trust_configuration_digest, 'trust_configuration_digest'),
        configuration_epoch: nonNegativeInteger(raw.configuration_epoch, 'configuration_epoch'),
        configuration_digest: digest(raw.configuration_digest, 'configuration_digest'),
        inputs,
        resource_reservations: resources,
        admitted_at: admitted.iso,
        expires_at: expires.iso,
        supersedes_admission_id: raw.supersedes_admission_id === undefined || raw.supersedes_admission_id === null
            ? null : identifier(raw.supersedes_admission_id, 'supersedes_admission_id'),
        remedy_for: normalizeRelation(raw.remedy_for),
    };
    const ceilings = [statusBinding.expires_at, ...inputs.map((input) => input.valid_until), ...resources.map((resource) => resource.expires_at)];
    if (ceilings.some((ceiling) => expires.ms > Date.parse(ceiling)))
        fail('expiration_exceeds_evidence', 'expires_at exceeds an input deadline');
    const snapshot = {
        body: frozenCopy(body),
        snapshot_digest: hash(`${ADMISSION_SNAPSHOT_VERSION}:DIGEST`, body),
    };
    return frozenCopy(snapshot);
}
function validateSnapshot(raw) {
    if (!plain(raw) || !plain(raw.body))
        fail('invalid_snapshot', 'snapshot is invalid');
    const recreated = createAdmissionSnapshot(raw.body);
    if (raw.snapshot_digest !== recreated.snapshot_digest)
        fail('snapshot_digest_mismatch', 'snapshot digest does not match body');
    return recreated;
}
function operationKey(tenant, operation) { return JSON.stringify([tenant, operation]); }
function admissionKey(tenant, admission) { return JSON.stringify([tenant, admission]); }
function resourceKey(tenant, resource) { return JSON.stringify([tenant, resource.kind, resource.resource_id]); }
function monotonicCounterKey(tenant, resourceId) { return JSON.stringify([tenant, 'monotonic_counter', resourceId]); }
function tokenDigest(token) { return hash(`${ADMISSION_RECORD_VERSION}:TOKEN`, token); }
function defaultOwnerToken() { return `admission-owner:v2:${crypto.randomBytes(32).toString('base64url')}`; }
function defaultInvocationToken() { return `admission-invocation:v2:${crypto.randomBytes(32).toString('base64url')}`; }
function validateOwner(value) {
    if (typeof value !== 'string' || !OWNER_TOKEN.test(value))
        fail('invalid_owner_token', 'owner token is invalid');
    return value;
}
function finalizeRecord(raw) {
    const { record_digest: _ignored, ...body } = raw;
    return frozenCopy({ ...body, record_digest: hash(`${ADMISSION_RECORD_VERSION}:DIGEST`, body) });
}
function finalizeJournal(raw) {
    return frozenCopy({ ...raw, entry_digest: hash(`${ADMISSION_JOURNAL_VERSION}:DIGEST`, raw) });
}
export function verifyAdmissionJournal(entries) {
    let predecessor = null;
    for (let index = 0; index < entries.length; index += 1) {
        const entry = entries[index];
        if (entry.sequence !== index)
            return { ok: false, at: index, reason: 'sequence_mismatch' };
        if (entry.predecessor_digest !== predecessor)
            return { ok: false, at: index, reason: 'predecessor_mismatch' };
        const { entry_digest, ...body } = entry;
        if (hash(`${ADMISSION_JOURNAL_VERSION}:DIGEST`, body) !== entry_digest)
            return { ok: false, at: index, reason: 'digest_mismatch' };
        predecessor = entry_digest;
    }
    return { ok: true };
}
function exactOperationIdentity(left, right) {
    return left.tenant_id === right.tenant_id
        && left.operation_id === right.operation_id
        && left.caid === right.caid
        && left.action_digest === right.action_digest
        && left.effect_request_digest === right.effect_request_digest
        && canonical(left.provider) === canonical(right.provider)
        && left.executor_adapter_digest === right.executor_adapter_digest
        && left.idempotency_key === right.idempotency_key;
}
function currentnessMatches(snapshot, observation, now, maxAgeMs) {
    const body = snapshot.body;
    const observedAt = Date.parse(observation.observed_at);
    if (observation['@version'] !== ADMISSION_CURRENTNESS_VERSION
        || observation.candidate_match !== 'EXACT_MATCH'
        || !Number.isFinite(observedAt)
        || observedAt > now
        || now - observedAt > maxAgeMs
        || Date.parse(observation.qualification_status_expires_at) <= now
        || observation.qualification_status_authority_id !== body.qualification_status.authority_id
        || observation.qualification_status_sequence !== body.qualification_status.sequence
        || observation.qualification_status_head_digest !== body.qualification_status.head_payload_digest
        || observation.trust_epoch !== body.trust_epoch
        || observation.trust_configuration_digest !== body.trust_configuration_digest
        || observation.configuration_epoch !== body.configuration_epoch
        || observation.configuration_digest !== body.configuration_digest
        || observation.runtime_measurement_digest !== body.runtime_measurement_digest)
        return false;
    const expected = body.resource_reservations.filter((resource) => resource.kind === 'external_lease');
    if (observation.external_leases.length !== expected.length)
        return false;
    const byId = new Map(observation.external_leases.map((lease) => [lease.resource_id, lease]));
    return expected.every((lease) => {
        const current = byId.get(lease.resource_id);
        return current?.digest === lease.digest && Date.parse(current.expires_at) > now;
    });
}
/** Linearizable, explicitly test-only reference implementation. */
export function createMemoryAdmissionStore(options = {}) {
    const snapshots = new Map();
    const records = new Map();
    const operationHeads = new Map();
    const resourceOwners = new Map();
    const monotonicCounterHeads = new Map();
    const configuredCounterHeads = options.initialMonotonicCounterHeads ?? [];
    if (!Array.isArray(configuredCounterHeads)) {
        fail('invalid_counter_heads', 'initial monotonic counter heads are invalid');
    }
    const counterHeadKeys = new Set(['tenant_id', 'resource_id', 'current_value']);
    for (const [index, head] of configuredCounterHeads.entries()) {
        if (!plain(head)
            || Reflect.ownKeys(head).some((key) => typeof key !== 'string' || !counterHeadKeys.has(key))
            || Reflect.ownKeys(head).length !== counterHeadKeys.size) {
            fail('invalid_counter_head', `initial monotonic counter head[${index}] is invalid`);
        }
        const tenant = identifier(head.tenant_id, `initialMonotonicCounterHeads[${index}].tenant_id`);
        const resourceId = identifier(head.resource_id, `initialMonotonicCounterHeads[${index}].resource_id`);
        const currentValue = nonNegativeInteger(head.current_value, `initialMonotonicCounterHeads[${index}].current_value`);
        if (currentValue > 0xffffffff) {
            fail('invalid_counter_head', `initial monotonic counter head[${index}] is invalid`);
        }
        const key = monotonicCounterKey(tenant, resourceId);
        if (monotonicCounterHeads.has(key)) {
            fail('duplicate_counter_head', `initial monotonic counter head[${index}] is duplicated`);
        }
        monotonicCounterHeads.set(key, currentValue);
    }
    const journals = new Map();
    const ownerFactory = options.ownerTokenFactory ?? defaultOwnerToken;
    const invocationFactory = options.invocationTokenFactory ?? defaultInvocationToken;
    const maxCurrentnessAgeMs = options.maxCurrentnessAgeMs
        ?? ADMISSION_LIMITS.currentnessMaxAgeMs;
    if (!Number.isSafeInteger(maxCurrentnessAgeMs)
        || maxCurrentnessAgeMs < 1
        || maxCurrentnessAgeMs > 300_000) {
        fail('invalid_currentness_age', 'max currentness age is invalid');
    }
    let queue = Promise.resolve();
    function atomic(fn) {
        const next = queue.then(fn, fn);
        queue = next.then(() => undefined, () => undefined);
        return next;
    }
    function append(key, ownerToken, draft, event, at) {
        const history = journals.get(key) ?? [];
        if (draft.revision !== history.length)
            throw new Error('admission invariant: revision/journal mismatch');
        const record = finalizeRecord(draft);
        const previous = history.at(-1);
        const entry = finalizeJournal({
            '@version': ADMISSION_JOURNAL_VERSION,
            tenant_id: record.tenant_id,
            admission_id: record.admission_id,
            operation_id: record.operation_id,
            sequence: history.length,
            event,
            snapshot_digest: record.snapshot_digest,
            record_digest: record.record_digest,
            predecessor_digest: previous?.entry_digest ?? null,
            recorded_at: at,
        });
        journals.set(key, [...history, entry]);
        records.set(key, { record, ownerToken });
        return record;
    }
    function next(current, at, changes) {
        return {
            ...current,
            ...changes,
            revision: current.revision + 1,
            updated_at: at,
            predecessor_record_digest: current.record_digest,
            resources: changes.resources ?? current.resources.map((resource) => ({ ...resource })),
            record_digest: undefined,
        };
    }
    function selectCas(input) {
        const key = admissionKey(identifier(input.tenant_id, 'tenant_id'), identifier(input.admission_id, 'admission_id'));
        const stored = records.get(key);
        if (!stored)
            return { ok: false, reason: 'admission_not_found' };
        if (stored.record.revision !== nonNegativeInteger(input.expected_revision, 'expected_revision'))
            return { ok: false, reason: 'revision_conflict' };
        if (stored.ownerToken !== validateOwner(input.owner_token))
            return { ok: false, reason: 'owner_conflict' };
        return { key, stored };
    }
    function resourcesAvailable(snapshot, ignored) {
        return snapshot.body.resource_reservations.every((resource) => {
            if (resource.kind === 'monotonic_counter') {
                const current = monotonicCounterHeads.get(resourceKey(snapshot.body.tenant_id, resource));
                return current === resource.expected_value;
            }
            const owner = resourceOwners.get(resourceKey(snapshot.body.tenant_id, resource));
            return owner === undefined || owner === ignored;
        });
    }
    // Monotonic counter heads advance atomically with the successful reservation mutation.
    function claimResources(snapshot, key) {
        for (const resource of snapshot.body.resource_reservations) {
            const rKey = resourceKey(snapshot.body.tenant_id, resource);
            if (resource.kind === 'monotonic_counter') {
                monotonicCounterHeads.set(rKey, resource.next_value);
            }
            else
                resourceOwners.set(rKey, key);
        }
    }
    function freeResources(record, key) {
        for (const resource of record.resources) {
            if (resource.kind === 'monotonic_counter')
                continue;
            const rKey = resourceKey(record.tenant_id, resource);
            if (resourceOwners.get(rKey) === key)
                resourceOwners.delete(rKey);
        }
    }
    function invariantViolations() {
        const violations = [];
        for (const [key, stored] of records) {
            const record = stored.record;
            const history = journals.get(key) ?? [];
            if (!snapshots.has(record.snapshot_digest))
                violations.push(`${key}:snapshot_missing`);
            if (!verifyAdmissionJournal(history).ok)
                violations.push(`${key}:journal_invalid`);
            if (history.length !== record.revision + 1 || history.at(-1)?.record_digest !== record.record_digest)
                violations.push(`${key}:head_mismatch`);
            if (record.state === 'RESERVED' && (record.execution_right !== 'RESERVED' || record.provider_attempt !== 'NOT_ENTERED'))
                violations.push(`${key}:reserved_invalid`);
            for (const resource of record.resources) {
                if (resource.kind === 'monotonic_counter') {
                    const head = monotonicCounterHeads.get(resourceKey(record.tenant_id, resource));
                    if (head === undefined || head < resource.next_value) {
                        violations.push(`${key}:monotonic_counter_head_invalid`);
                    }
                }
            }
            if (['INVOKING', 'INDETERMINATE', 'COMMITTED', 'PROVEN_NOT_COMMITTED'].includes(record.state)
                && (record.execution_right !== 'CONSUMED' || record.resources.some((resource) => resource.state !== 'CONSUMED')))
                violations.push(`${key}:consumption_invalid`);
            if (record.state === 'SUPERSEDED') {
                if (record.superseded_by_admission_id === null) {
                    violations.push(`${key}:supersession_missing`);
                }
                else {
                    const predecessorSnapshot = snapshots.get(record.snapshot_digest);
                    const successorKey = admissionKey(record.tenant_id, record.superseded_by_admission_id);
                    const successor = records.get(successorKey);
                    const successorSnapshot = successor
                        ? snapshots.get(successor.record.snapshot_digest)
                        : undefined;
                    if (!successor
                        || !predecessorSnapshot
                        || !successorSnapshot
                        || successorSnapshot.body.supersedes_admission_id !== record.admission_id
                        || !exactOperationIdentity(predecessorSnapshot.body, successorSnapshot.body)) {
                        violations.push(`${key}:supersession_target_invalid`);
                    }
                    const operationHead = operationHeads.get(operationKey(record.tenant_id, record.operation_id));
                    if (operationHead !== successorKey) {
                        violations.push(`${key}:supersession_head_invalid`);
                    }
                }
            }
        }
        for (const [op, admission] of operationHeads) {
            const stored = records.get(admission);
            if (!stored || operationKey(stored.record.tenant_id, stored.record.operation_id) !== op)
                violations.push(`${op}:operation_head_invalid`);
        }
        return violations;
    }
    const store = {
        testOnly: true,
        durable: false,
        atomic: true,
        compareAndSwap: true,
        appendOnlyJournal: true,
        exclusiveActuation: true,
        transactionalCurrentness: true,
        reserve(raw) {
            return atomic(() => {
                const snapshot = plain(raw) && Object.hasOwn(raw, 'snapshot_digest')
                    ? validateSnapshot(raw)
                    : createAdmissionSnapshot(raw);
                const body = snapshot.body;
                if (body.supersedes_admission_id !== null)
                    return { ok: false, reason: 'relation_conflict' };
                const key = admissionKey(body.tenant_id, body.admission_id);
                const opKey = operationKey(body.tenant_id, body.operation_id);
                if (records.has(key))
                    return { ok: false, reason: 'admission_exists' };
                if (operationHeads.has(opKey))
                    return { ok: false, reason: 'operation_exists' };
                const now = currentMs(options.now);
                if (Date.parse(body.expires_at) <= now)
                    return { ok: false, reason: 'admission_expired' };
                if (body.remedy_for !== null) {
                    const target = records.get(admissionKey(body.remedy_for.tenant_id, body.remedy_for.admission_id));
                    if (!target || target.record.snapshot_digest !== body.remedy_for.snapshot_digest)
                        return { ok: false, reason: 'relation_not_found' };
                    if (!['INVOKING', 'INDETERMINATE', 'COMMITTED', 'PROVEN_NOT_COMMITTED'].includes(target.record.state))
                        return { ok: false, reason: 'relation_conflict' };
                    const targetSnapshot = snapshots.get(target.record.snapshot_digest);
                    if (!targetSnapshot || targetSnapshot.body.operation_id === body.operation_id || targetSnapshot.body.caid === body.caid)
                        return { ok: false, reason: 'relation_conflict' };
                }
                if (!resourcesAvailable(snapshot))
                    return { ok: false, reason: 'resource_conflict' };
                const owner = validateOwner(ownerFactory());
                const at = new Date(now).toISOString();
                snapshots.set(snapshot.snapshot_digest, snapshot);
                operationHeads.set(opKey, key);
                claimResources(snapshot, key);
                const record = append(key, owner, {
                    '@version': ADMISSION_RECORD_VERSION,
                    tenant_id: body.tenant_id,
                    admission_id: body.admission_id,
                    operation_id: body.operation_id,
                    snapshot_digest: snapshot.snapshot_digest,
                    revision: 0,
                    state: 'RESERVED',
                    execution_right: 'RESERVED',
                    provider_attempt: 'NOT_ENTERED',
                    owner_digest: tokenDigest(owner),
                    invocation_token_digest: null,
                    provider_outcome: null,
                    effect_relation: null,
                    resources: body.resource_reservations.map((resource) => ({ ...resource, state: 'RESERVED' })),
                    superseded_by_admission_id: null,
                    refusal_reason: null,
                    invocation_started_at: null,
                    created_at: at,
                    updated_at: at,
                    predecessor_record_digest: null,
                }, 'RESERVED', at);
                return { ok: true, snapshot, record, owner_token: owner };
            });
        },
        release(input, reason = 'released_before_invocation') {
            return atomic(() => {
                const selected = selectCas(input);
                if ('ok' in selected)
                    return selected;
                const { key, stored } = selected;
                if (stored.record.execution_right === 'CONSUMED')
                    return { ok: false, reason: 'execution_right_consumed' };
                if (stored.record.state !== 'RESERVED')
                    return { ok: false, reason: 'state_conflict' };
                const at = new Date(currentMs(options.now)).toISOString();
                freeResources(stored.record, key);
                const record = append(key, stored.ownerToken, next(stored.record, at, {
                    state: 'RELEASED', execution_right: 'RELEASED', refusal_reason: reason,
                    resources: stored.record.resources.map((resource) => ({ ...resource, state: 'RELEASED' })),
                }), 'RELEASED', at);
                return { ok: true, record };
            });
        },
        expire(input) {
            return atomic(() => {
                const selected = selectCas(input);
                if ('ok' in selected)
                    return selected;
                const { key, stored } = selected;
                if (stored.record.state !== 'RESERVED')
                    return { ok: false, reason: 'state_conflict' };
                const snapshot = snapshots.get(stored.record.snapshot_digest);
                const now = currentMs(options.now);
                if (Date.parse(snapshot.body.expires_at) > now)
                    return { ok: false, reason: 'state_conflict' };
                const at = new Date(now).toISOString();
                freeResources(stored.record, key);
                const record = append(key, stored.ownerToken, next(stored.record, at, {
                    state: 'EXPIRED', execution_right: 'RELEASED', refusal_reason: 'admission_expired',
                    resources: stored.record.resources.map((resource) => ({ ...resource, state: 'RELEASED' })),
                }), 'EXPIRED', at);
                return { ok: true, record };
            });
        },
        supersede(input) {
            return atomic(() => {
                const selected = selectCas(input);
                if ('ok' in selected)
                    return selected;
                const { key, stored } = selected;
                if (stored.record.state !== 'RESERVED' || stored.record.execution_right !== 'RESERVED')
                    return { ok: false, reason: 'state_conflict' };
                const predecessor = snapshots.get(stored.record.snapshot_digest);
                const successor = createAdmissionSnapshot({ ...input.successor, supersedes_admission_id: stored.record.admission_id, remedy_for: null });
                if (successor.body.admission_id === stored.record.admission_id || !exactOperationIdentity(predecessor.body, successor.body))
                    return { ok: false, reason: 'operation_conflict' };
                const successorKey = admissionKey(successor.body.tenant_id, successor.body.admission_id);
                if (records.has(successorKey))
                    return { ok: false, reason: 'admission_exists' };
                const now = currentMs(options.now);
                if (Date.parse(successor.body.expires_at) <= now)
                    return { ok: false, reason: 'admission_expired' };
                if (!resourcesAvailable(successor, key))
                    return { ok: false, reason: 'resource_conflict' };
                const owner = validateOwner(ownerFactory());
                const at = new Date(now).toISOString();
                freeResources(stored.record, key);
                const predecessorRecord = append(key, stored.ownerToken, next(stored.record, at, {
                    state: 'SUPERSEDED', execution_right: 'RELEASED', superseded_by_admission_id: successor.body.admission_id,
                    resources: stored.record.resources.map((resource) => ({ ...resource, state: 'RELEASED' })),
                }), 'SUPERSEDED', at);
                snapshots.set(successor.snapshot_digest, successor);
                claimResources(successor, successorKey);
                operationHeads.set(operationKey(successor.body.tenant_id, successor.body.operation_id), successorKey);
                const successorRecord = append(successorKey, owner, {
                    '@version': ADMISSION_RECORD_VERSION,
                    tenant_id: successor.body.tenant_id,
                    admission_id: successor.body.admission_id,
                    operation_id: successor.body.operation_id,
                    snapshot_digest: successor.snapshot_digest,
                    revision: 0,
                    state: 'RESERVED', execution_right: 'RESERVED', provider_attempt: 'NOT_ENTERED',
                    owner_digest: tokenDigest(owner), invocation_token_digest: null,
                    provider_outcome: null, effect_relation: null,
                    resources: successor.body.resource_reservations.map((resource) => ({ ...resource, state: 'RESERVED' })),
                    superseded_by_admission_id: null, refusal_reason: null, invocation_started_at: null,
                    created_at: at, updated_at: at, predecessor_record_digest: null,
                }, 'RESERVED', at);
                return { ok: true, predecessor_record: predecessorRecord, successor_snapshot: successor, successor_record: successorRecord, successor_owner_token: owner };
            });
        },
        beginInvocation(input) {
            return atomic(async () => {
                const selected = selectCas(input);
                if ('ok' in selected)
                    return selected;
                const { key, stored } = selected;
                if (stored.record.state !== 'RESERVED' || stored.record.execution_right !== 'RESERVED' || stored.record.provider_attempt !== 'NOT_ENTERED')
                    return { ok: false, reason: 'state_conflict' };
                const snapshot = snapshots.get(stored.record.snapshot_digest);
                const now = currentMs(options.now);
                if (Date.parse(snapshot.body.expires_at) <= now)
                    return { ok: false, reason: 'admission_expired' };
                const observation = options.currentnessOracle
                    ? await options.currentnessOracle.read(snapshot)
                    : null;
                const countersCurrent = snapshot.body.resource_reservations.every((resource) => (resource.kind !== 'monotonic_counter'
                    || (monotonicCounterHeads.get(resourceKey(snapshot.body.tenant_id, resource)) ?? -1)
                        >= resource.next_value));
                if (!observation || !countersCurrent || !currentnessMatches(snapshot, observation, now, maxCurrentnessAgeMs)) {
                    const at = new Date(now).toISOString();
                    freeResources(stored.record, key);
                    append(key, stored.ownerToken, next(stored.record, at, {
                        state: 'RELEASED', execution_right: 'RELEASED', refusal_reason: 'currentness_refused',
                        resources: stored.record.resources.map((resource) => ({ ...resource, state: 'RELEASED' })),
                    }), 'RELEASED', at);
                    return { ok: false, reason: 'currentness_refused' };
                }
                const invocationToken = invocationFactory();
                if (typeof invocationToken !== 'string' || invocationToken.length < 48)
                    fail('invalid_invocation_token', 'invocation token is invalid');
                const at = new Date(now).toISOString();
                const record = append(key, stored.ownerToken, next(stored.record, at, {
                    state: 'INVOKING', execution_right: 'CONSUMED', provider_attempt: 'INVOKING',
                    invocation_token_digest: tokenDigest(invocationToken), invocation_started_at: at,
                    resources: stored.record.resources.map((resource) => ({ ...resource, state: 'CONSUMED' })),
                }), 'INVOKING', at);
                return { ok: true, snapshot, record, invocation_token: invocationToken };
            });
        },
        recoverIndeterminate(input) {
            return atomic(() => {
                const key = admissionKey(identifier(input.tenant_id, 'tenant_id'), identifier(input.admission_id, 'admission_id'));
                const stored = records.get(key);
                if (!stored)
                    return { ok: false, reason: 'admission_not_found' };
                if (stored.ownerToken !== validateOwner(input.owner_token))
                    return { ok: false, reason: 'owner_conflict' };
                if (stored.record.state !== 'INVOKING')
                    return { ok: false, reason: 'state_conflict' };
                const reconciliationToken = invocationFactory();
                if (typeof reconciliationToken !== 'string' || reconciliationToken.length < 48)
                    fail('invalid_invocation_token', 'reconciliation token is invalid');
                const at = new Date(currentMs(options.now)).toISOString();
                const record = append(key, stored.ownerToken, next(stored.record, at, {
                    state: 'INDETERMINATE', provider_attempt: 'INDETERMINATE',
                    invocation_token_digest: tokenDigest(reconciliationToken),
                    provider_outcome: { value: 'INDETERMINATE', evidence_digest: null, observed_at: at },
                    refusal_reason: 'ambiguous_provider_entry',
                }), 'RECOVERED_INDETERMINATE', at);
                return { ok: true, record, reconciliation_token: reconciliationToken };
            });
        },
        recordProviderOutcome(input) {
            return atomic(() => {
                const selected = selectCas(input);
                if ('ok' in selected)
                    return selected;
                const { key, stored } = selected;
                if (stored.record.execution_right !== 'CONSUMED' || stored.record.invocation_token_digest !== tokenDigest(input.invocation_token))
                    return { ok: false, reason: 'invocation_token_conflict' };
                if (!['INVOKING', 'INDETERMINATE', 'COMMITTED', 'PROVEN_NOT_COMMITTED'].includes(stored.record.state))
                    return { ok: false, reason: 'state_conflict' };
                if (!['COMMITTED', 'PROVEN_NOT_COMMITTED', 'INDETERMINATE'].includes(input.value))
                    fail('invalid_provider_outcome', 'provider outcome is invalid');
                const observed = instant(input.observed_at, 'observed_at').iso;
                const evidence = input.evidence_digest === null ? null : digest(input.evidence_digest, 'evidence_digest');
                if (input.value !== 'INDETERMINATE' && evidence === null)
                    return { ok: false, reason: 'evidence_required' };
                const current = stored.record.provider_outcome;
                if (current && current.value !== 'INDETERMINATE' && (current.value !== input.value || current.evidence_digest !== evidence))
                    return { ok: false, reason: 'outcome_conflict' };
                const at = new Date(currentMs(options.now)).toISOString();
                const record = append(key, stored.ownerToken, next(stored.record, at, {
                    state: input.value,
                    provider_attempt: input.value,
                    provider_outcome: { value: input.value, evidence_digest: evidence, observed_at: observed },
                }), 'PROVIDER_OUTCOME', at);
                return { ok: true, record };
            });
        },
        recordEffectRelation(input) {
            return atomic(() => {
                const selected = selectCas(input);
                if ('ok' in selected)
                    return selected;
                const { key, stored } = selected;
                if (stored.record.execution_right !== 'CONSUMED' || stored.record.invocation_token_digest !== tokenDigest(input.invocation_token))
                    return { ok: false, reason: 'invocation_token_conflict' };
                if (!['OBSERVED_AS_REQUESTED', 'DIVERGED', 'INDETERMINATE'].includes(input.value))
                    fail('invalid_effect_relation', 'effect relation is invalid');
                const observed = instant(input.observed_at, 'observed_at').iso;
                const evidence = input.evidence_digest === null ? null : digest(input.evidence_digest, 'evidence_digest');
                if (input.value !== 'INDETERMINATE' && evidence === null)
                    return { ok: false, reason: 'evidence_required' };
                const current = stored.record.effect_relation;
                if (current && current.value !== 'INDETERMINATE' && (current.value !== input.value || current.evidence_digest !== evidence))
                    return { ok: false, reason: 'outcome_conflict' };
                const at = new Date(currentMs(options.now)).toISOString();
                const record = append(key, stored.ownerToken, next(stored.record, at, {
                    effect_relation: { value: input.value, evidence_digest: evidence, observed_at: observed },
                }), 'EFFECT_RELATION', at);
                return { ok: true, record };
            });
        },
        read(input) {
            return atomic(() => records.get(admissionKey(identifier(input.tenant_id, 'tenant_id'), identifier(input.admission_id, 'admission_id')))?.record ?? null);
        },
        readByOperation(input) {
            return atomic(() => {
                const head = operationHeads.get(operationKey(identifier(input.tenant_id, 'tenant_id'), identifier(input.operation_id, 'operation_id')));
                return head ? records.get(head)?.record ?? null : null;
            });
        },
        readSnapshot(raw) { return atomic(() => snapshots.get(digest(raw, 'snapshot_digest')) ?? null); },
        journal(input) {
            return atomic(() => journals.get(admissionKey(identifier(input.tenant_id, 'tenant_id'), identifier(input.admission_id, 'admission_id'))) ?? []);
        },
        checkInvariants() {
            return atomic(() => {
                const violations = invariantViolations();
                return { ok: violations.length === 0, violations };
            });
        },
    };
    return store;
}
export default createMemoryAdmissionStore;
//# sourceMappingURL=admission-store.js.map