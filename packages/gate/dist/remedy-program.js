// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate Remedy Program Profile v1.
 *
 * A fail-closed, post-effect compensation state machine. The kernel never
 * rewrites an already-observed effect: it verifies the original effect,
 * records disputes and late revocations, and authorizes separately bound
 * compensating operations through atomic compare-and-swap transitions.
 */
import { createHash } from 'node:crypto';
import { canonicalize } from '../execution-binding.js';
export const REMEDY_PROGRAM_VERSION = 'EP-GATE-REMEDY-PROGRAM-PROFILE-v1';
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const CAID = /^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const MAX_CONTEXT_BYTES = 512;
const MAX_REMEDY_ATTEMPTS = 1024;
const DEFAULT_MAX_DISPUTE_AGE_MS = 30 * 24 * 60 * 60 * 1000;
const CONFIG_KEYS = new Set([
    'store', 'verifyOriginalEffect', 'verifyRevocation', 'verifyDispute',
    'verifyRemedyAuthorization', 'verifyRemedyOutcome', 'verifyOriginalReconciliation',
    'verifyResolution',
    'now', 'maxDisputeAgeMs', 'allowEphemeralState', 'production',
]);
const CREATE_KEYS = new Set([
    'instanceId', 'tenantId', 'environment', 'audience', 'original',
    'remedyProfileDigest', 'destinationBindingDigest', 'maxRemedyUnits',
    'unit', 'evidence',
]);
const ORIGINAL_KEYS = new Set([
    'caid', 'action_digest', 'operation_id', 'consequence_mode',
    'consequence_digest', 'terminal_evidence_digest', 'outcome', 'occurred_at',
]);
const VERIFIED_ORIGINAL_KEYS = new Set(['ok', ...ORIGINAL_KEYS, 'evidence_digest']);
const ORIGINAL_RECONCILIATION_INPUT_KEYS = new Set([
    'tenantId', 'instanceId', 'outcome', 'evidence',
]);
const ORIGINAL_RECONCILIATION_EVIDENCE_KEYS = new Set([
    'evidence_id', 'evidence_digest', 'observed_at',
]);
const VERIFIED_ORIGINAL_RECONCILIATION_KEYS = new Set([
    'ok', ...ORIGINAL_RECONCILIATION_EVIDENCE_KEYS, 'original_operation_id',
    'original_action_digest', 'terminal_evidence_digest', 'outcome',
]);
const REVOCATION_INPUT_KEYS = new Set(['tenantId', 'instanceId', 'evidence']);
const REVOCATION_EVIDENCE_KEYS = new Set(['id', 'digest']);
const VERIFIED_REVOCATION_KEYS = new Set([
    'ok', 'evidence_id', 'evidence_digest', 'target_operation_id',
    'action_digest', 'authority_id', 'revoked_at',
]);
const DISPUTE_INPUT_KEYS = new Set(['tenantId', 'instanceId', 'dispute']);
const DISPUTE_KEYS = new Set([
    'dispute_id', 'evidence_id', 'evidence_digest', 'challenger_id',
    'requested_units', 'opened_at',
]);
const VERIFIED_DISPUTE_KEYS = new Set([
    'ok', ...DISPUTE_KEYS, 'original_operation_id', 'original_action_digest',
]);
const AUTHORIZATION_INPUT_KEYS = new Set(['tenantId', 'instanceId', 'authorization']);
const AUTHORIZATION_KEYS = new Set([
    'evidence_id', 'evidence_digest', 'remedy_operation_id', 'remedy_caid',
    'remedy_action_digest', 'consequence_mode', 'capability_template_digest',
    'escrow_profile_digest', 'units', 'authorized_at',
]);
const VERIFIED_AUTHORIZATION_KEYS = new Set([
    'ok', ...AUTHORIZATION_KEYS, 'dispute_id', 'original_operation_id',
    'destination_binding_digest', 'unit',
]);
const CLAIM_KEYS = new Set(['tenantId', 'instanceId', 'remedyOperationId', 'claimToken']);
const FINALIZE_KEYS = new Set([
    'tenantId', 'instanceId', 'remedyOperationId', 'claimToken', 'outcome', 'evidence',
]);
const RECONCILE_KEYS = new Set(['tenantId', 'instanceId', 'remedyOperationId', 'outcome', 'evidence']);
const OUTCOME_EVIDENCE_KEYS = new Set(['evidence_id', 'evidence_digest', 'observed_at']);
const VERIFIED_OUTCOME_KEYS = new Set([
    'ok', ...OUTCOME_EVIDENCE_KEYS, 'remedy_operation_id',
    'remedy_action_digest', 'destination_binding_digest', 'units', 'unit',
    'outcome',
]);
const RESOLUTION_INPUT_KEYS = new Set(['tenantId', 'instanceId', 'resolution']);
const RESOLUTION_KEYS = new Set([
    'evidence_id', 'evidence_digest', 'outcome', 'resolved_at',
]);
const VERIFIED_RESOLUTION_KEYS = new Set(['ok', ...RESOLUTION_KEYS, 'dispute_id']);
const STATE_KEYS = new Set([
    'version', 'instance_id', 'tenant_id', 'environment', 'audience', 'status',
    'revision', 'created_at', 'updated_at', 'original', 'remedy_profile_digest',
    'destination_binding_digest', 'max_remedy_units', 'unit', 'remedied_units',
    'remaining_units', 'used_evidence_ids', 'used_evidence_digests',
    'original_reconciliation', 'revocation', 'dispute', 'active_remedy',
    'remedies', 'resolution',
    'create_request_digest',
]);
const STORED_ORIGINAL_KEYS = new Set([...ORIGINAL_KEYS, 'evidence_digest']);
const STORED_ORIGINAL_RECONCILIATION_KEYS = new Set([
    ...VERIFIED_ORIGINAL_RECONCILIATION_KEYS,
    'request_digest',
]);
STORED_ORIGINAL_RECONCILIATION_KEYS.delete('ok');
const STORED_REVOCATION_KEYS = new Set([
    'evidence_id', 'evidence_digest', 'target_operation_id', 'action_digest',
    'authority_id', 'revoked_at', 'effect', 'request_digest',
]);
const STORED_DISPUTE_KEYS = new Set([
    ...DISPUTE_KEYS, 'original_operation_id', 'original_action_digest',
    'request_digest',
]);
const ATTEMPT_KEYS = new Set([
    'evidence_id', 'evidence_digest', 'dispute_id', 'original_operation_id',
    'remedy_operation_id', 'remedy_caid', 'remedy_action_digest',
    'consequence_mode', 'capability_template_digest', 'escrow_profile_digest',
    'destination_binding_digest', 'units', 'unit', 'authorized_at',
    'request_digest', 'status', 'claim_token_digest', 'claimed_at',
    'claim_request_digest', 'outcome', 'outcome_evidence',
    'finalize_request_digest', 'reconciliation', 'reconcile_request_digest',
]);
const STORED_OUTCOME_KEYS = new Set([
    ...OUTCOME_EVIDENCE_KEYS, 'remedy_operation_id', 'remedy_action_digest',
    'destination_binding_digest', 'units', 'unit', 'outcome',
]);
const STORED_RESOLUTION_KEYS = new Set([
    ...RESOLUTION_KEYS, 'dispute_id', 'request_digest',
]);
function deepFreeze(value) {
    if (value === null || typeof value !== 'object')
        return value;
    const stack = [value];
    const seen = new WeakSet();
    while (stack.length > 0) {
        const current = stack.pop();
        if (seen.has(current))
            continue;
        seen.add(current);
        for (const child of Object.values(current)) {
            if (child !== null && typeof child === 'object')
                stack.push(child);
        }
        Object.freeze(current);
    }
    return value;
}
function snapshot(value, label) {
    try {
        canonicalize(value);
        return deepFreeze(structuredClone(value));
    }
    catch {
        throw new TypeError(`${label} must be bounded canonical JSON`);
    }
}
function clone(value) {
    return structuredClone(value);
}
function isRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function isDataRecord(value) {
    return isRecord(value) && Reflect.ownKeys(value).every((key) => {
        if (typeof key !== 'string')
            return false;
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
    });
}
function exactKeys(value, keys) {
    return isDataRecord(value)
        && Reflect.ownKeys(value).length === keys.size
        && Object.keys(value).every((key) => keys.has(key));
}
function validId(value) {
    return typeof value === 'string' && ID.test(value);
}
function validContext(value) {
    return typeof value === 'string' && value.length > 0
        && Buffer.byteLength(value, 'utf8') <= MAX_CONTEXT_BYTES
        && !/[\u0000-\u001f\u007f]/.test(value);
}
function instant(value) {
    if (typeof value !== 'string'
        || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value))
        return NaN;
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : NaN;
}
function digest(value) {
    return `sha256:${createHash('sha256').update(canonicalize(value)).digest('hex')}`;
}
function same(left, right) {
    try {
        return canonicalize(left) === canonicalize(right);
    }
    catch {
        return false;
    }
}
function fail(reason) {
    return Object.freeze({ ok: false, reason });
}
function isFailure(value) {
    return value.ok === false && typeof value.reason === 'string';
}
function pass(fields) {
    return deepFreeze(fields);
}
function withoutOk(projection) {
    const result = {};
    for (const [key, value] of Object.entries(projection)) {
        if (key !== 'ok')
            result[key] = clone(value);
    }
    return result;
}
function validOriginal(value, stored = false) {
    const keys = stored ? STORED_ORIGINAL_KEYS : ORIGINAL_KEYS;
    return exactKeys(value, keys)
        && typeof value.caid === 'string' && CAID.test(value.caid)
        && typeof value.action_digest === 'string' && DIGEST.test(value.action_digest)
        && validId(value.operation_id)
        && ['receipt-program', 'action-escrow'].includes(value.consequence_mode)
        && typeof value.consequence_digest === 'string' && DIGEST.test(value.consequence_digest)
        && typeof value.terminal_evidence_digest === 'string' && DIGEST.test(value.terminal_evidence_digest)
        && ['executed', 'indeterminate'].includes(value.outcome)
        && Number.isFinite(instant(value.occurred_at))
        && (!stored || (typeof value.evidence_digest === 'string' && DIGEST.test(value.evidence_digest)));
}
function validOriginalReconciliation(value) {
    return exactKeys(value, STORED_ORIGINAL_RECONCILIATION_KEYS)
        && validEvidencePair(value.evidence_id, value.evidence_digest)
        && validId(value.original_operation_id)
        && typeof value.original_action_digest === 'string' && DIGEST.test(value.original_action_digest)
        && typeof value.terminal_evidence_digest === 'string' && DIGEST.test(value.terminal_evidence_digest)
        && ['executed', 'proved_no_effect'].includes(value.outcome)
        && Number.isFinite(instant(value.observed_at))
        && typeof value.request_digest === 'string' && DIGEST.test(value.request_digest);
}
function validDispute(value) {
    return exactKeys(value, STORED_DISPUTE_KEYS)
        && validId(value.dispute_id) && validId(value.evidence_id)
        && typeof value.evidence_digest === 'string' && DIGEST.test(value.evidence_digest)
        && validContext(value.challenger_id)
        && validId(value.original_operation_id)
        && typeof value.original_action_digest === 'string' && DIGEST.test(value.original_action_digest)
        && Number.isSafeInteger(value.requested_units) && value.requested_units > 0
        && Number.isFinite(instant(value.opened_at))
        && typeof value.request_digest === 'string' && DIGEST.test(value.request_digest);
}
function validStoredOutcome(value, reconciliation) {
    return exactKeys(value, STORED_OUTCOME_KEYS)
        && validId(value.evidence_id)
        && typeof value.evidence_digest === 'string' && DIGEST.test(value.evidence_digest)
        && validId(value.remedy_operation_id)
        && typeof value.remedy_action_digest === 'string' && DIGEST.test(value.remedy_action_digest)
        && typeof value.destination_binding_digest === 'string' && DIGEST.test(value.destination_binding_digest)
        && Number.isSafeInteger(value.units) && value.units > 0
        && validContext(value.unit)
        && (reconciliation
            ? ['executed', 'proved_no_effect'].includes(value.outcome)
            : ['executed', 'proved_no_effect', 'indeterminate'].includes(value.outcome))
        && Number.isFinite(instant(value.observed_at));
}
function validRemedyOwner(value) {
    return (value.consequence_mode === 'receipt-program'
        && typeof value.capability_template_digest === 'string'
        && DIGEST.test(value.capability_template_digest)
        && value.escrow_profile_digest === null)
        || (value.consequence_mode === 'action-escrow'
            && value.capability_template_digest === null
            && typeof value.escrow_profile_digest === 'string'
            && DIGEST.test(value.escrow_profile_digest));
}
function validAttempt(value) {
    if (!exactKeys(value, ATTEMPT_KEYS)
        || !validId(value.evidence_id)
        || typeof value.evidence_digest !== 'string' || !DIGEST.test(value.evidence_digest)
        || !validId(value.dispute_id) || !validId(value.original_operation_id)
        || !validId(value.remedy_operation_id)
        || typeof value.remedy_caid !== 'string' || !CAID.test(value.remedy_caid)
        || typeof value.remedy_action_digest !== 'string' || !DIGEST.test(value.remedy_action_digest)
        || !validRemedyOwner(value)
        || typeof value.destination_binding_digest !== 'string' || !DIGEST.test(value.destination_binding_digest)
        || !Number.isSafeInteger(value.units) || value.units < 1
        || !validContext(value.unit) || !Number.isFinite(instant(value.authorized_at))
        || typeof value.request_digest !== 'string' || !DIGEST.test(value.request_digest)
        || !['authorized', 'claimed', 'indeterminate', 'executed', 'proved_no_effect'].includes(value.status)) {
        return false;
    }
    const claimed = value.status !== 'authorized';
    if (claimed !== (typeof value.claim_token_digest === 'string' && DIGEST.test(value.claim_token_digest))
        || claimed !== Number.isFinite(instant(value.claimed_at))
        || claimed !== (typeof value.claim_request_digest === 'string' && DIGEST.test(value.claim_request_digest))) {
        return false;
    }
    const finalized = ['indeterminate', 'executed', 'proved_no_effect'].includes(value.status);
    if (finalized !== (typeof value.finalize_request_digest === 'string' && DIGEST.test(value.finalize_request_digest))
        || finalized !== validStoredOutcome(value.outcome_evidence, false)
        || finalized !== (typeof value.outcome === 'string'))
        return false;
    const reconciled = value.reconciliation !== null;
    if (reconciled !== (typeof value.reconcile_request_digest === 'string' && DIGEST.test(value.reconcile_request_digest))) {
        return false;
    }
    if (reconciled && !validStoredOutcome(value.reconciliation, true))
        return false;
    return true;
}
function validState(value, tenantId, instanceId) {
    if (!exactKeys(value, STATE_KEYS)
        || value.version !== REMEDY_PROGRAM_VERSION
        || !validId(value.instance_id) || (instanceId !== undefined && value.instance_id !== instanceId)
        || !validContext(value.tenant_id) || (tenantId !== undefined && value.tenant_id !== tenantId)
        || !validContext(value.environment) || !validContext(value.audience)
        || ![
            'effect_executed', 'effect_indeterminate', 'disputed', 'remedy_authorized',
            'remedy_claimed', 'remedy_indeterminate', 'partially_remedied',
            'remedied', 'resolved_no_remedy', 'original_proved_no_effect',
        ].includes(value.status)
        || !Number.isSafeInteger(value.revision) || value.revision < 0
        || !Number.isFinite(instant(value.created_at)) || !Number.isFinite(instant(value.updated_at))
        || instant(value.updated_at) < instant(value.created_at)
        || !validOriginal(value.original, true)
        || typeof value.remedy_profile_digest !== 'string' || !DIGEST.test(value.remedy_profile_digest)
        || typeof value.destination_binding_digest !== 'string' || !DIGEST.test(value.destination_binding_digest)
        || !Number.isSafeInteger(value.max_remedy_units) || value.max_remedy_units < 1
        || !validContext(value.unit)
        || !Number.isSafeInteger(value.remedied_units) || value.remedied_units < 0
        || !Number.isSafeInteger(value.remaining_units) || value.remaining_units < 0
        || value.remedied_units + value.remaining_units !== value.max_remedy_units
        || !Array.isArray(value.used_evidence_ids) || !value.used_evidence_ids.every(validId)
        || new Set(value.used_evidence_ids).size !== value.used_evidence_ids.length
        || !Array.isArray(value.used_evidence_digests)
        || !value.used_evidence_digests.every((entry) => typeof entry === 'string' && DIGEST.test(entry))
        || new Set(value.used_evidence_digests).size !== value.used_evidence_digests.length
        || !Array.isArray(value.remedies) || value.remedies.length > MAX_REMEDY_ATTEMPTS
        || !value.remedies.every(validAttempt)
        || (value.dispute !== null && !validDispute(value.dispute))
        || (value.active_remedy !== null && !validAttempt(value.active_remedy))
        || typeof value.create_request_digest !== 'string' || !DIGEST.test(value.create_request_digest)) {
        return false;
    }
    if (value.revocation !== null && (!exactKeys(value.revocation, STORED_REVOCATION_KEYS)
        || !validId(value.revocation.evidence_id)
        || typeof value.revocation.evidence_digest !== 'string' || !DIGEST.test(value.revocation.evidence_digest)
        || !validId(value.revocation.target_operation_id)
        || typeof value.revocation.action_digest !== 'string' || !DIGEST.test(value.revocation.action_digest)
        || !validContext(value.revocation.authority_id)
        || !Number.isFinite(instant(value.revocation.revoked_at))
        || value.revocation.effect !== 'future_authority_only'
        || typeof value.revocation.request_digest !== 'string' || !DIGEST.test(value.revocation.request_digest))) {
        return false;
    }
    if (value.original_reconciliation !== null
        && !validOriginalReconciliation(value.original_reconciliation))
        return false;
    if (value.original_reconciliation !== null
        && (value.original.outcome !== 'indeterminate'
            || value.original_reconciliation.original_operation_id !== value.original.operation_id
            || value.original_reconciliation.original_action_digest !== value.original.action_digest
            || value.original_reconciliation.terminal_evidence_digest !== value.original.terminal_evidence_digest
            || instant(value.original_reconciliation.observed_at) < instant(value.original.occurred_at))) {
        return false;
    }
    if (value.resolution !== null && (!exactKeys(value.resolution, STORED_RESOLUTION_KEYS)
        || !validId(value.resolution.evidence_id)
        || typeof value.resolution.evidence_digest !== 'string' || !DIGEST.test(value.resolution.evidence_digest)
        || value.resolution.outcome !== 'no_remedy'
        || !Number.isFinite(instant(value.resolution.resolved_at))
        || !validId(value.resolution.dispute_id)
        || typeof value.resolution.request_digest !== 'string' || !DIGEST.test(value.resolution.request_digest))) {
        return false;
    }
    const committed = value.remedies
        .filter((attempt) => attempt.status === 'executed')
        .reduce((total, attempt) => total + attempt.units, 0);
    if (committed !== value.remedied_units || committed > value.max_remedy_units)
        return false;
    const effectiveOriginalOutcome = value.original.outcome === 'executed'
        ? 'executed' : value.original_reconciliation?.outcome ?? 'indeterminate';
    if (value.status === 'effect_indeterminate' && effectiveOriginalOutcome !== 'indeterminate')
        return false;
    if (value.status === 'original_proved_no_effect') {
        if (effectiveOriginalOutcome !== 'proved_no_effect'
            || value.active_remedy !== null || value.remedies.length !== 0
            || value.remedied_units !== 0)
            return false;
    }
    else if (effectiveOriginalOutcome === 'proved_no_effect')
        return false;
    if (!['effect_indeterminate', 'original_proved_no_effect', 'disputed', 'resolved_no_remedy'].includes(value.status)
        && effectiveOriginalOutcome !== 'executed')
        return false;
    if (value.status === 'disputed' && effectiveOriginalOutcome === 'proved_no_effect')
        return false;
    if (['remedy_authorized', 'remedy_claimed', 'remedy_indeterminate'].includes(value.status)
        !== (value.active_remedy !== null))
        return false;
    return true;
}
function tokenDigest(token) {
    return digest({ claim_token: token });
}
function validEvidencePair(id, evidenceDigest) {
    return validId(id) && typeof evidenceDigest === 'string' && DIGEST.test(evidenceDigest);
}
function evidenceUsed(state, id, evidenceDigest) {
    return state.used_evidence_ids.includes(id) || state.used_evidence_digests.includes(evidenceDigest);
}
function consumeEvidence(state, id, evidenceDigest) {
    state.used_evidence_ids.push(id);
    state.used_evidence_digests.push(evidenceDigest);
}
function expectedContext(state) {
    return snapshot({
        instance_id: state.instance_id,
        tenant_id: state.tenant_id,
        environment: state.environment,
        audience: state.audience,
        original: clone(state.original),
        original_reconciliation: state.original_reconciliation === null
            ? null : clone(state.original_reconciliation),
        remedy_profile_digest: state.remedy_profile_digest,
        destination_binding_digest: state.destination_binding_digest,
        max_remedy_units: state.max_remedy_units,
        unit: state.unit,
        dispute: state.dispute === null ? null : clone(state.dispute),
    }, 'verifier expectation');
}
/**
 * In-process atomic CAS store. It is intentionally marked non-durable; callers
 * selecting production mode must provide a durable external CAS store.
 */
export function createRemedyMemoryStore() {
    const records = new Map();
    const storageKey = (tenantId, instanceId) => `${tenantId.length}:${tenantId}${instanceId}`;
    const evidenceIds = new Set();
    const evidenceDigests = new Set();
    const remedyOperations = new Set();
    const remedyActions = new Set();
    const remedyCaids = new Set();
    const claimKey = (tenantId, value) => `${tenantId.length}:${tenantId}${value}`;
    const attempts = (state) => [
        ...(state.active_remedy === null ? [] : [state.active_remedy]),
        ...state.remedies,
    ];
    const claimEvidence = (state) => {
        for (const id of state.used_evidence_ids)
            evidenceIds.add(claimKey(state.tenant_id, id));
        for (const value of state.used_evidence_digests) {
            evidenceDigests.add(claimKey(state.tenant_id, value));
        }
    };
    const claimAttempts = (state) => {
        for (const attempt of attempts(state)) {
            remedyOperations.add(claimKey(state.tenant_id, attempt.remedy_operation_id));
            remedyActions.add(claimKey(state.tenant_id, attempt.remedy_action_digest));
            remedyCaids.add(claimKey(state.tenant_id, attempt.remedy_caid));
        }
    };
    return Object.freeze({
        durable: false,
        async create(state) {
            let candidate;
            try {
                candidate = snapshot(state, 'remedy state');
            }
            catch {
                return fail('store_state_invalid');
            }
            if (!validState(candidate))
                return fail('store_state_invalid');
            const key = storageKey(candidate.tenant_id, candidate.instance_id);
            if (records.has(key))
                return fail('instance_exists');
            if (candidate.used_evidence_ids.some((id) => evidenceIds.has(claimKey(candidate.tenant_id, id)))
                || candidate.used_evidence_digests.some((value) => (evidenceDigests.has(claimKey(candidate.tenant_id, value)))))
                return fail('evidence_replayed');
            records.set(key, clone(candidate));
            claimEvidence(candidate);
            claimAttempts(candidate);
            return { ok: true, state: clone(candidate) };
        },
        async get({ tenantId, instanceId }) {
            const state = records.get(storageKey(tenantId, instanceId));
            return state ? { ok: true, state: clone(state) } : fail('instance_not_found');
        },
        async compareAndSwap({ tenantId, instanceId, expectedRevision, state }) {
            const key = storageKey(tenantId, instanceId);
            const current = records.get(key);
            if (!current)
                return fail('instance_not_found');
            if (current.revision !== expectedRevision)
                return fail('revision_conflict');
            let candidate;
            try {
                candidate = snapshot(state, 'remedy state');
            }
            catch {
                return fail('store_state_invalid');
            }
            if (!validState(candidate, tenantId, instanceId)
                || candidate.revision !== expectedRevision + 1
                || instant(candidate.updated_at) < instant(current.updated_at)) {
                return fail('store_state_invalid');
            }
            const newEvidenceIds = candidate.used_evidence_ids.filter((id) => (!current.used_evidence_ids.includes(id)));
            const newEvidenceDigests = candidate.used_evidence_digests.filter((value) => (!current.used_evidence_digests.includes(value)));
            if (newEvidenceIds.some((id) => evidenceIds.has(claimKey(tenantId, id)))
                || newEvidenceDigests.some((value) => evidenceDigests.has(claimKey(tenantId, value)))) {
                return fail('evidence_replayed');
            }
            const currentOperations = new Set(attempts(current).map((attempt) => attempt.remedy_operation_id));
            const newAttempts = attempts(candidate).filter((attempt) => (!currentOperations.has(attempt.remedy_operation_id)));
            if (newAttempts.some((attempt) => (remedyOperations.has(claimKey(tenantId, attempt.remedy_operation_id))
                || remedyActions.has(claimKey(tenantId, attempt.remedy_action_digest))
                || remedyCaids.has(claimKey(tenantId, attempt.remedy_caid)))))
                return fail('remedy_operation_replayed');
            records.set(key, clone(candidate));
            claimEvidence(candidate);
            claimAttempts(candidate);
            return { ok: true, state: clone(candidate) };
        },
    });
}
function verifierInput(fields) {
    return snapshot(fields, 'verifier input');
}
function validClock(value) {
    return Number.isSafeInteger(value) && Number(value) >= 0 && Number(value) <= 8_640_000_000_000_000;
}
/** Build a remedy kernel with all trust callbacks and store methods pinned. */
export function createRemedyProgramKernel(options) {
    if (!isDataRecord(options) || Object.keys(options).some((key) => !CONFIG_KEYS.has(key))) {
        throw new TypeError('remedy program configuration invalid');
    }
    const sourceStore = options.store;
    if (!sourceStore || typeof sourceStore.create !== 'function'
        || typeof sourceStore.get !== 'function'
        || typeof sourceStore.compareAndSwap !== 'function') {
        throw new TypeError('remedy program CAS store required');
    }
    for (const key of [
        'verifyOriginalEffect', 'verifyRevocation', 'verifyDispute',
        'verifyRemedyAuthorization', 'verifyRemedyOutcome', 'verifyOriginalReconciliation',
    ]) {
        if (typeof options[key] !== 'function')
            throw new TypeError(`${key} callback required`);
    }
    if (options.verifyResolution !== undefined && typeof options.verifyResolution !== 'function') {
        throw new TypeError('verifyResolution callback invalid');
    }
    if (options.now !== undefined && typeof options.now !== 'function') {
        throw new TypeError('remedy program clock invalid');
    }
    if (options.production === true && options.allowEphemeralState === true) {
        throw new TypeError('production remedy program cannot allow ephemeral state');
    }
    if ((options.production === true || options.allowEphemeralState === false)
        && sourceStore.durable !== true) {
        throw new TypeError('durable remedy program CAS store required');
    }
    const maxDisputeAgeMs = options.maxDisputeAgeMs ?? DEFAULT_MAX_DISPUTE_AGE_MS;
    if (!Number.isSafeInteger(maxDisputeAgeMs) || maxDisputeAgeMs < 1) {
        throw new TypeError('maxDisputeAgeMs invalid');
    }
    const store = Object.freeze({
        durable: sourceStore.durable === true,
        create: sourceStore.create.bind(sourceStore),
        get: sourceStore.get.bind(sourceStore),
        compareAndSwap: sourceStore.compareAndSwap.bind(sourceStore),
    });
    const verifyOriginalEffect = options.verifyOriginalEffect;
    const verifyRevocation = options.verifyRevocation;
    const verifyDispute = options.verifyDispute;
    const verifyRemedyAuthorization = options.verifyRemedyAuthorization;
    const verifyRemedyOutcome = options.verifyRemedyOutcome;
    const verifyOriginalReconciliation = options.verifyOriginalReconciliation;
    const verifyResolution = options.verifyResolution;
    const now = options.now ?? Date.now;
    const clock = () => {
        let value;
        try {
            value = now();
        }
        catch {
            return NaN;
        }
        return validClock(value) ? Number(value) : NaN;
    };
    const checkedState = (value, tenantId, instanceId) => {
        let state;
        try {
            state = snapshot(value, 'stored remedy state');
        }
        catch {
            return fail('store_state_invalid');
        }
        return validState(state, tenantId, instanceId)
            ? pass({ ok: true, state })
            : fail('store_state_invalid');
    };
    const normalizeStoreResult = (value, tenantId, instanceId, proposedState) => {
        if (!isDataRecord(value))
            return fail('store_response_invalid');
        if (value.ok === true)
            return checkedState(value.state ?? proposedState, tenantId, instanceId);
        if (value.applied === true && proposedState)
            return checkedState(value.state ?? proposedState, tenantId, instanceId);
        const reason = value.reason;
        if ([
            'instance_not_found', 'instance_exists', 'revision_conflict', 'clock_regression',
            'evidence_replayed', 'remedy_operation_replayed',
        ].includes(reason)) {
            return fail(reason);
        }
        if (value.ok === false || value.applied === false)
            return fail('store_operation_failed');
        return fail('store_response_invalid');
    };
    const load = async (tenantId, instanceId, creationProbe = false) => {
        if (!validContext(tenantId) || !validId(instanceId))
            return fail('remedy_lookup_invalid');
        try {
            const result = normalizeStoreResult(await store.get({ tenantId, instanceId }), tenantId, instanceId);
            return result.reason === 'instance_not_found' && !creationProbe
                ? fail('remedy_case_not_found') : result;
        }
        catch {
            return fail('store_unavailable');
        }
    };
    const commit = async (state, next) => {
        try {
            const result = normalizeStoreResult(await store.compareAndSwap({
                tenantId: state.tenant_id,
                instanceId: state.instance_id,
                expectedRevision: state.revision,
                state: next,
            }), state.tenant_id, state.instance_id, next);
            return result.reason === 'revision_conflict' ? fail('state_transition_conflict') : result;
        }
        catch {
            return fail('store_unavailable');
        }
    };
    const operationInput = (input, keys, reason) => {
        let value;
        try {
            value = snapshot(input, reason);
        }
        catch {
            return fail(reason);
        }
        return exactKeys(value, keys) ? value : fail(reason);
    };
    const transitionTime = (state) => {
        const current = clock();
        if (!Number.isFinite(current))
            return fail('clock_invalid');
        if (current < instant(state.updated_at))
            return fail('clock_regression');
        return current;
    };
    const touch = (state, at) => {
        const next = clone(state);
        next.revision += 1;
        next.updated_at = new Date(at).toISOString();
        return next;
    };
    const invoke = async (callback, input) => {
        try {
            const result = await callback(verifierInput(input));
            return snapshot(result, 'verifier projection');
        }
        catch {
            return null;
        }
    };
    async function create(input) {
        const parsed = operationInput(input, CREATE_KEYS, 'create_input_invalid');
        if (isFailure(parsed))
            return parsed;
        const value = parsed;
        if (!validId(value.instanceId) || !validContext(value.tenantId)
            || !validContext(value.environment) || !validContext(value.audience)
            || !validOriginal(value.original)
            || typeof value.remedyProfileDigest !== 'string' || !DIGEST.test(value.remedyProfileDigest)
            || typeof value.destinationBindingDigest !== 'string' || !DIGEST.test(value.destinationBindingDigest)
            || !Number.isSafeInteger(value.maxRemedyUnits) || value.maxRemedyUnits < 1
            || !validContext(value.unit) || !isDataRecord(value.evidence)) {
            return fail('create_input_invalid');
        }
        const requestDigest = digest(value);
        const existing = await load(value.tenantId, value.instanceId, true);
        if (existing.ok) {
            return existing.state.create_request_digest === requestDigest
                ? pass({ ok: true, idempotent: true, state: existing.state })
                : fail('instance_exists');
        }
        if (existing.reason !== 'instance_not_found')
            return existing;
        const current = clock();
        if (!Number.isFinite(current))
            return fail('clock_invalid');
        if (instant(value.original.occurred_at) > current)
            return fail('original_effect_time_invalid');
        const verified = await invoke(verifyOriginalEffect, {
            original: clone(value.original),
            evidence: clone(value.evidence),
            expected: {
                instance_id: value.instanceId,
                tenant_id: value.tenantId,
                environment: value.environment,
                audience: value.audience,
                remedy_profile_digest: value.remedyProfileDigest,
                destination_binding_digest: value.destinationBindingDigest,
                max_remedy_units: value.maxRemedyUnits,
                unit: value.unit,
            },
        });
        if (!verified || verified.ok !== true || !exactKeys(verified, VERIFIED_ORIGINAL_KEYS)) {
            return fail('original_effect_invalid');
        }
        if (!ORIGINAL_KEYS.size || [...ORIGINAL_KEYS].some((key) => !same(verified[key], value.original[key]))
            || verified.evidence_digest !== value.original.terminal_evidence_digest) {
            return fail('original_effect_binding_mismatch');
        }
        const at = new Date(current).toISOString();
        const state = {
            version: REMEDY_PROGRAM_VERSION,
            instance_id: value.instanceId,
            tenant_id: value.tenantId,
            environment: value.environment,
            audience: value.audience,
            status: value.original.outcome === 'executed' ? 'effect_executed' : 'effect_indeterminate',
            revision: 0,
            created_at: at,
            updated_at: at,
            original: withoutOk(verified),
            remedy_profile_digest: value.remedyProfileDigest,
            destination_binding_digest: value.destinationBindingDigest,
            max_remedy_units: value.maxRemedyUnits,
            unit: value.unit,
            remedied_units: 0,
            remaining_units: value.maxRemedyUnits,
            used_evidence_ids: [],
            used_evidence_digests: [value.original.terminal_evidence_digest],
            original_reconciliation: null,
            revocation: null,
            dispute: null,
            active_remedy: null,
            remedies: [],
            resolution: null,
            create_request_digest: requestDigest,
        };
        if (!validState(state, value.tenantId, value.instanceId))
            return fail('original_effect_invalid');
        try {
            const result = normalizeStoreResult(await store.create(snapshot(state, 'initial remedy state')), value.tenantId, value.instanceId, state);
            if (result.reason !== 'instance_exists')
                return result;
            const raced = await load(value.tenantId, value.instanceId, true);
            return raced.ok && raced.state.create_request_digest === requestDigest
                ? pass({ ok: true, idempotent: true, state: raced.state })
                : fail('instance_exists');
        }
        catch {
            return fail('store_unavailable');
        }
    }
    async function reconcileOriginalEffect(input) {
        const parsed = operationInput(input, ORIGINAL_RECONCILIATION_INPUT_KEYS, 'original_reconciliation_input_invalid');
        if (isFailure(parsed))
            return parsed;
        const value = parsed;
        if (!validContext(value.tenantId) || !validId(value.instanceId)
            || !['executed', 'proved_no_effect'].includes(value.outcome)
            || !exactKeys(value.evidence, ORIGINAL_RECONCILIATION_EVIDENCE_KEYS)
            || !validEvidencePair(value.evidence.evidence_id, value.evidence.evidence_digest)
            || !Number.isFinite(instant(value.evidence.observed_at))) {
            return fail('original_reconciliation_input_invalid');
        }
        const loaded = await load(value.tenantId, value.instanceId);
        if (!loaded.ok)
            return loaded;
        const state = loaded.state;
        const requestDigest = digest(value);
        if (state.original.outcome !== 'indeterminate')
            return fail('original_effect_already_conclusive');
        if (state.original_reconciliation !== null) {
            return state.original_reconciliation.request_digest === requestDigest
                ? pass({ ok: true, idempotent: true, state })
                : fail('original_reconciliation_conflict');
        }
        if (!['effect_indeterminate', 'disputed'].includes(state.status)
            || state.active_remedy !== null || state.remedies.length !== 0) {
            return fail('original_reconciliation_unavailable');
        }
        if (evidenceUsed(state, value.evidence.evidence_id, value.evidence.evidence_digest)) {
            return fail('evidence_replayed');
        }
        const at = transitionTime(state);
        if (typeof at !== 'number')
            return at;
        const observedAt = instant(value.evidence.observed_at);
        if (observedAt < instant(state.original.occurred_at) || observedAt > at) {
            return fail('original_reconciliation_time_invalid');
        }
        const verified = await invoke(verifyOriginalReconciliation, {
            evidence: clone(value.evidence), outcome: value.outcome,
            expected: expectedContext(state),
        });
        if (!verified || verified.ok !== true
            || !exactKeys(verified, VERIFIED_ORIGINAL_RECONCILIATION_KEYS)) {
            return fail('original_reconciliation_invalid');
        }
        if (verified.evidence_id !== value.evidence.evidence_id
            || verified.evidence_digest !== value.evidence.evidence_digest
            || verified.original_operation_id !== state.original.operation_id
            || verified.original_action_digest !== state.original.action_digest
            || verified.terminal_evidence_digest !== state.original.terminal_evidence_digest
            || verified.outcome !== value.outcome
            || verified.observed_at !== value.evidence.observed_at) {
            return fail('original_reconciliation_binding_mismatch');
        }
        const next = touch(state, at);
        next.original_reconciliation = {
            ...withoutOk(verified), request_digest: requestDigest,
        };
        next.status = value.outcome === 'executed'
            ? (state.dispute === null ? 'effect_executed' : 'disputed')
            : 'original_proved_no_effect';
        consumeEvidence(next, verified.evidence_id, verified.evidence_digest);
        const committed = await commit(state, next);
        return committed.ok ? pass({ ok: true, state: committed.state }) : committed;
    }
    async function recordRevocation(input) {
        const parsed = operationInput(input, REVOCATION_INPUT_KEYS, 'revocation_input_invalid');
        if (isFailure(parsed))
            return parsed;
        const value = parsed;
        if (!validContext(value.tenantId) || !validId(value.instanceId)
            || !exactKeys(value.evidence, REVOCATION_EVIDENCE_KEYS)
            || !validEvidencePair(value.evidence.id, value.evidence.digest)) {
            return fail('revocation_input_invalid');
        }
        const loaded = await load(value.tenantId, value.instanceId);
        if (!loaded.ok)
            return loaded;
        const state = loaded.state;
        const requestDigest = digest(value);
        if (state.revocation !== null) {
            return state.revocation.request_digest === requestDigest
                ? pass({ ok: true, idempotent: true, code: 'late_revocation_recorded', state })
                : fail('revocation_already_recorded');
        }
        if (evidenceUsed(state, value.evidence.id, value.evidence.digest))
            return fail('evidence_replayed');
        const at = transitionTime(state);
        if (typeof at !== 'number')
            return at;
        const verified = await invoke(verifyRevocation, {
            evidence: clone(value.evidence), expected: expectedContext(state),
        });
        if (!verified || verified.ok !== true || !exactKeys(verified, VERIFIED_REVOCATION_KEYS)) {
            return fail('revocation_invalid');
        }
        if (verified.evidence_id !== value.evidence.id
            || verified.evidence_digest !== value.evidence.digest
            || verified.target_operation_id !== state.original.operation_id
            || verified.action_digest !== state.original.action_digest) {
            return fail('revocation_binding_mismatch');
        }
        const revokedAt = instant(verified.revoked_at);
        if (!validContext(verified.authority_id) || !Number.isFinite(revokedAt)
            || revokedAt < instant(state.original.occurred_at) || revokedAt > at) {
            return fail('revocation_time_invalid');
        }
        const next = touch(state, at);
        next.revocation = {
            ...withoutOk(verified),
            effect: 'future_authority_only',
            request_digest: requestDigest,
        };
        consumeEvidence(next, verified.evidence_id, verified.evidence_digest);
        const committed = await commit(state, next);
        return committed.ok
            ? pass({ ok: true, code: 'late_revocation_recorded', state: committed.state })
            : committed;
    }
    async function openDispute(input) {
        const parsed = operationInput(input, DISPUTE_INPUT_KEYS, 'dispute_input_invalid');
        if (isFailure(parsed))
            return parsed;
        const value = parsed;
        if (!validContext(value.tenantId) || !validId(value.instanceId)
            || !exactKeys(value.dispute, DISPUTE_KEYS)
            || !validId(value.dispute.dispute_id)
            || !validEvidencePair(value.dispute.evidence_id, value.dispute.evidence_digest)
            || !validContext(value.dispute.challenger_id)
            || !Number.isSafeInteger(value.dispute.requested_units) || value.dispute.requested_units < 1
            || !Number.isFinite(instant(value.dispute.opened_at))) {
            return fail('dispute_input_invalid');
        }
        const loaded = await load(value.tenantId, value.instanceId);
        if (!loaded.ok)
            return loaded;
        const state = loaded.state;
        const requestDigest = digest(value);
        if (state.dispute !== null) {
            return state.dispute.request_digest === requestDigest
                ? pass({ ok: true, idempotent: true, state })
                : fail('dispute_already_open');
        }
        if (!['effect_executed', 'effect_indeterminate'].includes(state.status)) {
            return fail('remedy_case_unavailable');
        }
        if (evidenceUsed(state, value.dispute.evidence_id, value.dispute.evidence_digest)) {
            return fail('evidence_replayed');
        }
        const at = transitionTime(state);
        if (typeof at !== 'number')
            return at;
        const openedAt = instant(value.dispute.opened_at);
        if (openedAt < instant(state.original.occurred_at) || openedAt > at || at - openedAt > maxDisputeAgeMs) {
            return fail('dispute_not_fresh');
        }
        if (value.dispute.requested_units > state.remaining_units)
            return fail('dispute_limit_exceeded');
        const verified = await invoke(verifyDispute, {
            dispute: clone(value.dispute), expected: expectedContext(state),
        });
        if (!verified || verified.ok !== true || !exactKeys(verified, VERIFIED_DISPUTE_KEYS)) {
            return fail('dispute_invalid');
        }
        if ([...DISPUTE_KEYS].some((key) => !same(verified[key], value.dispute[key]))
            || verified.original_operation_id !== state.original.operation_id
            || verified.original_action_digest !== state.original.action_digest) {
            return fail('dispute_binding_mismatch');
        }
        const next = touch(state, at);
        next.status = 'disputed';
        next.dispute = { ...withoutOk(verified), request_digest: requestDigest };
        consumeEvidence(next, verified.evidence_id, verified.evidence_digest);
        const committed = await commit(state, next);
        return committed.ok ? pass({ ok: true, state: committed.state }) : committed;
    }
    const allAttempts = (state) => [
        ...(state.active_remedy ? [state.active_remedy] : []), ...state.remedies,
    ];
    async function authorizeRemedy(input) {
        const parsed = operationInput(input, AUTHORIZATION_INPUT_KEYS, 'remedy_authorization_input_invalid');
        if (isFailure(parsed))
            return parsed;
        const value = parsed;
        if (!validContext(value.tenantId) || !validId(value.instanceId)
            || !exactKeys(value.authorization, AUTHORIZATION_KEYS)
            || !validEvidencePair(value.authorization.evidence_id, value.authorization.evidence_digest)
            || !validId(value.authorization.remedy_operation_id)
            || typeof value.authorization.remedy_caid !== 'string' || !CAID.test(value.authorization.remedy_caid)
            || typeof value.authorization.remedy_action_digest !== 'string'
            || !DIGEST.test(value.authorization.remedy_action_digest)
            || !Number.isSafeInteger(value.authorization.units) || value.authorization.units < 1
            || !Number.isFinite(instant(value.authorization.authorized_at))) {
            return fail('remedy_authorization_input_invalid');
        }
        if (!validRemedyOwner(value.authorization))
            return fail('remedy_owner_invalid');
        const loaded = await load(value.tenantId, value.instanceId);
        if (!loaded.ok)
            return loaded;
        const state = loaded.state;
        const requestDigest = digest(value);
        if (state.status === 'original_proved_no_effect')
            return fail('remedy_case_terminal');
        if (state.original.outcome === 'indeterminate'
            && state.original_reconciliation?.outcome !== 'executed') {
            return fail('original_effect_indeterminate');
        }
        const priorOperation = allAttempts(state).find((attempt) => (attempt.remedy_operation_id === value.authorization.remedy_operation_id));
        if (priorOperation) {
            return priorOperation.request_digest === requestDigest
                ? pass({ ok: true, idempotent: true, state })
                : fail('remedy_operation_replayed');
        }
        if (state.remaining_units === 0)
            return fail('remedy_limit_exhausted');
        if (['remedied', 'resolved_no_remedy'].includes(state.status))
            return fail('remedy_case_terminal');
        if (state.active_remedy !== null) {
            return state.status === 'remedy_indeterminate'
                ? fail('remedy_indeterminate') : fail('remedy_already_active');
        }
        if (!['disputed', 'partially_remedied'].includes(state.status) || state.dispute === null) {
            return fail('remedy_case_unavailable');
        }
        if (evidenceUsed(state, value.authorization.evidence_id, value.authorization.evidence_digest)) {
            return fail('evidence_replayed');
        }
        const at = transitionTime(state);
        if (typeof at !== 'number')
            return at;
        if (instant(value.authorization.authorized_at) > at
            || instant(value.authorization.authorized_at) < instant(state.dispute.opened_at)) {
            return fail('remedy_authorization_time_invalid');
        }
        const disputeRemaining = state.dispute.requested_units - state.remedied_units;
        if (value.authorization.units > state.remaining_units || value.authorization.units > disputeRemaining) {
            return fail('remedy_limit_exceeded');
        }
        if (value.authorization.remedy_operation_id === state.original.operation_id
            || value.authorization.remedy_action_digest === state.original.action_digest) {
            return fail('remedy_must_be_compensating');
        }
        const verified = await invoke(verifyRemedyAuthorization, {
            authorization: clone(value.authorization), expected: expectedContext(state),
        });
        if (!verified || verified.ok !== true || !exactKeys(verified, VERIFIED_AUTHORIZATION_KEYS)) {
            return fail('remedy_authorization_invalid');
        }
        if (!validRemedyOwner(verified)) {
            return fail('remedy_owner_invalid');
        }
        if ([...AUTHORIZATION_KEYS].some((key) => !same(verified[key], value.authorization[key]))
            || verified.dispute_id !== state.dispute.dispute_id
            || verified.original_operation_id !== state.original.operation_id
            || verified.destination_binding_digest !== state.destination_binding_digest
            || verified.unit !== state.unit) {
            return fail('remedy_authorization_binding_mismatch');
        }
        const next = touch(state, at);
        next.status = 'remedy_authorized';
        next.active_remedy = {
            ...withoutOk(verified),
            request_digest: requestDigest,
            status: 'authorized',
            claim_token_digest: null,
            claimed_at: null,
            claim_request_digest: null,
            outcome: null,
            outcome_evidence: null,
            finalize_request_digest: null,
            reconciliation: null,
            reconcile_request_digest: null,
        };
        consumeEvidence(next, verified.evidence_id, verified.evidence_digest);
        const committed = await commit(state, next);
        return committed.ok ? pass({ ok: true, state: committed.state }) : committed;
    }
    async function claimRemedy(input) {
        const parsed = operationInput(input, CLAIM_KEYS, 'remedy_claim_input_invalid');
        if (isFailure(parsed))
            return parsed;
        const value = parsed;
        if (!validContext(value.tenantId) || !validId(value.instanceId)
            || !validId(value.remedyOperationId)
            || !validContext(value.claimToken) || Buffer.byteLength(value.claimToken, 'utf8') > 256) {
            return fail('remedy_claim_input_invalid');
        }
        const loaded = await load(value.tenantId, value.instanceId);
        if (!loaded.ok)
            return loaded;
        const state = loaded.state;
        if (state.status === 'original_proved_no_effect')
            return fail('remedy_case_terminal');
        if (state.original.outcome === 'indeterminate'
            && state.original_reconciliation?.outcome !== 'executed') {
            return fail('original_effect_indeterminate');
        }
        const requestDigest = digest(value);
        const prior = allAttempts(state).find((attempt) => attempt.remedy_operation_id === value.remedyOperationId);
        if (prior?.claim_request_digest === requestDigest) {
            if (state.status === 'remedy_indeterminate' && state.active_remedy === prior) {
                return fail('remedy_indeterminate');
            }
            return pass({ ok: true, idempotent: true, state });
        }
        if (state.status === 'remedy_indeterminate')
            return fail('remedy_indeterminate');
        if (!state.active_remedy)
            return prior ? fail('remedy_already_finalized') : fail('remedy_not_authorized');
        if (state.active_remedy.remedy_operation_id !== value.remedyOperationId) {
            return fail('remedy_operation_mismatch');
        }
        if (state.active_remedy.status === 'claimed')
            return fail('remedy_claim_owned');
        if (state.active_remedy.status !== 'authorized' || state.status !== 'remedy_authorized') {
            return fail('remedy_not_authorized');
        }
        const at = transitionTime(state);
        if (typeof at !== 'number')
            return at;
        const next = touch(state, at);
        next.status = 'remedy_claimed';
        next.active_remedy.status = 'claimed';
        next.active_remedy.claim_token_digest = tokenDigest(value.claimToken);
        next.active_remedy.claimed_at = new Date(at).toISOString();
        next.active_remedy.claim_request_digest = requestDigest;
        const committed = await commit(state, next);
        return committed.ok ? pass({ ok: true, state: committed.state }) : committed;
    }
    const outcomeExpected = (state, attempt) => ({
        ...clone(expectedContext(state)),
        remedy_operation_id: attempt.remedy_operation_id,
        remedy_caid: attempt.remedy_caid,
        remedy_action_digest: attempt.remedy_action_digest,
        destination_binding_digest: attempt.destination_binding_digest,
        units: attempt.units,
        unit: attempt.unit,
    });
    const outcomeBound = (verified, value, attempt) => verified.evidence_id === value.evidence.evidence_id
        && verified.evidence_digest === value.evidence.evidence_digest
        && verified.remedy_operation_id === attempt.remedy_operation_id
        && verified.remedy_action_digest === attempt.remedy_action_digest
        && verified.destination_binding_digest === attempt.destination_binding_digest
        && verified.units === attempt.units && verified.unit === attempt.unit
        && verified.outcome === value.outcome
        && verified.observed_at === value.evidence.observed_at;
    async function finalizeRemedy(input) {
        const parsed = operationInput(input, FINALIZE_KEYS, 'remedy_outcome_input_invalid');
        if (isFailure(parsed))
            return parsed;
        const value = parsed;
        if (!validContext(value.tenantId) || !validId(value.instanceId)
            || !validId(value.remedyOperationId)
            || !validContext(value.claimToken) || Buffer.byteLength(value.claimToken, 'utf8') > 256
            || !['executed', 'proved_no_effect', 'indeterminate'].includes(value.outcome)
            || !exactKeys(value.evidence, OUTCOME_EVIDENCE_KEYS)
            || !validEvidencePair(value.evidence.evidence_id, value.evidence.evidence_digest)
            || !Number.isFinite(instant(value.evidence.observed_at))) {
            return fail('remedy_outcome_input_invalid');
        }
        const loaded = await load(value.tenantId, value.instanceId);
        if (!loaded.ok)
            return loaded;
        const state = loaded.state;
        const requestDigest = digest(value);
        const prior = allAttempts(state).find((attempt) => attempt.remedy_operation_id === value.remedyOperationId);
        if (prior?.finalize_request_digest === requestDigest) {
            return pass({ ok: true, idempotent: true, state });
        }
        if (state.status === 'remedy_indeterminate')
            return fail('remedy_indeterminate');
        if (!state.active_remedy)
            return prior ? fail('remedy_already_finalized') : fail('remedy_not_authorized');
        const attempt = state.active_remedy;
        if (attempt.remedy_operation_id !== value.remedyOperationId)
            return fail('remedy_operation_mismatch');
        if (attempt.status !== 'claimed' || state.status !== 'remedy_claimed')
            return fail('remedy_not_claimed');
        if (attempt.claim_token_digest !== tokenDigest(value.claimToken))
            return fail('remedy_claim_owned');
        if (evidenceUsed(state, value.evidence.evidence_id, value.evidence.evidence_digest)) {
            return fail('evidence_replayed');
        }
        const at = transitionTime(state);
        if (typeof at !== 'number')
            return at;
        if (instant(value.evidence.observed_at) < instant(attempt.authorized_at)
            || instant(value.evidence.observed_at) > at)
            return fail('remedy_outcome_time_invalid');
        const verified = await invoke(verifyRemedyOutcome, {
            evidence: clone(value.evidence), outcome: value.outcome,
            expected: outcomeExpected(state, attempt), reconciliation: false,
        });
        if (!verified || verified.ok !== true || !exactKeys(verified, VERIFIED_OUTCOME_KEYS)) {
            return fail('remedy_outcome_invalid');
        }
        if (!outcomeBound(verified, value, attempt)) {
            return fail('remedy_outcome_binding_mismatch');
        }
        if (value.outcome === 'executed' && attempt.units > state.remaining_units) {
            return fail('remedy_limit_exceeded');
        }
        const next = touch(state, at);
        const completed = next.active_remedy;
        completed.status = value.outcome;
        completed.outcome = value.outcome;
        completed.outcome_evidence = withoutOk(verified);
        completed.finalize_request_digest = requestDigest;
        consumeEvidence(next, verified.evidence_id, verified.evidence_digest);
        if (value.outcome === 'indeterminate') {
            next.status = 'remedy_indeterminate';
        }
        else {
            next.active_remedy = null;
            next.remedies.push(completed);
            if (value.outcome === 'executed') {
                next.remedied_units += completed.units;
                next.remaining_units -= completed.units;
                next.status = next.remaining_units === 0 ? 'remedied' : 'partially_remedied';
            }
            else {
                next.status = 'disputed';
            }
        }
        const committed = await commit(state, next);
        return committed.ok ? pass({ ok: true, state: committed.state }) : committed;
    }
    async function reconcileRemedy(input) {
        const parsed = operationInput(input, RECONCILE_KEYS, 'remedy_reconciliation_input_invalid');
        if (isFailure(parsed))
            return parsed;
        const value = parsed;
        if (!validContext(value.tenantId) || !validId(value.instanceId)
            || !validId(value.remedyOperationId)
            || !['executed', 'proved_no_effect'].includes(value.outcome)
            || !exactKeys(value.evidence, OUTCOME_EVIDENCE_KEYS)
            || !validEvidencePair(value.evidence.evidence_id, value.evidence.evidence_digest)
            || !Number.isFinite(instant(value.evidence.observed_at))) {
            return fail('remedy_reconciliation_input_invalid');
        }
        const loaded = await load(value.tenantId, value.instanceId);
        if (!loaded.ok)
            return loaded;
        const state = loaded.state;
        const requestDigest = digest(value);
        const prior = allAttempts(state).find((attempt) => attempt.remedy_operation_id === value.remedyOperationId);
        if (prior?.reconcile_request_digest === requestDigest) {
            return pass({ ok: true, idempotent: true, state });
        }
        if (state.status !== 'remedy_indeterminate' || !state.active_remedy
            || state.active_remedy.status !== 'indeterminate') {
            return prior ? fail('remedy_reconciliation_conflict') : fail('remedy_not_indeterminate');
        }
        const attempt = state.active_remedy;
        if (attempt.remedy_operation_id !== value.remedyOperationId)
            return fail('remedy_operation_mismatch');
        if (evidenceUsed(state, value.evidence.evidence_id, value.evidence.evidence_digest)) {
            return fail('evidence_replayed');
        }
        const at = transitionTime(state);
        if (typeof at !== 'number')
            return at;
        if (instant(value.evidence.observed_at) < instant(attempt.outcome_evidence.observed_at)
            || instant(value.evidence.observed_at) > at)
            return fail('remedy_reconciliation_time_invalid');
        const verified = await invoke(verifyRemedyOutcome, {
            evidence: clone(value.evidence), outcome: value.outcome,
            expected: outcomeExpected(state, attempt), reconciliation: true,
        });
        if (!verified || verified.ok !== true || !exactKeys(verified, VERIFIED_OUTCOME_KEYS)) {
            return fail('remedy_reconciliation_invalid');
        }
        if (!outcomeBound(verified, value, attempt)) {
            return fail('remedy_reconciliation_binding_mismatch');
        }
        if (value.outcome === 'executed' && attempt.units > state.remaining_units) {
            return fail('remedy_limit_exceeded');
        }
        const next = touch(state, at);
        const completed = next.active_remedy;
        completed.status = value.outcome;
        completed.outcome = value.outcome;
        completed.reconciliation = withoutOk(verified);
        completed.reconcile_request_digest = requestDigest;
        next.active_remedy = null;
        next.remedies.push(completed);
        consumeEvidence(next, verified.evidence_id, verified.evidence_digest);
        if (value.outcome === 'executed') {
            next.remedied_units += completed.units;
            next.remaining_units -= completed.units;
            next.status = next.remaining_units === 0 ? 'remedied' : 'partially_remedied';
        }
        else {
            next.status = 'disputed';
        }
        const committed = await commit(state, next);
        return committed.ok ? pass({ ok: true, state: committed.state }) : committed;
    }
    async function resolveDispute(input) {
        const parsed = operationInput(input, RESOLUTION_INPUT_KEYS, 'resolution_input_invalid');
        if (isFailure(parsed))
            return parsed;
        const value = parsed;
        if (!validContext(value.tenantId) || !validId(value.instanceId)
            || !exactKeys(value.resolution, RESOLUTION_KEYS)
            || !validEvidencePair(value.resolution.evidence_id, value.resolution.evidence_digest)
            || value.resolution.outcome !== 'no_remedy'
            || !Number.isFinite(instant(value.resolution.resolved_at))) {
            return fail('resolution_input_invalid');
        }
        const loaded = await load(value.tenantId, value.instanceId);
        if (!loaded.ok)
            return loaded;
        const state = loaded.state;
        const requestDigest = digest(value);
        if (state.resolution !== null) {
            return state.resolution.request_digest === requestDigest
                ? pass({ ok: true, idempotent: true, state })
                : fail('remedy_case_terminal');
        }
        if (['remedied', 'resolved_no_remedy'].includes(state.status))
            return fail('remedy_case_terminal');
        if (!['disputed', 'partially_remedied'].includes(state.status)
            || state.dispute === null || state.active_remedy !== null) {
            return fail('resolution_unavailable');
        }
        if (typeof verifyResolution !== 'function')
            return fail('resolution_verifier_unavailable');
        if (evidenceUsed(state, value.resolution.evidence_id, value.resolution.evidence_digest)) {
            return fail('evidence_replayed');
        }
        const at = transitionTime(state);
        if (typeof at !== 'number')
            return at;
        if (instant(value.resolution.resolved_at) < instant(state.dispute.opened_at)
            || instant(value.resolution.resolved_at) > at)
            return fail('resolution_time_invalid');
        const verified = await invoke(verifyResolution, {
            resolution: clone(value.resolution), expected: expectedContext(state),
        });
        if (!verified || verified.ok !== true || !exactKeys(verified, VERIFIED_RESOLUTION_KEYS)) {
            return fail('resolution_invalid');
        }
        if ([...RESOLUTION_KEYS].some((key) => !same(verified[key], value.resolution[key]))
            || verified.dispute_id !== state.dispute.dispute_id) {
            return fail('resolution_binding_mismatch');
        }
        const next = touch(state, at);
        next.status = 'resolved_no_remedy';
        next.resolution = { ...withoutOk(verified), request_digest: requestDigest };
        consumeEvidence(next, verified.evidence_id, verified.evidence_digest);
        const committed = await commit(state, next);
        return committed.ok ? pass({ ok: true, state: committed.state }) : committed;
    }
    async function status(input) {
        const parsed = operationInput(input, new Set(['tenantId', 'instanceId']), 'remedy_lookup_invalid');
        if (isFailure(parsed))
            return parsed;
        const value = parsed;
        return load(value.tenantId, value.instanceId);
    }
    return Object.freeze({
        create, status, recordRevocation, reconcileOriginalEffect, openDispute, authorizeRemedy,
        claimRemedy, finalizeRemedy, reconcileRemedy, resolveDispute,
    });
}
export default {
    REMEDY_PROGRAM_VERSION,
    createRemedyMemoryStore,
    createRemedyProgramKernel,
};
//# sourceMappingURL=remedy-program.js.map