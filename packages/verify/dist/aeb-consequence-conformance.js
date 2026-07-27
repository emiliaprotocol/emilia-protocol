// SPDX-License-Identifier: Apache-2.0
/**
 * Format-neutral executable AEB consequence-admission conformance kernel.
 *
 * The kernel consumes closed, normalized verifier findings. It deliberately
 * keeps native verification, material-action matching, requirement
 * satisfaction, local authorization, local reservation/custody, provider
 * outcome, and observed-effect relation on separate axes.
 *
 * Its atomicity claim is intentionally narrow: `local_atomic` means one
 * linearizable local admission domain reserves operation/native replay and
 * consumes execution authority before provider entry. It makes no remote or
 * federated atomicity, provider truth, effect truth, or exactly-once claim.
 */
import crypto from 'node:crypto';
export const AEB_CONSEQUENCE_CONFORMANCE_VERSION = 'AEB-CONSEQUENCE-CONFORMANCE-v1';
export const AEB_CONSEQUENCE_CASE_VERSION = 'AEB-CONSEQUENCE-CASE-v1';
export const AEB_CONSEQUENCE_CONFORMANCE_REPORT_VERSION = 'AEB-CONSEQUENCE-CONFORMANCE-REPORT-v1';
export const AEB_CONSEQUENCE_LOCAL_ATOMIC_SCOPE = Object.freeze({
    profile: 'local_atomic',
    guarantees: Object.freeze([
        'one_linearizable_local_admission_domain',
        'operation_and_native_replay_reserved_before_invocation',
        'execution_authority_consumed_before_provider_entry',
    ]),
    exclusions: Object.freeze([
        'remote_atomicity',
        'federated_atomicity',
        'provider_commitment',
        'observed_effect_truth',
        'downstream_exactly_once',
    ]),
});
export const AEB_CONSEQUENCE_LIMITS = Object.freeze({
    max_string_bytes: 4096,
    max_depth: 32,
    max_nodes: 65_536,
    max_document_bytes: 1_048_576,
    max_evidence: 16,
    max_requirements: 16,
    max_prior_operations: 64,
    max_replay_units: 128,
    max_vectors: 256,
    max_reasons: 32,
});
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const CAID_RE = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{0,255}$/;
const ROLE_RE = /^[a-z][a-z0-9-]{0,127}$/;
const TOKEN_RE = /^[a-z][a-z0-9_-]{0,127}$/;
const VERSION_RE = /^[A-Za-z0-9][A-Za-z0-9:_.+@/-]{0,127}$/;
const RFC3339_SECOND_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/;
export const AEB_CONSEQUENCE_REASONS = Object.freeze([
    'authenticated_reconciliation',
    'blind_retry_refused',
    'distinct_principal_quorum_unsatisfied',
    'evidence_revoked',
    'evidence_stale',
    'exact_action_mismatch',
    'executor_self_approval_refused',
    'initiator_self_approval_refused',
    'local_atomic_reservation_unavailable',
    'local_policy_denied',
    'native_evidence_replay',
    'native_verification_failed',
    'native_verification_indeterminate',
    'normalized_action_mismatch',
    'operation_binding_mismatch',
    'operation_replay',
    'provider_and_effect_indeterminate',
    'provider_committed_effect_diverged',
    'provider_committed_effect_observed',
    'provider_proven_not_committed',
    'reconciliation_binding_mismatch',
    'reconciliation_indeterminate',
    'required_role_unsatisfied',
    'status_authority_not_pinned',
    'status_unavailable',
    'timeout_after_dispatch',
    'unauthenticated_reconciliation',
]);
export class AebConsequenceConformanceError extends TypeError {
    code;
    path;
    constructor(code, path) {
        super(`${path}: ${code}`);
        this.name = 'AebConsequenceConformanceError';
        this.code = code;
        this.path = path;
    }
}
function fail(code, path) {
    throw new AebConsequenceConformanceError(code, path);
}
function isRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function validUnicode(value) {
    for (let index = 0; index < value.length; index += 1) {
        const code = value.charCodeAt(index);
        if (code >= 0xd800 && code <= 0xdbff) {
            const next = value.charCodeAt(index + 1);
            if (next < 0xdc00 || next > 0xdfff)
                return false;
            index += 1;
        }
        else if (code >= 0xdc00 && code <= 0xdfff)
            return false;
    }
    return true;
}
function canonicalizeInternal(value, state, depth, path) {
    if (depth > AEB_CONSEQUENCE_LIMITS.max_depth)
        fail('max_depth_exceeded', path);
    state.nodes += 1;
    if (state.nodes > AEB_CONSEQUENCE_LIMITS.max_nodes)
        fail('max_nodes_exceeded', path);
    if (value === null)
        return 'null';
    if (typeof value === 'boolean')
        return value ? 'true' : 'false';
    if (typeof value === 'string') {
        if (!validUnicode(value)
            || Buffer.byteLength(value, 'utf8') > AEB_CONSEQUENCE_LIMITS.max_string_bytes) {
            fail('invalid_string', path);
        }
        return JSON.stringify(value);
    }
    if (typeof value === 'number') {
        if (!Number.isSafeInteger(value))
            fail('non_canonical_value', path);
        return JSON.stringify(value);
    }
    if (typeof value !== 'object' || value === undefined)
        fail('non_canonical_value', path);
    if (state.seen.has(value))
        fail('cyclic_value', path);
    state.seen.add(value);
    let result;
    if (Array.isArray(value)) {
        result = `[${value.map((entry, index) => canonicalizeInternal(entry, state, depth + 1, `${path}[${index}]`)).join(',')}]`;
    }
    else {
        if (!isRecord(value))
            fail('non_canonical_value', path);
        result = `{${Object.keys(value).sort().map((key) => {
            if (!validUnicode(key)
                || Buffer.byteLength(key, 'utf8') > AEB_CONSEQUENCE_LIMITS.max_string_bytes) {
                fail('invalid_string', `${path}.{key}`);
            }
            return `${JSON.stringify(key)}:${canonicalizeInternal(value[key], state, depth + 1, `${path}.${key}`)}`;
        }).join(',')}}`;
    }
    state.seen.delete(value);
    return result;
}
export function canonicalizeAebConsequenceConformance(value) {
    const canonical = canonicalizeInternal(value, { nodes: 0, seen: new WeakSet() }, 0, '$');
    if (Buffer.byteLength(canonical, 'utf8') > AEB_CONSEQUENCE_LIMITS.max_document_bytes) {
        fail('max_document_bytes_exceeded', '$');
    }
    return canonical;
}
export function digestAebConsequenceConformance(value) {
    const canonical = canonicalizeAebConsequenceConformance(value);
    // Protocol content commitment, not password or credential storage.
    // codeql[js/insufficient-password-hash]
    return `sha256:${crypto.createHash('sha256').update(canonical, 'utf8').digest('hex')}`;
}
export function digestAebConsequenceCase(value) {
    return digestAebConsequenceConformance(value);
}
function exactObject(value, keys, path) {
    if (!isRecord(value))
        fail('invalid_object', path);
    const allowed = new Set(keys);
    for (const key of Object.keys(value))
        if (!allowed.has(key))
            fail('unknown_key', `${path}.${key}`);
    for (const key of keys)
        if (!Object.hasOwn(value, key))
            fail('missing_key', `${path}.${key}`);
    return value;
}
function boundedString(value, path, pattern) {
    if (typeof value !== 'string' || value.length === 0 || !validUnicode(value)
        || Buffer.byteLength(value, 'utf8') > AEB_CONSEQUENCE_LIMITS.max_string_bytes
        || (pattern && !pattern.test(value)))
        fail('invalid_string', path);
    return value;
}
function enumValue(value, allowed, path) {
    if (typeof value !== 'string' || !allowed.includes(value))
        fail('invalid_enum', path);
    return value;
}
function digestValue(value, path) {
    if (typeof value !== 'string' || !DIGEST_RE.test(value))
        fail('invalid_digest', path);
    return value;
}
function caidValue(value, path) {
    if (typeof value !== 'string' || !CAID_RE.test(value))
        fail('invalid_caid', path);
    return value;
}
function instantValue(value, path) {
    if (typeof value !== 'string' || !RFC3339_SECOND_RE.test(value))
        fail('invalid_instant', path);
    const milliseconds = Date.parse(value);
    if (!Number.isFinite(milliseconds)
        || new Date(milliseconds).toISOString().replace('.000Z', 'Z') !== value) {
        fail('invalid_instant', path);
    }
    return value;
}
function arrayValue(value, maximum, path) {
    if (!Array.isArray(value) || value.length > maximum)
        fail('invalid_array', path);
    return value;
}
function unique(values, path) {
    if (new Set(values).size !== values.length)
        fail('duplicate_value', path);
}
function deepFreeze(value) {
    if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
        for (const child of Object.values(value))
            deepFreeze(child);
        Object.freeze(value);
    }
    return value;
}
function parseRequirement(value, path) {
    const object = exactObject(value, [
        'role', 'principal_kind', 'minimum', 'distinct_principals',
        'exclude_initiator', 'exclude_executor',
    ], path);
    const minimum = object.minimum;
    if (!Number.isSafeInteger(minimum) || Number(minimum) < 1
        || Number(minimum) > AEB_CONSEQUENCE_LIMITS.max_evidence)
        fail('invalid_integer', `${path}.minimum`);
    if (typeof object.distinct_principals !== 'boolean')
        fail('invalid_boolean', `${path}.distinct_principals`);
    if (typeof object.exclude_initiator !== 'boolean')
        fail('invalid_boolean', `${path}.exclude_initiator`);
    if (typeof object.exclude_executor !== 'boolean')
        fail('invalid_boolean', `${path}.exclude_executor`);
    return {
        role: boundedString(object.role, `${path}.role`, ROLE_RE),
        principal_kind: enumValue(object.principal_kind, ['HUMAN', 'MACHINE', 'ORGANIZATION', 'SYSTEM'], `${path}.principal_kind`),
        minimum: Number(minimum),
        distinct_principals: object.distinct_principals,
        exclude_initiator: object.exclude_initiator,
        exclude_executor: object.exclude_executor,
    };
}
function parseOperation(value, path) {
    const object = exactObject(value, [
        'operation_id', 'provider_id', 'initiator_id', 'executor_id', 'caid',
        'normalized_action_digest', 'requirements',
    ], path);
    const requirements = arrayValue(object.requirements, AEB_CONSEQUENCE_LIMITS.max_requirements, `${path}.requirements`).map((entry, index) => parseRequirement(entry, `${path}.requirements[${index}]`));
    if (requirements.length === 0)
        fail('invalid_array', `${path}.requirements`);
    unique(requirements.map((entry) => `${entry.role}\0${entry.principal_kind}`), `${path}.requirements`);
    return {
        operation_id: boundedString(object.operation_id, `${path}.operation_id`, IDENTIFIER_RE),
        provider_id: boundedString(object.provider_id, `${path}.provider_id`, IDENTIFIER_RE),
        initiator_id: boundedString(object.initiator_id, `${path}.initiator_id`, IDENTIFIER_RE),
        executor_id: boundedString(object.executor_id, `${path}.executor_id`, IDENTIFIER_RE),
        caid: caidValue(object.caid, `${path}.caid`),
        normalized_action_digest: digestValue(object.normalized_action_digest, `${path}.normalized_action_digest`),
        requirements,
    };
}
function parseStatus(value, path) {
    const object = exactObject(value, ['verdict', 'authority_pinned', 'checked_at', 'valid_until'], path);
    if (typeof object.authority_pinned !== 'boolean')
        fail('invalid_boolean', `${path}.authority_pinned`);
    const checkedAt = instantValue(object.checked_at, `${path}.checked_at`);
    const validUntil = instantValue(object.valid_until, `${path}.valid_until`);
    if (Date.parse(checkedAt) > Date.parse(validUntil))
        fail('invalid_combination', path);
    return {
        verdict: enumValue(object.verdict, ['CURRENT', 'REVOKED', 'UNAVAILABLE'], `${path}.verdict`),
        authority_pinned: object.authority_pinned,
        checked_at: checkedAt,
        valid_until: validUntil,
    };
}
function parseEvidence(value, path) {
    const object = exactObject(value, [
        'wrapper_digest', 'native_replay_unit', 'native_verification', 'mapped_caid',
        'mapped_action_digest', 'role', 'principal_kind', 'principal_id', 'status',
    ], path);
    return {
        wrapper_digest: digestValue(object.wrapper_digest, `${path}.wrapper_digest`),
        native_replay_unit: digestValue(object.native_replay_unit, `${path}.native_replay_unit`),
        native_verification: enumValue(object.native_verification, ['VERIFIED', 'FAILED', 'INDETERMINATE'], `${path}.native_verification`),
        mapped_caid: caidValue(object.mapped_caid, `${path}.mapped_caid`),
        mapped_action_digest: digestValue(object.mapped_action_digest, `${path}.mapped_action_digest`),
        role: boundedString(object.role, `${path}.role`, ROLE_RE),
        principal_kind: enumValue(object.principal_kind, ['HUMAN', 'MACHINE', 'ORGANIZATION', 'SYSTEM'], `${path}.principal_kind`),
        principal_id: boundedString(object.principal_id, `${path}.principal_id`, IDENTIFIER_RE),
        status: parseStatus(object.status, `${path}.status`),
    };
}
function truthPairValid(provider, effect) {
    if (provider === 'NOT_INVOKED')
        return effect === 'NOT_OBSERVED';
    if (provider === 'PROVEN_NOT_COMMITTED')
        return effect === 'NOT_OBSERVED';
    if (provider === 'INDETERMINATE')
        return effect === 'INDETERMINATE';
    return provider === 'COMMITTED';
}
function terminalTruthPair(provider, effect) {
    return (provider === 'PROVEN_NOT_COMMITTED' && effect === 'NOT_OBSERVED')
        || (provider === 'COMMITTED'
            && (effect === 'OBSERVED_AS_REQUESTED' || effect === 'DIVERGED'));
}
function parsePriorOperation(value, path) {
    const object = exactObject(value, [
        'operation_id', 'caid', 'normalized_action_digest', 'custody',
        'provider_outcome', 'effect_relation',
    ], path);
    const provider = enumValue(object.provider_outcome, ['NOT_INVOKED', 'COMMITTED', 'PROVEN_NOT_COMMITTED', 'INDETERMINATE'], `${path}.provider_outcome`);
    const effect = enumValue(object.effect_relation, ['NOT_OBSERVED', 'OBSERVED_AS_REQUESTED', 'DIVERGED', 'INDETERMINATE'], `${path}.effect_relation`);
    const custody = enumValue(object.custody, ['INVOKING', 'TERMINAL'], `${path}.custody`);
    if (!truthPairValid(provider, effect)
        || (custody === 'TERMINAL' && !terminalTruthPair(provider, effect))) {
        fail('invalid_combination', path);
    }
    return {
        operation_id: boundedString(object.operation_id, `${path}.operation_id`, IDENTIFIER_RE),
        caid: caidValue(object.caid, `${path}.caid`),
        normalized_action_digest: digestValue(object.normalized_action_digest, `${path}.normalized_action_digest`),
        custody,
        provider_outcome: provider,
        effect_relation: effect,
    };
}
function parseReservation(value, path) {
    const object = exactObject(value, ['atomicity', 'prior_operations', 'consumed_native_replay_units'], path);
    const priorOperations = arrayValue(object.prior_operations, AEB_CONSEQUENCE_LIMITS.max_prior_operations, `${path}.prior_operations`).map((entry, index) => parsePriorOperation(entry, `${path}.prior_operations[${index}]`));
    unique(priorOperations.map((entry) => entry.operation_id), `${path}.prior_operations`);
    const replayUnits = arrayValue(object.consumed_native_replay_units, AEB_CONSEQUENCE_LIMITS.max_replay_units, `${path}.consumed_native_replay_units`).map((entry, index) => digestValue(entry, `${path}.consumed_native_replay_units[${index}]`));
    unique(replayUnits, `${path}.consumed_native_replay_units`);
    return {
        atomicity: enumValue(object.atomicity, ['local_atomic', 'unavailable'], `${path}.atomicity`),
        prior_operations: priorOperations,
        consumed_native_replay_units: replayUnits,
    };
}
function parseObservation(value, path) {
    if (value === null)
        return null;
    const object = exactObject(value, ['source', 'provider_outcome', 'effect_relation'], path);
    const provider = enumValue(object.provider_outcome, ['COMMITTED', 'PROVEN_NOT_COMMITTED', 'INDETERMINATE'], `${path}.provider_outcome`);
    const effect = enumValue(object.effect_relation, ['NOT_OBSERVED', 'OBSERVED_AS_REQUESTED', 'DIVERGED', 'INDETERMINATE'], `${path}.effect_relation`);
    if (!truthPairValid(provider, effect))
        fail('invalid_combination', path);
    const source = enumValue(object.source, ['TIMEOUT_AFTER_DISPATCH', 'PROVIDER_EVIDENCE'], `${path}.source`);
    if (source === 'TIMEOUT_AFTER_DISPATCH'
        && (provider !== 'INDETERMINATE' || effect !== 'INDETERMINATE')) {
        fail('invalid_combination', path);
    }
    return { source, provider_outcome: provider, effect_relation: effect };
}
function parseReconciliation(value, path) {
    if (value === null)
        return null;
    const object = exactObject(value, [
        'authenticated', 'provider_id', 'operation_id', 'caid',
        'normalized_action_digest', 'provider_outcome', 'effect_relation',
    ], path);
    if (typeof object.authenticated !== 'boolean')
        fail('invalid_boolean', `${path}.authenticated`);
    const provider = enumValue(object.provider_outcome, ['COMMITTED', 'PROVEN_NOT_COMMITTED', 'INDETERMINATE'], `${path}.provider_outcome`);
    const effect = enumValue(object.effect_relation, ['NOT_OBSERVED', 'OBSERVED_AS_REQUESTED', 'DIVERGED', 'INDETERMINATE'], `${path}.effect_relation`);
    if (!truthPairValid(provider, effect))
        fail('invalid_combination', path);
    return {
        authenticated: object.authenticated,
        provider_id: boundedString(object.provider_id, `${path}.provider_id`, IDENTIFIER_RE),
        operation_id: boundedString(object.operation_id, `${path}.operation_id`, IDENTIFIER_RE),
        caid: caidValue(object.caid, `${path}.caid`),
        normalized_action_digest: digestValue(object.normalized_action_digest, `${path}.normalized_action_digest`),
        provider_outcome: provider,
        effect_relation: effect,
    };
}
export function parseAebConsequenceCase(value) {
    canonicalizeAebConsequenceConformance(value);
    const object = exactObject(value, [
        '@version', 'id', 'mode', 'evaluated_at', 'operation', 'evidence',
        'local_policy', 'reservation', 'observation', 'reconciliation',
    ], '$');
    if (object['@version'] !== AEB_CONSEQUENCE_CASE_VERSION)
        fail('invalid_enum', '$.@version');
    const parsed = {
        '@version': AEB_CONSEQUENCE_CASE_VERSION,
        id: boundedString(object.id, '$.id', IDENTIFIER_RE),
        mode: enumValue(object.mode, ['ADMISSION', 'INVOCATION_OBSERVATION', 'RETRY', 'RECONCILIATION'], '$.mode'),
        evaluated_at: instantValue(object.evaluated_at, '$.evaluated_at'),
        operation: parseOperation(object.operation, '$.operation'),
        evidence: arrayValue(object.evidence, AEB_CONSEQUENCE_LIMITS.max_evidence, '$.evidence')
            .map((entry, index) => parseEvidence(entry, `$.evidence[${index}]`)),
        local_policy: enumValue(object.local_policy, ['PERMIT', 'DENY'], '$.local_policy'),
        reservation: parseReservation(object.reservation, '$.reservation'),
        observation: parseObservation(object.observation, '$.observation'),
        reconciliation: parseReconciliation(object.reconciliation, '$.reconciliation'),
    };
    unique(parsed.evidence.map((entry) => entry.wrapper_digest), '$.evidence.wrapper_digest');
    unique(parsed.evidence.map((entry) => entry.native_replay_unit), '$.evidence.native_replay_unit');
    const prior = parsed.reservation.prior_operations.find((entry) => entry.operation_id === parsed.operation.operation_id);
    if (parsed.mode === 'ADMISSION') {
        if (parsed.observation !== null || parsed.reconciliation !== null)
            fail('invalid_combination', '$.mode');
    }
    else {
        if (parsed.reservation.atomicity !== 'local_atomic' || !prior)
            fail('invalid_combination', '$.reservation');
        if (parsed.mode === 'INVOCATION_OBSERVATION') {
            if (!parsed.observation || parsed.reconciliation !== null || prior.custody !== 'INVOKING') {
                fail('invalid_combination', '$.mode');
            }
        }
        else if (parsed.mode === 'RETRY') {
            if (parsed.observation !== null || parsed.reconciliation !== null)
                fail('invalid_combination', '$.mode');
        }
        else if (parsed.observation !== null || !parsed.reconciliation || prior.custody !== 'INVOKING') {
            fail('invalid_combination', '$.mode');
        }
    }
    return deepFreeze(parsed);
}
const RESULT_KEYS = Object.freeze([
    'verification', 'acceptance', 'action_match', 'satisfaction', 'authorization', 'reservation',
    'custody', 'provider_outcome', 'effect_relation', 'retry', 'reconciliation',
    'decision', 'reasons',
]);
function parseResult(value, path) {
    const object = exactObject(value, RESULT_KEYS, path);
    const reasons = arrayValue(object.reasons, AEB_CONSEQUENCE_LIMITS.max_reasons, `${path}.reasons`)
        .map((entry, index) => enumValue(entry, AEB_CONSEQUENCE_REASONS, `${path}.reasons[${index}]`));
    unique(reasons, `${path}.reasons`);
    if (reasons.some((entry, index) => index > 0 && reasons[index - 1].localeCompare(entry) > 0)) {
        fail('non_canonical_value', `${path}.reasons`);
    }
    const result = {
        verification: enumValue(object.verification, ['VERIFIED', 'FAILED', 'INDETERMINATE'], `${path}.verification`),
        acceptance: enumValue(object.acceptance, ['ACCEPTED', 'REJECTED', 'INDETERMINATE'], `${path}.acceptance`),
        action_match: enumValue(object.action_match, ['MATCH', 'MISMATCH', 'INDETERMINATE'], `${path}.action_match`),
        satisfaction: enumValue(object.satisfaction, ['SATISFIED', 'UNSATISFIED', 'INDETERMINATE'], `${path}.satisfaction`),
        authorization: enumValue(object.authorization, ['AUTHORIZED', 'NOT_AUTHORIZED', 'INDETERMINATE'], `${path}.authorization`),
        reservation: enumValue(object.reservation, ['NOT_ATTEMPTED', 'RESERVED', 'CONSUMED', 'UNAVAILABLE', 'OPERATION_REPLAY', 'NATIVE_EVIDENCE_REPLAY'], `${path}.reservation`),
        custody: enumValue(object.custody, ['UNRESERVED', 'RESERVED', 'INVOKING', 'TERMINAL'], `${path}.custody`),
        provider_outcome: enumValue(object.provider_outcome, ['NOT_INVOKED', 'COMMITTED', 'PROVEN_NOT_COMMITTED', 'INDETERMINATE'], `${path}.provider_outcome`),
        effect_relation: enumValue(object.effect_relation, ['NOT_OBSERVED', 'OBSERVED_AS_REQUESTED', 'DIVERGED', 'INDETERMINATE'], `${path}.effect_relation`),
        retry: enumValue(object.retry, ['NOT_APPLICABLE', 'REFUSED'], `${path}.retry`),
        reconciliation: enumValue(object.reconciliation, ['NOT_APPLICABLE', 'NOT_REQUIRED', 'REQUIRED', 'REFUSED', 'ACCEPTED'], `${path}.reconciliation`),
        decision: enumValue(object.decision, ['ADMIT', 'REFUSE', 'INDETERMINATE', 'RECORDED', 'RECONCILED'], `${path}.decision`),
        reasons,
    };
    if (!truthPairValid(result.provider_outcome, result.effect_relation))
        fail('invalid_combination', path);
    return deepFreeze(result);
}
export function validateAebConsequenceResult(value) {
    try {
        canonicalizeAebConsequenceConformance(value);
        return { valid: true, value: parseResult(value, '$'), errors: [] };
    }
    catch (error) {
        return {
            valid: false,
            errors: [error instanceof Error ? error.message : 'invalid_result'],
        };
    }
}
function sortedReasons(values) {
    return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}
function assessEvidence(input) {
    const reasons = new Set();
    const hasFailed = input.evidence.length === 0
        || input.evidence.some((entry) => entry.native_verification === 'FAILED');
    const hasIndeterminateVerification = input.evidence.some((entry) => entry.native_verification === 'INDETERMINATE');
    const verification = hasFailed ? 'FAILED'
        : hasIndeterminateVerification ? 'INDETERMINATE' : 'VERIFIED';
    if (hasFailed)
        reasons.add('native_verification_failed');
    if (hasIndeterminateVerification)
        reasons.add('native_verification_indeterminate');
    let actionMatch = 'INDETERMINATE';
    if (verification === 'VERIFIED') {
        const caidMismatch = input.evidence.some((entry) => entry.mapped_caid !== input.operation.caid);
        const normalizedMismatch = input.evidence.some((entry) => entry.mapped_action_digest !== input.operation.normalized_action_digest);
        actionMatch = caidMismatch || normalizedMismatch ? 'MISMATCH' : 'MATCH';
        if (caidMismatch)
            reasons.add('exact_action_mismatch');
        if (normalizedMismatch)
            reasons.add('normalized_action_mismatch');
    }
    const evaluationTime = Date.parse(input.evaluated_at);
    const revoked = input.evidence.some((entry) => entry.status.verdict === 'REVOKED');
    const unpinned = input.evidence.some((entry) => !entry.status.authority_pinned);
    const unavailable = input.evidence.some((entry) => entry.status.verdict === 'UNAVAILABLE'
        || Date.parse(entry.status.checked_at) > evaluationTime);
    const stale = input.evidence.some((entry) => entry.status.verdict === 'CURRENT'
        && evaluationTime >= Date.parse(entry.status.valid_until));
    if (revoked)
        reasons.add('evidence_revoked');
    if (unpinned)
        reasons.add('status_authority_not_pinned');
    if (stale)
        reasons.add('evidence_stale');
    if (unavailable)
        reasons.add('status_unavailable');
    let authorityConstraintFailure = false;
    for (const requirement of input.operation.requirements) {
        const candidates = input.evidence.filter((entry) => entry.role === requirement.role
            && entry.principal_kind === requirement.principal_kind);
        if (candidates.length < requirement.minimum) {
            authorityConstraintFailure = true;
            reasons.add('required_role_unsatisfied');
            continue;
        }
        const withoutInitiator = requirement.exclude_initiator
            ? candidates.filter((entry) => entry.principal_id !== input.operation.initiator_id)
            : candidates;
        if (withoutInitiator.length < requirement.minimum) {
            authorityConstraintFailure = true;
            reasons.add('initiator_self_approval_refused');
            continue;
        }
        const eligible = requirement.exclude_executor
            ? withoutInitiator.filter((entry) => entry.principal_id !== input.operation.executor_id)
            : withoutInitiator;
        if (eligible.length < requirement.minimum) {
            authorityConstraintFailure = true;
            reasons.add('executor_self_approval_refused');
            continue;
        }
        if (requirement.distinct_principals
            && new Set(eligible.map((entry) => entry.principal_id)).size < requirement.minimum) {
            authorityConstraintFailure = true;
            reasons.add('distinct_principal_quorum_unsatisfied');
        }
    }
    const acceptance = verification === 'FAILED' || revoked || unpinned
        ? 'REJECTED'
        : verification === 'INDETERMINATE' || stale || unavailable
            ? 'INDETERMINATE'
            : 'ACCEPTED';
    const definitelyUnsatisfied = acceptance === 'REJECTED'
        || actionMatch === 'MISMATCH' || authorityConstraintFailure;
    const indeterminate = acceptance === 'INDETERMINATE';
    const satisfaction = definitelyUnsatisfied ? 'UNSATISFIED'
        : indeterminate ? 'INDETERMINATE' : 'SATISFIED';
    let authorization;
    if (input.local_policy === 'DENY') {
        reasons.add('local_policy_denied');
        authorization = 'NOT_AUTHORIZED';
    }
    else if (satisfaction === 'SATISFIED')
        authorization = 'AUTHORIZED';
    else if (satisfaction === 'INDETERMINATE')
        authorization = 'INDETERMINATE';
    else
        authorization = 'NOT_AUTHORIZED';
    return {
        verification,
        acceptance,
        actionMatch,
        satisfaction,
        authorization,
        reasons: sortedReasons(reasons),
    };
}
function result(assessment, override, additionalReasons = []) {
    return deepFreeze({
        verification: assessment.verification,
        acceptance: assessment.acceptance,
        action_match: assessment.actionMatch,
        satisfaction: assessment.satisfaction,
        authorization: assessment.authorization,
        ...override,
        reasons: sortedReasons([...assessment.reasons, ...additionalReasons]),
    });
}
function priorFor(input) {
    return input.reservation.prior_operations.find((entry) => entry.operation_id === input.operation.operation_id);
}
function exactPriorBinding(input, prior) {
    return prior.caid === input.operation.caid
        && prior.normalized_action_digest === input.operation.normalized_action_digest;
}
function unresolved(provider, effect) {
    return !terminalTruthPair(provider, effect);
}
export function evaluateAebConsequenceCase(value) {
    const input = parseAebConsequenceCase(value);
    const assessment = assessEvidence(input);
    const prior = priorFor(input);
    if (input.mode === 'ADMISSION') {
        if (assessment.authorization !== 'AUTHORIZED') {
            return result(assessment, {
                reservation: 'NOT_ATTEMPTED', custody: 'UNRESERVED',
                provider_outcome: 'NOT_INVOKED', effect_relation: 'NOT_OBSERVED',
                retry: 'NOT_APPLICABLE', reconciliation: 'NOT_APPLICABLE',
                decision: assessment.authorization === 'INDETERMINATE' ? 'INDETERMINATE' : 'REFUSE',
            });
        }
        if (prior) {
            const bindingReason = exactPriorBinding(input, prior)
                ? 'operation_replay' : 'operation_binding_mismatch';
            return result(assessment, {
                reservation: 'OPERATION_REPLAY', custody: prior.custody,
                provider_outcome: prior.provider_outcome, effect_relation: prior.effect_relation,
                retry: 'REFUSED',
                reconciliation: unresolved(prior.provider_outcome, prior.effect_relation)
                    ? 'REQUIRED' : 'NOT_REQUIRED',
                decision: 'REFUSE',
            }, [bindingReason]);
        }
        const consumed = new Set(input.reservation.consumed_native_replay_units);
        if (input.evidence.some((entry) => consumed.has(entry.native_replay_unit))) {
            return result(assessment, {
                reservation: 'NATIVE_EVIDENCE_REPLAY', custody: 'UNRESERVED',
                provider_outcome: 'NOT_INVOKED', effect_relation: 'NOT_OBSERVED',
                retry: 'REFUSED', reconciliation: 'NOT_APPLICABLE', decision: 'REFUSE',
            }, ['native_evidence_replay']);
        }
        if (input.reservation.atomicity === 'unavailable') {
            return result(assessment, {
                reservation: 'UNAVAILABLE', custody: 'UNRESERVED',
                provider_outcome: 'NOT_INVOKED', effect_relation: 'NOT_OBSERVED',
                retry: 'NOT_APPLICABLE', reconciliation: 'NOT_APPLICABLE', decision: 'REFUSE',
            }, ['local_atomic_reservation_unavailable']);
        }
        return result(assessment, {
            reservation: 'RESERVED', custody: 'RESERVED',
            provider_outcome: 'NOT_INVOKED', effect_relation: 'NOT_OBSERVED',
            retry: 'NOT_APPLICABLE', reconciliation: 'NOT_APPLICABLE', decision: 'ADMIT',
        });
    }
    if (!prior)
        fail('invalid_combination', '$.reservation.prior_operations');
    if (!exactPriorBinding(input, prior)) {
        return result(assessment, {
            reservation: 'OPERATION_REPLAY', custody: prior.custody,
            provider_outcome: prior.provider_outcome, effect_relation: prior.effect_relation,
            retry: 'REFUSED', reconciliation: 'REQUIRED', decision: 'REFUSE',
        }, ['operation_binding_mismatch']);
    }
    if (input.mode === 'RETRY') {
        return result(assessment, {
            reservation: 'OPERATION_REPLAY', custody: prior.custody,
            provider_outcome: prior.provider_outcome, effect_relation: prior.effect_relation,
            retry: 'REFUSED',
            reconciliation: unresolved(prior.provider_outcome, prior.effect_relation)
                ? 'REQUIRED' : 'NOT_REQUIRED',
            decision: 'REFUSE',
        }, ['blind_retry_refused']);
    }
    if (input.mode === 'INVOCATION_OBSERVATION') {
        const observation = input.observation;
        const terminal = terminalTruthPair(observation.provider_outcome, observation.effect_relation);
        let reason;
        if (observation.source === 'TIMEOUT_AFTER_DISPATCH')
            reason = 'timeout_after_dispatch';
        else if (observation.provider_outcome === 'INDETERMINATE')
            reason = 'provider_and_effect_indeterminate';
        else if (observation.provider_outcome === 'PROVEN_NOT_COMMITTED')
            reason = 'provider_proven_not_committed';
        else if (observation.effect_relation === 'DIVERGED')
            reason = 'provider_committed_effect_diverged';
        else
            reason = 'provider_committed_effect_observed';
        return result(assessment, {
            reservation: 'CONSUMED', custody: terminal ? 'TERMINAL' : 'INVOKING',
            provider_outcome: observation.provider_outcome,
            effect_relation: observation.effect_relation,
            retry: 'REFUSED', reconciliation: terminal ? 'NOT_REQUIRED' : 'REQUIRED',
            decision: terminal ? 'RECORDED' : 'INDETERMINATE',
        }, [reason]);
    }
    const reconciliation = input.reconciliation;
    if (!reconciliation.authenticated) {
        return result(assessment, {
            reservation: 'CONSUMED', custody: 'INVOKING',
            provider_outcome: prior.provider_outcome, effect_relation: prior.effect_relation,
            retry: 'REFUSED', reconciliation: 'REFUSED', decision: 'REFUSE',
        }, ['unauthenticated_reconciliation']);
    }
    const bindingMatches = reconciliation.provider_id === input.operation.provider_id
        && reconciliation.operation_id === input.operation.operation_id
        && reconciliation.caid === input.operation.caid
        && reconciliation.normalized_action_digest === input.operation.normalized_action_digest;
    if (!bindingMatches) {
        return result(assessment, {
            reservation: 'CONSUMED', custody: 'INVOKING',
            provider_outcome: prior.provider_outcome, effect_relation: prior.effect_relation,
            retry: 'REFUSED', reconciliation: 'REFUSED', decision: 'REFUSE',
        }, ['reconciliation_binding_mismatch']);
    }
    const terminal = terminalTruthPair(reconciliation.provider_outcome, reconciliation.effect_relation);
    if (!terminal) {
        return result(assessment, {
            reservation: 'CONSUMED', custody: 'INVOKING',
            provider_outcome: reconciliation.provider_outcome,
            effect_relation: reconciliation.effect_relation,
            retry: 'REFUSED', reconciliation: 'REQUIRED', decision: 'INDETERMINATE',
        }, ['reconciliation_indeterminate']);
    }
    return result(assessment, {
        reservation: 'CONSUMED', custody: 'TERMINAL',
        provider_outcome: reconciliation.provider_outcome,
        effect_relation: reconciliation.effect_relation,
        retry: 'REFUSED', reconciliation: 'ACCEPTED', decision: 'RECONCILED',
    }, ['authenticated_reconciliation']);
}
function claimScopeCopy() {
    return {
        profile: 'local_atomic',
        guarantees: [...AEB_CONSEQUENCE_LOCAL_ATOMIC_SCOPE.guarantees],
        exclusions: [...AEB_CONSEQUENCE_LOCAL_ATOMIC_SCOPE.exclusions],
    };
}
function parseClaimScope(value, path) {
    const object = exactObject(value, ['profile', 'guarantees', 'exclusions'], path);
    const scope = {
        profile: enumValue(object.profile, ['local_atomic'], `${path}.profile`),
        guarantees: arrayValue(object.guarantees, 16, `${path}.guarantees`)
            .map((entry, index) => boundedString(entry, `${path}.guarantees[${index}]`, TOKEN_RE)),
        exclusions: arrayValue(object.exclusions, 16, `${path}.exclusions`)
            .map((entry, index) => boundedString(entry, `${path}.exclusions[${index}]`, TOKEN_RE)),
    };
    if (canonicalizeAebConsequenceConformance(scope)
        !== canonicalizeAebConsequenceConformance(AEB_CONSEQUENCE_LOCAL_ATOMIC_SCOPE)) {
        fail('invalid_combination', path);
    }
    return scope;
}
function parseSuite(value) {
    canonicalizeAebConsequenceConformance(value);
    const object = exactObject(value, ['@version', 'claim_scope', 'vectors'], '$');
    if (object['@version'] !== AEB_CONSEQUENCE_CONFORMANCE_VERSION)
        fail('invalid_enum', '$.@version');
    const vectors = arrayValue(object.vectors, AEB_CONSEQUENCE_LIMITS.max_vectors, '$.vectors')
        .map((entry, index) => {
        const path = `$.vectors[${index}]`;
        const vectorObject = exactObject(entry, ['id', 'input', 'expected'], path);
        const id = boundedString(vectorObject.id, `${path}.id`, IDENTIFIER_RE);
        const input = parseAebConsequenceCase(vectorObject.input);
        if (input.id !== id)
            fail('invalid_combination', `${path}.input.id`);
        return { id, input, expected: parseResult(vectorObject.expected, `${path}.expected`) };
    });
    if (vectors.length === 0)
        fail('invalid_array', '$.vectors');
    unique(vectors.map((entry) => entry.id), '$.vectors');
    return deepFreeze({
        '@version': AEB_CONSEQUENCE_CONFORMANCE_VERSION,
        claim_scope: parseClaimScope(object.claim_scope, '$.claim_scope'),
        vectors,
    });
}
export function validateAebConsequenceConformanceSuite(value) {
    try {
        return { valid: true, value: parseSuite(value), errors: [] };
    }
    catch (error) {
        return { valid: false, errors: [error instanceof Error ? error.message : 'invalid_suite'] };
    }
}
function parseImplementation(value, path) {
    const object = exactObject(value, ['id', 'version', 'revision'], path);
    return {
        id: boundedString(object.id, `${path}.id`, IDENTIFIER_RE),
        version: boundedString(object.version, `${path}.version`, VERSION_RE),
        revision: boundedString(object.revision, `${path}.revision`, VERSION_RE),
    };
}
function equal(left, right) {
    return canonicalizeAebConsequenceConformance(left)
        === canonicalizeAebConsequenceConformance(right);
}
export function evaluateAebConsequenceSuite(suiteValue, implementationValue) {
    const suite = parseSuite(suiteValue);
    const implementation = parseImplementation(implementationValue, '$.implementation');
    const rows = suite.vectors.map((vector) => {
        const actual = evaluateAebConsequenceCase(vector.input);
        return {
            id: vector.id,
            case_digest: digestAebConsequenceCase(vector.input),
            expected: vector.expected,
            actual,
            pass: equal(vector.expected, actual),
        };
    });
    const passed = rows.filter((row) => row.pass).length;
    const body = {
        '@version': AEB_CONSEQUENCE_CONFORMANCE_REPORT_VERSION,
        suite_digest: digestAebConsequenceConformance(suiteValue),
        claim_scope: claimScopeCopy(),
        implementation,
        rows,
        summary: { total: rows.length, passed, failed: rows.length - passed },
        assurance: {
            self_attested: true,
            certification: false,
            statement: 'SELF_ATTESTED_NOT_CERTIFICATION',
        },
    };
    return deepFreeze({
        ...body,
        report_digest: digestAebConsequenceConformance(body),
    });
}
function parseNonNegativeInteger(value, path) {
    if (!Number.isSafeInteger(value) || Number(value) < 0)
        fail('invalid_integer', path);
    return Number(value);
}
function parseReport(value) {
    canonicalizeAebConsequenceConformance(value);
    const object = exactObject(value, [
        '@version', 'suite_digest', 'claim_scope', 'implementation', 'rows',
        'summary', 'assurance', 'report_digest',
    ], '$');
    if (object['@version'] !== AEB_CONSEQUENCE_CONFORMANCE_REPORT_VERSION)
        fail('invalid_enum', '$.@version');
    const rows = arrayValue(object.rows, AEB_CONSEQUENCE_LIMITS.max_vectors, '$.rows')
        .map((entry, index) => {
        const path = `$.rows[${index}]`;
        const row = exactObject(entry, ['id', 'case_digest', 'expected', 'actual', 'pass'], path);
        if (typeof row.pass !== 'boolean')
            fail('invalid_boolean', `${path}.pass`);
        return {
            id: boundedString(row.id, `${path}.id`, IDENTIFIER_RE),
            case_digest: digestValue(row.case_digest, `${path}.case_digest`),
            expected: parseResult(row.expected, `${path}.expected`),
            actual: parseResult(row.actual, `${path}.actual`),
            pass: row.pass,
        };
    });
    unique(rows.map((row) => row.id), '$.rows');
    const summaryObject = exactObject(object.summary, ['total', 'passed', 'failed'], '$.summary');
    const assuranceObject = exactObject(object.assurance, ['self_attested', 'certification', 'statement'], '$.assurance');
    if (assuranceObject.self_attested !== true || assuranceObject.certification !== false
        || assuranceObject.statement !== 'SELF_ATTESTED_NOT_CERTIFICATION') {
        fail('invalid_combination', '$.assurance');
    }
    return deepFreeze({
        '@version': AEB_CONSEQUENCE_CONFORMANCE_REPORT_VERSION,
        suite_digest: digestValue(object.suite_digest, '$.suite_digest'),
        claim_scope: parseClaimScope(object.claim_scope, '$.claim_scope'),
        implementation: parseImplementation(object.implementation, '$.implementation'),
        rows,
        summary: {
            total: parseNonNegativeInteger(summaryObject.total, '$.summary.total'),
            passed: parseNonNegativeInteger(summaryObject.passed, '$.summary.passed'),
            failed: parseNonNegativeInteger(summaryObject.failed, '$.summary.failed'),
        },
        assurance: {
            self_attested: true,
            certification: false,
            statement: 'SELF_ATTESTED_NOT_CERTIFICATION',
        },
        report_digest: digestValue(object.report_digest, '$.report_digest'),
    });
}
export function validateAebConsequenceSubmission(suiteValue, submissionValue) {
    try {
        const suite = parseSuite(suiteValue);
        const report = parseReport(submissionValue);
        if (report.suite_digest !== digestAebConsequenceConformance(suiteValue)) {
            return { valid: false, conformant: false, errors: ['suite_digest_mismatch'] };
        }
        if (!equal(report.claim_scope, suite.claim_scope)) {
            return { valid: false, conformant: false, errors: ['claim_scope_mismatch'] };
        }
        if (report.rows.length !== suite.vectors.length) {
            return { valid: false, conformant: false, errors: ['row_count_mismatch'] };
        }
        for (let index = 0; index < suite.vectors.length; index += 1) {
            const vector = suite.vectors[index];
            const row = report.rows[index];
            if (row.id !== vector.id)
                return { valid: false, conformant: false, errors: ['row_id_mismatch'] };
            if (row.case_digest !== digestAebConsequenceCase(vector.input)) {
                return { valid: false, conformant: false, errors: ['case_digest_mismatch'] };
            }
            if (!equal(row.expected, vector.expected)) {
                return { valid: false, conformant: false, errors: ['expected_row_mismatch'] };
            }
            if (row.pass !== equal(row.expected, row.actual)) {
                return { valid: false, conformant: false, errors: ['row_pass_mismatch'] };
            }
        }
        const passed = report.rows.filter((row) => row.pass).length;
        if (report.summary.total !== report.rows.length
            || report.summary.passed !== passed
            || report.summary.failed !== report.rows.length - passed) {
            return { valid: false, conformant: false, errors: ['summary_mismatch'] };
        }
        const { report_digest: ignored, ...body } = report;
        void ignored;
        if (report.report_digest !== digestAebConsequenceConformance(body)) {
            return { valid: false, conformant: false, errors: ['report_digest_mismatch'] };
        }
        return { valid: true, conformant: report.summary.failed === 0, errors: [] };
    }
    catch (error) {
        return {
            valid: false,
            conformant: false,
            errors: [error instanceof Error ? error.message : 'invalid_submission'],
        };
    }
}
export default {
    AEB_CONSEQUENCE_CONFORMANCE_VERSION,
    AEB_CONSEQUENCE_CASE_VERSION,
    AEB_CONSEQUENCE_CONFORMANCE_REPORT_VERSION,
    AEB_CONSEQUENCE_LIMITS,
    AEB_CONSEQUENCE_LOCAL_ATOMIC_SCOPE,
    canonicalizeAebConsequenceConformance,
    digestAebConsequenceCase,
    digestAebConsequenceConformance,
    evaluateAebConsequenceCase,
    evaluateAebConsequenceSuite,
    parseAebConsequenceCase,
    validateAebConsequenceConformanceSuite,
    validateAebConsequenceResult,
    validateAebConsequenceSubmission,
};
//# sourceMappingURL=aeb-consequence-conformance.js.map