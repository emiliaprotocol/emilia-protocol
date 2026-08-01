// SPDX-License-Identifier: Apache-2.0
/**
 * Open Exposure Ledger v1.
 *
 * The ledger reserves fixed minor-unit exposure before provider entry. A
 * reservation remains open while RESERVED, INVOKING, or INDETERMINATE and can
 * be closed only by a separately authenticated reconciliation authority. The
 * in-memory implementation is a linearizable conformance/reference store; it
 * is not a durability claim.
 */
import crypto from 'node:crypto';
import { performance } from 'node:perf_hooks';
export const OPEN_EXPOSURE_LEDGER_VERSION = 'EP-OPEN-EXPOSURE-LEDGER-v1';
export const OPEN_EXPOSURE_HISTORY_VERSION = 'EP-OPEN-EXPOSURE-HISTORY-v1';
export class OpenExposureValidationError extends TypeError {
    code;
    constructor(code, message) {
        super(message);
        this.name = 'OpenExposureValidationError';
        this.code = code;
    }
}
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{0,511}$/;
const CURRENCY = /^[A-Z]{3}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const OPERATION_TOKEN = /^open-exposure-op:v1:[A-Za-z0-9_-]{32,128}$/;
const RECONCILIATION_TOKEN = /^open-exposure-reconcile:v1:[A-Za-z0-9_-]{32,128}$/;
const CAID = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const OPEN_STATUSES = new Set([
    'RESERVED', 'INVOKING', 'INDETERMINATE',
]);
const SCOPES = [
    'TENANT', 'PROGRAM', 'COUNTERPARTY', 'ACTION_CLASS',
];
function fail(code, message) {
    throw new OpenExposureValidationError(code, message);
}
function canonical(value) {
    if (value === null || typeof value === 'boolean' || typeof value === 'string') {
        return JSON.stringify(value);
    }
    if (typeof value === 'number') {
        if (!Number.isFinite(value))
            fail('invalid_number', 'numbers must be finite');
        return JSON.stringify(value);
    }
    if (typeof value === 'bigint')
        return JSON.stringify({ '@bigint': value.toString(10) });
    if (Array.isArray(value))
        return `[${value.map(canonical).join(',')}]`;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
        fail('invalid_object', 'values must be plain objects');
    }
    return `{${Object.keys(value).sort().map((key) => (`${JSON.stringify(key)}:${canonical(value[key])}`)).join(',')}}`;
}
function digest(domain, value) {
    return `sha256:${crypto.createHash('sha256')
        .update(domain)
        .update('\0')
        .update(canonical(value))
        .digest('hex')}`;
}
function frozenCopy(value) {
    return deepFreeze(structuredClone(value));
}
function deepFreeze(value) {
    if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
        for (const child of Object.values(value))
            deepFreeze(child);
        Object.freeze(value);
    }
    return value;
}
function identifier(value, field) {
    if (typeof value !== 'string' || !IDENTIFIER.test(value)) {
        fail('invalid_identifier', `${field} is invalid`);
    }
}
function sha256(value, field) {
    if (typeof value !== 'string' || !SHA256.test(value)) {
        fail('invalid_digest', `${field} must be a sha256 digest`);
    }
}
function instant(value, field) {
    if (typeof value !== 'string')
        fail('invalid_time', `${field} must be an RFC3339 instant`);
    const parsed = Date.parse(value);
    if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
        fail('invalid_time', `${field} must be a canonical millisecond UTC instant`);
    }
    return parsed;
}
function positiveBigInt(value, field) {
    if (typeof value !== 'bigint' || value <= 0n || value > 9223372036854775807n) {
        fail('invalid_amount', `${field} must be a positive signed 64-bit bigint`);
    }
}
function nonNegativeBigInt(value, field) {
    if (typeof value !== 'bigint' || value < 0n || value > 9223372036854775807n) {
        fail('invalid_amount', `${field} must be a non-negative signed 64-bit bigint`);
    }
}
function validateAuth(auth) {
    if (!auth || !['POLICY_ADMIN', 'ORIGIN', 'EXECUTOR', 'RECONCILER', 'READER'].includes(auth.role)) {
        fail('invalid_auth', 'auth role is invalid');
    }
    identifier(auth.authorityId, 'auth.authorityId');
    if (typeof auth.credential !== 'string' || auth.credential.length < 1 || auth.credential.length > 4096) {
        fail('invalid_auth', 'auth credential is invalid');
    }
}
function validateWindow(windowStart, windowEnd) {
    if (instant(windowStart, 'windowStart') >= instant(windowEnd, 'windowEnd')) {
        fail('invalid_window', 'windowStart must precede windowEnd');
    }
}
function validateCeiling(input) {
    identifier(input.tenantId, 'tenantId');
    identifier(input.ceilingId, 'ceilingId');
    if (!SCOPES.includes(input.scope))
        fail('invalid_scope', 'ceiling scope is invalid');
    if (!(input.scope === 'TENANT' && input.scopeValue === '*')) {
        identifier(input.scopeValue, 'scopeValue');
    }
    if (input.scope === 'TENANT' && input.scopeValue !== '*') {
        fail('invalid_scope', 'TENANT scopeValue must be *');
    }
    if (input.scope !== 'TENANT' && input.scopeValue === '*') {
        fail('invalid_scope', 'non-tenant scopeValue cannot be *');
    }
    if (!CURRENCY.test(input.currency))
        fail('invalid_currency', 'currency must be ISO-like uppercase ASCII');
    validateWindow(input.windowStart, input.windowEnd);
    nonNegativeBigInt(input.limitMinor, 'limitMinor');
    sha256(input.policyDigest, 'policyDigest');
}
function validateReservation(input) {
    for (const [field, value] of Object.entries({
        tenantId: input.tenantId,
        exposureId: input.exposureId,
        programId: input.programId,
        programVersion: input.programVersion,
        counterpartyId: input.counterpartyId,
        actionClass: input.actionClass,
        originAuthorityId: input.originAuthorityId,
        executorAuthorityId: input.executorAuthorityId,
        reconciliationAuthorityId: input.reconciliationAuthorityId,
    }))
        identifier(value, field);
    if (typeof input.caid !== 'string' || !CAID.test(input.caid)) {
        fail('invalid_caid', 'caid is invalid');
    }
    for (const [field, value] of Object.entries({
        programSourceDigest: input.programSourceDigest,
        programDigest: input.programDigest,
        actionDigest: input.actionDigest,
        admissionSnapshotDigest: input.admissionSnapshotDigest,
        authorizationDigest: input.authorizationDigest,
    }))
        sha256(value, field);
    if (!OPERATION_TOKEN.test(input.operationToken))
        fail('invalid_operation_token', 'operationToken is invalid');
    positiveBigInt(input.amountMinor, 'amountMinor');
    if (!CURRENCY.test(input.currency))
        fail('invalid_currency', 'currency must be ISO-like uppercase ASCII');
    validateWindow(input.windowStart, input.windowEnd);
    const reservedAt = instant(input.reservedAt, 'reservedAt');
    const invokeBy = instant(input.invokeBy, 'invokeBy');
    const reconcileBy = instant(input.reconcileBy, 'reconcileBy');
    const authorizationExpiresAt = instant(input.authorizationExpiresAt, 'authorizationExpiresAt');
    if (reservedAt < instant(input.windowStart, 'windowStart')
        || reservedAt >= instant(input.windowEnd, 'windowEnd')) {
        fail('invalid_time', 'reservedAt must be inside the ceiling window');
    }
    if (invokeBy < reservedAt || reconcileBy < invokeBy
        || invokeBy > instant(input.windowEnd, 'windowEnd')
        || invokeBy > authorizationExpiresAt
        || authorizationExpiresAt < reservedAt) {
        fail('invalid_time', 'deadlines must be monotonic');
    }
    sha256(input.reservationEvidenceDigest, 'reservationEvidenceDigest');
}
function validateInvocationBinding(input) {
    identifier(input.programVersion, 'programVersion');
    if (typeof input.caid !== 'string' || !CAID.test(input.caid)) {
        fail('invalid_caid', 'caid is invalid');
    }
    for (const [field, value] of Object.entries({
        programSourceDigest: input.programSourceDigest,
        programDigest: input.programDigest,
        actionDigest: input.actionDigest,
        admissionSnapshotDigest: input.admissionSnapshotDigest,
        authorizationDigest: input.authorizationDigest,
    }))
        sha256(value, field);
    instant(input.authorizationExpiresAt, 'authorizationExpiresAt');
}
function invocationBindingMatches(record, input) {
    return record.programVersion === input.programVersion
        && record.programSourceDigest === input.programSourceDigest
        && record.programDigest === input.programDigest
        && record.caid === input.caid
        && record.actionDigest === input.actionDigest
        && record.admissionSnapshotDigest === input.admissionSnapshotDigest
        && record.authorizationDigest === input.authorizationDigest
        && record.authorizationExpiresAt === input.authorizationExpiresAt;
}
function validateReference(input) {
    identifier(input.tenantId, 'tenantId');
    identifier(input.exposureId, 'exposureId');
}
function tokenDigest(token) {
    return digest('EP-OPEN-EXPOSURE-TOKEN-v1', token);
}
function permitDigest(record, permit) {
    return digest('EP-OPEN-EXPOSURE-INVOCATION-PERMIT-v1', {
        permit,
        tenantId: record.tenantId,
        exposureId: record.exposureId,
        operationTokenDigest: record.operationTokenDigest,
        reservationDigest: record.reservationDigest,
        programVersion: record.programVersion,
        programSourceDigest: record.programSourceDigest,
        programDigest: record.programDigest,
        caid: record.caid,
        actionDigest: record.actionDigest,
        admissionSnapshotDigest: record.admissionSnapshotDigest,
        authorizationDigest: record.authorizationDigest,
        authorizationExpiresAt: record.authorizationExpiresAt,
    });
}
function key(...parts) {
    return parts.join('\u0000');
}
function ceilingScopeValue(input, scope) {
    if (scope === 'TENANT')
        return '*';
    if (scope === 'PROGRAM')
        return input.programId;
    if (scope === 'COUNTERPARTY')
        return input.counterpartyId;
    return input.actionClass;
}
function ceilingScopeKey(input) {
    return key(input.tenantId, input.scope, input.scopeValue, input.currency, input.windowStart, input.windowEnd);
}
function recordBody(record) {
    return record;
}
function makeRecord(body) {
    return frozenCopy({
        ...body,
        recordDigest: digest('EP-OPEN-EXPOSURE-RECORD-v1', recordBody(body)),
    });
}
function isOpen(record) {
    return OPEN_STATUSES.has(record.status);
}
function compareText(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}
function addBreakdown(source) {
    return frozenCopy([...source.entries()]
        .sort(([left], [right]) => compareText(left, right))
        .map(([breakdownKey, amountMinor]) => ({ key: breakdownKey, amountMinor })));
}
export function createMemoryOpenExposureLedger(options) {
    if (!options || typeof options.authenticate !== 'function') {
        fail('authenticator_required', 'authenticate is required');
    }
    if (options.clock !== undefined && typeof options.clock !== 'function') {
        fail('clock_invalid', 'clock must be a function');
    }
    const readClock = options.clock ?? (() => (new Date(performance.timeOrigin + performance.now()).toISOString()));
    let lastClockMs = null;
    function trustedNow() {
        let value;
        try {
            value = readClock();
        }
        catch (cause) {
            throw new OpenExposureValidationError('clock_failed', `trusted clock failed${cause instanceof Error ? `: ${cause.message}` : ''}`);
        }
        const parsed = instant(value, 'clock');
        if (lastClockMs !== null && parsed < lastClockMs) {
            fail('clock_regressed', 'trusted clock regressed');
        }
        lastClockMs = parsed;
        return value;
    }
    const ceilingsById = new Map();
    const ceilingsByScope = new Map();
    const records = new Map();
    const operations = new Map();
    const histories = new Map();
    const reconciliationTokens = new Map();
    let mutexTail = Promise.resolve();
    async function exclusive(operation) {
        let release;
        const mine = new Promise((resolve) => { release = resolve; });
        const previous = mutexTail;
        mutexTail = mine;
        await previous;
        try {
            return await operation();
        }
        finally {
            release();
        }
    }
    async function authenticated(tenantId, auth, expectedRole, expectedAuthority) {
        validateAuth(auth);
        let accepted = false;
        try {
            accepted = await options.authenticate(frozenCopy({ tenantId, auth }));
        }
        catch {
            accepted = false;
        }
        if (!accepted)
            return { ok: false, reason: 'unauthenticated' };
        if ((expectedRole && auth.role !== expectedRole)
            || (expectedAuthority && auth.authorityId !== expectedAuthority)) {
            return { ok: false, reason: 'wrong_authority' };
        }
        return null;
    }
    function appendHistory(record, event, evidenceDigest, recordedAt) {
        const recordKey = key(record.tenantId, record.exposureId);
        const existing = histories.get(recordKey) ?? [];
        const predecessor = existing.at(-1)?.entryDigest ?? null;
        const body = {
            '@version': OPEN_EXPOSURE_HISTORY_VERSION,
            tenantId: record.tenantId,
            exposureId: record.exposureId,
            sequence: existing.length,
            event,
            programVersion: record.programVersion,
            programSourceDigest: record.programSourceDigest,
            programDigest: record.programDigest,
            caid: record.caid,
            actionDigest: record.actionDigest,
            admissionSnapshotDigest: record.admissionSnapshotDigest,
            authorizationDigest: record.authorizationDigest,
            authorizationExpiresAt: record.authorizationExpiresAt,
            invocationPermitDigest: record.invocationPermitDigest,
            recordDigest: record.recordDigest,
            evidenceDigest,
            recordedAt,
            predecessorEntryDigest: predecessor,
        };
        const entry = frozenCopy({
            ...body,
            entryDigest: digest('EP-OPEN-EXPOSURE-HISTORY-ENTRY-v1', body),
        });
        histories.set(recordKey, [...existing, entry]);
    }
    function replaceRecord(current, update) {
        const { recordDigest: predecessorRecordDigest, ...body } = current;
        return makeRecord({
            ...body,
            ...update,
            revision: current.revision + 1,
            predecessorRecordDigest,
        });
    }
    function recordFor(input) {
        return records.get(key(input.tenantId, input.exposureId)) ?? null;
    }
    function operationMatches(record, operationToken) {
        return record.operationTokenDigest === tokenDigest(operationToken);
    }
    return {
        durable: false,
        atomicReserve: true,
        appendOnlyHistory: true,
        blindRelease: false,
        reconciliationOnlyCloseout: true,
        testOnly: true,
        async registerCeiling(input, auth) {
            validateCeiling(input);
            const denied = await authenticated(input.tenantId, auth, 'POLICY_ADMIN');
            if (denied)
                return denied;
            return exclusive(() => {
                const idKey = key(input.tenantId, input.ceilingId);
                const scopeKey = ceilingScopeKey(input);
                const body = {
                    '@version': OPEN_EXPOSURE_LEDGER_VERSION,
                    ...structuredClone(input),
                };
                const candidate = frozenCopy({
                    ...body,
                    ceilingDigest: digest('EP-OPEN-EXPOSURE-CEILING-v1', body),
                });
                const byId = ceilingsById.get(idKey);
                if (byId) {
                    return byId.ceilingDigest === candidate.ceilingDigest
                        ? { ok: true, ceiling: byId, replayed: true }
                        : { ok: false, reason: 'ceiling_id_conflict' };
                }
                const byScope = ceilingsByScope.get(scopeKey);
                if (byScope) {
                    return byScope.ceilingDigest === candidate.ceilingDigest
                        ? { ok: true, ceiling: byScope, replayed: true }
                        : { ok: false, reason: 'ceiling_scope_conflict' };
                }
                ceilingsById.set(idKey, candidate);
                ceilingsByScope.set(scopeKey, candidate);
                return { ok: true, ceiling: candidate, replayed: false };
            });
        },
        async reserve(input, auth) {
            validateReservation(input);
            const denied = await authenticated(input.tenantId, auth, 'ORIGIN', input.originAuthorityId);
            if (denied)
                return denied;
            if (new Set([
                input.originAuthorityId,
                input.executorAuthorityId,
                input.reconciliationAuthorityId,
            ]).size !== 3) {
                return { ok: false, reason: 'authority_separation_required' };
            }
            const operationTokenDigest = tokenDigest(input.operationToken);
            const { operationToken: _operationToken, ...reservationInput } = structuredClone(input);
            const reservationBody = { ...reservationInput, operationTokenDigest };
            const reservationDigest = digest('EP-OPEN-EXPOSURE-RESERVATION-v1', reservationBody);
            return exclusive(() => {
                const operationKey = key(input.tenantId, operationTokenDigest);
                const existingOperation = operations.get(operationKey);
                if (existingOperation) {
                    return existingOperation.reservationDigest === reservationDigest
                        ? { ok: true, record: existingOperation.record, replayed: true }
                        : { ok: false, reason: 'operation_token_conflict' };
                }
                const recordKey = key(input.tenantId, input.exposureId);
                if (records.has(recordKey))
                    return { ok: false, reason: 'exposure_exists' };
                const applicable = [];
                for (const scope of SCOPES) {
                    const configured = ceilingsByScope.get(key(input.tenantId, scope, ceilingScopeValue(input, scope), input.currency, input.windowStart, input.windowEnd));
                    if (!configured)
                        return { ok: false, reason: 'ceiling_not_configured' };
                    applicable.push(configured);
                }
                const open = [...records.values()].filter((record) => (record.tenantId === input.tenantId
                    && record.currency === input.currency
                    && record.windowStart === input.windowStart
                    && record.windowEnd === input.windowEnd
                    && isOpen(record)));
                for (const configured of applicable) {
                    const used = open
                        .filter((record) => {
                        if (configured.scope === 'TENANT')
                            return true;
                        if (configured.scope === 'PROGRAM')
                            return record.programId === configured.scopeValue;
                        if (configured.scope === 'COUNTERPARTY')
                            return record.counterpartyId === configured.scopeValue;
                        return record.actionClass === configured.scopeValue;
                    })
                        .reduce((sum, record) => sum + record.amountMinor, 0n);
                    if (used > configured.limitMinor
                        || input.amountMinor > configured.limitMinor - used) {
                        return { ok: false, reason: 'ceiling_exceeded' };
                    }
                }
                const record = makeRecord({
                    '@version': OPEN_EXPOSURE_LEDGER_VERSION,
                    tenantId: input.tenantId,
                    exposureId: input.exposureId,
                    operationTokenDigest,
                    reservationDigest,
                    programId: input.programId,
                    programVersion: input.programVersion,
                    programSourceDigest: input.programSourceDigest,
                    programDigest: input.programDigest,
                    caid: input.caid,
                    actionDigest: input.actionDigest,
                    admissionSnapshotDigest: input.admissionSnapshotDigest,
                    authorizationDigest: input.authorizationDigest,
                    authorizationExpiresAt: input.authorizationExpiresAt,
                    counterpartyId: input.counterpartyId,
                    actionClass: input.actionClass,
                    amountMinor: input.amountMinor,
                    currency: input.currency,
                    windowStart: input.windowStart,
                    windowEnd: input.windowEnd,
                    reservedAt: input.reservedAt,
                    invokeBy: input.invokeBy,
                    reconcileBy: input.reconcileBy,
                    originAuthorityId: input.originAuthorityId,
                    executorAuthorityId: input.executorAuthorityId,
                    reconciliationAuthorityId: input.reconciliationAuthorityId,
                    reservationEvidenceDigest: input.reservationEvidenceDigest,
                    ceilingDigests: applicable.map((entry) => entry.ceilingDigest).sort(compareText),
                    revision: 0,
                    status: 'RESERVED',
                    invokedAt: null,
                    invocationPermitDigest: null,
                    indeterminateEvidenceDigest: null,
                    reconciliationOutcome: null,
                    reconciliationEvidenceDigest: null,
                    lastChangedAt: input.reservedAt,
                    predecessorRecordDigest: null,
                });
                records.set(recordKey, record);
                operations.set(operationKey, { reservationDigest, record });
                appendHistory(record, 'RESERVED', input.reservationEvidenceDigest, input.reservedAt);
                return { ok: true, record, replayed: false };
            });
        },
        async beginInvocation(input, auth) {
            validateReference(input);
            if (!OPERATION_TOKEN.test(input.operationToken))
                fail('invalid_operation_token', 'operationToken is invalid');
            validateInvocationBinding(input);
            const initial = recordFor(input);
            if (!initial) {
                const denied = await authenticated(input.tenantId, auth, 'EXECUTOR');
                return denied ?? { ok: false, reason: 'exposure_not_found' };
            }
            const denied = await authenticated(input.tenantId, auth, 'EXECUTOR', initial.executorAuthorityId);
            if (denied)
                return denied;
            return exclusive(() => {
                const current = recordFor(input);
                if (!current)
                    return { ok: false, reason: 'exposure_not_found' };
                if (!operationMatches(current, input.operationToken)) {
                    return { ok: false, reason: 'operation_token_conflict' };
                }
                if (!invocationBindingMatches(current, input)) {
                    return { ok: false, reason: 'immutable_binding_conflict' };
                }
                if (current.status === 'INVOKING' || current.status === 'INDETERMINATE') {
                    return { ok: false, reason: 'reconciliation_required' };
                }
                if (!isOpen(current))
                    return { ok: false, reason: 'already_closed' };
                if (current.status !== 'RESERVED')
                    return { ok: false, reason: 'state_conflict' };
                const invokedAt = trustedNow();
                if (instant(invokedAt, 'clock') > instant(current.invokeBy, 'invokeBy')
                    || instant(invokedAt, 'clock') > instant(current.authorizationExpiresAt, 'authorizationExpiresAt')) {
                    return { ok: false, reason: 'invocation_expired' };
                }
                if (instant(invokedAt, 'clock') < instant(current.reservedAt, 'reservedAt')) {
                    return { ok: false, reason: 'state_conflict' };
                }
                const invocationPermit = `open-exposure-invoke:v1:${crypto.randomBytes(32).toString('hex')}`;
                const next = replaceRecord(current, {
                    status: 'INVOKING',
                    invokedAt,
                    invocationPermitDigest: permitDigest(current, invocationPermit),
                    lastChangedAt: invokedAt,
                });
                records.set(key(input.tenantId, input.exposureId), next);
                appendHistory(next, 'INVOKING', current.reservationEvidenceDigest, invokedAt);
                return {
                    ok: true,
                    record: next,
                    replayed: false,
                    invocationPermit,
                };
            });
        },
        async markIndeterminate(input, auth) {
            validateReference(input);
            if (!OPERATION_TOKEN.test(input.operationToken))
                fail('invalid_operation_token', 'operationToken is invalid');
            sha256(input.evidenceDigest, 'evidenceDigest');
            instant(input.observedAt, 'observedAt');
            const initial = recordFor(input);
            if (!initial) {
                const denied = await authenticated(input.tenantId, auth, 'EXECUTOR');
                return denied ?? { ok: false, reason: 'exposure_not_found' };
            }
            const denied = await authenticated(input.tenantId, auth, 'EXECUTOR', initial.executorAuthorityId);
            if (denied)
                return denied;
            return exclusive(() => {
                const current = recordFor(input);
                if (!current)
                    return { ok: false, reason: 'exposure_not_found' };
                if (!operationMatches(current, input.operationToken)) {
                    return { ok: false, reason: 'operation_token_conflict' };
                }
                if (current.status === 'INDETERMINATE') {
                    return current.indeterminateEvidenceDigest === input.evidenceDigest
                        && current.lastChangedAt === input.observedAt
                        ? { ok: true, record: current, replayed: true }
                        : { ok: false, reason: 'state_conflict' };
                }
                if (!isOpen(current))
                    return { ok: false, reason: 'already_closed' };
                if (current.status !== 'INVOKING')
                    return { ok: false, reason: 'state_conflict' };
                if (current.invokedAt && instant(input.observedAt, 'observedAt') < instant(current.invokedAt, 'invokedAt')) {
                    return { ok: false, reason: 'state_conflict' };
                }
                const next = replaceRecord(current, {
                    status: 'INDETERMINATE',
                    indeterminateEvidenceDigest: input.evidenceDigest,
                    lastChangedAt: input.observedAt,
                });
                records.set(key(input.tenantId, input.exposureId), next);
                appendHistory(next, 'INDETERMINATE', input.evidenceDigest, input.observedAt);
                return { ok: true, record: next, replayed: false };
            });
        },
        async reconcile(input, auth) {
            validateReference(input);
            if (!OPERATION_TOKEN.test(input.operationToken))
                fail('invalid_operation_token', 'operationToken is invalid');
            if (!RECONCILIATION_TOKEN.test(input.reconciliationToken)) {
                fail('invalid_reconciliation_token', 'reconciliationToken is invalid');
            }
            if (!['COMMITTED', 'PROVEN_NOT_COMMITTED', 'INDETERMINATE'].includes(input.outcome)) {
                fail('invalid_outcome', 'reconciliation outcome is invalid');
            }
            sha256(input.evidenceDigest, 'evidenceDigest');
            instant(input.observedAt, 'observedAt');
            const initial = recordFor(input);
            if (!initial) {
                const denied = await authenticated(input.tenantId, auth, 'RECONCILER');
                return denied ?? { ok: false, reason: 'exposure_not_found' };
            }
            const denied = await authenticated(input.tenantId, auth, 'RECONCILER', initial.reconciliationAuthorityId);
            if (denied)
                return denied;
            const reconciliationTokenDigest = tokenDigest(input.reconciliationToken);
            const { operationToken: _operationToken, reconciliationToken: _reconciliationToken, ...reconciliationInput } = structuredClone(input);
            const requestDigest = digest('EP-OPEN-EXPOSURE-RECONCILIATION-v1', {
                ...reconciliationInput,
                operationTokenDigest: tokenDigest(input.operationToken),
                reconciliationTokenDigest,
            });
            return exclusive(() => {
                const reconciliationKey = key(input.tenantId, reconciliationTokenDigest);
                const prior = reconciliationTokens.get(reconciliationKey);
                if (prior) {
                    return prior.requestDigest === requestDigest
                        ? { ok: true, record: prior.record, replayed: true }
                        : { ok: false, reason: 'reconciliation_token_conflict' };
                }
                const current = recordFor(input);
                if (!current)
                    return { ok: false, reason: 'exposure_not_found' };
                if (!operationMatches(current, input.operationToken)) {
                    return { ok: false, reason: 'operation_token_conflict' };
                }
                if (!isOpen(current))
                    return { ok: false, reason: 'already_closed' };
                if (instant(input.observedAt, 'observedAt') < instant(current.lastChangedAt, 'lastChangedAt')) {
                    return { ok: false, reason: 'state_conflict' };
                }
                if (input.outcome === 'COMMITTED' && current.status === 'RESERVED') {
                    return { ok: false, reason: 'state_conflict' };
                }
                if (input.outcome === 'INDETERMINATE' && current.status === 'RESERVED') {
                    return { ok: false, reason: 'state_conflict' };
                }
                const status = input.outcome === 'COMMITTED'
                    ? 'CLOSED_COMMITTED'
                    : input.outcome === 'PROVEN_NOT_COMMITTED'
                        ? 'CLOSED_PROVEN_NOT_COMMITTED'
                        : 'INDETERMINATE';
                const next = replaceRecord(current, {
                    status,
                    indeterminateEvidenceDigest: input.outcome === 'INDETERMINATE'
                        ? input.evidenceDigest
                        : current.indeterminateEvidenceDigest,
                    reconciliationOutcome: input.outcome,
                    reconciliationEvidenceDigest: input.evidenceDigest,
                    lastChangedAt: input.observedAt,
                });
                records.set(key(input.tenantId, input.exposureId), next);
                const event = input.outcome === 'COMMITTED'
                    ? 'CLOSED_COMMITTED'
                    : input.outcome === 'PROVEN_NOT_COMMITTED'
                        ? 'CLOSED_PROVEN_NOT_COMMITTED'
                        : 'RECONCILED_INDETERMINATE';
                appendHistory(next, event, input.evidenceDigest, input.observedAt);
                reconciliationTokens.set(reconciliationKey, { requestDigest, record: next });
                return { ok: true, record: next, replayed: false };
            });
        },
        async read(input, auth) {
            validateReference(input);
            const denied = await authenticated(input.tenantId, auth, 'READER');
            if (denied)
                return denied;
            return { ok: true, record: recordFor(input) };
        },
        async history(input, auth) {
            validateReference(input);
            const denied = await authenticated(input.tenantId, auth, 'READER');
            if (denied)
                return denied;
            return {
                ok: true,
                entries: frozenCopy(histories.get(key(input.tenantId, input.exposureId)) ?? []),
            };
        },
        async sumOpen(input, auth) {
            identifier(input.tenantId, 'tenantId');
            if (!CURRENCY.test(input.currency))
                fail('invalid_currency', 'currency is invalid');
            validateWindow(input.windowStart, input.windowEnd);
            if (input.programId !== undefined)
                identifier(input.programId, 'programId');
            if (input.counterpartyId !== undefined)
                identifier(input.counterpartyId, 'counterpartyId');
            if (input.actionClass !== undefined)
                identifier(input.actionClass, 'actionClass');
            const denied = await authenticated(input.tenantId, auth, 'READER');
            if (denied)
                return denied;
            const selected = [...records.values()].filter((record) => (record.tenantId === input.tenantId
                && record.currency === input.currency
                && record.windowStart === input.windowStart
                && record.windowEnd === input.windowEnd
                && (input.programId === undefined || record.programId === input.programId)
                && (input.counterpartyId === undefined || record.counterpartyId === input.counterpartyId)
                && (input.actionClass === undefined || record.actionClass === input.actionClass)
                && isOpen(record)));
            const maps = {
                program: new Map(),
                counterparty: new Map(),
                actionClass: new Map(),
                status: new Map(),
            };
            for (const record of selected) {
                maps.program.set(record.programId, (maps.program.get(record.programId) ?? 0n) + record.amountMinor);
                maps.counterparty.set(record.counterpartyId, (maps.counterparty.get(record.counterpartyId) ?? 0n) + record.amountMinor);
                maps.actionClass.set(record.actionClass, (maps.actionClass.get(record.actionClass) ?? 0n) + record.amountMinor);
                maps.status.set(record.status, (maps.status.get(record.status) ?? 0n) + record.amountMinor);
            }
            return {
                ok: true,
                totalMinor: selected.reduce((sum, record) => sum + record.amountMinor, 0n),
                byProgram: addBreakdown(maps.program),
                byCounterparty: addBreakdown(maps.counterparty),
                byActionClass: addBreakdown(maps.actionClass),
                byStatus: addBreakdown(maps.status),
            };
        },
        async listAging(input, auth) {
            identifier(input.tenantId, 'tenantId');
            const asOf = instant(input.asOf, 'asOf');
            if (!Number.isSafeInteger(input.minimumAgeMs) || input.minimumAgeMs < 0) {
                fail('invalid_age', 'minimumAgeMs must be a non-negative safe integer');
            }
            if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 10_000) {
                fail('invalid_limit', 'limit is invalid');
            }
            const denied = await authenticated(input.tenantId, auth, 'READER');
            if (denied)
                return denied;
            const selected = [...records.values()]
                .filter((record) => record.tenantId === input.tenantId
                && isOpen(record)
                && asOf - instant(record.reservedAt, 'reservedAt') >= input.minimumAgeMs)
                .sort((left, right) => compareText(left.reservedAt, right.reservedAt)
                || compareText(left.exposureId, right.exposureId))
                .slice(0, input.limit);
            return { ok: true, records: frozenCopy(selected) };
        },
        async listDeadlines(input, auth) {
            identifier(input.tenantId, 'tenantId');
            const dueAtOrBefore = instant(input.dueAtOrBefore, 'dueAtOrBefore');
            if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 10_000) {
                fail('invalid_limit', 'limit is invalid');
            }
            const denied = await authenticated(input.tenantId, auth, 'READER');
            if (denied)
                return denied;
            const deadline = (record) => (record.status === 'RESERVED' ? record.invokeBy : record.reconcileBy);
            const selected = [...records.values()]
                .filter((record) => record.tenantId === input.tenantId
                && isOpen(record)
                && instant(deadline(record), 'deadline') <= dueAtOrBefore)
                .sort((left, right) => compareText(deadline(left), deadline(right))
                || compareText(left.exposureId, right.exposureId))
                .slice(0, input.limit);
            return { ok: true, records: frozenCopy(selected) };
        },
    };
}
//# sourceMappingURL=open-exposure-ledger.js.map