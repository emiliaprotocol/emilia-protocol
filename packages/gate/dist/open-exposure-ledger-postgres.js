// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Deployment-bound PostgreSQL adapter for the Open Exposure Ledger.
 *
 * Each mutation is one PostgreSQL function call. Authentication is the
 * PostgreSQL session principal plus its private tenant/authority mapping; the
 * application credential field is deliberately never serialized to SQL.
 */
import crypto from 'node:crypto';
import { OPEN_EXPOSURE_HISTORY_VERSION, OPEN_EXPOSURE_LEDGER_VERSION, } from './open-exposure-ledger.js';
export const OPEN_EXPOSURE_POSTGRES_SQL = Object.freeze({
    registerCeiling: 'SELECT open_exposure_private.register_ceiling($1::jsonb) AS result',
    reserve: 'SELECT open_exposure_private.reserve($1::jsonb) AS result',
    beginInvocation: 'SELECT open_exposure_private.begin_invocation($1::jsonb) AS result',
    markIndeterminate: 'SELECT open_exposure_private.mark_indeterminate($1::jsonb) AS result',
    reconcile: 'SELECT open_exposure_private.reconcile($1::jsonb) AS result',
    read: 'SELECT open_exposure_private.read_exposure($1::jsonb) AS result',
    history: 'SELECT open_exposure_private.read_history($1::jsonb) AS result',
    sumOpen: 'SELECT open_exposure_private.sum_open($1::jsonb) AS result',
    listAging: 'SELECT open_exposure_private.list_aging($1::jsonb) AS result',
    listDeadlines: 'SELECT open_exposure_private.list_deadlines($1::jsonb) AS result',
});
export class OpenExposurePostgresProtocolError extends Error {
    constructor(message, options) {
        super(message, options);
        this.name = 'OpenExposurePostgresProtocolError';
    }
}
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{0,511}$/;
const CURRENCY = /^[A-Z]{3}$/;
const OPERATION_TOKEN = /^open-exposure-op:v1:[A-Za-z0-9_-]{32,128}$/;
const RECONCILIATION_TOKEN = /^open-exposure-reconcile:v1:[A-Za-z0-9_-]{32,128}$/;
const STATUSES = new Set([
    'RESERVED', 'INVOKING', 'INDETERMINATE',
    'CLOSED_COMMITTED', 'CLOSED_PROVEN_NOT_COMMITTED',
]);
const REASONS = new Set([
    'unauthenticated', 'wrong_authority', 'authority_separation_required',
    'ceiling_not_configured', 'ceiling_exceeded', 'ceiling_id_conflict',
    'ceiling_scope_conflict', 'exposure_exists', 'exposure_not_found',
    'operation_token_conflict', 'reconciliation_token_conflict',
    'state_conflict', 'reconciliation_required', 'already_closed',
]);
function plain(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function protocol(condition, message) {
    if (!condition)
        throw new OpenExposurePostgresProtocolError(message);
}
function frozenCopy(value) {
    const copy = structuredClone(value);
    const freeze = (candidate) => {
        if (candidate !== null && typeof candidate === 'object' && !Object.isFrozen(candidate)) {
            for (const child of Object.values(candidate))
                freeze(child);
            Object.freeze(candidate);
        }
    };
    freeze(copy);
    return copy;
}
function canonical(value) {
    if (value === null || typeof value === 'boolean' || typeof value === 'string') {
        return JSON.stringify(value);
    }
    if (typeof value === 'number') {
        protocol(Number.isFinite(value), 'cannot hash a non-finite number');
        return JSON.stringify(value);
    }
    if (Array.isArray(value))
        return `[${value.map(canonical).join(',')}]`;
    protocol(plain(value), 'cannot hash a non-plain object');
    return `{${Object.keys(value).sort().map((key) => (`${JSON.stringify(key)}:${canonical(value[key])}`)).join(',')}}`;
}
function digest(domain, value) {
    return `sha256:${crypto.createHash('sha256')
        .update(domain)
        .update('\0')
        .update(canonical(value))
        .digest('hex')}`;
}
function tokenDigest(token) {
    return digest('EP-OPEN-EXPOSURE-TOKEN-v1', token);
}
function text(value, field, pattern = IDENTIFIER) {
    protocol(typeof value === 'string' && pattern.test(value), `database returned invalid ${field}`);
    return value;
}
function nullableText(value, field, pattern = IDENTIFIER) {
    if (value === null)
        return null;
    return text(value, field, pattern);
}
function iso(value, field) {
    protocol(typeof value === 'string', `database returned invalid ${field}`);
    const parsed = Date.parse(value);
    protocol(Number.isFinite(parsed) && new Date(parsed).toISOString() === value, `database returned non-canonical ${field}`);
    return value;
}
function integer(value, field) {
    const candidate = typeof value === 'string' ? Number(value) : value;
    protocol(Number.isSafeInteger(candidate) && Number(candidate) >= 0, `database returned invalid ${field}`);
    return Number(candidate);
}
function minor(value, field, allowZero = false) {
    protocol(typeof value === 'string' && /^(?:0|[1-9][0-9]{0,18})$/.test(value), `database returned invalid ${field}`);
    const parsed = BigInt(value);
    protocol(parsed <= 9223372036854775807n && (allowZero ? parsed >= 0n : parsed > 0n), `database returned out-of-range ${field}`);
    return parsed;
}
function digestArray(value, field) {
    protocol(Array.isArray(value), `database returned invalid ${field}`);
    const parsed = value.map((entry, index) => text(entry, `${field}[${index}]`, SHA256));
    protocol(new Set(parsed).size === parsed.length, `database returned duplicate ${field}`);
    return frozenCopy(parsed);
}
function parseCeiling(value) {
    protocol(plain(value), 'database returned invalid ceiling');
    protocol(value.version === OPEN_EXPOSURE_LEDGER_VERSION, 'database returned unsupported ceiling version');
    protocol(['TENANT', 'PROGRAM', 'COUNTERPARTY', 'ACTION_CLASS'].includes(String(value.scope)), 'database returned invalid ceiling scope');
    return frozenCopy({
        '@version': OPEN_EXPOSURE_LEDGER_VERSION,
        tenantId: text(value.tenant_id, 'ceiling tenant_id'),
        ceilingId: text(value.ceiling_id, 'ceiling ceiling_id'),
        scope: value.scope,
        scopeValue: value.scope === 'TENANT' && value.scope_value === '*'
            ? '*'
            : text(value.scope_value, 'ceiling scope_value'),
        currency: text(value.currency, 'ceiling currency', CURRENCY),
        windowStart: iso(value.window_start, 'ceiling window_start'),
        windowEnd: iso(value.window_end, 'ceiling window_end'),
        limitMinor: minor(value.limit_minor, 'ceiling limit_minor', true),
        policyDigest: text(value.policy_digest, 'ceiling policy_digest', SHA256),
        ceilingDigest: text(value.ceiling_digest, 'ceiling ceiling_digest', SHA256),
    });
}
function parseRecord(value) {
    protocol(plain(value), 'database returned invalid exposure record');
    protocol(value.version === OPEN_EXPOSURE_LEDGER_VERSION, 'database returned unsupported record version');
    protocol(typeof value.status === 'string' && STATUSES.has(value.status), 'database returned invalid exposure status');
    protocol(value.reconciliation_outcome === null
        || ['COMMITTED', 'PROVEN_NOT_COMMITTED', 'INDETERMINATE'].includes(String(value.reconciliation_outcome)), 'database returned invalid reconciliation outcome');
    return frozenCopy({
        '@version': OPEN_EXPOSURE_LEDGER_VERSION,
        tenantId: text(value.tenant_id, 'tenant_id'),
        exposureId: text(value.exposure_id, 'exposure_id'),
        operationTokenDigest: text(value.operation_token_digest, 'operation_token_digest', SHA256),
        reservationDigest: text(value.reservation_digest, 'reservation_digest', SHA256),
        programId: text(value.program_id, 'program_id'),
        counterpartyId: text(value.counterparty_id, 'counterparty_id'),
        actionClass: text(value.action_class, 'action_class'),
        amountMinor: minor(value.amount_minor, 'amount_minor'),
        currency: text(value.currency, 'currency', CURRENCY),
        windowStart: iso(value.window_start, 'window_start'),
        windowEnd: iso(value.window_end, 'window_end'),
        reservedAt: iso(value.reserved_at, 'reserved_at'),
        invokeBy: iso(value.invoke_by, 'invoke_by'),
        reconcileBy: iso(value.reconcile_by, 'reconcile_by'),
        originAuthorityId: text(value.origin_authority_id, 'origin_authority_id'),
        executorAuthorityId: text(value.executor_authority_id, 'executor_authority_id'),
        reconciliationAuthorityId: text(value.reconciliation_authority_id, 'reconciliation_authority_id'),
        reservationEvidenceDigest: text(value.reservation_evidence_digest, 'reservation_evidence_digest', SHA256),
        ceilingDigests: digestArray(value.ceiling_digests, 'ceiling_digests'),
        revision: integer(value.revision, 'revision'),
        status: value.status,
        invokedAt: value.invoked_at === null ? null : iso(value.invoked_at, 'invoked_at'),
        indeterminateEvidenceDigest: nullableText(value.indeterminate_evidence_digest, 'indeterminate_evidence_digest', SHA256),
        reconciliationOutcome: value.reconciliation_outcome,
        reconciliationEvidenceDigest: nullableText(value.reconciliation_evidence_digest, 'reconciliation_evidence_digest', SHA256),
        lastChangedAt: iso(value.last_changed_at, 'last_changed_at'),
        predecessorRecordDigest: nullableText(value.predecessor_record_digest, 'predecessor_record_digest', SHA256),
        recordDigest: text(value.record_digest, 'record_digest', SHA256),
    });
}
function parseHistoryEntry(value) {
    protocol(plain(value), 'database returned invalid history entry');
    protocol(value.version === OPEN_EXPOSURE_HISTORY_VERSION, 'database returned unsupported history version');
    protocol([
        'RESERVED', 'INVOKING', 'INDETERMINATE', 'RECONCILED_INDETERMINATE',
        'CLOSED_COMMITTED', 'CLOSED_PROVEN_NOT_COMMITTED',
    ].includes(String(value.event)), 'database returned invalid history event');
    return frozenCopy({
        '@version': OPEN_EXPOSURE_HISTORY_VERSION,
        tenantId: text(value.tenant_id, 'history tenant_id'),
        exposureId: text(value.exposure_id, 'history exposure_id'),
        sequence: integer(value.sequence, 'history sequence'),
        event: value.event,
        recordDigest: text(value.record_digest, 'history record_digest', SHA256),
        evidenceDigest: text(value.evidence_digest, 'history evidence_digest', SHA256),
        recordedAt: iso(value.recorded_at, 'history recorded_at'),
        predecessorEntryDigest: nullableText(value.predecessor_entry_digest, 'history predecessor_entry_digest', SHA256),
        entryDigest: text(value.entry_digest, 'history entry_digest', SHA256),
    });
}
function parseBreakdowns(value, field) {
    protocol(Array.isArray(value), `database returned invalid ${field}`);
    const parsed = value.map((entry) => {
        protocol(plain(entry), `database returned invalid ${field} entry`);
        return { key: text(entry.key, `${field} key`), amountMinor: minor(entry.amount_minor, `${field} amount`, true) };
    });
    for (let index = 1; index < parsed.length; index += 1) {
        protocol(parsed[index - 1].key < parsed[index].key, `database returned unsorted ${field}`);
    }
    return frozenCopy(parsed);
}
function parseRefusal(value) {
    protocol(value.ok === false && typeof value.reason === 'string'
        && REASONS.has(value.reason), 'database returned invalid refusal');
    return { ok: false, reason: value.reason };
}
function wireAuth(auth) {
    protocol(auth && typeof auth === 'object', 'auth is required');
    protocol(['POLICY_ADMIN', 'ORIGIN', 'EXECUTOR', 'RECONCILER', 'READER'].includes(auth.role), 'auth role is invalid');
    protocol(IDENTIFIER.test(auth.authorityId), 'auth authorityId is invalid');
    return { authority_kind: auth.role, authority_id: auth.authorityId };
}
function wireReservation(input, auth) {
    protocol(OPERATION_TOKEN.test(input.operationToken), 'operationToken is invalid');
    protocol(typeof input.amountMinor === 'bigint' && input.amountMinor > 0n, 'amountMinor is invalid');
    const operationTokenDigest = tokenDigest(input.operationToken);
    const body = {
        version: OPEN_EXPOSURE_LEDGER_VERSION,
        tenant_id: input.tenantId,
        exposure_id: input.exposureId,
        operation_token_digest: operationTokenDigest,
        program_id: input.programId,
        counterparty_id: input.counterpartyId,
        action_class: input.actionClass,
        amount_minor: input.amountMinor.toString(10),
        currency: input.currency,
        window_start: input.windowStart,
        window_end: input.windowEnd,
        reserved_at: input.reservedAt,
        invoke_by: input.invokeBy,
        reconcile_by: input.reconcileBy,
        origin_authority_id: input.originAuthorityId,
        executor_authority_id: input.executorAuthorityId,
        reconciliation_authority_id: input.reconciliationAuthorityId,
        reservation_evidence_digest: input.reservationEvidenceDigest,
        ...wireAuth(auth),
    };
    return {
        ...body,
        reservation_digest: digest('EP-OPEN-EXPOSURE-RESERVATION-WIRE-v1', body),
    };
}
function wireCeiling(input, auth) {
    protocol(typeof input.limitMinor === 'bigint' && input.limitMinor >= 0n, 'limitMinor is invalid');
    const body = {
        version: OPEN_EXPOSURE_LEDGER_VERSION,
        tenant_id: input.tenantId,
        ceiling_id: input.ceilingId,
        scope: input.scope,
        scope_value: input.scopeValue,
        currency: input.currency,
        window_start: input.windowStart,
        window_end: input.windowEnd,
        limit_minor: input.limitMinor.toString(10),
        policy_digest: input.policyDigest,
        ...wireAuth(auth),
    };
    return { ...body, ceiling_digest: digest('EP-OPEN-EXPOSURE-CEILING-WIRE-v1', body) };
}
function roleRefusal(auth, expected) {
    return auth.role === expected ? null : { ok: false, reason: 'wrong_authority' };
}
export function createOpenExposurePostgresLedger(options) {
    protocol(options && typeof options.query === 'function', 'query is required');
    protocol(typeof options.tenantId === 'string' && IDENTIFIER.test(options.tenantId), 'tenantId is invalid');
    function tenantRefusal(tenantId) {
        return tenantId === options.tenantId ? null : { ok: false, reason: 'unauthenticated' };
    }
    async function rpc(sql, payload) {
        const result = await options.query(sql, [JSON.stringify(payload)]);
        protocol(result && result.rowCount === 1 && Array.isArray(result.rows)
            && result.rows.length === 1 && plain(result.rows[0]), 'ledger RPC returned no single result row');
        let raw = result.rows[0].result;
        if (typeof raw === 'string') {
            try {
                raw = JSON.parse(raw);
            }
            catch (cause) {
                throw new OpenExposurePostgresProtocolError('ledger RPC returned invalid JSON', { cause });
            }
        }
        protocol(plain(raw), 'ledger RPC returned an invalid result envelope');
        return raw;
    }
    async function recordMutation(sql, payload) {
        const envelope = await rpc(sql, payload);
        if (envelope.ok === false)
            return parseRefusal(envelope);
        protocol(envelope.ok === true && typeof envelope.replayed === 'boolean', 'ledger RPC returned invalid mutation result');
        return {
            ok: true,
            replayed: envelope.replayed,
            record: parseRecord(envelope.record),
        };
    }
    function referencePayload(input, auth) {
        return {
            version: OPEN_EXPOSURE_LEDGER_VERSION,
            tenant_id: input.tenantId,
            exposure_id: input.exposureId,
            ...wireAuth(auth),
        };
    }
    return {
        durable: true,
        deploymentBound: true,
        singleTenant: true,
        authentication: 'postgres_session_principal',
        atomicReserve: true,
        appendOnlyHistory: true,
        blindRelease: false,
        reconciliationOnlyCloseout: true,
        async registerCeiling(input, auth) {
            const tenantDenied = tenantRefusal(input.tenantId);
            if (tenantDenied)
                return tenantDenied;
            const roleDenied = roleRefusal(auth, 'POLICY_ADMIN');
            if (roleDenied)
                return roleDenied;
            const envelope = await rpc(OPEN_EXPOSURE_POSTGRES_SQL.registerCeiling, wireCeiling(input, auth));
            if (envelope.ok === false)
                return parseRefusal(envelope);
            protocol(envelope.ok === true && typeof envelope.replayed === 'boolean', 'ledger RPC returned invalid ceiling result');
            return {
                ok: true,
                replayed: envelope.replayed,
                ceiling: parseCeiling(envelope.ceiling),
            };
        },
        async reserve(input, auth) {
            const tenantDenied = tenantRefusal(input.tenantId);
            if (tenantDenied)
                return tenantDenied;
            const roleDenied = roleRefusal(auth, 'ORIGIN');
            if (roleDenied)
                return roleDenied;
            if (auth.authorityId !== input.originAuthorityId) {
                return { ok: false, reason: 'wrong_authority' };
            }
            if (new Set([
                input.originAuthorityId,
                input.executorAuthorityId,
                input.reconciliationAuthorityId,
            ]).size !== 3) {
                return { ok: false, reason: 'authority_separation_required' };
            }
            return recordMutation(OPEN_EXPOSURE_POSTGRES_SQL.reserve, wireReservation(input, auth));
        },
        async beginInvocation(input, auth) {
            const tenantDenied = tenantRefusal(input.tenantId);
            if (tenantDenied)
                return tenantDenied;
            const roleDenied = roleRefusal(auth, 'EXECUTOR');
            if (roleDenied)
                return roleDenied;
            protocol(OPERATION_TOKEN.test(input.operationToken), 'operationToken is invalid');
            return recordMutation(OPEN_EXPOSURE_POSTGRES_SQL.beginInvocation, {
                ...referencePayload(input, auth),
                operation_token_digest: tokenDigest(input.operationToken),
                invoked_at: input.invokedAt,
            });
        },
        async markIndeterminate(input, auth) {
            const tenantDenied = tenantRefusal(input.tenantId);
            if (tenantDenied)
                return tenantDenied;
            const roleDenied = roleRefusal(auth, 'EXECUTOR');
            if (roleDenied)
                return roleDenied;
            protocol(OPERATION_TOKEN.test(input.operationToken), 'operationToken is invalid');
            return recordMutation(OPEN_EXPOSURE_POSTGRES_SQL.markIndeterminate, {
                ...referencePayload(input, auth),
                operation_token_digest: tokenDigest(input.operationToken),
                evidence_digest: input.evidenceDigest,
                observed_at: input.observedAt,
            });
        },
        async reconcile(input, auth) {
            const tenantDenied = tenantRefusal(input.tenantId);
            if (tenantDenied)
                return tenantDenied;
            const roleDenied = roleRefusal(auth, 'RECONCILER');
            if (roleDenied)
                return roleDenied;
            protocol(OPERATION_TOKEN.test(input.operationToken), 'operationToken is invalid');
            protocol(RECONCILIATION_TOKEN.test(input.reconciliationToken), 'reconciliationToken is invalid');
            const reconciliationTokenDigest = tokenDigest(input.reconciliationToken);
            const body = {
                ...referencePayload(input, auth),
                operation_token_digest: tokenDigest(input.operationToken),
                reconciliation_token_digest: reconciliationTokenDigest,
                outcome: input.outcome,
                evidence_digest: input.evidenceDigest,
                observed_at: input.observedAt,
            };
            return recordMutation(OPEN_EXPOSURE_POSTGRES_SQL.reconcile, {
                ...body,
                request_digest: digest('EP-OPEN-EXPOSURE-RECONCILIATION-WIRE-v1', body),
            });
        },
        async read(input, auth) {
            const tenantDenied = tenantRefusal(input.tenantId);
            if (tenantDenied)
                return tenantDenied;
            const envelope = await rpc(OPEN_EXPOSURE_POSTGRES_SQL.read, referencePayload(input, auth));
            if (envelope.ok === false)
                return parseRefusal(envelope);
            protocol(envelope.ok === true, 'ledger RPC returned invalid read result');
            return { ok: true, record: envelope.record === null ? null : parseRecord(envelope.record) };
        },
        async history(input, auth) {
            const tenantDenied = tenantRefusal(input.tenantId);
            if (tenantDenied)
                return tenantDenied;
            const envelope = await rpc(OPEN_EXPOSURE_POSTGRES_SQL.history, referencePayload(input, auth));
            if (envelope.ok === false)
                return parseRefusal(envelope);
            protocol(envelope.ok === true && Array.isArray(envelope.entries), 'ledger RPC returned invalid history result');
            return { ok: true, entries: frozenCopy(envelope.entries.map(parseHistoryEntry)) };
        },
        async sumOpen(input, auth) {
            const tenantDenied = tenantRefusal(input.tenantId);
            if (tenantDenied)
                return tenantDenied;
            const envelope = await rpc(OPEN_EXPOSURE_POSTGRES_SQL.sumOpen, {
                version: OPEN_EXPOSURE_LEDGER_VERSION,
                tenant_id: input.tenantId,
                currency: input.currency,
                window_start: input.windowStart,
                window_end: input.windowEnd,
                program_id: input.programId ?? null,
                counterparty_id: input.counterpartyId ?? null,
                action_class: input.actionClass ?? null,
                ...wireAuth(auth),
            });
            if (envelope.ok === false)
                return parseRefusal(envelope);
            protocol(envelope.ok === true, 'ledger RPC returned invalid sum result');
            return {
                ok: true,
                totalMinor: minor(envelope.total_minor, 'total_minor', true),
                byProgram: parseBreakdowns(envelope.by_program, 'by_program'),
                byCounterparty: parseBreakdowns(envelope.by_counterparty, 'by_counterparty'),
                byActionClass: parseBreakdowns(envelope.by_action_class, 'by_action_class'),
                byStatus: parseBreakdowns(envelope.by_status, 'by_status'),
            };
        },
        async listAging(input, auth) {
            const tenantDenied = tenantRefusal(input.tenantId);
            if (tenantDenied)
                return tenantDenied;
            const envelope = await rpc(OPEN_EXPOSURE_POSTGRES_SQL.listAging, {
                version: OPEN_EXPOSURE_LEDGER_VERSION,
                tenant_id: input.tenantId,
                as_of: input.asOf,
                minimum_age_ms: input.minimumAgeMs,
                limit: input.limit,
                ...wireAuth(auth),
            });
            if (envelope.ok === false)
                return parseRefusal(envelope);
            protocol(envelope.ok === true && Array.isArray(envelope.records), 'ledger RPC returned invalid aging result');
            return { ok: true, records: frozenCopy(envelope.records.map(parseRecord)) };
        },
        async listDeadlines(input, auth) {
            const tenantDenied = tenantRefusal(input.tenantId);
            if (tenantDenied)
                return tenantDenied;
            const envelope = await rpc(OPEN_EXPOSURE_POSTGRES_SQL.listDeadlines, {
                version: OPEN_EXPOSURE_LEDGER_VERSION,
                tenant_id: input.tenantId,
                due_at_or_before: input.dueAtOrBefore,
                limit: input.limit,
                ...wireAuth(auth),
            });
            if (envelope.ok === false)
                return parseRefusal(envelope);
            protocol(envelope.ok === true && Array.isArray(envelope.records), 'ledger RPC returned invalid deadline result');
            return { ok: true, records: frozenCopy(envelope.records.map(parseRecord)) };
        },
    };
}
//# sourceMappingURL=open-exposure-ledger-postgres.js.map