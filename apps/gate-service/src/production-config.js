// SPDX-License-Identifier: Apache-2.0
// Generated from production-config.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
import { createAtomicEvidenceLog, createDurableConsumptionStore, } from '../../../packages/gate/index.js';
import { createPostgresEvidenceBackend } from '../../../packages/gate/evidence-postgres.js';
import { createSiemForwarder } from '../../../packages/gate/siem.js';
import { createPostgresBackend } from '../../../packages/gate/store-postgres.js';
import { strictJsonGate } from '../../../packages/require-receipt/strict-json.js';
import { createStaticBearerAuthenticator } from './auth.js';
import { createGithubRestConnector } from './github-client.js';
import { GITHUB_REPOSITORY_DELETE_ACTION } from './runtime.js';
const ACTION_TABLE = 'ep_gate_actions';
const REPOSITORY = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;
const EVIDENCE_OPERATIONS = new Set(['head', 'record', 'history', 'verify', 'export', 'metrics']);
export const ACTION_STORE_SQL = Object.freeze({
    create: `INSERT INTO ${ACTION_TABLE} (id, record) VALUES ($1, $2::jsonb) ON CONFLICT (id) DO NOTHING`,
    get: `SELECT record FROM ${ACTION_TABLE}
WHERE id = $1 AND record ->> 'principal_id' = $2
  AND record ->> 'tenant_id' = $3 AND record ->> 'gate_id' = $4`,
    update: `UPDATE ${ACTION_TABLE}
SET record = record || $5::jsonb, updated_at = now()
WHERE id = $1 AND record ->> 'principal_id' = $2
  AND record ->> 'tenant_id' = $3 AND record ->> 'gate_id' = $4`,
    transition: `UPDATE ${ACTION_TABLE}
SET record = record || $6::jsonb, updated_at = now()
WHERE id = $1 AND record ->> 'principal_id' = $2
  AND record ->> 'tenant_id' = $3 AND record ->> 'gate_id' = $4
  AND record ->> 'status' = ANY($5::text[])`,
    reconcileInterrupted: `UPDATE ${ACTION_TABLE}
SET record = record || $5::jsonb, updated_at = now()
WHERE record ->> 'action' = $1
  AND record ->> 'tenant_id' = $2 AND record ->> 'gate_id' = $3
  AND record ->> 'status' = ANY($4::text[])`,
    health: `SELECT
  to_regclass('public.${ACTION_TABLE}') IS NOT NULL AS table_ready,
  CASE WHEN to_regclass('public.${ACTION_TABLE}') IS NULL THEN FALSE
    ELSE has_table_privilege(current_user, to_regclass('public.${ACTION_TABLE}'), 'SELECT,INSERT,UPDATE') END AS can_use`,
});
function plainObject(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function pgResult(result, operation, { rowsMatch = false } = {}) {
    const res = result;
    if (!res || !Number.isInteger(res.rowCount) || res.rowCount < 0
        || !Array.isArray(res.rows) || (rowsMatch && res.rows.length !== res.rowCount)) {
        throw new Error(`${operation}: malformed Postgres result`);
    }
    return res;
}
function jsonObject(value, operation) {
    let parsed = value;
    if (typeof value === 'string') {
        try {
            parsed = JSON.parse(value);
        }
        catch {
            throw new Error(`${operation}: malformed JSON record`);
        }
    }
    if (!plainObject(parsed))
        throw new Error(`${operation}: malformed JSON record`);
    return structuredClone(parsed);
}
function safePatch(patch) {
    const p = patch;
    if (!plainObject(p))
        throw new TypeError('action patch must be an object');
    for (const key of ['id', 'action', 'principal_id', 'tenant_id', 'gate_id', 'target', 'created_at']) {
        if (Object.hasOwn(p, key))
            throw new TypeError(`action patch cannot change ${key}`);
    }
    return structuredClone(p);
}
/**
 * @param {{
 *   query?: (text: string, values?: unknown[]) => Promise<{rowCount: number, rows: object[]}>,
 *   tenantId?: string,
 *   gateId?: string,
 *   close?: (() => Promise<unknown>) | null
 * }} [options]
 */
export function createPostgresActionStore({ query, tenantId, gateId, close = null } = {}) {
    if (typeof query !== 'function')
        throw new TypeError('Postgres action store requires query');
    if (close !== null && typeof close !== 'function')
        throw new TypeError('Postgres action store close must be a function');
    for (const [name, value] of [['tenantId', tenantId], ['gateId', gateId]]) {
        if (typeof value !== 'string' || value.length === 0 || value.length > 256 || value.includes('\0')) {
            throw new TypeError(`Postgres action store ${name} is invalid`);
        }
    }
    return {
        durable: true,
        async create(record) {
            if (!plainObject(record) || typeof record.id !== 'string'
                || record.tenant_id !== tenantId || record.gate_id !== gateId) {
                throw new TypeError('action record invalid');
            }
            const result = pgResult(await query(ACTION_STORE_SQL.create, [record.id, JSON.stringify(record)]), 'action create');
            if (result.rowCount > 1)
                throw new Error('action create affected multiple rows');
            return result.rowCount === 1;
        },
        async get(id, principalId) {
            const result = pgResult(await query(ACTION_STORE_SQL.get, [id, principalId, tenantId, gateId]), 'action get', { rowsMatch: true });
            if (result.rowCount > 1)
                throw new Error('action get returned multiple rows');
            return result.rowCount === 0 ? null : jsonObject(result.rows[0].record, 'action get');
        },
        async update(id, principalId, patch) {
            const result = pgResult(await query(ACTION_STORE_SQL.update, [
                id,
                principalId,
                tenantId,
                gateId,
                JSON.stringify(safePatch(patch)),
            ]), 'action update');
            if (result.rowCount > 1)
                throw new Error('action update affected multiple rows');
            return result.rowCount === 1;
        },
        async transition(id, principalId, statuses, patch) {
            if (!Array.isArray(statuses) || statuses.length === 0
                || statuses.some((status) => typeof status !== 'string')) {
                throw new TypeError('action transition statuses invalid');
            }
            const result = pgResult(await query(ACTION_STORE_SQL.transition, [
                id,
                principalId,
                tenantId,
                gateId,
                [...statuses],
                JSON.stringify(safePatch(patch)),
            ]), 'action transition');
            if (result.rowCount > 1)
                throw new Error('action transition affected multiple rows');
            return result.rowCount === 1;
        },
        async reconcileInterrupted({ action, statuses, patch }) {
            if (action !== GITHUB_REPOSITORY_DELETE_ACTION || !Array.isArray(statuses)
                || statuses.length === 0 || statuses.some((status) => typeof status !== 'string')) {
                throw new TypeError('action reconciliation scope invalid');
            }
            const result = pgResult(await query(ACTION_STORE_SQL.reconcileInterrupted, [
                action,
                tenantId,
                gateId,
                [...statuses],
                JSON.stringify(safePatch(patch)),
            ]), 'action reconciliation');
            return result.rowCount;
        },
        async health() {
            const result = pgResult(await query(ACTION_STORE_SQL.health, []), 'action health', { rowsMatch: true });
            if (result.rowCount !== 1)
                throw new Error('action health returned an invalid row count');
            return { ok: result.rows[0].table_ready === true && result.rows[0].can_use === true };
        },
        ...(close ? { close } : {}),
    };
}
function evidenceForAction(records, actionId) {
    const decisions = new Set(records
        .filter((record) => record?.kind === 'decision' && record.selector?.action_id === actionId)
        .map((record) => record.hash));
    return records.filter((record) => ((record?.kind === 'decision' && record.selector?.action_id === actionId)
        || (record?.kind === 'execution' && decisions.has(record.authorizes_decision))));
}
function createScopedEvidenceLog({ backend, streamId, tenantId, gateId }) {
    const atomic = createAtomicEvidenceLog(backend, { streamId });
    function assertScope(scope) {
        if (scope?.tenantId !== tenantId || scope?.gateId !== gateId
            || typeof scope?.actionId !== 'string' || scope.actionId.length === 0) {
            throw new Error('evidence scope mismatch');
        }
    }
    async function scopedRecords(scope) {
        assertScope(scope);
        return evidenceForAction(await backend.all(streamId), scope.actionId);
    }
    return {
        ...atomic,
        async head(scope) {
            const records = await scopedRecords(scope);
            const record = records.at(-1);
            return record ? { seq: record.seq, hash: record.hash } : null;
        },
        async getRecord(scope) {
            const records = await scopedRecords(scope);
            return structuredClone(records.find((record) => record.record_id === scope.recordId) ?? null);
        },
        async history(scope) {
            const records = await scopedRecords(scope);
            const page = records.slice(scope.cursor, scope.cursor + scope.limit);
            const next = scope.cursor + page.length;
            return {
                records: structuredClone(page),
                nextCursor: next < records.length ? next : null,
            };
        },
        async verify(scope) {
            assertScope(scope);
            return backend.verify(streamId);
        },
    };
}
function requiredEnvironment(environment, name, { max = 16_384 } = {}) {
    const value = environment[name];
    if (typeof value !== 'string' || value.length === 0 || value.length > max || /[\r\n\u0000]/.test(value)) {
        throw new Error(`${name}_required`);
    }
    return value;
}
function optionalInteger(environment, name, { min, max }) {
    if (environment[name] === undefined || environment[name] === '')
        return undefined;
    if (!/^[0-9]+$/.test(environment[name]))
        throw new Error(`${name}_invalid`);
    const value = Number(environment[name]);
    if (!Number.isSafeInteger(value) || value < min || value > max)
        throw new Error(`${name}_invalid`);
    return value;
}
function parseTrust(environment) {
    const source = requiredEnvironment(environment, 'EMILIA_GATE_TRUST_JSON', { max: 1024 * 1024 });
    if (!strictJsonGate(source).ok)
        throw new Error('EMILIA_GATE_TRUST_JSON_invalid');
    let parsed;
    try {
        parsed = JSON.parse(source);
    }
    catch {
        throw new Error('EMILIA_GATE_TRUST_JSON_invalid');
    }
    if (!plainObject(parsed))
        throw new Error('EMILIA_GATE_TRUST_JSON_invalid');
    return parsed;
}
function parseAllowedRepositories(environment) {
    const source = requiredEnvironment(environment, 'EMILIA_GATE_ALLOWED_REPOSITORIES');
    const entries = source.split(',');
    if (entries.length === 0 || entries.length > 10_000) {
        throw new Error('EMILIA_GATE_ALLOWED_REPOSITORIES_invalid');
    }
    const allowed = new Set();
    for (const entry of entries) {
        if (!REPOSITORY.test(entry) || entry.includes('/./') || entry.includes('/../')) {
            throw new Error('EMILIA_GATE_ALLOWED_REPOSITORIES_invalid');
        }
        allowed.add(entry.toLowerCase());
    }
    return allowed;
}
function optionalSiemForwarder(environment, fetchImpl) {
    if (!environment.EMILIA_GATE_SIEM_URL)
        return null;
    let url;
    try {
        url = new URL(environment.EMILIA_GATE_SIEM_URL);
    }
    catch {
        throw new Error('EMILIA_GATE_SIEM_URL_invalid');
    }
    if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
        throw new Error('EMILIA_GATE_SIEM_URL_invalid');
    }
    const format = environment.EMILIA_GATE_SIEM_FORMAT ?? 'ocsf';
    const bearer = environment.EMILIA_GATE_SIEM_BEARER_TOKEN;
    if (bearer !== undefined && (bearer.length === 0 || /[\r\n\u0000]/.test(bearer))) {
        throw new Error('EMILIA_GATE_SIEM_BEARER_TOKEN_invalid');
    }
    return createSiemForwarder({
        format,
        sink: async (event) => {
            const body = typeof event === 'string' ? event : JSON.stringify(event);
            const response = await fetchImpl(url, {
                method: 'POST',
                headers: {
                    'Content-Type': typeof event === 'string' ? 'text/plain; charset=utf-8' : 'application/json',
                    ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}),
                },
                body,
                redirect: 'error',
                signal: AbortSignal.timeout(3_000),
            });
            if (!response?.ok)
                throw new Error('siem_delivery_failed');
            try {
                Promise.resolve(response.body?.cancel?.()).catch(() => { });
            }
            catch { /* no-op */ }
        },
    });
}
export async function createProductionGateConfig({ environment = process.env, PoolClass = null, fetchImpl = globalThis.fetch, } = {}) {
    const databaseUrl = requiredEnvironment(environment, 'EMILIA_GATE_DATABASE_URL');
    const githubToken = requiredEnvironment(environment, 'GITHUB_TOKEN', { max: 4096 });
    const apiToken = requiredEnvironment(environment, 'EMILIA_GATE_API_TOKEN', { max: 1024 });
    const principalId = requiredEnvironment(environment, 'EMILIA_GATE_PRINCIPAL_ID', { max: 256 });
    const tenantId = requiredEnvironment(environment, 'EMILIA_GATE_TENANT_ID', { max: 256 });
    const gateId = requiredEnvironment(environment, 'EMILIA_GATE_ID', { max: 256 });
    const streamId = environment.EMILIA_GATE_EVIDENCE_STREAM_ID ?? 'gate-service';
    const trust = parseTrust(environment);
    const allowedRepositories = parseAllowedRepositories(environment);
    const ResolvedPool = PoolClass ?? (await import('pg')).default.Pool;
    const max = optionalInteger(environment, 'EMILIA_GATE_POSTGRES_POOL_MAX', { min: 1, max: 100 }) ?? 10;
    const pool = new ResolvedPool({ connectionString: databaseUrl, max });
    const query = pool.query.bind(pool);
    const consumptionBackend = createPostgresBackend({ query });
    const consumptionStore = createDurableConsumptionStore(consumptionBackend);
    const evidenceBackend = createPostgresEvidenceBackend({ query, tenantId, gateId });
    const evidenceLog = createScopedEvidenceLog({ backend: evidenceBackend, streamId, tenantId, gateId });
    const actionStore = createPostgresActionStore({
        query,
        tenantId,
        gateId,
        close: pool.end.bind(pool),
    });
    const principal = Object.freeze({ id: principalId });
    const siemForwarder = optionalSiemForwarder(environment, fetchImpl);
    return {
        connector: createGithubRestConnector({
            token: githubToken,
            apiVersion: environment.GITHUB_API_VERSION,
            fetchImpl,
            maxResponseBytes: optionalInteger(environment, 'EMILIA_GATE_MAX_GITHUB_RESPONSE_BYTES', {
                min: 1024,
                max: 4 * 1024 * 1024,
            }),
        }),
        consumptionStore,
        evidenceLog,
        actionStore,
        authenticateRequest: createStaticBearerAuthenticator(apiToken, principal),
        authorizeAction: async (candidate, action, owner, repo) => (candidate?.id === principal.id
            && action === GITHUB_REPOSITORY_DELETE_ACTION
            && allowedRepositories.has(`${owner}/${repo}`.toLowerCase())),
        authorizeEvidence: async (candidate, operation, tenant, gate, actionId) => (candidate?.id === principal.id
            && EVIDENCE_OPERATIONS.has(operation)
            && tenant === tenantId
            && gate === gateId
            && typeof actionId === 'string'
            && actionId.length > 0
            && actionId.length <= 128),
        tenantId,
        gateId,
        readiness: async () => {
            const [consumption, evidence, actions] = await Promise.all([
                consumptionStore.health(),
                evidenceLog.health(),
                actionStore.health(),
            ]);
            return { ok: consumption.ok === true && evidence.ok === true && actions.ok === true };
        },
        trustedKeys: trust.trustedKeys,
        keyRegistry: trust.keyRegistry,
        approverKeys: trust.approverKeys,
        rpId: trust.rpId,
        allowedOrigins: trust.allowedOrigins,
        maxAgeSec: optionalInteger(environment, 'EMILIA_GATE_MAX_AGE_SEC', { min: 1, max: 86_400 }),
        maxBodyBytes: optionalInteger(environment, 'EMILIA_GATE_MAX_BODY_BYTES', { min: 256, max: 16 * 1024 }),
        maxReceiptBytes: optionalInteger(environment, 'EMILIA_GATE_MAX_RECEIPT_BYTES', {
            min: 1024,
            max: 256 * 1024,
        }),
        connectorTimeoutMs: optionalInteger(environment, 'EMILIA_GATE_CONNECTOR_TIMEOUT_MS', {
            min: 100,
            max: 120_000,
        }),
        readinessTimeoutMs: optionalInteger(environment, 'EMILIA_GATE_READINESS_TIMEOUT_MS', {
            min: 100,
            max: 30_000,
        }),
        siemForwarder,
    };
}
export default createProductionGateConfig;
