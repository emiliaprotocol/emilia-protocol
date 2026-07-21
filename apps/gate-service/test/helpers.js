// SPDX-License-Identifier: Apache-2.0
// Generated from helpers.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
import { createAtomicEvidenceLog, createDurableConsumptionStore, createEg1Harness, createMemoryAtomicEvidenceBackend, createMemoryBackend, } from '../../../packages/gate/index.js';
import { createGateRuntime, GITHUB_REPOSITORY_DELETE_ACTION } from '../src/runtime.js';
import { createHttpServer } from '../src/server.js';
export const REPOSITORY = Object.freeze({
    owner: Object.freeze({ login: 'Acme' }),
    name: 'Prod',
    full_name: 'Acme/Prod',
    node_id: 'R_kgDOExample123',
    default_branch: 'main',
    visibility: 'private',
});
export const OBSERVED_ACTION = Object.freeze({
    action_type: GITHUB_REPOSITORY_DELETE_ACTION,
    owner: 'Acme',
    repo: 'Prod',
    node_id: 'R_kgDOExample123',
    default_branch: 'main',
    visibility: 'private',
});
export const DELETE_BODY = Object.freeze({
    action: GITHUB_REPOSITORY_DELETE_ACTION,
    owner: 'acme',
    repo: 'prod',
});
export const TEST_API_TOKEN = 'test-gate-api-token-0000000000000001';
export const SECOND_API_TOKEN = 'test-gate-api-token-0000000000000002';
export const TEST_PRINCIPAL = Object.freeze({ id: 'operator:primary' });
export const SECOND_PRINCIPAL = Object.freeze({ id: 'operator:secondary' });
export const TEST_TENANT_ID = 'tenant:test';
export const TEST_GATE_ID = 'gate:test';
export function receiptCarrier(receipt) {
    return Buffer.from(JSON.stringify(receipt), 'utf8').toString('base64');
}
export function createActionStore(initialRecords = []) {
    const records = new Map(initialRecords.map((record) => [record.id, structuredClone(record)]));
    const calls = { create: [], update: [], get: [], reconcileInterrupted: [] };
    return {
        durable: true,
        records,
        calls,
        async create(record) {
            calls.create.push(structuredClone(record));
            if (records.has(record.id))
                return false;
            records.set(record.id, structuredClone(record));
            return true;
        },
        async update(id, principalId, patch) {
            calls.update.push({ id, principalId, patch: structuredClone(patch) });
            const current = records.get(id);
            if (!current || current.principal_id !== principalId)
                return false;
            records.set(id, { ...current, ...structuredClone(patch) });
            return true;
        },
        async get(id, principalId) {
            calls.get.push({ id, principalId });
            const record = records.get(id);
            if (!record || record.principal_id !== principalId)
                return null;
            return structuredClone(record);
        },
        async transition(id, principalId, statuses, patch) {
            calls.transition ??= [];
            calls.transition.push({ id, principalId, statuses: [...statuses], patch: structuredClone(patch) });
            const current = records.get(id);
            if (!current || current.principal_id !== principalId || !statuses.includes(current.status))
                return false;
            records.set(id, { ...current, ...structuredClone(patch) });
            return true;
        },
        async reconcileInterrupted({ action, statuses, patch }) {
            calls.reconcileInterrupted.push({ action, statuses: [...statuses], patch: structuredClone(patch) });
            let updated = 0;
            for (const [id, record] of records) {
                if (record.action !== action || !statuses.includes(record.status))
                    continue;
                records.set(id, { ...record, ...structuredClone(patch) });
                updated += 1;
            }
            return updated;
        },
        async health() { return { ok: true }; },
    };
}
export function createDurableTestState({ initialActions = [] } = {}) {
    let reservationCounter = 0;
    const consumptionBackend = createMemoryBackend();
    consumptionBackend.durable = true;
    consumptionBackend.health = async () => ({ ok: true });
    const consumptionStore = createDurableConsumptionStore(consumptionBackend, {
        reservationTokenFactory: () => `test-reservation-token-${String(++reservationCounter).padStart(12, '0')}`,
    });
    let evidenceCounter = 0;
    const evidenceBackend = createMemoryAtomicEvidenceBackend();
    evidenceBackend.durable = true;
    evidenceBackend.health = async () => ({ ok: true });
    const atomicEvidenceLog = createAtomicEvidenceLog(evidenceBackend, {
        streamId: 'gate-service-test',
        recordIdFactory: () => `test-evidence-record-${String(++evidenceCounter).padStart(12, '0')}`,
    });
    const evidenceCalls = { head: [], getRecord: [], history: [], verify: [] };
    async function actionRecords(actionId) {
        const records = await atomicEvidenceLog.all();
        const decisionHashes = new Set(records
            .filter((record) => record.kind === 'decision' && record.selector?.action_id === actionId)
            .map((record) => record.hash));
        return records.filter((record) => ((record.kind === 'decision' && record.selector?.action_id === actionId)
            || (record.kind === 'execution' && decisionHashes.has(record.authorizes_decision))));
    }
    const evidenceLog = {
        ...atomicEvidenceLog,
        async head(scope) {
            evidenceCalls.head.push(structuredClone(scope));
            const records = await actionRecords(scope.actionId);
            const record = records.at(-1);
            return record ? { seq: record.seq, hash: record.hash } : null;
        },
        async getRecord(scope) {
            evidenceCalls.getRecord.push(structuredClone(scope));
            const records = await actionRecords(scope.actionId);
            return structuredClone(records.find((record) => record.record_id === scope.recordId) ?? null);
        },
        async history(scope) {
            evidenceCalls.history.push(structuredClone(scope));
            const records = await actionRecords(scope.actionId);
            const selected = records.slice(scope.cursor, scope.cursor + scope.limit);
            const next = scope.cursor + selected.length;
            return {
                records: structuredClone(selected),
                nextCursor: next < records.length ? next : null,
            };
        },
        async verify(scope) {
            evidenceCalls.verify.push(structuredClone(scope));
            return atomicEvidenceLog.verify();
        },
    };
    evidenceLog.calls = evidenceCalls;
    return {
        consumptionStore,
        consumptionBackend,
        evidenceLog,
        evidenceBackend,
        actionStore: createActionStore(initialActions),
    };
}
function copyConnectorArgs(args) {
    const copy = { ...args };
    delete copy.signal;
    return structuredClone(copy);
}
export async function createServiceFixture(testContext, { harnessAction = OBSERVED_ACTION, repository = REPOSITORY, deleteImpl = null, logger = null, readiness = async () => ({ ok: true }), readinessTimeoutMs = 100, authorizeAction = async () => true, authorizeEvidence = async (principal, _operation, tenantId, gateId) => (principal.id === TEST_PRINCIPAL.id && tenantId === TEST_TENANT_ID && gateId === TEST_GATE_ID), authenticateRequest = async (request) => {
    if (request.headers?.authorization === `Bearer ${TEST_API_TOKEN}`)
        return TEST_PRINCIPAL;
    if (request.headers?.authorization === `Bearer ${SECOND_API_TOKEN}`)
        return SECOND_PRINCIPAL;
    return null;
}, initialActions = [], connectorClose = null, siemForwarder = null, evidenceVerify = null, } = {}) {
    const state = createDurableTestState({ initialActions });
    if (evidenceVerify)
        state.evidenceLog.verify = evidenceVerify;
    const harness = createEg1Harness({ action: harnessAction });
    const getCalls = [];
    const deleteCalls = [];
    const connector = {
        async getRepository(args) {
            getCalls.push(copyConnectorArgs(args));
            const observed = typeof repository === 'function' ? await repository(args, getCalls.length) : repository;
            return structuredClone(observed);
        },
        async deleteRepository(args) {
            const copied = copyConnectorArgs(args);
            deleteCalls.push(copied);
            if (deleteImpl)
                return deleteImpl(args, deleteCalls.length);
            return { status: 204 };
        },
        ...(connectorClose ? { close: connectorClose } : {}),
    };
    let actionCounter = 0;
    const runtime = createGateRuntime({
        connector,
        consumptionStore: state.consumptionStore,
        evidenceLog: state.evidenceLog,
        actionStore: state.actionStore,
        authenticateRequest,
        authorizeAction,
        authorizeEvidence,
        tenantId: TEST_TENANT_ID,
        gateId: TEST_GATE_ID,
        readiness,
        readinessTimeoutMs,
        trustedKeys: [harness.publicKey],
        approverKeys: harness.approverKeys,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        connectorTimeoutMs: 1000,
        idFactory: () => `test-action-${String(++actionCounter).padStart(16, '0')}`,
        logger,
        siemForwarder,
    });
    await runtime.initialize();
    const server = createHttpServer(runtime);
    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolve);
    });
    testContext.after(() => new Promise((resolve, reject) => {
        if (!server.listening) {
            resolve();
            return;
        }
        server.close((error) => (error ? reject(error) : resolve()));
    }));
    const address = server.address();
    const baseUrl = `http://127.0.0.1:${address.port}`;
    async function request(path, { method = 'GET', body, rawBody, carrier, headers = {}, authenticated = true, token = TEST_API_TOKEN, } = {}) {
        const requestHeaders = {
            ...(authenticated ? { Authorization: `Bearer ${token}` } : {}),
            ...headers,
        };
        let payload;
        if (rawBody !== undefined) {
            payload = rawBody;
            if (!Object.keys(requestHeaders).some((name) => name.toLowerCase() === 'content-type')) {
                requestHeaders['Content-Type'] = 'application/json';
            }
        }
        else if (body !== undefined) {
            payload = JSON.stringify(body);
            requestHeaders['Content-Type'] = 'application/json';
        }
        if (carrier !== undefined && carrier !== null)
            requestHeaders['X-EMILIA-Receipt'] = carrier;
        const received = await fetch(`${baseUrl}${path}`, {
            method,
            headers: requestHeaders,
            ...(payload !== undefined ? { body: payload } : {}),
        });
        const text = await received.text();
        return {
            status: received.status,
            headers: received.headers,
            body: text ? JSON.parse(text) : null,
        };
    }
    return {
        ...state,
        harness,
        connector,
        getCalls,
        deleteCalls,
        runtime,
        server,
        baseUrl,
        request,
    };
}
