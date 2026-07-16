// SPDX-License-Identifier: Apache-2.0
import {
  createAtomicEvidenceLog,
  createDurableConsumptionStore,
  createEg1Harness,
  createMemoryAtomicEvidenceBackend,
  createMemoryBackend,
} from '../../../packages/gate/index.js';
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

export function receiptCarrier(receipt) {
  return Buffer.from(JSON.stringify(receipt), 'utf8').toString('base64');
}

export function createActionStore() {
  const records = new Map();
  return {
    durable: true,
    records,
    async create(record) {
      if (records.has(record.id)) return false;
      records.set(record.id, structuredClone(record));
      return true;
    },
    async update(id, patch) {
      const current = records.get(id);
      if (!current) return false;
      records.set(id, { ...current, ...structuredClone(patch) });
      return true;
    },
    async get(id) {
      return structuredClone(records.get(id) ?? null);
    },
  };
}

export function createDurableTestState() {
  let reservationCounter = 0;
  const consumptionBackend = createMemoryBackend();
  consumptionBackend.durable = true;
  const consumptionStore = createDurableConsumptionStore(consumptionBackend, {
    reservationTokenFactory: () => `test-reservation-token-${String(++reservationCounter).padStart(12, '0')}`,
  });

  let evidenceCounter = 0;
  const evidenceBackend = createMemoryAtomicEvidenceBackend();
  evidenceBackend.durable = true;
  const evidenceLog = createAtomicEvidenceLog(evidenceBackend, {
    streamId: 'gate-service-test',
    recordIdFactory: () => `test-evidence-record-${String(++evidenceCounter).padStart(12, '0')}`,
  });

  return {
    consumptionStore,
    consumptionBackend,
    evidenceLog,
    evidenceBackend,
    actionStore: createActionStore(),
  };
}

function copyConnectorArgs(args) {
  const copy = { ...args };
  delete copy.signal;
  return structuredClone(copy);
}

export async function createServiceFixture(testContext, {
  harnessAction = OBSERVED_ACTION,
  repository = REPOSITORY,
  deleteImpl = null,
  logger = null,
} = {}) {
  const state = createDurableTestState();
  const harness = createEg1Harness({ action: harnessAction });
  const getCalls = [];
  const deleteCalls = [];
  const connector = {
    async getRepository(args) {
      getCalls.push(copyConnectorArgs(args));
      return structuredClone(repository);
    },
    async deleteRepository(args) {
      const copied = copyConnectorArgs(args);
      deleteCalls.push(copied);
      if (deleteImpl) return deleteImpl(copied, deleteCalls.length);
      return { status: 204 };
    },
  };

  let actionCounter = 0;
  const runtime = createGateRuntime({
    connector,
    consumptionStore: state.consumptionStore,
    evidenceLog: state.evidenceLog,
    actionStore: state.actionStore,
    trustedKeys: [harness.publicKey],
    approverKeys: harness.approverKeys,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
    connectorTimeoutMs: 1000,
    idFactory: () => `test-action-${String(++actionCounter).padStart(16, '0')}`,
    logger,
  });
  const server = createHttpServer(runtime);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  testContext.after(() => new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  }));
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  async function request(path, {
    method = 'GET',
    body,
    rawBody,
    carrier,
    headers = {},
  } = {}) {
    const requestHeaders = { ...headers };
    let payload;
    if (rawBody !== undefined) {
      payload = rawBody;
      if (!Object.keys(requestHeaders).some((name) => name.toLowerCase() === 'content-type')) {
        requestHeaders['Content-Type'] = 'application/json';
      }
    } else if (body !== undefined) {
      payload = JSON.stringify(body);
      requestHeaders['Content-Type'] = 'application/json';
    }
    if (carrier !== undefined && carrier !== null) requestHeaders['X-EMILIA-Receipt'] = carrier;
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
