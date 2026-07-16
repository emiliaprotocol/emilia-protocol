// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import {
  createTrustedActionFirewall,
  hashCanonical,
} from '../../../packages/gate/index.js';
import { parseReceiptCarrier } from '../../../packages/require-receipt/index.js';
import { validateGateServiceConfig } from './config.js';

export const GITHUB_REPOSITORY_DELETE_ACTION = 'github.repo.delete';
export const GITHUB_REPOSITORY_DELETE_SELECTOR = Object.freeze({
  protocol: 'github',
  tool: 'delete_repo',
});
export const GITHUB_REPOSITORY_DELETE_MANIFEST = Object.freeze({
  '@version': 'EP-ACTION-RISK-MANIFEST-v0.1',
  actions: Object.freeze([Object.freeze({
    id: 'github.repo.delete.complete-mediation',
    label: 'GitHub repository delete',
    action_type: GITHUB_REPOSITORY_DELETE_ACTION,
    risk: 'critical',
    receipt_required: true,
    assurance_class: 'class_a',
    match: GITHUB_REPOSITORY_DELETE_SELECTOR,
    why: 'Deletes one GitHub repository after system-of-record observation and exact receipt binding.',
    execution_binding: Object.freeze({
      required_fields: Object.freeze([
        'action_type',
        'owner',
        'repo',
        'node_id',
        'default_branch',
        'visibility',
      ]),
    }),
  })]),
});

const BODY_KEYS = Object.freeze(['action', 'owner', 'repo']);
const ACTION_ID = /^[A-Za-z0-9_-]{16,128}$/;
const REPOSITORY_SEGMENT = /^[A-Za-z0-9_.-]+$/;
const VISIBILITIES = new Set(['public', 'private', 'internal']);

function response(status, body, headers = {}) {
  return { status, body, headers };
}

function closedError(status, code, id = null, state = status >= 500 ? 'failed' : 'refused') {
  return response(status, {
    ...(id ? { id } : {}),
    status: state,
    error: { code },
  });
}

function currentTimestamp(now) {
  const value = now();
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error('clock_invalid');
  return date.toISOString();
}

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function validateDeleteRequest(body) {
  if (!isPlainObject(body)) return { ok: false, code: 'request_object_required' };
  const keys = Object.keys(body).sort();
  if (keys.length !== BODY_KEYS.length || keys.some((key, index) => key !== [...BODY_KEYS].sort()[index])) {
    return { ok: false, code: 'request_fields_invalid' };
  }
  if (body.action !== GITHUB_REPOSITORY_DELETE_ACTION) {
    return { ok: false, code: 'unsupported_action' };
  }
  for (const field of ['owner', 'repo']) {
    const value = body[field];
    if (typeof value !== 'string' || value.length === 0 || value.length > 100
        || value === '.' || value === '..'
        || value !== value.trim() || !REPOSITORY_SEGMENT.test(value)) {
      return { ok: false, code: `${field}_invalid` };
    }
  }
  return { ok: true, locator: { owner: body.owner, repo: body.repo } };
}

function boundedObservedText(value, field, max = 256) {
  if (typeof value !== 'string' || value.length === 0 || value.length > max
      || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error(`github_repository_${field}_invalid`);
  }
  return value;
}

export function observedGithubRepository(repository, locator) {
  if (!isPlainObject(repository) || !isPlainObject(repository.owner)) {
    throw new Error('github_repository_response_invalid');
  }
  const owner = boundedObservedText(repository.owner.login, 'owner', 100);
  const repo = boundedObservedText(repository.name, 'repo', 100);
  const nodeId = boundedObservedText(repository.node_id, 'node_id', 512);
  const defaultBranch = boundedObservedText(repository.default_branch, 'default_branch', 256);
  const visibility = boundedObservedText(repository.visibility, 'visibility', 32);
  if (!VISIBILITIES.has(visibility)) throw new Error('github_repository_visibility_invalid');
  if (owner.toLowerCase() !== locator.owner.toLowerCase()
      || repo.toLowerCase() !== locator.repo.toLowerCase()) {
    throw new Error('github_repository_locator_mismatch');
  }
  if (repository.full_name !== undefined
      && (typeof repository.full_name !== 'string'
        || repository.full_name.toLowerCase() !== `${owner}/${repo}`.toLowerCase())) {
    throw new Error('github_repository_full_name_invalid');
  }
  return Object.freeze({
    action_type: GITHUB_REPOSITORY_DELETE_ACTION,
    owner,
    repo,
    node_id: nodeId,
    default_branch: defaultBranch,
    visibility,
  });
}

function stableIdempotencyKey(receiptId) {
  if (typeof receiptId !== 'string' || receiptId.length === 0) {
    throw new Error('receipt_id_missing_after_authorization');
  }
  return `emilia-${crypto.createHash('sha256').update(receiptId, 'utf8').digest('base64url')}`;
}

function timeoutSignal(milliseconds) {
  return AbortSignal.timeout(milliseconds);
}

function timeoutLike(error) {
  return error?.timeout === true || error?.name === 'TimeoutError' || error?.name === 'AbortError';
}

function publicActionRecord(record, expectedId) {
  if (!isPlainObject(record) || record.id !== expectedId
      || record.action !== GITHUB_REPOSITORY_DELETE_ACTION
      || typeof record.status !== 'string') return null;
  const projected = {};
  for (const field of [
    'id',
    'action',
    'status',
    'created_at',
    'updated_at',
    'outcome',
    'reason',
    'authorization_evidence_hash',
    'execution_evidence_hash',
  ]) {
    if (typeof record[field] === 'string') projected[field] = record[field];
  }
  if (isPlainObject(record.target)
      && typeof record.target.owner === 'string'
      && typeof record.target.repo === 'string') {
    projected.target = { owner: record.target.owner, repo: record.target.repo };
  }
  if (isPlainObject(record.observed_action)) {
    const observed = {};
    for (const field of [
      'action_type',
      'owner',
      'repo',
      'node_id',
      'default_branch',
      'visibility',
    ]) {
      if (typeof record.observed_action[field] === 'string') {
        observed[field] = record.observed_action[field];
      }
    }
    projected.observed_action = observed;
  }
  if (isPlainObject(record.error) && typeof record.error.code === 'string') {
    projected.error = { code: record.error.code };
  }
  return projected;
}

function challengeBody(gateBody, { id, observedAction, carrierInvalid }) {
  const required = isPlainObject(gateBody?.required) ? gateBody.required : {};
  return {
    ...(isPlainObject(gateBody) ? gateBody : {}),
    action_id: id,
    detail: carrierInvalid ? 'receipt_carrier_invalid' : gateBody?.detail,
    required: {
      ...required,
      action: GITHUB_REPOSITORY_DELETE_ACTION,
      action_hash: hashCanonical(observedAction),
      observed_action: observedAction,
    },
  };
}

export function createGateRuntime(inputConfig) {
  const config = validateGateServiceConfig(inputConfig);
  const connector = Object.freeze({
    getRepository: config.connector.getRepository.bind(config.connector),
    deleteRepository: config.connector.deleteRepository.bind(config.connector),
  });
  const actionStore = Object.freeze({
    create: config.actionStore.create.bind(config.actionStore),
    update: config.actionStore.update.bind(config.actionStore),
    get: config.actionStore.get.bind(config.actionStore),
  });
  const consumptionStore = Object.freeze({
    durable: true,
    ownershipFenced: true,
    permanentConsumption: true,
    reserve: config.consumptionStore.reserve.bind(config.consumptionStore),
    commit: config.consumptionStore.commit.bind(config.consumptionStore),
    consume: config.consumptionStore.consume.bind(config.consumptionStore),
    has: config.consumptionStore.has.bind(config.consumptionStore),
  });
  const evidenceLog = Object.freeze({
    durable: true,
    persisted: true,
    strict: true,
    forkAware: true,
    atomicAppend: true,
    record: config.evidenceLog.record.bind(config.evidenceLog),
    verify: config.evidenceLog.verify.bind(config.evidenceLog),
  });
  const gate = createTrustedActionFirewall({
    manifest: GITHUB_REPOSITORY_DELETE_MANIFEST,
    trustedKeys: config.trustedKeys,
    keyRegistry: config.keyRegistry,
    approverKeys: config.approverKeys,
    verifyAssurance: config.verifyAssurance,
    rpId: config.rpId,
    allowedOrigins: config.allowedOrigins,
    maxAgeSec: config.maxAgeSec,
    store: consumptionStore,
    log: evidenceLog,
    allowInlineKey: false,
    allowEphemeralStore: false,
    strictEvidence: true,
    now: config.now,
  });

  function auditEvent(event, id, status) {
    try {
      config.logger?.info?.({
        component: 'emilia-gate-service',
        event,
        action_id: id,
        status,
      });
    } catch {
      // Application logging cannot participate in authorization or execution.
    }
  }

  async function createAction(locator) {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const id = config.idFactory();
      if (typeof id !== 'string' || !ACTION_ID.test(id)) throw new Error('action_id_factory_invalid');
      const at = currentTimestamp(config.now);
      const record = {
        id,
        action: GITHUB_REPOSITORY_DELETE_ACTION,
        status: 'observing',
        target: { ...locator },
        created_at: at,
        updated_at: at,
      };
      const created = await actionStore.create(structuredClone(record));
      if (created === true) return record;
      if (created !== false) throw new Error('action_store_create_contract_invalid');
    }
    throw new Error('action_id_collision_limit');
  }

  async function updateAction(id, patch) {
    const updated = await actionStore.update(id, structuredClone({
      ...patch,
      updated_at: currentTimestamp(config.now),
    }));
    if (updated !== true) throw new Error('action_store_update_failed');
  }

  async function executeDelete({ body, receiptCarrier = null } = {}) {
    const request = validateDeleteRequest(body);
    if (!request.ok) return closedError(400, request.code);

    let actionRecord;
    try {
      actionRecord = await createAction(request.locator);
    } catch {
      return closedError(503, 'action_store_unavailable');
    }
    const { id } = actionRecord;

    let observedAction;
    try {
      const repository = await connector.getRepository({
        ...request.locator,
        signal: timeoutSignal(config.connectorTimeoutMs),
      });
      observedAction = observedGithubRepository(repository, request.locator);
      await updateAction(id, {
        status: 'authorizing',
        observed_action: observedAction,
      });
    } catch (error) {
      const code = timeoutLike(error) ? 'github_observation_timeout' : 'github_observation_failed';
      try { await updateAction(id, { status: 'failed', error: { code } }); } catch { /* closed response below */ }
      auditEvent('observation_failed', id, 'failed');
      return closedError(timeoutLike(error) ? 504 : 502, code, id);
    }

    const carrierProvided = typeof receiptCarrier === 'string' && receiptCarrier.length > 0;
    const receipt = parseReceiptCarrier(receiptCarrier, { maxBytes: config.maxReceiptBytes });
    const carrierInvalid = carrierProvided && receipt === null;
    let deleteAttempted = false;
    let result;

    try {
      result = await gate.run({
        selector: { ...GITHUB_REPOSITORY_DELETE_SELECTOR, action_id: id },
        receipt,
        observedAction,
      }, async (authorization) => {
        deleteAttempted = true;
        const deleted = await connector.deleteRepository({
          owner: observedAction.owner,
          repo: observedAction.repo,
          node_id: observedAction.node_id,
          default_branch: observedAction.default_branch,
          visibility: observedAction.visibility,
          idempotencyKey: stableIdempotencyKey(authorization.evidence?.receipt_id),
          actionId: id,
          signal: timeoutSignal(config.connectorTimeoutMs),
        });
        if (!isPlainObject(deleted) || deleted.status !== 204) {
          throw new Error('github_delete_outcome_unknown');
        }
        return { status: 204 };
      });
    } catch (error) {
      const indeterminate = deleteAttempted;
      const status = indeterminate ? 'indeterminate' : 'failed';
      const code = indeterminate
        ? (timeoutLike(error) ? 'github_delete_timeout_outcome_unknown' : 'github_delete_outcome_unknown')
        : 'gate_unavailable';
      try { await updateAction(id, { status, error: { code } }); } catch { /* evidence remains authoritative */ }
      auditEvent(indeterminate ? 'delete_indeterminate' : 'gate_failed', id, status);
      const httpStatus = indeterminate ? (timeoutLike(error) ? 504 : 502) : 503;
      return closedError(httpStatus, code, id, status);
    }

    if (!result.ok) {
      const reason = carrierInvalid ? 'receipt_carrier_invalid' : result.authorization.reason;
      try { await updateAction(id, { status: 'challenged', reason }); } catch {
        return closedError(503, 'action_store_unavailable', id);
      }
      auditEvent('receipt_challenged', id, 'challenged');
      return response(428, challengeBody(result.body, {
        id,
        observedAction,
        carrierInvalid,
      }), result.authorization.header ? { 'Receipt-Required': result.authorization.header } : {});
    }

    try {
      await updateAction(id, {
        status: 'succeeded',
        outcome: 'deleted',
        authorization_evidence_hash: result.authorization.evidence?.hash ?? null,
        execution_evidence_hash: result.execution?.hash ?? null,
      });
    } catch {
      auditEvent('action_record_failed_after_delete', id, 'indeterminate');
      return closedError(503, 'action_record_failed_after_delete', id, 'indeterminate');
    }
    auditEvent('delete_succeeded', id, 'succeeded');
    return response(200, {
      id,
      action: GITHUB_REPOSITORY_DELETE_ACTION,
      status: 'succeeded',
      outcome: 'deleted',
      observed_action: observedAction,
      evidence: {
        authorization_hash: result.authorization.evidence?.hash ?? null,
        execution_hash: result.execution?.hash ?? null,
      },
    });
  }

  async function getAction(id) {
    if (typeof id !== 'string' || !ACTION_ID.test(id)) return closedError(400, 'action_id_invalid');
    try {
      const record = publicActionRecord(await actionStore.get(id), id);
      if (!record) return closedError(404, 'action_not_found');
      return response(200, record);
    } catch {
      return closedError(503, 'action_store_unavailable');
    }
  }

  function health() {
    return response(200, {
      status: 'ok',
      service: 'emilia-gate-service',
      action: GITHUB_REPOSITORY_DELETE_ACTION,
    });
  }

  const maxReceiptCarrierChars = Math.ceil(config.maxReceiptBytes * 4 / 3) + 4;
  return Object.freeze({
    executeDelete,
    getAction,
    health,
    limits: Object.freeze({
      maxBodyBytes: config.maxBodyBytes,
      maxReceiptBytes: config.maxReceiptBytes,
      maxReceiptCarrierChars,
      maxHeaderBytes: maxReceiptCarrierChars + 8 * 1024,
      connectorTimeoutMs: config.connectorTimeoutMs,
    }),
  });
}
