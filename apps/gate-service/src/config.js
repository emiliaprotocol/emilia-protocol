// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const DEFAULT_MAX_BODY_BYTES = 4 * 1024;
export const DEFAULT_MAX_RECEIPT_BYTES = 64 * 1024;
export const DEFAULT_CONNECTOR_TIMEOUT_MS = 15_000;

const ALLOWED_CONFIG_KEYS = new Set([
  'connector',
  'consumptionStore',
  'evidenceLog',
  'actionStore',
  'authenticateRequest',
  'readiness',
  'trustedKeys',
  'keyRegistry',
  'approverKeys',
  'verifyAssurance',
  'rpId',
  'allowedOrigins',
  'maxAgeSec',
  'maxBodyBytes',
  'maxReceiptBytes',
  'connectorTimeoutMs',
  'now',
  'idFactory',
  'logger',
  'allowInlineKey',
]);

function isObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function snapshotMap(value) {
  const entries = Object.entries(value).map(([key, entry]) => {
    const isEntryObject = entry !== null && typeof entry === 'object';
    const prototype = isEntryObject ? Object.getPrototypeOf(entry) : undefined;
    const copied = isEntryObject && (prototype === Object.prototype || prototype === null)
      ? Object.freeze({ ...entry })
      : entry;
    return [key, copied];
  });
  return Object.freeze(Object.fromEntries(entries));
}

function hasMethods(value, methods) {
  return isObject(value) && methods.every((method) => typeof value[method] === 'function');
}

function boundedInteger(value, fallback, min, max, field, errors) {
  const selected = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(selected) || selected < min || selected > max) {
    errors.push(`${field}_invalid`);
  }
  return selected;
}

export class GateServiceConfigError extends Error {
  constructor(reasons) {
    super(`EMILIA Gate service configuration refused: ${reasons.join(', ')}`);
    this.name = 'GateServiceConfigError';
    this.code = 'EMILIA_GATE_CONFIG_INVALID';
    this.reasons = [...reasons];
  }
}

export function validateGateServiceConfig(input) {
  const errors = [];
  if (!isObject(input)) throw new GateServiceConfigError(['config_object_required']);

  for (const key of Object.keys(input)) {
    if (!ALLOWED_CONFIG_KEYS.has(key)) errors.push(`unknown_config_key:${key}`);
  }

  if (input.allowInlineKey === true) errors.push('inline_receipt_keys_forbidden');

  if (!hasMethods(input.connector, ['getRepository', 'deleteRepository'])) {
    errors.push('connector_contract_invalid');
  }
  if (typeof input.authenticateRequest !== 'function') {
    errors.push('request_authenticator_required');
  }
  if (typeof input.readiness !== 'function') {
    errors.push('readiness_check_required');
  }

  const consumptionStore = input.consumptionStore;
  if (!hasMethods(consumptionStore, ['reserve', 'commit', 'consume', 'has'])
      || consumptionStore?.durable !== true
      || consumptionStore?.ownershipFenced !== true
      || consumptionStore?.permanentConsumption !== true) {
    errors.push('durable_consumption_store_required');
  }

  const evidenceLog = input.evidenceLog;
  if (!hasMethods(evidenceLog, ['record', 'verify'])
      || evidenceLog?.durable !== true
      || evidenceLog?.persisted !== true
      || evidenceLog?.strict !== true
      || evidenceLog?.forkAware !== true
      || evidenceLog?.atomicAppend !== true) {
    errors.push('durable_atomic_evidence_log_required');
  }

  const actionStore = input.actionStore;
  if (!hasMethods(actionStore, ['create', 'update', 'get']) || actionStore?.durable !== true) {
    errors.push('durable_action_store_required');
  }

  const trustedKeys = input.trustedKeys ?? [];
  const keyRegistry = input.keyRegistry ?? null;
  if (!Array.isArray(trustedKeys)) errors.push('trusted_keys_invalid');
  if (keyRegistry !== null && typeof keyRegistry?.keysValidAt !== 'function') {
    errors.push('key_registry_invalid');
  }
  if (Array.isArray(trustedKeys) && trustedKeys.length === 0
      && typeof keyRegistry?.keysValidAt !== 'function') {
    errors.push('trusted_issuer_keys_required');
  }

  const verifyAssurance = input.verifyAssurance ?? null;
  const approverKeys = input.approverKeys ?? {};
  const allowedOrigins = input.allowedOrigins ?? [];
  const rpId = input.rpId ?? null;
  if (verifyAssurance !== null && typeof verifyAssurance !== 'function') {
    errors.push('verify_assurance_invalid');
  }
  if (!isObject(approverKeys)) errors.push('approver_keys_invalid');
  if (!Array.isArray(allowedOrigins)
      || allowedOrigins.some((origin) => typeof origin !== 'string'
        || origin.length === 0 || origin.length > 2048)) {
    errors.push('allowed_origins_invalid');
  }
  if (rpId !== null && (typeof rpId !== 'string' || rpId.length === 0 || rpId.length > 253)) {
    errors.push('rp_id_invalid');
  }
  if (verifyAssurance === null) {
    if (!isObject(approverKeys) || Object.keys(approverKeys).length === 0) {
      errors.push('pinned_approver_keys_required');
    }
    if (rpId === null) errors.push('rp_id_invalid');
    if (Array.isArray(allowedOrigins) && allowedOrigins.length === 0) {
      errors.push('allowed_origins_invalid');
    }
  }

  const maxAgeSec = boundedInteger(input.maxAgeSec, 900, 1, 86_400, 'max_age_sec', errors);
  const maxBodyBytes = boundedInteger(
    input.maxBodyBytes,
    DEFAULT_MAX_BODY_BYTES,
    256,
    16 * 1024,
    'max_body_bytes',
    errors,
  );
  const maxReceiptBytes = boundedInteger(
    input.maxReceiptBytes,
    DEFAULT_MAX_RECEIPT_BYTES,
    1024,
    256 * 1024,
    'max_receipt_bytes',
    errors,
  );
  const connectorTimeoutMs = boundedInteger(
    input.connectorTimeoutMs,
    DEFAULT_CONNECTOR_TIMEOUT_MS,
    100,
    120_000,
    'connector_timeout_ms',
    errors,
  );

  const now = input.now ?? Date.now;
  const idFactory = input.idFactory ?? (() => crypto.randomUUID());
  if (typeof now !== 'function') errors.push('now_function_required');
  if (typeof idFactory !== 'function') errors.push('id_factory_required');
  if (input.logger !== undefined && input.logger !== null && !isObject(input.logger)) {
    errors.push('logger_invalid');
  }

  if (errors.length > 0) throw new GateServiceConfigError(errors);

  return Object.freeze({
    connector: input.connector,
    consumptionStore,
    evidenceLog,
    actionStore,
    authenticateRequest: input.authenticateRequest,
    readiness: input.readiness,
    trustedKeys: Object.freeze([...trustedKeys]),
    keyRegistry,
    approverKeys: snapshotMap(approverKeys),
    verifyAssurance,
    rpId,
    allowedOrigins: Object.freeze([...allowedOrigins]),
    maxAgeSec,
    maxBodyBytes,
    maxReceiptBytes,
    connectorTimeoutMs,
    now,
    idFactory,
    logger: input.logger ?? null,
    allowInlineKey: false,
  });
}

export async function loadGateServiceConfig(file = process.env.EMILIA_GATE_CONFIG) {
  if (typeof file !== 'string' || file.length === 0) {
    throw new GateServiceConfigError(['EMILIA_GATE_CONFIG_path_required']);
  }
  const moduleUrl = pathToFileURL(path.resolve(file)).href;
  const loaded = await import(moduleUrl);
  const exported = loaded.default;
  const candidate = typeof exported === 'function' ? await exported() : exported;
  return validateGateServiceConfig(candidate);
}
