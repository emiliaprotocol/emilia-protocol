// SPDX-License-Identifier: Apache-2.0

type CustodianCreateResult =
  | {
      kind: 'created' | 'existing';
      provider: string;
      environment: 'sandbox' | 'production';
      operation: string;
      transaction: Readonly<Record<string, unknown>>;
    }
  | {
      kind: 'refused' | 'provider_error' | 'indeterminate';
      provider: string;
      environment: 'sandbox' | 'production';
      operation: string;
      reason_code: string;
    };

type CustodianReconcileResult =
  | {
      kind: 'reconciled';
      provider: string;
      environment: 'sandbox' | 'production';
      operation: string;
      transaction: Readonly<Record<string, unknown>>;
    }
  | {
      kind: 'not_found' | 'refused' | 'provider_error';
      provider: string;
      environment: 'sandbox' | 'production';
      operation: string;
      reason_code?: string;
    };

type CustodianReleaseResult =
  | {
      kind: 'released' | 'release_submitted';
      provider: string;
      environment: 'sandbox' | 'production';
      transaction: Readonly<Record<string, unknown>>;
    }
  | {
      kind: 'provider_action_required' | 'refused' | 'provider_error' | 'indeterminate';
      provider: string;
      environment: 'sandbox' | 'production';
      operation: string;
      reason_code: string;
    };

type CustodianDisbursementResult =
  | {
      kind: 'released';
      provider: string;
      environment: 'sandbox' | 'production';
      transaction: Readonly<Record<string, unknown>>;
    }
  | {
      kind: 'provider_action_required' | 'refused' | 'provider_error';
      provider: string;
      environment: 'sandbox' | 'production';
      operation: string;
      reason_code: string;
    };

interface ExternalCustodianAdapter {
  kind: 'external_custodian';
  provider: string;
  environment: 'sandbox' | 'production';
  customer_diligence: Readonly<Record<string, unknown>>;
  capabilities: Readonly<{
    create_transaction: boolean;
    reconcile_transaction: boolean;
    milestone_release: 'provider_api' | 'provider_action_required';
    direct_disbursement: 'provider_api' | 'provider_action_required';
  }>;
  createTransaction: (request: object) => Promise<CustodianCreateResult>;
  reconcileTransaction: (request: object) => Promise<CustodianReconcileResult>;
  releaseMilestone: (request: object) => Promise<CustodianReleaseResult>;
  requestMilestoneDisbursement: (request: object) => Promise<CustodianDisbursementResult>;
}

const ADAPTER_METHODS = [
  'createTransaction',
  'reconcileTransaction',
  'releaseMilestone',
  'requestMilestoneDisbursement',
];
const RESULT_KINDS_BY_METHOD = Object.freeze({
  createTransaction: Object.freeze([
    'created',
    'existing',
    'refused',
    'provider_error',
    'indeterminate',
  ]),
  reconcileTransaction: Object.freeze([
    'reconciled',
    'not_found',
    'refused',
    'provider_error',
  ]),
  releaseMilestone: Object.freeze([
    'released',
    'release_submitted',
    'provider_action_required',
    'refused',
    'provider_error',
    'indeterminate',
  ]),
  requestMilestoneDisbursement: Object.freeze([
    'released',
    'provider_action_required',
    'refused',
    'provider_error',
  ]),
});
const OPERATION_BY_METHOD = Object.freeze({
  createTransaction: 'create_transaction',
  reconcileTransaction: 'reconcile_transaction',
  releaseMilestone: 'release_milestone',
  requestMilestoneDisbursement: 'request_milestone_disbursement',
});
const SENSITIVE_METADATA_KEY =
  /(?:^|[_-])(?:api[_-]?(?:key|token|secret)|access[_-]?(?:key|token)|refresh[_-]?token|oauth[_-]?token|bearer[_-]?token|session[_-]?(?:id|key|token|secret)|private[_-]?key|signing[_-]?key|client[_-]?secret|password|passwd|secret|token|cookie)(?:$|[_-])|^(?:credential|credentials|authorization|proxy_authorization|headers?)$/i;
const MAX_DILIGENCE_BYTES = 8 * 1024;
const MAX_METADATA_DEPTH = 8;

/**
 * This contract is intended for a custodian selected by the customer after its
 * own legal diligence. Defining an adapter does not assert a provider's
 * licensing, regulatory status, or fitness for a particular transaction.
 */

function isRecord(value: any): boolean {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function isPlainRecord(value: any): boolean {
  if (!isRecord(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertJsonMetadata(value: any, depth: number = 0, seen: Set<any> = new Set()): void {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number' && Number.isFinite(value)) return;
  if (depth > MAX_METADATA_DEPTH || typeof value !== 'object') {
    throw new TypeError('customerDiligence must contain bounded JSON values');
  }
  if (seen.has(value)) throw new TypeError('customerDiligence must not contain cycles');
  seen.add(value);
  if (Array.isArray(value)) {
    for (const item of value) assertJsonMetadata(item, depth + 1, seen);
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError('customerDiligence must contain plain JSON objects');
    }
    for (const [key, item] of Object.entries(value)) {
      if (SENSITIVE_METADATA_KEY.test(key)) {
        throw new TypeError('customerDiligence must not contain credential-like fields');
      }
      assertJsonMetadata(item, depth + 1, seen);
    }
  }
  seen.delete(value);
}

/**
 * Freeze JSON-like records while leaving byte arrays and other non-plain
 * values alone.
 */
export function deepFreezeJson<T = any>(value: T): T {
  if (Array.isArray(value)) {
    for (const item of value) deepFreezeJson(item);
    return Object.freeze(value);
  }
  if (isPlainRecord(value)) {
    const record = value as Record<string, unknown>;
    for (const item of Object.values(record)) deepFreezeJson(item);
    return Object.freeze(value);
  }
  return value;
}

function cloneDiligenceMetadata(value: any): Record<string, unknown> {
  if (!isRecord(value)) throw new TypeError('customerDiligence must be a JSON object');
  assertJsonMetadata(value);
  const serialized = JSON.stringify(value);
  if (Buffer.byteLength(serialized, 'utf8') > MAX_DILIGENCE_BYTES) {
    throw new TypeError('customerDiligence exceeds the size limit');
  }
  return deepFreezeJson(JSON.parse(serialized));
}

function validateCapabilities(value: any): Readonly<{
  create_transaction: boolean;
  reconcile_transaction: boolean;
  milestone_release: 'provider_api' | 'provider_action_required';
  direct_disbursement: 'provider_api' | 'provider_action_required';
}> {
  if (!isRecord(value)
      || typeof value.create_transaction !== 'boolean'
      || typeof value.reconcile_transaction !== 'boolean'
      || !['provider_api', 'provider_action_required'].includes(value.milestone_release)
      || !['provider_api', 'provider_action_required'].includes(value.direct_disbursement)) {
    throw new TypeError('custodian capabilities are invalid');
  }
  return deepFreezeJson({
    create_transaction: value.create_transaction,
    reconcile_transaction: value.reconcile_transaction,
    milestone_release: value.milestone_release,
    direct_disbursement: value.direct_disbursement,
  });
}

function bindClosedOperation(definition: any, method: string): (...args: any[]) => Promise<any> {
  const operation = definition[method].bind(definition);
  const allowedKinds = RESULT_KINDS_BY_METHOD[method as keyof typeof RESULT_KINDS_BY_METHOD];
  return async (...args: any[]) => {
    const result = await operation(...args);
    if (!isPlainRecord(result)
        || !allowedKinds.includes(result.kind)
        || result.provider !== definition.provider
        || result.environment !== definition.environment
        || result.operation !== OPERATION_BY_METHOD[method as keyof typeof OPERATION_BY_METHOD]) {
      throw new TypeError(`${method} returned an unsupported closed result kind`);
    }
    return deepFreezeJson(result);
  };
}

/**
 * Defines the common adapter surface without making a licensing assertion.
 */
export function defineExternalCustodianAdapter(definition: any): ExternalCustodianAdapter {
  if (!isRecord(definition)
      || typeof definition.provider !== 'string'
      || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(definition.provider)
      || !['sandbox', 'production'].includes(definition.environment)) {
    throw new TypeError('custodian adapter identity is invalid');
  }
  for (const method of ADAPTER_METHODS) {
    if (typeof definition[method] !== 'function') {
      throw new TypeError(`custodian adapter is missing ${method}`);
    }
  }

  return Object.freeze({
    kind: 'external_custodian',
    provider: definition.provider,
    environment: definition.environment,
    customer_diligence: cloneDiligenceMetadata(definition.customerDiligence),
    capabilities: validateCapabilities(definition.capabilities),
    createTransaction: bindClosedOperation(definition, 'createTransaction'),
    reconcileTransaction: bindClosedOperation(definition, 'reconcileTransaction'),
    releaseMilestone: bindClosedOperation(definition, 'releaseMilestone'),
    requestMilestoneDisbursement: bindClosedOperation(
      definition,
      'requestMilestoneDisbursement',
    ),
  });
}
