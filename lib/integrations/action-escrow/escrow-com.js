// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import {
  parseJsonObject,
  requestBounded,
  responseHeader,
  validatePinnedOrigin,
  validateResponseLimit,
  validateTimeout,
} from './bounded-fetch.js';
import {
  deepFreezeJson,
  defineExternalCustodianAdapter,
} from './licensed-custodian.js';

const ESCROW_ORIGINS = Object.freeze({
  sandbox: 'https://api.escrow-sandbox.com',
  production: 'https://api.escrow.com',
});
const ESCROW_HOSTS = new Set(['api.escrow-sandbox.com', 'api.escrow.com']);
const API_PREFIX = '/2017-09-01';
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_REQUEST_BYTES = 256 * 1024;
const MONEY = /^(?:0|[1-9][0-9]{0,15})(?:\.[0-9]{1,2})?$/;
const EFFECT_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const PROVIDER_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,23}$/;
const ITEM_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$/;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/;
const UTC_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const CURRENCY_TO_PROVIDER = Object.freeze({ USD: 'usd', EUR: 'euro' });
const PROVIDER_TO_CURRENCY = Object.freeze({
  usd: 'USD',
  euro: 'EUR',
  aud: 'AUD',
  gbp: 'GBP',
  cad: 'CAD',
});

function isRecord(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function closedResult(environment, kind, fields = {}) {
  return deepFreezeJson({
    kind,
    provider: 'escrow.com',
    environment,
    ...fields,
  });
}

function transportReason(reason) {
  return {
    timeout: 'PROVIDER_TIMEOUT',
    network: 'PROVIDER_UNAVAILABLE',
    response_too_large: 'PROVIDER_RESPONSE_TOO_LARGE',
    invalid_response: 'PROVIDER_RESPONSE_INVALID',
  }[reason] || 'PROVIDER_RESPONSE_INVALID';
}

function providerFailure(environment, operation, response) {
  if (response.kind === 'failure') {
    return closedResult(environment, 'provider_error', {
      operation,
      reason_code: transportReason(response.reason),
      http_status: null,
    });
  }
  return closedResult(environment, 'provider_error', {
    operation,
    reason_code: response.kind === 'invalid'
      ? 'PROVIDER_RESPONSE_INVALID'
      : 'PROVIDER_HTTP_ERROR',
    http_status: response.status ?? null,
  });
}

function canonicalMoney(value) {
  if (typeof value !== 'string') return null;
  const match = MONEY.exec(value);
  if (!match) return null;
  const [integer, fraction = ''] = value.split('.');
  return `${integer}.${fraction.padEnd(2, '0')}`;
}

function validText(value, maxLength) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= maxLength
    && !CONTROL_CHARACTER.test(value);
}

function validCustomer(value) {
  return value === 'me'
    || (validText(value, 254)
      && /^[^@\s]+@[^@\s]+$/.test(value));
}

function validUtcInstant(value) {
  return typeof value === 'string'
    && UTC_INSTANT.test(value)
    && Number.isFinite(Date.parse(value));
}

function normalizeIdentifier(value) {
  if (Number.isSafeInteger(value) && value > 0) return String(value);
  if (typeof value === 'string' && /^[1-9][0-9]*$/.test(value)) return value;
  return null;
}

function normalizeBoolean(value) {
  return value === true;
}

function normalizeSchedule(schedule) {
  if (!isRecord(schedule)) return null;
  const amount = canonicalMoney(schedule.amount);
  if (!amount
      || !validCustomer(schedule.payer_customer)
      || !validCustomer(schedule.beneficiary_customer)) {
    return null;
  }
  const status = isRecord(schedule.status) ? schedule.status : {};
  return {
    amount,
    payer_customer: schedule.payer_customer,
    beneficiary_customer: schedule.beneficiary_customer,
    due_date: typeof schedule.due_date === 'string' ? schedule.due_date : null,
    status: {
      secured: normalizeBoolean(status.secured),
      payment_sent: normalizeBoolean(status.payment_sent),
      payment_received: normalizeBoolean(status.payment_received),
      disbursed_to_beneficiary: normalizeBoolean(status.disbursed_to_beneficiary),
      disbursed_to_payer: normalizeBoolean(status.disbursed_to_payer),
      refund_created: normalizeBoolean(status.refund_created),
      refund_resolved: normalizeBoolean(status.refund_resolved),
      refund_rejected: normalizeBoolean(status.refund_rejected),
    },
  };
}

function normalizeMilestone(item) {
  if (!isRecord(item) || item.type !== 'milestone') return null;
  const providerItemId = normalizeIdentifier(item.id);
  if (!providerItemId || !Array.isArray(item.schedule) || item.schedule.length === 0) return null;
  const schedules = item.schedule.map(normalizeSchedule);
  if (schedules.some((entry) => entry === null)) return null;
  const status = isRecord(item.status) ? item.status : {};
  return {
    provider_item_id: providerItemId,
    reference: typeof item.reference === 'string' ? item.reference : null,
    title: typeof item.title === 'string' ? item.title : '',
    description: typeof item.description === 'string' ? item.description : '',
    inspection_period_seconds: Number.isSafeInteger(item.inspection_period)
      ? item.inspection_period
      : null,
    schedules,
    status: {
      accepted: normalizeBoolean(status.accepted),
      received: normalizeBoolean(status.received),
      rejected: normalizeBoolean(status.rejected),
    },
  };
}

function normalizeTransaction(value) {
  if (!isRecord(value)) return null;
  const providerTransactionId = normalizeIdentifier(value.id);
  const currency = PROVIDER_TO_CURRENCY[String(value.currency || '').toLowerCase()];
  if (!providerTransactionId || !currency
      || !Array.isArray(value.parties)
      || !Array.isArray(value.items)) {
    return null;
  }
  const parties = value.parties.map((party) => {
    if (!isRecord(party)
        || !['buyer', 'seller', 'broker', 'partner'].includes(party.role)
        || !validCustomer(party.customer)) return null;
    return {
      role: party.role,
      customer: party.customer,
      agreed: typeof party.agreed === 'boolean' ? party.agreed : null,
    };
  });
  if (parties.some((party) => party === null)
      || !parties.some((party) => party.role === 'buyer')
      || !parties.some((party) => party.role === 'seller')) {
    return null;
  }
  const milestoneItems = value.items.filter((item) => item?.type === 'milestone');
  const milestones = milestoneItems.map(normalizeMilestone);
  if (milestones.length === 0 || milestones.some((item) => item === null)) return null;

  return deepFreezeJson({
    transaction_id: providerTransactionId,
    provider_reference: typeof value.reference === 'string' ? value.reference : null,
    currency,
    description: typeof value.description === 'string' ? value.description : '',
    parties,
    milestones,
    provider_created_at: typeof value.creation_date === 'string' ? value.creation_date : null,
    provider_closed_at: typeof value.close_date === 'string' ? value.close_date : null,
    provider_cancelled: value.is_cancelled === true,
  });
}

function validateEffectReference(value) {
  return typeof value === 'string' && EFFECT_REFERENCE.test(value);
}

/**
 * Escrow.com's transaction reference is limited to 24 characters. This maps a
 * caller-owned effect reference to a stable 126-bit provider reference without
 * treating the provider reference as an idempotency header the API does not
 * document.
 */
export function escrowReferenceForEffect(effectReference) {
  if (!validateEffectReference(effectReference)) {
    throw new TypeError('effectReference is invalid');
  }
  const digest = createHash('sha256').update(effectReference, 'utf8').digest('base64url');
  return `ep-${digest.slice(0, 21)}`;
}

/**
 * @typedef {{
 *   effectReference: string,
 *   providerReference: string,
 *   currency: string,
 *   description: string,
 *   buyerCustomer: string,
 *   sellerCustomer: string,
 *   milestones: Array<{
 *     reference: string,
 *     title: string,
 *     description: string,
 *     amount: string|null,
 *     dueDate: string,
 *     inspectionPeriodSeconds: number,
 *   }>,
 * }} EscrowCreateRequest
 */

/**
 * @param {*} request
 * @param {string} accountEmail
 * @returns {{ ok: true, value: EscrowCreateRequest } | { ok: false, reason_code: string }}
 */
function validateCreateRequest(request, accountEmail) {
  if (!isRecord(request) || !validateEffectReference(request.effectReference)) {
    return { ok: false, reason_code: 'INVALID_EFFECT_REFERENCE' };
  }
  if (!Object.hasOwn(CURRENCY_TO_PROVIDER, request.currency)) {
    return { ok: false, reason_code: 'UNSUPPORTED_CURRENCY' };
  }
  if (!validText(request.description, 256)
      || !validCustomer(request.buyerCustomer)
      || !validCustomer(request.sellerCustomer)
      || comparableCustomer(request.buyerCustomer, accountEmail)
        === comparableCustomer(request.sellerCustomer, accountEmail)
      || !Array.isArray(request.milestones)
      || request.milestones.length === 0
      || request.milestones.length > 50) {
    return { ok: false, reason_code: 'INVALID_REQUEST' };
  }

  const references = new Set();
  const milestones = [];
  for (const item of request.milestones) {
    const amount = canonicalMoney(item?.amount);
    if (!isRecord(item)
        || !ITEM_REFERENCE.test(item.reference || '')
        || references.has(item.reference)
        || !validText(item.title, 256)
        || !validText(item.description, 256)
        || amount !== item.amount
        || !validUtcInstant(item.dueDate)
        || !Number.isSafeInteger(item.inspectionPeriodSeconds)
        || item.inspectionPeriodSeconds < 1
        || item.inspectionPeriodSeconds > 31_536_000) {
      return { ok: false, reason_code: 'INVALID_MILESTONE' };
    }
    references.add(item.reference);
    milestones.push({
      reference: item.reference,
      title: item.title,
      description: item.description,
      amount,
      dueDate: item.dueDate,
      inspectionPeriodSeconds: item.inspectionPeriodSeconds,
    });
  }

  return {
    ok: true,
    value: {
      effectReference: request.effectReference,
      providerReference: escrowReferenceForEffect(request.effectReference),
      currency: request.currency,
      description: request.description,
      buyerCustomer: request.buyerCustomer,
      sellerCustomer: request.sellerCustomer,
      milestones,
    },
  };
}

function createProviderPayload(request) {
  return {
    reference: request.providerReference,
    parties: [
      { role: 'buyer', customer: request.buyerCustomer },
      { role: 'seller', customer: request.sellerCustomer },
    ],
    currency: CURRENCY_TO_PROVIDER[request.currency],
    description: request.description,
    items: request.milestones.map((milestone) => ({
      reference: milestone.reference,
      title: milestone.title,
      description: milestone.description,
      type: 'milestone',
      inspection_period: milestone.inspectionPeriodSeconds,
      quantity: 1,
      schedule: [{
        amount: milestone.amount,
        payer_customer: request.buyerCustomer,
        beneficiary_customer: request.sellerCustomer,
        due_date: milestone.dueDate,
      }],
    })),
  };
}

function comparableCustomer(value, accountEmail) {
  return value === 'me' ? accountEmail.toLowerCase() : value.toLowerCase();
}

function transactionMatchesRequest(transaction, request, accountEmail) {
  if (transaction.provider_reference !== request.providerReference
      || transaction.currency !== request.currency
      || transaction.description !== request.description) return false;

  const buyer = transaction.parties.find((party) => party.role === 'buyer');
  const seller = transaction.parties.find((party) => party.role === 'seller');
  if (!buyer || !seller
      || comparableCustomer(buyer.customer, accountEmail)
        !== comparableCustomer(request.buyerCustomer, accountEmail)
      || comparableCustomer(seller.customer, accountEmail)
        !== comparableCustomer(request.sellerCustomer, accountEmail)) {
    return false;
  }

  if (transaction.milestones.length !== request.milestones.length) return false;
  const actualByReference = new Map(
    transaction.milestones.map((milestone) => [milestone.reference, milestone]),
  );
  return request.milestones.every((expected) => {
    const actual = actualByReference.get(expected.reference);
    if (!actual
        || actual.title !== expected.title
        || actual.description !== expected.description
        || actual.inspection_period_seconds !== expected.inspectionPeriodSeconds
        || actual.schedules.length !== 1) return false;
    const schedule = actual.schedules[0];
    return schedule.amount === expected.amount
      && schedule.due_date === expected.dueDate
      && comparableCustomer(schedule.payer_customer, accountEmail)
        === comparableCustomer(request.buyerCustomer, accountEmail)
      && comparableCustomer(schedule.beneficiary_customer, accountEmail)
        === comparableCustomer(request.sellerCustomer, accountEmail);
  });
}

function validateLocator(request) {
  if (!isRecord(request)) return null;
  const selectors = [
    request.transactionId !== undefined,
    request.providerReference !== undefined,
    request.effectReference !== undefined,
  ].filter(Boolean).length;
  if (selectors !== 1) return null;
  if (request.transactionId !== undefined) {
    const transactionId = normalizeIdentifier(request.transactionId);
    return transactionId ? { type: 'id', value: transactionId } : null;
  }
  if (request.providerReference !== undefined) {
    return typeof request.providerReference === 'string'
      && PROVIDER_REFERENCE.test(request.providerReference)
      ? { type: 'reference', value: request.providerReference }
      : null;
  }
  return validateEffectReference(request.effectReference)
    ? { type: 'reference', value: escrowReferenceForEffect(request.effectReference) }
    : null;
}

function validateReleaseRequest(request) {
  if (!isRecord(request) || !validateEffectReference(request.effectReference)) return null;
  const transactionId = normalizeIdentifier(request.transactionId);
  const milestoneId = normalizeIdentifier(request.milestoneId);
  if (!transactionId || !milestoneId) return null;
  return {
    effectReference: request.effectReference,
    transactionId,
    milestoneId,
  };
}

function milestonePhase(milestone) {
  const disbursed = milestone.schedules.length > 0
    && milestone.schedules.every(
      (schedule) => schedule.status.disbursed_to_beneficiary === true,
    );
  if (disbursed) return 'disbursed';
  if (milestone.status.accepted) return 'accepted_pending_disbursement';
  return 'not_accepted';
}

function releaseStateResult(environment, operation, request, transaction, milestone) {
  const phase = milestonePhase(milestone);
  return closedResult(
    environment,
    phase === 'disbursed' ? 'released' : 'release_submitted',
    {
      operation,
      effect_reference: request.effectReference,
      transaction_id: request.transactionId,
      milestone_id: request.milestoneId,
      provider_effect: 'milestone_acceptance',
      provider_phase: phase,
      transaction,
    },
  );
}

/**
 * Escrow.com REST adapter. It models Escrow.com as an external provider and
 * never represents EMILIA as the holder or transmitter of funds.
 *
 * @param {object} [opts]
 * @param {string} [opts.environment] 'sandbox' | 'production'
 * @param {string} [opts.email]
 * @param {string} [opts.apiKey]
 * @param {typeof fetch} [opts.fetch]
 * @param {object} [opts.customerDiligence]
 * @param {(binding: object) => Promise<boolean>} [opts.claimEffectBinding]
 * @param {number} [opts.timeoutMs]
 * @param {number} [opts.maxResponseBytes]
 */
export function createEscrowComAdapter({
  environment,
  email,
  apiKey,
  fetch: fetchImpl,
  customerDiligence,
  claimEffectBinding,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
} = {}) {
  if (!Object.hasOwn(ESCROW_ORIGINS, /** @type {PropertyKey} */ (environment))) {
    throw new TypeError('environment must be sandbox or production');
  }
  if (!validCustomer(email) || email === 'me'
      || !validText(apiKey, 4096)) {
    throw new TypeError('Escrow.com credentials are invalid');
  }
  if (typeof fetchImpl !== 'function') throw new TypeError('fetch must be injected');
  if (typeof claimEffectBinding !== 'function') {
    throw new TypeError('claimEffectBinding must be a durable fail-closed function');
  }
  const origin = validatePinnedOrigin(ESCROW_ORIGINS[
    /** @type {'sandbox'|'production'} */ (environment)
  ], /** @type {*} */ ({
    allowedHosts: ESCROW_HOSTS,
    fieldName: 'Escrow.com API origin',
  }));
  const requestTimeoutMs = validateTimeout(timeoutMs);
  const responseLimit = validateResponseLimit(maxResponseBytes, 'maxResponseBytes');
  const authorization = `Basic ${Buffer.from(`${email}:${apiKey}`, 'utf8').toString('base64')}`;

  /**
   * @param {string} path
   * @param {{ method?: string, body?: object }} [opts]
   * @returns {Promise<
   *   { kind: 'invalid', status: number|null }
   *   | { kind: 'failure', reason: 'timeout'|'network'|'response_too_large'|'invalid_response' }
   *   | { kind: 'not_found', status: 404 }
   *   | { kind: 'http_error', status: number }
   *   | { kind: 'ok', status: number, value: any }
   * >}
   */
  async function callJson(path, { method = 'GET', body } = {}) {
    const serialized = body === undefined ? undefined : JSON.stringify(body);
    if (serialized !== undefined && Buffer.byteLength(serialized, 'utf8') > MAX_REQUEST_BYTES) {
      return { kind: 'invalid', status: null };
    }
    const response = await requestBounded(
      /** @type {typeof fetch} */ (fetchImpl),
      `${origin}${API_PREFIX}${path}`,
      {
        method,
        headers: {
          Accept: 'application/json',
          Authorization: authorization,
          ...(serialized === undefined ? {} : { 'Content-Type': 'application/json' }),
        },
        ...(serialized === undefined ? {} : { body: serialized }),
      },
      {
        expectedOrigin: origin,
        maxBytes: responseLimit,
        timeoutMs: requestTimeoutMs,
      },
    );
    if (response.kind === 'failure') return response;
    if (response.status === 404) return { kind: 'not_found', status: 404 };
    if (response.status < 200 || response.status >= 300) {
      return { kind: 'http_error', status: response.status };
    }
    const parsed = parseJsonObject(
      response.bytes,
      responseHeader(response, 'content-type'),
    );
    return parsed.ok
      ? { kind: 'ok', status: response.status, value: parsed.value }
      : { kind: 'invalid', status: response.status };
  }

  /**
   * @param {{ type: string, value: string }} locator
   * @returns {Promise<{ kind: string, status?: number|null, value?: any, reason?: string, transaction?: object }>}
   */
  async function fetchTransaction(locator) {
    const path = locator.type === 'id'
      ? `/transaction/${encodeURIComponent(locator.value)}`
      : `/transaction/reference/${encodeURIComponent(locator.value)}`;
    const response = await callJson(path);
    if (response.kind !== 'ok') return response;
    const transaction = normalizeTransaction(response.value);
    return transaction
      ? { kind: 'ok', status: response.status, transaction }
      : { kind: 'invalid', status: response.status };
  }

  async function reconcileTransaction(request) {
    const locator = validateLocator(request);
    if (!locator) {
      return closedResult(environment, 'refused', {
        operation: 'reconcile_transaction',
        reason_code: 'INVALID_LOCATOR',
      });
    }
    const response = await fetchTransaction(locator);
    if (response.kind === 'not_found') {
      return closedResult(environment, 'not_found', {
        operation: 'reconcile_transaction',
      });
    }
    if (response.kind !== 'ok') {
      return providerFailure(environment, 'reconcile_transaction', response);
    }
    return closedResult(environment, 'reconciled', {
      operation: 'reconcile_transaction',
      transaction_id: response.transaction.transaction_id,
      transaction: response.transaction,
    });
  }

  function existingCreateResult(request, transaction, reconciledAfter) {
    if (!transactionMatchesRequest(transaction, request, email)) {
      return closedResult(environment, 'refused', {
        operation: 'create_transaction',
        reason_code: 'REFERENCE_CONFLICT',
        effect_reference: request.effectReference,
        provider_reference: request.providerReference,
      });
    }
    return closedResult(environment, 'existing', {
      operation: 'create_transaction',
      effect_reference: request.effectReference,
      provider_reference: request.providerReference,
      reconciled_after: reconciledAfter,
      transaction,
    });
  }

  async function reconcileCreateAttempt(request, attemptedResponse) {
    const reconciliation = await fetchTransaction({
      type: 'reference',
      value: request.providerReference,
    });
    if (reconciliation.kind === 'ok') {
      return existingCreateResult(request, reconciliation.transaction, 'create_attempt');
    }
    if (attemptedResponse.kind === 'http_error'
        && attemptedResponse.status >= 400
        && attemptedResponse.status < 500
        && reconciliation.kind === 'not_found') {
      return providerFailure(environment, 'create_transaction', attemptedResponse);
    }
    return closedResult(environment, 'indeterminate', {
      operation: 'create_transaction',
      reason_code: 'CREATE_OUTCOME_INDETERMINATE',
      effect_reference: request.effectReference,
      provider_reference: request.providerReference,
      http_status: attemptedResponse.status ?? null,
    });
  }

  async function createTransaction(input) {
    const validation = validateCreateRequest(input, /** @type {string} */ (email));
    if (!validation.ok) {
      return closedResult(environment, 'refused', {
        operation: 'create_transaction',
        reason_code: validation.reason_code,
      });
    }
    const request = validation.value;
    const prior = await fetchTransaction({
      type: 'reference',
      value: request.providerReference,
    });
    if (prior.kind === 'ok') {
      return existingCreateResult(request, prior.transaction, 'preflight');
    }
    if (prior.kind !== 'not_found') {
      return providerFailure(environment, 'create_transaction', prior);
    }

    const attempted = await callJson('/transaction', {
      method: 'POST',
      body: createProviderPayload(request),
    });
    if (attempted.kind !== 'ok') {
      return reconcileCreateAttempt(request, attempted);
    }
    const transaction = normalizeTransaction(attempted.value);
    if (!transaction) return reconcileCreateAttempt(request, attempted);
    if (!transactionMatchesRequest(transaction, request, email)) {
      return existingCreateResult(request, transaction, 'create_response');
    }
    return closedResult(environment, 'created', {
      operation: 'create_transaction',
      effect_reference: request.effectReference,
      provider_reference: request.providerReference,
      transaction,
    });
  }

  async function fetchReleaseSnapshot(request, operation) {
    const response = await fetchTransaction({ type: 'id', value: request.transactionId });
    if (response.kind === 'not_found') {
      return {
        result: closedResult(environment, 'provider_action_required', {
          operation,
          reason_code: 'TRANSACTION_NOT_FOUND',
          effect_reference: request.effectReference,
          transaction_id: request.transactionId,
          milestone_id: request.milestoneId,
        }),
      };
    }
    if (response.kind !== 'ok') {
      return { result: providerFailure(environment, operation, response) };
    }
    const milestone = response.transaction.milestones.find(
      (item) => item.provider_item_id === request.milestoneId,
    );
    if (!milestone) {
      return {
        result: closedResult(environment, 'provider_action_required', {
          operation,
          reason_code: 'MILESTONE_NOT_FOUND',
          effect_reference: request.effectReference,
          transaction_id: request.transactionId,
          milestone_id: request.milestoneId,
        }),
      };
    }
    return { transaction: response.transaction, milestone };
  }

  async function releaseMilestone(input) {
    const request = validateReleaseRequest(input);
    if (!request) {
      return closedResult(environment, 'refused', {
        operation: 'release_milestone',
        reason_code: 'INVALID_REQUEST',
      });
    }
    let effectClaim;
    try {
      effectClaim = await (/** @type {(binding: object) => Promise<boolean>} */ (
        claimEffectBinding
      ))(deepFreezeJson({
        effect_reference: request.effectReference,
        transaction_id: request.transactionId,
        milestone_id: request.milestoneId,
      }));
    } catch {
      return closedResult(environment, 'provider_error', {
        operation: 'release_milestone',
        reason_code: 'EFFECT_BINDING_STORE_UNAVAILABLE',
        effect_reference: request.effectReference,
        transaction_id: request.transactionId,
        milestone_id: request.milestoneId,
      });
    }
    if (effectClaim !== true) {
      return closedResult(environment, 'refused', {
        operation: 'release_milestone',
        reason_code: 'EFFECT_REFERENCE_CONFLICT',
        effect_reference: request.effectReference,
        transaction_id: request.transactionId,
        milestone_id: request.milestoneId,
      });
    }

    const before = await fetchReleaseSnapshot(request, 'release_milestone');
    if (before.result) return before.result;
    if (milestonePhase(before.milestone) !== 'not_accepted') {
      return releaseStateResult(
        environment,
        'release_milestone',
        request,
        before.transaction,
        before.milestone,
      );
    }
    if (!before.milestone.schedules.every(
      (schedule) => schedule.status.secured === true
        && schedule.status.payment_received === true,
    )) {
      return closedResult(environment, 'provider_action_required', {
        operation: 'release_milestone',
        reason_code: 'FUNDING_REQUIRED',
        effect_reference: request.effectReference,
        transaction_id: request.transactionId,
        milestone_id: request.milestoneId,
      });
    }
    const isAuthenticatedBuyer = before.transaction.parties.some(
      (party) => party.role === 'buyer'
        && comparableCustomer(party.customer, email)
          === (/** @type {string} */ (email)).toLowerCase(),
    );
    if (!isAuthenticatedBuyer) {
      return closedResult(environment, 'provider_action_required', {
        operation: 'release_milestone',
        reason_code: 'BUYER_ACTION_REQUIRED',
        effect_reference: request.effectReference,
        transaction_id: request.transactionId,
        milestone_id: request.milestoneId,
      });
    }

    const attempted = await callJson(
      `/transaction/${encodeURIComponent(request.transactionId)}`
        + `/item/${encodeURIComponent(request.milestoneId)}`,
      { method: 'PATCH', body: { action: 'accept' } },
    );

    // Always establish the provider state with an authenticated GET. A caller
    // can safely invoke this method again with the same effect reference: every
    // invocation performs this reconciliation before any new PATCH.
    const after = await fetchReleaseSnapshot(request, 'release_milestone_reconcile');
    if (!after.result && milestonePhase(after.milestone) !== 'not_accepted') {
      return releaseStateResult(
        environment,
        'release_milestone',
        request,
        after.transaction,
        after.milestone,
      );
    }
    if (attempted.kind === 'http_error'
        && attempted.status >= 400
        && attempted.status < 500) {
      return closedResult(environment, 'provider_action_required', {
        operation: 'release_milestone',
        reason_code: 'PROVIDER_REFUSED_RELEASE',
        effect_reference: request.effectReference,
        transaction_id: request.transactionId,
        milestone_id: request.milestoneId,
        http_status: attempted.status,
      });
    }
    return closedResult(environment, 'indeterminate', {
      operation: 'release_milestone',
      reason_code: 'RELEASE_OUTCOME_INDETERMINATE',
      effect_reference: request.effectReference,
      transaction_id: request.transactionId,
      milestone_id: request.milestoneId,
      http_status: /** @type {{ status?: number|null }} */ (attempted).status ?? null,
    });
  }

  async function requestMilestoneDisbursement(input) {
    const request = validateReleaseRequest(input);
    if (!request) {
      return closedResult(environment, 'refused', {
        operation: 'request_milestone_disbursement',
        reason_code: 'INVALID_REQUEST',
      });
    }
    const snapshot = await fetchReleaseSnapshot(request, 'request_milestone_disbursement');
    if (snapshot.result) return snapshot.result;
    if (milestonePhase(snapshot.milestone) === 'disbursed') {
      return releaseStateResult(
        environment,
        'request_milestone_disbursement',
        request,
        snapshot.transaction,
        snapshot.milestone,
      );
    }
    return closedResult(environment, 'provider_action_required', {
      operation: 'request_milestone_disbursement',
      reason_code: 'NO_DOCUMENTED_DIRECT_DISBURSEMENT',
      effect_reference: request.effectReference,
      transaction_id: request.transactionId,
      milestone_id: request.milestoneId,
      provider_phase: milestonePhase(snapshot.milestone),
      transaction: snapshot.transaction,
    });
  }

  return defineExternalCustodianAdapter({
    provider: 'escrow.com',
    environment,
    customerDiligence,
    capabilities: {
      create_transaction: true,
      reconcile_transaction: true,
      milestone_release: 'provider_api',
      direct_disbursement: 'provider_action_required',
    },
    createTransaction,
    reconcileTransaction,
    releaseMilestone,
    requestMilestoneDisbursement,
  });
}
