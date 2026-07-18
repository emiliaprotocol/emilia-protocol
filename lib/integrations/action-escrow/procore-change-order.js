// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { canonicalize } from '../../../packages/verify/index.js';
import {
  parseJsonObject,
  requestBounded,
  responseHeader,
  validatePinnedOrigin,
  validateResponseLimit,
  validateTimeout,
} from './bounded-fetch.js';
import { deepFreezeJson } from './licensed-custodian.js';

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_METADATA_BYTES = 1024 * 1024;
const MAX_LINE_ITEMS = 1000;
const PAGE_SIZE = 100;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const DECIMAL = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/;
const RFC3339_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const PROCORE_HOSTS = new Set(['api.procore.com', 'sandbox.procore.com']);
const RESOURCE_BY_TYPE = Object.freeze({
  commitment: 'commitment_change_orders',
  prime: 'prime_change_orders',
});
const PROJECT_RECORD_VERSION = 'EMILIA-EXTERNAL-PROJECT-RECORD-EVIDENCE-v1';
const PROJECT_RECORD_RETRIEVAL_METHOD = 'authenticated_provider_refetch';
const PROJECT_RECORD_CLAIM_BOUNDARY =
  'The provider reported these project facts at the observation time. '
  + 'This record is neither contract acceptance nor release authorization.';
const PROJECT_RECORD_KEYS = new Set([
  '@version',
  'provider',
  'retrieval_method',
  'api_origin',
  'company_id',
  'project_id',
  'change_order_type',
  'change_order_id',
  'snapshot_digest',
  'change_order',
  'line_items',
  'observed_at',
  'authorizes_action',
  'establishes_acceptance',
  'claim_boundary',
]);
const PROJECT_RECORD_EXPECTED_KEYS = new Set([
  'snapshotDigest',
  'apiOrigin',
  'companyId',
  'projectId',
  'changeOrderType',
  'changeOrderId',
]);
const HASH = /^sha256:[0-9a-f]{64}$/;

function isRecord(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function exactKeys(value, allowed, required = allowed) {
  if (!isRecord(value)) return false;
  const keys = Object.keys(value);
  return keys.every((key) => allowed.has(key))
    && [...required].every((key) => Object.hasOwn(value, key));
}

function validString(value, maxLength) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= maxLength
    && !CONTROL_CHARACTER.test(value);
}

function identifier(value) {
  const normalized = typeof value === 'number' && Number.isSafeInteger(value)
    ? String(value)
    : value;
  return typeof normalized === 'string' && IDENTIFIER.test(normalized)
    ? normalized
    : null;
}

function optionalString(value, maxLength) {
  return value === null || value === undefined
    ? null
    : validString(value, maxLength) ? value : null;
}

function decimal(value) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) return null;
    value = String(value);
  }
  return typeof value === 'string' && DECIMAL.test(value) ? value : null;
}

function safeInteger(value) {
  if (Number.isSafeInteger(value)) return value;
  if (typeof value === 'string' && /^(?:0|[1-9][0-9]*)$/.test(value)) {
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : null;
  }
  return null;
}

function strictInstantMs(value) {
  if (typeof value !== 'string') return NaN;
  const match = value.match(RFC3339_INSTANT);
  if (!match) return NaN;
  const [
    ,
    yearText,
    monthText,
    dayText,
    hourText,
    minuteText,
    secondText,
    ,
    offsetHourText,
    offsetMinuteText,
  ] = match;
  const localText = `${yearText}-${monthText}-${dayText}`
    + `T${hourText}:${minuteText}:${secondText}`;
  const calendar = new Date(0);
  calendar.setUTCFullYear(Number(yearText), Number(monthText) - 1, Number(dayText));
  calendar.setUTCHours(
    Number(hourText),
    Number(minuteText),
    Number(secondText),
    0,
  );
  if (calendar.toISOString().slice(0, 19) !== localText) return NaN;
  if (offsetHourText !== undefined
      && (Number(offsetHourText) > 23 || Number(offsetMinuteText) > 59)) {
    return NaN;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : NaN;
}

function validateProcoreOrigin(value) {
  const origin = validatePinnedOrigin(value, { fieldName: 'apiOrigin' });
  const hostname = new URL(origin).hostname.toLowerCase();
  if (!PROCORE_HOSTS.has(hostname)) {
    throw new TypeError('apiOrigin must be an official Procore API origin');
  }
  return origin;
}

function closedResult(kind, fields = {}) {
  return deepFreezeJson({
    kind,
    provider: 'procore',
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

function providerFailure(operation, response) {
  if (response.kind === 'failure') {
    return closedResult('provider_error', {
      operation,
      reason_code: transportReason(response.reason),
      http_status: null,
    });
  }
  return closedResult('provider_error', {
    operation,
    reason_code: response.kind === 'invalid'
      ? 'PROVIDER_RESPONSE_INVALID'
      : 'PROVIDER_HTTP_ERROR',
    http_status: response.status ?? null,
  });
}

function canonicalDigest(value) {
  return `sha256:${createHash('sha256')
    .update(canonicalize(value), 'utf8')
    .digest('hex')}`;
}

function projectRecordDigestScope(value) {
  const { snapshot_digest: _snapshotDigest, ...scope } = value;
  return scope;
}

function normalizeWbsCode(value) {
  if (value === null || value === undefined) return null;
  if (!isRecord(value)) return undefined;
  const id = identifier(value.id);
  const flatCode = optionalString(value.flat_code, 256);
  const description = optionalString(value.description, 2048);
  if (!id || (value.flat_code !== undefined && flatCode === null)
      || (value.description !== undefined && description === null)) {
    return undefined;
  }
  return {
    id,
    flat_code: flatCode,
    description,
  };
}

function normalizeLineItem(value) {
  if (!isRecord(value)) return null;
  const id = identifier(value.id);
  const position = safeInteger(value.position);
  const description = optionalString(value.description, 4096);
  const amount = decimal(value.amount);
  const quantity = value.quantity === null || value.quantity === undefined
    ? null
    : decimal(value.quantity);
  const unitCost = value.unit_cost === null || value.unit_cost === undefined
    ? null
    : decimal(value.unit_cost);
  const uom = optionalString(value.uom, 128);
  const wbsCode = normalizeWbsCode(value.wbs_code);
  const primeLineItemId = value.prime_line_item_id === null
    || value.prime_line_item_id === undefined
    ? null
    : identifier(value.prime_line_item_id);
  const commitmentLineItemId = value.commitment_line_item_id === null
    || value.commitment_line_item_id === undefined
    ? null
    : identifier(value.commitment_line_item_id);
  const fundingRuleId = value.funding_rule_id === null
    || value.funding_rule_id === undefined
    ? null
    : identifier(value.funding_rule_id);
  if (!id || position === null || description === null || amount === null
      || (value.quantity !== null && value.quantity !== undefined && quantity === null)
      || (value.unit_cost !== null && value.unit_cost !== undefined && unitCost === null)
      || (value.uom !== null && value.uom !== undefined && uom === null)
      || wbsCode === undefined
      || (value.prime_line_item_id !== null
        && value.prime_line_item_id !== undefined
        && primeLineItemId === null)
      || (value.commitment_line_item_id !== null
        && value.commitment_line_item_id !== undefined
        && commitmentLineItemId === null)
      || (value.funding_rule_id !== null
        && value.funding_rule_id !== undefined
        && fundingRuleId === null)) {
    return null;
  }
  return {
    id,
    position,
    description,
    amount,
    quantity,
    unit_cost: unitCost,
    uom,
    wbs_code: wbsCode,
    prime_line_item_id: primeLineItemId,
    commitment_line_item_id: commitmentLineItemId,
    funding_rule_id: fundingRuleId,
  };
}

function normalizeChangeOrder(value, expectedId) {
  if (!isRecord(value)) return null;
  const id = identifier(value.id);
  const number = optionalString(value.number, 256);
  const title = optionalString(value.title, 2048);
  const description = optionalString(value.description, 16_384);
  const status = optionalString(value.status, 128);
  const total = decimal(
    value.grand_total ?? value.total_amount ?? value.amount,
  );
  const updatedAt = optionalString(value.updated_at, 64);
  const updatedAtMs = strictInstantMs(updatedAt);
  const contractId = identifier(
    value.contract_id
      ?? value.commitment_id
      ?? value.prime_contract_id
      ?? value.contract?.id,
  );
  if (!id || id !== expectedId || number === null || title === null
      || description === null || status === null || total === null
      || updatedAt === null || !Number.isFinite(updatedAtMs)
      || !contractId) {
    return null;
  }
  return {
    id,
    number,
    title,
    description,
    status: status.toLowerCase(),
    total_amount: total,
    contract_id: contractId,
    updated_at: new Date(updatedAtMs).toISOString(),
  };
}

function normalizeExpected(expected) {
  if (!isRecord(expected)) return null;
  const status = optionalString(expected.status, 128);
  const number = expected.number === undefined
    ? undefined
    : optionalString(expected.number, 256);
  const totalAmount = expected.totalAmount === undefined
    ? undefined
    : decimal(expected.totalAmount);
  if (status === null || (expected.number !== undefined && number === null)
      || (expected.totalAmount !== undefined && totalAmount === null)) {
    return null;
  }
  return {
    status: status.toLowerCase(),
    ...(number === undefined ? {} : { number }),
    ...(totalAmount === undefined ? {} : { totalAmount }),
  };
}

function expectationsMatch(changeOrder, expected) {
  return changeOrder.status === expected.status
    && (expected.number === undefined || changeOrder.number === expected.number)
    && (expected.totalAmount === undefined
      || changeOrder.total_amount === expected.totalAmount);
}

function snapshotsMatch(left, right) {
  return canonicalize(left) === canonicalize(right);
}

function lineItemSort(left, right) {
  return left.position - right.position || left.id.localeCompare(right.id);
}

function parseTotalHeader(response) {
  const raw = responseHeader(response, 'total');
  if (typeof raw !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(raw)) return null;
  const parsed = Number(raw);
  return Number.isSafeInteger(parsed) && parsed <= MAX_LINE_ITEMS ? parsed : null;
}

function hasNextLink(response) {
  const link = responseHeader(response, 'link');
  return typeof link === 'string' && /rel="?next"?/i.test(link);
}

function validObservedAt(value) {
  const parsed = strictInstantMs(value);
  return Number.isFinite(parsed)
    && new Date(parsed).toISOString() === value;
}

/**
 * Re-perform the complete project-record digest under relying-party-pinned
 * source coordinates. Provider data remains evidence only and cannot fill an
 * agreement-acceptance or release-authorization row.
 */
export function verifyProcoreChangeOrderEvidence(value, expected = {}) {
  try {
    if (!exactKeys(expected, PROJECT_RECORD_EXPECTED_KEYS)
      || !exactKeys(value, PROJECT_RECORD_KEYS)
      || value['@version'] !== PROJECT_RECORD_VERSION
      || value.provider !== 'procore'
      || value.retrieval_method !== PROJECT_RECORD_RETRIEVAL_METHOD
      || value.authorizes_action !== false
      || value.establishes_acceptance !== false
      || value.claim_boundary !== PROJECT_RECORD_CLAIM_BOUNDARY
      || !HASH.test(value.snapshot_digest)
      || !HASH.test(expected.snapshotDigest)
      || value.snapshot_digest !== expected.snapshotDigest) {
      return Object.freeze({ valid: false, reason: 'project_record_malformed' });
    }

    const expectedOrigin = validateProcoreOrigin(expected.apiOrigin);
    const expectedCompanyId = identifier(expected.companyId);
    const expectedProjectId = identifier(expected.projectId);
    const expectedChangeOrderId = identifier(expected.changeOrderId);
    if (!expectedCompanyId
      || !expectedProjectId
      || !expectedChangeOrderId
      || !Object.hasOwn(RESOURCE_BY_TYPE, expected.changeOrderType)
      || value.api_origin !== expectedOrigin
      || value.company_id !== expectedCompanyId
      || value.project_id !== expectedProjectId
      || value.change_order_type !== expected.changeOrderType
      || value.change_order_id !== expectedChangeOrderId
      || !validObservedAt(value.observed_at)
      || !Array.isArray(value.line_items)
      || value.line_items.length > MAX_LINE_ITEMS) {
      return Object.freeze({ valid: false, reason: 'project_record_context_mismatch' });
    }

    const normalizedChangeOrder = normalizeChangeOrder(
      value.change_order,
      expectedChangeOrderId,
    );
    const normalizedLineItems = value.line_items
      .map((entry) => normalizeLineItem(entry));
    if (!normalizedChangeOrder
      || normalizedLineItems.some((entry) => entry === null)) {
      return Object.freeze({ valid: false, reason: 'project_record_payload_malformed' });
    }
    normalizedLineItems.sort(lineItemSort);
    const lineItemIds = normalizedLineItems.map((entry) => entry.id);
    if (new Set(lineItemIds).size !== lineItemIds.length
      || canonicalize(normalizedChangeOrder) !== canonicalize(value.change_order)
      || canonicalize(normalizedLineItems) !== canonicalize(value.line_items)) {
      return Object.freeze({ valid: false, reason: 'project_record_payload_malformed' });
    }

    const snapshotDigest = canonicalDigest(projectRecordDigestScope(value));
    if (snapshotDigest !== expected.snapshotDigest) {
      return Object.freeze({ valid: false, reason: 'project_record_digest_mismatch' });
    }
    return deepFreezeJson({
      valid: true,
      reason: 'verified',
      provider: 'procore',
      snapshot_digest: snapshotDigest,
      api_origin: expectedOrigin,
      company_id: expectedCompanyId,
      project_id: expectedProjectId,
      change_order_type: expected.changeOrderType,
      change_order_id: expectedChangeOrderId,
      observed_at: value.observed_at,
      authorizes_action: false,
      establishes_acceptance: false,
    });
  } catch {
    return Object.freeze({ valid: false, reason: 'project_record_verifier_failed' });
  }
}

/**
 * Read-only Procore evidence adapter. Provider data is source evidence only:
 * it does not establish contract acceptance, human approval, or payment
 * authority. A separately pinned DAB issuer decides whether and how these
 * source facts map to one final document and action.
 */
export function createProcoreChangeOrderAdapter({
  apiOrigin = 'https://api.procore.com',
  accessToken,
  companyId,
  fetch: fetchImpl,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxMetadataBytes = DEFAULT_MAX_METADATA_BYTES,
  clock = () => new Date().toISOString(),
} = {}) {
  const origin = validateProcoreOrigin(apiOrigin);
  const normalizedCompanyId = identifier(companyId);
  if (!normalizedCompanyId) throw new TypeError('companyId is invalid');
  if (!validString(accessToken, 8192) || /\s/.test(accessToken)) {
    throw new TypeError('accessToken is invalid');
  }
  if (typeof fetchImpl !== 'function') throw new TypeError('fetch must be injected');
  if (typeof clock !== 'function') throw new TypeError('clock must be a function');
  const totalTimeoutMs = validateTimeout(timeoutMs);
  const metadataLimit = validateResponseLimit(maxMetadataBytes, 'maxMetadataBytes');
  const authorization = `Bearer ${accessToken}`;

  async function call(path, deadline) {
    const remaining = deadline - Date.now();
    if (remaining < 1) return { kind: 'failure', reason: 'timeout' };
    return requestBounded(
      fetchImpl,
      `${origin}${path}`,
      {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          Authorization: authorization,
          'Procore-Company-Id': normalizedCompanyId,
        },
      },
      {
        expectedOrigin: origin,
        maxBytes: metadataLimit,
        timeoutMs: Math.max(1, Math.min(totalTimeoutMs, remaining)),
      },
    );
  }

  async function fetchJson(path, deadline, operation) {
    const response = await call(path, deadline);
    if (response.kind === 'failure') {
      return { ok: false, result: providerFailure(operation, response) };
    }
    if (response.status < 200 || response.status >= 300) {
      return {
        ok: false,
        result: providerFailure(operation, {
          kind: 'http_error',
          status: response.status,
        }),
      };
    }
    const parsed = parseJsonObject(
      response.bytes,
      responseHeader(response, 'content-type'),
    );
    if (!parsed.ok) {
      return {
        ok: false,
        result: providerFailure(operation, {
          kind: 'invalid',
          status: response.status,
        }),
      };
    }
    return { ok: true, value: parsed.value, response };
  }

  async function fetchLineItems(resource, projectId, changeOrderId, deadline) {
    const items = [];
    let page = 1;
    let expectedTotal = null;
    while (items.length <= MAX_LINE_ITEMS) {
      const path = `/rest/v2.0/companies/${encodeURIComponent(normalizedCompanyId)}`
        + `/projects/${encodeURIComponent(projectId)}`
        + `/${resource}/${encodeURIComponent(changeOrderId)}/line_items`
        + `?page=${page}&per_page=${PAGE_SIZE}&view=extended`;
      const fetched = await fetchJson(path, deadline, 'fetch_change_order_line_items');
      if (!fetched.ok) return fetched;
      if (!Array.isArray(fetched.value.data)) {
        return {
          ok: false,
          result: providerFailure('fetch_change_order_line_items', {
            kind: 'invalid',
            status: fetched.response.status,
          }),
        };
      }
      const total = parseTotalHeader(fetched.response);
      if (total === null || (expectedTotal !== null && total !== expectedTotal)) {
        return {
          ok: false,
          result: closedResult('refused', {
            operation: 'fetch_change_order_line_items',
            reason_code: 'INCOMPLETE_LINE_ITEM_VIEW',
          }),
        };
      }
      expectedTotal = total;
      for (const raw of fetched.value.data) {
        const item = normalizeLineItem(raw);
        if (!item || items.some((existing) => existing.id === item.id)) {
          return {
            ok: false,
            result: closedResult('refused', {
              operation: 'fetch_change_order_line_items',
              reason_code: 'MALFORMED_LINE_ITEM',
            }),
          };
        }
        items.push(item);
      }
      if (items.length > expectedTotal || items.length > MAX_LINE_ITEMS) {
        return {
          ok: false,
          result: closedResult('refused', {
            operation: 'fetch_change_order_line_items',
            reason_code: 'INCOMPLETE_LINE_ITEM_VIEW',
          }),
        };
      }
      const next = hasNextLink(fetched.response);
      if (items.length === expectedTotal) {
        if (next) {
          return {
            ok: false,
            result: closedResult('refused', {
              operation: 'fetch_change_order_line_items',
              reason_code: 'INCOMPLETE_LINE_ITEM_VIEW',
            }),
          };
        }
        items.sort(lineItemSort);
        return { ok: true, value: items };
      }
      if (!next || fetched.value.data.length === 0) {
        return {
          ok: false,
          result: closedResult('refused', {
            operation: 'fetch_change_order_line_items',
            reason_code: 'INCOMPLETE_LINE_ITEM_VIEW',
          }),
        };
      }
      page += 1;
    }
    return {
      ok: false,
      result: closedResult('refused', {
        operation: 'fetch_change_order_line_items',
        reason_code: 'LINE_ITEM_LIMIT_EXCEEDED',
      }),
    };
  }

  async function fetchSnapshot(resource, projectId, changeOrderId, deadline) {
    const orderPath = `/rest/v1.0/projects/${encodeURIComponent(projectId)}`
      + `/${resource}/${encodeURIComponent(changeOrderId)}`;
    const order = await fetchJson(orderPath, deadline, 'fetch_change_order');
    if (!order.ok) return order;
    const normalizedOrder = normalizeChangeOrder(order.value, changeOrderId);
    if (!normalizedOrder) {
      return {
        ok: false,
        result: closedResult('mismatch', {
          operation: 'fetch_change_order',
          reason_code: 'CHANGE_ORDER_ID_OR_SHAPE_MISMATCH',
        }),
      };
    }
    const lineItems = await fetchLineItems(
      resource,
      projectId,
      changeOrderId,
      deadline,
    );
    if (!lineItems.ok) return lineItems;
    return {
      ok: true,
      value: {
        change_order: normalizedOrder,
        line_items: lineItems.value,
      },
    };
  }

  async function fetchChangeOrderEvidence(input = {}) {
    if (!isRecord(input)) {
      return closedResult('refused', {
        operation: 'fetch_change_order_evidence',
        reason_code: 'INVALID_EXPECTATION',
      });
    }
    const {
      projectId,
      changeOrderId,
      changeOrderType,
      expected,
    } = input;
    const normalizedProjectId = identifier(projectId);
    const normalizedChangeOrderId = identifier(changeOrderId);
    const resource = RESOURCE_BY_TYPE[changeOrderType];
    const normalizedExpected = normalizeExpected(expected);
    if (!normalizedProjectId || !normalizedChangeOrderId || !resource
        || !normalizedExpected) {
      return closedResult('refused', {
        operation: 'fetch_change_order_evidence',
        reason_code: 'INVALID_EXPECTATION',
      });
    }
    const deadline = Date.now() + totalTimeoutMs;
    const initial = await fetchSnapshot(
      resource,
      normalizedProjectId,
      normalizedChangeOrderId,
      deadline,
    );
    if (!initial.ok) return initial.result;
    if (!expectationsMatch(initial.value.change_order, normalizedExpected)) {
      return closedResult(
        initial.value.change_order.status === normalizedExpected.status
          ? 'mismatch'
          : 'not_final',
        {
          operation: 'fetch_change_order_evidence',
          reason_code: initial.value.change_order.status === normalizedExpected.status
            ? 'CHANGE_ORDER_EXPECTATION_MISMATCH'
            : 'CHANGE_ORDER_NOT_FINAL',
          provider_status: initial.value.change_order.status,
        },
      );
    }

    const final = await fetchSnapshot(
      resource,
      normalizedProjectId,
      normalizedChangeOrderId,
      deadline,
    );
    if (!final.ok) return final.result;
    if (!snapshotsMatch(initial.value, final.value)) {
      return closedResult('mismatch', {
        operation: 'fetch_change_order_evidence',
        reason_code: 'CHANGE_ORDER_CHANGED_DURING_FETCH',
      });
    }

    let observedAt;
    try {
      observedAt = clock();
    } catch {
      observedAt = null;
    }
    if (!validObservedAt(observedAt)) {
      return closedResult('refused', {
        operation: 'fetch_change_order_evidence',
        reason_code: 'INVALID_CLOCK',
      });
    }

    const evidenceBody = {
      '@version': PROJECT_RECORD_VERSION,
      provider: 'procore',
      retrieval_method: PROJECT_RECORD_RETRIEVAL_METHOD,
      api_origin: origin,
      company_id: normalizedCompanyId,
      project_id: normalizedProjectId,
      change_order_type: changeOrderType,
      change_order_id: normalizedChangeOrderId,
      change_order: initial.value.change_order,
      line_items: initial.value.line_items,
      observed_at: observedAt,
      authorizes_action: false,
      establishes_acceptance: false,
      claim_boundary: PROJECT_RECORD_CLAIM_BOUNDARY,
    };
    const snapshotDigest = canonicalDigest(evidenceBody);
    const evidence = deepFreezeJson({
      ...evidenceBody,
      snapshot_digest: snapshotDigest,
    });
    return Object.freeze({
      kind: 'evidence_ready',
      provider: 'procore',
      evidence,
      material_source_digest: snapshotDigest,
    });
  }

  return Object.freeze({
    kind: 'external_project_record_adapter',
    provider: 'procore',
    api_origin: origin,
    company_id: normalizedCompanyId,
    fetchChangeOrderEvidence,
  });
}

export default createProcoreChangeOrderAdapter;
