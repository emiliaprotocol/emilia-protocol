// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';
import {
  createProcoreChangeOrderAdapter,
  verifyProcoreChangeOrderEvidence,
} from '../lib/integrations/action-escrow/procore-change-order.ts';

const API_ORIGIN = 'https://api.procore.com';
const TOKEN = 'procore-oauth-token';
const COMPANY_ID = '42';
const PROJECT_ID = '2048';
const CHANGE_ORDER_ID = '9001';
const OBSERVED_AT = '2026-07-18T16:00:00.000Z';

function jsonResponse(value, {
  status = 200,
  total,
  link,
  contentType = 'application/json; charset=utf-8',
} = {}) {
  const headers = { 'Content-Type': contentType };
  if (total !== undefined) headers.Total = String(total);
  if (link !== undefined) headers.Link = link;
  return new Response(JSON.stringify(value), { status, headers });
}

function changeOrder(overrides = {}) {
  return {
    id: CHANGE_ORDER_ID,
    number: 'CCO-017',
    title: 'Cabinet and countertop revision',
    description: 'Replace cabinet package and add countertop template milestone.',
    status: 'approved',
    grand_total: '23000.00',
    commitment_id: 'contract-77',
    updated_at: '2026-07-18T15:59:00Z',
    ...overrides,
  };
}

function lineItem(id, position, amount, description) {
  return {
    id,
    position,
    amount,
    description,
    quantity: '1',
    unit_cost: amount,
    uom: 'LS',
    commitment_line_item_id: `commitment-${id}`,
    prime_line_item_id: `prime-${id}`,
    funding_rule_id: null,
    wbs_code: {
      id: `wbs-${id}`,
      flat_code: `01-0${position}`,
      description,
    },
  };
}

function request(overrides = {}) {
  return {
    projectId: PROJECT_ID,
    changeOrderId: CHANGE_ORDER_ID,
    changeOrderType: 'commitment',
    expected: {
      status: 'approved',
      number: 'CCO-017',
      totalAmount: '23000.00',
    },
    ...overrides,
  };
}

function adapter(fetchImpl, overrides = {}) {
  return createProcoreChangeOrderAdapter({
    apiOrigin: API_ORIGIN,
    accessToken: TOKEN,
    companyId: COMPANY_ID,
    fetch: fetchImpl,
    clock: () => OBSERVED_AT,
    ...overrides,
  });
}

function evidenceExpectation(snapshotDigest, overrides = {}) {
  return {
    snapshotDigest,
    apiOrigin: API_ORIGIN,
    companyId: COMPANY_ID,
    projectId: PROJECT_ID,
    changeOrderType: 'commitment',
    changeOrderId: CHANGE_ORDER_ID,
    ...overrides,
  };
}

function stableFetch() {
  const items = [
    lineItem('line-2', 2, '5000.00', 'Countertop template'),
    lineItem('line-1', 1, '18000.00', 'Cabinet installation'),
  ];
  return vi.fn()
    .mockResolvedValueOnce(jsonResponse(changeOrder()))
    .mockResolvedValueOnce(jsonResponse({ data: items }, { total: 2 }))
    .mockResolvedValueOnce(jsonResponse(changeOrder()))
    .mockResolvedValueOnce(jsonResponse({ data: items }, { total: 2 }));
}

describe('Procore change-order source adapter', () => {
  it('double-fetches an exact read-only snapshot and marks it non-authoritative', async () => {
    const fetchImpl = stableFetch();

    const result = await adapter(fetchImpl).fetchChangeOrderEvidence(request());

    expect(result.kind).toBe('evidence_ready');
    expect(result.material_source_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(result.evidence).toMatchObject({
      '@version': 'EMILIA-EXTERNAL-PROJECT-RECORD-EVIDENCE-v1',
      provider: 'procore',
      retrieval_method: 'authenticated_provider_refetch',
      api_origin: API_ORIGIN,
      company_id: COMPANY_ID,
      project_id: PROJECT_ID,
      change_order_type: 'commitment',
      change_order_id: CHANGE_ORDER_ID,
      snapshot_digest: result.material_source_digest,
      observed_at: OBSERVED_AT,
      authorizes_action: false,
      establishes_acceptance: false,
      change_order: {
        id: CHANGE_ORDER_ID,
        number: 'CCO-017',
        status: 'approved',
        total_amount: '23000.00',
        contract_id: 'contract-77',
      },
    });
    expect(result.evidence.line_items.map((item) => item.id))
      .toEqual(['line-1', 'line-2']);
    expect(Object.isFrozen(result.evidence)).toBe(true);
    expect(JSON.stringify(result)).not.toContain(TOKEN);
    expect(verifyProcoreChangeOrderEvidence(
      result.evidence,
      evidenceExpectation(result.material_source_digest),
    )).toMatchObject({
      valid: true,
      provider: 'procore',
      authorizes_action: false,
      establishes_acceptance: false,
    });

    const resource = 'commitment_change_orders';
    expect(fetchImpl.mock.calls.map(([url]) => url)).toEqual([
      `${API_ORIGIN}/rest/v1.0/projects/${PROJECT_ID}/${resource}/${CHANGE_ORDER_ID}`,
      `${API_ORIGIN}/rest/v2.0/companies/${COMPANY_ID}/projects/${PROJECT_ID}`
        + `/${resource}/${CHANGE_ORDER_ID}/line_items?page=1&per_page=100&view=extended`,
      `${API_ORIGIN}/rest/v1.0/projects/${PROJECT_ID}/${resource}/${CHANGE_ORDER_ID}`,
      `${API_ORIGIN}/rest/v2.0/companies/${COMPANY_ID}/projects/${PROJECT_ID}`
        + `/${resource}/${CHANGE_ORDER_ID}/line_items?page=1&per_page=100&view=extended`,
    ]);
    expect(fetchImpl.mock.calls[0][1]).toMatchObject({
      method: 'GET',
      redirect: 'error',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${TOKEN}`,
        'Procore-Company-Id': COMPANY_ID,
      },
    });
  });

  it('binds every source coordinate and refuses provenance relabeling', async () => {
    const result = await adapter(stableFetch()).fetchChangeOrderEvidence(request());
    expect(result.kind).toBe('evidence_ready');
    const expected = evidenceExpectation(result.material_source_digest);

    for (const [field, value] of [
      ['api_origin', 'https://sandbox.procore.com'],
      ['company_id', 'attacker-company'],
      ['project_id', 'attacker-project'],
      ['change_order_type', 'prime'],
      ['change_order_id', 'attacker-order'],
      ['observed_at', '2026-07-18T16:00:01.000Z'],
      ['authorizes_action', true],
      ['establishes_acceptance', true],
      ['claim_boundary', 'This record authorizes release.'],
    ]) {
      const mutated = structuredClone(result.evidence);
      mutated[field] = value;
      expect(
        verifyProcoreChangeOrderEvidence(mutated, expected),
        `${field} substitution must fail`,
      ).toMatchObject({ valid: false });
    }

    const wrongPinnedProject = verifyProcoreChangeOrderEvidence(
      result.evidence,
      evidenceExpectation(result.material_source_digest, {
        projectId: 'different-project',
      }),
    );
    expect(wrongPinnedProject).toMatchObject({
      valid: false,
      reason: 'project_record_context_mismatch',
    });
  });

  it('fetches every declared line-item page before producing evidence', async () => {
    const first = lineItem('line-1', 1, '18000.00', 'Cabinet installation');
    const second = lineItem('line-2', 2, '5000.00', 'Countertop template');
    const next = `<${API_ORIGIN}/next>; rel="next"`;
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(changeOrder()))
      .mockResolvedValueOnce(jsonResponse({ data: [first] }, { total: 2, link: next }))
      .mockResolvedValueOnce(jsonResponse({ data: [second] }, { total: 2 }))
      .mockResolvedValueOnce(jsonResponse(changeOrder()))
      .mockResolvedValueOnce(jsonResponse({ data: [first] }, { total: 2, link: next }))
      .mockResolvedValueOnce(jsonResponse({ data: [second] }, { total: 2 }));

    const result = await adapter(fetchImpl).fetchChangeOrderEvidence(request());

    expect(result.kind).toBe('evidence_ready');
    expect(result.evidence.line_items).toHaveLength(2);
    expect(fetchImpl.mock.calls[2][0]).toContain('page=2');
    expect(fetchImpl.mock.calls[5][0]).toContain('page=2');
  });

  it('refuses incomplete pagination instead of binding a partial authority view', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(changeOrder()))
      .mockResolvedValueOnce(jsonResponse(
        { data: [lineItem('line-1', 1, '18000.00', 'Cabinet installation')] },
        { total: 2 },
      ));

    const result = await adapter(fetchImpl).fetchChangeOrderEvidence(request());

    expect(result).toMatchObject({
      kind: 'refused',
      reason_code: 'INCOMPLETE_LINE_ITEM_VIEW',
    });
  });

  it('refuses provider ID substitution and expectation mismatch', async () => {
    const idFetch = vi.fn()
      .mockResolvedValueOnce(jsonResponse(changeOrder({ id: 'attacker-order' })));
    await expect(adapter(idFetch).fetchChangeOrderEvidence(request()))
      .resolves.toMatchObject({
        kind: 'mismatch',
        reason_code: 'CHANGE_ORDER_ID_OR_SHAPE_MISMATCH',
      });

    const totalFetch = stableFetch();
    const totalResult = await adapter(totalFetch).fetchChangeOrderEvidence(request({
      expected: {
        status: 'approved',
        number: 'CCO-017',
        totalAmount: '1.00',
      },
    }));
    expect(totalResult).toMatchObject({
      kind: 'mismatch',
      reason_code: 'CHANGE_ORDER_EXPECTATION_MISMATCH',
    });
    expect(totalFetch).toHaveBeenCalledTimes(2);
  });

  it('distinguishes a non-final provider state from a structural mismatch', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(changeOrder({ status: 'pending' })))
      .mockResolvedValueOnce(jsonResponse({
        data: [lineItem('line-1', 1, '23000.00', 'Pending work')],
      }, { total: 1 }));

    const result = await adapter(fetchImpl).fetchChangeOrderEvidence(request());

    expect(result).toMatchObject({
      kind: 'not_final',
      reason_code: 'CHANGE_ORDER_NOT_FINAL',
      provider_status: 'pending',
    });
  });

  it('refuses a change between the first and second authoritative snapshots', async () => {
    const items = [lineItem('line-1', 1, '23000.00', 'Cabinet package')];
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(changeOrder()))
      .mockResolvedValueOnce(jsonResponse({ data: items }, { total: 1 }))
      .mockResolvedValueOnce(jsonResponse(changeOrder({
        description: 'Mutated after first read',
        updated_at: '2026-07-18T15:59:30Z',
      })))
      .mockResolvedValueOnce(jsonResponse({ data: items }, { total: 1 }));

    const result = await adapter(fetchImpl).fetchChangeOrderEvidence(request());

    expect(result).toMatchObject({
      kind: 'mismatch',
      reason_code: 'CHANGE_ORDER_CHANGED_DURING_FETCH',
    });
  });

  it('fails closed on malformed line-item money and missing completeness headers', async () => {
    const malformedFetch = vi.fn()
      .mockResolvedValueOnce(jsonResponse(changeOrder()))
      .mockResolvedValueOnce(jsonResponse({
        data: [lineItem('line-1', 1, '01.00', 'Noncanonical amount')],
      }, { total: 1 }));
    await expect(adapter(malformedFetch).fetchChangeOrderEvidence(request()))
      .resolves.toMatchObject({
        kind: 'refused',
        reason_code: 'MALFORMED_LINE_ITEM',
      });

    const noTotalFetch = vi.fn()
      .mockResolvedValueOnce(jsonResponse(changeOrder()))
      .mockResolvedValueOnce(jsonResponse({
        data: [lineItem('line-1', 1, '23000.00', 'No total header')],
      }));
    await expect(adapter(noTotalFetch).fetchChangeOrderEvidence(request()))
      .resolves.toMatchObject({
        kind: 'refused',
        reason_code: 'INCOMPLETE_LINE_ITEM_VIEW',
      });
  });

  it('accepts only official Procore origins and never exposes write methods', () => {
    expect(() => adapter(vi.fn(), { apiOrigin: 'https://attacker.example' }))
      .toThrow(/official Procore API origin/);
    const subject = adapter(vi.fn(), { apiOrigin: 'https://sandbox.procore.com' });
    expect(subject).toMatchObject({
      kind: 'external_project_record_adapter',
      provider: 'procore',
    });
    expect(subject).not.toHaveProperty('createChangeOrder');
    expect(subject).not.toHaveProperty('updateChangeOrder');
    expect(subject).not.toHaveProperty('releaseFunds');
  });
});

describe('Procore adapter defensive branches', () => {
  it('classifies network, HTTP, content-type, and malformed-JSON failures', async () => {
    const networkFetch = vi.fn(async () => {
      throw new Error(`socket failed with ${TOKEN}`);
    });
    const network = await adapter(networkFetch).fetchChangeOrderEvidence(request());
    expect(network).toMatchObject({
      kind: 'provider_error',
      operation: 'fetch_change_order',
      reason_code: 'PROVIDER_UNAVAILABLE',
      http_status: null,
    });
    expect(JSON.stringify(network)).not.toContain(TOKEN);

    const http = await adapter(vi.fn(async () => new Response('unavailable', {
      status: 503,
    }))).fetchChangeOrderEvidence(request());
    expect(http).toMatchObject({
      kind: 'provider_error',
      reason_code: 'PROVIDER_HTTP_ERROR',
      http_status: 503,
    });

    const wrongType = await adapter(vi.fn(async () => new Response('{}', {
      status: 200,
      headers: { 'Content-Type': 'text/plain' },
    }))).fetchChangeOrderEvidence(request());
    expect(wrongType).toMatchObject({
      kind: 'provider_error',
      reason_code: 'PROVIDER_RESPONSE_INVALID',
      http_status: 200,
    });

    const malformed = await adapter(vi.fn(async () => new Response('{"id":', {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))).fetchChangeOrderEvidence(request());
    expect(malformed).toMatchObject({
      kind: 'provider_error',
      reason_code: 'PROVIDER_RESPONSE_INVALID',
      http_status: 200,
    });
  });

  it('bounds provider bytes and wall-clock duration', async () => {
    const oversized = await adapter(vi.fn(async () => new Response('x', {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': '65',
      },
    })), { maxMetadataBytes: 64 }).fetchChangeOrderEvidence(request());
    expect(oversized).toMatchObject({
      kind: 'provider_error',
      reason_code: 'PROVIDER_RESPONSE_TOO_LARGE',
    });

    vi.useFakeTimers();
    try {
      const pending = adapter(vi.fn(() => new Promise(() => {})), {
        timeoutMs: 5,
      }).fetchChangeOrderEvidence(request());
      await vi.advanceTimersByTimeAsync(5);
      await expect(pending).resolves.toMatchObject({
        kind: 'provider_error',
        reason_code: 'PROVIDER_TIMEOUT',
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it('refuses invalid dependencies, credentials, limits, and request shapes', async () => {
    const base = {
      apiOrigin: API_ORIGIN,
      accessToken: TOKEN,
      companyId: COMPANY_ID,
      fetch: vi.fn(),
      clock: () => OBSERVED_AT,
    };
    for (const companyId of [null, '', -1, 'bad id']) {
      expect(() => createProcoreChangeOrderAdapter({ ...base, companyId }))
        .toThrow(/companyId/);
    }
    for (const accessToken of [null, '', 'token with spaces', 'bad\u0000token']) {
      expect(() => createProcoreChangeOrderAdapter({ ...base, accessToken }))
        .toThrow(/accessToken/);
    }
    expect(() => createProcoreChangeOrderAdapter({ ...base, fetch: null }))
      .toThrow(/fetch/);
    expect(() => createProcoreChangeOrderAdapter({ ...base, clock: null }))
      .toThrow(/clock/);
    expect(() => createProcoreChangeOrderAdapter({ ...base, timeoutMs: 0 }))
      .toThrow(/timeoutMs/);
    expect(() => createProcoreChangeOrderAdapter({ ...base, maxMetadataBytes: 0 }))
      .toThrow(/maxMetadataBytes/);

    const fetchImpl = vi.fn();
    const subject = adapter(fetchImpl);
    for (const input of [
      null,
      {},
      request({ projectId: 'bad id' }),
      request({ changeOrderId: 'bad id' }),
      request({ changeOrderType: 'subcontract' }),
      request({ expected: null }),
      request({ expected: { status: '' } }),
      request({ expected: { status: 'approved', number: '' } }),
      request({ expected: { status: 'approved', totalAmount: '01.00' } }),
    ]) {
      await expect(subject.fetchChangeOrderEvidence(input)).resolves.toMatchObject({
        kind: 'refused',
        reason_code: 'INVALID_EXPECTATION',
      });
    }
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('accepts numeric identifiers, optional expectations, and nullable line-item fields', async () => {
    const nullableItem = {
      id: 17,
      position: '0',
      amount: 23000,
      description: 'Cabinet package',
      quantity: null,
      unit_cost: null,
      uom: null,
      commitment_line_item_id: null,
      prime_line_item_id: null,
      funding_rule_id: null,
      wbs_code: null,
    };
    const order = {
      id: 9001,
      number: 'CCO-017',
      title: 'Cabinet and countertop revision',
      description: 'Nullable line-item fields remain explicit.',
      status: 'APPROVED',
      amount: 23000,
      contract: { id: 77 },
      updated_at: '2026-07-18T15:59:00.000Z',
    };
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(order))
      .mockResolvedValueOnce(jsonResponse({ data: [nullableItem] }, { total: 1 }))
      .mockResolvedValueOnce(jsonResponse(order))
      .mockResolvedValueOnce(jsonResponse({ data: [nullableItem] }, { total: 1 }));
    const subject = createProcoreChangeOrderAdapter({
      accessToken: TOKEN,
      companyId: 42,
      fetch: fetchImpl,
      clock: () => OBSERVED_AT,
    });

    const result = await subject.fetchChangeOrderEvidence({
      projectId: 2048,
      changeOrderId: 9001,
      changeOrderType: 'commitment',
      expected: { status: 'APPROVED' },
    });

    expect(result.kind).toBe('evidence_ready');
    expect(result.evidence.change_order).toMatchObject({
      id: CHANGE_ORDER_ID,
      total_amount: '23000',
      contract_id: '77',
    });
    expect(result.evidence.line_items[0]).toMatchObject({
      id: '17',
      position: 0,
      amount: '23000',
      description: 'Cabinet package',
      wbs_code: null,
    });
  });

  it('refuses malformed collection envelopes, duplicate items, and shifting totals', async () => {
    const notArray = vi.fn()
      .mockResolvedValueOnce(jsonResponse(changeOrder()))
      .mockResolvedValueOnce(jsonResponse({ data: {} }, { total: 0 }));
    await expect(adapter(notArray).fetchChangeOrderEvidence(request()))
      .resolves.toMatchObject({
        kind: 'provider_error',
        reason_code: 'PROVIDER_RESPONSE_INVALID',
      });

    const duplicate = lineItem('line-1', 1, '23000.00', 'Duplicate');
    const duplicateFetch = vi.fn()
      .mockResolvedValueOnce(jsonResponse(changeOrder()))
      .mockResolvedValueOnce(jsonResponse(
        { data: [duplicate, duplicate] },
        { total: 2 },
      ));
    await expect(adapter(duplicateFetch).fetchChangeOrderEvidence(request()))
      .resolves.toMatchObject({
        kind: 'refused',
        reason_code: 'MALFORMED_LINE_ITEM',
      });

    const next = `<${API_ORIGIN}/next>; rel=next`;
    const shiftingTotal = vi.fn()
      .mockResolvedValueOnce(jsonResponse(changeOrder()))
      .mockResolvedValueOnce(jsonResponse(
        { data: [lineItem('line-1', 1, '18000.00', 'First')] },
        { total: 2, link: next },
      ))
      .mockResolvedValueOnce(jsonResponse(
        { data: [lineItem('line-2', 2, '5000.00', 'Second')] },
        { total: 3 },
      ));
    await expect(adapter(shiftingTotal).fetchChangeOrderEvidence(request()))
      .resolves.toMatchObject({
        kind: 'refused',
        reason_code: 'INCOMPLETE_LINE_ITEM_VIEW',
      });
  });

  it('refuses contradictory pagination, malformed provider fields, and bad clocks', async () => {
    const next = `<${API_ORIGIN}/next>; rel="next"`;
    const contradictory = vi.fn()
      .mockResolvedValueOnce(jsonResponse(changeOrder()))
      .mockResolvedValueOnce(jsonResponse(
        { data: [lineItem('line-1', 1, '23000.00', 'Complete')] },
        { total: 1, link: next },
      ));
    await expect(adapter(contradictory).fetchChangeOrderEvidence(request()))
      .resolves.toMatchObject({
        kind: 'refused',
        reason_code: 'INCOMPLETE_LINE_ITEM_VIEW',
      });

    const invalidTotal = vi.fn()
      .mockResolvedValueOnce(jsonResponse(changeOrder()))
      .mockResolvedValueOnce(jsonResponse(
        { data: [lineItem('line-1', 1, '23000.00', 'Bad total')] },
        { total: '01' },
      ));
    await expect(adapter(invalidTotal).fetchChangeOrderEvidence(request()))
      .resolves.toMatchObject({
        kind: 'refused',
        reason_code: 'INCOMPLETE_LINE_ITEM_VIEW',
      });

    const malformedOrder = vi.fn()
      .mockResolvedValueOnce(jsonResponse(changeOrder({
        updated_at: '2026-02-30T00:00:00Z',
      })));
    await expect(adapter(malformedOrder).fetchChangeOrderEvidence(request()))
      .resolves.toMatchObject({
        kind: 'mismatch',
        reason_code: 'CHANGE_ORDER_ID_OR_SHAPE_MISMATCH',
      });

    for (const clock of [
      () => {
        throw new Error('clock unavailable');
      },
      () => 'not-an-instant',
    ]) {
      const fetchImpl = stableFetch();
      await expect(adapter(fetchImpl, { clock }).fetchChangeOrderEvidence(request()))
        .resolves.toMatchObject({
          kind: 'refused',
          reason_code: 'INVALID_CLOCK',
        });
    }
  });
});
