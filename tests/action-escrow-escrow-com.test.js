// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  createEscrowComAdapter,
  escrowReferenceForEffect,
} from '../lib/integrations/action-escrow/escrow-com.js';

const ACCOUNT_EMAIL = 'buyer@example.com';
const API_KEY = 'sandbox-key-value';
const CREATE_EFFECT = 'order:42:create';
const RELEASE_EFFECT = 'order:42:milestone:design:release';
const MILESTONE_ID = '9001';
const TRANSACTION_ID = '7001';
const DUE_DATE = '2026-08-01T00:00:00Z';

function jsonResponse(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...headers,
    },
  });
}

function rawResponse(value, status = 200, contentType = 'application/json') {
  return new Response(value, {
    status,
    headers: { 'Content-Type': contentType },
  });
}

function notFoundResponse() {
  return new Response('not found', { status: 404, headers: { 'Content-Type': 'text/plain' } });
}

function createRequest(overrides = {}) {
  return {
    effectReference: CREATE_EFFECT,
    currency: 'USD',
    description: 'Design and deliver the release package',
    buyerCustomer: ACCOUNT_EMAIL,
    sellerCustomer: 'seller@example.com',
    milestones: [{
      reference: 'design',
      title: 'Design approval',
      description: 'Approved design files',
      amount: '1250.00',
      dueDate: DUE_DATE,
      inspectionPeriodSeconds: 86_400,
    }],
    ...overrides,
  };
}

function providerTransaction({
  reference = escrowReferenceForEffect(CREATE_EFFECT),
  buyer = ACCOUNT_EMAIL,
  amount = '1250.00',
  accepted = false,
  disbursed = false,
  funded = true,
} = {}) {
  return {
    id: Number(TRANSACTION_ID),
    reference,
    currency: 'usd',
    description: 'Design and deliver the release package',
    creation_date: '2026-07-17T20:00:00Z',
    parties: [
      { role: 'buyer', customer: buyer, agreed: true },
      { role: 'seller', customer: 'seller@example.com', agreed: true },
    ],
    items: [{
      id: Number(MILESTONE_ID),
      reference: 'design',
      title: 'Design approval',
      description: 'Approved design files',
      type: 'milestone',
      inspection_period: 86_400,
      quantity: 1,
      schedule: [{
        amount,
        payer_customer: ACCOUNT_EMAIL,
        beneficiary_customer: 'seller@example.com',
        due_date: DUE_DATE,
        status: {
          secured: funded,
          payment_sent: funded,
          payment_received: funded,
          disbursed_to_beneficiary: disbursed,
        },
      }],
      status: {
        accepted,
        received: true,
        rejected: false,
      },
    }],
  };
}

function effectBindingClaims() {
  const claims = new Map();
  return async ({ effect_reference: effectReference, transaction_id: transactionId,
    milestone_id: milestoneId }) => {
    const scope = `${transactionId}\0${milestoneId}`;
    const existing = claims.get(effectReference);
    if (existing !== undefined) return existing === scope;
    claims.set(effectReference, scope);
    return true;
  };
}

function adapter(fetchImpl, overrides = {}) {
  return createEscrowComAdapter({
    environment: 'sandbox',
    email: ACCOUNT_EMAIL,
    apiKey: API_KEY,
    fetch: fetchImpl,
    claimEffectBinding: effectBindingClaims(),
    customerDiligence: {
      review_status: 'customer_pending',
      evidence_references: ['https://customer.example/escrow-diligence'],
    },
    ...overrides,
  });
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('Escrow.com transaction creation and reconciliation', () => {
  it('uses stable references, the sandbox allowlist, decimal strings, and preflight GET', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(notFoundResponse())
      .mockResolvedValueOnce(jsonResponse(providerTransaction(), 201));
    const subject = adapter(fetchImpl);

    const result = await subject.createTransaction(createRequest());

    expect(result.kind).toBe('created');
    expect(result.effect_reference).toBe(CREATE_EFFECT);
    expect(result.provider_reference).toBe(escrowReferenceForEffect(CREATE_EFFECT));
    expect(result.provider_reference).toHaveLength(24);
    expect(subject.capabilities).toEqual({
      create_transaction: true,
      reconcile_transaction: true,
      milestone_release: 'provider_api',
      direct_disbursement: 'provider_action_required',
    });

    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(fetchImpl.mock.calls[0][0]).toBe(
      `https://api.escrow-sandbox.com/2017-09-01/transaction/reference/`
        + escrowReferenceForEffect(CREATE_EFFECT),
    );
    const [createUrl, createInit] = fetchImpl.mock.calls[1];
    expect(createUrl).toBe('https://api.escrow-sandbox.com/2017-09-01/transaction');
    expect(createInit.method).toBe('POST');
    expect(createInit.redirect).toBe('error');
    expect(createInit.headers.Authorization).toMatch(/^Basic /);
    const payload = JSON.parse(createInit.body);
    expect(payload.reference).toBe(escrowReferenceForEffect(CREATE_EFFECT));
    expect(payload.items[0].schedule[0].amount).toBe('1250.00');
    expect(typeof payload.items[0].schedule[0].amount).toBe('string');
    expect(JSON.stringify(result)).not.toContain(API_KEY);
  });

  it('returns the existing matching transaction without issuing a POST', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(providerTransaction()));
    const result = await adapter(fetchImpl).createTransaction(createRequest());

    expect(result.kind).toBe('existing');
    expect(result.reconciled_after).toBe('preflight');
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(fetchImpl.mock.calls[0][1].method).toBe('GET');
  });

  it('refuses buyer and seller aliases that identify the same provider customer', async () => {
    const fetchImpl = vi.fn();
    const result = await adapter(fetchImpl).createTransaction(createRequest({
      buyerCustomer: 'me',
      sellerCustomer: ACCOUNT_EMAIL,
    }));

    expect(result).toMatchObject({ kind: 'refused', reason_code: 'INVALID_REQUEST' });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('returns a contract-valid provider error when the create preflight is unavailable', async () => {
    const fetchImpl = vi.fn(async () => new Response('unavailable', { status: 503 }));
    const result = await adapter(fetchImpl).createTransaction(createRequest());

    expect(result).toMatchObject({
      kind: 'provider_error',
      operation: 'create_transaction',
      reason_code: 'PROVIDER_HTTP_ERROR',
    });
  });

  it('refuses reuse of the stable provider reference for different terms', async () => {
    const conflict = providerTransaction();
    conflict.description = 'Different transaction';
    const fetchImpl = vi.fn(async () => jsonResponse(conflict));

    const result = await adapter(fetchImpl).createTransaction(createRequest());

    expect(result).toMatchObject({
      kind: 'refused',
      reason_code: 'REFERENCE_CONFLICT',
      provider_reference: escrowReferenceForEffect(CREATE_EFFECT),
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('rejects non-canonical or numeric money before any provider call', async () => {
    const fetchImpl = vi.fn();
    const subject = adapter(fetchImpl);
    const nonCanonical = createRequest();
    nonCanonical.milestones[0].amount = '1250';
    const numeric = createRequest();
    numeric.milestones[0].amount = 1250;

    await expect(subject.createTransaction(nonCanonical))
      .resolves.toMatchObject({ kind: 'refused', reason_code: 'INVALID_MILESTONE' });
    await expect(subject.createTransaction(numeric))
      .resolves.toMatchObject({ kind: 'refused', reason_code: 'INVALID_MILESTONE' });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('rejects numeric money in a provider response', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(providerTransaction({ amount: 1250 })));
    const result = await adapter(fetchImpl).reconcileTransaction({
      transactionId: TRANSACTION_ID,
    });

    expect(result).toMatchObject({
      kind: 'provider_error',
      reason_code: 'PROVIDER_RESPONSE_INVALID',
    });
  });

  it.each([
    ['duplicate keys', '{"id":7001,"id":7002}'],
    ['unpaired Unicode', String.raw`{"id":7001,"value":"\ud800"}`],
    ['excessive depth', `{"id":7001,"value":${'['.repeat(65)}0${']'.repeat(65)}}`],
  ])('rejects security-bearing provider JSON with %s', async (_label, raw) => {
    const fetchImpl = vi.fn(async () => rawResponse(raw));
    const result = await adapter(fetchImpl).reconcileTransaction({
      transactionId: TRANSACTION_ID,
    });

    expect(result).toMatchObject({
      kind: 'provider_error',
      reason_code: 'PROVIDER_RESPONSE_INVALID',
    });
  });

  it('refuses to parse a successful body without an allowed JSON content type', async () => {
    const fetchImpl = vi.fn(async () => rawResponse(
      JSON.stringify(providerTransaction()),
      200,
      'text/plain',
    ));
    const result = await adapter(fetchImpl).reconcileTransaction({
      transactionId: TRANSACTION_ID,
    });

    expect(result).toMatchObject({
      kind: 'provider_error',
      reason_code: 'PROVIDER_RESPONSE_INVALID',
    });
  });

  it('bounds provider response bytes before parsing', async () => {
    const fetchImpl = vi.fn(async () => new Response('x', {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': '65',
      },
    }));
    const result = await adapter(fetchImpl, { maxResponseBytes: 64 })
      .reconcileTransaction({ transactionId: TRANSACTION_ID });

    expect(result).toMatchObject({
      kind: 'provider_error',
      reason_code: 'PROVIDER_RESPONSE_TOO_LARGE',
    });
  });

  it('enforces a wall-clock timeout even if injected fetch never settles', async () => {
    vi.useFakeTimers();
    const fetchImpl = vi.fn(() => new Promise(() => {}));
    const pending = adapter(fetchImpl, { timeoutMs: 5 })
      .reconcileTransaction({ transactionId: TRANSACTION_ID });

    await vi.advanceTimersByTimeAsync(5);
    await expect(pending).resolves.toMatchObject({
      kind: 'provider_error',
      reason_code: 'PROVIDER_TIMEOUT',
    });
  });

  it('uses only the production Escrow.com host in production mode', async () => {
    const fetchImpl = vi.fn(async () => notFoundResponse());
    const subject = createEscrowComAdapter({
      environment: 'production',
      email: ACCOUNT_EMAIL,
      apiKey: API_KEY,
      fetch: fetchImpl,
      claimEffectBinding: effectBindingClaims(),
      customerDiligence: { review_status: 'customer_complete' },
    });

    await subject.reconcileTransaction({ transactionId: TRANSACTION_ID });

    expect(fetchImpl.mock.calls[0][0]).toBe(
      `https://api.escrow.com/2017-09-01/transaction/${TRANSACTION_ID}`,
    );
  });
});

describe('Escrow.com milestone release and disbursement limitation', () => {
  it('refuses milestone acceptance until every schedule is secured and funded', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(providerTransaction({ funded: false })));
    const result = await adapter(fetchImpl).releaseMilestone({
      effectReference: RELEASE_EFFECT,
      transactionId: TRANSACTION_ID,
      milestoneId: MILESTONE_ID,
    });

    expect(result).toMatchObject({
      kind: 'provider_action_required',
      reason_code: 'FUNDING_REQUIRED',
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(fetchImpl.mock.calls[0][1].method).toBe('GET');
  });

  it('fails closed when durable effect-reference claiming is unavailable', async () => {
    const fetchImpl = vi.fn();
    const result = await adapter(fetchImpl, {
      claimEffectBinding: async () => {
        throw new Error('store unavailable');
      },
    }).releaseMilestone({
      effectReference: RELEASE_EFFECT,
      transactionId: TRANSACTION_ID,
      milestoneId: MILESTONE_ID,
    });

    expect(result).toMatchObject({
      kind: 'provider_error',
      reason_code: 'EFFECT_BINDING_STORE_UNAVAILABLE',
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('refuses reuse of one effect reference for another provider milestone scope', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(providerTransaction({ accepted: true })));
    const subject = adapter(fetchImpl);
    const first = await subject.releaseMilestone({
      effectReference: RELEASE_EFFECT,
      transactionId: TRANSACTION_ID,
      milestoneId: MILESTONE_ID,
    });
    const second = await subject.releaseMilestone({
      effectReference: RELEASE_EFFECT,
      transactionId: '7002',
      milestoneId: MILESTONE_ID,
    });

    expect(first.kind).toBe('release_submitted');
    expect(second).toMatchObject({
      kind: 'refused',
      reason_code: 'EFFECT_REFERENCE_CONFLICT',
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('reconciles with GET, performs only documented milestone acceptance, then GETs again', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(providerTransaction()))
      .mockResolvedValueOnce(jsonResponse(providerTransaction({ accepted: true })))
      .mockResolvedValueOnce(jsonResponse(providerTransaction({ accepted: true })));
    const result = await adapter(fetchImpl).releaseMilestone({
      effectReference: RELEASE_EFFECT,
      transactionId: TRANSACTION_ID,
      milestoneId: MILESTONE_ID,
    });

    expect(result).toMatchObject({
      kind: 'release_submitted',
      effect_reference: RELEASE_EFFECT,
      provider_effect: 'milestone_acceptance',
      provider_phase: 'accepted_pending_disbursement',
    });
    expect(fetchImpl.mock.calls.map(([, init]) => init.method)).toEqual(['GET', 'PATCH', 'GET']);
    const patchBody = JSON.parse(fetchImpl.mock.calls[1][1].body);
    expect(patchBody).toEqual({ action: 'accept' });
    expect(fetchImpl.mock.calls[1][0]).toBe(
      `https://api.escrow-sandbox.com/2017-09-01/transaction/${TRANSACTION_ID}`
        + `/item/${MILESTONE_ID}`,
    );
    expect(fetchImpl.mock.calls[1][1].body).not.toContain(RELEASE_EFFECT);
  });

  it('never repeats acceptance when the authenticated GET already shows it applied', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(providerTransaction({ accepted: true })));
    const result = await adapter(fetchImpl).releaseMilestone({
      effectReference: RELEASE_EFFECT,
      transactionId: TRANSACTION_ID,
      milestoneId: MILESTONE_ID,
    });

    expect(result.kind).toBe('release_submitted');
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(fetchImpl.mock.calls[0][1].method).toBe('GET');
  });

  it('reconciles an ambiguous PATCH outcome and does not retry the mutation', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(providerTransaction()))
      .mockRejectedValueOnce(new Error(`transport failure ${API_KEY}`))
      .mockResolvedValueOnce(jsonResponse(providerTransaction({ accepted: true })));
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const result = await adapter(fetchImpl).releaseMilestone({
      effectReference: RELEASE_EFFECT,
      transactionId: TRANSACTION_ID,
      milestoneId: MILESTONE_ID,
    });

    expect(result.kind).toBe('release_submitted');
    expect(fetchImpl.mock.calls.map(([, init]) => init.method)).toEqual(['GET', 'PATCH', 'GET']);
    expect(errorSpy).not.toHaveBeenCalled();
    expect(JSON.stringify(result)).not.toContain(API_KEY);
  });

  it('returns indeterminate after one PATCH when reconciliation still shows no effect', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(providerTransaction()))
      .mockResolvedValueOnce(new Response('unavailable', { status: 503 }))
      .mockResolvedValueOnce(jsonResponse(providerTransaction()));
    const result = await adapter(fetchImpl).releaseMilestone({
      effectReference: RELEASE_EFFECT,
      transactionId: TRANSACTION_ID,
      milestoneId: MILESTONE_ID,
    });

    expect(result).toMatchObject({
      kind: 'indeterminate',
      reason_code: 'RELEASE_OUTCOME_INDETERMINATE',
      effect_reference: RELEASE_EFFECT,
    });
    expect(fetchImpl.mock.calls.filter(([, init]) => init.method === 'PATCH')).toHaveLength(1);
  });

  it('requires the authenticated account to be the buyer for milestone acceptance', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(providerTransaction({
      buyer: 'other-buyer@example.com',
    })));
    const result = await adapter(fetchImpl).releaseMilestone({
      effectReference: RELEASE_EFFECT,
      transactionId: TRANSACTION_ID,
      milestoneId: MILESTONE_ID,
    });

    expect(result).toMatchObject({
      kind: 'provider_action_required',
      reason_code: 'BUYER_ACTION_REQUIRED',
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('does not invent a direct disbursement endpoint', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(providerTransaction({ accepted: true })));
    const result = await adapter(fetchImpl).requestMilestoneDisbursement({
      effectReference: RELEASE_EFFECT,
      transactionId: TRANSACTION_ID,
      milestoneId: MILESTONE_ID,
    });

    expect(result).toMatchObject({
      kind: 'provider_action_required',
      reason_code: 'NO_DOCUMENTED_DIRECT_DISBURSEMENT',
      provider_phase: 'accepted_pending_disbursement',
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(fetchImpl.mock.calls[0][1].method).toBe('GET');
  });

  it('reports provider-confirmed disbursement without making a mutation', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(providerTransaction({
      accepted: true,
      disbursed: true,
    })));
    const result = await adapter(fetchImpl).requestMilestoneDisbursement({
      effectReference: RELEASE_EFFECT,
      transactionId: TRANSACTION_ID,
      milestoneId: MILESTONE_ID,
    });

    expect(result).toMatchObject({
      kind: 'released',
      provider_phase: 'disbursed',
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});
