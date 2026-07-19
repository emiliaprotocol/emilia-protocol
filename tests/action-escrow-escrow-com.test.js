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

  it.each([
    ['missing request', () => null, 'INVALID_EFFECT_REFERENCE'],
    ['invalid effect reference', (input) => {
      input.effectReference = 'contains spaces';
      return input;
    }, 'INVALID_EFFECT_REFERENCE'],
    ['unsupported currency', (input) => {
      input.currency = 'GBP';
      return input;
    }, 'UNSUPPORTED_CURRENCY'],
    ['empty description', (input) => {
      input.description = '';
      return input;
    }, 'INVALID_REQUEST'],
    ['invalid buyer', (input) => {
      input.buyerCustomer = 'not-an-email';
      return input;
    }, 'INVALID_REQUEST'],
    ['invalid seller', (input) => {
      input.sellerCustomer = 'not-an-email';
      return input;
    }, 'INVALID_REQUEST'],
    ['missing milestone array', (input) => {
      input.milestones = null;
      return input;
    }, 'INVALID_REQUEST'],
    ['empty milestone array', (input) => {
      input.milestones = [];
      return input;
    }, 'INVALID_REQUEST'],
    ['too many milestones', (input) => {
      input.milestones = Array.from(
        { length: 51 },
        (_, index) => ({
          ...input.milestones[0],
          reference: `milestone-${index}`,
        }),
      );
      return input;
    }, 'INVALID_REQUEST'],
  ])('refuses create requests with %s', async (_label, mutate, reasonCode) => {
    const fetchImpl = vi.fn();
    const input = mutate(createRequest());
    await expect(adapter(fetchImpl).createTransaction(input))
      .resolves.toMatchObject({ kind: 'refused', reason_code: reasonCode });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it.each([
    ['non-object milestone', (input) => {
      input.milestones[0] = null;
    }],
    ['invalid milestone reference', (input) => {
      input.milestones[0].reference = 'contains spaces';
    }],
    ['duplicate milestone reference', (input) => {
      input.milestones.push({ ...input.milestones[0] });
    }],
    ['empty milestone title', (input) => {
      input.milestones[0].title = '';
    }],
    ['empty milestone description', (input) => {
      input.milestones[0].description = '';
    }],
    ['invalid due date', (input) => {
      input.milestones[0].dueDate = '2026-13-01T00:00:00Z';
    }],
    ['non-integer inspection period', (input) => {
      input.milestones[0].inspectionPeriodSeconds = 1.5;
    }],
    ['zero inspection period', (input) => {
      input.milestones[0].inspectionPeriodSeconds = 0;
    }],
    ['excessive inspection period', (input) => {
      input.milestones[0].inspectionPeriodSeconds = 31_536_001;
    }],
  ])('refuses a milestone with %s', async (_label, mutate) => {
    const fetchImpl = vi.fn();
    const input = createRequest();
    mutate(input);
    await expect(adapter(fetchImpl).createTransaction(input))
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

  it.each([
    ['non-object transaction', null],
    ['invalid transaction id', (() => {
      const value = providerTransaction();
      value.id = 0;
      return value;
    })()],
    ['unsupported provider currency', (() => {
      const value = providerTransaction();
      value.currency = 'bitcoin';
      return value;
    })()],
    ['missing parties', (() => {
      const value = providerTransaction();
      value.parties = null;
      return value;
    })()],
    ['missing items', (() => {
      const value = providerTransaction();
      value.items = null;
      return value;
    })()],
    ['non-object party', (() => {
      const value = providerTransaction();
      value.parties[0] = null;
      return value;
    })()],
    ['unknown party role', (() => {
      const value = providerTransaction();
      value.parties[0].role = 'attacker';
      return value;
    })()],
    ['invalid party customer', (() => {
      const value = providerTransaction();
      value.parties[0].customer = 'not-an-email';
      return value;
    })()],
    ['missing buyer', (() => {
      const value = providerTransaction();
      value.parties = value.parties.filter((party) => party.role !== 'buyer');
      return value;
    })()],
    ['missing seller', (() => {
      const value = providerTransaction();
      value.parties = value.parties.filter((party) => party.role !== 'seller');
      return value;
    })()],
    ['no milestone items', (() => {
      const value = providerTransaction();
      value.items[0].type = 'domain_name';
      return value;
    })()],
    ['invalid milestone id', (() => {
      const value = providerTransaction();
      value.items[0].id = 0;
      return value;
    })()],
    ['missing milestone schedule', (() => {
      const value = providerTransaction();
      value.items[0].schedule = null;
      return value;
    })()],
    ['empty milestone schedule', (() => {
      const value = providerTransaction();
      value.items[0].schedule = [];
      return value;
    })()],
    ['non-object schedule', (() => {
      const value = providerTransaction();
      value.items[0].schedule[0] = null;
      return value;
    })()],
    ['invalid schedule payer', (() => {
      const value = providerTransaction();
      value.items[0].schedule[0].payer_customer = 'not-an-email';
      return value;
    })()],
    ['invalid schedule beneficiary', (() => {
      const value = providerTransaction();
      value.items[0].schedule[0].beneficiary_customer = 'not-an-email';
      return value;
    })()],
  ])('fails closed on provider state with %s', async (_label, providerState) => {
    const fetchImpl = vi.fn(async () => jsonResponse(providerState));
    await expect(adapter(fetchImpl).reconcileTransaction({
      transactionId: TRANSACTION_ID,
    })).resolves.toMatchObject({
      kind: 'provider_error',
      reason_code: 'PROVIDER_RESPONSE_INVALID',
    });
  });

  it('normalizes optional provider fields without trusting their types', async () => {
    const value = providerTransaction();
    value.reference = 7;
    value.description = null;
    value.creation_date = 17;
    value.close_date = {};
    value.is_cancelled = 'true';
    value.parties[0].agreed = 'true';
    value.items[0].reference = 7;
    value.items[0].title = null;
    value.items[0].description = null;
    value.items[0].inspection_period = '86400';
    value.items[0].status = null;
    value.items[0].schedule[0].due_date = 7;
    value.items[0].schedule[0].status = null;
    const result = await adapter(vi.fn(async () => jsonResponse(value)))
      .reconcileTransaction({ transactionId: TRANSACTION_ID });

    expect(result).toMatchObject({
      kind: 'reconciled',
      transaction: {
        provider_reference: null,
        description: '',
        provider_created_at: null,
        provider_closed_at: null,
        provider_cancelled: false,
        milestones: [{
          reference: null,
          title: '',
          description: '',
          inspection_period_seconds: null,
          schedules: [{ due_date: null }],
        }],
      },
    });
  });

  it.each([
    ['no selector', {}],
    ['multiple selectors', { transactionId: TRANSACTION_ID, effectReference: CREATE_EFFECT }],
    ['invalid transaction id', { transactionId: 0 }],
    ['invalid provider reference', { providerReference: 'contains spaces' }],
    ['invalid effect reference', { effectReference: 'contains spaces' }],
  ])('refuses a reconcile locator with %s', async (_label, locator) => {
    const fetchImpl = vi.fn();
    await expect(adapter(fetchImpl).reconcileTransaction(locator))
      .resolves.toMatchObject({ kind: 'refused', reason_code: 'INVALID_LOCATOR' });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('supports provider-reference and effect-reference reconciliation locators', async () => {
    const fetchImpl = vi.fn(async () => notFoundResponse());
    const subject = adapter(fetchImpl);
    await expect(subject.reconcileTransaction({
      providerReference: escrowReferenceForEffect(CREATE_EFFECT),
    })).resolves.toMatchObject({ kind: 'not_found' });
    await expect(subject.reconcileTransaction({
      effectReference: CREATE_EFFECT,
    })).resolves.toMatchObject({ kind: 'not_found' });
    expect(fetchImpl.mock.calls[0][0]).toContain('/transaction/reference/');
    expect(fetchImpl.mock.calls[1][0]).toContain(
      `/transaction/reference/${escrowReferenceForEffect(CREATE_EFFECT)}`,
    );
  });

  it('classifies a thrown provider fetch without exposing the thrown detail', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error(`socket failed with ${API_KEY}`);
    });
    const result = await adapter(fetchImpl)
      .reconcileTransaction({ transactionId: TRANSACTION_ID });
    expect(result).toMatchObject({
      kind: 'provider_error',
      reason_code: 'PROVIDER_UNAVAILABLE',
      http_status: null,
    });
    expect(JSON.stringify(result)).not.toContain(API_KEY);
  });

  it('returns a deterministic 4xx create failure only after a not-found reconciliation', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(notFoundResponse())
      .mockResolvedValueOnce(new Response('invalid', { status: 422 }))
      .mockResolvedValueOnce(notFoundResponse());
    const result = await adapter(fetchImpl).createTransaction(createRequest());

    expect(result).toMatchObject({
      kind: 'provider_error',
      operation: 'create_transaction',
      reason_code: 'PROVIDER_HTTP_ERROR',
      http_status: 422,
    });
    expect(fetchImpl.mock.calls.map(([, init]) => init.method)).toEqual(['GET', 'POST', 'GET']);
  });

  it('returns indeterminate when a thrown create fetch cannot be reconciled', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(notFoundResponse())
      .mockRejectedValueOnce(new Error('connection reset'))
      .mockResolvedValueOnce(notFoundResponse());
    const result = await adapter(fetchImpl).createTransaction(createRequest());

    expect(result).toMatchObject({
      kind: 'indeterminate',
      reason_code: 'CREATE_OUTCOME_INDETERMINATE',
      http_status: null,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it('reconciles a malformed create response to authenticated provider state', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(notFoundResponse())
      .mockResolvedValueOnce(rawResponse('{"id":', 201))
      .mockResolvedValueOnce(jsonResponse(providerTransaction()));
    const result = await adapter(fetchImpl).createTransaction(createRequest());

    expect(result).toMatchObject({
      kind: 'existing',
      reconciled_after: 'create_attempt',
    });
  });

  it('rejects provider substitution in the immediate create response', async () => {
    const substituted = providerTransaction({ buyer: 'attacker@example.com' });
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(notFoundResponse())
      .mockResolvedValueOnce(jsonResponse(substituted, 201));
    const result = await adapter(fetchImpl).createTransaction(createRequest());

    expect(result).toMatchObject({
      kind: 'refused',
      reason_code: 'REFERENCE_CONFLICT',
    });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
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

  it('rejects invalid adapter dependencies and limits', () => {
    const base = {
      environment: 'sandbox',
      email: ACCOUNT_EMAIL,
      apiKey: API_KEY,
      fetch: vi.fn(),
      claimEffectBinding: effectBindingClaims(),
      customerDiligence: { review_status: 'customer_pending' },
    };
    expect(() => createEscrowComAdapter({ ...base, environment: 'staging' }))
      .toThrow(/environment/);
    for (const email of [null, 'me', 'not-an-email']) {
      expect(() => createEscrowComAdapter({ ...base, email })).toThrow(/credentials/);
    }
    for (const apiKey of [null, '', 'bad\u0000key']) {
      expect(() => createEscrowComAdapter({ ...base, apiKey })).toThrow(/credentials/);
    }
    expect(() => createEscrowComAdapter({ ...base, fetch: null })).toThrow(/fetch/);
    expect(() => createEscrowComAdapter({ ...base, claimEffectBinding: null }))
      .toThrow(/claimEffectBinding/);
    expect(() => createEscrowComAdapter({ ...base, timeoutMs: 0 })).toThrow(/timeoutMs/);
    expect(() => createEscrowComAdapter({ ...base, maxResponseBytes: 0 }))
      .toThrow(/maxResponseBytes/);
    expect(() => escrowReferenceForEffect('contains spaces')).toThrow(/effectReference/);
  });
});

describe('Escrow.com milestone release and disbursement limitation', () => {
  it.each([
    ['missing request', null],
    ['invalid effect reference', {
      effectReference: 'contains spaces',
      transactionId: TRANSACTION_ID,
      milestoneId: MILESTONE_ID,
    }],
    ['invalid transaction id', {
      effectReference: RELEASE_EFFECT,
      transactionId: 0,
      milestoneId: MILESTONE_ID,
    }],
    ['invalid milestone id', {
      effectReference: RELEASE_EFFECT,
      transactionId: TRANSACTION_ID,
      milestoneId: '0',
    }],
  ])('refuses a release request with %s', async (_label, input) => {
    const fetchImpl = vi.fn();
    await expect(adapter(fetchImpl).releaseMilestone(input))
      .resolves.toMatchObject({ kind: 'refused', reason_code: 'INVALID_REQUEST' });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it.each([
    ['missing transaction', () => notFoundResponse(), 'TRANSACTION_NOT_FOUND'],
    ['missing milestone', () => {
      const value = providerTransaction();
      value.items[0].id = 9002;
      return jsonResponse(value);
    }, 'MILESTONE_NOT_FOUND'],
  ])('requires provider action for a %s', async (_label, response, reasonCode) => {
    const fetchImpl = vi.fn(async () => response());
    await expect(adapter(fetchImpl).releaseMilestone({
      effectReference: RELEASE_EFFECT,
      transactionId: TRANSACTION_ID,
      milestoneId: MILESTONE_ID,
    })).resolves.toMatchObject({
      kind: 'provider_action_required',
      reason_code: reasonCode,
    });
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it('fails closed when release reconciliation returns malformed provider state', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ id: TRANSACTION_ID }));
    await expect(adapter(fetchImpl).releaseMilestone({
      effectReference: RELEASE_EFFECT,
      transactionId: TRANSACTION_ID,
      milestoneId: MILESTONE_ID,
    })).resolves.toMatchObject({
      kind: 'provider_error',
      operation: 'release_milestone',
      reason_code: 'PROVIDER_RESPONSE_INVALID',
    });
  });

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

  it('surfaces a deterministic provider refusal after unchanged-state reconciliation', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(providerTransaction()))
      .mockResolvedValueOnce(new Response('forbidden', { status: 403 }))
      .mockResolvedValueOnce(jsonResponse(providerTransaction()));
    const result = await adapter(fetchImpl).releaseMilestone({
      effectReference: RELEASE_EFFECT,
      transactionId: TRANSACTION_ID,
      milestoneId: MILESTONE_ID,
    });

    expect(result).toMatchObject({
      kind: 'provider_action_required',
      reason_code: 'PROVIDER_REFUSED_RELEASE',
      http_status: 403,
    });
    expect(fetchImpl.mock.calls.map(([, init]) => init.method)).toEqual(['GET', 'PATCH', 'GET']);
  });

  it('returns indeterminate when the post-PATCH provider snapshot is unavailable', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(providerTransaction()))
      .mockResolvedValueOnce(new Response('unavailable', { status: 503 }))
      .mockRejectedValueOnce(new Error('reconciliation transport failed'));
    const result = await adapter(fetchImpl).releaseMilestone({
      effectReference: RELEASE_EFFECT,
      transactionId: TRANSACTION_ID,
      milestoneId: MILESTONE_ID,
    });

    expect(result).toMatchObject({
      kind: 'indeterminate',
      reason_code: 'RELEASE_OUTCOME_INDETERMINATE',
      http_status: 503,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(3);
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

  it('refuses an invalid disbursement request without contacting the provider', async () => {
    const fetchImpl = vi.fn();
    await expect(adapter(fetchImpl).requestMilestoneDisbursement({
      effectReference: RELEASE_EFFECT,
      transactionId: TRANSACTION_ID,
      milestoneId: 0,
    })).resolves.toMatchObject({
      kind: 'refused',
      reason_code: 'INVALID_REQUEST',
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
