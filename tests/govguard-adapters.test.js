// SPDX-License-Identifier: Apache-2.0
// GovGuard adapter surface — each marketed government workflow has a live
// precheck endpoint wired to the shared policy engine.

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockGetGuardedClient = vi.fn();
const mockAuthenticateRequest = vi.fn();

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args) => mockGetGuardedClient(...args),
}));
vi.mock('@/lib/supabase', () => ({
  authenticateRequest: (...args) => mockAuthenticateRequest(...args),
  authEntityId: (auth) => (typeof auth?.entity === 'string' ? auth.entity : auth?.entity?.entity_id || ''),
  getServiceClient: vi.fn(),
}));
vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));
vi.mock('../lib/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import { POST as benefitBankChange } from '../app/api/v1/adapters/gov/benefit-bank-change/precheck/route.js';
import { POST as benefitAddressChange } from '../app/api/v1/adapters/gov/benefit-address-change/precheck/route.js';
import { POST as caseworkerOverride } from '../app/api/v1/adapters/gov/caseworker-override/precheck/route.js';
import { POST as vendorPaymentDestinationChange } from '../app/api/v1/adapters/gov/vendor-payment-destination-change/precheck/route.js';
import { POST as disbursementRelease } from '../app/api/v1/adapters/gov/disbursement-release/precheck/route.js';
import { POST as grantDisbursement } from '../app/api/v1/adapters/gov/grant-disbursement/precheck/route.js';
import { POST as providerEnrollmentChange } from '../app/api/v1/adapters/gov/provider-enrollment-change/precheck/route.js';
import { POST as eligibilityOverride } from '../app/api/v1/adapters/gov/eligibility-override/precheck/route.js';

const inserted = [];

function makeChain({ table, auditError = null }) {
  return {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    gte: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    insert: vi.fn(async (row) => {
      if (table === 'audit_events' && auditError) return { data: null, error: auditError };
      inserted.push({ table, row });
      return { data: null, error: null };
    }),
    then: (resolve) => Promise.resolve({ data: [], error: null }).then(resolve),
  };
}

function makeSupabase({ auditError = null } = {}) {
  return {
    from: vi.fn((table) => makeChain({ table, auditError })),
  };
}

function req(body) {
  return new Request('https://www.emiliaprotocol.ai/api/v1/adapters/gov/test/precheck', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer ep_live_test' },
    body: JSON.stringify(body),
  });
}

const BASE = Object.freeze({
  organization_id: 'org_gov',
  enforcement_mode: 'enforce',
  before_state: { status: 'before' },
  after_state: { status: 'after' },
});

beforeEach(() => {
  inserted.length = 0;
  mockGetGuardedClient.mockReset();
  mockGetGuardedClient.mockReturnValue(makeSupabase());
  mockAuthenticateRequest.mockReset();
  mockAuthenticateRequest.mockResolvedValue({ entity: { entity_id: 'caseworker_1', organization_id: 'org_gov' } });
});

describe('GovGuard adapters', () => {
  const cases = [
    ['benefit bank account change', benefitBankChange, { recipient_id: 'rec_1', target_changed_fields: ['bank_account'] }, 'benefit_bank_account_change'],
    ['benefit address change', benefitAddressChange, { recipient_id: 'rec_2', target_changed_fields: ['mailing_address'] }, 'benefit_address_change'],
    ['caseworker override', caseworkerOverride, { case_id: 'case_1' }, 'caseworker_override'],
    ['vendor payment destination change', vendorPaymentDestinationChange, { vendor_id: 'vendor_1', target_changed_fields: ['bank_account'] }, 'gov.vendor_payment_destination_change'],
    ['disbursement release', disbursementRelease, { payment_instruction_id: 'pay_1', amount: 10_000, currency: 'USD' }, 'gov.disbursement_release'],
    ['grant disbursement', grantDisbursement, { grant_id: 'grant_1', amount: 10_000, currency: 'USD' }, 'gov.grant_disbursement'],
    ['provider enrollment change', providerEnrollmentChange, { provider_id: 'npi_1', npi: '1234567890' }, 'gov.provider_enrollment_change'],
    ['eligibility override', eligibilityOverride, { case_id: 'case_2', eligibility_status: 'approved' }, 'gov.eligibility_override'],
  ];

  for (const [label, route, body, actionType] of cases) {
    it(`${label} issues a Class-A pending-signoff receipt`, async () => {
      const res = await route(req({ ...BASE, ...body }));
      expect(res.status).toBe(201);
      const json = await res.json();
      expect(json.signoff_required).toBe(true);
      expect(json.required_assurance).toBe('A');
      expect(json.receipt_status).toBe('pending_signoff');
      expect(json.canonical_action.action_type).toBe(actionType);
      expect(json.evidence_status).toBe('durable');
      expect(inserted.some((i) => i.table === 'audit_events')).toBe(true);
    });
  }

  it('fails closed in enforce mode when evidence cannot be recorded', async () => {
    mockGetGuardedClient.mockReturnValue(makeSupabase({ auditError: { message: 'insert failed' } }));
    const res = await disbursementRelease(req({
      ...BASE,
      payment_instruction_id: 'pay_2',
      amount: 10_000,
      currency: 'USD',
    }));
    expect(res.status).toBe(503);
    const body = await res.json();
    expect(`${body.code ?? ''} ${body.type ?? ''}`).toContain('evidence_write_failed');
  });

  it('marks observe-mode evidence degraded instead of blocking when evidence cannot be recorded', async () => {
    mockGetGuardedClient.mockReturnValue(makeSupabase({ auditError: { message: 'insert failed' } }));
    const res = await disbursementRelease(req({
      ...BASE,
      enforcement_mode: 'observe',
      payment_instruction_id: 'pay_3',
      amount: 10_000,
      currency: 'USD',
    }));
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.decision).toBe('observe');
    expect(body.evidence_status).toBe('degraded');
  });

  it('binds hashed destination and government program fields into the receipt', async () => {
    const res = await vendorPaymentDestinationChange(req({
      ...BASE,
      enforcement_mode: undefined,
      mode: 'observe',
      vendor_id: 'vendor_9',
      agency_id: 'agency_hhs',
      program_id: 'medicaid',
      target_changed_fields: ['bank_account_hash', 'routing_number_hash'],
      destination_hash: 'sha256:destination',
      bank_account_hash: 'sha256:bank',
      routing_number_hash: 'sha256:routing',
    }));
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.decision).toBe('observe');
    expect(body.observed_decision).toBe('allow_with_signoff');
    expect(body.canonical_action).toMatchObject({
      vendor_id: 'vendor_9',
      agency_id: 'agency_hhs',
      program_id: 'medicaid',
      destination_hash: 'sha256:destination',
      bank_account_hash: 'sha256:bank',
      routing_number_hash: 'sha256:routing',
    });
    expect(body.execution_binding.required_fields).toEqual(expect.arrayContaining([
      'vendor_id',
      'agency_id',
      'program_id',
      'destination_hash',
      'bank_account_hash',
      'routing_number_hash',
    ]));
  });

  it('binds provider and eligibility fields that a system of record could mutate', async () => {
    const provider = await providerEnrollmentChange(req({
      ...BASE,
      provider_id: 'provider_1',
      npi: '1234567890',
      provider_tax_id_hash: 'sha256:tax',
      provider_status: 'active',
      payment_address: 'hash:address',
      program_id: 'medicaid',
    }));
    expect(provider.status).toBe(201);
    const providerBody = await provider.json();
    expect(providerBody.canonical_action).toMatchObject({
      provider_id: 'provider_1',
      npi: '1234567890',
      provider_tax_id_hash: 'sha256:tax',
      provider_status: 'active',
      payment_address: 'hash:address',
      program_id: 'medicaid',
    });
    expect(providerBody.execution_binding.required_fields).toEqual(expect.arrayContaining([
      'provider_id',
      'npi',
      'provider_tax_id_hash',
      'provider_status',
      'payment_address',
      'program_id',
    ]));

    const eligibility = await eligibilityOverride(req({
      ...BASE,
      case_id: 'case_1',
      claimant_id: 'claimant_1',
      eligibility_case_id: 'elig_1',
      eligibility_status: 'approved',
      benefit_amount: 1250,
      program_id: 'snap',
    }));
    expect(eligibility.status).toBe(201);
    const eligibilityBody = await eligibility.json();
    expect(eligibilityBody.canonical_action).toMatchObject({
      claimant_id: 'claimant_1',
      eligibility_case_id: 'elig_1',
      eligibility_status: 'approved',
      benefit_amount: 1250,
      program_id: 'snap',
    });
    expect(eligibilityBody.execution_binding.required_fields).toEqual(expect.arrayContaining([
      'claimant_id',
      'eligibility_case_id',
      'eligibility_status',
      'benefit_amount',
      'program_id',
    ]));
  });

  it('rejects amount type confusion that could weaken dual approval classification', async () => {
    const res = await grantDisbursement(req({
      ...BASE,
      grant_id: 'grant_2',
      amount: '1000000',
      currency: 'USD',
    }));
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(`${body.code ?? ''} ${body.type ?? ''}`).toContain('invalid_amount');
  });
});
