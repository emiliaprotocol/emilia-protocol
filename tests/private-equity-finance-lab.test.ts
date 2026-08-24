// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { FINANCE_LAB_PATH, FINANCE_LAB_SCENARIOS } from '../app/private-equity/finance-lab-fixture';

const mockGetGuardedClient = vi.fn();
const mockAuthenticateRequest = vi.fn();
const inserted: Array<{ table: string; row: Record<string, unknown> }> = [];

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args: unknown[]) => mockGetGuardedClient(...args),
}));

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: (...args: unknown[]) => mockAuthenticateRequest(...args),
  authEntityId: (auth: any) => (
    typeof auth?.entity === 'string' ? auth.entity : auth?.entity?.entity_id || ''
  ),
  getServiceClient: vi.fn(),
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import { POST as paymentRelease } from '../app/api/v1/adapters/fin/payment-release/precheck/route';

class Query {
  private readonly table: string;

  constructor(table: string) {
    this.table = table;
  }

  select(): this { return this; }
  eq(): this { return this; }
  gte(): this { return this; }
  order(): this { return this; }
  limit(): this { return this; }

  async insert(row: Record<string, unknown>): Promise<{ error: null }> {
    inserted.push({ table: this.table, row });
    return { error: null };
  }

  then(resolve: (value: { data: never[]; error: null }) => unknown): unknown {
    return Promise.resolve({ data: [], error: null }).then(resolve);
  }
}

function request(path: string, body: Record<string, unknown>): Request {
  return new Request(`https://www.emiliaprotocol.ai${path}`, {
    method: 'POST',
    headers: { authorization: 'Bearer ep_live_portfolio_lab', 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

beforeEach(() => {
  inserted.length = 0;
  mockGetGuardedClient.mockReset();
  mockGetGuardedClient.mockReturnValue({ from: (table: string) => new Query(table) });
  mockAuthenticateRequest.mockReset();
  mockAuthenticateRequest.mockResolvedValue({
    entity: { entity_id: 'ep_entity_portfolio_lab', organization_id: 'ep_entity_portfolio_lab' },
  });
});

describe('Portfolio Action Risk Lab finance payloads', () => {
  it('keeps every public scenario on one payment-release boundary', () => {
    expect(new Set(FINANCE_LAB_SCENARIOS.map((scenario) => scenario.path))).toEqual(new Set([FINANCE_LAB_PATH]));
    expect(FINANCE_LAB_PATH).toBe('/api/v1/adapters/fin/payment-release/precheck');
  });

  for (const scenario of FINANCE_LAB_SCENARIOS) {
    it(`${scenario.id} runs through the real observe-mode payment adapter`, async () => {
      const response = await paymentRelease(request(
        scenario.path,
        scenario.body('ep_entity_portfolio_lab'),
      ) as never);
      const body = await response.json();

      expect(response.status).toBe(201);
      expect(body.decision).toBe('observe');
      expect(body.evidence_status).toBe('durable');
      expect(body.canonical_action.organization_id).toBe('ep_entity_portfolio_lab');
      expect(body.canonical_action).toMatchObject({
        action_type: 'large_payment_release',
        counterparty_name: 'Northstar Demo Vendor',
        currency: 'USD',
      });
      expect(inserted.some((entry) => entry.table === 'audit_events')).toBe(true);
      expect(inserted.some((entry) => entry.table === 'aml_history')).toBe(true);

      if (scenario.id === 'hard_refusal') {
        expect(body.observed_decision).toBe('deny');
        expect(body.signoff_tier).toBeNull();
      } else {
        expect(body.observed_decision).toBe('allow_with_signoff');
        expect(body.required_assurance).toBe('A');
        expect(body.signoff_tier).toBe(scenario.id === 'dual_signoff' ? 'dual' : 'single');
      }
    });
  }
});
