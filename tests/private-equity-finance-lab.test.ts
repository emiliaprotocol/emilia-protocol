// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { FINANCE_LAB_ACTIONS } from '../app/private-equity/finance-lab-fixture';

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

import { POST as vendorBankChange } from '../app/api/v1/adapters/fin/vendor-bank-change/precheck/route';
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
  for (const action of FINANCE_LAB_ACTIONS) {
    it(`${action.id} runs through its real observe-mode adapter`, async () => {
      const route = action.id === 'vendor-change' ? vendorBankChange : paymentRelease;
      const response = await route(request(
        action.path,
        action.body('ep_entity_portfolio_lab'),
      ) as never);
      const body = await response.json();

      expect(response.status).toBe(201);
      expect(body.decision).toBe('observe');
      expect(body.observed_decision).toBe('allow_with_signoff');
      expect(body.evidence_status).toBe('durable');
      expect(body.canonical_action.organization_id).toBe('ep_entity_portfolio_lab');
      expect(inserted.some((entry) => entry.table === 'audit_events')).toBe(true);

      if (action.id === 'vendor-change') {
        expect(body.canonical_action).toMatchObject({
          action_type: 'vendor_bank_account_change',
          target_resource_id: 'vendor_014',
          target_changed_fields: ['bank_account', 'routing_number'],
        });
      } else {
        expect(body.canonical_action).toMatchObject({
          action_type: 'large_payment_release',
          payment_instruction_id: 'pi_northstar_082',
          counterparty_name: 'Northstar Demo Vendor',
          amount: 82_000,
          currency: 'USD',
        });
        expect(inserted.some((entry) => entry.table === 'aml_history')).toBe(true);
      }
    });
  }
});
