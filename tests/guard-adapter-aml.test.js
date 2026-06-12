/**
 * Guard adapter — AML end-to-end through runGuardPrecheck.
 *
 * Drives the real adapter (auth + policy + audit + response) with a mocked
 * Supabase + auth, and proves AML context flows through: a sanctioned
 * counterparty DENIES, a structuring pattern escalates to signoff, and a clean
 * financial action allows. Also covers the adapter's happy path (previously
 * unit-uncovered).
 */

import { vi, describe, it, expect, beforeEach } from 'vitest';

const inserted = [];
vi.mock('@/lib/supabase', () => ({
  authenticateRequest: async () => ({ entity: 'ep_entity_acme' }),
  authEntityId: (auth) => (typeof auth?.entity === 'string' ? auth.entity : auth?.entity?.entity_id || ''),
  getServiceClient: vi.fn(),
}));
vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: () => ({
    from: () => ({ insert: async (row) => { inserted.push(row); return { error: null }; } }),
  }),
}));

const { runGuardPrecheck } = await import('../lib/guard-adapter.js');
const { GUARD_ACTION_TYPES, GUARD_DECISIONS } = await import('../lib/guard-policies.js');

const FIN_SPEC = {
  adapterName: 'fin.payment-release',
  actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE,
  policyId: 'fin.payment-release.v1',
  targetResourceField: 'payment_instruction_id',
  actorRole: 'system',
};

function precheck(body) {
  const req = new Request('https://www.emiliaprotocol.ai/api/v1/adapters/fin/payment-release/precheck', {
    method: 'POST',
    headers: { authorization: 'Bearer ep_live_test', 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return runGuardPrecheck(req, FIN_SPEC);
}

const baseBody = (extra = {}) => ({
  organization_id: 'ep_entity_acme',
  payment_instruction_id: 'pi_1',
  amount: 2000,
  currency: 'USD',
  enforcement_mode: 'enforce',
  before_state: { status: 'pending' },
  after_state: { status: 'released' },
  ...extra,
});

beforeEach(() => { inserted.length = 0; });

describe('guard adapter + AML', () => {
  it('allows a clean financial action (no AML signals)', async () => {
    const res = await precheck(baseBody());
    expect(res.status).toBe(201);
    const json = await res.json();
    expect(json.decision).toBe(GUARD_DECISIONS.ALLOW);
    expect(json.aml_signals).toBeNull();
  });

  it('DENIES a payment to a sanctioned counterparty', async () => {
    const res = await precheck(baseBody({ counterparty_name: 'Blocked Person Alpha' }));
    const json = await res.json();
    expect(json.decision).toBe(GUARD_DECISIONS.DENY);
    expect(json.receipt_status).toBe('denied');
    expect(json.aml_signals.some((s) => s.startsWith('sanctions_match'))).toBe(true);
    // The decision is recorded in the audit trail.
    expect(inserted.at(-1).after_state.aml_signals).toBeTruthy();
  });

  it('DENIES a payment to an embargoed jurisdiction', async () => {
    const res = await precheck(baseBody({ counterparty_name: 'Neutral Co', counterparty_country: 'IR' }));
    expect((await res.json()).decision).toBe(GUARD_DECISIONS.DENY);
  });

  it('escalates a structuring pattern to signoff', async () => {
    const res = await precheck(baseBody({ amount: 9500, recent_amounts: [9400, 9600] }));
    const json = await res.json();
    expect(json.decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
    expect(json.signoff_required).toBe(true);
    expect(json.aml_signals.some((s) => s.startsWith('structuring'))).toBe(true);
  });

  it('observe mode never blocks even on a sanctions hit', async () => {
    const res = await precheck(baseBody({ counterparty_name: 'Blocked Person Alpha', enforcement_mode: 'observe' }));
    const json = await res.json();
    expect(json.decision).toBe(GUARD_DECISIONS.OBSERVE);
    expect(json.observed_decision).toBe(GUARD_DECISIONS.DENY);
  });

  it('rejects a body missing organization_id (400)', async () => {
    const res = await precheck({ payment_instruction_id: 'pi_1', before_state: {}, after_state: {} });
    expect(res.status).toBe(400);
  });
});
