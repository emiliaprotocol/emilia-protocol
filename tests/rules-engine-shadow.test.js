/**
 * EP rules-engine v0 shadow-signal integration test.
 * @license Apache-2.0
 *
 * Proves the EP_RULES_ENGINE_V0=enabled wiring in
 * app/api/v1/trust-receipts/route.js works end-to-end without needing a
 * live API call. Supabase is mocked at the @/lib/write-guard + @/lib/supabase
 * boundary; the route is imported directly and invoked with a synthetic
 * request. Two audit_events insertions should occur when the flag is on,
 * one when it is off.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const mockGetGuardedClient = vi.fn();
const mockAuthenticateRequest = vi.fn();

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args) => mockGetGuardedClient(...args),
}));
vi.mock('@/lib/supabase', () => ({
  authenticateRequest: (...args) => mockAuthenticateRequest(...args),
  getServiceClient: vi.fn(),
}));
vi.mock('../lib/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));
vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import { POST as createReceipt } from '../app/api/v1/trust-receipts/route.js';

function req(body) {
  return { json: () => Promise.resolve(body ?? {}) };
}

/** Supabase mock that captures every `.from('audit_events').insert(...)` call. */
function makeAuditCapture() {
  const inserts = [];
  const client = {
    from(table) {
      return {
        insert: (row) => {
          if (table === 'audit_events') inserts.push(row);
          return Promise.resolve({ error: null });
        },
      };
    },
  };
  return { client, inserts };
}

const VALID_BODY = {
  organization_id: 'org_demo_treasury',
  action_type: 'vendor_bank_account_change',
  target_resource_id: 'vendor:VEND-9821',
  amount: 25_000,
  business_hours: false,
  destination_age_days: 5,
};

describe('rules-engine v0 shadow signal — wiring', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockAuthenticateRequest.mockResolvedValue({ entity: 'actor_alice', permissions: [] });
  });

  afterEach(() => {
    delete process.env.EP_RULES_ENGINE_V0;
  });

  it('when EP_RULES_ENGINE_V0=enabled, emits TWO audit_events: live + shadow', async () => {
    process.env.EP_RULES_ENGINE_V0 = 'enabled';
    const { client, inserts } = makeAuditCapture();
    mockGetGuardedClient.mockReturnValue(client);

    const res = await createReceipt(req(VALID_BODY));
    expect(res.status).toBe(201);

    // Two audit_events: the live 'guard.trust_receipt.created' + the
    // 'rules-engine.v0.shadow' side-channel.
    expect(inserts).toHaveLength(2);
    expect(inserts[0].event_type).toBe('guard.trust_receipt.created');
    expect(inserts[1].event_type).toBe('rules-engine.v0.shadow');

    // The shadow event carries the audit's §4.2 decision enum.
    const shadow = inserts[1].after_state;
    expect(shadow.rules_engine_decision).toMatch(
      /^(ALLOW|ALLOW_WITH_RECEIPT|REQUIRE_SIGNOFF|REQUIRE_SECOND_APPROVAL|REQUIRE_THIRD_APPROVAL|HOLD_FOR_REVIEW|DENY)$/,
    );
    expect(Array.isArray(shadow.rules_engine_reason_codes)).toBe(true);
    expect(typeof shadow.rules_engine_required_approvals).toBe('number');
    expect(typeof shadow.rules_engine_risk_score).toBe('number');
    expect(shadow.feature_flag).toBe('EP_RULES_ENGINE_V0');
    expect(shadow.evaluator_version).toBe('0');
    // The shadow record pins the live evaluator's decision alongside,
    // so ops can diff old-vs-new without joining tables.
    expect(typeof shadow.guard_policy_decision).toBe('string');
  });

  it('shadow event correctly identifies vendor_bank_account_change as REQUIRE_SECOND_APPROVAL or stronger', async () => {
    // Per §4.6 + §4.7 + §4.9 — vendor_bank_account_change always requires
    // signoff (BANK_DESTINATION_CHANGE), quorum 2+. With after-hours +
    // new-destination + amount-25K, risk crosses 50, escalating to
    // REQUIRE_THIRD_APPROVAL.
    process.env.EP_RULES_ENGINE_V0 = 'enabled';
    const { client, inserts } = makeAuditCapture();
    mockGetGuardedClient.mockReturnValue(client);

    await createReceipt(req(VALID_BODY));
    const shadow = inserts[1].after_state;

    expect(shadow.rules_engine_required_approvals).toBeGreaterThanOrEqual(2);
    expect(shadow.rules_engine_reason_codes).toContain('BANK_DESTINATION_CHANGE');
    expect(shadow.rules_engine_required_signoff?.reason_code).toBe('BANK_DESTINATION_CHANGE');
  });

  it('when EP_RULES_ENGINE_V0 is unset, emits ONLY the live audit_event (no shadow)', async () => {
    // Default state: flag absent → shadow path is dormant.
    delete process.env.EP_RULES_ENGINE_V0;
    const { client, inserts } = makeAuditCapture();
    mockGetGuardedClient.mockReturnValue(client);

    const res = await createReceipt(req(VALID_BODY));
    expect(res.status).toBe(201);
    expect(inserts).toHaveLength(1);
    expect(inserts[0].event_type).toBe('guard.trust_receipt.created');
  });

  it('when EP_RULES_ENGINE_V0 has any value other than "enabled", emits ONLY the live audit_event', async () => {
    // The check is strict equality to the string 'enabled' — anything
    // else (typo, "true", "1", "yes") leaves the shadow path dormant.
    // Important so a misconfigured env var doesn't accidentally double-
    // write audit events.
    for (const candidate of ['true', '1', 'yes', 'ENABLED', '']) {
      process.env.EP_RULES_ENGINE_V0 = candidate;
      const { client, inserts } = makeAuditCapture();
      mockGetGuardedClient.mockReturnValue(client);
      mockAuthenticateRequest.mockResolvedValue({ entity: 'actor_alice', permissions: [] });

      const res = await createReceipt(req(VALID_BODY));
      expect(res.status).toBe(201);
      expect(inserts.length, `flag value="${candidate}" should NOT activate shadow`).toBe(1);
    }
  });

  it('shadow eval failure does not break the live route (try/catch contract)', async () => {
    // Even if the shadow path throws (say, audit_events.insert rejects on
    // the second call), the live response must still be 201. The wiring
    // wraps the shadow block in try/catch precisely to enforce this.
    process.env.EP_RULES_ENGINE_V0 = 'enabled';
    let callCount = 0;
    const client = {
      from() {
        return {
          insert: () => {
            callCount += 1;
            if (callCount === 2) {
              // Second insert (the shadow event) — simulate a DB failure.
              return Promise.resolve({ error: { code: '23505', message: 'simulated' } });
            }
            return Promise.resolve({ error: null });
          },
        };
      },
    };
    mockGetGuardedClient.mockReturnValue(client);

    const res = await createReceipt(req(VALID_BODY));
    expect(res.status).toBe(201);
  });
});
