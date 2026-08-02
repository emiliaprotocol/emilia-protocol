// SPDX-License-Identifier: Apache-2.0
//
// POST /api/delegations/create — principal resolution.
//
// Audit #12 finding 1. Line 40 read the bare identifier `authEntityId` instead
// of calling it, so a request that omitted principal_id passed the FUNCTION as
// principalId. Two things followed, and the second is the one that matters:
//
//   1. JSON.stringify drops function-valued keys, so principal_id vanished from
//      the insert body. `delegations.principal_id` is NOT NULL (migration 023),
//      so the row was refused by Postgres and the caller got a 500. No
//      delegation with a forged principal was ever created — but a DDL
//      constraint was the only thing preventing one, and an authority boundary
//      does not belong in a column definition.
//
//   2. The re-delegation containment query filtered
//      `agent_entity_id=eq.function authEntityId(auth){...}` — the function's
//      SOURCE TEXT. That matches no row, so heldScopes came back empty and the
//      SCOPE_ESCALATION guard had nothing to compare against. The guard did not
//      fire; it was skipped. That is the failure mode that survives any future
//      schema change.
//
// These cases pin the resolved principal at the boundary where it is decided,
// which is the only place a string can still be told apart from a function.

import { describe, it, expect, vi, beforeEach } from 'vitest';

const mocks = vi.hoisted(() => ({
  authenticateRequest: vi.fn(),
  createDelegation: vi.fn(),
  checkRateLimit: vi.fn(),
}));

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: mocks.authenticateRequest,
}));

vi.mock('@/lib/delegation', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/delegation.js')>();
  return { ...actual, createDelegation: mocks.createDelegation };
});

vi.mock('@/lib/rate-limit', () => ({
  checkRateLimit: mocks.checkRateLimit,
  getClientIP: () => '203.0.113.9',
}));

const CALLER = 'ep_entity_caller';

function req(body: unknown): Request {
  return new Request('https://ep.test/api/delegations/create', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.checkRateLimit.mockResolvedValue({ allowed: true, remaining: 10, reset: 60 });
  mocks.authenticateRequest.mockResolvedValue({ entity: { entity_id: CALLER, id: CALLER } });
  mocks.createDelegation.mockImplementation(async ({ principalId }) => ({
    delegation_id: 'dlg_1',
    principal_id: principalId,
    status: 'active',
  }));
});

describe('POST /api/delegations/create — principal resolution', () => {
  it('defaults the principal to the authenticated entity id, not the projection function', async () => {
    const { POST } = await import('../app/api/delegations/create/route.js');

    const res = await POST(req({
      agent_entity_id: 'ep_entity_agent',
      scope: ['payments.execute'],
      max_value_usd: 1_000_000,
    }) as never);

    expect(res.status).toBe(201);
    expect(mocks.createDelegation).toHaveBeenCalledTimes(1);

    const { principalId } = mocks.createDelegation.mock.calls[0][0];
    expect(typeof principalId).toBe('string');
    expect(principalId).toBe(CALLER);
  });

  it('never hands createDelegation a function as the principal', async () => {
    const { POST } = await import('../app/api/delegations/create/route.js');

    // The precise regression. A function principalId is truthy, so it survives
    // createDelegation's own `if (!principalId)` guard and reaches the
    // containment query and the insert.
    await POST(req({ agent_entity_id: 'ep_entity_agent', scope: ['payments.execute'] }) as never);

    const { principalId } = mocks.createDelegation.mock.calls[0][0];
    expect(typeof principalId).not.toBe('function');
    expect(String(principalId)).not.toMatch(/function|=>/);
  });

  it('still honours an explicit principal_id that matches the caller', async () => {
    const { POST } = await import('../app/api/delegations/create/route.js');

    const res = await POST(req({
      principal_id: CALLER,
      agent_entity_id: 'ep_entity_agent',
      scope: ['payments.execute'],
    }) as never);

    expect(res.status).toBe(201);
    expect(mocks.createDelegation.mock.calls[0][0].principalId).toBe(CALLER);
  });

  it('still refuses a principal_id that is not the caller', async () => {
    const { POST } = await import('../app/api/delegations/create/route.js');

    const res = await POST(req({
      principal_id: 'ep_entity_someone_else',
      agent_entity_id: 'ep_entity_agent',
      scope: ['payments.execute'],
    }) as never);

    expect(res.status).toBe(403);
    expect(mocks.createDelegation).not.toHaveBeenCalled();
  });

  it('refuses a non-string principal_id instead of passing it through', async () => {
    const { POST } = await import('../app/api/delegations/create/route.js');

    // An object principal_id used to be truthy, skip the equality check (it is
    // !== callerEntityId only by identity), and land in the insert. Narrowing
    // to string means it is simply not a principal, so the caller's own id is
    // used and the forged value is discarded.
    const res = await POST(req({
      principal_id: { toString: () => CALLER },
      agent_entity_id: 'ep_entity_agent',
      scope: ['payments.execute'],
    }) as never);

    expect(res.status).toBe(201);
    expect(mocks.createDelegation.mock.calls[0][0].principalId).toBe(CALLER);
  });

  it('refuses when the authenticated request carries no resolvable entity identity', async () => {
    mocks.authenticateRequest.mockResolvedValue({ entity: {} });
    const { POST } = await import('../app/api/delegations/create/route.js');

    const res = await POST(req({
      agent_entity_id: 'ep_entity_agent',
      scope: ['payments.execute'],
    }) as never);

    expect(res.status).toBe(403);
    expect(mocks.createDelegation).not.toHaveBeenCalled();
  });
});
