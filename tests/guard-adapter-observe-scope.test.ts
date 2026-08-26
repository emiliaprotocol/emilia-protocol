// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  auth: {
    entity: {
      entity_id: 'pilot-1',
      organization_id: 'pilot-1',
      metadata: { pilot_sandbox: true, scope: 'observe' },
    },
    permissions: ['observe'],
  } as any,
  getGuardedClient: vi.fn(),
}));

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: vi.fn(async () => mocks.auth),
  authEntityId: (auth) => auth?.entity?.entity_id || '',
}));

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args) => mocks.getGuardedClient(...args),
}));

const { runGuardPrecheck } = await import('../lib/guard-adapter.js');
const { GUARD_ACTION_TYPES } = await import('../lib/guard-policies.js');

const SPEC = {
  adapterName: 'fin.payment-release',
  actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE,
  policyId: 'fin.payment-release.v1',
  targetResourceField: 'payment_instruction_id',
};

function precheck(enforcementMode: string): Promise<Response> {
  return runGuardPrecheck(new Request(
    'https://www.emiliaprotocol.ai/api/v1/adapters/fin/payment-release/precheck',
    {
      method: 'POST',
      headers: {
        authorization: 'Bearer ep_live_pilot',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        organization_id: 'pilot-1',
        enforcement_mode: enforcementMode,
        payment_instruction_id: 'pi-1',
        amount: 100,
        currency: 'USD',
        before_state: { status: 'pending' },
        after_state: { status: 'released' },
      }),
    },
  ), SPEC) as Promise<Response>;
}

describe('guard adapter observe-scope defense in depth', () => {
  beforeEach(() => {
    mocks.auth = {
      entity: {
        entity_id: 'pilot-1',
        organization_id: 'pilot-1',
        metadata: { pilot_sandbox: true, scope: 'observe' },
      },
      permissions: ['observe'],
    };
    mocks.getGuardedClient.mockReset();
    mocks.getGuardedClient.mockImplementation(() => {
      throw new Error('database must not be reached');
    });
  });

  it('refuses an enforce-mode body even when authentication was mocked as successful', async () => {
    const response = await precheck('enforce');
    const body = await response.json();

    expect(response.status).toBe(403);
    expect(`${body.code ?? ''} ${body.type ?? ''}`).toContain('insufficient_permissions');
    expect(mocks.getGuardedClient).not.toHaveBeenCalled();
  });

  it('requires the explicit observe permission at the adapter boundary too', async () => {
    mocks.auth.permissions = [];

    const response = await precheck('observe');
    const body = await response.json();

    expect(response.status).toBe(403);
    expect(`${body.code ?? ''} ${body.type ?? ''}`).toContain('insufficient_permissions');
    expect(mocks.getGuardedClient).not.toHaveBeenCalled();
  });
});
