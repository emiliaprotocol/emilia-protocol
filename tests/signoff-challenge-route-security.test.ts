// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authenticateRequest: vi.fn(),
}));

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: mocks.authenticateRequest,
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const { POST } = await import('../app/api/signoff/challenge/route.ts');

function request(): Request {
  return new Request('https://www.emiliaprotocol.ai/api/signoff/challenge', {
    method: 'POST',
    headers: {
      authorization: 'Bearer ep_live_test',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      handshakeId: 'handshake-1',
      bindingHash: 'sha256:binding',
      expiresAt: '2099-01-01T00:00:00Z',
      accountableActorRef: 'entity-attacker',
      signoffPolicyId: 'weaker-policy',
      requiredAssurance: 'low',
      allowedMethods: ['out_of_band'],
    }),
  });
}

describe('POST /api/signoff/challenge ceremony availability boundary', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.authenticateRequest.mockResolvedValue({
      entity: { entity_id: 'entity-issuer' },
      permissions: ['write'],
    });
  });

  it('does not mint an uncompletable challenge while no verified ceremony producer exists', async () => {
    const response = await POST(request() as any);

    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({
      type: 'https://emiliaprotocol.ai/errors/verified_ceremony_unavailable',
      status: 503,
      detail: expect.stringMatching(/server-verified WebAuthn or secure-application ceremony producer/i),
    });
  });

  it('still rejects unauthenticated issuance before disclosing availability state', async () => {
    mocks.authenticateRequest.mockResolvedValueOnce({
      error: { code: 'invalid_api_key' },
    });

    const response = await POST(request() as any);
    expect(response.status).toBe(401);
  });
});
