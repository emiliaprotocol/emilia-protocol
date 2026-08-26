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

const { POST } = await import('../app/api/signoff/[challengeId]/attest/route.ts');

function forgedRequest(): Request {
  return new Request('https://www.emiliaprotocol.ai/api/signoff/challenge-1/attest', {
    method: 'POST',
    headers: {
      authorization: 'Bearer ep_live_attacker',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      humanEntityRef: 'entity-alice',
      authMethod: 'passkey',
      assuranceLevel: 'high',
      channel: 'platform_authenticator',
      attestationHash: 'sha256:caller-asserted',
    }),
  });
}

describe('POST /api/signoff/[challengeId]/attest security boundary', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.authenticateRequest.mockResolvedValue({
      entity: { entity_id: 'entity-alice' },
      permissions: ['write'],
    });
  });

  it('rejects bearer JSON claims of fresh passkey and high assurance', async () => {
    const response = await POST(forgedRequest() as any, {
      params: Promise.resolve({ challengeId: 'challenge-1' }),
    });

    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({
      type: 'https://emiliaprotocol.ai/errors/verified_ceremony_required',
      status: 409,
      detail: expect.stringMatching(/server-verified WebAuthn or secure-application ceremony/i),
    });
  });

  it('authenticates before returning the fail-closed ceremony response', async () => {
    mocks.authenticateRequest.mockResolvedValueOnce({
      error: { code: 'invalid_api_key' },
    });

    const response = await POST(forgedRequest() as any, {
      params: Promise.resolve({ challengeId: 'challenge-1' }),
    });

    expect(response.status).toBe(401);
  });

  it('requires a named authenticated entity before returning the ceremony response', async () => {
    mocks.authenticateRequest.mockResolvedValueOnce({ entity: null, permissions: ['write'] });

    const response = await POST(forgedRequest() as any, {
      params: Promise.resolve({ challengeId: 'challenge-1' }),
    });

    expect(response.status).toBe(403);
  });
});
