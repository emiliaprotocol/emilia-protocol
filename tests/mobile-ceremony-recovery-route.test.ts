// SPDX-License-Identifier: Apache-2.0
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authenticateMobileToken: vi.fn(),
  checkRateLimit: vi.fn(),
  getClientIP: vi.fn(),
  getGuardedClient: vi.fn(),
  loggerError: vi.fn(),
  lookupMobileCeremonyResult: vi.fn(),
}));

vi.mock('@/lib/write-guard.js', () => ({
  getGuardedClient: (...args) => mocks.getGuardedClient(...args),
}));
vi.mock('@/lib/mobile/store.js', () => ({
  authenticateMobileToken: (...args) => mocks.authenticateMobileToken(...args),
  lookupMobileCeremonyResult: (...args) => mocks.lookupMobileCeremonyResult(...args),
}));
vi.mock('@/lib/rate-limit.js', () => ({
  checkRateLimit: (...args) => mocks.checkRateLimit(...args),
  getClientIP: (...args) => mocks.getClientIP(...args),
}));
vi.mock('@/lib/logger.js', () => ({
  logger: { error: (...args) => mocks.loggerError(...args) },
}));

const route = await import('@/app/api/v1/mobile/ceremonies/[challengeId]/route.js');

const TOKEN = `Bearer ep_mobile_${'a'.repeat(43)}`;
const CHALLENGE_ID = 'mob_0123456789abcdef0123456789abcdef';
const SESSION = Object.freeze({
  session_id: '00000000-0000-0000-0000-000000000001',
  entity_ref: 'entity-1',
  approver_id: 'ep:approver:supervisor',
  platform: 'ios',
  app_id: 'ai.emiliaprotocol.approver',
  device_key_id: 'ep:key:mobile-device-1',
});
const RESULT = Object.freeze({
  valid: true,
  verdict: 'verified',
  decision: 'approved',
  reason: null,
  context_hash: `sha256:${'c'.repeat(64)}`,
});

function request() {
  return new Request(`https://www.emiliaprotocol.ai/api/v1/mobile/ceremonies/${CHALLENGE_ID}`, {
    headers: { authorization: TOKEN },
  });
}

async function get(challengeId = CHALLENGE_ID) {
  return route.GET(request(), { params: Promise.resolve({ challengeId }) });
}

describe('mobile ceremony result route', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getGuardedClient.mockReturnValue({ guarded: true });
    mocks.getClientIP.mockReturnValue('203.0.113.7');
    mocks.checkRateLimit.mockResolvedValue({ allowed: true, reset: 60 });
    mocks.authenticateMobileToken.mockResolvedValue(SESSION);
    mocks.lookupMobileCeremonyResult.mockResolvedValue(RESULT);
  });

  it('returns a no-store committed result scoped from the authenticated session', async () => {
    const response = await get();
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      committed: true,
      outcome: 'committed',
      result: RESULT,
    });
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('pragma')).toBe('no-cache');
    expect(mocks.lookupMobileCeremonyResult).toHaveBeenCalledWith({ guarded: true }, {
      entityRef: SESSION.entity_ref,
      sessionId: SESSION.session_id,
      approverId: SESSION.approver_id,
      platform: SESSION.platform,
      appId: SESSION.app_id,
      deviceKeyId: SESSION.device_key_id,
      challengeId: CHALLENGE_ID,
    });
  });

  it('uses one indistinguishable closed body for unknown or uncommitted state', async () => {
    mocks.lookupMobileCeremonyResult.mockResolvedValue(null);
    const unknown = await get('mob_ffffffffffffffffffffffffffffffff');
    expect(unknown.status).toBe(200);
    expect(await unknown.json()).toEqual({
      committed: false,
      outcome: 'unknown',
      result: null,
    });

    const malformed = await get('../other-tenant');
    expect(malformed.status).toBe(200);
    expect(await malformed.json()).toEqual({
      committed: false,
      outcome: 'unknown',
      result: null,
    });
  });

  it('authenticates before lookup and closes storage failure without leaking state', async () => {
    mocks.authenticateMobileToken.mockResolvedValueOnce(null);
    const unauthorized = await get();
    expect(unauthorized.status).toBe(401);
    expect(mocks.lookupMobileCeremonyResult).not.toHaveBeenCalled();

    mocks.lookupMobileCeremonyResult.mockRejectedValueOnce(new Error('sensitive database detail'));
    const unavailable = await get();
    expect(unavailable.status).toBe(503);
    expect(JSON.stringify(await unavailable.json())).not.toContain('sensitive database detail');
    expect(unavailable.headers.get('cache-control')).toBe('no-store');
  });
});
