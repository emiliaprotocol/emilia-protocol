// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockAuthenticateRequest = vi.fn();
const mockGetDomainScores = vi.fn();
const mockCreateBinding = vi.fn();
const mockFileContinuityClaim = vi.fn();
const mockEmitAudit = vi.fn();
const mockAuthenticateOperator = vi.fn();
const mockProtocolWrite = vi.fn();
const mockGetGuardedClient = vi.fn();

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: (...args) => mockAuthenticateRequest(...args),
  authEntityId: (auth) => {
    const e = auth?.entity;
    if (typeof e === 'string') return e;
    return e?.entity_id || e?.id || '';
  },
}));

vi.mock('@/lib/domain-scoring', () => ({
  KNOWN_DOMAINS: ['delivery', 'payments', 'identity', 'quality'],
  getDomainScores: (...args) => mockGetDomainScores(...args),
}));

vi.mock('@/lib/ep-ix', () => ({
  createBinding: (...args) => mockCreateBinding(...args),
  fileContinuityClaim: (...args) => mockFileContinuityClaim(...args),
  emitAudit: (...args) => mockEmitAudit(...args),
}));

vi.mock('@/lib/operator-auth', () => ({
  authenticateOperator: (...args) => mockAuthenticateOperator(...args),
}));

vi.mock('@/lib/protocol-write', () => ({
  COMMAND_TYPES: {
    RESOLVE_DISPUTE: 'resolve_dispute',
    RESOLVE_APPEAL: 'resolve_appeal',
  },
  protocolWrite: (...args) => mockProtocolWrite(...args),
}));

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args) => mockGetGuardedClient(...args),
}));

const { GET: domainScoreGET } = await import('../app/api/trust/domain-score/[entityId]/route.ts');
const { POST: identityBindPOST } = await import('../app/api/identity/bind/route.ts');
const { POST: identityContinuityPOST } = await import('../app/api/identity/continuity/route.ts');
const { POST: disputeResolvePOST } = await import('../app/api/disputes/resolve/route.js');
const { POST: appealResolvePOST } = await import('../app/api/disputes/appeal/resolve/route.js');
const { GET: signoffGET } = await import('../app/api/signoff/[challengeId]/route.ts');

function jsonRequest(url, body, init = {}) {
  return new Request(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(init.headers || {}) },
    body: JSON.stringify(body),
  });
}

function params(value) {
  return { params: Promise.resolve(value) };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockAuthenticateRequest.mockResolvedValue({ entity: { entity_id: 'entity-owner' }, permissions: [] });
});

describe('control-plane object authorization', () => {
  it('denies domain-score reads for a different entity', async () => {
    const res = await domainScoreGET(
      new Request('https://example.test/api/trust/domain-score/entity-victim'),
      params({ entityId: 'entity-victim' }),
    );

    expect(res.status).toBe(403);
    expect(mockGetDomainScores).not.toHaveBeenCalled();
  });

  it('denies identity binding under a foreign principal id', async () => {
    const res = await identityBindPOST(jsonRequest('https://example.test/api/identity/bind', {
      principal_id: 'entity-victim',
      binding_type: 'domain_control',
      binding_target: 'victim.example',
    }));

    expect(res.status).toBe(403);
    expect(mockCreateBinding).not.toHaveBeenCalled();
  });

  it('denies continuity claims under a foreign principal id', async () => {
    const res = await identityContinuityPOST(jsonRequest('https://example.test/api/identity/continuity', {
      principal_id: 'entity-victim',
      old_entity_id: 'entity-old',
      new_entity_id: 'entity-new',
      reason: 'entity_rename',
    }));

    expect(res.status).toBe(403);
    expect(mockFileContinuityClaim).not.toHaveBeenCalled();
  });

  it('requires dispute.resolve permission for dispute resolution', async () => {
    mockAuthenticateOperator.mockReturnValue({
      valid: true,
      operator_id: 'op_reporter',
      role: 'reporter',
    });

    const res = await disputeResolvePOST(jsonRequest('https://example.test/api/disputes/resolve', {
      dispute_id: 'disp-1',
      resolution: 'dismissed',
    }));

    expect(res.status).toBe(403);
    expect(mockProtocolWrite).not.toHaveBeenCalled();
  });

  it('requires appeal.resolve permission for appeal resolution', async () => {
    mockAuthenticateOperator.mockReturnValue({
      valid: true,
      operator_id: 'op_reviewer',
      role: 'reviewer',
    });

    const res = await appealResolvePOST(jsonRequest('https://example.test/api/disputes/appeal/resolve', {
      dispute_id: 'disp-1',
      resolution: 'appeal_reversed',
    }));

    expect(res.status).toBe(403);
    expect(mockProtocolWrite).not.toHaveBeenCalled();
  });

  it('allows the accountable actor to read their own signoff challenge', async () => {
    const challenge = {
      id: 'ch-1',
      accountable_actor_ref: 'entity-owner',
      status: 'pending',
    };
    const chain = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      maybeSingle: vi.fn().mockResolvedValue({ data: challenge, error: null }),
    };
    mockGetGuardedClient.mockReturnValue({
      from: vi.fn(() => chain),
    });

    const res = await signoffGET(
      new Request('https://example.test/api/signoff/ch-1'),
      params({ challengeId: 'ch-1' }),
    );
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.accountable_actor_ref).toBe('entity-owner');
  });
});
