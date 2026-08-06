// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const {
  mockAuthenticate,
  mockGetGuardedClient,
  mockDeliverTenantEvent,
} = vi.hoisted(() => ({
  mockAuthenticate: vi.fn(),
  mockGetGuardedClient: vi.fn(),
  mockDeliverTenantEvent: vi.fn(),
}));

vi.mock('@/lib/cloud/auth', () => ({
  authenticateCloudRequest: (...args) => mockAuthenticate(...args),
}));
vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: () => mockGetGuardedClient(),
}));
vi.mock('@/lib/cloud/webhooks', () => ({
  deliverTenantEvent: (...args) => mockDeliverTenantEvent(...args),
}));
vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import { GET as pending } from '../app/api/cloud/signoff/pending/route.js';
import { POST as notify } from '../app/api/cloud/signoff/notify/route.js';
import { POST as escalate } from '../app/api/cloud/signoff/escalate/route.js';

const TENANT_ID = '33333333-3333-4333-8333-333333333333';
const CHALLENGE_ID = '11111111-1111-4111-8111-111111111111';
const FUTURE = '2099-01-01T00:00:00.000Z';

function request(path, method = 'GET', body) {
  return new Request(`https://www.emiliaprotocol.ai${path}`, {
    method,
    headers: {
      authorization: 'Bearer ept_live_signoff',
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
}

function chain(result) {
  const value = {
    select: vi.fn().mockReturnThis(),
    insert: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    gt: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    range: vi.fn().mockReturnThis(),
    maybeSingle: vi.fn().mockResolvedValue(result),
    single: vi.fn().mockResolvedValue(result),
    then: (resolve, reject) => Promise.resolve(result).then(resolve, reject),
  };
  return value;
}

beforeEach(() => {
  vi.clearAllMocks();
  mockAuthenticate.mockResolvedValue({
    tenantId: TENANT_ID,
    environment: 'production',
    permissions: ['write'],
    keyId: 'key-signoff',
  });
  mockDeliverTenantEvent.mockResolvedValue({
    delivery_state: 'delivered',
    deliveries: [{ endpoint_id: 'ep-1', delivery_id: 'del-1', status: 'delivered' }],
  });
});

describe('cloud signoff operational truth', () => {
  it('lists the real pending states and excludes expired challenges', async () => {
    const query = chain({ data: [], error: null, count: 0 });
    mockGetGuardedClient.mockReturnValue({ from: vi.fn(() => query) });

    const response = await pending(request('/api/cloud/signoff/pending'));

    expect(response.status).toBe(200);
    expect(query.eq).toHaveBeenCalledWith('tenant_id', TENANT_ID);
    expect(query.in).toHaveBeenCalledWith('status', ['challenge_issued', 'challenge_viewed']);
    expect(query.gt).toHaveBeenCalledWith('expires_at', expect.any(String));
  });

  it('returns evidence-backed webhook delivery state, not a fake queued flag', async () => {
    const challenge = chain({
      data: {
        challenge_id: CHALLENGE_ID,
        status: 'challenge_issued',
        expires_at: FUTURE,
        binding_hash: 'sha256:binding',
        accountable_actor_ref: 'approver:cfo@example.com',
      },
      error: null,
    });
    mockGetGuardedClient.mockReturnValue({ from: vi.fn(() => challenge) });

    const response = await notify(request('/api/cloud/signoff/notify', 'POST', {
      challenge_id: CHALLENGE_ID,
      channel: 'webhook',
    }));
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body.notification_state).toBe('delivered');
    expect(body).not.toHaveProperty('notification_queued');
    expect(mockDeliverTenantEvent).toHaveBeenCalledWith(
      TENANT_ID,
      'signoff.challenge.notification_requested',
      expect.objectContaining({ challenge_id: CHALLENGE_ID }),
    );
  });

  it('rejects an unsupported channel without claiming work was queued', async () => {
    const response = await notify(request('/api/cloud/signoff/notify', 'POST', {
      challenge_id: CHALLENGE_ID,
      channel: 'email',
    }));
    expect(response.status).toBe(501);
    expect(mockDeliverTenantEvent).not.toHaveBeenCalled();
  });

  it('persists escalation and returns the durable audit event identity', async () => {
    const challengeQuery = chain({
      data: { challenge_id: CHALLENGE_ID, status: 'challenge_viewed', expires_at: FUTURE },
      error: null,
    });
    const auditQuery = chain({
      data: { id: 'audit-1', created_at: '2026-08-05T12:00:00.000Z' },
      error: null,
    });
    const client = {
      from: vi.fn((table) => table === 'signoff_challenges' ? challengeQuery : auditQuery),
    };
    mockGetGuardedClient.mockReturnValue(client);

    const response = await escalate(request('/api/cloud/signoff/escalate', 'POST', {
      challenge_id: CHALLENGE_ID,
      reason: 'Approver device unavailable',
    }));
    const body = await response.json();

    expect(response.status).toBe(201);
    expect(body.escalation_event_id).toBe('audit-1');
    expect(auditQuery.insert).toHaveBeenCalledWith(expect.objectContaining({
      event_type: 'cloud.signoff.escalated',
      target_id: CHALLENGE_ID,
    }));
  });
});
