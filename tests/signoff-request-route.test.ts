// SPDX-License-Identifier: Apache-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const {
  mockAuthenticateGuardRequest,
  mockGetGuardedClient,
} = vi.hoisted(() => ({
  mockAuthenticateGuardRequest: vi.fn(),
  mockGetGuardedClient: vi.fn(),
}));

vi.mock('@/lib/guard-auth.js', () => ({
  authenticateGuardRequest: (...args) => mockAuthenticateGuardRequest(...args),
  isCloudGuardPrincipal: () => false,
}));
vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args) => mockGetGuardedClient(...args),
}));
vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import { POST as requestSignoff } from '../app/api/v1/signoffs/request/route.js';

const NOW = new Date('2026-07-19T19:00:00.000Z');
const RECEIPT_ID = `tr_${'a'.repeat(32)}`;

function req(body) {
  return new Request('https://www.emiliaprotocol.ai/api/v1/signoffs/request', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function createdEvent(expiresAt, afterState = {}) {
  return {
    event_type: 'guard.trust_receipt.created',
    actor_id: 'user_1',
    created_at: '2026-07-19T18:55:00.000Z',
    after_state: {
      signoff_required: true,
      action_hash: 'action-hash',
      expires_at: expiresAt,
      ...afterState,
    },
  };
}

function auditClient(events, insertError = null) {
  const insert = vi.fn().mockResolvedValue({ data: null, error: insertError });
  const client = {
    from: vi.fn(() => {
      const chain = {
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        order: vi.fn().mockReturnThis(),
        insert,
        then: (resolve, reject) => Promise.resolve({ data: events, error: null }).then(resolve, reject),
      };
      return chain;
    }),
  };
  return { client, insert };
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
  mockAuthenticateGuardRequest.mockReset();
  mockGetGuardedClient.mockReset();
  mockAuthenticateGuardRequest.mockResolvedValue({
    entity: { id: 'user_1', entity_id: 'user_1', organization_id: 'org_1' },
  });
});

afterEach(() => {
  vi.useRealTimers();
});

describe('POST /api/v1/signoffs/request lifetime and duplicate races', () => {
  it('caps the default signoff lifetime at the receipt expiry', async () => {
    const receiptExpiry = new Date(NOW.getTime() + 30 * 60 * 1000).toISOString();
    const { client, insert } = auditClient([createdEvent(receiptExpiry)]);
    mockGetGuardedClient.mockReturnValue(client);

    const response = await requestSignoff(req({
      receipt_id: RECEIPT_ID,
      approver_id: 'approver_1',
    }));

    expect(response.status).toBe(201);
    expect((await response.json()).expires_at).toBe(receiptExpiry);
    expect(insert.mock.calls[0][0].after_state.expires_at).toBe(receiptExpiry);
  });

  it('uses a requested lifetime when it expires before the receipt', async () => {
    const receiptExpiry = new Date(NOW.getTime() + 60 * 60 * 1000).toISOString();
    const requestedExpiry = new Date(NOW.getTime() + 15 * 60 * 1000).toISOString();
    const { client, insert } = auditClient([createdEvent(receiptExpiry)]);
    mockGetGuardedClient.mockReturnValue(client);

    const response = await requestSignoff(req({
      receipt_id: RECEIPT_ID,
      approver_id: 'approver_1',
      expires_in_minutes: 15,
    }));

    expect(response.status).toBe(201);
    expect((await response.json()).expires_at).toBe(requestedExpiry);
    expect(insert.mock.calls[0][0].after_state.expires_at).toBe(requestedExpiry);
  });

  it('rejects a receipt exactly at its expiry boundary', async () => {
    const { client, insert } = auditClient([createdEvent(NOW.toISOString())]);
    mockGetGuardedClient.mockReturnValue(client);

    const response = await requestSignoff(req({
      receipt_id: RECEIPT_ID,
      approver_id: 'approver_1',
    }));

    expect(response.status).toBe(410);
    expect(JSON.stringify(await response.json())).toContain('receipt_expired');
    expect(insert).not.toHaveBeenCalled();
  });

  it('fails closed when the receipt expiry is malformed', async () => {
    const { client, insert } = auditClient([createdEvent('not-a-timestamp')]);
    mockGetGuardedClient.mockReturnValue(client);

    const response = await requestSignoff(req({
      receipt_id: RECEIPT_ID,
      approver_id: 'approver_1',
    }));

    expect(response.status).toBe(500);
    expect(JSON.stringify(await response.json())).toContain('corrupted_receipt');
    expect(insert).not.toHaveBeenCalled();
  });

  it('allows one remaining millisecond and caps the signoff to it', async () => {
    const receiptExpiry = new Date(NOW.getTime() + 1).toISOString();
    const { client, insert } = auditClient([createdEvent(receiptExpiry)]);
    mockGetGuardedClient.mockReturnValue(client);

    const response = await requestSignoff(req({
      receipt_id: RECEIPT_ID,
      approver_id: 'approver_1',
    }));

    expect(response.status).toBe(201);
    expect((await response.json()).expires_at).toBe(receiptExpiry);
    expect(insert.mock.calls[0][0].after_state.expires_at).toBe(receiptExpiry);
  });

  it('maps a concurrent duplicate single-signoff insert to 409', async () => {
    const receiptExpiry = new Date(NOW.getTime() + 60 * 60 * 1000).toISOString();
    const { client } = auditClient(
      [createdEvent(receiptExpiry)],
      { code: '23505', message: 'duplicate key value violates unique constraint' },
    );
    mockGetGuardedClient.mockReturnValue(client);

    const response = await requestSignoff(req({
      receipt_id: RECEIPT_ID,
      approver_id: 'approver_1',
    }));

    expect(response.status).toBe(409);
    expect(JSON.stringify(await response.json())).toContain('signoff_already_requested');
  });

  it('maps a concurrent duplicate quorum fan-out insert to 409', async () => {
    const receiptExpiry = new Date(NOW.getTime() + 60 * 60 * 1000).toISOString();
    const quorumPolicy = {
      mode: 'threshold',
      required: 2,
      approvers: [
        { role: 'reviewer', approver: 'approver_1' },
        { role: 'controller', approver: 'approver_2' },
      ],
    };
    const { client } = auditClient(
      [createdEvent(receiptExpiry, { quorum_policy: quorumPolicy })],
      { code: '23505', message: 'duplicate key value violates unique constraint' },
    );
    mockGetGuardedClient.mockReturnValue(client);

    const response = await requestSignoff(req({ receipt_id: RECEIPT_ID }));

    expect(response.status).toBe(409);
    expect(JSON.stringify(await response.json())).toContain('signoff_already_requested');
  });
});
