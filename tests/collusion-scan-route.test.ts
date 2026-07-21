// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockGetGuardedClient = vi.fn();
const mockAuthenticateOperator = vi.fn();
const mockAppendSecurityEvent = vi.fn();

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args) => mockGetGuardedClient(...args),
}));

vi.mock('@/lib/operator-auth', () => ({
  authenticateOperator: (...args) => mockAuthenticateOperator(...args),
}));

vi.mock('@/lib/security-events', async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    appendSecurityEvent: (...args) => mockAppendSecurityEvent(...args),
  };
});

vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

const { GET } = await import('../app/api/cron/collusion-scan/route.js');

function makeClient(receipts) {
  return {
    from(table) {
      expect(table).toBe('receipts');
      return {
        select() { return this; },
        async range(from, to) {
          return { data: receipts.slice(from, to + 1), error: null };
        },
      };
    },
  };
}

describe('/api/cron/collusion-scan route hardening', () => {
  beforeEach(() => {
    mockGetGuardedClient.mockReset();
    mockAuthenticateOperator.mockReset();
    mockAppendSecurityEvent.mockReset();
    mockAuthenticateOperator.mockReturnValue({ valid: true, operator_id: 'op_redteam' });
  });

  it('stamps ledger findings with the authenticated operator identity', async () => {
    mockGetGuardedClient.mockReturnValue(makeClient([
      { submitted_by: 'A', entity_id: 'B', created_at: '2026-06-01T00:00:00Z' },
      { submitted_by: 'B', entity_id: 'A', created_at: '2026-06-01T00:00:01Z' },
    ]));
    mockAppendSecurityEvent.mockResolvedValue({ id: 'evt_1' });

    const res = await GET(new Request('https://x.test/api/cron/collusion-scan'));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.events_written).toBe(2);
    expect(mockAppendSecurityEvent).toHaveBeenCalled();
    for (const [event] of mockAppendSecurityEvent.mock.calls) {
      expect(event.actorId).toBe('op_redteam');
      expect(event.eventType).toBe('collusion_suspected');
    }
  });

  it('does not write ledger events during dry_run', async () => {
    mockGetGuardedClient.mockReturnValue(makeClient([
      { submitted_by: 'A', entity_id: 'B', created_at: '2026-06-01T00:00:00Z' },
      { submitted_by: 'B', entity_id: 'A', created_at: '2026-06-01T00:00:01Z' },
    ]));

    const res = await GET(new Request('https://x.test/api/cron/collusion-scan?dry_run=1'));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.dry_run).toBe(true);
    expect(body.events_written).toBe(0);
    expect(mockAppendSecurityEvent).not.toHaveBeenCalled();
  });
});
