// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi, beforeEach } from 'vitest';

const state = vi.hoisted(() => ({
  inserts: [],
  existing: null,
  lastEntityNumber: 42,
  lastClaimedNumber: 50,
}));

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: () => ({
    from(table: string) {
      const query: any = {
        _table: table,
        _select: '',
        _order: '',
        select(cols: string) { this._select = cols; return this; },
        eq() { return this; },
        order(col: string) { this._order = col; return this; },
        limit() { return this; },
        single: vi.fn(async () => {
          if (table === 'waitlist' && query._select === 'id') {
            return { data: state.existing, error: null };
          }
          if (table === 'entities') {
            return { data: { entity_number: state.lastEntityNumber }, error: null };
          }
          if (table === 'waitlist' && query._select === 'claimed_number') {
            return { data: { claimed_number: state.lastClaimedNumber }, error: null };
          }
          return { data: null, error: null };
        }),
        insert: vi.fn((row: any) => {
          state.inserts.push({ table, row });
          return {
            select() { return this; },
            async single() {
              return {
                data: { claimed_number: row.claimed_number, email: row.email, created_at: '2026-06-28T00:00:00Z' },
                error: null,
              };
            },
          };
        }),
      };
      return query;
    },
  }),
}));

vi.mock('@/lib/errors', () => ({
  epProblem: (status: number, code: string, detail: string) => Response.json({ code, detail }, { status }),
}));

const { POST } = await import('../app/api/waitlist/route.js');

function request(body: any): Request {
  return new Request('http://localhost/api/waitlist', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

describe('waitlist route', () => {
  beforeEach(() => {
    state.inserts = [];
    state.existing = null;
    state.lastEntityNumber = 42;
    state.lastClaimedNumber = 50;
  });

  it('uses entities.entity_number, not UUID id, when assigning claimed_number', async () => {
    const res = await POST(request({ email: ' New@Example.COM ' }));
    expect(res.status).toBe(202);
    const body = await res.json();
    expect(body).toEqual({
      ok: true,
      status: 'received',
      message: 'If this address is eligible, it has been added to the waitlist.',
    });
    expect(state.inserts[0].row.claimed_number).toBe(51);
    expect(state.inserts[0].row.email).toBe('new@example.com');
  });

  it('returns the same response for an existing email to prevent enumeration', async () => {
    state.existing = { id: 'waitlist-existing' };

    const res = await POST(request({ email: 'known@example.com' }));
    const body = await res.json();

    expect(res.status).toBe(202);
    expect(body).toEqual({
      ok: true,
      status: 'received',
      message: 'If this address is eligible, it has been added to the waitlist.',
    });
    expect(state.inserts).toEqual([]);
  });
});
