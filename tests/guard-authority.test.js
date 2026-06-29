// SPDX-License-Identifier: Apache-2.0
// #5 Authority registry — credentials prove control; authorities prove permission.

import { describe, it, expect } from 'vitest';
import { evaluateAuthority, resolveGuardAuthority } from '../lib/guard-authority.js';

// Chainable mock matching resolveGuardAuthority's query:
// .from().select().eq().eq().eq().limit() -> Promise<{ data, error }>
function mockClient({ data = null, error = null } = {}) {
  const result = Promise.resolve({ data, error });
  const chain = { select: () => chain, eq: () => chain, limit: () => result };
  return { from: () => chain };
}

const NOW = '2026-06-23T12:00:00.000Z';
const active = {
  authority_id: 'auth_1',
  role: 'controller',
  assurance_class: 'A',
  status: 'active',
  valid_from: '2026-01-01T00:00:00.000Z',
  valid_to: '2026-12-31T00:00:00.000Z',
  revoked_at: null,
  organization_id: 'org_1',
};

describe('evaluateAuthority — fail closed unless a valid authority proves permission', () => {
  it('authorizes a valid, in-window, in-role, sufficient-assurance record', () => {
    const r = evaluateAuthority(active, { role: 'controller', at: NOW, requiredAssurance: 'A' });
    expect(r.authorized).toBe(true);
    expect(r.assurance_class).toBe('A');
  });

  it('fails closed when no authority record exists (e.g. wrong org → no row)', () => {
    expect(evaluateAuthority(null, { role: 'controller', at: NOW }).authorized).toBe(false);
    expect(evaluateAuthority(null, {}).reason).toBe('no_active_authority');
  });

  it('rejects a revoked authority', () => {
    const r = evaluateAuthority({ ...active, revoked_at: '2026-06-01T00:00:00.000Z' }, { role: 'controller', at: NOW });
    expect(r.authorized).toBe(false);
    expect(r.reason).toBe('authority_revoked');
  });

  it('rejects an expired authority', () => {
    const r = evaluateAuthority({ ...active, valid_to: '2026-03-01T00:00:00.000Z' }, { role: 'controller', at: NOW });
    expect(r.authorized).toBe(false);
    expect(r.reason).toBe('authority_expired');
  });

  it('rejects the wrong role', () => {
    const r = evaluateAuthority(active, { role: 'supervisor', at: NOW });
    expect(r.authorized).toBe(false);
    expect(r.reason).toBe('wrong_role');
  });

  it('rejects insufficient assurance (C cannot satisfy a Class-A requirement)', () => {
    const r = evaluateAuthority({ ...active, assurance_class: 'C' }, { role: 'controller', at: NOW, requiredAssurance: 'A' });
    expect(r.authorized).toBe(false);
    expect(r.reason).toBe('insufficient_assurance');
  });

  it('rejects a non-active status', () => {
    expect(evaluateAuthority({ ...active, status: 'retired' }, { at: NOW }).reason).toBe('authority_retired');
  });
});

describe('resolveGuardAuthority — missing/empty/bad authority never resolves authorized (regression)', () => {
  const ctx = { organizationId: 'org_1', approverId: 'ep:approver:x', requiredAssurance: 'A', at: NOW };

  it('fails closed when the authorities table is MISSING (SQLSTATE 42P01)', async () => {
    const r = await resolveGuardAuthority(mockClient({ error: { code: '42P01', message: 'relation "authorities" does not exist' } }), ctx);
    expect(r.authorized).toBe(false);
    expect(r.reason).toBe('authority_lookup_failed');
  });

  it('fails closed when the table is EMPTY (no row for this approver/org)', async () => {
    const r = await resolveGuardAuthority(mockClient({ data: [] }), ctx);
    expect(r.authorized).toBe(false);
    expect(r.reason).toBe('no_active_authority');
  });

  it('fails closed on a BAD row (revoked)', async () => {
    const r = await resolveGuardAuthority(mockClient({ data: [{ ...active, revoked_at: '2026-06-01T00:00:00.000Z' }] }), ctx);
    expect(r.authorized).toBe(false);
  });

  it('fails closed when org or approver is missing (never queries)', async () => {
    expect((await resolveGuardAuthority(mockClient(), { approverId: 'x' })).reason).toBe('missing_authority_subject');
    expect((await resolveGuardAuthority(mockClient(), { organizationId: 'o' })).reason).toBe('missing_authority_subject');
  });

  it('authorizes a valid, active, in-window, sufficient-assurance row', async () => {
    const r = await resolveGuardAuthority(mockClient({ data: [active] }), { ...ctx, role: 'controller' });
    expect(r.authorized).toBe(true);
  });
});
