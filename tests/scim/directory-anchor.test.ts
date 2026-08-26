// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for the enrollment directory anchor predicate
// (lib/scim/directory-anchor.js). The org -> tenant map is a SET (not a single
// newest token), organization_id is its only authority-bearing provenance, and
// directory governance is sticky across token revocation.

import { describe, it, expect, vi } from 'vitest';

vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

const { resolveEnrollmentBasis } = await import('../../lib/scim/directory-anchor.js');

// Minimal supabase double: filters seeded rows by the accumulated eq/in state,
// supports per-table error injection, and is awaitable (thenable) like a
// PostgREST builder that terminates without .single().
function makeSupabase({ tokens = [], users = [], errors = {} }: any = {}): any {
  const seeded: any = { scim_provisioning_tokens: tokens, scim_users: users };
  function match(row: any, state: any): boolean {
    return Object.entries(state.eq).every(([k, v]: any[]) => row[k] === v)
      && Object.entries(state.in).every(([k, vals]: any[]) => vals.includes(row[k]));
  }
  function builder(table: string): any {
    const state: any = { eq: {}, in: {} };
    const b: any = {
      select() { return b; },
      eq(k: string, v: any) { state.eq[k] = v; return b; },
      in(k: string, v: any) { state.in[k] = v; return b; },
      then(resolve: any, reject: any) {
        try {
          if (errors[table]) return resolve({ data: null, error: errors[table] });
          const rows: any[] = (seeded[table] || []).filter((r: any) => match(r, state));
          return resolve({ data: rows, error: null });
        } catch (e) { return reject(e); }
      },
    };
    return b;
  }
  return { from: (t: string) => builder(t) };
}

describe('resolveEnrollmentBasis', () => {
  it('1: no tokens => operator_attested, hasDirectory false, raw storedApproverId', async () => {
    const sb: any = makeSupabase();
    const r: any = await resolveEnrollmentBasis(sb, 'org_x', 'ep:approver:JChen');
    expect(r).toMatchObject({
      basis: 'operator_attested',
      directoryUserId: null,
      storedApproverId: 'ep:approver:JChen',
      hasDirectory: false,
    });
    expect(r.error).toBeUndefined();
  });

  it('2: org-bound token + active match => directory, id pinned, normalized storedApproverId', async () => {
    const sb: any = makeSupabase({
      tokens: [{ organization_id: 'org_x', tenant_id: 't_x', revoked_at: null }],
      users: [{ id: 'su_1', tenant_id: 't_x', user_name: 'cfo@corp.com', active: true }],
    });
    const r: any = await resolveEnrollmentBasis(sb, 'org_x', 'cfo@corp.com');
    expect(r).toMatchObject({
      basis: 'directory',
      directoryUserId: 'su_1',
      storedApproverId: 'cfo@corp.com',
      hasDirectory: true,
    });
  });

  it('3: token + no matching user => 403 approver_not_provisioned', async () => {
    const sb: any = makeSupabase({
      tokens: [{ organization_id: 'org_x', tenant_id: 't_x', revoked_at: null }],
      users: [{ id: 'su_1', tenant_id: 't_x', user_name: 'someone@corp.com', active: true }],
    });
    const r: any = await resolveEnrollmentBasis(sb, 'org_x', 'cfo@corp.com');
    expect(r.error).toMatchObject({ status: 403, code: 'approver_not_provisioned' });
    expect(r.basis).toBeUndefined();
  });

  it('4: token + user active:false => 403 approver_not_provisioned', async () => {
    const sb: any = makeSupabase({
      tokens: [{ organization_id: 'org_x', tenant_id: 't_x', revoked_at: null }],
      users: [{ id: 'su_1', tenant_id: 't_x', user_name: 'cfo@corp.com', active: false }],
    });
    const r: any = await resolveEnrollmentBasis(sb, 'org_x', 'cfo@corp.com');
    expect(r.error).toMatchObject({ status: 403, code: 'approver_not_provisioned' });
  });

  it('5: normalization matches a lower-cased directory row and stores the normalized id', async () => {
    const sb: any = makeSupabase({
      tokens: [{ organization_id: 'org_x', tenant_id: 't_x', revoked_at: null }],
      users: [{ id: 'su_1', tenant_id: 't_x', user_name: 'cfo@corp.com', active: true }],
    });
    const r: any = await resolveEnrollmentBasis(sb, 'org_x', '  CFO@Corp.com  ');
    expect(r).toMatchObject({ basis: 'directory', storedApproverId: 'cfo@corp.com' });
  });

  it('6: multi-tenant — active user under the OLDER tenant is still found (set, not newest-single)', async () => {
    const sb: any = makeSupabase({
      tokens: [
        { organization_id: 'org_x', tenant_id: 't_old', revoked_at: null },
        { organization_id: 'org_x', tenant_id: 't_new', revoked_at: null },
      ],
      users: [{ id: 'su_old', tenant_id: 't_old', user_name: 'cfo@corp.com', active: true }],
    });
    const r: any = await resolveEnrollmentBasis(sb, 'org_x', 'cfo@corp.com');
    expect(r).toMatchObject({ basis: 'directory', directoryUserId: 'su_old' });
  });

  it('7: a legacy NULL organization never gains authority from a matching tenant slug', async () => {
    const sb: any = makeSupabase({
      tokens: [{ organization_id: null, tenant_id: 'org_x', revoked_at: null }],
      users: [{ id: 'su_1', tenant_id: 'org_x', user_name: 'cfo@corp.com', active: true }],
    });
    const r: any = await resolveEnrollmentBasis(sb, 'org_x', 'cfo@corp.com');
    expect(r).toMatchObject({
      basis: 'operator_attested',
      directoryUserId: null,
      hasDirectory: false,
    });
  });

  it('8: an attacker tenant slug matching a victim org cannot import attacker SCIM users', async () => {
    const sb: any = makeSupabase({
      tokens: [{
        organization_id: '@org:attacker',
        tenant_id: 'victim-org',
        revoked_at: null,
      }],
      users: [{
        id: 'attacker-user',
        tenant_id: 'victim-org',
        user_name: 'cfo@victim.example',
        active: true,
      }],
    });
    const r: any = await resolveEnrollmentBasis(sb, 'victim-org', 'cfo@victim.example');
    expect(r).toMatchObject({
      basis: 'operator_attested',
      directoryUserId: null,
      hasDirectory: false,
    });
  });

  it('9: a revoked legacy self-org token is not sticky authority for its squatted slug', async () => {
    const sb: any = makeSupabase({
      tokens: [{ organization_id: 'victim-org', tenant_id: 'victim-org', revoked_at: '2026-08-26T00:00:00Z' }],
      users: [{ id: 'attacker-user', tenant_id: 'victim-org', user_name: 'cfo@victim.example', active: true }],
    });
    await expect(resolveEnrollmentBasis(sb, 'victim-org', 'cfo@victim.example')).resolves.toMatchObject({
      basis: 'operator_attested',
      directoryUserId: null,
      hasDirectory: false,
    });
  });

  it('10: sticky — a REVOKED explicitly org-bound token still anchors; active user => directory, absent user => 403', async () => {
    const revokedToken: any[] = [{ organization_id: 'org_x', tenant_id: 't_x', revoked_at: '2020-01-01T00:00:00Z' }];

    const active: any = makeSupabase({
      tokens: revokedToken,
      users: [{ id: 'su_1', tenant_id: 't_x', user_name: 'cfo@corp.com', active: true }],
    });
    expect(await resolveEnrollmentBasis(active, 'org_x', 'cfo@corp.com'))
      .toMatchObject({ basis: 'directory', directoryUserId: 'su_1' });

    const absent: any = makeSupabase({ tokens: revokedToken, users: [] });
    expect((await resolveEnrollmentBasis(absent, 'org_x', 'cfo@corp.com')).error)
      .toMatchObject({ status: 403, code: 'approver_not_provisioned' });
  });

  it('11: token lookup error => 503 directory_lookup_failed (fail closed, never downgrade)', async () => {
    const sb: any = makeSupabase({ errors: { scim_provisioning_tokens: { message: 'db down' } } });
    const r: any = await resolveEnrollmentBasis(sb, 'org_x', 'cfo@corp.com');
    expect(r.error).toMatchObject({ status: 503, code: 'directory_lookup_failed' });
    expect(r.basis).toBeUndefined();
  });

  it('12: scim_users lookup error => 503 directory_lookup_failed', async () => {
    const sb: any = makeSupabase({
      tokens: [{ organization_id: 'org_x', tenant_id: 't_x', revoked_at: null }],
      errors: { scim_users: { message: 'db down' } },
    });
    const r: any = await resolveEnrollmentBasis(sb, 'org_x', 'cfo@corp.com');
    expect(r.error).toMatchObject({ status: 503, code: 'directory_lookup_failed' });
  });
});
