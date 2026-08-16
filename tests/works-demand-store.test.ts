// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';

import { createSupabaseAuthorityDemandStore } from '../lib/works/demand-store.ts';

describe('Supabase Authority Record demand store', () => {
  it('maps request creation to its narrow RPC without raw contact data', async () => {
    const rpc = vi.fn(async () => ({ data: { status: 'PENDING' }, error: null }));
    const store = createSupabaseAuthorityDemandStore({ rpc } as any);
    const result = await store.createRequest({
      record_id: 'authority-record-acme-agent',
      requester_digest: `hmac-sha256:${'a'.repeat(64)}`,
      organization_domain: 'one.example',
      verification_token_digest: `sha256:${'b'.repeat(64)}`,
      verification_expires_at: '2026-08-15T02:00:00.000Z',
      created_at: '2026-08-14T02:00:00.000Z',
    });
    expect(result).toEqual({ ok: true, status: 'PENDING' });
    expect(rpc).toHaveBeenCalledWith('create_works_authority_demand_request', {
      p_record_id: 'authority-record-acme-agent',
      p_requester_digest: `hmac-sha256:${'a'.repeat(64)}`,
      p_organization_domain: 'one.example',
      p_verification_token_digest: `sha256:${'b'.repeat(64)}`,
      p_verification_expires_at: '2026-08-15T02:00:00.000Z',
      p_created_at: '2026-08-14T02:00:00.000Z',
    });
    expect(JSON.stringify(rpc.mock.calls)).not.toContain('@');
  });

  it('returns exact verification counts and drops undeclared fields', async () => {
    const rpc = vi.fn(async () => ({
      data: {
        record_id: 'authority-record-acme-agent',
        verified_requesters: 2,
        verified_organizations: 2,
        owner_contact_route: 'mailto:owner@acme.example',
      },
      error: null,
    }));
    const result = await createSupabaseAuthorityDemandStore({ rpc } as any).verifyRequest({
      verification_token_digest: `sha256:${'b'.repeat(64)}`,
      verified_at: '2026-08-14T02:01:00.000Z',
    });
    expect(result).toEqual({
      ok: true,
      result: {
        record_id: 'authority-record-acme-agent',
        verified_requesters: 2,
        verified_organizations: 2,
      },
    });
  });

  it('maps unavailable verification tokens to a non-enumerating failure', async () => {
    const rpc = vi.fn(async () => ({ data: null, error: { code: 'AR004' } }));
    const result = await createSupabaseAuthorityDemandStore({ rpc } as any).verifyRequest({
      verification_token_digest: `sha256:${'b'.repeat(64)}`,
      verified_at: '2026-08-14T02:01:00.000Z',
    });
    expect(result).toEqual(expect.objectContaining({ ok: false, code: 'token_unavailable' }));
  });

  it('treats null count results as an unavailable public record', async () => {
    const rpc = vi.fn(async () => ({ data: null, error: null }));
    const result = await createSupabaseAuthorityDemandStore({ rpc } as any)
      .readCounts('authority-record-missing-agent');
    expect(result).toEqual(expect.objectContaining({ ok: false, code: 'record_unavailable' }));
  });
});
