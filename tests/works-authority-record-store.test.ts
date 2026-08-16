// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';

import { createSupabaseAuthorityRecordStore } from '../lib/works/authority-record-store.ts';

const RECORD_ID = 'authority-record-acme-agent';
const DIGEST = `sha256:${'a'.repeat(64)}`;
const TOKEN_DIGEST = `sha256:${'b'.repeat(64)}`;
const OWNER_DIGEST = `sha256:${'c'.repeat(64)}`;
const PROJECTION = {
  '@version': 'EMILIA-AUTHORITY-RECORD-v1',
  record_id: RECORD_ID,
  subject: { name: 'Acme', builder_name: 'Acme', repository_url: 'https://github.com/acme/agent' },
  provenance: {
    source_locator: 'https://github.com/acme/agent',
    watched_ref: 'refs/heads/main',
    resolved_revision: 'a'.repeat(40),
    artifact_digest: DIGEST,
    observed_at: '2026-08-13T00:00:00.000Z',
    expires_at: '2026-09-13T00:00:00.000Z',
    scanner: { name: '@emilia-protocol/scan', version: '0.1.0', profile_digest: DIGEST },
  },
  surfaces: [{
    surface_id: 'merge-code', label: 'Merge code', action_class: 'code_change',
    consequence_class: 'code', evidence_status: 'OBSERVED', enforcement_status: 'NOT_ASSESSED',
  }],
  owner_statement: null,
  claim_boundary: 'versioned_public_authority_mapping_not_certification_not_safety_rating_not_complete_mediation',
} as any;

function client(data: unknown = {}, error: unknown = null) {
  return { rpc: vi.fn(async () => ({ data, error })) };
}

describe('Supabase Authority Record store adapter', () => {
  it('maps draft creation to the atomic RPC without exposing raw credentials', async () => {
    const db = client({ record_id: RECORD_ID });
    const store = createSupabaseAuthorityRecordStore(db as any);
    const result = await store.createDraft({
      record_id: RECORD_ID,
      record_digest: DIGEST,
      projection: PROJECTION,
      repository_url: 'https://github.com/acme/agent',
      contact_route: 'mailto:owner@acme.example',
      created_by_entity_id: '11111111-1111-4111-8111-111111111111',
      invitation_token_digest: TOKEN_DIGEST,
      claim_challenge: `claim_${'d'.repeat(48)}`,
      invitation_expires_at: '2026-08-21T00:00:00.000Z',
    });
    expect(result.ok).toBe(true);
    expect(db.rpc).toHaveBeenCalledWith('create_works_authority_record_draft', {
      p_record_id: RECORD_ID,
      p_record_digest: DIGEST,
      p_projection: PROJECTION,
      p_repository_url: 'https://github.com/acme/agent',
      p_contact_route: 'mailto:owner@acme.example',
      p_created_by_entity_id: '11111111-1111-4111-8111-111111111111',
      p_invitation_token_digest: TOKEN_DIGEST,
      p_claim_challenge: `claim_${'d'.repeat(48)}`,
      p_invitation_expires_at: '2026-08-21T00:00:00.000Z',
    });
    expect(JSON.stringify(db.rpc.mock.calls)).not.toContain('ari1_');
    expect(JSON.stringify(db.rpc.mock.calls)).not.toContain('aro1_');
  });

  it('normalizes invitation and owner-state rows and never returns token digests in state', async () => {
    const invitationDb = client({
      record_id: RECORD_ID,
      record_digest: DIGEST,
      projection: PROJECTION,
      repository_url: 'https://github.com/acme/agent',
      contact_route: 'mailto:owner@acme.example',
      claim_challenge: `claim_${'d'.repeat(48)}`,
      invitation_expires_at: '2026-08-21T00:00:00.000Z',
      claimed_at: null,
    });
    const invitation = await createSupabaseAuthorityRecordStore(invitationDb as any)
      .inspectInvitation(TOKEN_DIGEST);
    expect(invitation).toMatchObject({ ok: true, invitation: { record_id: RECORD_ID } });

    const ownerDb = client({
      record_id: RECORD_ID,
      current_version: 2,
      current_digest: DIGEST,
      current_projection: PROJECTION,
      repository_url: 'https://github.com/acme/agent',
      status: 'CLAIMED_PRIVATE',
      approved_at: null,
      withdrawn_at: null,
    });
    const owner = await createSupabaseAuthorityRecordStore(ownerDb as any)
      .readOwnerState(RECORD_ID, OWNER_DIGEST);
    expect(owner).toMatchObject({ ok: true, state: { record_id: RECORD_ID, current_version: 2 } });
    expect(JSON.stringify(owner)).not.toContain(OWNER_DIGEST);
  });

  it('passes credentials only as digests to atomic claim, revise, approve, and withdraw RPCs', async () => {
    const state = {
      record_id: RECORD_ID,
      current_version: 1,
      current_digest: DIGEST,
      current_projection: PROJECTION,
      repository_url: 'https://github.com/acme/agent',
      status: 'CLAIMED_PRIVATE',
      approved_at: null,
      withdrawn_at: null,
    };
    const db = client(state);
    const store = createSupabaseAuthorityRecordStore(db as any);
    await store.claimInvitation({
      invitation_token_digest: TOKEN_DIGEST,
      owner_token_digest: OWNER_DIGEST,
      proof_url: `https://raw.githubusercontent.com/acme/agent/${'a'.repeat(40)}/.well-known/emilia-authority-record.json`,
      proof_revision: 'a'.repeat(40),
      proof_digest: DIGEST,
      claimed_at: '2026-08-14T00:00:00.000Z',
    });
    await store.appendOwnerVersion({
      record_id: RECORD_ID, owner_token_digest: OWNER_DIGEST, record_digest: DIGEST,
      projection: PROJECTION, created_at: '2026-08-14T00:01:00.000Z',
    });
    await store.approveOwnerVersion({
      record_id: RECORD_ID, owner_token_digest: OWNER_DIGEST, record_digest: DIGEST,
      approved_at: '2026-08-14T00:02:00.000Z',
    });
    await store.withdrawOwnerRecord({
      record_id: RECORD_ID, owner_token_digest: OWNER_DIGEST,
      withdrawn_at: '2026-08-14T00:03:00.000Z',
    });
    expect(db.rpc.mock.calls.map((call) => call[0])).toEqual([
      'claim_works_authority_record',
      'append_works_authority_record_version',
      'approve_works_authority_record_version',
      'withdraw_works_authority_record',
    ]);
    expect(JSON.stringify(db.rpc.mock.calls)).not.toContain('ari1_');
    expect(JSON.stringify(db.rpc.mock.calls)).not.toContain('aro1_');
  });

  it('fails closed on RPC errors and malformed returned state', async () => {
    const failed = await createSupabaseAuthorityRecordStore(client(null, { code: '42501' }) as any)
      .readPublicRecord(RECORD_ID);
    expect(failed).toEqual({ ok: false, code: 'store_unavailable', detail: 'Authority Record storage is unavailable.' });

    const malformed = await createSupabaseAuthorityRecordStore(client({ record_id: RECORD_ID }) as any)
      .readPublicRecord(RECORD_ID);
    expect(malformed).toEqual({ ok: false, code: 'store_invalid', detail: 'Authority Record storage returned invalid data.' });
  });

  it('fails closed when the RPC transport throws', async () => {
    const db = { rpc: vi.fn(async () => { throw new Error('database unavailable'); }) };
    await expect(createSupabaseAuthorityRecordStore(db as any).readPublicRecord(RECORD_ID))
      .resolves.toEqual({
        ok: false, code: 'store_unavailable', detail: 'Authority Record storage is unavailable.',
      });
  });

  it('normalizes empty and populated public listings and rejects malformed lists', async () => {
    await expect(createSupabaseAuthorityRecordStore(client(null) as any).readPublicRecord(RECORD_ID))
      .resolves.toEqual({ ok: true, record: null });
    await expect(createSupabaseAuthorityRecordStore(client(null) as any).inspectInvitation(TOKEN_DIGEST))
      .resolves.toEqual({ ok: true, invitation: null });

    const validRow = {
      record_id: RECORD_ID,
      version: 1,
      record_digest: DIGEST,
      approved_at: '2026-08-14T00:00:00.000Z',
      projection: PROJECTION,
    };
    await expect(createSupabaseAuthorityRecordStore(client([validRow]) as any).listPublicRecords())
      .resolves.toEqual({ ok: true, records: [validRow] });
    await expect(createSupabaseAuthorityRecordStore(client({}) as any).listPublicRecords())
      .resolves.toMatchObject({ ok: false, code: 'store_invalid' });
    await expect(createSupabaseAuthorityRecordStore(client([{ record_id: RECORD_ID }]) as any)
      .listPublicRecords()).resolves.toMatchObject({ ok: false, code: 'store_invalid' });
  });
});
