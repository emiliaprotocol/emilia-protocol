// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  AuthorityRecordServiceError,
  approveAuthorityRecord,
  claimAuthorityRecord,
  createAuthorityRecordDraft,
  getOwnerAuthorityRecord,
  getPublicAuthorityRecord,
  listPublicAuthorityRecords,
  reviseAuthorityRecord,
  withdrawAuthorityRecord,
  __authorityRecordServiceInternals,
  type AuthorityRecordStore,
  type StoredAuthorityInvitation,
  type StoredAuthorityOwnerState,
} from '../lib/works/authority-record-service.ts';
import {
  authorityRecordDigest,
  buildAuthorityClaimProof,
  validateAuthorityRecordProjection,
} from '../lib/works/authority-record.ts';

const NOW = Date.parse('2026-08-14T00:00:00.000Z');
const REPO = 'https://github.com/acme/agent';
const REVISION = 'a'.repeat(40);
const ADMIN_ID = '11111111-1111-4111-8111-111111111111';

function projection(overrides: Record<string, unknown> = {}) {
  return {
    '@version': 'EMILIA-AUTHORITY-RECORD-v1',
    record_id: 'authority-record-acme-agent',
    subject: {
      name: 'Acme Agent',
      builder_name: 'Acme Labs',
      repository_url: REPO,
    },
    provenance: {
      source_locator: REPO,
      watched_ref: 'refs/heads/main',
      resolved_revision: REVISION,
      artifact_digest: `sha256:${'a'.repeat(64)}`,
      observed_at: '2026-08-13T20:00:00.000Z',
      expires_at: '2026-09-12T20:00:00.000Z',
      scanner: {
        name: '@emilia-protocol/scan',
        version: '0.1.0',
        profile_digest: `sha256:${'b'.repeat(64)}`,
      },
    },
    surfaces: [{
      surface_id: 'github-merge',
      label: 'Merge a commit',
      action_class: 'code_change',
      consequence_class: 'code',
      evidence_status: 'OBSERVED',
      enforcement_status: 'NOT_ASSESSED',
    }],
    owner_statement: null,
    claim_boundary:
      'versioned_public_authority_mapping_not_certification_not_safety_rating_not_complete_mediation',
    ...overrides,
  };
}

class MemoryStore implements AuthorityRecordStore {
  invitations = new Map<string, StoredAuthorityInvitation>();
  owners = new Map<string, StoredAuthorityOwnerState>();
  published = new Map<string, any>();
  rawTokenSeen = false;

  async createDraft(input: any) {
    this.rawTokenSeen = JSON.stringify(input).includes('ari1_');
    if ([...this.invitations.values()].some((item) => item.record_id === input.record_id)) {
      return { ok: false as const, code: 'already_exists', detail: 'already exists' };
    }
    this.invitations.set(input.invitation_token_digest, {
      record_id: input.record_id,
      record_digest: input.record_digest,
      projection: input.projection,
      repository_url: input.repository_url,
      contact_route: input.contact_route,
      claim_challenge: input.claim_challenge,
      invitation_expires_at: input.invitation_expires_at,
      claimed_at: null,
    });
    return { ok: true as const };
  }

  async inspectInvitation(tokenDigest: string) {
    const invitation = this.invitations.get(tokenDigest) ?? null;
    return { ok: true as const, invitation };
  }

  async claimInvitation(input: any) {
    const invitation = this.invitations.get(input.invitation_token_digest);
    if (!invitation || invitation.claimed_at) {
      return { ok: false as const, code: 'invitation_unavailable', detail: 'unavailable' };
    }
    invitation.claimed_at = input.claimed_at;
    const owner = {
      record_id: invitation.record_id,
      owner_token_digest: input.owner_token_digest,
      current_version: 1,
      current_digest: invitation.record_digest,
      current_projection: invitation.projection,
      repository_url: invitation.repository_url,
      status: 'CLAIMED_PRIVATE' as const,
      approved_at: null,
      withdrawn_at: null,
    };
    this.owners.set(owner.record_id, owner);
    return { ok: true as const, state: owner };
  }

  async readOwnerState(recordId: string, ownerTokenDigest: string) {
    const state = this.owners.get(recordId);
    return {
      ok: true as const,
      state: state?.owner_token_digest === ownerTokenDigest ? state : null,
    };
  }

  async appendOwnerVersion(input: any) {
    const state = this.owners.get(input.record_id);
    if (!state || state.owner_token_digest !== input.owner_token_digest) {
      return { ok: false as const, code: 'owner_credential_invalid', detail: 'invalid' };
    }
    state.current_version += 1;
    state.current_digest = input.record_digest;
    state.current_projection = input.projection;
    state.status = 'CLAIMED_PRIVATE';
    state.approved_at = null;
    this.published.delete(input.record_id);
    return { ok: true as const, state: { ...state } };
  }

  async approveOwnerVersion(input: any) {
    const state = this.owners.get(input.record_id);
    if (!state || state.owner_token_digest !== input.owner_token_digest) {
      return { ok: false as const, code: 'owner_credential_invalid', detail: 'invalid' };
    }
    if (state.current_digest !== input.record_digest) {
      return { ok: false as const, code: 'record_digest_mismatch', detail: 'mismatch' };
    }
    state.status = 'PUBLISHED';
    state.approved_at = input.approved_at;
    state.withdrawn_at = null;
    this.published.set(input.record_id, {
      record_id: input.record_id,
      version: state.current_version,
      record_digest: state.current_digest,
      approved_at: input.approved_at,
      projection: state.current_projection,
    });
    return { ok: true as const, state: { ...state } };
  }

  async withdrawOwnerRecord(input: any) {
    const state = this.owners.get(input.record_id);
    if (!state || state.owner_token_digest !== input.owner_token_digest) {
      return { ok: false as const, code: 'owner_credential_invalid', detail: 'invalid' };
    }
    state.status = 'WITHDRAWN';
    state.withdrawn_at = input.withdrawn_at;
    this.published.delete(input.record_id);
    return { ok: true as const, state: { ...state } };
  }

  async readPublicRecord(recordId: string) {
    return { ok: true as const, record: this.published.get(recordId) ?? null };
  }

  async listPublicRecords() {
    return { ok: true as const, records: [...this.published.values()] };
  }
}

function responseForProof(proof: unknown, init: ResponseInit = {}) {
  return new Response(JSON.stringify(proof), {
    status: 200,
    headers: { 'content-type': 'application/json', 'content-length': String(JSON.stringify(proof).length) },
    ...init,
  });
}

async function draft(store: MemoryStore) {
  return createAuthorityRecordDraft({
    actor: { entityId: ADMIN_ID, isAdmin: true },
    input: { projection: projection(), contact_route: 'mailto:owner@acme.example' },
    store,
    now: NOW,
    randomBytes: (size) => Buffer.alloc(size, 7),
    siteOrigin: 'https://www.emiliaprotocol.ai',
  });
}

async function claim(store: MemoryStore, invitation: Awaited<ReturnType<typeof draft>>) {
  const proof = buildAuthorityClaimProof({
    challenge: invitation.claim_challenge,
    recordDigest: invitation.record_digest,
    repositoryUrl: REPO,
    expiresAt: invitation.invitation_expires_at,
  });
  return claimAuthorityRecord({
    input: {
      invitation_token: invitation.invitation_token,
      proof_url:
        `https://raw.githubusercontent.com/acme/agent/${REVISION}/.well-known/emilia-authority-record.json`,
    },
    store,
    fetchImpl: vi.fn(async () => responseForProof(proof)),
    now: NOW + 60_000,
    randomBytes: (size) => Buffer.alloc(size, 9),
  });
}

describe('Authority Record consent lifecycle', () => {
  let store: MemoryStore;

  beforeEach(() => {
    store = new MemoryStore();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('lets only an authenticated admin prepare a private draft and one-time invitation', async () => {
    await expect(createAuthorityRecordDraft({
      actor: { entityId: ADMIN_ID, isAdmin: false },
      input: { projection: projection(), contact_route: 'mailto:owner@acme.example' },
      store,
      now: NOW,
    })).rejects.toMatchObject({ status: 403, code: 'authority_record_admin_required' });

    const result = await draft(store);
    expect(result).toMatchObject({
      record_id: 'authority-record-acme-agent',
      record_digest: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      invitation_token: expect.stringMatching(/^ari1_[0-9a-f]{64}$/),
      claim_challenge: expect.stringMatching(/^claim_[A-Za-z0-9_-]{32,96}$/),
      claim_url: expect.stringMatching(/^https:\/\/www\.emiliaprotocol\.ai\/works\/claim#/),
    });
    expect(store.rawTokenSeen).toBe(false);
    expect([...store.invitations.keys()][0]).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(JSON.stringify([...store.invitations.values()])).not.toContain(result.invitation_token);
  });

  it('refuses invalid draft boundaries before exposing an invitation', async () => {
    await expect(createAuthorityRecordDraft({
      actor: { entityId: ADMIN_ID, isAdmin: true },
      input: { projection: projection(), contact_route: 'owner@acme.example' },
      store: new MemoryStore(), now: NOW,
    })).rejects.toMatchObject({ status: 400, code: 'authority_record_contact_invalid' });

    await expect(createAuthorityRecordDraft({
      actor: { entityId: ADMIN_ID, isAdmin: true },
      input: {
        projection: projection({
          provenance: { ...projection().provenance, observed_at: '2026-08-15T00:00:00.000Z' },
        }),
        contact_route: 'mailto:owner@acme.example',
      },
      store: new MemoryStore(), now: NOW,
    })).rejects.toMatchObject({ status: 400, code: 'authority_record_observation_invalid' });

    await expect(createAuthorityRecordDraft({
      actor: { entityId: ADMIN_ID, isAdmin: true },
      input: { projection: projection(), contact_route: 'mailto:owner@acme.example' },
      store: new MemoryStore(), now: NOW,
      randomBytes: (size) => Buffer.alloc(size - 1),
    })).rejects.toMatchObject({ status: 503, code: 'authority_record_randomness_unavailable' });

    let calls = 0;
    await expect(createAuthorityRecordDraft({
      actor: { entityId: ADMIN_ID, isAdmin: true },
      input: { projection: projection(), contact_route: 'mailto:owner@acme.example' },
      store: new MemoryStore(), now: NOW,
      randomBytes: (size) => Buffer.alloc(++calls === 1 ? size : size - 1),
    })).rejects.toMatchObject({ status: 503, code: 'authority_record_randomness_unavailable' });

    await expect(createAuthorityRecordDraft({
      actor: { entityId: ADMIN_ID, isAdmin: true },
      input: { projection: projection(), contact_route: 'mailto:owner@acme.example' },
      store: new MemoryStore(), now: NOW, randomBytes: (size) => Buffer.alloc(size, 7),
      siteOrigin: 'http://www.emiliaprotocol.ai?unsafe=1',
    })).rejects.toMatchObject({ status: 503, code: 'authority_record_origin_unavailable' });
  });

  it('maps store failures to stable public errors without leaking storage details', async () => {
    for (const [failure, expected] of [
      [{ ok: false, code: 'already_exists', detail: 'row conflict' }, 'authority_record_already_exists'],
      [{ ok: false, code: 'storage_offline', detail: 'database detail' }, 'authority_record_store_unavailable'],
    ] as const) {
      const failingStore = new MemoryStore();
      failingStore.createDraft = vi.fn(async () => failure as any);
      await expect(createAuthorityRecordDraft({
        actor: { entityId: ADMIN_ID, isAdmin: true },
        input: { projection: projection(), contact_route: 'mailto:owner@acme.example' },
        store: failingStore, now: NOW, randomBytes: (size) => Buffer.alloc(size, 7),
      })).rejects.toMatchObject({ code: expected });
    }
  });

  it('does not publish an unclaimed private scan', async () => {
    const invitation = await draft(store);
    expect(await getPublicAuthorityRecord({ recordId: invitation.record_id, store, now: NOW }))
      .toBeNull();
  });

  it('requires immutable GitHub repository control and returns the owner credential once', async () => {
    const invitation = await draft(store);
    const result = await claim(store, invitation);
    expect(result).toMatchObject({
      record_id: invitation.record_id,
      owner_token: expect.stringMatching(/^aro1_[0-9a-f]{64}$/),
      status: 'CLAIMED_PRIVATE',
    });
    expect(JSON.stringify(store.owners.get(invitation.record_id))).not.toContain(result.owner_token);
    expect(await getPublicAuthorityRecord({ recordId: invitation.record_id, store, now: NOW }))
      .toBeNull();

    await expect(claim(store, invitation)).rejects.toMatchObject({
      status: 409, code: 'authority_record_invitation_unavailable',
    });
  });

  it('refuses redirects, forks, moving refs, oversized proof, and mismatched bytes', async () => {
    const invitation = await draft(store);
    const validProof = buildAuthorityClaimProof({
      challenge: invitation.claim_challenge,
      recordDigest: invitation.record_digest,
      repositoryUrl: REPO,
      expiresAt: invitation.invitation_expires_at,
    });
    const base = {
      input: {
        invitation_token: invitation.invitation_token,
        proof_url: `https://raw.githubusercontent.com/acme/agent/${REVISION}/.well-known/emilia-authority-record.json`,
      },
      store,
      now: NOW + 60_000,
    };

    for (const [name, proofUrl, response] of [
      ['redirect', base.input.proof_url, new Response('', { status: 302, headers: { location: 'https://evil.example' } })],
      ['fork', `https://raw.githubusercontent.com/evil/fork/${REVISION}/.well-known/emilia-authority-record.json`, responseForProof(validProof)],
      ['moving', 'https://raw.githubusercontent.com/acme/agent/main/.well-known/emilia-authority-record.json', responseForProof(validProof)],
      ['oversized', base.input.proof_url, new Response('x'.repeat(70_000), { status: 200, headers: { 'content-length': '70000' } })],
      ['mismatch', base.input.proof_url, responseForProof({ ...validProof, record_digest: `sha256:${'f'.repeat(64)}` })],
    ] as const) {
      await expect(claimAuthorityRecord({
        ...base,
        input: { ...base.input, proof_url: proofUrl },
        fetchImpl: vi.fn(async () => response),
      }), name).rejects.toBeInstanceOf(AuthorityRecordServiceError);
    }
  });

  it('fails closed on malformed claim inputs and unreadable proof bytes', async () => {
    const invitation = await draft(store);
    const proofUrl =
      `https://raw.githubusercontent.com/acme/agent/${REVISION}/.well-known/emilia-authority-record.json`;

    await expect(claimAuthorityRecord({
      input: { invitation_token: 'bad', proof_url: proofUrl }, store, now: NOW,
    })).rejects.toMatchObject({ status: 400, code: 'authority_record_invitation_invalid' });
    await expect(claimAuthorityRecord({
      input: { invitation_token: invitation.invitation_token, proof_url: 'not-a-url' },
      store, now: NOW,
    })).rejects.toMatchObject({ status: 400, code: 'authority_record_proof_url_invalid' });

    for (const fetchImpl of [
      vi.fn(async () => { throw new Error('offline'); }),
      vi.fn(async () => new Response('not-json', { status: 200 })),
      vi.fn(async () => new Response('x'.repeat(70_000), { status: 200 })),
    ]) {
      await expect(claimAuthorityRecord({
        input: { invitation_token: invitation.invitation_token, proof_url: proofUrl },
        store, fetchImpl: fetchImpl as any, now: NOW + 60_000,
      })).rejects.toBeInstanceOf(AuthorityRecordServiceError);
    }
  });

  it('creates immutable correction versions and publishes only exact owner-approved bytes', async () => {
    const invitation = await draft(store);
    const claimed = await claim(store, invitation);
    const corrected = projection({
      owner_statement: { status: 'SELLER_ASSERTED', statement: 'The owner reviewed this mapping.' },
    });
    const revised = await reviseAuthorityRecord({
      recordId: invitation.record_id,
      ownerToken: claimed.owner_token,
      projection: corrected,
      store,
      now: NOW + 120_000,
    });
    expect(revised.version).toBe(2);
    expect(revised.record_digest).not.toBe(invitation.record_digest);
    expect(await getPublicAuthorityRecord({ recordId: invitation.record_id, store, now: NOW }))
      .toBeNull();

    await expect(approveAuthorityRecord({
      recordId: invitation.record_id,
      ownerToken: claimed.owner_token,
      recordDigest: invitation.record_digest,
      store,
      now: NOW + 180_000,
    })).rejects.toMatchObject({ status: 409, code: 'authority_record_digest_mismatch' });

    const approved = await approveAuthorityRecord({
      recordId: invitation.record_id,
      ownerToken: claimed.owner_token,
      recordDigest: revised.record_digest,
      store,
      now: NOW + 180_000,
    });
    expect(approved).toMatchObject({ status: 'PUBLISHED', version: 2 });
    expect(await getPublicAuthorityRecord({
      recordId: invitation.record_id, store, now: NOW + 180_001,
    })).toMatchObject({
      record_digest: revised.record_digest,
      projection: { owner_statement: { status: 'SELLER_ASSERTED' } },
    });

    await expect(approveAuthorityRecord({
      recordId: invitation.record_id,
      ownerToken: claimed.owner_token,
      recordDigest: 'not-a-digest',
      store,
      now: NOW + 180_000,
    })).rejects.toMatchObject({ status: 400, code: 'authority_record_digest_invalid' });
  });

  it('does not let corrections pivot the claimed repository or record id', async () => {
    const invitation = await draft(store);
    const claimed = await claim(store, invitation);
    for (const changed of [
      projection({ record_id: 'authority-record-attacker-agent' }),
      projection({
        subject: { ...projection().subject, repository_url: 'https://github.com/evil/fork' },
        provenance: { ...projection().provenance, source_locator: 'https://github.com/evil/fork' },
      }),
    ]) {
      await expect(reviseAuthorityRecord({
        recordId: invitation.record_id,
        ownerToken: claimed.owner_token,
        projection: changed,
        store,
        now: NOW + 120_000,
      })).rejects.toMatchObject({ status: 400 });
    }
  });

  it('withdrawal immediately removes the public projection and wrong credentials reveal nothing', async () => {
    const invitation = await draft(store);
    const claimed = await claim(store, invitation);
    await approveAuthorityRecord({
      recordId: invitation.record_id,
      ownerToken: claimed.owner_token,
      recordDigest: invitation.record_digest,
      store,
      now: NOW + 180_000,
    });
    expect(await getPublicAuthorityRecord({ recordId: invitation.record_id, store, now: NOW + 1 }))
      .not.toBeNull();

    await expect(withdrawAuthorityRecord({
      recordId: invitation.record_id,
      ownerToken: `aro1_${'0'.repeat(64)}`,
      store,
      now: NOW + 240_000,
    })).rejects.toMatchObject({ status: 404, code: 'authority_record_not_found' });

    await withdrawAuthorityRecord({
      recordId: invitation.record_id,
      ownerToken: claimed.owner_token,
      store,
      now: NOW + 240_000,
    });
    expect(await getPublicAuthorityRecord({ recordId: invitation.record_id, store, now: NOW + 240_001 }))
      .toBeNull();
  });

  it('rejects malformed owner credentials before consulting storage', async () => {
    const readOwnerState = vi.spyOn(store, 'readOwnerState');
    await expect(getOwnerAuthorityRecord({
      recordId: 'authority-record-acme-agent', ownerToken: 'not-an-owner-token', store,
    })).rejects.toMatchObject({ status: 404, code: 'authority_record_not_found' });
    expect(readOwnerState).not.toHaveBeenCalled();
  });

  it('hides expired projections even if a stale database row still says published', async () => {
    const invitation = await draft(store);
    const claimed = await claim(store, invitation);
    await approveAuthorityRecord({
      recordId: invitation.record_id,
      ownerToken: claimed.owner_token,
      recordDigest: invitation.record_digest,
      store,
      now: NOW + 180_000,
    });
    expect(await getPublicAuthorityRecord({
      recordId: invitation.record_id,
      store,
      now: Date.parse('2026-10-01T00:00:00.000Z'),
    })).toBeNull();
  });

  it('lists only current public records and refuses inconsistent stored rows', async () => {
    const invitation = await draft(store);
    const claimed = await claim(store, invitation);
    await approveAuthorityRecord({
      recordId: invitation.record_id,
      ownerToken: claimed.owner_token,
      recordDigest: invitation.record_digest,
      store,
      now: NOW + 180_000,
    });

    await expect(listPublicAuthorityRecords({ store, now: NOW + 180_001 }))
      .resolves.toHaveLength(1);
    await expect(listPublicAuthorityRecords({
      store, now: Date.parse('2026-10-01T00:00:00.000Z'),
    })).resolves.toEqual([]);

    const corruptStore = new MemoryStore();
    corruptStore.listPublicRecords = vi.fn(async () => ({
      ok: true as const,
      records: [{
        record_id: invitation.record_id,
        version: 0,
        record_digest: invitation.record_digest,
        approved_at: 'not-a-time',
        projection: projection(),
      }],
    }));
    await expect(listPublicAuthorityRecords({ store: corruptStore }))
      .rejects.toMatchObject({ status: 503, code: 'authority_record_store_invalid' });

    expect(__authorityRecordServiceInternals.invitationTokenDigest(invitation.invitation_token))
      .toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(__authorityRecordServiceInternals.ownerTokenDigest(claimed.owner_token))
      .toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(__authorityRecordServiceInternals.parseRawProofUrl(
      `https://user:password@raw.githubusercontent.com/acme/agent/${REVISION}/.well-known/emilia-authority-record.json`,
    )).toBeNull();
  });
});
