// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';

import {
  DemandServiceError,
  createAuthorityRecordDemandRequest,
  readAuthorityRecordDemandCounts,
  verifyAuthorityRecordDemandRequest,
  type AuthorityDemandStore,
} from '../lib/works/demand-service.ts';

const RECORD_ID = 'authority-record-acme-agent';
const NOW = Date.parse('2026-08-14T02:00:00.000Z');

class DemandStore implements AuthorityDemandStore {
  created: any = null;
  rawEmailSeen = false;
  createStatus: 'PENDING' | 'ALREADY_VERIFIED' = 'PENDING';
  async createRequest(input: any) {
    this.created = input;
    this.rawEmailSeen = JSON.stringify(input).includes('@');
    return { ok: true as const, status: this.createStatus };
  }
  async verifyRequest(input: any) {
    if (input.verification_token_digest !== this.created?.verification_token_digest) {
      return { ok: false as const, code: 'not_found', detail: 'not found' };
    }
    return {
      ok: true as const,
      result: {
        record_id: RECORD_ID,
        verified_requesters: 1,
        verified_organizations: 1,
        owner_contact_route: 'mailto:owner@acme.example',
      },
    };
  }
  async readCounts() {
    return { ok: true as const, counts: { verified_requesters: 1, verified_organizations: 1 } };
  }
}

describe('verified Authority Record demand service', () => {
  it('stores keyed identity and token digests, never the raw email or token', async () => {
    const store = new DemandStore();
    const sendEmail = vi.fn(async () => ({ delivered: true }));
    const result = await createAuthorityRecordDemandRequest({
      input: { record_id: RECORD_ID, email: 'Person@One.Example' },
      store,
      hmacKey: 'd'.repeat(64),
      siteOrigin: 'https://www.emiliaprotocol.ai',
      now: NOW,
      randomBytes: (size) => Buffer.alloc(size, 6),
      sendEmail,
    });
    expect(result).toEqual({ accepted: true, verification_sent: true });
    expect(store.created.requester_digest).toMatch(/^hmac-sha256:[0-9a-f]{64}$/);
    expect(store.created.organization_domain).toBe('one.example');
    expect(store.created.verification_token_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(store.rawEmailSeen).toBe(false);
    expect(sendEmail).toHaveBeenCalledWith(expect.objectContaining({
      to: 'person@one.example',
      verifyUrl: expect.stringMatching(/^https:\/\/www\.emiliaprotocol\.ai\/works\/request\/verify#ardv1_/),
    }));
    expect(JSON.stringify(store.created)).not.toContain('ardv1_');
  });

  it('fails closed when the demand HMAC key is absent or weak', async () => {
    for (const hmacKey of ['', 'short']) {
      await expect(createAuthorityRecordDemandRequest({
        input: { record_id: RECORD_ID, email: 'person@one.example' },
        store: new DemandStore(), hmacKey, now: NOW,
      })).rejects.toMatchObject({ status: 503, code: 'authority_demand_unavailable' });
    }
  });

  it('refuses malformed identity, time, randomness, and callback origins', async () => {
    for (const email of [
      null,
      'missing-at.example',
      'person@two@one.example',
      'person@localhost',
      `x${'a'.repeat(65)}@one.example`,
    ]) {
      await expect(createAuthorityRecordDemandRequest({
        input: { record_id: RECORD_ID, email }, store: new DemandStore(),
        hmacKey: 'd'.repeat(64), now: NOW,
      })).rejects.toMatchObject({ status: 400, code: 'authority_demand_email_invalid' });
    }
    await expect(createAuthorityRecordDemandRequest({
      input: { record_id: RECORD_ID, email: 'person@one.example' },
      store: new DemandStore(), hmacKey: 'd'.repeat(64), now: Number.NaN,
    })).rejects.toMatchObject({ status: 400, code: 'authority_demand_time_invalid' });
    await expect(createAuthorityRecordDemandRequest({
      input: { record_id: RECORD_ID, email: 'person@one.example' },
      store: new DemandStore(), hmacKey: 'd'.repeat(64), now: NOW,
      randomBytes: () => Buffer.alloc(31),
    })).rejects.toMatchObject({ status: 503, code: 'authority_demand_unavailable' });
    await expect(createAuthorityRecordDemandRequest({
      input: { record_id: RECORD_ID, email: 'person@one.example' },
      store: new DemandStore(), hmacKey: 'd'.repeat(64), now: NOW,
      randomBytes: (size) => Buffer.alloc(size, 6),
      siteOrigin: 'http://www.emiliaprotocol.ai',
      sendEmail: vi.fn(async () => ({ delivered: true })),
    })).resolves.toEqual({ accepted: true, verification_sent: false });
  });

  it('returns a generic acceptance even when mail delivery is unavailable', async () => {
    const result = await createAuthorityRecordDemandRequest({
      input: { record_id: RECORD_ID, email: 'person@one.example' },
      store: new DemandStore(), hmacKey: 'd'.repeat(64), now: NOW,
      randomBytes: (size) => Buffer.alloc(size, 6),
      sendEmail: vi.fn(async () => ({ delivered: false })),
    });
    expect(result).toEqual({ accepted: true, verification_sent: false });
    expect(result).not.toHaveProperty('exists');
  });

  it('does not issue an unusable verification email for an already-verified requester', async () => {
    const store = new DemandStore();
    store.createStatus = 'ALREADY_VERIFIED';
    const sendEmail = vi.fn(async () => ({ delivered: true }));
    const result = await createAuthorityRecordDemandRequest({
      input: { record_id: RECORD_ID, email: 'person@one.example' },
      store, hmacKey: 'd'.repeat(64), now: NOW,
      randomBytes: (size) => Buffer.alloc(size, 6), sendEmail,
    });
    expect(result).toEqual({ accepted: true, verification_sent: false });
    expect(sendEmail).not.toHaveBeenCalled();
  });

  it('verifies the one-time token and returns exact requester and organization counts without calling them buyers', async () => {
    const store = new DemandStore();
    const created = await createAuthorityRecordDemandRequest({
      input: { record_id: RECORD_ID, email: 'person@one.example' },
      store, hmacKey: 'd'.repeat(64), now: NOW,
      randomBytes: (size) => Buffer.alloc(size, 6),
    });
    expect(created.accepted).toBe(true);
    const token = `ardv1_${Buffer.alloc(32, 6).toString('hex')}`;
    const result = await verifyAuthorityRecordDemandRequest({ token, store, now: NOW + 60_000 });
    expect(result).toEqual({
      record_id: RECORD_ID, verified_requesters: 1, verified_organizations: 1,
    });
    expect(result).not.toHaveProperty('buyers');
    expect(result).not.toHaveProperty('purchasers');
  });

  it('does not reveal whether a malformed or unknown token ever existed', async () => {
    for (const token of ['bad', `ardv1_${'f'.repeat(64)}`]) {
      await expect(verifyAuthorityRecordDemandRequest({
        token, store: new DemandStore(), now: NOW,
      })).rejects.toBeInstanceOf(DemandServiceError);
    }
  });

  it('maps store failures without disclosing whether a requester or record exists', async () => {
    for (const [code, expected] of [
      ['record_unavailable', 'authority_record_not_found'],
      ['storage_offline', 'authority_demand_unavailable'],
    ] as const) {
      const failingStore = new DemandStore();
      failingStore.createRequest = vi.fn(async () => ({ ok: false as const, code, detail: 'private' }));
      await expect(createAuthorityRecordDemandRequest({
        input: { record_id: RECORD_ID, email: 'person@one.example' },
        store: failingStore, hmacKey: 'd'.repeat(64), now: NOW,
        randomBytes: (size) => Buffer.alloc(size, 6),
      })).rejects.toMatchObject({ code: expected });
    }

    const unavailableTokenStore = new DemandStore();
    unavailableTokenStore.verifyRequest = vi.fn(async () => ({
      ok: false as const, code: 'token_unavailable', detail: 'private',
    }));
    await expect(verifyAuthorityRecordDemandRequest({
      token: `ardv1_${'a'.repeat(64)}`, store: unavailableTokenStore, now: NOW,
    })).rejects.toMatchObject({ status: 404, code: 'authority_demand_verification_unavailable' });
  });

  it('returns exact verified demand counts and hides missing records', async () => {
    await expect(readAuthorityRecordDemandCounts({ recordId: RECORD_ID, store: new DemandStore() }))
      .resolves.toEqual({ verified_requesters: 1, verified_organizations: 1 });
    await expect(readAuthorityRecordDemandCounts({ recordId: 'bad', store: new DemandStore() }))
      .rejects.toMatchObject({ status: 404, code: 'authority_record_not_found' });

    const missingStore = new DemandStore();
    missingStore.readCounts = vi.fn(async () => ({
      ok: false as const, code: 'record_unavailable', detail: 'private',
    }));
    await expect(readAuthorityRecordDemandCounts({ recordId: RECORD_ID, store: missingStore }))
      .rejects.toMatchObject({ status: 404, code: 'authority_record_not_found' });
  });
});
