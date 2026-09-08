// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';

import { createSupabaseWorksAccountStore } from '../lib/works/account-store.ts';

const CHALLENGE = '11111111-1111-4111-8111-111111111111';
const ACTOR_ROW = {
  status: 'AUTHENTICATED',
  account_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  owner_entity_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  display_name: 'Avery Chen',
  email_notifications: false,
};

function client() {
  const rpc = vi.fn();
  return { rpc, store: createSupabaseWorksAccountStore({ rpc } as any) };
}

describe('Works account PostgreSQL adapter', () => {
  it('binds account challenges to the exact digests and maps durable request limits', async () => {
    const { rpc, store } = client();
    rpc.mockResolvedValueOnce({ data: { challenge_id: CHALLENGE }, error: null });
    const input = {
      challengeId: CHALLENGE,
      emailDigest: `hmac-sha256:${'a'.repeat(64)}`,
      clientDigest: `hmac-sha256:${'b'.repeat(64)}`,
      codeDigest: `hmac-sha256:${'c'.repeat(64)}`,
      mode: 'signup' as const,
      displayName: 'Avery Chen',
      consent: true,
      emailNotifications: false,
    };
    await expect(store.beginChallenge(input)).resolves.toEqual({ ok: true, challengeId: CHALLENGE });
    expect(rpc).toHaveBeenCalledWith('begin_works_account_email_challenge', {
      p_challenge_id: CHALLENGE,
      p_email_digest: input.emailDigest,
      p_client_digest: input.clientDigest,
      p_code_digest: input.codeDigest,
      p_mode: 'signup',
      p_display_name: 'Avery Chen',
      p_consent: true,
      p_email_notifications: false,
    });

    rpc.mockResolvedValueOnce({ data: null, error: { code: 'WA001' } });
    await expect(store.beginChallenge(input)).resolves.toEqual({ ok: false, code: 'request_limited' });
    rpc.mockResolvedValueOnce({ data: { challenge_id: 'different' }, error: null });
    await expect(store.beginChallenge(input)).resolves.toEqual({ ok: false, code: 'store_invalid' });
  });

  it('requires delivery marking to identify an available challenge', async () => {
    const { rpc, store } = client();
    const input = { challengeId: CHALLENGE, codeDigest: `hmac-sha256:${'c'.repeat(64)}`, delivered: true };
    rpc.mockResolvedValueOnce({ data: true, error: null });
    await expect(store.markDelivery(input)).resolves.toEqual({ ok: true });
    expect(rpc).toHaveBeenCalledWith('mark_works_account_email_delivery', {
      p_challenge_id: CHALLENGE,
      p_code_digest: input.codeDigest,
      p_delivered: true,
    });
    rpc.mockResolvedValueOnce({ data: false, error: null });
    await expect(store.markDelivery(input)).resolves.toEqual({ ok: false, code: 'challenge_unavailable' });
  });

  it('accepts only an authenticated, least-disclosure actor projection on exchange', async () => {
    const { rpc, store } = client();
    const input = {
      challengeId: CHALLENGE,
      emailDigest: `hmac-sha256:${'a'.repeat(64)}`,
      codeDigest: `hmac-sha256:${'c'.repeat(64)}`,
      sessionDigest: `sha256:${'d'.repeat(64)}`,
      sessionExpiresAt: '2026-09-15T00:00:00.000Z',
    };
    rpc.mockResolvedValueOnce({ data: ACTOR_ROW, error: null });
    await expect(store.exchangeChallenge(input)).resolves.toEqual({ ok: true, actor: {
      accountId: ACTOR_ROW.account_id,
      ownerEntityId: ACTOR_ROW.owner_entity_id,
      displayName: 'Avery Chen',
      emailVerified: true,
      emailNotifications: false,
      claimsVerified: false,
      authMethod: 'email_code',
    } });
    expect(rpc).toHaveBeenCalledWith('exchange_works_account_email_challenge', {
      p_challenge_id: CHALLENGE,
      p_email_digest: input.emailDigest,
      p_code_digest: input.codeDigest,
      p_session_token_digest: input.sessionDigest,
      p_session_expires_at: input.sessionExpiresAt,
    });

    rpc.mockResolvedValueOnce({ data: { ...ACTOR_ROW, status: 'REFUSED' }, error: null });
    await expect(store.exchangeChallenge(input)).resolves.toEqual({ ok: false, code: 'challenge_unavailable' });
    rpc.mockResolvedValueOnce({ data: { ...ACTOR_ROW, account_id: null }, error: null });
    await expect(store.exchangeChallenge(input)).resolves.toEqual({ ok: false, code: 'store_invalid' });
  });

  it('distinguishes absent sessions, valid actors, malformed projections and revocation state', async () => {
    const { rpc, store } = client();
    const digest = `sha256:${'d'.repeat(64)}`;
    rpc.mockResolvedValueOnce({ data: null, error: null });
    await expect(store.readSession(digest)).resolves.toEqual({ ok: true, actor: null });
    rpc.mockResolvedValueOnce({ data: ACTOR_ROW, error: null });
    await expect(store.readSession(digest)).resolves.toMatchObject({ ok: true, actor: { displayName: 'Avery Chen' } });
    rpc.mockResolvedValueOnce({ data: { ...ACTOR_ROW, email_notifications: 'false' }, error: null });
    await expect(store.readSession(digest)).resolves.toEqual({ ok: false, code: 'store_invalid' });

    rpc.mockResolvedValueOnce({ data: true, error: null });
    await expect(store.revokeSession(digest)).resolves.toEqual({ ok: true, revoked: true });
    rpc.mockResolvedValueOnce({ data: false, error: null });
    await expect(store.revokeSession(digest)).resolves.toEqual({ ok: true, revoked: false });
    rpc.mockResolvedValueOnce({ data: 'true', error: null });
    await expect(store.revokeSession(digest)).resolves.toEqual({ ok: false, code: 'store_invalid' });
  });

  it('collapses database errors and thrown transport details to store_unavailable', async () => {
    const { rpc, store } = client();
    rpc.mockResolvedValueOnce({ data: null, error: { code: 'XX000', message: 'private database detail' } });
    await expect(store.readSession('sha256:test')).resolves.toEqual({ ok: false, code: 'store_unavailable' });
    rpc.mockRejectedValueOnce(new Error('private transport detail'));
    await expect(store.revokeSession('sha256:test')).resolves.toEqual({ ok: false, code: 'store_unavailable' });

    rpc.mockResolvedValueOnce({ data: null, error: { code: 'XX000' } });
    await expect(store.markDelivery({
      challengeId: CHALLENGE, codeDigest: `hmac-sha256:${'c'.repeat(64)}`, delivered: true,
    })).resolves.toEqual({ ok: false, code: 'store_unavailable' });
    rpc.mockResolvedValueOnce({ data: null, error: { code: 'XX000' } });
    await expect(store.exchangeChallenge({
      challengeId: CHALLENGE, emailDigest: 'email', codeDigest: 'code',
      sessionDigest: 'session', sessionExpiresAt: '2026-09-15T00:00:00Z',
    })).resolves.toEqual({ ok: false, code: 'store_unavailable' });
  });
});
