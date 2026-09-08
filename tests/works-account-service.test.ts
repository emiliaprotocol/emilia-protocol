// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  AccountServiceError,
  startWorksAccountChallenge,
  verifyWorksAccountChallenge,
  type WorksAccountStore,
} from '../lib/works/account-service.ts';

const SECRET = 'account-test-secret-with-at-least-thirty-two-bytes';
const ACTOR = {
  accountId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  ownerEntityId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  displayName: 'Avery Chen',
  emailVerified: true as const,
  emailNotifications: false,
  claimsVerified: false as const,
  authMethod: 'email_code' as const,
};

function store(overrides: Partial<WorksAccountStore> = {}): WorksAccountStore {
  return {
    beginChallenge: vi.fn(async input => ({ ok: true, challengeId: input.challengeId })),
    markDelivery: vi.fn(async () => ({ ok: true })),
    exchangeChallenge: vi.fn(async () => ({ ok: true, actor: ACTOR })),
    readSession: vi.fn(async () => ({ ok: true, actor: ACTOR })),
    revokeSession: vi.fn(async () => ({ ok: true, revoked: true })),
    ...overrides,
  };
}

beforeEach(() => vi.restoreAllMocks());

describe('Works email account ceremony', () => {
  it('requires an explicit signup name and consent, but allows email-only recovery', async () => {
    const shared = {
      store: store(), secret: SECRET, clientAddress: '203.0.113.9',
      sendEmail: vi.fn(async () => ({ delivered: true })),
    };
    await expect(startWorksAccountChallenge({ ...shared, input: {
      email: 'new@example.com', name: 'New Person', consent: false,
    } })).rejects.toMatchObject({ code: 'account_consent_required', status: 400 });

    await expect(startWorksAccountChallenge({ ...shared, input: {
      email: 'returning@example.com',
    } })).resolves.toMatchObject({ accepted: true, challengeId: expect.any(String) });
  });

  it('stores only keyed email/client/code digests and sends a typed six-digit code', async () => {
    const accountStore = store();
    const sendEmail = vi.fn(async () => ({ delivered: true }));
    const result = await startWorksAccountChallenge({
      input: { email: ' Avery@Example.COM ', name: ' Avery Chen ', consent: true },
      clientAddress: '203.0.113.9', secret: SECRET, store: accountStore, sendEmail,
    });

    expect(result).toEqual({ accepted: true, challengeId: expect.stringMatching(/^[0-9a-f-]{36}$/) });
    const begin = vi.mocked(accountStore.beginChallenge).mock.calls[0][0];
    expect(begin).toMatchObject({
      mode: 'signup', displayName: 'Avery Chen', consent: true,
      emailDigest: expect.stringMatching(/^hmac-sha256:[a-f0-9]{64}$/),
      clientDigest: expect.stringMatching(/^hmac-sha256:[a-f0-9]{64}$/),
      codeDigest: expect.stringMatching(/^hmac-sha256:[a-f0-9]{64}$/),
    });
    expect(JSON.stringify(begin)).not.toMatch(/avery@|203\.0\.113\.9/i);
    expect(sendEmail).toHaveBeenCalledWith(expect.objectContaining({
      to: 'avery@example.com', code: expect.stringMatching(/^\d{6}$/),
    }));
    expect(vi.mocked(accountStore.markDelivery)).toHaveBeenCalledWith({
      challengeId: result.challengeId, codeDigest: begin.codeDigest, delivered: true,
    });
  });

  it('fails closed and revokes the challenge when Resend does not accept delivery', async () => {
    const accountStore = store();
    await expect(startWorksAccountChallenge({
      input: { email: 'new@example.com', name: 'New Person', consent: true },
      clientAddress: '203.0.113.9', secret: SECRET, store: accountStore,
      sendEmail: vi.fn(async () => ({ delivered: false })),
    })).rejects.toMatchObject({ code: 'account_delivery_unavailable', status: 503 });
    expect(vi.mocked(accountStore.markDelivery)).toHaveBeenCalledWith(expect.objectContaining({ delivered: false }));
  });

  it('does not disclose whether an address exists when durable request limits apply', async () => {
    const accountStore = store({ beginChallenge: vi.fn(async () => ({ ok: false, code: 'request_limited' })) });
    const sendEmail = vi.fn();
    await expect(startWorksAccountChallenge({
      input: { email: 'target@example.com' }, clientAddress: '203.0.113.9',
      secret: SECRET, store: accountStore, sendEmail,
    })).resolves.toMatchObject({ accepted: true, challengeId: expect.any(String) });
    expect(sendEmail).not.toHaveBeenCalled();
  });

  it('binds verification to email and challenge while returning a fresh opaque session token', async () => {
    const accountStore = store();
    const result = await verifyWorksAccountChallenge({
      input: {
        email: 'avery@example.com', challengeId: '11111111-1111-4111-8111-111111111111', code: '123456',
      },
      secret: SECRET, store: accountStore,
    });
    expect(result).toMatchObject({ actor: ACTOR, sessionToken: expect.stringMatching(/^wss1_[a-f0-9]{64}$/) });
    const exchange = vi.mocked(accountStore.exchangeChallenge).mock.calls[0][0];
    expect(exchange).toMatchObject({
      challengeId: '11111111-1111-4111-8111-111111111111',
      emailDigest: expect.stringMatching(/^hmac-sha256:/),
      codeDigest: expect.stringMatching(/^hmac-sha256:/),
      sessionDigest: expect.stringMatching(/^sha256:/),
    });
    expect(JSON.stringify(exchange)).not.toContain('avery@example.com');
    expect(JSON.stringify(exchange)).not.toContain('123456');
  });

  it('collapses wrong, expired, replayed and unknown-account exchanges into one response', async () => {
    for (const code of ['challenge_unavailable', 'challenge_mismatch', 'account_unavailable']) {
      const accountStore = store({ exchangeChallenge: vi.fn(async () => ({ ok: false, code } as const)) });
      await expect(verifyWorksAccountChallenge({
        input: { email: 'target@example.com', challengeId: '11111111-1111-4111-8111-111111111111', code: '123456' },
        secret: SECRET, store: accountStore,
      })).rejects.toEqual(new AccountServiceError(401, 'account_verification_failed', 'The code could not be verified. Start again and use the newest email.'));
    }
  });
});
