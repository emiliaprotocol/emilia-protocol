// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';
import {
  createResendReleaseLockInvitationAdapter,
  releaseLockInvitationDeliveryInternals,
} from './invitation-delivery.js';

const LOCK_ID = `rlk_${'1'.repeat(32)}`;
const TOKEN = 'A'.repeat(43);

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function adapter(fetchImpl) {
  return createResendReleaseLockInvitationAdapter({
    apiKey: 're_test_key',
    from: 'Release Lock <release-lock@emiliaprotocol.ai>',
    publicAppOrigin: 'https://www.emiliaprotocol.ai',
    fetch: fetchImpl,
  });
}

describe('Release Lock verified-contact invitation delivery', () => {
  it('keeps the one-time capability out of the HTTP request target', () => {
    const url = releaseLockInvitationDeliveryInternals.invitationUrl(
      'https://www.emiliaprotocol.ai',
      {
        lockId: LOCK_ID,
        role: 'customer',
        token: TOKEN,
      },
    );
    expect(url).toBe(
      `https://www.emiliaprotocol.ai/release-lock/c?lock_id=${LOCK_ID}`
      + `&role=customer#cap=${TOKEN}`,
    );
    expect(new URL(url).search).not.toContain(TOKEN);
  });

  it('delivers a bound fragment capability without returning the token', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ id: 'email_123' }));
    const result = await adapter(fetchImpl).deliver({
      lockId: LOCK_ID,
      role: 'customer',
      channel: 'email',
      identifier: 'customer@example.com',
      token: TOKEN,
      expiresAt: '2030-01-03T00:00:00.000Z',
    });
    expect(result).toEqual({
      kind: 'delivered',
      provider: 'resend',
      reference: 'email_123',
      channel: 'email',
      role: 'customer',
      lock_id: LOCK_ID,
    });
    expect(JSON.stringify(result)).not.toContain(TOKEN);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [target, request] = fetchImpl.mock.calls[0];
    expect(target).toBe('https://api.resend.com/emails');
    expect(target).not.toContain(TOKEN);
    const body = JSON.parse(request.body);
    expect(body.to).toEqual(['customer@example.com']);
    expect(body.text).toContain(`#cap=${TOKEN}`);
    expect(body.text).toContain(`Release Lock ${LOCK_ID}`);
  });

  it('fails closed on ambiguous provider responses', async () => {
    await expect(adapter(async () => jsonResponse({}, 202)).deliver({
      lockId: LOCK_ID,
      role: 'contractor',
      channel: 'email',
      identifier: 'contractor@example.com',
      token: TOKEN,
      expiresAt: '2030-01-03T00:00:00.000Z',
    })).rejects.toThrow(/response is invalid/);

    await expect(adapter(async () => jsonResponse({ id: 'email_123' }, 500)).deliver({
      lockId: LOCK_ID,
      role: 'contractor',
      channel: 'email',
      identifier: 'contractor@example.com',
      token: TOKEN,
      expiresAt: '2030-01-03T00:00:00.000Z',
    })).rejects.toThrow(/delivery failed/);
  });
});
