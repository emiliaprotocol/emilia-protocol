// SPDX-License-Identifier: Apache-2.0
import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';

import { authenticateArenaRequest } from './auth';

const TOKEN = `ep_arena_${'a'.repeat(64)}`;
const SESSION = `arena_session_${'b'.repeat(32)}`;

function request(token = TOKEN): Request {
  return new Request('https://example.test/api/arena', {
    headers: { authorization: `Bearer ${token}` },
  });
}

function clientFor(data: unknown, error: unknown = null) {
  const maybeSingle = vi.fn(async () => ({ data, error }));
  const secondEq = vi.fn(() => ({ maybeSingle }));
  const firstEq = vi.fn(() => ({ eq: secondEq }));
  const select = vi.fn(() => ({ eq: firstEq }));
  const from = vi.fn(() => ({ select }));
  return { client: { from }, spies: { from, select, firstEq, secondEq, maybeSingle } };
}

describe('Arena-only credential authentication', () => {
  it('rejects generic EP keys before touching storage', async () => {
    const { client, spies } = clientFor(null);
    const result = await authenticateArenaRequest(request(`ep_live_${'a'.repeat(64)}`), SESSION, { client: client as any });
    expect(result).toEqual({ ok: false, status: 401, reason: 'arena_credential_invalid' });
    expect(spies.from).not.toHaveBeenCalled();
  });

  it('hashes the Arena token and derives the session from the private row', async () => {
    const row = {
      id: 'row-1', tenant_id: 'tenant-1', session_id: SESSION,
      token_hash: createHash('sha256').update(TOKEN).digest('hex'),
      status: 'active', expires_at: '2026-08-03T00:00:00.000Z',
      agent_name: 'Night Shift', challenge_id: 'emilia.arena.allowance',
      challenge_version: 1, allowance_profile: {}, issuer_id: 'arena:issuer',
      key_id: 'arena-key', public_key: 'abc', private_key_encrypted: 'epenc:v1:abc',
    };
    const { client, spies } = clientFor(row);
    const result = await authenticateArenaRequest(request(), SESSION, {
      client: client as any,
      now: Date.parse('2026-08-02T00:00:00.000Z'),
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.session.session_id).toBe(SESSION);
    expect(spies.firstEq).toHaveBeenCalledWith('token_hash', row.token_hash);
    expect(spies.secondEq).toHaveBeenCalledWith('session_id', SESSION);
    expect(JSON.stringify(result)).not.toContain(TOKEN);
  });

  it('uses one indistinguishable not-found response for wrong session or token', async () => {
    const { client } = clientFor(null);
    await expect(authenticateArenaRequest(request(), SESSION, { client: client as any }))
      .resolves.toEqual({ ok: false, status: 404, reason: 'arena_session_not_found' });
  });

  it.each([
    ['suspended', '2026-08-03T00:00:00.000Z', 'arena_session_inactive'],
    ['active', '2026-08-02T00:00:00.000Z', 'arena_session_expired'],
  ])('fails closed for inactive or expired sessions', async (status, expiresAt, reason) => {
    const { client } = clientFor({ status, expires_at: expiresAt, session_id: SESSION });
    const result = await authenticateArenaRequest(request(), SESSION, {
      client: client as any,
      now: Date.parse('2026-08-02T00:00:00.000Z'),
    });
    expect(result).toEqual({ ok: false, status: 403, reason });
  });

  it('fails closed when the credential store is unavailable', async () => {
    const { client } = clientFor(null, { message: 'db down' });
    await expect(authenticateArenaRequest(request(), SESSION, { client: client as any }))
      .resolves.toEqual({ ok: false, status: 503, reason: 'arena_auth_unavailable' });
  });
});
