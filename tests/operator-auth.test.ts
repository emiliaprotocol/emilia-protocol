// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  authenticateOperator,
  generateOperatorToken,
  verifyOperatorAuth,
} from '../lib/operator-auth.js';
import { _resetOperatorTokenReplayMemory } from '../lib/operator-token-replay.js';

const SECRET_HEX = '11'.repeat(32);

// Legacy-token construction is intentionally test-local. Production callers
// can only mint the request-bound v2 shape through generateOperatorToken().
function legacyOperatorToken(operatorId: string, secretHex: string): string {
  const message = `${operatorId}.${Date.now().toString(16)}`;
  const hmac = crypto.createHmac('sha256', Buffer.from(secretHex, 'hex'))
    .update(message)
    .digest('hex');
  return `ep_op_${message}.${hmac}`;
}

beforeEach(() => {
  _resetOperatorTokenReplayMemory();
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe('operator auth — red-team accountability boundary', () => {
  it('accepts a fresh per-operator token and returns the named operator id', async () => {
    vi.stubEnv('EP_OPERATOR_KEYS', JSON.stringify({ op_alice: SECRET_HEX }));
    vi.stubEnv('EP_OPERATOR_ROLES', JSON.stringify({ op_alice: 'reviewer' }));

    const token = legacyOperatorToken('op_alice', SECRET_HEX);
    const result = await verifyOperatorAuth(token, { requireOperatorIdentity: true });

    expect(result).toMatchObject({ valid: true, operator_id: 'op_alice', role: 'reviewer' });
  });

  it('does not invent a role for a named operator without EP_OPERATOR_ROLES', async () => {
    vi.stubEnv('EP_OPERATOR_KEYS', JSON.stringify({ op_alice: SECRET_HEX }));
    vi.stubEnv('EP_OPERATOR_ROLES', '');

    const token = legacyOperatorToken('op_alice', SECRET_HEX);
    const result = await verifyOperatorAuth(token, { requireOperatorIdentity: true });

    expect(result).toMatchObject({ valid: true, operator_id: 'op_alice', role: null });
  });

  it('refuses legacy CRON_SECRET on identity-required actions once operator keys exist', async () => {
    vi.stubEnv('EP_OPERATOR_KEYS', JSON.stringify({ op_alice: SECRET_HEX }));
    vi.stubEnv('CRON_SECRET', 'shared-cron-secret');

    const result = await verifyOperatorAuth('shared-cron-secret', { requireOperatorIdentity: true });

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/per-operator token/i);
  });

  it('refuses the shared CRON_SECRET on a requireOperatorIdentity route even when no operator keys are configured', async () => {
    // The shared cron secret is anonymous ('_legacy_cron'); a named-operator
    // action must never be authorized by it, regardless of migration state.
    // Previously this refusal was contingent on getOperatorKeys().size > 0,
    // so a pre-cutover deployment let a leaked CRON_SECRET resolve disputes
    // and revoke commit keys with the full 'operator' role.
    vi.stubEnv('EP_OPERATOR_KEYS', '');
    vi.stubEnv('CRON_SECRET', 'shared-cron-secret');

    const result = await authenticateOperator(new Request('https://x/internal', {
      headers: { authorization: 'Bearer shared-cron-secret' },
    }), { requireOperatorIdentity: true });

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/per-operator token/i);
  });

  it('still authenticates the shared CRON_SECRET for a scheduler that explicitly opts out', async () => {
    vi.stubEnv('EP_OPERATOR_KEYS', '');
    vi.stubEnv('CRON_SECRET', 'shared-cron-secret');

    const result = await authenticateOperator(new Request('https://x/cron', {
      headers: { authorization: 'Bearer shared-cron-secret' },
    }), { requireOperatorIdentity: false });

    expect(result).toMatchObject({ valid: true, operator_id: '_legacy_cron' });
  });
});

describe('operator auth — named identity is the default, not an opt-in', () => {
  // Audit #11 finding 2 claimed requireOperatorIdentity was never passed by any
  // caller. It is: six routes pass it (identity/verify, disputes/resolve,
  // disputes/appeal/resolve, disputes/[id]/adjudicate, release-lock/reconcile,
  // commit-keys/revoke). The residual risk the finding did land on is the
  // DIRECTION of the default — a NEW sensitive route that forgot the flag used
  // to inherit "anonymous shared secret is fine". These cases pin the inversion.

  it('refuses the shared secret for a caller that passes no options at all', async () => {
    vi.stubEnv('EP_OPERATOR_KEYS', '');
    vi.stubEnv('CRON_SECRET', 'shared-cron-secret');

    const result = await authenticateOperator(new Request('https://x/api/some/new/route', {
      headers: { authorization: 'Bearer shared-cron-secret' },
    }));

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/per-operator token/i);
  });

  it('refuses the shared secret for an explicit undefined flag', async () => {
    vi.stubEnv('EP_OPERATOR_KEYS', '');
    vi.stubEnv('CRON_SECRET', 'shared-cron-secret');

    const result = await verifyOperatorAuth('shared-cron-secret', {
      requireOperatorIdentity: undefined,
    });

    expect(result.valid).toBe(false);
  });

  it('never labels the anonymous shared secret with the operator role', async () => {
    // 'operator' carries entity.suspend, evidence.redact and dispute.override in
    // OPERATOR_ROLES. An anonymous credential must not answer to that name even
    // where nothing currently reads it.
    vi.stubEnv('EP_OPERATOR_KEYS', '');
    vi.stubEnv('CRON_SECRET', 'shared-cron-secret');

    const result = await verifyOperatorAuth('shared-cron-secret', {
      requireOperatorIdentity: false,
    });

    expect(result.valid).toBe(true);
    expect(result.operator_id).toBe('_legacy_cron');
    expect(result.role).toBeNull();
  });
});

describe('operator auth — token replay', () => {
  it('accepts an exactly matching request-bound token once and refuses its replay', async () => {
    vi.stubEnv('EP_OPERATOR_KEYS', JSON.stringify({ op_alice: SECRET_HEX }));
    vi.stubEnv('EP_OPERATOR_ROLES', JSON.stringify({ op_alice: 'operator' }));
    const body = JSON.stringify({ kid: 'compromised-kid' });
    const token = generateOperatorToken('op_alice', SECRET_HEX, {
      method: 'POST',
      target: '/api/commit-keys/revoke?source=console',
      body,
    });
    const makeRequest = () => new Request(
      'https://x/api/commit-keys/revoke?source=console',
      { method: 'POST', headers: { authorization: `Bearer ${token}` }, body },
    );

    await expect(authenticateOperator(makeRequest(), {
      requireOperatorIdentity: true,
    })).resolves.toMatchObject({ valid: true, operator_id: 'op_alice', role: 'operator' });
    const replay = await authenticateOperator(makeRequest(), { requireOperatorIdentity: true });
    expect(replay.valid).toBe(false);
    expect(replay.error).toMatch(/already used/i);
  });

  it('refuses body substitution on the same method and route', async () => {
    vi.stubEnv('EP_OPERATOR_KEYS', JSON.stringify({ op_alice: SECRET_HEX }));
    const token = generateOperatorToken('op_alice', SECRET_HEX, {
      method: 'POST',
      target: '/api/commit-keys/revoke',
      body: JSON.stringify({ kid: 'approved-kid' }),
    });
    const result = await authenticateOperator(new Request(
      'https://x/api/commit-keys/revoke',
      {
        method: 'POST',
        headers: { authorization: `Bearer ${token}` },
        body: JSON.stringify({ kid: 'substituted-kid' }),
      },
    ), { requireOperatorIdentity: true });

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/request binding/i);
  });

  it('refuses a fresh token when it is raced into a different request', async () => {
    vi.stubEnv('EP_OPERATOR_KEYS', JSON.stringify({ op_alice: SECRET_HEX }));
    vi.stubEnv('EP_OPERATOR_ROLES', JSON.stringify({ op_alice: 'reviewer' }));

    const token = generateOperatorToken('op_alice', SECRET_HEX, {
      method: 'POST',
      target: '/api/cron/expire',
      body: '',
    });

    const substituted = await authenticateOperator(
      new Request('https://x/api/commit-keys/revoke', {
        method: 'POST',
        headers: { authorization: `Bearer ${token}` },
        body: JSON.stringify({ kid: 'compromised-kid' }),
      }),
      { requireOperatorIdentity: true },
    );

    expect(substituted.valid).toBe(false);
    expect(substituted.error).toMatch(/request binding/i);
  });

  it('spends a per-operator token on first use and refuses the replay', async () => {
    vi.stubEnv('EP_OPERATOR_KEYS', JSON.stringify({ op_alice: SECRET_HEX }));

    const token = legacyOperatorToken('op_alice', SECRET_HEX);

    const first = await verifyOperatorAuth(token, { requireOperatorIdentity: true });
    expect(first.valid).toBe(true);

    // Same bytes, still inside the 5-minute window, genuine HMAC. Before this
    // guard a token lifted from a CI log or a `ps aux` line was as good as the
    // operator's secret for the rest of that window, at every operator route.
    const replay = await verifyOperatorAuth(token, { requireOperatorIdentity: true });
    expect(replay.valid).toBe(false);
    expect(replay.error).toMatch(/already used/i);
  });

  it('refuses a token replayed against a DIFFERENT route than the one that spent it', async () => {
    vi.stubEnv('EP_OPERATOR_KEYS', JSON.stringify({ op_alice: SECRET_HEX }));

    const token = generateOperatorToken('op_alice', SECRET_HEX, {
      method: 'GET',
      target: '/api/cron/expire',
      body: '',
    });
    const headers = { authorization: `Bearer ${token}` };

    const cron = await authenticateOperator(
      new Request('https://x/api/cron/expire', { headers }),
      { requireOperatorIdentity: false },
    );
    expect(cron.valid).toBe(true);

    const escalation = await authenticateOperator(
      new Request('https://x/api/commit-keys/revoke', { headers }),
      { requireOperatorIdentity: true },
    );
    expect(escalation.valid).toBe(false);
    expect(escalation.error).toMatch(/request binding/i);
  });

  it('lets two DIFFERENT tokens from the same operator through', async () => {
    vi.stubEnv('EP_OPERATOR_KEYS', JSON.stringify({ op_alice: SECRET_HEX }));

    // Distinct timestamps produce distinct HMACs, so consumption is per token
    // rather than per operator: single-use must not throttle a real operator
    // down to one action per five minutes.
    const first = await verifyOperatorAuth(
      legacyOperatorToken('op_alice', SECRET_HEX),
      { requireOperatorIdentity: true },
    );
    await new Promise((resolve) => { setTimeout(resolve, 2); });
    const second = await verifyOperatorAuth(
      legacyOperatorToken('op_alice', SECRET_HEX),
      { requireOperatorIdentity: true },
    );

    expect(first.valid).toBe(true);
    expect(second.valid).toBe(true);
  });

  it('does not consume anything when the HMAC is forged', async () => {
    vi.stubEnv('EP_OPERATOR_KEYS', JSON.stringify({ op_alice: SECRET_HEX }));

    const real = legacyOperatorToken('op_alice', SECRET_HEX);
    const forged = `${real.slice(0, -1)}${real.endsWith('0') ? '1' : '0'}`;

    const attack = await verifyOperatorAuth(forged, { requireOperatorIdentity: true });
    expect(attack.valid).toBe(false);
    expect(attack.error).toMatch(/invalid signature/i);

    // An attacker must not be able to burn a legitimate operator's token by
    // presenting a near-miss first: verification precedes consumption.
    const legitimate = await verifyOperatorAuth(real, { requireOperatorIdentity: true });
    expect(legitimate.valid).toBe(true);
  });

  it('leaves the shared cron secret unaffected — it has no nonce to spend', async () => {
    vi.stubEnv('EP_OPERATOR_KEYS', '');
    vi.stubEnv('CRON_SECRET', 'shared-cron-secret');

    for (let i = 0; i < 3; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      const result = await verifyOperatorAuth('shared-cron-secret', {
        requireOperatorIdentity: false,
      });
      expect(result.valid).toBe(true);
    }
  });
});

describe('operator auth — durable replay-store contract', () => {
  function useUpstash(): void {
    vi.stubEnv('UPSTASH_REDIS_REST_URL', 'https://redis.example.test');
    vi.stubEnv('UPSTASH_REDIS_REST_TOKEN', 'test-token');
    vi.stubEnv('EP_OPERATOR_KEYS', JSON.stringify({ op_alice: SECRET_HEX }));
  }

  it('accepts only an explicit atomic SET success from Redis', async () => {
    useUpstash();
    const fetchMock = vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ result: 'OK' }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    ));
    vi.stubGlobal('fetch', fetchMock);

    const result = await verifyOperatorAuth(
      legacyOperatorToken('op_alice', SECRET_HEX),
      { requireOperatorIdentity: true },
    );

    expect(result.valid).toBe(true);
    expect(fetchMock).toHaveBeenCalledOnce();
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(String(init.body))).toEqual(expect.arrayContaining(['SET', 'NX', 'EX']));
  });

  it('maps Redis NX contention to an already-used refusal', async () => {
    useUpstash();
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ result: null }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    )));

    const result = await verifyOperatorAuth(
      legacyOperatorToken('op_alice', SECRET_HEX),
      { requireOperatorIdentity: true },
    );

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/already used/i);
  });

  it.each([
    ['HTTP failure', new Response('unavailable', { status: 503 })],
    ['Redis error', new Response(JSON.stringify({ error: 'READONLY' }), { status: 200 })],
    ['unexpected result', new Response(JSON.stringify({ result: 1 }), { status: 200 })],
  ])('fails closed when the durable replay store returns %s', async (_label, response) => {
    useUpstash();
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response));

    const result = await verifyOperatorAuth(
      legacyOperatorToken('op_alice', SECRET_HEX),
      { requireOperatorIdentity: true },
    );

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/replay protection unavailable/i);
  });

  it('fails closed when the durable replay store cannot be reached', async () => {
    useUpstash();
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network down')));

    const result = await verifyOperatorAuth(
      legacyOperatorToken('op_alice', SECRET_HEX),
      { requireOperatorIdentity: true },
    );

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/replay protection unavailable/i);
  });

  it('fails closed in production when no durable replay store is configured', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('UPSTASH_REDIS_REST_URL', '');
    vi.stubEnv('UPSTASH_REDIS_REST_TOKEN', '');
    vi.stubEnv('EP_OPERATOR_KEYS', JSON.stringify({ op_alice: SECRET_HEX }));

    const result = await verifyOperatorAuth(
      legacyOperatorToken('op_alice', SECRET_HEX),
      { requireOperatorIdentity: true },
    );

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/replay protection unavailable/i);
  });
});
