// SPDX-License-Identifier: Apache-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  authenticateOperator,
  generateOperatorToken,
  verifyOperatorAuth,
} from '../lib/operator-auth.js';
import { _resetOperatorTokenReplayMemory } from '../lib/operator-token-replay.js';

const SECRET_HEX = '11'.repeat(32);

beforeEach(() => {
  _resetOperatorTokenReplayMemory();
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('operator auth — red-team accountability boundary', () => {
  it('accepts a fresh per-operator token and returns the named operator id', async () => {
    vi.stubEnv('EP_OPERATOR_KEYS', JSON.stringify({ op_alice: SECRET_HEX }));
    vi.stubEnv('EP_OPERATOR_ROLES', JSON.stringify({ op_alice: 'reviewer' }));

    const token = generateOperatorToken('op_alice', SECRET_HEX);
    const result = await verifyOperatorAuth(token, { requireOperatorIdentity: true });

    expect(result).toMatchObject({ valid: true, operator_id: 'op_alice', role: 'reviewer' });
  });

  it('does not invent a role for a named operator without EP_OPERATOR_ROLES', async () => {
    vi.stubEnv('EP_OPERATOR_KEYS', JSON.stringify({ op_alice: SECRET_HEX }));
    vi.stubEnv('EP_OPERATOR_ROLES', '');

    const token = generateOperatorToken('op_alice', SECRET_HEX);
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
  it('spends a per-operator token on first use and refuses the replay', async () => {
    vi.stubEnv('EP_OPERATOR_KEYS', JSON.stringify({ op_alice: SECRET_HEX }));

    const token = generateOperatorToken('op_alice', SECRET_HEX);

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

    const token = generateOperatorToken('op_alice', SECRET_HEX);
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
    expect(escalation.error).toMatch(/already used/i);
  });

  it('lets two DIFFERENT tokens from the same operator through', async () => {
    vi.stubEnv('EP_OPERATOR_KEYS', JSON.stringify({ op_alice: SECRET_HEX }));

    // Distinct timestamps produce distinct HMACs, so consumption is per token
    // rather than per operator: single-use must not throttle a real operator
    // down to one action per five minutes.
    const first = await verifyOperatorAuth(
      generateOperatorToken('op_alice', SECRET_HEX),
      { requireOperatorIdentity: true },
    );
    await new Promise((resolve) => { setTimeout(resolve, 2); });
    const second = await verifyOperatorAuth(
      generateOperatorToken('op_alice', SECRET_HEX),
      { requireOperatorIdentity: true },
    );

    expect(first.valid).toBe(true);
    expect(second.valid).toBe(true);
  });

  it('does not consume anything when the HMAC is forged', async () => {
    vi.stubEnv('EP_OPERATOR_KEYS', JSON.stringify({ op_alice: SECRET_HEX }));

    const real = generateOperatorToken('op_alice', SECRET_HEX);
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
