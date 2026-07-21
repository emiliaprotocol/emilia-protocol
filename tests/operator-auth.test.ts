// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  authenticateOperator,
  generateOperatorToken,
  verifyOperatorAuth,
} from '../lib/operator-auth.js';

const SECRET_HEX = '11'.repeat(32);

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('operator auth — red-team accountability boundary', () => {
  it('accepts a fresh per-operator token and returns the named operator id', () => {
    vi.stubEnv('EP_OPERATOR_KEYS', JSON.stringify({ op_alice: SECRET_HEX }));
    vi.stubEnv('EP_OPERATOR_ROLES', JSON.stringify({ op_alice: 'reviewer' }));

    const token = generateOperatorToken('op_alice', SECRET_HEX);
    const result = verifyOperatorAuth(token, { requireOperatorIdentity: true });

    expect(result).toMatchObject({ valid: true, operator_id: 'op_alice', role: 'reviewer' });
  });

  it('does not invent a role for a named operator without EP_OPERATOR_ROLES', () => {
    vi.stubEnv('EP_OPERATOR_KEYS', JSON.stringify({ op_alice: SECRET_HEX }));
    vi.stubEnv('EP_OPERATOR_ROLES', '');

    const token = generateOperatorToken('op_alice', SECRET_HEX);
    const result = verifyOperatorAuth(token, { requireOperatorIdentity: true });

    expect(result).toMatchObject({ valid: true, operator_id: 'op_alice', role: null });
  });

  it('refuses legacy CRON_SECRET on identity-required actions once operator keys exist', () => {
    vi.stubEnv('EP_OPERATOR_KEYS', JSON.stringify({ op_alice: SECRET_HEX }));
    vi.stubEnv('CRON_SECRET', 'shared-cron-secret');

    const result = verifyOperatorAuth('shared-cron-secret', { requireOperatorIdentity: true });

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/per-operator token/i);
  });

  it('refuses the shared CRON_SECRET on a requireOperatorIdentity route even when no operator keys are configured', () => {
    // The shared cron secret is anonymous ('_legacy_cron'); a named-operator
    // action must never be authorized by it, regardless of migration state.
    // Previously this refusal was contingent on getOperatorKeys().size > 0,
    // so a pre-cutover deployment let a leaked CRON_SECRET resolve disputes
    // and revoke commit keys with the full 'operator' role.
    vi.stubEnv('EP_OPERATOR_KEYS', '');
    vi.stubEnv('CRON_SECRET', 'shared-cron-secret');

    const result = authenticateOperator(new Request('https://x/internal', {
      headers: { authorization: 'Bearer shared-cron-secret' },
    }), { requireOperatorIdentity: true });

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/per-operator token/i);
  });

  it('still authenticates the shared CRON_SECRET for unattended cron jobs (no requireOperatorIdentity)', () => {
    vi.stubEnv('EP_OPERATOR_KEYS', '');
    vi.stubEnv('CRON_SECRET', 'shared-cron-secret');

    const result = authenticateOperator(new Request('https://x/cron', {
      headers: { authorization: 'Bearer shared-cron-secret' },
    }));

    expect(result).toMatchObject({ valid: true, operator_id: '_legacy_cron' });
  });
});
