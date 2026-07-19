// SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, it } from 'vitest';
import {
  getCommitSigningConfig,
  getOperatorKeys,
  getOperatorRoles,
  getPinnedApproverKeys,
  getPinnedQuorumPolicies,
  getRateLimitConfig,
} from '../lib/env.js';

const ORIGINAL = { ...process.env };

afterEach(() => {
  for (const key of Object.keys(process.env)) if (!(key in ORIGINAL)) delete process.env[key];
  Object.assign(process.env, ORIGINAL);
});

describe('security-sensitive environment JSON', () => {
  it('refuses duplicate trust-root and policy members', () => {
    process.env.NODE_ENV = 'test';
    process.env.EP_COMMIT_SIGNING_KEYS = '{"kid":"safe","kid":"attacker"}';
    process.env.EP_QUORUM_POLICIES = '{"payment.release":{"required":2},"payment.release":{"required":1}}';
    process.env.EP_PINNED_APPROVER_KEYS = '{"key-1":{"public_key":"safe"},"key-1":{"public_key":"attacker"}}';
    expect(getCommitSigningConfig().trustedKeys).toBeNull();
    expect(getPinnedQuorumPolicies()).toEqual({});
    expect(getPinnedApproverKeys()).toEqual({});
  });

  it('requires operator HMAC secrets to be valid and at least 32 bytes', () => {
    process.env.EP_OPERATOR_KEYS = '{"operator-1":"zz"}';
    expect(getOperatorKeys().size).toBe(0);
    process.env.EP_OPERATOR_KEYS = JSON.stringify({ 'operator-1': 'ab'.repeat(32) });
    expect(getOperatorKeys().get('operator-1')).toHaveLength(32);
  });

  it('refuses duplicate role assignments', () => {
    process.env.EP_OPERATOR_ROLES = '{"operator-1":"reviewer","operator-1":"admin"}';
    expect(getOperatorRoles().size).toBe(0);
  });

  it('requires a durable rate limiter for sensitive production categories', () => {
    process.env.NODE_ENV = 'production';
    delete process.env.EP_GOV_STRICT;
    delete process.env.EP_REQUIRE_DURABLE_RATE_LIMIT;
    expect(getRateLimitConfig().durableRequired).toBe(true);
  });
});
