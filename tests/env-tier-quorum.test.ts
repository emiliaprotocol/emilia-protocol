// SPDX-License-Identifier: Apache-2.0
// Pins the fail-closed default of the dual-authorization enforcement flag.
// A 'dual' value-tier receipt (e.g. payment >= $1M) must require two distinct
// Class-A approvers UNLESS a deployment explicitly opts out. Regressing this to
// opt-in would silently let high-value receipts consume on a single approval.
import { describe, it, expect, afterEach } from 'vitest';
import { isTierQuorumEnforced } from '../lib/env.js';

describe('isTierQuorumEnforced (fail-closed default)', () => {
  const original = process.env.EP_TIER_QUORUM_ENFORCE;
  afterEach(() => {
    if (original === undefined) delete process.env.EP_TIER_QUORUM_ENFORCE;
    else process.env.EP_TIER_QUORUM_ENFORCE = original;
  });

  it('is ON when unset (default fail-closed)', () => {
    delete process.env.EP_TIER_QUORUM_ENFORCE;
    expect(isTierQuorumEnforced()).toBe(true);
  });

  it('is ON for any value other than the explicit opt-out', () => {
    process.env.EP_TIER_QUORUM_ENFORCE = 'true';
    expect(isTierQuorumEnforced()).toBe(true);
    process.env.EP_TIER_QUORUM_ENFORCE = '1';
    expect(isTierQuorumEnforced()).toBe(true);
  });

  it('opts out ONLY on the exact string "false"', () => {
    process.env.EP_TIER_QUORUM_ENFORCE = 'false';
    expect(isTierQuorumEnforced()).toBe(false);
  });
});
