// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import { countDistinctValidApprovers, requiredApprovalsForTier } from '../lib/guard-tier.js';

// Authorize everyone unless the approval explicitly sets authorized:false
// (simulates a revoked / out-of-window / unregistered authority).
const okAuth = (a) => ({ authorized: a.authorized !== false });

describe('requiredApprovalsForTier', () => {
  it('dual requires 2, single/other require 1', () => {
    expect(requiredApprovalsForTier('dual')).toBe(2);
    expect(requiredApprovalsForTier('single')).toBe(1);
    expect(requiredApprovalsForTier(null)).toBe(1);
    expect(requiredApprovalsForTier(undefined)).toBe(1);
  });
});

describe('countDistinctValidApprovers (the dual-authorization rule)', () => {
  it('counts two distinct Class-A authorized approvers', async () => {
    const n = await countDistinctValidApprovers(
      [{ approver_id: 'A1', key_class: 'A' }, { approver_id: 'A2', key_class: 'A' }],
      { requiredAssurance: 'A', resolveAuthority: okAuth },
    );
    expect(n).toBe(2);
  });

  it('the same human signing twice counts once (distinct humans)', async () => {
    const n = await countDistinctValidApprovers(
      [{ approver_id: 'A1', key_class: 'A' }, { approver_id: 'A1', key_class: 'A' }],
      { requiredAssurance: 'A', resolveAuthority: okAuth },
    );
    expect(n).toBe(1);
  });

  it('excludes the initiator (self-approval guard)', async () => {
    const n = await countDistinctValidApprovers(
      [{ approver_id: 'INIT', key_class: 'A' }, { approver_id: 'A2', key_class: 'A' }],
      { initiatorId: 'INIT', requiredAssurance: 'A', resolveAuthority: okAuth },
    );
    expect(n).toBe(1);
  });

  it('excludes Class-C approvals when Class-A is required', async () => {
    const n = await countDistinctValidApprovers(
      [{ approver_id: 'A1', key_class: 'C' }, { approver_id: 'A2', key_class: 'A' }],
      { requiredAssurance: 'A', resolveAuthority: okAuth },
    );
    expect(n).toBe(1);
  });

  it('excludes approvers whose authority is invalid/revoked at execution', async () => {
    const n = await countDistinctValidApprovers(
      [{ approver_id: 'A1', key_class: 'A', authorized: false }, { approver_id: 'A2', key_class: 'A' }],
      { requiredAssurance: 'A', resolveAuthority: okAuth },
    );
    expect(n).toBe(1);
  });

  it('without a Class-A requirement, Class-C distinct approvers count', async () => {
    const n = await countDistinctValidApprovers(
      [{ approver_id: 'A1', key_class: 'C' }, { approver_id: 'A2', key_class: 'C' }],
      { requiredAssurance: null, resolveAuthority: okAuth },
    );
    expect(n).toBe(2);
  });

  it('a single valid approver is below the dual threshold (cannot consume $1M alone)', async () => {
    const n = await countDistinctValidApprovers(
      [{ approver_id: 'A1', key_class: 'A' }],
      { requiredAssurance: 'A', resolveAuthority: okAuth },
    );
    expect(n).toBeLessThan(requiredApprovalsForTier('dual'));
  });

  it('throws if no resolveAuthority is provided (fail closed by construction)', async () => {
    await expect(countDistinctValidApprovers([{ approver_id: 'A1' }], {})).rejects.toThrow(/resolveAuthority/);
  });

  it('skips null/undefined entries in the approvals array', async () => {
    const n = await countDistinctValidApprovers(
      [null, { approver_id: 'A1', key_class: 'A' }, undefined],
      { requiredAssurance: 'A', resolveAuthority: okAuth },
    );
    expect(n).toBe(1);
  });

  it('treats a missing key_class as Class-C (excluded when Class-A is required)', async () => {
    const n = await countDistinctValidApprovers(
      [{ approver_id: 'A1' }, { approver_id: 'A2', key_class: 'A' }],
      { requiredAssurance: 'A', resolveAuthority: okAuth },
    );
    expect(n).toBe(1);
  });

  it('skips an approval with no approver_id', async () => {
    const n = await countDistinctValidApprovers(
      [{ key_class: 'A' }, { approver_id: 'A2', key_class: 'A' }],
      { requiredAssurance: 'A', resolveAuthority: okAuth },
    );
    expect(n).toBe(1);
  });

  it('returns 0 for a null/undefined approvals list', async () => {
    expect(await countDistinctValidApprovers(null, { resolveAuthority: okAuth })).toBe(0);
    expect(await countDistinctValidApprovers(undefined, { resolveAuthority: okAuth })).toBe(0);
  });

  it('counts an authority resolver that returns a falsy verdict as not-authorized', async () => {
    const n = await countDistinctValidApprovers(
      [{ approver_id: 'A1', key_class: 'A' }],
      { requiredAssurance: 'A', resolveAuthority: async () => null },
    );
    expect(n).toBe(0);
  });
});
