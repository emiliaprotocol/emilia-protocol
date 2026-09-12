// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from 'vitest';
import { sanitizeSecurityPayload } from '@/lib/security-events';

// The public ledger's payload boundary must be covered by public tests, without
// depending on consumers in the private Works application.
describe('security event payload boundary', () => {
  it('redacts secrets inside nested arrays without modifying the caller payload', () => {
    const input = { actions: [{ count: 2, api_key: 'fixture-only' }, [true, null, 'ready']] };
    expect(sanitizeSecurityPayload(input)).toEqual({
      actions: [{ count: 2, api_key: '[redacted]' }, [true, null, 'ready']],
    });
    expect(input.actions[0]).toEqual({ count: 2, api_key: 'fixture-only' });
  });

  it('rejects array accessors without evaluating them', () => {
    const getter = vi.fn(() => 'must-not-run');
    const input: unknown[] = [];
    Object.defineProperty(input, '0', { enumerable: true, get: getter });
    expect(() => sanitizeSecurityPayload(input)).toThrow('array accessor');
    expect(getter).not.toHaveBeenCalled();
  });

  it('rejects sparse, extended and nonstandard arrays', () => {
    expect(() => sanitizeSecurityPayload(new Array(2))).toThrow('sparse or extended array');
    const extended = Object.assign([1], { extra: 'not a JSON array member' });
    expect(() => sanitizeSecurityPayload(extended)).toThrow('sparse or extended array');
    const nonstandard = Object.setPrototypeOf([1], null);
    expect(() => sanitizeSecurityPayload(nonstandard)).toThrow('unsafe array prototype');
  });

  it('allows repeated values but rejects ancestor cycles', () => {
    const shared = { amount: 12 };
    expect(sanitizeSecurityPayload([shared, shared])).toEqual([{ amount: 12 }, { amount: 12 }]);
    const cyclic: unknown[] = [];
    cyclic.push(cyclic);
    expect(() => sanitizeSecurityPayload(cyclic)).toThrow('cyclic reference');
  });
});
