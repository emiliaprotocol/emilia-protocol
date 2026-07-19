// SPDX-License-Identifier: Apache-2.0
//
// Gate execution-binding — fail-closed when required_fields are declared but the
// caller supplies no observedAction.
//
// verifyExecutionBinding (packages/gate/execution-binding.js) is the primitive
// behind the "approve $250K to Vendor A cannot execute as $300K to Vendor B"
// guarantee. That guarantee only holds when the executor passes observedAction
// from the system of record. This test pins the invariant that a MISSING /
// EMPTY observedAction, against a requirement that declares required_fields,
// resolves to ok:false — never a silent pass. (It also confirms the guarantee is
// a Gate-with-observed-action property, which the docs are being narrowed to say.)
//
// Regression for: "Gate fails closed when required_fields exist but
// observedAction is absent."

import { describe, it, expect } from 'vitest';
import { verifyExecutionBinding } from '../packages/gate/execution-binding.js';

const REQUIREMENT = Object.freeze({
  execution_binding: {
    required_fields: ['amount_usd', 'beneficiary_account_hash'],
  },
});

const RECEIPT = Object.freeze({
  payload: {
    claim: {
      action_type: 'payment.release',
      amount_usd: 250000,
      beneficiary_account_hash: 'sha256:vendorA',
    },
  },
});

describe('Gate execution-binding — fail-closed on absent observed action', () => {
  it('REFUSES when observedAction is undefined but required_fields are declared', () => {
    const r = verifyExecutionBinding({ requirement: REQUIREMENT, receipt: RECEIPT });
    expect(r.required).toBe(true);
    expect(r.ok).toBe(false);
    expect(r.missing_observed_fields).toEqual(
      expect.arrayContaining(['amount_usd', 'beneficiary_account_hash']),
    );
  });

  it('REFUSES when observedAction is an empty object', () => {
    const r = verifyExecutionBinding({ requirement: REQUIREMENT, receipt: RECEIPT, observedAction: {} });
    expect(r.ok).toBe(false);
    expect(r.missing_observed_fields.length).toBeGreaterThan(0);
  });

  it('REFUSES a parameter swap (observed beneficiary != authorized beneficiary)', () => {
    const r = verifyExecutionBinding({
      requirement: REQUIREMENT,
      receipt: RECEIPT,
      observedAction: { amount_usd: 250000, beneficiary_account_hash: 'sha256:vendorB' },
    });
    expect(r.ok).toBe(false);
    expect(r.mismatched_fields).toContain('beneficiary_account_hash');
  });

  it('ALLOWS only when observedAction matches every authorized material field', () => {
    const r = verifyExecutionBinding({
      requirement: REQUIREMENT,
      receipt: RECEIPT,
      observedAction: { amount_usd: 250000, beneficiary_account_hash: 'sha256:vendorA' },
    });
    expect(r.ok).toBe(true);
  });

  it('is not-required (ok:true) only when a requirement declares no material fields', () => {
    const r = verifyExecutionBinding({
      requirement: { execution_binding: { required_fields: [] } },
      receipt: RECEIPT,
    });
    expect(r.required).toBe(false);
    expect(r.ok).toBe(true);
  });

  it('REFUSES the historical NaN/null nested-value collision', () => {
    const requirement = { execution_binding: { required_fields: ['material'] } };
    const receipt = { payload: { claim: { material: { amount: Number.NaN } } } };
    const r = verifyExecutionBinding({
      requirement,
      receipt,
      observedAction: { material: { amount: null } },
    });
    expect(r.ok).toBe(false);
    expect(r.invalid_signed_fields).toContain('material');
    expect(r.invalid_observed_fields).toEqual([]);
    expect(r.signed_hash).toBeNull();
  });

  it('REFUSES observed-side invalidity independently of a valid signed value', () => {
    const requirement = { execution_binding: { required_fields: ['material'] } };
    const receipt = { payload: { claim: { material: { amount: 1 } } } };
    const r = verifyExecutionBinding({
      requirement,
      receipt,
      observedAction: { material: { amount: Number.NaN } },
    });
    expect(r.ok).toBe(false);
    expect(r.invalid_signed_fields).toEqual([]);
    expect(r.invalid_observed_fields).toEqual(['material']);
    expect(r.observed_hash).toBeNull();
  });

  it('REFUSES a missing signed field independently of a present observed field', () => {
    const r = verifyExecutionBinding({
      requirement: REQUIREMENT,
      receipt: { payload: { claim: { beneficiary_account_hash: 'sha256:vendorA' } } },
      observedAction: { amount_usd: 250000, beneficiary_account_hash: 'sha256:vendorA' },
    });
    expect(r.ok).toBe(false);
    expect(r.missing_signed_fields).toEqual(['amount_usd']);
    expect(r.missing_observed_fields).toEqual([]);
  });

  it('distinguishes missing, non-enumerable, accessor, and invalid containers exactly', () => {
    const requirement = { execution_binding: { required_fields: ['amount'] } };
    const observedAction = { amount: 1 };

    const absent = verifyExecutionBinding({
      requirement,
      receipt: { payload: { claim: {} } },
      observedAction,
    });
    expect(absent.missing_signed_fields).toEqual(['amount']);
    expect(absent.invalid_signed_fields).toEqual([]);

    const nonEnumerableClaim = {};
    Object.defineProperty(nonEnumerableClaim, 'amount', { value: 1, enumerable: false });
    const nonEnumerable = verifyExecutionBinding({
      requirement,
      receipt: { payload: { claim: nonEnumerableClaim } },
      observedAction,
    });
    expect(nonEnumerable.missing_signed_fields).toEqual([]);
    expect(nonEnumerable.invalid_signed_fields).toEqual(['amount']);

    const accessorClaim = {};
    Object.defineProperty(accessorClaim, 'amount', { get: () => 1, enumerable: true });
    const accessor = verifyExecutionBinding({
      requirement,
      receipt: { payload: { claim: accessorClaim } },
      observedAction,
    });
    expect(accessor.missing_signed_fields).toEqual([]);
    expect(accessor.invalid_signed_fields).toEqual(['amount']);

    const invalidContainer = verifyExecutionBinding({
      requirement,
      receipt: { payload: { claim: [] } },
      observedAction,
    });
    expect(invalidContainer.missing_signed_fields).toEqual([]);
    expect(invalidContainer.invalid_signed_fields).toEqual(['amount']);

    const nullValue = verifyExecutionBinding({
      requirement,
      receipt: { payload: { claim: { amount: null } } },
      observedAction,
    });
    expect(nullValue.missing_signed_fields).toEqual(['amount']);
    expect(nullValue.invalid_signed_fields).toEqual([]);
  });

  it('REFUSES aliases spanning separate required fields on either side', () => {
    const requirement = { execution_binding: { required_fields: ['left', 'right'] } };
    const signedShared = { amount: 1 };
    const signedAlias = verifyExecutionBinding({
      requirement,
      receipt: { payload: { claim: { left: signedShared, right: signedShared } } },
      observedAction: { left: { amount: 1 }, right: { amount: 1 } },
    });
    expect(signedAlias.ok).toBe(false);
    expect(signedAlias.invalid_signed_fields).toEqual(['left', 'right']);
    expect(signedAlias.invalid_observed_fields).toEqual([]);

    const observedShared = { amount: 1 };
    const observedAlias = verifyExecutionBinding({
      requirement,
      receipt: { payload: { claim: { left: { amount: 1 }, right: { amount: 1 } } } },
      observedAction: { left: observedShared, right: observedShared },
    });
    expect(observedAlias.ok).toBe(false);
    expect(observedAlias.invalid_signed_fields).toEqual([]);
    expect(observedAlias.invalid_observed_fields).toEqual(['left', 'right']);
  });

  it('REFUSES every value outside the EP canonical JSON profile before hashing', () => {
    const shared = { value: 1 };
    const cycle = {};
    cycle.self = cycle;
    const cases = [
      ['undefined', undefined],
      ['NaN', Number.NaN],
      ['Infinity', Number.POSITIVE_INFINITY],
      ['fractional number', 1.5],
      ['unsafe integer', Number.MAX_SAFE_INTEGER + 1],
      ['BigInt', 1n],
      ['non-plain object', new Date('2026-01-01T00:00:00.000Z')],
      ['cycle', cycle],
      ['alias', { left: shared, right: shared }],
    ];

    for (const [name, value] of cases) {
      const requirement = { execution_binding: { required_fields: ['material'] } };
      const receipt = { payload: { claim: { material: value } } };
      expect(() => verifyExecutionBinding({
        requirement,
        receipt,
        observedAction: { material: value },
      }), name).not.toThrow();
      const r = verifyExecutionBinding({ requirement, receipt, observedAction: { material: value } });
      expect(r.ok, name).toBe(false);
      expect(r.invalid_signed_fields, name).toContain('material');
      expect(r.invalid_observed_fields, name).toContain('material');
    }
  });
});
