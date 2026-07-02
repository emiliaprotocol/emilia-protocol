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
});
