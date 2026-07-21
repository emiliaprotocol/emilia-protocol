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
import { verifyExecutionBinding, hashCanonical } from '../packages/gate/execution-binding.js';

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

  // The refusals below use a required field literally named `__proto__`.
  // That name is load-bearing, not decoration: the verifier accumulates
  // accepted values into a plain `{}` and writes them with `values[field] =`,
  // so a `__proto__` field hits Object.prototype's setter instead of creating
  // an own key. A refusal that is recorded only as "this field never landed in
  // the accumulator" is therefore INVISIBLE for this field name, and the
  // aggregate re-check that normally backstops per-field refusals cannot see it
  // either. These cases pin that each per-field refusal is recorded explicitly,
  // by name, rather than being inferred from the accumulator's contents.

  it('REFUSES a __proto__-named field when the container is not a plain object', () => {
    const r = verifyExecutionBinding({
      requirement: { execution_binding: { required_fields: ['__proto__'] } },
      receipt: { payload: { claim: [] } },
      observedAction: new Map(),
    });
    expect(r.ok).toBe(false);
    expect(r.invalid_signed_fields).toEqual(['__proto__']);
    expect(r.invalid_observed_fields).toEqual(['__proto__']);
    expect(r.signed_hash).toBeNull();
    expect(r.observed_hash).toBeNull();
  });

  it('REFUSES a __proto__-named field carried as a non-enumerable or accessor property', () => {
    const withDescriptor = (descriptor) => {
      const container = {};
      Object.defineProperty(container, '__proto__', descriptor);
      return container;
    };
    const cases = [
      ['non-enumerable', { value: 1, enumerable: false, configurable: true }],
      ['accessor', { get: () => 1, enumerable: true, configurable: true }],
    ];

    for (const [name, descriptor] of cases) {
      const r = verifyExecutionBinding({
        requirement: { execution_binding: { required_fields: ['__proto__'] } },
        receipt: { payload: { claim: withDescriptor(descriptor) } },
        observedAction: withDescriptor(descriptor),
      });
      expect(r.ok, name).toBe(false);
      expect(r.missing_signed_fields, name).toEqual([]);
      expect(r.missing_observed_fields, name).toEqual([]);
      expect(r.invalid_signed_fields, name).toEqual(['__proto__']);
      expect(r.invalid_observed_fields, name).toEqual(['__proto__']);
      expect(r.signed_hash, name).toBeNull();
      expect(r.observed_hash, name).toBeNull();
    }
  });

  it('REFUSES a __proto__-named field holding an out-of-profile value, on each side independently', () => {
    const withValue = (value) => {
      const container = {};
      Object.defineProperty(container, '__proto__', {
        value, enumerable: true, writable: true, configurable: true,
      });
      return container;
    };
    const requirement = { execution_binding: { required_fields: ['__proto__'] } };

    const both = verifyExecutionBinding({
      requirement,
      receipt: { payload: { claim: withValue(Number.NaN) } },
      observedAction: withValue(Number.NaN),
    });
    expect(both.ok).toBe(false);
    expect(both.invalid_signed_fields).toEqual(['__proto__']);
    expect(both.invalid_observed_fields).toEqual(['__proto__']);
    expect(both.signed_hash).toBeNull();
    expect(both.observed_hash).toBeNull();

    // Signed side alone: the observed side is a well-formed plain field, so the
    // refusal cannot be attributed to the observed container.
    const signedOnly = verifyExecutionBinding({
      requirement,
      receipt: { payload: { claim: withValue(Number.NaN) } },
      observedAction: withValue(1),
    });
    expect(signedOnly.ok).toBe(false);
    expect(signedOnly.invalid_signed_fields).toEqual(['__proto__']);
    expect(signedOnly.invalid_observed_fields).toEqual([]);
    expect(signedOnly.signed_hash).toBeNull();

    const observedOnly = verifyExecutionBinding({
      requirement,
      receipt: { payload: { claim: withValue(1) } },
      observedAction: withValue(Number.NaN),
    });
    expect(observedOnly.ok).toBe(false);
    expect(observedOnly.invalid_signed_fields).toEqual([]);
    expect(observedOnly.invalid_observed_fields).toEqual(['__proto__']);
    expect(observedOnly.observed_hash).toBeNull();
  });

  // The three cases below are the other half of the `__proto__` story. The
  // refusals above pin that a REFUSED `__proto__` field is still named; these
  // pin that an ACCEPTED one is still BOUND. Writing `values['__proto__'] = v`
  // onto a plain `{}` runs Object.prototype's setter: a scalar is dropped
  // (the field never reaches the digest it is supposed to be covered by) and an
  // object repoints the accumulator's prototype (the aggregate re-check then
  // throws with no own key to attribute the refusal to, so the throw escapes
  // verifyExecutionBinding as a crash instead of a reasoned refusal).

  const withOwnProto = (value) => {
    const container = {};
    Object.defineProperty(container, '__proto__', {
      value, enumerable: true, writable: true, configurable: true,
    });
    return container;
  };
  const PROTO_REQUIREMENT = { execution_binding: { required_fields: ['__proto__'] } };

  it('BINDS a scalar __proto__-named field into the digest instead of dropping it', () => {
    const r = verifyExecutionBinding({
      requirement: PROTO_REQUIREMENT,
      receipt: { payload: { claim: withOwnProto(250000) } },
      observedAction: withOwnProto(250000),
    });
    expect(r.ok).toBe(true);
    // The digest must cover the field. An empty-object digest means the value
    // never landed, and the binding claims coverage it does not have.
    expect(r.signed_hash).not.toBe(hashCanonical({}));
    expect(r.signed_hash).toBe(hashCanonical(withOwnProto(250000)));
    expect(r.observed_hash).toBe(r.signed_hash);

    // ...and the digest is a function of the VALUE, not just the field name.
    const other = verifyExecutionBinding({
      requirement: PROTO_REQUIREMENT,
      receipt: { payload: { claim: withOwnProto(300000) } },
      observedAction: withOwnProto(300000),
    });
    expect(other.ok).toBe(true);
    expect(other.signed_hash).not.toBe(r.signed_hash);
  });

  it('does not CRASH on an object-valued __proto__-named field, and binds it', () => {
    const call = () => verifyExecutionBinding({
      requirement: PROTO_REQUIREMENT,
      receipt: { payload: { claim: withOwnProto({ amount: 1 }) } },
      observedAction: withOwnProto({ amount: 1 }),
    });
    expect(call).not.toThrow();
    const r = call();
    expect(r.ok).toBe(true);
    expect(r.signed_hash).toBe(hashCanonical(withOwnProto({ amount: 1 })));
    expect(r.observed_hash).toBe(r.signed_hash);
  });

  it('NAMES a __proto__-named field refused only by the aggregate alias check', () => {
    const requirement = { execution_binding: { required_fields: ['__proto__', 'sibling'] } };
    const shared = { amount: 1 };
    const aliased = withOwnProto(shared);
    aliased.sibling = shared;
    // Built with defineProperty, never an object literal: `{ __proto__: v }` is
    // the prototype-setter syntax and would produce no own key at all.
    const observed = withOwnProto({ amount: 1 });
    observed.sibling = { amount: 1 };

    const r = verifyExecutionBinding({
      requirement,
      receipt: { payload: { claim: aliased } },
      observedAction: observed,
    });
    expect(r.ok).toBe(false);
    // Each field passes on its own; only the aggregate graph sees the alias.
    // Both must be named, including the one no Object.keys walk would return
    // from a plain-object accumulator.
    expect(r.invalid_signed_fields).toEqual(['__proto__', 'sibling']);
    expect(r.invalid_observed_fields).toEqual([]);
    expect(r.signed_hash).toBeNull();
  });

  // A symbol-named required field is the same defect at a different key type:
  // it reaches the accumulator as an own symbol property, which the canonical
  // JSON profile refuses -- but no Object.keys walk can name it, so the refusal
  // used to be unrecordable and the digest call threw uncaught.
  it('REFUSES a symbol-named required field with a reason instead of throwing', () => {
    const material = Symbol('material');
    const call = () => verifyExecutionBinding({
      requirement: { execution_binding: { required_fields: [material] } },
      receipt: { payload: { claim: { [material]: 1 } } },
      observedAction: { [material]: 1 },
    });
    expect(call).not.toThrow();
    const r = call();
    expect(r.ok).toBe(false);
    expect(r.invalid_signed_fields).toEqual([material]);
    expect(r.invalid_observed_fields).toEqual([material]);
    expect(r.signed_hash).toBeNull();
    expect(r.observed_hash).toBeNull();
  });

  // A per-field refusal and the aggregate backstop are different mechanisms with
  // different blast radii: the per-field pass refuses one field, the aggregate
  // pass refuses every field it accepted. A field that the per-field pass
  // already refused must never reach the accumulator, or its refusal widens
  // into its siblings and the response blames fields that were never wrong.
  //
  // These two are also what pin fieldValue's per-property refusals under
  // mutation. Its per-CONTAINER refusal (the `isPlainObject(container)` guard)
  // has no such oracle and cannot get one: a non-plain container refuses every
  // required field at once, so returning an unrecognized state instead of
  // `invalid` moves all of them from the per-field refusal to the identical
  // aggregate refusal, with the same fields, order, and null hashes. That
  // mutant is equivalent. It reported as killed before the `__proto__`
  // accumulator fix only by accident: the refused field's `undefined` was
  // swallowed by Object.prototype's setter, which flipped the verdict to a
  // wrong ok:true that a test then caught.
  it('confines a per-field signed refusal to that field, leaving a valid sibling clean', () => {
    const requirement = { execution_binding: { required_fields: ['refused', 'sibling'] } };
    const claim = { sibling: { amount: 1 } };
    Object.defineProperty(claim, 'refused', {
      value: { amount: 2 }, enumerable: false, configurable: true,
    });

    const r = verifyExecutionBinding({
      requirement,
      receipt: { payload: { claim } },
      observedAction: { refused: { amount: 2 }, sibling: { amount: 1 } },
    });
    expect(r.ok).toBe(false);
    expect(r.invalid_signed_fields).toEqual(['refused']);
    expect(r.invalid_observed_fields).toEqual([]);
    expect(r.observed_hash).toBe(hashCanonical({ refused: { amount: 2 }, sibling: { amount: 1 } }));
  });

  it('confines a per-field observed refusal to that field, leaving a valid sibling clean', () => {
    const requirement = { execution_binding: { required_fields: ['refused', 'sibling'] } };
    const observed = { sibling: { amount: 1 } };
    Object.defineProperty(observed, 'refused', {
      value: { amount: 2 }, enumerable: false, configurable: true,
    });

    const r = verifyExecutionBinding({
      requirement,
      receipt: { payload: { claim: { refused: { amount: 2 }, sibling: { amount: 1 } } } },
      observedAction: observed,
    });
    expect(r.ok).toBe(false);
    expect(r.invalid_observed_fields).toEqual(['refused']);
    expect(r.invalid_signed_fields).toEqual([]);
    expect(r.signed_hash).toBe(hashCanonical({ refused: { amount: 2 }, sibling: { amount: 1 } }));
  });

  // A required-field entry that is not a string is coerced to a property key
  // every time it is used, so a non-string entry can run code BETWEEN the
  // per-field read and the accumulator write, and make one property answer
  // twice differently. The already-refused field must stay refused exactly
  // once: the aggregate re-check must not re-report a field the per-field pass
  // already named.
  it('binds an accepted value under the same field name it was read from', () => {
    // A field name that answers differently on each coercion. If the verifier
    // resolves the entry to a property key more than once, it can read
    // `amount_usd` and then bind that value under `beneficiary_account_hash` --
    // a digest that attests to a field pairing neither side ever presented.
    let coercions = 0;
    const drifting = {
      toString() {
        coercions += 1;
        return coercions === 1 ? 'amount_usd' : 'beneficiary_account_hash';
      },
    };
    const claim = { amount_usd: 250000, beneficiary_account_hash: 'sha256:vendorA' };

    const r = verifyExecutionBinding({
      requirement: { execution_binding: { required_fields: [drifting] } },
      receipt: { payload: { claim } },
      observedAction: { ...claim },
    });
    expect(r.ok).toBe(true);
    expect(r.signed_hash).toBe(hashCanonical({ amount_usd: 250000 }));
    expect(r.observed_hash).toBe(r.signed_hash);
  });

  it('reports an already-refused signed field exactly once under a side-effecting field name', () => {
    const shared = { amount: 1 };
    const claim = { b: shared };
    Object.defineProperty(claim, 'a', { get: () => 1, enumerable: true, configurable: true });
    const rebinder = {
      toString() {
        Object.defineProperty(claim, 'a', {
          value: shared, enumerable: true, writable: true, configurable: true,
        });
        return 'a';
      },
    };

    const r = verifyExecutionBinding({
      requirement: { execution_binding: { required_fields: ['a', rebinder, 'b'] } },
      receipt: { payload: { claim } },
      observedAction: { a: { amount: 1 }, b: { amount: 1 } },
    });
    expect(r.ok).toBe(false);
    // 'a' was refused as an accessor by the per-field pass; the rebound alias
    // then poisoned the aggregate, which refuses 'b'. Each field once.
    expect(r.invalid_signed_fields).toEqual(['a', 'b']);
    expect(r.invalid_observed_fields).toEqual([]);
    expect(r.signed_hash).toBeNull();
  });

  it('reports an already-refused observed field exactly once under a side-effecting field name', () => {
    const shared = { amount: 1 };
    const observed = { b: shared };
    Object.defineProperty(observed, 'a', { get: () => 1, enumerable: true, configurable: true });
    const rebinder = {
      toString() {
        Object.defineProperty(observed, 'a', {
          value: shared, enumerable: true, writable: true, configurable: true,
        });
        return 'a';
      },
    };

    const r = verifyExecutionBinding({
      requirement: { execution_binding: { required_fields: ['a', rebinder, 'b'] } },
      receipt: { payload: { claim: { a: { amount: 1 }, b: { amount: 1 } } } },
      observedAction: observed,
    });
    expect(r.ok).toBe(false);
    expect(r.invalid_observed_fields).toEqual(['a', 'b']);
    expect(r.invalid_signed_fields).toEqual([]);
    expect(r.observed_hash).toBeNull();
  });
});
