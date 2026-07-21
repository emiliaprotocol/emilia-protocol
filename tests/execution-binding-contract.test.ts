// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest';
import {
  actionMaterialFields,
  buildExecutionBindingContract,
  enrichCanonicalActionForExecution,
  verifyExecutionBindingContract,
} from '../lib/execution/binding-contract.js';
import { hashCanonicalAction } from '../lib/guard-policies.js';

const BASE = Object.freeze({
  organization_id: 'org_1',
  actor_id: 'ep:entity:operator',
  action_type: 'production_deploy',
  target_resource_id: 'service:api',
  policy_id: 'deploy.policy.v1',
  policy_hash: 'sha256:policy',
});

describe('execution-binding contract', () => {
  it('binds non-payment high-risk deployment material into the canonical action', () => {
    const action = enrichCanonicalActionForExecution(BASE, {
      repo: 'emilia/api',
      commit_sha: 'abc123',
      artifact_digest: 'sha256:artifact',
      environment: 'production',
    });

    expect(action).toMatchObject({
      repo: 'emilia/api',
      commit_sha: 'abc123',
      artifact_digest: 'sha256:artifact',
      environment: 'production',
    });

    const contract = buildExecutionBindingContract({
      canonicalAction: action,
      decision: { signoffRequired: true, requiredAssurance: 'A' },
    });
    expect(contract.required_fields).toEqual(expect.arrayContaining([
      'repo',
      'commit_sha',
      'artifact_digest',
      'environment',
      'target_resource_id',
    ]));
  });

  it('rejects a permission/role drift, not only amount drift', () => {
    const action = enrichCanonicalActionForExecution({
      ...BASE,
      action_type: 'permission_change',
      target_resource_id: 'repo:emilia/api',
    }, {
      principal_id: 'user:alice',
      role: 'reader',
      scope: 'repo:emilia/api',
      permission: 'read',
    });
    const contract = buildExecutionBindingContract({
      canonicalAction: action,
      decision: { signoffRequired: true, requiredAssurance: 'A' },
    });

    const check = verifyExecutionBindingContract({
      contract,
      executedAction: action,
      observedAction: { ...action, role: 'admin' },
    });

    expect(check.ok).toBe(false);
    expect(check.mismatched_fields).toContain('role');
  });

  it('accepts observed state objects by hashing them to the authorized state hashes', () => {
    const afterState = { status: 'released', destination: 'acct_9f12' };
    const action = {
      ...BASE,
      action_type: 'large_payment_release',
      target_resource_id: 'payment_1',
      amount: 50000,
      currency: 'USD',
      after_state_hash: hashCanonicalAction(afterState),
    };
    const contract = buildExecutionBindingContract({
      canonicalAction: action,
      decision: { signoffRequired: true, requiredAssurance: 'A' },
    });

    const check = verifyExecutionBindingContract({
      contract,
      executedAction: action,
      observedAction: { ...action, after_state: afterState },
    });

    expect(check.ok).toBe(true);
  });

  it('binds GovGuard provider enrollment fields into the execution contract', () => {
    const action = enrichCanonicalActionForExecution({
      ...BASE,
      action_type: 'gov.provider_enrollment_change',
      target_resource_id: 'provider:NPI-123',
    }, {
      provider_id: 'provider:NPI-123',
      npi: '1234567890',
      provider_tax_id_hash: 'sha256:taxid',
      program_id: 'medicaid',
      payment_address: 'hash:new-payment-address',
    });
    const contract = buildExecutionBindingContract({
      canonicalAction: action,
      decision: { signoffRequired: true, requiredAssurance: 'A' },
    });
    expect(contract.required_fields).toEqual(expect.arrayContaining([
      'provider_id',
      'npi',
      'provider_tax_id_hash',
      'program_id',
      'payment_address',
    ]));

    const drift = verifyExecutionBindingContract({
      contract,
      executedAction: action,
      observedAction: { ...action, provider_id: 'provider:attacker' },
    });
    expect(drift.ok).toBe(false);
    expect(drift.mismatched_fields).toContain('provider_id');
  });

  it('fails closed rather than throwing on malformed required field contracts', () => {
    const check = verifyExecutionBindingContract({
      contract: {
        required: true,
        required_fields: ['amount'],
        field_values: {},
      },
      observedAction: { amount: 1 },
      executedAction: { amount: 1 },
    });

    expect(check.ok).toBe(false);
    expect(check.missing_fields).toContain('amount');
  });
});

describe('execution-binding contract — branch coverage', () => {
  it('a non-required contract verifies ok without inspecting any fields', () => {
    const contract = buildExecutionBindingContract({
      canonicalAction: { ...BASE, action_type: 'low_risk_read' },
      decision: {},
    });
    expect(contract.required).toBe(false);
    const check = verifyExecutionBindingContract({ contract, observedAction: {}, executedAction: {} });
    expect(check.ok).toBe(true);
    expect(check.required).toBe(false);
  });

  it('infers money fields from a payment-shaped action_type not in the explicit map', () => {
    const fields = buildExecutionBindingContract({
      canonicalAction: { ...BASE, action_type: 'wire_payment_send', amount: 100, currency: 'USD' },
      actionDetails: { beneficiary_name: 'Acme', iban: 'DE00' },
      decision: { signoffRequired: true },
    }).required_fields;
    expect(fields).toEqual(expect.arrayContaining(['amount', 'currency', 'beneficiary_name', 'iban']));
  });

  it('infers record fields from a delete/decision/override-shaped action_type', () => {
    const action = enrichCanonicalActionForExecution(
      { ...BASE, action_type: 'record_delete_override' },
      { record_id: 'rec_1', decision_id: 'dec_1', override_reason: 'court order' },
    );
    const contract = buildExecutionBindingContract({ canonicalAction: action, decision: { signoffRequired: true } });
    expect(contract.required_fields).toEqual(expect.arrayContaining(['record_id', 'decision_id', 'override_reason']));
  });

  it('infers permission fields from an admin-shaped action_type', () => {
    const action = enrichCanonicalActionForExecution(
      { ...BASE, action_type: 'admin_role_grant' },
      { principal_id: 'user:x', role: 'admin', scope: 'org' },
    );
    const contract = buildExecutionBindingContract({ canonicalAction: action, decision: { signoffRequired: true } });
    expect(contract.required_fields).toEqual(expect.arrayContaining(['principal_id', 'role', 'scope']));
  });

  it('does not overwrite a field already present on the canonical action during enrichment', () => {
    const enriched = enrichCanonicalActionForExecution(
      { ...BASE, action_type: 'large_payment_release', amount: 999 },
      { amount: 1 },
    );
    expect(enriched.amount).toBe(999); // authorized value wins; detail cannot clobber
  });

  it('normalizes array material fields (dedup + sort) consistently on both sides', () => {
    const action = enrichCanonicalActionForExecution(
      { ...BASE, action_type: 'caseworker_override' },
      { target_changed_fields: ['b', 'a', 'a'] },
    );
    expect(action.target_changed_fields).toEqual(['a', 'b']);
    const contract = buildExecutionBindingContract({ canonicalAction: action, decision: { signoffRequired: true } });
    const check = verifyExecutionBindingContract({
      contract,
      executedAction: action,
      observedAction: { ...action, target_changed_fields: ['a', 'b', 'b'] },
    });
    expect(check.mismatched_fields).not.toContain('target_changed_fields');
  });

  it('uses a directly-provided state hash when present (no re-derivation)', () => {
    const action = {
      ...BASE,
      action_type: 'large_payment_release',
      amount: 1,
      currency: 'USD',
      before_state_hash: 'sha256:beef',
      after_state_hash: 'sha256:cafe',
    };
    const contract = buildExecutionBindingContract({ canonicalAction: action, decision: { signoffRequired: true } });
    const check = verifyExecutionBindingContract({
      contract,
      executedAction: action,
      observedAction: { ...action, before_state_hash: 'sha256:beef', after_state_hash: 'sha256:cafe' },
    });
    expect(check.mismatched_fields).not.toContain('before_state_hash');
    expect(check.mismatched_fields).not.toContain('after_state_hash');
  });

  it('derives before_state_hash from an observed before_state object', () => {
    const beforeState = { balance: 100 };
    const action = {
      ...BASE,
      action_type: 'large_payment_release',
      amount: 1,
      currency: 'USD',
      before_state_hash: hashCanonicalAction(beforeState),
    };
    const contract = buildExecutionBindingContract({ canonicalAction: action, decision: { signoffRequired: true } });
    const check = verifyExecutionBindingContract({
      contract,
      executedAction: action,
      observedAction: { ...action, before_state_hash: undefined, before_state: beforeState },
    });
    expect(check.mismatched_fields).not.toContain('before_state_hash');
  });

  it('derives after_state_hash from an observed after_state object (no direct hash present)', () => {
    const afterState = { status: 'released' };
    const action = {
      ...BASE,
      action_type: 'large_payment_release',
      amount: 1,
      currency: 'USD',
      after_state_hash: hashCanonicalAction(afterState),
    };
    const contract = buildExecutionBindingContract({ canonicalAction: action, decision: { signoffRequired: true } });
    const check = verifyExecutionBindingContract({
      contract,
      executedAction: { ...action, after_state_hash: undefined },
      observedAction: { ...action, after_state_hash: undefined, after_state: afterState },
    });
    expect(check.mismatched_fields).not.toContain('after_state_hash');
  });

  it('treats a non-object observed state as a missing state hash (fail-closed derivation)', () => {
    const afterState = { status: 'released' };
    const action = {
      ...BASE,
      action_type: 'large_payment_release',
      amount: 1,
      currency: 'USD',
      after_state_hash: hashCanonicalAction(afterState),
    };
    const contract = buildExecutionBindingContract({ canonicalAction: action, decision: { signoffRequired: true } });
    const check = verifyExecutionBindingContract({
      contract,
      executedAction: { ...action, after_state_hash: undefined },
      observedAction: { ...action, after_state_hash: undefined, after_state: 'not-an-object' },
    });
    expect(check.ok).toBe(false);
    expect(check.missing_fields).toContain('after_state_hash');
  });
});

// The contract reaches verifyExecutionBindingContract from the database
// (app/api/v1/trust-receipts/[receiptId]/execution/route.ts reads it out of
// `created.after_state.execution_binding`), so at verify time the field names
// are untrusted input rather than a compile-time allowlist.
//
// Every fixture here is built with JSON.parse, which is how the contract and the
// observed action actually arrive. An object literal `{ __proto__: v }` is the
// prototype-setter syntax and creates NO own key, so it does not reproduce any
// of this; JSON.parse creates a real own '__proto__' property.
describe('execution-binding contract: prototype-named fields', () => {
  it('covers an observed field named __proto__ in observed_hash', () => {
    const contract = JSON.parse(
      '{"required":true,"required_fields":["__proto__"],"field_values":{"__proto__":250000},"field_hash":"x"}',
    );
    const observed = JSON.parse('{"__proto__":999999}');

    const check = verifyExecutionBindingContract({ contract, observedAction: observed, executedAction: {} });

    // The divergence is caught either way; the defect was that observed_hash
    // attested to a digest that did not cover the field it named.
    expect(check.mismatched_fields).toContain('__proto__');
    expect(Object.prototype.hasOwnProperty.call(check.observed_values, '__proto__')).toBe(true);
    expect(check.observed_values.__proto__).toBe(999999);
    expect(check.observed_hash).toBe(hashCanonicalAction(check.observed_values));
    expect(check.observed_hash).not.toBe(hashCanonicalAction({}));
  });

  it('keeps an object-valued __proto__ in the digest instead of repointing the accumulator', () => {
    const contract = JSON.parse(
      '{"required":true,"required_fields":["__proto__","amount"],"field_values":{"__proto__":{"x":1},"amount":5},"field_hash":"x"}',
    );
    const observed = JSON.parse('{"__proto__":{"x":2},"amount":5}');

    const check = verifyExecutionBindingContract({ contract, observedAction: observed, executedAction: {} });

    expect(check.mismatched_fields).toContain('__proto__');
    expect(check.observed_values.__proto__).toEqual({ x: 2 });
    expect(Object.keys(check.observed_values).sort()).toEqual(['__proto__', 'amount']);
    expect(check.observed_hash).toBe(hashCanonicalAction(check.observed_values));
  });

  it.each(['__proto__', 'toString', 'constructor', 'valueOf', 'hasOwnProperty'])(
    'refuses an unbound field named %s with a reason instead of throwing',
    (name) => {
      // required_fields names the field but field_values carries no own entry for
      // it, while the observed action does supply it. Reading the expected value
      // off Object.prototype made toString/constructor/valueOf reach
      // hashCanonicalAction as a function and throw a TypeError, which the route
      // turns into a 500 rather than a binding refusal.
      const contract = JSON.parse(JSON.stringify({
        required: true, required_fields: [name], field_values: {}, field_hash: 'x',
      }));
      const observed = JSON.parse(`{"${name}":999}`);

      const check = verifyExecutionBindingContract({ contract, observedAction: observed, executedAction: {} });

      expect(check.ok).toBe(false);
      expect(check.missing_fields).toContain(name);
    },
  );

  it.each(['__proto__', 'toString', 'constructor', 'valueOf'])(
    'resolves material fields for an action_type named %s without throwing',
    (actionType) => {
      // ACTION_FIELD_MAP[actionType] returned an Object.prototype member for these
      // names, and spreading that non-iterable value threw. The HTTP route
      // allowlists action_type, but these functions are exported and must not
      // make that allowlist load-bearing.
      expect(() => actionMaterialFields(actionType)).not.toThrow();
      expect(actionMaterialFields(actionType)).toEqual(expect.arrayContaining(['organization_id', 'actor_id']));

      const contract = buildExecutionBindingContract({
        canonicalAction: { ...BASE, action_type: actionType, amount: 1 },
        decision: { signoffRequired: true },
      });
      expect(contract.required_fields).toContain('amount');
    },
  );

  it('advertises a bound __proto__ field in required_fields and field_hash', () => {
    // required_fields is published from the names recorded at acceptance rather
    // than read back out of the accumulator, so a bound field cannot be dropped
    // from the advertised list by the shape of its own name.
    const contract = buildExecutionBindingContract({
      canonicalAction: JSON.parse(`{"action_type":"large_payment_release","amount":7,"currency":"USD",
        "organization_id":"org_1","actor_id":"ep:entity:operator","target_resource_id":"acct:1"}`),
      decision: { signoffRequired: true },
    });

    expect(contract.required_fields).toEqual([...contract.required_fields].sort());
    expect(contract.required_fields).toContain('amount');
    expect(contract.field_hash).toBe(hashCanonicalAction(contract.field_values));
    // Every advertised required field is actually bound in field_values.
    for (const field of contract.required_fields) {
      expect(Object.prototype.hasOwnProperty.call(contract.field_values, field)).toBe(true);
    }
  });
});
