// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest';
import {
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
