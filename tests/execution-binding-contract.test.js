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
