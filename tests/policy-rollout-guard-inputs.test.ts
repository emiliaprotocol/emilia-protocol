// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import {
  extractGuardActionDetails,
  validateGuardActionInput,
} from '../lib/guard-action-inputs.js';
import { GUARD_ACTION_TYPES } from '../lib/guard-policies.js';

const valid = () => ({
  action_type: GUARD_ACTION_TYPES.POLICY_ROLLOUT,
  target_resource_id: 'policy:strict',
  executing_key_id: 'key-abc123',
  rollout_policy_id: '11111111-1111-4111-8111-111111111111',
  rollout_policy_key: 'strict',
  rollout_policy_version: 2,
  rollout_policy_rules: { deny: ['compromised'] },
  rollout_policy_mode: 'mutual',
  rollout_policy_status: 'active',
  rollout_environment: 'production',
  rollout_strategy: 'immediate',
  rollout_canary_pct: null,
  rollout_metadata: { ticket: 'CAB-42' },
  before_state: { active_rollouts: [] },
  after_state: {
    policy_id: '11111111-1111-4111-8111-111111111111',
    policy_key: 'strict',
    policy_version: 2,
    policy_rules: { deny: ['compromised'] },
    policy_mode: 'mutual',
    policy_status: 'active',
    environment: 'production',
    strategy: 'immediate',
    canary_pct: null,
    metadata: { ticket: 'CAB-42' },
  },
  expires_in_sec: 900,
});

describe('policy rollout Trust Receipt input', () => {
  it('accepts and extracts every execution-material field', () => {
    const body = valid();
    expect(validateGuardActionInput(body, {
      actionType: GUARD_ACTION_TYPES.POLICY_ROLLOUT,
      changedFields: [],
    })).toBeNull();

    expect(extractGuardActionDetails(body)).toMatchObject({
      executing_key_id: body.executing_key_id,
      rollout_policy_id: body.rollout_policy_id,
      rollout_policy_key: body.rollout_policy_key,
      rollout_policy_version: body.rollout_policy_version,
      rollout_policy_rules: body.rollout_policy_rules,
      rollout_policy_mode: body.rollout_policy_mode,
      rollout_policy_status: body.rollout_policy_status,
      rollout_environment: body.rollout_environment,
      rollout_strategy: body.rollout_strategy,
      rollout_canary_pct: null,
      rollout_metadata: body.rollout_metadata,
      rollout_before_state: body.before_state,
      rollout_after_state: body.after_state,
    });
  });

  it.each([
    ['target substitution', (body) => { body.target_resource_id = 'policy:other'; }, 'rollout_target_mismatch'],
    ['rules substitution', (body) => { body.after_state.policy_rules = { allow: ['all'] }; }, 'rollout_after_state_mismatch'],
    ['metadata substitution', (body) => { body.after_state.metadata = { ticket: 'CAB-99' }; }, 'rollout_after_state_mismatch'],
    ['overlong lifetime', (body) => { body.expires_in_sec = 901; }, 'invalid_rollout_expiry'],
    ['invalid canary', (body) => {
      body.rollout_strategy = 'canary';
      body.rollout_canary_pct = 0;
    }, 'invalid_rollout_canary_pct'],
  ])('fails closed on %s', (_name, mutate, code) => {
    const body = valid();
    mutate(body);
    expect(validateGuardActionInput(body, {
      actionType: GUARD_ACTION_TYPES.POLICY_ROLLOUT,
      changedFields: [],
    })).toMatchObject({ status: 400, code });
  });
});
