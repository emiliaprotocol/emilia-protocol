// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';

import { renderAction, RENDER_PROFILE } from '../lib/wysiwys/render.js';

const LEGACY_ACTION = Object.freeze({
  action_type: 'payment.release',
  target_resource_id: 'wire/8841',
  organization_id: 'org:acme',
  actor_id: 'ep:agent:worker-7',
  policy_id: 'ep:policy:wires-over-100k@v12',
  amount: 82000,
  currency: 'USD',
  requested_at: '2026-06-13T17:21:04.000Z',
  risk_flags: ['new_destination'],
});

const POLICY_ROLLOUT_ACTION = Object.freeze({
  ...LEGACY_ACTION,
  action_type: 'policy.rollout',
  executing_key_id: 'ep:key:operator#2026-07',
  rollout_policy_id: 'pol_01JZ8M3R6V',
  rollout_policy_key: 'payments.high_value',
  rollout_policy_version: 7,
  rollout_policy_rules: {
    threshold: { maximum: 100000, currency: 'USD' },
    enabled: true,
    approvals: ['finance', 'security'],
  },
  rollout_environment: 'production',
  rollout_strategy: 'canary',
  rollout_canary_pct: 10,
  rollout_metadata: {
    regions: ['us-east-1', 'us-west-2'],
    initiated_by: { user: 'alice', team: 'platform' },
    change_ticket: 'CHG-2048',
  },
  rollout_before_state: {
    version: 6,
    strategy: 'all-at-once',
    rules: { limit: 50000, approval_count: 1 },
    environment: 'production',
    canary_pct: 0,
  },
  rollout_after_state: {
    version: 7,
    strategy: 'canary',
    rules: { limit: 100000, approval_count: 2 },
    environment: 'production',
    canary_pct: 10,
  },
});

const MATERIAL_RENDERINGS = Object.freeze({
  executing_key_id: ['Executing key ID', 'ep:key:operator#2026-07'],
  rollout_policy_id: ['Rollout policy ID', 'pol_01JZ8M3R6V'],
  rollout_policy_key: ['Rollout policy key', 'payments.high_value'],
  rollout_policy_version: ['Rollout policy version', '7'],
  rollout_policy_rules: [
    'Rollout policy rules',
    '{"approvals":["finance","security"],"enabled":true,"threshold":{"currency":"USD","maximum":100000}}',
  ],
  rollout_environment: ['Rollout environment', 'production'],
  rollout_strategy: ['Rollout strategy', 'canary'],
  rollout_canary_pct: ['Rollout canary percent', '10'],
  rollout_metadata: [
    'Rollout metadata',
    '{"change_ticket":"CHG-2048","initiated_by":{"team":"platform","user":"alice"},"regions":["us-east-1","us-west-2"]}',
  ],
  rollout_before_state: [
    'Rollout before state',
    '{"canary_pct":0,"environment":"production","rules":{"approval_count":1,"limit":50000},"strategy":"all-at-once","version":6}',
  ],
  rollout_after_state: [
    'Rollout after state',
    '{"canary_pct":10,"environment":"production","rules":{"approval_count":2,"limit":100000},"strategy":"canary","version":7}',
  ],
});

const CHANGED_MATERIAL = Object.freeze({
  executing_key_id: 'ep:key:operator#2026-08',
  rollout_policy_id: 'pol_01JZ8M3R7W',
  rollout_policy_key: 'payments.high_value.v2',
  rollout_policy_version: 8,
  rollout_policy_rules: {
    threshold: { maximum: 125000, currency: 'USD' },
    enabled: true,
    approvals: ['finance', 'security'],
  },
  rollout_environment: 'staging',
  rollout_strategy: 'blue-green',
  rollout_canary_pct: 25,
  rollout_metadata: {
    regions: ['us-east-1', 'us-west-2'],
    initiated_by: { user: 'alice', team: 'platform' },
    change_ticket: 'CHG-2049',
  },
  rollout_before_state: {
    version: 6,
    strategy: 'all-at-once',
    rules: { limit: 55000, approval_count: 1 },
    environment: 'production',
    canary_pct: 0,
  },
  rollout_after_state: {
    version: 7,
    strategy: 'canary',
    rules: { limit: 125000, approval_count: 2 },
    environment: 'production',
    canary_pct: 10,
  },
});

describe('WYSIWYS policy-rollout rendering', () => {
  it('preserves the frozen v1 rendering for actions without rollout material', () => {
    const rendered = renderAction(LEGACY_ACTION);

    expect(rendered.render_profile).toBe(RENDER_PROFILE);
    expect(rendered.text).toBe([
      'Action: payment.release',
      'Target: wire/8841',
      'Organization: org:acme',
      'Initiator: ep:agent:worker-7',
      'Policy: ep:policy:wires-over-100k@v12',
      'Amount: 82000',
      'Currency: USD',
      'Requested: 2026-06-13T17:21:04.000Z',
      'Risk signals: new_destination',
    ].join('\n'));
    expect(rendered.display_hash).toBe(
      'sha256:bed13087f9c035f741dccead15f884187a689e6ce4d57017bd02abcbc4683f99',
    );
  });

  it('names and displays every material field in readable canonical form', () => {
    const rendered = renderAction(POLICY_ROLLOUT_ACTION);

    for (const [field, [label, value]] of Object.entries(MATERIAL_RENDERINGS)) {
      expect(rendered.lines, field).toContainEqual({ label, value });
      expect(rendered.text, field).toContain(`${label}: ${value}`);
    }
    expect(rendered.text).not.toContain('[object Object]');
  });

  for (const [field, changedValue] of Object.entries(CHANGED_MATERIAL)) {
    it(`changing ${field} changes display_hash`, () => {
      const baseline = renderAction(POLICY_ROLLOUT_ACTION);
      const changed = renderAction({ ...POLICY_ROLLOUT_ACTION, [field]: changedValue });

      expect(changed.display_hash).not.toBe(baseline.display_hash);
    });
  }

  it('renders structured material identically regardless of object insertion order', () => {
    const reordered = {
      ...POLICY_ROLLOUT_ACTION,
      rollout_policy_rules: {
        approvals: ['finance', 'security'],
        enabled: true,
        threshold: { currency: 'USD', maximum: 100000 },
      },
      rollout_metadata: {
        change_ticket: 'CHG-2048',
        initiated_by: { team: 'platform', user: 'alice' },
        regions: ['us-east-1', 'us-west-2'],
      },
      rollout_before_state: {
        canary_pct: 0,
        environment: 'production',
        rules: { approval_count: 1, limit: 50000 },
        strategy: 'all-at-once',
        version: 6,
      },
      rollout_after_state: {
        canary_pct: 10,
        environment: 'production',
        rules: { approval_count: 2, limit: 100000 },
        strategy: 'canary',
        version: 7,
      },
    };

    expect(renderAction(reordered)).toEqual(renderAction(POLICY_ROLLOUT_ACTION));
  });
});
