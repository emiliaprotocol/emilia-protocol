// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';

import {
  CRASH_SCENARIOS,
  buildCanonicalAction,
  getCrashScenario,
} from '../lib/crash-scenarios';

describe('crash-test scenario catalog', () => {
  it('keeps every published scenario addressable by its stable identifier', () => {
    expect(CRASH_SCENARIOS.map((scenario) => scenario.id)).toEqual([
      'treasury-wire',
      'prod-db-drop',
      'benefits-redirect',
      'pii-exfil',
    ]);

    for (const scenario of CRASH_SCENARIOS) {
      expect(getCrashScenario(scenario.id)).toBe(scenario);
    }
    expect(getCrashScenario('not-a-scenario')).toBeNull();
  });

  it('builds the exact deterministic action used by the demo boundary', () => {
    const scenario = getCrashScenario('treasury-wire');
    expect(scenario).not.toBeNull();
    expect(buildCanonicalAction(scenario!)).toEqual({
      organization_id: 'demo_org',
      actor_id: 'autonomous_ai_agent',
      action_type: 'ai_agent_payment_action',
      target_changed_fields: ['bank_account', 'routing_number'],
      amount_usd: 2_400_000,
      risk_flags: [
        'NEW_DESTINATION',
        'PROMPT_INJECTION_SUSPECTED',
        'AFTER_HOURS',
        'NO_PRIOR_CHANGE_30D',
      ],
      requested_at: '2026-06-01T03:11:42Z',
    });
  });

  it('normalizes optional action fields without manufacturing values', () => {
    expect(buildCanonicalAction({
      actionType: 'bounded_test_action',
      requestedAt: '2026-08-15T00:00:00Z',
    })).toEqual({
      organization_id: 'demo_org',
      actor_id: 'autonomous_ai_agent',
      action_type: 'bounded_test_action',
      target_changed_fields: [],
      amount_usd: null,
      risk_flags: [],
      requested_at: '2026-08-15T00:00:00Z',
    });
  });
});
