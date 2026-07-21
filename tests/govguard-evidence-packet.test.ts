// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import {
  GG1_CHECKS,
  buildGovGuardEvidencePacket,
  effectiveGovGuardDecision,
} from '../lib/govguard-evidence-packet.js';

describe('GovGuard evidence packet', () => {
  it('exports procurement-grade observe-mode evidence with GG-1 controls', () => {
    const packet = buildGovGuardEvidencePacket({
      pilotId: 'pilot_gov_1',
      generatedAt: '2026-06-29T00:00:00.000Z',
      events: [
        {
          target_id: 'tr_1',
          created_at: '2026-06-29T00:00:00.000Z',
          after_state: {
            action_type: 'gov.vendor_payment_destination_change',
            target_resource_id: 'vendor:123',
            enforcement_mode: 'observe',
            decision: 'observe',
            observed_decision: 'allow_with_signoff',
            required_assurance: 'A',
            policy_id: 'policy_gov_vendor_payment_destination_change_v1',
            policy_hash: 'policy_hash',
            action_hash: 'action_hash',
            execution_binding: { field_hash: 'field_hash' },
            reasons: ['Government vendor payment-destination change requires accountable signoff before future payments can route.'],
          },
        },
        {
          target_id: 'tr_2',
          created_at: '2026-06-29T00:01:00.000Z',
          after_state: {
            action_type: 'benefit_address_change',
            enforcement_mode: 'observe',
            decision: 'allow',
          },
        },
      ],
    });

    expect(packet['@version']).toBe('GG-EVIDENCE-PACKET-v1');
    expect(packet.summary.total_actions).toBe(2);
    expect(packet.summary.would_require_signoff).toBe(1);
    expect(packet.high_risk_actions).toHaveLength(1);
    expect(packet.high_risk_actions[0]).toMatchObject({
      receipt_id: 'tr_1',
      action_type: 'gov.vendor_payment_destination_change',
      required_assurance: 'A',
      policy_hash: 'policy_hash',
      action_hash: 'action_hash',
      execution_binding_hash: 'field_hash',
    });
    expect(packet.verification.offline_command).toContain('@emilia-protocol/verify');
    expect(packet.gg1.badge).toBe('GG-1 Enforced');
    expect(packet.gg1.checks.map((c) => c.id)).toEqual(GG1_CHECKS.map((c) => c.id));
  });

  it('uses observed_decision as the enforce-mode decision in observe mode', () => {
    expect(effectiveGovGuardDecision({
      enforcement_mode: 'observe',
      decision: 'observe',
      observed_decision: 'deny',
    })).toBe('deny');
    expect(effectiveGovGuardDecision({
      enforcement_mode: 'enforce',
      decision: 'allow_with_signoff',
    })).toBe('allow_with_signoff');
  });
});
