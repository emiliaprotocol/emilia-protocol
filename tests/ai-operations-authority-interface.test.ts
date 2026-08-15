// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';

import {
  AUTHORITY_OPERATIONS_INTERFACE_VERSION,
  beginProviderEntry,
  createAuthorityOperation,
  intervene,
  presentAuthorizationEvidence,
  projectAuthorityOperation,
  recordProviderOutcome,
  reserveAuthorityOperation,
} from '../examples/ai-operations-authority-interface/index.mjs';

const NOW = '2026-08-14T20:00:00.000Z';
const D = (character: string) => `sha256:${character.repeat(64)}`;

const action = {
  action_type: 'network.route-policy.apply',
  target: {
    controller: 'sdn-controller-east',
    site_id: 'site-17',
    policy_id: 'route-policy:core-b',
  },
  parameters: {
    prefixes: ['198.51.100.0/24'],
    estimated_customer_impact_percent: '2.0',
    change_window: '2026-08-14T20:10:00Z/2026-08-14T20:20:00Z',
  },
};

const policy = {
  policy_id: 'network-operations-authority-v1',
  policy_digest: D('1'),
  action_type: action.action_type,
  mode: 'AUTOMATIC_WITHIN_ENVELOPE',
  evaluator_profile: 'network-impact-policy:v1',
  outside_envelope: 'FRESH_AUTHORIZATION_REQUIRED',
  indeterminate: 'REFUSE',
  required_evidence: [{
    evidence_type: 'ep-quorum',
    role: 'network-change-approver',
    minimum: 2,
  }],
};

function operation(policyResult = 'OUTSIDE_ENVELOPE') {
  return createAuthorityOperation({
    operation_id: 'operation:route-site-17',
    action,
    policy,
    policy_result: policyResult,
    observed_at: NOW,
  });
}

describe('AI Operations authority and intervention reference interface', () => {
  it('exposes the exact proposed target and parameters before execution', () => {
    const view = projectAuthorityOperation(operation());

    expect(view['@version']).toBe(AUTHORITY_OPERATIONS_INTERFACE_VERSION);
    expect(view.proposed_action.action).toEqual(action);
    expect(view.proposed_action.action_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(view.execution.provider_attempt).toBe('NOT_ENTERED');
    expect(view.execution.state).toBe('AUTHORIZATION_REQUIRED');
  });

  it('signals the exact additional human evidence required', () => {
    const view = projectAuthorityOperation(operation());

    expect(view.authorization.state).toBe('REQUIRED');
    expect(view.authorization.signal).toEqual({
      code: 'additional_authorization_required',
      requirements: policy.required_evidence,
    });
    expect(view.management.available_interventions).toContain('cancel_before_entry');
  });

  it('refuses verified authorization evidence bound to a different action', () => {
    const current = operation();
    const next = presentAuthorizationEvidence(current, {
      evidence_type: 'ep-quorum',
      role: 'network-change-approver',
      evidence_digest: D('2'),
      action_digest: D('3'),
      verification: 'VERIFIED',
      subjects: ['operator:alice', 'operator:bob'],
    }, '2026-08-14T20:01:00.000Z');

    const view = projectAuthorityOperation(next);
    expect(view.authorization.state).toBe('REQUIRED');
    expect(view.execution.state).toBe('AUTHORIZATION_REQUIRED');
    expect(view.history.at(-1)).toMatchObject({
      type: 'AUTHORIZATION_REJECTED',
      reason: 'action_binding_mismatch',
    });
  });

  it('accepts matching quorum evidence and exposes the full lifecycle', () => {
    let current = operation();
    current = presentAuthorizationEvidence(current, {
      evidence_type: 'ep-quorum',
      role: 'network-change-approver',
      evidence_digest: D('2'),
      action_digest: current.action_digest,
      verification: 'VERIFIED',
      subjects: ['operator:alice', 'operator:bob'],
    }, '2026-08-14T20:01:00.000Z');
    current = reserveAuthorityOperation(current, '2026-08-14T20:02:00.000Z');
    current = beginProviderEntry(current, '2026-08-14T20:03:00.000Z');
    current = recordProviderOutcome(current, {
      value: 'COMMITTED',
      evidence_digest: D('4'),
      resulting_state: { active_route_policy: 'route-policy:core-b' },
    }, '2026-08-14T20:04:00.000Z');

    const view = projectAuthorityOperation(current);
    expect(view.authorization.state).toBe('SATISFIED');
    expect(view.execution).toMatchObject({
      state: 'COMMITTED',
      provider_attempt: 'ENTERED',
      outcome: 'COMMITTED',
      reconciliation_required: false,
      retry_safe: false,
      resulting_state: { active_route_policy: 'route-policy:core-b' },
    });
    expect(view.history.map((event: any) => event.type)).toEqual([
      'ACTION_PROPOSED',
      'AUTHORIZATION_REQUIRED',
      'AUTHORIZATION_ACCEPTED',
      'AUTHORITY_RESERVED',
      'PROVIDER_ENTERED',
      'PROVIDER_OUTCOME_RECORDED',
    ]);
  });

  it('allows automatic operation only after the pinned policy says it is inside the envelope', () => {
    const within = projectAuthorityOperation(operation('WITHIN_ENVELOPE'));
    expect(within.authorization.state).toBe('NOT_REQUIRED');
    expect(within.execution.state).toBe('READY');

    const unknown = projectAuthorityOperation(operation('INDETERMINATE'));
    expect(unknown.authorization.state).toBe('INDETERMINATE');
    expect(unknown.execution.state).toBe('REFUSED');
  });

  it('lets an operator stop a pre-entry action without relabeling an entered one', () => {
    const cancelled = projectAuthorityOperation(intervene(
      operation('WITHIN_ENVELOPE'),
      { type: 'CANCEL_BEFORE_ENTRY', actor_id: 'operator:alice', reason: 'maintenance_window_closed' },
      '2026-08-14T20:01:00.000Z',
    ));
    expect(cancelled.execution.state).toBe('REFUSED');
    expect(cancelled.execution.provider_attempt).toBe('NOT_ENTERED');

    let entered = reserveAuthorityOperation(operation('WITHIN_ENVELOPE'), '2026-08-14T20:01:00.000Z');
    entered = beginProviderEntry(entered, '2026-08-14T20:02:00.000Z');
    const afterEntry = projectAuthorityOperation(intervene(
      entered,
      { type: 'CANCEL_BEFORE_ENTRY', actor_id: 'operator:alice', reason: 'too_late' },
      '2026-08-14T20:03:00.000Z',
    ));
    expect(afterEntry.execution.state).toBe('PROVIDER_ENTERED');
    expect(afterEntry.execution.provider_attempt).toBe('ENTERED');
    expect(afterEntry.history.at(-1)).toMatchObject({
      type: 'INTERVENTION_REFUSED',
      reason: 'provider_already_entered',
    });
  });

  it('keeps a lost provider acknowledgement unsettled and unsafe to retry', () => {
    let current = reserveAuthorityOperation(operation('WITHIN_ENVELOPE'), '2026-08-14T20:01:00.000Z');
    current = beginProviderEntry(current, '2026-08-14T20:02:00.000Z');
    current = recordProviderOutcome(current, {
      value: 'INDETERMINATE',
      evidence_digest: null,
      resulting_state: null,
    }, '2026-08-14T20:03:00.000Z');

    const view = projectAuthorityOperation(current);
    expect(view.execution.state).toBe('INDETERMINATE');
    expect(view.execution.reconciliation_required).toBe(true);
    expect(view.execution.retry_safe).toBe(false);
    expect(view.management.available_interventions).toContain('reconcile');
  });

  it('freezes new admissions without claiming to stop an already entered effect', () => {
    let current = reserveAuthorityOperation(operation('WITHIN_ENVELOPE'), '2026-08-14T20:01:00.000Z');
    current = beginProviderEntry(current, '2026-08-14T20:02:00.000Z');
    current = intervene(current, {
      type: 'FREEZE_NEW_ADMISSIONS',
      actor_id: 'operator:alice',
      reason: 'incident_response',
    }, '2026-08-14T20:03:00.000Z');

    const view = projectAuthorityOperation(current);
    expect(view.management.control_state).toBe('FROZEN');
    expect(view.execution.state).toBe('PROVIDER_ENTERED');
    expect(view.execution.provider_attempt).toBe('ENTERED');
    expect(view.management.limitations).toContain(
      'A freeze blocks new admissions at covered boundaries; it does not stop computation or undo an entered effect.',
    );
  });

  it('refuses a management view when the proposed action changed without a new digest', () => {
    const current = operation();
    current.action.target.site_id = 'site-99';

    expect(() => projectAuthorityOperation(current)).toThrow(
      'authority_operations:action_digest_mismatch',
    );
  });

  it('refuses a management view whose event history was rewritten', () => {
    const current = operation();
    current.history[1].sequence = 1;

    expect(() => projectAuthorityOperation(current)).toThrow(
      'authority_operations:history_invalid',
    );
  });
});
