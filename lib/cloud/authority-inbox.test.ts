// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import {
  authorityInboxMetrics,
  blindRetryNotice,
  buildAuthorityNotification,
  projectAuthorityInboxEntry,
  simulateAuthorityPolicy,
  type AuthorityInboxSource,
} from './authority-inbox.js';

const base: AuthorityInboxSource = {
  receipt_id: 'r_01',
  action_hash: `sha256:${'a'.repeat(64)}`,
  action_caid: 'caid:example:payment-release',
  action_type: 'large_payment_release',
  amount: 125_000,
  currency: 'USD',
  counterparty_name: 'Northwind Parts',
  target_resource_id: 'invoice-8813',
  payment_destination_hash: `sha256:${'b'.repeat(64)}`,
  created_at: '2026-08-18T10:00:00.000Z',
  expires_at: '2026-08-18T11:00:00.000Z',
  status: 'pending',
  signoff_id: 'sig_01',
  approver_id: 'finance@example.com',
  approver_role: 'controller',
  required_assurance: 'A',
  profile_digest: `sha256:${'c'.repeat(64)}`,
  review_path: '/signoff/sig_01',
  consumed_at: null,
  decision_at: null,
};

describe('authority inbox projection', () => {
  it('projects the approval path without inventing consequence progress', () => {
    expect(projectAuthorityInboxEntry({ ...base, status: 'receipt_required' }).state)
      .toBe('RECEIPT_REQUIRED');
    expect(projectAuthorityInboxEntry(base).state).toBe('WAITING_FOR_APPROVER');
    expect(projectAuthorityInboxEntry({ ...base, status: 'approved' }).state)
      .toBe('AUTHORIZED_NOT_ADMITTED');

    const consumed = projectAuthorityInboxEntry({
      ...base,
      status: 'consumed',
      consumed_at: '2026-08-18T10:10:00.000Z',
    });
    expect(consumed.state).toBe('INDETERMINATE');
    expect(consumed.named_refusal).toBe('authority_consumed_outcome_unobserved');
    expect(consumed.one_time_status).toBe('consumed');
    expect(consumed.outcome_source).toBeNull();
  });

  it('requires independently established lifecycle evidence for later states', () => {
    expect(projectAuthorityInboxEntry({
      ...base,
      status: 'approved',
      provider_entry: {
        established: true,
        at: '2026-08-18T10:05:00.000Z',
        source: 'gate-admission-store',
      },
    }).state).toBe('ADMITTED');

    expect(projectAuthorityInboxEntry({
      ...base,
      status: 'consumed',
      provider_entry: {
        established: true,
        at: '2026-08-18T10:05:00.000Z',
        source: 'gate-admission-store',
      },
      execution: {
        state: 'EXECUTED',
        at: '2026-08-18T10:06:00.000Z',
        source: 'provider-outcome-attestation',
      },
    }).state).toBe('EXECUTED');

    expect(projectAuthorityInboxEntry({
      ...base,
      status: 'consumed',
      execution: {
        state: 'INDETERMINATE',
        at: '2026-08-18T10:06:00.000Z',
        source: 'gate-admission-store',
      },
      reconciliation: {
        established: true,
        at: '2026-08-18T10:20:00.000Z',
        source: 'provider-reconciliation',
      },
    }).state).toBe('RECONCILED');
  });

  it('keeps refusals and material changes visible', () => {
    const item = projectAuthorityInboxEntry({
      ...base,
      status: 'rejected',
      material_changes: ['payment_destination_hash'],
      named_refusal: 'execution_binding_failed',
    });
    expect(item.state).toBe('FAILED_BEFORE_EFFECT');
    expect(item.material_changes).toEqual(['payment_destination_hash']);
    expect(item.named_refusal).toBe('execution_binding_failed');
  });
});

describe('authority inbox metrics', () => {
  it('measures only timestamps established by the records', () => {
    const items = [
      projectAuthorityInboxEntry({
        ...base,
        status: 'approved',
        decision_at: '2026-08-18T10:02:00.000Z',
      }),
      projectAuthorityInboxEntry({
        ...base,
        receipt_id: 'r_02',
        status: 'expired',
      }),
      projectAuthorityInboxEntry({
        ...base,
        receipt_id: 'r_03',
        status: 'consumed',
        consumed_at: '2026-08-18T10:03:00.000Z',
      }),
      projectAuthorityInboxEntry({
        ...base,
        receipt_id: 'r_04',
        status: 'consumed',
        execution: {
          state: 'INDETERMINATE',
          at: '2026-08-18T10:05:00.000Z',
          source: 'gate-admission-store',
        },
        reconciliation: {
          established: true,
          at: '2026-08-18T10:15:00.000Z',
          source: 'provider-reconciliation',
        },
      }),
    ];

    const metrics = authorityInboxMetrics(items, '2026-08-18T10:30:00.000Z');
    expect(metrics.approval_latency_ms).toBe(120_000);
    expect(metrics.expired_count).toBe(1);
    expect(metrics.abandoned_count).toBe(1);
    expect(metrics.oldest_indeterminate_age_ms).toBe(1_620_000);
    expect(metrics.reconciliation_time_ms).toBe(600_000);
  });
});

describe('policy simulation and notifications', () => {
  it('surfaces a prior indeterminate attempt before any new authority', () => {
    const item = projectAuthorityInboxEntry({
      ...base,
      status: 'consumed',
      consumed_at: '2026-08-18T10:10:00.000Z',
    });
    expect(blindRetryNotice(item)).toEqual({
      prior_attempt_state: 'INDETERMINATE',
      prior_receipt_id: 'r_01',
      retry_safe: false,
      required_next_step: 'AUTHENTICATED_RECONCILIATION',
      authorizes_new_authority: false,
    });
    expect(blindRetryNotice(projectAuthorityInboxEntry(base))).toBeNull();
  });

  it('returns a non-authorizing policy preview', () => {
    const result = simulateAuthorityPolicy({
      action_type: 'large_payment_release',
      amount: 125_000,
      policy: {
        protected_action_types: ['large_payment_release'],
        approval_threshold: 100_000,
        required_assurance: 'A',
      },
    });
    expect(result.verdict).toBe('WOULD_REQUIRE_AUTHORITY');
    expect(result.mode).toBe('simulation');
    expect(result.authorizes).toBe(false);
    expect(result.consumes_authority).toBe(false);
    expect(result.receipt_id).toBeNull();
  });

  it('refuses malformed values and can preview an unguarded classification', () => {
    const refused = simulateAuthorityPolicy({
      action_type: 'read_inventory',
      amount: -1,
      policy: { protected_action_types: [] },
    });
    expect(refused.verdict).toBe('WOULD_REFUSE');
    expect(refused.reason).toBe('amount_invalid');

    const unguarded = simulateAuthorityPolicy({
      action_type: 'read_inventory',
      amount: 5,
      policy: {
        protected_action_types: ['large_payment_release'],
        approval_threshold: 100_000,
      },
    });
    expect(unguarded.verdict).toBe('WOULD_ALLOW_UNGUARDED');
    expect(unguarded.reason).toBe('no_simulated_authority_requirement');
    expect(unguarded.authorizes).toBe(false);

    const invalid = simulateAuthorityPolicy({
      action_type: '',
      policy: { protected_action_types: [] },
    });
    expect(invalid.verdict).toBe('INDETERMINATE');
    expect(invalid.reason).toBe('simulation_input_invalid');

    const threshold = simulateAuthorityPolicy({
      action_type: 'inventory_export',
      amount: 100_000,
      policy: { protected_action_types: [], approval_threshold: 100_000 },
    });
    expect(threshold.verdict).toBe('WOULD_REQUIRE_AUTHORITY');
    expect(threshold.reason).toBe('approval_threshold_met');
  });

  it('builds a delivery-neutral notification that cannot authorize', () => {
    const item = projectAuthorityInboxEntry(base);
    const notification = buildAuthorityNotification(item, 'state_changed');
    expect(notification.delivery_state).toBe('NOT_ATTEMPTED');
    expect(notification.authorizes).toBe(false);
    expect(notification.receipt_id).toBe(item.receipt_id);
    expect(notification.state).toBe('WAITING_FOR_APPROVER');
  });
});
