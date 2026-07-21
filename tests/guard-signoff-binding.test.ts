// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import {
  boundSignoffDecisionEvents,
  creatorBoundSignoffRequests,
  decisionMatchesRequest,
  findBoundSignoffDecision,
} from '../lib/guard-signoff-binding.js';

const created = {
  event_type: 'guard.trust_receipt.created',
  actor_id: 'creator',
  after_state: { action_hash: 'a' },
};

describe('guard signoff binding predicates', () => {
  it('keeps only signoff requests made by the receipt creator', () => {
    const requests = creatorBoundSignoffRequests([
      created,
      { event_type: 'guard.signoff.requested', actor_id: 'creator', after_state: { signoff_id: 'sig_good', approver_id: 'approver_1' } },
      { event_type: 'guard.signoff.requested', actor_id: 'attacker', after_state: { signoff_id: 'sig_bad', approver_id: 'attacker_approver' } },
    ], created);

    expect(requests.map((r) => r.signoff_id)).toEqual(['sig_good']);
  });

  it('enforces the intended approver for single-signoff requests', () => {
    const request = { signoff_id: 'sig_1', approver_id: 'approver_1' };

    expect(decisionMatchesRequest({
      event_type: 'guard.signoff.approved',
      actor_id: 'approver_1',
      after_state: { signoff_id: 'sig_1' },
    }, request)).toBe(true);

    expect(decisionMatchesRequest({
      event_type: 'guard.signoff.approved',
      actor_id: 'wrong_approver',
      after_state: { signoff_id: 'sig_1' },
    }, request)).toBe(false);
  });

  it('enforces the intended approver for quorum-seat requests', () => {
    const request = {
      signoff_id: 'sig_q1',
      quorum: { role: 'controller', approver_id: 'controller_1' },
    };

    expect(decisionMatchesRequest({
      event_type: 'guard.signoff.approved',
      actor_id: 'controller_1',
      after_state: { signoff_id: 'sig_q1' },
    }, request)).toBe(true);

    expect(decisionMatchesRequest({
      event_type: 'guard.signoff.approved',
      actor_id: 'wrong_controller',
      after_state: { signoff_id: 'sig_q1' },
    }, request)).toBe(false);
  });

  it('returns only creator-bound decisions', () => {
    const events = [
      created,
      { event_type: 'guard.signoff.requested', actor_id: 'creator', after_state: { signoff_id: 'sig_good', approver_id: 'approver_1' } },
      { event_type: 'guard.signoff.requested', actor_id: 'attacker', after_state: { signoff_id: 'sig_bad', approver_id: 'attacker_approver' } },
      { event_type: 'guard.signoff.approved', actor_id: 'approver_1', after_state: { signoff_id: 'sig_good' } },
      { event_type: 'guard.signoff.approved', actor_id: 'attacker_approver', after_state: { signoff_id: 'sig_bad' } },
    ];

    const decisions = boundSignoffDecisionEvents(events, created, 'guard.signoff.approved');

    expect(decisions).toHaveLength(1);
    expect(decisions[0].after_state.signoff_id).toBe('sig_good');
    expect(findBoundSignoffDecision(events, created, 'guard.signoff.approved')?.after_state.signoff_id).toBe('sig_good');
  });
});
