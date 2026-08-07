// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  EXACT_ACTION,
  LAB_VERSION,
  runCrossGatewayLab,
} from '../examples/cross-gateway/demo.mjs';

describe('Cross-Gateway Evidence Lab', () => {
  it('verifies one artifact independently at each gateway, executes once, and refuses every bad presentation by name', async () => {
    const result = await runCrossGatewayLab();

    expect(result['@version']).toBe(LAB_VERSION);
    expect(result.action).toEqual(EXACT_ACTION);
    expect(result.executor_call_count).toBe(1);

    const byId = Object.fromEntries(result.cases.map((item) => [item.id, item]));

    for (const id of [
      'a-refuses-without-evidence',
      'decision-does-not-travel',
      'tampered-in-transit-refused-at-b',
      'b-does-not-inherit-a-trust',
      'replay-refused-at-b',
      'stale-status-refused-at-b',
    ]) {
      expect(byId[id].verdict, id).toBe('refuse');
      expect(byId[id].executor_called, id).toBe(false);
      expect(byId[id].reason, id).toBeTruthy();
    }

    // The refusals name the failed check rather than failing generically.
    expect(byId['a-refuses-without-evidence'].reason).toBe('receipt_required');
    expect(byId['decision-does-not-travel'].reason).toBe('receipt_required');
    expect(byId['tampered-in-transit-refused-at-b'].reason).toBe('execution_binding_failed');
    expect(byId['b-does-not-inherit-a-trust'].reason).toContain('untrusted');
    expect(byId['replay-refused-at-b'].reason).toBe('replay_refused');

    // The through-case: both gateways verified independently and their audit
    // records join by the shared action digest, never by each other's verdicts.
    const through = byId['one-artifact-two-independent-verifications'];
    expect(through.verdict).toBe('execute');
    expect(through.executor_called).toBe(true);
    expect(through.a.allow).toBe(true);
    expect(through.b.allow).toBe(true);
    expect(through.audit_join.joined_by_action_digest).toBe(true);
    expect(through.a.observed_action_hash).toBe(through.b.observed_action_hash);
    expect(through.execution_binds_authorization).toBe(true);

    // A gateway allowing is not another gateway accepting: the misconfigured
    // gateway credited the rogue artifact, Gateway B refused the same bytes.
    const anchors = byId['b-does-not-inherit-a-trust'];
    expect(anchors.a.allow).toBe(true);
    expect(anchors.b.allow).toBe(false);

    // The verdict that did not travel was a genuine allow at Gateway A.
    expect(byId['decision-does-not-travel'].a.allow).toBe(true);

    // Status and freshness: the artifact still verifies, but the signed
    // statement about whether it is STILL good is past its own next_update.
    // The refusal is the EP-STATUS-v1 verifier's own reason string.
    const stale = byId['stale-status-refused-at-b'];
    expect(stale.reason).toBe('status_stale');
    expect(stale.b.allow).toBe(false);
    expect(stale.status_evidence.mechanism).toBe('EP-STATUS-v1');
    expect(stale.status_evidence.status_outcome).toBe('indeterminate');
    expect(stale.status_evidence.reasons).toContain('status_stale');
    expect(stale.status_evidence.b_max_staleness_sec).toBe(300);
    // Gateway A validated the same artifact and would have forwarded it;
    // currency is the receiver's question.
    expect(stale.a.allow).toBe(true);
    // Never fails open: absence of a status bundle is not currency either.
    expect(stale.fail_closed_without_status.allow).toBe(false);
    expect(stale.fail_closed_without_status.reason).toBe('status_evidence_absent');
    // The issuer's window is not the receiver's bound. A bundle still inside
    // its own next_update but older than Gateway B's bound is refused by the
    // second mechanism on its own, so neither check is decorative.
    expect(stale.b_bound_refuses_inside_issuer_window.allow).toBe(false);
    expect(stale.b_bound_refuses_inside_issuer_window.reason).toBe('fresh_head_stale');
    // And the same policy admitted a current bundle, so it discriminates.
    expect(stale.control_current_status_admitted).toBe(true);

    // An unresolved provider outcome is neither success nor a clean refusal,
    // and it must not hand the approval back for a second attempt.
    const indeterminate = byId['indeterminate-does-not-reopen-a'];
    expect(indeterminate.verdict).toBe('indeterminate');
    expect(indeterminate.provider_entered).toBe(true);
    expect(indeterminate.executor_called).toBe(false);
    expect(result.provider_entry_count).toBe(1);
    // (a) recorded as indeterminate by the gate, not labelled so by this lab.
    expect(indeterminate.reason).toBe('effect_attempted_outcome_unknown');
    expect(indeterminate.indeterminate.outcome).toBe('indeterminate');
    expect(indeterminate.indeterminate.execution_record_kind).toBe('execution');
    expect(indeterminate.indeterminate.execution_record_outcome).toBe('indeterminate');
    expect(indeterminate.indeterminate.execution_record_code).toBe('effect_attempted_outcome_unknown');
    expect(indeterminate.indeterminate.authorizes_decision).toBeTruthy();
    // (b) a blind retry at Gateway B is refused.
    expect(indeterminate.not_returned_to_pool.blind_retry_at_b.allow).toBe(false);
    expect(indeterminate.not_returned_to_pool.blind_retry_at_b.reason).toBe('replay_refused');
    // (c) the authorization was committed at B, never released back to the
    // pool, and Gateway A's leg is byte-for-byte what it was before.
    expect(indeterminate.not_returned_to_pool.committed_at_b).toBe(true);
    expect(indeterminate.not_returned_to_pool.still_reserved_at_b).toBe(false);
    expect(indeterminate.a_leg.unchanged).toBe(true);
    expect(indeterminate.a_leg.after).toEqual(indeterminate.a_leg.before);
    // "Unchanged" is only worth asserting against a snapshot that had
    // something in it: Gateway A was holding this exact leg and had already
    // written its own evidence when Gateway B's attempt went unresolved.
    expect(indeterminate.a_leg.before.reserved).toContain(
      indeterminate.not_returned_to_pool.consumption_key,
    );
    expect(indeterminate.a_leg.before.evidence_records).toBeGreaterThan(0);
    expect(indeterminate.a_leg.before.evidence_head).toBeTruthy();
    expect(indeterminate.a_leg.still_reserved).toBe(true);
    expect(indeterminate.a_leg.re_presentation.allow).toBe(false);
    expect(indeterminate.a_leg.re_presentation.reason).toBe('replay_refused');

    // The machine-readable result is safe to publish: no key material, no
    // approver credentials, and no provider payloads ride along in it.
    const serialized = JSON.stringify(result);
    for (const marker of [
      'PRIVATE KEY',
      'privateKey',
      'private_key',
      'privateKeyB64u',
      'secret',
      'BEGIN ',
    ]) {
      expect(serialized, marker).not.toContain(marker);
    }
  });
});
