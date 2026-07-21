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
  });
});
