// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  runAgentOperationAuthorizationPolicyBindingLab,
} from '../examples/agent-operation-authorization/policy-binding.mjs';

describe('Agent Operation Authorization policy-resolution binding', () => {
  it('reproduces a valid-signature policy-alias substitution and refuses it with a digest binding', async () => {
    const result = await runAgentOperationAuthorizationPolicyBindingLab();

    expect(result.source_draft).toBe('draft-liu-agent-operation-authorization-02');
    expect(result.finding).toBe('signed_token_changed_policy_semantics');
    expect(result.same_signed_token).toBe(true);
    expect(result.same_policy_id).toBe(true);
    expect(result.policy_at_confirmation.digest).not.toBe(result.policy_at_execution.digest);

    expect(result.unbound_resolution).toMatchObject({
      token_signature_valid: true,
      displayed_limit: 50,
      attempted_amount: 500,
      resolved_policy_allows: true,
      substitution_detectable_from_token: false,
      portable_verdict: 'INDETERMINATE',
    });

    expect(result.digest_bound_resolution).toMatchObject({
      token_signature_valid: true,
      policy_binding_valid: false,
      resolved_policy_allows: false,
      reason: 'policy_digest_mismatch',
    });
  });

  it('accepts the approved policy bytes under the same digest-bound profile', async () => {
    const result = await runAgentOperationAuthorizationPolicyBindingLab({
      resolveApprovedPolicyAtExecution: true,
      attemptedAmount: 25,
    });

    expect(result.digest_bound_resolution).toMatchObject({
      token_signature_valid: true,
      policy_binding_valid: true,
      resolved_policy_allows: true,
      reason: null,
    });
  });
});
