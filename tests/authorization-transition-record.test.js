// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  runAuthorizationTransitionLab,
  verifyAuthorizationTransition,
} from '../examples/authorization-transition-record/demo.mjs';

describe('Authorization Transition Record + EP triggering evidence', () => {
  it('accepts the composed transition and refuses every substitution case', async () => {
    const result = await runAuthorizationTransitionLab();
    expect(result.cases).toHaveLength(6);
    for (const testCase of result.cases) {
      expect(testCase.result.accepted, `${testCase.id}: ${testCase.result.reason}`)
        .toBe(testCase.expected === 'accept');
    }
  });

  it('fails closed on absent input', () => {
    expect(verifyAuthorizationTransition()).toMatchObject({
      accepted: false,
      reason: 'malformed_signed_transition_record',
    });
  });
});
