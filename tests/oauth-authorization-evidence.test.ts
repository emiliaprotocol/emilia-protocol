// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  runOAuthAuthorizationEvidenceLab,
  verifyOAuthAuthorizationEvidence,
} from '../examples/oauth-authorization-evidence/demo.mjs';

describe('OAuth Authorization Evidence + EP receipt composition', () => {
  it('accepts the composed artifact and refuses every cross-boundary substitution', async () => {
    const result = await runOAuthAuthorizationEvidenceLab();
    expect(result.cases).toHaveLength(8);
    for (const testCase of result.cases) {
      expect(
        testCase.result.accepted,
        `${testCase.id}: ${testCase.result.reason}`,
      ).toBe(testCase.expected === 'accept');
    }
  });

  it('turns hostile or missing input into a typed refusal instead of throwing', async () => {
    await expect(verifyOAuthAuthorizationEvidence()).resolves.toMatchObject({
      accepted: false,
      reason: 'missing_expected_action',
    });
    await expect(verifyOAuthAuthorizationEvidence({ expectedAction: {} })).resolves.toMatchObject({
      accepted: false,
    });
  });
});
