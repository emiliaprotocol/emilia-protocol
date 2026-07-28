// SPDX-License-Identifier: Apache-2.0
import { expect, test } from 'vitest';
import { runRelianceRiskChecks } from '../formal/check-reliance-risk-plane.mjs';
import { RELIANCE_RISK_OBLIGATIONS } from '../formal/reliance-risk-plane.model.mjs';

test('reliance risk plane verifies every bounded obligation and exposes each removed guard', () => {
  const result = runRelianceRiskChecks();
  expect(result.verified).toBe(true);
  expect(Object.keys(result.obligations)).toHaveLength(RELIANCE_RISK_OBLIGATIONS.length);
  for (const name of RELIANCE_RISK_OBLIGATIONS) {
    expect(result.obligations[name].counterexample, name).toBeNull();
    expect(result.obligations[name].mutation_counterexample, name).not.toBeNull();
  }
});
