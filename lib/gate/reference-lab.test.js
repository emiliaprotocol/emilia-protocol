// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { GATE_REFERENCE_PROFILES, runGateReferenceLab } from './reference-lab.js';

describe('EMILIA Gate reference lab', () => {
  for (const profileId of Object.keys(GATE_REFERENCE_PROFILES)) {
    it(`${profileId} executes once and refuses every hostile path`, async () => {
      const result = await runGateReferenceLab(profileId);
      expect(result.ok).toBe(true);
      expect(result.reference_only).toBe(true);
      expect(result.physical_claim).toBe(false);
      expect(result.challenge.status).toBe(428);
      expect(result.authorization.allowed).toBe(true);
      expect(result.authorization.required_tier).toBe(result.profile.tier);
      expect(result.execution.bound).toBe(true);
      expect(result.reliance.verdict).toBe('rely');
      expect(result.evidence.ok).toBe(true);
      expect(result.attacks).toHaveLength(5);
      expect(result.attacks.every((attack) => attack.refused)).toBe(true);
    });
  }

  it('falls back only inside the direct profile helper, never in the HTTP route', async () => {
    const result = await runGateReferenceLab('not-a-profile');
    expect(result.profile.id).toBe('treasury');
  });
});
