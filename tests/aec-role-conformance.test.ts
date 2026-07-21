// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

import { verifyAuthorizationChain } from '../packages/verify/evidence-chain.js';

const suite = JSON.parse(readFileSync(new URL('../conformance/vectors/aec-role.v1.json', import.meta.url), 'utf8'));

function evaluate(vector) {
  const stub = (evidence) => ({
    valid: evidence?.valid !== false,
    action_digest: evidence?.action_digest,
  });
  const verifiers = Object.fromEntries((vector.stub_types || []).map((type) => [type, stub]));
  return verifyAuthorizationChain(vector.aec_chain, {
    keysByType: vector.keys_by_type,
    policiesByType: vector.policies_by_type,
    verifiers,
    requirement: vector.requirement,
    expectedActionDigest: vector.expected_action_digest,
    verificationTime: vector.verification_time,
  });
}

describe('EP-AEC-ROLE-v1 real-crypto acceptance vectors', () => {
  for (const vector of suite.vectors) {
    it(`${vector.id}: ${vector.description}`, () => {
      const result = evaluate(vector);
      expect(result.allow, JSON.stringify(result)).toBe(vector.expect.valid);
    });
  }
});
