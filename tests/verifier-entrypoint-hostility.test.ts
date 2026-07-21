// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';

import { verifyTrustReceipt } from '../packages/verify/index.js';
import { verifyRevocation } from '../packages/verify/revocation.js';
import { verifyProvenanceOffline } from '../packages/verify/provenance.js';
import { verifyEvidenceRecord } from '../packages/verify/evidence-record.js';
import { verifyTimeAttestation } from '../packages/verify/time-attestation.js';
import { verifyAuthorizationChain } from '../packages/verify/evidence-chain.js';

describe('public verifier entry points fail closed on JSON null options', () => {
  const probes = [
    ['trust receipt', () => verifyTrustReceipt(null, null)],
    ['revocation', () => verifyRevocation(null, null, null)],
    ['provenance', () => verifyProvenanceOffline(null, null)],
    ['evidence record', () => verifyEvidenceRecord(null, null)],
    ['time attestation', () => verifyTimeAttestation(null, null)],
    ['authorization chain', () => verifyAuthorizationChain(null, null)],
  ];

  for (const [name, probe] of probes) {
    it(`${name}: returns a refusal instead of throwing`, () => {
      let result;
      expect(() => { result = probe(); }).not.toThrow();
      expect(result?.valid === false || result?.allow === false).toBe(true);
    });
  }
});
