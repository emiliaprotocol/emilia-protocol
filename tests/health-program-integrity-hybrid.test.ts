// SPDX-License-Identifier: Apache-2.0
//
// EP-SYNTHETIC-HOSPICE-PROVIDER-EVIDENCE-v2: hostile matrix for the hybrid
// (Ed25519 + ML-DSA-65) synthetic provider-evidence artifact -- the one
// asymmetric-signature artifact lib/health/program-integrity.ts mints and
// verifies itself (both keys are deliberately fixed demo constants, never a
// production trust anchor; see the module's own SYNTHETIC_PROVIDER_* comments).
import { describe, expect, it } from 'vitest';
import {
  buildProviderEvidenceV2,
  verifyProviderEvidenceV2,
  verifyProviderEvidenceAny,
} from '../lib/health/program-integrity.js';

const ACTION = { provider_npi: '1234567893', operation_id: 'hospice-op-hybrid-001' };
const CAID = 'caid:synthetic-hybrid-test';
const ACTION_DIGEST = `sha256:${'7'.repeat(64)}`;

describe('synthetic hospice provider evidence -- hybrid v2', () => {
  it('valid v2 roundtrip: real Ed25519 + ML-DSA-65 signatures verify', async () => {
    const evidence = await buildProviderEvidenceV2(ACTION, CAID, ACTION_DIGEST);
    expect(evidence.body['@version']).toBe('EP-SYNTHETIC-HOSPICE-PROVIDER-EVIDENCE-v2');
    expect(evidence.signature.required_algorithms).toEqual(['Ed25519', 'ML-DSA-65']);
    const result = await verifyProviderEvidenceV2(evidence, ACTION, CAID, ACTION_DIGEST);
    expect(result).toEqual({ evidenceDigest: expect.any(String) });
  });

  it('routes a v2 artifact to the hybrid verifier via verifyProviderEvidenceAny', async () => {
    const evidence = await buildProviderEvidenceV2(ACTION, CAID, ACTION_DIGEST);
    const viaAny = await verifyProviderEvidenceAny(evidence, ACTION, CAID, ACTION_DIGEST);
    const direct = await verifyProviderEvidenceV2(evidence, ACTION, CAID, ACTION_DIGEST);
    expect(viaAny).toEqual(direct);
  });

  it('v2 verifier refuses a v1-shaped evidence object (missing required_algorithms) as malformed', async () => {
    const evidence = await buildProviderEvidenceV2(ACTION, CAID, ACTION_DIGEST);
    const v1Shaped = {
      body: { ...evidence.body, '@version': 'EP-SYNTHETIC-HOSPICE-PROVIDER-EVIDENCE-v1' },
      signature: { algorithm: 'Ed25519', public_key: evidence.signature.public_key, value: 'x'.repeat(86) },
    };
    expect(await verifyProviderEvidenceV2(v1Shaped, ACTION, CAID, ACTION_DIGEST)).toBeNull();
  });

  it('stripped leg: dropping the ML-DSA-65 signature refuses', async () => {
    const evidence = structuredClone(await buildProviderEvidenceV2(ACTION, CAID, ACTION_DIGEST));
    evidence.signature.signatures = evidence.signature.signatures.filter((s: any) => s.alg !== 'ML-DSA-65');
    expect(await verifyProviderEvidenceV2(evidence, ACTION, CAID, ACTION_DIGEST)).toBeNull();
  });

  it('stripped leg: dropping the Ed25519 signature refuses', async () => {
    const evidence = structuredClone(await buildProviderEvidenceV2(ACTION, CAID, ACTION_DIGEST));
    evidence.signature.signatures = evidence.signature.signatures.filter((s: any) => s.alg !== 'Ed25519');
    expect(await verifyProviderEvidenceV2(evidence, ACTION, CAID, ACTION_DIGEST)).toBeNull();
  });

  it('narrowed set: required_algorithms=[Ed25519] is refused structurally, never a pass on the classical leg', async () => {
    const evidence = structuredClone(await buildProviderEvidenceV2(ACTION, CAID, ACTION_DIGEST));
    evidence.signature.required_algorithms = ['Ed25519'];
    evidence.signature.signatures = evidence.signature.signatures.filter((s: any) => s.alg === 'Ed25519');
    expect(await verifyProviderEvidenceV2(evidence, ACTION, CAID, ACTION_DIGEST)).toBeNull();
  });

  it('wrong-length signature: a truncated Ed25519 leg refuses as a signature failure, not a crash', async () => {
    const evidence = structuredClone(await buildProviderEvidenceV2(ACTION, CAID, ACTION_DIGEST));
    evidence.signature.signatures = evidence.signature.signatures.map((s: any) => (
      s.alg === 'Ed25519' ? { ...s, sig: s.sig.slice(0, 9) } : s
    ));
    expect(await verifyProviderEvidenceV2(evidence, ACTION, CAID, ACTION_DIGEST)).toBeNull();
  });

  it('key substitution: an unpinned ML-DSA-65 public key is refused even with well-formed signatures', async () => {
    const evidence = structuredClone(await buildProviderEvidenceV2(ACTION, CAID, ACTION_DIGEST));
    const other = await buildProviderEvidenceV2(ACTION, CAID, ACTION_DIGEST);
    evidence.signature.pq_public_key = 'A'.repeat(evidence.signature.pq_public_key.length);
    expect(await verifyProviderEvidenceV2(evidence, ACTION, CAID, ACTION_DIGEST)).toBeNull();
    expect(other).toBeTruthy();
  });

  it('binding mismatch: a v2 evidence artifact bound to a different action refuses', async () => {
    const evidence = await buildProviderEvidenceV2(ACTION, CAID, ACTION_DIGEST);
    const otherAction = { ...ACTION, operation_id: 'hospice-op-hybrid-002' };
    expect(await verifyProviderEvidenceV2(evidence, otherAction, CAID, ACTION_DIGEST)).toBeNull();
  });
});
