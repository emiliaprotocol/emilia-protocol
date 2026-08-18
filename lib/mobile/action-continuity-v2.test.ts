// SPDX-License-Identifier: Apache-2.0
//
// EP-MOBILE-PROVIDER-OUTCOME-v2 hostile matrix: the hybrid (Ed25519 +
// ML-DSA-65) provider outcome evidence. The PQ leg runs for real.
import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';

import {
  MOBILE_PROVIDER_OUTCOME_V2_VERSION,
  MOBILE_PROVIDER_OUTCOME_V2_REQUIRED_ALGORITHMS,
  buildMobileProviderOutcomeV2,
  verifyMobileProviderOutcomeV2,
  verifyMobileProviderOutcome,
  mobileExecutorKeyId,
  mobilePqExecutorKeyId,
} from './action-continuity';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = crypto.createPublicKey(ed.privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const pqPrivB64u = Buffer.from(pq.secretKey).toString('base64url');

const CAID = 'caid:1:ep.mobile-action.1:jcs-sha256:' + 'A'.repeat(43);

function input(overrides: Record<string, any> = {}) {
  return {
    operationId: 'op-001',
    actionCaid: CAID,
    actionDigest: `sha256:${'9'.repeat(64)}`,
    consumptionNonce: 'nonce-001',
    executorId: 'executor-001',
    outcome: 'executed',
    observedAt: '2026-08-17T12:00:00.000Z',
    providerReference: 'provider-ref-001',
    privateKey: ed.privateKey,
    pqPrivateKey: pqPrivB64u,
    pqPublicKey: pqPubB64u,
    ...overrides,
  };
}

async function buildEvidence() {
  return buildMobileProviderOutcomeV2(input());
}

function pin() {
  return { 'executor-001': { public_key: edPubB64u, pq_public_key: pqPubB64u } };
}

function verifyOpts() {
  return {
    expected: {
      operation_id: 'op-001', action_caid: CAID, action_digest: `sha256:${'9'.repeat(64)}`,
      consumption_nonce: 'nonce-001', executor_id: 'executor-001', executor_key_id: mobileExecutorKeyId(edPubB64u),
    },
    executorKeys: pin(),
    now: '2026-08-17T12:05:00.000Z',
  };
}

describe('EP-MOBILE-PROVIDER-OUTCOME-v2 hostile matrix', () => {
  it('real ML-DSA-65 backend is available for this suite', () => {
    expect(typeof ml_dsa65?.sign).toBe('function');
  });

  it('a real hybrid outcome verifies under both pinned keys', async () => {
    const evidence = await buildEvidence();
    const res = await verifyMobileProviderOutcomeV2(evidence, verifyOpts());
    expect(res.valid).toBe(true);
    expect(res.outcome).toBe('executed');
  });

  it('the envelope names the registered algorithm set', async () => {
    const evidence: any = await buildEvidence();
    expect(evidence.proof.required_algorithms).toEqual([...MOBILE_PROVIDER_OUTCOME_V2_REQUIRED_ALGORITHMS]);
    expect(evidence['@version']).toBe(MOBILE_PROVIDER_OUTCOME_V2_VERSION);
    expect(evidence.proof.pq_key_id).toBe(mobilePqExecutorKeyId(pqPubB64u));
  });

  it('LEG STRIPPING: removing the ML-DSA leg refuses', async () => {
    const evidence: any = await buildEvidence();
    evidence.proof.signatures = evidence.proof.signatures.filter((s: any) => s.alg === 'Ed25519');
    const res = await verifyMobileProviderOutcomeV2(evidence, verifyOpts());
    expect(res.valid).toBe(false);
    expect(res.reason).toBe('provider_outcome_signature_invalid');
  });

  it('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const evidence: any = await buildEvidence();
    evidence.proof.signatures = evidence.proof.signatures.filter((s: any) => s.alg === 'ML-DSA-65');
    const res = await verifyMobileProviderOutcomeV2(evidence, verifyOpts());
    expect(res.valid).toBe(false);
  });

  it('NARROWED SET: required_algorithms trimmed refuses structurally', async () => {
    const evidence: any = await buildEvidence();
    evidence.proof.required_algorithms = ['Ed25519'];
    const res = await verifyMobileProviderOutcomeV2(evidence, verifyOpts());
    expect(res.valid).toBe(false);
    expect(res.reason).toBe('malformed_provider_outcome');
  });

  it('WRONG-LENGTH SIGNATURE: a truncated leg refuses without throwing', async () => {
    const evidence: any = await buildEvidence();
    evidence.proof.signatures = evidence.proof.signatures.map((s: any) => (
      s.alg === 'Ed25519' ? { ...s, sig: Buffer.from(s.sig, 'base64url').subarray(0, 5).toString('base64url') } : s
    ));
    const res = await verifyMobileProviderOutcomeV2(evidence, verifyOpts());
    expect(res.valid).toBe(false);
  });

  it('ED448 MASQUERADE: an Ed448 SPKI presented and pinned as the Ed25519 half refuses', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448Pub = ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const evidence: any = await buildEvidence();
    evidence.proof.public_key = ed448Pub;
    evidence.proof.key_id = mobileExecutorKeyId(ed448Pub);
    const res = await verifyMobileProviderOutcomeV2(evidence, {
      ...verifyOpts(),
      expected: { ...verifyOpts().expected, executor_key_id: mobileExecutorKeyId(ed448Pub) },
      executorKeys: { 'executor-001': { public_key: ed448Pub, pq_public_key: pqPubB64u } },
    });
    expect(res.valid).toBe(false);
  });

  it('V1 REFUSES V2: verifyMobileProviderOutcome (v1, sync) refuses a v2 envelope cleanly, without throwing', async () => {
    const evidence = await buildEvidence();
    const res = verifyMobileProviderOutcome(evidence as any, { expected: verifyOpts().expected, executorKeys: pin() });
    expect(res.valid).toBe(false);
    expect(res.reason).toBe('malformed_provider_outcome');
  });

  it('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const evidence = await buildEvidence();
    const res = await verifyMobileProviderOutcomeV2(evidence, verifyOpts(), { mldsaBackendLoader: async () => null });
    expect(res.valid).toBe(false);
  });

  it('malformed input refuses without throwing', async () => {
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
      const res = await verifyMobileProviderOutcomeV2(junk as any, verifyOpts());
      expect(res.valid).toBe(false);
    }
  });
});
