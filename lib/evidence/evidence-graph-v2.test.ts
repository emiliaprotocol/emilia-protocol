// SPDX-License-Identifier: Apache-2.0
//
// EP-RELIANCE-RESULT-v2 hostile matrix: the hybrid (Ed25519 + ML-DSA-65)
// signed reliance verdict. The PQ leg runs for real.
import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';

import {
  RELIANCE_RESULT_V2_VERSION,
  RELIANCE_RESULT_V2_REQUIRED_ALGORITHMS,
  signRelianceResultV2,
  verifyRelianceResultV2,
  verifyRelianceResult,
} from './evidence-graph';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = crypto.createPublicKey(ed.privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const pqPrivB64u = Buffer.from(pq.secretKey).toString('base64url');

const SIGNER = { privateKey: ed.privateKey, pqPrivateKey: pqPrivB64u, pqPublicKey: pqPubB64u };

function result() {
  return {
    verdict: 'admissible',
    reasons: ['all required evidence composes'],
    action_digest: `sha256:${'1'.repeat(64)}`,
    graph: { graph_digest: `sha256:${'2'.repeat(64)}` },
    replay_digest: `sha256:${'3'.repeat(64)}`,
    outcome_binding: { '@version': 'EP-OUTCOME-BINDING-v1', outcome: 'in_bounds', evaluations: [] },
  };
}

function policy() {
  return { policy_id: 'ep:policy:test', reliance_purpose: 'test' };
}

async function buildDoc() {
  return signRelianceResultV2(result(), policy(), SIGNER);
}

function pinnedPairs() {
  return [{ verifier_key: edPubB64u, pq_verifier_key: pqPubB64u }];
}

describe('EP-RELIANCE-RESULT-v2 hostile matrix', () => {
  it('real ML-DSA-65 backend is available for this suite', () => {
    expect(typeof ml_dsa65?.sign).toBe('function');
  });

  it('a real hybrid document verifies and is accepted under the pinned key pair', async () => {
    const doc = await buildDoc();
    const res = await verifyRelianceResultV2(doc, pinnedPairs());
    expect(res.verified).toBe(true);
    expect(res.accepted).toBe(true);
  });

  it('the registered algorithm set is Ed25519 then ML-DSA-65', () => {
    expect(RELIANCE_RESULT_V2_REQUIRED_ALGORITHMS).toEqual(['Ed25519', 'ML-DSA-65']);
  });

  it('LEG STRIPPING: removing the ML-DSA leg refuses', async () => {
    const doc: any = await buildDoc();
    doc.proof.signatures = doc.proof.signatures.filter((s: any) => s.alg === 'Ed25519');
    const res = await verifyRelianceResultV2(doc, pinnedPairs());
    expect(res.verified).toBe(false);
    expect(res.checks.signature).toBe(false);
  });

  it('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const doc: any = await buildDoc();
    doc.proof.signatures = doc.proof.signatures.filter((s: any) => s.alg === 'ML-DSA-65');
    const res = await verifyRelianceResultV2(doc, pinnedPairs());
    expect(res.verified).toBe(false);
  });

  it('NARROWED SET: required_algorithms trimmed refuses structurally', async () => {
    const doc: any = await buildDoc();
    doc.proof.required_algorithms = ['Ed25519'];
    const res = await verifyRelianceResultV2(doc, pinnedPairs());
    expect(res.verified).toBe(false);
    expect(res.checks.algorithm_set).toBe(false);
  });

  it('WRONG-LENGTH SIGNATURE: a truncated leg refuses without throwing', async () => {
    const doc: any = await buildDoc();
    doc.proof.signatures = doc.proof.signatures.map((s: any) => (
      s.alg === 'Ed25519' ? { ...s, sig: Buffer.from(s.sig, 'base64url').subarray(0, 5).toString('base64url') } : s
    ));
    const res = await verifyRelianceResultV2(doc, pinnedPairs());
    expect(res.verified).toBe(false);
  });

  it('ED448 MASQUERADE: an Ed448 SPKI presented and pinned as the Ed25519 half refuses', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448Pub = ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const doc: any = await buildDoc();
    doc.proof.verifier_key = ed448Pub;
    const res = await verifyRelianceResultV2(doc, [{ verifier_key: ed448Pub, pq_verifier_key: pqPubB64u }]);
    expect(res.verified).toBe(false);
  });

  it('V1 REFUSES V2: verifyRelianceResult (v1, sync) refuses a v2 document cleanly, without throwing', async () => {
    const doc = await buildDoc();
    const res = verifyRelianceResult(doc, [edPubB64u]);
    expect(res.verified).toBe(false);
  });

  it('KEY SUBSTITUTION: presented key pair not pinned refuses acceptance (verified true, accepted false)', async () => {
    const doc = await buildDoc();
    const res = await verifyRelianceResultV2(doc, []);
    expect(res.verified).toBe(true);
    expect(res.accepted).toBe(false);
  });

  it('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const doc = await buildDoc();
    const res = await verifyRelianceResultV2(doc, pinnedPairs(), { mldsaBackendLoader: async () => null });
    expect(res.verified).toBe(false);
  });

  it('malformed input refuses without throwing', async () => {
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
      const res = await verifyRelianceResultV2(junk as any, pinnedPairs());
      expect(res.verified).toBe(false);
    }
  });
});
