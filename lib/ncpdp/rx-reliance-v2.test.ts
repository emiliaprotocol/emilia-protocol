// SPDX-License-Identifier: Apache-2.0
//
// EP-RX-EVIDENCE-ARTIFACT-v2 hostile matrix: the hybrid (Ed25519 + ML-DSA-65)
// signature envelope shared by every Rx reliance evidence artifact
// (EP-RX-BENEFIT-v1, EP-RX-CLINICAL-v1, EP-RX-CONSENT-v1, EP-RX-DENIAL-v1).
// The PQ leg runs for real: this suite fails loudly if @noble/post-quantum is
// missing rather than silently skipping.
import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';

import {
  RX_ARTIFACT_V2_REQUIRED_ALGORITHMS,
  signRxArtifactV2,
  verifyRxArtifactV2,
  verifyRxArtifact,
} from './rx-reliance';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const ed = crypto.generateKeyPairSync('ed25519');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');

const SIGNER = {
  privateKey: ed.privateKey,
  pqPrivateKey: Buffer.from(pq.secretKey).toString('base64url'),
  pqPublicKey: pqPubB64u,
};

function benefitBody() {
  return {
    '@type': 'EP-RX-BENEFIT-v1',
    action_hash: `sha256:${'a'.repeat(64)}`,
    privacy_key_id: 'privacy-key-1',
    policy_hash: `sha256:${'b'.repeat(64)}`,
    issued_at: '2026-08-17T12:00:00.000Z',
  };
}

async function buildArtifact() {
  return signRxArtifactV2(benefitBody(), SIGNER);
}

function pinOpts() {
  return {
    expectType: 'EP-RX-BENEFIT-v1',
    pinnedKeyPairs: [{
      public_key: crypto.createPublicKey(ed.privateKey).export({ type: 'spki', format: 'der' }).toString('base64url'),
      pq_public_key: pqPubB64u,
    }],
    now: Date.parse('2026-08-17T12:05:00.000Z'),
  };
}

describe('EP-RX-EVIDENCE-ARTIFACT-v2 hostile matrix', () => {
  it('real ML-DSA-65 backend is available for this suite', () => {
    expect(typeof ml_dsa65?.sign).toBe('function');
  });

  it('a real hybrid artifact verifies and is accepted under the pinned key pair', async () => {
    const artifact = await buildArtifact();
    const res = await verifyRxArtifactV2(artifact, pinOpts());
    expect(res.verified).toBe(true);
    expect(res.accepted).toBe(true);
    expect(res.reason).toBeNull();
  });

  it('the committed bytes carry the registered algorithm set', () => {
    expect(RX_ARTIFACT_V2_REQUIRED_ALGORITHMS).toEqual(['Ed25519', 'ML-DSA-65']);
  });

  it('LEG STRIPPING: removing the ML-DSA leg refuses (missing required leg)', async () => {
    const artifact: any = await buildArtifact();
    artifact.signature.signatures = artifact.signature.signatures.filter((s: any) => s.alg === 'Ed25519');
    const res = await verifyRxArtifactV2(artifact, pinOpts());
    expect(res.verified).toBe(false);
    expect(res.reason).toBe('signature_invalid');
  });

  it('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const artifact: any = await buildArtifact();
    artifact.signature.signatures = artifact.signature.signatures.filter((s: any) => s.alg === 'ML-DSA-65');
    const res = await verifyRxArtifactV2(artifact, pinOpts());
    expect(res.verified).toBe(false);
  });

  it('NARROWED SET: required_algorithms trimmed to one algorithm refuses structurally', async () => {
    const artifact: any = await buildArtifact();
    artifact.signature.required_algorithms = ['Ed25519'];
    const res = await verifyRxArtifactV2(artifact, pinOpts());
    expect(res.verified).toBe(false);
    expect(res.reason).toBe('signature_malformed');
  });

  it('NARROWED SET + stripped leg: the surviving Ed25519 signature no longer verifies over the narrowed bytes', async () => {
    // Independently proves the anti-stripping byte-commitment: a signature
    // minted over the FULL required_algorithms set cannot be replayed against
    // a narrowed claim, even bypassing verifyRxArtifactV2's structural gate.
    const artifact: any = await buildArtifact();
    const edSig = artifact.signature.signatures.find((s: any) => s.alg === 'Ed25519');
    const publicKey = crypto.createPublicKey(ed.privateKey).export({ type: 'spki', format: 'der' });
    const { canonicalize } = await import('../../packages/verify/index.js');
    const narrowedBytes = Buffer.from(canonicalize({ ...benefitBody(), required_algorithms: ['Ed25519'] }), 'utf8');
    const key = crypto.createPublicKey({ key: publicKey, format: 'der', type: 'spki' });
    expect(crypto.verify(null, narrowedBytes, key, Buffer.from(edSig.sig, 'base64url'))).toBe(false);
  });

  it('WRONG-LENGTH SIGNATURE: a truncated Ed25519 leg refuses without throwing', async () => {
    const artifact: any = await buildArtifact();
    artifact.signature.signatures = artifact.signature.signatures.map((s: any) => (
      s.alg === 'Ed25519' ? { ...s, sig: Buffer.from(s.sig, 'base64url').subarray(0, 10).toString('base64url') } : s
    ));
    const res = await verifyRxArtifactV2(artifact, pinOpts());
    expect(res.verified).toBe(false);
    expect(res.reason).toBe('signature_invalid');
  });

  it('WRONG-LENGTH SIGNATURE: a truncated ML-DSA-65 leg refuses without throwing', async () => {
    const artifact: any = await buildArtifact();
    artifact.signature.signatures = artifact.signature.signatures.map((s: any) => (
      s.alg === 'ML-DSA-65' ? { ...s, sig: Buffer.from(s.sig, 'base64url').subarray(0, 10).toString('base64url') } : s
    ));
    const res = await verifyRxArtifactV2(artifact, pinOpts());
    expect(res.verified).toBe(false);
  });

  it('ED448 MASQUERADE: an Ed448 SPKI presented and pinned as the Ed25519 half refuses', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448Pub = ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const artifact: any = await buildArtifact();
    artifact.signature.public_key = ed448Pub;
    artifact.signature.key_id = `ep:rx-artifact-key:sha256:${crypto.createHash('sha256')
      .update(Buffer.from(ed448Pub, 'base64url')).digest('hex')}`;
    const res = await verifyRxArtifactV2(artifact, {
      expectType: 'EP-RX-BENEFIT-v1',
      pinnedKeyPairs: [{ public_key: ed448Pub, pq_public_key: pqPubB64u }],
      now: Date.parse('2026-08-17T12:05:00.000Z'),
    });
    expect(res.verified).toBe(false);
  });

  it('V1 REFUSES V2: verifyRxArtifact (v1, sync) refuses a v2 artifact cleanly, without throwing', async () => {
    const artifact = await buildArtifact();
    const res = verifyRxArtifact(artifact as any, { expectType: 'EP-RX-BENEFIT-v1', pinnedKeys: [] });
    expect(res.verified).toBe(false);
    expect(res.reason).toBe('signature_malformed');
  });

  it('KEY SUBSTITUTION: presented keys not in the pinned set refuse (accepted:false, verified:true)', async () => {
    const artifact = await buildArtifact();
    const res = await verifyRxArtifactV2(artifact, { expectType: 'EP-RX-BENEFIT-v1', pinnedKeyPairs: [] });
    expect(res.verified).toBe(true);
    expect(res.accepted).toBe(false);
    expect(res.reason).toBe('issuer_key_not_pinned');
  });

  it('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const artifact = await buildArtifact();
    const res = await verifyRxArtifactV2(artifact, { ...pinOpts(), mldsaBackendLoader: async () => null });
    expect(res.verified).toBe(false);
    expect(res.reason).toBe('signature_invalid');
  });

  it('malformed input refuses without throwing', async () => {
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
      const res = await verifyRxArtifactV2(junk as any, pinOpts());
      expect(res.verified).toBe(false);
    }
  });
});
