// SPDX-License-Identifier: Apache-2.0
//
// Grace artifact signature envelope hostile matrix (hybrid Ed25519 +
// ML-DSA-65), covering EP-GRACE-CURTAILMENT-ACTION-v1,
// -MOBILE-CONTROL-v1, -COSA-DISPATCH-v1, -COSA-ACK-v1: every Grace artifact
// type shares this one envelope. The PQ leg runs for real.
import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';

import {
  GRACE_ARTIFACT_V2_REQUIRED_ALGORITHMS,
  GRACE_DISPATCH_VERSION,
  signGraceArtifactV2,
  verifyGraceArtifactV2,
  verifyGraceArtifact,
} from './mobile-grid';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = crypto.createPublicKey(ed.privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const pqPrivB64u = Buffer.from(pq.secretKey).toString('base64url');

const KEY_ID = 'ep:key:grace-dispatch-signer';
const PQ_KEY_ID = 'ep:key:grace-dispatch-signer-pq';

function body() {
  return { '@version': GRACE_DISPATCH_VERSION, action_hash: `sha256:${'d'.repeat(64)}`, dispatched_by: 'ep:agent:grid-coordinator' };
}

async function buildArtifact() {
  return signGraceArtifactV2(body(), {
    privateKey: ed.privateKey, keyId: KEY_ID, pqPrivateKey: pqPrivB64u, pqPublicKey: pqPubB64u, pqKeyId: PQ_KEY_ID,
  });
}

function verifyOpts() {
  return { publicKeySpkiB64u: edPubB64u, keyId: KEY_ID, pqPublicKeyB64u: pqPubB64u, pqKeyId: PQ_KEY_ID, version: GRACE_DISPATCH_VERSION };
}

describe('Grace artifact signature envelope v2 hostile matrix', () => {
  it('real ML-DSA-65 backend is available for this suite', () => {
    expect(typeof ml_dsa65?.sign).toBe('function');
  });

  it('a real hybrid artifact verifies under both pinned keys', async () => {
    const artifact = await buildArtifact();
    expect(await verifyGraceArtifactV2(artifact, verifyOpts())).toBe(true);
  });

  it('the registered algorithm set is Ed25519 then ML-DSA-65', () => {
    expect(GRACE_ARTIFACT_V2_REQUIRED_ALGORITHMS).toEqual(['Ed25519', 'ML-DSA-65']);
  });

  it('LEG STRIPPING: removing the ML-DSA leg refuses', async () => {
    const artifact: any = await buildArtifact();
    artifact.signature.signatures = artifact.signature.signatures.filter((s: any) => s.alg === 'Ed25519');
    expect(await verifyGraceArtifactV2(artifact, verifyOpts())).toBe(false);
  });

  it('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const artifact: any = await buildArtifact();
    artifact.signature.signatures = artifact.signature.signatures.filter((s: any) => s.alg === 'ML-DSA-65');
    expect(await verifyGraceArtifactV2(artifact, verifyOpts())).toBe(false);
  });

  it('NARROWED SET: required_algorithms trimmed refuses structurally', async () => {
    const artifact: any = await buildArtifact();
    artifact.signature.required_algorithms = ['Ed25519'];
    expect(await verifyGraceArtifactV2(artifact, verifyOpts())).toBe(false);
  });

  it('WRONG-LENGTH SIGNATURE: a truncated leg refuses without throwing', async () => {
    const artifact: any = await buildArtifact();
    artifact.signature.signatures = artifact.signature.signatures.map((s: any) => (
      s.alg === 'Ed25519' ? { ...s, sig: Buffer.from(s.sig, 'base64url').subarray(0, 5).toString('base64url') } : s
    ));
    expect(await verifyGraceArtifactV2(artifact, verifyOpts())).toBe(false);
  });

  it('ED448 MASQUERADE: an Ed448 SPKI presented (and pinned) as the Ed25519 half refuses', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448Pub = ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const artifact = await buildArtifact();
    const res = await verifyGraceArtifactV2(artifact, { ...verifyOpts(), publicKeySpkiB64u: ed448Pub });
    expect(res).toBe(false);
  });

  it('V1 REFUSES V2: verifyGraceArtifact (v1, sync) refuses a v2 artifact cleanly, without throwing', async () => {
    const artifact = await buildArtifact();
    const res = verifyGraceArtifact(artifact, { publicKeySpkiB64u: edPubB64u, keyId: KEY_ID, version: GRACE_DISPATCH_VERSION });
    expect(res).toBe(false);
  });

  it('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const artifact = await buildArtifact();
    const res = await verifyGraceArtifactV2(artifact, verifyOpts(), { mldsaBackendLoader: async () => null });
    expect(res).toBe(false);
  });

  it('malformed input refuses without throwing', async () => {
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
      expect(await verifyGraceArtifactV2(junk as any, verifyOpts())).toBe(false);
    }
  });
});
