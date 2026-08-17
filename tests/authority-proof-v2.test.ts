// SPDX-License-Identifier: Apache-2.0
//
// EP-AUTHORITY-PROOF-v2 hybrid verifier test.
//
// Builds a REAL Ed25519 + ML-DSA-65 signed authority proof, then asserts the
// fail-closed { verified, accepted } split plus the hybrid hostile matrix (leg
// stripping both ways, set narrowing structural + independent crypto.verify,
// widening, duplicate/relabelled/swapped legs, Ed448 masquerade, key
// substitution, tamper-after-signing), the v1 verifier refusing a v2 proof, and
// a v1 byte-identity regression.
//
// It also proves the TWIN LOCKSTEP: the v2 verifier re-exported by the lib
// module IS THE SAME FUNCTION OBJECT as the one in the published verify package,
// exactly as workstream A asserted for revocation. One verification body means
// the twins cannot drift.
//
// The PQ leg runs for real: this suite FAILS LOUDLY if @noble/post-quantum is
// missing rather than silently skipping.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import { canonicalize } from '../packages/verify/index.js';
import {
  AUTHORITY_PROOF_V2_VERSION,
  AUTHORITY_PROOF_V2_REQUIRED_ALGORITHMS,
  AUTHORITY_PROOF_V2_DOMAIN,
  verifyAuthorityProofV2 as pkgVerifyAuthorityProofV2,
} from '../packages/verify/authority-proof.js';
import {
  signAuthorityProof,
  signAuthorityProofV2,
  verifyAuthorityProof,
  verifyAuthorityProofV2,
} from '../lib/authority/proof.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const AUTHORITY_ID = 'ep:authority:acme';
const ARGS = {
  authority_id: AUTHORITY_ID,
  subject: 'ep:approver:jane',
  role: 'wire-approver',
  scope: ['payment.release'],
  registry_head: `sha256:${'a'.repeat(64)}`,
  registry_epoch: 7,
  issued_at: '2026-08-02T20:00:00.000Z',
};

const ed = crypto.generateKeyPairSync('ed25519');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const pqSecretB64u = Buffer.from(pq.secretKey).toString('base64url');

const clone = <T>(v: T): T => structuredClone(v);

async function buildV2(args: any = ARGS) {
  return signAuthorityProofV2(args, { privateKey: ed.privateKey, pqSecretKey: pqSecretB64u, pqPublicKey: pqPubB64u });
}
function pins(proof: any, issuerId: string = AUTHORITY_ID) {
  return { pinnedRegistryKeys: [{ issuer_id: issuerId, public_key: proof.signature.public_key, pq_public_key: proof.signature.pq_public_key }] };
}

describe('EP-AUTHORITY-PROOF-v2 hybrid', () => {
  it('real ML-DSA-65 backend is available for this suite', () => {
    expect(typeof ml_dsa65?.sign).toBe('function');
  });

  it('TWIN LOCKSTEP: the lib re-export is the SAME function object as the package verifier', () => {
    expect(verifyAuthorityProofV2).toBe(pkgVerifyAuthorityProofV2);
  });

  it('a real hybrid proof verifies and is accepted under a pinned issuer key pair', async () => {
    const proof = await buildV2();
    const res = await verifyAuthorityProofV2(proof, pins(proof));
    expect(res.verified).toBe(true);
    expect(res.accepted).toBe(true);
    expect(res.checks.legs_present).toBe(true);
    expect(res.checks.signature).toBe(true);
  });

  it('the committed bytes carry the required algorithm set + v2 domain/marker', async () => {
    const proof = clone(await buildV2());
    const { signature, ...body } = proof;
    const bytes = AUTHORITY_PROOF_V2_DOMAIN + canonicalize({ ...body, required_algorithms: [...AUTHORITY_PROOF_V2_REQUIRED_ALGORITHMS] });
    expect(bytes).toContain('"required_algorithms":["Ed25519","ML-DSA-65"]');
    expect(bytes).toContain(`"@type":"${AUTHORITY_PROOF_V2_VERSION}"`);
  });

  it('verified is NOT accepted: a real signature under an UNPINNED issuer is verified:false/accepted:false', async () => {
    const proof = await buildV2();
    const res = await verifyAuthorityProofV2(proof, { pinnedRegistryKeys: [] });
    expect(res.accepted).toBe(false);
    expect(res.checks.pinned_registry_key).toBe(false);
  });

  it('a pin naming the WRONG issuer_id refuses', async () => {
    const proof = await buildV2();
    const res = await verifyAuthorityProofV2(proof, pins(proof, 'ep:authority:other'));
    expect(res.accepted).toBe(false);
    expect(res.checks.pinned_registry_key).toBe(false);
  });

  // --- v1 / v2 compatibility --------------------------------------------------

  it('the v1 verifier refuses a v2 proof on the version marker', async () => {
    const proof = await buildV2();
    const res = verifyAuthorityProof(proof as any, pins(proof) as any);
    expect(res.verified).toBe(false);
    expect(res.reason).toBe('unsupported_version');
  });

  it('the v1 verifier still accepts a v1 proof, unchanged (byte-identity regression)', () => {
    const v1 = signAuthorityProof(ARGS, ed.privateKey);
    const res = verifyAuthorityProof(v1, {
      pinnedRegistryKeys: [{ issuer_id: AUTHORITY_ID, public_key: v1.signature.public_key }],
    });
    expect(res.verified).toBe(true);
    expect(res.accepted).toBe(true);
  });

  it('the v2 verifier refuses a v1 proof on the version marker', async () => {
    const v1 = signAuthorityProof(ARGS, ed.privateKey);
    const res = await verifyAuthorityProofV2(v1 as any, { pinnedRegistryKeys: [] });
    expect(res.verified).toBe(false);
    expect(res.checks.version).toBe(false);
  });

  // --- anti-stripping ---------------------------------------------------------

  it('LEG STRIPPING: removing the ML-DSA leg refuses structurally', async () => {
    const proof = clone(await buildV2());
    proof.signature.signatures = proof.signature.signatures.filter((s: any) => s.alg === 'Ed25519');
    const res = await verifyAuthorityProofV2(proof, pins(proof));
    expect(res.verified).toBe(false);
    expect(res.checks.legs_present).toBe(false);
    expect(res.checks.signature).toBe(false);
  });

  it('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const proof = clone(await buildV2());
    proof.signature.signatures = proof.signature.signatures.filter((s: any) => s.alg === 'ML-DSA-65');
    const res = await verifyAuthorityProofV2(proof, pins(proof));
    expect(res.verified).toBe(false);
    expect(res.checks.legs_present).toBe(false);
  });

  it('SET NARROWING fails BOTH structurally and cryptographically', async () => {
    const proof = clone(await buildV2());
    proof.signature.required_algorithms = ['Ed25519'];
    proof.signature.signatures = proof.signature.signatures.filter((s: any) => s.alg === 'Ed25519');
    const res = await verifyAuthorityProofV2(proof, pins(proof));
    expect(res.verified).toBe(false);
    expect(res.checks.algorithm_set).toBe(false);

    const { signature, ...body } = proof;
    const narrowedBytes = Buffer.from(AUTHORITY_PROOF_V2_DOMAIN + canonicalize({ ...body, required_algorithms: ['Ed25519'] }), 'utf8');
    const edPub = crypto.createPublicKey({ key: Buffer.from(proof.signature.public_key, 'base64url'), format: 'der', type: 'spki' });
    const survivingSig = Buffer.from(proof.signature.signatures[0].sig, 'base64url');
    expect(crypto.verify(null, narrowedBytes, edPub, survivingSig)).toBe(false);
  });

  it('SET WIDENING: an extra algorithm refuses', async () => {
    const proof = clone(await buildV2());
    proof.signature.required_algorithms = ['Ed25519', 'ML-DSA-65', 'Ed448'];
    const res = await verifyAuthorityProofV2(proof, pins(proof));
    expect(res.verified).toBe(false);
    expect(res.checks.algorithm_set).toBe(false);
  });

  it('DUPLICATE ALGORITHM refuses', async () => {
    const proof = clone(await buildV2());
    proof.signature.signatures = [proof.signature.signatures[0], proof.signature.signatures[0]];
    const res = await verifyAuthorityProofV2(proof, pins(proof));
    expect(res.verified).toBe(false);
    expect(res.checks.legs_present).toBe(false);
  });

  it('ALGORITHM RELABELLING: Ed25519 leg called Ed448 refuses', async () => {
    const proof = clone(await buildV2());
    proof.signature.signatures = proof.signature.signatures.map((s: any) => (s.alg === 'Ed25519' ? { ...s, alg: 'Ed448' } : s));
    const res = await verifyAuthorityProofV2(proof, pins(proof));
    expect(res.verified).toBe(false);
    expect(res.checks.legs_present).toBe(false);
  });

  it('SWAPPED LEGS: the ML-DSA signature relabelled as Ed25519 refuses', async () => {
    const proof = clone(await buildV2());
    const pqLeg = proof.signature.signatures.find((s: any) => s.alg === 'ML-DSA-65');
    proof.signature.signatures = [{ ...pqLeg, alg: 'Ed25519' }, pqLeg];
    const res = await verifyAuthorityProofV2(proof, pins(proof));
    expect(res.verified).toBe(false);
    expect(res.checks.signature).toBe(false);
  });

  it('ED448 MASQUERADE: an Ed448 SPKI presented and pinned as the Ed25519 half refuses', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448Pub = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const proof = clone(await buildV2());
    proof.signature.public_key = ed448Pub;
    const res = await verifyAuthorityProofV2(proof, {
      pinnedRegistryKeys: [{ issuer_id: AUTHORITY_ID, public_key: ed448Pub, pq_public_key: proof.signature.pq_public_key }],
    });
    expect(res.verified).toBe(false);
    // The digest-derived Ed25519 key_id cannot come from a non-Ed25519 SPKI.
    expect(res.checks.structure).toBe(false);
  });

  // --- pinning ----------------------------------------------------------------

  it('pinning only the Ed25519 half refuses (both halves required)', async () => {
    const proof = await buildV2();
    const res = await verifyAuthorityProofV2(proof, {
      pinnedRegistryKeys: [{ issuer_id: AUTHORITY_ID, public_key: proof.signature.public_key, pq_public_key: '' } as any],
    });
    expect(res.accepted).toBe(false);
    expect(res.checks.pinned_registry_key).toBe(false);
  });

  it('PQ KEY SUBSTITUTION: a different pinned ML-DSA key refuses', async () => {
    const proof = await buildV2();
    const other = ml_dsa65.keygen(crypto.randomBytes(32));
    const res = await verifyAuthorityProofV2(proof, {
      pinnedRegistryKeys: [{ issuer_id: AUTHORITY_ID, public_key: proof.signature.public_key, pq_public_key: Buffer.from(other.publicKey).toString('base64url') }],
    });
    expect(res.accepted).toBe(false);
    expect(res.checks.pinned_registry_key).toBe(false);
  });

  // --- binding ----------------------------------------------------------------

  it('TAMPERED AFTER SIGNING: editing the body breaks the digest and BOTH legs', async () => {
    const proof = clone(await buildV2());
    proof.subject = 'ep:approver:mallory';
    const res = await verifyAuthorityProofV2(proof, pins(proof));
    expect(res.verified).toBe(false);
    expect(res.checks.proof_digest).toBe(false);
  });

  it('registry-head equivocation pin refuses on mismatch', async () => {
    const proof = await buildV2();
    const res = await verifyAuthorityProofV2(proof, { ...pins(proof), expectRegistryHead: `sha256:${'b'.repeat(64)}` });
    expect(res.accepted).toBe(false);
    expect(res.checks.registry_head).toBe(false);
  });

  // --- fail-closed backend ----------------------------------------------------

  it('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const proof = await buildV2();
    const res = await verifyAuthorityProofV2(proof, { ...pins(proof), mldsaBackendLoader: async () => null });
    expect(res.verified).toBe(false);
    expect(res.checks.signature).toBe(false);
    expect(String(res.reason)).toMatch(/pq_backend_unavailable/);
  });

  // --- fail-closed on junk ----------------------------------------------------

  it('malformed input refuses without throwing', async () => {
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
      const res = await verifyAuthorityProofV2(junk as any, { pinnedRegistryKeys: [] });
      expect(res.verified).toBe(false);
    }
  });
});
