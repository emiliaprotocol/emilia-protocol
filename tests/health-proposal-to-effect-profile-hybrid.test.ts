// SPDX-License-Identifier: Apache-2.0
//
// Healthcare assurance assertion/packet, hybrid (Ed25519 + ML-DSA-65)
// profile: hostile matrix for the signature primitive
// (signAssuranceValueV2 / verifyPinnedSignatureV2) and for the version
// routing that gates v1 vs v2 (checkHealthcareAssurancePacketInternalConsistency,
// verifyHealthcareAssurancePacketOfflineV2 / Any).
//
// This suite targets the primitive EP-SIG-AGILITY-v1-shaped set signature
// this migration adds, over an arbitrary signed value -- exactly the same
// scope packages/verify/pq-signature-agility.test.ts tests verifyAgileSignature
// against arbitrary message bytes rather than a full production receipt.
// The full production packet assembly (createHealthcareConsequenceControl's
// exportAssurancePacket / exportAssurancePacketV2) is exercised by
// tests/health-proposal-to-effect-profile.test.ts for v1; this file adds the
// v2 crypto layer without re-deriving that fixture's FHIR/CAID plumbing.
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  HEALTHCARE_ASSURANCE_ASSERTION_VERSION,
  HEALTHCARE_ASSURANCE_ASSERTION_V2_VERSION,
  HEALTHCARE_ASSURANCE_PACKET_VERSION,
  HEALTHCARE_ASSURANCE_PACKET_V2_VERSION,
  HEALTHCARE_ASSURANCE_V2_REQUIRED_ALGORITHMS,
  assuranceProofV2Shape,
  signAssuranceValueV2,
  verifyPinnedSignatureV2,
  signedAssuranceAssertionV2,
  checkHealthcareAssurancePacketInternalConsistency,
  verifyHealthcareAssurancePacketOffline,
  verifyHealthcareAssurancePacketOfflineV2,
  verifyHealthcareAssurancePacketOfflineAny,
  type HealthcareAssuranceHybridSigner,
  type HealthcareAssuranceHybridKeyPin,
} from '../lib/health/proposal-to-effect-profile.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const pqSecretB64u = Buffer.from(pq.secretKey).toString('base64url');

const SIGNER: HealthcareAssuranceHybridSigner = {
  ed25519: {
    algorithm: 'Ed25519',
    key_id: 'assurance:hybrid:test',
    sign: (bytes: Uint8Array) => crypto.sign(null, Buffer.from(bytes), ed.privateKey).toString('base64url'),
  },
  mldsa65: { key_id: 'assurance:hybrid:test:pq', private_key: pqSecretB64u },
};
const PIN: HealthcareAssuranceHybridKeyPin = {
  key_id: 'assurance:hybrid:test',
  public_key_spki_b64u: edPubB64u,
  pq_key_id: 'assurance:hybrid:test:pq',
  pq_public_key_b64u: pqPubB64u,
};
const VALUE = { role: 'receipt', arbitrary: 'signed-value-under-test' };

describe('healthcare assurance proof -- hybrid v2 primitive', () => {
  it('valid v2 roundtrip: signAssuranceValueV2 produces a proof verifyPinnedSignatureV2 accepts', async () => {
    const proof = await signAssuranceValueV2('roundtrip', VALUE, SIGNER);
    expect(proof.profile).toBe(HEALTHCARE_ASSURANCE_PACKET_V2_VERSION);
    expect(proof.required_algorithms).toEqual([...HEALTHCARE_ASSURANCE_V2_REQUIRED_ALGORITHMS]);
    expect(assuranceProofV2Shape(proof)).toBe(true);
    expect(await verifyPinnedSignatureV2('roundtrip', VALUE, proof, PIN)).toBe(true);
  });

  it('a proof signed for one domain does not verify under another (domain separation holds)', async () => {
    const proof = await signAssuranceValueV2('domain-a', VALUE, SIGNER);
    expect(await verifyPinnedSignatureV2('domain-b', VALUE, proof, PIN)).toBe(false);
  });

  it('a proof over one value does not verify over a mutated value', async () => {
    const proof = await signAssuranceValueV2('mutation', VALUE, SIGNER);
    expect(await verifyPinnedSignatureV2('mutation', { ...VALUE, arbitrary: 'tampered' }, proof, PIN)).toBe(false);
  });

  it('stripped leg: dropping the ML-DSA-65 signature refuses (never a pass on the classical leg alone)', async () => {
    const proof = await signAssuranceValueV2('strip-pq', VALUE, SIGNER);
    const stripped = { ...proof, signatures: proof.signatures.filter((s) => s.alg !== 'ML-DSA-65') };
    expect(assuranceProofV2Shape(stripped)).toBe(false);
    expect(await verifyPinnedSignatureV2('strip-pq', VALUE, stripped, PIN)).toBe(false);
  });

  it('stripped leg: dropping the Ed25519 signature refuses', async () => {
    const proof = await signAssuranceValueV2('strip-ed', VALUE, SIGNER);
    const stripped = { ...proof, signatures: proof.signatures.filter((s) => s.alg !== 'Ed25519') };
    expect(assuranceProofV2Shape(stripped)).toBe(false);
    expect(await verifyPinnedSignatureV2('strip-ed', VALUE, stripped, PIN)).toBe(false);
  });

  it('narrowed set: required_algorithms=[Ed25519] is rejected by the proof shape check, never silently accepted', async () => {
    const proof = await signAssuranceValueV2('narrow', VALUE, SIGNER);
    const narrowed = {
      ...proof,
      required_algorithms: ['Ed25519'],
      signatures: proof.signatures.filter((s) => s.alg === 'Ed25519'),
    };
    expect(assuranceProofV2Shape(narrowed)).toBe(false);
    expect(await verifyPinnedSignatureV2('narrow', VALUE, narrowed, PIN)).toBe(false);
  });

  it('wrong-length signature: a truncated Ed25519 leg refuses as a signature failure, not a crash', async () => {
    const proof = await signAssuranceValueV2('wrong-length', VALUE, SIGNER);
    const truncated = {
      ...proof,
      signatures: proof.signatures.map((s) => (s.alg === 'Ed25519' ? { ...s, sig: s.sig.slice(0, 6) } : s)),
    };
    expect(await verifyPinnedSignatureV2('wrong-length', VALUE, truncated, PIN)).toBe(false);
  });

  it('Ed448-masquerade: an Ed448 key presented as the Ed25519 pin is refused, never silently accepted', async () => {
    const proof = await signAssuranceValueV2('ed448', VALUE, SIGNER);
    const ed448 = crypto.generateKeyPairSync('ed448');
    const badPin = {
      ...PIN,
      public_key_spki_b64u: ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
    };
    expect(await verifyPinnedSignatureV2('ed448', VALUE, proof, badPin)).toBe(false);
  });

  it('key substitution: an unpinned ML-DSA-65 public key is refused even with well-formed signatures', async () => {
    const proof = await signAssuranceValueV2('substitution', VALUE, SIGNER);
    const otherPq = ml_dsa65.keygen(crypto.randomBytes(32));
    const badPin = { ...PIN, pq_public_key_b64u: Buffer.from(otherPq.publicKey).toString('base64url') };
    expect(await verifyPinnedSignatureV2('substitution', VALUE, proof, badPin)).toBe(false);
  });

  it('signedAssuranceAssertionV2 mints an assertion with the v2 version marker and a verifiable proof', async () => {
    const assertion = await signedAssuranceAssertionV2('receipt', { role: 'receipt', projection: {}, artifact_digest: `sha256:${'0'.repeat(64)}` }, SIGNER);
    expect(assertion['@version']).toBe(HEALTHCARE_ASSURANCE_ASSERTION_V2_VERSION);
    expect(await verifyPinnedSignatureV2('assertion:receipt', { '@version': assertion['@version'], role: assertion.role, body: assertion.body }, assertion.proof, PIN)).toBe(true);
  });
});

describe('healthcare assurance packet -- v1/v2 version routing', () => {
  it('checkHealthcareAssurancePacketInternalConsistency defaults are byte-identical to the hardcoded v1 constants', () => {
    const packet = { '@version': 'not-even-close' };
    const viaDefault = checkHealthcareAssurancePacketInternalConsistency(packet);
    const viaExplicitV1 = checkHealthcareAssurancePacketInternalConsistency(packet, {
      version: HEALTHCARE_ASSURANCE_PACKET_VERSION,
      assertionVersion: HEALTHCARE_ASSURANCE_ASSERTION_VERSION,
    });
    expect(viaDefault).toEqual(viaExplicitV1);
    expect(viaDefault).toEqual({ consistent: false, reasons: ['packet_shape_invalid'] });
  });

  it('the v1 consistency check refuses a v2-versioned packet on the version marker', () => {
    const result = checkHealthcareAssurancePacketInternalConsistency({ '@version': HEALTHCARE_ASSURANCE_PACKET_V2_VERSION });
    expect(result).toEqual({ consistent: false, reasons: ['packet_shape_invalid'] });
  });

  it('the v2 consistency check (explicit options) refuses a v1-versioned packet on the version marker', () => {
    const result = checkHealthcareAssurancePacketInternalConsistency({ '@version': HEALTHCARE_ASSURANCE_PACKET_VERSION }, {
      version: HEALTHCARE_ASSURANCE_PACKET_V2_VERSION,
      assertionVersion: HEALTHCARE_ASSURANCE_ASSERTION_V2_VERSION,
      proofShapeCheck: assuranceProofV2Shape,
    });
    expect(result).toEqual({ consistent: false, reasons: ['packet_shape_invalid'] });
  });

  it('v1 verifyHealthcareAssurancePacketOffline stays synchronous and refuses a v2 packet on the version marker', () => {
    const result = verifyHealthcareAssurancePacketOffline(
      { '@version': HEALTHCARE_ASSURANCE_PACKET_V2_VERSION },
      { '@version': 'irrelevant' },
    );
    expect(result.valid).toBe(false);
  });

  it('v2 verifier refuses a v1 packet on the version marker', async () => {
    const result = await verifyHealthcareAssurancePacketOfflineV2(
      { '@version': HEALTHCARE_ASSURANCE_PACKET_VERSION },
      { '@version': 'irrelevant' },
    );
    expect(result.valid).toBe(false);
  });

  it('verifyHealthcareAssurancePacketOfflineAny routes a v2-versioned packet to the hybrid verifier', async () => {
    const packet = { '@version': HEALTHCARE_ASSURANCE_PACKET_V2_VERSION };
    const trust = { '@version': 'irrelevant' };
    expect(await verifyHealthcareAssurancePacketOfflineAny(packet, trust))
      .toEqual(await verifyHealthcareAssurancePacketOfflineV2(packet, trust));
  });

  it('verifyHealthcareAssurancePacketOfflineAny routes anything else to the v1 verifier', async () => {
    const packet = { '@version': HEALTHCARE_ASSURANCE_PACKET_VERSION };
    const trust = { '@version': 'irrelevant' };
    expect(await verifyHealthcareAssurancePacketOfflineAny(packet, trust))
      .toEqual(verifyHealthcareAssurancePacketOffline(packet, trust));
  });
});
