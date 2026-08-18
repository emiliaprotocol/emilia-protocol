// SPDX-License-Identifier: Apache-2.0
//
// EP-AEB-NATIVE-VERIFICATION-ATTESTATION-v2 hostile matrix.
//
// The PQ leg runs for real: this suite FAILS LOUDLY if @noble/post-quantum is
// missing rather than skipping, so a green run means ML-DSA-65 actually
// verified. The hostile half is the point -- stripped leg, narrowed set,
// wrong-length signature, an Ed448 key masquerading as the Ed25519 half, and
// the unchanged synchronous v1 adapter handed a v2 attestation.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import {
  AEB_NATIVE_VERIFICATION_ATTESTATION_VERSION,
  AEB_NATIVE_VERIFICATION_ATTESTATION_V2_VERSION,
  AEB_NATIVE_ATTESTATION_V2_REQUIRED_ALGORITHMS,
  aebNativeAttestationV2SigningBytes,
  signAebNativeVerificationAttestationV2,
  verifyAebNativeVerificationAttestationV2,
  createAebNativeVerificationAttestationAdapter,
  digestAeb,
  type AebNativeVerificationAttestationV2,
  type AebNativeVerificationAttestationV2Body,
} from '../packages/verify/src/aeb-adapter-contract.ts';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');

const KEY_ID = 'ep:native-verifier:1';
const PQ_KEY_ID = 'ep:native-verifier-pq:1';

const PIN = {
  key_id: KEY_ID,
  public_key: edPubB64u,
  pq_key_id: PQ_KEY_ID,
  pq_public_key: pqPubB64u,
};

const SIGNER = {
  key_id: KEY_ID,
  private_key: ed.privateKey,
  pq_key_id: PQ_KEY_ID,
  pq_secret_key: pq.secretKey,
  pq_public_key: pqPubB64u,
};

const CAID = `caid:1:payment.transfer.1:jcs-sha256:${'A'.repeat(43)}`;

const BODY: AebNativeVerificationAttestationV2Body = {
  '@version': AEB_NATIVE_VERIFICATION_ATTESTATION_V2_VERSION,
  protocol_id: 'wimse.workload-identity',
  audience: 'gate.example',
  native_artifact_ref: 'artifact:1',
  native_artifact_digest: digestAeb({ artifact: 1 }),
  evidence_role: 'human-authorization',
  subject: { id: 'user:alice', kind: 'human' },
  verified_at: '2026-08-17T10:00:00.000Z',
  expires_at: '2026-08-17T11:00:00.000Z',
  mapping: {
    profile_digest: digestAeb({ profile: 1 }),
    mapper_id: 'mapper:exact-action-v1',
    resolver_digest: digestAeb({ resolver: 1 }),
    caid: CAID,
    normalized_action_digest: digestAeb({ action_type: 'payment.transfer.1' }),
  },
};

const build = () => signAebNativeVerificationAttestationV2(BODY, SIGNER);
const clone = (a: AebNativeVerificationAttestationV2) =>
  JSON.parse(JSON.stringify(a)) as AebNativeVerificationAttestationV2;

describe('EP-AEB-NATIVE-VERIFICATION-ATTESTATION-v2 happy path', () => {
  it('the real ML-DSA-65 backend is present (this suite never silently skips the PQ leg)', () => {
    expect(typeof ml_dsa65.verify).toBe('function');
    expect(pq.publicKey.length).toBe(1952);
  });

  it('round-trips a hybrid attestation under both pinned keys', async () => {
    const attestation = await build();
    expect(attestation.proof.required_algorithms)
      .toEqual([...AEB_NATIVE_ATTESTATION_V2_REQUIRED_ALGORITHMS]);
    expect((attestation.proof.signatures as Array<{ alg: string }>).map((s) => s.alg))
      .toEqual(['Ed25519', 'ML-DSA-65']);
    const result = await verifyAebNativeVerificationAttestationV2(attestation, PIN);
    expect(result.errors).toEqual([]);
    expect(result.valid).toBe(true);
  });

  it('the ML-DSA-65 leg is really 3309 bytes and really checks out standalone', async () => {
    const attestation = await build();
    const legs = attestation.proof.signatures as Array<{ alg: string; sig: string }>;
    const pqLeg = legs.find((s) => s.alg === 'ML-DSA-65')!;
    const sigBytes = Buffer.from(pqLeg.sig, 'base64url');
    expect(sigBytes.length).toBe(3309);
    const bytes = aebNativeAttestationV2SigningBytes(BODY);
    expect(ml_dsa65.verify(new Uint8Array(sigBytes), new Uint8Array(bytes), pq.publicKey)).toBe(true);
  });
});

describe('EP-AEB-NATIVE-VERIFICATION-ATTESTATION-v2 hostile matrix', () => {
  it('refuses a stripped ML-DSA leg with the set left intact', async () => {
    const attestation = clone(await build());
    attestation.proof.signatures =
      (attestation.proof.signatures as Array<{ alg: string }>).filter((s) => s.alg !== 'ML-DSA-65');
    const result = await verifyAebNativeVerificationAttestationV2(attestation, PIN);
    expect(result.valid).toBe(false);
    expect(result.checks.legs_present).toBe(false);
    expect(result.errors.join(' ')).toContain('missing required ML-DSA-65 signature');
  });

  it('refuses a stripped leg WITH a narrowed required_algorithms set', async () => {
    const attestation = clone(await build());
    attestation.proof.signatures =
      (attestation.proof.signatures as Array<{ alg: string }>).filter((s) => s.alg !== 'ML-DSA-65');
    attestation.proof.required_algorithms = ['Ed25519'];
    const result = await verifyAebNativeVerificationAttestationV2(attestation, PIN);
    expect(result.valid).toBe(false);
    expect(result.checks.algorithm_set).toBe(false);
    expect(result.checks.legs_present).toBe(false);
  });

  it('refuses a WIDENED algorithm set', async () => {
    const attestation = clone(await build());
    attestation.proof.required_algorithms = ['Ed25519', 'ML-DSA-65', 'Ed448'];
    const result = await verifyAebNativeVerificationAttestationV2(attestation, PIN);
    expect(result.valid).toBe(false);
    expect(result.checks.algorithm_set).toBe(false);
  });

  it('refuses a wrong-length Ed25519 signature (never treats it as a pass)', async () => {
    const attestation = clone(await build());
    const legs = attestation.proof.signatures as Array<{ alg: string; sig: string }>;
    const edLeg = legs.find((s) => s.alg === 'Ed25519')!;
    edLeg.sig = Buffer.alloc(63).toString('base64url');
    const result = await verifyAebNativeVerificationAttestationV2(attestation, PIN);
    expect(result.valid).toBe(false);
    expect(result.checks.signature_valid).toBe(false);
    expect(result.errors.join(' ')).toContain('malformed_signature');
  });

  it('refuses a wrong-length ML-DSA-65 signature', async () => {
    const attestation = clone(await build());
    const legs = attestation.proof.signatures as Array<{ alg: string; sig: string }>;
    const pqLeg = legs.find((s) => s.alg === 'ML-DSA-65')!;
    pqLeg.sig = Buffer.alloc(3308).toString('base64url');
    const result = await verifyAebNativeVerificationAttestationV2(attestation, PIN);
    expect(result.valid).toBe(false);
    expect(result.checks.signature_valid).toBe(false);
  });

  it('refuses an Ed448 SPKI masquerading as the pinned Ed25519 half', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448Pub = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const attestation = clone(await build());
    attestation.proof.public_key = ed448Pub;
    const result = await verifyAebNativeVerificationAttestationV2(
      attestation,
      { ...PIN, public_key: ed448Pub },
    );
    expect(result.valid).toBe(false);
    expect(result.checks.verifier_key_pinned).toBe(false);
    expect(result.errors.join(' ')).toContain('not a canonical Ed25519 SPKI');
  });

  it('refuses key substitution: a presented key that is not the pinned key', async () => {
    const other = crypto.generateKeyPairSync('ed25519');
    const attestation = clone(await build());
    attestation.proof.public_key = other.publicKey
      .export({ format: 'der', type: 'spki' }).toString('base64url');
    const result = await verifyAebNativeVerificationAttestationV2(attestation, PIN);
    expect(result.valid).toBe(false);
    expect(result.checks.verifier_key_pinned).toBe(false);
  });

  it('refuses when the attestation body was tampered after signing', async () => {
    const attestation = clone(await build());
    attestation.audience = 'gate.attacker';
    const result = await verifyAebNativeVerificationAttestationV2(attestation, PIN);
    expect(result.valid).toBe(false);
    expect(result.checks.signature_valid).toBe(false);
    expect(result.checks.signature_binds_attestation).toBe(false);
  });

  it('refuses with pq_backend_unavailable rather than passing on the classical leg', async () => {
    const attestation = await build();
    const result = await verifyAebNativeVerificationAttestationV2(
      attestation,
      PIN,
      { mldsaBackendLoader: () => null },
    );
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toContain('pq_backend_unavailable');
  });

  it('refuses an unpinned verifier (identified but not trusted)', async () => {
    const attestation = await build();
    const result = await verifyAebNativeVerificationAttestationV2(attestation, null);
    expect(result.valid).toBe(false);
    expect(result.checks.verifier_key_pinned).toBe(false);
  });

  it('never throws on hostile caller input', async () => {
    for (const bad of [null, undefined, 'x', 42, [], { proof: null }]) {
      const result = await verifyAebNativeVerificationAttestationV2(bad, PIN);
      expect(result.valid).toBe(false);
    }
  });

  it('refuses a v1 attestation handed to the v2 verifier (mirror image)', async () => {
    const v1Shaped = {
      ...BODY,
      '@version': AEB_NATIVE_VERIFICATION_ATTESTATION_VERSION,
      signature: { alg: 'Ed25519', key_id: KEY_ID, value: Buffer.alloc(64).toString('base64url') },
    };
    const result = await verifyAebNativeVerificationAttestationV2(v1Shaped, PIN);
    expect(result.valid).toBe(false);
    expect(result.checks.version).toBe(false);
  });
});

describe('the unchanged v1 adapter refuses a v2 attestation on the version marker', () => {
  it('returns native_attestation_malformed and does not throw or accept', async () => {
    const attestation = await build();
    const adapter = createAebNativeVerificationAttestationAdapter({
      id: 'native:test-bridge', version: '1',
    });
    const native = adapter.verifyNative({
      artifact: attestation,
      artifact_ref: 'artifact:1',
      status: {
        checked_at: '2026-08-17T10:30:00.000Z',
        expires_at: '2026-08-17T11:00:00.000Z',
        revocation_checked: true,
        revoked: false,
        consumed: false,
      },
      trust_roots: [{ key_id: KEY_ID, public_key: edPubB64u }],
      adapter_config: { audience: 'gate.example', accepted_protocols: ['wimse.workload-identity'] },
      expected_action: { action_type: 'payment.transfer.1', parameters: { amount: 1 } },
      now: '2026-08-17T10:30:00.000Z',
    });
    expect(native.native_verification).toBe('FAILED');
    expect(native.reasons).toEqual(['native_attestation_malformed']);
  });
});
