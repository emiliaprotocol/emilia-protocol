// SPDX-License-Identifier: Apache-2.0
//
// EP-WITNESS-v2 hybrid cosignature test: applies the EP-REVOCATION-v2 template
// (packages/verify/src/revocation.ts) to the transparency-log witness
// cosignature (packages/verify/src/witness.ts). Builds a REAL Ed25519 +
// ML-DSA-65 signed cosignature over a checkpoint, then exercises the
// fail-closed hostile matrix: v1/v2 cross-refusal, leg stripping, set
// narrowing (structural AND cryptographic), truncated signatures, an Ed448
// key masquerading as the Ed25519 half, and a cosignature echoed for a
// different head.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import { canonicalize } from '../packages/verify/src/index.js';
import {
  WITNESS_VERSION,
  WITNESS_DOMAIN_TAG_V2,
  WITNESS_V2_VERSION,
  WITNESS_V2_REQUIRED_ALGORITHMS,
  witnessSigningDigest,
  witnessSigningDigestV2,
  verifyWitnessCosignature,
  verifyWitnessCosignatureV2,
  verifyWitnessCosignatureStatement,
  buildWitnessCosignatureV2,
} from '../packages/verify/src/witness.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

function makeCheckpoint(overrides: any = {}): any {
  return {
    tree_size: 42,
    root_hash: `sha256:${'a1'.repeat(32)}`,
    log_key_id: 'ep:log:test#1',
    merkle_alg: 'EP-MERKLE-v2',
    ...overrides,
  };
}

const CHECKPOINT = makeCheckpoint();
const WITNESS_ID = 'witness-hybrid-1';

const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');

const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');

const SIGNER = {
  privateKey: ed.privateKey,
  publicKeyB64u: edPubB64u,
  pqSecretKey: pq.secretKey,
  pqPublicKeyB64u: pq.publicKey,
};

const PIN = { witness_id: WITNESS_ID, public_key: edPubB64u, pq_public_key: pqPubB64u };

const build = (overrides: any = {}) => buildWitnessCosignatureV2({
  checkpoint: CHECKPOINT,
  witness_id: WITNESS_ID,
  signer: SIGNER,
  ...overrides,
});

// --- honesty gate: the PQ leg must actually run ------------------------------

describe('PQ backend availability', () => {
  it('real ML-DSA-65 backend is available for this suite', () => {
    expect(typeof ml_dsa65?.sign).toBe('function');
  });
});

// --- (a) happy path -----------------------------------------------------------

describe('valid v2 roundtrip', () => {
  it('a real hybrid cosignature verifies under both pinned keys', async () => {
    const cosig = await build();
    expect(cosig.alg).toBe(WITNESS_V2_VERSION);
    expect(cosig.required_algorithms).toEqual([...WITNESS_V2_REQUIRED_ALGORITHMS]);
    expect(cosig.signatures.map((s: any) => s.alg)).toEqual([...WITNESS_V2_REQUIRED_ALGORITHMS]);

    const res = await verifyWitnessCosignatureV2(CHECKPOINT, cosig, PIN);
    expect(res.verified).toBe(true);
    expect(res.witness_id).toBe(WITNESS_ID);
    expect(res.reason).toBeUndefined();
    expect(res.checks.version).toBe(true);
    expect(res.checks.algorithm_set).toBe(true);
    expect(res.checks.legs_present).toBe(true);
    expect(res.checks.key_material).toBe(true);
    expect(res.checks.echoed_head_consistent).toBe(true);
    expect(res.checks.signature_set_valid).toBe(true);
  });

  it('the digest carries the required algorithm set and the v2 domain tag', async () => {
    const cosig = await build();
    const digest = witnessSigningDigestV2(CHECKPOINT);
    expect(digest).not.toBeNull();
    expect(digest!.length).toBe(32);

    // Rebuild by hand to prove the exported digest matches the documented
    // construction, and that it differs from the v1 digest for the same head.
    const committed = { ...CHECKPOINT };
    delete committed.log_signature;
    const preimage = Buffer.concat([
      Buffer.from(WITNESS_DOMAIN_TAG_V2, 'utf8'),
      Buffer.from(canonicalize({ ...committed, required_algorithms: [...WITNESS_V2_REQUIRED_ALGORITHMS] }), 'utf8'),
    ]);
    const expected = crypto.createHash('sha256').update(preimage).digest();
    expect(digest!.equals(expected)).toBe(true);

    const v1Digest = witnessSigningDigest(CHECKPOINT);
    expect(v1Digest).not.toBeNull();
    expect(digest!.equals(v1Digest!)).toBe(false);

    const [edLeg, pqLeg] = cosig.signatures;
    expect(crypto.verify(null, digest!, ed.publicKey, Buffer.from(edLeg.sig, 'base64url'))).toBe(true);
    expect(ml_dsa65.verify(
      new Uint8Array(Buffer.from(pqLeg.sig, 'base64url')), new Uint8Array(digest!), pq.publicKey,
    )).toBe(true);
  });

  it('router dispatches a v2 cosignature to the v2 verifier', async () => {
    const cosig = await build();
    const res = await verifyWitnessCosignatureStatement(CHECKPOINT, cosig, PIN);
    expect(res.verified).toBe(true);
    expect(res.witness_id).toBe(WITNESS_ID);
  });
});

// --- (b) v1/v2 cross-refusal ---------------------------------------------------

describe('v1 / v2 cross-refusal', () => {
  it('v1 verifier refuses a v2 cosignature via the alg-marker guard', async () => {
    const cosig = await build();
    // Sanity: the v2 cosignature really does carry the v2 alg marker.
    expect(cosig.alg).toBe(WITNESS_V2_VERSION);
    expect(cosig.alg).not.toBe(WITNESS_VERSION);

    const res = verifyWitnessCosignature(CHECKPOINT, cosig as any, { witness_id: WITNESS_ID, public_key: edPubB64u });
    expect(res.verified).toBe(false);
    expect(res.reason).toMatch(new RegExp(`must be ${WITNESS_VERSION}`));
  });

  it('v1 verifier refuses a v2 cosignature via the missing-signature-string guard, independently', async () => {
    const cosig = await build();
    // Isolate the SECOND guard: strip the alg marker so the first guard
    // (alg !== WITNESS_VERSION) does not fire, and confirm refusal still
    // happens purely because `signature` (singular string) is absent -- a v2
    // cosignature has `signatures` (plural array) instead.
    expect(typeof (cosig as any).signature).not.toBe('string');
    const noAlg: any = { ...cosig };
    delete noAlg.alg;
    expect(noAlg.alg).toBeUndefined();

    const res = verifyWitnessCosignature(CHECKPOINT, noAlg, { witness_id: WITNESS_ID, public_key: edPubB64u });
    expect(res.verified).toBe(false);
    expect(res.reason).toMatch(/cosignature\.signature is missing/);
  });

  it('a v1 cosignature still round-trips through the unmodified v1 verifier', () => {
    const digest = witnessSigningDigest(CHECKPOINT)!;
    const signature = crypto.sign(null, digest, ed.privateKey).toString('base64url');
    const v1Cosig = {
      alg: WITNESS_VERSION,
      witness_id: WITNESS_ID,
      tree_size: CHECKPOINT.tree_size,
      root_hash: CHECKPOINT.root_hash,
      log_key_id: CHECKPOINT.log_key_id,
      signature,
    };
    const res = verifyWitnessCosignature(CHECKPOINT, v1Cosig, { witness_id: WITNESS_ID, public_key: edPubB64u });
    expect(res.verified).toBe(true);
    expect(res.witness_id).toBe(WITNESS_ID);
  });

  it('v2 verifier refuses a v1 cosignature on the version marker', async () => {
    const digest = witnessSigningDigest(CHECKPOINT)!;
    const signature = crypto.sign(null, digest, ed.privateKey).toString('base64url');
    const v1Cosig: any = {
      alg: WITNESS_VERSION,
      witness_id: WITNESS_ID,
      signature,
    };
    const res = await verifyWitnessCosignatureV2(CHECKPOINT, v1Cosig, PIN);
    expect(res.verified).toBe(false);
    expect(res.checks.version).toBe(false);
    expect(res.reason).toMatch(new RegExp(`unsupported version: ${WITNESS_VERSION}`));
  });

  it('the router sends a v1 cosignature to the v1 verifier and a v2 cosignature to the v2 verifier', async () => {
    const digest = witnessSigningDigest(CHECKPOINT)!;
    const signature = crypto.sign(null, digest, ed.privateKey).toString('base64url');
    const v1Cosig = { alg: WITNESS_VERSION, witness_id: WITNESS_ID, signature };
    const v2Cosig = await build();

    expect((await verifyWitnessCosignatureStatement(CHECKPOINT, v1Cosig, PIN)).verified).toBe(true);
    expect((await verifyWitnessCosignatureStatement(CHECKPOINT, v2Cosig, PIN)).verified).toBe(true);
  });
});

// --- (c) leg stripping ----------------------------------------------------------

describe('leg stripping', () => {
  it('removing the ML-DSA-65 leg refuses (legs_present / missing_required_algorithm)', async () => {
    const cosig = await build();
    cosig.signatures = cosig.signatures.filter((s: any) => s.alg === 'Ed25519');
    const res = await verifyWitnessCosignatureV2(CHECKPOINT, cosig, PIN);
    expect(res.verified).toBe(false);
    expect(res.checks.legs_present).toBe(false);
    expect(res.reason).toMatch(/missing required ML-DSA-65 signature/);
  });

  it('removing the Ed25519 leg refuses too (neither leg alone suffices)', async () => {
    const cosig = await build();
    cosig.signatures = cosig.signatures.filter((s: any) => s.alg === 'ML-DSA-65');
    const res = await verifyWitnessCosignatureV2(CHECKPOINT, cosig, PIN);
    expect(res.verified).toBe(false);
    expect(res.checks.legs_present).toBe(false);
  });
});

// --- (d) set narrowing -----------------------------------------------------------

describe('set narrowing', () => {
  it('narrowing required_algorithms (signatures left intact) refuses structurally', async () => {
    const cosig = await build();
    cosig.required_algorithms = ['Ed25519'];
    const res = await verifyWitnessCosignatureV2(CHECKPOINT, cosig, PIN);
    expect(res.verified).toBe(false);
    expect(res.checks.algorithm_set).toBe(false);
    // The signatures are the ORIGINAL full-set ones, still present.
    expect(cosig.signatures).toHaveLength(2);
  });

  it('the Ed25519 signature no longer verifies over the recomputed NARROWED digest', async () => {
    const cosig = await build();
    const edLeg = cosig.signatures.find((s: any) => s.alg === 'Ed25519');

    // witnessSigningDigestV2 throws on a non-registered set by design (the
    // guard this test is proving matters) -- so the narrowed digest is
    // reconstructed by hand here, exactly like the committed construction,
    // to show the signed bytes genuinely differ once the set is narrowed.
    expect(() => witnessSigningDigestV2(CHECKPOINT, ['Ed25519'] as any)).toThrow(
      /algorithm set is not the registered EP-WITNESS-v2 set/,
    );
    const committed = { ...CHECKPOINT };
    delete committed.log_signature;
    const narrowedPreimage = Buffer.concat([
      Buffer.from(WITNESS_DOMAIN_TAG_V2, 'utf8'),
      Buffer.from(canonicalize({ ...committed, required_algorithms: ['Ed25519'] }), 'utf8'),
    ]);
    const narrowedDigest = crypto.createHash('sha256').update(narrowedPreimage).digest();

    expect(
      crypto.verify(null, narrowedDigest, ed.publicKey, Buffer.from(edLeg.sig, 'base64url')),
    ).toBe(false);
    // And confirm it DOES verify over the correctly-committed (full-set) digest.
    const fullDigest = witnessSigningDigestV2(CHECKPOINT)!;
    expect(
      crypto.verify(null, fullDigest, ed.publicKey, Buffer.from(edLeg.sig, 'base64url')),
    ).toBe(true);
  });

  it('SET WIDENING: an extra algorithm in required_algorithms also refuses', async () => {
    const cosig = await build();
    cosig.required_algorithms = ['Ed25519', 'ML-DSA-65', 'Ed448'];
    const res = await verifyWitnessCosignatureV2(CHECKPOINT, cosig, PIN);
    expect(res.verified).toBe(false);
    expect(res.checks.algorithm_set).toBe(false);
  });
});

// --- (e) wrong-length signature ---------------------------------------------------

describe('malformed signature', () => {
  it('a truncated ML-DSA-65 signature refuses via malformed_signature, no throw', async () => {
    const cosig = await build();
    const pqLeg = cosig.signatures.find((s: any) => s.alg === 'ML-DSA-65');
    const truncated = Buffer.from(pqLeg.sig, 'base64url').subarray(0, 100).toString('base64url');
    cosig.signatures = cosig.signatures.map((s: any) => (s.alg === 'ML-DSA-65' ? { ...s, sig: truncated } : s));

    const res = await verifyWitnessCosignatureV2(CHECKPOINT, cosig, PIN);
    expect(res.verified).toBe(false);
    expect(res.checks.signature_set_valid).toBe(false);
    expect(res.reason).toMatch(/malformed_signature/);
  });

  it('a truncated Ed25519 signature also refuses via malformed_signature', async () => {
    const cosig = await build();
    const edLeg = cosig.signatures.find((s: any) => s.alg === 'Ed25519');
    const truncated = Buffer.from(edLeg.sig, 'base64url').subarray(0, 10).toString('base64url');
    cosig.signatures = cosig.signatures.map((s: any) => (s.alg === 'Ed25519' ? { ...s, sig: truncated } : s));

    const res = await verifyWitnessCosignatureV2(CHECKPOINT, cosig, PIN);
    expect(res.verified).toBe(false);
    expect(res.checks.signature_set_valid).toBe(false);
    expect(res.reason).toMatch(/malformed_signature/);
  });
});

// --- (f) Ed448 masquerade ---------------------------------------------------------

describe('Ed448 masquerade', () => {
  it('an Ed448 SPKI key pinned as the Ed25519 half refuses via malformed_key, never a silent pass', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448PubB64u = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const cosig = await build();

    const res = await verifyWitnessCosignatureV2(CHECKPOINT, cosig, {
      witness_id: WITNESS_ID, public_key: ed448PubB64u, pq_public_key: pqPubB64u,
    });
    expect(res.verified).toBe(false);
    expect(res.checks.signature_set_valid).toBe(false);
    expect(res.reason).toMatch(/malformed_key/);
  });
});

// --- (g) different checkpoint (echoed-head mismatch) -------------------------------

describe('echoed-head consistency', () => {
  it('a cosignature echoing a different tree_size refuses before crypto runs', async () => {
    const cosig = await build();
    cosig.tree_size = 999;
    const res = await verifyWitnessCosignatureV2(CHECKPOINT, cosig, PIN);
    expect(res.verified).toBe(false);
    expect(res.checks.echoed_head_consistent).toBe(false);
    expect(res.reason).toMatch(/different head/);
  });

  it('a cosignature echoing a different root_hash refuses', async () => {
    const cosig = await build();
    cosig.root_hash = `sha256:${'ff'.repeat(32)}`;
    const res = await verifyWitnessCosignatureV2(CHECKPOINT, cosig, PIN);
    expect(res.verified).toBe(false);
    expect(res.checks.echoed_head_consistent).toBe(false);
  });

  it('a cosignature echoing a different log_key_id refuses', async () => {
    const cosig = await build();
    cosig.log_key_id = 'ep:log:evil#9';
    const res = await verifyWitnessCosignatureV2(CHECKPOINT, cosig, PIN);
    expect(res.verified).toBe(false);
    expect(res.checks.echoed_head_consistent).toBe(false);
    expect(res.reason).toMatch(/different log/);
  });

  it('presenting the cosignature against an actually different checkpoint refuses on the crypto too', async () => {
    const cosig = await build();
    // Drop the echoed fields so the mismatch is caught by the digest check,
    // not the echo guard.
    delete cosig.tree_size;
    delete cosig.root_hash;
    delete cosig.log_key_id;
    const otherCheckpoint = makeCheckpoint({ tree_size: 100 });
    const res = await verifyWitnessCosignatureV2(otherCheckpoint, cosig, PIN);
    expect(res.verified).toBe(false);
    expect(res.checks.signature_set_valid).toBe(false);
  });
});

// --- fail-closed backend --------------------------------------------------------

describe('fail-closed ML-DSA backend', () => {
  it('an unavailable ML-DSA backend is a refusal, never a pass on the classical leg', async () => {
    const cosig = await build();
    const res = await verifyWitnessCosignatureV2(CHECKPOINT, cosig, PIN, {
      mldsaBackendLoader: async () => null,
    });
    expect(res.verified).toBe(false);
    expect(res.checks.signature_set_valid).toBe(false);
    expect(res.reason).toMatch(/pq_backend_unavailable/);
  });
});

// --- fail-closed on junk / pinning ----------------------------------------------

describe('fail-closed on malformed input', () => {
  it('malformed checkpoint / cosignature / pin refuse without throwing', async () => {
    const cosig = await build();
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
      const res = await verifyWitnessCosignatureV2(junk as any, cosig, PIN);
      expect(res.verified).toBe(false);
    }
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
      const res = await verifyWitnessCosignatureV2(CHECKPOINT, junk as any, PIN);
      expect(res.verified).toBe(false);
    }
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
      const res = await verifyWitnessCosignatureV2(CHECKPOINT, cosig, junk as any);
      expect(res.verified).toBe(false);
    }
  });

  it('an unpinned witness (missing pq_public_key half) refuses', async () => {
    const cosig = await build();
    const res = await verifyWitnessCosignatureV2(CHECKPOINT, cosig, { witness_id: WITNESS_ID, public_key: edPubB64u });
    expect(res.verified).toBe(false);
    expect(res.checks.key_material).toBe(false);
  });

  it('a cosignature naming an unpinned witness_id refuses', async () => {
    const cosig = await build({ witness_id: 'witness-stranger' });
    const res = await verifyWitnessCosignatureV2(CHECKPOINT, cosig, PIN);
    expect(res.verified).toBe(false);
    expect(res.checks.key_material).toBe(false);
  });

  it('duplicate signature entries for one algorithm refuse', async () => {
    const cosig = await build();
    cosig.signatures = [cosig.signatures[0], cosig.signatures[0]];
    const res = await verifyWitnessCosignatureV2(CHECKPOINT, cosig, PIN);
    expect(res.verified).toBe(false);
    expect(res.checks.legs_present).toBe(false);
    expect(res.reason).toMatch(/duplicate signature/);
  });
});

// --- buildWitnessCosignatureV2 issuer-side gates --------------------------------

describe('buildWitnessCosignatureV2', () => {
  it('emits signatures in registered order', async () => {
    const cosig = await build();
    expect(cosig.signatures.map((s: any) => s.alg)).toEqual(['Ed25519', 'ML-DSA-65']);
  });

  it('the deterministic variant reproduces byte-identical signatures', async () => {
    const a = await build({ deterministic: true });
    const b = await build({ deterministic: true });
    expect(a.signatures).toEqual(b.signatures);
  });

  it('refuses a missing checkpoint', async () => {
    await expect(build({ checkpoint: null })).rejects.toThrow(/requires a checkpoint object/);
  });

  it('refuses a missing witness_id', async () => {
    await expect(build({ witness_id: '' })).rejects.toThrow(/requires witness_id/);
  });

  it('refuses a signer missing the PQ half', async () => {
    await expect(build({ signer: { privateKey: ed.privateKey, publicKeyB64u: edPubB64u } }))
      .rejects.toThrow(/pqSecretKey/);
  });

  it('refuses a wrong-length pq public key', async () => {
    await expect(build({ signer: { ...SIGNER, pqPublicKeyB64u: new Uint8Array(10) } }))
      .rejects.toThrow(/1952/);
  });

  it('refuses a non-Ed25519 privateKey', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    await expect(build({ signer: { ...SIGNER, privateKey: ed448.privateKey } }))
      .rejects.toThrow(/Ed25519 private KeyObject/);
  });
});
