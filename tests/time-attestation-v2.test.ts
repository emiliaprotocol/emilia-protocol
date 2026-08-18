// SPDX-License-Identifier: Apache-2.0
//
// EP-TIME-ATTESTATION-v2 hybrid verifier test: the reference hybrid
// migration applied to the TSA attestation.
//
// Builds a REAL Ed25519 + ML-DSA-65 signed time attestation, then asserts the
// fail-closed predicate. The hostile half is the point: leg stripping, set
// narrowing, a truncated ML-DSA-65 signature, an Ed448 key masquerading as
// the Ed25519 half, TSA key substitution, an out-of-bounds attested time, and
// a v1 verifier handed a v2 attestation (and vice versa).
//
// The PQ leg runs for real. This suite relies on @noble/post-quantum being
// installed rather than silently skipping, so a green run means ML-DSA-65
// actually verified.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import { canonicalize } from '../packages/verify/src/index.ts';
import {
  TIME_ATTESTATION_VERSION,
  verifyTimeAttestation,
  TIME_ATTESTATION_V2_VERSION,
  TIME_ATTESTATION_V2_REQUIRED_ALGORITHMS,
  timeAttestationV2SignedBytes,
  verifyTimeAttestationV2,
  verifyTimeAttestationStatement,
  buildTimeAttestationV2,
  timeAttestationSignedBytes,
} from '../packages/verify/src/time-attestation.ts';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const TSA = 'ep:tsa:roughtime-2-hybrid';
const HASH = `sha256:${'c'.repeat(64)}`;
const TIME = '2026-06-20T12:00:00.000Z';

function newSigner() {
  const ed = crypto.generateKeyPairSync('ed25519');
  const edPubB64u = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
  const pq = ml_dsa65.keygen(crypto.randomBytes(32));
  const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
  return {
    privateKey: ed.privateKey,
    publicKeyB64u: edPubB64u,
    pqSecretKey: pq.secretKey,
    pqPublicKeyB64u: pq.publicKey,
    pqPublicKeyRawB64u: pqPubB64u,
  };
}

const pinOf = (s: ReturnType<typeof newSigner>) => ({
  [TSA]: { public_key: s.publicKeyB64u, pq_public_key: s.pqPublicKeyRawB64u },
});

const build = (s: ReturnType<typeof newSigner>, overrides: Partial<{ ts_authority_id: string; hashed: string; time: string }> = {}) =>
  buildTimeAttestationV2({
    ts_authority_id: TSA, hashed: HASH, time: TIME, signer: s, ...overrides,
  });

describe('EP-TIME-ATTESTATION-v2', () => {
  it('does not touch the v1 exported signed-bytes seam', () => {
    // evidence-record.ts's algorithm-AGILE per-attestation path depends on
    // timeAttestationSignedBytes returning exactly the v1 bytes. Assert the
    // v1 version marker still appears literally in what it returns for an
    // attestation that itself claims v2 -- i.e. it is NOT reading @version
    // off the input, confirming the v2 work did not rewire this seam.
    const bytes = timeAttestationSignedBytes({
      '@version': 'anything-a-caller-might-pass', hashed: HASH, time: TIME, ts_authority_id: TSA,
    });
    const decoded = JSON.parse(bytes.toString('utf8'));
    expect(decoded['@version']).toBe(TIME_ATTESTATION_VERSION);
  });

  it('(a) valid v2 roundtrip', async () => {
    const s = newSigner();
    const att = await build(s);
    expect(att['@version']).toBe(TIME_ATTESTATION_V2_VERSION);
    expect(att.proof.required_algorithms).toEqual([...TIME_ATTESTATION_V2_REQUIRED_ALGORITHMS]);
    expect(att.proof.signatures.map((sig: { alg: string }) => sig.alg)).toEqual([...TIME_ATTESTATION_V2_REQUIRED_ALGORITHMS]);

    const res = await verifyTimeAttestationV2(att, {
      tsaKeys: pinOf(s),
      expectedHash: HASH,
      notBefore: '2026-06-01T00:00:00Z',
      notAfter: '2026-07-01T00:00:00Z',
    });
    expect(res.valid).toBe(true);
    expect(res.errors).toEqual([]);

    // The router reaches the same verdict.
    const routed = await verifyTimeAttestationStatement(att, { tsaKeys: pinOf(s) });
    expect(routed.valid).toBe(true);
  });

  it('(b) v1 verifier refuses a v2 attestation cleanly, with no throw; a v1 attestation still round-trips unmodified', async () => {
    const s = newSigner();
    const v2att = await build(s);

    let result: ReturnType<typeof verifyTimeAttestation> | undefined;
    expect(() => {
      result = verifyTimeAttestation(v2att, { tsaKeys: { [TSA]: { public_key: s.publicKeyB64u } } });
    }).not.toThrow();
    expect(result!.valid).toBe(false);
    expect(result!.checks.version).toBe(false);

    // A v1 attestation still verifies through the completely unmodified v1
    // verifier, using the completely unmodified v1 signed-bytes seam.
    const v1payload = timeAttestationSignedBytes({
      '@version': TIME_ATTESTATION_VERSION, hashed: HASH, time: TIME, ts_authority_id: TSA,
    });
    const v1att = {
      '@version': TIME_ATTESTATION_VERSION,
      ts_authority_id: TSA,
      hashed: HASH,
      time: TIME,
      proof: {
        algorithm: 'Ed25519',
        ts_key_id: 'tk1',
        public_key: s.publicKeyB64u,
        signature_b64u: crypto.sign(null, v1payload, s.privateKey).toString('base64url'),
      },
    };
    const v1res = verifyTimeAttestation(v1att, { tsaKeys: { [TSA]: { public_key: s.publicKeyB64u } } });
    expect(v1res.valid).toBe(true);

    // The v1->v2 mirror: the v2 verifier refuses a v1 attestation too, cleanly.
    const mirrored = await verifyTimeAttestationV2(v1att, { tsaKeys: pinOf(s) });
    expect(mirrored.valid).toBe(false);
    expect(mirrored.checks.version).toBe(false);
  });

  it('(c) a stripped ML-DSA-65 leg refuses via missing_required_algorithm, set left intact', async () => {
    const s = newSigner();
    const att = await build(s);
    att.proof.signatures = att.proof.signatures.filter((sig: { alg: string }) => sig.alg === 'Ed25519');

    const res = await verifyTimeAttestationV2(att, { tsaKeys: pinOf(s) });
    expect(res.valid).toBe(false);
    expect(res.checks.signature_set_valid).toBe(false);
    expect(res.errors.some((e) => e.includes('missing_required_algorithm'))).toBe(true);
  });

  it('(d) narrowing required_algorithms refuses structurally, and breaks the surviving Ed25519 signature over the recomputed bytes', async () => {
    const s = newSigner();
    const att = await build(s);
    const original = JSON.parse(JSON.stringify(att));

    att.proof.required_algorithms = ['Ed25519'];
    // Both original signatures are left in place -- only the declared set is narrowed.
    const res = await verifyTimeAttestationV2(att, { tsaKeys: pinOf(s) });
    expect(res.valid).toBe(false);
    expect(res.checks.algorithm_set).toBe(false);

    // Out-of-band cryptographic proof of WHY narrowing is dangerous: the
    // surviving Ed25519 signature was made over bytes that commit to the
    // FULL registered set, so it does not verify over bytes recomputed with
    // the narrowed set (this is not what the verifier itself computes -- it
    // always uses the REGISTERED set -- this demonstrates the byte-level
    // commitment property directly).
    const narrowedBytes = Buffer.from(canonicalize({
      '@version': TIME_ATTESTATION_V2_VERSION,
      hashed: original.hashed,
      required_algorithms: ['Ed25519'],
      time: original.time,
      ts_authority_id: original.ts_authority_id,
    }), 'utf8');
    const edSig = original.proof.signatures.find((sig: { alg: string }) => sig.alg === 'Ed25519');
    const edKey = crypto.createPublicKey({ key: Buffer.from(s.publicKeyB64u, 'base64url'), format: 'der', type: 'spki' });
    expect(crypto.verify(null, narrowedBytes, edKey, Buffer.from(edSig.sig, 'base64url'))).toBe(false);

    // And the full, untampered recomputed bytes are exactly what
    // timeAttestationV2SignedBytes produces for the registered set.
    const fullBytes = timeAttestationV2SignedBytes(original, TIME_ATTESTATION_V2_REQUIRED_ALGORITHMS);
    expect(crypto.verify(null, fullBytes, edKey, Buffer.from(edSig.sig, 'base64url'))).toBe(true);
  });

  it('(e) a truncated ML-DSA-65 signature refuses via malformed_signature, no throw', async () => {
    const s = newSigner();
    const att = await build(s);
    const pqSig = att.proof.signatures.find((sig: { alg: string }) => sig.alg === 'ML-DSA-65');
    const truncated = Buffer.from(pqSig.sig, 'base64url').subarray(0, 100).toString('base64url');
    att.proof.signatures = att.proof.signatures.map((sig: { alg: string; sig: string }) => (
      sig.alg === 'ML-DSA-65' ? { ...sig, sig: truncated } : sig
    ));

    let res: Awaited<ReturnType<typeof verifyTimeAttestationV2>>;
    let threw = false;
    try {
      res = await verifyTimeAttestationV2(att, { tsaKeys: pinOf(s) });
    } catch {
      threw = true;
      res = { valid: true, checks: {}, errors: [] };
    }
    expect(threw).toBe(false);
    expect(res!.valid).toBe(false);
    expect(res!.checks.signature_set_valid).toBe(false);
    expect(res!.errors.some((e) => e.includes('malformed_signature'))).toBe(true);
  });

  it('(f) an Ed448 SPKI presented and pinned as the Ed25519 half is refused by the curve pin, never accepted', async () => {
    const s = newSigner();
    const att = await build(s);
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448PubB64u = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    att.proof.public_key = ed448PubB64u;

    const res = await verifyTimeAttestationV2(att, {
      tsaKeys: { [TSA]: { public_key: ed448PubB64u, pq_public_key: s.pqPublicKeyRawB64u } },
    });
    expect(res.valid).toBe(false);
    expect(res.checks.signature_set_valid).toBe(false);
  });

  it('(g) pinning a different TSA key pair than the one that actually signed refuses (key substitution)', async () => {
    const s = newSigner();
    const other = newSigner();
    const att = await build(s);

    const res = await verifyTimeAttestationV2(att, { tsaKeys: pinOf(other) });
    expect(res.valid).toBe(false);
    expect(res.checks.tsa_key_pinned).toBe(false);
  });

  it('(h) an out-of-bounds attested time refuses via within_bounds, same semantics as v1', async () => {
    const s = newSigner();
    const att = await build(s);

    const res = await verifyTimeAttestationV2(att, {
      tsaKeys: pinOf(s),
      notBefore: '2026-07-01T00:00:00Z',
      notAfter: '2026-08-01T00:00:00Z',
    });
    expect(res.valid).toBe(false);
    expect(res.checks.within_bounds).toBe(false);
  });

  it('a missing ML-DSA backend is a named refusal, never a pass on the classical leg', async () => {
    const s = newSigner();
    const att = await build(s);

    const res = await verifyTimeAttestationV2(att, {
      tsaKeys: pinOf(s),
      mldsaBackendLoader: async () => null,
    });
    expect(res.valid).toBe(false);
    expect(res.checks.signature_set_valid).toBe(false);
    expect(res.errors.some((e) => e.includes('pq_backend_unavailable'))).toBe(true);
  });

  it('malformed input refuses without throwing', async () => {
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
      // eslint-disable-next-line no-await-in-loop
      const res = await verifyTimeAttestationV2(junk as never, { tsaKeys: {} });
      expect(res.valid).toBe(false);
    }
  });

  it('buildTimeAttestationV2 throws rather than emit a half-hybrid attestation', async () => {
    const s = newSigner();
    await expect(buildTimeAttestationV2({
      ts_authority_id: TSA, hashed: HASH, time: TIME,
      signer: { ...s, pqSecretKey: new Uint8Array(10) },
    })).rejects.toThrow();
    await expect(buildTimeAttestationV2({
      ts_authority_id: '', hashed: HASH, time: TIME, signer: s,
    })).rejects.toThrow();
  });
});
