// SPDX-License-Identifier: Apache-2.0
//
// The DUAL-SIGNER custody seam (EP-CUSTODY-HYBRID-v1). Two properties matter
// here and both are asserted directly:
//
//   ADDITIVITY   -- a HybridCustodySigner IS a CustodySigner. Every existing
//                   member behaves identically to the wrapped Ed25519 signer,
//                   registerCustodySigner/resolveIssuerSigner take it
//                   unchanged, and an unaware call site gets byte-identical
//                   Ed25519 signatures.
//   HONEST NOTES -- the PQ leg is software-held and says so, and it never
//                   silently degrades when no ML-DSA backend is available.
//
// Real ML-DSA-65 runs here (@noble/post-quantum, root devDependency).
import { describe, it, expect, afterEach } from 'vitest';
import crypto from 'node:crypto';

import {
  HYBRID_CUSTODY_PROFILE,
  HYBRID_CUSTODY_ALGORITHMS,
  ML_DSA_65_SIGNATURE_BYTES,
  createLocalDevSigner,
  createExternalCustodySigner,
  createPqCustodySigner,
  createHybridCustodySigner,
  isHybridCustodySigner,
  resolveHybridPublicKeys,
  registerCustodySigner,
  clearCustodySigner,
  resolveIssuerSigner,
} from '../lib/key-custody.js';
import { softwareMldsaSigner, hybridSigner } from '../lib/custody-signers.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

afterEach(() => clearCustodySigner());

const MESSAGE = Buffer.from('EP-CUSTODY-HYBRID-v1 test message', 'utf8');

function makeClassical() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spkiB64u = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const signer = createExternalCustodySigner({
    mode: 'hsm',
    keyId: 'pkcs11:ep-issuer#1',
    sign: async (bytes) => crypto.sign(null, Buffer.from(bytes), privateKey).toString('base64url'),
    getPublicKey: () => spkiB64u,
  });
  return { signer, publicKey, privateKey, spkiB64u };
}

function makePq(keyId = 'ep:key:pq#1') {
  const pair = ml_dsa65.keygen(crypto.randomBytes(32));
  return {
    pair,
    signer: softwareMldsaSigner({
      keyId,
      secretKey: pair.secretKey,
      publicKeyRawB64u: pair.publicKey,
    }),
  };
}

describe('softwareMldsaSigner (the PQ leg)', () => {
  it('labels its custody honestly: software, never kms/hsm', () => {
    const { signer } = makePq();
    expect(signer.custody).toBe('software');
    expect(signer.algorithm).toBe('ML-DSA-65');
  });

  it('produces a real ML-DSA-65 signature of the FIPS 204 fixed length', async () => {
    const { pair, signer } = makePq();
    const sigB64u = await signer.sign(MESSAGE);
    const sig = Buffer.from(sigB64u, 'base64url');
    expect(sig.length).toBe(ML_DSA_65_SIGNATURE_BYTES);
    expect(ml_dsa65.verify(new Uint8Array(sig), new Uint8Array(MESSAGE), pair.publicKey)).toBe(true);
  });

  it('refuses a secret key of the wrong size', () => {
    expect(() => softwareMldsaSigner({ keyId: 'k', secretKey: new Uint8Array(32) }))
      .toThrow(/4032/);
  });

  it('an unavailable ML-DSA backend is a THROW at signing, never a skipped leg', async () => {
    const { pair } = makePq();
    const signer = softwareMldsaSigner({
      keyId: 'ep:key:pq#nobackend',
      secretKey: pair.secretKey,
      publicKeyRawB64u: pair.publicKey,
      mldsaBackend: {}, // present but has no sign()
    });
    await expect(signer.sign(MESSAGE)).rejects.toThrow(/pq_backend_unavailable/);
  });

  it('rejects a backend whose signature is not ML-DSA-65 sized', async () => {
    const { pair } = makePq();
    const signer = softwareMldsaSigner({
      keyId: 'ep:key:pq#short',
      secretKey: pair.secretKey,
      publicKeyRawB64u: pair.publicKey,
      mldsaBackend: { sign: () => new Uint8Array(64) },
    });
    await expect(signer.sign(MESSAGE)).rejects.toThrow(new RegExp(String(ML_DSA_65_SIGNATURE_BYTES)));
  });
});

describe('createHybridCustodySigner (additivity)', () => {
  it('is recognisable as hybrid, and a plain signer is not', () => {
    const { signer: classical } = makeClassical();
    const { signer: pq } = makePq();
    const hybrid = createHybridCustodySigner({ classical, pq });
    expect(isHybridCustodySigner(hybrid)).toBe(true);
    expect(hybrid.hybrid.profile).toBe(HYBRID_CUSTODY_PROFILE);
    expect(isHybridCustodySigner(classical)).toBe(false);
    expect(isHybridCustodySigner(createLocalDevSigner({ seedB64: Buffer.alloc(32, 7).toString('base64') }))).toBe(false);
    expect(isHybridCustodySigner(null)).toBe(false);
  });

  it('sign() is BYTE-IDENTICAL to the wrapped classical signer', async () => {
    const { signer: classical } = makeClassical();
    const { signer: pq } = makePq();
    const hybrid = createHybridCustodySigner({ classical, pq });
    expect(await hybrid.sign(MESSAGE)).toBe(await classical.sign(MESSAGE));
  });

  it('carries the wrapped signer keyId, custody, and public key through unchanged', async () => {
    const { signer: classical, spkiB64u } = makeClassical();
    const { signer: pq } = makePq();
    const hybrid = createHybridCustodySigner({ classical, pq });
    expect(hybrid.keyId).toBe(classical.keyId);
    expect(hybrid.custody).toBe('hsm');
    expect(typeof hybrid.publicKeySpkiB64u).toBe('function');
    expect(await (hybrid.publicKeySpkiB64u as () => Promise<string>)()).toBe(spkiB64u);
  });

  it('registers and resolves through the EXISTING seam with no changes', () => {
    const { signer: classical } = makeClassical();
    const { signer: pq } = makePq();
    const hybrid = hybridSigner({ classical, pq });
    registerCustodySigner(hybrid);
    const resolved = resolveIssuerSigner({ mode: 'hsm', keyId: 'pkcs11:ep-issuer#1' });
    expect(resolved).toBe(hybrid);
    // An unaware call site sees exactly the interface it always saw.
    expect(typeof resolved!.sign).toBe('function');
    expect(resolved!.keyId).toBe('pkcs11:ep-issuer#1');
  });

  it('refuses two legs sharing one keyId (an unattributable signature set)', () => {
    const { signer: classical } = makeClassical();
    const { signer: pq } = makePq('pkcs11:ep-issuer#1');
    expect(() => createHybridCustodySigner({ classical, pq })).toThrow(/distinct keyIds/);
  });

  it('refuses a PQ leg that is not a PqCustodySigner', () => {
    const { signer: classical } = makeClassical();
    expect(() => createHybridCustodySigner({ classical, pq: { keyId: 'x', sign: async () => 'y' } as any }))
      .toThrow(/createPqCustodySigner/);
  });
});

describe('signSet', () => {
  it('signs the SAME bytes under both algorithms, in the registered order', async () => {
    const { signer: classical, publicKey } = makeClassical();
    const { pair, signer: pq } = makePq();
    const hybrid = createHybridCustodySigner({ classical, pq });

    const set = await hybrid.signSet(MESSAGE);
    expect(set.map((s) => s.alg)).toEqual([...HYBRID_CUSTODY_ALGORITHMS]);
    expect(set.map((s) => s.key_id)).toEqual([classical.keyId, pq.keyId]);

    // Both legs verify over the identical message bytes.
    expect(crypto.verify(null, MESSAGE, publicKey, Buffer.from(set[0].sig, 'base64url'))).toBe(true);
    expect(ml_dsa65.verify(
      new Uint8Array(Buffer.from(set[1].sig, 'base64url')),
      new Uint8Array(MESSAGE),
      pair.publicKey,
    )).toBe(true);
  });

  it('fails closed as a whole when the PQ leg cannot sign', async () => {
    const { signer: classical } = makeClassical();
    const { pair } = makePq();
    const pq = softwareMldsaSigner({
      keyId: 'ep:key:pq#dead',
      secretKey: pair.secretKey,
      publicKeyRawB64u: pair.publicKey,
      mldsaBackend: {},
    });
    const hybrid = createHybridCustodySigner({ classical, pq });
    await expect(hybrid.signSet(MESSAGE)).rejects.toThrow(/pq_backend_unavailable/);
  });
});

describe('createPqCustodySigner', () => {
  it('requires a keyId, a sign callback, and a custody label', () => {
    expect(() => createPqCustodySigner({ keyId: '', sign: async () => '' } as any)).toThrow(/keyId/);
    expect(() => createPqCustodySigner({ keyId: 'k' } as any)).toThrow(/sign/);
    expect(() => createPqCustodySigner({ keyId: 'k', sign: async () => '', custody: '' } as any)).toThrow(/custody/);
  });

  it('refuses a non-base64url signature from the backend', async () => {
    const signer = createPqCustodySigner({ keyId: 'k', sign: async () => 'not base64url!!' });
    await expect(signer.sign(MESSAGE)).rejects.toThrow(/base64url/);
  });
});

describe('resolveHybridPublicKeys', () => {
  it('returns both public halves in the encodings the agility module verifies under', async () => {
    const { signer: classical, spkiB64u } = makeClassical();
    const { pair, signer: pq } = makePq();
    const hybrid = createHybridCustodySigner({ classical, pq });
    const keys = await resolveHybridPublicKeys(hybrid);
    expect(keys.ed25519KeyId).toBe(classical.keyId);
    expect(keys.ed25519PublicKeySpkiB64u).toBe(spkiB64u);
    expect(keys.mldsaKeyId).toBe(pq.keyId);
    expect(keys.mldsaPublicKeyRawB64u).toBe(Buffer.from(pair.publicKey).toString('base64url'));
  });

  it('returns nulls rather than throwing when a leg publishes no public key', async () => {
    const classical = createExternalCustodySigner({
      mode: 'hsm', keyId: 'pkcs11:nokey', sign: async () => 'AA',
    });
    const pq = createPqCustodySigner({ keyId: 'pq:nokey', sign: async () => 'AA' });
    const keys = await resolveHybridPublicKeys(createHybridCustodySigner({ classical, pq }));
    expect(keys.ed25519PublicKeySpkiB64u).toBe(null);
    expect(keys.mldsaPublicKeyRawB64u).toBe(null);
  });
});
