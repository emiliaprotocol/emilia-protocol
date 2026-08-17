// SPDX-License-Identifier: Apache-2.0

/**
 * EP-HYBRID-v1 hybrid envelope, exercised from the app tier.
 *
 * WHY THIS FILE EXISTS AT ALL, given packages/verify ships its own suite for
 * the same module: this repository used to carry TWO implementations of the
 * hybrid Ed25519 + ML-DSA-65 envelope. `lib/quantum-safe.ts` (tag
 * EP-HYBRID-SIGNATURE-v1) was a near-copy of packages/verify/src/pq-hybrid.ts
 * (tag EP-HYBRID-v1), reachable only from this test. The duplicate was removed
 * and this suite repointed at the canonical module, so the app tier keeps a
 * regression on the ONE implementation instead of pinning a second one.
 *
 * The last three cases are the ones the duplicate never had: the classical-leg
 * curve pin and the exact signature-length pins that landed on the canonical
 * module in the adversarial-review pass (commit 57788d12) and, by construction,
 * never reached a copy that no security pass knew existed.
 */

import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  signHybrid,
  verifyHybrid,
  HYBRID_ALG,
  HYBRID_SIGNATURE_ALGOS,
  HYBRID_REASONS,
  ED25519_SIGNATURE_BYTES,
} from '../packages/verify/pq-hybrid.js';

const PAYLOAD = 'action-escrow:authorize:fixture';

async function fixture() {
  const ed = crypto.generateKeyPairSync('ed25519');
  const ml = ml_dsa65.keygen(new Uint8Array(32).fill(7));
  const envelope = await signHybrid(PAYLOAD, {
    ed25519PrivateKey: ed.privateKey,
    mldsaSecretKey: ml.secretKey,
  });
  const keys = {
    ed25519PublicKey: ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
    mldsaPublicKey: ml.publicKey,
  };
  return { ed, ml, envelope, keys };
}

describe('EP-HYBRID-v1 envelope (canonical packages/verify implementation)', () => {
  it('signs and verifies the exact same payload with both algorithms', async () => {
    const { envelope, keys } = await fixture();
    expect(envelope.alg).toBe(HYBRID_ALG);
    expect(envelope.signature_algos).toEqual([...HYBRID_SIGNATURE_ALGOS]);
    expect(await verifyHybrid(PAYLOAD, envelope, keys)).toMatchObject({
      verified: true,
      reason: null,
      checks: { classical_signature: true, pq_signature: true },
    });
  });

  it('fails closed when the message changes', async () => {
    const { envelope, keys } = await fixture();
    const result = await verifyHybrid('different action', envelope, keys);
    expect(result.verified).toBe(false);
    expect(result.reason).toBe(HYBRID_REASONS.CLASSICAL_INVALID);
  });

  it('requires both legs: a stripped ML-DSA signature refuses', async () => {
    const { envelope, keys } = await fixture();
    const stripped = structuredClone(envelope);
    delete stripped.sigs['ML-DSA-65'];
    const result = await verifyHybrid(PAYLOAD, stripped, keys);
    expect(result.verified).toBe(false);
    expect(result.reason).toBe(HYBRID_REASONS.MISSING_SIGNATURE);
  });

  it('rejects a tampered ML-DSA signature', async () => {
    const { envelope, keys } = await fixture();
    const tampered = structuredClone(envelope);
    const sig = tampered.sigs['ML-DSA-65'];
    tampered.sigs['ML-DSA-65'] = `${sig.slice(0, -1)}${sig.endsWith('A') ? 'B' : 'A'}`;
    const result = await verifyHybrid(PAYLOAD, tampered, keys);
    expect(result.verified).toBe(false);
    expect(result.reason).toBe(HYBRID_REASONS.PQ_INVALID);
  });

  it('rejects a narrowed algorithm set (the stripping cover story)', async () => {
    const { envelope, keys } = await fixture();
    const narrowed = structuredClone(envelope);
    narrowed.signature_algos = ['Ed25519'];
    delete narrowed.sigs['ML-DSA-65'];
    const result = await verifyHybrid(PAYLOAD, narrowed, keys);
    expect(result.verified).toBe(false);
    expect(result.reason).toBe(HYBRID_REASONS.ALGO_SET_MISMATCH);
  });

  it('rejects an extra signature entry beyond the committed set', async () => {
    const { envelope, keys } = await fixture();
    const extra = structuredClone(envelope);
    extra.sigs.extra = envelope.sigs['Ed25519'];
    const result = await verifyHybrid(PAYLOAD, extra, keys);
    expect(result.verified).toBe(false);
    expect(result.reason).toBe(HYBRID_REASONS.INVALID_ENVELOPE);
  });

  it('refuses rather than skipping the PQ leg when no backend is available', async () => {
    const { envelope, keys } = await fixture();
    const result = await verifyHybrid(PAYLOAD, envelope, keys, { mldsaBackendLoader: () => null });
    expect(result.verified).toBe(false);
    expect(result.reason).toBe(HYBRID_REASONS.PQ_BACKEND_UNAVAILABLE);
  });

  // --- the hardening the removed duplicate was never given ------------------

  it('curve-pins the classical verification key: an Ed448 key refuses', async () => {
    const { envelope, ml } = await fixture();
    const ed448 = crypto.generateKeyPairSync('ed448');
    const result = await verifyHybrid(PAYLOAD, envelope, {
      ed25519PublicKey: ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
      mldsaPublicKey: ml.publicKey,
    });
    expect(result.verified).toBe(false);
    expect(result.reason).toBe(HYBRID_REASONS.ALGORITHM_KEY_MISMATCH);
  });

  it('length-pins the classical signature: a 114-byte Ed448 signature refuses', async () => {
    const { envelope, keys } = await fixture();
    const ed448 = crypto.generateKeyPairSync('ed448');
    const relabeled = structuredClone(envelope);
    relabeled.sigs['Ed25519'] = crypto
      .sign(null, Buffer.from(PAYLOAD, 'utf8'), ed448.privateKey)
      .toString('base64url');
    expect(Buffer.from(relabeled.sigs['Ed25519'], 'base64url').length).not.toBe(ED25519_SIGNATURE_BYTES);
    const result = await verifyHybrid(PAYLOAD, relabeled, keys);
    expect(result.verified).toBe(false);
    expect(result.reason).toBe(HYBRID_REASONS.SIGNATURE_LENGTH_INVALID);
  });

  it('curve-pins the classical signing key: signHybrid refuses a non-Ed25519 private key', async () => {
    const ml = ml_dsa65.keygen(new Uint8Array(32).fill(9));
    const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    await expect(
      signHybrid(PAYLOAD, { ed25519PrivateKey: rsa.privateKey, mldsaSecretKey: ml.secretKey }),
    ).rejects.toThrow(/algorithm_key_mismatch/);
  });
});
