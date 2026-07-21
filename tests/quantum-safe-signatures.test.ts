// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { signHybrid, verifyHybrid, HYBRID_SIGNATURE_TYPE, HYBRID_LENGTHS } from '../lib/quantum-safe.js';

function ed25519RawPublicKey(keyObject) {
  return keyObject.export({ format: 'der', type: 'spki' }).subarray(-HYBRID_LENGTHS.ed25519PublicKey);
}

function fixture() {
  const ed = crypto.generateKeyPairSync('ed25519');
  const ml = ml_dsa65.keygen(new Uint8Array(32).fill(7));
  const payload = Buffer.from('action-escrow:authorize:fixture', 'utf8');
  const envelope = signHybrid(payload, {
    ed25519PrivateKey: ed.privateKey,
    mlDsaSecretKey: ml.secretKey,
    keyIds: { ed25519: 'ep:ed:fixture', mlDsa65: 'ep:pq:fixture' },
  });
  return { ed, ml, payload, envelope };
}

describe('hybrid Ed25519 + ML-DSA-65 signatures', () => {
  it('signs and verifies the exact same payload with both algorithms', () => {
    const { ed, ml, payload, envelope } = fixture();
    expect(envelope.type).toBe(HYBRID_SIGNATURE_TYPE);
    expect(verifyHybrid(payload, envelope, {
      ed25519: ed25519RawPublicKey(ed.publicKey),
      mlDsa65: ml.publicKey,
    })).toMatchObject({ valid: true, hybrid: true, checks: { ed25519: true, ml_dsa65: true } });
  });

  it('fails closed when the payload changes', () => {
    const { ed, ml, envelope } = fixture();
    expect(verifyHybrid('different action', envelope, {
      ed25519: ed25519RawPublicKey(ed.publicKey),
      mlDsa65: ml.publicKey,
    })).toMatchObject({ valid: false, reason: 'payload hash mismatch' });
  });

  it('requires both signatures and rejects a tampered signature', () => {
    const { ed, ml, payload, envelope } = fixture();
    const missing = structuredClone(envelope);
    delete missing.signatures.ml_dsa65;
    expect(verifyHybrid(payload, missing, { ed25519: ed25519RawPublicKey(ed.publicKey), mlDsa65: ml.publicKey }).valid).toBe(false);

    const tampered = structuredClone(envelope);
    tampered.signatures.ml_dsa65 = `${tampered.signatures.ml_dsa65.slice(0, -1)}${tampered.signatures.ml_dsa65.endsWith('A') ? 'B' : 'A'}`;
    expect(verifyHybrid(payload, tampered, { ed25519: ed25519RawPublicKey(ed.publicKey), mlDsa65: ml.publicKey }).valid).toBe(false);
  });

  it('rejects extra envelope members and binds key identifiers to the signatures', () => {
    const { ed, ml, payload, envelope } = fixture();
    const trusted = { ed25519: ed25519RawPublicKey(ed.publicKey), mlDsa65: ml.publicKey };
    expect(verifyHybrid(payload, { ...envelope, extra: true }, trusted).valid).toBe(false);

    const changedId = structuredClone(envelope);
    changedId.key_ids.ed25519 = 'ep:attacker';
    expect(verifyHybrid(payload, changedId, trusted).valid).toBe(false);
  });

  it('rejects non-Ed25519 signing keys', () => {
    const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const { ml } = fixture();
    expect(() => signHybrid('payload', { ed25519PrivateKey: rsa.privateKey, mlDsaSecretKey: ml.secretKey })).toThrow(/Ed25519/);
  });
});
