// SPDX-License-Identifier: Apache-2.0
// The issuer-side KMS/HSM custody seam: resolveIssuerSigner + a registered
// custody signer that produces commit.js-compatible signatures. No DB.
import { describe, it, expect, afterEach } from 'vitest';
import crypto from 'node:crypto';
import {
  resolveIssuerSigner, registerCustodySigner, clearCustodySigner, getRegisteredCustodySigner,
  createExternalCustodySigner,
} from '../lib/key-custody.js';

const ED25519_SPKI_DER_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

afterEach(() => clearCustodySigner());

describe('resolveIssuerSigner', () => {
  it('returns null for local-dev (use the built-in env key path)', () => {
    expect(resolveIssuerSigner({ mode: 'local-dev' })).toBe(null);
  });

  it('returns null for local-dev even under gov-strict (KMS is opt-in; env-key path is enforced by the issuer / gov:check, not here)', () => {
    expect(resolveIssuerSigner({ mode: 'local-dev', govStrict: true })).toBe(null);
  });

  it('throws when kms mode is configured but no signer is registered (fail closed)', () => {
    expect(() => resolveIssuerSigner({ mode: 'kms', keyId: 'arn:kms:key/1' }))
      .toThrow(/no custody signer is registered/);
  });

  it('throws when gov-strict kms mode has no key id', () => {
    expect(() => resolveIssuerSigner({ mode: 'kms', govStrict: true })).toThrow(/EP_KMS_KEY_ID|key id/i);
  });

  it('returns the registered custody signer for kms mode', () => {
    const signer = registerCustodySigner({ keyId: 'arn:kms:key/1', sign: async () => 'x' });
    expect(resolveIssuerSigner({ mode: 'kms', keyId: 'arn:kms:key/1' })).toBe(signer);
    expect(getRegisteredCustodySigner()).toBe(signer);
  });
});

describe('registerCustodySigner validation', () => {
  it('rejects a signer without keyId or sign', () => {
    expect(() => registerCustodySigner({})).toThrow(/keyId/);
    expect(() => registerCustodySigner({ keyId: 'k' })).toThrow(/sign/);
  });
});

describe('a KMS-style custody signer produces commit-compatible signatures', () => {
  it('signs canonical bytes that verify under the bridged raw public key', async () => {
    // Stand-in for a KMS: a local Ed25519 key whose sign() is injected. In prod
    // this callback would call AWS KMS / GCP KMS / a PKCS#11 HSM.
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const spkiB64u = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');

    const signer = createExternalCustodySigner({
      mode: 'kms',
      keyId: 'arn:kms:key/abc',
      sign: async (bytes) => crypto.sign(null, Buffer.from(bytes), privateKey).toString('base64url'),
      getPublicKey: () => spkiB64u,
    });
    registerCustodySigner(signer);
    const resolved = resolveIssuerSigner({ mode: 'kms', keyId: 'arn:kms:key/abc' });
    expect(resolved.keyId).toBe('arn:kms:key/abc');

    // Reproduce the exact format bridging lib/commit.js does, then verify the
    // signature the way verifyCommit() does (raw 32-byte key → SPKI → verify).
    const payload = '{"commit_id":"cmt_demo","action":"x"}';
    const sigB64u = await resolved.sign(Buffer.from(payload, 'utf8'));
    const signatureBase64 = Buffer.from(sigB64u, 'base64url').toString('base64');

    const rawPub = Buffer.from(await resolved.publicKeySpkiB64u(), 'base64url');
    const pub32 = rawPub.length === 32 ? rawPub : rawPub.subarray(rawPub.length - 32);
    const publicKeyBase64 = pub32.toString('base64');

    // verifyCommit-equivalent check
    const spkiDer = Buffer.concat([ED25519_SPKI_DER_PREFIX, Buffer.from(publicKeyBase64, 'base64')]);
    const keyObject = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
    const ok = crypto.verify(null, Buffer.from(payload, 'utf8'), keyObject, Buffer.from(signatureBase64, 'base64'));
    expect(ok).toBe(true);

    // A tampered payload must NOT verify.
    const bad = crypto.verify(null, Buffer.from(payload + 'x', 'utf8'), keyObject, Buffer.from(signatureBase64, 'base64'));
    expect(bad).toBe(false);
  });
});
