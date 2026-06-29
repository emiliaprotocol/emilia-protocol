// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, afterEach } from 'vitest';
import crypto from 'node:crypto';
import { externalSigner, vaultTransitSigner, hsmEd25519Signer } from '../lib/custody-signers.js';
import { registerCustodySigner, resolveIssuerSigner, clearCustodySigner } from '../lib/key-custody.js';

afterEach(() => clearCustodySigner());

function keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, spkiB64u: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
async function verifies(signer, message) {
  const sigB64u = await signer.sign(Buffer.from(message));
  const spki = Buffer.from(await signer.publicKeySpkiB64u(), 'base64url');
  const pub = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
  return crypto.verify(null, Buffer.from(message), pub, Buffer.from(sigB64u, 'base64url'));
}

describe('vaultTransitSigner', () => {
  it('produces a signer whose Vault-Transit signature verifies', async () => {
    const { privateKey, spkiB64u } = keypair();
    const vault = { sign: async (_key, b64) => `vault:v1:${crypto.sign(null, Buffer.from(b64, 'base64'), privateKey).toString('base64')}` };
    const signer = vaultTransitSigner({ vault, keyName: 'ep-issuer', publicKeySpkiB64u: spkiB64u });
    expect(signer.keyId).toBe('vault-transit:ep-issuer');
    expect(await verifies(signer, 'authorize-payment')).toBe(true);
  });

  it('rejects a bad vault client', () => {
    expect(() => vaultTransitSigner({ vault: {}, keyName: 'k' })).toThrow(/vault/i);
    expect(() => vaultTransitSigner({ vault: { sign() {} } })).toThrow(/keyName/);
  });
});

describe('hsmEd25519Signer', () => {
  it('produces a signer whose HSM signature verifies', async () => {
    const { privateKey, spkiB64u } = keypair();
    const hsm = { signEd25519: async (_label, data) => crypto.sign(null, data, privateKey) };
    const signer = hsmEd25519Signer({ hsm, keyLabel: 'ep-key-1', publicKeySpkiB64u: spkiB64u });
    expect(signer.keyId).toBe('pkcs11:ep-key-1');
    expect(await verifies(signer, 'delete-prod')).toBe(true);
  });

  it('rejects a bad hsm client', () => {
    expect(() => hsmEd25519Signer({ hsm: {}, keyLabel: 'k' })).toThrow(/hsm/i);
  });
});

describe('externalSigner + registration round-trip', () => {
  it('registers and resolves through the issuer custody seam', async () => {
    const { privateKey, spkiB64u } = keypair();
    const signer = externalSigner({ mode: 'kms', keyId: 'enclave:1', publicKeySpkiB64u: spkiB64u, sign: async (b) => crypto.sign(null, b, privateKey) });
    registerCustodySigner(signer);
    const resolved = resolveIssuerSigner({ mode: 'kms', keyId: 'enclave:1' });
    expect(resolved).toBe(signer);
    expect(await verifies(resolved, 'x')).toBe(true);
  });

  it('throws without a sign callback', () => {
    expect(() => externalSigner({ keyId: 'k' })).toThrow(/sign/);
  });
});
