// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, afterEach } from 'vitest';
import { toAccount } from 'viem/accounts';
import {
  clearBlockchainSigner,
  createEnvBlockchainSigner,
  createExternalBlockchainSigner,
  registerBlockchainSigner,
  resolveBlockchainSigner,
} from '../lib/blockchain-signing.js';

afterEach(() => clearBlockchainSigner());

describe('blockchain signing-provider boundary', () => {
  it('keeps the env key inside the env provider adapter', () => {
    const calls = [];
    const provider = createEnvBlockchainSigner({ privateKey: 'aa'.repeat(32) });
    const account = provider.createAccount({
      privateKeyToAccount: (key) => {
        calls.push(key);
        return { address: '0x1111111111111111111111111111111111111111' };
      },
    });

    expect(account.address).toBe('0x1111111111111111111111111111111111111111');
    expect(calls).toEqual([`0x${'aa'.repeat(32)}`]);
    expect(provider.getAlgorithm()).toBe('secp256k1/eth-transaction');
    expect(provider.getMetadata().provider).toBe('env');
  });

  it('rejects malformed env keys before the viem account factory', () => {
    expect(() => createEnvBlockchainSigner({ privateKey: 'not-a-key' })).toThrow(/32-byte hexadecimal/);
  });

  it('fails closed when external custody is selected without registration', () => {
    expect(() => resolveBlockchainSigner({ signingMode: 'hsm', signingKeyId: 'pkcs11:base-anchor' }))
      .toThrow(/no matching blockchain signer is registered/);
  });

  it('requires an auditable key id for external custody', () => {
    expect(() => resolveBlockchainSigner({ signingMode: 'kms' }))
      .toThrow(/EP_BLOCKCHAIN_SIGNING_KEY_ID/);
  });

  it('registers an external signer without accepting private-key material', async () => {
    const calls = [];
    const provider = createExternalBlockchainSigner({
      mode: 'hsm',
      keyId: 'pkcs11:base-anchor',
      address: '0x1111111111111111111111111111111111111111',
      signTransaction: async (transaction) => {
        calls.push(transaction);
        return '0xsigned';
      },
    });
    registerBlockchainSigner(provider);
    const resolved = resolveBlockchainSigner({ signingMode: 'hsm', signingKeyId: 'pkcs11:base-anchor' });
    const account = resolved.createAccount({ toAccount });
    expect(await account.signTransaction({ to: '0x2222222222222222222222222222222222222222' })).toBe('0xsigned');
    expect(calls).toHaveLength(1);
    expect(resolved.getMetadata()).toMatchObject({ provider: 'hsm', keyId: 'pkcs11:base-anchor' });
  });

  it('rejects an external key-id mismatch rather than silently choosing another key', () => {
    registerBlockchainSigner(createExternalBlockchainSigner({
      mode: 'kms',
      keyId: 'kms:base-anchor-v1',
      address: '0x1111111111111111111111111111111111111111',
      signTransaction: async () => '0xsigned',
    }));
    expect(() => resolveBlockchainSigner({ signingMode: 'kms', signingKeyId: 'kms:base-anchor-v2' }))
      .toThrow(/key id does not match/);
  });
});
