// SPDX-License-Identifier: Apache-2.0
// Cross-row regression: withdrawing one authorization is not credential
// compromise and does not withdraw a sibling authorization.

import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';
import { createKeyRegistry } from '../packages/gate/key-registry.js';
import { canonicalize } from '../packages/verify/index.js';
import { isRevoked, REVOCATION_VERSION } from '../packages/verify/revocation.js';

const receiptTarget = (id: string, fill: string) => ({
  target_type: 'receipt' as const,
  target_id: id,
  action_hash: `sha256:${fill.repeat(64)}`,
});

function signedWithdrawal(target, signer) {
  const revokerId = 'ep:revoker:authorization-owner';
  const publicKey = signer.publicKey
    .export({ type: 'spki', format: 'der' })
    .toString('base64url');
  const statement = {
    '@version': REVOCATION_VERSION,
    target_type: target.target_type,
    target_id: target.target_id,
    action_hash: target.action_hash,
    revoker_id: revokerId,
    revoked_at: '2026-08-06T12:00:00.000Z',
    reason: 'human approval withdrawn',
  };
  const signature = crypto.sign(
    null,
    Buffer.from(canonicalize(statement), 'utf8'),
    signer.privateKey,
  ).toString('base64url');
  return {
    ...statement,
    proof: {
      algorithm: 'Ed25519',
      revoker_key_id: `ep:revoker-key:sha256:${crypto
        .createHash('sha256')
        .update(Buffer.from(publicKey, 'base64url'))
        .digest('hex')}`,
      signature_b64u: signature,
      public_key: publicKey,
    },
    pin: { [revokerId]: { public_key: publicKey } },
  };
}

describe('authorization withdrawal stays on the authorization row', () => {
  it('withdraws approval A while the credential and approval B remain unaffected', () => {
    const credential = crypto.generateKeyPairSync('ed25519');
    const credentialPublicKey = credential.publicKey
      .export({ type: 'spki', format: 'der' })
      .toString('base64url');
    const credentialRegistry = createKeyRegistry([{
      kid: 'approver-passkey',
      key: credentialPublicKey,
    }]);
    const approvalA = receiptTarget('receipt:A', 'a');
    const approvalB = receiptTarget('receipt:B', 'b');
    const withdrawal = signedWithdrawal(
      approvalA,
      crypto.generateKeyPairSync('ed25519'),
    );
    const { pin, ...statement } = withdrawal;

    expect(isRevoked(approvalA, [statement], { revokerKeys: pin })).toBe(true);
    expect(isRevoked(approvalB, [statement], { revokerKeys: pin })).toBe(false);
    expect(credentialRegistry.keysValidAt('2026-08-06T12:00:01.000Z'))
      .toEqual([credentialPublicKey]);
  });
});
