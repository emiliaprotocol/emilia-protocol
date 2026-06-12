/**
 * Trust Receipt issuer → published verifier round-trip.
 *
 * The other half of I-D §6.3: a receipt the issuer emits must pass all seven
 * steps of @emilia-protocol/verify's verifyTrustReceipt. Issues a dual-approval
 * (Class A + Class B) receipt with a real Merkle log + log-signed checkpoint and
 * confirms the published verifier accepts it — and rejects an issued receipt
 * whose action is tampered after issuance.
 */

import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { issueTrustReceipt, assembleTrustReceipt, buildContexts, collectSignoffs } from '../lib/trust-receipt/issuer.js';
import { verifyTrustReceipt } from '../packages/verify/index.js';

const RP_ID = 'www.emiliaprotocol.ai';
const ORIGIN = 'https://www.emiliaprotocol.ai';

// Class B software signer (Ed25519 over the raw context digest).
function classBSigner(approverKeyId, signedAt) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    keyEntry: { public_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'), key_class: 'B', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
    signer: { approverKeyId, keyClass: 'B', signedAt, sign: (digest) => crypto.sign(null, digest, privateKey).toString('base64url') },
  };
}

// Class A WebAuthn signer (challenge = b64u(context digest)).
function classASigner(approverKeyId, signedAt) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    keyEntry: { public_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'), key_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
    signer: {
      approverKeyId, keyClass: 'A', signedAt,
      signWebAuthn: (digest) => {
        const challenge = digest.toString('base64url');
        const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: ORIGIN }), 'utf8');
        const authData = Buffer.concat([crypto.createHash('sha256').update(RP_ID).digest(), Buffer.from([0x05]), Buffer.from([0, 0, 0, 0])]);
        const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataJSON).digest()]);
        return {
          authenticator_data: authData.toString('base64url'),
          client_data_json: clientDataJSON.toString('base64url'),
          signature: crypto.sign('sha256', signedData, privateKey).toString('base64url'),
        };
      },
    },
  };
}

const log = (() => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'), logKeyId: 'ep:log:test#1' };
})();

const action = {
  ep_version: '1.0',
  action_type: 'wire.release',
  target: { system: 'treasury.example', resource: 'wire/8841' },
  parameters: { amount: '2400000.00', currency: 'USD' },
  initiator: 'ep:entity:agent-recon-7',
  policy_id: 'ep:policy:wires-over-100k@v12',
  requested_at: '2026-06-09T17:21:04Z',
};

async function issueDual() {
  const a = classASigner('ep:key:cfo#1', '2026-06-09T17:24:40Z');
  const b = classBSigner('ep:key:controller#1', '2026-06-09T17:24:55Z');
  const receipt = await issueTrustReceipt({
    receiptId: 'ep:receipt:01JISSUE',
    action,
    policyHash: 'sha256:77ab1234',
    approvers: ['ep:approver:mrios-cfo', 'ep:approver:jchen-controller'],
    issuedAt: '2026-06-09T17:21:05Z',
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    committedAt: new Date().toISOString(),
    signers: [a.signer, b.signer],
    log,
  });
  const approverKeys = { 'ep:key:cfo#1': a.keyEntry, 'ep:key:controller#1': b.keyEntry };
  return { receipt, approverKeys };
}

describe('Trust Receipt issuer', () => {
  it('issues a dual-approval receipt that passes all seven §6.3 steps', async () => {
    const { receipt, approverKeys } = await issueDual();
    const r = verifyTrustReceipt(receipt, { approverKeys, logPublicKey: log.pub });
    expect(r.valid).toBe(true);
    expect(r.errors).toEqual([]);
    expect(Object.values(r.checks).every(Boolean)).toBe(true);
  });

  it('a receipt anchored in a log with prior leaves still verifies (real inclusion proof)', async () => {
    const a = classBSigner('ep:key:k1', '2026-06-09T17:24:40Z');
    const contexts = buildContexts({ action, policyHash: 'sha256:aa', approvers: ['ep:approver:solo'], requiredApprovals: 1, issuedAt: '2026-06-09T17:21:05Z', expiresAt: new Date(Date.now() + 3600_000).toISOString() });
    const signoffs = await collectSignoffs(contexts, [a.signer]);
    const priorLeaves = Array.from({ length: 6 }, (_, i) => crypto.createHash('sha256').update(`leaf-${i}`).digest('hex'));
    const receipt = assembleTrustReceipt({
      receiptId: 'ep:receipt:withlog', action, contexts, signoffs,
      committedAt: new Date().toISOString(), log: { ...log, priorLeaves },
    });
    const r = verifyTrustReceipt(receipt, { approverKeys: { 'ep:key:k1': a.keyEntry }, logPublicKey: log.pub });
    expect(r.valid).toBe(true);
    expect(receipt.log_proof.checkpoint.tree_size).toBe(7);
    expect(receipt.log_proof.inclusion_path.length).toBeGreaterThan(0);
  });

  it('a receipt tampered after issuance fails verification', async () => {
    const { receipt, approverKeys } = await issueDual();
    receipt.action.parameters.amount = '24000000.00'; // 10x after the log-signed checkpoint
    const r = verifyTrustReceipt(receipt, { approverKeys, logPublicKey: log.pub });
    expect(r.valid).toBe(false);
    // The action-hash and the inclusion proof both break.
    expect(r.checks.action_hash).toBe(false);
  });

  it('a single-approver receipt verifies (required_approvals respected)', async () => {
    const a = classASigner('ep:key:solo#1', '2026-06-09T17:24:40Z');
    const receipt = await issueTrustReceipt({
      receiptId: 'ep:receipt:solo', action, policyHash: 'sha256:bb',
      approvers: ['ep:approver:solo'], requiredApprovals: 1,
      issuedAt: '2026-06-09T17:21:05Z', expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      committedAt: new Date().toISOString(), signers: [a.signer], log,
    });
    const r = verifyTrustReceipt(receipt, { approverKeys: { 'ep:key:solo#1': a.keyEntry }, logPublicKey: log.pub });
    expect(r.valid).toBe(true);
  });
});
