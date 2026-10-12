// SPDX-License-Identifier: Apache-2.0
// SYNTHETIC LOCAL FIXTURE ONLY. Keys and WebAuthn assertions are generated in
// software. Real cryptography does not turn this into a real device ceremony,
// user approval, independent interoperability result, or production issuer.
import crypto from 'node:crypto';
import { buildContexts, collectSignoffs, assembleTrustReceipt } from '../../packages/issue/index.js';
import { actionDigest } from '../../packages/verify/dist/evidence-chain.js';
import { buildPoppyAction, createPoppyApprovalVerifier } from './evidence.mjs';

export const SYNTHETIC_POPPY_VERIFY_AT = '2026-10-12T18:00:30Z';
export const SYNTHETIC_POPPY_COMPANY = 'https://shop.example';
export const SYNTHETIC_POPPY_POLICY_HASH = `sha256:${'a'.repeat(64)}`;

export function syntheticPoppyOperation(): any {
  return { operation_id: 'op-refund-1', revision: 1, state: 'proposed',
    summary: 'Refund $50.00 USD to the original card for order 100.',
    terms: { order_id: '100', amount: '50.00', currency: 'USD', destination: 'original-card' },
    expires_at: '2026-10-12T18:05:00Z', user_approval_required: true,
    confirmation: null, result: null };
}

export function syntheticPoppyOwner(): any {
  return { clientId: 'https://agent.example/client.json', userId: 'user-123',
    sessionId: 'session-1', accountId: 'account-1' };
}

/** Fresh synthetic keys for each fixture. Never use this to mint real approval. */
export async function createSyntheticPoppyApprovalFixture({
  operation = syntheticPoppyOperation(), owner = syntheticPoppyOwner(),
  companyIssuer = SYNTHETIC_POPPY_COMPANY, actionIssuer = companyIssuer,
  at = SYNTHETIC_POPPY_VERIFY_AT, decision = 'approved', flags = 0x05, keyClass = 'A',
  issuedAt = '2026-10-12T18:00:05Z', signedAt = '2026-10-12T18:00:15Z',
  committedAt = '2026-10-12T18:00:22Z', expiresAt = '2026-10-12T18:05:00Z',
}: any = {}): Promise<any> {
  const rpId = new URL(companyIssuer).hostname;
  const approvalOrigin = new URL(companyIssuer).origin;
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const logKeys = crypto.generateKeyPairSync('ed25519');
  const action = buildPoppyAction(operation, owner, actionIssuer);
  const contexts = buildContexts({ action, policyHash: SYNTHETIC_POPPY_POLICY_HASH,
    approvers: ['approver:123'], requiredApprovals: 1, issuedAt, expiresAt });
  if (decision !== undefined) (contexts[0] as any).decision = decision;
  const signoffs = await collectSignoffs(contexts, [{ approverKeyId: 'key:123', keyClass: 'A', signedAt,
    signWebAuthn(digest: Buffer) {
      const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get',
        challenge: digest.toString('base64url'), origin: approvalOrigin }));
      const authData = Buffer.concat([crypto.createHash('sha256').update(rpId).digest(),
        Buffer.from([flags, 0, 0, 0, 1])]);
      return { authenticator_data: authData.toString('base64url'),
        client_data_json: clientData.toString('base64url'),
        signature: crypto.sign('sha256', Buffer.concat([authData,
          crypto.createHash('sha256').update(clientData).digest()]), privateKey).toString('base64url') };
    } }]);
  const receipt = assembleTrustReceipt({ receiptId: 'receipt:poppy-test', action, contexts,
    signoffs, committedAt, log: { privateKey: logKeys.privateKey, logKeyId: 'log:shop' } });
  const epReceiptProfile = {
    approver_keys: { 'key:123': { approver_id: 'approver:123',
      public_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      key_class: keyClass, status: 'active', valid_from: '2026-01-01T00:00:00Z',
      valid_to: '2027-01-01T00:00:00Z', revoked_at: null } },
    log_public_key: logKeys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    rp_id: rpId, allowed_origins: [approvalOrigin], expected_policy_hash: SYNTHETIC_POPPY_POLICY_HASH,
    max_age_sec: 120, registry_checked_at: '2026-10-12T18:00:00Z', max_registry_age_sec: 120,
  };
  const evidence = { '@version': 'EP-AEC-v1', action,
    action_digest: `sha256:${actionDigest(action)}`, requirement: 'ep-receipt',
    components: [{ type: 'ep-receipt', evidence: receipt }] };
  const config = { companyIssuer, ownerScope: structuredClone(owner), epReceiptProfile, now: () => Date.parse(at) };
  const request = { operation, owner, evidence, approved_by: 'user' };
  return { evidence, epReceiptProfile, operation, owner, receipt, config, request,
    profile: epReceiptProfile, verifier: createPoppyApprovalVerifier(config),
    fixture_kind: 'software-emulated Class-A assertions, synthetic local test only' };
}
