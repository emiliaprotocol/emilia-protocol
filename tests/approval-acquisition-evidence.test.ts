// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';
import { contextHashHex } from '../lib/webauthn.ts';
import { deriveApprovalStatus } from '../lib/approval-acquisition/evidence.ts';
import type { ApprovalAcquisitionRow } from '../lib/approval-acquisition/store.ts';
import { buildPaymentReleaseActionIdentity } from '../lib/approval-acquisition/contract.ts';
import {
  approvalActionHash,
  evaluateReceiptAssurance,
  verifyEmiliaReceipt,
} from '@emilia-protocol/require-receipt';

const INNER_HASH = `sha256:${'1'.repeat(64)}`;
const PAYMENT_MATERIAL = {
  action_type: 'payment.release',
  amount_usd: 200,
  currency: 'USD',
  payment_instruction_id: 'payment:bike:0001',
  beneficiary_account_hash: `sha256:${'b'.repeat(64)}`,
  counterparty_name: 'Bicycle Shop',
};
const IDENTITY = buildPaymentReleaseActionIdentity(PAYMENT_MATERIAL);
if (!IDENTITY.ok) throw new Error(IDENTITY.detail);
const CAID = IDENTITY.actionCaid;
const EXACT_ACTION = { ...PAYMENT_MATERIAL, action_caid: CAID };
const EXACT_HASH = approvalActionHash(EXACT_ACTION);

function row(overrides: Partial<ApprovalAcquisitionRow> = {}): ApprovalAcquisitionRow {
  return {
    request_id: `apr_${'a'.repeat(32)}`,
    tenant_id: 'tenant-a',
    environment: 'production',
    requester_key_id: 'key-a',
    idempotency_digest: `sha256:${'3'.repeat(64)}`,
    request_digest: `sha256:${'4'.repeat(64)}`,
    challenge_hash: `sha256:${'5'.repeat(64)}`,
    action_hash: EXACT_HASH,
    action_caid: CAID,
    action: EXACT_ACTION,
    approver_id: 'approver@example.test',
    poll_token_hash: `sha256:${'6'.repeat(64)}`,
    poll_token_ciphertext: 'ciphertext',
    poll_token_iv: 'iv',
    poll_token_tag: 'tag',
    status: 'pending',
    receipt_id: 'tr_receipt_1',
    signoff_id: 'so_signoff_1',
    receipt_action_hash: INNER_HASH,
    expires_at: '2026-07-21T20:00:00.000Z',
    created_at: '2026-07-21T19:00:00.000Z',
    updated_at: '2026-07-21T19:00:01.000Z',
    ...overrides,
  };
}

function timeline({ approved = true, rejected = false, portable = true, assertion = null as any } = {}) {
  const context = {
    nonce: 'so_signoff_1',
    approver: 'approver@example.test',
    action_hash: INNER_HASH,
    decision: approved ? 'approved' : 'denied',
  };
  const events: any[] = [
    {
      event_type: 'guard.trust_receipt.created',
      actor_id: 'ep:cloud-key:key-a',
      created_at: '2026-07-21T19:00:02.000Z',
      after_state: {
        organization_id: 'tenant-a',
        action_type: 'large_payment_release',
        action_hash: INNER_HASH,
        signoff_required: true,
        required_assurance: 'A',
        decision: 'allow_with_signoff',
        enforcement_mode: 'enforce',
        expires_at: '2026-07-21T20:00:00.000Z',
        canonical_action: {
          action_type: 'large_payment_release',
          target_resource_id: 'payment:bike:0001',
          amount: 200,
          currency: 'USD',
          counterparty_name: 'Bicycle Shop',
          payment_destination_hash: `sha256:${'b'.repeat(64)}`,
          action_caid: CAID,
        },
      },
    },
    {
      event_type: 'guard.signoff.requested',
      actor_id: 'ep:cloud-key:key-a',
      created_at: '2026-07-21T19:00:03.000Z',
      after_state: {
        signoff_id: 'so_signoff_1',
        approver_id: 'approver@example.test',
        action_hash: INNER_HASH,
      },
    },
  ];
  if (approved) {
    events.push({
      event_type: 'guard.signoff.approved',
      actor_id: 'approver@example.test',
      created_at: '2026-07-21T19:05:00.000Z',
      after_state: {
        signoff_id: 'so_signoff_1',
        approver_id: 'approver@example.test',
        approved_action_hash: INNER_HASH,
        key_class: 'A',
        context,
        context_hash: `sha256:${contextHashHex(context)}`,
        webauthn: portable ? (assertion || {
          credential_id: 'credential-a',
          authenticator_data: 'YQ',
          client_data_json: 'Yg',
          signature: 'Yw',
        }) : null,
      },
    });
  }
  if (rejected) {
    const deniedContext = { ...context, decision: 'denied' };
    events.push({
      event_type: 'guard.signoff.rejected',
      actor_id: 'approver@example.test',
      created_at: '2026-07-21T19:04:00.000Z',
      after_state: {
        signoff_id: 'so_signoff_1',
        approver_id: 'approver@example.test',
        approved_action_hash: INNER_HASH,
        key_class: 'A',
        context: deniedContext,
        context_hash: `sha256:${contextHashHex(deniedContext)}`,
        webauthn: {
          credential_id: 'credential-a',
          authenticator_data: 'YQ',
          client_data_json: 'Yg',
          signature: 'Yw',
        },
      },
    });
  }
  return events;
}

describe('EP-APPROVAL-v1 terminal evidence', () => {
  it('returns an approved receipt only when Class-A proof and operator signing both exist', () => {
    const result = deriveApprovalStatus(row(), timeline(), new Date('2026-07-21T19:10:00.000Z'), {
      signer: (payload) => ({ '@version': 'EP-RECEIPT-v1', payload, signature: { value: 'signed' } }),
    });
    expect(result.status).toBe('approved');
    if (result.status !== 'approved') return;
    expect(result.receipt.payload.claim.action_hash).toBe(EXACT_HASH);
    expect(result.receipt.payload.claim.outcome).toBe('allow_with_signoff');
    expect(result.receipt.payload.claim.source_receipt_action_hash).toBe(INNER_HASH);
    expect(result.receipt.payload.signoff.context.action_hash).toBe(INNER_HASH);
    expect(result.receipt.payload.approver_key_id).toBe('credential-a');
    expect(result.receipt.payload.authorization.class_a_decision_evidence.key_class).toBe('A');
  });

  it('produces a receipt the standard verifier accepts at Class-A for the exact challenged action', () => {
    const rpId = 'www.emiliaprotocol.ai';
    const origin = 'https://www.emiliaprotocol.ai';
    const context = {
      nonce: 'so_signoff_1',
      approver: 'approver@example.test',
      action_hash: INNER_HASH,
      decision: 'approved',
    };
    const approver = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const clientData = Buffer.from(JSON.stringify({
      type: 'webauthn.get',
      challenge: Buffer.from(contextHashHex(context), 'hex').toString('base64url'),
      origin,
    }), 'utf8');
    const authData = Buffer.concat([
      crypto.createHash('sha256').update(rpId).digest(),
      Buffer.from([0x05, 0, 0, 0, 0]),
    ]);
    const signature = crypto.sign('sha256', Buffer.concat([
      authData,
      crypto.createHash('sha256').update(clientData).digest(),
    ]), approver.privateKey).toString('base64url');
    const assertion = {
      credential_id: 'credential-a',
      authenticator_data: authData.toString('base64url'),
      client_data_json: clientData.toString('base64url'),
      signature,
    };
    const operator = crypto.generateKeyPairSync('ed25519');
    const canonicalize = (value: any): string => (value === null || typeof value !== 'object'
      ? JSON.stringify(value)
      : Array.isArray(value)
        ? `[${value.map(canonicalize).join(',')}]`
        : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`);
    const result = deriveApprovalStatus(row(), timeline({ assertion }), new Date('2026-07-21T19:10:00.000Z'), {
      signer: (payload) => ({
        '@version': 'EP-RECEIPT-v1',
        payload,
        signature: {
          algorithm: 'Ed25519',
          value: crypto.sign(null, Buffer.from(canonicalize(payload)), operator.privateKey).toString('base64url'),
        },
      }),
    });
    expect(result.status).toBe('approved');
    if (result.status !== 'approved') return;
    const issuerKey = operator.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    expect(verifyEmiliaReceipt(result.receipt, {
      trustedKeys: [issuerKey],
      action: 'payment.release',
      actionHash: EXACT_HASH,
      requiredFields: ['action_type', 'amount_usd', 'currency', 'payment_instruction_id', 'beneficiary_account_hash'],
      caidSelector: { field: 'action_caid' },
      now: () => Date.parse('2026-07-21T19:10:00.000Z'),
    }).ok).toBe(true);
    expect(evaluateReceiptAssurance(result.receipt, 'class_a', {
      approverKeys: {
        'credential-a': {
          public_key: approver.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
          key_class: 'A',
          approver_id: 'approver@example.test',
        },
      },
      rpId,
      allowedOrigins: [origin],
    })).toMatchObject({ ok: true, have: 'class_a' });
  });

  it('refuses operator-only, unsigned, ambiguous, or mismatched evidence', () => {
    const now = new Date('2026-07-21T19:10:00.000Z');
    expect(deriveApprovalStatus(row(), timeline({ portable: false }), now).status).toBe('not_ready');
    expect(deriveApprovalStatus(row(), timeline(), now, { signer: () => null }).status).toBe('not_ready');
    expect(deriveApprovalStatus(row(), timeline({ approved: true, rejected: true }), now).status).toBe('not_ready');
    expect(deriveApprovalStatus(row({ tenant_id: 'tenant-b' }), timeline(), now).status).toBe('not_ready');
  });

  it('never attaches a receipt to pending, denied, or expired states', () => {
    const pending = deriveApprovalStatus(row(), timeline({ approved: false }), new Date('2026-07-21T19:10:00.000Z'));
    const denied = deriveApprovalStatus(row(), timeline({ approved: false, rejected: true }), new Date('2026-07-21T19:10:00.000Z'));
    const expired = deriveApprovalStatus(row(), timeline(), new Date('2026-07-21T20:00:00.000Z'));
    expect(pending).toEqual({ status: 'pending' });
    expect(denied).toEqual({ status: 'denied' });
    expect(expired).toEqual({ status: 'expired' });
  });
});
