// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { approvalActionHash } from '@emilia-protocol/require-receipt';
import { buildPaymentReleaseActionIdentity } from '../lib/approval-acquisition/contract.ts';
import type { ApprovalAcquisitionRow } from '../lib/approval-acquisition/store.ts';

const mocks = vi.hoisted(() => ({
  getServiceClient: vi.fn(),
  getEvidenceSigningKeypair: vi.fn(),
}));

vi.mock('@/lib/supabase.js', () => ({ getServiceClient: mocks.getServiceClient }));
vi.mock('@/lib/guard-evidence-receipt.js', () => ({
  canonicalize: (value: unknown) => JSON.stringify(value),
  getEvidenceSigningKeypair: mocks.getEvidenceSigningKeypair,
}));

import {
  ApprovalEvidenceError,
  _internals,
  loadApprovalStatus,
} from '../lib/approval-acquisition/evidence.ts';

const action = {
  action_type: 'payment.release',
  amount_usd: 200,
  currency: 'USD',
  payment_instruction_id: 'payment:bike:0001',
  beneficiary_account_hash: `sha256:${'b'.repeat(64)}`,
  counterparty_name: 'Bicycle Shop',
};
const identity = buildPaymentReleaseActionIdentity(action);
if (!identity.ok) throw new Error(identity.detail);
const actionWithCaid = { ...action, action_caid: identity.actionCaid };

function row(overrides: Partial<ApprovalAcquisitionRow> = {}): ApprovalAcquisitionRow {
  return {
    request_id: `apr_${'a'.repeat(32)}`,
    tenant_id: 'tenant-a',
    environment: 'production',
    requester_key_id: 'requester-key',
    producer_key_id: 'producer-key',
    idempotency_digest: `sha256:${'1'.repeat(64)}`,
    request_digest: `sha256:${'2'.repeat(64)}`,
    challenge_hash: `sha256:${'3'.repeat(64)}`,
    action_hash: approvalActionHash(actionWithCaid),
    action_caid: identity.actionCaid,
    action: actionWithCaid,
    approver_id: 'approver@example.test',
    poll_token_hash: `sha256:${'4'.repeat(64)}`,
    poll_token_key_id: 'key-v1',
    poll_token_ciphertext: 'ciphertext',
    poll_token_iv: 'iv',
    poll_token_tag: 'tag',
    status: 'pending',
    reconciliation_state: 'not_required',
    refusal_code: null,
    receipt_id: 'receipt-1',
    signoff_id: null,
    receipt_action_hash: null,
    indeterminate_at: null,
    reconciled_at: null,
    refused_at: null,
    expires_at: '2026-07-22T05:00:00.000Z',
    created_at: '2026-07-22T03:00:00.000Z',
    updated_at: '2026-07-22T03:00:00.000Z',
    ...overrides,
  };
}

function canonicalAction(overrides: Record<string, unknown> = {}) {
  return {
    action_type: 'large_payment_release',
    target_resource_id: action.payment_instruction_id,
    amount: action.amount_usd,
    currency: action.currency,
    counterparty_name: action.counterparty_name,
    payment_destination_hash: action.beneficiary_account_hash,
    action_caid: identity.actionCaid,
    ...overrides,
  };
}

function acquisitionState(overrides: Record<string, unknown> = {}) {
  const request = row();
  return {
    acquisition_tenant_id: request.tenant_id,
    acquisition_environment: request.environment,
    acquisition_request_id: request.request_id,
    acquisition_request_digest: request.request_digest,
    acquisition_action_hash: request.action_hash,
    acquisition_action_caid: request.action_caid,
    acquisition_challenge_hash: request.challenge_hash,
    canonical_action: {
      acquisition_scope: {
        tenant_id: request.tenant_id,
        environment: request.environment,
        request_id: request.request_id,
        request_digest: request.request_digest,
        action_hash: request.action_hash,
        action_caid: request.action_caid,
        challenge_hash: request.challenge_hash,
      },
    },
    ...overrides,
  };
}

function query(result: unknown) {
  const limit = vi.fn().mockResolvedValue(result);
  const order = vi.fn(() => ({ limit }));
  const like = vi.fn(() => ({ order }));
  const secondEq = vi.fn(() => ({ like }));
  const firstEq = vi.fn(() => ({ eq: secondEq }));
  const select = vi.fn(() => ({ eq: firstEq }));
  const from = vi.fn(() => ({ select }));
  return { client: { from }, from, select, firstEq, secondEq, like, order, limit };
}

beforeEach(() => {
  mocks.getServiceClient.mockReset();
  mocks.getEvidenceSigningKeypair.mockReset();
});

describe('approval evidence storage and binding hostility', () => {
  it('loads the bounded timeline through the exact audit projection', async () => {
    const q = query({ data: [], error: null });
    mocks.getServiceClient.mockReturnValue(q.client);
    await expect(loadApprovalStatus(row(), new Date('2026-07-22T04:00:00.000Z')))
      .resolves.toEqual({ status: 'pending' });
    expect(q.from).toHaveBeenCalledWith('audit_events');
    expect(q.firstEq).toHaveBeenCalledWith('target_type', 'trust_receipt');
    expect(q.secondEq).toHaveBeenCalledWith('target_id', 'receipt-1');
    expect(q.like).toHaveBeenCalledWith('event_type', 'guard.%');
    expect(q.order).toHaveBeenCalledWith('created_at', { ascending: true });
    expect(q.limit).toHaveBeenCalledWith(201);
  });

  it('does not touch storage when no terminal receipt exists', async () => {
    await expect(loadApprovalStatus(row({ status: 'refused', receipt_id: null }), new Date('2026-07-22T04:00:00.000Z')))
      .resolves.toEqual({ status: 'pending' });
    expect(mocks.getServiceClient).not.toHaveBeenCalled();
  });

  it.each([
    { data: null, error: null },
    { data: {}, error: null },
    { data: Array.from({ length: 201 }, () => ({})), error: null },
    { data: [], error: { message: 'db' } },
  ])('fails closed on malformed or unavailable audit data %#', async (result) => {
    mocks.getServiceClient.mockReturnValue(query(result).client);
    await expect(loadApprovalStatus(row())).rejects.toBeInstanceOf(ApprovalEvidenceError);
  });

  it('normalizes service-client construction failures', async () => {
    mocks.getServiceClient.mockImplementation(() => { throw new Error('secret detail'); });
    await expect(loadApprovalStatus(row())).rejects.toMatchObject({
      name: 'ApprovalEvidenceError', message: 'approval_evidence_unavailable',
    });
  });

  it('signs and self-verifies the portable operator receipt with a pinned keypair', () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    mocks.getEvidenceSigningKeypair.mockReturnValue({
      privateKey: pair.privateKey,
      publicKeySpkiB64u: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    });
    const signed = _internals.signApprovalReceipt({
      issuer: 'ep_operator_emilia_primary', created_at: '2026-07-22T03:00:00.000Z', claim: { allow: true },
    });
    expect(signed).toMatchObject({
      '@version': 'EP-RECEIPT-v1',
      signature: { algorithm: 'Ed25519', key_class: 'C', key_id: 'ep-signing-key-1' },
      metadata: { profile: 'EP-APPROVAL-v1' },
    });
    mocks.getEvidenceSigningKeypair.mockReturnValue(null);
    expect(_internals.signApprovalReceipt({ issuer: 'issuer' })).toBeNull();

    const other = crypto.generateKeyPairSync('ed25519');
    mocks.getEvidenceSigningKeypair.mockReturnValue({
      privateKey: pair.privateKey,
      publicKeySpkiB64u: other.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    });
    expect(_internals.signApprovalReceipt({ issuer: 'issuer' })).toBeNull();
  });

  it('accepts only exact payment material', () => {
    expect(_internals.samePaymentMaterial(row(), canonicalAction())).toBe(true);
    const mutations = [
      { action_type: 'other' },
      { target_resource_id: 'other' },
      { amount: 201 },
      { currency: 'EUR' },
      { counterparty_name: 'Other' },
      { payment_destination_hash: `sha256:${'f'.repeat(64)}` },
      { action_caid: 'other' },
    ];
    for (const mutation of mutations) {
      expect(_internals.samePaymentMaterial(row(), canonicalAction(mutation))).toBe(false);
    }
    expect(_internals.samePaymentMaterial(row({ action: { action_type: 'unsupported' } }), canonicalAction())).toBe(false);
    expect(_internals.samePaymentMaterial(row({ action_hash: `sha256:${'e'.repeat(64)}` }), canonicalAction())).toBe(false);
    expect(_internals.samePaymentMaterial(row({ action_caid: 'other' }), canonicalAction())).toBe(false);
  });

  it('accepts only an exact closed acquisition scope', () => {
    const request = row();
    expect(_internals.sameAcquisitionScope(request, acquisitionState())).toBe(true);
    const topLevelKeys = [
      'acquisition_tenant_id', 'acquisition_environment', 'acquisition_request_id',
      'acquisition_request_digest', 'acquisition_action_hash', 'acquisition_action_caid',
      'acquisition_challenge_hash',
    ];
    for (const key of topLevelKeys) {
      expect(_internals.sameAcquisitionScope(request, acquisitionState({ [key]: 'other' }))).toBe(false);
    }
    expect(_internals.sameAcquisitionScope(request, acquisitionState({ canonical_action: {} }))).toBeFalsy();
    expect(_internals.sameAcquisitionScope(request, acquisitionState({
      canonical_action: { acquisition_scope: [] },
    }))).toBe(false);
    for (const key of ['tenant_id', 'environment', 'request_id', 'request_digest', 'action_hash', 'action_caid', 'challenge_hash']) {
      const state = acquisitionState();
      state.canonical_action.acquisition_scope[key] = 'other';
      expect(_internals.sameAcquisitionScope(request, state)).toBe(false);
    }
  });

  it('accepts only a non-empty producer identity', () => {
    expect(_internals.producerKeyId(row())).toBe('producer-key');
    expect(_internals.producerKeyId(row({ producer_key_id: '' }))).toBeNull();
    expect(_internals.producerKeyId(row({ producer_key_id: null }))).toBeNull();
  });
});
