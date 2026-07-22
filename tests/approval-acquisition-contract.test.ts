// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import {
  APPROVAL_REQUIRED_FIELDS,
  SUPPORTED_APPROVAL_ACTION_TYPES,
  bindApprovalCreateRequestScope,
  buildPaymentReleaseActionIdentity,
  parseApprovalCreateRequest,
} from '../lib/approval-acquisition/contract.ts';

function fixture() {
  const material = {
    action_type: 'payment.release',
    amount_usd: 200,
    currency: 'USD',
    payment_instruction_id: 'payment:bike:0001',
    beneficiary_account_hash: `sha256:${'a'.repeat(64)}`,
    counterparty_name: 'Bicycle Shop',
  };
  const identity = buildPaymentReleaseActionIdentity(material);
  if (!identity.ok) throw new Error(identity.detail);
  const action = { ...material, action_caid: identity.actionCaid };
  const provisional = {
    flow: 'EP-APPROVAL-v1',
    challenge: {
      action: 'payment.release',
      action_hash: '',
      required_fields: [...APPROVAL_REQUIRED_FIELDS],
      caid_selector: { field: 'action_caid' },
    },
    action,
    approver_id: 'approver@example.test',
    idempotency_key: 'idem_0123456789abcdef',
  };
  const parsedWithoutHash = parseApprovalCreateRequest({
    ...provisional,
    challenge: { ...provisional.challenge, action_hash: `sha256:${'0'.repeat(64)}` },
  });
  expect(parsedWithoutHash.ok).toBe(false);
  return { provisional, action };
}

describe('EP-APPROVAL-v1 fixed payment profile', () => {
  it('keeps the server registry equal to the action types advertised for acquisition', async () => {
    const { readFile } = await import('node:fs/promises');
    const manifest = JSON.parse(await readFile(
      new URL('../public/.well-known/agent-action-control.json', import.meta.url),
      'utf8',
    ));
    const advertised = [...new Set(manifest.actions
      .filter((action) => action.control?.authorization)
      .map((action) => action.action_type))];
    expect(advertised).toEqual(SUPPORTED_APPROVAL_ACTION_TYPES);
  });

  it('accepts only an exact, CAID-bound, parameter-complete challenge', async () => {
    const { provisional } = fixture();
    const { approvalActionHash } = await import('@emilia-protocol/require-receipt');
    const body = {
      ...provisional,
      challenge: {
        ...provisional.challenge,
        action_hash: approvalActionHash(provisional.action),
      },
    };

    const parsed = parseApprovalCreateRequest(body);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.value.actionHash).toBe(body.challenge.action_hash);
    expect(parsed.value.actionCaid).toBe(body.action.action_caid);
    expect(parsed.value.cloudApprovalBody).toEqual({
      payment_reference: 'payment:bike:0001',
      amount: 200,
      currency: 'USD',
      counterparty_name: 'Bicycle Shop',
      payment_destination_hash: `sha256:${'a'.repeat(64)}`,
      approver_id: 'approver@example.test',
    });
  });

  it('cryptographically scopes the logical request to tenant and environment, not key generation', async () => {
    const { provisional } = fixture();
    const { approvalActionHash } = await import('@emilia-protocol/require-receipt');
    const parsed = parseApprovalCreateRequest({
      ...provisional,
      challenge: { ...provisional.challenge, action_hash: approvalActionHash(provisional.action) },
    });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;

    const production = bindApprovalCreateRequestScope(parsed.value, {
      tenantId: '33333333-3333-4333-8333-333333333333',
      environment: 'production',
    });
    const sameScopeAfterKeyRotation = bindApprovalCreateRequestScope(parsed.value, {
      tenantId: '33333333-3333-4333-8333-333333333333',
      environment: 'production',
    });
    const staging = bindApprovalCreateRequestScope(parsed.value, {
      tenantId: '33333333-3333-4333-8333-333333333333',
      environment: 'staging',
    });
    const otherTenant = bindApprovalCreateRequestScope(parsed.value, {
      tenantId: '44444444-4444-4444-8444-444444444444',
      environment: 'production',
    });

    expect(production.requestDigest).toBe(sameScopeAfterKeyRotation.requestDigest);
    expect(staging.requestDigest).not.toBe(production.requestDigest);
    expect(otherTenant.requestDigest).not.toBe(production.requestDigest);
    expect(production.requestScope).toEqual({
      tenant_id: '33333333-3333-4333-8333-333333333333',
      environment: 'production',
    });
  });

  it('fails closed on schema extension, weakened fields, hash drift, or CAID substitution', async () => {
    const { provisional } = fixture();
    const { approvalActionHash } = await import('@emilia-protocol/require-receipt');
    const valid = {
      ...provisional,
      challenge: { ...provisional.challenge, action_hash: approvalActionHash(provisional.action) },
    };
    const cases = [
      { ...valid, extra: true },
      { ...valid, challenge: { ...valid.challenge, required_fields: ['action_type'] } },
      { ...valid, challenge: { ...valid.challenge, action_hash: `sha256:${'1'.repeat(64)}` } },
      { ...valid, action: { ...valid.action, action_caid: valid.action.action_caid.replace(/.$/, 'A') } },
      { ...valid, action: { ...valid.action, amount_usd: 200.001 } },
      { ...valid, action: { ...valid.action, constructor: 'polluted' } },
    ];
    for (const candidate of cases) expect(parseApprovalCreateRequest(candidate).ok).toBe(false);
  });
});
