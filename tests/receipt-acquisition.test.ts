// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';
import crypto from 'node:crypto';
import {
  EP_APPROVAL_FLOW,
  approvalActionHash,
  beginReceiptApproval,
  pollReceiptApproval,
  makeReceiptGate,
  receiptChallenge,
  receiptRequiredHeader,
  validateApprovalAuthorization,
  verifyEmiliaReceipt,
} from '../packages/require-receipt/index.js';
import {
  createDefaultActionControlManifest,
  createGate,
} from '../packages/gate/index.js';

const authorization = Object.freeze({
  authorization_endpoint: 'https://authorize.example.test/v1/approvals',
  flow: 'EP-APPROVAL-v1',
});
const requesterAuthorization = `Bearer ept_test_${'a'.repeat(64)}`;

const challenge = Object.freeze({
  action: 'payment.release',
  action_hash: 'sha256:63539c8f0d053f0de6fe0049130f77322482483aeda92d0ca2496a40eebc6f89',
  required_fields: ['action_type', 'amount', 'currency', 'beneficiary_account_hash'],
  caid_selector: { field: 'action_caid' },
});

const action = Object.freeze({
  action_type: 'payment.release',
  amount: 200,
  currency: 'USD',
  beneficiary_account_hash: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  action_caid: 'caid:1:payment.release.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
});

function signedReceipt(claimOverrides = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const payload = {
    receipt_id: 'rcpt_acquisition_binding',
    created_at: '2026-07-21T19:00:00.000Z',
    claim: {
      action_type: action.action_type,
      outcome: 'allow_with_signoff',
      canonical_action: action,
      action_hash: approvalActionHash(action),
      ...claimOverrides,
    },
  };
  const canonicalize = (value) => {
    if (value === null || typeof value !== 'object') return JSON.stringify(value);
    if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  };
  return {
    key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    doc: {
      '@version': 'EP-RECEIPT-v1',
      payload,
      signature: {
        value: crypto.sign(null, Buffer.from(canonicalize(payload)), privateKey).toString('base64url'),
      },
    },
  };
}

describe('EP-APPROVAL-v1 challenge contract', () => {
  it('adds one closed authorization block and parameter bindings to the 428 body', () => {
    const body = receiptChallenge('payment.release', 'approval required', {
      status: 428,
      actionHash: challenge.action_hash,
      authorization,
      requiredFields: challenge.required_fields,
      caidSelector: challenge.caid_selector,
    });

    expect(body.required.authorization).toEqual(authorization);
    expect(body.required.required_fields).toEqual(challenge.required_fields);
    expect(body.required.caid_selector).toEqual(challenge.caid_selector);
    expect(body.required.authorization).not.toBe(authorization);
  });

  it('surfaces acquisition in the compact header without dropping legacy fields', () => {
    const header = receiptRequiredHeader({
      action: challenge.action,
      authorization,
      requiredFields: challenge.required_fields,
      caidSelector: challenge.caid_selector,
    });

    expect(header).toContain('action="payment.release"');
    expect(header).toContain('authorization_endpoint="https://authorize.example.test/v1/approvals"');
    expect(header).toContain('flow="EP-APPROVAL-v1"');
    expect(header).toContain('required_fields="[\\"action_type\\",\\"amount\\",\\"currency\\",\\"beneficiary_account_hash\\"]"');
  });

  it('refuses open, downgraded, credential-bearing, or non-HTTPS authorization descriptors', () => {
    expect(validateApprovalAuthorization(authorization)).toEqual({ ok: true, value: authorization });
    for (const candidate of [
      { ...authorization, flow: 'EP-APPROVAL-v0' },
      { ...authorization, extra: true },
      { ...authorization, authorization_endpoint: 'http://authorize.example.test/v1/approvals' },
      { ...authorization, authorization_endpoint: 'https://user:secret@authorize.example.test/v1/approvals' },
      { ...authorization, authorization_endpoint: 'https://authorize.example.test/v1/approvals#fragment' },
    ]) {
      expect(validateApprovalAuthorization(candidate).ok).toBe(false);
    }
  });

  it('is emitted by the real Gate when it consumes the Action Control manifest', async () => {
    const gate = createGate({
      manifest: createDefaultActionControlManifest(),
      allowEphemeralStore: true,
    });
    const observedAction = {
      action_type: 'payment.release',
      amount_usd: 200,
      currency: 'USD',
      payment_instruction_id: 'payment:bike:0001',
      beneficiary_account_hash: `sha256:${'a'.repeat(64)}`,
      action_caid: `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`,
    };
    const result = await gate.check({
      selector: { protocol: 'mcp', tool: 'release_payment' },
      observedAction,
    });

    expect(result.allow).toBe(false);
    expect(result.challenge.required.authorization).toEqual({
      authorization_endpoint: 'https://www.emiliaprotocol.ai/api/v1/approvals',
      flow: EP_APPROVAL_FLOW,
    });
    expect(result.challenge.required.required_fields).toEqual([
      'action_type',
      'amount_usd',
      'currency',
      'payment_instruction_id',
      'beneficiary_account_hash',
    ]);
    expect(result.challenge.required.action_hash).toBe(approvalActionHash(observedAction));
    expect(result.challenge.required.caid_selector).toEqual({ field: 'action_caid' });
  });

  it('does not advertise a dead-end acquisition flow without an observed exact action', async () => {
    const gate = createGate({
      manifest: createDefaultActionControlManifest(),
      allowEphemeralStore: true,
    });
    const result = await gate.check({
      selector: { protocol: 'mcp', tool: 'release_payment' },
    });
    expect(result.allow).toBe(false);
    expect(result.challenge.required.action_hash).toBeNull();
    expect(result.challenge.required.authorization).toBeNull();
  });

  it('survives the hardened reserve-before-effect gate path', async () => {
    const gate = makeReceiptGate({
      action: challenge.action,
      authorization,
      requiredFields: challenge.required_fields,
      caidSelector: challenge.caid_selector,
    });
    const result = await gate.check(null, { observedAction: action });
    expect(result.ok).toBe(false);
    expect(result.body.required).toMatchObject({
      authorization,
      required_fields: challenge.required_fields,
      caid_selector: challenge.caid_selector,
      action_hash: approvalActionHash(action),
    });
  });

  it('refuses to advertise or accept parameter binding without the observed action', async () => {
    const gate = makeReceiptGate({
      action: challenge.action,
      authorization,
      requiredFields: challenge.required_fields,
      caidSelector: challenge.caid_selector,
    });
    const result = await gate.check(null);
    expect(result.ok).toBe(false);
    expect(result.body.rejected.reason).toBe('observed_action_required');
    expect(result.body.required.authorization).toBeNull();
    expect(result.body.required.action_hash).toBeNull();
  });
});

describe('EP-APPROVAL-v1 acquisition client', () => {
  it('posts the exact challenged action without following redirects', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({
      request_id: 'apr_0123456789abcdef0123456789abcdef',
      approval_url: 'https://authorize.example.test/approve/apr_0123456789abcdef0123456789abcdef',
      poll_token: 'apt_0123456789abcdef0123456789abcdef0123456789abcdef',
      status: 'pending',
      expires_at: '2026-07-21T20:00:00.000Z',
    }), { status: 201, headers: { 'content-type': 'application/json' } }));

    const result = await beginReceiptApproval({
      authorization,
      trustedAuthorization: authorization,
      challenge,
      action,
      approver_id: 'approver@example.test',
      idempotency_key: 'idem_0123456789abcdef',
      requesterAuthorization,
      fetchImpl,
    });

    expect(result.status).toBe('pending');
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe(authorization.authorization_endpoint);
    expect(init.redirect).toBe('error');
    expect(init.headers).toEqual({
      accept: 'application/json',
      authorization: requesterAuthorization,
      'content-type': 'application/json',
    });
    expect(JSON.parse(String(init.body))).toEqual({
      flow: EP_APPROVAL_FLOW,
      challenge,
      action,
      approver_id: 'approver@example.test',
      idempotency_key: 'idem_0123456789abcdef',
    });
  });

  it('rejects recursively oversized action JSON before any network request', async () => {
    let nested: any = 'leaf';
    for (let index = 0; index < 34; index += 1) nested = { next: nested };
    const fetchImpl = vi.fn();
    await expect(beginReceiptApproval({
      authorization,
      trustedAuthorization: authorization,
      challenge,
      action: { ...action, nested },
      approver_id: 'approver@example.test',
      idempotency_key: 'idem_0123456789abcdef',
      requesterAuthorization,
      fetchImpl,
    })).rejects.toThrow(/json_too_deep/);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('refuses missing challenged fields and an action-hash mismatch before network I/O', async () => {
    const fetchImpl = vi.fn();
    await expect(beginReceiptApproval({
      authorization,
      trustedAuthorization: authorization,
      challenge,
      action: { ...action, amount: undefined },
      approver_id: 'approver@example.test',
      idempotency_key: 'idem_0123456789abcdef',
      requesterAuthorization,
      fetchImpl,
    })).rejects.toThrow('required_field_missing:amount');
    await expect(beginReceiptApproval({
      authorization,
      trustedAuthorization: authorization,
      challenge: { ...challenge, action_hash: `sha256:${'0'.repeat(64)}` },
      action,
      approver_id: 'approver@example.test',
      idempotency_key: 'idem_0123456789abcdef',
      requesterAuthorization,
      fetchImpl,
    })).rejects.toThrow('action_hash_mismatch');
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('polls with a separate unguessable token and accepts a receipt only in approved state', async () => {
    const receipt = { '@version': 'EP-RECEIPT-v1', payload: {}, signature: { value: 'x' } };
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({
      request_id: 'apr_0123456789abcdef0123456789abcdef',
      status: 'approved',
      receipt,
    }), { status: 200, headers: { 'content-type': 'application/json' } }));

    const result = await pollReceiptApproval({
      authorization,
      trustedAuthorization: authorization,
      request_id: 'apr_0123456789abcdef0123456789abcdef',
      poll_token: 'apt_0123456789abcdef0123456789abcdef0123456789abcdef',
      fetchImpl,
    });

    expect(result.receipt).toEqual(receipt);
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe('https://authorize.example.test/v1/approvals/apr_0123456789abcdef0123456789abcdef');
    expect(init.redirect).toBe('error');
    expect(init.headers.authorization).toBe('EP-Approval apt_0123456789abcdef0123456789abcdef0123456789abcdef');
  });

  it('rejects cross-origin approval URLs and malformed state responses', async () => {
    const crossOrigin = vi.fn(async () => new Response(JSON.stringify({
      request_id: 'apr_0123456789abcdef0123456789abcdef',
      approval_url: 'https://phish.example/approve',
      poll_token: 'apt_0123456789abcdef0123456789abcdef0123456789abcdef',
      status: 'pending',
      expires_at: '2026-07-21T20:00:00.000Z',
    }), { status: 201, headers: { 'content-type': 'application/json' } }));
    await expect(beginReceiptApproval({
      authorization,
      trustedAuthorization: authorization,
      challenge,
      action,
      approver_id: 'approver@example.test',
      idempotency_key: 'idem_0123456789abcdef',
      requesterAuthorization,
      fetchImpl: crossOrigin,
    })).rejects.toThrow('approval_url_origin_mismatch');

    const pendingWithReceipt = vi.fn(async () => new Response(JSON.stringify({
      request_id: 'apr_0123456789abcdef0123456789abcdef',
      status: 'pending',
      receipt: { forged: true },
    }), { status: 200, headers: { 'content-type': 'application/json' } }));
    await expect(pollReceiptApproval({
      authorization,
      trustedAuthorization: authorization,
      request_id: 'apr_0123456789abcdef0123456789abcdef',
      poll_token: 'apt_0123456789abcdef0123456789abcdef0123456789abcdef',
      fetchImpl: pendingWithReceipt,
    })).rejects.toThrow('receipt_on_nonapproved_status');
  });

  it('refuses a challenge-selected authorization service without an out-of-band exact pin', async () => {
    const fetchImpl = vi.fn();
    await expect(beginReceiptApproval({
      authorization,
      challenge,
      action,
      approver_id: 'approver@example.test',
      idempotency_key: 'idem_0123456789abcdef',
      requesterAuthorization,
      fetchImpl,
    })).rejects.toThrow('authorization_endpoint_not_pinned');
    await expect(beginReceiptApproval({
      authorization,
      trustedAuthorization: {
        ...authorization,
        authorization_endpoint: 'https://other.example.test/v1/approvals',
      },
      challenge,
      action,
      approver_id: 'approver@example.test',
      idempotency_key: 'idem_0123456789abcdef',
      requesterAuthorization,
      fetchImpl,
    })).rejects.toThrow('authorization_endpoint_not_pinned');
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('requires an out-of-band requester credential and exposes no open header injection', async () => {
    const fetchImpl = vi.fn();
    const base = {
      authorization,
      trustedAuthorization: authorization,
      challenge,
      action,
      approver_id: 'approver@example.test',
      idempotency_key: 'idem_0123456789abcdef',
      fetchImpl,
    };
    await expect(beginReceiptApproval(base as any)).rejects.toThrow('requester_authorization_invalid');
    await expect(beginReceiptApproval({
      ...base,
      requesterAuthorization: 'Bearer challenge-discovered-secret',
    })).rejects.toThrow('requester_authorization_invalid');
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

describe('EP-APPROVAL-v1 demand-side binding', () => {
  it('recomputes the signed canonical action and binds required fields plus CAID', () => {
    const { doc, key } = signedReceipt();
    expect(verifyEmiliaReceipt(doc, {
      trustedKeys: [key],
      action: action.action_type,
      actionHash: approvalActionHash(action),
      requiredFields: challenge.required_fields,
      caidSelector: challenge.caid_selector,
      now: () => Date.parse('2026-07-21T19:01:00.000Z'),
    }).ok).toBe(true);

    const alteredAction = { ...action, amount: 201 };
    const altered = signedReceipt({
      canonical_action: alteredAction,
      action_hash: approvalActionHash(action),
    });
    expect(verifyEmiliaReceipt(altered.doc, {
      trustedKeys: [altered.key],
      action: action.action_type,
      actionHash: approvalActionHash(action),
      requiredFields: challenge.required_fields,
      caidSelector: challenge.caid_selector,
      now: () => Date.parse('2026-07-21T19:01:00.000Z'),
    })).toMatchObject({ ok: false, reason: 'signed_action_hash_mismatch' });
  });

  it('rejects a CAID whose action-type segment violates the deployed v1 grammar', () => {
    const malformedAction = {
      ...action,
      action_caid: `caid:1:payment.9release.1:jcs-sha256:${'A'.repeat(43)}`,
    };
    const malformed = signedReceipt({
      canonical_action: malformedAction,
      action_hash: approvalActionHash(malformedAction),
    });
    expect(verifyEmiliaReceipt(malformed.doc, {
      trustedKeys: [malformed.key],
      action: action.action_type,
      actionHash: approvalActionHash(malformedAction),
      requiredFields: challenge.required_fields,
      caidSelector: challenge.caid_selector,
      now: () => Date.parse('2026-07-21T19:01:00.000Z'),
    })).toMatchObject({ ok: false, reason: 'signed_action_caid_invalid' });
  });
});
