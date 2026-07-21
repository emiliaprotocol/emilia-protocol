// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';
import { createReceiptRequiredEdgeHandler } from '../packages/require-receipt/src/edge.js';
import { approvalActionHash } from '../packages/require-receipt/src/acquisition.js';

const authorization = Object.freeze({
  authorization_endpoint: 'https://authorize.example.test/v1/approvals',
  flow: 'EP-APPROVAL-v1',
});

const baseOptions = {
  action: 'payment.release',
  actionHash: `sha256:${'a'.repeat(64)}`,
  authorization,
  requiredFields: ['action_type', 'amount', 'currency', 'beneficiary_account_hash'],
  caidSelector: { field: 'action_caid' },
};

function request(headers: Record<string, string | string[]> = {}, extra: Record<string, unknown> = {}) {
  return {
    method: 'POST',
    url: 'https://merchant.example.test/v1/payments/release',
    headers: {
      'content-length': '0',
      ...headers,
    },
    bodyByteLength: 0,
    ...extra,
  };
}

describe('runtime-neutral Receipt Required edge enforcement', () => {
  it('returns a strict RFC 7807 428 challenge with acquisition and parameter metadata', async () => {
    const verifyReceipt = vi.fn();
    const authorize = createReceiptRequiredEdgeHandler({ ...baseOptions, verifyReceipt });

    const result = await authorize(request());

    expect(result.ok).toBe(false);
    if (result.ok) throw new Error('expected refusal');
    expect(result.status).toBe(428);
    expect(result.headers['content-type']).toBe('application/problem+json');
    expect(result.headers['cache-control']).toBe('no-store');
    expect(result.headers['receipt-required']).toContain('action="payment.release"');
    expect(result.headers['receipt-required']).toContain('authorization_endpoint="https://authorize.example.test/v1/approvals"');
    expect(result.headers['receipt-required']).toContain('flow="EP-APPROVAL-v1"');
    expect(result.body).toMatchObject({
      type: 'https://emiliaprotocol.ai/errors/emilia_receipt_required',
      title: 'EMILIA Receipt Required',
      status: 428,
      required: {
        action: 'payment.release',
        action_hash: baseOptions.actionHash,
        authorization,
        required_fields: baseOptions.requiredFields,
        caid_selector: baseOptions.caidSelector,
        proof_header: 'X-EMILIA-Receipt',
      },
    });
    expect(verifyReceipt).not.toHaveBeenCalled();
  });

  it('verifies the exact edge-bound action, atomically consumes, and strips proof upstream', async () => {
    const verifyReceipt = vi.fn(async () => ({
      ok: true,
      receipt_id: 'rct_0123456789abcdef',
      action: 'payment.release',
    }));
    const consume = vi.fn(async () => true);
    const authorize = createReceiptRequiredEdgeHandler({ ...baseOptions, verifyReceipt, consume });

    const result = await authorize(request({
      'x-emilia-receipt': 'ZXhhY3QtcmVjZWlwdA==',
      'x-client-header': 'kept-by-the-real-proxy',
    }));

    expect(result).toEqual({
      ok: true,
      status: 200,
      upstream: {
        method: 'POST',
        url: 'https://merchant.example.test/v1/payments/release',
        redirect: 'manual',
        remove_headers: ['x-emilia-receipt'],
        set_headers: {
          'x-emilia-verified-action': 'payment.release',
          'x-emilia-verified-receipt-id': 'rct_0123456789abcdef',
        },
      },
      authorization: {
        action: 'payment.release',
        receipt_id: 'rct_0123456789abcdef',
        consumption: 'consumed',
      },
    });
    expect(verifyReceipt).toHaveBeenCalledWith('ZXhhY3QtcmVjZWlwdA==', expect.objectContaining({
      action: 'payment.release',
      action_hash: baseOptions.actionHash,
      required_fields: baseOptions.requiredFields,
      caid_selector: baseOptions.caidSelector,
      request: {
        method: 'POST',
        url: 'https://merchant.example.test/v1/payments/release',
        body_bytes: 0,
      },
    }));
    expect(consume).toHaveBeenCalledWith('rct_0123456789abcdef', expect.objectContaining({
      action: 'payment.release',
    }));
  });

  it('projects a variable request body and binds verification to its exact hash', async () => {
    const observed = {
      action_type: 'payment.release',
      amount: 200,
      currency: 'USD',
      beneficiary_account_hash: `sha256:${'b'.repeat(64)}`,
      action_caid: `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`,
    };
    const verifyReceipt = vi.fn(async (_carrier, context) => ({
      ok: true,
      receipt_id: 'rct_projected_action',
      action: context.action,
    }));
    const authorize = createReceiptRequiredEdgeHandler({
      ...baseOptions,
      actionHash: undefined,
      projectAction: async (input) => JSON.parse(await (input as Request).clone().text()),
      verifyReceipt,
    });
    const input = new Request('https://merchant.example.test/v1/payments/release', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-emilia-receipt': 'ZXhhY3Q=',
      },
      body: JSON.stringify(observed),
    });
    const result = await authorize(input);
    expect(result.ok).toBe(true);
    expect(verifyReceipt).toHaveBeenCalledWith('ZXhhY3Q=', expect.objectContaining({
      action_hash: approvalActionHash(observed),
      observed_action: observed,
    }));
  });

  it('fails closed and exposes only stable reason codes on verifier failures', async () => {
    for (const verifyReceipt of [
      vi.fn(async () => ({ ok: false, reason: 'signature_invalid', secret: 'do-not-leak' })),
      vi.fn(async () => { throw new Error('HSM hostname and credential leaked here'); }),
      vi.fn(async () => ({ ok: true, receipt_id: 'rct_1', action: 'different.action' })),
    ]) {
      const authorize = createReceiptRequiredEdgeHandler({ ...baseOptions, verifyReceipt });
      const result = await authorize(request({ 'x-emilia-receipt': 'ZXhhY3Q=' }));
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error('expected refusal');
      expect(JSON.stringify(result)).not.toContain('do-not-leak');
      expect(JSON.stringify(result)).not.toContain('HSM hostname');
      expect(result.body.rejected?.reason).toMatch(/^(signature_invalid|verifier_unavailable|action_binding_mismatch)$/);
    }
  });

  it('requires an exact true result from atomic consumption and rejects missing receipt identity', async () => {
    const outcomes = [
      { verified: { ok: true, action: 'payment.release' }, consume: vi.fn(async () => true), reason: 'missing_receipt_id' },
      { verified: { ok: true, action: 'payment.release', receipt_id: 'rct_1' }, consume: vi.fn(async () => false), reason: 'replay_refused' },
      { verified: { ok: true, action: 'payment.release', receipt_id: 'rct_1' }, consume: vi.fn(async () => { throw new Error('db down'); }), reason: 'consumption_store_unavailable' },
    ];
    for (const entry of outcomes) {
      const authorize = createReceiptRequiredEdgeHandler({
        ...baseOptions,
        verifyReceipt: vi.fn(async () => entry.verified),
        consume: entry.consume,
      });
      const result = await authorize(request({ 'x-emilia-receipt': 'ZXhhY3Q=' }));
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error('expected refusal');
      expect(result.body.rejected?.reason).toBe(entry.reason);
    }
  });

  it('rejects ambiguous, oversized, or control-character headers before verification', async () => {
    const verifyReceipt = vi.fn();
    const authorize = createReceiptRequiredEdgeHandler({
      ...baseOptions,
      verifyReceipt,
      maxHeaderBytes: 128,
      maxReceiptBytes: 16,
    });

    const cases = [
      request({ 'x-emilia-receipt': ['first', 'second'] }),
      request({ 'x-emilia-receipt': 'x'.repeat(17) }),
      request({ 'x-emilia-receipt': 'valid', 'x-long': 'y'.repeat(160) }),
      request({ 'x-emilia-receipt': 'valid\r\nforwarded: forged' }),
    ];
    const reasons: string[] = [];
    for (const input of cases) {
      const result = await authorize(input);
      expect(result.ok).toBe(false);
      if (!result.ok) reasons.push(result.body.rejected?.reason || '');
    }
    expect(reasons).toEqual([
      'ambiguous_proof_header',
      'receipt_header_too_large',
      'request_headers_too_large',
      'request_header_invalid',
    ]);
    expect(verifyReceipt).not.toHaveBeenCalled();
  });

  it('measures a cloned request body and refuses bodies that exceed the configured bound', async () => {
    const verifyReceipt = vi.fn();
    const authorize = createReceiptRequiredEdgeHandler({
      ...baseOptions,
      verifyReceipt,
      maxBodyBytes: 4,
    });
    const input = new Request('https://merchant.example.test/v1/payments/release', {
      method: 'POST',
      headers: { 'x-emilia-receipt': 'ZXhhY3Q=' },
      body: '12345',
    });

    const result = await authorize(input);

    expect(result.ok).toBe(false);
    if (result.ok) throw new Error('expected refusal');
    expect(result.body.rejected?.reason).toBe('request_body_too_large');
    expect(verifyReceipt).not.toHaveBeenCalled();
    expect(await input.text()).toBe('12345');
  });

  it('rejects unsafe discovery and invalid limits at construction time', () => {
    const verifyReceipt = vi.fn();
    expect(() => createReceiptRequiredEdgeHandler({
      ...baseOptions,
      authorization: { ...authorization, authorization_endpoint: 'http://authorize.example.test/v1/approvals' },
      verifyReceipt,
    })).toThrow('authorization_endpoint_unsafe');
    expect(() => createReceiptRequiredEdgeHandler({
      ...baseOptions,
      authorization: { ...authorization, extra: true },
      verifyReceipt,
    })).toThrow('authorization_not_closed');
    expect(() => createReceiptRequiredEdgeHandler({ ...baseOptions, maxBodyBytes: 0, verifyReceipt }))
      .toThrow('maxBodyBytes_invalid');
    expect(() => createReceiptRequiredEdgeHandler({
      ...baseOptions,
      actionHash: undefined,
      verifyReceipt,
    })).toThrow('projectAction_required_for_material_binding');
  });
});
