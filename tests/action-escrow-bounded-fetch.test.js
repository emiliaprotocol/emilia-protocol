// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';
import {
  parseJsonObject,
  requestBounded,
  validatePinnedOrigin,
} from '../lib/integrations/action-escrow/bounded-fetch.js';
import { defineExternalCustodianAdapter } from '../lib/integrations/action-escrow/licensed-custodian.js';

const encoder = new TextEncoder();

function noOpMethods() {
  return {
    createTransaction: async () => ({ kind: 'refused' }),
    reconcileTransaction: async () => ({ kind: 'not_found' }),
    releaseMilestone: async () => ({ kind: 'provider_action_required' }),
    requestMilestoneDisbursement: async () => ({ kind: 'provider_action_required' }),
  };
}

describe('action escrow bounded provider fetch', () => {
  it.each([
    ['duplicate member names', '{"id":"safe","id":"attacker"}'],
    ['escaped duplicate member names', String.raw`{"origin":"safe","\u006frigin":"attacker"}`],
    ['unpaired high surrogate', String.raw`{"value":"\ud800"}`],
    ['unpaired low surrogate', String.raw`{"value":"\udc00"}`],
    ['excessive nesting', `{"value":${'['.repeat(65)}0${']'.repeat(65)}}`],
  ])('rejects %s before JSON.parse', (_label, raw) => {
    expect(parseJsonObject(
      encoder.encode(raw),
      'application/json; charset=utf-8',
    )).toEqual({ ok: false });
  });

  it('requires a JSON media type and permits only explicitly allowed provider types', () => {
    const bytes = encoder.encode('{"ok":true}');
    expect(parseJsonObject(bytes, 'text/plain')).toEqual({ ok: false });
    expect(parseJsonObject(bytes, null)).toEqual({ ok: false });
    expect(parseJsonObject(bytes, 'application/vnd.provider.transaction+json'))
      .toEqual({ ok: false });
    expect(parseJsonObject(
      bytes,
      'application/vnd.provider.transaction+json',
      ['application/vnd.provider.transaction+json'],
    )).toEqual({ ok: true, value: { ok: true } });
  });

  it('pins the final URL to the configured HTTPS origin and forbids redirects', async () => {
    const fetchImpl = vi.fn(async () => new Response('ok', { status: 200 }));
    const result = await requestBounded(
      fetchImpl,
      'https://api.example.test/resource',
      { method: 'GET' },
      {
        expectedOrigin: 'https://api.example.test',
        maxBytes: 16,
        timeoutMs: 100,
      },
    );

    expect(result.kind).toBe('response');
    expect(fetchImpl).toHaveBeenCalledWith(
      'https://api.example.test/resource',
      expect.objectContaining({ redirect: 'error', signal: expect.any(AbortSignal) }),
    );

    const blocked = await requestBounded(
      fetchImpl,
      'https://other.example.test/resource',
      {},
      {
        expectedOrigin: 'https://api.example.test',
        maxBytes: 16,
        timeoutMs: 100,
      },
    );
    expect(blocked).toEqual({ kind: 'failure', reason: 'invalid_response' });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('rejects an injected response that reports a redirect or different final URL', async () => {
    const body = new Response('ok').body;
    const fetchImpl = vi.fn(async () => ({
      status: 200,
      headers: new Headers({ 'Content-Type': 'text/plain' }),
      body,
      redirected: true,
      url: 'https://other.example.test/resource',
    }));

    await expect(requestBounded(
      fetchImpl,
      'https://api.example.test/resource',
      {},
      {
        expectedOrigin: 'https://api.example.test',
        maxBytes: 16,
        timeoutMs: 100,
      },
    )).resolves.toEqual({ kind: 'failure', reason: 'invalid_response' });
  });

  it('rejects malformed lengths and non-stream bodies before unbounded allocation', async () => {
    const malformedLengthFetch = vi.fn(async () => ({
      status: 200,
      headers: new Headers({ 'Content-Length': '1e2' }),
      body: null,
      redirected: false,
      url: '',
    }));
    const unboundedBodyFetch = vi.fn(async () => ({
      status: 200,
      headers: new Headers(),
      body: {},
      arrayBuffer: async () => new ArrayBuffer(1024 * 1024),
      redirected: false,
      url: '',
    }));
    const policy = {
      expectedOrigin: 'https://api.example.test',
      maxBytes: 16,
      timeoutMs: 100,
    };

    await expect(requestBounded(
      malformedLengthFetch,
      'https://api.example.test/resource',
      {},
      policy,
    )).resolves.toEqual({ kind: 'failure', reason: 'invalid_response' });
    await expect(requestBounded(
      unboundedBodyFetch,
      'https://api.example.test/resource',
      {},
      policy,
    )).resolves.toEqual({ kind: 'failure', reason: 'invalid_response' });
  });

  it('rejects non-HTTPS, credentialed, and path-bearing pinned origins', () => {
    expect(() => validatePinnedOrigin('http://api.example.test')).toThrow(/HTTPS/);
    expect(() => validatePinnedOrigin('https://user@api.example.test')).toThrow(/HTTPS/);
    expect(() => validatePinnedOrigin('https://api.example.test/v1')).toThrow(/HTTPS/);
  });
});

describe('external custodian contract', () => {
  it('exposes caller diligence metadata without asserting provider licensing', () => {
    const adapter = defineExternalCustodianAdapter({
      provider: 'example-custodian',
      environment: 'sandbox',
      customerDiligence: {
        review_status: 'customer_pending',
        credential_review: 'customer_pending',
        evidence_references: ['https://customer.example/diligence/1'],
      },
      capabilities: {
        create_transaction: true,
        reconcile_transaction: true,
        milestone_release: 'provider_action_required',
        direct_disbursement: 'provider_action_required',
      },
      ...noOpMethods(),
    });

    expect(adapter.customer_diligence).toEqual({
      review_status: 'customer_pending',
      credential_review: 'customer_pending',
      evidence_references: ['https://customer.example/diligence/1'],
    });
    expect(adapter).not.toHaveProperty('licensed');
    expect(Object.isFrozen(adapter.customer_diligence)).toBe(true);
  });

  it('refuses credential-like fields in exposed diligence metadata', () => {
    expect(() => defineExternalCustodianAdapter({
      provider: 'example-custodian',
      environment: 'sandbox',
      customerDiligence: { access_token: 'must-not-be-exposed' },
      capabilities: {
        create_transaction: true,
        reconcile_transaction: true,
        milestone_release: 'provider_action_required',
        direct_disbursement: 'provider_action_required',
      },
      ...noOpMethods(),
    })).toThrow(/credential-like/);
  });

  it('rejects result kinds outside each closed operation union', async () => {
    const adapter = defineExternalCustodianAdapter({
      provider: 'example-custodian',
      environment: 'sandbox',
      customerDiligence: { review_status: 'customer_pending' },
      capabilities: {
        create_transaction: true,
        reconcile_transaction: true,
        milestone_release: 'provider_action_required',
        direct_disbursement: 'provider_action_required',
      },
      ...noOpMethods(),
      createTransaction: async () => ({ kind: 'provider_claims_success' }),
    });

    await expect(adapter.createTransaction({}))
      .rejects.toThrow(/unsupported closed result kind/);
  });
});
