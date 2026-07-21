// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';
import {
  parseJsonObject,
  requestBounded,
  responseHeader,
  validatePinnedOrigin,
  validateResponseLimit,
  validateTimeout,
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

  it.each([
    ['malformed JSON', encoder.encode('{"ok":')],
    ['invalid UTF-8', new Uint8Array([0xc3, 0x28])],
    ['JSON null', encoder.encode('null')],
    ['JSON array', encoder.encode('[]')],
    ['JSON scalar', encoder.encode('"value"')],
  ])('rejects %s as a provider object', (_label, bytes) => {
    expect(parseJsonObject(bytes, 'application/json')).toEqual({ ok: false });
  });

  it('validates configured byte and timeout bounds', () => {
    for (const value of [undefined, 0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, 64 * 1024 * 1024 + 1]) {
      expect(() => validateResponseLimit(value, 'bodyLimit')).toThrow(/bodyLimit/);
    }
    for (const value of [undefined, 0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, 60_001]) {
      expect(() => validateTimeout(value)).toThrow(/timeoutMs/);
    }
    expect(validateResponseLimit(1, 'bodyLimit')).toBe(1);
    expect(validateResponseLimit(64 * 1024 * 1024, 'bodyLimit')).toBe(64 * 1024 * 1024);
    expect(validateTimeout(1)).toBe(1);
    expect(validateTimeout(60_000, 'providerTimeout')).toBe(60_000);
  });

  it('reads response headers from Headers and case-insensitive plain objects', () => {
    expect(responseHeader({ headers: new Headers({ ETag: '"v1"' }) }, 'etag')).toBe('"v1"');
    expect(responseHeader({ headers: { 'CONTENT-TYPE': 'application/json' } }, 'content-type'))
      .toBe('application/json');
    expect(responseHeader({ headers: { other: 'value' } }, 'content-type')).toBeNull();
    expect(responseHeader({ headers: null }, 'content-type')).toBeNull();
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

  it.each([
    ['missing response', null],
    ['non-integer status', { status: '200' }],
    ['status below HTTP range', { status: 99 }],
    ['status above HTTP range', { status: 600 }],
  ])('rejects %s from an injected fetch', async (_label, injected) => {
    await expect(requestBounded(
      vi.fn(async () => injected),
      'https://api.example.test/resource',
      {},
      {
        expectedOrigin: 'https://api.example.test',
        maxBytes: 16,
        timeoutMs: 100,
      },
    )).resolves.toEqual({ kind: 'failure', reason: 'invalid_response' });
  });

  it.each([
    ['malformed final URL', 'not a url'],
    ['different final path', 'https://api.example.test/other'],
    ['credentialed final URL', 'https://user@api.example.test/resource'],
  ])('rejects a response with %s', async (_label, url) => {
    const fetchImpl = vi.fn(async () => ({
      status: 200,
      headers: new Headers({ 'Content-Length': '0' }),
      body: null,
      redirected: false,
      url,
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

  it.each([
    ['oversized declared length', '17', null, 'response_too_large'],
    ['unsafe declared length', '9007199254740992', null, 'invalid_response'],
    ['missing body with nonzero length', '1', null, 'invalid_response'],
  ])('rejects %s', async (_label, contentLength, body, reason) => {
    const fetchImpl = vi.fn(async () => ({
      status: 200,
      headers: { 'Content-Length': contentLength },
      body,
      redirected: false,
      url: '',
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
    )).resolves.toEqual({ kind: 'failure', reason });
  });

  it('accepts an explicitly empty body and normalizes absent response headers', async () => {
    const fetchImpl = vi.fn(async () => ({
      status: 204,
      headers: undefined,
      body: null,
      redirected: false,
      url: '',
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
    )).resolves.toMatchObject({
      kind: 'response',
      status: 204,
      headers: {},
      bytes: new Uint8Array(),
    });
  });

  it.each([
    ['non-byte stream chunks', 'not-bytes', 'invalid_response'],
    ['stream growth beyond the limit', encoder.encode('seventeen bytes!!!'), 'response_too_large'],
  ])('aborts on %s', async (_label, value, reason) => {
    const cancel = vi.fn(async () => {
      throw new Error('cancel failure must not replace the bounded result');
    });
    const fetchImpl = vi.fn(async () => ({
      status: 200,
      headers: {},
      body: {
        getReader: () => ({
          read: vi.fn()
            .mockResolvedValueOnce({ done: false, value })
            .mockResolvedValueOnce({ done: true }),
          cancel,
        }),
      },
      redirected: false,
      url: '',
    }));
    const result = await requestBounded(
      fetchImpl,
      'https://api.example.test/resource',
      {},
      {
        expectedOrigin: 'https://api.example.test',
        maxBytes: 16,
        timeoutMs: 100,
      },
    );
    expect(result).toEqual({ kind: 'failure', reason });
    expect(cancel).toHaveBeenCalledOnce();
  });

  it('classifies a thrown fetch as a network failure', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error('socket reset with sensitive detail');
    });
    await expect(requestBounded(
      fetchImpl,
      'https://api.example.test/resource',
      {},
      {
        expectedOrigin: 'https://api.example.test',
        maxBytes: 16,
        timeoutMs: 100,
      },
    )).resolves.toEqual({ kind: 'failure', reason: 'network' });
  });

  it('rejects malformed and credentialed request URLs before fetch', async () => {
    const fetchImpl = vi.fn();
    const policy = {
      expectedOrigin: 'https://api.example.test',
      maxBytes: 16,
      timeoutMs: 100,
    };
    for (const input of [
      'not a url',
      'http://api.example.test/resource',
      'https://user@api.example.test/resource',
    ]) {
      await expect(requestBounded(fetchImpl, input, {}, policy))
        .resolves.toEqual({ kind: 'failure', reason: 'invalid_response' });
    }
    expect(fetchImpl).not.toHaveBeenCalled();
    await expect(requestBounded(null, 'https://api.example.test/resource', {}, policy))
      .rejects.toThrow(/fetch/);
  });

  it('rejects non-HTTPS, credentialed, and path-bearing pinned origins', () => {
    expect(() => validatePinnedOrigin('http://api.example.test')).toThrow(/HTTPS/);
    expect(() => validatePinnedOrigin('https://user@api.example.test')).toThrow(/HTTPS/);
    expect(() => validatePinnedOrigin('https://api.example.test/v1')).toThrow(/HTTPS/);
  });

  it('rejects every non-origin component and enforces an optional host allowlist', () => {
    for (const origin of [
      '',
      null,
      'not a url',
      'https://user:password@api.example.test',
      'https://api.example.test?next=https://attacker.test',
      'https://api.example.test#fragment',
      'https://api.example.test:444',
    ]) {
      expect(() => validatePinnedOrigin(origin)).toThrow();
    }
    expect(() => validatePinnedOrigin(
      'https://api.example.test',
      { allowedHosts: new Set(['other.example.test']), fieldName: 'providerOrigin' },
    )).toThrow(/allowlisted/);
    expect(validatePinnedOrigin(
      'https://API.EXAMPLE.TEST:443',
      { allowedHosts: new Set(['api.example.test']) },
    )).toBe('https://api.example.test');
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

  it.each([
    ['access_token', 'token'],
    ['private_key', 'key'],
    ['bearer_token', 'bearer'],
    ['session_token', 'session'],
    ['headers', { authorization: 'secret' }],
  ])('refuses credential-like field %s in exposed diligence metadata', (field, value) => {
    expect(() => defineExternalCustodianAdapter({
      provider: 'example-custodian',
      environment: 'sandbox',
      customerDiligence: { nested: { [field]: value } },
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
