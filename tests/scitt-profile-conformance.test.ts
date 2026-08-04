// SPDX-License-Identifier: Apache-2.0

import { describe, expect, test } from 'vitest';
import {
  registerAndResolveScrapi,
  buildArtifacts,
  inspectCoseSign1,
  verifyProfileArtifacts,
} from '../examples/scitt/ep-receipt-scitt-conformance.mjs';
import { runEndToEnd } from '../examples/scitt/ep-receipt-scitt-end-to-end.mjs';
import { verifyMockTransparencyReceipt } from '../examples/scitt/mock-scrapi-transparency-service.mjs';

function rfc9162Receipt() {
  return Buffer.from([0xd2, 0x84, 0x45, 0xa1, 0x19, 0x01, 0x8b, 0x01, 0xa0, 0xf6, 0x40]);
}

describe('EP-SCITT profile conformance harness', () => {
  test('passes the local EP/COSE/SCRAPI profile checks', () => {
    const artifacts: any = buildArtifacts();
    const checks: any[] = verifyProfileArtifacts(artifacts);
    const byId: any = Object.fromEntries(checks.map((c: any) => [c.id, c.pass]));

    expect(byId).toMatchObject({
      native_ep_signature: true,
      cose_sign1_tag: true,
      protected_alg: true,
      protected_cty: true,
      protected_kid: true,
      protected_cwt_issuer: true,
      protected_cwt_subject: true,
      payload_byte_identity: true,
      sig_structure_signature: true,
      scrapi_request_shape: true,
    });
    expect(checks.every((c: any) => c.pass)).toBe(true);
  });

  test('carries the EP payload bytes and profile headers inside COSE_Sign1', () => {
    const artifacts: any = buildArtifacts();
    const parsed: any = inspectCoseSign1(artifacts.coseSign1);

    expect(Buffer.compare(parsed.payloadBytes, artifacts.payloadBytes)).toBe(0);
    expect(parsed.protected.get(1)).toBe(-8);
    expect(parsed.protected.get(3)).toBe('application/ep-receipt+json');
    expect(Buffer.compare(parsed.protected.get(4), artifacts.kid)).toBe(0);
    expect(parsed.protected.get(15)).toBeInstanceOf(Map);
    expect(parsed.protected.get(15).get(1)).toBe(artifacts.issuer);
    expect(parsed.protected.get(15).get(2)).toBe(artifacts.subject);
  });

  test('follows SCRAPI 202 -> 204 -> 200 and honors Retry-After', async () => {
    const artifacts: any = buildArtifacts();
    const requests: Array<{ url: string; method: string }> = [];
    const waits: number[] = [];
    const responses = [
      new Response(null, {
        status: 202,
        headers: { location: '/entries/abc', 'retry-after': '2' },
      }),
      new Response(null, {
        status: 204,
        headers: { 'retry-after': '3', 'cache-control': 'no-store' },
      }),
      new Response(Buffer.from('receipt'), {
        status: 200,
        headers: { 'content-type': 'application/cose' },
      }),
    ];
    const fetchImpl = async (input: URL | RequestInfo, init?: RequestInit) => {
      requests.push({
        url: String(input),
        method: String(init?.method || 'GET'),
      });
      const response = responses.shift();
      if (!response) throw new Error('unexpected request');
      return response;
    };

    const resolved: any = await registerAndResolveScrapi(
      artifacts,
      'https://transparency.example',
      {
        fetchImpl,
        wait: async (milliseconds: number) => waits.push(milliseconds),
        maxPolls: 3,
      },
    );

    expect(requests).toEqual([
      { url: 'https://transparency.example/entries', method: 'POST' },
      { url: 'https://transparency.example/entries/abc', method: 'GET' },
      { url: 'https://transparency.example/entries/abc', method: 'GET' },
    ]);
    expect(waits).toEqual([2000, 3000]);
    expect(resolved.status).toBe(200);
    expect(resolved.receipt.equals(Buffer.from('receipt'))).toBe(true);
    expect(resolved.polls).toBe(2);
  });

  test('refuses an asynchronous registration without Location', async () => {
    const artifacts: any = buildArtifacts();
    await expect(registerAndResolveScrapi(
      artifacts,
      'https://transparency.example',
      {
        fetchImpl: async () => new Response(null, { status: 202 }),
        wait: async () => {},
      },
    )).rejects.toThrow('scrapi_202_missing_location');
  });

  test('refuses a synchronous registration without the required Location', async () => {
    const artifacts: any = buildArtifacts();
    await expect(registerAndResolveScrapi(
      artifacts,
      'https://transparency.example',
      {
        fetchImpl: async () => new Response(Buffer.from('receipt'), {
          status: 201,
          headers: { 'content-type': 'application/cose' },
        }),
        wait: async () => {},
      },
    )).rejects.toThrow('scrapi_201_missing_location');
  });

  test('refuses a receipt with the wrong media type', async () => {
    const artifacts: any = buildArtifacts();
    await expect(registerAndResolveScrapi(
      artifacts,
      'https://transparency.example',
      {
        fetchImpl: async () => new Response(Buffer.from('receipt'), {
          status: 201,
          headers: { location: '/entries/abc', 'content-type': 'application/json' },
        }),
        wait: async () => {},
      },
    )).rejects.toThrow('scrapi_receipt_content_type_invalid');
  });

  test('refuses an empty resolved receipt', async () => {
    const artifacts: any = buildArtifacts();
    const responses = [
      new Response(null, { status: 202, headers: { location: '/entries/abc', 'retry-after': '0' } }),
      new Response(null, { status: 200, headers: { 'content-type': 'application/cose' } }),
    ];
    await expect(registerAndResolveScrapi(
      artifacts,
      'https://transparency.example',
      {
        fetchImpl: async () => {
          const response = responses.shift();
          if (!response) throw new Error('unexpected request');
          return response;
        },
        wait: async () => {},
      },
    )).rejects.toThrow('scrapi_receipt_empty');
  });

  test('caps receipt polling instead of retrying forever', async () => {
    const artifacts: any = buildArtifacts();
    await expect(registerAndResolveScrapi(
      artifacts,
      'https://transparency.example',
      {
        fetchImpl: async (_input: URL | RequestInfo, init?: RequestInit) => (
          init?.method === 'POST'
            ? new Response(null, { status: 202, headers: { location: '/entries/abc', 'retry-after': '0' } })
            : new Response(null, { status: 204, headers: { 'retry-after': '0' } })
        ),
        wait: async () => {},
        maxPolls: 2,
      },
    )).rejects.toThrow('scrapi_receipt_poll_limit_exceeded');
  });

  test('calls a pinned native receipt verifier before external mode can pass', async () => {
    const receipt = rfc9162Receipt();
    const responses = [
      new Response(null, { status: 202, headers: { location: '/entries/abc', 'retry-after': '0' } }),
      new Response(receipt, { status: 200, headers: { 'content-type': 'application/cose' } }),
    ];
    const fetchImpl = async () => {
      const response = responses.shift();
      if (!response) throw new Error('unexpected request');
      return response;
    };
    const result: any = await runEndToEnd({
      scittUrl: 'https://transparency.example',
      useMockFallback: false,
      fetchImpl,
      wait: async () => {},
      receiptProfiles: new Map([[
        1,
        {
          id: 'rfc9942-rfc9162-test-profile',
          verify: () => ({ native_verification: 'VERIFIED', reasons: [] }),
        },
      ]]),
    });

    expect(result.target).toBe('external');
    expect(result.registration.status).toBe(200);
    expect(result.transparencyChecks).toEqual([
      expect.objectContaining({ id: 'external_receipt_native_verification', pass: true }),
    ]);
    expect(result.passed).toBe(true);
  });

  test('registers with the mock transparency service and verifies inclusion', async () => {
    const result: any = await runEndToEnd({ useMockFallback: true });

    expect(result.target).toBe('mock');
    expect(result.registration.ok).toBe(true);
    expect(result.profileChecks.every((c: any) => c.pass)).toBe(true);
    expect(result.transparencyChecks.every((c: any) => c.pass)).toBe(true);
    expect(result.passed).toBe(true);
  });

  test('mock transparency receipt refuses statement-byte tampering', async () => {
    const result: any = await runEndToEnd({ useMockFallback: true });
    const tamperedStatement: Buffer = Buffer.from(result.artifacts.coseSign1);
    tamperedStatement[tamperedStatement.length - 1] ^= 0x01;
    const checks: any[] = verifyMockTransparencyReceipt(result.receipt, tamperedStatement);
    const byId: any = Object.fromEntries(checks.map((c: any) => [c.id, c.pass]));

    expect(byId.mock_receipt_signature).toBe(true);
    expect(byId.statement_hash_binding).toBe(false);
    expect(byId.leaf_hash_binding).toBe(false);
  });
});
