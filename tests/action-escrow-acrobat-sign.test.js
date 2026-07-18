// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createAcrobatSignAdapter } from '../lib/integrations/action-escrow/acrobat-sign.js';

const API_ORIGIN = 'https://api.na1.adobesign.com';
const OAUTH_TOKEN = 'oauth-access-token-value';
const AGREEMENT_ID = 'CBJCHBCAABAA-example-agreement';
const OBSERVED_AT = '2026-07-17T21:30:00.000Z';
const PDF_BYTES = new TextEncoder().encode('%PDF-1.7\nfinal signed bytes\n%%EOF');

function jsonResponse(value, status = 200, contentType = 'application/json; charset=utf-8') {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': contentType },
  });
}

function pdfResponse(bytes = PDF_BYTES, status = 200, contentType = 'application/pdf') {
  return new Response(bytes, {
    status,
    headers: { 'Content-Type': contentType },
  });
}

function agreement({
  id = AGREEMENT_ID,
  status = 'SIGNED',
  email = 'signer@example.com',
  memberStatus = 'COMPLETED',
} = {}) {
  return {
    id,
    name: 'Release authorization',
    status,
    participantSetsInfo: [{
      role: 'SIGNER',
      order: 1,
      memberInfos: [{
        email,
        status: memberStatus,
      }],
    }],
  };
}

function request(overrides = {}) {
  return {
    notification: {
      event: 'AGREEMENT_SIGNED',
      agreement: {
        id: AGREEMENT_ID,
        status: 'CANCELLED',
        participantSetsInfo: [{
          role: 'SIGNER',
          memberInfos: [{ email: 'attacker@example.com' }],
        }],
        signedDocument: 'untrusted-webhook-bytes',
      },
    },
    expected: {
      agreementId: AGREEMENT_ID,
      status: 'SIGNED',
      participants: [{
        email: 'signer@example.com',
        role: 'SIGNER',
        status: 'COMPLETED',
      }],
    },
    ...overrides,
  };
}

function adapter(fetchImpl, overrides = {}) {
  return createAcrobatSignAdapter({
    apiOrigin: API_ORIGIN,
    oauthAccessToken: OAUTH_TOKEN,
    fetch: fetchImpl,
    clock: () => OBSERVED_AT,
    ...overrides,
  });
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('Acrobat Sign authoritative evidence fetch', () => {
  it('uses the webhook only as a hint and returns provider-fetched final bytes and metadata', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(agreement()))
      .mockResolvedValueOnce(pdfResponse());
    const subject = adapter(fetchImpl);

    const result = await subject.fetchFinalEvidence(request());

    expect(result.kind).toBe('evidence_ready');
    expect(Array.from(result.document_bytes)).toEqual(Array.from(PDF_BYTES));
    expect(result.evidence).toEqual({
      '@version': 'EMILIA-EXTERNAL-ESIGN-EVIDENCE-v1',
      provider: 'acrobat_sign',
      retrieval_method: 'authenticated_provider_refetch',
      api_origin: API_ORIGIN,
      agreement_id: AGREEMENT_ID,
      agreement_status: 'SIGNED',
      participants: [{
        email: 'signer@example.com',
        role: 'SIGNER',
        order: 1,
        member_status: 'COMPLETED',
      }],
      document: {
        media_type: 'application/pdf',
        byte_length: PDF_BYTES.byteLength,
        sha256: `sha256:${createHash('sha256').update(PDF_BYTES).digest('hex')}`,
      },
      observed_at: OBSERVED_AT,
    });
    expect(result.evidence).not.toHaveProperty('dab_digest');
    expect(Object.isFrozen(result.evidence)).toBe(true);
    expect(JSON.stringify(result)).not.toContain(OAUTH_TOKEN);

    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(fetchImpl.mock.calls[0][0]).toBe(
      `${API_ORIGIN}/api/rest/v6/agreements/${AGREEMENT_ID}`,
    );
    expect(fetchImpl.mock.calls[1][0]).toBe(
      `${API_ORIGIN}/api/rest/v6/agreements/${AGREEMENT_ID}/combinedDocument`,
    );
    expect(fetchImpl.mock.calls[0][1]).toMatchObject({
      method: 'GET',
      redirect: 'error',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${OAUTH_TOKEN}`,
      },
    });
    expect(fetchImpl.mock.calls[1][1].headers.Accept).toBe('application/pdf');
  });

  it('refuses a mismatched webhook agreement hint without making a request', async () => {
    const fetchImpl = vi.fn();
    const input = request();
    input.notification.agreement.id = 'different-agreement';

    const result = await adapter(fetchImpl).fetchFinalEvidence(input);

    expect(result).toMatchObject({
      kind: 'mismatch',
      reason_code: 'NOTIFICATION_AGREEMENT_ID_MISMATCH',
      expected_agreement_id: AGREEMENT_ID,
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('does not download a document until authenticated metadata is final', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(agreement({
      status: 'OUT_FOR_SIGNATURE',
    })));

    const result = await adapter(fetchImpl).fetchFinalEvidence(request());

    expect(result).toMatchObject({
      kind: 'not_final',
      reason_code: 'AGREEMENT_NOT_FINAL',
      expected_status: 'SIGNED',
      provider_status: 'OUT_FOR_SIGNATURE',
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('requires the provider agreement id and participant set to match exactly', async () => {
    const idFetch = vi.fn(async () => jsonResponse(agreement({ id: 'wrong-id' })));
    const idResult = await adapter(idFetch).fetchFinalEvidence(request());
    expect(idResult).toMatchObject({
      kind: 'mismatch',
      reason_code: 'PROVIDER_AGREEMENT_ID_MISMATCH',
    });

    const participantFetch = vi.fn(async () => jsonResponse(agreement({
      email: 'other@example.com',
    })));
    const participantResult = await adapter(participantFetch).fetchFinalEvidence(request());
    expect(participantResult).toMatchObject({
      kind: 'mismatch',
      reason_code: 'PARTICIPANT_MISMATCH',
    });
    expect(participantFetch).toHaveBeenCalledTimes(1);
  });

  it('rejects non-JSON metadata and duplicate-key provider JSON', async () => {
    const wrongTypeFetch = vi.fn(async () => jsonResponse(
      agreement(),
      200,
      'text/plain',
    ));
    await expect(adapter(wrongTypeFetch).fetchFinalEvidence(request()))
      .resolves.toMatchObject({
        kind: 'provider_error',
        reason_code: 'PROVIDER_RESPONSE_INVALID',
      });

    const duplicateFetch = vi.fn(async () => new Response(
      `{"id":"${AGREEMENT_ID}","id":"attacker","status":"SIGNED"}`,
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    ));
    await expect(adapter(duplicateFetch).fetchFinalEvidence(request()))
      .resolves.toMatchObject({
        kind: 'provider_error',
        reason_code: 'PROVIDER_RESPONSE_INVALID',
      });
  });

  it.each([
    ['wrong content type', PDF_BYTES, 'application/octet-stream'],
    ['wrong file signature', new TextEncoder().encode('not a pdf'), 'application/pdf'],
  ])('rejects a final document with %s', async (_label, bytes, contentType) => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(agreement()))
      .mockResolvedValueOnce(pdfResponse(bytes, 200, contentType));

    const result = await adapter(fetchImpl).fetchFinalEvidence(request());

    expect(result).toMatchObject({
      kind: 'mismatch',
      reason_code: 'FINAL_DOCUMENT_NOT_PDF',
    });
  });

  it('bounds final PDF bytes', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(agreement()))
      .mockResolvedValueOnce(new Response('%PDF-large', {
        status: 200,
        headers: {
          'Content-Type': 'application/pdf',
          'Content-Length': '10',
        },
      }));

    const result = await adapter(fetchImpl, { maxDocumentBytes: 9 })
      .fetchFinalEvidence(request());

    expect(result).toMatchObject({
      kind: 'provider_error',
      reason_code: 'PROVIDER_RESPONSE_TOO_LARGE',
    });
  });

  it('enforces a total timeout and does not log OAuth material', async () => {
    vi.useFakeTimers();
    const fetchImpl = vi.fn(() => new Promise(() => {}));
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const pending = adapter(fetchImpl, { timeoutMs: 5 }).fetchFinalEvidence(request());

    await vi.advanceTimersByTimeAsync(5);
    const result = await pending;
    expect(result).toMatchObject({
      kind: 'provider_error',
      reason_code: 'PROVIDER_TIMEOUT',
    });
    expect(errorSpy).not.toHaveBeenCalled();
    expect(JSON.stringify(result)).not.toContain(OAUTH_TOKEN);
  });

  it('requires a caller-pinned bare HTTPS API origin and keeps OAuth private', () => {
    const fetchImpl = vi.fn();
    expect(() => createAcrobatSignAdapter({
      apiOrigin: 'http://api.na1.adobesign.com',
      oauthAccessToken: OAUTH_TOKEN,
      fetch: fetchImpl,
    })).toThrow(/HTTPS/);
    expect(() => createAcrobatSignAdapter({
      apiOrigin: `${API_ORIGIN}/api/rest/v6`,
      oauthAccessToken: OAUTH_TOKEN,
      fetch: fetchImpl,
    })).toThrow(/HTTPS/);

    const subject = adapter(fetchImpl);
    expect(subject).not.toHaveProperty('oauthAccessToken');
    expect(subject.api_origin).toBe(API_ORIGIN);
  });
});
