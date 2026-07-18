// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createAcrobatSignAdapter } from '../lib/integrations/action-escrow/acrobat-sign.js';

const API_ORIGIN = 'https://api.na1.adobesign.com';
const OAUTH_TOKEN = 'oauth-access-token-value';
const AGREEMENT_ID = 'CBJCHBCAABAA-example-agreement';
const AGREEMENT_VERSION = '3AAABLblqZhA-final-version';
const OBSERVED_AT = '2026-07-17T21:30:00.000Z';
const PDF_BYTES = new TextEncoder().encode('%PDF-1.7\nfinal signed bytes\n%%EOF');

function jsonResponse(
  value,
  status = 200,
  contentType = 'application/json; charset=utf-8',
  headers = {},
) {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      'Content-Type': contentType,
      ...headers,
    },
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
  role = 'SIGNER',
  memberInfos,
  participantSetsInfo,
} = {}) {
  return {
    id,
    name: 'Release authorization',
    status,
    participantSetsInfo: participantSetsInfo || [{
      id: 'participant-set-1',
      role,
      order: 1,
      memberInfos: memberInfos || [{
        email,
        status: 'ACTIVE',
        extendedStatus: memberStatus,
      }],
    }],
  };
}

function events({
  version = AGREEMENT_VERSION,
  id = 'event-final-signed',
  type = 'SIGNED',
  date = '2026-07-17T21:29:59Z',
} = {}) {
  return {
    events: [{
      id,
      type,
      date,
      versionId: version,
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
      participantSets: [{
        id: 'participant-set-1',
        role: 'SIGNER',
        order: 1,
        members: [{
          email: 'signer@example.com',
          status: 'COMPLETED',
        }],
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
      .mockResolvedValueOnce(jsonResponse(events()))
      .mockResolvedValueOnce(pdfResponse())
      .mockResolvedValueOnce(jsonResponse(agreement()))
      .mockResolvedValueOnce(jsonResponse(events()));
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
      agreement_version: AGREEMENT_VERSION,
      agreement_events_digest: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      participant_sets: [{
        set_id: 'participant-set-1',
        role: 'SIGNER',
        order: 1,
        members: [{
          email: 'signer@example.com',
          member_status: 'COMPLETED',
        }],
        completion_status: 'COMPLETED',
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

    expect(fetchImpl).toHaveBeenCalledTimes(5);
    expect(fetchImpl.mock.calls[0][0]).toBe(
      `${API_ORIGIN}/api/rest/v6/agreements/${AGREEMENT_ID}`,
    );
    expect(fetchImpl.mock.calls[1][0]).toBe(
      `${API_ORIGIN}/api/rest/v6/agreements/${AGREEMENT_ID}/events`,
    );
    expect(fetchImpl.mock.calls[2][0]).toBe(
      `${API_ORIGIN}/api/rest/v6/agreements/${AGREEMENT_ID}/combinedDocument`
        + `?versionId=${encodeURIComponent(AGREEMENT_VERSION)}`,
    );
    expect(fetchImpl.mock.calls[3][0]).toBe(
      `${API_ORIGIN}/api/rest/v6/agreements/${AGREEMENT_ID}`,
    );
    expect(fetchImpl.mock.calls[4][0]).toBe(
      `${API_ORIGIN}/api/rest/v6/agreements/${AGREEMENT_ID}/events`,
    );
    expect(fetchImpl.mock.calls[0][1]).toMatchObject({
      method: 'GET',
      redirect: 'error',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${OAUTH_TOKEN}`,
      },
    });
    expect(fetchImpl.mock.calls[1][1].headers.Accept).toBe('application/json');
    expect(fetchImpl.mock.calls[2][1].headers.Accept).toBe('application/pdf');
    expect(fetchImpl.mock.calls[3][1].headers.Accept).toBe('application/json');
    expect(fetchImpl.mock.calls[4][1].headers.Accept).toBe('application/json');
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

  it('fails closed on non-signers, wrong provider roles, and missing participants', async () => {
    const nonSignerInput = request();
    nonSignerInput.expected.participantSets[0].role = 'APPROVER';
    const nonSignerFetch = vi.fn();
    await expect(adapter(nonSignerFetch).fetchFinalEvidence(nonSignerInput))
      .resolves.toMatchObject({
        kind: 'refused',
        reason_code: 'INVALID_EXPECTATION',
      });
    expect(nonSignerFetch).not.toHaveBeenCalled();

    const wrongRoleFetch = vi.fn(async () => jsonResponse(agreement({
      role: 'APPROVER',
    })));
    await expect(adapter(wrongRoleFetch).fetchFinalEvidence(request()))
      .resolves.toMatchObject({
        kind: 'mismatch',
        reason_code: 'PARTICIPANT_MISMATCH',
      });
    expect(wrongRoleFetch).toHaveBeenCalledTimes(1);

    const missingParticipantInput = request();
    missingParticipantInput.expected.participantSets.push({
      id: 'participant-set-2',
      role: 'SIGNER',
      order: 2,
      members: [{
        email: 'second@example.com',
        status: 'COMPLETED',
      }],
    });
    const missingParticipantFetch = vi.fn(async () => jsonResponse(agreement()));
    await expect(adapter(missingParticipantFetch).fetchFinalEvidence(missingParticipantInput))
      .resolves.toMatchObject({
        kind: 'mismatch',
        reason_code: 'PARTICIPANT_MISMATCH',
      });
    expect(missingParticipantFetch).toHaveBeenCalledTimes(1);
  });

  it('requires every expected signer to be completed before downloading the PDF', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(agreement({
      memberStatus: 'ACTIVE',
    })));

    const result = await adapter(fetchImpl).fetchFinalEvidence(request());

    expect(result).toMatchObject({
      kind: 'mismatch',
      reason_code: 'PARTICIPANT_MISMATCH',
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('never treats two members of one signing group as two independent signer seats', async () => {
    const input = request();
    input.expected.participantSets.push({
      id: 'participant-set-2',
      role: 'SIGNER',
      order: 2,
      members: [{
        email: 'second@example.com',
        status: 'COMPLETED',
      }],
    });
    const signingGroup = agreement({
      participantSetsInfo: [{
        id: 'participant-set-1',
        role: 'SIGNER',
        order: 1,
        memberInfos: [
          {
            email: 'signer@example.com',
            status: 'ACTIVE',
            extendedStatus: 'COMPLETED',
          },
          {
            email: 'second@example.com',
            status: 'ACTIVE',
            extendedStatus: 'COMPLETED',
          },
        ],
      }],
    });
    const fetchImpl = vi.fn(async () => jsonResponse(signingGroup));

    const result = await adapter(fetchImpl).fetchFinalEvidence(input);

    expect(result).toMatchObject({
      kind: 'provider_error',
      reason_code: 'PROVIDER_RESPONSE_INVALID',
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['identity', agreement({ id: 'different-agreement' })],
    ['status', agreement({ status: 'CANCELLED' })],
  ])('rejects an authoritative %s change around the PDF fetch', async (_field, changed) => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(agreement()))
      .mockResolvedValueOnce(jsonResponse(events()))
      .mockResolvedValueOnce(pdfResponse())
      .mockResolvedValueOnce(jsonResponse(changed))
      .mockResolvedValueOnce(jsonResponse(events()));

    const result = await adapter(fetchImpl).fetchFinalEvidence(request());

    expect(result).toMatchObject({
      kind: 'mismatch',
      reason_code: 'AGREEMENT_CHANGED_DURING_FETCH',
    });
    expect(result).not.toHaveProperty('evidence');
    expect(fetchImpl).toHaveBeenCalledTimes(5);
  });

  it('rejects an authoritative document version change around the PDF fetch', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(agreement()))
      .mockResolvedValueOnce(jsonResponse(events()))
      .mockResolvedValueOnce(pdfResponse())
      .mockResolvedValueOnce(jsonResponse(agreement()))
      .mockResolvedValueOnce(jsonResponse(events({
        id: 'event-new-version',
        version: '3AAABLblqZhA-substituted-version',
        date: '2026-07-17T21:30:00Z',
      })));

    const result = await adapter(fetchImpl).fetchFinalEvidence(request());

    expect(result).toMatchObject({
      kind: 'mismatch',
      reason_code: 'AGREEMENT_CHANGED_DURING_FETCH',
    });
    expect(result).not.toHaveProperty('evidence');
  });

  it('rejects roster equivocation around the PDF fetch', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(agreement()))
      .mockResolvedValueOnce(jsonResponse(events()))
      .mockResolvedValueOnce(pdfResponse())
      .mockResolvedValueOnce(jsonResponse(agreement({
        email: 'substituted@example.com',
      })))
      .mockResolvedValueOnce(jsonResponse(events()));

    const result = await adapter(fetchImpl).fetchFinalEvidence(request());

    expect(result).toMatchObject({
      kind: 'mismatch',
      reason_code: 'AGREEMENT_CHANGED_DURING_FETCH',
    });
    expect(result).not.toHaveProperty('document_bytes');
  });

  it('pins the PDF fetch to the authoritative version instead of provider latest', async () => {
    const substitutedBytes = new TextEncoder()
      .encode('%PDF-1.7\nsubstituted latest bytes\n%%EOF');
    const metadataUrl = `${API_ORIGIN}/api/rest/v6/agreements/${AGREEMENT_ID}`;
    const eventsUrl = `${metadataUrl}/events`;
    const versionedPdfUrl = `${metadataUrl}/combinedDocument`
      + `?versionId=${encodeURIComponent(AGREEMENT_VERSION)}`;
    const fetchImpl = vi.fn(async (url) => {
      if (url === metadataUrl) return jsonResponse(agreement());
      if (url === eventsUrl) return jsonResponse(events());
      return pdfResponse(url === versionedPdfUrl ? PDF_BYTES : substitutedBytes);
    });

    const result = await adapter(fetchImpl).fetchFinalEvidence(request());

    expect(result.kind).toBe('evidence_ready');
    expect(Array.from(result.document_bytes)).toEqual(Array.from(PDF_BYTES));
    expect(fetchImpl.mock.calls[2][0]).toBe(versionedPdfUrl);
    expect(result.evidence.document.sha256).not.toBe(
      `sha256:${createHash('sha256').update(substitutedBytes).digest('hex')}`,
    );
  });

  it('refuses event history without an authoritative agreement version', async () => {
    const unversionedEvents = events();
    delete unversionedEvents.events[0].versionId;
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(agreement()))
      .mockResolvedValueOnce(jsonResponse(unversionedEvents));

    const result = await adapter(fetchImpl).fetchFinalEvidence(request());

    expect(result).toMatchObject({
      kind: 'provider_error',
      reason_code: 'PROVIDER_RESPONSE_INVALID',
    });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('uses ETag only for metadata stability and the event version for document bytes', async () => {
    const etag = 'D27e5290dc3a748068e42a59f4dfc6f6b1d5eaba1';
    const metadataResponse = () => jsonResponse(
      agreement(),
      200,
      'application/json; charset=utf-8',
      { ETag: `"${etag}"` },
    );
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(metadataResponse())
      .mockResolvedValueOnce(jsonResponse(events()))
      .mockResolvedValueOnce(pdfResponse())
      .mockResolvedValueOnce(metadataResponse())
      .mockResolvedValueOnce(jsonResponse(events()));

    const result = await adapter(fetchImpl).fetchFinalEvidence(request());

    expect(result).toMatchObject({
      kind: 'evidence_ready',
      evidence: {
        agreement_version: AGREEMENT_VERSION,
      },
    });
    expect(fetchImpl.mock.calls[2][0]).toBe(
      `${API_ORIGIN}/api/rest/v6/agreements/${AGREEMENT_ID}/combinedDocument`
        + `?versionId=${encodeURIComponent(AGREEMENT_VERSION)}`,
    );
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
      .mockResolvedValueOnce(jsonResponse(events()))
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
      .mockResolvedValueOnce(jsonResponse(events()))
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
    for (const apiOrigin of [
      'https://example.com',
      'https://api.na1.adobesign.com.example.com',
      'https://secure.na1.adobesign.com',
      'https://api.attacker.adobesign.com',
    ]) {
      expect(() => createAcrobatSignAdapter({
        apiOrigin,
        oauthAccessToken: OAUTH_TOKEN,
        fetch: fetchImpl,
      })).toThrow(/Acrobat Sign/);
    }
    for (const apiOrigin of [
      'https://api.adobesign.com',
      'https://api.eu1.adobesign.com',
      'https://api.na1.echosign.com',
      'https://api.na1.adobesign.us',
    ]) {
      expect(() => createAcrobatSignAdapter({
        apiOrigin,
        oauthAccessToken: OAUTH_TOKEN,
        fetch: fetchImpl,
      })).not.toThrow();
    }

    const subject = adapter(fetchImpl);
    expect(subject).not.toHaveProperty('oauthAccessToken');
    expect(subject.api_origin).toBe(API_ORIGIN);
  });
});
