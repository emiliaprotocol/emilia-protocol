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

  it.each([
    ['missing expectation', (input) => {
      input.expected = null;
      return input;
    }],
    ['invalid agreement id', (input) => {
      input.expected.agreementId = '';
      return input;
    }],
    ['wrong required status', (input) => {
      input.expected.status = 'OUT_FOR_SIGNATURE';
      return input;
    }],
    ['missing participant array', (input) => {
      input.expected.participantSets = null;
      return input;
    }],
    ['empty participant array', (input) => {
      input.expected.participantSets = [];
      return input;
    }],
    ['too many participant sets', (input) => {
      input.expected.participantSets = Array.from(
        { length: 101 },
        (_, index) => ({
          id: `participant-set-${index}`,
          role: 'SIGNER',
          order: index,
          members: [{ email: `signer-${index}@example.com`, status: 'COMPLETED' }],
        }),
      );
      return input;
    }],
    ['non-object participant set', (input) => {
      input.expected.participantSets[0] = null;
      return input;
    }],
    ['invalid participant set id', (input) => {
      input.expected.participantSets[0].id = '';
      return input;
    }],
    ['invalid signing order', (input) => {
      input.expected.participantSets[0].order = '01';
      return input;
    }],
    ['missing members', (input) => {
      input.expected.participantSets[0].members = null;
      return input;
    }],
    ['multiple signing-group members', (input) => {
      input.expected.participantSets[0].members.push({
        email: 'second@example.com',
        status: 'COMPLETED',
      });
      return input;
    }],
    ['duplicate participant set id', (input) => {
      input.expected.participantSets.push({
        ...input.expected.participantSets[0],
        members: [{ email: 'second@example.com', status: 'COMPLETED' }],
      });
      return input;
    }],
    ['non-object signer', (input) => {
      input.expected.participantSets[0].members[0] = null;
      return input;
    }],
    ['invalid signer email', (input) => {
      input.expected.participantSets[0].members[0].email = 'not-an-email';
      return input;
    }],
    ['non-string signer status', (input) => {
      input.expected.participantSets[0].members[0].status = 7;
      return input;
    }],
    ['incomplete expected signer', (input) => {
      input.expected.participantSets[0].members[0].status = 'ACTIVE';
      return input;
    }],
  ])('refuses %s before contacting Acrobat Sign', async (_label, mutate) => {
    const fetchImpl = vi.fn();
    const base = request();
    const input = mutate(base);
    await expect(adapter(fetchImpl).fetchFinalEvidence(input))
      .resolves.toMatchObject({
        kind: 'refused',
        reason_code: 'INVALID_EXPECTATION',
      });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('normalizes alternate provider shapes without weakening signer-seat matching', async () => {
    const input = request();
    delete input.expected.participantSets[0].members[0].status;
    input.expected.participantSets[0].order = '1';
    input.expected.participantSets.push({
      id: 'participant-set-0',
      role: 'signer',
      order: 1,
      members: [{ email: 'SECOND@example.com' }],
    });
    const providerSets = [
      {
        id: 'participant-set-1',
        role: 'signer',
        order: '1',
        memberInfos: [{ email: 'SIGNER@example.com', status: 'completed' }],
      },
      {
        id: 'participant-set-0',
        role: 'SIGNER',
        order: 1,
        memberInfos: [{ email: 'second@example.com', extendedStatus: 'completed' }],
      },
    ];
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(agreement({
        participantSetsInfo: { participantSets: providerSets },
      })))
      .mockResolvedValueOnce(jsonResponse(events()))
      .mockResolvedValueOnce(pdfResponse())
      .mockResolvedValueOnce(jsonResponse(agreement({
        participantSetsInfo: { participantSets: providerSets },
      })))
      .mockResolvedValueOnce(jsonResponse(events()));

    const result = await adapter(fetchImpl).fetchFinalEvidence(input);

    expect(result.kind).toBe('evidence_ready');
    expect(result.evidence.participant_sets.map((set) => set.set_id))
      .toEqual(['participant-set-0', 'participant-set-1']);
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
    ['non-object agreement', null, {}],
    ['invalid agreement id', agreement({ id: '' }), {}],
    ['invalid agreement status', agreement({ status: null }), {}],
    ['weak metadata ETag', agreement(), { ETag: 'W/"weak"' }],
    ['half-quoted metadata ETag', agreement(), { ETag: '"unterminated' }],
    ['embedded-quote metadata ETag', agreement(), { ETag: 'bad"token' }],
    ['missing participant sets', {
      ...agreement(),
      participantSetsInfo: null,
    }, {}],
    ['empty participant sets', agreement({ participantSetsInfo: [] }), {}],
    ['non-object participant set', agreement({ participantSetsInfo: [null] }), {}],
    ['invalid participant set id', agreement({
      participantSetsInfo: [{
        id: '',
        role: 'SIGNER',
        order: 1,
        memberInfos: [{ email: 'signer@example.com', extendedStatus: 'COMPLETED' }],
      }],
    }), {}],
    ['unknown participant role', agreement({ role: 'OWNER' }), {}],
    ['invalid participant order', agreement({
      participantSetsInfo: [{
        id: 'participant-set-1',
        role: 'SIGNER',
        order: '01',
        memberInfos: [{ email: 'signer@example.com', extendedStatus: 'COMPLETED' }],
      }],
    }), {}],
    ['missing member infos', agreement({
      participantSetsInfo: [{
        id: 'participant-set-1',
        role: 'SIGNER',
        order: 1,
      }],
    }), {}],
    ['duplicate participant set ids', agreement({
      participantSetsInfo: [
        {
          id: 'duplicate',
          role: 'SIGNER',
          order: 1,
          memberInfos: [{ email: 'signer@example.com', extendedStatus: 'COMPLETED' }],
        },
        {
          id: 'duplicate',
          role: 'SIGNER',
          order: 2,
          memberInfos: [{ email: 'second@example.com', extendedStatus: 'COMPLETED' }],
        },
      ],
    }), {}],
    ['non-object member', agreement({ memberInfos: [null] }), {}],
    ['invalid member email', agreement({ email: 'not-an-email' }), {}],
    ['non-string member status', agreement({
      memberInfos: [{ email: 'signer@example.com', status: 7 }],
    }), {}],
    ['invalid extended member status', agreement({
      memberInfos: [{
        email: 'signer@example.com',
        status: 'ACTIVE',
        extendedStatus: 'COMPLETED\u0000',
      }],
    }), {}],
    ['missing effective member status', agreement({
      memberInfos: [{ email: 'signer@example.com' }],
    }), {}],
  ])('fails closed on provider metadata with %s', async (_label, body, headers) => {
    const fetchImpl = vi.fn(async () => jsonResponse(
      body,
      200,
      'application/json',
      headers,
    ));
    await expect(adapter(fetchImpl).fetchFinalEvidence(request()))
      .resolves.toMatchObject({
        kind: 'provider_error',
        operation: 'fetch_agreement',
        reason_code: 'PROVIDER_RESPONSE_INVALID',
      });
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it.each([
    ['non-object event response', null],
    ['missing events array', {}],
    ['empty events array', { events: [] }],
    ['non-object event', { events: [null] }],
    ['invalid event id', events({ id: '' })],
    ['invalid event type', events({ type: '' })],
    ['invalid event date', events({ date: 'not-a-date' })],
    ['whitespace in version token', events({ version: 'version with spaces' })],
    ['duplicate event ids', {
      events: [
        events().events[0],
        { ...events().events[0], date: '2026-07-17T21:30:00Z' },
      ],
    }],
    ['equivocal versions at the latest instant', {
      events: [
        events({ id: 'event-a', version: 'version-a' }).events[0],
        events({ id: 'event-b', version: 'version-b' }).events[0],
      ],
    }],
  ])('fails closed on event history with %s', async (_label, eventBody) => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(agreement()))
      .mockResolvedValueOnce(jsonResponse(eventBody));
    await expect(adapter(fetchImpl).fetchFinalEvidence(request()))
      .resolves.toMatchObject({
        kind: 'provider_error',
        operation: 'fetch_agreement_events',
        reason_code: 'PROVIDER_RESPONSE_INVALID',
      });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it.each([
    ['initial agreement', 0, 'fetch_agreement'],
    ['initial events', 1, 'fetch_agreement_events'],
    ['final document', 2, 'fetch_final_document'],
    ['agreement recheck', 3, 'refetch_agreement'],
    ['event recheck', 4, 'refetch_agreement_events'],
  ])('classifies a thrown fetch during %s', async (_label, failureIndex, operation) => {
    const responses = [
      () => jsonResponse(agreement()),
      () => jsonResponse(events()),
      () => pdfResponse(),
      () => jsonResponse(agreement()),
      () => jsonResponse(events()),
    ];
    const fetchImpl = vi.fn(async () => {
      const index = fetchImpl.mock.calls.length - 1;
      if (index === failureIndex) throw new Error('provider transport failed');
      return responses[index]();
    });

    await expect(adapter(fetchImpl).fetchFinalEvidence(request()))
      .resolves.toMatchObject({
        kind: 'provider_error',
        operation,
        reason_code: 'PROVIDER_UNAVAILABLE',
      });
    expect(fetchImpl).toHaveBeenCalledTimes(failureIndex + 1);
  });

  it.each([
    ['initial agreement', 0, 'fetch_agreement'],
    ['initial events', 1, 'fetch_agreement_events'],
    ['final document', 2, 'fetch_final_document'],
    ['agreement recheck', 3, 'refetch_agreement'],
    ['event recheck', 4, 'refetch_agreement_events'],
  ])('preserves a provider HTTP error during %s', async (_label, failureIndex, operation) => {
    const responses = [
      () => jsonResponse(agreement()),
      () => jsonResponse(events()),
      () => pdfResponse(),
      () => jsonResponse(agreement()),
      () => jsonResponse(events()),
    ];
    const fetchImpl = vi.fn(async () => {
      const index = fetchImpl.mock.calls.length - 1;
      if (index === failureIndex) return new Response('unavailable', { status: 503 });
      return responses[index]();
    });

    await expect(adapter(fetchImpl).fetchFinalEvidence(request()))
      .resolves.toMatchObject({
        kind: 'provider_error',
        operation,
        reason_code: 'PROVIDER_HTTP_ERROR',
        http_status: 503,
      });
  });

  it.each([0, 1, 2, 3, 4])('rejects a PDF truncated to %i bytes', async (length) => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(agreement()))
      .mockResolvedValueOnce(jsonResponse(events()))
      .mockResolvedValueOnce(pdfResponse(PDF_BYTES.slice(0, length)));
    await expect(adapter(fetchImpl).fetchFinalEvidence(request()))
      .resolves.toMatchObject({
        kind: 'mismatch',
        reason_code: 'FINAL_DOCUMENT_NOT_PDF',
      });
  });

  it.each([
    ['metadata ETag substitution', () => jsonResponse(
      agreement(),
      200,
      'application/json',
      { ETag: '"changed"' },
    )],
    ['same-version event-history substitution', () => jsonResponse(events({
      id: 'substituted-event',
    }))],
  ])('detects %s across the document fetch', async (_label, changedResponse) => {
    const initialMetadata = jsonResponse(
      agreement(),
      200,
      'application/json',
      { ETag: '"initial"' },
    );
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(initialMetadata)
      .mockResolvedValueOnce(jsonResponse(events()))
      .mockResolvedValueOnce(pdfResponse())
      .mockResolvedValueOnce(
        _label === 'metadata ETag substitution'
          ? changedResponse()
          : jsonResponse(agreement(), 200, 'application/json', { ETag: '"initial"' }),
      )
      .mockResolvedValueOnce(
        _label === 'same-version event-history substitution'
          ? changedResponse()
          : jsonResponse(events()),
      );

    await expect(adapter(fetchImpl).fetchFinalEvidence(request()))
      .resolves.toMatchObject({
        kind: 'mismatch',
        reason_code: 'AGREEMENT_CHANGED_DURING_FETCH',
      });
  });

  it.each([
    ['throwing clock', () => {
      throw new Error('clock unavailable');
    }],
    ['malformed clock', () => '2026-07-17T21:30:00Z'],
  ])('refuses evidence when using a %s', async (_label, clock) => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(agreement()))
      .mockResolvedValueOnce(jsonResponse(events()))
      .mockResolvedValueOnce(pdfResponse())
      .mockResolvedValueOnce(jsonResponse(agreement()))
      .mockResolvedValueOnce(jsonResponse(events()));
    await expect(adapter(fetchImpl, { clock }).fetchFinalEvidence(request()))
      .resolves.toMatchObject({
        kind: 'refused',
        reason_code: 'INVALID_CLOCK',
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

  it('rejects invalid constructor dependencies and bounds', () => {
    const fetchImpl = vi.fn();
    for (const oauthAccessToken of [null, '', 'token with spaces', 'x'.repeat(8193)]) {
      expect(() => createAcrobatSignAdapter({
        apiOrigin: API_ORIGIN,
        oauthAccessToken,
        fetch: fetchImpl,
      })).toThrow(/oauthAccessToken/);
    }
    expect(() => createAcrobatSignAdapter({
      apiOrigin: API_ORIGIN,
      oauthAccessToken: OAUTH_TOKEN,
      fetch: null,
    })).toThrow(/fetch/);
    expect(() => createAcrobatSignAdapter({
      apiOrigin: API_ORIGIN,
      oauthAccessToken: OAUTH_TOKEN,
      fetch: fetchImpl,
      clock: null,
    })).toThrow(/clock/);
    expect(() => adapter(fetchImpl, { maxMetadataBytes: 0 })).toThrow(/maxMetadataBytes/);
    expect(() => adapter(fetchImpl, { maxDocumentBytes: 0 })).toThrow(/maxDocumentBytes/);
    expect(() => adapter(fetchImpl, { timeoutMs: 0 })).toThrow(/timeoutMs/);
  });
});
