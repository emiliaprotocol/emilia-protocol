// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authorize: vi.fn(),
  create: vi.fn(),
  load: vi.fn(),
  revoke: vi.fn(),
}));

vi.mock('../app/api/adopt/session-cookie', () => ({
  authorizeAgentAdoptionRequest: mocks.authorize,
}));

vi.mock('@/lib/agent-record/service', () => ({
  AgentRecordServiceError: class AgentRecordServiceError extends Error {
    constructor(public status: number, public code: string, message = code) {
      super(message);
    }
  },
  createAgentRecord: mocks.create,
  loadPublicAgentRecord: mocks.load,
  revokeAgentRecord: mocks.revoke,
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

const CreateRoute = await import('../app/api/adopt/sessions/[sessionId]/records/route');
const PublicRoute = await import('../app/api/agent-records/[recordId]/route');
const RevokeRoute = await import('../app/api/agent-records/[recordId]/revoke/route');

const SESSION_ID = '00000000-0000-4000-8000-000000000001';
const SESSION_TOKEN = `eaa1_${'a'.repeat(64)}`;
const RECORD_ID = `agent_record_${'b'.repeat(40)}`;
const OWNER_TOKEN = `ear1_${'c'.repeat(64)}`;
const ATTEMPT_ID = `arena_attempt_${'d'.repeat(32)}`;
const TRIAL_TOKEN = `epenc:v1:${'e'.repeat(64)}`;
const authorization = Object.freeze({
  sessionId: SESSION_ID,
  sessionToken: SESSION_TOKEN,
  session: { adoption_id: SESSION_ID, status: 'active' },
});

function createRequest(body: unknown, headers: Record<string, string> = {}) {
  return new Request(
    `https://www.emiliaprotocol.ai/api/adopt/sessions/${SESSION_ID}/records`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(body),
    },
  );
}

const createParams = { params: { sessionId: SESSION_ID } };
const recordParams = { params: { recordId: RECORD_ID } };

describe('Agent Record HTTP contract', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mocks.authorize.mockResolvedValue(authorization);
  });

  it('authenticates the exact adoption session before creating one refusal-bound record', async () => {
    mocks.create.mockResolvedValue({
      record_id: RECORD_ID,
      created_at: '2026-08-03T00:00:00.000Z',
      retention_expires_at: '2027-08-03T00:00:00.000Z',
      public_projection: { '@version': 'EP-AGENT-RECORD-OBSERVATION-v1' },
    });

    const request = createRequest(
      {
        trial_token: TRIAL_TOKEN,
        attempt_id: ATTEMPT_ID,
        record_id: RECORD_ID,
        owner_token: OWNER_TOKEN,
      },
      { origin: 'https://www.emiliaprotocol.ai' },
    );
    const response = await CreateRoute.POST(request as never, createParams);

    expect(response.status).toBe(201);
    expect(mocks.authorize).toHaveBeenCalledWith({ request, sessionId: SESSION_ID });
    expect(mocks.create).toHaveBeenCalledWith({
      authorization,
      input: {
        trial_token: TRIAL_TOKEN,
        attempt_id: ATTEMPT_ID,
        record_id: RECORD_ID,
        owner_token: OWNER_TOKEN,
      },
    });
    const body = await response.json();
    expect(body).toMatchObject({ record_id: RECORD_ID });
    expect(JSON.stringify(body)).not.toContain(OWNER_TOKEN);
    expect(response.headers.get('cache-control')).toContain('no-store');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
  });

  it('authenticates before parsing attacker-controlled creation input', async () => {
    const ServiceError = (await import('@/lib/agent-record/service')).AgentRecordServiceError;
    mocks.authorize.mockRejectedValue(new ServiceError(401, 'agent_adoption_unauthorized'));
    const request = createRequest({ padding: 'x'.repeat(20_000) });

    const response = await CreateRoute.POST(request as never, createParams);

    expect(response.status).toBe(401);
    expect(request.bodyUsed).toBe(false);
    expect(mocks.create).not.toHaveBeenCalled();
  });

  it('returns one exact current record with no cache and never returns an owner token', async () => {
    mocks.load.mockResolvedValue({
      record_id: RECORD_ID,
      public_projection: {
        '@version': 'EP-AGENT-RECORD-OBSERVATION-v1',
        record: { claim_boundary: 'fact-only' },
      },
      verification: { integrity_verified: true, currently_public: true },
    });

    const response = await PublicRoute.GET(
      new Request(`https://www.emiliaprotocol.ai/api/agent-records/${RECORD_ID}`),
      recordParams,
    );

    expect(response.status).toBe(200);
    expect(mocks.load).toHaveBeenCalledWith({ recordId: RECORD_ID });
    const body = await response.json();
    expect(body.record_id).toBe(RECORD_ID);
    expect(JSON.stringify(body)).not.toContain('ear1_');
    expect(response.headers.get('cache-control')).toContain('no-store');
    expect(response.headers.get('content-security-policy')).toContain("default-src 'none'");
  });

  it('makes unknown, revoked, expired, and malformed public records indistinguishable', async () => {
    for (const recordId of [RECORD_ID, `agent_record_${'f'.repeat(40)}`, 'not-a-record']) {
      mocks.load.mockResolvedValueOnce(null);
      const response = await PublicRoute.GET(
        new Request(`https://www.emiliaprotocol.ai/api/agent-records/${recordId}`),
        { params: { recordId } },
      );
      expect(response.status).toBe(404);
      expect(await response.json()).toMatchObject({
        type: 'https://emiliaprotocol.ai/errors/agent_record_not_found',
        status: 404,
      });
    }
  });

  it('revokes only with a header-held record-specific owner token', async () => {
    mocks.revoke.mockResolvedValue({
      record_id: RECORD_ID,
      revoked: true,
      revoked_at: '2026-08-03T00:01:00.000Z',
    });
    const request = new Request(
      `https://www.emiliaprotocol.ai/api/agent-records/${RECORD_ID}/revoke`,
      {
        method: 'POST',
        headers: {
          authorization: `Bearer ${OWNER_TOKEN}`,
          origin: 'https://www.emiliaprotocol.ai',
        },
      },
    );

    const response = await RevokeRoute.POST(request, recordParams);

    expect(response.status).toBe(200);
    expect(mocks.revoke).toHaveBeenCalledWith({ recordId: RECORD_ID, ownerToken: OWNER_TOKEN });
    expect(await response.json()).toMatchObject({ record_id: RECORD_ID, revoked: true });
    expect(response.headers.get('cache-control')).toContain('no-store');
  });

  it('normalizes missing or wrong owner credentials to the same not-found response', async () => {
    const ServiceError = (await import('@/lib/agent-record/service')).AgentRecordServiceError;
    mocks.revoke.mockRejectedValue(new ServiceError(404, 'agent_record_not_found'));

    for (const authorizationHeader of [undefined, 'Bearer wrong']) {
      const response = await RevokeRoute.POST(
        new Request(`https://www.emiliaprotocol.ai/api/agent-records/${RECORD_ID}/revoke`, {
          method: 'POST',
          headers: {
            origin: 'https://www.emiliaprotocol.ai',
            ...(authorizationHeader ? { authorization: authorizationHeader } : {}),
          },
        }),
        recordParams,
      );
      expect(response.status).toBe(404);
      expect(await response.json()).toMatchObject({
        type: 'https://emiliaprotocol.ai/errors/agent_record_not_found',
        status: 404,
      });
    }
  });
});

describe('Agent Record UI and custody contract', () => {
  const adopt = readFileSync(resolve('app/adopt/AdoptExperience.tsx'), 'utf8');
  const page = readFileSync(resolve('app/agent-record/r/[recordId]/page.tsx'), 'utf8');
  const controls = readFileSync(resolve('app/agent-record/r/[recordId]/OwnerControls.tsx'), 'utf8');

  it('creates only after an explicit confirmation of a refused trial attempt', () => {
    expect(adopt).toContain("latestAttempt.decision === 'refuse'");
    expect(adopt).toContain('recordConfirmed');
    expect(adopt).toContain('/records');
    expect(adopt).toContain('trial_token: session.trial_token');
    expect(adopt).toContain('attempt_id: attempt.attempt_id');
    expect(adopt).not.toContain("latestAttempt.decision === 'permit' && create");
  });

  it('keeps the owner token only in record-specific local storage and out of URLs and analytics', () => {
    expect(adopt).toContain('emilia_agent_record_owner:');
    expect(adopt).toContain('window.localStorage.setItem(ownerKey(record.record_id), credential.owner_token)');
    expect(adopt).toContain('window.localStorage.setItem(storageKey');
    expect(adopt).not.toContain('record.owner_token');
    expect(adopt).not.toMatch(/searchParams[^\n]+owner_token/);
    expect(adopt).not.toMatch(/emitAdoptEvent\([^)]*owner_token/);
    expect(controls).toContain('window.localStorage.getItem(ownerKey(recordId))');
    expect(controls).toContain('authorization: `Bearer ${ownerToken}`');
    expect(controls).not.toContain('document.cookie');
  });

  it('states the narrow fact-only claim and rejects directory or reputation framing', () => {
    const publicSurface = `${page}\n${controls}`;
    expect(publicSurface).toContain('one verified Arena refusal');
    expect(publicSurface).toMatch(/one\s+Operating Bond/);
    for (const boundary of [
      'not identity',
      'not certification',
      'not marketplace reputation',
      'not production coverage',
      'not future authorization',
    ]) {
      expect(publicSurface.toLowerCase()).toContain(boundary);
    }
    expect(publicSurface).not.toMatch(/leaderboard|score|rank|search agents|browse agents/i);
    expect(page).toContain("`/pilot?artifact_id=${encodeURIComponent(recordId)}`");
  });
});
