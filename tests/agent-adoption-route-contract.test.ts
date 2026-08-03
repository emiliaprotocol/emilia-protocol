// SPDX-License-Identifier: Apache-2.0
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authorize: vi.fn(),
  createSession: vi.fn(),
  registrationOptions: vi.fn(),
  registrationVerify: vi.fn(),
  assertionOptions: vi.fn(),
  assertionVerify: vi.fn(),
  provisionTrial: vi.fn(),
  attemptTrial: vi.fn(),
  publishBond: vi.fn(),
  revoke: vi.fn(),
  loadShare: vi.fn(),
}));

vi.mock('@/lib/agent-adoption/service', () => ({
  AgentAdoptionServiceError: class AgentAdoptionServiceError extends Error {
    constructor(public status: number, public code: string, message = code) { super(message); }
  },
  authorizeAgentAdoptionSession: mocks.authorize,
  createAgentAdoptionSession: mocks.createSession,
  createAgentAdoptionRegistrationCeremony: mocks.registrationOptions,
  completeAgentAdoptionRegistration: mocks.registrationVerify,
  createAgentAdoptionAssertionCeremony: mocks.assertionOptions,
  completeAgentAdoptionAssertion: mocks.assertionVerify,
  provisionAgentAdoptionTrial: mocks.provisionTrial,
  attemptAgentAdoptionTrial: mocks.attemptTrial,
  publishAgentAdoptionBond: mocks.publishBond,
  revokeAgentAdoption: mocks.revoke,
  loadPublicAgentAdoptionBond: mocks.loadShare,
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

const Sessions = await import('../app/api/adopt/sessions/route');
const SessionRecovery = await import('../app/api/adopt/sessions/[sessionId]/route');
const RegistrationOptions = await import(
  '../app/api/adopt/sessions/[sessionId]/passkey/register/options/route'
);
const RegistrationVerify = await import(
  '../app/api/adopt/sessions/[sessionId]/passkey/register/verify/route'
);
const AssertionOptions = await import(
  '../app/api/adopt/sessions/[sessionId]/passkey/assert/options/route'
);
const AssertionVerify = await import(
  '../app/api/adopt/sessions/[sessionId]/passkey/assert/verify/route'
);
const Trial = await import('../app/api/adopt/sessions/[sessionId]/trial/route');
const Attempts = await import('../app/api/adopt/sessions/[sessionId]/attempts/route');
const Share = await import('../app/api/adopt/sessions/[sessionId]/share/route');
const Revoke = await import('../app/api/adopt/sessions/[sessionId]/revoke/route');
const PublicShare = await import('../app/api/adopt/shares/[shareId]/route');

const SESSION_ID = '00000000-0000-4000-8000-000000000001';
const SESSION_TOKEN = `eaa1_${'a'.repeat(64)}`;
const authorization = Object.freeze({
  sessionId: SESSION_ID,
  sessionToken: SESSION_TOKEN,
  session: { adoption_id: SESSION_ID, status: 'active' },
});

function request(path: string, body?: unknown): Request {
  return new Request(`https://www.emiliaprotocol.ai${path}`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${SESSION_TOKEN}`,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

const params = { params: { sessionId: SESSION_ID } };

describe('Agent Adoption route contract', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mocks.authorize.mockResolvedValue(authorization);
  });

  it('creates a bounded session with no-store response headers', async () => {
    mocks.createSession.mockResolvedValue({
      session_id: SESSION_ID,
      session_token: SESSION_TOKEN,
      expires_at: '2099-08-02T00:00:00.000Z',
      authority_state: 'draft',
      passkey_registered: false,
      passkey_asserted: false,
    });
    const response = await Sessions.POST(request('/api/adopt/sessions', {
      label: 'Atlas',
      source_kind: 'local',
      job_template_id: 'job_vendor_intake_v1',
      allowance_template_id: 'allowance_cautious_v1',
    }) as any);

    expect(response.status).toBe(201);
    expect(response.headers.get('cache-control')).toContain('no-store');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
    const sessionCookie = response.headers.get('set-cookie') ?? '';
    expect(sessionCookie).toContain('__Secure-emilia-adoption-session=');
    expect(sessionCookie).toContain('HttpOnly');
    expect(sessionCookie).toContain('Secure');
    expect(sessionCookie).toContain('SameSite=strict');
    expect(sessionCookie).toContain('Path=/api/adopt/');
    expect(JSON.stringify(await response.json())).not.toContain(SESSION_TOKEN);
    expect(mocks.createSession).toHaveBeenCalledTimes(1);
  });

  it('normalizes unexpected service failures without exposing their details', async () => {
    mocks.createSession.mockRejectedValueOnce(new Error('private backend detail'));
    const response = await Sessions.POST(request('/api/adopt/sessions', {
      label: 'Atlas',
      source_kind: 'local',
      job_template_id: 'job_vendor_intake_v1',
      allowance_template_id: 'allowance_cautious_v1',
    }) as any);

    expect(response.status).toBe(503);
    expect(JSON.stringify(await response.json())).not.toContain('private backend detail');
  });

  it('recovers non-secret session state from the HttpOnly cookie without returning the bearer', async () => {
    mocks.authorize.mockImplementationOnce(async ({ request }: { request: Request }) => {
      expect(request.headers.get('authorization')).toBe(`Bearer ${SESSION_TOKEN}`);
      return {
        ...authorization,
        session: {
          adoption_id: SESSION_ID,
          status: 'active',
          expires_at: '2099-08-02T00:00:00.000Z',
          credential_count: 1,
          bond_count: 1,
          latest_bond_id: SESSION_ID,
          latest_bond_digest: `sha256:${'b'.repeat(64)}`,
          bond_digest: `sha256:${'b'.repeat(64)}`,
          operating_bond: {
            candidate: {
              label: 'Atlas',
              source_kind: 'local',
              job_template_id: 'job_vendor_intake_v1',
              allowance_template_id: 'allowance_cautious_v1',
            },
          },
        },
      };
    });
    const response = await SessionRecovery.GET(new Request(
      `https://www.emiliaprotocol.ai/api/adopt/sessions/${SESSION_ID}`,
      { headers: { cookie: `__Secure-emilia-adoption-session=${SESSION_ID}.${SESSION_TOKEN}` } },
    ) as any, params);

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toMatchObject({
      session_id: SESSION_ID,
      authority_state: 'asserted',
      passkey_registered: true,
      passkey_asserted: true,
      recovery: { label: 'Atlas', source_kind: 'local' },
    });
    expect(JSON.stringify(body)).not.toContain(SESSION_TOKEN);
    expect(JSON.stringify(body)).not.toContain('credential_id');
    expect(response.headers.get('cache-control')).toContain('no-store');
  });

  it('reports durable passkey registration separately from assertion without returning its credential ID', async () => {
    mocks.authorize.mockResolvedValueOnce({
      ...authorization,
      session: {
        adoption_id: SESSION_ID,
        status: 'active',
        expires_at: '2099-08-02T00:00:00.000Z',
        credential_count: 1,
        bond_count: 0,
        bond_digest: `sha256:${'b'.repeat(64)}`,
        operating_bond: { candidate: { label: 'Atlas' } },
      },
    });
    const response = await SessionRecovery.GET(new Request(
      `https://www.emiliaprotocol.ai/api/adopt/sessions/${SESSION_ID}`,
      { headers: { authorization: `Bearer ${SESSION_TOKEN}` } },
    ) as any, params);

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toMatchObject({
      session_id: SESSION_ID,
      authority_state: 'draft',
      passkey_registered: true,
      passkey_asserted: false,
    });
    expect(JSON.stringify(body)).not.toContain('credential_id');
    expect(JSON.stringify(body)).not.toContain(SESSION_TOKEN);
  });

  it('requires exact same-origin for cookie-authenticated mutations', async () => {
    mocks.provisionTrial.mockResolvedValue({ session_id: SESSION_ID, passkey_asserted: true });
    mocks.authorize.mockImplementation(async ({ request }: { request: Request }) => {
      expect(request.headers.get('authorization')).toBe(`Bearer ${SESSION_TOKEN}`);
      return authorization;
    });
    const cookie = `__Secure-emilia-adoption-session=${SESSION_ID}.${SESSION_TOKEN}`;
    const url = `https://www.emiliaprotocol.ai/api/adopt/sessions/${SESSION_ID}/trial`;

    const accepted = await Trial.POST(new Request(url, {
      method: 'POST',
      headers: { cookie, origin: 'https://www.emiliaprotocol.ai' },
    }) as any, params);
    expect(accepted.status).toBe(201);
    expect(mocks.provisionTrial).toHaveBeenCalledTimes(1);

    for (const origin of [undefined, 'https://evil.emiliaprotocol.ai']) {
      mocks.provisionTrial.mockClear();
      mocks.authorize.mockClear();
      const denied = await Trial.POST(new Request(url, {
        method: 'POST',
        headers: { cookie, ...(origin ? { origin } : {}) },
      }) as any, params);
      expect(denied.status).toBe(401);
      expect(mocks.authorize).not.toHaveBeenCalled();
      expect(mocks.provisionTrial).not.toHaveBeenCalled();
    }
  });

  it('authenticates before reading a registration response body', async () => {
    const ServiceError = (await import('@/lib/agent-adoption/service')).AgentAdoptionServiceError;
    mocks.authorize.mockRejectedValue(new ServiceError(401, 'agent_adoption_unauthorized'));
    const largeBody = { attestation: 'x'.repeat(310 * 1024) };
    const req = request(`/api/adopt/sessions/${SESSION_ID}/passkey/register/verify`, largeBody);

    const response = await RegistrationVerify.POST(req as any, params);

    expect(response.status).toBe(401);
    expect(req.bodyUsed).toBe(false);
    expect(mocks.registrationVerify).not.toHaveBeenCalled();
  });

  it('keeps registration and assertion ceremonies separate', async () => {
    mocks.registrationOptions.mockResolvedValue({ ceremony_token: 'sealed-registration', options: {} });
    mocks.assertionOptions.mockResolvedValue({ ceremony_token: 'sealed-assertion', options: {} });

    const registration = await RegistrationOptions.POST(
      request(`/api/adopt/sessions/${SESSION_ID}/passkey/register/options`) as any,
      params,
    );
    const assertion = await AssertionOptions.POST(
      request(`/api/adopt/sessions/${SESSION_ID}/passkey/assert/options`, {
        credential_id: 'credential-id-1234',
      }) as any,
      params,
    );

    expect((await registration.json()).ceremony_token).toBe('sealed-registration');
    expect((await assertion.json()).ceremony_token).toBe('sealed-assertion');
    expect(mocks.registrationOptions).toHaveBeenCalledWith({ authorization });
    expect(mocks.assertionOptions).toHaveBeenCalledWith(expect.objectContaining({ authorization }));
  });

  it('passes only authenticated parsed ceremony responses to verification', async () => {
    mocks.registrationVerify.mockResolvedValue({ credential_id: 'credential-id-1234' });
    mocks.assertionVerify.mockResolvedValue({
      session_id: SESSION_ID,
      authority_state: 'asserted',
      passkey_asserted: true,
    });

    const registrationInput = { ceremony_token: 'sealed-registration', attestation: { id: 'one' } };
    const assertionInput = { ceremony_token: 'sealed-assertion', assertion: { id: 'one' } };
    const registration = await RegistrationVerify.POST(
      request(`/api/adopt/sessions/${SESSION_ID}/passkey/register/verify`, registrationInput) as any,
      params,
    );
    const assertion = await AssertionVerify.POST(
      request(`/api/adopt/sessions/${SESSION_ID}/passkey/assert/verify`, assertionInput) as any,
      params,
    );

    expect(registration.status).toBe(201);
    expect(assertion.status).toBe(200);
    expect(JSON.stringify(await assertion.json())).not.toContain(SESSION_TOKEN);
    expect(mocks.registrationVerify).toHaveBeenCalledWith({ authorization, input: registrationInput });
    expect(mocks.assertionVerify).toHaveBeenCalledWith({ authorization, input: assertionInput });
  });

  it('never mirrors the bearer from trial provisioning into browser JSON', async () => {
    mocks.provisionTrial.mockResolvedValue({
      session_id: SESSION_ID,
      session_token: SESSION_TOKEN,
      passkey_asserted: true,
    });
    const response = await Trial.POST(
      request(`/api/adopt/sessions/${SESSION_ID}/trial`) as any,
      params,
    );
    expect(response.status).toBe(201);
    expect(JSON.stringify(await response.json())).not.toContain(SESSION_TOKEN);
  });

  it('provisions a separate opaque no-egress trial only after authorization', async () => {
    mocks.provisionTrial.mockResolvedValue({ trial_token: 'epenc:v1:opaque' });
    const response = await Trial.POST(
      request(`/api/adopt/sessions/${SESSION_ID}/trial`) as any,
      params,
    );
    expect(response.status).toBe(201);
    expect(mocks.provisionTrial).toHaveBeenCalledWith({ authorization });
    expect((await response.json()).trial_token).toBe('epenc:v1:opaque');
  });

  it('does not let callers supply a decision to the attempt service', async () => {
    const input = {
      attempt_template_id: 'attempt_over_limit_v1',
      trial_token: 'epenc:v1:opaque',
    };
    mocks.attemptTrial.mockResolvedValue({ decision: 'refuse', reason_code: 'per_action_limit_exceeded' });
    const response = await Attempts.POST(
      request(`/api/adopt/sessions/${SESSION_ID}/attempts`, input) as any,
      params,
    );
    expect(response.status).toBe(201);
    expect(mocks.attemptTrial).toHaveBeenCalledWith({ authorization, input });
  });

  it('publishes and revokes through separate authenticated operations', async () => {
    mocks.publishBond.mockResolvedValue({ share_url: `/adopt/r/agent_share_${'1'.repeat(40)}` });
    mocks.revoke.mockResolvedValue({ authority_state: 'revoked' });

    const publication = await Share.POST(
      request(`/api/adopt/sessions/${SESSION_ID}/share`, { bond_id: SESSION_ID }) as any,
      params,
    );
    const revocation = await Revoke.POST(
      request(`/api/adopt/sessions/${SESSION_ID}/revoke`) as any,
      params,
    );

    expect(publication.status).toBe(201);
    expect(revocation.status).toBe(200);
    expect(mocks.publishBond).toHaveBeenCalledTimes(1);
    expect(mocks.revoke).toHaveBeenCalledTimes(1);
  });

  it('makes unknown and revoked public shares non-enumerable', async () => {
    mocks.loadShare.mockResolvedValue(null);
    const response = await PublicShare.GET(new Request('https://example.test'), {
      params: { shareId: `agent_share_${'2'.repeat(40)}` },
    });
    expect(response.status).toBe(404);
  });

  it('serves an active projection with restrictive public headers', async () => {
    mocks.loadShare.mockResolvedValue({
      share_id: `agent_share_${'3'.repeat(40)}`,
      revoked: false,
      projection: { '@version': 'EP-OPERATING-BOND-PUBLIC-v1' },
    });
    const response = await PublicShare.GET(new Request('https://example.test'), {
      params: { shareId: `agent_share_${'3'.repeat(40)}` },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get('content-security-policy')).toContain("default-src 'none'");
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
    expect(response.headers.get('cache-control')).toBe('no-store, max-age=0');
    expect(response.headers.get('pragma')).toBe('no-cache');
  });
});
