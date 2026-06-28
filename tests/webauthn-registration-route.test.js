// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockAuthenticateRequest = vi.fn();
const mockGetGuardedClient = vi.fn();
const mockGenerateRegistrationOptions = vi.fn();
const mockVerifyRegistrationResponse = vi.fn();

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: (...args) => mockAuthenticateRequest(...args),
  authEntityId: (auth) => {
    const e = auth?.entity;
    return typeof e === 'string' ? e : e?.entity_id || e?.id || '';
  },
}));

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args) => mockGetGuardedClient(...args),
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

vi.mock('@simplewebauthn/server', () => ({
  generateRegistrationOptions: (...args) => mockGenerateRegistrationOptions(...args),
  verifyRegistrationResponse: (...args) => mockVerifyRegistrationResponse(...args),
}));

vi.mock('@/lib/webauthn', () => ({
  getRpConfig: () => ({ rpName: 'EMILIA Protocol', rpID: 'example.com', origin: 'https://example.com' }),
  APPROVER_ID_PATTERN: /^[A-Za-z0-9:_.@-]{3,128}$/,
  CHALLENGE_TTL_MS: 300000,
  coseToSpkiP256: () => Buffer.from('mock-spki'),
}));

const RegisterOptions = await import('../app/api/v1/approvers/webauthn/register-options/route.js');
const RegisterVerify = await import('../app/api/v1/approvers/webauthn/register-verify/route.js');

function req(body) {
  return { json: () => Promise.resolve(body ?? {}) };
}

function authed(entity) {
  mockAuthenticateRequest.mockResolvedValue({ entity });
}

function makeClient({ challenges = [] } = {}) {
  const calls = { inserts: [], selects: [], updates: [] };
  function builder(table) {
    const state = { table, eq: {}, is: {} };
    const b = {
      select() { return b; },
      eq(k, v) { state.eq[k] = v; return b; },
      is(k, v) { state.is[k] = v; return b; },
      order() { return b; },
      limit() { return b; },
      insert: vi.fn(async (payload) => {
        calls.inserts.push({ table, payload });
        return { error: null };
      }),
      update(patch) { calls.updates.push({ table, patch, state }); return b; },
      then(resolve, reject) {
        try {
          calls.selects.push({ ...state });
          return resolve({ data: table === 'webauthn_challenges' ? challenges : [], error: null });
        } catch (e) {
          return reject(e);
        }
      },
    };
    return b;
  }
  return { client: { from: (table) => builder(table) }, calls };
}

describe('WebAuthn registration route org binding red-team regressions', () => {
  beforeEach(() => {
    mockAuthenticateRequest.mockReset();
    mockGetGuardedClient.mockReset();
    mockGenerateRegistrationOptions.mockReset();
    mockVerifyRegistrationResponse.mockReset();
    mockGenerateRegistrationOptions.mockResolvedValue({ challenge: 'reg_challenge' });
  });

  it('rejects registration enrollment when the API key is not organization-bound', async () => {
    authed({ entity_id: 'ep_entity_unbound' });
    const { client, calls } = makeClient();
    mockGetGuardedClient.mockReturnValue(client);

    const res = await RegisterOptions.POST(req({ approver_id: 'cfo@example.com' }));

    expect(res.status).toBe(403);
    expect((await res.json()).type).toContain('entity_not_org_bound');
    expect(calls.inserts).toHaveLength(0);
  });

  it('rejects a cross-org enrollment attempt even for a syntactically valid approver id', async () => {
    authed({ entity_id: 'ep_entity_attacker', organization_id: 'org_attacker' });
    const { client, calls } = makeClient();
    mockGetGuardedClient.mockReturnValue(client);

    const res = await RegisterOptions.POST(req({
      organization_id: 'org_victim',
      approver_id: 'cfo@victim.example',
    }));

    expect(res.status).toBe(403);
    expect((await res.json()).type).toContain('organization_mismatch');
    expect(calls.inserts).toHaveLength(0);
  });

  it('stores registration challenges and enrolled credentials under the authenticated org', async () => {
    authed({ entity_id: 'ep_entity_acme', organization_id: 'org_acme' });
    const { client: optionsClient, calls: optionCalls } = makeClient();
    mockGetGuardedClient.mockReturnValueOnce(optionsClient);

    const optionsRes = await RegisterOptions.POST(req({ approver_id: 'cfo@acme.example' }));
    expect(optionsRes.status).toBe(200);
    expect(optionCalls.inserts[0]).toMatchObject({
      table: 'webauthn_challenges',
      payload: { organization_id: 'org_acme', approver_id: 'cfo@acme.example' },
    });

    const { client: verifyClient, calls: verifyCalls } = makeClient({
      challenges: [{ id: 'ch_1', challenge: 'reg_challenge', expires_at: '2999-01-01T00:00:00.000Z' }],
    });
    mockGetGuardedClient.mockReturnValueOnce(verifyClient);
    mockVerifyRegistrationResponse.mockResolvedValue({
      verified: true,
      registrationInfo: {
        fmt: 'packed',
        credential: {
          id: 'cred_acme',
          publicKey: Buffer.from('cose'),
          counter: 0,
          transports: ['internal'],
        },
      },
    });

    const verifyRes = await RegisterVerify.POST(req({
      approver_id: 'cfo@acme.example',
      attestation: { id: 'cred_acme', response: {} },
    }));

    expect(verifyRes.status).toBe(201);
    expect(verifyCalls.selects[0].eq).toMatchObject({
      organization_id: 'org_acme',
      approver_id: 'cfo@acme.example',
    });
    expect(verifyCalls.inserts[0]).toMatchObject({
      table: 'approver_credentials',
      payload: { organization_id: 'org_acme', approver_id: 'cfo@acme.example', credential_id: 'cred_acme' },
    });
  });
});
