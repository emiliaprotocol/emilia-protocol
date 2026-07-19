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

function authed(entity, permissions = ['approver.enroll']) {
  mockAuthenticateRequest.mockResolvedValue({ entity, permissions });
}

function makeClient({ challenges = [], scimTokens = [], scimUsers = [], errors = {} } = {}) {
  const calls = { inserts: [], selects: [], updates: [], rpcs: [] };
  const seeded = {
    webauthn_challenges: challenges,
    scim_provisioning_tokens: scimTokens,
    scim_users: scimUsers,
  };
  function matches(row, state) {
    return Object.entries(state.eq).every(([k, v]) => row[k] === v)
      && Object.entries(state.is).every(([k, v]) => row[k] === v)
      && Object.entries(state.in).every(([k, vals]) => vals.includes(row[k]));
  }
  function builder(table) {
    const state = { table, eq: {}, is: {}, in: {} };
    const b = {
      select() { return b; },
      eq(k, v) { state.eq[k] = v; return b; },
      in(k, v) { state.in[k] = v; return b; },
      is(k, v) { state.is[k] = v; return b; },
      order() { return b; },
      limit() { return b; },
      // Single-row read helper, kept for any caller that terminates with it.
      // Filters seeded rows by the accumulated state so userName normalization
      // is exercised. Does NOT push to calls.selects (index-stable).
      maybeSingle: async () => {
        if (errors[table]) return { data: null, error: errors[table] };
        const rows = (seeded[table] || []).filter((r) => matches(r, state));
        return { data: rows[0] ?? null, error: null };
      },
      insert: vi.fn(async (payload) => {
        calls.inserts.push({ table, payload });
        return { error: null };
      }),
      update(patch) { calls.updates.push({ table, patch, state }); return b; },
      then(resolve, reject) {
        try {
          if (errors[table]) return resolve({ data: null, error: errors[table] });
          // The webauthn_challenges query is what the existing challenge-index
          // assertions observe, so it (and only it) is recorded in calls.selects
          // and returns the seeded challenge list verbatim. The SCIM directory
          // lookups filter seeded rows by the accumulated eq/in/is state and are
          // deliberately NOT recorded, keeping the challenge-query index stable.
          if (table === 'webauthn_challenges') {
            calls.selects.push({ ...state });
            return resolve({ data: challenges, error: null });
          }
          const rows = (seeded[table] || []).filter((r) => matches(r, state));
          return resolve({ data: rows, error: null });
        } catch (e) {
          return reject(e);
        }
      },
    };
    return b;
  }
  return {
    client: {
      from: (table) => builder(table),
      rpc: vi.fn(async (name, params) => {
        calls.rpcs.push({ name, params });
        return {
          data: {
            credential_id: params.p_credential.credential_id,
            consumed: true,
            enrollment_basis: params.p_credential.enrollment_basis,
          },
          error: null,
        };
      }),
    },
    calls,
  };
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

  it('rejects registration enrollment for a non-admin organization key', async () => {
    authed({ entity_id: 'ep_entity_member', organization_id: 'org_acme' }, ['read', 'write']);
    const { client, calls } = makeClient();
    mockGetGuardedClient.mockReturnValue(client);

    const res = await RegisterOptions.POST(req({ approver_id: 'cfo@acme.example' }));

    expect(res.status).toBe(403);
    expect((await res.json()).type).toContain('insufficient_permissions');
    expect(calls.inserts).toHaveLength(0);
  });

  it('rejects registration completion for a non-admin organization key', async () => {
    authed({ entity_id: 'ep_entity_member', organization_id: 'org_acme' }, ['read', 'write']);
    const { client, calls } = makeClient();
    mockGetGuardedClient.mockReturnValue(client);

    const res = await RegisterVerify.POST(req({
      approver_id: 'cfo@acme.example',
      attestation: { id: 'cred_acme', response: {} },
    }));

    expect(res.status).toBe(403);
    expect((await res.json()).type).toContain('insufficient_permissions');
    expect(calls.inserts).toHaveLength(0);
    expect(calls.selects).toHaveLength(0);
  });

  it('accepts the hosted enrollment surface admin capability', async () => {
    authed({ entity_id: 'ep_entity_admin', organization_id: 'org_acme' }, ['admin']);
    const { client, calls } = makeClient();
    mockGetGuardedClient.mockReturnValue(client);

    const res = await RegisterOptions.POST(req({ approver_id: 'cfo@acme.example' }));

    expect(res.status).toBe(200);
    expect(calls.inserts).toHaveLength(1);
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
    expect(verifyCalls.rpcs[0]).toMatchObject({
      name: 'complete_webauthn_registration_atomic',
      params: {
        p_organization_id: 'org_acme',
        p_approver_id: 'cfo@acme.example',
        p_credential: { credential_id: 'cred_acme' },
      },
    });
  });

  it('records operator_attested basis when the org has no provisioned directory', async () => {
    authed({ entity_id: 'ep_entity_acme', organization_id: 'org_acme' });
    const { client, calls } = makeClient({
      challenges: [{ id: 'ch_1', challenge: 'reg_challenge', expires_at: '2999-01-01T00:00:00.000Z' }],
    });
    mockGetGuardedClient.mockReturnValue(client);
    mockVerifyRegistrationResponse.mockResolvedValue({
      verified: true,
      registrationInfo: {
        fmt: 'packed',
        credential: { id: 'cred_acme', publicKey: Buffer.from('cose'), counter: 0, transports: ['internal'] },
      },
    });

    const res = await RegisterVerify.POST(req({
      approver_id: 'ep:approver:jchen-controller',
      attestation: { id: 'cred_acme', response: {} },
    }));

    expect(res.status).toBe(201);
    expect((await res.json()).enrollment_basis).toBe('operator_attested');
    expect(calls.rpcs[0].params.p_credential).toMatchObject({
      enrollment_basis: 'operator_attested',
      directory_user_id: null,
    });
  });
});

describe('WebAuthn registration directory anchor', () => {
  beforeEach(() => {
    mockAuthenticateRequest.mockReset();
    mockGetGuardedClient.mockReset();
    mockGenerateRegistrationOptions.mockReset();
    mockVerifyRegistrationResponse.mockReset();
    mockGenerateRegistrationOptions.mockResolvedValue({ challenge: 'reg_challenge' });
  });

  const VERIFIED = {
    verified: true,
    registrationInfo: {
      fmt: 'packed',
      credential: { id: 'cred_acme', publicKey: Buffer.from('cose'), counter: 0, transports: ['internal'] },
    },
  };

  // org_acme provisions a directory (tenant t_acme) with one active user.
  function directoryClient(extra = {}) {
    return makeClient({
      scimTokens: [{ organization_id: 'org_acme', tenant_id: 't_acme', revoked_at: null }],
      scimUsers: [{ id: 'su_cfo', tenant_id: 't_acme', user_name: 'cfo@acme.example', active: true }],
      ...extra,
    });
  }
  const withChallenge = { challenges: [{ id: 'ch_1', challenge: 'reg_challenge', expires_at: '2999-01-01T00:00:00.000Z' }] };

  // R1 — options, no directory: pilot path intact, challenge minted.
  it('R1 options: no directory falls back to operator_attested and mints the challenge', async () => {
    authed({ entity_id: 'ep_entity_acme', organization_id: 'org_acme' });
    const { client, calls } = makeClient(); // no scim rows
    mockGetGuardedClient.mockReturnValue(client);

    const res = await RegisterOptions.POST(req({ approver_id: 'ep:approver:jchen-controller' }));

    expect(res.status).toBe(200);
    expect(calls.inserts).toHaveLength(1);
    // Operator-attested keeps the raw id.
    expect(calls.inserts[0].payload).toMatchObject({ approver_id: 'ep:approver:jchen-controller' });
  });

  // R2 — options, directory + unprovisioned: 403, no challenge.
  it('R2 options: rejects an approver the directory does not carry (no challenge)', async () => {
    authed({ entity_id: 'ep_entity_acme', organization_id: 'org_acme' });
    const { client, calls } = directoryClient();
    mockGetGuardedClient.mockReturnValue(client);

    const res = await RegisterOptions.POST(req({ approver_id: 'attacker@acme.example' }));

    expect(res.status).toBe(403);
    expect((await res.json()).type).toContain('approver_not_provisioned');
    expect(calls.inserts).toHaveLength(0);
  });

  // R3 — options, directory + active: 200, challenge under the NORMALIZED id.
  it('R3 options: admits an active directory user and mints the challenge under the normalized id', async () => {
    authed({ entity_id: 'ep_entity_acme', organization_id: 'org_acme' });
    const { client, calls } = directoryClient();
    mockGetGuardedClient.mockReturnValue(client);

    // Operator names the approver with mixed case; the directory row is lower.
    const res = await RegisterOptions.POST(req({ approver_id: 'CFO@Acme.Example' }));

    expect(res.status).toBe(200);
    expect(calls.inserts).toHaveLength(1);
    expect(calls.inserts[0].payload).toMatchObject({ approver_id: 'cfo@acme.example' });
  });

  // R4 — verify, directory + unprovisioned: 403, RPC not called.
  it('R4 verify: refuses to bind a credential for a non-directory approver (no RPC)', async () => {
    authed({ entity_id: 'ep_entity_acme', organization_id: 'org_acme' });
    const { client, calls } = directoryClient(withChallenge);
    mockGetGuardedClient.mockReturnValue(client);

    const res = await RegisterVerify.POST(req({
      approver_id: 'cfo@evil.example',
      attestation: { id: 'cred_x', response: {} },
    }));

    expect(res.status).toBe(403);
    expect((await res.json()).type).toContain('approver_not_provisioned');
    expect(calls.rpcs).toHaveLength(0);
  });

  // R5 — verify, directory + active: RPC called with basis=directory, id pinned,
  // p_approver_id normalized; 201.
  it('R5 verify: records enrollment_basis=directory, pins directory_user_id, normalized p_approver_id', async () => {
    authed({ entity_id: 'ep_entity_acme', organization_id: 'org_acme' });
    const { client, calls } = directoryClient(withChallenge);
    mockGetGuardedClient.mockReturnValue(client);
    mockVerifyRegistrationResponse.mockResolvedValue(VERIFIED);

    const res = await RegisterVerify.POST(req({
      approver_id: 'cfo@acme.example',
      attestation: { id: 'cred_acme', response: {} },
    }));

    expect(res.status).toBe(201);
    expect((await res.json()).enrollment_basis).toBe('directory');
    expect(calls.rpcs[0].params.p_approver_id).toBe('cfo@acme.example');
    expect(calls.rpcs[0].params.p_credential).toMatchObject({
      enrollment_basis: 'directory',
      directory_user_id: 'su_cfo',
    });
  });

  // R6 — verify, directory + inactive (deprovisioned mid-flight): 403, no RPC.
  it('R6 verify: refuses an inactive (deprovisioned) directory user', async () => {
    authed({ entity_id: 'ep_entity_acme', organization_id: 'org_acme' });
    const { client, calls } = makeClient({
      scimTokens: [{ organization_id: 'org_acme', tenant_id: 't_acme', revoked_at: null }],
      scimUsers: [{ id: 'su_cfo', tenant_id: 't_acme', user_name: 'cfo@acme.example', active: false }],
      ...withChallenge,
    });
    mockGetGuardedClient.mockReturnValue(client);

    const res = await RegisterVerify.POST(req({
      approver_id: 'cfo@acme.example',
      attestation: { id: 'cred_acme', response: {} },
    }));

    expect(res.status).toBe(403);
    expect((await res.json()).type).toContain('approver_not_provisioned');
    expect(calls.rpcs).toHaveLength(0);
  });

  // R7 — verify, non-directory: RPC basis=operator_attested, null id, RAW p_approver_id.
  it('R7 verify: non-directory records operator_attested with a raw p_approver_id', async () => {
    authed({ entity_id: 'ep_entity_acme', organization_id: 'org_acme' });
    const { client, calls } = makeClient(withChallenge);
    mockGetGuardedClient.mockReturnValue(client);
    mockVerifyRegistrationResponse.mockResolvedValue(VERIFIED);

    const res = await RegisterVerify.POST(req({
      approver_id: 'ep:approver:JChen-Controller',
      attestation: { id: 'cred_acme', response: {} },
    }));

    expect(res.status).toBe(201);
    expect((await res.json()).enrollment_basis).toBe('operator_attested');
    expect(calls.rpcs[0].params.p_approver_id).toBe('ep:approver:JChen-Controller');
    expect(calls.rpcs[0].params.p_credential).toMatchObject({
      enrollment_basis: 'operator_attested',
      directory_user_id: null,
    });
  });

  // R8 — deprovision-consistency: a mixed-case directory enrollment is stored
  // under the exact normalized string the SCIM deprovision path revokes by.
  it('R8 verify: directory enrollment stores p_approver_id as the normalized string SCIM revoke uses', async () => {
    authed({ entity_id: 'ep_entity_acme', organization_id: 'org_acme' });
    // The challenge for the mixed-case enrollment was minted under the normalized id.
    const { client, calls } = directoryClient(withChallenge);
    mockGetGuardedClient.mockReturnValue(client);
    mockVerifyRegistrationResponse.mockResolvedValue(VERIFIED);

    const res = await RegisterVerify.POST(req({
      approver_id: 'CFO@Acme.Example', // mixed-case for the provisioned cfo@acme.example
      attestation: { id: 'cred_acme', response: {} },
    }));

    expect(res.status).toBe(201);
    // The exact string SCIM deprovision runs `.eq('approver_id', normalizeUserName(userName))` with.
    expect(calls.rpcs[0].params.p_approver_id).toBe('cfo@acme.example');
  });

  // R9 — directory lookup infra error: 503 on both routes; no challenge / no RPC.
  it('R9 options: a directory lookup error fails closed with 503 and mints no challenge', async () => {
    authed({ entity_id: 'ep_entity_acme', organization_id: 'org_acme' });
    const { client, calls } = makeClient({ errors: { scim_provisioning_tokens: { message: 'db down' } } });
    mockGetGuardedClient.mockReturnValue(client);

    const res = await RegisterOptions.POST(req({ approver_id: 'cfo@acme.example' }));

    expect(res.status).toBe(503);
    expect((await res.json()).type).toContain('directory_lookup_failed');
    expect(calls.inserts).toHaveLength(0);
  });

  it('R9 verify: a directory lookup error fails closed with 503 and calls no RPC', async () => {
    authed({ entity_id: 'ep_entity_acme', organization_id: 'org_acme' });
    const { client, calls } = makeClient({
      errors: { scim_provisioning_tokens: { message: 'db down' } },
      ...withChallenge,
    });
    mockGetGuardedClient.mockReturnValue(client);

    const res = await RegisterVerify.POST(req({
      approver_id: 'cfo@acme.example',
      attestation: { id: 'cred_acme', response: {} },
    }));

    expect(res.status).toBe(503);
    expect((await res.json()).type).toContain('directory_lookup_failed');
    expect(calls.rpcs).toHaveLength(0);
  });
});
