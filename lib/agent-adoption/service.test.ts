// SPDX-License-Identifier: Apache-2.0
import { beforeEach, describe, expect, it, vi } from 'vitest';

const webauthn = vi.hoisted(() => ({
  createRegistration: vi.fn(),
  verifyRegistration: vi.fn(),
  createAssertion: vi.fn(),
  verifyAssertion: vi.fn(),
}));

const environment = vi.hoisted(() => ({
  webauthn: vi.fn(),
}));

const arena = vi.hoisted(() => ({
  provision: vi.fn(),
  submit: vi.fn(),
}));

vi.mock('./webauthn', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./webauthn')>();
  return {
    ...actual,
    createAgentAdoptionRegistrationOptions: webauthn.createRegistration,
    verifyAgentAdoptionRegistration: webauthn.verifyRegistration,
    createAgentAdoptionAssertionOptions: webauthn.createAssertion,
    verifyAgentAdoptionAssertion: webauthn.verifyAssertion,
  };
});

vi.mock('@/lib/env', () => ({
  getSecretBoxKey: () => '11'.repeat(32),
  getWebAuthnConfig: environment.webauthn,
}));

vi.mock('@/lib/arena/service', () => ({
  provisionArenaSession: arena.provision,
  submitArenaAttempt: arena.submit,
}));

vi.mock('@/lib/supabase', () => ({
  getServiceClient: () => { throw new Error('test must inject a client'); },
}));

const Service = await import('./service');
const { createOperatingBond } = await import('./core');
const { AGENT_ADOPTION_WEBAUTHN_CLAIM_BOUNDARY, AgentAdoptionWebAuthnError } =
  await import('./webauthn');

const ADOPTION_ID = '00000000-0000-4000-8000-000000000001';
const TENANT_ID = '00000000-0000-4000-8000-000000000002';
const BOND_ID = '00000000-0000-4000-8000-000000000003';
const SESSION_TOKEN = `eaa1_${'a'.repeat(64)}`;
const CREDENTIAL_ID = 'credential_id_123';
const REGISTRATION_CHALLENGE = `ear1_${'b'.repeat(64)}`;
const ASSERTION_CHALLENGE = `eaa1c_${'c'.repeat(64)}`;
const ISSUED_AT = '2026-08-02T12:00:00.000Z';
const EXPIRES_AT = '2026-08-02T12:05:00.000Z';
const SESSION_CREATED_AT = '2030-01-01T00:00:00.000Z';
const SESSION_EXPIRES_AT = '2030-01-31T00:00:00.000Z';

const candidate = {
  label: 'Atlas',
  source_kind: 'local',
  job_template_id: 'job_vendor_intake_v1',
  allowance_template_id: 'allowance_cautious_v1',
} as const;
const built = createOperatingBond(candidate);

const credential = Object.freeze({
  claim_boundary: AGENT_ADOPTION_WEBAUTHN_CLAIM_BOUNDARY,
  algorithm: 'ES256' as const,
  curve: 'P-256' as const,
  credential_id: CREDENTIAL_ID,
  public_key_cose: 'AQID',
  public_key_spki: 'BAUG',
  transports: ['internal'] as const,
  device_type: 'multiDevice' as const,
  backed_up: true,
  sign_count: 0,
  counter_supported: false,
  rp_id: 'www.emiliaprotocol.ai',
  origin: 'https://www.emiliaprotocol.ai',
});

function draftSession() {
  return {
    tenant_id: TENANT_ID,
    adoption_id: ADOPTION_ID,
    status: 'active',
    candidate_digest: built.candidate_digest,
    bond_digest: built.bond_digest,
    operating_bond: built.bond,
    public_projection: built.public_projection,
    credential_count: 0,
    bond_count: 0,
    latest_bond_id: null,
    latest_bond_digest: null,
    created_at: SESSION_CREATED_AT,
    expires_at: SESSION_EXPIRES_AT,
  };
}

function authorization(overrides: Record<string, unknown> = {}) {
  return Object.freeze({
    sessionId: ADOPTION_ID,
    sessionToken: SESSION_TOKEN,
    session: { ...draftSession(), ...overrides },
  });
}

function challenge(token: string, purpose: 'registration' | 'assertion') {
  return {
    tenant_id: TENANT_ID,
    adoption_id: ADOPTION_ID,
    candidate_digest: built.candidate_digest,
    bond_digest: built.bond_digest,
    bond_purpose: 'synthetic_agent_adoption_operating_bond_v1',
    challenge_token: token,
    issued_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    purpose,
  };
}

function rpcClient(handler: (name: string, args: Record<string, unknown>) => unknown) {
  return {
    rpc: vi.fn(async (name: string, args: Record<string, unknown>) => ({
      data: handler(name, args),
      error: null,
    })),
  } as any;
}

describe('Agent Adoption service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    environment.webauthn.mockReturnValue({
      rpId: 'www.emiliaprotocol.ai',
      origin: 'https://www.emiliaprotocol.ai',
      isDevelopment: false,
    });
    webauthn.createRegistration.mockImplementation(async ({ context }) => ({
      context,
      challenge: 'registration-web-challenge',
      rp_id: context.rp_id,
      origin: context.origin,
      expires_at: context.expires_at,
      options: { challenge: 'registration-web-challenge', rp: { id: context.rp_id } },
    }));
    webauthn.verifyRegistration.mockResolvedValue(credential);
    webauthn.createAssertion.mockImplementation(async ({ context, credential: material }) => ({
      context,
      challenge: 'assertion-web-challenge',
      rp_id: context.rp_id,
      origin: context.origin,
      expires_at: context.expires_at,
      credential_id: material.credential_id,
      options: { challenge: 'assertion-web-challenge', rpId: context.rp_id },
    }));
    webauthn.verifyAssertion.mockResolvedValue({
      claim_boundary: AGENT_ADOPTION_WEBAUTHN_CLAIM_BOUNDARY,
      credential_id: CREDENTIAL_ID,
      transports: ['internal'],
      device_type: 'multiDevice',
      backed_up: true,
      sign_count: 0,
      counter_supported: false,
      rp_id: 'www.emiliaprotocol.ai',
      origin: 'https://www.emiliaprotocol.ai',
    });
    arena.provision.mockResolvedValue({
      session_id: `arena_session_${'1'.repeat(32)}`,
      token: `ep_arena_${'2'.repeat(64)}`,
      allowance: { expires_at: '2030-01-02T00:00:00.000Z' },
    });
    arena.submit.mockResolvedValue({
      attempt_id: `arena_attempt_${'3'.repeat(32)}`,
      decision: 'allow',
      action_digest: `sha256:${'4'.repeat(64)}`,
    });
  });

  it('stores and returns the one exact server-built Operating Bond', async () => {
    const client = rpcClient((name, args) => {
      expect(name).toBe('create_agent_adoption_session');
      expect(args.p_operating_bond).toEqual(built.bond);
      expect(args.p_bond_digest).toBe(built.bond_digest);
      return {
        session_id: ADOPTION_ID,
        session_token: SESSION_TOKEN,
        candidate_digest: built.candidate_digest,
        bond_digest: built.bond_digest,
        operating_bond: built.bond,
        public_projection: built.public_projection,
        created_at: SESSION_CREATED_AT,
        expires_at: SESSION_EXPIRES_AT,
      };
    });

    const result = await Service.createAgentAdoptionSession({ input: candidate, client });

    expect(result).toMatchObject({
      session_id: ADOPTION_ID,
      session_token: SESSION_TOKEN,
      authority_state: 'draft',
      passkey_registered: false,
      passkey_asserted: false,
      bond_digest: built.bond_digest,
      expires_at: SESSION_EXPIRES_AT,
    });
  });

  it('normalizes unknown session tokens into a non-enumerating refusal', async () => {
    const client = {
      rpc: vi.fn(async () => ({ data: null, error: { code: 'P0002', message: 'missing row' } })),
    } as any;
    const request = new Request('https://example.test', {
      headers: { authorization: `Bearer ${SESSION_TOKEN}` },
    });

    await expect(Service.authorizeAgentAdoptionSession({
      request,
      sessionId: ADOPTION_ID,
      client,
    })).rejects.toMatchObject({ status: 401, code: 'agent_adoption_unauthorized' });
  });

  it('refuses an expired session capability even if a malformed store returns it', async () => {
    const client = rpcClient((name) => {
      expect(name).toBe('read_agent_adoption_session');
      return { ...draftSession(), expires_at: '2000-01-01T00:00:00.000Z' };
    });
    const request = new Request('https://example.test', {
      headers: { authorization: `Bearer ${SESSION_TOKEN}` },
    });

    await expect(Service.authorizeAgentAdoptionSession({
      request,
      sessionId: ADOPTION_ID,
      client,
    })).rejects.toMatchObject({ status: 401, code: 'agent_adoption_unauthorized' });
  });

  it('cryptographically verifies registration before consuming its one-time challenge', async () => {
    const calls: string[] = [];
    const client = rpcClient((name, args) => {
      calls.push(name);
      if (name === 'create_agent_adoption_registration_challenge') {
        return challenge(REGISTRATION_CHALLENGE, 'registration');
      }
      expect(name).toBe('complete_agent_adoption_registration');
      expect(webauthn.verifyRegistration).toHaveBeenCalledTimes(1);
      expect(args).toMatchObject({
        p_adoption_id: ADOPTION_ID,
        p_challenge_token: REGISTRATION_CHALLENGE,
        p_credential_id: CREDENTIAL_ID,
        p_sign_count: 0,
        p_counter_supported: false,
      });
      return {
        credential_id: CREDENTIAL_ID,
        registration_digest: args.p_registration_digest,
      };
    });
    const auth = authorization();
    const ceremony = await Service.createAgentAdoptionRegistrationCeremony({ authorization: auth, client });
    const completed = await Service.completeAgentAdoptionRegistration({
      authorization: auth,
      input: { ceremony_token: ceremony.ceremony_token, attestation: { id: CREDENTIAL_ID } },
      client,
    });

    expect(completed).toEqual({ credential_id: CREDENTIAL_ID, registered: true });
    expect(calls).toEqual([
      'create_agent_adoption_registration_challenge',
      'complete_agent_adoption_registration',
    ]);
  });

  it('refuses a sealed ceremony replayed under another adoption before touching storage', async () => {
    const client = rpcClient((name) => {
      if (name === 'create_agent_adoption_registration_challenge') {
        return challenge(REGISTRATION_CHALLENGE, 'registration');
      }
      throw new Error(`unexpected ${name}`);
    });
    const ceremony = await Service.createAgentAdoptionRegistrationCeremony({
      authorization: authorization(),
      client,
    });
    const otherId = '00000000-0000-4000-8000-000000000099';
    const other = Object.freeze({
      sessionId: otherId,
      sessionToken: SESSION_TOKEN,
      session: { ...draftSession(), adoption_id: otherId },
    });

    await expect(Service.completeAgentAdoptionRegistration({
      authorization: other,
      input: { ceremony_token: ceremony.ceremony_token, attestation: { id: CREDENTIAL_ID } },
      client,
    })).rejects.toMatchObject({ code: 'agent_adoption_ceremony_invalid' });
    expect(client.rpc).toHaveBeenCalledTimes(1);
  });

  it('supports a zero-counter passkey and binds its assertion to the exact bond digest', async () => {
    const calls: Array<{ name: string; args: Record<string, unknown> }> = [];
    const client = rpcClient((name, args) => {
      calls.push({ name, args });
      if (name === 'create_agent_adoption_assertion_challenge') {
        return { ...challenge(ASSERTION_CHALLENGE, 'assertion'), credential };
      }
      expect(name).toBe('complete_agent_adoption_assertion');
      expect(args).toMatchObject({
        p_challenge_token: ASSERTION_CHALLENGE,
        p_new_counter: 0,
        p_counter_supported: false,
      });
      return {
        bond_id: BOND_ID,
        adoption_id: ADOPTION_ID,
        bond_digest: built.bond_digest,
        operating_bond: built.bond,
        assertion_observation: { assertion_digest: args.p_assertion_digest },
      };
    });
    const auth = authorization({ credential_count: 1 });
    const ceremony = await Service.createAgentAdoptionAssertionCeremony({
      authorization: auth,
      input: { credential_id: CREDENTIAL_ID },
      client,
    });
    const result = await Service.completeAgentAdoptionAssertion({
      authorization: auth,
      input: { ceremony_token: ceremony.ceremony_token, assertion: { id: CREDENTIAL_ID } },
      client,
    });

    expect(result).toMatchObject({
      session_id: ADOPTION_ID,
      session_token: SESSION_TOKEN,
      authority_state: 'asserted',
      passkey_registered: true,
      passkey_asserted: true,
      bond_id: BOND_ID,
      bond_digest: built.bond_digest,
    });
    expect(calls.map(({ name }) => name)).toEqual([
      'create_agent_adoption_assertion_challenge',
      'complete_agent_adoption_assertion',
    ]);
  });

  it('rejects malformed stored passkey material before generating assertion options', async () => {
    const client = rpcClient((name) => {
      expect(name).toBe('create_agent_adoption_assertion_challenge');
      return {
        ...challenge(ASSERTION_CHALLENGE, 'assertion'),
        credential: { ...credential, credential_id: 'not valid base64url' },
      };
    });

    await expect(Service.createAgentAdoptionAssertionCeremony({
      authorization: authorization({ credential_count: 1 }),
      input: { credential_id: CREDENTIAL_ID },
      client,
    })).rejects.toMatchObject({ code: 'agent_adoption_store_invalid' });
    expect(webauthn.createAssertion).not.toHaveBeenCalled();
  });

  it('keeps revoked and never-created public shares indistinguishable', async () => {
    const shareId = `agent_share_${'d'.repeat(40)}`;
    const revoked = rpcClient(() => ({
      share_id: shareId,
      revoked: true,
      projection: null,
    }));
    const missing = {
      rpc: vi.fn(async () => ({ data: null, error: { code: 'P0002', message: 'missing' } })),
    } as any;

    await expect(Service.loadPublicAgentAdoptionBond({ shareId, client: revoked })).resolves.toBeNull();
    await expect(Service.loadPublicAgentAdoptionBond({ shareId, client: missing })).resolves.toBeNull();
  });

  it.each([
    ['22023', 400, 'agent_adoption_invalid'],
    ['55000', 409, 'agent_adoption_conflict'],
    ['23505', 409, 'agent_adoption_conflict'],
    ['XX000', 503, 'agent_adoption_store_unavailable'],
  ])('normalizes RPC error %s without leaking store details', async (code, status, expectedCode) => {
    const client = {
      rpc: vi.fn(async () => ({ data: null, error: { code, message: 'private database detail' } })),
    } as any;
    await expect(Service.createAgentAdoptionSession({ input: candidate, client }))
      .rejects.toMatchObject({ status, code: expectedCode });
  });

  it('fails closed when storage throws, returns a non-object, or widens a session', async () => {
    const thrown = { rpc: vi.fn(async () => { throw new Error('socket closed'); }) } as any;
    await expect(Service.createAgentAdoptionSession({ input: candidate, client: thrown }))
      .rejects.toMatchObject({ status: 503, code: 'agent_adoption_store_unavailable' });

    const invalid = { rpc: vi.fn(async () => ({ data: [], error: null })) } as any;
    await expect(Service.createAgentAdoptionSession({ input: candidate, client: invalid }))
      .rejects.toMatchObject({ status: 503, code: 'agent_adoption_store_invalid' });

    const widened = rpcClient(() => ({
      session_id: ADOPTION_ID,
      session_token: SESSION_TOKEN,
      candidate_digest: built.candidate_digest,
      bond_digest: built.bond_digest,
      operating_bond: { ...built.bond, hidden: 1n },
      public_projection: built.public_projection,
      created_at: SESSION_CREATED_AT,
      expires_at: SESSION_EXPIRES_AT,
    }));
    await expect(Service.createAgentAdoptionSession({ input: candidate, client: widened }))
      .rejects.toMatchObject({ code: 'agent_adoption_store_invalid' });
  });

  it('normalizes candidate validation and capability-state failures', async () => {
    await expect(Service.createAgentAdoptionSession({ input: { ...candidate, label: '' }, client: rpcClient(() => ({})) }))
      .rejects.toMatchObject({ status: 400 });

    await expect(Service.authorizeAgentAdoptionSession({
      request: new Request('https://example.test'),
      sessionId: ADOPTION_ID,
      client: rpcClient(() => draftSession()),
    })).rejects.toMatchObject({ status: 401, code: 'agent_adoption_unauthorized' });

    const request = new Request('https://example.test', {
      headers: { authorization: `Bearer ${SESSION_TOKEN}` },
    });
    await expect(Service.authorizeAgentAdoptionSession({
      request,
      sessionId: ADOPTION_ID,
      client: rpcClient(() => ({ ...draftSession(), tenant_id: 'bad' })),
    })).rejects.toMatchObject({ status: 503, code: 'agent_adoption_store_invalid' });
    await expect(Service.authorizeAgentAdoptionSession({
      request,
      sessionId: ADOPTION_ID,
      client: rpcClient(() => ({ ...draftSession(), status: 'revoked' })),
    })).rejects.toMatchObject({ status: 410, code: 'agent_adoption_revoked' });
    await expect(Service.authorizeAgentAdoptionSession({
      request,
      sessionId: ADOPTION_ID,
      client: rpcClient(() => ({ ...draftSession(), status: 'draft' })),
    })).rejects.toMatchObject({ status: 409, code: 'agent_adoption_state_invalid' });
    await expect(Service.authorizeAgentAdoptionSession({
      request,
      sessionId: ADOPTION_ID,
      client: rpcClient(() => draftSession()),
    })).resolves.toMatchObject({ sessionId: ADOPTION_ID, sessionToken: SESSION_TOKEN });
  });

  it('fails closed on malformed, mismatched, and unverifiable registration ceremonies', async () => {
    const auth = authorization();
    await expect(Service.completeAgentAdoptionRegistration({ authorization: auth, input: {}, client: rpcClient(() => ({})) }))
      .rejects.toMatchObject({ code: 'agent_adoption_registration_invalid' });
    await expect(Service.completeAgentAdoptionRegistration({
      authorization: auth,
      input: { ceremony_token: `epenc:v1:${'x'.repeat(40)}`, attestation: {} },
      client: rpcClient(() => ({})),
    })).rejects.toMatchObject({ code: 'agent_adoption_ceremony_invalid' });

    const client = rpcClient((name, args) => name === 'create_agent_adoption_registration_challenge'
      ? challenge(REGISTRATION_CHALLENGE, 'registration')
      : { credential_id: CREDENTIAL_ID, registration_digest: args.p_registration_digest });
    const ceremony = await Service.createAgentAdoptionRegistrationCeremony({ authorization: auth, client });
    webauthn.verifyRegistration.mockRejectedValueOnce(
      new AgentAdoptionWebAuthnError('registration_refused', 'registration refused'),
    );
    await expect(Service.completeAgentAdoptionRegistration({
      authorization: auth,
      input: { ceremony_token: ceremony.ceremony_token, attestation: {} },
      client,
    })).rejects.toMatchObject({ status: 400, code: 'registration_refused' });

    webauthn.verifyRegistration.mockResolvedValueOnce(credential);
    await expect(Service.completeAgentAdoptionRegistration({
      authorization: auth,
      input: { ceremony_token: ceremony.ceremony_token, attestation: { hidden: 1n } },
      client,
    })).rejects.toMatchObject({ status: 400, code: 'agent_adoption_response_invalid' });
  });

  it('refuses inconsistent passkey challenge and credential state', async () => {
    const auth = authorization({ credential_count: 1 });
    const badContext = rpcClient(() => ({
      ...challenge(ASSERTION_CHALLENGE, 'assertion'),
      tenant_id: '00000000-0000-4000-8000-000000000099',
      credential,
    }));
    await expect(Service.createAgentAdoptionAssertionCeremony({
      authorization: auth,
      input: { credential_id: CREDENTIAL_ID },
      client: badContext,
    })).rejects.toMatchObject({ code: 'agent_adoption_store_invalid' });

    const missingCredential = rpcClient(() => ({
      ...challenge(ASSERTION_CHALLENGE, 'assertion'), credential: null,
    }));
    await expect(Service.createAgentAdoptionAssertionCeremony({
      authorization: auth,
      input: { credential_id: CREDENTIAL_ID },
      client: missingCredential,
    })).rejects.toMatchObject({ code: 'agent_adoption_store_invalid' });

    await expect(Service.createAgentAdoptionAssertionCeremony({
      authorization: auth,
      input: { credential_id: 'bad id' },
      client: missingCredential,
    })).rejects.toMatchObject({ code: 'agent_adoption_assertion_invalid' });
  });

  it('normalizes assertion verification errors and refuses a widened stored bond', async () => {
    const auth = authorization({ credential_count: 1 });
    const client = rpcClient((name, args) => {
      if (name === 'create_agent_adoption_assertion_challenge') {
        return { ...challenge(ASSERTION_CHALLENGE, 'assertion'), credential };
      }
      return {
        bond_id: BOND_ID,
        adoption_id: ADOPTION_ID,
        bond_digest: built.bond_digest,
        operating_bond: { ...built.bond, widened: true },
        assertion_observation: { assertion_digest: args.p_assertion_digest },
      };
    });
    const ceremony = await Service.createAgentAdoptionAssertionCeremony({
      authorization: auth,
      input: { credential_id: CREDENTIAL_ID },
      client,
    });
    await expect(Service.completeAgentAdoptionAssertion({ authorization: auth, input: {}, client }))
      .rejects.toMatchObject({ code: 'agent_adoption_assertion_invalid' });
    webauthn.verifyAssertion.mockRejectedValueOnce(
      new AgentAdoptionWebAuthnError('assertion_refused', 'assertion refused'),
    );
    await expect(Service.completeAgentAdoptionAssertion({
      authorization: auth,
      input: { ceremony_token: ceremony.ceremony_token, assertion: {} },
      client,
    })).rejects.toMatchObject({ status: 400, code: 'assertion_refused' });
    webauthn.verifyAssertion.mockResolvedValueOnce({
      claim_boundary: AGENT_ADOPTION_WEBAUTHN_CLAIM_BOUNDARY,
      credential_id: CREDENTIAL_ID,
      transports: ['internal'],
      device_type: 'multiDevice',
      backed_up: true,
      sign_count: 0,
      counter_supported: false,
      rp_id: 'www.emiliaprotocol.ai',
      origin: 'https://www.emiliaprotocol.ai',
    });
    await expect(Service.completeAgentAdoptionAssertion({
      authorization: auth,
      input: { ceremony_token: ceremony.ceremony_token, assertion: {} },
      client,
    })).rejects.toMatchObject({ code: 'agent_adoption_store_invalid' });
  });

  it('covers the bounded trial wrappers and normalizes trial refusals', async () => {
    const auth = authorization({
      agent_label: 'Atlas',
      bond_count: 1,
      latest_bond_id: BOND_ID,
      latest_bond_digest: built.bond_digest,
      operating_bond: built.bond,
    });
    const provisioned = await Service.provisionAgentAdoptionTrial({ authorization: auth, client: {} as any });
    expect(provisioned).toMatchObject({ session_id: ADOPTION_ID, session_token: SESSION_TOKEN });
    await expect(Service.attemptAgentAdoptionTrial({
      authorization: auth,
      input: { attempt_template_id: 'attempt_in_bounds_v1', trial_token: provisioned.trial_token },
      client: {} as any,
    })).resolves.toMatchObject({ decision: 'permit', reason_code: 'within_allowance' });

    await expect(Service.provisionAgentAdoptionTrial({
      authorization: authorization(), client: {} as any,
    })).rejects.toMatchObject({ status: 409, code: 'agent_adoption_bond_not_asserted' });
    await expect(Service.attemptAgentAdoptionTrial({
      authorization: auth, input: {}, client: {} as any,
    })).rejects.toMatchObject({ status: 400, code: 'agent_adoption_attempt_invalid' });
  });

  it('publishes, validates, revokes, and reads the public projection', async () => {
    const shareId = `agent_share_${'d'.repeat(40)}`;
    const auth = authorization({ latest_bond_id: BOND_ID });
    await expect(Service.publishAgentAdoptionBond({ authorization: auth, input: {}, client: rpcClient(() => ({})) }))
      .rejects.toMatchObject({ code: 'agent_adoption_share_invalid' });
    await expect(Service.publishAgentAdoptionBond({
      authorization: auth,
      input: { bond_id: BOND_ID },
      client: rpcClient(() => ({ share_id: 'bad', projection: { bond_digest: built.bond_digest } })),
    })).rejects.toMatchObject({ code: 'agent_adoption_store_invalid' });
    await expect(Service.publishAgentAdoptionBond({
      authorization: auth,
      input: { bond_id: BOND_ID },
      client: rpcClient(() => ({ share_id: shareId, projection: { bond_digest: built.bond_digest } })),
      now: Date.parse(ISSUED_AT),
    })).resolves.toEqual({ share_id: shareId, share_url: `/adopt/r/${shareId}`, published_at: ISSUED_AT });

    await expect(Service.revokeAgentAdoption({
      authorization: auth,
      client: rpcClient(() => ({ adoption_id: ADOPTION_ID, status: 'revoked', revoked_at: ISSUED_AT })),
    })).resolves.toEqual({ authority_state: 'revoked', revoked_at: ISSUED_AT });
    await expect(Service.revokeAgentAdoption({
      authorization: auth,
      client: rpcClient(() => ({ adoption_id: ADOPTION_ID, status: 'active' })),
    })).rejects.toMatchObject({ code: 'agent_adoption_store_invalid' });

    const projection = {
      '@version': 'EP-OPERATING-BOND-PUBLIC-v1',
      share_id: shareId,
      bond_digest: built.bond_digest,
    };
    await expect(Service.loadPublicAgentAdoptionBond({
      shareId,
      client: rpcClient(() => ({ share_id: shareId, revoked: false, projection, created_at: ISSUED_AT })),
    })).resolves.toMatchObject({ share_id: shareId, revoked: false, projection });
    await expect(Service.loadPublicAgentAdoptionBond({
      shareId,
      client: rpcClient(() => ({ share_id: shareId, revoked: false, projection: { ...projection, bond_digest: 'bad' } })),
    })).rejects.toMatchObject({ code: 'agent_adoption_store_invalid' });
  });

  it('preserves fail-closed internal errors and both RP configuration branches', async () => {
    const throwingInput = { ...candidate } as Record<string, unknown>;
    Object.defineProperty(throwingInput, 'label', {
      enumerable: true,
      get() { throw new Error('caller getter failed'); },
    });
    await expect(Service.createAgentAdoptionSession({ input: throwingInput, client: rpcClient(() => ({})) }))
      .rejects.toMatchObject({ status: 400, code: 'invalid_json_domain' });

    const request = new Request('https://example.test', {
      headers: { authorization: `Bearer ${SESSION_TOKEN}` },
    });
    const invalidRpc = {
      rpc: vi.fn(async () => ({ data: null, error: { code: '22023', message: 'invalid' } })),
    } as any;
    await expect(Service.authorizeAgentAdoptionSession({ request, sessionId: ADOPTION_ID, client: invalidRpc }))
      .rejects.toMatchObject({ status: 400, code: 'agent_adoption_invalid' });

    environment.webauthn.mockReturnValueOnce({ rpId: null, origin: null, isDevelopment: true });
    const development = rpcClient(() => challenge(REGISTRATION_CHALLENGE, 'registration'));
    await expect(Service.createAgentAdoptionRegistrationCeremony({
      authorization: authorization(), client: development,
    })).resolves.toHaveProperty('ceremony_token');

    environment.webauthn.mockReturnValueOnce({ rpId: null, origin: null, isDevelopment: false });
    await expect(Service.createAgentAdoptionRegistrationCeremony({
      authorization: authorization(), client: development,
    })).rejects.toMatchObject({ code: 'agent_adoption_webauthn_unconfigured' });
  });

  it('refuses every inconsistent credential completion and preserves unexpected verifier faults', async () => {
    const auth = authorization({ credential_count: 1 });
    await expect(Service.completeAgentAdoptionRegistration({
      authorization: auth,
      input: { ceremony_token: null, attestation: {} },
      client: rpcClient(() => ({})),
    })).rejects.toMatchObject({ code: 'agent_adoption_ceremony_invalid' });

    const registrationClient = rpcClient((name) => name === 'create_agent_adoption_registration_challenge'
      ? challenge(REGISTRATION_CHALLENGE, 'registration')
      : { credential_id: 'other_credential', registration_digest: 'wrong' });
    const registration = await Service.createAgentAdoptionRegistrationCeremony({
      authorization: auth, client: registrationClient,
    });
    webauthn.verifyRegistration.mockRejectedValueOnce(new Error('unexpected verifier fault'));
    await expect(Service.completeAgentAdoptionRegistration({
      authorization: auth,
      input: { ceremony_token: registration.ceremony_token, attestation: {} },
      client: registrationClient,
    })).rejects.toThrow('unexpected verifier fault');
    webauthn.verifyRegistration.mockResolvedValueOnce(credential);
    await expect(Service.completeAgentAdoptionRegistration({
      authorization: auth,
      input: { ceremony_token: registration.ceremony_token, attestation: {} },
      client: registrationClient,
    })).rejects.toMatchObject({ code: 'agent_adoption_store_invalid' });

    const mismatchedCredential = rpcClient(() => ({
      ...challenge(ASSERTION_CHALLENGE, 'assertion'),
      credential: { ...credential, credential_id: `${CREDENTIAL_ID}x` },
    }));
    await expect(Service.createAgentAdoptionAssertionCeremony({
      authorization: auth,
      input: { credential_id: CREDENTIAL_ID },
      client: mismatchedCredential,
    })).rejects.toMatchObject({ code: 'agent_adoption_store_invalid' });

    const assertionClient = rpcClient((name, args) => name === 'create_agent_adoption_assertion_challenge'
      ? { ...challenge(ASSERTION_CHALLENGE, 'assertion'), credential }
      : {
          bond_id: BOND_ID,
          adoption_id: ADOPTION_ID,
          bond_digest: built.bond_digest,
          operating_bond: built.bond,
          assertion_observation: { assertion_digest: args.p_assertion_digest },
        });
    const assertion = await Service.createAgentAdoptionAssertionCeremony({
      authorization: auth,
      input: { credential_id: CREDENTIAL_ID },
      client: assertionClient,
    });
    webauthn.verifyAssertion.mockRejectedValueOnce(new Error('unexpected assertion fault'));
    await expect(Service.completeAgentAdoptionAssertion({
      authorization: auth,
      input: { ceremony_token: assertion.ceremony_token, assertion: {} },
      client: assertionClient,
    })).rejects.toThrow('unexpected assertion fault');
  });

  it('does not launder unexpected trial or public-store failures', async () => {
    const auth = authorization({
      agent_label: 'Atlas',
      bond_count: 1,
      latest_bond_id: BOND_ID,
      latest_bond_digest: built.bond_digest,
      operating_bond: built.bond,
    });
    arena.provision.mockRejectedValueOnce(new Error('arena unavailable'));
    await expect(Service.provisionAgentAdoptionTrial({ authorization: auth, client: {} as any }))
      .rejects.toThrow('arena unavailable');

    const provisioned = await Service.provisionAgentAdoptionTrial({ authorization: auth, client: {} as any });
    arena.submit.mockRejectedValueOnce(new Error('arena submit unavailable'));
    await expect(Service.attemptAgentAdoptionTrial({
      authorization: auth,
      input: { attempt_template_id: 'attempt_in_bounds_v1', trial_token: provisioned.trial_token },
      client: {} as any,
    })).rejects.toThrow('arena submit unavailable');

    const shareId = `agent_share_${'e'.repeat(40)}`;
    const broken = { rpc: vi.fn(async () => { throw new Error('store unavailable'); }) } as any;
    await expect(Service.loadPublicAgentAdoptionBond({ shareId, client: broken }))
      .rejects.toMatchObject({ code: 'agent_adoption_store_unavailable' });
  });
});
