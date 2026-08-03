// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AgentAdoptionCredentialMaterial } from './webauthn.js';

const mocks = vi.hoisted(() => ({
  generateRegistrationOptions: vi.fn(),
  verifyRegistrationResponse: vi.fn(),
  generateAuthenticationOptions: vi.fn(),
  verifyAuthenticationResponse: vi.fn(),
  coseToSpkiP256: vi.fn(),
}));

vi.mock('@simplewebauthn/server', () => ({
  generateRegistrationOptions: (...args: unknown[]) => mocks.generateRegistrationOptions(...args),
  verifyRegistrationResponse: (...args: unknown[]) => mocks.verifyRegistrationResponse(...args),
  generateAuthenticationOptions: (...args: unknown[]) => mocks.generateAuthenticationOptions(...args),
  verifyAuthenticationResponse: (...args: unknown[]) => mocks.verifyAuthenticationResponse(...args),
}));

vi.mock('../webauthn.js', () => ({
  coseToSpkiP256: (...args: unknown[]) => mocks.coseToSpkiP256(...args),
}));

const {
  AGENT_ADOPTION_WEBAUTHN_ASSERTION_CONTEXT_TYPE,
  AGENT_ADOPTION_WEBAUTHN_CLAIM_BOUNDARY,
  AGENT_ADOPTION_WEBAUTHN_REGISTRATION_CONTEXT_TYPE,
  AGENT_ADOPTION_WEBAUTHN_VERSION,
  agentAdoptionWebAuthnChallenge,
  buildAgentAdoptionAssertionContext,
  buildAgentAdoptionRegistrationContext,
  createAgentAdoptionAssertionOptions,
  createAgentAdoptionRegistrationOptions,
  verifyAgentAdoptionAssertion,
  verifyAgentAdoptionRegistration,
} = await import('./webauthn.js');

const NOW = Date.parse('2030-01-01T00:01:00.000Z');
const RP_ID = 'adopt.example.test';
const ORIGIN = 'https://adopt.example.test';
const CONTEXT_INPUT = Object.freeze({
  tenantId: 'tenant_public_demo',
  adoptionId: 'adoption_candidate_001',
  candidateDigest: `sha256:${'a'.repeat(64)}`,
  bondDigest: `sha256:${'b'.repeat(64)}`,
  bondPurpose: 'synthetic_agent_adoption_bond',
  nonce: 'adoption_nonce_1234567890abcdef',
  issuedAt: '2030-01-01T00:00:00.000Z',
  expiresAt: '2030-01-01T00:05:00.000Z',
  rpId: RP_ID,
  origin: ORIGIN,
});

function registrationContext(overrides: Record<string, unknown> = {}) {
  return buildAgentAdoptionRegistrationContext({ ...CONTEXT_INPUT, ...overrides });
}

function assertionContext(overrides: Record<string, unknown> = {}) {
  return buildAgentAdoptionAssertionContext({ ...CONTEXT_INPUT, ...overrides });
}

function clientData(type: 'webauthn.create' | 'webauthn.get', challenge: string, origin = ORIGIN) {
  return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }), 'utf8')
    .toString('base64url');
}

function authenticatorData({
  rpId = RP_ID,
  flags = 0x05,
  counter = 1,
}: {
  rpId?: string;
  flags?: number;
  counter?: number;
} = {}) {
  const value = Buffer.alloc(37);
  createHash('sha256').update(rpId, 'utf8').digest().copy(value, 0);
  value[32] = flags;
  value.writeUInt32BE(counter, 33);
  return value.toString('base64url');
}

function registrationResponse(challenge: string, overrides: Record<string, unknown> = {}) {
  return {
    id: 'credential_adoption_123456789w',
    rawId: 'credential_adoption_123456789w',
    type: 'public-key',
    response: {
      clientDataJSON: clientData('webauthn.create', challenge),
      attestationObject: 'AA',
      transports: ['internal'],
    },
    clientExtensionResults: {},
    ...overrides,
  };
}

function assertionResponse(
  challenge: string,
  counter = 1,
  overrides: Record<string, unknown> = {},
) {
  return {
    id: 'credential_adoption_123456789w',
    rawId: 'credential_adoption_123456789w',
    type: 'public-key',
    response: {
      clientDataJSON: clientData('webauthn.get', challenge),
      authenticatorData: authenticatorData({ counter }),
      signature: 'AA',
      userHandle: null,
    },
    clientExtensionResults: {},
    ...overrides,
  };
}

const CREDENTIAL: Readonly<AgentAdoptionCredentialMaterial> = Object.freeze({
  claim_boundary: AGENT_ADOPTION_WEBAUTHN_CLAIM_BOUNDARY,
  algorithm: 'ES256',
  curve: 'P-256',
  credential_id: 'credential_adoption_123456789w',
  public_key_cose: 'AQID',
  public_key_spki: 'BAUG',
  transports: ['internal'] as AgentAdoptionCredentialMaterial['transports'],
  device_type: 'singleDevice',
  backed_up: false,
  sign_count: 0,
  counter_supported: false,
  rp_id: RP_ID,
  origin: ORIGIN,
});

beforeEach(() => {
  mocks.generateRegistrationOptions.mockReset().mockImplementation(async (input) => ({
    challenge: input.challenge,
    rp: { id: input.rpID, name: input.rpName },
    user: { id: 'candidate', name: input.userName, displayName: input.userDisplayName },
  }));
  mocks.verifyRegistrationResponse.mockReset().mockImplementation(async ({ response }) => ({
    verified: true,
    registrationInfo: {
      fmt: 'none',
      credential: {
        id: response.id,
        publicKey: new Uint8Array([1, 2, 3]),
        counter: 0,
        transports: ['internal'],
      },
      userVerified: true,
      credentialDeviceType: 'singleDevice',
      credentialBackedUp: false,
      origin: ORIGIN,
      rpID: RP_ID,
    },
  }));
  mocks.generateAuthenticationOptions.mockReset().mockImplementation(async (input) => ({
    challenge: input.challenge,
    rpId: input.rpID,
    allowCredentials: input.allowCredentials,
    userVerification: input.userVerification,
  }));
  mocks.verifyAuthenticationResponse.mockReset().mockImplementation(async ({ response }) => {
    const bytes = Buffer.from(response.response.authenticatorData, 'base64url');
    return {
      verified: true,
      authenticationInfo: {
        credentialID: response.id,
        newCounter: bytes.readUInt32BE(33),
        userVerified: true,
        credentialDeviceType: 'singleDevice',
        credentialBackedUp: false,
        origin: ORIGIN,
        rpID: RP_ID,
      },
    };
  });
  mocks.coseToSpkiP256.mockReset().mockReturnValue(Buffer.from([4, 5, 6]));
});

describe('agent-adoption WebAuthn contexts and claim boundary', () => {
  it('builds separate closed registration and assertion contexts', () => {
    const registration = registrationContext();
    const assertion = assertionContext();

    expect(registration).toEqual({
      '@version': AGENT_ADOPTION_WEBAUTHN_VERSION,
      context_type: AGENT_ADOPTION_WEBAUTHN_REGISTRATION_CONTEXT_TYPE,
      claim_boundary: AGENT_ADOPTION_WEBAUTHN_CLAIM_BOUNDARY,
      tenant_id: CONTEXT_INPUT.tenantId,
      adoption_id: CONTEXT_INPUT.adoptionId,
      candidate_digest: CONTEXT_INPUT.candidateDigest,
      bond_digest: CONTEXT_INPUT.bondDigest,
      bond_purpose: CONTEXT_INPUT.bondPurpose,
      nonce: CONTEXT_INPUT.nonce,
      issued_at: CONTEXT_INPUT.issuedAt,
      expires_at: CONTEXT_INPUT.expiresAt,
      rp_id: RP_ID,
      origin: ORIGIN,
    });
    expect(assertion).toEqual({
      ...registration,
      context_type: AGENT_ADOPTION_WEBAUTHN_ASSERTION_CONTEXT_TYPE,
    });
    expect(Object.isFrozen(registration)).toBe(true);
    expect(Object.keys(registration)).not.toContain('approver_credentials');
    expect(Object.keys(registration)).not.toContain('key_class');
  });

  it('states every public no-egress non-claim in challenge-bound text', () => {
    for (const boundary of [
      'public_no_egress_agent_adoption_evidence_only',
      'not_real_money',
      'not_provider_credentials',
      'not_civil_identity',
      'not_certification',
      'not_marketplace',
      'not_production_execution',
    ]) {
      expect(AGENT_ADOPTION_WEBAUTHN_CLAIM_BOUNDARY).toContain(boundary);
    }
  });

  it.each([
    ['tenant', { tenantId: 'tenant_other' }],
    ['adoption', { adoptionId: 'adoption_other' }],
    ['candidate digest', { candidateDigest: `sha256:${'c'.repeat(64)}` }],
    ['bond digest', { bondDigest: `sha256:${'d'.repeat(64)}` }],
    ['bond purpose', { bondPurpose: 'synthetic_other_purpose' }],
    ['nonce', { nonce: 'adoption_nonce_fedcba0987654321' }],
    ['issued time', { issuedAt: '2030-01-01T00:00:01.000Z' }],
    ['expiry', { expiresAt: '2030-01-01T00:04:59.000Z' }],
    ['RP ID', { rpId: 'other.example.test', origin: 'https://other.example.test' }],
    ['origin', { origin: 'https://sub.adopt.example.test' }],
  ])('changes the challenge when the bound %s changes', (_name, override) => {
    expect(agentAdoptionWebAuthnChallenge(assertionContext(override)))
      .not.toBe(agentAdoptionWebAuthnChallenge(assertionContext()));
  });

  it.each([
    [{ tenantId: 'x'.repeat(129) }, /tenant/i],
    [{ adoptionId: '' }, /adoption/i],
    [{ candidateDigest: `sha256:${'A'.repeat(64)}` }, /candidate.*digest/i],
    [{ bondDigest: 'sha256:short' }, /bond.*digest/i],
    [{ bondPurpose: 'real_money_transfer' }, /bond.*purpose/i],
    [{ bondPurpose: 'x'.repeat(129) }, /bond.*purpose/i],
    [{ nonce: 'short' }, /nonce/i],
    [{ issuedAt: 'not-a-time' }, /issued/i],
    [{ expiresAt: CONTEXT_INPUT.issuedAt }, /expiry/i],
    [{ rpId: 'https://adopt.example.test' }, /RP/i],
    [{ origin: 'https://adopt.example.test/path' }, /origin/i],
    [{ origin: 'https://evil.example.test' }, /origin/i],
  ])('refuses malformed or oversized context input %#', (override, message) => {
    expect(() => registrationContext(override)).toThrow(message);
  });
});

describe('agent-adoption WebAuthn registration', () => {
  it('generates adoption-only ES256 options bound to the exact context', async () => {
    const context = registrationContext();
    const ceremony = await createAgentAdoptionRegistrationOptions({
      context,
      rpName: 'EMILIA Agent Adoption',
      existingCredentials: [{ credential_id: 'existing_credential_1234', transports: ['usb'] }],
      now: NOW,
    });

    expect(mocks.generateRegistrationOptions).toHaveBeenCalledWith({
      rpName: 'EMILIA Agent Adoption',
      rpID: RP_ID,
      userID: Buffer.from('a'.repeat(64), 'hex'),
      userName: CONTEXT_INPUT.adoptionId,
      userDisplayName: CONTEXT_INPUT.adoptionId,
      challenge: agentAdoptionWebAuthnChallenge(context),
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required',
      },
      supportedAlgorithmIDs: [-7],
      excludeCredentials: [{ id: 'existing_credential_1234', transports: ['usb'] }],
    });
    expect(ceremony).toMatchObject({
      context,
      challenge: agentAdoptionWebAuthnChallenge(context),
      rp_id: RP_ID,
      origin: ORIGIN,
      expires_at: CONTEXT_INPUT.expiresAt,
    });
  });

  it('strictly verifies UP+UV, exact challenge/origin/RP, and ES256 P-256', async () => {
    const ceremony = await createAgentAdoptionRegistrationOptions({
      context: registrationContext(),
      now: NOW,
    });
    const attestation = registrationResponse(ceremony.challenge);

    await expect(verifyAgentAdoptionRegistration({ ceremony, attestation, now: NOW }))
      .resolves.toEqual(CREDENTIAL);
    expect(mocks.verifyRegistrationResponse).toHaveBeenCalledWith({
      response: attestation,
      expectedChallenge: ceremony.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      expectedType: 'webauthn.create',
      requireUserPresence: true,
      requireUserVerification: true,
      supportedAlgorithmIDs: [-7],
    });
    expect(mocks.coseToSpkiP256).toHaveBeenCalledWith(new Uint8Array([1, 2, 3]));
  });

  it.each([
    ['challenge', (ceremony) => registrationResponse('wrong_challenge_1234567890')],
    ['origin', (ceremony) => ({
      ...registrationResponse(ceremony.challenge),
      response: {
        ...registrationResponse(ceremony.challenge).response,
        clientDataJSON: clientData('webauthn.create', ceremony.challenge, 'https://evil.example.test'),
      },
    })],
  ])('refuses a wrong client-data %s before the WebAuthn verifier', async (_name, response) => {
    const ceremony = await createAgentAdoptionRegistrationOptions({
      context: registrationContext(),
      now: NOW,
    });
    await expect(verifyAgentAdoptionRegistration({
      ceremony,
      attestation: response(ceremony),
      now: NOW,
    })).rejects.toMatchObject({ code: 'registration_client_data_invalid' });
    expect(mocks.verifyRegistrationResponse).not.toHaveBeenCalled();
  });

  it('refuses verifier RP drift, missing UV, and a non-P-256 public key', async () => {
    const ceremony = await createAgentAdoptionRegistrationOptions({
      context: registrationContext(),
      now: NOW,
    });
    const attestation = registrationResponse(ceremony.challenge);

    mocks.verifyRegistrationResponse.mockResolvedValueOnce({
      verified: true,
      registrationInfo: {
        credential: { id: attestation.id, publicKey: new Uint8Array([1]), counter: 0 },
        userVerified: true,
        credentialDeviceType: 'singleDevice',
        credentialBackedUp: false,
        origin: ORIGIN,
        rpID: 'wrong.example.test',
      },
    });
    await expect(verifyAgentAdoptionRegistration({ ceremony, attestation, now: NOW }))
      .rejects.toMatchObject({ code: 'registration_scope_invalid' });

    mocks.verifyRegistrationResponse.mockResolvedValueOnce({
      verified: true,
      registrationInfo: {
        credential: { id: attestation.id, publicKey: new Uint8Array([1]), counter: 0 },
        userVerified: false,
        credentialDeviceType: 'singleDevice',
        credentialBackedUp: false,
        origin: ORIGIN,
        rpID: RP_ID,
      },
    });
    await expect(verifyAgentAdoptionRegistration({ ceremony, attestation, now: NOW }))
      .rejects.toMatchObject({ code: 'registration_user_verification_required' });

    mocks.coseToSpkiP256.mockImplementationOnce(() => {
      throw new Error('not P-256');
    });
    await expect(verifyAgentAdoptionRegistration({ ceremony, attestation, now: NOW }))
      .rejects.toMatchObject({ code: 'registration_key_unsupported' });
  });
});

describe('agent-adoption WebAuthn assertion', () => {
  it('generates an exact-credential UV-required assertion challenge', async () => {
    const context = assertionContext();
    const ceremony = await createAgentAdoptionAssertionOptions({
      context,
      credential: CREDENTIAL,
      now: NOW,
    });

    expect(mocks.generateAuthenticationOptions).toHaveBeenCalledWith({
      rpID: RP_ID,
      challenge: agentAdoptionWebAuthnChallenge(context),
      allowCredentials: [{
        id: CREDENTIAL.credential_id,
        transports: CREDENTIAL.transports,
      }],
      userVerification: 'required',
    });
    expect(ceremony).toMatchObject({
      context,
      challenge: agentAdoptionWebAuthnChallenge(context),
      rp_id: RP_ID,
      origin: ORIGIN,
      expires_at: CONTEXT_INPUT.expiresAt,
      credential_id: CREDENTIAL.credential_id,
    });
  });

  it('verifies the exact credential and returns monotonic counter/device metadata', async () => {
    const ceremony = await createAgentAdoptionAssertionOptions({
      context: assertionContext(),
      credential: CREDENTIAL,
      now: NOW,
    });
    const assertion = assertionResponse(ceremony.challenge, 1);

    await expect(verifyAgentAdoptionAssertion({
      ceremony,
      assertion,
      credential: CREDENTIAL,
      now: NOW,
    })).resolves.toEqual({
      claim_boundary: AGENT_ADOPTION_WEBAUTHN_CLAIM_BOUNDARY,
      credential_id: CREDENTIAL.credential_id,
      transports: ['internal'],
      device_type: 'singleDevice',
      backed_up: false,
      sign_count: 1,
      counter_supported: true,
      rp_id: RP_ID,
      origin: ORIGIN,
    });
    expect(mocks.verifyAuthenticationResponse).toHaveBeenCalledWith({
      response: assertion,
      expectedChallenge: ceremony.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      expectedType: 'webauthn.get',
      credential: {
        id: CREDENTIAL.credential_id,
        publicKey: new Uint8Array(Buffer.from(CREDENTIAL.public_key_cose, 'base64url')),
        counter: 0,
        transports: ['internal'],
      },
      requireUserVerification: true,
    });
  });

  it.each([
    ['credential', () => ({ id: 'other_credential_123456', rawId: 'other_credential_123456' })],
    ['challenge', (ceremony) => ({
      response: {
        ...assertionResponse(ceremony.challenge).response,
        clientDataJSON: clientData('webauthn.get', 'wrong_challenge_1234567890'),
      },
    })],
    ['origin', (ceremony) => ({
      response: {
        ...assertionResponse(ceremony.challenge).response,
        clientDataJSON: clientData('webauthn.get', ceremony.challenge, 'https://evil.example.test'),
      },
    })],
    ['RP ID', () => ({
      response: {
        ...assertionResponse('placeholder').response,
        authenticatorData: authenticatorData({ rpId: 'evil.example.test' }),
      },
    })],
    ['UP', () => ({
      response: {
        ...assertionResponse('placeholder').response,
        authenticatorData: authenticatorData({ flags: 0x04 }),
      },
    })],
    ['UV', () => ({
      response: {
        ...assertionResponse('placeholder').response,
        authenticatorData: authenticatorData({ flags: 0x01 }),
      },
    })],
  ])('refuses wrong %s before cryptographic verification', async (_name, change) => {
    const ceremony = await createAgentAdoptionAssertionOptions({
      context: assertionContext(),
      credential: CREDENTIAL,
      now: NOW,
    });
    const base = assertionResponse(ceremony.challenge, 1);
    const changed: any = change(ceremony);
    const response: any = {
      ...base,
      ...changed,
      response: { ...base.response, ...(changed.response || {}) },
    };
    // RP/flag changes use a placeholder client-data fixture above; restore the
    // ceremony-bound client data so each case isolates the intended check.
    if (['RP ID', 'UP', 'UV'].includes(_name)) {
      response.response.clientDataJSON = base.response.clientDataJSON;
    }
    await expect(verifyAgentAdoptionAssertion({
      ceremony,
      assertion: response,
      credential: CREDENTIAL,
      now: NOW,
    })).rejects.toMatchObject({ code: expect.stringMatching(/^assertion_/) });
    expect(mocks.verifyAuthenticationResponse).not.toHaveBeenCalled();
  });

  it('allows 0/0 as unsupported and requires every nonzero counter to increase', async () => {
    const ceremony = await createAgentAdoptionAssertionOptions({
      context: assertionContext(),
      credential: CREDENTIAL,
      now: NOW,
    });
    const unsupported = assertionResponse(ceremony.challenge, 0);
    await expect(verifyAgentAdoptionAssertion({
      ceremony,
      assertion: unsupported,
      credential: CREDENTIAL,
      now: NOW,
    })).resolves.toMatchObject({ sign_count: 0, counter_supported: false });

    const prior = { ...CREDENTIAL, sign_count: 7, counter_supported: true };
    const nextCeremony = await createAgentAdoptionAssertionOptions({
      context: assertionContext(),
      credential: prior,
      now: NOW,
    });
    await expect(verifyAgentAdoptionAssertion({
      ceremony: nextCeremony,
      assertion: assertionResponse(nextCeremony.challenge, 7),
      credential: prior,
      now: NOW,
    })).rejects.toMatchObject({ code: 'assertion_counter_not_monotonic' });
    expect(mocks.verifyAuthenticationResponse).toHaveBeenCalledTimes(1);
  });

  it('refuses missing backed-up metadata instead of silently normalizing it', async () => {
    const ceremony = await createAgentAdoptionAssertionOptions({
      context: assertionContext(),
      credential: CREDENTIAL,
      now: NOW,
    });
    mocks.verifyAuthenticationResponse.mockResolvedValueOnce({
      verified: true,
      authenticationInfo: {
        credentialID: CREDENTIAL.credential_id,
        newCounter: 1,
        userVerified: true,
        credentialDeviceType: 'singleDevice',
        origin: ORIGIN,
        rpID: RP_ID,
      },
    });
    await expect(verifyAgentAdoptionAssertion({
      ceremony,
      assertion: assertionResponse(ceremony.challenge),
      credential: CREDENTIAL,
      now: NOW,
    })).rejects.toMatchObject({ code: 'assertion_metadata_invalid' });
  });
});

describe('agent-adoption WebAuthn hostile ceremony handling', () => {
  it('refuses cross-tenant/context replay before invoking a verifier', async () => {
    const ceremony = await createAgentAdoptionAssertionOptions({
      context: assertionContext(),
      credential: CREDENTIAL,
      now: NOW,
    });
    const replay = {
      ...ceremony,
      context: assertionContext({ tenantId: 'tenant_other' }),
    };
    await expect(verifyAgentAdoptionAssertion({
      ceremony: replay,
      assertion: assertionResponse(ceremony.challenge),
      credential: CREDENTIAL,
      now: NOW,
    })).rejects.toMatchObject({ code: 'ceremony_context_mismatch' });
    expect(mocks.verifyAuthenticationResponse).not.toHaveBeenCalled();
  });

  it.each([
    ['challenge', { challenge: 'tampered_challenge_1234567890' }],
    ['RP', { rp_id: 'other.example.test' }],
    ['origin', { origin: 'https://other.example.test' }],
    ['expiry', { expires_at: '2030-01-01T00:04:00.000Z' }],
  ])('refuses stored ceremony %s drift', async (_name, override) => {
    const ceremony = await createAgentAdoptionAssertionOptions({
      context: assertionContext(),
      credential: CREDENTIAL,
      now: NOW,
    });
    await expect(verifyAgentAdoptionAssertion({
      ceremony: { ...ceremony, ...override },
      assertion: assertionResponse(ceremony.challenge),
      credential: CREDENTIAL,
      now: NOW,
    })).rejects.toMatchObject({ code: 'ceremony_context_mismatch' });
    expect(mocks.verifyAuthenticationResponse).not.toHaveBeenCalled();
  });

  it('refuses expired contexts before option generation or verification', async () => {
    const context = assertionContext();
    await expect(createAgentAdoptionAssertionOptions({
      context,
      credential: CREDENTIAL,
      now: Date.parse(CONTEXT_INPUT.expiresAt),
    })).rejects.toMatchObject({ code: 'context_expired' });

    const ceremony = await createAgentAdoptionAssertionOptions({
      context,
      credential: CREDENTIAL,
      now: NOW,
    });
    await expect(verifyAgentAdoptionAssertion({
      ceremony,
      assertion: assertionResponse(ceremony.challenge),
      credential: CREDENTIAL,
      now: Date.parse(CONTEXT_INPUT.expiresAt),
    })).rejects.toMatchObject({ code: 'context_expired' });
    expect(mocks.verifyAuthenticationResponse).not.toHaveBeenCalled();
  });

  it('rejects oversized responses and credential material before dependencies', async () => {
    const registration = await createAgentAdoptionRegistrationOptions({
      context: registrationContext(),
      now: NOW,
    });
    const oversized = registrationResponse(registration.challenge);
    oversized.response.attestationObject = 'A'.repeat(300_000);
    await expect(verifyAgentAdoptionRegistration({
      ceremony: registration,
      attestation: oversized,
      now: NOW,
    })).rejects.toMatchObject({ code: 'registration_response_too_large' });
    expect(mocks.verifyRegistrationResponse).not.toHaveBeenCalled();

    const assertion = await createAgentAdoptionAssertionOptions({
      context: assertionContext(),
      credential: CREDENTIAL,
      now: NOW,
    });
    await expect(verifyAgentAdoptionAssertion({
      ceremony: assertion,
      assertion: assertionResponse(assertion.challenge),
      credential: { ...CREDENTIAL, public_key_cose: 'A'.repeat(3_000) },
      now: NOW,
    })).rejects.toMatchObject({ code: 'credential_invalid' });
    expect(mocks.verifyAuthenticationResponse).not.toHaveBeenCalled();
    expect(mocks.coseToSpkiP256).not.toHaveBeenCalled();
  });
});
