// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  generateRegistrationOptions: vi.fn(),
  verifyRegistrationResponse: vi.fn(),
  coseToSpkiP256: vi.fn(),
}));

vi.mock('@simplewebauthn/server', () => ({
  generateRegistrationOptions: (...args) => mocks.generateRegistrationOptions(...args),
  verifyRegistrationResponse: (...args) => mocks.verifyRegistrationResponse(...args),
}));

vi.mock('../webauthn.js', () => ({
  coseToSpkiP256: (...args) => mocks.coseToSpkiP256(...args),
  getRpConfig: () => ({
    rpID: 'example.com',
    origin: 'https://example.com',
    rpName: 'Example RP',
  }),
}));

const {
  createReleaseLockRegistrationOptions,
  releaseLockRegistrationInternals,
  verifyReleaseLockRegistration,
} = await import('./registration.js');

const NOW = Date.parse('2030-01-01T00:00:00.000Z');
const SESSION = Object.freeze({
  lock_id: `rlk_${'a'.repeat(32)}`,
  role: 'customer',
  contact_binding_id: '11111111-1111-4111-8111-111111111111',
  expires_at: '2030-01-01T00:10:00.000Z',
  lock_expires_at: '2030-01-02T00:00:00.000Z',
});
const RP = Object.freeze({
  rpID: 'example.com',
  origin: 'https://example.com',
  rpName: 'Example RP',
});
const CHALLENGE = Object.freeze({
  challenge: 'registration-challenge',
  rp_id: RP.rpID,
  origin: RP.origin,
});

beforeEach(() => {
  mocks.generateRegistrationOptions.mockReset().mockResolvedValue({
    challenge: CHALLENGE.challenge,
  });
  mocks.verifyRegistrationResponse.mockReset().mockResolvedValue({
    verified: true,
    registrationInfo: {
      credential: {
        id: 'credential_1234567890',
        publicKey: new Uint8Array([1, 2, 3]),
      },
    },
  });
  mocks.coseToSpkiP256.mockReset().mockReturnValue(Buffer.from([4, 5, 6]));
});

describe('Release Lock passkey registration', () => {
  it.each([
    [null],
    [{}],
    [{ rpID: '', origin: RP.origin, rpName: RP.rpName }],
    [{ rpID: RP.rpID, origin: '', rpName: RP.rpName }],
    [{ rpID: RP.rpID, origin: RP.origin, rpName: 7 }],
    [{ rpID: 'x'.repeat(254), origin: RP.origin, rpName: RP.rpName }],
    [{ rpID: RP.rpID, origin: `https://${'x'.repeat(505)}`, rpName: RP.rpName }],
    [{ rpID: RP.rpID, origin: RP.origin, rpName: 'x'.repeat(129) }],
  ])('refuses an invalid RP policy %#', (policy) => {
    expect(() => releaseLockRegistrationInternals.rpPolicy(policy))
      .toThrow(expect.objectContaining({ code: 'webauthn_policy_unconfigured' }));
  });

  it('applies the default RP name when the deployment omits one', () => {
    expect(releaseLockRegistrationInternals.rpPolicy({
      rpID: RP.rpID,
      origin: RP.origin,
    })).toEqual({
      rpID: RP.rpID,
      origin: RP.origin,
      rpName: 'EMILIA Protocol',
    });
  });

  it.each([
    [undefined],
    [{}],
    [{ ...SESSION, lock_id: '' }],
    [{ ...SESSION, role: '' }],
    [{ ...SESSION, contact_binding_id: '' }],
  ])('requires a role-scoped participant session %#', async (session) => {
    await expect(createReleaseLockRegistrationOptions({
      session,
      now: NOW,
      rpConfig: RP,
    })).rejects.toMatchObject({ status: 401, code: 'session_invalid' });
  });

  it('builds direct ES256 registration options and caps challenge lifetime', async () => {
    const result = await createReleaseLockRegistrationOptions({
      session: SESSION,
      existingCredentials: [
        { credential_id: 'existing_credential_1', transports: ['internal'] },
        { credential_id: 'existing_credential_2' },
      ],
      now: () => NOW,
      rpConfig: RP,
    });

    expect(mocks.generateRegistrationOptions).toHaveBeenCalledWith(
      expect.objectContaining({
        rpName: RP.rpName,
        rpID: RP.rpID,
        attestationType: 'direct',
        supportedAlgorithmIDs: [-7],
        authenticatorSelection: {
          residentKey: 'preferred',
          userVerification: 'required',
        },
        excludeCredentials: [
          { id: 'existing_credential_1', transports: ['internal'] },
          { id: 'existing_credential_2', transports: undefined },
        ],
      }),
    );
    expect(result).toMatchObject({
      challenge: CHALLENGE.challenge,
      rpId: RP.rpID,
      origin: RP.origin,
      expiresAt: '2030-01-01T00:05:00.000Z',
    });
  });

  it('uses the earliest participant-session deadline', async () => {
    const result = await createReleaseLockRegistrationOptions({
      session: {
        ...SESSION,
        expires_at: '2030-01-01T00:02:00.000Z',
      },
      now: NOW,
      rpConfig: RP,
    });
    expect(result.expiresAt).toBe('2030-01-01T00:02:00.000Z');
  });

  it.each([
    [{}],
    [{ challenge: CHALLENGE.challenge }],
    [{ ...CHALLENGE, origin: '' }],
  ])('refuses malformed registration verification input %#', async (challenge) => {
    await expect(verifyReleaseLockRegistration({
      challenge,
      attestation: challenge.origin ? null : {},
      rpConfig: RP,
    })).rejects.toMatchObject({ status: 400, code: 'registration_invalid' });
  });

  it('refuses RP policy drift before invoking WebAuthn verification', async () => {
    await expect(verifyReleaseLockRegistration({
      challenge: CHALLENGE,
      attestation: {},
      rpConfig: { ...RP, origin: 'https://other.example' },
    })).rejects.toMatchObject({ status: 409, code: 'webauthn_policy_mismatch' });
    expect(mocks.verifyRegistrationResponse).not.toHaveBeenCalled();
  });

  it('types verifier exceptions and negative verification as attestation refusal', async () => {
    mocks.verifyRegistrationResponse.mockRejectedValueOnce(new Error('bad attestation'));
    await expect(verifyReleaseLockRegistration({
      challenge: CHALLENGE,
      attestation: {},
      rpConfig: RP,
    })).rejects.toMatchObject({ status: 400, code: 'attestation_invalid' });

    mocks.verifyRegistrationResponse.mockResolvedValueOnce({
      verified: false,
      registrationInfo: null,
    });
    await expect(verifyReleaseLockRegistration({
      challenge: CHALLENGE,
      attestation: {},
      rpConfig: RP,
    })).rejects.toMatchObject({ status: 400, code: 'attestation_invalid' });
  });

  it('refuses malformed credential identifiers and non-P-256 keys', async () => {
    mocks.verifyRegistrationResponse.mockResolvedValueOnce({
      verified: true,
      registrationInfo: {
        credential: { id: 'short', publicKey: new Uint8Array([1]) },
      },
    });
    await expect(verifyReleaseLockRegistration({
      challenge: CHALLENGE,
      attestation: {},
      rpConfig: RP,
    })).rejects.toMatchObject({ status: 400, code: 'credential_id_invalid' });

    mocks.coseToSpkiP256.mockImplementationOnce(() => {
      throw new Error('not P-256');
    });
    await expect(verifyReleaseLockRegistration({
      challenge: CHALLENGE,
      attestation: {},
      rpConfig: RP,
    })).rejects.toMatchObject({ status: 400, code: 'unsupported_credential_key' });
  });

  it('returns the exact enrolled credential and preserves attestation metadata', async () => {
    mocks.verifyRegistrationResponse.mockResolvedValueOnce({
      verified: true,
      registrationInfo: {
        credential: {
          id: 'credential_1234567890',
          publicKey: new Uint8Array([1, 2, 3]),
          counter: 7,
          transports: ['internal'],
        },
        credentialDeviceType: 'multiDevice',
        credentialBackedUp: true,
        fmt: 'packed',
      },
    });
    await expect(verifyReleaseLockRegistration({
      challenge: CHALLENGE,
      attestation: { id: 'attestation' },
      rpConfig: RP,
    })).resolves.toEqual({
      credentialId: 'credential_1234567890',
      publicKeyCose: 'AQID',
      publicKeySpki: 'BAUG',
      signCount: 7,
      transports: ['internal'],
      deviceType: 'multiDevice',
      backedUp: true,
      attestationFormat: 'packed',
      rpId: RP.rpID,
      origin: RP.origin,
    });
    expect(mocks.verifyRegistrationResponse).toHaveBeenCalledWith({
      response: { id: 'attestation' },
      expectedChallenge: CHALLENGE.challenge,
      expectedOrigin: RP.origin,
      expectedRPID: RP.rpID,
      requireUserVerification: true,
    });
  });

  it('normalizes optional authenticator metadata to explicit defaults', async () => {
    await expect(verifyReleaseLockRegistration({
      challenge: CHALLENGE,
      attestation: {},
      rpConfig: RP,
    })).resolves.toMatchObject({
      signCount: 0,
      transports: null,
      deviceType: null,
      backedUp: false,
      attestationFormat: null,
    });
  });
});
