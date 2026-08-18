// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';
import { createReleaseLockService } from './service.js';

const NOW = Date.parse('2030-01-01T00:00:00.000Z');
const LOCK_ID = `rlk_${'1'.repeat(32)}`;
const SESSION = 'session-token';
const RP = Object.freeze({
  rpID: 'example.com',
  origin: 'https://example.com',
});

function cryptoSuite() {
  return {
    invitation: vi.fn(() => ({ token: 'invite-token', digest: 'invite-digest' })),
    invitationDigest: vi.fn((token) => `invite:${token}`),
    pairing: vi.fn(() => ({ token: 'pair-token', digest: 'pair-digest' })),
    pairingDigest: vi.fn((token) => `pair:${token}`),
    session: vi.fn(() => ({ token: SESSION, digest: 'session-digest' })),
    sessionDigest: vi.fn((token) => `session:${token}`),
  };
}

function service({
  rpc = vi.fn(async (name) => ({ data: { operation: name }, error: null })),
  adapters = {},
  ...overrides
}: any = {}) {
  return createReleaseLockService({
    rpc,
    cryptoSuite: cryptoSuite(),
    adapters: {
      fetchDocument: vi.fn(),
      executeEffect: vi.fn(),
      reconcileEffect: vi.fn(),
      ...adapters,
    },
    now: () => NOW,
    randomUUID: () => '11111111-1111-4111-8111-111111111111',
    rpConfigProvider: () => RP,
    ...overrides,
  });
}

describe('Release Lock service public contract', () => {
  it('rejects missing required dependencies', () => {
    expect(() => createReleaseLockService()).toThrow('rpc adapter is required');
    expect(() => createReleaseLockService({ rpc: vi.fn() })).toThrow('crypto suite is required');
    expect(() => createReleaseLockService({ rpc: vi.fn(), cryptoSuite: {} }))
      .toThrow('provider adapters are required');
    expect(() => createReleaseLockService({
      rpc: vi.fn(),
      cryptoSuite: {},
      adapters: {},
      randomUUID: null,
    })).toThrow('randomUUID is required');
  });

  it.each([
    [{}, 'Invitation exchange is malformed.'],
    [{ token: 'x', lock_id: LOCK_ID, role: 'intruder' }, 'Invitation exchange is malformed.'],
  ])('rejects malformed invitation exchange %#', async (input, message) => {
    await expect(service().exchangeInvitation(input)).rejects.toThrow(message);
  });

  it('round-trips invitation, pairing, session, and participant-view RPCs', async () => {
    const rpc = vi.fn(async (name, args) => ({ data: { name, args }, error: null }));
    const target = service({ rpc });

    await expect(target.exchangeInvitation({
      token: 'invite-token',
      lock_id: LOCK_ID,
      role: 'customer',
    })).resolves.toMatchObject({
      name: 'release_lock_exchange_invitation',
      rawSessionToken: SESSION,
    });
    await expect(target.createPairing({
      rawSessionToken: SESSION,
      lockId: LOCK_ID,
      round: 'CO_ACCEPTED',
    })).resolves.toMatchObject({
      name: 'release_lock_create_pairing',
      rawPairingToken: 'pair-token',
    });
    await expect(target.exchangePairing({
      token: 'pair-token',
      lock_id: LOCK_ID,
      role: 'contractor',
      round: 'DRAW_RELEASE',
    })).resolves.toMatchObject({
      name: 'release_lock_exchange_pairing',
      rawSessionToken: SESSION,
    });
    await expect(target.resolveSession(SESSION, LOCK_ID)).resolves.toMatchObject({
      name: 'release_lock_resolve_session',
    });
    await expect(target.participantView({ rawSessionToken: SESSION, lockId: LOCK_ID }))
      .resolves.toMatchObject({ name: 'release_lock_participant_view' });

    expect(rpc).toHaveBeenCalledTimes(5);
  });

  it.each([
    ['createPairing', { rawSessionToken: SESSION, lockId: LOCK_ID, round: 'INVALID' }],
    ['exchangePairing', { token: 'x', lock_id: LOCK_ID, role: 'customer', round: 'INVALID' }],
    ['completeRegistration', { rawSessionToken: SESSION, lockId: LOCK_ID, input: {} }],
    ['amendLock', {
      organizationId: 'org', contractorEntityId: 'actor', lockId: LOCK_ID, expectedVersion: 0, input: {},
    }],
    ['actionCheckOptions', { rawSessionToken: SESSION, lockId: LOCK_ID, round: 'INVALID' }],
    ['approve', { rawSessionToken: SESSION, lockId: LOCK_ID, round: 'INVALID', input: {} }],
  ])('rejects malformed %s input before storage', async (method, input) => {
    const rpc = vi.fn();
    await expect(service({ rpc })[method](input)).rejects.toMatchObject({ status: 400 });
    expect(rpc).not.toHaveBeenCalled();
  });

  it('maps absent RPC envelopes and absent RPC data to storage-unavailable refusals', async () => {
    for (const result of [null, { data: null, error: null }]) {
      const target = service({ rpc: vi.fn(async () => result) });
      await expect(target.evidence({ organizationId: 'org', lockId: LOCK_ID }))
        .rejects.toMatchObject({ status: 503, code: 'release_lock_storage_unavailable' });
    }
  });

  it('requires an invitation-delivery adapter before validating lock input', async () => {
    await expect(service().createLock({
      organizationId: 'org',
      contractorEntityId: 'actor',
      input: {},
    })).rejects.toMatchObject({
      status: 503,
      code: 'invitation_delivery_adapter_unconfigured',
    });
  });

  it('begins and completes registration under one RP policy', async () => {
    const rpc = vi.fn(async (name) => {
      if (name === 'release_lock_resolve_session') {
        return { data: { session_expires_at: '2030-01-01T01:00:00.000Z' }, error: null };
      }
      if (name === 'release_lock_load_registration') {
        return { data: { challenge: 'challenge' }, error: null };
      }
      return { data: { operation: name }, error: null };
    });
    const registrationOptions = vi.fn(async () => ({
      challenge: 'registration-challenge',
      rpId: RP.rpID,
      origin: RP.origin,
      expiresAt: '2030-01-01T00:05:00.000Z',
      options: { challenge: 'registration-challenge' },
    }));
    const registrationVerifier = vi.fn(async () => ({
      credentialId: 'credential_123456',
      publicKeyCose: 'cose-key',
      publicKeySpki: 'spki-key',
      signCount: 1,
      transports: ['internal'],
      deviceType: 'singleDevice',
      backedUp: false,
      attestationFormat: 'none',
      rpId: RP.rpID,
      origin: RP.origin,
    }));
    const target = service({ rpc, registrationOptions, registrationVerifier });

    await expect(target.beginRegistration({ rawSessionToken: SESSION, lockId: LOCK_ID }))
      .resolves.toMatchObject({
        challenge_id: '11111111-1111-4111-8111-111111111111',
        claims: {
          identity_verified: false,
          biometric_verified: false,
          device_bound_claimed: false,
        },
      });
    await expect(target.completeRegistration({
      rawSessionToken: SESSION,
      lockId: LOCK_ID,
      input: { challenge_id: 'challenge-id', attestation: { id: 'attestation' } },
    })).resolves.toMatchObject({ operation: 'release_lock_complete_registration' });
    expect(registrationOptions).toHaveBeenCalledOnce();
    expect(registrationVerifier).toHaveBeenCalledWith(expect.objectContaining({ rpConfig: RP }));
  });

  it('builds and stores an action-check challenge under the enrolled credential policy', async () => {
    const rpc = vi.fn(async (name) => {
      if (name === 'release_lock_action_check_context') {
        return {
          data: {
            version: 3,
            role: 'customer',
            contact_binding_id: 'contact-1',
            contractor_entity_id: 'contractor-1',
            action: { action_type: 'release' },
            action_hash: `sha256:${'a'.repeat(64)}`,
            session_expires_at: '2030-01-01T01:00:00.000Z',
            credential: {
              credential_id: 'credential_123456',
              rp_id: RP.rpID,
              origin: RP.origin,
              transports: [],
            },
          },
          error: null,
        };
      }
      return { data: { operation: name }, error: null };
    });
    const actionCheckBuilder = vi.fn(() => ({
      challenge: Buffer.from('challenge').toString('base64url'),
      promptSet: [{ prompt_id: 'approve' }],
      promptSetDigest: `sha256:${'b'.repeat(64)}`,
      answerDigest: `sha256:${'c'.repeat(64)}`,
      bindingMoment: 'submit',
      randomNonce: 'nonce-random',
      nonce: 'nonce',
      context: { action_hash: `sha256:${'a'.repeat(64)}` },
      issuedAt: '2030-01-01T00:00:00.000Z',
      expiresAt: '2030-01-01T00:05:00.000Z',
    }));
    const authenticationOptions = vi.fn(async () => ({ challenge: 'webauthn' }));
    const target = service({ rpc, actionCheckBuilder, authenticationOptions });

    await expect(target.actionCheckOptions({
      rawSessionToken: SESSION,
      lockId: LOCK_ID,
      round: 'DRAW_RELEASE',
    })).resolves.toMatchObject({
      challenge_id: '11111111-1111-4111-8111-111111111111',
      round: 'DRAW_RELEASE',
      options: { challenge: 'webauthn' },
    });
    expect(authenticationOptions).toHaveBeenCalledWith(expect.objectContaining({
      rpID: RP.rpID,
      userVerification: 'required',
    }));
  });

  it('fails closed when RP policy is absent or an enrolled credential belongs elsewhere', async () => {
    const registration = service({
      rpc: vi.fn(async () => ({
        data: { session_expires_at: '2030-01-01T01:00:00.000Z' },
        error: null,
      })),
      rpConfigProvider: () => ({}),
    });
    await expect(registration.beginRegistration({
      rawSessionToken: SESSION,
      lockId: LOCK_ID,
    })).rejects.toMatchObject({
      status: 503,
      code: 'webauthn_policy_unconfigured',
    });

    const actionCheck = service({
      rpc: vi.fn(async () => ({
        data: {
          credential: {
            credential_id: 'credential_123456',
            rp_id: 'other.example',
            origin: 'https://other.example',
          },
        },
        error: null,
      })),
    });
    await expect(actionCheck.actionCheckOptions({
      rawSessionToken: SESSION,
      lockId: LOCK_ID,
      round: 'CO_ACCEPTED',
    })).rejects.toMatchObject({
      status: 409,
      code: 'webauthn_policy_mismatch',
    });
  });

  it('refuses an effect request attached to the non-effect approval round', async () => {
    const rpc = vi.fn(async (name) => {
      if (name === 'release_lock_load_action_challenge') {
        return {
          data: {
            credential: {
              credential_id: 'credential_123456',
              rp_id: RP.rpID,
              origin: RP.origin,
            },
          },
          error: null,
        };
      }
      if (name === 'release_lock_record_approval') {
        return { data: { invoke_effect: true, effect: {} }, error: null };
      }
      throw new Error(`unexpected RPC ${name}`);
    });
    const target = service({
      rpc,
      actionCheckVerifier: vi.fn(async () => ({
        newCounter: 2,
        submittedAnswerDigest: `sha256:${'d'.repeat(64)}`,
        receipt: { profile: 'EP-RESOLUTION-v1' },
      })),
    });

    await expect(target.approve({
      rawSessionToken: SESSION,
      lockId: LOCK_ID,
      round: 'CO_ACCEPTED',
      input: { challenge_id: 'challenge-id', answers: [], assertion: {} },
    })).rejects.toThrow('CO_ACCEPTED attempted to invoke a custodian effect');
  });

  it('handles terminal, malformed, and authoritative reconciliation outcomes', async () => {
    const effect = {
      effect_reference: 'effect-1',
      provider: 'custodian',
      environment: 'sandbox',
      transaction_id: 'txn-1',
      milestone_id: 'milestone-1',
    };
    const recoveries = [
      { mode: 'terminal', result: { status: 'applied' } },
      { mode: 'reconcile' },
      { mode: 'unsupported', effect },
      { mode: 'reconcile', effect },
      { mode: 'reconcile', effect },
    ];
    const rpc = vi.fn(async (name, args) => {
      if (name === 'release_lock_recover_effect') {
        return { data: recoveries.shift(), error: null };
      }
      if (name === 'release_lock_record_effect_outcome') {
        return { data: { status: args.p_outcome }, error: null };
      }
      throw new Error(`unexpected RPC ${name}`);
    });
    const providerFailure = Object.assign(new Error('provider unavailable'), {
      code: 'provider_unavailable',
    });
    const reconcileEffect = vi.fn()
      .mockResolvedValueOnce({
        status: 'applied',
        retryable: false,
        result: { provider: 'custodian' },
      })
      .mockRejectedValueOnce(providerFailure);
    const target = service({ rpc, adapters: { reconcileEffect } });

    await expect(target.reconcile({ effectReference: 'effect-1' }))
      .resolves.toEqual({ status: 'applied' });
    await expect(target.reconcile({ effectReference: 'effect-1' }))
      .rejects.toThrow('no exact effect');
    await expect(target.reconcile({ effectReference: 'effect-1' }))
      .rejects.toThrow('unsupported mode');
    await expect(target.reconcile({ effectReference: 'effect-1' }))
      .resolves.toEqual({ status: 'applied' });
    await expect(target.reconcile({ effectReference: 'effect-1' }))
      .rejects.toBe(providerFailure);
    expect(rpc).toHaveBeenCalledWith('release_lock_record_effect_outcome', expect.objectContaining({
      p_outcome: 'unknown_effect',
      p_retryable: false,
    }));
  });
});
