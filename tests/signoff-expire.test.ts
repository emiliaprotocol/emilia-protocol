/**
 * Tests for the atomic accountable-signoff expiry wrappers.
 *
 * @license Apache-2.0
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockGetServiceClient = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args: unknown[]) => mockGetServiceClient(...args),
}));

import { expireAttestation, expireChallenge } from '../lib/signoff/expire.js';

function clientWithRpc(result: { data?: unknown; error?: unknown } = {}) {
  return {
    rpc: vi.fn().mockResolvedValue({ data: null, error: null, ...result }),
  };
}

describe('signoff expiry wrappers', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('validates challenge expiry inputs', async () => {
    await expect(expireChallenge({
      challengeId: '',
      actor: { entity_id: 'system' },
    })).rejects.toMatchObject({ code: 'MISSING_CHALLENGE_ID', status: 400 });
    await expect(expireChallenge({
      challengeId: 'challenge-1',
      actor: { entity_id: '' },
    })).rejects.toMatchObject({ code: 'MISSING_ACTOR', status: 400 });
  });

  it('calls expire_challenge_atomic and returns its authoritative row', async () => {
    const expired = { challenge_id: 'challenge-1', status: 'expired' };
    const client = clientWithRpc({ data: expired });
    mockGetServiceClient.mockReturnValue(client);

    await expect(expireChallenge({
      challengeId: 'challenge-1',
      actor: { entity_id: 'system' },
    })).resolves.toEqual(expired);
    expect(client.rpc).toHaveBeenCalledWith('expire_challenge_atomic', {
      p_challenge_id: 'challenge-1',
      p_actor_entity_ref: 'system',
    });
  });

  it.each([
    ['SIGNOFF_CHALLENGE_NOT_FOUND', 404, 'CHALLENGE_NOT_FOUND'],
    ['SIGNOFF_CHALLENGE_NOT_EXPIRABLE', 409, 'INVALID_STATE_FOR_EXPIRY'],
    ['SIGNOFF_CHALLENGE_NOT_EXPIRED', 409, 'SIGNOFF_CHALLENGE_NOT_EXPIRED'],
  ])('maps challenge RPC error %s', async (message, status, code) => {
    mockGetServiceClient.mockReturnValue(clientWithRpc({ error: { message } }));
    await expect(expireChallenge({
      challengeId: 'challenge-1',
      actor: { entity_id: 'system' },
    })).rejects.toMatchObject({ status, code });
  });

  it('validates attestation expiry inputs', async () => {
    await expect(expireAttestation({
      signoffId: '',
      actor: { entity_id: 'system' },
    })).rejects.toMatchObject({ code: 'MISSING_SIGNOFF_ID', status: 400 });
    await expect(expireAttestation({
      signoffId: 'signoff-1',
      actor: { entity_id: '' },
    })).rejects.toMatchObject({ code: 'MISSING_ACTOR', status: 400 });
  });

  it('calls expire_attestation_atomic and returns its authoritative row', async () => {
    const expired = { signoff_id: 'signoff-1', status: 'expired' };
    const client = clientWithRpc({ data: expired });
    mockGetServiceClient.mockReturnValue(client);

    await expect(expireAttestation({
      signoffId: 'signoff-1',
      actor: { entity_id: 'system' },
    })).resolves.toEqual(expired);
    expect(client.rpc).toHaveBeenCalledWith('expire_attestation_atomic', {
      p_signoff_id: 'signoff-1',
      p_actor_entity_ref: 'system',
    });
  });

  it.each([
    ['SIGNOFF_ATTESTATION_NOT_FOUND', 404, 'ATTESTATION_NOT_FOUND'],
    ['SIGNOFF_ATTESTATION_NOT_EXPIRABLE', 409, 'INVALID_STATE_FOR_EXPIRY'],
    ['SIGNOFF_ATTESTATION_NOT_EXPIRED', 409, 'SIGNOFF_ATTESTATION_NOT_EXPIRED'],
    ['SIGNOFF_ATTESTATION_BINDING_MISMATCH', 409, 'SIGNOFF_ATTESTATION_BINDING_MISMATCH'],
  ])('maps attestation RPC error %s', async (message, status, code) => {
    mockGetServiceClient.mockReturnValue(clientWithRpc({ error: { message } }));
    await expect(expireAttestation({
      signoffId: 'signoff-1',
      actor: { entity_id: 'system' },
    })).rejects.toMatchObject({ status, code });
  });

  it('does not swallow unexpected database failures', async () => {
    mockGetServiceClient.mockReturnValue(clientWithRpc({
      error: { message: 'connection refused' },
    }));
    await expect(expireChallenge({
      challengeId: 'challenge-1',
      actor: { entity_id: 'system' },
    })).rejects.toMatchObject({ code: 'DB_ERROR', status: 500 });
  });
});
