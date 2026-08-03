// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('./source', () => ({
  AgentRecordSourceError: class AgentRecordSourceError extends Error {
    constructor(public status: number, public code: string, message = code) {
      super(message);
    }
  },
  prepareAgentRecordRefusalSource: vi.fn(),
}));

import {
  AgentRecordSourceError,
  prepareAgentRecordRefusalSource,
} from './source';
import {
  AGENT_RECORD_RETENTION_MS,
  signAgentRecordObservation,
} from './core';
import {
  AgentRecordServiceError,
  agentRecordIdForOwnerToken,
  createAgentRecord,
  loadPublicAgentRecord,
  revokeAgentRecord,
} from './service';

const ADOPTION_ID = '11111111-1111-4111-8111-111111111111';
const BOND_ID = '22222222-2222-4222-8222-222222222222';
const BOND_DIGEST = `sha256:${'b'.repeat(64)}`;
const ACTION_DIGEST = `sha256:${'c'.repeat(64)}`;
const REFUSAL_DIGEST = `sha256:${'d'.repeat(64)}`;
const ARENA_SESSION_ID = `arena_session_${'e'.repeat(32)}`;
const ARENA_TOKEN = `ep_arena_${'e'.repeat(64)}`;
const SOURCE_COMMITMENT = `sha256:${'e'.repeat(64)}`;
const ATTEMPT_ID = `arena_attempt_${'f'.repeat(32)}`;
const TRIAL_TOKEN = `epenc:v1:${'A'.repeat(64)}`;
const SESSION_TOKEN = `eaa1_${'1'.repeat(64)}`;
const OWNER_TOKEN = `ear1_${'3'.repeat(64)}`;
const CREATION_CAPABILITY = `earc1_${'4'.repeat(64)}`;
const OWNER_RECORD_DOMAIN = 'emilia-agent-record-owner-token-v1\0';
const RECORD_ID = `agent_record_${crypto.createHash('sha256')
  .update(OWNER_RECORD_DOMAIN + OWNER_TOKEN, 'utf8')
  .digest('hex')
  .slice(0, 40)}`;
const NOW = Date.parse('2026-08-02T20:01:00.000Z');
const REFUSED_AT = '2026-08-02T20:00:00.000Z';
const RETENTION_EXPIRES_AT = new Date(NOW + AGENT_RECORD_RETENTION_MS).toISOString();
const CREATION_INPUT = Object.freeze({
  trial_token: TRIAL_TOKEN,
  attempt_id: ATTEMPT_ID,
  record_id: RECORD_ID,
  owner_token: OWNER_TOKEN,
});

const authorization: any = Object.freeze({
  sessionId: ADOPTION_ID,
  sessionToken: SESSION_TOKEN,
  session: {
    adoption_id: ADOPTION_ID,
    status: 'active',
    bond_count: 1,
    latest_bond_id: BOND_ID,
    bond_digest: BOND_DIGEST,
    latest_bond_digest: BOND_DIGEST,
  },
});

const refusalSource = () => ({
  adoption_id: ADOPTION_ID,
  bond_id: BOND_ID,
  bond_digest: BOND_DIGEST,
  source_session_id: ARENA_SESSION_ID,
  source_token: ARENA_TOKEN,
  source_attempt_id: ATTEMPT_ID,
  source_commitment: SOURCE_COMMITMENT,
  source_artifact_digest: REFUSAL_DIGEST,
  action_digest: ACTION_DIGEST,
  refusal_digest: REFUSAL_DIGEST,
  refused_at: REFUSED_AT,
});

function createClient() {
  const rpc = vi.fn(async (name: string, args: Record<string, any>) => {
    if (name !== 'create_agent_record_with_capability') throw new Error(`unexpected RPC ${name}`);
    return {
      data: {
        record_id: args.p_record_id,
        created_at: args.p_observed_at,
        retention_expires_at: args.p_retention_expires_at,
        public_projection: args.p_public_projection,
      },
      error: null,
    };
  });
  return { rpc };
}

function signedObservation() {
  return signAgentRecordObservation({
    recordId: RECORD_ID,
    bondId: BOND_ID,
    bondDigest: BOND_DIGEST,
    sourceArtifactDigest: REFUSAL_DIGEST,
    actionDigest: ACTION_DIGEST,
    refusalDigest: REFUSAL_DIGEST,
    refusedAt: REFUSED_AT,
    observedAt: new Date(NOW).toISOString(),
    retentionExpiresAt: RETENTION_EXPIRES_AT,
  });
}

describe('Agent Record service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv('NODE_ENV', 'test');
    vi.stubEnv('EP_COMMIT_SIGNING_KEY', crypto.randomBytes(32).toString('base64'));
    vi.stubEnv('EP_COMMIT_SIGNING_KEYS', '');
    vi.stubEnv('EP_AGENT_RECORD_CREATION_CAPABILITY', CREATION_CAPABILITY);
    vi.mocked(prepareAgentRecordRefusalSource).mockResolvedValue(refusalSource() as any);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('implements the exact domain-separated browser record-id derivation', () => {
    expect(agentRecordIdForOwnerToken(OWNER_TOKEN)).toBe(
      'agent_record_57c9d565c4e6067446854eb778b970a039a9ac74',
    );
  });

  it('creates from the exact bound refusal without returning the owner credential', async () => {
    const client = createClient();

    const result = await createAgentRecord({
      authorization,
      input: CREATION_INPUT,
      client: client as any,
      now: NOW,
    });

    expect(prepareAgentRecordRefusalSource).toHaveBeenCalledWith({
      authorization,
      input: { trial_token: TRIAL_TOKEN, attempt_id: ATTEMPT_ID },
      client,
      now: NOW,
    });
    expect(result).toMatchObject({
      record_id: RECORD_ID,
      created_at: new Date(NOW).toISOString(),
      retention_expires_at: RETENTION_EXPIRES_AT,
    });

    const [, args] = client.rpc.mock.calls[0];
    expect(args).toMatchObject({
      p_record_id: result.record_id,
      p_owner_token: OWNER_TOKEN,
      p_adoption_id: ADOPTION_ID,
      p_adoption_session_token: SESSION_TOKEN,
      p_bond_id: BOND_ID,
      p_bond_digest: BOND_DIGEST,
      p_source_session_id: ARENA_SESSION_ID,
      p_source_token: ARENA_TOKEN,
      p_source_attempt_id: ATTEMPT_ID,
      p_source_commitment: SOURCE_COMMITMENT,
      p_source_artifact_digest: REFUSAL_DIGEST,
      p_action_digest: ACTION_DIGEST,
      p_refusal_digest: REFUSAL_DIGEST,
      p_refused_at: REFUSED_AT,
      p_observed_at: new Date(NOW).toISOString(),
      p_retention_expires_at: RETENTION_EXPIRES_AT,
      p_creation_capability: CREATION_CAPABILITY,
    });
    expect(JSON.stringify(args.p_public_projection)).not.toMatch(
      /adoption_id|session_id|owner_token|credential_id|candidate_url|source_url|arena_share_id|arena_share_|\/arena\/|\/api\/arena\/refusals|webauthn|prompt|ip_address|raw_action|action_parameters|agent_label/i,
    );
    expect(args).not.toHaveProperty('p_arena_share_id');
    expect(args).not.toHaveProperty('p_public_refusal_projection');
    expect(args.p_public_projection.record.source).toEqual({
      profile: 'EP-ACTION-REFUSAL-STATEMENT-v1',
      artifact_digest: REFUSAL_DIGEST,
    });
  });

  it.each([
    ['a missing owner credential', { ...CREATION_INPUT, owner_token: undefined }],
    ['an injected extra field', { ...CREATION_INPUT, admin: true }],
    ['a malformed encrypted trial token', { ...CREATION_INPUT, trial_token: 'plaintext' }],
  ])('rejects %s before source preparation or persistence', async (_name, input) => {
    const client = createClient();

    await expect(createAgentRecord({
      authorization,
      input,
      client: client as any,
      now: NOW,
    })).rejects.toMatchObject({ status: 400, code: 'agent_record_creation_invalid' });
    expect(prepareAgentRecordRefusalSource).not.toHaveBeenCalled();
    expect(client.rpc).not.toHaveBeenCalled();
  });

  it('rejects a caller record id that is not derived from the owner token', async () => {
    const client = createClient();

    await expect(createAgentRecord({
      authorization,
      input: { ...CREATION_INPUT, record_id: `agent_record_${'0'.repeat(40)}` },
      client: client as any,
      now: NOW,
    })).rejects.toMatchObject({ status: 400, code: 'agent_record_creation_invalid' });
    expect(prepareAgentRecordRefusalSource).not.toHaveBeenCalled();
    expect(client.rpc).not.toHaveBeenCalled();
  });

  it('rejects a non-finite observation clock before source preparation', async () => {
    const client = createClient();

    await expect(createAgentRecord({
      authorization,
      input: CREATION_INPUT,
      client: client as any,
      now: Number.NaN,
    })).rejects.toMatchObject({ status: 400, code: 'agent_record_creation_invalid' });
    expect(prepareAgentRecordRefusalSource).not.toHaveBeenCalled();
    expect(client.rpc).not.toHaveBeenCalled();
  });

  it('preserves a typed trial refusal and never reaches persistence', async () => {
    vi.mocked(prepareAgentRecordRefusalSource).mockRejectedValue(
      new AgentRecordSourceError(401, 'agent_adoption_trial_invalid', 'trial denied'),
    );
    const client = createClient();

    await expect(createAgentRecord({
      authorization,
      input: CREATION_INPUT,
      client: client as any,
      now: NOW,
    })).rejects.toMatchObject({ status: 401, code: 'agent_adoption_trial_invalid' });
    expect(client.rpc).not.toHaveBeenCalled();
  });

  it('does not misclassify an unexpected trial preparation failure', async () => {
    const failure = new Error('unexpected preparation failure');
    vi.mocked(prepareAgentRecordRefusalSource).mockRejectedValue(failure);

    await expect(createAgentRecord({
      authorization,
      input: CREATION_INPUT,
      client: createClient() as any,
      now: NOW,
    })).rejects.toBe(failure);
  });

  it.each([
    ['cross-adoption', (source: any) => { source.adoption_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'; }],
    ['cross-bond id', (source: any) => { source.bond_id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'; }],
    ['cross-bond digest', (source: any) => { source.bond_digest = `sha256:${'1'.repeat(64)}`; }],
    ['source digest substitution', (source: any) => {
      source.source_artifact_digest = `sha256:${'2'.repeat(64)}`;
    }],
    ['source commitment substitution', (source: any) => {
      source.source_commitment = 'not-a-commitment';
    }],
    ['attempt substitution', (source: any) => {
      source.source_attempt_id = `arena_attempt_${'4'.repeat(32)}`;
    }],
  ])('refuses %s before persistence', async (_name, mutate) => {
    const source: any = refusalSource();
    mutate(source);
    vi.mocked(prepareAgentRecordRefusalSource).mockResolvedValue(source);
    const client = createClient();

    await expect(createAgentRecord({
      authorization,
      input: CREATION_INPUT,
      client: client as any,
      now: NOW,
    })).rejects.toMatchObject({ code: 'agent_record_refusal_invalid' });
    expect(client.rpc).not.toHaveBeenCalled();
  });

  it('rejects a refusal source without its artifact digest before persistence', async () => {
    const source: any = refusalSource();
    delete source.source_artifact_digest;
    vi.mocked(prepareAgentRecordRefusalSource).mockResolvedValue(source);
    const client = createClient();

    await expect(createAgentRecord({
      authorization,
      input: CREATION_INPUT,
      client: client as any,
      now: NOW,
    })).rejects.toMatchObject({ code: 'agent_record_refusal_invalid' });
    expect(client.rpc).not.toHaveBeenCalled();
  });

  it('fails closed before atomic creation when the production operator key is absent', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('EP_COMMIT_SIGNING_KEY', '');
    const client = createClient();

    await expect(createAgentRecord({
      authorization,
      input: CREATION_INPUT,
      client: client as any,
      now: NOW,
    })).rejects.toMatchObject({
      status: 503,
      code: 'agent_record_operator_key_unavailable',
    });
    expect(client.rpc).not.toHaveBeenCalled();
  });

  it.each([undefined, '', `earc1_${'A'.repeat(64)}`, `earc1_${'4'.repeat(63)}`])(
    'fails closed before source access when the creation capability is %s',
    async (capability) => {
      vi.stubEnv('EP_AGENT_RECORD_CREATION_CAPABILITY', capability ?? '');
      const client = createClient();

      await expect(createAgentRecord({
        authorization,
        input: CREATION_INPUT,
        client: client as any,
        now: NOW,
      })).rejects.toMatchObject({
        status: 503,
        code: 'agent_record_creation_capability_unavailable',
      });
      expect(prepareAgentRecordRefusalSource).not.toHaveBeenCalled();
      expect(client.rpc).not.toHaveBeenCalled();
    },
  );

  it('uses one atomic mutation RPC and exposes no secondary publication path on failure', async () => {
    const client = {
      rpc: vi.fn().mockResolvedValue({
        data: null,
        error: { code: 'XX000', message: 'injected transaction failure' },
      }),
    };

    await expect(createAgentRecord({
      authorization,
      input: CREATION_INPUT,
      client: client as any,
      now: NOW,
    })).rejects.toMatchObject({
      status: 503,
      code: 'agent_record_store_unavailable',
    });
    expect(prepareAgentRecordRefusalSource).toHaveBeenCalledOnce();
    expect(client.rpc).toHaveBeenCalledTimes(1);
    expect(client.rpc).toHaveBeenCalledWith('create_agent_record_with_capability', expect.objectContaining({
      p_source_session_id: ARENA_SESSION_ID,
      p_source_token: ARENA_TOKEN,
      p_source_attempt_id: ATTEMPT_ID,
      p_source_commitment: SOURCE_COMMITMENT,
    }));
  });

  it('maps a refusal timestamp after observation to an invalid bound refusal', async () => {
    const source: any = refusalSource();
    source.refused_at = '2026-08-02T20:02:00.000Z';
    vi.mocked(prepareAgentRecordRefusalSource).mockResolvedValue(source);
    const client = createClient();

    await expect(createAgentRecord({
      authorization,
      input: CREATION_INPUT,
      client: client as any,
      now: NOW,
    })).rejects.toMatchObject({ status: 503, code: 'agent_record_refusal_invalid' });
    expect(client.rpc).not.toHaveBeenCalled();
  });

  it('maps atomic source replay to a conflict and never fabricates an owner token', async () => {
    const client = {
      rpc: vi.fn().mockResolvedValue({
        data: null,
        error: { code: '23505', message: 'duplicate source artifact digest' },
      }),
    };

    await expect(createAgentRecord({
      authorization,
      input: CREATION_INPUT,
      client: client as any,
      now: NOW,
    })).rejects.toMatchObject({ status: 409, code: 'agent_record_conflict' });
  });

  it('maps database capability denial to generic storage unavailability', async () => {
    const client = {
      rpc: vi.fn().mockResolvedValue({
        data: null,
        error: { code: '42501', message: 'capability mismatch' },
      }),
    };

    await expect(createAgentRecord({
      authorization,
      input: CREATION_INPUT,
      client: client as any,
      now: NOW,
    })).rejects.toMatchObject({ status: 503, code: 'agent_record_store_unavailable' });
  });

  it.each([
    ['invalid database input', '22023', 400, 'agent_record_invalid'],
    ['atomic credential conflict', '55000', 409, 'agent_record_conflict'],
    ['unavailable storage', 'XX000', 503, 'agent_record_store_unavailable'],
  ])('maps %s without exposing raw store errors', async (_name, code, status, expectedCode) => {
    const client = {
      rpc: vi.fn().mockResolvedValue({
        data: null,
        error: { code, message: 'database detail that must not escape' },
      }),
    };

    await expect(revokeAgentRecord({
      recordId: RECORD_ID,
      ownerToken: OWNER_TOKEN,
      client: client as any,
    })).rejects.toMatchObject({ status, code: expectedCode });
  });

  it('rejects a missing success payload from storage', async () => {
    const client = { rpc: vi.fn().mockResolvedValue({ data: null, error: null }) };

    await expect(revokeAgentRecord({
      recordId: RECORD_ID,
      ownerToken: OWNER_TOKEN,
      client: client as any,
    })).rejects.toMatchObject({ status: 503, code: 'agent_record_store_invalid' });
  });

  it('revokes with the dedicated owner credential and an operation nonce', async () => {
    const client = {
      rpc: vi.fn().mockResolvedValue({
        data: {
          record_id: RECORD_ID,
          revoked: true,
          revoked_at: '2026-08-02T20:02:00.000Z',
        },
        error: null,
      }),
    };

    await expect(revokeAgentRecord({
      recordId: RECORD_ID,
      ownerToken: OWNER_TOKEN,
      client: client as any,
    })).resolves.toEqual({
      record_id: RECORD_ID,
      revoked: true,
      revoked_at: '2026-08-02T20:02:00.000Z',
    });
    expect(client.rpc).toHaveBeenCalledWith('revoke_agent_record', {
      p_record_id: RECORD_ID,
      p_owner_token: OWNER_TOKEN,
      p_revocation_nonce: expect.stringMatching(/^earv1_[0-9a-f]{64}$/),
    });
  });

  it.each([
    ['invalid record id', 'not-a-record', OWNER_TOKEN],
    ['invalid owner token', RECORD_ID, 'ear1_not-hex'],
    ['mismatched record and owner pair', `agent_record_${'0'.repeat(40)}`, OWNER_TOKEN],
  ])('rejects an %s before revocation storage', async (_name, recordId, ownerToken) => {
    const client = { rpc: vi.fn() };

    await expect(revokeAgentRecord({
      recordId,
      ownerToken,
      client: client as any,
    })).rejects.toMatchObject({ status: 400, code: 'agent_record_owner_credential_invalid' });
    expect(client.rpc).not.toHaveBeenCalled();
  });

  it('rejects an inconsistent revocation result', async () => {
    const client = {
      rpc: vi.fn().mockResolvedValue({
        data: { record_id: RECORD_ID, revoked: false, revoked_at: null },
        error: null,
      }),
    };

    await expect(revokeAgentRecord({
      recordId: RECORD_ID,
      ownerToken: OWNER_TOKEN,
      client: client as any,
    })).rejects.toMatchObject({ status: 503, code: 'agent_record_store_invalid' });
  });

  it('returns the same null for unknown and revoked public records', async () => {
    const client = {
      rpc: vi.fn().mockResolvedValue({
        data: null,
        error: { code: 'P0002', message: 'agent record not found' },
      }),
    };

    await expect(loadPublicAgentRecord({ recordId: RECORD_ID, client: client as any, now: NOW }))
      .resolves.toBeNull();
    await expect(loadPublicAgentRecord({ recordId: RECORD_ID, client: client as any, now: NOW }))
      .resolves.toBeNull();
    await expect(loadPublicAgentRecord({ recordId: 'not-a-record', client: client as any, now: NOW }))
      .resolves.toBeNull();
  });

  it('loads a retained signed record and marks storage status as checked', async () => {
    const observation = signedObservation();
    const client = {
      rpc: vi.fn().mockResolvedValue({
        data: { record_id: RECORD_ID, public_projection: observation },
        error: null,
      }),
    };

    await expect(loadPublicAgentRecord({
      recordId: RECORD_ID,
      client: client as any,
      now: NOW,
    })).resolves.toMatchObject({
      record_id: RECORD_ID,
      public_projection: observation,
      verification: {
        integrity_verified: true,
        status_checked: true,
        currently_public: true,
        claim_boundary: observation.record.claim_boundary,
      },
    });
  });

  it('hides an expired but cryptographically valid public record', async () => {
    const client = {
      rpc: vi.fn().mockResolvedValue({
        data: { record_id: RECORD_ID, public_projection: signedObservation() },
        error: null,
      }),
    };

    await expect(loadPublicAgentRecord({
      recordId: RECORD_ID,
      client: client as any,
      now: Date.parse(RETENTION_EXPIRES_AT),
    })).resolves.toBeNull();
  });

  it('rejects an inconsistent public store envelope', async () => {
    const client = {
      rpc: vi.fn().mockResolvedValue({
        data: { record_id: `agent_record_${'9'.repeat(40)}`, public_projection: signedObservation() },
        error: null,
      }),
    };

    await expect(loadPublicAgentRecord({
      recordId: RECORD_ID,
      client: client as any,
      now: NOW,
    })).rejects.toMatchObject({ status: 503, code: 'agent_record_store_invalid' });
  });

  it('rejects an embedded-key substitution returned by storage', async () => {
    const observation: any = structuredClone(signAgentRecordObservation({
      recordId: RECORD_ID,
      bondId: BOND_ID,
      bondDigest: BOND_DIGEST,
      sourceArtifactDigest: REFUSAL_DIGEST,
      actionDigest: ACTION_DIGEST,
      refusalDigest: REFUSAL_DIGEST,
      refusedAt: REFUSED_AT,
      observedAt: new Date(NOW).toISOString(),
      retentionExpiresAt: RETENTION_EXPIRES_AT,
    }));
    observation.signature.public_key = crypto.randomBytes(32).toString('base64url');
    const client = {
      rpc: vi.fn().mockResolvedValue({
        data: { record_id: RECORD_ID, public_projection: observation },
        error: null,
      }),
    };

    await expect(loadPublicAgentRecord({
      recordId: RECORD_ID,
      client: client as any,
      now: NOW,
    })).rejects.toMatchObject({
      status: 503,
      code: 'agent_record_store_invalid',
    });
  });

  it('rejects storage that echoes an owner credential into the response shape', async () => {
    const client = createClient();
    client.rpc.mockImplementationOnce(async (_name, args) => ({
      data: {
        record_id: args.p_record_id,
        owner_token: 'not-an-owner-token',
        created_at: args.p_observed_at,
        retention_expires_at: args.p_retention_expires_at,
        public_projection: args.p_public_projection,
      },
      error: null,
    }));

    await expect(createAgentRecord({
      authorization,
      input: CREATION_INPUT,
      client: client as any,
      now: NOW,
    })).rejects.toMatchObject({
      status: 503,
      code: 'agent_record_store_invalid',
    });
  });

  it('rejects a persisted projection whose signature no longer verifies', async () => {
    const client = createClient();
    client.rpc.mockImplementationOnce(async (_name, args) => {
      const publicProjection: any = structuredClone(args.p_public_projection);
      publicProjection.signature.value = `${publicProjection.signature.value.startsWith('A') ? 'B' : 'A'}${publicProjection.signature.value.slice(1)}`;
      return {
        data: {
          record_id: args.p_record_id,
          created_at: args.p_observed_at,
          retention_expires_at: args.p_retention_expires_at,
          public_projection: publicProjection,
        },
        error: null,
      };
    });

    await expect(createAgentRecord({
      authorization,
      input: CREATION_INPUT,
      client: client as any,
      now: NOW,
    })).rejects.toMatchObject({ status: 503, code: 'agent_record_store_invalid' });
  });

  it('uses typed service errors for store failures', async () => {
    const client = { rpc: vi.fn().mockRejectedValue(new Error('offline')) };

    await expect(revokeAgentRecord({
      recordId: RECORD_ID,
      ownerToken: OWNER_TOKEN,
      client: client as any,
    })).rejects.toBeInstanceOf(AgentRecordServiceError);
  });
});
