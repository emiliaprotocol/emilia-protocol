// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@/lib/agent-adoption/trial', () => ({
  AgentAdoptionTrialError: class AgentAdoptionTrialError extends Error {
    constructor(public status: number, public code: string, message = code) {
      super(message);
    }
  },
  publishBoundAgentTrialRefusal: vi.fn(),
}));

import { publishBoundAgentTrialRefusal } from '@/lib/agent-adoption/trial';
import {
  AGENT_RECORD_RETENTION_MS,
  signAgentRecordObservation,
} from './core';
import {
  AgentRecordServiceError,
  createAgentRecord,
  loadPublicAgentRecord,
  revokeAgentRecord,
} from './service';

const ADOPTION_ID = '11111111-1111-4111-8111-111111111111';
const BOND_ID = '22222222-2222-4222-8222-222222222222';
const BOND_DIGEST = `sha256:${'b'.repeat(64)}`;
const ACTION_DIGEST = `sha256:${'c'.repeat(64)}`;
const REFUSAL_DIGEST = `sha256:${'d'.repeat(64)}`;
const ARENA_SHARE_ID = `arena_share_${'e'.repeat(40)}`;
const ATTEMPT_ID = `arena_attempt_${'f'.repeat(32)}`;
const TRIAL_TOKEN = `epenc:v1:${'A'.repeat(64)}`;
const SESSION_TOKEN = `eaa1_${'1'.repeat(64)}`;
const RECORD_ID = `agent_record_${'2'.repeat(40)}`;
const OWNER_TOKEN = `ear1_${'3'.repeat(64)}`;
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
  agent_label: 'Atlas',
  arena_share_id: ARENA_SHARE_ID,
  action_digest: ACTION_DIGEST,
  refusal_digest: REFUSAL_DIGEST,
  refused_at: REFUSED_AT,
  public_refusal_projection: {
    profile: 'EP-ARENA-PUBLIC-REFUSAL-v1',
    challenge_id: 'emilia.arena.allowance',
    challenge_version: 1,
    attempt: {
      attempt_id: ATTEMPT_ID,
      decision: 'refuse',
      action_digest: ACTION_DIGEST,
      created_at: REFUSED_AT,
    },
    refusal_artifact: { '@version': 'EP-ACTION-REFUSAL-STATEMENT-v1' },
    refusal_digest: REFUSAL_DIGEST,
  },
});

function createClient() {
  const rpc = vi.fn(async (name: string, args: Record<string, any>) => {
    if (name !== 'create_agent_record') throw new Error(`unexpected RPC ${name}`);
    return {
      data: {
        record_id: args.p_record_id,
        owner_token: args.p_owner_token,
        created_at: args.p_observed_at,
        retention_expires_at: args.p_retention_expires_at,
        public_projection: args.p_public_projection,
      },
      error: null,
    };
  });
  return { rpc };
}

describe('Agent Record service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv('NODE_ENV', 'test');
    vi.stubEnv('EP_COMMIT_SIGNING_KEY', crypto.randomBytes(32).toString('base64'));
    vi.stubEnv('EP_COMMIT_SIGNING_KEYS', '');
    vi.mocked(publishBoundAgentTrialRefusal).mockResolvedValue(refusalSource() as any);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('creates from the exact bound refusal and returns the dedicated owner token once', async () => {
    const client = createClient();

    const result = await createAgentRecord({
      authorization,
      input: CREATION_INPUT,
      client: client as any,
      now: NOW,
    });

    expect(publishBoundAgentTrialRefusal).toHaveBeenCalledWith({
      authorization,
      input: { trial_token: TRIAL_TOKEN, attempt_id: ATTEMPT_ID },
      client,
      now: NOW,
    });
    expect(result).toMatchObject({
      record_id: RECORD_ID,
      owner_token: OWNER_TOKEN,
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
      p_arena_share_id: ARENA_SHARE_ID,
      p_source_artifact_digest: REFUSAL_DIGEST,
      p_action_digest: ACTION_DIGEST,
      p_refusal_digest: REFUSAL_DIGEST,
      p_refused_at: REFUSED_AT,
      p_observed_at: new Date(NOW).toISOString(),
      p_retention_expires_at: RETENTION_EXPIRES_AT,
    });
    expect(JSON.stringify(args.p_public_projection)).not.toMatch(
      /adoption_id|session_id|owner_token|credential_id|candidate_url|source_url|webauthn|prompt|ip_address|raw_action|action_parameters|agent_label/i,
    );
  });

  it.each([
    ['cross-adoption', (source: any) => { source.adoption_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'; }],
    ['cross-bond id', (source: any) => { source.bond_id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'; }],
    ['cross-bond digest', (source: any) => { source.bond_digest = `sha256:${'1'.repeat(64)}`; }],
    ['source digest substitution', (source: any) => {
      source.public_refusal_projection.refusal_digest = `sha256:${'2'.repeat(64)}`;
    }],
    ['action substitution', (source: any) => {
      source.public_refusal_projection.attempt.action_digest = `sha256:${'3'.repeat(64)}`;
    }],
    ['attempt substitution', (source: any) => {
      source.public_refusal_projection.attempt.attempt_id = `arena_attempt_${'4'.repeat(32)}`;
    }],
  ])('refuses %s before persistence', async (_name, mutate) => {
    const source: any = refusalSource();
    mutate(source);
    vi.mocked(publishBoundAgentTrialRefusal).mockResolvedValue(source);
    const client = createClient();

    await expect(createAgentRecord({
      authorization,
      input: CREATION_INPUT,
      client: client as any,
      now: NOW,
    })).rejects.toMatchObject({ code: 'agent_record_refusal_invalid' });
    expect(client.rpc).not.toHaveBeenCalled();
  });

  it('rejects an unsigned permit event before persistence', async () => {
    const source: any = refusalSource();
    source.public_refusal_projection.attempt.decision = 'permit';
    delete source.public_refusal_projection.refusal_artifact;
    vi.mocked(publishBoundAgentTrialRefusal).mockResolvedValue(source);
    const client = createClient();

    await expect(createAgentRecord({
      authorization,
      input: CREATION_INPUT,
      client: client as any,
      now: NOW,
    })).rejects.toMatchObject({ code: 'agent_record_refusal_invalid' });
    expect(client.rpc).not.toHaveBeenCalled();
  });

  it('fails closed before persistence when the production operator key is absent', async () => {
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

  it('rejects an embedded-key substitution returned by storage', async () => {
    const observation: any = structuredClone(signAgentRecordObservation({
      recordId: RECORD_ID,
      bondId: BOND_ID,
      bondDigest: BOND_DIGEST,
      arenaShareId: ARENA_SHARE_ID,
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

  it('rejects invalid one-time owner credentials returned by storage', async () => {
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

  it('uses typed service errors for store failures', async () => {
    const client = { rpc: vi.fn().mockRejectedValue(new Error('offline')) };

    await expect(revokeAgentRecord({
      recordId: RECORD_ID,
      ownerToken: OWNER_TOKEN,
      client: client as any,
    })).rejects.toBeInstanceOf(AgentRecordServiceError);
  });
});
