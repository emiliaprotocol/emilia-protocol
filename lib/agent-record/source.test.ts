// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { seal } from '@/lib/crypto/secret-box';
import { createArenaAllowance } from '@/lib/arena/core';
import { signArenaRefusal } from '@/lib/arena/refusal';
import { prepareAgentRecordRefusalSource } from './source';

const ADOPTION_ID = '11111111-1111-4111-8111-111111111111';
const BOND_ID = '22222222-2222-4222-8222-222222222222';
const BOND_DIGEST = `sha256:${'b'.repeat(64)}`;
const SESSION_ID = `arena_session_${'c'.repeat(32)}`;
const ARENA_TOKEN = `ep_arena_${'d'.repeat(64)}`;
const ATTEMPT_ID = `arena_attempt_${'e'.repeat(32)}`;
const REFUSED_AT = '2026-08-02T20:00:00.000Z';
const NOW = Date.parse('2026-08-02T20:01:00.000Z');
const SOURCE_COMMITMENT = `sha256:${'a'.repeat(64)}`;

const authorization: any = Object.freeze({
  sessionId: ADOPTION_ID,
  sessionToken: `eaa1_${'1'.repeat(64)}`,
  session: Object.freeze({
    adoption_id: ADOPTION_ID,
    status: 'active',
    bond_count: 1,
    latest_bond_id: BOND_ID,
    bond_digest: BOND_DIGEST,
    latest_bond_digest: BOND_DIGEST,
  }),
});

function signedSource() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const allowance = createArenaAllowance({
    sessionId: SESSION_ID,
    agentName: 'Private Agent Record Test',
    totalAmount: 1_000,
    maxAmountPerAction: 250,
    allowedTargets: ['vendor.demo'],
    issuedAt: '2026-08-02T19:00:00.000Z',
    expiresAt: '2026-08-03T19:00:00.000Z',
  });
  const signed = signArenaRefusal({
    allowance,
    action: {
      operation_id: 'operation-private-source-1',
      action_type: 'arena.resource.allocate.1',
      target: 'vendor.demo',
      amount: 900,
      currency: 'CREDITS',
      purpose: 'private-agent-record-source',
    },
    reason: 'allowance_per_action_limit_exceeded',
    attemptId: ATTEMPT_ID,
    attemptNonce: Buffer.alloc(32, 4).toString('base64url'),
    refusedAt: REFUSED_AT,
    expiresAt: '2026-08-02T20:05:00.000Z',
    signer: {
      issuer_id: 'arena:session:test',
      key_id: 'arena-session-key-1',
      private_key: privateKey,
    },
  });
  return {
    source_commitment: SOURCE_COMMITMENT,
    source_artifact_digest: signed.refusal_digest,
    action_digest: signed.binding.action_digest,
    refusal_digest: signed.refusal_digest,
    refused_at: REFUSED_AT,
    refusal_artifact: signed.statement,
    issuer: {
      issuer_id: 'arena:session:test',
      key_id: 'arena-session-key-1',
      public_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    },
  };
}

function trialToken() {
  return seal(JSON.stringify({
    '@version': 'EP-AGENT-ADOPTION-TRIAL-v1',
    adoption_id: ADOPTION_ID,
    bond_id: BOND_ID,
    bond_digest: BOND_DIGEST,
    arena_session_id: SESSION_ID,
    arena_token: ARENA_TOKEN,
    expires_at: '2026-08-02T20:04:00.000Z',
  }))!;
}

describe('Agent Record private refusal source', () => {
  beforeEach(() => {
    vi.stubEnv('NODE_ENV', 'test');
    vi.stubEnv('EP_SECRET_KEY', '7'.repeat(64));
  });

  afterEach(() => vi.unstubAllEnvs());

  it('verifies the direct signed refusal and returns only digest bindings', async () => {
    const source = signedSource();
    const client = { rpc: vi.fn().mockResolvedValue({ data: source, error: null }) };

    const result = await prepareAgentRecordRefusalSource({
      authorization,
      input: { trial_token: trialToken(), attempt_id: ATTEMPT_ID },
      client: client as any,
      now: NOW,
    });

    expect(client.rpc).toHaveBeenCalledWith('read_agent_record_refusal_source', {
      p_source_token: ARENA_TOKEN,
      p_source_session_id: SESSION_ID,
      p_source_attempt_id: ATTEMPT_ID,
    });
    expect(result).toEqual({
      adoption_id: ADOPTION_ID,
      bond_id: BOND_ID,
      bond_digest: BOND_DIGEST,
      source_session_id: SESSION_ID,
      source_attempt_id: ATTEMPT_ID,
      source_commitment: SOURCE_COMMITMENT,
      source_artifact_digest: source.refusal_digest,
      action_digest: source.action_digest,
      refusal_digest: source.refusal_digest,
      refused_at: REFUSED_AT,
    });
    expect((result as any).source_token).toBe(ARENA_TOKEN);
    expect(Object.getOwnPropertyDescriptor(result, 'source_token')).toMatchObject({
      enumerable: false,
      configurable: false,
      writable: false,
    });
    expect(JSON.stringify(result)).not.toMatch(
      /refusal_artifact|public_projection|raw_action|action_parameters|arena_token|public_key|private_key/,
    );
  });

  it('rejects a signature-shaped but inauthentic refusal before creation', async () => {
    const source: any = signedSource();
    source.refusal_artifact = structuredClone(source.refusal_artifact);
    const signature = source.refusal_artifact.proof.signature_b64u;
    source.refusal_artifact.proof.signature_b64u = `${signature.startsWith('A') ? 'B' : 'A'}${signature.slice(1)}`;
    const client = { rpc: vi.fn().mockResolvedValue({ data: source, error: null }) };

    await expect(prepareAgentRecordRefusalSource({
      authorization,
      input: { trial_token: trialToken(), attempt_id: ATTEMPT_ID },
      client: client as any,
      now: NOW,
    })).rejects.toMatchObject({
      status: 503,
      code: 'agent_adoption_refusal_source_invalid',
    });
  });
});
