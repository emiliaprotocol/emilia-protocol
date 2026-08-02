// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { seal } from '@/lib/crypto/secret-box';

vi.mock('@/lib/supabase', () => ({
  getServiceClient: vi.fn(() => {
    throw new Error('service client must be injected in tests');
  }),
}));

const { provisionArenaSession, submitArenaAttempt, publishArenaRefusal, ArenaServiceError } =
  await import('./service');

const NOW = Date.parse('2026-08-02T12:00:00.000Z');

function request(token: string): Request {
  return new Request('https://example.test/api/arena', {
    headers: { authorization: `Bearer ${token}` },
  });
}

function sessionRow(token: string) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const sessionId = 'arena_session_11111111111111111111111111111111';
  return {
    id: '00000000-0000-4000-8000-000000000001',
    tenant_id: '00000000-0000-4000-8000-000000000002',
    session_id: sessionId,
    token_hash: crypto.createHash('sha256').update(token).digest('hex'),
    status: 'active',
    expires_at: '2026-08-03T12:00:00.000Z',
    agent_name: 'Night Shift',
    challenge_id: 'emilia.arena.allowance',
    challenge_version: 1,
    allowance_profile: {
      '@version': 'EP-ARENA-ALLOWANCE-v1',
      session_id: sessionId,
      agent_name: 'Night Shift',
      currency: 'CREDITS',
      total_amount: 1000,
      max_amount_per_action: 250,
      allowed_targets: ['compute.batch', 'vendor.demo'],
      issued_at: '2026-08-02T12:00:00.000Z',
      expires_at: '2026-08-03T12:00:00.000Z',
      claim_boundary: 'synthetic_challenge_not_money_custody_settlement_identity_certification_or_production_authorization',
    },
    issuer_id: `arena:session:${sessionId}`,
    key_id: `arena-key:${sessionId}`,
    public_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    private_key_encrypted: seal(
      privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64url'),
    ),
  };
}

function clientFor(row: ReturnType<typeof sessionRow>, rpc: ReturnType<typeof vi.fn>) {
  const maybeSingle = vi.fn(async () => ({ data: row, error: null }));
  const secondEq = vi.fn(() => ({ maybeSingle }));
  const firstEq = vi.fn(() => ({ eq: secondEq }));
  const select = vi.fn(() => ({ eq: firstEq }));
  const from = vi.fn(() => ({ select }));
  return { client: { from, rpc } as any, spies: { from, rpc, maybeSingle } };
}

describe('Arena service boundary', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('issues a dedicated Arena token once and stores only its hash', async () => {
    const rpc = vi.fn(async (_name: string, args: Record<string, unknown>) => ({
      data: { ok: true, tenant_id: '00000000-0000-4000-8000-000000000002' },
      error: null,
      args,
    }));
    const result = await provisionArenaSession({ agentName: 'Night Shift', client: { rpc } as any, now: NOW });
    expect(result.token).toMatch(/^ep_arena_[0-9a-f]{64}$/);
    expect(result.allowance.currency).toBe('CREDITS');
    expect(result.note).toContain('No money');
    const [, args] = rpc.mock.calls[0];
    expect(args.p_token_hash).toBe(crypto.createHash('sha256').update(result.token).digest('hex'));
    expect(JSON.stringify(args)).not.toContain(result.token);
  });

  it('rejects caller-supplied verdict fields before touching the atomic attempt RPC', async () => {
    const token = `ep_arena_${'a'.repeat(64)}`;
    const row = sessionRow(token);
    const rpc = vi.fn();
    const { client } = clientFor(row, rpc);
    await expect(submitArenaAttempt({
      request: request(token), sessionId: row.session_id, client, now: NOW,
      input: {
        operation_id: 'arena-op-1', target: 'vendor.demo', amount: 80,
        purpose: 'synthetic-vendor-payment', decision: 'allow',
      },
    })).rejects.toMatchObject({ status: 400, code: 'arena_action_input_invalid' });
    expect(rpc).not.toHaveBeenCalled();
  });

  it('returns an allow only after the atomic store debits the allowance', async () => {
    const token = `ep_arena_${'b'.repeat(64)}`;
    const row = sessionRow(token);
    const rpc = vi.fn(async (name: string) => {
      expect(name).toBe('attempt_arena_action');
      return { data: {
        ok: true, attempt_id: `arena_attempt_${'1'.repeat(32)}`, decision: 'allow',
        reason: null, remaining_amount: 920, evidence_status: 'not_applicable',
      }, error: null };
    });
    const { client } = clientFor(row, rpc);
    const result = await submitArenaAttempt({
      request: request(token), sessionId: row.session_id, client, now: NOW,
      input: { operation_id: 'arena-op-2', target: 'vendor.demo', amount: 80, purpose: 'synthetic-vendor-payment' },
    });
    expect(result).toMatchObject({ decision: 'allow', remaining_amount: 920 });
    expect(result).not.toHaveProperty('refusal_artifact');
  });

  it('fails closed on an unknown store decision instead of interpreting it as allow', async () => {
    const token = `ep_arena_${'8'.repeat(64)}`;
    const row = sessionRow(token);
    const rpc = vi.fn(async () => ({ data: {
      ok: true, attempt_id: `arena_attempt_${'8'.repeat(32)}`,
      decision: 'pending', remaining_amount: 1000,
    }, error: null }));
    const { client } = clientFor(row, rpc);
    await expect(submitArenaAttempt({
      request: request(token), sessionId: row.session_id, client, now: NOW,
      input: { operation_id: 'arena-op-unknown', target: 'vendor.demo', amount: 80, purpose: 'synthetic-vendor-payment' },
    })).rejects.toMatchObject({ status: 503, code: 'arena_store_decision_invalid' });
  });

  it('refuses to expose a completed artifact that does not verify for this session and action', async () => {
    const token = `ep_arena_${'9'.repeat(64)}`;
    const row = sessionRow(token);
    const rpc = vi.fn(async () => ({ data: {
      ok: true, attempt_id: `arena_attempt_${'9'.repeat(32)}`,
      attempt_nonce: 'n'.repeat(32), decision: 'refuse',
      reason: 'allowance_per_action_limit_exceeded', remaining_amount: 1000,
      evidence_status: 'complete', created_at: '2026-08-02T12:00:00.000Z',
      refusal_artifact: { issuer_id: 'another-session' },
      refusal_digest: `sha256:${'0'.repeat(64)}`,
    }, error: null }));
    const { client } = clientFor(row, rpc);
    await expect(submitArenaAttempt({
      request: request(token), sessionId: row.session_id, client, now: NOW,
      input: { operation_id: 'arena-op-substitution', target: 'vendor.demo', amount: 900, purpose: 'synthetic-oversized-transfer' },
    })).rejects.toMatchObject({ status: 503, code: 'arena_stored_refusal_invalid' });
  });

  it('never exposes a refusal if the durable commit fails', async () => {
    const token = `ep_arena_${'c'.repeat(64)}`;
    const row = sessionRow(token);
    const rpc = vi.fn()
      .mockResolvedValueOnce({ data: {
        ok: true, attempt_id: `arena_attempt_${'2'.repeat(32)}`,
        attempt_nonce: 'n'.repeat(32), decision: 'refuse',
        reason: 'allowance_per_action_limit_exceeded', remaining_amount: 1000,
        evidence_status: 'pending', created_at: '2026-08-02T12:00:00.000Z',
      }, error: null })
      .mockResolvedValueOnce({ data: null, error: { message: 'database unavailable' } });
    const { client } = clientFor(row, rpc);
    await expect(submitArenaAttempt({
      request: request(token), sessionId: row.session_id, client, now: NOW,
      input: { operation_id: 'arena-op-3', target: 'vendor.demo', amount: 900, purpose: 'synthetic-oversized-transfer' },
    })).rejects.toMatchObject({ status: 503 });
    expect(rpc).toHaveBeenCalledTimes(2);
  });

  it('publishes only through an explicit authenticated publication call', async () => {
    const token = `ep_arena_${'d'.repeat(64)}`;
    const row = sessionRow(token);
    const rpc = vi.fn(async (name: string) => {
      expect(name).toBe('publish_arena_refusal');
      return { data: { ok: true, share_id: `arena_share_${'e'.repeat(40)}` }, error: null };
    });
    const { client } = clientFor(row, rpc);
    const result = await publishArenaRefusal({
      request: request(token), sessionId: row.session_id,
      attemptId: `arena_attempt_${'3'.repeat(32)}`, client, now: NOW,
    });
    expect(result.share_url).toBe(`/arena/r/arena_share_${'e'.repeat(40)}`);
  });

  it('normalizes store failures into a fail-closed service error', async () => {
    const rpc = vi.fn(async () => { throw new Error('down'); });
    await expect(provisionArenaSession({ agentName: 'Night Shift', client: { rpc } as any, now: NOW }))
      .rejects.toBeInstanceOf(ArenaServiceError);
  });
});
