// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockGetServiceClient = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args: unknown[]) => mockGetServiceClient(...args),
}));

const {
  challengeContinuity,
  fileContinuityClaim,
  freezeContinuityOnDispute,
  resolveContinuity,
  unfreezeResolvedContinuity,
  withdrawContinuityClaim,
} = await import('../lib/ep-ix.js');

describe('fileContinuityClaim atomic boundary', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('checks the dispute freeze and commits claim plus audit through one atomic RPC', async () => {
    const rpc = vi.fn().mockResolvedValue({
      data: {
        continuity: { continuity_id: 'ep_ix_atomic', status: 'pending' },
        challenge_deadline: '2026-09-02T00:00:00.000Z',
        expires_at: '2026-09-25T00:00:00.000Z',
      },
      error: null,
    });
    const from = vi.fn(() => {
      throw new Error('fileContinuityClaim must not split the transaction across table calls');
    });
    mockGetServiceClient.mockReturnValue({ rpc, from });

    const result = await fileContinuityClaim({
      principal_id: 'ep_principal_owner',
      old_entity_id: 'old-entity',
      new_entity_id: 'new-entity',
      reason: 'key_rotation',
      continuity_mode: 'linear',
      proofs: [{ type: 'old_key_signature' }],
      transfer_budget: 0.75,
    }, 'filing-actor');

    expect(result.continuity).toMatchObject({ status: 'pending' });
    expect(rpc).toHaveBeenCalledWith('file_continuity_claim_atomic', {
      p_continuity_id: expect.stringMatching(/^ep_ix_[a-f0-9]{16}$/),
      p_principal_id: 'ep_principal_owner',
      p_actor_entity_id: 'filing-actor',
      p_old_entity_id: 'old-entity',
      p_new_entity_id: 'new-entity',
      p_reason: 'key_rotation',
      p_continuity_mode: 'linear',
      p_proofs: [{ type: 'old_key_signature' }],
      p_transfer_budget: 0.75,
    });
    expect(from).not.toHaveBeenCalled();
  });

  it('preserves an active-dispute freeze returned inside the transaction', async () => {
    const rpc = vi.fn().mockResolvedValue({
      data: {
        error: 'Continuity frozen: old entity has active disputes. Resolve disputes before claiming continuity.',
        status: 409,
        frozen: true,
        active_disputes: 1,
      },
      error: null,
    });
    mockGetServiceClient.mockReturnValue({ rpc });

    const result = await fileContinuityClaim({
      principal_id: 'ep_principal_owner',
      old_entity_id: 'old-entity',
      new_entity_id: 'new-entity',
      reason: 'recovery_after_compromise',
    }, 'filing-actor');

    expect(result).toMatchObject({ status: 409, frozen: true, active_disputes: 1 });
  });

  it('fails closed before RPC when the trusted actor projection is absent', async () => {
    const rpc = vi.fn(() => {
      throw new Error('missing actor must not reach the database');
    });
    mockGetServiceClient.mockReturnValue({ rpc });

    const result = await fileContinuityClaim({
      principal_id: 'ep_principal_owner',
      old_entity_id: 'old-entity',
      new_entity_id: 'new-entity',
      reason: 'key_rotation',
    }, '');

    expect(result).toMatchObject({ status: 400 });
    expect(result.error).toMatch(/actor identity/i);
    expect(rpc).not.toHaveBeenCalled();
  });
});

describe('challengeContinuity atomic boundary', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('delegates role derivation and every trust-changing write to one atomic RPC', async () => {
    const rpc = vi.fn().mockResolvedValue({
      data: {
        challenge: {
          challenge_id: 'ep_ch_atomic',
          challenger_type: 'dispute_counterparty',
          status: 'open',
        },
      },
      error: null,
    });
    const from = vi.fn(() => {
      throw new Error('challengeContinuity must not split the transaction across table calls');
    });
    mockGetServiceClient.mockReturnValue({ rpc, from });

    const result = await challengeContinuity({
      continuity_id: 'ep_ix_claim',
      challenger_id: 'counterparty-entity',
      reason: 'evidence contradicts the continuity claim',
      evidence: { dispute_id: 'ep_dispute_1' },
      enterprise_admin_authorized: false,
    });

    expect(result.challenge).toMatchObject({
      challenge_id: 'ep_ch_atomic',
      challenger_type: 'dispute_counterparty',
    });
    expect(rpc).toHaveBeenCalledOnce();
    expect(rpc).toHaveBeenCalledWith('challenge_continuity_atomic', {
      p_continuity_id: 'ep_ix_claim',
      p_challenge_id: expect.stringMatching(/^ep_ch_[a-f0-9]{16}$/),
      p_challenger_id: 'counterparty-entity',
      p_reason: 'evidence contradicts the continuity claim',
      p_evidence: { dispute_id: 'ep_dispute_1' },
      p_enterprise_admin_authorized: false,
    });
    expect(from).not.toHaveBeenCalled();
  });

  it('passes only the server-derived enterprise-admin authorization bit', async () => {
    const rpc = vi.fn().mockResolvedValue({
      data: { challenge: { challenge_id: 'ep_ch_admin', challenger_type: 'enterprise_admin' } },
      error: null,
    });
    mockGetServiceClient.mockReturnValue({ rpc });

    await challengeContinuity({
      continuity_id: 'ep_ix_claim',
      challenger_id: 'tenant-admin',
      reason: 'enterprise review',
      enterprise_admin_authorized: true,
    });

    expect(rpc).toHaveBeenCalledWith('challenge_continuity_atomic', expect.objectContaining({
      p_enterprise_admin_authorized: true,
    }));
  });

  it('preserves deterministic expected errors returned by the atomic RPC', async () => {
    const rpc = vi.fn().mockResolvedValue({
      data: { error: 'Principal cannot challenge their own continuity claim', status: 403 },
      error: null,
    });
    mockGetServiceClient.mockReturnValue({ rpc });

    const result = await challengeContinuity({
      continuity_id: 'ep_ix_claim',
      challenger_id: 'filing-principal-entity',
      reason: 'self contest',
    });

    expect(result).toEqual({
      error: 'Principal cannot challenge their own continuity claim',
      status: 403,
    });
  });

  it('fails closed when the transaction RPC fails', async () => {
    const rpc = vi.fn().mockResolvedValue({
      data: null,
      error: { message: 'audit insert rejected' },
    });
    mockGetServiceClient.mockReturnValue({ rpc });

    const result = await challengeContinuity({
      continuity_id: 'ep_ix_claim',
      challenger_id: 'counterparty-entity',
      reason: 'counterparty challenge',
    });

    expect(result).toEqual({ error: 'audit insert rejected', status: 500 });
  });
});

describe('resolveContinuity atomic boundary', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('resolves and audits through one dispute-serialized RPC', async () => {
    const rpc = vi.fn().mockResolvedValue({
      data: {
        continuity_id: 'ep_ix_claim',
        decision: 'approved_partial',
        resolved_at: '2026-08-26T12:00:00.000Z',
      },
      error: null,
    });
    const from = vi.fn(() => {
      throw new Error('resolveContinuity must not split the transaction across table calls');
    });
    mockGetServiceClient.mockReturnValue({ rpc, from });

    const result = await resolveContinuity(
      'ep_ix_claim',
      'approved_partial',
      ['identity proof verified'],
      'operator-entity',
    );

    expect(result).toMatchObject({
      continuity_id: 'ep_ix_claim',
      decision: 'approved_partial',
    });
    expect(rpc).toHaveBeenCalledWith('resolve_continuity_atomic', {
      p_continuity_id: 'ep_ix_claim',
      p_decision: 'approved_partial',
      p_reasoning: ['identity proof verified'],
      p_operator_id: 'operator-entity',
    });
    expect(from).not.toHaveBeenCalled();
  });

  it('preserves an active-dispute refusal returned inside the transaction', async () => {
    const rpc = vi.fn().mockResolvedValue({
      data: {
        error: 'Claim is frozen behind 2 active disputes',
        status: 409,
        frozen: true,
        active_disputes: 2,
      },
      error: null,
    });
    mockGetServiceClient.mockReturnValue({ rpc });

    const result = await resolveContinuity('ep_ix_claim', 'approved_full', [], 'operator-entity');
    expect(result).toMatchObject({ status: 409, frozen: true, active_disputes: 2 });
  });

  it.each([
    ['', 'approved_full', [], 'operator', 'continuity_id'],
    ['ep_ix_claim', 'invented_decision', [], 'operator', 'decision'],
    ['ep_ix_claim', 'approved_full', {} as any, 'operator', 'reasoning'],
    ['ep_ix_claim', 'approved_full', [], '', 'operator'],
  ])('rejects malformed resolution before database access', async (
    continuityId,
    decision,
    reasoning,
    operatorId,
    expected,
  ) => {
    mockGetServiceClient.mockReturnValue({
      rpc: vi.fn(() => {
        throw new Error('invalid input must not reach the database');
      }),
    });

    const result = await resolveContinuity(continuityId, decision, reasoning, operatorId);
    expect(result).toMatchObject({ status: 400 });
    expect(result.error).toContain(expected);
  });
});

describe('withdrawContinuityClaim atomic boundary', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('withdraws and audits through one actor-bound transaction RPC', async () => {
    const rpc = vi.fn().mockResolvedValue({
      data: {
        continuity_id: 'ep_ix_claim',
        status: 'withdrawn',
        withdrawn_at: '2026-08-26T12:00:00.000Z',
      },
      error: null,
    });
    const from = vi.fn(() => {
      throw new Error('withdrawContinuityClaim must not split state and audit writes');
    });
    mockGetServiceClient.mockReturnValue({ rpc, from });

    const result = await withdrawContinuityClaim(
      'ep_ix_claim',
      'authenticated-successor',
      'replacement abandoned',
    );

    expect(result).toEqual({
      continuity_id: 'ep_ix_claim',
      status: 'withdrawn',
      withdrawn_at: '2026-08-26T12:00:00.000Z',
    });
    expect(rpc).toHaveBeenCalledWith('withdraw_continuity_claim_atomic', {
      p_continuity_id: 'ep_ix_claim',
      p_actor_entity_id: 'authenticated-successor',
      p_reason: 'replacement abandoned',
    });
    expect(from).not.toHaveBeenCalled();
  });

  it.each([
    ['', 'authenticated-successor', 'continuity_id'],
    ['ep_ix_claim', '', 'actor identity'],
  ])('rejects malformed withdrawal before database access', async (
    continuityId,
    actorEntityId,
    expected,
  ) => {
    const rpc = vi.fn(() => {
      throw new Error('invalid withdrawal must not reach the database');
    });
    mockGetServiceClient.mockReturnValue({ rpc });

    const result = await withdrawContinuityClaim(continuityId, actorEntityId);

    expect(result).toMatchObject({ status: 400 });
    expect(result.error).toMatch(new RegExp(expected, 'i'));
    expect(rpc).not.toHaveBeenCalled();
  });
});

describe('continuity dispute reconciliation atomic boundary', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('reconciles a requested freeze through the dispute RPC', async () => {
    const rpc = vi.fn().mockResolvedValue({
      data: {
        continuity_id: 'ep_ix_claim',
        status: 'frozen_pending_dispute',
        frozen_due_to: 'ep_dispute_1',
        frozen: 1,
        unfrozen: 0,
      },
      error: null,
    });
    mockGetServiceClient.mockReturnValue({ rpc });

    const result = await freezeContinuityOnDispute('ep_ix_claim', 'ep_dispute_1');

    expect(result).toMatchObject({
      continuity_id: 'ep_ix_claim',
      status: 'frozen_pending_dispute',
      frozen_due_to: 'ep_dispute_1',
    });
    expect(rpc).toHaveBeenCalledWith('reconcile_continuity_dispute_atomic', {
      p_dispute_id: 'ep_dispute_1',
      p_continuity_id: 'ep_ix_claim',
    });
  });

  it('rechecks all active blockers before reporting an unfreeze', async () => {
    const rpc = vi.fn().mockResolvedValue({
      data: { frozen: 0, unfrozen: 0, remaining_active_disputes: 1 },
      error: null,
    });
    mockGetServiceClient.mockReturnValue({ rpc });

    const result = await unfreezeResolvedContinuity('ep_dispute_1');

    expect(result).toEqual({ unfrozen: 0 });
    expect(rpc).toHaveBeenCalledWith('reconcile_continuity_dispute_atomic', {
      p_dispute_id: 'ep_dispute_1',
      p_continuity_id: null,
    });
  });
});
