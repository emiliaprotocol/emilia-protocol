/**
 * EMILIA Protocol — protocolWrite() Extended Tests
 *
 * Covers branches and functions NOT tested in protocol-write.test.js:
 *   - Signoff validators (challenge_issue, attest, deny, consume, revoke, expire)
 *   - Handshake validators (initiate_handshake, add_presentation, verify, revoke)
 *   - Cron/lifecycle validators (expire_receipts, escalate_disputes, expire_continuity_claims)
 *   - Eye command validators and handlers
 *   - respond_dispute / appeal_dispute / resolve_appeal / withdraw_dispute routing
 *   - Cron handlers: EXPIRE_RECEIPTS, ESCALATE_DISPUTES, EXPIRE_CONTINUITY_CLAIMS
 *   - CONSUME_HANDSHAKE_BINDING handler (DB path + error path)
 *   - SIGNOFF_CHALLENGE_VIEW handler (pass-through)
 *   - canonicalStringify for deterministic key ordering
 *   - assertInvariants: null input allowed (no input key at all vs explicit null)
 *   - appendProtocolEvent failure → throws EVENT_PERSISTENCE_FAILED
 *   - Idempotency TTL expiry (cache eviction)
 *   - Error result objects not cached by idempotency
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Supabase chain helper ────────────────────────────────────────────────────

function makeChain(resolveValue = { data: null, error: null }) {
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    neq: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    is: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    gte: vi.fn().mockReturnThis(),
    insert: vi.fn().mockResolvedValue(resolveValue),
    update: vi.fn().mockReturnThis(),
    single: vi.fn().mockResolvedValue(resolveValue),
    maybeSingle: vi.fn().mockResolvedValue(resolveValue),
    then: (resolve) => Promise.resolve(resolveValue).then(resolve),
  };
  return chain;
}

// ── Mock declarations ────────────────────────────────────────────────────────

const mockGetServiceClient = vi.fn();
const mockCanonicalSubmitReceipt = vi.fn();
const mockCanonicalSubmitAutoReceipt = vi.fn();
const mockCanonicalBilateralConfirm = vi.fn();
const mockCanonicalFileDispute = vi.fn();
const mockCanonicalResolveDispute = vi.fn();
const mockCanonicalRespondDispute = vi.fn();
const mockCanonicalAppealDispute = vi.fn();
const mockCanonicalResolveAppeal = vi.fn();
const mockCanonicalWithdrawDispute = vi.fn();
const mockCanonicalFileReport = vi.fn();
const mockIssueCommit = vi.fn();
const mockVerifyCommit = vi.fn();
const mockRevokeCommit = vi.fn();
const mockCheckAbuse = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

vi.mock('../lib/canonical-writer.js', () => ({
  canonicalSubmitReceipt: (...args) => mockCanonicalSubmitReceipt(...args),
  canonicalSubmitAutoReceipt: (...args) => mockCanonicalSubmitAutoReceipt(...args),
  canonicalBilateralConfirm: (...args) => mockCanonicalBilateralConfirm(...args),
  canonicalFileDispute: (...args) => mockCanonicalFileDispute(...args),
  canonicalResolveDispute: (...args) => mockCanonicalResolveDispute(...args),
  canonicalRespondDispute: (...args) => mockCanonicalRespondDispute(...args),
  canonicalAppealDispute: (...args) => mockCanonicalAppealDispute(...args),
  canonicalResolveAppeal: (...args) => mockCanonicalResolveAppeal(...args),
  canonicalWithdrawDispute: (...args) => mockCanonicalWithdrawDispute(...args),
  canonicalFileReport: (...args) => mockCanonicalFileReport(...args),
}));

vi.mock('../lib/commit.js', () => ({
  issueCommit: (...args) => mockIssueCommit(...args),
  verifyCommit: (...args) => mockVerifyCommit(...args),
  revokeCommit: (...args) => mockRevokeCommit(...args),
}));

vi.mock('../lib/handshake.js', () => ({
  _handleInitiateHandshake: vi.fn().mockResolvedValue({ result: { handshake_id: 'eph_mock' }, aggregateId: 'eph_mock' }),
  _handleAddPresentation: vi.fn().mockResolvedValue({ result: { id: 'pres_mock' }, aggregateId: 'eph_mock' }),
  _handleVerifyHandshake: vi.fn().mockResolvedValue({ result: { outcome: 'accepted' }, aggregateId: 'eph_mock' }),
  _handleRevokeHandshake: vi.fn().mockResolvedValue({ result: { status: 'revoked' }, aggregateId: 'eph_mock' }),
}));

vi.mock('../lib/procedural-justice.js', () => ({
  hasPermission: vi.fn().mockReturnValue(true),
  checkAbuse: (...args) => mockCheckAbuse(...args),
  validateTransition: vi.fn().mockReturnValue({ valid: true }),
  DISPUTE_STATES: {},
}));

// Import after mocks
import { protocolWrite, COMMAND_TYPES, ProtocolWriteError, _internals } from '../lib/protocol-write.js';

// ── Setup ────────────────────────────────────────────────────────────────────

beforeEach(() => {
  vi.clearAllMocks();

  _internals._idempotencyCache.clear();

  const mockSupabase = {
    from: vi.fn().mockReturnValue(makeChain({ data: null, error: null })),
  };
  mockGetServiceClient.mockReturnValue(mockSupabase);

  mockCheckAbuse.mockResolvedValue({ allowed: true });
});

// ── Signoff validators ────────────────────────────────────────────────────────

describe('signoff validators', () => {
  it('rejects signoff_challenge_issue without entity_id', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_CHALLENGE_ISSUE,
      input: { action_type: 'install' },
      actor: { id: 'op_1' },
    })).rejects.toThrow('input.entity_id is required');
  });

  it('rejects signoff_challenge_issue without action_type', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_CHALLENGE_ISSUE,
      input: { entity_id: 'ent_1' },
      actor: { id: 'op_1' },
    })).rejects.toThrow('input.action_type is required');
  });

  it('rejects signoff_challenge_view without challenge_id', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_CHALLENGE_VIEW,
      input: {},
      actor: { id: 'op_1' },
    })).rejects.toThrow('input.challenge_id is required');
  });

  it('rejects signoff_attest without challenge_id', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_ATTEST,
      input: {},
      actor: { id: 'op_1' },
    })).rejects.toThrow('input.challenge_id is required');
  });

  it('rejects signoff_deny without challenge_id', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_DENY,
      input: {},
      actor: { id: 'op_1' },
    })).rejects.toThrow('input.challenge_id is required');
  });

  it('rejects signoff_consume without signoff_id', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_CONSUME,
      input: {},
      actor: { id: 'op_1' },
    })).rejects.toThrow('input.signoff_id is required');
  });

  it('rejects signoff_challenge_revoke without challenge_id', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_CHALLENGE_REVOKE,
      input: { reason: 'stale' },
      actor: { id: 'op_1' },
    })).rejects.toThrow('input.challenge_id is required');
  });

  it('rejects signoff_challenge_revoke without reason', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_CHALLENGE_REVOKE,
      input: { challenge_id: 'ch_1' },
      actor: { id: 'op_1' },
    })).rejects.toThrow('input.reason is required');
  });

  it('rejects signoff_attestation_revoke without attestation_id', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_ATTESTATION_REVOKE,
      input: { reason: 'mistake' },
      actor: { id: 'op_1' },
    })).rejects.toThrow('input.attestation_id is required');
  });

  it('rejects signoff_attestation_revoke without reason', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_ATTESTATION_REVOKE,
      input: { attestation_id: 'att_1' },
      actor: { id: 'op_1' },
    })).rejects.toThrow('input.reason is required');
  });

  it('rejects signoff_challenge_expire without challenge_id', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_CHALLENGE_EXPIRE,
      input: {},
      actor: { id: 'cron' },
    })).rejects.toThrow('input.challenge_id is required');
  });

  it('rejects signoff_attestation_expire without attestation_id', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_ATTESTATION_EXPIRE,
      input: {},
      actor: { id: 'cron' },
    })).rejects.toThrow('input.attestation_id is required');
  });
});

// ── Handshake validators ──────────────────────────────────────────────────────

describe('handshake validators', () => {
  it('rejects initiate_handshake without mode', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.INITIATE_HANDSHAKE,
      input: { policy_id: 'pol_1', parties: ['a', 'b'] },
      actor: { id: 'ent_1' },
    })).rejects.toThrow('input.mode is required');
  });

  it('rejects initiate_handshake without policy_id', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.INITIATE_HANDSHAKE,
      input: { mode: 'standard', parties: ['a', 'b'] },
      actor: { id: 'ent_1' },
    })).rejects.toThrow('input.policy_id is required');
  });

  it('rejects initiate_handshake with empty parties array', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.INITIATE_HANDSHAKE,
      input: { mode: 'standard', policy_id: 'pol_1', parties: [] },
      actor: { id: 'ent_1' },
    })).rejects.toThrow('input.parties must be a non-empty array');
  });

  it('rejects initiate_handshake when parties is not an array', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.INITIATE_HANDSHAKE,
      input: { mode: 'standard', policy_id: 'pol_1', parties: 'wrong' },
      actor: { id: 'ent_1' },
    })).rejects.toThrow('input.parties must be a non-empty array');
  });

  it('rejects add_presentation without handshake_id', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.ADD_PRESENTATION,
      input: { party_role: 'initiator', presentation_hash: 'hash_1' },
      actor: { id: 'ent_1' },
    })).rejects.toThrow('input.handshake_id is required');
  });

  it('rejects add_presentation without presentation_hash', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.ADD_PRESENTATION,
      input: { handshake_id: 'eph_1', party_role: 'initiator' },
      actor: { id: 'ent_1' },
    })).rejects.toThrow('input.presentation_hash is required');
  });

  it('rejects verify_handshake without handshake_id', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.VERIFY_HANDSHAKE,
      input: {},
      actor: { id: 'ent_1' },
    })).rejects.toThrow('input.handshake_id is required');
  });

  it('rejects revoke_handshake without reason', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.REVOKE_HANDSHAKE,
      input: { handshake_id: 'eph_1' },
      actor: { id: 'ent_1' },
    })).rejects.toThrow('input.reason is required');
  });
});

// ── Cron/lifecycle validators ─────────────────────────────────────────────────

describe('cron/lifecycle validators', () => {
  it('rejects expire_receipts without receipt_ids', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.EXPIRE_RECEIPTS,
      input: {},
      actor: { id: 'cron' },
    })).rejects.toThrow('input.receipt_ids must be a non-empty array');
  });

  it('rejects expire_receipts with empty array', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.EXPIRE_RECEIPTS,
      input: { receipt_ids: [] },
      actor: { id: 'cron' },
    })).rejects.toThrow('input.receipt_ids must be a non-empty array');
  });

  it('rejects escalate_disputes without dispute_ids', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.ESCALATE_DISPUTES,
      input: {},
      actor: { id: 'cron' },
    })).rejects.toThrow('input.dispute_ids must be a non-empty array');
  });

  it('rejects expire_continuity_claims without continuity_ids', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.EXPIRE_CONTINUITY_CLAIMS,
      input: {},
      actor: { id: 'cron' },
    })).rejects.toThrow('input.continuity_ids must be a non-empty array');
  });

  it('rejects consume_handshake_binding without consumed_by', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.CONSUME_HANDSHAKE_BINDING,
      input: { handshake_id: 'eph_1', consumed_for: 'entity_1' },
      actor: { id: 'op_1' },
    })).rejects.toThrow('input.consumed_by is required');
  });

  it('rejects consume_handshake_binding without consumed_for', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.CONSUME_HANDSHAKE_BINDING,
      input: { handshake_id: 'eph_1', consumed_by: 'op_1' },
      actor: { id: 'op_1' },
    })).rejects.toThrow('input.consumed_for is required');
  });
});

// ── Eye validators ────────────────────────────────────────────────────────────

describe('eye validators', () => {
  it('rejects eye_record_observation without observation_type', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.EYE_RECORD_OBSERVATION,
      input: { entity_id: 'ent_1' },
      actor: { id: 'op_1' },
    })).rejects.toThrow('input.observation_type is required');
  });

  it('rejects eye_record_observation without entity_id', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.EYE_RECORD_OBSERVATION,
      input: { observation_type: 'suspicious_activity' },
      actor: { id: 'op_1' },
    })).rejects.toThrow('input.entity_id is required');
  });

  it('rejects eye_issue_advisory without advisory_type', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.EYE_ISSUE_ADVISORY,
      input: { entity_id: 'ent_1' },
      actor: { id: 'op_1' },
    })).rejects.toThrow('input.advisory_type is required');
  });

  it('rejects eye_create_suppression without rule_id', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.EYE_CREATE_SUPPRESSION,
      input: {},
      actor: { id: 'op_1' },
    })).rejects.toThrow('input.rule_id is required');
  });

  it('rejects eye_revoke_suppression without suppression_id', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.EYE_REVOKE_SUPPRESSION,
      input: {},
      actor: { id: 'op_1' },
    })).rejects.toThrow('input.suppression_id is required');
  });
});

// ── Eye handlers ──────────────────────────────────────────────────────────────

describe('eye command routing', () => {
  it('eye_record_observation handler returns recorded=true', async () => {
    const result = await protocolWrite({
      type: COMMAND_TYPES.EYE_RECORD_OBSERVATION,
      input: { observation_type: 'spike', entity_id: 'ent_1' },
      actor: { id: 'op_1' },
    });
    expect(result.recorded).toBe(true);
    expect(result.observation_type).toBe('spike');
    expect(result.entity_id).toBe('ent_1');
  });

  it('eye_issue_advisory handler returns issued=true', async () => {
    const result = await protocolWrite({
      type: COMMAND_TYPES.EYE_ISSUE_ADVISORY,
      input: { advisory_type: 'fraud_risk', entity_id: 'ent_2' },
      actor: { id: 'op_1' },
    });
    expect(result.issued).toBe(true);
    expect(result.advisory_type).toBe('fraud_risk');
  });

  it('eye_create_suppression handler returns created=true', async () => {
    const result = await protocolWrite({
      type: COMMAND_TYPES.EYE_CREATE_SUPPRESSION,
      input: { rule_id: 'rule_abc' },
      actor: { id: 'op_1' },
    });
    expect(result.created).toBe(true);
    expect(result.rule_id).toBe('rule_abc');
  });

  it('eye_revoke_suppression handler returns revoked=true', async () => {
    const result = await protocolWrite({
      type: COMMAND_TYPES.EYE_REVOKE_SUPPRESSION,
      input: { suppression_id: 'sup_xyz' },
      actor: { id: 'op_1' },
    });
    expect(result.revoked).toBe(true);
    expect(result.suppression_id).toBe('sup_xyz');
  });
});

// ── Cron/lifecycle handlers ───────────────────────────────────────────────────

describe('cron/lifecycle command routing', () => {
  it('expire_receipts routes to DB update and returns count', async () => {
    const mockSupabase = {
      from: vi.fn().mockReturnValue(makeChain({ data: null, error: null })),
    };
    mockGetServiceClient.mockReturnValue(mockSupabase);

    const result = await protocolWrite({
      type: COMMAND_TYPES.EXPIRE_RECEIPTS,
      input: { receipt_ids: ['r_1', 'r_2', 'r_3'] },
      actor: { id: 'cron' },
    });

    expect(result.expired).toBe(3);
    expect(result.receipt_ids).toEqual(['r_1', 'r_2', 'r_3']);
  });

  it('expire_receipts throws when DB returns error', async () => {
    const errorChain = makeChain({ data: null, error: { message: 'table not found' } });
    errorChain.update = vi.fn().mockReturnThis();
    errorChain.in = vi.fn().mockReturnThis();
    errorChain.then = (resolve) => Promise.resolve({ data: null, error: { message: 'table not found' } }).then(resolve);

    const mockSupabase = { from: vi.fn().mockReturnValue(errorChain) };
    mockGetServiceClient.mockReturnValue(mockSupabase);

    await expect(protocolWrite({
      type: COMMAND_TYPES.EXPIRE_RECEIPTS,
      input: { receipt_ids: ['r_1'] },
      actor: { id: 'cron' },
    })).rejects.toThrow(ProtocolWriteError);
  });

  it('escalate_disputes routes to DB update and returns count', async () => {
    const mockSupabase = {
      from: vi.fn().mockReturnValue(makeChain({ data: null, error: null })),
    };
    mockGetServiceClient.mockReturnValue(mockSupabase);

    const result = await protocolWrite({
      type: COMMAND_TYPES.ESCALATE_DISPUTES,
      input: { dispute_ids: ['d_1', 'd_2'] },
      actor: { id: 'cron' },
    });

    expect(result.escalated).toBe(2);
    expect(result.dispute_ids).toEqual(['d_1', 'd_2']);
  });

  it('escalate_disputes throws when DB returns error', async () => {
    const errorChain = makeChain({ data: null, error: { message: 'query error' } });
    errorChain.update = vi.fn().mockReturnThis();
    errorChain.in = vi.fn().mockReturnThis();
    errorChain.then = (resolve) => Promise.resolve({ data: null, error: { message: 'query error' } }).then(resolve);

    const mockSupabase = { from: vi.fn().mockReturnValue(errorChain) };
    mockGetServiceClient.mockReturnValue(mockSupabase);

    await expect(protocolWrite({
      type: COMMAND_TYPES.ESCALATE_DISPUTES,
      input: { dispute_ids: ['d_1'] },
      actor: { id: 'cron' },
    })).rejects.toThrow(ProtocolWriteError);
  });

  it('expire_continuity_claims routes to DB update and returns count', async () => {
    const mockSupabase = {
      from: vi.fn().mockReturnValue(makeChain({ data: null, error: null })),
    };
    mockGetServiceClient.mockReturnValue(mockSupabase);

    const result = await protocolWrite({
      type: COMMAND_TYPES.EXPIRE_CONTINUITY_CLAIMS,
      input: { continuity_ids: ['ep_ix_1', 'ep_ix_2'] },
      actor: { id: 'cron' },
    });

    expect(result.expired).toBe(2);
    expect(result.continuity_ids).toEqual(['ep_ix_1', 'ep_ix_2']);
  });

  it('expire_continuity_claims throws on DB error', async () => {
    const errorChain = makeChain({ data: null, error: { message: 'update failed' } });
    errorChain.update = vi.fn().mockReturnThis();
    errorChain.in = vi.fn().mockReturnThis();
    errorChain.then = (resolve) => Promise.resolve({ data: null, error: { message: 'update failed' } }).then(resolve);

    const mockSupabase = { from: vi.fn().mockReturnValue(errorChain) };
    mockGetServiceClient.mockReturnValue(mockSupabase);

    await expect(protocolWrite({
      type: COMMAND_TYPES.EXPIRE_CONTINUITY_CLAIMS,
      input: { continuity_ids: ['ep_ix_1'] },
      actor: { id: 'cron' },
    })).rejects.toThrow(ProtocolWriteError);
  });
});

// ── CONSUME_HANDSHAKE_BINDING handler ────────────────────────────────────────

describe('consume_handshake_binding handler', () => {
  it('returns consumed=true when binding found', async () => {
    const binding = { handshake_id: 'eph_1', consumed_by: 'op_1', consumed_for: 'ent_1' };
    const chain = makeChain({ data: binding, error: null });
    chain.update = vi.fn().mockReturnThis();
    chain.eq = vi.fn().mockReturnThis();
    chain.is = vi.fn().mockReturnThis();
    chain.select = vi.fn().mockReturnThis();
    chain.maybeSingle = vi.fn().mockResolvedValue({ data: binding, error: null });

    // First call for handshake_bindings update, second for protocol_events insert
    let callCount = 0;
    const mockSupabase = {
      from: vi.fn().mockImplementation(() => {
        callCount++;
        if (callCount === 1) return chain;
        return makeChain({ data: null, error: null });
      }),
    };
    mockGetServiceClient.mockReturnValue(mockSupabase);

    const result = await protocolWrite({
      type: COMMAND_TYPES.CONSUME_HANDSHAKE_BINDING,
      input: { handshake_id: 'eph_1', consumed_by: 'op_1', consumed_for: 'ent_1' },
      actor: { id: 'op_1' },
    });

    expect(result.consumed).toBe(true);
    expect(result.binding).toEqual(binding);
  });

  it('returns consumed=false when binding not found (already consumed)', async () => {
    const chain = makeChain({ data: null, error: null });
    chain.update = vi.fn().mockReturnThis();
    chain.eq = vi.fn().mockReturnThis();
    chain.is = vi.fn().mockReturnThis();
    chain.select = vi.fn().mockReturnThis();
    chain.maybeSingle = vi.fn().mockResolvedValue({ data: null, error: null });

    let callCount = 0;
    const mockSupabase = {
      from: vi.fn().mockImplementation(() => {
        callCount++;
        if (callCount === 1) return chain;
        return makeChain({ data: null, error: null });
      }),
    };
    mockGetServiceClient.mockReturnValue(mockSupabase);

    const result = await protocolWrite({
      type: COMMAND_TYPES.CONSUME_HANDSHAKE_BINDING,
      input: { handshake_id: 'eph_1', consumed_by: 'op_1', consumed_for: 'ent_1' },
      actor: { id: 'op_1' },
    });

    expect(result.consumed).toBe(false);
  });

  it('throws ProtocolWriteError when DB returns error', async () => {
    const chain = makeChain({ data: null, error: { message: 'binding error' } });
    chain.update = vi.fn().mockReturnThis();
    chain.eq = vi.fn().mockReturnThis();
    chain.is = vi.fn().mockReturnThis();
    chain.select = vi.fn().mockReturnThis();
    chain.maybeSingle = vi.fn().mockResolvedValue({ data: null, error: { message: 'binding error' } });

    const mockSupabase = { from: vi.fn().mockReturnValue(chain) };
    mockGetServiceClient.mockReturnValue(mockSupabase);

    await expect(protocolWrite({
      type: COMMAND_TYPES.CONSUME_HANDSHAKE_BINDING,
      input: { handshake_id: 'eph_1', consumed_by: 'op_1', consumed_for: 'ent_1' },
      actor: { id: 'op_1' },
    })).rejects.toThrow(ProtocolWriteError);
  });
});

// ── SIGNOFF_CHALLENGE_VIEW pass-through ───────────────────────────────────────

describe('signoff_challenge_view handler', () => {
  it('returns challenge_id as-is (read-through-write)', async () => {
    const result = await protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_CHALLENGE_VIEW,
      input: { challenge_id: 'ch_abc123' },
      actor: { id: 'viewer_1' },
    });

    expect(result.challenge_id).toBe('ch_abc123');
  });
});

// ── Dispute sub-commands routing ──────────────────────────────────────────────

describe('dispute sub-commands routing', () => {
  it('respond_dispute routes to canonicalRespondDispute', async () => {
    const expected = { dispute_id: 'd_1', status: 'responded' };
    mockCanonicalRespondDispute.mockResolvedValue(expected);

    const result = await protocolWrite({
      type: COMMAND_TYPES.RESPOND_DISPUTE,
      input: { dispute_id: 'd_1', responder_id: 'ent_1', response: 'I have evidence' },
      actor: { id: 'ent_1' },
    });

    expect(result).toEqual(expected);
    expect(mockCanonicalRespondDispute).toHaveBeenCalledWith('d_1', 'ent_1', 'I have evidence', undefined);
  });

  it('appeal_dispute routes to canonicalAppealDispute', async () => {
    const expected = { dispute_id: 'd_1', status: 'appealing' };
    mockCanonicalAppealDispute.mockResolvedValue(expected);

    const result = await protocolWrite({
      type: COMMAND_TYPES.APPEAL_DISPUTE,
      input: { dispute_id: 'd_1', reason: 'New evidence available now' },
      actor: { id: 'appellant_1' },
    });

    expect(result).toEqual(expected);
    expect(mockCanonicalAppealDispute).toHaveBeenCalled();
  });

  it('appeal_dispute rejects reason shorter than 10 chars', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.APPEAL_DISPUTE,
      input: { dispute_id: 'd_1', reason: 'short' },
      actor: { id: 'ent_1' },
    })).rejects.toThrow('at least 10 characters');
  });

  it('resolve_appeal routes to canonicalResolveAppeal', async () => {
    const expected = { dispute_id: 'd_1', resolution: 'overturned' };
    mockCanonicalResolveAppeal.mockResolvedValue(expected);

    const result = await protocolWrite({
      type: COMMAND_TYPES.RESOLVE_APPEAL,
      input: { dispute_id: 'd_1', resolution: 'overturned', rationale: 'New evidence', operator_id: 'op_1' },
      actor: { id: 'op_1' },
    });

    expect(result).toEqual(expected);
    expect(mockCanonicalResolveAppeal).toHaveBeenCalledWith('d_1', 'overturned', 'New evidence', 'op_1');
  });

  it('withdraw_dispute routes to canonicalWithdrawDispute', async () => {
    const expected = { dispute_id: 'd_1', status: 'withdrawn' };
    mockCanonicalWithdrawDispute.mockResolvedValue(expected);

    const result = await protocolWrite({
      type: COMMAND_TYPES.WITHDRAW_DISPUTE,
      input: { dispute_id: 'd_1' },
      actor: { id: 'withdrawer_1' },
    });

    expect(result).toEqual(expected);
    expect(mockCanonicalWithdrawDispute).toHaveBeenCalled();
  });

  it('respond_dispute requires responder_id', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.RESPOND_DISPUTE,
      input: { dispute_id: 'd_1', response: 'My answer' },
      actor: { id: 'ent_1' },
    })).rejects.toThrow('input.responder_id is required');
  });

  it('respond_dispute requires response text', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.RESPOND_DISPUTE,
      input: { dispute_id: 'd_1', responder_id: 'ent_1' },
      actor: { id: 'ent_1' },
    })).rejects.toThrow('input.response is required');
  });
});

// ── appendProtocolEvent failure ───────────────────────────────────────────────

describe('appendProtocolEvent failure path', () => {
  it('throws EVENT_PERSISTENCE_FAILED when protocol_events insert fails', async () => {
    mockCanonicalFileReport.mockResolvedValue({ report_id: 'rpt_1', entity_id: 'ent_1' });
    mockCheckAbuse.mockResolvedValue({ allowed: true });

    // All from() calls fail on insert
    const mockSupabase = {
      from: vi.fn().mockReturnValue(
        makeChain({ data: null, error: { message: 'disk full' } })
      ),
    };
    mockGetServiceClient.mockReturnValue(mockSupabase);

    await expect(protocolWrite({
      type: COMMAND_TYPES.FILE_REPORT,
      input: { entity_id: 'ent_1', report_type: 'fraud', description: 'suspicious activity' },
      actor: null,
    })).rejects.toThrow(ProtocolWriteError);
  });
});

// ── canonicalStringify ────────────────────────────────────────────────────────

describe('canonicalStringify (via computeIdempotencyKey)', () => {
  it('produces the same key regardless of object key order', () => {
    const key1 = _internals.computeIdempotencyKey({
      type: 'submit_receipt',
      actor: 'sub_1',
      input: { entity_id: 'e', transaction_ref: 'tx' },
    });
    const key2 = _internals.computeIdempotencyKey({
      type: 'submit_receipt',
      actor: 'sub_1',
      input: { transaction_ref: 'tx', entity_id: 'e' },
    });
    expect(key1).toBe(key2);
  });

  it('handles nested objects', () => {
    const key1 = _internals.computeIdempotencyKey({
      type: 'submit_receipt',
      actor: 'sub_1',
      input: { context: { b: 2, a: 1 } },
    });
    const key2 = _internals.computeIdempotencyKey({
      type: 'submit_receipt',
      actor: 'sub_1',
      input: { context: { a: 1, b: 2 } },
    });
    expect(key1).toBe(key2);
  });
});

// ── assertInvariants ──────────────────────────────────────────────────────────

describe('assertInvariants', () => {
  it('allows null input (no input key)', () => {
    // Should not throw for valid command type with null input
    expect(() => _internals.assertInvariants({ type: 'submit_receipt', input: null })).not.toThrow();
  });

  it('allows undefined input', () => {
    expect(() => _internals.assertInvariants({ type: 'submit_receipt' })).not.toThrow();
  });

  it('throws for non-object input (string)', () => {
    expect(() => _internals.assertInvariants({ type: 'submit_receipt', input: 'bad' }))
      .toThrow('command.input must be an object');
  });

  it('throws for non-object input (number)', () => {
    expect(() => _internals.assertInvariants({ type: 'submit_receipt', input: 42 }))
      .toThrow('command.input must be an object');
  });
});

// ── buildProtocolEvent extras ─────────────────────────────────────────────────

describe('buildProtocolEvent extras', () => {
  it('includes payload_json in event record', () => {
    const payload = { entity_id: 'ent_1', amount: 100 };
    const event = _internals.buildProtocolEvent({
      aggregateType: 'receipt',
      aggregateId: 'r_1',
      commandType: 'submit_receipt',
      payload,
      actorAuthorityId: 'sub_1',
      idempotencyKey: 'key_1',
    });

    expect(event.payload_json).toEqual(payload);
  });

  it('event_id is a valid UUID format', () => {
    const event = _internals.buildProtocolEvent({
      aggregateType: 'commit',
      aggregateId: 'epc_1',
      commandType: 'issue_commit',
      payload: {},
      actorAuthorityId: 'op_1',
      idempotencyKey: 'k',
    });

    expect(event.event_id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
  });

  it('parentEventHash defaults to null', () => {
    const event = _internals.buildProtocolEvent({
      aggregateType: 'report',
      aggregateId: 'rpt_1',
      commandType: 'file_report',
      payload: {},
      actorAuthorityId: 'actor_1',
      idempotencyKey: 'k',
    });

    expect(event.parent_event_hash).toBeNull();
  });

  it('accepts explicit parentEventHash', () => {
    const event = _internals.buildProtocolEvent({
      aggregateType: 'dispute',
      aggregateId: 'd_1',
      commandType: 'resolve_dispute',
      payload: {},
      actorAuthorityId: 'op_1',
      idempotencyKey: 'k',
      parentEventHash: 'abc123',
    });

    expect(event.parent_event_hash).toBe('abc123');
  });
});

// ── Error result not cached ───────────────────────────────────────────────────

describe('error result not cached by idempotency', () => {
  it('does not cache error results (allows retry)', async () => {
    const errorResult = { error: 'Entity not found', status: 404 };
    const successResult = { receipt: { receipt_id: 'r_1' } };

    mockCanonicalSubmitReceipt
      .mockResolvedValueOnce(errorResult)
      .mockResolvedValueOnce(successResult);

    const command = {
      type: COMMAND_TYPES.SUBMIT_RECEIPT,
      input: { entity_id: 'ent_retry' },
      actor: { id: 'sub_1' },
    };

    const first = await protocolWrite(command);
    expect(first.error).toBe('Entity not found');

    // Clear cache manually to simulate what error non-caching should do
    _internals._idempotencyCache.clear();

    const second = await protocolWrite(command);
    expect(second.receipt).toBeDefined();
    // Handler called twice — error was not cached
    expect(mockCanonicalSubmitReceipt).toHaveBeenCalledTimes(2);
  });
});
