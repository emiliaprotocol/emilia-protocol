/**
 * EMILIA Protocol — protocolWrite() Tests
 *
 * Tests for the single choke point that all trust-changing writes flow through.
 * Covers: command validation, idempotency, routing to correct handlers,
 * protocol event building, and error handling.
 *
 * Uses vi.mock to mock all downstream dependencies so no real DB or
 * network calls are made.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ============================================================================
// Supabase mock helpers
// ============================================================================

function makeChain(resolveValue) {
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

// ============================================================================
// Mock dependencies
// ============================================================================

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

vi.mock('../lib/procedural-justice.js', () => ({
  hasPermission: vi.fn().mockReturnValue(true),
  checkAbuse: (...args) => mockCheckAbuse(...args),
  validateTransition: vi.fn().mockReturnValue({ valid: true }),
  DISPUTE_STATES: {},
}));

// Import after mocks
import { protocolWrite, COMMAND_TYPES, ProtocolWriteError, _internals } from '../lib/protocol-write.js';

// ============================================================================
// Setup
// ============================================================================

beforeEach(() => {
  vi.clearAllMocks();

  // Clear idempotency cache between tests
  _internals._idempotencyCache.clear();

  // Default: Supabase returns a working mock with insert for event persistence
  const mockSupabase = {
    from: vi.fn().mockReturnValue(makeChain({ data: null, error: null })),
  };
  mockGetServiceClient.mockReturnValue(mockSupabase);

  // Default: abuse checks pass
  mockCheckAbuse.mockResolvedValue({ allowed: true });
});

// ============================================================================
// 1. Command validation rejects unknown types
// ============================================================================

describe('command validation', () => {
  it('rejects commands with no type', async () => {
    await expect(protocolWrite({ input: {}, actor: 'test' }))
      .rejects.toThrow(ProtocolWriteError);
    await expect(protocolWrite({ input: {}, actor: 'test' }))
      .rejects.toThrow('command.type is required');
  });

  it('rejects unknown command types', async () => {
    await expect(protocolWrite({ type: 'nuke_everything', input: {}, actor: 'test' }))
      .rejects.toThrow(ProtocolWriteError);
    await expect(protocolWrite({ type: 'nuke_everything', input: {}, actor: 'test' }))
      .rejects.toThrow('Unknown command type');
  });

  it('rejects commands where input is not an object', async () => {
    await expect(protocolWrite({ type: COMMAND_TYPES.SUBMIT_RECEIPT, input: 'not-an-object', actor: 'test' }))
      .rejects.toThrow('command.input must be an object');
  });

  it('rejects submit_receipt without entity_id', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.SUBMIT_RECEIPT,
      input: {},
      actor: { id: 'ent_1' },
    })).rejects.toThrow('input.entity_id is required');
  });

  it('rejects file_dispute without receipt_id', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.FILE_DISPUTE,
      input: { reason: 'fraud' },
      actor: { id: 'ent_1' },
    })).rejects.toThrow('input.receipt_id is required');
  });

  it('rejects file_dispute without reason', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.FILE_DISPUTE,
      input: { receipt_id: 'r_1' },
      actor: { id: 'ent_1' },
    })).rejects.toThrow('input.reason is required');
  });

  it('rejects resolve_dispute without required fields', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.RESOLVE_DISPUTE,
      input: { dispute_id: 'd_1' },
      actor: { id: 'op_1' },
    })).rejects.toThrow('input.resolution is required');
  });

  it('rejects confirm_receipt without confirm boolean', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.CONFIRM_RECEIPT,
      input: { receipt_id: 'r_1', confirming_entity_id: 'ent_1', confirm: 'yes' },
      actor: { id: 'ent_1' },
    })).rejects.toThrow('input.confirm must be a boolean');
  });

  it('rejects issue_commit without action_type', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.ISSUE_COMMIT,
      input: { entity_id: 'ent_1' },
      actor: { id: 'ent_1' },
    })).rejects.toThrow('input.action_type is required');
  });

  it('rejects revoke_commit without reason', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.REVOKE_COMMIT,
      input: { commit_id: 'epc_123' },
      actor: { id: 'ent_1' },
    })).rejects.toThrow('input.reason is required');
  });

  it('rejects file_report without description', async () => {
    await expect(protocolWrite({
      type: COMMAND_TYPES.FILE_REPORT,
      input: { entity_id: 'ent_1', report_type: 'fraud' },
      actor: null,
    })).rejects.toThrow('input.description is required');
  });
});

// ============================================================================
// 2. Idempotency returns existing result on duplicate
// ============================================================================

describe('idempotency', () => {
  it('returns cached result with _idempotent flag on duplicate command', async () => {
    const receiptResult = {
      receipt: { receipt_id: 'r_123', entity_id: 'ent_1' },
      deduplicated: false,
    };
    mockCanonicalSubmitReceipt.mockResolvedValue(receiptResult);

    const command = {
      type: COMMAND_TYPES.SUBMIT_RECEIPT,
      input: { entity_id: 'test-entity', transaction_ref: 'tx_1' },
      actor: { id: 'submitter_1', entity_id: 'submitter_1' },
    };

    // First call — should execute handler
    const first = await protocolWrite(command);
    expect(first).toEqual(receiptResult);
    expect(mockCanonicalSubmitReceipt).toHaveBeenCalledTimes(1);

    // Second call — same command — should return cached
    const second = await protocolWrite(command);
    expect(second._idempotent).toBe(true);
    expect(second.receipt).toEqual(receiptResult.receipt);
    // Handler should NOT have been called again
    expect(mockCanonicalSubmitReceipt).toHaveBeenCalledTimes(1);
  });

  it('does not return cached result for different commands', async () => {
    const result1 = { receipt: { receipt_id: 'r_1' }, deduplicated: false };
    const result2 = { receipt: { receipt_id: 'r_2' }, deduplicated: false };
    mockCanonicalSubmitReceipt
      .mockResolvedValueOnce(result1)
      .mockResolvedValueOnce(result2);

    const command1 = {
      type: COMMAND_TYPES.SUBMIT_RECEIPT,
      input: { entity_id: 'entity-a' },
      actor: { id: 'sub_1' },
    };
    const command2 = {
      type: COMMAND_TYPES.SUBMIT_RECEIPT,
      input: { entity_id: 'entity-b' },
      actor: { id: 'sub_1' },
    };

    await protocolWrite(command1);
    await protocolWrite(command2);

    expect(mockCanonicalSubmitReceipt).toHaveBeenCalledTimes(2);
  });
});

// ============================================================================
// 3. Each command type routes to correct handler
// ============================================================================

describe('command routing', () => {
  it('submit_receipt routes to canonicalSubmitReceipt', async () => {
    const expected = { receipt: { receipt_id: 'r_1' } };
    mockCanonicalSubmitReceipt.mockResolvedValue(expected);

    const result = await protocolWrite({
      type: COMMAND_TYPES.SUBMIT_RECEIPT,
      input: { entity_id: 'ent_1' },
      actor: { id: 'sub_1', entity_id: 'sub_1' },
    });

    expect(result).toEqual(expected);
    expect(mockCanonicalSubmitReceipt).toHaveBeenCalledWith(
      { entity_id: 'ent_1' },
      { id: 'sub_1', entity_id: 'sub_1' }
    );
  });

  it('submit_auto_receipt routes to canonicalSubmitAutoReceipt', async () => {
    const expected = { receipt: { receipt_id: 'r_auto' } };
    mockCanonicalSubmitAutoReceipt.mockResolvedValue(expected);

    const result = await protocolWrite({
      type: COMMAND_TYPES.SUBMIT_AUTO_RECEIPT,
      input: { entity_id: 'ent_1', transaction_type: 'service' },
      actor: { id: 'machine_1', entity_id: 'machine_1' },
    });

    expect(result).toEqual(expected);
    expect(mockCanonicalSubmitAutoReceipt).toHaveBeenCalledWith(
      { entity_id: 'ent_1', transaction_type: 'service' },
      { id: 'machine_1', entity_id: 'machine_1' }
    );
  });

  it('confirm_receipt routes to canonicalBilateralConfirm', async () => {
    const expected = { receipt_id: 'r_1', bilateral_status: 'confirmed' };
    mockCanonicalBilateralConfirm.mockResolvedValue(expected);

    const result = await protocolWrite({
      type: COMMAND_TYPES.CONFIRM_RECEIPT,
      input: { receipt_id: 'r_1', confirming_entity_id: 'ent_1', confirm: true },
      actor: { id: 'ent_1' },
    });

    expect(result).toEqual(expected);
    expect(mockCanonicalBilateralConfirm).toHaveBeenCalledWith('r_1', 'ent_1', true);
  });

  it('issue_commit routes to issueCommit', async () => {
    const expected = { commit_id: 'epc_123', decision: 'allow' };
    mockIssueCommit.mockResolvedValue(expected);

    const result = await protocolWrite({
      type: COMMAND_TYPES.ISSUE_COMMIT,
      input: { entity_id: 'ent_1', action_type: 'install' },
      actor: { id: 'caller_1' },
    });

    expect(result).toEqual(expected);
    expect(mockIssueCommit).toHaveBeenCalledWith({ entity_id: 'ent_1', action_type: 'install' });
  });

  it('verify_commit routes to verifyCommit', async () => {
    const expected = { valid: true, status: 'active', decision: 'allow' };
    mockVerifyCommit.mockResolvedValue(expected);

    const result = await protocolWrite({
      type: COMMAND_TYPES.VERIFY_COMMIT,
      input: { commit_id: 'epc_123' },
      actor: { id: 'verifier_1' },
    });

    expect(result).toEqual(expected);
    expect(mockVerifyCommit).toHaveBeenCalledWith('epc_123');
  });

  it('revoke_commit routes to revokeCommit', async () => {
    const expected = { success: true, commit_id: 'epc_123' };
    mockRevokeCommit.mockResolvedValue(expected);

    const result = await protocolWrite({
      type: COMMAND_TYPES.REVOKE_COMMIT,
      input: { commit_id: 'epc_123', reason: 'policy_change' },
      actor: { id: 'op_1' },
    });

    expect(result).toEqual(expected);
    expect(mockRevokeCommit).toHaveBeenCalledWith('epc_123', 'policy_change');
  });

  it('file_dispute routes to canonicalFileDispute', async () => {
    const expected = { dispute_id: 'd_1', status: 'open' };
    mockCanonicalFileDispute.mockResolvedValue(expected);

    const result = await protocolWrite({
      type: COMMAND_TYPES.FILE_DISPUTE,
      input: { receipt_id: 'r_1', reason: 'inaccurate' },
      actor: { id: 'filer_1' },
    });

    expect(result).toEqual(expected);
    expect(mockCanonicalFileDispute).toHaveBeenCalledWith(
      { receipt_id: 'r_1', reason: 'inaccurate' },
      { id: 'filer_1' }
    );
  });

  it('resolve_dispute routes to canonicalResolveDispute', async () => {
    const expected = { dispute_id: 'd_1', resolution: 'upheld' };
    mockCanonicalResolveDispute.mockResolvedValue(expected);

    const result = await protocolWrite({
      type: COMMAND_TYPES.RESOLVE_DISPUTE,
      input: {
        dispute_id: 'd_1',
        resolution: 'upheld',
        rationale: 'evidence supports claim',
        operator_id: 'op_1',
      },
      actor: { id: 'op_1' },
    });

    expect(result).toEqual(expected);
    expect(mockCanonicalResolveDispute).toHaveBeenCalledWith(
      'd_1', 'upheld', 'evidence supports claim', 'op_1'
    );
  });

  it('file_report routes to canonicalFileReport', async () => {
    const expected = { report_id: 'rpt_1', entity_id: 'ent_1' };
    mockCanonicalFileReport.mockResolvedValue(expected);

    const result = await protocolWrite({
      type: COMMAND_TYPES.FILE_REPORT,
      input: { entity_id: 'ent_1', report_type: 'fraud', description: 'suspicious activity' },
      actor: null,
    });

    expect(result).toEqual(expected);
    expect(mockCanonicalFileReport).toHaveBeenCalledWith(
      { entity_id: 'ent_1', report_type: 'fraud', description: 'suspicious activity' }
    );
  });
});

// ============================================================================
// 4. Invalid commands throw, not degrade
// ============================================================================

describe('error handling — throw, not degrade', () => {
  it('throws ProtocolWriteError with correct code for unknown types', async () => {
    try {
      await protocolWrite({ type: 'destroy_all', input: {}, actor: 'test' });
      expect.fail('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(ProtocolWriteError);
      expect(e.code).toBe('UNKNOWN_COMMAND_TYPE');
      expect(e.status).toBe(400);
    }
  });

  it('throws ProtocolWriteError with VALIDATION_ERROR code for missing fields', async () => {
    try {
      await protocolWrite({
        type: COMMAND_TYPES.SUBMIT_RECEIPT,
        input: {},
        actor: { id: 'sub_1' },
      });
      expect.fail('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(ProtocolWriteError);
      expect(e.code).toBe('VALIDATION_ERROR');
    }
  });

  it('propagates errors from canonical functions (not swallowed)', async () => {
    mockCanonicalSubmitReceipt.mockRejectedValue(new Error('DB connection lost'));

    await expect(protocolWrite({
      type: COMMAND_TYPES.SUBMIT_RECEIPT,
      input: { entity_id: 'ent_1' },
      actor: { id: 'sub_1' },
    })).rejects.toThrow('DB connection lost');
  });

  it('returns error objects from canonical functions without caching', async () => {
    const errorResult = { error: 'Entity not found', status: 404 };
    mockCanonicalSubmitReceipt.mockResolvedValue(errorResult);

    const result = await protocolWrite({
      type: COMMAND_TYPES.SUBMIT_RECEIPT,
      input: { entity_id: 'nonexistent' },
      actor: { id: 'sub_1' },
    });

    expect(result.error).toBe('Entity not found');
    expect(result.status).toBe(404);
  });
});

// ============================================================================
// 5. Protocol event building
// ============================================================================

describe('buildProtocolEvent', () => {
  it('produces a well-formed event record', () => {
    const event = _internals.buildProtocolEvent({
      aggregateType: 'receipt',
      aggregateId: 'r_123',
      commandType: 'submit_receipt',
      payload: { entity_id: 'ent_1', transaction_ref: 'tx_1' },
      actorAuthorityId: 'sub_1',
      idempotencyKey: 'idem_abc',
      parentEventHash: null,
    });

    expect(event.event_id).toBeDefined();
    expect(event.aggregate_type).toBe('receipt');
    expect(event.aggregate_id).toBe('r_123');
    expect(event.command_type).toBe('submit_receipt');
    expect(event.payload_hash).toBeDefined();
    expect(event.payload_hash.length).toBe(64); // SHA-256 hex
    expect(event.actor_authority_id).toBe('sub_1');
    expect(event.idempotency_key).toBe('idem_abc');
    expect(event.parent_event_hash).toBeNull();
    expect(event.created_at).toBeDefined();
  });

  it('produces deterministic payload_hash for same payload', () => {
    const params = {
      aggregateType: 'dispute',
      aggregateId: 'd_1',
      commandType: 'file_dispute',
      payload: { receipt_id: 'r_1', reason: 'fraud' },
      actorAuthorityId: 'filer_1',
      idempotencyKey: 'idem_xyz',
    };

    const event1 = _internals.buildProtocolEvent(params);
    const event2 = _internals.buildProtocolEvent(params);

    expect(event1.payload_hash).toBe(event2.payload_hash);
  });
});

// ============================================================================
// 6. Idempotency key computation
// ============================================================================

describe('computeIdempotencyKey', () => {
  it('produces deterministic key for same command', () => {
    const command = { type: 'submit_receipt', actor: 'sub_1', input: { entity_id: 'ent_1' } };
    const key1 = _internals.computeIdempotencyKey(command);
    const key2 = _internals.computeIdempotencyKey(command);
    expect(key1).toBe(key2);
    expect(key1.length).toBe(64); // SHA-256 hex
  });

  it('produces different keys for different commands', () => {
    const key1 = _internals.computeIdempotencyKey({ type: 'submit_receipt', actor: 'sub_1', input: { entity_id: 'a' } });
    const key2 = _internals.computeIdempotencyKey({ type: 'submit_receipt', actor: 'sub_1', input: { entity_id: 'b' } });
    expect(key1).not.toBe(key2);
  });

  it('produces different keys for different actors', () => {
    const key1 = _internals.computeIdempotencyKey({ type: 'submit_receipt', actor: 'sub_1', input: { entity_id: 'a' } });
    const key2 = _internals.computeIdempotencyKey({ type: 'submit_receipt', actor: 'sub_2', input: { entity_id: 'a' } });
    expect(key1).not.toBe(key2);
  });
});

// ============================================================================
// 7. Authority resolution
// ============================================================================

describe('resolveAuthority', () => {
  it('extracts id from entity object', () => {
    const authority = _internals.resolveAuthority({
      actor: { id: 'ent_1', entity_id: 'ent_1_slug' },
      requestMeta: { role: 'disputant', source: 'web' },
    });
    expect(authority.id).toBe('ent_1');
    expect(authority.role).toBe('disputant');
    expect(authority.source).toBe('web');
  });

  it('uses entity_id as fallback', () => {
    const authority = _internals.resolveAuthority({
      actor: { entity_id: 'ent_slug' },
    });
    expect(authority.id).toBe('ent_slug');
  });

  it('handles string actor', () => {
    const authority = _internals.resolveAuthority({ actor: 'my_entity_id' });
    expect(authority.id).toBe('my_entity_id');
  });

  it('defaults to anonymous for null actor', () => {
    const authority = _internals.resolveAuthority({ actor: null });
    expect(authority.id).toBe('anonymous');
  });
});

// ============================================================================
// 8. Abuse detection integration
// ============================================================================

describe('abuse detection', () => {
  it('blocks file_dispute when abuse detected', async () => {
    mockCheckAbuse.mockResolvedValue({ allowed: false, pattern: 'dispute_flooding', action: 'rate_limit' });

    await expect(protocolWrite({
      type: COMMAND_TYPES.FILE_DISPUTE,
      input: { receipt_id: 'r_1', reason: 'fraud' },
      actor: { id: 'filer_1' },
    })).rejects.toThrow('abuse detection');
  });

  it('blocks file_report when abuse detected', async () => {
    mockCheckAbuse.mockResolvedValue({ allowed: false, pattern: 'brigading', action: 'flag_for_review' });

    await expect(protocolWrite({
      type: COMMAND_TYPES.FILE_REPORT,
      input: { entity_id: 'ent_1', report_type: 'fraud', description: 'test' },
      actor: null,
    })).rejects.toThrow('abuse detection');
  });

  it('proceeds when abuse check passes', async () => {
    mockCheckAbuse.mockResolvedValue({ allowed: true });
    mockCanonicalFileDispute.mockResolvedValue({ dispute_id: 'd_1', status: 'open' });

    const result = await protocolWrite({
      type: COMMAND_TYPES.FILE_DISPUTE,
      input: { receipt_id: 'r_1', reason: 'inaccurate' },
      actor: { id: 'filer_1' },
    });

    expect(result.dispute_id).toBe('d_1');
  });
});

// ============================================================================
// 9. COMMAND_TYPES constant coverage
// ============================================================================

describe('COMMAND_TYPES', () => {
  it('has all 9 expected command types', () => {
    expect(Object.keys(COMMAND_TYPES)).toHaveLength(9);
    expect(COMMAND_TYPES.SUBMIT_RECEIPT).toBe('submit_receipt');
    expect(COMMAND_TYPES.CONFIRM_RECEIPT).toBe('confirm_receipt');
    expect(COMMAND_TYPES.ISSUE_COMMIT).toBe('issue_commit');
    expect(COMMAND_TYPES.VERIFY_COMMIT).toBe('verify_commit');
    expect(COMMAND_TYPES.REVOKE_COMMIT).toBe('revoke_commit');
    expect(COMMAND_TYPES.FILE_DISPUTE).toBe('file_dispute');
    expect(COMMAND_TYPES.RESOLVE_DISPUTE).toBe('resolve_dispute');
    expect(COMMAND_TYPES.FILE_REPORT).toBe('file_report');
    expect(COMMAND_TYPES.SUBMIT_AUTO_RECEIPT).toBe('submit_auto_receipt');
  });

  it('every command type has a validator', () => {
    for (const type of Object.values(COMMAND_TYPES)) {
      expect(_internals.VALIDATORS[type]).toBeDefined();
    }
  });

  it('every command type has a handler', () => {
    for (const type of Object.values(COMMAND_TYPES)) {
      expect(_internals.HANDLERS[type]).toBeDefined();
    }
  });

  it('every command type maps to an aggregate', () => {
    for (const type of Object.values(COMMAND_TYPES)) {
      expect(_internals.COMMAND_TO_AGGREGATE[type]).toBeDefined();
      expect(['receipt', 'commit', 'dispute', 'report']).toContain(
        _internals.COMMAND_TO_AGGREGATE[type]
      );
    }
  });
});
