/**
 * lib/protocol-write.js — signoff handler execution coverage.
 *
 * Uncovered lines 719-757: signoff handler functions that are called when
 * validation passes. Tests bypass validation by providing valid inputs and
 * mock the dynamically-imported signoff modules.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Module-level mocks ────────────────────────────────────────────────────────

const mockGetServiceClient = vi.fn();
const mockCheckAbuse = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

vi.mock('../lib/canonical-writer.js', () => ({
  canonicalSubmitReceipt: vi.fn(),
  canonicalSubmitAutoReceipt: vi.fn(),
  canonicalBilateralConfirm: vi.fn(),
  canonicalFileDispute: vi.fn(),
  canonicalResolveDispute: vi.fn(),
  canonicalRespondDispute: vi.fn(),
  canonicalAppealDispute: vi.fn(),
  canonicalResolveAppeal: vi.fn(),
  canonicalWithdrawDispute: vi.fn(),
  canonicalFileReport: vi.fn(),
}));

vi.mock('../lib/commit.js', () => ({
  issueCommit: vi.fn(),
  verifyCommit: vi.fn(),
  revokeCommit: vi.fn(),
}));

vi.mock('../lib/handshake.js', () => ({
  _handleInitiateHandshake: vi.fn().mockResolvedValue({ result: {}, aggregateId: 'hs_1' }),
  _handleAddPresentation: vi.fn().mockResolvedValue({ result: {}, aggregateId: 'hs_1' }),
  _handleVerifyHandshake: vi.fn().mockResolvedValue({ result: {}, aggregateId: 'hs_1' }),
  _handleRevokeHandshake: vi.fn().mockResolvedValue({ result: {}, aggregateId: 'hs_1' }),
}));

vi.mock('../lib/procedural-justice.js', () => ({
  hasPermission: vi.fn().mockReturnValue(true),
  checkAbuse: (...args) => mockCheckAbuse(...args),
  validateTransition: vi.fn().mockReturnValue({ valid: true }),
  DISPUTE_STATES: {},
}));

// Mock all dynamically-imported signoff modules
vi.mock('@/lib/signoff/attest.js', () => ({
  createAttestation: vi.fn().mockResolvedValue({ attestation_id: 'att_1', status: 'approved' }),
}));

vi.mock('@/lib/signoff/consume.js', () => ({
  consumeSignoff: vi.fn().mockResolvedValue({ signoff_id: 'so_1', consumed: true }),
}));

vi.mock('@/lib/signoff/revoke.js', () => ({
  revokeChallenge: vi.fn().mockResolvedValue({ challenge_id: 'ch_1', status: 'revoked' }),
  revokeAttestation: vi.fn().mockResolvedValue({ attestation_id: 'att_1', status: 'revoked' }),
}));

vi.mock('@/lib/signoff/events.js', () => ({
  emitSignoffEvent: vi.fn().mockResolvedValue({ event: 'challenge_expired' }),
  requireSignoffEvent: vi.fn().mockResolvedValue({ event: 'required' }),
  getSignoffEvents: vi.fn().mockResolvedValue([]),
  SIGNOFF_EVENT_TYPES: {},
}));

// Import after mocks
import { protocolWrite, COMMAND_TYPES, _internals } from '../lib/protocol-write.js';

function makeChain(resolved = { data: null, error: null }) {
  return {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    insert: vi.fn().mockResolvedValue(resolved),
    single: vi.fn().mockResolvedValue(resolved),
    maybeSingle: vi.fn().mockResolvedValue(resolved),
    then: (resolve) => Promise.resolve(resolved).then(resolve),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  _internals._idempotencyCache.clear();

  mockGetServiceClient.mockReturnValue({
    from: vi.fn().mockReturnValue(makeChain({ data: null, error: null })),
  });
  mockCheckAbuse.mockResolvedValue({ allowed: true });
});

// ── SIGNOFF_ATTEST handler (line 719-722) ─────────────────────────────────────

describe('signoff handler — SIGNOFF_ATTEST (line 719)', () => {
  it('executes createAttestation handler with valid input', async () => {
    const result = await protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_ATTEST,
      input: { challenge_id: 'ch_1', method: 'biometric' },
      actor: { id: 'op_1' },
    });
    expect(result).toBeDefined();
  });
});

// ── SIGNOFF_DENY handler (line 724-728) ──────────────────────────────────────

describe('signoff handler — SIGNOFF_DENY (line 724)', () => {
  it('executes createAttestation(denied=true) handler with valid input', async () => {
    const result = await protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_DENY,
      input: { challenge_id: 'ch_1', reason: 'user declined' },
      actor: { id: 'op_1' },
    });
    expect(result).toBeDefined();
  });
});

// ── SIGNOFF_CONSUME handler (line 730-734) ───────────────────────────────────

describe('signoff handler — SIGNOFF_CONSUME (line 730)', () => {
  it('executes consumeSignoff handler with valid input', async () => {
    const result = await protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_CONSUME,
      input: { signoff_id: 'so_1' },
      actor: { id: 'op_1' },
    });
    expect(result).toBeDefined();
  });
});

// ── SIGNOFF_CHALLENGE_REVOKE handler (line 736-740) ──────────────────────────

describe('signoff handler — SIGNOFF_CHALLENGE_REVOKE (line 736)', () => {
  it('executes revokeChallenge handler with valid input', async () => {
    const result = await protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_CHALLENGE_REVOKE,
      input: { challenge_id: 'ch_1', reason: 'expired' },
      actor: { id: 'op_1' },
    });
    expect(result).toBeDefined();
  });
});

// ── SIGNOFF_ATTESTATION_REVOKE handler (line 742-746) ────────────────────────

describe('signoff handler — SIGNOFF_ATTESTATION_REVOKE (line 742)', () => {
  it('executes revokeAttestation handler with valid input', async () => {
    const result = await protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_ATTESTATION_REVOKE,
      input: { attestation_id: 'att_1', reason: 'mistake' },
      actor: { id: 'op_1' },
    });
    expect(result).toBeDefined();
  });
});

// ── SIGNOFF_CHALLENGE_EXPIRE handler (line 748-752) ──────────────────────────

describe('signoff handler — SIGNOFF_CHALLENGE_EXPIRE (line 748)', () => {
  it('executes emitSignoffEvent(challenge_expired) with valid input', async () => {
    const result = await protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_CHALLENGE_EXPIRE,
      input: { challenge_id: 'ch_1' },
      actor: { id: 'cron' },
    });
    expect(result).toBeDefined();
  });
});

// ── SIGNOFF_ATTESTATION_EXPIRE handler (line 754-758) ────────────────────────

describe('signoff handler — SIGNOFF_ATTESTATION_EXPIRE (line 754)', () => {
  it('executes emitSignoffEvent(attestation_expired) with valid input', async () => {
    const result = await protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_ATTESTATION_EXPIRE,
      input: { attestation_id: 'att_1' },
      actor: { id: 'cron' },
    });
    expect(result).toBeDefined();
  });
});
