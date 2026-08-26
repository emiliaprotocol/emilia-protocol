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
const mockIssueChallenge = vi.fn();
const mockCreateAttestation = vi.fn();
const mockDenyChallenge = vi.fn();
const mockConsumeSignoff = vi.fn();
const mockRevokeChallenge = vi.fn();
const mockRevokeAttestation = vi.fn();
const mockExpireChallenge = vi.fn();
const mockExpireAttestation = vi.fn();

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
  createAttestation: (...args) => mockCreateAttestation(...args),
}));

vi.mock('@/lib/signoff/challenge.js', () => ({
  issueChallenge: (...args) => mockIssueChallenge(...args),
}));

vi.mock('@/lib/signoff/deny.js', () => ({
  denyChallenge: (...args) => mockDenyChallenge(...args),
}));

vi.mock('@/lib/signoff/consume.js', () => ({
  consumeSignoff: (...args) => mockConsumeSignoff(...args),
}));

vi.mock('@/lib/signoff/revoke.js', () => ({
  revokeChallenge: (...args) => mockRevokeChallenge(...args),
  revokeAttestation: (...args) => mockRevokeAttestation(...args),
}));

vi.mock('@/lib/signoff/expire.js', () => ({
  expireChallenge: (...args) => mockExpireChallenge(...args),
  expireAttestation: (...args) => mockExpireAttestation(...args),
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
  mockIssueChallenge.mockResolvedValue({ challenge_id: 'ch_1', status: 'challenge_issued' });
  mockCreateAttestation.mockResolvedValue({ signoff_id: 'att_1', status: 'approved' });
  mockDenyChallenge.mockResolvedValue({ challenge_id: 'ch_1', status: 'denied' });
  mockConsumeSignoff.mockResolvedValue({ signoff_id: 'so_1', consumed: true });
  mockRevokeChallenge.mockResolvedValue({ challenge_id: 'ch_1', status: 'revoked' });
  mockRevokeAttestation.mockResolvedValue({ signoff_id: 'att_1', status: 'revoked' });
  mockExpireChallenge.mockResolvedValue({ challenge_id: 'ch_1', status: 'expired' });
  mockExpireAttestation.mockResolvedValue({ signoff_id: 'att_1', status: 'expired' });
});

describe('signoff handler — SIGNOFF_CHALLENGE_ISSUE', () => {
  it('passes the current handshake-bound challenge contract exactly', async () => {
    await protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_CHALLENGE_ISSUE,
      input: {
        handshakeId: 'hs_1',
        bindingHash: 'sha256:binding',
        expiresAt: '2099-01-01T00:00:00Z',
        metadata: { source: 'verified-producer' },
      },
      actor: { entity_id: 'entity-issuer' },
    });

    expect(mockIssueChallenge).toHaveBeenCalledWith({
      handshakeId: 'hs_1',
      bindingHash: 'sha256:binding',
      expiresAt: '2099-01-01T00:00:00Z',
      metadata: { source: 'verified-producer' },
      actor: { entity_id: 'entity-issuer' },
    });
  });
});

// ── SIGNOFF_ATTEST handler (line 719-722) ─────────────────────────────────────

describe('signoff handler — SIGNOFF_ATTEST (line 719)', () => {
  it('executes createAttestation handler with valid input', async () => {
    await protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_ATTEST,
      input: {
        challengeId: 'ch_1',
        humanEntityRef: 'entity-alice',
        authMethod: 'passkey',
        assuranceLevel: 'substantial',
        channel: 'web',
        ceremonyEvidenceId: '99999999-9999-4999-8999-999999999999',
      },
      actor: { entity_id: 'entity-alice' },
    });
    expect(mockCreateAttestation).toHaveBeenCalledWith(expect.objectContaining({
      challengeId: 'ch_1',
      ceremonyEvidenceId: '99999999-9999-4999-8999-999999999999',
      actor: { entity_id: 'entity-alice' },
    }));
  });
});

// ── SIGNOFF_DENY handler (line 724-728) ──────────────────────────────────────

describe('signoff handler — SIGNOFF_DENY (line 724)', () => {
  it('executes the denial transition and never the approval handler', async () => {
    await protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_DENY,
      input: { challengeId: 'ch_1', reason: 'user declined' },
      actor: { entity_id: 'entity-alice' },
    });
    expect(mockDenyChallenge).toHaveBeenCalledWith({
      challengeId: 'ch_1',
      reason: 'user declined',
      actor: { entity_id: 'entity-alice' },
    });
    expect(mockCreateAttestation).not.toHaveBeenCalled();
  });
});

// ── SIGNOFF_CONSUME handler (line 730-734) ───────────────────────────────────

describe('signoff handler — SIGNOFF_CONSUME (line 730)', () => {
  it('executes consumeSignoff handler with valid input', async () => {
    await protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_CONSUME,
      input: {
        signoffId: 'so_1',
        bindingHash: 'sha256:binding',
        executionRef: 'execution-1',
      },
      actor: { entity_id: 'entity-alice' },
    });
    expect(mockConsumeSignoff).toHaveBeenCalledWith({
      signoffId: 'so_1',
      bindingHash: 'sha256:binding',
      executionRef: 'execution-1',
      actor: { entity_id: 'entity-alice' },
    });
  });
});

// ── SIGNOFF_CHALLENGE_REVOKE handler (line 736-740) ──────────────────────────

describe('signoff handler — SIGNOFF_CHALLENGE_REVOKE (line 736)', () => {
  it('executes revokeChallenge handler with valid input', async () => {
    const result = await protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_CHALLENGE_REVOKE,
      input: { challenge_id: 'ch_1', reason: 'expired' },
      actor: { entity_id: 'entity-alice' },
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
      actor: { entity_id: 'entity-alice' },
    });
    expect(result).toBeDefined();
  });
});

// ── SIGNOFF_CHALLENGE_EXPIRE handler (line 748-752) ──────────────────────────

describe('signoff handler — SIGNOFF_CHALLENGE_EXPIRE (line 748)', () => {
  it('executes the atomic challenge expiry transition with exact arguments', async () => {
    await protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_CHALLENGE_EXPIRE,
      input: { challenge_id: 'ch_1' },
      actor: { id: 'cron' },
    });
    expect(mockExpireChallenge).toHaveBeenCalledWith({
      challengeId: 'ch_1',
      actor: { entity_id: 'cron' },
    });
  });
});

// ── SIGNOFF_ATTESTATION_EXPIRE handler (line 754-758) ────────────────────────

describe('signoff handler — SIGNOFF_ATTESTATION_EXPIRE (line 754)', () => {
  it('executes the atomic attestation expiry transition with exact arguments', async () => {
    await protocolWrite({
      type: COMMAND_TYPES.SIGNOFF_ATTESTATION_EXPIRE,
      input: { attestation_id: 'att_1' },
      actor: { id: 'cron' },
    });
    expect(mockExpireAttestation).toHaveBeenCalledWith({
      signoffId: 'att_1',
      actor: { entity_id: 'cron' },
    });
  });
});
