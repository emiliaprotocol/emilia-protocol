/**
 * lib/handshake/present.js — extended coverage for uncovered lines.
 *
 * Uncovered lines:
 *   141-142  _handleAddPresentation: no issuer_ref → self_asserted trust
 *   155      _handleAddPresentation: authorities DB error (non-table-missing) → throws
 *   229      _handleAddPresentation: rpcError → throws HandshakeError DB_ERROR
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockGetServiceClient = vi.fn();
const mockProtocolWrite = vi.fn();

vi.mock('@/lib/supabase', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

vi.mock('@/lib/actor', () => ({
  resolveActorRef: (actor) => (typeof actor === 'string' ? actor : 'system'),
}));

vi.mock('@/lib/protocol-write', () => ({
  protocolWrite: (...args) => mockProtocolWrite(...args),
  COMMAND_TYPES: { ADD_PRESENTATION: 'add_presentation' },
}));

vi.mock('./invariants.js', () => ({
  VALID_PARTY_ROLES: new Set(['initiator', 'responder']),
  VALID_DISCLOSURE_MODES: new Set(['full', 'minimal', 'selective']),
  sha256: (s) => 'sha256:' + s,
}));

vi.mock('./normalize.js', () => ({
  normalizeClaims: (c) => c,
  claimsToCanonicalHash: (c) => 'hash:' + JSON.stringify(c),
}));

import { _handleAddPresentation } from '../lib/handshake/present.js';

beforeEach(() => {
  vi.clearAllMocks();
});

function makeBaseSupabase({ handshake, handshakeError, party, partyError, authorityResult, rpcResult }) {
  return {
    from: vi.fn((table) => {
      if (table === 'handshakes') {
        return {
          select: vi.fn().mockReturnThis(),
          eq: vi.fn().mockReturnThis(),
          maybeSingle: vi.fn().mockResolvedValue({ data: handshake ?? null, error: handshakeError ?? null }),
        };
      }
      if (table === 'handshake_parties') {
        return {
          select: vi.fn().mockReturnThis(),
          eq: vi.fn().mockReturnThis(),
          maybeSingle: vi.fn().mockResolvedValue({ data: party ?? null, error: partyError ?? null }),
        };
      }
      if (table === 'authorities') {
        return {
          select: vi.fn().mockReturnThis(),
          eq: vi.fn().mockReturnThis(),
          maybeSingle: vi.fn().mockResolvedValue(authorityResult ?? { data: null, error: null }),
        };
      }
      return {
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        maybeSingle: vi.fn().mockResolvedValue({ data: null, error: null }),
        insert: vi.fn().mockReturnThis(),
        single: vi.fn().mockResolvedValue({ data: null, error: null }),
      };
    }),
    rpc: vi.fn().mockResolvedValue(rpcResult ?? { data: { ok: true }, error: null }),
  };
}

const validHandshake = {
  handshake_id: 'hs-1',
  status: 'initiated',
  policy_id: 'pol-1',
};

const validParty = {
  id: 'party-1',
  party_role: 'initiator',
  entity_ref: 'system',
};

function makeCommand(overrides = {}) {
  return {
    actor: 'system',
    input: {
      handshake_id: 'hs-1',
      party_role: 'initiator',
      presentation_type: 'self_asserted',
      issuer_ref: null,
      presentation_hash: 'sha256:abc',
      disclosure_mode: 'full',
      raw_claims: { name: 'Alice' },
      ...overrides,
    },
  };
}

// ── Lines 141-142: no issuer_ref → self_asserted ─────────────────────────────

describe('_handleAddPresentation — self_asserted trust (lines 141-142)', () => {
  it('sets issuerTrusted=true and issuerTrustReason=self_asserted when no issuer_ref', async () => {
    const db = makeBaseSupabase({
      handshake: validHandshake,
      party: validParty,
    });
    mockGetServiceClient.mockReturnValue(db);

    const result = await _handleAddPresentation(makeCommand({ issuer_ref: null }));
    // If we reach here without throwing, the self_asserted path ran successfully
    expect(result).toHaveProperty('_protocolEventWritten', true);
    // Verify the rpc was called with p_issuer_trusted: true
    expect(db.rpc).toHaveBeenCalledWith(
      'present_handshake_writes',
      expect.objectContaining({ p_issuer_trusted: true, p_issuer_status: 'self_asserted' })
    );
  });
});

// ── Line 155: authorities DB error (non-table-missing) → throws ──────────────

describe('_handleAddPresentation — authority DB error (line 155)', () => {
  it('throws HandshakeError DB_ERROR when authority query fails with non-table error', async () => {
    const db = makeBaseSupabase({
      handshake: validHandshake,
      party: validParty,
      authorityResult: { data: null, error: { message: 'permission denied for table authorities' } },
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(
      _handleAddPresentation(makeCommand({ issuer_ref: 'key-abc' }))
    ).rejects.toMatchObject({ code: 'DB_ERROR' });
  });

  it('does NOT throw when authority error is a missing-table error', async () => {
    const db = makeBaseSupabase({
      handshake: validHandshake,
      party: validParty,
      authorityResult: { data: null, error: { message: 'relation "authorities" does not exist' } },
    });
    mockGetServiceClient.mockReturnValue(db);

    const result = await _handleAddPresentation(makeCommand({ issuer_ref: 'key-abc' }));
    expect(result).toHaveProperty('_protocolEventWritten', true);
    // authority_table_missing → issuerTrusted = false
    expect(db.rpc).toHaveBeenCalledWith(
      'present_handshake_writes',
      expect.objectContaining({ p_issuer_trusted: false, p_issuer_status: 'authority_table_missing' })
    );
  });
});

// ── Line 229: rpcError → throws HandshakeError DB_ERROR ──────────────────────

describe('_handleAddPresentation — rpcError (line 229)', () => {
  it('throws HandshakeError DB_ERROR when RPC call fails', async () => {
    const db = makeBaseSupabase({
      handshake: validHandshake,
      party: validParty,
      rpcResult: { data: null, error: { message: 'function not found' } },
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(
      _handleAddPresentation(makeCommand({ issuer_ref: null }))
    ).rejects.toMatchObject({ code: 'DB_ERROR' });
  });
});
