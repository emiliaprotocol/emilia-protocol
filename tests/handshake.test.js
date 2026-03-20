/**
 * EMILIA Protocol — EP Handshake Tests
 *
 * Tests for the EP Handshake system: transaction-scoped identity verification
 * with policy-bound presentations and assurance levels.
 *
 * Covers initiateHandshake, addPresentation, verifyHandshake, getHandshake,
 * revokeHandshake, constants, state machine, and security invariants.
 *
 * Uses vi.mock to mock Supabase and protocol-write so no real DB or network
 * calls are made. protocolWrite is wired to call the handshake _handle*
 * functions directly, simulating the real dispatch pipeline.
 *
 * @license Apache-2.0
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import crypto from 'crypto';

// ============================================================================
// Mock: Supabase
// ============================================================================

const mockGetServiceClient = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

// ============================================================================
// Mock: protocol-write
//
// We provide the COMMAND_TYPES the handshake module expects and route
// protocolWrite calls to the real _handle* functions so we exercise the
// actual business logic without the real protocolWrite invariant checks.
// ============================================================================

/** Pending handler registration — filled after import */
let _handshakeHandlers = {};

vi.mock('../lib/protocol-write.js', () => {
  const COMMAND_TYPES = {
    SUBMIT_RECEIPT: 'submit_receipt',
    CONFIRM_RECEIPT: 'confirm_receipt',
    ISSUE_COMMIT: 'issue_commit',
    VERIFY_COMMIT: 'verify_commit',
    REVOKE_COMMIT: 'revoke_commit',
    FILE_DISPUTE: 'file_dispute',
    RESOLVE_DISPUTE: 'resolve_dispute',
    FILE_REPORT: 'file_report',
    SUBMIT_AUTO_RECEIPT: 'submit_auto_receipt',
    INITIATE_HANDSHAKE: 'initiate_handshake',
    ADD_PRESENTATION: 'add_presentation',
    VERIFY_HANDSHAKE: 'verify_handshake',
    REVOKE_HANDSHAKE: 'revoke_handshake',
  };

  return {
    COMMAND_TYPES,
    protocolWrite: vi.fn(async (command) => {
      const handler = _handshakeHandlers[command.type];
      if (!handler) {
        throw new Error(`No handler for command type: ${command.type}`);
      }
      const res = await handler(command);
      return res?.result ?? res;
    }),
  };
});

// ============================================================================
// Import module under test (after mocks)
// ============================================================================

import {
  initiateHandshake,
  addPresentation,
  verifyHandshake,
  getHandshake,
  revokeHandshake,
  HANDSHAKE_MODES,
  ASSURANCE_LEVELS,
  HANDSHAKE_STATUSES,
  _handleInitiateHandshake,
  _handleAddPresentation,
  _handleVerifyHandshake,
  _handleRevokeHandshake,
  _internals,
} from '../lib/handshake/index.js';

// Wire handlers after import so they reference the real functions
_handshakeHandlers = {
  initiate_handshake: _handleInitiateHandshake,
  add_presentation: _handleAddPresentation,
  verify_handshake: _handleVerifyHandshake,
  revoke_handshake: _handleRevokeHandshake,
  // issue_commit — stub that returns a mock commit
  issue_commit: async () => ({
    result: { commit_id: 'epc_mock_' + crypto.randomBytes(4).toString('hex'), decision: 'allow' },
    aggregateId: 'epc_mock',
  }),
};

// ============================================================================
// Supabase table simulator
//
// Instead of a flat mock, we maintain in-memory tables so the handlers can
// insert, select, and update records realistically.
// ============================================================================

function createTableSim() {
  const tables = {};

  function getTable(name) {
    if (!tables[name]) tables[name] = [];
    // Seed default trusted authority on first access to 'authorities'
    if (name === 'authorities' && tables[name].length === 0) {
      tables[name].push({
        authority_id: 'auth-trusted-ca',
        key_id: 'issuer-trusted-ca',
        status: 'active',
        valid_from: new Date(Date.now() - 365 * 86_400_000).toISOString(),
        valid_to: new Date(Date.now() + 365 * 86_400_000).toISOString(),
      });
    }
    return tables[name];
  }

  function applyFilters(rows, filters) {
    let result = rows;
    for (const f of filters) {
      result = result.filter((r) => r[f.col] === f.val);
    }
    return result;
  }

  function buildSelectChain(tableName) {
    let filters = [];
    const chain = {
      select: vi.fn().mockImplementation(() => chain),
      eq: vi.fn().mockImplementation((col, val) => {
        filters.push({ col, val });
        return chain;
      }),
      neq: vi.fn().mockImplementation(() => chain),
      order: vi.fn().mockImplementation(() => chain),
      limit: vi.fn().mockImplementation(() => chain),
      single: vi.fn().mockImplementation(() => {
        const filtered = applyFilters(getTable(tableName), filters);
        filters = [];
        return Promise.resolve({ data: filtered[0] || null, error: null });
      }),
      maybeSingle: vi.fn().mockImplementation(() => {
        const filtered = applyFilters(getTable(tableName), filters);
        filters = [];
        return Promise.resolve({ data: filtered[0] || null, error: null });
      }),
      then: undefined,
    };
    chain.then = (resolve, reject) => {
      const filtered = applyFilters(getTable(tableName), filters);
      filters = [];
      return Promise.resolve({ data: filtered, error: null }).then(resolve, reject);
    };
    return chain;
  }

  function buildInsertChain(tableName) {
    let insertedRows = null;
    const chain = {
      insert: vi.fn().mockImplementation((rows) => {
        const arr = Array.isArray(rows) ? rows : [rows];
        for (const row of arr) {
          if (tableName === 'handshakes' && !row.handshake_id) {
            row.handshake_id = 'eph_' + crypto.randomBytes(12).toString('hex');
          }
          if (tableName === 'handshake_parties' && !row.id) {
            row.id = crypto.randomBytes(8).toString('hex');
          }
          getTable(tableName).push(row);
        }
        insertedRows = arr;
        return chain;
      }),
      select: vi.fn().mockImplementation(() => chain),
      single: vi.fn().mockImplementation(() => {
        return Promise.resolve({ data: insertedRows?.[0] || null, error: null });
      }),
      then: undefined,
    };
    chain.then = (resolve, reject) => {
      return Promise.resolve({ data: insertedRows, error: null }).then(resolve, reject);
    };
    return chain;
  }

  function buildUpdateChain(tableName) {
    let updateData = null;
    let filters = [];
    const chain = {
      update: vi.fn().mockImplementation((data) => {
        updateData = data;
        return chain;
      }),
      eq: vi.fn().mockImplementation((col, val) => {
        filters.push({ col, val });
        return chain;
      }),
      select: vi.fn().mockImplementation(() => chain),
      single: vi.fn().mockImplementation(() => {
        const rows = applyFilters(getTable(tableName), filters);
        for (const row of rows) Object.assign(row, updateData);
        filters = [];
        return Promise.resolve({ data: rows[0] || null, error: null });
      }),
      then: undefined,
    };
    chain.then = (resolve, reject) => {
      const rows = applyFilters(getTable(tableName), filters);
      for (const row of rows) Object.assign(row, updateData);
      filters = [];
      return Promise.resolve({ data: rows, error: null }).then(resolve, reject);
    };
    return chain;
  }

  function mockClient() {
    return {
      from: vi.fn().mockImplementation((tableName) => {
        return {
          select: (...args) => {
            const c = buildSelectChain(tableName);
            c.select(...args);
            return c;
          },
          insert: (rows) => {
            const c = buildInsertChain(tableName);
            return c.insert(rows);
          },
          update: (data) => {
            const c = buildUpdateChain(tableName);
            return c.update(data);
          },
        };
      }),
    };
  }

  return { tables, getTable, mockClient };
}

// ============================================================================
// Helpers: valid params builders
// ============================================================================

function validHandshakeParams(overrides = {}) {
  return {
    mode: 'basic',
    policy_id: 'policy-abc-123',
    parties: [
      { role: 'initiator', entity_ref: 'entity-alice' },
    ],
    payload: { action: 'connect', target: 'service-xyz' },
    binding_ttl_ms: 600_000,
    actor: 'entity-alice',
    ...overrides,
  };
}

function mutualHandshakeParams(overrides = {}) {
  return validHandshakeParams({
    mode: 'mutual',
    parties: [
      { role: 'initiator', entity_ref: 'entity-alice' },
      { role: 'responder', entity_ref: 'entity-bob' },
    ],
    ...overrides,
  });
}

function validPresentation(overrides = {}) {
  return {
    type: 'vc',
    data: JSON.stringify({
      entity_id: 'entity-alice',
      display_name: 'Alice Agent',
      assurance_level: 'substantial',
    }),
    issuer_ref: 'issuer-trusted-ca',
    disclosure_mode: 'full',
    ...overrides,
  };
}

// ============================================================================
// 1. Initiation Tests (8 tests)
// ============================================================================

describe('initiateHandshake', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it('creates a valid basic handshake record with eph_ prefix', async () => {
    const result = await initiateHandshake(validHandshakeParams());

    expect(result).toBeDefined();
    expect(result.handshake_id).toMatch(/^eph_/);
    expect(result.status).toBe('initiated');
    expect(result.mode).toBe('basic');
  });

  it('creates a mutual handshake with two party records', async () => {
    const result = await initiateHandshake(mutualHandshakeParams());

    expect(result).toBeDefined();
    expect(result.handshake_id).toMatch(/^eph_/);
    expect(result.mode).toBe('mutual');
    expect(result.parties).toHaveLength(2);
    expect(result.parties[0].party_role).toBe('initiator');
    expect(result.parties[1].party_role).toBe('responder');
  });

  it('creates a selective handshake with disclosure_mode preserved', async () => {
    const result = await initiateHandshake(
      validHandshakeParams({ mode: 'selective' }),
    );

    expect(result).toBeDefined();
    expect(result.mode).toBe('selective');
    expect(result.status).toBe('initiated');
  });

  it('creates a delegated handshake with delegation_chain', async () => {
    const result = await initiateHandshake(
      validHandshakeParams({
        mode: 'delegated',
        parties: [
          { role: 'initiator', entity_ref: 'entity-principal' },
          {
            role: 'delegate',
            entity_ref: 'entity-alice',
            delegation_chain: {
              scope: ['*'],
              expires_at: new Date(Date.now() + 3_600_000).toISOString(),
            },
          },
        ],
      }),
    );

    expect(result).toBeDefined();
    expect(result.mode).toBe('delegated');
    expect(result.parties).toHaveLength(2);
  });

  it('rejects initiation when policy_id is missing', async () => {
    await expect(
      initiateHandshake(validHandshakeParams({ policy_id: undefined })),
    ).rejects.toThrow(/policy/i);
  });

  it('rejects initiation when parties are missing', async () => {
    await expect(
      initiateHandshake(validHandshakeParams({ parties: undefined })),
    ).rejects.toThrow(/part/i);
  });

  it('rejects initiation with invalid mode', async () => {
    await expect(
      initiateHandshake(validHandshakeParams({ mode: 'nonexistent_mode' })),
    ).rejects.toThrow(/mode/i);
  });

  it('rejects initiation with empty parties array', async () => {
    await expect(
      initiateHandshake(validHandshakeParams({ parties: [] })),
    ).rejects.toThrow(/part/i);
  });
});

// ============================================================================
// 2. Presentation Tests (6 tests)
// ============================================================================

describe('addPresentation', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  /** Seed a handshake so addPresentation can find it */
  function seedHandshake(overrides = {}) {
    const hs = {
      handshake_id: 'eph_test_' + crypto.randomBytes(6).toString('hex'),
      mode: 'basic',
      status: 'initiated',
      policy_id: 'policy-abc-123',
      policy_version: '1.0.0',
      ...overrides,
    };
    sim.getTable('handshakes').push(hs);
    return hs;
  }

  function seedParty(handshake_id, role, entity_ref) {
    const p = {
      id: crypto.randomBytes(8).toString('hex'),
      handshake_id,
      party_role: role,
      entity_ref,
      verified_status: 'pending',
    };
    sim.getTable('handshake_parties').push(p);
    return p;
  }

  it('stores a valid presentation with computed hash', async () => {
    const hs = seedHandshake();
    seedParty(hs.handshake_id, 'initiator', 'entity-alice');

    const result = await addPresentation(
      hs.handshake_id,
      'initiator',
      validPresentation(),
    );

    expect(result).toBeDefined();
    expect(result.presentation_hash).toBeDefined();
    expect(result.presentation_hash.length).toBe(64); // sha256 hex
  });

  it('rejects presentation from unknown party_role', async () => {
    await expect(
      addPresentation('eph_test_123', 'unknown_role', validPresentation()),
    ).rejects.toThrow(/role/i);
  });

  it('rejects presentation with revoked issuer', async () => {
    const hs = seedHandshake();
    seedParty(hs.handshake_id, 'initiator', 'entity-alice');
    // Seed a revoked authority
    sim.getTable('authorities').push({
      authority_id: 'auth-1',
      key_id: 'issuer-revoked',
      status: 'revoked',
      valid_from: new Date(Date.now() - 86_400_000).toISOString(),
      valid_to: new Date(Date.now() + 86_400_000).toISOString(),
    });

    const result = await addPresentation(
      hs.handshake_id,
      'initiator',
      validPresentation({ issuer_ref: 'issuer-revoked' }),
    );

    // The handler stores the presentation but marks it as unverified
    expect(result).toBeDefined();
    expect(result.verified).toBe(false);
    expect(result.revocation_status).toBe('revoked');
  });

  it('stores selective disclosure with commitment mode', async () => {
    const hs = seedHandshake({ mode: 'selective' });
    seedParty(hs.handshake_id, 'initiator', 'entity-alice');

    const result = await addPresentation(
      hs.handshake_id,
      'initiator',
      validPresentation({ disclosure_mode: 'commitment' }),
    );

    expect(result).toBeDefined();
    expect(result.disclosure_mode).toBe('commitment');
    // Data is stored as a hash, not raw
    expect(result.presentation_hash).toBeDefined();
  });

  it('allows multiple presentations per party', async () => {
    const hs = seedHandshake();
    seedParty(hs.handshake_id, 'initiator', 'entity-alice');

    const result1 = await addPresentation(
      hs.handshake_id,
      'initiator',
      validPresentation({ data: 'proof-1' }),
    );
    expect(result1).toBeDefined();

    const result2 = await addPresentation(
      hs.handshake_id,
      'initiator',
      validPresentation({ type: 'x509', data: 'proof-2' }),
    );
    expect(result2).toBeDefined();

    // Both should be stored
    const stored = sim.getTable('handshake_presentations');
    const partyPres = stored.filter(
      (p) => p.handshake_id === hs.handshake_id && p.party_role === 'initiator',
    );
    expect(partyPres).toHaveLength(2);
  });

  it('rejects presentation after handshake is already verified', async () => {
    const hs = seedHandshake({ status: 'verified' });
    seedParty(hs.handshake_id, 'initiator', 'entity-alice');

    await expect(
      addPresentation(hs.handshake_id, 'initiator', validPresentation()),
    ).rejects.toThrow(/state/i);
  });
});

// ============================================================================
// 3. Verification Tests (10 tests)
// ============================================================================

describe('verifyHandshake', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  /** Seed a fully ready handshake with binding and presentations */
  function seedReadyHandshake(overrides = {}) {
    const hs_id = 'eph_v_' + crypto.randomBytes(6).toString('hex');
    const hs = {
      handshake_id: hs_id,
      mode: 'mutual',
      status: 'pending_verification',
      policy_id: 'policy-abc-123',
      policy_version: '1.0.0',
      ...(overrides.handshake || {}),
    };
    sim.getTable('handshakes').push(hs);

    // Parties
    const parties = overrides.parties || [
      { party_role: 'initiator', entity_ref: 'entity-alice', assurance_level: 'substantial' },
      { party_role: 'responder', entity_ref: 'entity-bob', assurance_level: 'substantial' },
    ];
    for (const p of parties) {
      sim.getTable('handshake_parties').push({
        id: crypto.randomBytes(8).toString('hex'),
        handshake_id: hs_id,
        verified_status: 'pending',
        ...p,
      });
    }

    // Binding
    const binding = {
      handshake_id: hs_id,
      payload_hash: _internals.sha256(JSON.stringify({ action: 'connect' })),
      nonce: crypto.randomBytes(32).toString('hex'),
      expires_at: new Date(Date.now() + 600_000).toISOString(),
      bound_at: new Date().toISOString(),
      ...(overrides.binding || {}),
    };
    sim.getTable('handshake_bindings').push(binding);

    // Presentations
    const presentations = overrides.presentations || [
      {
        handshake_id: hs_id,
        party_role: 'initiator',
        presentation_type: 'vc',
        issuer_ref: 'issuer-trusted-ca',
        presentation_hash: crypto.randomBytes(32).toString('hex'),
        disclosure_mode: 'full',
        verified: true,
        verified_at: new Date().toISOString(),
        revocation_checked: true,
        revocation_status: 'good',
      },
      {
        handshake_id: hs_id,
        party_role: 'responder',
        presentation_type: 'vc',
        issuer_ref: 'issuer-trusted-ca',
        presentation_hash: crypto.randomBytes(32).toString('hex'),
        disclosure_mode: 'full',
        verified: true,
        verified_at: new Date().toISOString(),
        revocation_checked: true,
        revocation_status: 'good',
      },
    ];
    for (const pres of presentations) {
      sim.getTable('handshake_presentations').push(pres);
    }

    return { hs_id, hs, binding };
  }

  it('accepts when all claims are met (outcome = accepted)', async () => {
    const { hs_id } = seedReadyHandshake();

    const result = await verifyHandshake(hs_id);

    expect(result).toBeDefined();
    expect(result.outcome).toBe('accepted');
    expect(result.reason_codes).toHaveLength(0);
  });

  it('rejects with reason_code when a required presentation is missing', async () => {
    const { hs_id } = seedReadyHandshake({
      presentations: [
        // Only initiator has a presentation — responder is missing
        {
          handshake_id: null, // will be set below
          party_role: 'initiator',
          presentation_type: 'vc',
          issuer_ref: 'issuer-trusted-ca',
          presentation_hash: crypto.randomBytes(32).toString('hex'),
          disclosure_mode: 'full',
          verified: true,
          verified_at: new Date().toISOString(),
          revocation_checked: true,
          revocation_status: 'good',
        },
      ],
    });
    // Fix handshake_id on the presentation
    sim.getTable('handshake_presentations')[0].handshake_id = hs_id;

    const result = await verifyHandshake(hs_id);

    expect(result.outcome).toBe('rejected');
    expect(result.reason_codes).toContain('missing_presentation_responder');
  });

  it('rejects when assurance level is below minimum', async () => {
    const { hs_id } = seedReadyHandshake({
      presentations: [], // override to add unverified ones
    });
    // Add presentations that are NOT verified
    sim.getTable('handshake_presentations').push(
      {
        handshake_id: hs_id,
        party_role: 'initiator',
        presentation_type: 'vc',
        issuer_ref: 'issuer-weak',
        presentation_hash: crypto.randomBytes(32).toString('hex'),
        disclosure_mode: 'full',
        verified: false,
        revocation_checked: true,
        revocation_status: 'good',
      },
      {
        handshake_id: hs_id,
        party_role: 'responder',
        presentation_type: 'vc',
        issuer_ref: 'issuer-weak',
        presentation_hash: crypto.randomBytes(32).toString('hex'),
        disclosure_mode: 'full',
        verified: false,
        revocation_checked: true,
        revocation_status: 'good',
      },
    );

    const result = await verifyHandshake(hs_id);

    // Unverified presentations means assurance not met — should not be accepted
    expect(result.outcome).not.toBe('accepted');
    expect(result.reason_codes.some((c) => c.includes('assurance') || c.includes('unverified'))).toBe(true);
  });

  it('rejects when binding is expired', async () => {
    const { hs_id } = seedReadyHandshake({
      binding: {
        expires_at: new Date(Date.now() - 60_000).toISOString(), // expired
      },
    });

    const result = await verifyHandshake(hs_id);

    expect(result.reason_codes).toContain('binding_expired');
    // Expired binding -> expired outcome
    expect(result.outcome).toBe('expired');
  });

  it('rejects when nonce is missing/invalid', async () => {
    const { hs_id } = seedReadyHandshake({
      binding: {
        nonce: '', // empty nonce
      },
    });

    const result = await verifyHandshake(hs_id);

    expect(result.reason_codes).toContain('missing_nonce');
    expect(result.outcome).toBe('rejected');
  });

  it('rejects when issuer is revoked', async () => {
    const { hs_id } = seedReadyHandshake({
      presentations: [],
    });
    sim.getTable('handshake_presentations').push(
      {
        handshake_id: hs_id,
        party_role: 'initiator',
        presentation_type: 'vc',
        issuer_ref: 'issuer-revoked',
        presentation_hash: crypto.randomBytes(32).toString('hex'),
        disclosure_mode: 'full',
        verified: false,
        revocation_checked: true,
        revocation_status: 'revoked',
      },
      {
        handshake_id: hs_id,
        party_role: 'responder',
        presentation_type: 'vc',
        issuer_ref: 'issuer-trusted-ca',
        presentation_hash: crypto.randomBytes(32).toString('hex'),
        disclosure_mode: 'full',
        verified: true,
        verified_at: new Date().toISOString(),
        revocation_checked: true,
        revocation_status: 'good',
      },
    );

    const result = await verifyHandshake(hs_id);

    expect(result.outcome).not.toBe('accepted');
    expect(result.reason_codes.some((c) => c.includes('revoked'))).toBe(true);
  });

  it('rejects when payload hash mismatches', async () => {
    const { hs_id } = seedReadyHandshake();

    const result = await verifyHandshake(hs_id, {
      payload_hash: 'wrong_hash_does_not_match',
    });

    expect(result.reason_codes).toContain('payload_hash_mismatch');
    expect(result.outcome).toBe('rejected');
  });

  it('rejects when delegation exceeds scope', async () => {
    const hs_id = 'eph_del_' + crypto.randomBytes(6).toString('hex');
    sim.getTable('handshakes').push({
      handshake_id: hs_id,
      mode: 'delegated',
      status: 'pending_verification',
      policy_id: 'policy-restricted',
      policy_version: '1.0.0',
    });
    sim.getTable('handshake_parties').push(
      {
        id: crypto.randomBytes(8).toString('hex'),
        handshake_id: hs_id,
        party_role: 'initiator',
        entity_ref: 'entity-principal',
        verified_status: 'pending',
      },
      {
        id: crypto.randomBytes(8).toString('hex'),
        handshake_id: hs_id,
        party_role: 'delegate',
        entity_ref: 'entity-alice',
        verified_status: 'pending',
        delegation_chain: {
          scope: ['policy-other-only'], // does NOT include policy-restricted
          expires_at: new Date(Date.now() + 3_600_000).toISOString(),
        },
      },
    );
    sim.getTable('handshake_bindings').push({
      handshake_id: hs_id,
      payload_hash: _internals.sha256('{}'),
      nonce: crypto.randomBytes(32).toString('hex'),
      expires_at: new Date(Date.now() + 600_000).toISOString(),
      bound_at: new Date().toISOString(),
    });
    sim.getTable('handshake_presentations').push({
      handshake_id: hs_id,
      party_role: 'initiator',
      presentation_type: 'vc',
      presentation_hash: crypto.randomBytes(32).toString('hex'),
      verified: true,
      verified_at: new Date().toISOString(),
      revocation_checked: true,
      revocation_status: 'good',
    });

    const result = await verifyHandshake(hs_id);

    expect(result.reason_codes).toContain('delegation_out_of_scope');
    expect(result.outcome).toBe('rejected');
  });

  it('returns partial when some parties verified and some not', async () => {
    const { hs_id } = seedReadyHandshake({
      presentations: [],
    });
    // initiator is verified, responder is not
    sim.getTable('handshake_presentations').push(
      {
        handshake_id: hs_id,
        party_role: 'initiator',
        presentation_type: 'vc',
        issuer_ref: 'issuer-trusted-ca',
        presentation_hash: crypto.randomBytes(32).toString('hex'),
        disclosure_mode: 'full',
        verified: true,
        verified_at: new Date().toISOString(),
        revocation_checked: true,
        revocation_status: 'good',
      },
      {
        handshake_id: hs_id,
        party_role: 'responder',
        presentation_type: 'vc',
        issuer_ref: 'issuer-untrusted',
        presentation_hash: crypto.randomBytes(32).toString('hex'),
        disclosure_mode: 'full',
        verified: false,
        revocation_checked: true,
        revocation_status: 'good',
      },
    );

    const result = await verifyHandshake(hs_id);

    expect(result.outcome).toBe('partial');
  });

  it('issues an EP Commit when handshake is accepted', async () => {
    const { hs_id } = seedReadyHandshake();

    const result = await verifyHandshake(hs_id);

    expect(result.outcome).toBe('accepted');
    expect(result.commit_ref).toBeDefined();
    expect(result.commit_ref).toMatch(/^epc_/);
  });
});

// ============================================================================
// 4. Security Invariants (8 tests)
// ============================================================================

describe('Security invariants', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it('replay: same nonce cannot be reused (binding nonce is unique per handshake)', async () => {
    // First handshake
    const result1 = await initiateHandshake(validHandshakeParams());
    expect(result1.handshake_id).toMatch(/^eph_/);

    // Second handshake — the system generates its own nonce internally,
    // so each handshake always gets a unique nonce
    const result2 = await initiateHandshake(validHandshakeParams());
    expect(result2.handshake_id).toMatch(/^eph_/);

    // Verify the two bindings have different nonces
    const bindings = sim.getTable('handshake_bindings');
    expect(bindings).toHaveLength(2);
    expect(bindings[0].nonce).not.toBe(bindings[1].nonce);
  });

  it('cannot verify an expired handshake (status already expired)', async () => {
    const hs_id = 'eph_exp_' + crypto.randomBytes(6).toString('hex');
    sim.getTable('handshakes').push({
      handshake_id: hs_id,
      mode: 'basic',
      status: 'expired',
      policy_id: 'policy-abc-123',
    });

    await expect(verifyHandshake(hs_id)).rejects.toThrow(/state|expired/i);
  });

  it('cannot add presentation to a verified handshake', async () => {
    const hs_id = 'eph_ver_' + crypto.randomBytes(6).toString('hex');
    sim.getTable('handshakes').push({
      handshake_id: hs_id,
      mode: 'basic',
      status: 'verified',
      policy_id: 'policy-abc-123',
    });
    sim.getTable('handshake_parties').push({
      id: crypto.randomBytes(8).toString('hex'),
      handshake_id: hs_id,
      party_role: 'initiator',
      entity_ref: 'entity-alice',
      verified_status: 'verified',
    });

    await expect(
      addPresentation(hs_id, 'initiator', validPresentation()),
    ).rejects.toThrow(/state/i);
  });

  it('revoked handshake returns revoked status', async () => {
    const hs_id = 'eph_rev_' + crypto.randomBytes(6).toString('hex');
    sim.getTable('handshakes').push({
      handshake_id: hs_id,
      mode: 'basic',
      status: 'initiated',
      policy_id: 'policy-abc-123',
    });

    const result = await revokeHandshake(hs_id, 'policy_violation');

    expect(result).toBeDefined();
    expect(result.status).toBe('revoked');
    expect(result.reason).toBe('policy_violation');
  });

  it('verification result always references policy_version', async () => {
    const hs_id = 'eph_pv_' + crypto.randomBytes(6).toString('hex');
    sim.getTable('handshakes').push({
      handshake_id: hs_id,
      mode: 'basic',
      status: 'pending_verification',
      policy_id: 'policy-abc-123',
      policy_version: '2.1.0',
    });
    sim.getTable('handshake_parties').push({
      id: crypto.randomBytes(8).toString('hex'),
      handshake_id: hs_id,
      party_role: 'initiator',
      entity_ref: 'entity-alice',
      verified_status: 'pending',
    });
    sim.getTable('handshake_bindings').push({
      handshake_id: hs_id,
      payload_hash: _internals.sha256('{}'),
      nonce: crypto.randomBytes(32).toString('hex'),
      expires_at: new Date(Date.now() + 600_000).toISOString(),
    });
    sim.getTable('handshake_presentations').push({
      handshake_id: hs_id,
      party_role: 'initiator',
      presentation_type: 'vc',
      presentation_hash: crypto.randomBytes(32).toString('hex'),
      verified: true,
      verified_at: new Date().toISOString(),
      revocation_checked: true,
      revocation_status: 'good',
    });

    const result = await verifyHandshake(hs_id);

    expect(result.policy_version).toBe('2.1.0');
  });

  it('cannot initiate handshake without valid parties (no initiator role)', async () => {
    // Parties present but no initiator role
    await expect(
      initiateHandshake(
        validHandshakeParams({
          parties: [{ role: 'responder', entity_ref: 'entity-bob' }],
        }),
      ),
    ).rejects.toThrow(/initiator/i);
  });

  it('delegated handshake checked against delegation expiry at verification', async () => {
    const hs_id = 'eph_dexp_' + crypto.randomBytes(6).toString('hex');
    sim.getTable('handshakes').push({
      handshake_id: hs_id,
      mode: 'delegated',
      status: 'pending_verification',
      policy_id: 'policy-abc-123',
      policy_version: '1.0.0',
    });
    sim.getTable('handshake_parties').push(
      {
        id: crypto.randomBytes(8).toString('hex'),
        handshake_id: hs_id,
        party_role: 'initiator',
        entity_ref: 'entity-principal',
        verified_status: 'pending',
      },
      {
        id: crypto.randomBytes(8).toString('hex'),
        handshake_id: hs_id,
        party_role: 'delegate',
        entity_ref: 'entity-alice',
        verified_status: 'pending',
        delegation_chain: {
          scope: ['*'],
          expires_at: new Date(Date.now() - 3_600_000).toISOString(), // expired
        },
      },
    );
    sim.getTable('handshake_bindings').push({
      handshake_id: hs_id,
      payload_hash: _internals.sha256('{}'),
      nonce: crypto.randomBytes(32).toString('hex'),
      expires_at: new Date(Date.now() + 600_000).toISOString(),
    });
    sim.getTable('handshake_presentations').push({
      handshake_id: hs_id,
      party_role: 'initiator',
      presentation_type: 'vc',
      presentation_hash: crypto.randomBytes(32).toString('hex'),
      verified: true,
      verified_at: new Date().toISOString(),
      revocation_checked: true,
      revocation_status: 'good',
    });

    const result = await verifyHandshake(hs_id);

    expect(result.reason_codes).toContain('delegation_expired');
    expect(result.outcome).toBe('rejected');
  });

  it('cross-party spoofing: party role must exist in handshake to add presentation', async () => {
    const hs_id = 'eph_spf_' + crypto.randomBytes(6).toString('hex');
    sim.getTable('handshakes').push({
      handshake_id: hs_id,
      mode: 'basic',
      status: 'initiated',
      policy_id: 'policy-abc-123',
    });
    // Only initiator party exists
    sim.getTable('handshake_parties').push({
      id: crypto.randomBytes(8).toString('hex'),
      handshake_id: hs_id,
      party_role: 'initiator',
      entity_ref: 'entity-alice',
      verified_status: 'pending',
    });

    // Attempt to present as responder (which does not exist in this handshake)
    await expect(
      addPresentation(hs_id, 'responder', validPresentation()),
    ).rejects.toThrow(/party|role|not found/i);
  });
});

// ============================================================================
// 5. State Machine Tests (4 tests)
// ============================================================================

describe('Handshake state machine', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it('transitions initiated -> pending_verification -> verified', async () => {
    // Step 1: initiated -> pending_verification (via addPresentation)
    const hs_id = 'eph_sm1_' + crypto.randomBytes(6).toString('hex');
    sim.getTable('handshakes').push({
      handshake_id: hs_id,
      mode: 'basic',
      status: 'initiated',
      policy_id: 'policy-abc-123',
      policy_version: '1.0.0',
    });
    sim.getTable('handshake_parties').push({
      id: crypto.randomBytes(8).toString('hex'),
      handshake_id: hs_id,
      party_role: 'initiator',
      entity_ref: 'entity-alice',
      assurance_level: 'substantial',
      verified_status: 'pending',
    });
    sim.getTable('handshake_bindings').push({
      handshake_id: hs_id,
      payload_hash: _internals.sha256('{}'),
      nonce: crypto.randomBytes(32).toString('hex'),
      expires_at: new Date(Date.now() + 600_000).toISOString(),
    });

    // Add presentation -> status should transition to pending_verification
    await addPresentation(hs_id, 'initiator', validPresentation());

    const hsAfterPres = sim.getTable('handshakes').find((h) => h.handshake_id === hs_id);
    expect(hsAfterPres.status).toBe('pending_verification');

    // Step 2: verify -> status should transition to verified
    const result = await verifyHandshake(hs_id);

    expect(result.outcome).toBe('accepted');
    const hsAfterVerify = sim.getTable('handshakes').find((h) => h.handshake_id === hs_id);
    expect(hsAfterVerify.status).toBe('verified');
  });

  it('transitions initiated -> pending_verification -> rejected', async () => {
    const hs_id = 'eph_sm2_' + crypto.randomBytes(6).toString('hex');
    sim.getTable('handshakes').push({
      handshake_id: hs_id,
      mode: 'mutual',
      status: 'pending_verification',
      policy_id: 'policy-abc-123',
      policy_version: '1.0.0',
    });
    sim.getTable('handshake_parties').push(
      {
        id: crypto.randomBytes(8).toString('hex'),
        handshake_id: hs_id,
        party_role: 'initiator',
        entity_ref: 'entity-alice',
        verified_status: 'pending',
      },
      {
        id: crypto.randomBytes(8).toString('hex'),
        handshake_id: hs_id,
        party_role: 'responder',
        entity_ref: 'entity-bob',
        verified_status: 'pending',
      },
    );
    sim.getTable('handshake_bindings').push({
      handshake_id: hs_id,
      payload_hash: _internals.sha256('{}'),
      nonce: crypto.randomBytes(32).toString('hex'),
      expires_at: new Date(Date.now() + 600_000).toISOString(),
    });
    // No presentations — missing required presentations -> rejected

    const result = await verifyHandshake(hs_id);

    expect(result.outcome).toBe('rejected');
    const hsAfter = sim.getTable('handshakes').find((h) => h.handshake_id === hs_id);
    expect(hsAfter.status).toBe('rejected');
  });

  it('transitions verified -> revoked', async () => {
    const hs_id = 'eph_sm3_' + crypto.randomBytes(6).toString('hex');
    sim.getTable('handshakes').push({
      handshake_id: hs_id,
      mode: 'basic',
      status: 'verified',
      policy_id: 'policy-abc-123',
    });

    const result = await revokeHandshake(hs_id, 'abuse_detected');

    expect(result.status).toBe('revoked');
    const hsAfter = sim.getTable('handshakes').find((h) => h.handshake_id === hs_id);
    expect(hsAfter.status).toBe('revoked');
  });

  it('expired cannot transition to verified', async () => {
    const hs_id = 'eph_sm4_' + crypto.randomBytes(6).toString('hex');
    sim.getTable('handshakes').push({
      handshake_id: hs_id,
      mode: 'basic',
      status: 'expired',
      policy_id: 'policy-abc-123',
    });

    // Attempting to verify an expired handshake should fail
    await expect(verifyHandshake(hs_id)).rejects.toThrow(/state|expired/i);
  });
});

// ============================================================================
// 6. Constants & getHandshake
// ============================================================================

describe('Handshake constants and getHandshake', () => {
  it('HANDSHAKE_MODES includes all four modes', () => {
    expect(HANDSHAKE_MODES).toContain('basic');
    expect(HANDSHAKE_MODES).toContain('mutual');
    expect(HANDSHAKE_MODES).toContain('selective');
    expect(HANDSHAKE_MODES).toContain('delegated');
  });

  it('ASSURANCE_LEVELS includes low, substantial, high', () => {
    expect(ASSURANCE_LEVELS).toContain('low');
    expect(ASSURANCE_LEVELS).toContain('substantial');
    expect(ASSURANCE_LEVELS).toContain('high');
  });

  it('HANDSHAKE_STATUSES includes lifecycle states', () => {
    expect(HANDSHAKE_STATUSES).toContain('initiated');
    expect(HANDSHAKE_STATUSES).toContain('pending_verification');
    expect(HANDSHAKE_STATUSES).toContain('verified');
    expect(HANDSHAKE_STATUSES).toContain('rejected');
    expect(HANDSHAKE_STATUSES).toContain('expired');
    expect(HANDSHAKE_STATUSES).toContain('revoked');
  });

  it('getHandshake returns full state of an existing handshake', async () => {
    const sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());

    const hs_id = 'eph_get_' + crypto.randomBytes(6).toString('hex');
    sim.getTable('handshakes').push({
      handshake_id: hs_id,
      mode: 'basic',
      status: 'initiated',
      policy_id: 'policy-abc-123',
    });
    sim.getTable('handshake_parties').push({
      id: crypto.randomBytes(8).toString('hex'),
      handshake_id: hs_id,
      party_role: 'initiator',
      entity_ref: 'entity-alice',
    });

    const result = await getHandshake(hs_id);

    expect(result).toBeDefined();
    expect(result.handshake_id).toBe(hs_id);
    expect(result.status).toBe('initiated');
    expect(result.parties).toHaveLength(1);
  });
});
